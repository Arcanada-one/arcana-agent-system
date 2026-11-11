//! The rule that binds a work item to a contract: re-hash, or refuse.
//!
//! These are the assertions a mutant has to survive. The one that matters most
//! is [`digest_mismatch_is_refused`]: delete the comparison in
//! `arcana_core::contract::verify` and this test is the only thing in the
//! workspace that goes red, because every other path is happy to run under a
//! document that parses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_core::contract::{
    digest_of, is_wellformed_digest, verify, AllowlistSource, CanonicalBlock, ContractDocument,
    ContractRefusal, ContractTools, DigestPreimage, Kc2Block, DEFAULT_ALLOWLIST,
};
use serde_json::{json, Value};

/// A source that renders its projection as a string — the simplest shape this
/// client accepts, and the one a hand-written fixture takes.
fn document(projection: &str) -> ContractDocument {
    ContractDocument {
        digest: digest_of(projection.as_bytes()),
        projection: json!(projection),
        kc2_revision: Some("kc2-role-reviewer@r7".to_owned()),
        kc2_snapshot: Some(
            "sha256:192e2ce29dd00cf19dd682d948d6bd09f2fa8cc468ca44d2e6f1b2ff7abb563b".to_owned(),
        ),
        ..ContractDocument::default()
    }
}

#[test]
fn a_document_that_hashes_to_the_expected_digest_binds() {
    let doc = document("Role: reviewer. Deliverable: one review note.");
    let expected = doc.digest.clone();

    let binding = verify(&expected, &doc).expect("the bytes hash to the digest");

    assert_eq!(binding.digest(), expected);
    assert_eq!(binding.preimage(), DigestPreimage::Projection);
    assert_eq!(binding.kc2_revision(), Some("kc2-role-reviewer@r7"));
}

#[test]
fn digest_mismatch_is_refused() {
    let doc = document("Role: reviewer. Deliverable: one review note.");
    // The work item names a contract; the source answers with another one.
    // Every field of the answer is internally consistent — which is exactly
    // why trusting the answer's own `digest` field would let it through.
    let expected = digest_of(b"Role: deployer. Deliverable: production access.");

    let refusal = verify(&expected, &doc).expect_err("a different contract cannot bind");

    assert_eq!(refusal.code(), "CONTRACT_DIGEST_MISMATCH");
    match refusal {
        ContractRefusal::DigestMismatch {
            expected: named,
            computed,
            preimage,
        } => {
            assert_eq!(named, expected);
            assert_eq!(computed, doc.digest);
            assert_eq!(preimage, DigestPreimage::Projection);
        }
        other => panic!("wrong refusal: {other:?}"),
    }
}

#[test]
fn the_sources_own_digest_field_is_not_the_authority() {
    // A document whose `digest` field agrees with the request but whose bytes
    // do not: the tampering a self-consistency check cannot see.
    let expected = digest_of(b"Role: reviewer. Deliverable: one review note.");
    let doc = ContractDocument {
        digest: expected.clone(),
        projection: json!("Role: reviewer. Deliverable: one review note. Also: deploy."),
        ..ContractDocument::default()
    };

    let refusal = verify(&expected, &doc).expect_err("altered bytes cannot bind");
    assert_eq!(refusal.code(), "CONTRACT_DIGEST_MISMATCH");
}

#[test]
fn canonical_bytes_are_preferred_over_the_projection() {
    let canonical = "{\"body\":1,\"manifest\":[]}";
    let doc = ContractDocument {
        digest: digest_of(canonical.as_bytes()),
        canonical_bytes: Some(canonical.to_owned()),
        ..ContractDocument::default()
    };
    let expected = doc.digest.clone();

    let binding = verify(&expected, &doc).expect("the declared preimage hashes to the digest");
    assert_eq!(binding.preimage(), DigestPreimage::CanonicalBytes);
    // What the model is shown is the verified preimage itself, not an envelope
    // rendering that the digest does not cover (a differing one is refused —
    // see `opaque_text_preimage_cannot_carry_envelope_tools`).
    assert_eq!(binding.projection(), canonical);
}

#[test]
fn a_contract_that_names_no_tools_grants_no_shell() {
    let doc = document("Role: reviewer.");
    let binding = verify(&doc.digest.clone(), &doc).expect("binds");

    assert_eq!(binding.allowlist_source(), AllowlistSource::DefaultNoShell);
    for tool in DEFAULT_ALLOWLIST {
        assert!(binding.admits(tool), "{tool} should be admitted");
    }
    assert!(
        !binding.admits("bash"),
        "a contract that says nothing must not grant a shell"
    );
}

#[test]
fn a_contract_that_names_tools_is_the_allowlist() {
    let bytes = "{\"role\":\"r\",\"tools\":{\"allow\":[\"read\",\"grep\"]}}{\"revisions\":[]}";
    let doc = ContractDocument {
        digest: digest_of(bytes.as_bytes()),
        canonical_bytes: Some(bytes.to_owned()),
        ..ContractDocument::default()
    };
    let binding = verify(&doc.digest.clone(), &doc).expect("binds");

    assert_eq!(binding.allowlist_source(), AllowlistSource::Contract);
    assert!(binding.admits("read"));
    assert!(
        !binding.admits("write"),
        "the contract did not name `write`"
    );
}

#[test]
fn a_malformed_digest_is_refused_before_anything_is_fetched() {
    let doc = document("Role: reviewer.");
    let refusal = verify("769cc084", &doc).expect_err("not a sha256: digest");
    assert_eq!(refusal.code(), "CONTRACT_DIGEST_MALFORMED");

    assert!(!is_wellformed_digest("sha256:ABCD"));
    assert!(!is_wellformed_digest(&format!("sha256:{}", "A".repeat(64))));
    assert!(is_wellformed_digest(&digest_of(b"x")));
}

#[test]
fn a_document_with_nothing_to_hash_cannot_bind() {
    let expected = digest_of(b"anything");
    let doc = ContractDocument {
        digest: expected.clone(),
        ..ContractDocument::default()
    };
    let refusal = verify(&expected, &doc).expect_err("nothing to re-hash");
    assert_eq!(refusal.code(), "CONTRACT_UNVERIFIABLE");
}

#[test]
fn an_object_projection_is_never_hashed_on_a_guess() {
    // Argana's `projection` is `{body, closure_manifest}` — the digested object,
    // not the digested bytes. Re-serialising it here would be this client
    // inventing a canonicalisation rule, and the answer would be a digest that
    // is nobody's.
    let expected = digest_of(b"the real canonical bytes");
    let doc = ContractDocument {
        digest: expected.clone(),
        projection: json!({"body": {"role": "reviewer"}, "closure_manifest": {"revisions": []}}),
        ..ContractDocument::default()
    };

    let refusal = verify(&expected, &doc).expect_err("there is no preimage here");
    assert_eq!(refusal.code(), "CONTRACT_UNVERIFIABLE");
}

/// The shape Argana actually answers with (`ContractResponse`, A2-271):
/// `canonical.bytes_b64` is the preimage, `projection` is the parsed object,
/// and the pin is under `kc2`.
#[test]
fn the_argana_response_shape_verifies_off_canonical_bytes_b64() {
    let canonical = b"{\"role\":\"reviewer\"}{\"revisions\":[]}";
    let expected = digest_of(canonical);
    let doc = ContractDocument {
        digest: expected.clone(),
        projection: json!({"body": {"role": "reviewer"}, "closure_manifest": {"revisions": []}}),
        canonical: Some(CanonicalBlock {
            rule: Some("sha256(canonical(body) || canonical(closure_manifest))".to_owned()),
            bytes_b64: Some("eyJyb2xlIjoicmV2aWV3ZXIifXsicmV2aXNpb25zIjpbXX0=".to_owned()),
            length: Some(canonical.len() as u64),
        }),
        kc2: Some(Kc2Block {
            revision: Some("kc2@r41".to_owned()),
            snapshot: Some(digest_of(b"snapshot")),
            pin_status: Some("current".to_owned()),
        }),
        ..ContractDocument::default()
    };

    let binding = verify(&expected, &doc).expect("the live shape verifies");
    assert_eq!(binding.preimage(), DigestPreimage::CanonicalBytesB64);
    assert_eq!(binding.kc2_revision(), Some("kc2@r41"));
    // The projection the model is shown is TEXT, and it is not the preimage.
    assert!(binding.projection().contains("closure_manifest"));
}

#[test]
fn canonical_bytes_b64_that_is_not_base64_is_unverifiable_not_a_mismatch() {
    let expected = digest_of(b"x");
    let doc = ContractDocument {
        digest: expected.clone(),
        canonical: Some(CanonicalBlock {
            rule: None,
            bytes_b64: Some("!!! not base64 !!!".to_owned()),
            length: None,
        }),
        ..ContractDocument::default()
    };
    let refusal = verify(&expected, &doc).expect_err("undecodable");
    assert_eq!(refusal.code(), "CONTRACT_UNVERIFIABLE");
}

#[test]
fn an_explicit_empty_allowlist_admits_no_tools() {
    let bytes = "{\"role\":\"r\",\"tools\":{\"allow\":[]}}{\"revisions\":[]}";
    let doc = ContractDocument {
        digest: digest_of(bytes.as_bytes()),
        canonical_bytes: Some(bytes.to_owned()),
        ..ContractDocument::default()
    };
    let binding = verify(&doc.digest, &doc).expect("the fixture binds");
    assert_eq!(binding.allowlist_source(), AllowlistSource::Contract);
    assert!(binding.allowlist().is_empty());
    for tool in DEFAULT_ALLOWLIST.into_iter().chain(["bash"]) {
        assert!(!binding.admits(tool), "explicit empty must refuse {tool}");
    }
}

// ---------------------------------------------------------------------------
// Envelope-to-bytes binding (KCLIVE-11, SM-06). The digest covers only
// `canonical(body) ‖ canonical(closure_manifest)`; `projection` and `tools`
// sit outside it. Each test keeps the BYTES (so the digest still matches) and
// changes the envelope. Every one was run against a variant of `verify` that
// skips `derive_policy` and failed there — see the PR's mutation record.
// ---------------------------------------------------------------------------

const ARGANA_BYTES: &[u8] = b"{\"role\":\"reviewer\"}{\"revisions\":[]}";
const ARGANA_B64: &str = "eyJyb2xlIjoicmV2aWV3ZXIifXsicmV2aXNpb25zIjpbXX0=";

fn argana_doc() -> ContractDocument {
    ContractDocument {
        digest: digest_of(ARGANA_BYTES),
        projection: json!({"body": {"role": "reviewer"}, "closure_manifest": {"revisions": []}}),
        canonical: Some(CanonicalBlock {
            rule: None,
            bytes_b64: Some(ARGANA_B64.to_owned()),
            length: Some(ARGANA_BYTES.len() as u64),
        }),
        ..ContractDocument::default()
    }
}

#[test]
fn same_bytes_with_a_changed_projection_is_refused() {
    let mut doc = argana_doc();
    doc.projection = json!({"body": {"role": "deployer"}, "closure_manifest": {"revisions": []}});
    let refusal = verify(&doc.digest.clone(), &doc).expect_err("projection not in the bytes");
    assert_eq!(refusal.code(), "CONTRACT_POLICY_UNBOUND");
}

#[test]
fn same_bytes_with_expanded_tools_is_refused() {
    let mut doc = argana_doc();
    doc.tools = Some(ContractTools {
        allow: vec!["read".to_owned(), "bash".to_owned()],
    });
    let refusal = verify(&doc.digest.clone(), &doc).expect_err("a shell outside the bytes");
    assert_eq!(refusal.code(), "CONTRACT_POLICY_UNBOUND");
}

#[test]
fn same_bytes_with_omitted_or_narrowed_tools_is_not_silently_believed() {
    // The bytes name no tools. An envelope that narrows them is as unbound as
    // one that widens them: the effective set must come from the bytes only.
    let mut doc = argana_doc();
    doc.tools = Some(ContractTools { allow: vec![] });
    let refusal = verify(&doc.digest.clone(), &doc).expect_err("empty list is not in the bytes");
    assert_eq!(refusal.code(), "CONTRACT_POLICY_UNBOUND");

    // And with no envelope tools the effective set is the no-shell default.
    let binding = verify(&argana_doc().digest, &argana_doc()).expect("binds");
    assert_eq!(binding.allowlist_source(), AllowlistSource::DefaultNoShell);
    assert!(!binding.admits("bash"));
    assert_eq!(
        binding.policy_binding(),
        arcana_core::contract::PolicyBinding::DerivedFromCanonicalBytes
    );
}

#[test]
fn tools_in_the_digested_body_are_the_effective_allowlist() {
    let bytes = b"{\"role\":\"r\",\"tools\":{\"allow\":[\"read\",\"write\"]}}{\"revisions\":[]}";
    let mut doc = ContractDocument {
        digest: digest_of(bytes),
        canonical: Some(CanonicalBlock {
            rule: None,
            bytes_b64: Some(base64_of(bytes)),
            length: None,
        }),
        ..ContractDocument::default()
    };
    // No envelope tools at all: the bytes alone decide.
    let binding = verify(&doc.digest.clone(), &doc).expect("binds");
    assert_eq!(binding.allowlist_source(), AllowlistSource::Contract);
    assert!(binding.admits("read") && binding.admits("write"));
    assert!(!binding.admits("edit") && !binding.admits("bash"));
    // The projection the model reads is derived from the same bytes.
    assert!(binding.projection().contains("\"write\""));

    // An envelope that agrees is accepted; one that widens is refused.
    doc.tools = Some(ContractTools {
        allow: vec!["read".to_owned(), "write".to_owned()],
    });
    assert!(verify(&doc.digest.clone(), &doc).is_ok());
    doc.tools = Some(ContractTools {
        allow: vec!["read".to_owned(), "write".to_owned(), "bash".to_owned()],
    });
    assert_eq!(
        verify(&doc.digest.clone(), &doc)
            .expect_err("widened")
            .code(),
        "CONTRACT_POLICY_UNBOUND"
    );
}

#[test]
fn a_projection_the_model_reads_comes_from_the_bytes_not_the_envelope() {
    let mut doc = argana_doc();
    doc.projection = Value::Null; // an omitted projection is not a way to blank the policy text
    let binding = verify(&doc.digest.clone(), &doc).expect("binds");
    assert!(binding.projection().contains("reviewer"));
}

#[test]
fn opaque_text_preimage_cannot_carry_envelope_tools() {
    // String-projection and plain `canonical_bytes` fallbacks: there is no
    // structure in the digested text that could authenticate an allowlist.
    let mut doc = document("Role: reviewer.");
    doc.tools = Some(ContractTools {
        allow: vec!["read".to_owned()],
    });
    let refusal = verify(&doc.digest.clone(), &doc).expect_err("unbound allowlist");
    assert_eq!(refusal.code(), "CONTRACT_POLICY_UNBOUND");

    // A plain canonical_bytes preimage must also be what the model is shown.
    let canonical = "free text, not two JSON objects";
    let bad = ContractDocument {
        digest: digest_of(canonical.as_bytes()),
        projection: json!("something else entirely"),
        canonical_bytes: Some(canonical.to_owned()),
        ..ContractDocument::default()
    };
    assert_eq!(
        verify(&bad.digest.clone(), &bad)
            .expect_err("projection unbound")
            .code(),
        "CONTRACT_POLICY_UNBOUND"
    );
}

#[test]
fn trailing_or_extra_json_in_the_preimage_is_not_two_halves() {
    // Three objects, or trailing garbage, must not be read as body+manifest.
    for bytes in [
        &b"{\"a\":1}{\"b\":2}{\"c\":3}"[..],
        &b"{\"a\":1}{\"b\":2} trailing"[..],
        &b"[1][2]"[..],
    ] {
        let doc = ContractDocument {
            digest: digest_of(bytes),
            projection: json!({"body": {"a": 1}, "closure_manifest": {"b": 2}}),
            canonical: Some(CanonicalBlock {
                rule: None,
                bytes_b64: Some(base64_of(bytes)),
                length: None,
            }),
            ..ContractDocument::default()
        };
        let refusal = verify(&doc.digest.clone(), &doc).expect_err("not a structured preimage");
        assert_eq!(refusal.code(), "CONTRACT_POLICY_UNBOUND");
    }
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
