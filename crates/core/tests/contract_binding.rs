//! The rule that binds a work item to a contract: re-hash, or refuse.
//!
//! These are the assertions a mutant has to survive. The one that matters most
//! is [`digest_mismatch_is_refused`]: delete the comparison in
//! `arcana_core::contract::verify` and this test is the only thing in the
//! workspace that goes red, because every other path is happy to run under a
//! document that parses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_core::contract::{
    digest_of, is_wellformed_digest, verify, AllowlistSource, ContractDocument, ContractRefusal,
    ContractTools, DigestPreimage, DEFAULT_ALLOWLIST,
};

fn document(projection: &str) -> ContractDocument {
    ContractDocument {
        digest: digest_of(projection.as_bytes()),
        projection: projection.to_owned(),
        canonical_bytes: None,
        kc2_revision: Some("kc2-role-reviewer@r7".to_owned()),
        kc2_snapshot: Some("sha256:192e2ce29dd00cf19dd682d948d6bd09f2fa8cc468ca44d2e6f1b2ff7abb563b".to_owned()),
        tools: None,
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
        projection: "Role: reviewer. Deliverable: one review note. Also: deploy.".to_owned(),
        canonical_bytes: None,
        kc2_revision: None,
        kc2_snapshot: None,
        tools: None,
    };

    let refusal = verify(&expected, &doc).expect_err("altered bytes cannot bind");
    assert_eq!(refusal.code(), "CONTRACT_DIGEST_MISMATCH");
}

#[test]
fn canonical_bytes_are_preferred_over_the_projection() {
    let canonical = "{\"body\":1,\"manifest\":[]}";
    let doc = ContractDocument {
        digest: digest_of(canonical.as_bytes()),
        projection: "a human-readable rendering that is NOT the preimage".to_owned(),
        canonical_bytes: Some(canonical.to_owned()),
        kc2_revision: None,
        kc2_snapshot: None,
        tools: None,
    };
    let expected = doc.digest.clone();

    let binding = verify(&expected, &doc).expect("the declared preimage hashes to the digest");
    assert_eq!(binding.preimage(), DigestPreimage::CanonicalBytes);
    // The projection is still carried — it is what the model is told — but it
    // is not what was hashed, and the binding says so.
    assert!(binding.projection().starts_with("a human-readable"));
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
    let mut doc = document("Role: reviewer.");
    doc.tools = Some(ContractTools {
        allow: vec!["read".to_owned(), "grep".to_owned()],
    });
    doc.digest = digest_of(doc.projection.as_bytes());
    let binding = verify(&doc.digest.clone(), &doc).expect("binds");

    assert_eq!(binding.allowlist_source(), AllowlistSource::Contract);
    assert!(binding.admits("read"));
    assert!(!binding.admits("write"), "the contract did not name `write`");
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
        projection: String::new(),
        canonical_bytes: None,
        kc2_revision: None,
        kc2_snapshot: None,
        tools: None,
    };
    let refusal = verify(&expected, &doc).expect_err("nothing to re-hash");
    assert_eq!(refusal.code(), "CONTRACT_UNVERIFIABLE");
}
