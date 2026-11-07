//! Strict `arcanada-kc2-tools/v1` reader: the refusal matrix (KCLIVE-11).
//!
//! Every contract here is SYNTHETIC — built in this file, issued by nobody,
//! pinned to no native revision, and never run live. Positive fixtures show
//! only that the reader accepts a conforming shape; they are not a grant, not a
//! native policy, and not evidence that `["read","write"]` is eligible for any
//! task.
//!
//! The matrix mirrors the compatibility review of PR273 head 8808868b
//! (M1–M13, R1–R3, P25). The ONLY entry point is `harness::strict`, which
//! returns the sorted allowlist or the refusal CODE string, so the same file
//! can be run against the pre-change `verify` (see REPORT.md) to show each
//! refusal fixture red before and green after.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_pass_by_value,
    clippy::format_push_string,
    clippy::needless_raw_string_hashes
)]

use arcana_core::contract::{digest_of, CanonicalBlock, ContractDocument, ContractTools};
use base64::Engine as _;
use serde_json::json;

// HARNESS-BEGIN
mod harness {
    use super::*;

    pub const PROFILE: &str = "arcanada-kc2-tools/v1";

    /// Strict admission; `Ok(sorted allowlist)` or `Err(refusal code)`.
    pub fn strict_as(
        profile: &str,
        expected: &str,
        doc: &ContractDocument,
    ) -> Result<Vec<String>, String> {
        arcana_core::contract::verify_with(
            expected,
            doc,
            arcana_core::contract::ReaderMode::Strict { profile },
        )
        .map(|b| b.allowlist().iter().cloned().collect())
        .map_err(|e| e.code().to_owned())
    }

    pub fn strict(expected: &str, doc: &ContractDocument) -> Result<Vec<String>, String> {
        strict_as(PROFILE, expected, doc)
    }
}
// HARNESS-END
use harness::{strict, PROFILE};

// ---------- synthetic fixtures ----------

/// A canonical (sorted, compact) SYNTHETIC body with the twelve v2 members and
/// the given `tools` value (`None` omits the member).
fn body_with(tools: Option<serde_json::Value>) -> serde_json::Value {
    let mut body = json!({
        "task": "synthetic-task",
        "scope": {},
        "projection": {},
        "embedded": [],
        "reduction": {},
        "conflict_records": [],
        "refusals": [],
        "verdicts": [],
        "envelope_unverified": [],
        "verdict": "synthetic",
        "quarantined": [],
        "canonicalization": "json-c14n-pilot/v1"
    });
    if let Some(tools) = tools {
        body["tools"] = tools;
    }
    body
}

fn tools(allow: serde_json::Value) -> serde_json::Value {
    json!({ "profile": PROFILE, "allow": allow })
}

fn manifest(pins: usize) -> String {
    let revisions: Vec<_> = (0..pins)
        .map(|i| json!({"synthetic": format!("pin-{i}")}))
        .collect();
    json!({"snapshot_digest": "synthetic", "revisions": revisions}).to_string()
}

/// Build a document around raw `body‖manifest` text, hashed as given.
fn doc_raw(body: &str, manifest: &str) -> (String, ContractDocument) {
    let bytes = format!("{body}{manifest}");
    let digest = digest_of(bytes.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes.as_bytes());
    (
        digest.clone(),
        ContractDocument {
            digest,
            canonical: Some(CanonicalBlock {
                bytes_b64: Some(b64),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
}

/// `serde_json::Value` serialises objects with sorted keys and no spaces, which
/// is the canonical form for these ASCII-only fixtures.
fn doc_of(body: &serde_json::Value, pins: usize) -> (String, ContractDocument) {
    doc_raw(&body.to_string(), &manifest(pins))
}

fn refused(tools_value: Option<serde_json::Value>, pins: usize) -> String {
    let (d, doc) = doc_of(&body_with(tools_value), pins);
    strict(&d, &doc).expect_err("must refuse")
}

fn code_for_tools(t: serde_json::Value) -> String {
    refused(Some(t), 1)
}

/// Attach the top-level dispatch hints through the wire shape, so this file
/// also compiles against a reader whose `ContractDocument` has no such fields
/// (it then simply ignores them, which is the review's P24).
fn with_hints(
    doc: &ContractDocument,
    kind: Option<&str>,
    schema_version: Option<&str>,
) -> ContractDocument {
    let mut wire = serde_json::to_value(doc).unwrap();
    if let Some(kind) = kind {
        wire["kind"] = json!(kind);
    }
    if let Some(version) = schema_version {
        wire["schema_version"] = json!(version);
    }
    serde_json::from_value(wire).unwrap()
}

// ---------- positives (SYNTHETIC) ----------

#[test]
fn synthetic_read_write_is_accepted_with_exactly_those_tools() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read", "write"])))), 1);
    assert_eq!(strict(&d, &doc).unwrap(), vec!["read", "write"]);
}

#[test]
fn synthetic_empty_allow_is_explicit_deny_all() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!([])))), 0);
    assert_eq!(strict(&d, &doc).unwrap(), Vec::<String>::new());
}

// ---------- M1: profile marker ----------

#[test]
fn m1_unknown_profile_marker_is_invalid() {
    assert_eq!(
        code_for_tools(json!({"profile": "other/v9", "allow": ["read"]})),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m1_wrong_typed_profile_marker_is_invalid() {
    assert_eq!(
        code_for_tools(json!({"profile": 7, "allow": ["read"]})),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m1_null_profile_marker_is_invalid() {
    assert_eq!(
        code_for_tools(json!({"profile": null, "allow": ["read"]})),
        "CONTRACT_PROFILE_INVALID"
    );
}

// ---------- M2 / M3 / M4: required members ----------

#[test]
fn m2_profile_absent_is_required() {
    assert_eq!(
        code_for_tools(json!({"allow": ["read"]})),
        "CONTRACT_PROFILE_REQUIRED"
    );
}

#[test]
fn m3_tools_absent_is_required_never_the_default_set() {
    assert_eq!(refused(None, 1), "CONTRACT_PROFILE_REQUIRED");
}

#[test]
fn m4_empty_tools_object_is_required() {
    assert_eq!(code_for_tools(json!({})), "CONTRACT_PROFILE_REQUIRED");
}

#[test]
fn m4_allow_absent_is_required_not_deny_all() {
    assert_eq!(
        code_for_tools(json!({"profile": PROFILE})),
        "CONTRACT_PROFILE_REQUIRED"
    );
}

#[test]
fn tools_null_is_invalid() {
    assert_eq!(refused(Some(json!(null)), 1), "CONTRACT_PROFILE_INVALID");
}

#[test]
fn allow_null_is_invalid() {
    assert_eq!(
        code_for_tools(json!({"profile": PROFILE, "allow": null})),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn allow_non_string_entry_is_invalid() {
    assert_eq!(
        code_for_tools(tools(json!([1]))),
        "CONTRACT_PROFILE_INVALID"
    );
}

// ---------- M5 / M6 / M7 / M8: vocabulary, order, extras ----------

#[test]
fn m5_shell_is_invalid() {
    assert_eq!(
        code_for_tools(tools(json!(["bash"]))),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m5_more_than_four_entries_is_invalid() {
    assert_eq!(
        code_for_tools(tools(json!(["edit", "grep", "read", "write", "bash"]))),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m5_case_variant_is_invalid() {
    assert_eq!(
        code_for_tools(tools(json!(["Read"]))),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m5_alias_is_invalid() {
    assert_eq!(
        code_for_tools(tools(json!(["cat"]))),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m6_wildcard_is_invalid() {
    assert_eq!(
        code_for_tools(tools(json!(["*"]))),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m7_duplicate_entry_is_invalid_not_deduplicated() {
    assert_eq!(
        code_for_tools(tools(json!(["read", "read"]))),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m7_out_of_order_entries_are_invalid_not_sorted() {
    assert_eq!(
        code_for_tools(tools(json!(["write", "read"]))),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m8_extra_property_in_tools_is_invalid() {
    assert_eq!(
        code_for_tools(json!({"profile": PROFILE, "allow": ["read"], "shell": true})),
        "CONTRACT_PROFILE_INVALID"
    );
}

// ---------- M9: positional / array tools (P14, P25) ----------

#[test]
fn m9_tools_as_empty_array_is_invalid() {
    assert_eq!(refused(Some(json!([])), 1), "CONTRACT_PROFILE_INVALID");
}

#[test]
fn m9_p25_tools_as_positional_sequence_is_invalid() {
    assert_eq!(
        refused(Some(json!([["read"]])), 1),
        "CONTRACT_PROFILE_INVALID"
    );
}

#[test]
fn m9_p25_with_a_bare_body_is_refused_not_parsed_positionally() {
    // The exact probe-file shape: the whole body is only `{"tools":[["read"]]}`.
    let (d, doc) = doc_raw(r#"{"tools":[["read"]]}"#, &manifest(1));
    assert!(strict(&d, &doc).is_err());
}

// ---------- M10 / M11: raw bytes ----------

#[test]
fn m10_duplicate_tools_key_is_canonical_invalid() {
    let t = format!(r#""tools":{{"allow":["read"],"profile":"{PROFILE}"}}"#);
    let t2 = format!(r#""tools":{{"allow":["bash"],"profile":"{PROFILE}"}}"#);
    let (d, doc) = doc_raw(&format!(r#"{{{t},{t2}}}"#), &manifest(1));
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
}

#[test]
fn m10_duplicate_allow_key_inside_tools_is_canonical_invalid() {
    let mut body = body_with(None).to_string();
    body.pop();
    body.push_str(&format!(
        r#","tools":{{"allow":["read"],"allow":["bash"],"profile":"{PROFILE}"}}}}"#
    ));
    let (d, doc) = doc_raw(&body, &manifest(1));
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
}

#[test]
fn m11_pretty_printed_equivalent_with_matching_digest_is_canonical_invalid() {
    let pretty = serde_json::to_string_pretty(&body_with(Some(tools(json!(["read"]))))).unwrap();
    let (d, doc) = doc_raw(&pretty, &manifest(1));
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
}

#[test]
fn m11_unsorted_keys_with_matching_digest_are_canonical_invalid() {
    let t = format!(r#""tools":{{"profile":"{PROFILE}","allow":["read"]}}"#);
    let mut body = body_with(None).to_string();
    body.pop();
    body.push_str(&format!(",{t}}}"));
    let (d, doc) = doc_raw(&body, &manifest(1));
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
}

#[test]
fn m11_raw_non_ascii_where_the_rule_escapes_is_canonical_invalid() {
    let mut value = body_with(Some(tools(json!(["read"]))));
    value["task"] = json!("caf\u{e9}");
    // serde_json writes the raw character; json-c14n-pilot/v1 requires é.
    let (d, doc) = doc_of(&value, 1);
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
}

#[test]
fn m11_whitespace_between_the_halves_is_canonical_invalid() {
    let body = body_with(Some(tools(json!(["read"])))).to_string();
    let (d, doc) = doc_raw(&body, &format!(" {}", manifest(1)));
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
}

#[test]
fn float_number_is_canonical_invalid() {
    let mut value = body_with(Some(tools(json!(["read"]))));
    value["scope"] = json!({"n": 1.5});
    let (d, doc) = doc_of(&value, 1);
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
}

// ---------- M12: closed body / manifest ----------

#[test]
fn m12_extra_root_member_is_invalid() {
    let mut value = body_with(Some(tools(json!(["read"]))));
    value["zzz"] = json!(1);
    let (d, doc) = doc_of(&value, 1);
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
}

#[test]
fn m12_missing_v2_member_is_invalid() {
    let mut value = body_with(Some(tools(json!(["read"]))));
    value.as_object_mut().unwrap().remove("verdicts");
    let (d, doc) = doc_of(&value, 1);
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
}

#[test]
fn m12_body_with_only_tools_is_invalid() {
    let (d, doc) = doc_raw(
        &json!({"tools": tools(json!(["read"]))}).to_string(),
        &manifest(1),
    );
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
}

#[test]
fn m12_extra_manifest_member_is_invalid() {
    let body = body_with(Some(tools(json!(["read"])))).to_string();
    let m = json!({"snapshot_digest": "s", "revisions": [{"a": 1}], "extra": 1}).to_string();
    let (d, doc) = doc_raw(&body, &m);
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
}

#[test]
fn m12_manifest_revisions_must_be_an_array() {
    let body = body_with(Some(tools(json!(["read"])))).to_string();
    let m = json!({"snapshot_digest": "s", "revisions": "x"}).to_string();
    let (d, doc) = doc_raw(&body, &m);
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
}

// ---------- M13 / R2: only the Argana preimage route qualifies ----------

#[test]
fn m13_opaque_text_preimage_is_canonical_invalid() {
    let text = "plain contract text";
    let digest = digest_of(text.as_bytes());
    let doc = ContractDocument {
        digest: digest.clone(),
        projection: json!(text),
        ..Default::default()
    };
    assert_eq!(
        strict(&digest, &doc).unwrap_err(),
        "CONTRACT_CANONICAL_INVALID"
    );
}

#[test]
fn r2_plain_text_canonical_bytes_route_is_canonical_invalid() {
    let bytes = format!("{}{}", body_with(Some(tools(json!(["read"])))), manifest(1));
    let digest = digest_of(bytes.as_bytes());
    let doc = ContractDocument {
        digest: digest.clone(),
        canonical_bytes: Some(bytes),
        ..Default::default()
    };
    assert_eq!(
        strict(&digest, &doc).unwrap_err(),
        "CONTRACT_CANONICAL_INVALID"
    );
}

#[test]
fn r2_string_projection_route_is_canonical_invalid() {
    let bytes = format!("{}{}", body_with(Some(tools(json!(["read"])))), manifest(1));
    let digest = digest_of(bytes.as_bytes());
    let doc = ContractDocument {
        digest: digest.clone(),
        projection: json!(bytes),
        ..Default::default()
    };
    assert_eq!(
        strict(&digest, &doc).unwrap_err(),
        "CONTRACT_CANONICAL_INVALID"
    );
}

// ---------- R1: top-level hints and envelope copies ----------

#[test]
fn r1_envelope_schema_version_that_disagrees_with_the_inner_marker_is_unbound() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    let doc = with_hints(&doc, Some("KnowledgeContract"), Some("something-else"));
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_POLICY_UNBOUND");
}

#[test]
fn r1_envelope_kind_that_is_not_knowledge_contract_is_unbound() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    let doc = with_hints(&doc, Some("Nope"), Some(PROFILE));
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_POLICY_UNBOUND");
}

#[test]
fn r1_agreeing_hints_are_accepted() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    let doc = with_hints(&doc, Some("KnowledgeContract"), Some(PROFILE));
    assert_eq!(strict(&d, &doc).unwrap(), vec!["read"]);
}

#[test]
fn shipped_unbound_meaning_envelope_tools_that_differ_are_still_unbound() {
    let (d, mut doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    doc.tools = Some(ContractTools {
        allow: vec!["read".into(), "write".into()],
    });
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_POLICY_UNBOUND");
}

#[test]
fn shipped_unbound_meaning_envelope_projection_that_differs_is_still_unbound() {
    let (d, mut doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    doc.projection = json!({"body": {}, "closure_manifest": {}});
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_POLICY_UNBOUND");
}

// ---------- shipped digest meaning ----------

#[test]
fn shipped_digest_mismatch_meaning_is_unchanged() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    let other = digest_of(b"some other contract");
    assert_ne!(d, other);
    assert_eq!(
        strict(&other, &doc).unwrap_err(),
        "CONTRACT_DIGEST_MISMATCH"
    );
}

#[test]
fn changed_allow_under_an_unchanged_digest_is_a_digest_mismatch() {
    let (d, _) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    let (_, forged) = doc_of(&body_with(Some(tools(json!(["read", "write"])))), 1);
    assert_eq!(strict(&d, &forged).unwrap_err(), "CONTRACT_DIGEST_MISMATCH");
}

// ---------- CONTRACT_POLICY_SOURCE_UNRESOLVED ----------

#[test]
fn non_empty_allow_without_any_pinned_policy_revision_is_source_unresolved() {
    assert_eq!(
        refused(Some(tools(json!(["read", "write"]))), 0),
        "CONTRACT_POLICY_SOURCE_UNRESOLVED"
    );
}

#[test]
fn deny_all_needs_no_policy_source() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!([])))), 0);
    assert!(strict(&d, &doc).is_ok());
}

// ---------- R3: reader capability ----------

#[test]
fn r3_a_profile_this_reader_cannot_enforce_is_reader_unsupported() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    assert_eq!(
        harness::strict_as("arcanada-kc2-tools/v2", &d, &doc).unwrap_err(),
        "CONTRACT_READER_UNSUPPORTED"
    );
}

#[test]
fn r3_an_unpinned_empty_profile_request_is_reader_unsupported() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    assert_eq!(
        harness::strict_as("", &d, &doc).unwrap_err(),
        "CONTRACT_READER_UNSUPPORTED"
    );
}

#[test]
fn r3_reader_unsupported_is_raised_before_any_bytes_are_examined() {
    let doc = ContractDocument::default();
    assert_eq!(
        harness::strict_as("nope/v0", "not-a-digest", &doc).unwrap_err(),
        "CONTRACT_READER_UNSUPPORTED"
    );
}
