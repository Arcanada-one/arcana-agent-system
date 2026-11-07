//! What a strict binding records, and that the legacy route stays a separate,
//! recorded route that can never satisfy the strict profile. SYNTHETIC fixtures.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_pass_by_value,
    clippy::format_push_string,
    clippy::needless_raw_string_hashes
)]

use arcana_core::contract::{
    digest_of, schema_parity, verify, verify_with, AllowlistSource, CanonicalBlock,
    ContractDocument, ReaderMode, ReaderRoute, SchemaParity, READER_CAPABILITY, STRICT_PROFILE,
    TALOMNIA_SCHEMA_PIN,
};
use base64::Engine as _;
use serde_json::json;

fn synthetic(allow: serde_json::Value, pins: usize) -> (String, ContractDocument) {
    let body = json!({
        "task": "synthetic-task", "scope": {}, "projection": {}, "embedded": [],
        "reduction": {}, "conflict_records": [], "refusals": [], "verdicts": [],
        "envelope_unverified": [], "verdict": "synthetic", "quarantined": [],
        "canonicalization": "json-c14n-pilot/v1",
        "tools": {"profile": STRICT_PROFILE, "allow": allow}
    });
    let revisions: Vec<_> = (0..pins).map(|i| json!({"synthetic": i})).collect();
    let manifest = json!({"snapshot_digest": "synthetic", "revisions": revisions});
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

#[test]
fn a_strict_binding_records_route_profile_capability_and_parity() {
    let (d, doc) = synthetic(json!(["read", "write"]), 1);
    let b = verify_with(
        &d,
        &doc,
        ReaderMode::Strict {
            profile: STRICT_PROFILE,
        },
    )
    .unwrap();
    assert_eq!(b.reader_route(), ReaderRoute::Strict);
    assert_eq!(b.profile(), Some(STRICT_PROFILE));
    assert!(b.satisfies_profile(STRICT_PROFILE));
    assert_eq!(b.allowlist_source(), AllowlistSource::Contract);
    assert_eq!(b.reader_capability(), READER_CAPABILITY.signal());
    assert!(b
        .reader_capability()
        .contains("strict:arcanada-kc2-tools/v1"));
    assert!(b
        .reader_capability()
        .contains("canonical:json-c14n-pilot/v1"));
}

#[test]
fn schema_parity_is_not_ready_while_the_talomnia_pin_slot_is_empty() {
    assert!(
        TALOMNIA_SCHEMA_PIN.is_none(),
        "no schema identity may be invented"
    );
    assert_eq!(schema_parity(), SchemaParity::NotReady);
    assert_eq!(schema_parity().as_str(), "NOT_READY");
    let (d, doc) = synthetic(json!(["read"]), 1);
    let b = verify_with(
        &d,
        &doc,
        ReaderMode::Strict {
            profile: STRICT_PROFILE,
        },
    )
    .unwrap();
    assert_eq!(b.schema_parity(), SchemaParity::NotReady);
}

#[test]
fn the_legacy_route_is_recorded_and_never_satisfies_the_strict_profile() {
    let (d, doc) = synthetic(json!(["read", "write"]), 1);
    let legacy = verify(&d, &doc).unwrap();
    assert_eq!(legacy.reader_route(), ReaderRoute::Legacy);
    assert_eq!(legacy.profile(), None);
    assert!(!legacy.satisfies_profile(STRICT_PROFILE));
    // Same bytes, explicit legacy mode: identical binding.
    let explicit = verify_with(&d, &doc, ReaderMode::Legacy).unwrap();
    assert_eq!(legacy, explicit);
}

#[test]
fn a_legacy_binding_of_a_contract_with_no_tools_is_the_default_set_and_not_strict() {
    let body = json!({"role": "r"});
    let bytes = format!("{body}{}", json!({"snapshot_digest": "x", "revisions": []}));
    let digest = digest_of(bytes.as_bytes());
    let doc = ContractDocument {
        digest: digest.clone(),
        canonical_bytes: Some(bytes),
        ..Default::default()
    };
    let legacy = verify(&digest, &doc).unwrap();
    assert_eq!(legacy.allowlist_source(), AllowlistSource::DefaultNoShell);
    assert!(!legacy.satisfies_profile(STRICT_PROFILE));
    assert!(verify_with(
        &digest,
        &doc,
        ReaderMode::Strict {
            profile: STRICT_PROFILE
        }
    )
    .is_err());
}

#[test]
fn the_strict_reader_adds_no_default_tools_to_an_explicit_deny_all() {
    let (d, doc) = synthetic(json!([]), 0);
    let b = verify_with(
        &d,
        &doc,
        ReaderMode::Strict {
            profile: STRICT_PROFILE,
        },
    )
    .unwrap();
    assert!(b.allowlist().is_empty());
    assert!(!b.admits("read"));
    assert!(!b.admits("bash"));
}
