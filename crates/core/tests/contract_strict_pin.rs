//! The talomnia schema pin of the strict reader (KCLIVE-11): what is pinned, that the vendored
//! bytes are exactly the pinned blobs, and that any difference refuses with
//! `CONTRACT_READER_UNSUPPORTED` before a contract byte is read. SYNTHETIC fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_core::contract::{
    digest_of, git_blob_id, schema_parity, schema_parity_of, verify, verify_pin, verify_with_pin,
    CanonicalBlock, ContractDocument, PinnedSchema, ReaderMode, SchemaParity, SchemaPin,
    STRICT_PROFILE, TALOMNIA_SCHEMA_PIN,
};
use base64::Engine as _;
use serde_json::json;

/// The commit and blobs published by the schema owner (draft PR546 head), written out
/// independently of the pin so a typo in either is caught.
const COMMIT: &str = "e98c507b697baffaabf4f53471420082a13e8488";
const BLOBS: [(&str, &str); 5] = [
    (
        "arcanada-kc2-tools-v1.schema.json",
        "518c85d955abcc0925f10927932e7be5d5565247",
    ),
    (
        "kc2-v2-body.schema.json",
        "20a28176f1c90f5cd0fa0d80f62695e183bfa126",
    ),
    (
        "kc2-v2-closure-manifest.schema.json",
        "90e9db5d0443d72e573237b679e912bc2c1dccab",
    ),
    (
        "kc2-v2-contract.schema.json",
        "5e5a2c97e7dbd4183a35ebffa2d0b84d767af4e8",
    ),
    // measured with the GitHub contents API at COMMIT; not in the brief's list
    (
        "common-defs.schema.json",
        "9aa66b7eff2c3e7439b00725ec32f7ee1e8d4523",
    ),
];

fn real() -> SchemaPin {
    TALOMNIA_SCHEMA_PIN.expect("pinned")
}

fn good_doc() -> (String, ContractDocument) {
    let body = json!({
        "task": {"goal": "g"}, "scope": {"project": "synthetic"}, "projection": [],
        "embedded": [], "reduction": "closure-only", "conflict_records": [], "refusals": [],
        "verdicts": {}, "envelope_unverified": [], "verdict": "T", "quarantined": [],
        "canonicalization": {"name": "json-c14n-pilot", "version": "v1"},
        "tools": {"profile": STRICT_PROFILE, "allow": ["read"]}
    });
    let manifest = json!({
        "snapshot_digest": format!("sha256:{:064x}", 0),
        "revisions": [["synthetic-pin@r1", format!("sha256:{:064x}", 1)]]
    });
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

fn strict_code(pin: Option<&SchemaPin>) -> Result<(), String> {
    let (d, doc) = good_doc();
    verify_with_pin(
        &d,
        &doc,
        ReaderMode::Strict {
            profile: STRICT_PROFILE,
        },
        pin,
    )
    .map(|_| ())
    .map_err(|e| e.code().to_owned())
}

#[test]
fn the_pin_names_the_published_commit_and_every_published_blob() {
    let pin = real();
    assert_eq!(pin.repo, "Arcanada-one/talomnia-knowledge");
    assert_eq!(pin.commit, COMMIT);
    assert!(!pin.merged);
    assert_eq!(
        pin.reference_reader_blob,
        "f310ab09601ee0367f562a7a049ca9f6d0825ff5"
    );
    assert_eq!(pin.schemas.len(), BLOBS.len());
    for (name, blob) in BLOBS {
        let found = pin.schemas.iter().find(|s| s.name == name).expect(name);
        assert_eq!(found.blob, blob, "{name}");
    }
}

#[test]
fn the_vendored_bytes_hash_to_exactly_the_pinned_blobs() {
    for schema in real().schemas {
        assert_eq!(git_blob_id(schema.bytes), schema.blob, "{}", schema.name);
    }
    assert_eq!(verify_pin(&real()), Ok(()));
    // `git hash-object` of the empty blob, so the helper is checked against git itself
    assert_eq!(git_blob_id(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    assert_eq!(
        git_blob_id(b"hello\n"),
        "ce013625030ba8dba906f756967f9e9ca394464a"
    );
}

#[test]
fn parity_reports_the_real_state_a_verified_pin_at_an_unmerged_commit() {
    assert_eq!(schema_parity(), SchemaParity::PinnedVerifiedUnmerged);
    assert_eq!(schema_parity_of(None), SchemaParity::NotReady);
    assert_eq!(schema_parity_of(None).as_str(), "NOT_READY");
    let mut merged = real();
    merged.merged = true;
    assert_eq!(
        schema_parity_of(Some(&merged)),
        SchemaParity::PinnedVerified
    );
}

#[test]
fn the_real_pin_admits_a_conforming_contract() {
    assert_eq!(strict_code(Some(&real())), Ok(()));
}

#[test]
fn a_deliberately_wrong_blob_is_reader_unsupported() {
    let pin = real();
    let wrong: Vec<PinnedSchema> = pin
        .schemas
        .iter()
        .map(|s| {
            let mut s = *s;
            if s.name == "kc2-v2-body.schema.json" {
                s.blob = "0000000000000000000000000000000000000000";
            }
            s
        })
        .collect();
    let bad = SchemaPin {
        schemas: Box::leak(wrong.into_boxed_slice()),
        ..pin
    };
    assert!(verify_pin(&bad)
        .unwrap_err()
        .contains("kc2-v2-body.schema.json"));
    assert_eq!(schema_parity_of(Some(&bad)), SchemaParity::PinMismatch);
    assert_eq!(schema_parity_of(Some(&bad)).as_str(), "PIN_MISMATCH");
    assert_eq!(
        strict_code(Some(&bad)),
        Err("CONTRACT_READER_UNSUPPORTED".to_owned())
    );
}

#[test]
fn a_changed_vendored_byte_under_the_pinned_blob_is_reader_unsupported() {
    let pin = real();
    let tampered: Vec<PinnedSchema> = pin
        .schemas
        .iter()
        .map(|s| {
            let mut s = *s;
            if s.name == "arcanada-kc2-tools-v1.schema.json" {
                let mut bytes = s.bytes.to_vec();
                bytes.push(b'\n');
                s.bytes = Box::leak(bytes.into_boxed_slice());
            }
            s
        })
        .collect();
    let bad = SchemaPin {
        schemas: Box::leak(tampered.into_boxed_slice()),
        ..pin
    };
    assert_eq!(
        strict_code(Some(&bad)),
        Err("CONTRACT_READER_UNSUPPORTED".to_owned())
    );
}

#[test]
fn a_pin_that_omits_a_file_the_profile_reaches_is_reader_unsupported() {
    let pin = real();
    let partial: Vec<PinnedSchema> = pin
        .schemas
        .iter()
        .filter(|s| s.name != "common-defs.schema.json")
        .copied()
        .collect();
    let bad = SchemaPin {
        schemas: Box::leak(partial.into_boxed_slice()),
        ..pin
    };
    assert_eq!(
        strict_code(Some(&bad)),
        Err("CONTRACT_READER_UNSUPPORTED".to_owned())
    );
}

#[test]
fn no_pin_at_all_is_reader_unsupported_never_a_looser_reader() {
    assert_eq!(
        strict_code(None),
        Err("CONTRACT_READER_UNSUPPORTED".to_owned())
    );
}

#[test]
fn a_pin_mismatch_is_raised_before_any_contract_byte_is_examined() {
    let pin = real();
    let mut wrong = pin.schemas.to_vec();
    wrong[0].blob = "1111111111111111111111111111111111111111";
    let bad = SchemaPin {
        schemas: Box::leak(wrong.into_boxed_slice()),
        ..pin
    };
    let doc = ContractDocument::default();
    let err = verify_with_pin(
        "not-a-digest",
        &doc,
        ReaderMode::Strict {
            profile: STRICT_PROFILE,
        },
        Some(&bad),
    )
    .unwrap_err();
    assert_eq!(err.code(), "CONTRACT_READER_UNSUPPORTED");
}

#[test]
fn the_legacy_route_does_not_depend_on_the_pin() {
    // Legacy BYTES: profile-marked bytes are refused on the legacy route (R2), so the pin-free
    // legacy route is shown on a pre-profile contract.
    let body = json!({"role": "r", "tools": {"allow": ["read"]}});
    let bytes = format!("{body}{}", json!({"snapshot_digest": "x", "revisions": []}));
    let d = digest_of(bytes.as_bytes());
    let doc = ContractDocument {
        digest: d.clone(),
        canonical_bytes: Some(bytes),
        ..Default::default()
    };
    let via_pin = verify_with_pin(&d, &doc, ReaderMode::Legacy, None).unwrap();
    assert_eq!(via_pin, verify(&d, &doc).unwrap());
}
