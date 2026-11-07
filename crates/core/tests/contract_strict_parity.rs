//! Parity of the ARAS strict reader with talomnia's producer-side reader
//! `ontology/src/kc2_tools_profile.py` at the pinned commit (KCLIVE-11).
//!
//! ONE shared corpus (`fixtures/kc2_tools_parity/corpus.json`, SYNTHETIC, produced by
//! `generate_corpus.py`) is run through the ARAS strict reader here and was run through the
//! talomnia reader by `run_producer.py` (recorded in `producer_at_pin.json`). Every case where
//! the accept/refuse result or the refusal code differs is either gone or named in
//! `KNOWN_DIFFERENCES` with its reason. The test fails on any difference not named there and on
//! any named difference that no longer exists, so a fix or a regression is always visible.
//!
//! The measured table is written to `<target>/tmp/kc2_tools_parity_table.json` (used by REPORT.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;

use arcana_core::contract::{digest_of, verify_with, ContractDocument, ReaderMode};
use base64::Engine as _;
use serde_json::{json, Value};

const CORPUS: &str = include_str!("fixtures/kc2_tools_parity/corpus.json");
const PRODUCER: &str = include_str!("fixtures/kc2_tools_parity/producer_at_pin.json");

/// Differences that remain by design or are open questions for the schema owner.
/// (case id, why)
const KNOWN_DIFFERENCES: &[(&str, &str)] = &[
    (
        "POS-hint-absent",
        "Q2, NAMED LEGACY-ROUTE DIFFERENCE (KC-Brain decision 2026-11-07), compatibility \
         containment - NOT a waiver of the KC2 source schema and NOT a parity PASS. Per route: \
         direct/legacy read = ARAS ACCEPTs from the digested inner marker and asserts no \
         new-source strict admission; opt-in /source route = REFUSED (Argana put returns the \
         reference reader's CONTRACT_PROFILE_REQUIRED, so a hint-less object is never served). \
         The pinned reader requires the top-level schema_version",
    ),
    (
        "R1-hint-kind-wrong",
        "code only (both refuse): ARAS CONTRACT_POLICY_UNBOUND for an envelope kind hint that \
         disagrees with the digested bytes; the pinned reader sees a schema const violation",
    ),
    (
        "O-bad-digest-and-invalid",
        "by design (shipped order): ARAS re-hashes first, so a wrong digest is \
         CONTRACT_DIGEST_MISMATCH before any profile check; the pinned reader checks it last",
    ),
    (
        "M11-bignum-in-open-bounds",
        "Q3, DECLARED CAPABILITY DIFFERENCE (KC-Brain decision 2026-11-07; see INTEGER_DOMAIN in \
         contract/strict.rs): on EVERY route (strict and legacy) this reader holds integers in \
         [i64::MIN, u64::MAX] and refuses any other with the typed CONTRACT_READER_UNSUPPORTED, \
         never rounding, normalising or accepting; the pinned reader accepts exact integers up to \
         4300 decimal digits and refuses longer ones with the same code",
    ),
];

fn build(case: &Value) -> ContractDocument {
    let pre = case["preimage"].as_str().unwrap();
    let digest = case
        .get("digest_override")
        .and_then(Value::as_str)
        .map_or_else(|| digest_of(pre.as_bytes()), str::to_owned);
    let mut wire = if case.get("route").and_then(Value::as_str) == Some("opaque-text") {
        json!({"digest": digest_of(pre.as_bytes()), "projection": pre})
    } else {
        let b64 = base64::engine::general_purpose::STANDARD.encode(pre.as_bytes());
        json!({"digest": digest, "canonical": {"bytes_b64": b64}})
    };
    if let Some(kind) = case["hint_kind"].as_str() {
        wire["kind"] = json!(kind);
    }
    if let Some(version) = case["hint_schema_version"].as_str() {
        wire["schema_version"] = json!(version);
    }
    if let Some(tools) = case.get("envelope_tools").and_then(Value::as_array) {
        wire["tools"] = json!({"allow": tools});
    }
    if case.get("envelope_projection_wrong").is_some() {
        wire["projection"] = json!({"body": {}, "closure_manifest": {}});
    }
    serde_json::from_value(wire).unwrap()
}

fn aras(case: &Value) -> (String, Option<String>, Vec<String>) {
    let doc = build(case);
    let requested = case["requested"].as_str().unwrap();
    match verify_with(&doc.digest, &doc, ReaderMode::Strict { profile: requested }) {
        Ok(binding) => (
            "ACCEPT".into(),
            None,
            binding.allowlist().iter().cloned().collect(),
        ),
        Err(refusal) => ("REFUSE".into(), Some(refusal.code().to_owned()), vec![]),
    }
}

#[test]
fn aras_strict_reader_agrees_with_the_pinned_talomnia_reader_except_where_named() {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let producer: Value = serde_json::from_str(PRODUCER).unwrap();
    let known: BTreeMap<&str, &str> = KNOWN_DIFFERENCES.iter().copied().collect();

    let mut table: BTreeMap<String, Value> = BTreeMap::new();
    let mut unexpected = Vec::new();
    let mut stale = Vec::new();
    let mut compared = 0_usize;
    for case in corpus["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if case.get("pin").is_some() {
            continue; // pin refusals are exercised in contract_strict_pin.rs
        }
        let (result, code, allow) = aras(case);
        let p = &producer[id];
        let p_result = p["result"].as_str().unwrap();
        if p_result == "N/A" {
            table.insert(
                id.to_owned(),
                json!({"aras": result, "aras_code": code, "producer": "N/A"}),
            );
            continue;
        }
        compared += 1;
        let p_code = p["code"].as_str().map(str::to_owned);
        let p_allow: Vec<String> = p["allow"].as_array().map_or_else(Vec::new, |a| {
            a.iter().map(|v| v.as_str().unwrap().to_owned()).collect()
        });
        let same = result == p_result && code == p_code && allow == p_allow;
        table.insert(
            id.to_owned(),
            json!({"aras": result, "aras_code": code, "aras_allow": allow,
                   "producer": p_result, "producer_code": p_code, "same": same}),
        );
        match (same, known.contains_key(id)) {
            (false, false) => unexpected.push(format!(
                "{id}: aras {result}/{code:?} vs producer {p_result}/{p_code:?}"
            )),
            (true, true) => stale.push(id.to_owned()),
            _ => {}
        }
    }
    // The measured table, for REPORT.md: <target>/tmp/kc2_tools_parity_table.json
    let dump =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("kc2_tools_parity_table.json");
    std::fs::write(dump, serde_json::to_string_pretty(&table).unwrap()).unwrap();
    assert!(
        compared >= 90,
        "the shared corpus must be compared, got {compared}"
    );
    assert!(
        unexpected.is_empty(),
        "{} unexplained difference(s):\n{}",
        unexpected.len(),
        unexpected.join("\n")
    );
    assert!(
        stale.is_empty(),
        "named differences that no longer exist: {stale:?}"
    );
}

/// Q2 per route, asserted rather than only described. The legacy/direct read of the hint-less
/// object is the named difference; the /source route's behaviour is the reference reader's own
/// refusal (Argana put runs the pinned reader), recorded in `producer_at_pin.json`, and measured
/// end to end against a running Argana by `harness/e2e_source.py` (REPORT.md, put 422
/// `CONTRACT_PROFILE_REQUIRED`, nothing served).
#[test]
fn q2_hint_less_object_is_a_named_legacy_route_difference_and_a_refusal_on_the_source_route() {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let producer: Value = serde_json::from_str(PRODUCER).unwrap();
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "POS-hint-absent")
        .expect("the Q2 case stays in the shared corpus");
    // the object really has no top-level schema_version hint
    assert!(case.get("hint_schema_version").is_none_or(Value::is_null));
    // /source route: the reference reader (what Argana put runs) refuses it, with its own code
    assert_eq!(producer["POS-hint-absent"]["result"], "REFUSE");
    assert_eq!(
        producer["POS-hint-absent"]["code"],
        "CONTRACT_PROFILE_REQUIRED"
    );
    // direct/legacy read: ARAS accepts from the digested inner marker - the named difference
    let (result, code, _) = aras(case);
    assert_eq!((result.as_str(), code), ("ACCEPT", None));
    // and it is named, with the per-route statement, so it can neither grow silently nor vanish
    let named = KNOWN_DIFFERENCES
        .iter()
        .find(|(id, _)| *id == "POS-hint-absent")
        .unwrap();
    assert!(named.1.contains("NOT a waiver") && named.1.contains("/source route"));
}
