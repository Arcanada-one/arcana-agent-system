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

/// Producer-generated positives (R1): bytes emitted by the pinned talomnia opt-in producer
/// (`kc2_tools_profile_producer.emit_synthetic_profile_contract`, commit b3fe1199) from a SYNTHETIC
/// v2 source contract and re-read by that producer's own strict reader before it returned them.
/// Regenerate with `fixtures/kc2_tools_producer/emit.py`. They are not a grant and not evidence of
/// source eligibility.
const PRODUCER: &str = include_str!("fixtures/kc2_tools_producer/producer_positives.json");

fn producer_case(name: &str) -> serde_json::Value {
    let all: serde_json::Value = serde_json::from_str(PRODUCER).unwrap();
    all["cases"][name].clone()
}

/// The producer-generated body of `rw` with its `tools` member removed, then set to `tools`
/// (`None` omits the member). Every mutation in this file starts from producer bytes, so a
/// refusal means the one defect that was introduced, never "the fixture was never valid".
///
/// The producer body is pure ASCII with no string escapes, so `serde_json`'s sorted compact
/// rendering is its canonical form; `the_base_is_the_producers_own_bytes` proves it.
fn body_with(tools: Option<serde_json::Value>) -> serde_json::Value {
    let mut body: serde_json::Value =
        serde_json::from_str(producer_case("rw")["body_text"].as_str().unwrap()).unwrap();
    body.as_object_mut().unwrap().remove("tools");
    if let Some(tools) = tools {
        body["tools"] = tools;
    }
    body
}

fn tools(allow: serde_json::Value) -> serde_json::Value {
    json!({ "profile": PROFILE, "allow": allow })
}

/// Producer-generated closure manifest: `0` pins is the producer's own no-pin manifest, anything
/// else its two-pin manifest.
fn manifest(pins: usize) -> String {
    let name = if pins == 0 { "deny_all_no_pins" } else { "rw" };
    producer_case(name)["manifest_text"]
        .as_str()
        .unwrap()
        .to_owned()
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
fn the_base_is_the_producers_own_bytes() {
    let rw = producer_case("rw");
    assert_eq!(
        body_with(Some(tools(json!(["read", "write"])))).to_string(),
        rw["body_text"].as_str().unwrap()
    );
    let bytes = format!(
        "{}{}",
        rw["body_text"].as_str().unwrap(),
        rw["manifest_text"].as_str().unwrap()
    );
    assert_eq!(digest_of(bytes.as_bytes()), rw["digest"].as_str().unwrap());
}

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

// ---------- R1: producer-generated positives, and the first synthetic positives as negatives ----------

type Edit = Box<dyn FnOnce(&mut serde_json::Value)>;

fn doc_of_case(name: &str) -> (String, ContractDocument, Vec<String>) {
    let case = producer_case(name);
    let (d, doc) = doc_raw(
        case["body_text"].as_str().unwrap(),
        case["manifest_text"].as_str().unwrap(),
    );
    assert_eq!(
        d,
        case["digest"].as_str().unwrap(),
        "{name}: the producer's contract_digest is H(body || manifest) as this reader re-hashes it"
    );
    let allow = case["allow"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    (d, doc, allow)
}

fn detail_of(d: &str, doc: &ContractDocument) -> String {
    arcana_core::contract::verify_with(
        d,
        doc,
        arcana_core::contract::ReaderMode::Strict { profile: PROFILE },
    )
    .expect_err("must refuse")
    .to_string()
}

#[test]
fn r1_every_producer_generated_positive_in_the_supported_domain_is_accepted_with_its_own_allow() {
    for name in [
        "rw",
        "deny_all",
        "all_four",
        "deny_all_no_pins",
        "u64_max",
        "i64_min",
        "i64_max",
        "uni_bmp",
        "uni_non_bmp",
        "uni_controls",
    ] {
        let (d, doc, allow) = doc_of_case(name);
        assert_eq!(strict(&d, &doc).unwrap(), allow, "{name}");
    }
}

#[test]
fn r1_the_consumer_policy_source_rule_is_not_the_producers() {
    // Q1 is closed at e98c507b: the pinned reader applies the same rule (non-empty allow with no
    // pinned revision -> CONTRACT_POLICY_SOURCE_UNRESOLVED), so the producer refuses these bytes
    // and ARAS answers with the same code. (Before e98c507b this was a named parity difference.)
    assert_eq!(
        producer_case("rw_no_pins")["producer_refusal"]["code"],
        "CONTRACT_POLICY_SOURCE_UNRESOLVED"
    );
    let (d, doc, _) = doc_of_case("rw_no_pins");
    assert_eq!(
        strict(&d, &doc).unwrap_err(),
        "CONTRACT_POLICY_SOURCE_UNRESOLVED"
    );
}

#[test]
fn r1_the_first_synthetic_positives_are_now_one_defect_negatives_over_producer_bytes() {
    // The placeholder values PR273's first fixtures used as POSITIVES (the review's R1). Each one
    // alone, applied to producer-generated bytes that are accepted unmodified, is refused.
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read", "write"])))), 1);
    assert_eq!(
        strict(&d, &doc).unwrap(),
        vec!["read", "write"],
        "the unmodified base"
    );
    let defects: Vec<(&str, Edit)> = vec![
        (
            "task: \"synthetic-task\"",
            Box::new(|b| b["task"] = json!("synthetic-task")),
        ),
        ("scope: {}", Box::new(|b| b["scope"] = json!({}))),
        ("projection: {}", Box::new(|b| b["projection"] = json!({}))),
        ("reduction: {}", Box::new(|b| b["reduction"] = json!({}))),
        ("verdicts: []", Box::new(|b| b["verdicts"] = json!([]))),
        (
            "verdict: \"synthetic\"",
            Box::new(|b| b["verdict"] = json!("synthetic")),
        ),
        (
            "canonicalization: \"json-c14n-pilot/v1\"",
            Box::new(|b| b["canonicalization"] = json!("json-c14n-pilot/v1")),
        ),
    ];
    for (what, edit) in defects {
        assert_eq!(body_mut(edit), "CONTRACT_PROFILE_INVALID", "{what}");
    }
    let body = body_with(Some(tools(json!(["read"])))).to_string();
    for bad_manifest in [
        json!({"snapshot_digest": "synthetic", "revisions": []}),
        json!({"snapshot_digest": format!("sha256:{:064x}", 0), "revisions": [{"revision_id": "a@r1"}]}),
    ] {
        let (d, doc) = doc_raw(&body, &bad_manifest.to_string());
        assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
    }
    // and all of them together: the first hand-built positive in full
    let mut all = body_with(Some(tools(json!(["read"]))));
    all["task"] = json!("synthetic-task");
    all["scope"] = json!({});
    all["projection"] = json!({});
    all["reduction"] = json!({});
    all["verdicts"] = json!([]);
    all["verdict"] = json!("synthetic");
    all["canonicalization"] = json!("json-c14n-pilot/v1");
    let (d, doc) = doc_raw(
        &all.to_string(),
        &json!({"snapshot_digest": "synthetic", "revisions": [{"a": 1}]}).to_string(),
    );
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
}

// ---------- re-pin to b3fe1199: scope values, manifest revision pairs, whole-string matches ----------

#[test]
fn p1_scope_values_are_validated_not_just_the_axis_key() {
    let ok = |scope: serde_json::Value| {
        let mut b = body_with(Some(tools(json!(["read", "write"]))));
        b["scope"] = scope;
        let (d, doc) = doc_of(&b, 1);
        strict(&d, &doc)
    };
    // the accepted native syntax: ecosystem is true, env is prod/test/dev, others non-empty strings
    for good in [
        json!({"ecosystem": true}),
        json!({"env": "prod"}),
        json!({"env": "test"}),
        json!({"env": "dev"}),
        json!({"space": "s"}),
        json!({"repo": "r"}),
        json!({"actor": "a"}),
    ] {
        assert_eq!(ok(good.clone()).unwrap(), vec!["read", "write"], "{good}");
    }
    // one defect each, over the producer's own bytes
    for bad in [
        json!({"ecosystem": false}),
        json!({"ecosystem": "true"}),
        json!({"ecosystem": 1}),
        json!({"ecosystem": null}),
        json!({"env": "staging"}),
        json!({"env": "PROD"}),
        json!({"env": true}),
        json!({"space": ""}),
        json!({"project": 5}),
        json!({"repo": null}),
        json!({"host": ["h"]}),
        json!({"namespace": {"a": 1}}),
        json!({"task": false}),
        json!({"epic": 0}),
        json!({"actor": ""}),
    ] {
        assert_eq!(
            ok(bad.clone()).unwrap_err(),
            "CONTRACT_PROFILE_INVALID",
            "{bad}"
        );
    }
}

#[test]
fn p2_manifest_revision_entries_must_be_a_revision_id_and_a_digest() {
    let body = body_with(Some(tools(json!(["read"])))).to_string();
    let d0 = format!("sha256:{:064x}", 1);
    let snap = format!("sha256:{:064x}", 0);
    let run = |revisions: serde_json::Value| {
        let m = json!({"snapshot_digest": snap, "revisions": revisions}).to_string();
        let (d, doc) = doc_raw(&body, &m);
        strict(&d, &doc)
    };
    assert_eq!(
        run(json!([["a@r1", d0]])).unwrap(),
        vec!["read"],
        "the well-formed pair"
    );
    for bad in [
        json!([["a@r1", "sha256:xyz"]]),
        json!([["a@r1", "x"]]),
        json!([["a@r1", d0.to_uppercase()]]),
        json!([[d0, "a@r1"]]),
        json!([["", d0]]),
        json!([["a@r1", 1]]),
        json!([[1, d0]]),
        json!([["a@r1"]]),
        json!([["a@r1", d0, "extra"]]),
        json!([{"revision_id": "a@r1"}]),
    ] {
        assert_eq!(
            run(bad.clone()).unwrap_err(),
            "CONTRACT_PROFILE_INVALID",
            "{bad}"
        );
    }
}

#[test]
fn p3_a_trailing_newline_never_satisfies_a_pattern_or_a_marker() {
    // digest-shaped and revision-id-shaped strings with a trailing newline
    let body = body_with(Some(tools(json!(["read"])))).to_string();
    let snap = format!("sha256:{:064x}", 0);
    let d1 = format!("sha256:{:064x}", 1);
    for m in [
        json!({"snapshot_digest": format!("{snap}\n"), "revisions": [["a@r1", d1]]}),
        json!({"snapshot_digest": snap, "revisions": [["a@r1", format!("{d1}\n")]]}),
        json!({"snapshot_digest": snap, "revisions": [["a@r1\n", d1]]}),
    ] {
        let (d, doc) = doc_raw(&body, &m.to_string());
        assert_eq!(
            strict(&d, &doc).unwrap_err(),
            "CONTRACT_PROFILE_INVALID",
            "{m}"
        );
    }
    // the inner marker and the envelope hint: a newline-suffixed family member is not a family
    // member; the reference reader now answers CONTRACT_PROFILE_INVALID for it too.
    let (d, doc) = doc_of(
        &body_with(Some(
            json!({"profile": format!("{PROFILE}\n"), "allow": ["read"]}),
        )),
        1,
    );
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    let hinted = with_hints(&doc, None, Some("arcanada-kc2-tools/v2\n"));
    assert_eq!(strict(&d, &hinted).unwrap_err(), "CONTRACT_PROFILE_INVALID");
}

// ---------- C1: the canonical value domain (integers, non-BMP text, escaped surrogates) ----------

#[test]
fn c1_integers_up_to_the_64_bit_boundaries_are_supported() {
    for name in ["u64_max", "i64_min", "i64_max"] {
        let (d, doc, allow) = doc_of_case(name);
        assert_eq!(strict(&d, &doc).unwrap(), allow, "{name}");
    }
}

#[test]
fn c1_an_integer_beyond_the_64_bit_domain_is_a_named_restriction_not_a_float() {
    // 18446744073709551616 (2^64) in an open task value: producer-valid, accepted by the pinned
    // reader. Declared capability limit: refused, fail-closed with the typed
    // CONTRACT_READER_UNSUPPORTED (a reader capability, not a defect of the bytes), and the
    // refusal says why. Never rounded, truncated or read as a float.
    for name in ["u64_max_plus_1", "i64_min_minus_1", "pow2_200"] {
        let (d, doc, _) = doc_of_case(name);
        assert_eq!(
            strict(&d, &doc).unwrap_err(),
            "CONTRACT_READER_UNSUPPORTED",
            "{name}"
        );
        let detail = detail_of(&d, &doc);
        assert!(
            detail.contains("declared capability limit C1") && !detail.contains("forbids floats"),
            "{name}: {detail}"
        );
    }
}

#[test]
fn c1_non_bmp_text_is_supported_as_escaped_surrogate_pairs() {
    let (d, doc, allow) = doc_of_case("uni_non_bmp");
    let text = producer_case("uni_non_bmp")["body_text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(text.contains("\\ud83d\\ude00"), "{text}");
    assert_eq!(strict(&d, &doc).unwrap(), allow);
}

#[test]
fn c1_a_lone_escaped_surrogate_is_refused_and_the_pinned_producer_now_refuses_it_too() {
    let (d, doc, _) = doc_of_case("uni_lone_surrogate");
    assert!(producer_case("uni_lone_surrogate")["body_text"]
        .as_str()
        .unwrap()
        .contains("\\ud800"));
    // the pinned producer (e98c507b) refuses the same input with the same typed code
    assert_eq!(
        producer_case("uni_lone_surrogate")["producer_refusal"]["code"],
        "CONTRACT_CANONICAL_INVALID"
    );
    assert_eq!(
        strict(&d, &doc).unwrap_err(),
        "CONTRACT_CANONICAL_INVALID",
        "{}",
        detail_of(&d, &doc)
    );
}

#[test]
fn c1_a_literal_non_bmp_char_in_the_digested_bytes_is_not_canonical() {
    // The canonical form escapes every non-ASCII char; a raw one under a matching hash is refused.
    let (_, _, _) = doc_of_case("uni_non_bmp");
    let body = producer_case("uni_non_bmp")["body_text"]
        .as_str()
        .unwrap()
        .replace("\\ud83d\\ude00", "\u{1F600}");
    let (d, doc) = doc_raw(
        &body,
        producer_case("uni_non_bmp")["manifest_text"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
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
    value["task"] = json!({"goal": "caf\u{e9}"});
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
    value["scope"] = json!({"project": 1.5});
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
fn r1_envelope_schema_version_that_is_an_unknown_marker_is_profile_invalid() {
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    let doc = with_hints(&doc, Some("KnowledgeContract"), Some("something-else"));
    // KC-SWE interpretation point (pinned reader `kc2_tools_profile.py`): any other unknown
    // profile marker is CONTRACT_PROFILE_INVALID. This assertion said CONTRACT_POLICY_UNBOUND
    // before the pin; see the K1-K4 tests below and REPORT.md.
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
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

// ---------- KCLIVE-11 pin: parity with the pinned talomnia reader (kc2_tools_profile.py) ----------
//
// KC-SWE interpretation points, then the value shapes the pinned JSON schemas fix. Every
// expected code below was also produced by the pinned reader itself (see
// `contract_strict_parity.rs`, which runs one shared corpus through both).

fn hinted(schema_version: &str) -> (String, ContractDocument) {
    let (d, doc) = doc_of(&body_with(Some(tools(json!(["read"])))), 1);
    let doc = with_hints(&doc, None, Some(schema_version));
    (d, doc)
}

#[test]
fn k1_a_legacy_talomnia_ontology_marker_requires_the_profile() {
    for legacy in ["talomnia-ontology/v1", "talomnia-ontology/v2"] {
        let (d, doc) = hinted(legacy);
        assert_eq!(
            strict(&d, &doc).unwrap_err(),
            "CONTRACT_PROFILE_REQUIRED",
            "{legacy}"
        );
    }
}

#[test]
fn k3_another_version_of_the_tools_profile_family_is_reader_unsupported() {
    for other in [
        "arcanada-kc2-tools/v0",
        "arcanada-kc2-tools/v2",
        "arcanada-kc2-tools/v10",
    ] {
        let (d, doc) = hinted(other);
        assert_eq!(
            strict(&d, &doc).unwrap_err(),
            "CONTRACT_READER_UNSUPPORTED",
            "{other}"
        );
    }
}

#[test]
fn k4_any_other_unknown_marker_is_profile_invalid() {
    for other in [
        "other/v9",
        "ARCANADA-KC2-TOOLS/V1",
        "arcanada-kc2-tools/v1x",
        "arcanada-kc2-tools/v",
        "",
    ] {
        let (d, doc) = hinted(other);
        assert_eq!(
            strict(&d, &doc).unwrap_err(),
            "CONTRACT_PROFILE_INVALID",
            "{other:?}"
        );
    }
}

#[test]
fn k6_an_inner_marker_naming_another_version_is_profile_invalid() {
    assert_eq!(
        code_for_tools(json!({"profile": "arcanada-kc2-tools/v2", "allow": ["read"]})),
        "CONTRACT_PROFILE_INVALID"
    );
}

fn body_mut(edit: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut value = body_with(Some(tools(json!(["read"]))));
    edit(&mut value);
    let (d, doc) = doc_of(&value, 1);
    strict(&d, &doc).expect_err("must refuse")
}

#[test]
fn v_the_pinned_schema_fixes_the_value_shapes_inside_the_twelve_members() {
    let cases: Vec<(&str, Edit)> = vec![
        ("scope with no axis", Box::new(|b| b["scope"] = json!({}))),
        (
            "scope with two axes",
            Box::new(|b| b["scope"] = json!({"project": "a", "space": "b"})),
        ),
        (
            "scope with an unknown axis",
            Box::new(|b| b["scope"] = json!({"galaxy": "a"})),
        ),
        (
            "embedded not empty",
            Box::new(|b| b["embedded"] = json!(["x"])),
        ),
        (
            "refusals not empty",
            Box::new(|b| b["refusals"] = json!(["x"])),
        ),
        (
            "reduction outside the pattern",
            Box::new(|b| b["reduction"] = json!("whatever")),
        ),
        (
            "verdict outside T/K",
            Box::new(|b| b["verdict"] = json!("F")),
        ),
        (
            "verdicts as an array",
            Box::new(|b| b["verdicts"] = json!([])),
        ),
        (
            "a verdicts value outside TFUK",
            Box::new(|b| b["verdicts"] = json!({"a": "X"})),
        ),
        (
            "canonicalization as a string",
            Box::new(|b| b["canonicalization"] = json!("json-c14n-pilot/v1")),
        ),
        (
            "task with an unknown field",
            Box::new(|b| b["task"] = json!({"goal": "g", "zzz": 1})),
        ),
        ("task as a string", Box::new(|b| b["task"] = json!("goal"))),
        (
            "projection as an object",
            Box::new(|b| b["projection"] = json!({})),
        ),
        (
            "projection with a malformed revision id",
            Box::new(|b| {
                b["projection"] = json!([{"assertions": [], "source": {
                    "content_digest": format!("sha256:{:064x}", 1), "revision_id": "BAD"}}]);
            }),
        ),
        (
            "a malformed conflict record",
            Box::new(|b| b["conflict_records"] = json!([{"kind": "ConflictRecord"}])),
        ),
        (
            "an envelope_unverified item missing its provider",
            Box::new(|b| b["envelope_unverified"] = json!([{"condition": "c"}])),
        ),
        (
            "a quarantined item missing its key",
            Box::new(|b| b["quarantined"] = json!([{"addr": "a"}])),
        ),
    ];
    for (what, edit) in cases {
        assert_eq!(body_mut(edit), "CONTRACT_PROFILE_INVALID", "{what}");
    }
}

#[test]
fn v_manifest_value_shapes_are_the_pinned_schemas() {
    let body = body_with(Some(tools(json!(["read"])))).to_string();
    let digest0 = format!("sha256:{:064x}", 0);
    let bad = [
        json!({"snapshot_digest": "synthetic", "revisions": []}),
        json!({"snapshot_digest": "sha256:".to_owned() + &"A".repeat(64), "revisions": []}),
        json!({"snapshot_digest": digest0, "revisions": [["a@r1", "sha256:x", "extra"]]}),
        json!({"snapshot_digest": digest0, "revisions": [{"a": 1}]}),
    ];
    for m in bad {
        let (d, doc) = doc_raw(&body, &m.to_string());
        assert_eq!(
            strict(&d, &doc).unwrap_err(),
            "CONTRACT_PROFILE_INVALID",
            "{m}"
        );
    }
}

#[test]
fn v_values_the_schema_leaves_open_are_accepted() {
    let mut value = body_with(Some(tools(json!(["read"]))));
    value["task"] = json!({
        "goal": "g",
        "inputs": [1, {"a": [null]}, "x"],
        "outputs": [true],
        "required_capability_types": ["t"],
        "bounds": {"n": 1, "s": {"k": [1]}}
    });
    // scope VALUES are no longer open since the b3fe1199 pin (see p1_*): a native-syntax value here
    value["scope"] = json!({"project": "p"});
    value["verdicts"] = json!({"any key at all": "U", "b": "F"});
    let (d, doc) = doc_of(&value, 1);
    assert_eq!(strict(&d, &doc).unwrap(), vec!["read"]);
}

#[test]
fn v_a_body_or_manifest_that_is_not_an_object_is_profile_invalid() {
    let m = manifest(1);
    let (d, doc) = doc_raw("[]", &m);
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
    let body = body_with(Some(tools(json!(["read"])))).to_string();
    let (d, doc) = doc_raw(&body, "[]");
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
}

#[test]
fn o_required_members_are_judged_before_the_schema() {
    let mut value = body_with(Some(json!({"profile": PROFILE})));
    value.as_object_mut().unwrap().remove("verdicts");
    let (d, doc) = doc_of(&value, 1);
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_REQUIRED");
}

#[test]
fn o_a_float_is_refused_at_parse_time_before_the_schema() {
    let mut value = body_with(Some(tools(json!(["read"]))));
    value["verdict"] = json!("F");
    value["task"] = json!({"goal": "g", "bounds": {"n": 1.5}});
    let (d, doc) = doc_of(&value, 1);
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
}

#[test]
fn o_the_schema_is_judged_before_the_canonical_round_trip() {
    let mut value = body_with(Some(tools(json!(["read"]))));
    value["verdict"] = json!("F");
    let pretty = serde_json::to_string_pretty(&value).unwrap();
    let (d, doc) = doc_raw(&pretty, &manifest(1));
    assert_eq!(strict(&d, &doc).unwrap_err(), "CONTRACT_PROFILE_INVALID");
}
