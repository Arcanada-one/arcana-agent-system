//! Cross-runtime canonical fixtures (talomnia-knowledge PR546 `e98c507b`,
//! `kc2/tests/fixtures/tools-profile-canonical/`) run through the ARAS strict reader (KCLIVE-11).
//!
//! Each fixture is the exact byte file a consumer persists: a whole canonical contract document.
//! ARAS receives the two digested halves (`canonical(body)` then `canonical(closure_manifest)`)
//! and the digest, so the test splits the whole document with a byte scanner of its own (never
//! through `serde_json`, which would refuse the unpaired-surrogate negatives before the reader
//! under test saw them).
//!
//! The expected outcome per fixture is the index's literal outcome, except where this reader's
//! DECLARED capability differs (`INTEGER_DOMAIN`: `[i64::MIN, u64::MAX]`). There the expectation
//! is derived from the integer literal itself, independently of the reader, and is always the
//! typed `CONTRACT_READER_UNSUPPORTED` - never an accept (rounding/truncation) and never a
//! fallback. A fixture whose defect sits OUTSIDE the digested halves (a top-level key or the
//! `kind` value) has no input channel into this reader; it is listed in `OUTSIDE_THE_HALVES`
//! with the reason and the layer that does refuse it.
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

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/kc2_tools_canonical"
);
const PROFILE: &str = "arcanada-kc2-tools/v1";

/// Fixtures whose defect is outside the digested halves: this reader never receives it.
const OUTSIDE_THE_HALVES: &[(&str, &str)] = &[
    (
        "neg-surrogate-high-value-top",
        "top-level `kind` value is outside the digested halves; refused at the producer/Argana put (whole document)",
    ),
    (
        "neg-surrogate-high-key-top",
        "top-level key is outside the digested halves; refused at the producer/Argana put (whole document)",
    ),
    (
        "neg-surrogate-low-value-top",
        "top-level `kind` value is outside the digested halves; refused at the producer/Argana put (whole document)",
    ),
    (
        "neg-surrogate-low-key-top",
        "top-level key is outside the digested halves; refused at the producer/Argana put (whole document)",
    ),
];

/// Byte spans of the top-level members of the object `raw`: (key text, value text).
fn top_level_members(raw: &str) -> Vec<(String, String)> {
    let b = raw.as_bytes();
    assert_eq!(b[0], b'{');
    let mut i = 1;
    let mut out = Vec::new();
    let skip_string = |mut i: usize| -> usize {
        assert_eq!(b[i], b'"');
        i += 1;
        while b[i] != b'"' {
            i += if b[i] == b'\\' { 2 } else { 1 };
        }
        i + 1
    };
    while b[i] != b'}' {
        let k0 = i;
        i = skip_string(i);
        let key = raw[k0..i].to_owned();
        assert_eq!(b[i], b':');
        i += 1;
        let v0 = i;
        let mut depth = 0_i32;
        loop {
            match b[i] {
                b'"' => {
                    i = skip_string(i);
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                b',' if depth == 0 => break,
                _ => {}
            }
            i += 1;
        }
        out.push((key, raw[v0..i].to_owned()));
        if b[i] == b',' {
            i += 1;
        }
    }
    out
}

struct Fixture {
    halves: String,
    digest: String,
    hint: Option<String>,
}

fn load(file: &str) -> Fixture {
    let raw = std::fs::read_to_string(format!("{DIR}/{file}")).unwrap();
    let members: BTreeMap<String, String> = top_level_members(&raw).into_iter().collect();
    let body = &members["\"body\""];
    let manifest = &members["\"closure_manifest\""];
    Fixture {
        halves: format!("{body}{manifest}"),
        digest: members["\"contract_digest\""].trim_matches('"').to_owned(),
        hint: members
            .get("\"schema_version\"")
            .map(|v| v.trim_matches('"').to_owned()),
    }
}

fn read(f: &Fixture) -> Result<Vec<String>, String> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(f.halves.as_bytes());
    let mut wire = json!({"digest": f.digest, "canonical": {"bytes_b64": b64}});
    if let Some(h) = &f.hint {
        wire["schema_version"] = json!(h);
    }
    let doc: ContractDocument = serde_json::from_value(wire).unwrap();
    verify_with(&doc.digest, &doc, ReaderMode::Strict { profile: PROFILE })
        .map(|binding| binding.allowlist().iter().cloned().collect())
        .map_err(|r| r.code().to_owned())
}

/// The integer literal of the open member `body.task.bounds.n`, if the fixture has one.
fn bounds_n_literal(halves: &str) -> Option<String> {
    let at = halves.find("\"n\":")? + 4;
    let lit: String = halves[at..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    Some(lit)
}

/// What this reader's DECLARED capability makes of an integer literal, independently of the reader.
fn declared_for_integer(literal: &str) -> &'static str {
    if literal.parse::<i64>().is_ok() || literal.parse::<u64>().is_ok() {
        "ACCEPT"
    } else {
        "CONTRACT_READER_UNSUPPORTED"
    }
}

#[test]
fn the_index_binds_every_vendored_file_by_sha256_and_the_fixture_digest_recomputes() {
    let index: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/index.json")).unwrap())
            .unwrap();
    assert_eq!(index.len(), 29);
    for e in &index {
        let file = e["file"].as_str().unwrap();
        let bytes = std::fs::read(format!("{DIR}/{file}")).unwrap();
        assert_eq!(
            digest_of(&bytes),
            format!("sha256:{}", e["sha256"].as_str().unwrap()),
            "{file}"
        );
        let f = load(file);
        assert_eq!(
            digest_of(f.halves.as_bytes()),
            f.digest,
            "{file}: contract_digest is H(canonical(body) || canonical(closure_manifest))"
        );
    }
}

#[test]
fn every_fixture_gets_the_index_outcome_or_a_named_typed_capability_refusal() {
    let index: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/index.json")).unwrap())
            .unwrap();
    let outside: BTreeMap<&str, &str> = OUTSIDE_THE_HALVES.iter().copied().collect();
    let mut table = BTreeMap::new();
    let mut declared_differences = Vec::new();
    for e in &index {
        let name = e["name"].as_str().unwrap();
        let want = e["expect"].as_str().unwrap();
        let f = load(e["file"].as_str().unwrap());
        if outside.contains_key(name) {
            // The halves are clean; the defect is not reachable here. The reader must still agree
            // with the control on the halves it does receive.
            assert!(read(&f).is_ok(), "{name}: the halves alone are the control");
            table.insert(
                name.to_owned(),
                json!({"aras": "N/A", "why": outside[name]}),
            );
            continue;
        }
        let got = read(&f);
        let got_text = match &got {
            Ok(_) => "ACCEPT".to_owned(),
            Err(code) => code.clone(),
        };
        let expected = if name.starts_with("pos-int-") || name.starts_with("cap-int-") {
            let lit = bounds_n_literal(&f.halves).expect("integer fixture");
            let mine = declared_for_integer(&lit);
            if mine != want {
                declared_differences.push(name.to_owned());
            }
            if want == "ACCEPT" {
                mine
            } else {
                want
            }
        } else {
            want
        };
        assert_eq!(got_text, expected, "{name}: index says {want}");
        table.insert(
            name.to_owned(),
            json!({"index": want, "aras": got_text, "same_as_index": got_text == want}),
        );
    }
    let dump =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("kc2_canonical_fixture_table.json");
    std::fs::write(dump, serde_json::to_string_pretty(&table).unwrap()).unwrap();
    // The declared capability differences are exactly the integers outside [i64::MIN, u64::MAX]
    // that the Python reader holds exactly (2^64, -2^64, -2^63-1, 2^200, -2^200, and the 4299-digit ones).
    declared_differences.sort();
    assert_eq!(
        declared_differences,
        [
            "pos-int-1e4299",
            "pos-int-2p200",
            "pos-int-2p64",
            "pos-int-m1e4299",
            "pos-int-m2p200",
            "pos-int-m2p63m1",
            "pos-int-m2p64"
        ]
    );
}

#[test]
fn an_integer_outside_the_domain_is_never_rounded_truncated_or_read_as_a_float() {
    for name in [
        "pos-int-2p64",
        "pos-int-2p200",
        "pos-int-1e4299",
        "cap-int-1e4300",
    ] {
        let f = load(&format!("{name}.json"));
        assert_eq!(
            read(&f).unwrap_err(),
            "CONTRACT_READER_UNSUPPORTED",
            "{name}"
        );
    }
    // the domain edges are accepted exactly
    for name in [
        "pos-int-2p63m1",
        "pos-int-2p63",
        "pos-int-m2p63",
        "pos-int-2p64m1",
    ] {
        assert!(read(&load(&format!("{name}.json"))).is_ok(), "{name}");
    }
}

#[test]
fn a_lone_surrogate_wins_over_a_capability_limit_in_the_same_half() {
    // 2^200 would be UNSUPPORTED, the lone surrogate is a defect of the bytes: the defect is named.
    let f = load("neg-surrogate-high-value-nested.json");
    let halves = f.halves.replacen(
        "\"goal\":",
        "\"n\":1606938044258990275541962092341162602522202993782792835301376,\"goal\":",
        1,
    );
    assert_ne!(halves, f.halves);
    let g = Fixture {
        digest: digest_of(halves.as_bytes()),
        halves,
        hint: f.hint,
    };
    assert_eq!(read(&g).unwrap_err(), "CONTRACT_CANONICAL_INVALID");
}
