//! Rust leg of the canonical-source route check (KCLIVE-11): the object a running Argana
//! (`e758e922`, PR64) serves from `GET /v1/contract/{digest}/source?schema_version=arcanada-kc2-tools/v1`
//! is read by the ARAS strict reader. `#[ignore]`d: it needs the running Argana and the harness
//! manifest (the harness imports private repositories and is kept with the task evidence).
//!
//! `KC2_E2E_DIR=<out> KC2_E2E_ARGANA_URL=http://127.0.0.1:<port> cargo test -p arcana-agent --test kc2_source_route_e2e -- --ignored`
//!
//! `<out>/source_manifest.json`: `{"cases":[{"id","digest","probe":bool}]}`. Writes
//! `<out>/source_rust_results.json`: per id the HTTP status, the Argana code when refused, and the
//! strict-reader verdict on the served object. For `probe` cases it also runs three tamper
//! controls on the served object: (a) one field changed and re-hashed, read against the digest that
//! was asked for; (b) a profile-invalid field changed and re-hashed, read against its new digest;
//! (c) a harmless field changed and re-hashed, read against its new digest.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

use arcana_core::contract::{digest_of, verify_with, ContractDocument, ReaderMode};
use base64::Engine as _;
use serde_json::{json, Value};

const PROFILE: &str = "arcanada-kc2-tools/v1";

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

/// A plain HTTP/1.0 GET over a socket: (status, body).
fn http_get(base: &str, path: &str) -> (u16, Vec<u8>) {
    let host = base.trim_start_matches("http://");
    let mut s = TcpStream::connect(host).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, raw[split + 4..].to_vec())
}

/// Strict read of whole canonical document bytes `whole`, asked for `requested_digest`, with the
/// envelope hint `hint`.
fn read_whole(whole: &str, requested_digest: &str, hint: &str) -> Result<Vec<String>, String> {
    let members: BTreeMap<String, String> = top_level_members(whole).into_iter().collect();
    let halves = format!("{}{}", members["\"body\""], members["\"closure_manifest\""]);
    let b64 = base64::engine::general_purpose::STANDARD.encode(halves.as_bytes());
    let wire = json!({"digest": requested_digest, "canonical": {"bytes_b64": b64}, "schema_version": hint});
    let doc: ContractDocument = serde_json::from_value(wire).unwrap();
    verify_with(
        requested_digest,
        &doc,
        ReaderMode::Strict { profile: PROFILE },
    )
    .map(|b| b.allowlist().iter().cloned().collect())
    .map_err(|r| r.code().to_owned())
}

fn verdict(r: &Result<Vec<String>, String>) -> Value {
    match r {
        Ok(allow) => json!({"aras": "ACCEPT", "allow": allow}),
        Err(code) => json!({"aras": "REFUSE", "code": code}),
    }
}

/// The whole document with its digested halves edited by `edit` and `contract_digest` re-hashed.
fn rehashed(whole: &str, edit: impl Fn(&str) -> String) -> (String, String) {
    let members: BTreeMap<String, String> = top_level_members(whole).into_iter().collect();
    let body = edit(&members["\"body\""]);
    let manifest = members["\"closure_manifest\""].clone();
    let digest = digest_of(format!("{body}{manifest}").as_bytes());
    let doc = format!(
        "{{\"body\":{body},\"closure_manifest\":{manifest},\"contract_digest\":\"{digest}\",\"kind\":{},\"schema_version\":{}}}",
        members["\"kind\""], members["\"schema_version\""]
    );
    (doc, digest)
}

#[test]
#[ignore = "needs a running Argana at e758e922 and the harness manifest; see the module docs"]
fn the_served_canonical_source_object_is_read_by_the_strict_reader() {
    let dir = PathBuf::from(std::env::var("KC2_E2E_DIR").expect("KC2_E2E_DIR"));
    let base = std::env::var("KC2_E2E_ARGANA_URL").expect("KC2_E2E_ARGANA_URL");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(dir.join("source_manifest.json")).unwrap()).unwrap();
    let mut results = BTreeMap::new();
    for case in manifest["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let digest = case["digest"].as_str().unwrap();
        let (status, body) = http_get(
            &base,
            &format!("/v1/contract/{digest}/source?schema_version={PROFILE}"),
        );
        let mut row = json!({"http_status": status});
        if status != 200 {
            let b: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            row["argana_code"] = b["code"].clone();
            results.insert(id.to_owned(), row);
            continue;
        }
        let obj: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(obj["wire"], "argana-contract-source/v1", "{id}");
        let whole_bytes = base64::engine::general_purpose::STANDARD
            .decode(obj["contract_b64"].as_str().unwrap())
            .unwrap();
        let whole = String::from_utf8(whole_bytes).unwrap();
        // the JSON `contract` member is the same object as the bytes (after this reader's parse)
        let parsed: Value = serde_json::from_str(&whole).unwrap();
        assert_eq!(
            parsed, obj["contract"],
            "{id}: contract == parse(contract_b64)"
        );
        let hint = obj["schema_version"].as_str().unwrap();
        row["served_length"] = obj["length"].clone();
        row["read"] = verdict(&read_whole(&whole, digest, hint));
        if case["probe"].as_bool() == Some(true) {
            // (a) one field changed and re-hashed, read against the digest that was asked for
            let (changed, _) = rehashed(&whole, |b| b.replacen("\"goal\":\"", "\"goal\":\"X", 1));
            assert_ne!(changed, whole);
            row["tamper_a_changed_rehashed_vs_requested_digest"] =
                verdict(&read_whole(&changed, digest, hint));
            // (b) a profile-invalid change, re-hashed, read against its own new digest
            let (bad, bad_digest) = rehashed(&whole, |b| {
                b.replacen(
                    "\"allow\":[\"read\",\"write\"]",
                    "\"allow\":[\"read\",\"shell\"]",
                    1,
                )
            });
            assert_ne!(bad, whole);
            row["tamper_b_profile_invalid_rehashed"] =
                verdict(&read_whole(&bad, &bad_digest, hint));
            // (c) a harmless change, re-hashed, read against its own digest: a different contract
            let (other, other_digest) =
                rehashed(&whole, |b| b.replacen("\"goal\":\"", "\"goal\":\"X", 1));
            row["tamper_c_changed_rehashed_vs_its_own_digest"] =
                verdict(&read_whole(&other, &other_digest, hint));
        }
        results.insert(id.to_owned(), row);
    }
    std::fs::write(
        dir.join("source_rust_results.json"),
        serde_json::to_string_pretty(&results).unwrap(),
    )
    .unwrap();
}
