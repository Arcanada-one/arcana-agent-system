//! Rust leg of the producer -> persisted bytes -> contract source HTTP -> strict reader corpus
//! (KCLIVE-11). It needs a running contract source (Argana) and the `manifest.json` that the
//! external harness wrote, so it is `#[ignore]`d. The harness imports private repositories (the
//! producer and Argana at pinned commits) and is therefore kept with the task evidence, not in
//! this public repository. The manifest is one JSON object: `cases[]` with `id`, `digest`,
//! `rust_mode`, `producer{result,code,allow}`, `argana_put{result}`, `argana_get{status,
//! bytes_b64_sha256}`, `hints`, `rust_preimage_b64` and `allow`.
//!
//! `KC2_E2E_DIR=<out> KC2_E2E_ARGANA_URL=http://127.0.0.1:<port> cargo test -p arcana-agent --test kc2_tools_e2e -- --ignored`
//!
//! Positives (Argana stored the producer bytes) are fetched with the REAL `ArganaContractClient`
//! over a socket. Negatives are refused by Argana at put (nothing is stored, so there is nothing to
//! GET); their Rust leg runs the strict reader on a synthetic envelope built from the same
//! one-defect bytes, in the shape Argana answers with, and is compared with the producer's code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use arcana_connectors::contract_source::{ArganaContractClient, ContractSource};
use arcana_core::contract::{
    digest_of, verify, verify_with_pin, CanonicalBlock, ContractDocument, ReaderMode, ReaderRoute,
    SchemaPin, STRICT_PROFILE, TALOMNIA_SCHEMA_PIN,
};
use base64::Engine as _;
use serde_json::{json, Value};
use url::Url;

/// Cases where the strict reader and the pinned producer-side reader differ on purpose.
/// (case id, why). A difference not named here fails the test; a named one that vanished too.
const KNOWN_DIFFERENCES: &[(&str, &str)] = &[
    (
        "POS-int-u64-max-plus-1",
        "C1 restricted integer domain [i64::MIN, u64::MAX] (decision in contract/strict.rs): \
         Python integers are unbounded and the producer, Argana and the pinned reader accept; the \
         strict reader refuses, fail-closed",
    ),
    (
        "POS-int-i64-min-minus-1",
        "C1 restricted integer domain, see POS-int-u64-max-plus-1",
    ),
    (
        "POS-int-2pow200",
        "C1 restricted integer domain, see POS-int-u64-max-plus-1",
    ),
    (
        "POS-uni-lone-high-surrogate",
        "the pinned producer and reader accept a lone escaped surrogate and the source stores it, \
         but its GET answers 500, so no bytes reach this reader: NOT_SERVED, not a verdict of this \
         reader (a lone surrogate is also refused by this reader's parser, see C1)",
    ),
    (
        "POS-uni-lone-low-surrogate",
        "as POS-uni-lone-high-surrogate",
    ),
];

fn dir() -> PathBuf {
    PathBuf::from(std::env::var("KC2_E2E_DIR").expect("KC2_E2E_DIR"))
}

fn outcome(result: &str, code: Option<&str>, allow: &[String], detail: &str) -> Value {
    json!({"result": result, "code": code, "allow": allow, "detail": detail})
}

fn strict_outcome(
    digest: &str,
    doc: &ContractDocument,
    pin: Option<&SchemaPin>,
    requested: &str,
) -> Value {
    match verify_with_pin(digest, doc, ReaderMode::Strict { profile: requested }, pin) {
        Ok(binding) => {
            let allow: Vec<String> = binding.allowlist().iter().cloned().collect();
            assert_eq!(binding.reader_route(), ReaderRoute::Strict);
            assert!(binding.satisfies_profile(STRICT_PROFILE));
            outcome("ACCEPT", None, &allow, "")
        }
        Err(refusal) => outcome("REFUSE", Some(refusal.code()), &[], &refusal.to_string()),
    }
}

/// The omitted-flag route: what `arcana run --work-item` does when `--contract-profile` is absent.
fn omitted_outcome(digest: &str, doc: &ContractDocument) -> Value {
    match verify(digest, doc) {
        Ok(binding) => {
            assert_eq!(binding.reader_route(), ReaderRoute::Legacy);
            assert!(!binding.satisfies_profile(STRICT_PROFILE));
            let allow: Vec<String> = binding.allowlist().iter().cloned().collect();
            outcome("ACCEPT", None, &allow, "legacy route")
        }
        Err(refusal) => outcome("REFUSE", Some(refusal.code()), &[], &refusal.to_string()),
    }
}

fn synthetic_envelope(row: &Value) -> Option<ContractDocument> {
    let b64 = row.get("rust_preimage_b64")?.as_str()?;
    let digest = row["digest"].as_str()?.to_owned();
    let mut doc = ContractDocument {
        digest,
        canonical: Some(CanonicalBlock {
            bytes_b64: Some(b64.to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    };
    doc.kind = row["hints"]["kind"].as_str().map(str::to_owned);
    doc.schema_version = row["hints"]["schema_version"].as_str().map(str::to_owned);
    Some(doc)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running Argana at the pinned commit and the harness manifest; see the module docs"]
async fn producer_to_argana_http_to_strict_reader_corpus() {
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(dir().join("manifest.json")).unwrap()).unwrap();
    let base = std::env::var("KC2_E2E_ARGANA_URL").expect("KC2_E2E_ARGANA_URL");
    let client = ArganaContractClient::new(Url::parse(&base).unwrap()).unwrap();
    let known: BTreeMap<&str, &str> = KNOWN_DIFFERENCES.iter().copied().collect();
    let real_pin = TALOMNIA_SCHEMA_PIN.expect("pinned");

    let mut rows = Vec::new();
    let mut unexpected = Vec::new();
    let mut seen_known = Vec::new();
    let mut positives_over_http = 0_usize;

    for case in manifest["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let mode = case["rust_mode"].as_str().unwrap_or("compare");
        let put_stored = case["argana_put"]["result"] == "STORED";
        let get_status = case["argana_get"]["status"].as_u64();
        let producer = case["producer"]["result"].as_str().unwrap_or("N/A");
        let producer_code = case["producer"]["code"].as_str();
        let want_allow: Vec<String> = case["producer"]["allow"]
            .as_array()
            .map_or_else(Vec::new, |a| {
                a.iter().map(|v| v.as_str().unwrap().to_owned()).collect()
            });
        let mut row = json!({"id": id, "source": null, "strict": null, "omitted": null, "pin_missing": null, "pin_changed": null});

        if let Some(reason) = mode.strip_prefix("not_comparable:") {
            row["strict"] = outcome("N/A", None, &[], reason);
            rows.push(row);
            continue;
        }
        if mode == "not_emitted" || case["digest"].is_null() {
            row["strict"] = outcome("N/A", None, &[], "not emitted by the producer");
            rows.push(row);
            continue;
        }
        let digest = case["digest"].as_str().unwrap().to_owned();

        // ---- the document the strict reader gets
        let (doc, source) = if put_stored && get_status == Some(200) {
            let fetched = client.fetch(&digest).await;
            match fetched {
                Ok(doc) => {
                    // the bytes Rust got are the bytes Argana's HTTP body carried
                    let got = base64::engine::general_purpose::STANDARD
                        .decode(doc.canonical.as_ref().unwrap().bytes_b64.as_ref().unwrap())
                        .unwrap();
                    assert_eq!(
                        digest_of(&got),
                        case["argana_get"]["bytes_b64_sha256"].as_str().unwrap(),
                        "{id}: the client saw other bytes than the harness's own GET"
                    );
                    positives_over_http += 1;
                    (doc, "argana-http")
                }
                Err(refusal) => {
                    row["source"] = json!("argana-http");
                    row["strict"] = outcome(
                        "NOT_SERVED",
                        Some(refusal.code()),
                        &[],
                        &refusal.to_string(),
                    );
                    check(
                        id,
                        &row,
                        producer,
                        producer_code,
                        &want_allow,
                        &known,
                        &mut unexpected,
                        &mut seen_known,
                    );
                    rows.push(row);
                    continue;
                }
            }
        } else if put_stored && get_status != Some(200) {
            row["source"] = json!("argana-http");
            row["strict"] = outcome(
                "NOT_SERVED",
                None,
                &[],
                &format!("Argana stored the record but GET answered {get_status:?}"),
            );
            check(
                id,
                &row,
                producer,
                producer_code,
                &want_allow,
                &known,
                &mut unexpected,
                &mut seen_known,
            );
            rows.push(row);
            continue;
        } else if let Some(doc) = synthetic_envelope(case) {
            (
                doc,
                "synthetic-envelope (Argana refused the put; nothing to GET)",
            )
        } else {
            row["strict"] = outcome("N/A", None, &[], "no digested halves to read");
            rows.push(row);
            continue;
        };
        row["source"] = json!(source);

        if mode == "legacy" {
            // actual legacy bytes: the un-profiled v2 contract through Argana's unchanged v1 record
            row["omitted"] = omitted_outcome(&digest, &doc);
            row["strict"] = strict_outcome(&digest, &doc, Some(&real_pin), STRICT_PROFILE);
            assert_eq!(
                row["omitted"]["result"], "ACCEPT",
                "legacy bytes must stay accepted"
            );
            assert_eq!(row["strict"]["code"], "CONTRACT_PROFILE_REQUIRED");
            rows.push(row);
            continue;
        }

        row["strict"] = strict_outcome(&digest, &doc, Some(&real_pin), STRICT_PROFILE);
        if source == "argana-http" && producer == "ACCEPT" {
            // R2: the flag omitted must not downgrade a profile-marked contract to the legacy route
            row["omitted"] = omitted_outcome(&digest, &doc);
            if id == "POS-allow-read+write" {
                row["pin_missing"] = strict_outcome(&digest, &doc, None, STRICT_PROFILE);
                let mut changed = real_pin;
                let schemas: Vec<_> = real_pin
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
                let leaked: &'static [arcana_core::contract::PinnedSchema] =
                    Box::leak(schemas.into_boxed_slice());
                changed.schemas = leaked;
                row["pin_changed"] = strict_outcome(&digest, &doc, Some(&changed), STRICT_PROFILE);
                // requested profile other than the one the bytes carry, and an empty request
                row["request_other"] =
                    strict_outcome(&digest, &doc, Some(&real_pin), "arcanada-kc2-tools/v2");
                row["request_empty"] = strict_outcome(&digest, &doc, Some(&real_pin), "");
            }
        }
        check(
            id,
            &row,
            producer,
            producer_code,
            &want_allow,
            &known,
            &mut unexpected,
            &mut seen_known,
        );
        rows.push(row);
    }

    let stale: Vec<&&str> = known
        .keys()
        .filter(|k| !seen_known.contains(&(**k).to_owned()))
        .collect();
    std::fs::write(
        dir().join("rust_results.json"),
        serde_json::to_string_pretty(
            &json!({"rows": rows, "positives_over_http": positives_over_http}),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        positives_over_http >= 30,
        "positives fetched over HTTP: {positives_over_http}"
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

/// Compare the strict outcome with the producer verdict; record named differences.
fn check(
    id: &str,
    row: &Value,
    producer: &str,
    producer_code: Option<&str>,
    want_allow: &[String],
    known: &BTreeMap<&str, &str>,
    unexpected: &mut Vec<String>,
    seen_known: &mut Vec<String>,
) {
    let strict = &row["strict"];
    let result = strict["result"].as_str().unwrap();
    let code = strict["code"].as_str();
    let allow: Vec<String> = strict["allow"].as_array().map_or_else(Vec::new, |a| {
        a.iter().map(|v| v.as_str().unwrap().to_owned()).collect()
    });
    let same = match producer {
        "ACCEPT" => result == "ACCEPT" && allow == want_allow,
        "REFUSE" => result == "REFUSE" && code == producer_code,
        _ => true,
    };
    // the omitted route must refuse every profile-marked contract, whatever the strict verdict
    let omitted_ok = row["omitted"].is_null()
        || (row["omitted"]["result"] == "REFUSE"
            && row["omitted"]["code"] == "CONTRACT_PROFILE_ROUTE_REQUIRED");
    if !omitted_ok {
        unexpected.push(format!("{id}: omitted flag -> {}", row["omitted"]));
    }
    if !same {
        if known.contains_key(id) {
            seen_known.push(id.to_owned());
        } else {
            unexpected.push(format!(
                "{id}: strict {result}/{code:?}/{allow:?} vs producer {producer}/{producer_code:?}/{want_allow:?}"
            ));
        }
    } else if known.contains_key(id) {
        // a named difference that no longer differs is reported as stale (not pushed to seen)
    }
    for key in [
        "pin_missing",
        "pin_changed",
        "request_other",
        "request_empty",
    ] {
        if !row[key].is_null()
            && (row[key]["result"] != "REFUSE" || row[key]["code"] != "CONTRACT_READER_UNSUPPORTED")
        {
            unexpected.push(format!("{id}: {key} -> {}", row[key]));
        }
    }
}
