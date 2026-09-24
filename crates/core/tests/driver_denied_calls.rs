//! A2-249 / D1: a call the cascade refused leaves the reason and the call
//! behind, not just a layer name.
//!
//! Measured on pilot A2-240b (`/home/dev/aup/arc2/runs/A2-248/report.md` § 1):
//! 21 of the run's 100 paid turns produced nothing because the permission
//! cascade refused the call — 14 at the `schema` layer, 7 at
//! `workspace_boundary`. None of them could be analysed afterwards. The
//! `reason` built in `CapabilityExecutor::deny` reaches the model and the
//! audit log gets `decision`/`layer`/`input_hash` and nothing else, so the
//! largest single sink of that run was also the least diagnosable thing in it.
//!
//! What is pinned here:
//!   1. A denied call is written to the configured directory as JSON carrying
//!      the layer, the reason, and the call as the model wrote it — same
//!      counter/naming discipline as `.arcana/rejected/`.
//!   2. The audit log gains a `reason_hash` on the decision record, so two
//!      denials refused with the same sentence are countable from the log
//!      alone — and its stated limit: a sentence that quotes the model's own
//!      text does not group, which is exactly why the file exists.
//!   3. The property the audit already has is kept: a secret-looking value in
//!      a denied call never reaches `audit.log`, not through `input_hash`,
//!      and not through the new field either.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use arcana_core::agent_loop::{denied_call_line, Driver, DriverConfig, RunOutput, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, CountingTool, ScriptedConnector};

/// A value that looks exactly like a credential the model echoed into a call.
/// `counting` wants an integer, so this is refused at the `schema` layer — and
/// `jsonschema`'s message quotes the offending value, which is what makes this
/// the interesting case rather than a theoretical one.
const SECRET: &str = "mun_sk_EXAMPLE_THIS_IS_NOT_A_REAL_KEY";

async fn drive(
    replies: Vec<&str>,
    tune: impl FnOnce(&mut DriverConfig),
) -> (RunOutput, TempDir, Vec<String>) {
    let connector = ScriptedConnector::new(replies.into_iter().map(|t| response(t, 0.0)).collect());
    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(CountingTool::new(Arc::new(AtomicUsize::new(0)))))
        .expect("register the counting tool");
    let (executor, audit_dir) =
        common::test_executor(registry, common::allow_cascade(), HookChain::new());
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 12;
    tune(&mut config);
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    let out = driver.run("count something").await;
    let prompts = connector
        .requests()
        .into_iter()
        .map(|req| req.prompt)
        .collect();
    (out, audit_dir, prompts)
}

/// Every file under `dir`, in name order, as (name, parsed JSON).
fn denied_files(dir: &std::path::Path) -> Vec<(String, Value)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, Value)> = entries
        .map(|entry| entry.expect("dir entry"))
        .map(|entry| {
            let text = std::fs::read_to_string(entry.path()).expect("denied record is readable");
            (
                entry.file_name().to_string_lossy().into_owned(),
                serde_json::from_str(&text).expect("denied record is JSON"),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn audit_text(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("audit.log")).expect("audit.log")
}

fn audit_records(dir: &std::path::Path) -> Vec<Value> {
    audit_text(dir)
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit record is JSON"))
        .collect()
}

fn bad_call(value: &str) -> String {
    tool_call_result("counting", json!({ "value": value }))
}

// ---------------------------------------------------------------------------
// 1. The denied call itself
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_denied_call_leaves_a_file_with_the_reason_and_the_input() {
    let dir = TempDir::new().expect("tempdir");
    // A path that does not exist yet: the first denial of a fresh workspace
    // must be the one that is kept, not the one that discovers the directory.
    let denied = dir.path().join("nested").join("denied");
    let (out, _audit, _prompts) = drive(
        vec![
            &bad_call("one"),
            &bad_call("two"),
            &tool_call_result("counting", json!({ "value": 1 })),
            "counted",
        ],
        |config| config.denied_call_dir = Some(denied.clone()),
    )
    .await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let files = denied_files(&denied);
    assert_eq!(files.len(), 2, "one file per denied call: {files:?}");
    assert_eq!(
        files[0].0, "0001-turn1.json",
        "numbered, and named for its turn, exactly like a rejected reply"
    );
    assert_eq!(files[1].0, "0002-turn2.json");

    let first = &files[0].1;
    assert_eq!(first["tool"], json!("counting"));
    assert_eq!(first["layer"], json!("schema"), "{first}");
    assert_eq!(first["turn"], json!(1));
    assert_eq!(
        first["input"],
        json!({ "value": "one" }),
        "the call as the model wrote it, not what the runner made of it"
    );
    let reason = first["reason"].as_str().expect("a reason string");
    assert!(
        reason.contains("value"),
        "the reason must name the field that did not match: {reason}"
    );
    // The join back to `audit.log`, computed the same way the audit computes
    // it — without this the file and the log record cannot be paired.
    let hash = first["input_hash"].as_str().expect("an input hash");
    assert_eq!(hash.len(), 16, "the audit's 16-hex-digit prefix: {hash}");
}

#[tokio::test]
async fn saving_denied_calls_is_opt_in_and_a_run_without_a_directory_still_works() {
    assert!(
        DriverConfig::new("scripted").denied_call_dir.is_none(),
        "nothing writes denied calls to disk unless a caller asked for it"
    );
    let (out, _audit, _prompts) = drive(
        vec![
            &bad_call("one"),
            &tool_call_result("counting", json!({ "value": 1 })),
            "counted",
        ],
        |_| {},
    )
    .await;
    assert_eq!(out.reason, TerminalReason::Completed);
}

#[test]
fn the_operator_line_names_the_file_when_there_is_one() {
    let saved = "/w/.arcana/denied/0003-turn44.json";
    let line = denied_call_line(
        "schema",
        "read",
        "at `/path`: 3 is not of type \"string\"",
        Some(saved),
    );
    assert!(
        line.contains(saved),
        "the line must lead to the call: {line}"
    );
    assert!(line.contains("schema"), "{line}");
    assert!(line.contains("nothing was executed"), "{line}");

    // With nothing saved the line promises nothing — an operator sent to a
    // path that does not exist is worse off than one told nothing at all.
    let bare = denied_call_line("schema", "read", "bad", None);
    assert!(!bare.contains(".json"), "{bare}");
}

// ---------------------------------------------------------------------------
// 2. The audit record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_decision_record_carries_a_reason_hash_and_it_groups_by_the_sentence() {
    // Two calls that are DIFFERENT (`input_hash` separates them) and fail
    // with the SAME sentence, then one that fails with a different sentence.
    // "Was this the same mistake again?" is the question A2-248 could not
    // answer from the log at all; `reason_hash` answers it for any refusal
    // whose sentence does not quote the model's own text.
    let dir = TempDir::new().expect("tempdir");
    let denied = dir.path().join("denied");
    let (_out, audit, _prompts) = drive(
        vec![
            &tool_call_result("counting", json!({ "nope": 1 })),
            &tool_call_result("counting", json!({ "nope": 2 })),
            &bad_call("one"),
            &tool_call_result("counting", json!({ "value": 1 })),
            "counted",
        ],
        |config| config.denied_call_dir = Some(denied.clone()),
    )
    .await;

    let denials: Vec<Value> = audit_records(audit.path())
        .into_iter()
        .filter(|r| r["phase"] == "decision" && r["decision"] == "Denied")
        .collect();
    assert_eq!(denials.len(), 3, "three refused calls: {denials:?}");
    let hashes: Vec<&str> = denials
        .iter()
        .map(|r| r["reason_hash"].as_str().expect("a reason hash"))
        .collect();
    let inputs: Vec<&str> = denials
        .iter()
        .map(|r| r["input_hash"].as_str().expect("an input hash"))
        .collect();
    assert_ne!(inputs[0], inputs[1], "two different calls");
    assert_eq!(
        hashes[0], hashes[1],
        "and one cause — which is the whole reason this field is not \
         redundant with `input_hash`: {hashes:?}"
    );
    assert_ne!(hashes[1], hashes[2], "a different cause: {hashes:?}");

    // A decision that allowed has no reason, and says so rather than
    // inventing one: an absent reason and a blank one are different facts.
    let allowed: Vec<Value> = audit_records(audit.path())
        .into_iter()
        .filter(|r| r["phase"] == "decision" && r["decision"] == "Allowed")
        .collect();
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0]["reason_hash"], Value::Null);
}

#[tokio::test]
async fn the_hash_does_not_group_a_cause_whose_sentence_quotes_the_model() {
    // The stated limit of the log-only view, pinned so nobody reads
    // `reason_hash` as a cause classifier. `"one"` and `"two"` are the SAME
    // mistake — a string where an integer belongs — and the schema layer's
    // sentence quotes the value, so the hashes differ. That quoting is also
    // why the sentence itself cannot go into the audit log, and why the file
    // in `.arcana/denied/` is where the analysis actually happens.
    let dir = TempDir::new().expect("tempdir");
    let denied = dir.path().join("denied");
    let (_out, audit, _prompts) = drive(
        vec![
            &bad_call("one"),
            &bad_call("two"),
            &tool_call_result("counting", json!({ "value": 1 })),
            "counted",
        ],
        |config| config.denied_call_dir = Some(denied.clone()),
    )
    .await;

    let hashes: Vec<String> = audit_records(audit.path())
        .into_iter()
        .filter(|r| r["decision"] == "Denied")
        .map(|r| r["reason_hash"].as_str().expect("a reason hash").to_owned())
        .collect();
    assert_eq!(hashes.len(), 2);
    assert_ne!(hashes[0], hashes[1], "the sentence quotes the value");

    // The two files, on the other hand, carry both sentences in full.
    let files = denied_files(&denied);
    let reasons: Vec<&str> = files
        .iter()
        .map(|(_, r)| r["reason"].as_str().expect("a reason"))
        .collect();
    assert!(reasons[0].contains("\"one\""), "{reasons:?}");
    assert!(reasons[1].contains("\"two\""), "{reasons:?}");
    assert!(
        reasons
            .iter()
            .all(|r| r.contains("not of type \"integer\"")),
        "the same cause, readable as such, where the text is kept: {reasons:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. The property the audit already has, kept
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_secret_in_a_denied_call_is_treated_the_way_the_audit_treats_it_today() {
    let dir = TempDir::new().expect("tempdir");
    let denied = dir.path().join("denied");
    let (_out, audit, prompts) = drive(
        vec![
            &bad_call(SECRET),
            &tool_call_result("counting", json!({ "value": 1 })),
            "counted",
        ],
        |config| config.denied_call_dir = Some(denied.clone()),
    )
    .await;

    // The audit's stated invariant: hashes only, no raw input and no error
    // string. The reason for a schema refusal quotes the offending value —
    // `"mun_sk_…" is not of type "integer"` — so recording the reason
    // verbatim in `audit.log` would have put the value in the one file that
    // lives outside the workspace and is never rotated.
    let log = audit_text(audit.path());
    assert!(
        !log.contains(SECRET),
        "the audit log must not carry the value; it did: {log}"
    );

    // Where it does live is the workspace file, which is what
    // `.arcana/rejected/` already does with the whole reply the model sent —
    // and that reply contains this same call.
    let files = denied_files(&denied);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].1["input"], json!({ "value": SECRET }));
    assert!(
        files[0].1["reason"]
            .as_str()
            .expect("a reason")
            .contains(SECRET),
        "the reason is kept whole where the call is kept whole: {}",
        files[0].1
    );

    // Not a new disclosure to the model either: the refusal was already
    // folded back to it verbatim before this card, and still is.
    assert!(
        prompts
            .iter()
            .any(|p| p.contains("REJECTED at the schema layer")),
        "the model is still told why its call was refused"
    );
}
