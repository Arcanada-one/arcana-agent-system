//! A2-219: a reply the runner refuses to act on leaves the text behind, not
//! just a verdict about it.
//!
//! Measured 2026-09-23 (`/home/dev/aup/arc2/runs/A2-204c3/log`, ARAS
//! `92a4a7a`): a live run reached turn 34 with 21 executed tool calls, then
//! died `UnsupportedToolCallFormat` on two replies that "named `edit` but
//! carried no arguments" — the call that was about to write the patch. What
//! the model actually sent could not be recovered afterwards: the audit log
//! keeps `input_hash`/`output_hash` and no text, and no transcript is written
//! to disk. The defect could be reported and not diagnosed.
//!
//! Three things are pinned here:
//!   1. Every rejected reply — unreadable dialect or cut off mid-block — is
//!      written to the configured directory byte-for-byte, and the operator's
//!      log line names the file.
//!   2. Every dispatch records the SIZE of its request in the audit log, and
//!      no record carries the text.
//!   3. `--save-transcript` keeps every request, not just the last one, which
//!      is the only way a compacted run can be read afterwards.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::io::{self, Write};
use std::sync::Arc;

use arcana_core::agent_loop::{
    rejected_format_line, truncated_reply_line, Driver, DriverConfig, RunOutput, TerminalReason,
};
use arcana_core::connector::ConnectorResponse;
use arcana_core::cost::CostTracker;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::{AuditLog, DurableAuditWriter};
use arcana_core::hooks::HookChain;
use arcana_core::prompt_budget::utf16_units;
use arcana_core::tool::ToolDispatcher;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{allow_cascade, response, tool_call_result, EchoTool, ScriptedConnector};

/// A bare OpenAI-shaped object: recognisable as a call, deliberately never
/// dispatched, so every reply of this shape is a rejection.
const BARE_CALL: &str = "{\"name\":\"echo\",\"arguments\":{\"text\":\"hello\"}}";

/// The live A2-204c3 shape: this runner's own fence, a `name`, and no
/// arguments under any spelling.
const NO_ARGUMENTS: &str = "```tool_call\n{\"name\": \"edit\"}\n```";

fn echo_dispatcher() -> ToolDispatcher {
    let mut disp = ToolDispatcher::new();
    disp.register(Arc::new(EchoTool)).expect("register echo");
    disp
}

/// Drive one script with `config` mutated by `tune`; returns the outcome and
/// the requests the connector saw.
async fn run_with(
    responses: Vec<ConnectorResponse>,
    tune: impl FnOnce(&mut DriverConfig),
) -> (RunOutput, Vec<String>, TempDir) {
    let connector = ScriptedConnector::new(responses);
    let (executor, audit_dir) =
        common::test_executor(echo_dispatcher(), allow_cascade(), HookChain::new());
    let mut config = DriverConfig::new("scripted");
    config.require_action = true;
    tune(&mut config);
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    let out = driver.run("do a small task").await;
    let prompts = connector
        .requests()
        .into_iter()
        .map(|req| req.prompt)
        .collect();
    (out, prompts, audit_dir)
}

/// Every `.txt` under `dir`, in name order, as (name, contents).
fn saved_files(dir: &std::path::Path) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = entries
        .map(|entry| entry.expect("dir entry"))
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read_to_string(entry.path()).expect("saved reply is readable"),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

// ---------------------------------------------------------------------------
// 1. The reply itself
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_rejected_reply_is_written_out_byte_for_byte() {
    let dir = TempDir::new().expect("tempdir");
    // A path that does not exist yet: the run must create it, or the first
    // rejection of a fresh workspace is the one that is never kept.
    let rejected = dir.path().join("nested").join("rejected");
    let (out, _, _audit) = run_with(
        vec![
            response(NO_ARGUMENTS, 0.0),
            response(NO_ARGUMENTS, 0.0),
            response(NO_ARGUMENTS, 0.0),
        ],
        |config| config.rejected_reply_dir = Some(rejected.clone()),
    )
    .await;

    assert_eq!(out.reason, TerminalReason::UnsupportedToolCallFormat);
    assert_eq!(out.tool_calls, 0, "nothing ran");

    let files = saved_files(&rejected);
    assert_eq!(
        files.len(),
        2,
        "one file per rejected reply, and the run stops after the second: {files:?}"
    );
    assert_eq!(
        files[0].0, "0001-turn1.txt",
        "numbered, and named for its turn"
    );
    assert_eq!(files[1].0, "0002-turn2.txt");
    for (name, contents) in &files {
        assert_eq!(
            contents, NO_ARGUMENTS,
            "{name} must be what the model sent, with nothing added or trimmed"
        );
    }
}

#[tokio::test]
async fn a_truncated_reply_is_kept_although_the_transcript_drops_it() {
    let dir = TempDir::new().expect("tempdir");
    let rejected = dir.path().join("rejected");
    // An opened, never-closed fence — the signature of an output-limit cut-off.
    let fragment = "I will edit the file now.\n```tool_call\n{\"name\": \"edit\", \"input\": {\"pa";
    let (out, prompts, _audit) = run_with(
        vec![
            response(fragment, 0.0),
            response(&tool_call_result("echo", json!({ "text": "hello" })), 0.0),
            response("done", 0.0),
        ],
        |config| config.rejected_reply_dir = Some(rejected.clone()),
    )
    .await;

    assert_eq!(out.reason, TerminalReason::Completed);
    let files = saved_files(&rejected);
    assert_eq!(files.len(), 1, "the cut-off reply is a rejected reply too");
    assert_eq!(files[0].1, fragment);
    // The point of keeping it on disk: it is deliberately NOT in the history,
    // so the file is the only copy there is.
    assert!(
        prompts.iter().all(|prompt| !prompt.contains("\"pa")),
        "the fragment must stay out of the transcript, or this file is a duplicate"
    );
}

#[tokio::test]
async fn saving_is_opt_in_and_a_run_without_a_directory_still_works() {
    assert!(
        DriverConfig::new("scripted").rejected_reply_dir.is_none(),
        "nothing writes replies to disk unless a caller asked for it"
    );
    let (out, _, _audit) = run_with(
        vec![response(BARE_CALL, 0.0), response(BARE_CALL, 0.0)],
        |_| {},
    )
    .await;
    assert_eq!(out.reason, TerminalReason::UnsupportedToolCallFormat);
}

#[test]
fn the_operator_line_names_the_file_when_there_is_one() {
    let saved = "/w/.arcana/rejected/0003-turn34.txt";
    let line = rejected_format_line("a fenced `tool_call` block", "it named `edit`", Some(saved));
    assert!(
        line.contains(saved),
        "the line must lead to the reply: {line}"
    );
    assert!(line.contains("nothing was executed"), "{line}");

    let truncated = truncated_reply_line(195, Some(saved));
    assert!(truncated.contains(saved), "{truncated}");
    assert!(truncated.contains("195 bytes"), "{truncated}");

    // With nothing saved the line promises nothing — an operator sent to a
    // path that does not exist is worse off than one who was told nothing.
    let bare = rejected_format_line("a fenced `tool_call` block", "it named `edit`", None);
    assert!(!bare.contains(".txt"), "{bare}");
    assert!(!truncated_reply_line(195, None).contains(".txt"));
}

// ---------------------------------------------------------------------------
// 2. Request sizes in the audit log
// ---------------------------------------------------------------------------

/// Every record in `audit.log`, parsed.
fn audit_records(dir: &std::path::Path) -> Vec<Value> {
    let text = std::fs::read_to_string(dir.join("audit.log")).expect("audit.log");
    text.lines()
        .map(|line| serde_json::from_str(line).expect("audit record is JSON"))
        .collect()
}

#[tokio::test]
async fn every_dispatch_records_its_request_size_and_never_its_text() {
    const SYSTEM: &str = "you are a careful agent";
    let (out, prompts, audit_dir) = run_with(
        vec![
            response(&tool_call_result("echo", json!({ "text": "hello" })), 0.0),
            response("done", 0.0),
        ],
        |config| config.system_prompt = Some(SYSTEM.to_owned()),
    )
    .await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let records = audit_records(audit_dir.path());
    let dispatches: Vec<&Value> = records
        .iter()
        .filter(|record| record["phase"] == "run" && record["kind"] == "dispatch")
        .collect();
    assert_eq!(
        dispatches.len(),
        prompts.len(),
        "one record per dispatch, or the log cannot account for what was paid for"
    );
    for (index, record) in dispatches.iter().enumerate() {
        let fields = &record["fields"];
        assert_eq!(fields["turn"], json!(index + 1), "turns are 1-based");
        assert_eq!(
            fields["prompt_utf16"],
            json!(utf16_units(&prompts[index])),
            "the recorded size must be the size of the request that was sent"
        );
        assert_eq!(fields["system_prompt_utf16"], json!(utf16_units(SYSTEM)));
    }

    // The invariant the whole log rests on: sizes, never content.
    let text = std::fs::read_to_string(audit_dir.path().join("audit.log")).expect("audit.log");
    assert!(
        !text.contains(SYSTEM),
        "the system prompt must not be in the audit log"
    );
    assert!(
        !text.contains("do a small task"),
        "the task text must not be in the audit log"
    );
    assert!(
        !text.contains("hello"),
        "no tool argument may reach the audit log"
    );
}

#[tokio::test]
async fn no_system_prompt_is_recorded_as_null_not_as_zero() {
    let (_, _, audit_dir) = run_with(
        vec![
            response(&tool_call_result("echo", json!({ "text": "hello" })), 0.0),
            response("done", 0.0),
        ],
        |_| {},
    )
    .await;
    let records = audit_records(audit_dir.path());
    let first = records
        .iter()
        .find(|record| record["kind"] == "dispatch")
        .expect("a dispatch record");
    assert_eq!(
        first["fields"]["system_prompt_utf16"],
        Value::Null,
        "an absent system prompt and an empty one are different requests"
    );
}

/// A durable writer that refuses every append: the disk the audit log cannot
/// be written to.
struct DeadWriter;

impl Write for DeadWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("audit sink is gone"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DurableAuditWriter for DeadWriter {
    fn sync_data(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_dispatch_that_cannot_be_audited_is_never_sent() {
    let connector = ScriptedConnector::new(vec![response("done", 0.0)]);
    let executor = CapabilityExecutor::new(
        echo_dispatcher(),
        allow_cascade(),
        HookChain::new(),
        AuditLog::from_durable_writer(Box::new(DeadWriter)),
    );
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    );
    let out = driver.run("do a small task").await;

    assert_eq!(
        out.reason,
        TerminalReason::AuditFatal,
        "a turn whose size could not be recorded must not be a turn that was paid for"
    );
    assert!(
        connector.requests().is_empty(),
        "the record is written BEFORE the dispatch, not after it"
    );
}

// ---------------------------------------------------------------------------
// 3. --save-transcript
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_saved_transcript_holds_every_request_not_only_the_last() {
    const SYSTEM: &str = "SYSTEM-PROMPT-MARKER";
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("transcript.txt");
    let (out, prompts, _audit) = run_with(
        vec![
            response(&tool_call_result("echo", json!({ "text": "hello" })), 0.0),
            response("done", 0.0),
        ],
        |config| {
            config.system_prompt = Some(SYSTEM.to_owned());
            config.transcript_path = Some(path.clone());
        },
    )
    .await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let text = std::fs::read_to_string(&path).expect("the transcript exists");
    assert_eq!(prompts.len(), 2);
    for (index, prompt) in prompts.iter().enumerate() {
        assert!(
            text.contains(&format!("===== dispatch {} ", index + 1)),
            "every dispatch is headed, because a compacted run's last request \
             is not a superset of the earlier ones"
        );
        assert!(text.contains(prompt.as_str()), "request {index} is missing");
    }
    assert_eq!(
        text.matches(SYSTEM).count(),
        1,
        "the system prompt is written once: it does not change during a run"
    );
}

#[tokio::test]
async fn no_transcript_is_written_unless_a_path_was_given() {
    let dir = TempDir::new().expect("tempdir");
    let (out, _, _audit) = run_with(
        vec![
            response(&tool_call_result("echo", json!({ "text": "hello" })), 0.0),
            response("done", 0.0),
        ],
        |_| {},
    )
    .await;
    assert_eq!(out.reason, TerminalReason::Completed);
    assert!(
        DriverConfig::new("scripted").transcript_path.is_none(),
        "a transcript is the operator's decision about their own disk"
    );
    assert_eq!(
        std::fs::read_dir(dir.path()).expect("tempdir").count(),
        0,
        "nothing is written anywhere by default"
    );
}
