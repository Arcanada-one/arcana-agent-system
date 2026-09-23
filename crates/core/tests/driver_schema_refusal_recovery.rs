//! A2-225: a schema refusal is the model's formatting mistake, not a verdict
//! about what it is allowed to do.
//!
//! Measured on pilot run A2-204c4 (`~/.local/state/arcana/run/audit.log`,
//! entries up to 2026-09-23T18:18:52Z): 23 of the run's refusals came from the
//! `schema` layer, and the run ended `PermissionDenied`, `completed: false`,
//! after invocations 25, 26 and 27 — three refusals of the same `read` call,
//! `input_hash fe133faf0121151c`. A2-204 had already made a schema denial
//! recoverable; what still killed the run was a blunt count of consecutive
//! refusals, and a fold-back message that never said which field was wrong, so
//! the model had nothing to correct and sent the same bytes again.
//!
//! Two properties are pinned here:
//!
//! 1. Refusals at a *correctable* layer do not, by themselves, end a run. A
//!    model that keeps making **new** mistakes keeps getting told what they
//!    are, bounded by `max_turns` and the cost cap like any other work.
//! 2. Re-sending a call that was already refused **does** end the run — and the
//!    run says which layer refused it, which tool, and what the error was,
//!    rather than the bare `PermissionDenied` the pilot reported with
//!    `error: null`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, CountingTool, ScriptedConnector};

async fn drive(replies: Vec<&str>, executions: &Arc<AtomicUsize>) -> (RunOutput, Vec<String>) {
    let connector = ScriptedConnector::new(
        replies
            .into_iter()
            .map(|text| response(text, 0.0))
            .collect(),
    );
    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(CountingTool::new(Arc::clone(executions))))
        .expect("register the counting tool");
    let (executor, _audit_dir) =
        common::test_executor(registry, common::allow_cascade(), HookChain::new());
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 12;
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
    (out, prompts)
}

/// A malformed `counting` call. `nonce` makes each one a different call, which
/// is what separates "the model is still trying" from "the model is stuck".
fn bad_call(nonce: &str) -> String {
    tool_call_result("counting", json!({ "value": nonce }))
}

fn good_call() -> String {
    tool_call_result("counting", json!({ "value": 1 }))
}

#[tokio::test]
async fn four_distinct_schema_refusals_do_not_end_the_run() {
    // The pilot's number: more consecutive schema refusals than the old cap of
    // three, each a different mistake. Under the old rule the run died on the
    // third and the fifth reply was never reached; the corrected call at the
    // end is what makes this check able to go red.
    let executions = Arc::new(AtomicUsize::new(0));
    let (out, _prompts) = drive(
        vec![
            &bad_call("one"),
            &bad_call("two"),
            &bad_call("three"),
            &bad_call("four"),
            &good_call(),
            "counted",
        ],
        &executions,
    )
    .await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "a correctable refusal must not end the run: {:?} {:?}",
        out.reason,
        out.terminal_detail
    );
    assert_eq!(out.tool_calls, 1, "the corrected call ran");
    assert_eq!(executions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_refusal_the_model_reads_names_the_field_and_what_was_expected() {
    let executions = Arc::new(AtomicUsize::new(0));
    let (_out, prompts) = drive(vec![&bad_call("one"), &good_call(), "counted"], &executions).await;

    let second = prompts.get(1).expect("a second dispatch happened");
    assert!(
        second.contains("REJECTED at the schema layer"),
        "the model was not told the call was rejected: {second}"
    );
    // Which field. Without it the model is guessing at which of its arguments
    // the validator disliked — which is exactly how the pilot ended up sending
    // the same bytes three times.
    assert!(
        second.contains("/value"),
        "the rejection does not name the offending field: {second}"
    );
    // What was expected.
    assert!(
        second.contains("integer"),
        "the rejection does not say what was expected: {second}"
    );
}

#[tokio::test]
async fn re_sending_an_already_refused_call_ends_the_run_and_says_why() {
    let executions = Arc::new(AtomicUsize::new(0));
    let (out, _prompts) = drive(
        vec![&bad_call("same"), &bad_call("same"), &good_call()],
        &executions,
    )
    .await;

    assert_eq!(out.reason, TerminalReason::PermissionDenied);
    assert_eq!(out.tool_calls, 0, "nothing was ever executed");
    assert_eq!(
        out.turns, 2,
        "the repeat ends it; the third reply is never asked for"
    );
    let detail = out
        .terminal_detail
        .as_deref()
        .expect("the run must say what refused it, not just that something did");
    assert!(
        detail.contains("schema"),
        "the layer is not named: {detail}"
    );
    assert!(
        detail.contains("counting"),
        "the tool is not named: {detail}"
    );
    assert!(
        detail.contains("integer"),
        "the validation error is not carried: {detail}"
    );
}

#[tokio::test]
async fn an_executed_call_clears_the_memory_of_refused_calls() {
    // The bound is on a model stuck in one place, not on a long run that makes
    // the same slip twice an hour apart. Work clears it.
    let executions = Arc::new(AtomicUsize::new(0));
    let (out, _prompts) = drive(
        vec![
            &bad_call("same"),
            &good_call(),
            &bad_call("same"),
            &good_call(),
            "counted",
        ],
        &executions,
    )
    .await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "{:?} {:?}",
        out.reason,
        out.terminal_detail
    );
    assert_eq!(out.tool_calls, 2);
}
