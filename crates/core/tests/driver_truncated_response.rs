//! A2-208: a reply the model could not finish is not "the model did nothing".
//!
//! Measured 2026-09-23 during A2-203 on `arcana` 0.2.0: asked for a 3000-word
//! file, DeepSeek emitted a ```tool_call block that ran out at ~9148 output
//! tokens with no closing fence. `interpret` needs that fence, so the reply
//! fell through its fail-closed arm to `Final` — the loop concluded the model
//! had answered in prose, charged the $0.040 the dispatch cost, wrote no file,
//! and ended the run on `NoAction`. Three different things (an answer, a
//! refusal to act, a reply cut off mid-sentence) had one verdict.
//!
//! A cut-off reply is now its own outcome: never executed, re-dispatched once
//! with an instruction to work in smaller pieces, and — if the second reply is
//! cut off too — a terminal reason that says so.

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

/// A `tool_call` block that stopped where the output limit stopped it: the
/// fence is open, the JSON is half-written, and there is no closing fence.
///
/// The prose before it is part of the shape — the live reply began by
/// explaining what it was about to do, which is exactly why the whole thing
/// read as an answer.
fn cut_off_mid_json() -> String {
    "I will write the file now.\n```tool_call\n{\"name\":\"counting\",\"input\":{\"value\":\
     1"
    .to_string()
}

/// The crueller shape: the JSON is complete and only the closing fence is
/// missing. Whatever a reader might reconstruct, the model never said it had
/// finished, so this call must not be executed either.
fn cut_off_after_the_json() -> String {
    "```tool_call\n{\"name\":\"counting\",\"input\":{\"value\":1}}\n".to_string()
}

fn config() -> DriverConfig {
    DriverConfig::new("scripted")
}

async fn drive(
    connector: &ScriptedConnector,
    config: DriverConfig,
    count: &Arc<AtomicUsize>,
) -> RunOutput {
    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(CountingTool::new(Arc::clone(count))))
        .expect("register counting tool");
    let (executor, _audit_dir) =
        common::test_executor(registry, common::allow_cascade(), HookChain::new());
    let driver = Driver::new(
        connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    driver.run("write a long file").await
}

#[tokio::test]
async fn a_cut_off_tool_call_is_not_the_models_final_answer() {
    let count = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedConnector::new(vec![
        response(&cut_off_mid_json(), 0.04),
        response(&tool_call_result("counting", json!({ "value": 1 })), 0.01),
        response("The file is written.", 0.01),
    ]);

    let out = drive(&connector, config(), &count).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "the work is done on the second reply; the first only ran out of room"
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "the re-dispatched turn does the work the cut-off one could not"
    );
    assert_eq!(
        out.tool_calls, 1,
        "a run that ends with one executed tool call must say so"
    );
    assert_eq!(
        out.turns, 3,
        "the re-dispatch is an attempt like any other and is counted"
    );
}

#[tokio::test]
async fn a_cut_off_tool_call_is_never_executed() {
    let count = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedConnector::new(vec![
        response(&cut_off_after_the_json(), 0.04),
        response("I stopped.", 0.01),
    ]);

    let out = drive(&connector, config(), &count).await;

    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "a call the model never finished emitting is not a call we may make"
    );
    assert_eq!(out.tool_calls, 0);
    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "the second reply is a real answer"
    );
}

#[tokio::test]
async fn the_re_dispatch_asks_for_the_work_in_smaller_pieces() {
    let count = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedConnector::new(vec![
        response(&cut_off_mid_json(), 0.04),
        response("Understood.", 0.01),
    ]);

    let _ = drive(&connector, config(), &count).await;

    let requests = connector.requests();
    assert_eq!(requests.len(), 2, "the turn is re-dispatched exactly once");
    let second = &requests[1].prompt;
    assert!(
        second.contains("CUT OFF"),
        "the second prompt must tell the model its reply was cut off, not repeat the task \
         unchanged: {second}"
    );
    assert!(
        second.contains("SMALLER"),
        "and must ask for the work in smaller pieces: {second}"
    );
    assert!(
        !second.contains("\"value\":1"),
        "the half-written call itself is dropped rather than fed back as if it were said: \
         {second}"
    );
}

#[tokio::test]
async fn a_second_cut_off_reply_ends_the_run_saying_so() {
    let count = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedConnector::repeating(response(&cut_off_mid_json(), 0.04));
    let mut config = config();
    config.require_action = true;
    config.max_turns = 12;

    let out = drive(&connector, config, &count).await;

    assert_ne!(
        out.reason,
        TerminalReason::NoAction,
        "a model that tried twice and was cut off twice did not decline to act"
    );
    assert_ne!(
        out.reason,
        TerminalReason::Completed,
        "nothing was written, so nothing completed"
    );
    assert!(
        out.reason.explain().contains("output limit"),
        "the operator is told what actually happened, not a variant name: {}",
        out.reason.explain()
    );
    assert!(!out.reason.is_success());
    assert_eq!(
        out.turns, 2,
        "one attempt, one re-dispatch, then the verdict"
    );
}

#[tokio::test]
async fn the_re_dispatch_is_paid_for_out_of_max_turns() {
    let count = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedConnector::repeating(response(&cut_off_mid_json(), 0.04));
    let mut config = config();
    config.max_turns = 1;

    let out = drive(&connector, config, &count).await;

    assert_eq!(
        out.reason,
        TerminalReason::MaxTurns,
        "the recovery budget cannot outlive the turn budget"
    );
    assert_eq!(out.turns, 1);
    assert_eq!(
        connector.requests().len(),
        1,
        "--max-turns 1 buys one dispatch, cut off or not"
    );
}

#[tokio::test]
async fn the_re_dispatch_is_paid_for_out_of_the_cost_cap() {
    let count = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedConnector::repeating(response(&cut_off_mid_json(), 0.04));
    let mut config = config();
    config.max_cost_usd = Some(0.01);
    config.max_turns = 12;

    let out = drive(&connector, config, &count).await;

    assert_eq!(
        out.reason,
        TerminalReason::MaxCostUsd,
        "a reply that was cut off still cost money, and the cap still holds"
    );
    assert_eq!(
        connector.requests().len(),
        1,
        "the cap is checked before the re-dispatch goes out"
    );
}

#[tokio::test]
async fn a_turn_that_finished_restores_the_recovery_budget() {
    let count = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedConnector::new(vec![
        response(&cut_off_mid_json(), 0.04),
        response(&tool_call_result("counting", json!({ "value": 1 })), 0.01),
        response(&cut_off_mid_json(), 0.04),
        response(&tool_call_result("counting", json!({ "value": 2 })), 0.01),
        response("Both parts are written.", 0.01),
    ]);
    let mut config = config();
    config.max_turns = 12;

    let out = drive(&connector, config, &count).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "a long run legitimately hits the output limit more than once; only \
         back-to-back cut-offs mean the model cannot split the work"
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(out.tool_calls, 2);
}
