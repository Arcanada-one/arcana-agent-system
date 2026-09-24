//! A2-249 / D4: the done-marker counts what the model tried, not only what
//! worked.
//!
//! `RunOutput::tool_calls` is incremented in one place — after the executor
//! returns — so a refused call and a call that was never made are the same
//! number. Pilot A2-240b reported `"tool_calls":72` for a run that made **98**
//! attempts, 21 of which the cascade refused
//! (`/home/dev/aup/arc2/runs/A2-248/report.md` § 1). Read as intent, 72 says
//! "the model barely called tools"; the truth was "it called them constantly
//! and often wrongly", and the two lead to opposite conclusions about what to
//! fix.
//!
//! `tool_calls` keeps its meaning — evidence of work done — and two counters
//! are added beside it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, CountingTool, ScriptedConnector};

async fn drive(replies: Vec<String>) -> RunOutput {
    let connector = ScriptedConnector::new(replies.iter().map(|t| response(t, 0.0)).collect());
    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(CountingTool::new(Arc::new(AtomicUsize::new(0)))))
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
    driver.run("count something").await
}

fn good() -> String {
    tool_call_result("counting", json!({ "value": 1 }))
}

fn refused(nonce: &str) -> String {
    tool_call_result("counting", json!({ "value": nonce }))
}

#[tokio::test]
async fn a_run_reports_what_was_attempted_denied_and_executed() {
    let out = drive(vec![
        refused("one"),
        good(),
        refused("two"),
        good(),
        "counted".to_owned(),
    ])
    .await;
    assert_eq!(out.reason, TerminalReason::Completed, "{out:?}");
    assert_eq!(out.tool_calls, 2, "unchanged: calls that did work");
    assert_eq!(out.tool_calls_denied, 2, "calls the cascade refused");
    assert_eq!(
        out.tool_calls_attempted, 4,
        "every call that reached the executor"
    );
}

#[tokio::test]
async fn a_run_that_executed_nothing_still_says_how_hard_it_tried() {
    // The A2-240b shape in miniature: the model calls tools and never lands
    // one. The old marker reported `tool_calls: 0` and nothing else, which
    // reads identically to a model that answered in prose.
    let out = drive(vec![refused("one"), refused("one"), "gave up".to_owned()]).await;
    assert_eq!(
        out.reason,
        TerminalReason::PermissionDenied,
        "the same call twice ends the run: {out:?}"
    );
    assert_eq!(out.tool_calls, 0);
    assert_eq!(out.tool_calls_attempted, 2);
    assert_eq!(out.tool_calls_denied, 2);
}

#[tokio::test]
async fn a_run_with_no_calls_at_all_reports_zero_for_all_three() {
    let out = drive(vec!["I think the answer is 42.".to_owned()]).await;
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(out.tool_calls, 0);
    assert_eq!(out.tool_calls_attempted, 0);
    assert_eq!(out.tool_calls_denied, 0);
}
