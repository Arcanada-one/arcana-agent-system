//! V-AC-6 (D-REQ-07): cost accounting. Every connector call records into the
//! shared `CostTracker` (call count + tokens + USD from `Usage`); a cumulative
//! cost strictly over the `max_cost_usd` cap yields `Terminal(MaxCostUsd)`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, EchoTool, ScriptedConnector};

fn echo_dispatcher() -> ToolDispatcher {
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo tool");
    dispatcher
}

#[tokio::test]
async fn driver_cost_accounting() {
    // Each `response` reports usage {in:3, out:5}. Two calls with costs
    // 0.002 + 0.003 = 0.005 USD → 5000 micro-USD.
    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("echo", json!({ "text": "x" })), 0.002),
        response("done", 0.003),
    ]);
    let dispatcher = echo_dispatcher();
    let cascade = PermissionCascade::new(vec![]);
    let hooks = HookChain::new();
    let cost = Arc::new(CostTracker::new());

    let driver = Driver::new(
        &connector,
        &dispatcher,
        &cascade,
        &hooks,
        cost.clone(),
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    );
    let out = driver.run("do the thing").await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let snap = cost.snapshot();
    assert_eq!(snap.total_calls, 2, "one record per connector call");
    assert_eq!(snap.total_tokens_in, 6, "3 + 3 input tokens");
    assert_eq!(snap.total_tokens_out, 10, "5 + 5 output tokens");
    assert_eq!(snap.total_cost_usd_micros, 5_000, "0.002 + 0.003 USD");
    // The RunOutput carries the same snapshot.
    assert_eq!(out.cost.total_calls, 2);
    assert_eq!(out.cost.total_cost_usd_micros, 5_000);
}

#[tokio::test]
async fn driver_cost_cap_terminates() {
    // A connector whose per-call cost (0.01) strictly exceeds the cap (0.001)
    // trips the budget circuit breaker on the following iteration.
    let mut config = DriverConfig::new("scripted");
    config.max_cost_usd = Some(0.001);
    config.max_turns = 50; // ensure MaxCostUsd fires before MaxTurns

    let connector = ScriptedConnector::repeating(response(
        &tool_call_result("echo", json!({ "text": "x" })),
        0.01,
    ));
    let dispatcher = echo_dispatcher();
    let cascade = PermissionCascade::new(vec![]);
    let hooks = HookChain::new();
    let cost = Arc::new(CostTracker::new());

    let driver = Driver::new(
        &connector,
        &dispatcher,
        &cascade,
        &hooks,
        cost.clone(),
        CancellationToken::new(),
        config,
    );
    let out = driver.run("expensive task").await;

    assert_eq!(out.reason, TerminalReason::MaxCostUsd);
    assert!(
        cost.snapshot().total_calls >= 1,
        "at least one call was recorded before the cap tripped"
    );
}
