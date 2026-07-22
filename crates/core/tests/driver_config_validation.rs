//! Invalid driver budgets fail closed before the first connector attempt.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use tokio_util::sync::CancellationToken;

use common::{response, ScriptedConnector};

async fn run_with(config: DriverConfig) -> (RunOutput, usize) {
    let connector = ScriptedConnector::new(vec![response("must not run", 0.0)]);
    let dispatcher = ToolDispatcher::new();
    let cascade = PermissionCascade::new(vec![]);
    let hooks = HookChain::new();
    let driver = Driver::new(
        &connector,
        &dispatcher,
        &cascade,
        &hooks,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    let output = driver.run("task").await;
    (output, connector.requests().len())
}

#[tokio::test]
async fn driver_rejects_zero_turn_cap_before_call() {
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 0;

    let (out, calls) = run_with(config).await;

    assert_eq!(out.reason, TerminalReason::MaxTurns);
    assert_eq!(out.turns, 0);
    assert_eq!(calls, 0);
}

#[tokio::test]
async fn driver_rejects_non_finite_cost_cap_before_call() {
    let mut config = DriverConfig::new("scripted");
    config.max_cost_usd = Some(f64::NAN);

    let (out, calls) = run_with(config).await;

    assert_eq!(out.reason, TerminalReason::MaxCostUsd);
    assert_eq!(out.turns, 0);
    assert_eq!(calls, 0);
}

#[tokio::test]
async fn driver_rejects_infinite_cost_cap_before_call() {
    let mut config = DriverConfig::new("scripted");
    config.max_cost_usd = Some(f64::INFINITY);

    let (out, calls) = run_with(config).await;

    assert_eq!(out.reason, TerminalReason::MaxCostUsd);
    assert_eq!(out.turns, 0);
    assert_eq!(calls, 0);
}

#[tokio::test]
async fn driver_rejects_negative_cost_cap_before_call() {
    let mut config = DriverConfig::new("scripted");
    config.max_cost_usd = Some(-0.01);

    let (out, calls) = run_with(config).await;

    assert_eq!(out.reason, TerminalReason::MaxCostUsd);
    assert_eq!(out.turns, 0);
    assert_eq!(calls, 0);
}

#[tokio::test]
async fn driver_rejects_zero_context_budget_before_call() {
    let mut config = DriverConfig::new("scripted");
    config.context_budget_chars = 0;

    let (out, calls) = run_with(config).await;

    assert_eq!(out.reason, TerminalReason::ContextWindowExhausted);
    assert_eq!(out.turns, 0);
    assert_eq!(calls, 0);
}
