//! V-AC-2 (D-REQ-02): each of the 8 `TerminalReason` variants is produced
//! from its own cause. Table-driven: one scenario per terminal, each driving
//! `Driver::run` to exactly the expected `TerminalReason`. The exhaustive
//! `reduce` match inside the driver makes an unhandled future variant a
//! compile error; this test pins the run-time cause→terminal mapping.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::TerminalReason;
use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, DenyLayer, EchoTool, ScriptedConnector, StopHook};

/// Run one scenario end-to-end. Owns every collaborator so the borrowing
/// `Driver` stays valid for the whole run; returns the owned `RunOutput`.
async fn run_scenario(
    connector: ScriptedConnector,
    dispatcher: ToolDispatcher,
    cascade: PermissionCascade,
    hooks: HookChain,
    cancel: CancellationToken,
    config: DriverConfig,
) -> RunOutput {
    let cost = Arc::new(CostTracker::new());
    let (executor, _audit_dir) = common::test_executor(dispatcher, cascade, hooks);
    let driver = Driver::new(&connector, &executor, cost, cancel, config);
    driver.run("do a small task").await
}

fn echo_dispatcher() -> ToolDispatcher {
    let mut disp = ToolDispatcher::new();
    disp.register(Arc::new(EchoTool)).expect("register echo");
    disp
}

fn tool_call_response(cost_usd: f64) -> arcana_core::connector::ConnectorResponse {
    response(&tool_call_result("echo", json!({ "text": "x" })), cost_usd)
}

#[tokio::test]
async fn driver_terminal_mapping() {
    // 1. Completed — a plain final response terminates the run.
    let out = run_scenario(
        ScriptedConnector::new(vec![response("final answer", 0.0)]),
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    )
    .await;
    assert_eq!(out.reason, TerminalReason::Completed, "final → Completed");
    assert_eq!(out.final_text.as_deref(), Some("final answer"));
    assert_eq!(out.turns, 1, "a final-only run makes one connector attempt");

    // 2. MaxTurns — a connector that never stops calling the tool hits the cap.
    let mut cfg = DriverConfig::new("scripted");
    cfg.max_turns = 2;
    let out = run_scenario(
        ScriptedConnector::repeating(tool_call_response(0.0)),
        echo_dispatcher(),
        common::allow_cascade(),
        HookChain::new(),
        CancellationToken::new(),
        cfg,
    )
    .await;
    assert_eq!(out.reason, TerminalReason::MaxTurns, "tool loop → MaxTurns");
    assert_eq!(out.turns, 2, "the turn cap counts connector attempts");

    // 3. MaxCostUsd — cumulative cost strictly over the cap stops the loop.
    let mut cfg = DriverConfig::new("scripted");
    cfg.max_cost_usd = Some(0.001);
    cfg.max_turns = 50;
    let out = run_scenario(
        ScriptedConnector::repeating(tool_call_response(0.01)),
        echo_dispatcher(),
        common::allow_cascade(),
        HookChain::new(),
        CancellationToken::new(),
        cfg,
    )
    .await;
    assert_eq!(
        out.reason,
        TerminalReason::MaxCostUsd,
        "cost cap → MaxCostUsd"
    );
    assert_eq!(out.turns, 1, "the over-cap response consumed one attempt");

    // 4. AbortedByOperator — a pre-cancelled token aborts before any call.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let out = run_scenario(
        ScriptedConnector::new(vec![response("final", 0.0)]),
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
        cancel,
        DriverConfig::new("scripted"),
    )
    .await;
    assert_eq!(
        out.reason,
        TerminalReason::AbortedByOperator,
        "cancel → AbortedByOperator"
    );
    assert_eq!(out.turns, 0, "pre-call cancellation consumes no turn");

    // 5. AbortedByHook — a pre-tool hook Stop aborts the tool turn.
    let mut hooks = HookChain::new();
    hooks.push(Arc::new(StopHook));
    let out = run_scenario(
        ScriptedConnector::repeating(tool_call_response(0.0)),
        echo_dispatcher(),
        common::allow_cascade(),
        hooks,
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    )
    .await;
    assert_eq!(
        out.reason,
        TerminalReason::AbortedByHook,
        "hook Stop → AbortedByHook"
    );
    assert_eq!(out.turns, 1, "the tool response consumed one attempt");

    // 6. PermissionDenied — a denying cascade layer refuses the tool call.
    let out = run_scenario(
        ScriptedConnector::repeating(tool_call_response(0.0)),
        echo_dispatcher(),
        PermissionCascade::new(vec![Arc::new(DenyLayer)]),
        HookChain::new(),
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    )
    .await;
    assert_eq!(
        out.reason,
        TerminalReason::PermissionDenied,
        "cascade Deny → PermissionDenied"
    );
    assert_eq!(out.turns, 1, "the tool response consumed one attempt");

    // 7. ContextWindowExhausted — an irreducible budget stops before any call.
    let mut cfg = DriverConfig::new("scripted");
    cfg.context_budget_chars = 4; // smaller than the task framing itself
    let out = run_scenario(
        ScriptedConnector::new(vec![response("final", 0.0)]),
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
        CancellationToken::new(),
        cfg,
    )
    .await;
    assert_eq!(
        out.reason,
        TerminalReason::ContextWindowExhausted,
        "irreducible budget → ContextWindowExhausted"
    );
    assert_eq!(out.turns, 0, "pre-call context rejection consumes no turn");

    // 8. ConnectorFatal — a transport error terminates the run.
    let out = run_scenario(
        ScriptedConnector::failing(),
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    )
    .await;
    assert_eq!(
        out.reason,
        TerminalReason::ConnectorFatal,
        "connector Err → ConnectorFatal"
    );
    assert_eq!(
        out.turns, 1,
        "a failed connector attempt still consumes a turn"
    );
}
