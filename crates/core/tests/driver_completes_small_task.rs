//! V-AC-1 (D-REQ-01/05/08): `run()` drives a scripted small task
//! (tool-call turn → final turn) to `Terminal(Completed)` with ≥1 **real**
//! tool dispatch, fully offline via an in-crate scripted `ModelConnector`
//! double and a real `EchoTool` — no network, no DEVS, no `ARCANA_MC_TOKEN`.

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
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, EchoTool, ScriptedConnector};

#[tokio::test]
async fn driver_completes_small_task() {
    // Turn 1: the model asks for the echo tool. Turn 2: it answers.
    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("echo", json!({ "text": "world" })), 0.0),
        response("all done", 0.0),
    ]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo tool");
    let cascade = common::allow_cascade();
    let hooks = HookChain::new();
    let cost = Arc::new(CostTracker::new());

    let (executor, _audit_dir) = common::test_executor(dispatcher, cascade, hooks);
    let driver = Driver::new(
        &connector,
        &executor,
        cost,
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    );
    let out = driver.run("greet the world").await;

    // Reached the final answer.
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(out.final_text.as_deref(), Some("all done"));

    // Exactly one tool turn happened before the final answer.
    assert_eq!(out.turns, 2, "tool response + final response = two calls");

    // Two connector calls were made (offline, via the scripted double).
    let requests = connector.requests();
    assert_eq!(requests.len(), 2, "one call per turn");
    assert_eq!(
        out.cost.total_calls, 2,
        "both calls recorded in CostTracker"
    );

    // The real EchoTool actually ran: its output is folded into the 2nd call.
    assert!(
        requests[1].prompt.contains("echo:"),
        "2nd prompt must carry the real tool output, got: {}",
        requests[1].prompt
    );
}
