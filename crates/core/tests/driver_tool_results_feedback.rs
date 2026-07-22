//! V-AC-3 (D-REQ-03/05): the continue path. A tool turn folds the tool output
//! into the conversation history so the **next** `ExecuteRequest` carries it,
//! and the loop continues rather than terminating. A post-tool hook that
//! injects context takes the `HookContinuation` branch — observable as an
//! `[injected]` line in the next prompt.

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

use common::{response, tool_call_result, EchoTool, InjectHook, ScriptedConnector};

fn echo_dispatcher() -> ToolDispatcher {
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo tool");
    dispatcher
}

#[tokio::test]
async fn driver_tool_results_feedback() {
    // Turn 1: tool call carrying a unique marker; turn 2: final.
    let connector = ScriptedConnector::new(vec![
        response(
            &tool_call_result("echo", json!({ "text": "UNIQUE_MARKER" })),
            0.0,
        ),
        response("acknowledged", 0.0),
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
        cost,
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    );
    let out = driver.run("use the tool then answer").await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let requests = connector.requests();
    assert_eq!(requests.len(), 2, "the tool turn continued the loop");

    // History grew: the 1st prompt is only the task; the 2nd is strictly longer
    // and carries the folded-back tool result (the ToolResultsReady path).
    assert!(
        requests[1].prompt.len() > requests[0].prompt.len(),
        "history must grow across turns"
    );
    assert!(
        requests[1].prompt.contains("[tool_result]"),
        "2nd prompt must contain the tool result entry"
    );
    assert!(
        requests[1].prompt.contains("UNIQUE_MARKER"),
        "2nd prompt must carry the tool's output derived from the tool input"
    );
    // No injection happened → the plain ToolResultsReady path (no [injected]).
    assert!(
        !requests[1].prompt.contains("[injected]"),
        "no post-tool hook injected context in this scenario"
    );
}

#[tokio::test]
async fn driver_tool_results_feedback_hook_continuation() {
    // Same arc, but a post-tool hook injects a context line → HookContinuation,
    // observable as an [injected] entry folded into the next prompt.
    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("echo", json!({ "text": "x" })), 0.0),
        response("ok", 0.0),
    ]);
    let dispatcher = echo_dispatcher();
    let cascade = PermissionCascade::new(vec![]);
    let mut hooks = HookChain::new();
    hooks.push(Arc::new(InjectHook {
        line: "INJECTED_CTX_LINE".to_string(),
    }));
    let cost = Arc::new(CostTracker::new());

    let driver = Driver::new(
        &connector,
        &dispatcher,
        &cascade,
        &hooks,
        cost,
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    );
    let out = driver.run("use the tool then answer").await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let requests = connector.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1].prompt.contains("[injected] INJECTED_CTX_LINE"),
        "post-tool injected context must be folded into the next prompt"
    );
}
