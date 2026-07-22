//! V-AC-4 (D-REQ-04): the context-window guard. An oversized history compacts
//! by trimming oldest tool-result payloads and reports
//! `Microcompacted`/`ReactiveCompacted` (mapped to the `MicrocompactCompleted`
//! / `ReactiveCompactRetry` continue reasons); an irreducible history reports
//! `Irreducible` (mapped to `Terminal(ContextWindowExhausted)` by the driver).
//! The `Task` framing is never trimmed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{
    compaction_continue, guard_context, ContextVerdict, ContinueReason, Driver, DriverConfig,
    HistoryEntry, TerminalReason,
};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, EchoTool, ScriptedConnector};

fn tool_result(content_len: usize) -> HistoryEntry {
    HistoryEntry::ToolResult {
        name: "echo".to_string(),
        content: "A".repeat(content_len),
    }
}

#[test]
fn driver_context_window() {
    // Within budget → Ok, history untouched.
    let mut fits = vec![HistoryEntry::Task("small".to_string())];
    assert_eq!(guard_context(&mut fits, 1_000), ContextVerdict::Ok);
    assert_eq!(fits.len(), 1, "Ok must not mutate history");

    // One oversized tool-result, a single trim suffices → Microcompacted.
    let mut single = vec![HistoryEntry::Task("t".to_string()), tool_result(200)];
    assert_eq!(
        guard_context(&mut single, 100),
        ContextVerdict::Microcompacted
    );
    assert_eq!(single.len(), 1, "the tool-result was trimmed");
    assert!(
        matches!(single[0], HistoryEntry::Task(_)),
        "Task framing is never trimmed"
    );

    // Two oversized tool-results, both must be trimmed → ReactiveCompacted.
    let mut multi = vec![
        HistoryEntry::Task("t".to_string()),
        tool_result(200),
        tool_result(200),
    ];
    assert_eq!(
        guard_context(&mut multi, 100),
        ContextVerdict::ReactiveCompacted
    );
    assert!(
        matches!(multi.as_slice(), [HistoryEntry::Task(_)]),
        "only the Task framing survives"
    );

    // Irreducible: the Task alone still overflows and nothing is trimmable.
    let mut irreducible = vec![HistoryEntry::Task("a long task framing string".to_string())];
    assert_eq!(
        guard_context(&mut irreducible, 4),
        ContextVerdict::Irreducible
    );
    assert_eq!(irreducible.len(), 1, "Task is never removed");

    // Verdict → ContinueReason mapping the driver uses.
    assert_eq!(
        compaction_continue(ContextVerdict::Microcompacted),
        Some(ContinueReason::MicrocompactCompleted)
    );
    assert_eq!(
        compaction_continue(ContextVerdict::ReactiveCompacted),
        Some(ContinueReason::ReactiveCompactRetry)
    );
    assert_eq!(compaction_continue(ContextVerdict::Ok), None);
    assert_eq!(compaction_continue(ContextVerdict::Irreducible), None);
}

#[tokio::test]
async fn driver_context_window_irreducible_terminates() {
    // End-to-end: a budget below the task framing terminates before any call.
    let connector = ScriptedConnector::new(vec![response("unused", 0.0)]);
    let dispatcher = ToolDispatcher::new();
    let cascade = PermissionCascade::new(vec![]);
    let hooks = HookChain::new();
    let cost = Arc::new(CostTracker::new());
    let mut config = DriverConfig::new("scripted");
    config.context_budget_chars = 4;

    let driver = Driver::new(
        &connector,
        &dispatcher,
        &cascade,
        &hooks,
        cost,
        CancellationToken::new(),
        config,
    );
    let out = driver
        .run("a task that will not fit in four characters")
        .await;

    assert_eq!(out.reason, TerminalReason::ContextWindowExhausted);
    assert!(
        connector.requests().is_empty(),
        "irreducible budget must terminate before any connector call"
    );
}

#[tokio::test]
async fn driver_compaction_consumes_no_turn() {
    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("echo", json!({ "text": "x" })), 0.0),
        response("done", 0.0),
    ]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo");
    let cascade = PermissionCascade::new(vec![]);
    let hooks = HookChain::new();
    let cost = Arc::new(CostTracker::new());
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 2;
    // The first request fits. After the tool turn, trimming the tool result
    // brings history below this ceiling and forces one compaction re-loop.
    config.context_budget_chars = 110;

    let driver = Driver::new(
        &connector,
        &dispatcher,
        &cascade,
        &hooks,
        cost,
        CancellationToken::new(),
        config,
    );
    let out = driver.run("x").await;

    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(out.turns, 2, "only the two connector attempts count");
    let requests = connector.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        !requests[1].prompt.contains("echo:"),
        "the tool result must have been compacted before the second call"
    );
}
