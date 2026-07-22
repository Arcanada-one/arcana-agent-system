//! Audit conservation: exactly one pre + one post audit line per execution.
//!
//! The executor owns a concrete audit sink that is not a `ToolHook`, making a
//! second audit bridge structurally unavailable. One tool turn yields exactly
//! one correlated decision/result pair.

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
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, AllowLayer, EchoTool, NoopHook, ScriptedConnector};

/// V-AC-3: after one dispatch, the audit log carries exactly one `pre` and one
/// `post` line — no zero (silent execution), no double (audit noise).
#[tokio::test]
async fn exactly_one_pre_and_one_post_per_execution() {
    let dir = TempDir::new().expect("tempdir creation failed");

    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("echo", json!({ "text": "once" })), 0.0),
        response("finished", 0.0),
    ]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo tool");

    let cost = Arc::new(CostTracker::new());
    let cancel = CancellationToken::new();

    let cascade = PermissionCascade::new(vec![Arc::new(AllowLayer)]);
    let mut hooks = HookChain::new();
    hooks.push(Arc::new(NoopHook));
    let audit = AuditLog::new(dir.path()).expect("audit log construction");
    let executor = CapabilityExecutor::new(dispatcher, cascade, hooks, audit);

    let driver = Driver::new(
        &connector,
        &executor,
        Arc::clone(&cost),
        cancel,
        DriverConfig::new("scripted"),
    );
    let out = driver.run("run the tool exactly once").await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let contents =
        std::fs::read_to_string(dir.path().join("audit.log")).expect("audit.log read failed");
    let lines: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is not JSON"))
        .collect();

    let decision = lines
        .iter()
        .filter(|l| l["phase"].as_str() == Some("decision"))
        .count();
    let result = lines
        .iter()
        .filter(|l| l["phase"].as_str() == Some("result"))
        .count();

    assert_eq!(decision, 1, "exactly one decision audit record");
    assert_eq!(result, 1, "exactly one terminal result audit record");
}
