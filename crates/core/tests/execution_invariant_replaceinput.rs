//! Execution-invariant: the value a tool actually executes is the
//! cascade-mutated value, and the audit line records exactly that value.
//!
//! A `ReplaceInput` cascade layer rewrites `{"x":1}` → `{"x":2}`. The fused
//! executor revalidates that final payload and moves a private invocation
//! directly into the tool, so executed == mutated and audited == executed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::{Arc, Mutex};

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

use common::{response, tool_call_result, AllowLayer, ReplaceLayer, ScriptedConnector, SpyTool};

/// Read the single `pre` audit line's `input_hash` from `<dir>/audit.log`.
fn single_pre_input_hash(dir: &std::path::Path) -> String {
    let contents = std::fs::read_to_string(dir.join("audit.log")).expect("audit.log read failed");
    let pre: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is not JSON"))
        .filter(|l: &Value| l["phase"].as_str() == Some("decision"))
        .collect();
    assert_eq!(pre.len(), 1, "exactly one pre-tool audit line expected");
    pre[0]["input_hash"]
        .as_str()
        .expect("input_hash is a string")
        .to_string()
}

/// Blake3 of the compact JSON encoding, truncated to the audit's 16 hex chars.
fn audit_style_hash(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("serialize value");
    blake3::hash(&bytes).to_hex().as_str()[..16].to_string()
}

/// Build a driver whose cascade rewrites `{"x":1}` → `{"x":2}`, drive one tool
/// turn against the recording `SpyTool`, and return `(seen_value, audit_dir)`.
async fn drive_replace_turn() -> (Value, TempDir) {
    let dir = TempDir::new().expect("tempdir creation failed");

    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("spy", json!({ "x": 1 })), 0.0),
        response("finished", 0.0),
    ]);

    let seen = Arc::new(Mutex::new(None));
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(SpyTool::new(Arc::clone(&seen))))
        .expect("register spy tool");

    let cascade = PermissionCascade::new(vec![
        Arc::new(ReplaceLayer::new(json!({ "x": 1 }), json!({ "x": 2 }))),
        Arc::new(AllowLayer),
    ]);

    let audit = AuditLog::new(dir.path()).expect("audit log construction");
    let executor = CapabilityExecutor::new(dispatcher, cascade, HookChain::new(), audit);
    let cost = Arc::new(CostTracker::new());

    let driver = Driver::new(
        &connector,
        &executor,
        cost,
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    );
    let out = driver.run("mutate my input then run the tool").await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let value = seen
        .lock()
        .expect("spy lock")
        .clone()
        .expect("tool executed");
    (value, dir)
}

/// V-AC-1: the executed value is the `ReplaceInput`-mutated value, not the raw
/// input.
#[tokio::test]
async fn replaced_input_is_the_executed_input() {
    let (seen, _dir) = drive_replace_turn().await;
    assert_eq!(
        seen,
        json!({ "x": 2 }),
        "tool must execute the mutated value, never the raw {{\"x\":1}}"
    );
    assert_ne!(
        seen,
        json!({ "x": 1 }),
        "raw input must never reach the tool"
    );
}

/// V-AC-2: the audited hash equals the hash of the executed (mutated) value.
#[tokio::test]
async fn audited_hash_equals_executed_hash() {
    let (seen, dir) = drive_replace_turn().await;
    let audited = single_pre_input_hash(dir.path());
    let executed = audit_style_hash(&seen);
    assert_eq!(
        audited, executed,
        "audit decision hash must equal blake3 of the executed value"
    );
    // Guard against a false pass where both happen to hash the raw input.
    assert_ne!(
        audited,
        audit_style_hash(&json!({ "x": 1 })),
        "audit must not record the raw pre-cascade input"
    );
}
