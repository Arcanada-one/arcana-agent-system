//! AC-4: AuditHook emits one JSON line per phase with the documented field
//! set `{ts, phase, tool, input_hash, decision}`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::match_wildcard_for_single_variants
)]

use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::hooks::audit::AuditHook;
use arcana_core::hooks::{HookContext, HookResult, ToolHook};
use arcana_core::tool::ToolOutput;
use serde_json::Value;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

fn ctx() -> HookContext {
    HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()))
}

#[tokio::test]
async fn audit_pre_writes_json_line_with_documented_fields() {
    let dir = TempDir::new().expect("tempdir creation failed");
    let hook = AuditHook::new(dir.path()).expect("audit hook construction failed");

    let result = hook
        .pre_tool(&ctx(), "read", &serde_json::json!({"path": "/etc/passwd"}))
        .await
        .expect("pre_tool returned an error");
    assert_eq!(result, HookResult::Continue);

    drop(hook); // flush WorkerGuard
    let contents =
        std::fs::read_to_string(dir.path().join("audit.log")).expect("audit.log read failed");
    let line = contents.lines().next().expect("audit.log is empty");
    let parsed: Value = serde_json::from_str(line).expect("audit line is not JSON");

    let object = parsed.as_object().expect("audit record is not an object");
    for field in ["ts", "phase", "tool", "input_hash", "decision"] {
        assert!(object.contains_key(field), "missing field: {field}");
    }
    assert_eq!(object["phase"].as_str(), Some("pre"));
    assert_eq!(object["tool"].as_str(), Some("read"));
    assert_eq!(object["decision"].as_str(), Some("Continue"));
    let hash = object["input_hash"]
        .as_str()
        .expect("input_hash is not a string");
    assert_eq!(hash.len(), 16, "input_hash is not 16 hex chars: {hash}");
}

#[tokio::test]
async fn audit_post_writes_distinct_phase_marker() {
    let dir = TempDir::new().expect("tempdir creation failed");
    let hook = AuditHook::new(dir.path()).expect("audit hook construction failed");

    let output = ToolOutput {
        content: "hello".to_string(),
        metadata: None,
    };
    hook.post_tool(&ctx(), "read", &output)
        .await
        .expect("post_tool returned an error");
    drop(hook);

    let contents =
        std::fs::read_to_string(dir.path().join("audit.log")).expect("audit.log read failed");
    let line = contents.lines().next().expect("audit.log is empty");
    let parsed: Value = serde_json::from_str(line).expect("audit line is not JSON");
    assert_eq!(parsed["phase"].as_str(), Some("post"));
}
