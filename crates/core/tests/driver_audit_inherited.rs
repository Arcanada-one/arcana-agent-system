//! V-AC-7 (D-REQ-05/07): reuse-only + inherited audit. The driver adds no new
//! `Tool`/`PermissionLayer`/`ToolHook` in `src` (asserted by the grep in the
//! Validation Checklist); a driven tool turn produces the **existing**
//! `AuditHook`'s pre + post Blake3 lines with no audit code in the driver.

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
use arcana_core::hooks::audit::AuditHook;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, EchoTool, ScriptedConnector};

#[tokio::test]
async fn driver_audit_inherited() {
    let dir = TempDir::new().expect("tempdir creation failed");

    let connector = ScriptedConnector::new(vec![
        response(
            &tool_call_result("echo", json!({ "text": "audit-me" })),
            0.0,
        ),
        response("finished", 0.0),
    ]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo tool");
    let cascade = PermissionCascade::new(vec![]);

    // The unchanged AuditHook is the ONLY audit surface — the driver wires it
    // through the existing HookChain and writes no audit line itself.
    let audit = Arc::new(AuditHook::new(dir.path()).expect("audit hook construction"));
    let mut hooks = HookChain::new();
    hooks.push(audit.clone());
    let cost = Arc::new(CostTracker::new());

    {
        let driver = Driver::new(
            &connector,
            &dispatcher,
            &cascade,
            &hooks,
            cost,
            CancellationToken::new(),
            DriverConfig::new("scripted"),
        );
        let out = driver.run("do a thing that needs the tool").await;
        assert_eq!(out.reason, TerminalReason::Completed);
    }
    // Drop every AuditHook owner so the non-blocking WorkerGuard flushes.
    drop(hooks);
    drop(audit);

    let contents =
        std::fs::read_to_string(dir.path().join("audit.log")).expect("audit.log read failed");
    let lines: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is not JSON"))
        .collect();

    let pre: Vec<&Value> = lines
        .iter()
        .filter(|l| l["phase"].as_str() == Some("pre"))
        .collect();
    let post: Vec<&Value> = lines
        .iter()
        .filter(|l| l["phase"].as_str() == Some("post"))
        .collect();

    assert_eq!(pre.len(), 1, "exactly one inherited pre-tool audit line");
    assert_eq!(post.len(), 1, "exactly one inherited post-tool audit line");

    for record in [pre[0], post[0]] {
        assert_eq!(record["tool"].as_str(), Some("echo"));
        let hash = record["input_hash"]
            .as_str()
            .expect("input_hash is a string");
        assert_eq!(hash.len(), 16, "Blake3 input hash is 16 hex chars: {hash}");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "input_hash must be hex: {hash}"
        );
    }
}
