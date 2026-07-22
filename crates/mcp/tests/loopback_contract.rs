//! V-AC-10 (a)-(d): the extended MCP envelope over a real in-process handshake.
//!
//! An `ArcanaMcpServer` is served over a `tokio::io::duplex()` transport pair
//! and driven by a real rmcp client (`initialize` → `tools/list` → `tools/call`)
//! with zero sockets. Each test injects the cascade behaviour it needs via the
//! server's upstream layers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use arcana_core::permission::{LayerDecision, PermissionLayer};
use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use arcana_mcp::server::ArcanaMcpServer;
use async_trait::async_trait;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde_json::{Value, json};
use tempfile::TempDir;

// --- test tools -----------------------------------------------------------

struct EchoTool;

#[async_trait]
impl Tool for EchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn description(&self) -> &'static str {
        "Echo the input back as text."
    }
    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }
    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            content: invocation.into_input().to_string(),
            metadata: None,
        })
    }
}

struct ReplaceTool;

#[async_trait]
impl Tool for ReplaceTool {
    fn name(&self) -> &'static str {
        "replace"
    }
    fn description(&self) -> &'static str {
        "A second tool, used to prove tools/list carries the full set."
    }
    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }
    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            content: invocation.into_input().to_string(),
            metadata: None,
        })
    }
}

// --- test cascade layers --------------------------------------------------

struct AllowLayer;

#[async_trait]
impl PermissionLayer for AllowLayer {
    fn name(&self) -> &'static str {
        "test-allow"
    }
    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::Allow
    }
}

struct ReplaceThenAllow(Value);

#[async_trait]
impl PermissionLayer for ReplaceThenAllow {
    fn name(&self) -> &'static str {
        "test-replace"
    }
    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::ReplaceInput(self.0.clone())
    }
}

struct DeferLayer;

#[async_trait]
impl PermissionLayer for DeferLayer {
    fn name(&self) -> &'static str {
        "test-defer"
    }
    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::Defer
    }
}

struct DenyLayer;

#[async_trait]
impl PermissionLayer for DenyLayer {
    fn name(&self) -> &'static str {
        "test-deny"
    }
    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::Deny("test denial".to_owned())
    }
}

// --- harness --------------------------------------------------------------

fn tools() -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(EchoTool), Arc::new(ReplaceTool)]
}

/// Serve `server` over an in-process duplex pair and return a connected client.
async fn connect(
    server: ArcanaMcpServer,
) -> rmcp::service::RunningService<rmcp::service::RoleClient, ()> {
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_io).await.expect("client initialize")
}

fn call(name: &str, args: Value) -> CallToolRequestParams {
    let params = CallToolRequestParams::new(name.to_owned());
    match args {
        Value::Object(map) => params.with_arguments(map),
        _ => params,
    }
}

/// The `structured_content.arcana` extension object.
fn arcana(result: &CallToolResult) -> &Value {
    result
        .structured_content
        .as_ref()
        .expect("structured_content present")
        .get("arcana")
        .expect("arcana extension key")
}

/// Concatenate the text of every `content` block.
fn text_of(result: &CallToolResult) -> String {
    serde_json::to_value(&result.content)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|block| block.get("text").and_then(Value::as_str).map(str::to_owned))
        .collect::<String>()
}

/// The synchronous append-only audit log written under `dir` (empty if absent).
fn audit_text(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("audit.log")).unwrap_or_default()
}

/// Assert the ARAS-0033 invariant: exactly one Blake3 decision+result pair for a
/// single executed capability — one `Allowed` decision, one `success` result,
/// and the tool named in exactly those two lines. A double-audit regression
/// (e.g. a resume that re-runs the executor) pushes a count above its bound.
fn assert_one_audit_pair(log: &str, tool: &str) {
    assert_eq!(
        log.matches("\"decision\":\"Allowed\"").count(),
        1,
        "exactly one decision line per executed capability, got:\n{log}"
    );
    assert_eq!(
        log.matches("\"outcome\":\"success\"").count(),
        1,
        "exactly one success result line per executed capability, got:\n{log}"
    );
    assert_eq!(
        log.matches(&format!("\"tool\":\"{tool}\"")).count(),
        2,
        "one decision + one result, both naming the tool, got:\n{log}"
    );
}

// --- tests ----------------------------------------------------------------

#[tokio::test]
async fn tools_list_returns_registered_tool_set() {
    let tmp = TempDir::new().unwrap();
    let server = ArcanaMcpServer::new(
        tools(),
        vec![Arc::new(AllowLayer)],
        PathBuf::from(tmp.path()),
    );
    let client = connect(server).await;

    let listed = client.list_all_tools().await.expect("tools/list");
    let mut names: Vec<String> = listed.iter().map(|t| t.name.to_string()).collect();
    names.sort();

    assert_eq!(names, vec!["echo".to_owned(), "replace".to_owned()]);
    assert!(
        !names.iter().any(|n| n == "arcana.resume"),
        "the resume control tool must not be listed"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn tools_call_carries_effective_args() {
    let tmp = TempDir::new().unwrap();
    let server = ArcanaMcpServer::new(
        tools(),
        vec![Arc::new(AllowLayer)],
        PathBuf::from(tmp.path()),
    );
    let client = connect(server).await;

    let result = client
        .call_tool(call("echo", json!({ "msg": "hi" })))
        .await
        .expect("tools/call echo");
    let ext = arcana(&result);

    assert_eq!(ext["status"], json!("completed"));
    assert_eq!(ext["effective_args"], json!({ "msg": "hi" }));
    assert!(
        text_of(&result).contains("hi"),
        "content should carry the tool output, got: {}",
        text_of(&result)
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn replaceinput_rule_makes_effective_args_differ() {
    let tmp = TempDir::new().unwrap();
    let server = ArcanaMcpServer::new(
        tools(),
        vec![
            Arc::new(ReplaceThenAllow(json!({ "msg": "REDACTED" }))),
            Arc::new(AllowLayer),
        ],
        PathBuf::from(tmp.path()),
    );
    let client = connect(server).await;

    let result = client
        .call_tool(call("echo", json!({ "msg": "secret" })))
        .await
        .expect("tools/call echo");
    let ext = arcana(&result);

    assert_eq!(ext["effective_args"], json!({ "msg": "REDACTED" }));
    assert_ne!(ext["effective_args"], json!({ "msg": "secret" }));

    client.cancel().await.ok();
}

#[tokio::test]
async fn defer_suspends_and_resume_completes() {
    let tmp = TempDir::new().unwrap();
    let server = ArcanaMcpServer::new(
        tools(),
        vec![Arc::new(DeferLayer)],
        PathBuf::from(tmp.path()),
    );
    let client = connect(server).await;

    // Step 1 — Defer reaches the terminal SuspendLayer → InteractionRequired.
    let suspended = client
        .call_tool(call("echo", json!({ "msg": "hi" })))
        .await
        .expect("tools/call echo suspends");
    let ext = arcana(&suspended);
    assert_eq!(ext["status"], json!("interaction_required"));
    let token = ext["interaction_required"]["token"]
        .as_str()
        .expect("interaction token")
        .to_owned();
    assert!(!token.is_empty(), "resume token must be non-empty");

    // Step 2 — resume with "allow" → final output round-trips back.
    let resumed = client
        .call_tool(call(
            "arcana.resume",
            json!({ "token": token, "resolution": "allow" }),
        ))
        .await
        .expect("arcana.resume allow");
    let ext = arcana(&resumed);
    assert_eq!(ext["status"], json!("completed"));
    assert_eq!(ext["effective_args"], json!({ "msg": "hi" }));
    assert!(
        text_of(&resumed).contains("hi"),
        "resumed content should carry the real echo output"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn resume_with_replace_input_sets_effective_args() {
    let tmp = TempDir::new().unwrap();
    let server = ArcanaMcpServer::new(
        tools(),
        vec![Arc::new(DeferLayer)],
        PathBuf::from(tmp.path()),
    );
    let client = connect(server).await;

    let suspended = client
        .call_tool(call("echo", json!({ "msg": "hi" })))
        .await
        .expect("tools/call echo suspends");
    let token = arcana(&suspended)["interaction_required"]["token"]
        .as_str()
        .expect("interaction token")
        .to_owned();

    let resumed = client
        .call_tool(call(
            "arcana.resume",
            json!({ "token": token, "resolution": { "replace_input": { "msg": "R" } } }),
        ))
        .await
        .expect("arcana.resume replace_input");
    let ext = arcana(&resumed);

    assert_eq!(ext["status"], json!("completed"));
    assert_eq!(ext["effective_args"], json!({ "msg": "R" }));

    client.cancel().await.ok();
}

// --- N1: single-audit-line invariant (ARAS-0033) --------------------------

#[tokio::test]
async fn executed_capability_emits_exactly_one_audit_pair() {
    // Holds by construction on the MCP path but was unguarded by any MCP test
    // (QA finding N1). The interesting regression is a resume that re-runs the
    // executor and double-audits, so cover both entry paths: a direct Allow and
    // a Defer→resume round-trip must each leave exactly one decision+result pair.

    // (1) Direct Allow path.
    let direct = TempDir::new().unwrap();
    let client = connect(ArcanaMcpServer::new(
        tools(),
        vec![Arc::new(AllowLayer)],
        PathBuf::from(direct.path()),
    ))
    .await;
    client
        .call_tool(call("echo", json!({ "msg": "hi" })))
        .await
        .expect("tools/call echo");
    client.cancel().await.ok();
    assert_one_audit_pair(&audit_text(direct.path()), "echo");

    // (2) Defer → resume(allow): the executor runs exactly once across the
    // suspend/resume boundary — resume must not re-execute (and re-audit).
    let resumed = TempDir::new().unwrap();
    let client = connect(ArcanaMcpServer::new(
        tools(),
        vec![Arc::new(DeferLayer)],
        PathBuf::from(resumed.path()),
    ))
    .await;
    let suspended = client
        .call_tool(call("echo", json!({ "msg": "hi" })))
        .await
        .expect("tools/call echo suspends");
    let token = arcana(&suspended)["interaction_required"]["token"]
        .as_str()
        .expect("interaction token")
        .to_owned();
    client
        .call_tool(call(
            "arcana.resume",
            json!({ "token": token, "resolution": "allow" }),
        ))
        .await
        .expect("arcana.resume allow");
    client.cancel().await.ok();
    assert_one_audit_pair(&audit_text(resumed.path()), "echo");
}

// --- N2: an upstream Deny is not rescued by the trailing ProceedLayer ------

#[tokio::test]
async fn deny_is_not_rescued_by_proceed_layer() {
    // The `ProceedLayer` appended after the terminal `SuspendLayer` is always
    // Allow. A cascade `Deny` must NOT be converted to Allow by it. The property
    // currently holds only by short-circuit ordering (Deny returns before the
    // trailing layers are reached); this guards a future layer-reorder regression.
    let tmp = TempDir::new().unwrap();
    let server = ArcanaMcpServer::new(
        tools(),
        vec![Arc::new(DenyLayer)],
        PathBuf::from(tmp.path()),
    );
    let client = connect(server).await;

    let result = client
        .call_tool(call("echo", json!({ "msg": "hi" })))
        .await
        .expect("tools/call echo");
    let ext = arcana(&result);

    assert_eq!(
        ext["status"],
        json!("denied"),
        "an upstream Deny must surface as a denied envelope, not be rescued to completed"
    );
    assert_eq!(result.is_error, Some(true));

    let log = audit_text(tmp.path());
    assert_eq!(
        log.matches("\"outcome\":\"success\"").count(),
        0,
        "the tool must not execute when the cascade denies, got:\n{log}"
    );
    assert!(
        log.contains("\"decision\":\"Denied\""),
        "the denial must be audited, got:\n{log}"
    );

    client.cancel().await.ok();
}
