//! Shared offline test support: an allow-all cascade, a deterministic
//! `EchoTool`, a canned `ModelConnector`, and executor/context builders.
//!
//! Included via `mod common;` in several integration-test crates; not every
//! item is used by every crate, hence the blanket `dead_code` allow.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use std::path::Path;
use std::sync::Arc;

use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use arcana_core::cost::CostTracker;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::{HookChain, HookContext};
use arcana_core::permission::{LayerDecision, PermissionCascade, PermissionLayer};
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

/// A permission layer that approves every call. NOTE: an *empty* cascade
/// (`vec![]`) denies closed — no layer ever approves — so a run harness must
/// supply an explicit approving layer. (Corrects the plan's grounding note.)
pub struct AllowAllLayer;

#[async_trait]
impl PermissionLayer for AllowAllLayer {
    fn name(&self) -> &'static str {
        "allow-all"
    }
    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::Allow
    }
}

/// Deterministic tool that echoes its input back as the output content.
pub struct EchoTool;

#[async_trait]
impl Tool for EchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn description(&self) -> &'static str {
        "echoes its JSON input back as text (deterministic test tool)"
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

/// A `ModelConnector` that never touches the network: it echoes the requested
/// model id into `result` so a stage's routed model is observable in output.
pub struct FakeConnector;

#[async_trait]
impl ModelConnector for FakeConnector {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let model = req.model.clone().unwrap_or_else(|| "unset".to_owned());
        Ok(ConnectorResponse {
            id: "test-response".to_owned(),
            connector: req.connector,
            model: model.clone(),
            result: format!("echo:{model}"),
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
                total_tokens: 2,
                cost_usd: 0.0,
            },
            latency_ms: 0,
            status: "success".to_owned(),
            error: None,
        })
    }
}

/// Build an executor over the given tools with an allow-all cascade, an empty
/// hook chain, and a real `AuditLog` rooted at `audit_dir`.
pub fn executor_with(tools: Vec<Arc<dyn Tool>>, audit_dir: &Path) -> Arc<CapabilityExecutor> {
    let mut dispatcher = ToolDispatcher::new();
    for tool in tools {
        dispatcher.register(tool).expect("register test tool");
    }
    let cascade = PermissionCascade::new(vec![Arc::new(AllowAllLayer)]);
    let audit = AuditLog::new(audit_dir).expect("open audit log");
    Arc::new(CapabilityExecutor::new(
        dispatcher,
        cascade,
        HookChain::new(),
        audit,
    ))
}

/// A fresh hook context (new cancellation token + cost tracker).
pub fn hook_ctx() -> HookContext {
    HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()))
}
