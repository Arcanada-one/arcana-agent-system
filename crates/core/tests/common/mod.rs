//! Shared test doubles for the agent-loop driver integration tests.
//!
//! **These doubles deliberately live under `tests/` — never in `src` —** so
//! the V-AC-7 reuse grep over `crates/core/src/agent_loop*` stays empty. The
//! driver adds no new `Tool`/`PermissionLayer`/`ToolHook`; the impls below are
//! test-only edge doubles (`ScriptedConnector` mocks the network edge;
//! `EchoTool` is a *real* trivial tool so a genuine dispatch occurs;
//! `DenyLayer`/`StopHook`/`InjectHook` are edge doubles for the
//! deny/stop/inject causes).

#![allow(dead_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};

use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::HookChain;
use arcana_core::hooks::{HookContext, HookError, HookResult, ToolHook};
use arcana_core::permission::{LayerDecision, PermissionCascade, PermissionLayer};
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Response fixtures
// ---------------------------------------------------------------------------

/// Build a success [`ConnectorResponse`] carrying `result` text and `cost_usd`.
pub fn response(result: &str, cost_usd: f64) -> ConnectorResponse {
    ConnectorResponse {
        id: "scripted-id".to_string(),
        connector: "scripted".to_string(),
        model: "test-model".to_string(),
        result: result.to_string(),
        usage: Usage {
            input_tokens: 3,
            output_tokens: 5,
            total_tokens: 8,
            cost_usd,
        },
        latency_ms: 1,
        status: "success".to_string(),
        error: None,
        first_dispatch_observation: None,
    }
}

/// Render a `tool_call` fenced block the driver's `interpret` seam recognises.
pub fn tool_call_result(name: &str, input: Value) -> String {
    let payload = json!({ "name": name, "input": input });
    format!("```tool_call\n{payload}\n```")
}

/// Build a production-shaped executor with a private temporary audit log.
/// The returned directory must stay alive for the executor's lifetime.
pub fn test_executor(
    registry: ToolDispatcher,
    cascade: PermissionCascade,
    hooks: HookChain,
) -> (CapabilityExecutor, TempDir) {
    let dir = TempDir::new().expect("audit tempdir");
    let audit = AuditLog::new(dir.path()).expect("audit log");
    (
        CapabilityExecutor::new(registry, cascade, hooks, audit),
        dir,
    )
}

pub fn allow_cascade() -> PermissionCascade {
    PermissionCascade::new(vec![Arc::new(AllowLayer)])
}

// ---------------------------------------------------------------------------
// ScriptedConnector — mocks the network edge, records every request
// ---------------------------------------------------------------------------

/// One scripted turn: a canned success response, or a forced transport error.
enum Scripted {
    Ok(Box<ConnectorResponse>),
    Fail,
}

/// In-crate [`ModelConnector`] double: returns queued responses in order and
/// records each [`ExecuteRequest`] for later inspection. When the queue drains
/// and `repeat_last` is set, it re-emits the last success response (used to
/// drive turn/cost caps); otherwise a drained queue yields a transport error.
pub struct ScriptedConnector {
    queue: Mutex<VecDeque<Scripted>>,
    last: Mutex<Option<ConnectorResponse>>,
    requests: Mutex<Vec<ExecuteRequest>>,
    repeat_last: bool,
}

impl ScriptedConnector {
    /// Return each response once, in order; a drained queue errors.
    pub fn new(responses: Vec<ConnectorResponse>) -> Self {
        let queue = responses
            .into_iter()
            .map(|r| Scripted::Ok(Box::new(r)))
            .collect();
        Self {
            queue: Mutex::new(queue),
            last: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
            repeat_last: false,
        }
    }

    /// Always emit clones of `resp` (drives `MaxTurns` / `MaxCostUsd`).
    pub fn repeating(resp: ConnectorResponse) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            last: Mutex::new(Some(resp)),
            requests: Mutex::new(Vec::new()),
            repeat_last: true,
        }
    }

    /// First call returns a transport error (drives `ConnectorFatal`).
    pub fn failing() -> Self {
        let mut queue = VecDeque::new();
        queue.push_back(Scripted::Fail);
        Self {
            queue: Mutex::new(queue),
            last: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
            repeat_last: false,
        }
    }

    /// Every [`ExecuteRequest`] observed so far, in call order.
    pub fn requests(&self) -> Vec<ExecuteRequest> {
        self.requests.lock().expect("requests lock").clone()
    }
}

#[async_trait]
impl ModelConnector for ScriptedConnector {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.requests.lock().expect("requests lock").push(req);
        let next = self.queue.lock().expect("queue lock").pop_front();
        match next {
            Some(Scripted::Ok(resp)) => {
                *self.last.lock().expect("last lock") = Some((*resp).clone());
                Ok(*resp)
            }
            Some(Scripted::Fail) => Err(ConnectorError::Transport("scripted failure".to_string())),
            None => {
                if self.repeat_last {
                    if let Some(resp) = self.last.lock().expect("last lock").clone() {
                        return Ok(resp);
                    }
                }
                Err(ConnectorError::Transport(
                    "scripted queue exhausted".to_string(),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EchoTool — a REAL trivial tool (not a mock): a genuine dispatch occurs
// ---------------------------------------------------------------------------

/// Minimal real tool: returns its input echoed back as `content`. Registering
/// it lets the DoD driver drive ≥1 genuine tool dispatch fully offline.
pub struct EchoTool;

#[async_trait]
impl Tool for EchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "echoes its input back as content"
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        Ok(ToolOutput {
            content: format!("echo:{input}"),
            metadata: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Permission / hook edge doubles
// ---------------------------------------------------------------------------

/// Permission layer that always denies (drives `PermissionDenied`).
pub struct DenyLayer;

#[async_trait]
impl PermissionLayer for DenyLayer {
    fn name(&self) -> &'static str {
        "test-deny"
    }

    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::Deny("denied by test layer".to_string())
    }
}

/// Permission layer that explicitly allows. Production execution is
/// fail-closed when no layer gives a concrete answer, so happy-path tests must
/// opt in to this authority instead of relying on an empty cascade.
pub struct AllowLayer;

#[async_trait]
impl PermissionLayer for AllowLayer {
    fn name(&self) -> &'static str {
        "test-allow"
    }

    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::Allow
    }
}

/// Replaces a schema-valid payload with a schema-invalid payload. This pins
/// the executor's post-transform revalidation gate.
pub struct InvalidReplaceLayer;

#[async_trait]
impl PermissionLayer for InvalidReplaceLayer {
    fn name(&self) -> &'static str {
        "test-invalid-replace"
    }

    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::ReplaceInput(json!({ "value": "not-an-integer" }))
    }
}

/// Pre-tool hook that stops the chain (drives `AbortedByHook`).
pub struct StopHook;

#[async_trait]
impl ToolHook for StopHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::StopExecution(
            "stopped by test hook".to_string(),
        ))
    }

    async fn post_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::Continue)
    }
}

/// Pre-tool hook that attempts a post-cascade input transform. Registered in
/// the executor's own hook chain, this models a misconfigured hook trying to
/// mutate the payload *after* the cascade authorized it. The fused executor
/// must reject it fail-closed — the cascade is the sole transform authority.
pub struct ReplaceInputHook;

#[async_trait]
impl ToolHook for ReplaceInputHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::ReplaceInput(json!({ "value": "smuggled" })))
    }

    async fn post_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::Continue)
    }
}

/// Post-tool hook that injects a context line (drives `HookContinuation`).
pub struct InjectHook {
    pub line: String,
}

#[async_trait]
impl ToolHook for InjectHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::Continue)
    }

    async fn post_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::InjectContext(self.line.clone()))
    }
}

// ---------------------------------------------------------------------------
// SpyTool — records the exact Value it was asked to execute
// ---------------------------------------------------------------------------

/// Real tool that records the [`Value`] it received for execution. Lets the
/// execution-invariant tests assert the *executed* value equals the
/// cascade-mutated value (not the raw pre-cascade input).
pub struct SpyTool {
    seen: Arc<Mutex<Option<Value>>>,
}

/// Schema-constrained tool that increments an atomic counter per execution.
pub struct CountingTool {
    count: Arc<AtomicUsize>,
}

impl CountingTool {
    pub fn new(count: Arc<AtomicUsize>) -> Self {
        Self { count }
    }
}

#[async_trait]
impl Tool for CountingTool {
    fn name(&self) -> &'static str {
        "counting"
    }

    fn description(&self) -> &'static str {
        "counts executions"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["value"],
            "properties": { "value": { "type": "integer" } },
            "additionalProperties": false
        })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(ToolOutput {
            content: input.to_string(),
            metadata: None,
        })
    }
}

impl SpyTool {
    /// Construct a spy sharing `seen`; the test reads it after the run.
    pub fn new(seen: Arc<Mutex<Option<Value>>>) -> Self {
        Self { seen }
    }
}

#[async_trait]
impl Tool for SpyTool {
    fn name(&self) -> &'static str {
        "spy"
    }

    fn description(&self) -> &'static str {
        "records the value it was asked to execute"
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        *self.seen.lock().expect("spy lock") = Some(input.clone());
        Ok(ToolOutput {
            content: format!("spy:{input}"),
            metadata: None,
        })
    }
}

// ---------------------------------------------------------------------------
// ReplaceLayer — a cascade layer that mutates the input (ReplaceInput)
// ---------------------------------------------------------------------------

/// Permission layer that rewrites a matched `from` payload into `to`, modelling
/// a `ReplaceInput` rule (e.g. path sandboxing). Any other payload defers.
pub struct ReplaceLayer {
    from: Value,
    to: Value,
}

impl ReplaceLayer {
    /// Rewrite `from` → `to`; defer on any other input.
    pub fn new(from: Value, to: Value) -> Self {
        Self { from, to }
    }
}

#[async_trait]
impl PermissionLayer for ReplaceLayer {
    fn name(&self) -> &'static str {
        "test-replace"
    }

    async fn evaluate(&self, _tool: &str, input: &Value) -> LayerDecision {
        if input == &self.from {
            LayerDecision::ReplaceInput(self.to.clone())
        } else {
            LayerDecision::Defer
        }
    }
}

// ---------------------------------------------------------------------------
// NoopHook — a non-audit passthrough hook (Continue in both phases)
// ---------------------------------------------------------------------------

/// Benign non-audit hook: passes through in both phases. Used to build a
/// realistic, non-audit cascade chain that does NOT double-bridge the driver's
/// mandatory executor-owned audit sink.
pub struct NoopHook;

#[async_trait]
impl ToolHook for NoopHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::Continue)
    }

    async fn post_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::Continue)
    }
}
