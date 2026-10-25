//! Local admission cancellation, including the durable decision-write window.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arcana_core::cost::CostTracker;
use arcana_core::execution::{CapabilityError, CapabilityExecutor};
use arcana_core::hooks::audit::{AuditLog, DurableAuditWriter};
use arcana_core::hooks::{HookChain, HookContext, HookError, HookResult, ToolHook};
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

struct ProbeTool {
    cancel: CancellationToken,
    validations: AtomicUsize,
    calls: Arc<AtomicUsize>,
    cancel_validation: usize,
    cancel_in_tool: bool,
}

#[async_trait]
impl Tool for ProbeTool {
    fn name(&self) -> &'static str {
        "probe"
    }
    fn description(&self) -> &'static str {
        "counts actual invocations"
    }
    fn input_schema(&self) -> Value {
        json!({"type":"object"})
    }
    async fn validate_input(&self, _: &Value) -> Result<(), ToolError> {
        let ordinal = self.validations.fetch_add(1, Ordering::SeqCst) + 1;
        if ordinal == self.cancel_validation {
            self.cancel.cancel();
        }
        Ok(())
    }
    async fn execute(&self, _: ToolInvocation) -> Result<ToolOutput, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.cancel_in_tool {
            self.cancel.cancel();
        }
        Ok(ToolOutput {
            content: "effect completed".into(),
            metadata: None,
        })
    }
}

struct CancelHook;
#[async_trait]
impl ToolHook for CancelHook {
    async fn post_tool(
        &self,
        _: &HookContext,
        _: &str,
        _: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::Continue)
    }
    async fn pre_tool(
        &self,
        ctx: &HookContext,
        _: &str,
        _: &Value,
    ) -> Result<HookResult, HookError> {
        ctx.cancel.cancel();
        Ok(HookResult::Continue)
    }
}

struct Writer {
    bytes: Arc<Mutex<Vec<u8>>>,
    cancel_on_sync: Option<CancellationToken>,
    fail_sync: bool,
}
impl Write for Writer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl DurableAuditWriter for Writer {
    fn sync_data(&mut self) -> io::Result<()> {
        if let Some(token) = self.cancel_on_sync.take() {
            token.cancel();
        }
        if self.fail_sync {
            return Err(io::Error::other("injected sync failure"));
        }
        Ok(())
    }
}

struct Fixture {
    executor: CapabilityExecutor,
    ctx: HookContext,
    tool: Arc<ProbeTool>,
    bytes: Arc<Mutex<Vec<u8>>>,
}
impl Fixture {
    // Independent fault-injection switches; production has no such switches.
    #[allow(clippy::fn_params_excessive_bools)]
    fn new(validation: usize, hook: bool, sync: bool, fail: bool, in_tool: bool) -> Self {
        let token = CancellationToken::new();
        let tool = Arc::new(ProbeTool {
            cancel: token.clone(),
            validations: AtomicUsize::new(0),
            calls: Arc::new(AtomicUsize::new(0)),
            cancel_validation: validation,
            cancel_in_tool: in_tool,
        });
        let mut registry = ToolDispatcher::new();
        registry.register(tool.clone()).unwrap();
        let mut hooks = HookChain::new();
        if hook {
            hooks.push(Arc::new(CancelHook));
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Writer {
            bytes: bytes.clone(),
            cancel_on_sync: sync.then(|| token.clone()),
            fail_sync: fail,
        };
        let executor = CapabilityExecutor::new(
            registry,
            common::allow_cascade(),
            hooks,
            AuditLog::from_durable_writer(Box::new(writer)),
        );
        Self {
            executor,
            ctx: HookContext::new(token, Arc::new(CostTracker::new())),
            tool,
            bytes,
        }
    }
    async fn execute(&self) -> Result<arcana_core::execution::CapabilityOutput, CapabilityError> {
        self.executor.execute(&self.ctx, "probe", json!({})).await
    }
    fn records(&self) -> Vec<Value> {
        String::from_utf8(self.bytes.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn assert_cancelled(&self, decision: &str) {
        assert_eq!(
            self.tool.calls.load(Ordering::SeqCst),
            0,
            "cancelled attempt executed a tool"
        );
        let rows = self.records();
        assert_eq!(rows.len(), 2, "one decision and its terminal result");
        assert_eq!(rows[0]["decision"], decision);
        assert_eq!(rows[1]["outcome"], "cancelled");
        assert_eq!(rows[0]["invocation_id"], rows[1]["invocation_id"]);
    }
}

#[tokio::test]
async fn pre_cancelled_empty_hooks_refuse_before_validation() {
    let f = Fixture::new(0, false, false, false, false);
    f.ctx.cancel.cancel();
    assert!(matches!(f.execute().await, Err(CapabilityError::Cancelled)));
    assert_eq!(f.tool.validations.load(Ordering::SeqCst), 0);
    f.assert_cancelled("Denied");
    assert_eq!(f.records()[0]["layer"], "cancellation");
}

#[tokio::test]
async fn cancellation_in_last_hook_refuses_before_final_validation() {
    let f = Fixture::new(0, true, false, false, false);
    assert!(matches!(f.execute().await, Err(CapabilityError::Cancelled)));
    assert_eq!(f.tool.validations.load(Ordering::SeqCst), 1);
    f.assert_cancelled("Denied");
}

#[tokio::test]
async fn cancellation_in_final_validation_refuses_before_allowed_audit() {
    let f = Fixture::new(2, false, false, false, false);
    assert!(matches!(f.execute().await, Err(CapabilityError::Cancelled)));
    f.assert_cancelled("Denied");
}

#[tokio::test]
async fn cancellation_during_allowed_sync_closes_decision_without_tool() {
    let f = Fixture::new(0, false, true, false, false);
    assert!(matches!(f.execute().await, Err(CapabilityError::Cancelled)));
    f.assert_cancelled("Allowed");
}

#[tokio::test]
async fn cancellation_audit_failure_is_fatal_and_latches_closed() {
    let f = Fixture::new(0, false, false, true, false);
    f.ctx.cancel.cancel();
    assert!(matches!(
        f.execute().await,
        Err(CapabilityError::AuditFailure { .. })
    ));
    assert!(matches!(
        f.execute().await,
        Err(CapabilityError::AuditLatched)
    ));
    assert_eq!(f.tool.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn already_admitted_effect_keeps_its_result() {
    let f = Fixture::new(0, false, false, false, true);
    let result = f.execute().await.unwrap();
    assert_eq!(result.output.content, "effect completed");
    assert_eq!(f.tool.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.records()[1]["outcome"], "success");
}

#[tokio::test]
async fn fresh_turn_token_is_not_globally_cancelled() {
    let f = Fixture::new(0, false, false, false, false);
    f.ctx.cancel.cancel();
    assert!(matches!(f.execute().await, Err(CapabilityError::Cancelled)));
    let fresh = HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()));
    assert!(f.executor.execute(&fresh, "probe", json!({})).await.is_ok());
    assert_eq!(f.tool.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.records().len(), 4);
}

#[tokio::test]
async fn driver_reports_operator_abort_for_cancel_in_final_validation() {
    use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
    let f = Fixture::new(2, false, false, false, false);
    let connector = common::ScriptedConnector::new(vec![common::response(
        &common::tool_call_result("probe", json!({})),
        0.0,
    )]);
    let driver = Driver::new(
        &connector,
        &f.executor,
        Arc::new(CostTracker::new()),
        f.ctx.cancel.clone(),
        DriverConfig::new("scripted"),
    );
    let result = driver.run("run the probe").await;
    assert_eq!(result.reason, TerminalReason::AbortedByOperator);
    assert_eq!(result.tool_calls, 0);
    assert_eq!(result.tool_calls_attempted, 1);
    assert_eq!(connector.requests().len(), 1, "no retry after cancellation");
    assert_eq!(f.tool.calls.load(Ordering::SeqCst), 0);
    assert!(f.records().iter().any(|r| r["kind"] == "run_aborted"));
}
