//! Fused, fail-closed capability execution boundary.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde_json::Value;
use thiserror::Error;

use crate::hooks::audit::{AuditHookError, AuditLog};
use crate::hooks::{HookChain, HookContext, PostToolOutcome, PreToolGate};
use crate::permission::{EvaluatedCapability, PermissionCascade};
use crate::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};

struct PreparedInvocation {
    id: u64,
    tool: std::sync::Arc<dyn Tool>,
    input: Value,
}

/// Which durable audit append failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFailurePhase {
    Decision,
    Result,
}

/// Fatal or denied capability attempt.
#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("capability denied at {layer}: {reason}")]
    Denied { layer: &'static str, reason: String },
    #[error("capability hook aborted execution")]
    HookAborted,
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error("audit {phase:?} append failed: {source}")]
    AuditFailure {
        phase: AuditFailurePhase,
        #[source]
        source: AuditHookError,
    },
    #[error("capability executor is latched closed after audit failure")]
    AuditLatched,
}

/// Successful tool output plus context emitted by post-tool hooks.
#[derive(Debug)]
pub struct CapabilityOutput {
    pub output: ToolOutput,
    pub injected: Vec<String>,
    /// The exact input the tool executed on: the cascade-authorized value
    /// after any `ReplaceInput` transform (equal to the raw input when no
    /// layer transformed it). Read-only surfacing of the already-audited
    /// `transformed_input` so an out-of-crate adapter (e.g. the MCP seam)
    /// can report `effective_args` without re-running the cascade.
    pub effective_input: Value,
}

/// The sole execution authority for registered tools.
///
/// Registration is frozen at construction. The executor owns the cascade,
/// non-audit hooks, and mandatory audit log; no component can be omitted from
/// an execution attempt or composed twice by callers.
pub struct CapabilityExecutor {
    registry: ToolDispatcher,
    cascade: PermissionCascade,
    hooks: HookChain,
    audit: AuditLog,
    next_invocation_id: AtomicU64,
    audit_latched: AtomicBool,
}

impl CapabilityExecutor {
    #[must_use]
    pub fn new(
        registry: ToolDispatcher,
        cascade: PermissionCascade,
        hooks: HookChain,
        audit: AuditLog,
    ) -> Self {
        Self {
            registry,
            cascade,
            hooks,
            audit,
            next_invocation_id: AtomicU64::new(1),
            audit_latched: AtomicBool::new(false),
        }
    }

    /// Append an agent-run lifecycle record to the executor's audit sink.
    ///
    /// The audit log is owned by this executor and deliberately has no public
    /// accessor: exposing the sink would let a caller compose a second,
    /// unaudited execution path, which is the exact failure this type exists
    /// to prevent. This narrow method instead lets the agent loop record what
    /// happened to a RUN — the tool-level `decision`/`result` pair already
    /// covers what happened to a CAPABILITY.
    ///
    /// Honours the audit latch: once a durable append has failed, nothing more
    /// is written, so an abort record can never be the one line that appears
    /// after the log stopped being trustworthy.
    ///
    /// # Errors
    ///
    /// Returns [`AuditHookError`] when the executor is latched closed or the
    /// append does not reach the backing store.
    pub fn record_run_event(&self, kind: &str, fields: &Value) -> Result<(), AuditHookError> {
        if self.audit_latched.load(Ordering::Acquire) {
            return Err(AuditHookError::WriteFailed(std::io::Error::other(
                "capability executor is latched closed after audit failure",
            )));
        }
        self.audit.record_run_event(kind, fields)
    }

    /// Authorize, validate, audit, and execute one capability attempt.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError`] when authorization, validation, hooks, the
    /// tool, or either mandatory audit append fails.
    pub async fn execute(
        &self,
        ctx: &HookContext,
        tool_name: &str,
        raw_input: Value,
    ) -> Result<CapabilityOutput, CapabilityError> {
        let prepared = self.prepare(ctx, tool_name, raw_input).await?;
        self.invoke(ctx, tool_name, prepared).await
    }

    async fn prepare(
        &self,
        ctx: &HookContext,
        tool_name: &str,
        raw_input: Value,
    ) -> Result<PreparedInvocation, CapabilityError> {
        if self.audit_latched.load(Ordering::Acquire) {
            return Err(CapabilityError::AuditLatched);
        }
        let id = self.next_invocation_id.fetch_add(1, Ordering::Relaxed);
        let Some(tool) = self.registry.get(tool_name) else {
            return self.deny(id, tool_name, &raw_input, "registry", "unknown tool");
        };
        if let Err(err) = tool.validate_input(&raw_input).await {
            return self.deny(id, tool_name, &raw_input, "schema", &err.to_string());
        }
        let cascade_input = self.cascade_input(id, tool_name, raw_input).await?;
        // Post-cascade hooks are a veto/side-effect gate only: the cascade is
        // the sole input-transform authority, so the executed value is always
        // the cascade-authorized `cascade_input` — never a hook substitution.
        self.hook_gate(ctx, id, tool_name, &cascade_input).await?;
        if let Err(err) = tool.validate_input(&cascade_input).await {
            return self.deny(id, tool_name, &cascade_input, "schema", &err.to_string());
        }
        Ok(PreparedInvocation {
            id,
            tool,
            input: cascade_input,
        })
    }

    async fn cascade_input(
        &self,
        id: u64,
        tool_name: &str,
        raw_input: Value,
    ) -> Result<Value, CapabilityError> {
        match self
            .cascade
            .evaluate_for_execution(tool_name, raw_input)
            .await
        {
            EvaluatedCapability::Allowed { transformed_input } => Ok(transformed_input),
            EvaluatedCapability::Denied {
                layer,
                reason,
                final_input,
            } => self.deny(id, tool_name, &final_input, layer, &reason),
        }
    }

    /// Run the executor-owned post-cascade hooks as a veto/side-effect gate.
    ///
    /// The gate cannot transform the input: [`HookChain::pre_tool_gate`]
    /// returns a [`PreToolGate`] with no input field, so the only outcomes are
    /// proceed (with the cascade-authorized input untouched) or abort. A hook
    /// that attempts a post-cascade `ReplaceInput` surfaces as a hook error and
    /// aborts fail-closed.
    async fn hook_gate(
        &self,
        ctx: &HookContext,
        id: u64,
        tool_name: &str,
        input: &Value,
    ) -> Result<(), CapabilityError> {
        match self.hooks.pre_tool_gate(ctx, tool_name, input).await {
            Ok(PreToolGate::Proceed) => Ok(()),
            Ok(PreToolGate::Stop { reason }) => self.abort_hook(id, tool_name, input, &reason),
            Err(_) => self.abort_hook(id, tool_name, input, "hook error"),
        }
    }

    async fn invoke(
        &self,
        ctx: &HookContext,
        tool_name: &str,
        prepared: PreparedInvocation,
    ) -> Result<CapabilityOutput, CapabilityError> {
        self.audit_decision(
            prepared.id,
            tool_name,
            &prepared.input,
            "Allowed",
            "cascade",
        )?;
        // Capture the cascade-authorized input before it is moved into the
        // sealed invocation; this is the value the tool actually executes on.
        let effective_input = prepared.input.clone();
        let output = match prepared
            .tool
            .execute(ToolInvocation::new(prepared.input))
            .await
        {
            Ok(output) => output,
            Err(err) => {
                self.audit_result(prepared.id, tool_name, "tool_error", None)?;
                return Err(CapabilityError::Tool(err));
            }
        };
        let injected = match self.hooks.post_tool(ctx, tool_name, &output).await {
            Ok(PostToolOutcome::Proceed { injected }) => injected,
            Ok(PostToolOutcome::Stop { .. }) | Err(_) => {
                self.audit_result(prepared.id, tool_name, "hook_error", Some(&output))?;
                return Err(CapabilityError::HookAborted);
            }
        };
        self.audit_result(prepared.id, tool_name, "success", Some(&output))?;
        Ok(CapabilityOutput {
            output,
            injected,
            effective_input,
        })
    }

    fn deny<T>(
        &self,
        invocation_id: u64,
        tool: &str,
        input: &Value,
        layer: &'static str,
        reason: &str,
    ) -> Result<T, CapabilityError> {
        self.audit_decision(invocation_id, tool, input, "Denied", layer)?;
        self.audit_result(invocation_id, tool, "denied", None)?;
        Err(CapabilityError::Denied {
            layer,
            reason: reason.to_owned(),
        })
    }

    fn abort_hook<T>(
        &self,
        invocation_id: u64,
        tool: &str,
        input: &Value,
        _reason: &str,
    ) -> Result<T, CapabilityError> {
        self.audit_decision(invocation_id, tool, input, "Denied", "hook")?;
        self.audit_result(invocation_id, tool, "hook_aborted", None)?;
        Err(CapabilityError::HookAborted)
    }

    fn audit_decision(
        &self,
        invocation_id: u64,
        tool: &str,
        input: &Value,
        decision: &str,
        layer: &str,
    ) -> Result<(), CapabilityError> {
        self.audit
            .record_decision(invocation_id, tool, input, decision, layer)
            .map_err(|source| {
                self.audit_latched.store(true, Ordering::Release);
                CapabilityError::AuditFailure {
                    phase: AuditFailurePhase::Decision,
                    source,
                }
            })
    }

    fn audit_result(
        &self,
        invocation_id: u64,
        tool: &str,
        outcome: &str,
        output: Option<&ToolOutput>,
    ) -> Result<(), CapabilityError> {
        self.audit
            .record_result(invocation_id, tool, outcome, output)
            .map_err(|source| {
                self.audit_latched.store(true, Ordering::Release);
                CapabilityError::AuditFailure {
                    phase: AuditFailurePhase::Result,
                    source,
                }
            })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde_json::json;
    use tokio_util::sync::CancellationToken;

    use crate::cost::CostTracker;
    use crate::permission::{LayerDecision, PermissionCascade, PermissionLayer};

    struct EchoTool;

    #[async_trait]
    impl Tool for EchoTool {
        fn name(&self) -> &'static str {
            "t"
        }
        fn description(&self) -> &'static str {
            "echoes its input back as text"
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

    struct ReplaceLayer(Value);

    #[async_trait]
    impl PermissionLayer for ReplaceLayer {
        fn name(&self) -> &'static str {
            "replace"
        }
        async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
            LayerDecision::ReplaceInput(self.0.clone())
        }
    }

    struct AllowLayer;

    #[async_trait]
    impl PermissionLayer for AllowLayer {
        fn name(&self) -> &'static str {
            "allow"
        }
        async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
            LayerDecision::Allow
        }
    }

    #[tokio::test]
    async fn execute_surfaces_replaceinput_transformed_input() {
        let tmp = tempfile::tempdir().unwrap();
        let mut dispatcher = ToolDispatcher::new();
        dispatcher.register(Arc::new(EchoTool)).unwrap();
        let cascade = PermissionCascade::new(vec![
            Arc::new(ReplaceLayer(json!({ "x": 2 }))),
            Arc::new(AllowLayer),
        ]);
        let audit = AuditLog::new(tmp.path()).unwrap();
        let executor = CapabilityExecutor::new(dispatcher, cascade, HookChain::new(), audit);
        let ctx = HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()));

        let out = executor
            .execute(&ctx, "t", json!({ "x": 1 }))
            .await
            .unwrap();

        assert_eq!(out.effective_input, json!({ "x": 2 }));
        assert_ne!(out.effective_input, json!({ "x": 1 }));
    }
}
