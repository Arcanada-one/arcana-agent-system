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
        Ok(CapabilityOutput { output, injected })
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
            .map_err(|source| CapabilityError::AuditFailure {
                phase: AuditFailurePhase::Decision,
                source,
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
