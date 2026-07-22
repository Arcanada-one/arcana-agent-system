//! Hook subsystem — middleware around tool dispatch.
//!
//! A `HookChain` runs a sequence of `ToolHook` implementations before and
//! after each tool call. Hooks may permit, mutate, defer, or terminate the
//! call. Default hooks are wired in by the binary; the library exposes the
//! trait, the result enum, the shared context, and the chain orchestrator.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::cost::CostTracker;
use crate::tool::ToolOutput;

pub mod audit;
pub mod cost_budget;
pub mod ops_bot;

/// Recoverable failure surface emitted by a hook implementation.
#[derive(Debug, Error)]
pub enum HookError {
    /// Misuse of a phase-restricted variant (e.g. `ReplaceInput` in `post_tool`)
    /// or any unrecoverable internal error from a hook implementation.
    #[error("hook execution failed: {0}")]
    ExecutionFailed(String),
}

/// Decision returned by a hook for a given invocation.
///
/// Variants carry phase restrictions enforced by `HookChain`:
/// * `ReplaceInput` is valid only inside `pre_tool`.
/// * `InjectContext` is valid only inside `post_tool`.
/// * `Continue` and `StopExecution` are valid in either phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookResult {
    /// Pass-through; the chain advances to the next hook with the current input.
    Continue,
    /// Replace the input passed to subsequent hooks and the tool dispatcher.
    ReplaceInput(Value),
    /// Append a context string to be folded into the next agent turn.
    InjectContext(String),
    /// Halt the chain (and the surrounding dispatch) with an explanatory reason.
    StopExecution(String),
}

/// Shared context handed to every hook invocation.
///
/// The context is read-only to hooks; mutation of shared state happens
/// through the public API of the embedded handles (e.g. `CostTracker`).
pub struct HookContext {
    /// Cooperative cancellation signal observed by the chain between hooks.
    pub cancel: CancellationToken,
    /// Shared cost-accounting handle. Hooks read snapshots; the agent loop
    /// performs the writes.
    pub cost: Arc<CostTracker>,
}

impl HookContext {
    /// Construct a context with the given cancellation token and cost handle.
    #[must_use]
    pub fn new(cancel: CancellationToken, cost: Arc<CostTracker>) -> Self {
        Self { cancel, cost }
    }
}

/// A single hook participating in the dispatch chain.
#[async_trait]
pub trait ToolHook: Send + Sync {
    /// Invoked before the tool dispatcher executes a tool.
    ///
    /// # Errors
    ///
    /// Returns [`HookError::ExecutionFailed`] when the hook itself fails.
    async fn pre_tool(
        &self,
        ctx: &HookContext,
        tool: &str,
        input: &Value,
    ) -> Result<HookResult, HookError>;

    /// Invoked after the tool dispatcher produces an output.
    ///
    /// # Errors
    ///
    /// Returns [`HookError::ExecutionFailed`] when the hook itself fails.
    async fn post_tool(
        &self,
        ctx: &HookContext,
        tool: &str,
        output: &ToolOutput,
    ) -> Result<HookResult, HookError>;
}

/// Outcome of a `HookChain::pre_tool` traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreToolOutcome {
    /// All hooks passed; the dispatcher may proceed with the (possibly
    /// replaced) input.
    Proceed { input: Value },
    /// A hook or cancellation requested termination of this call.
    Stop { reason: String },
}

/// Outcome of a post-cascade `HookChain::pre_tool_gate` traversal.
///
/// Unlike [`PreToolOutcome`], this gate carries **no input**. Post-cascade
/// hooks may veto (`Stop`) or run side effects only; the permission cascade
/// is the sole input-transform authority. A post-cascade transform is
/// therefore unrepresentable — `Proceed` has no payload the executor could
/// route into execution in place of the cascade-authorized input:
///
/// ```compile_fail,E0559
/// use arcana_core::hooks::PreToolGate;
/// use serde_json::json;
///
/// let _ = PreToolGate::Proceed { input: json!({ "unsafe": true }) };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreToolGate {
    /// All hooks passed; execution proceeds with the cascade-authorized input.
    Proceed,
    /// A hook or cancellation requested termination of this call.
    Stop { reason: String },
}

/// Outcome of a `HookChain::post_tool` traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostToolOutcome {
    /// All hooks passed; collected context lines (possibly empty) are folded
    /// into the next agent turn.
    Proceed { injected: Vec<String> },
    /// A hook or cancellation requested termination.
    Stop { reason: String },
}

/// Ordered list of hooks executed around every tool call.
///
/// Hooks run in registration order. `ReplaceInput` mutates the input visible
/// to subsequent hooks and to the dispatcher. The first `StopExecution` short
/// circuits the chain. The cancellation token is sampled between hooks; once
/// cancelled, the chain returns `Stop { reason: "cancelled" }` without
/// invoking the remaining hooks.
#[derive(Default, Clone)]
pub struct HookChain {
    hooks: Vec<Arc<dyn ToolHook>>,
}

impl HookChain {
    /// Construct an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Append a hook to the end of the chain.
    pub fn push(&mut self, hook: Arc<dyn ToolHook>) {
        self.hooks.push(hook);
    }

    /// Number of registered hooks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// `true` when no hooks are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Run the pre-tool half of the chain.
    ///
    /// # Errors
    ///
    /// Propagates any [`HookError`] raised by a participating hook.
    pub async fn pre_tool(
        &self,
        ctx: &HookContext,
        tool: &str,
        input: &Value,
    ) -> Result<PreToolOutcome, HookError> {
        let mut current = input.clone();
        for hook in &self.hooks {
            if ctx.cancel.is_cancelled() {
                return Ok(PreToolOutcome::Stop {
                    reason: "cancelled".to_string(),
                });
            }
            match hook.pre_tool(ctx, tool, &current).await? {
                HookResult::Continue => {}
                HookResult::ReplaceInput(next) => {
                    current = next;
                }
                HookResult::InjectContext(_) => {
                    return Err(HookError::ExecutionFailed(
                        "InjectContext is not allowed in pre_tool".to_string(),
                    ));
                }
                HookResult::StopExecution(reason) => {
                    return Ok(PreToolOutcome::Stop { reason });
                }
            }
        }
        Ok(PreToolOutcome::Proceed { input: current })
    }

    /// Run the pre-tool half of the chain as a **post-cascade veto gate**.
    ///
    /// This is the entry point [`crate::execution::CapabilityExecutor`] uses
    /// *after* the permission cascade has already produced the authorized
    /// input. Hooks may pass through, veto (`StopExecution`), or fail — they
    /// may **not** transform the input. A `ReplaceInput` at this stage is a
    /// misconfiguration: input transforms must register as a cascade
    /// [`crate::permission::HookBridgeLayer`], where the downstream Rule and
    /// Interactive layers re-govern the mutated payload. The returned
    /// [`PreToolGate`] carries no input, so a post-cascade transform cannot be
    /// routed into execution even by mistake.
    ///
    /// # Errors
    ///
    /// Propagates any [`HookError`] raised by a participating hook, and raises
    /// [`HookError::ExecutionFailed`] if a hook returns `ReplaceInput`
    /// (unauthorized post-cascade transform) or `InjectContext` (pre-phase
    /// misuse).
    pub async fn pre_tool_gate(
        &self,
        ctx: &HookContext,
        tool: &str,
        input: &Value,
    ) -> Result<PreToolGate, HookError> {
        for hook in &self.hooks {
            if ctx.cancel.is_cancelled() {
                return Ok(PreToolGate::Stop {
                    reason: "cancelled".to_string(),
                });
            }
            match hook.pre_tool(ctx, tool, input).await? {
                HookResult::Continue => {}
                HookResult::StopExecution(reason) => {
                    return Ok(PreToolGate::Stop { reason });
                }
                HookResult::ReplaceInput(_) => {
                    return Err(HookError::ExecutionFailed(
                        "post-cascade hooks cannot transform input; register the \
                         transform as a cascade layer (HookBridge) instead"
                            .to_string(),
                    ));
                }
                HookResult::InjectContext(_) => {
                    return Err(HookError::ExecutionFailed(
                        "InjectContext is not allowed in pre_tool".to_string(),
                    ));
                }
            }
        }
        Ok(PreToolGate::Proceed)
    }

    /// Run the post-tool half of the chain.
    ///
    /// # Errors
    ///
    /// Propagates any [`HookError`] raised by a participating hook.
    pub async fn post_tool(
        &self,
        ctx: &HookContext,
        tool: &str,
        output: &ToolOutput,
    ) -> Result<PostToolOutcome, HookError> {
        let mut injected: Vec<String> = Vec::new();
        for hook in &self.hooks {
            if ctx.cancel.is_cancelled() {
                return Ok(PostToolOutcome::Stop {
                    reason: "cancelled".to_string(),
                });
            }
            match hook.post_tool(ctx, tool, output).await? {
                HookResult::Continue => {}
                HookResult::InjectContext(line) => injected.push(line),
                HookResult::ReplaceInput(_) => {
                    return Err(HookError::ExecutionFailed(
                        "ReplaceInput is not allowed in post_tool".to_string(),
                    ));
                }
                HookResult::StopExecution(reason) => {
                    return Ok(PostToolOutcome::Stop { reason });
                }
            }
        }
        Ok(PostToolOutcome::Proceed { injected })
    }
}
