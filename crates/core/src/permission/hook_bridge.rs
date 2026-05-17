//! Layer 2: bridge from the cascade to the hook subsystem.
//!
//! Wraps a [`HookChain`] in [`PermissionLayer`] form. Pre-tool hooks may
//! permit, mutate, defer, or terminate the call; the bridge maps their
//! result onto cascade vocabulary:
//!
//! * `HookResult::Continue` (passthrough) → [`LayerDecision::Defer`].
//! * `HookResult::ReplaceInput(v)` → [`LayerDecision::ReplaceInput(v)`].
//! * `HookResult::StopExecution(reason)` → [`LayerDecision::Deny(reason)`].
//! * `HookResult::InjectContext` (pre-phase misuse) → `Deny` plus a
//!   `tracing::warn!` audit line; `HookChain` itself rejects this variant
//!   in pre-tool, so the bridge only sees it on internal-error paths.
//!
//! Cancellation observed by `HookChain` between hooks surfaces as a
//! `Stop { reason: "cancelled" }` outcome, which becomes `Deny("cancelled")`.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use super::{LayerDecision, PermissionLayer};
use crate::cost::CostTracker;
use crate::hooks::{HookChain, HookContext, PreToolOutcome};

/// Bridge that adapts a [`HookChain`] into the permission cascade.
pub struct HookBridgeLayer {
    chain: Arc<HookChain>,
    cancel: CancellationToken,
    cost: Arc<CostTracker>,
}

impl HookBridgeLayer {
    /// Construct a bridge over `chain`, sharing `cancel` and `cost` with the
    /// agent loop.
    #[must_use]
    pub fn new(chain: Arc<HookChain>, cancel: CancellationToken, cost: Arc<CostTracker>) -> Self {
        Self {
            chain,
            cancel,
            cost,
        }
    }
}

#[async_trait]
impl PermissionLayer for HookBridgeLayer {
    fn name(&self) -> &'static str {
        "hook_bridge"
    }

    async fn evaluate(&self, tool: &str, input: &Value) -> LayerDecision {
        let ctx = HookContext::new(self.cancel.clone(), Arc::clone(&self.cost));
        match self.chain.pre_tool(&ctx, tool, input).await {
            Ok(PreToolOutcome::Proceed { input: produced }) => {
                if &produced == input {
                    LayerDecision::Defer
                } else {
                    LayerDecision::ReplaceInput(produced)
                }
            }
            Ok(PreToolOutcome::Stop { reason }) => LayerDecision::Deny(reason),
            Err(err) => {
                tracing::warn!(target: "permission.hook_bridge", error = %err, tool, "hook chain raised error");
                LayerDecision::Deny(format!("hook error: {err}"))
            }
        }
    }
}
