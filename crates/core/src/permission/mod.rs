//! Permission cascade for tool dispatch.
//!
//! A cascade is an ordered chain of [`PermissionLayer`]s. Each layer returns
//! a [`LayerDecision`]; the cascade walks the chain and short-circuits on
//! the first concrete answer (`Allow` or `Deny`). A `ReplaceInput` decision
//! mutates the working payload before the next layer evaluates. Layers that
//! return `Defer` pass the responsibility on; if every layer defers, the
//! cascade denies closed because no authority approved the attempt.
//!
//! Canonical Phase 1 chain: `Schema → HookBridge → Rule → Interactive`.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

pub mod hook_bridge;
pub mod interactive;
pub mod rule;
pub mod schema;

pub use hook_bridge::HookBridgeLayer;
pub use interactive::{AutoFromEnv, InteractiveDirective, InteractiveLayer};
pub use rule::{RuleLayer, RuleLoadError};
pub use schema::SchemaLayer;

/// Verdict returned by a single layer.
#[derive(Debug, Clone)]
pub enum LayerDecision {
    /// Approve the call as-is and skip the remaining layers.
    Allow,
    /// Reject the call; carries an operator-facing reason.
    Deny(String),
    /// Approve, but mutate the payload before downstream consumers see it.
    ReplaceInput(Value),
    /// Make no statement; let the next layer decide.
    Defer,
}

/// Public decision-only outcome. The transformed input never escapes the
/// fused executor, so this type cannot be used as an execution capability.
#[derive(Debug, Clone)]
pub enum CascadeOutcome {
    /// A layer explicitly approved the call.
    Allowed {},
    /// A layer rejected the call.
    Denied { layer: &'static str, reason: String },
}

pub(crate) enum EvaluatedCapability {
    Allowed {
        transformed_input: Value,
    },
    Denied {
        layer: &'static str,
        reason: String,
        final_input: Value,
    },
}

/// Pluggable gate evaluated by [`PermissionCascade`].
#[async_trait]
pub trait PermissionLayer: Send + Sync {
    fn name(&self) -> &'static str;
    async fn evaluate(&self, tool: &str, input: &Value) -> LayerDecision;
}

/// Ordered chain of [`PermissionLayer`] gates.
#[derive(Clone)]
pub struct PermissionCascade {
    layers: Vec<Arc<dyn PermissionLayer>>,
}

impl PermissionCascade {
    /// Construct a cascade from an ordered layer list.
    ///
    /// The supplied order is the evaluation order. The canonical Phase 1
    /// chain is `Schema → HookBridge → Rule → Interactive`.
    #[must_use]
    pub fn new(layers: Vec<Arc<dyn PermissionLayer>>) -> Self {
        Self { layers }
    }

    /// Walk the chain and expose only its decision, never an executable token.
    pub async fn evaluate(&self, tool: &str, input: Value) -> CascadeOutcome {
        match self.evaluate_for_execution(tool, input).await {
            EvaluatedCapability::Allowed { .. } => CascadeOutcome::Allowed {},
            EvaluatedCapability::Denied { layer, reason, .. } => {
                CascadeOutcome::Denied { layer, reason }
            }
        }
    }

    pub(crate) async fn evaluate_for_execution(
        &self,
        tool: &str,
        input: Value,
    ) -> EvaluatedCapability {
        let mut current = input;
        for layer in &self.layers {
            match layer.evaluate(tool, &current).await {
                LayerDecision::Allow => {
                    return EvaluatedCapability::Allowed {
                        transformed_input: current,
                    };
                }
                LayerDecision::Deny(reason) => {
                    return EvaluatedCapability::Denied {
                        layer: layer.name(),
                        reason,
                        final_input: current,
                    };
                }
                LayerDecision::ReplaceInput(next) => {
                    current = next;
                }
                LayerDecision::Defer => {}
            }
        }
        EvaluatedCapability::Denied {
            layer: "cascade",
            reason: "no permission layer explicitly allowed the capability".to_owned(),
            final_input: current,
        }
    }
}
