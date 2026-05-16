//! Permission cascade for tool dispatch.
//!
//! A cascade is an ordered chain of [`PermissionLayer`]s. Each layer returns
//! a [`LayerDecision`]; the cascade walks the chain and short-circuits on
//! the first concrete answer (`Allow` or `Deny`). A `ReplaceInput` decision
//! mutates the working payload before the next layer evaluates. Layers that
//! return `Defer` pass the responsibility on; if every layer defers, the
//! cascade resolves to `Allowed` with the most recent payload.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

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

/// Final outcome of running a payload through every layer in the cascade.
#[derive(Debug, Clone)]
pub enum CascadeOutcome {
    /// All gates passed; the payload (possibly mutated) is approved.
    Allowed { transformed_input: Value },
    /// A layer rejected the call.
    Denied { layer: &'static str, reason: String },
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
    /// chain is `Schema → PreHook → Rule → Interactive`.
    #[must_use]
    pub fn new(layers: Vec<Arc<dyn PermissionLayer>>) -> Self {
        Self { layers }
    }

    /// Walk the chain against `input` and return the cascade verdict.
    pub async fn evaluate(&self, tool: &str, input: Value) -> CascadeOutcome {
        let mut current = input;
        for layer in &self.layers {
            match layer.evaluate(tool, &current).await {
                LayerDecision::Allow => {
                    return CascadeOutcome::Allowed {
                        transformed_input: current,
                    };
                }
                LayerDecision::Deny(reason) => {
                    return CascadeOutcome::Denied {
                        layer: layer.name(),
                        reason,
                    };
                }
                LayerDecision::ReplaceInput(next) => {
                    current = next;
                }
                LayerDecision::Defer => {}
            }
        }
        CascadeOutcome::Allowed {
            transformed_input: current,
        }
    }
}
