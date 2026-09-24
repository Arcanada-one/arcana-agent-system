//! The contract's tool allowlist, as a permission layer.
//!
//! A contract-bound run may call the tools its KC2 contract admits and no
//! others. This layer is where that sentence becomes enforcement: it denies
//! any call whose tool is outside [`ContractBinding::allowlist`], and defers
//! on every call inside it so the layers that follow — the destructive-command
//! floor, the workspace boundary, the operator's own rules — still get their
//! say. Deny-or-defer, never allow: a contract widens nothing.
//!
//! Position in the cascade matters and is deliberate. It sits AFTER the schema
//! layer (a malformed call is a correction the model can act on, not a contract
//! violation) and BEFORE the floor and the boundary, so a tool the contract
//! never admitted is refused for that reason rather than for whatever else it
//! happened to trip.

use async_trait::async_trait;
use serde_json::Value;

use crate::contract::ContractBinding;

use super::{LayerDecision, PermissionLayer};

/// Deny every tool the bound contract does not admit.
#[derive(Debug, Clone)]
pub struct ContractAllowlistLayer {
    binding: ContractBinding,
}

impl ContractAllowlistLayer {
    #[must_use]
    pub fn new(binding: ContractBinding) -> Self {
        Self { binding }
    }
}

#[async_trait]
impl PermissionLayer for ContractAllowlistLayer {
    fn name(&self) -> &'static str {
        "contract-allowlist"
    }

    async fn evaluate(&self, tool: &str, _input: &Value) -> LayerDecision {
        if self.binding.admits(tool) {
            return LayerDecision::Defer;
        }
        let admitted = self
            .binding
            .allowlist()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        LayerDecision::Deny(format!(
            "`{tool}` is outside the allowlist of the contract this work item is bound to \
             ({digest}, allowlist from {source}). The contract admits: {admitted}. A run cannot \
             widen its own contract, so this is not a call to re-send in another shape.",
            digest = self.binding.digest(),
            source = self.binding.allowlist_source().as_str(),
        ))
    }
}
