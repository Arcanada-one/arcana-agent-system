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

/// The effect boundary has no authenticated, current-generation fence yet.
///
/// Gate-set: this refusal supplements the static tool allowlist and initial
/// point-in-time admission. It permits no effect. Authenticated revocation,
/// retry/resume fencing and a provider-free live executor remain unsupported.
/// A task claim, local contract file or operator permission rule cannot supply
/// the missing authority. Replace this gate only with a purpose-correct
/// authenticated protocol that fences authority through the actual effect.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("authenticated contract authority through the effect is unavailable")]
pub struct ContractEffectAuthorityUnavailable;

impl ContractEffectAuthorityUnavailable {
    #[must_use]
    pub const fn code(self) -> &'static str {
        "CONTRACT_EFFECT_AUTHORITY_UNAVAILABLE"
    }
}

/// Refuse before constructing a model client for a contract-bound run.
/// Initial admission alone is not an execution lease.
///
/// # Errors
///
/// Always returns the typed refusal until authenticated through-effect
/// authority is implemented. This is a closed gate, not a probe of a service.
pub fn require_contract_effect_authority() -> Result<(), ContractEffectAuthorityUnavailable> {
    Err(ContractEffectAuthorityUnavailable)
}

/// Deny contracted tool dispatch, including direct executor callers.
#[derive(Debug, Clone, Copy)]
pub struct ContractEffectAuthorityLayer;

#[async_trait]
impl PermissionLayer for ContractEffectAuthorityLayer {
    fn name(&self) -> &'static str {
        "contract-effect-authority"
    }

    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        let refusal = ContractEffectAuthorityUnavailable;
        LayerDecision::Deny(format!("{}: {refusal}", refusal.code()))
    }
}
