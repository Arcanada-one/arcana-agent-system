//! Work-item admission is distinct from hashing contract bytes.
//!
//! The provider and trust configuration belong to the trusted composition root,
//! never to a contract, command-line flag, task payload or environment override.
//! This follows KC2's trusted-provider boundary, but is a task-run consumer port,
//! not an implementation of its promotion-only authority protocol. Production
//! task-read mapping is absent; the shipped provider fails closed.
//! Admission is point-in-time. It does not implement an effect-time revocation
//! fence, consume a nonce, or grant a reservation, billing or provider capability.

use async_trait::async_trait;
use std::future::Future;

use crate::contract::ContractBinding;

/// Expected scope from authenticated caller/control-plane context.
/// Task revision and contract JSON are not an authenticated subject or epoch.
#[derive(Debug, Clone)]
pub struct WorkItemScope {
    pub task_id: String,
    pub project_id: Option<String>,
    pub subject_id: Option<String>,
}

/// Trusted issuer configuration. No default issuer or audience is invented.
pub struct AuthorityTrust {
    pub issuer: String,
    pub audience: String,
    pub verifier_pin: String,
}

/// Output of a purpose-correct Auth/KC verifier, NOT deserializable claims.
/// The adapter must authenticate the contract digest and all scope fields,
/// resolve issuer standing and principal/incarnation lineage independently,
/// and read current revocation/generation state in that same authority domain.
/// Public fields permit adapters to implement this port; only the trusted
/// composition root may supply one. Synthetic adapters prove predicates only.
pub struct AuthenticatedContractAuthority {
    pub contract_digest: String,
    pub task_id: String,
    pub project_id: String,
    pub subject_id: String,
    pub issuer: String,
    pub audience: String,
    pub verifier_pin: String,
    pub issuer_principal: String,
    pub issuer_incarnation: String,
    pub proposer_lineage: Vec<String>,
    pub executor_lineage: Vec<String>,
    pub signature_verified: bool,
    pub standing_verified: bool,
    pub issued_generation: u64,
    pub current_generation: Option<u64>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityRefusal {
    #[error("CONTRACT_SUBJECT_MISMATCH: contract task/project/subject does not match this run")]
    SubjectMismatch,
    #[error(
        "CONTRACT_ISSUER_UNVERIFIED: issuer signature, standing or trusted binding is unverified"
    )]
    IssuerUnverified,
    #[error("CONTRACT_ISSUER_NOT_INDEPENDENT: issuer belongs to proposer/executor lineage")]
    IssuerNotIndependent,
    #[error(
        "CONTRACT_REVOKED: contract authority is revoked or its generation is no longer current"
    )]
    Revoked,
    #[error("CONTRACT_AUTHORITY_UNAVAILABLE: authenticated task-run authority/current generation is unavailable")]
    Unavailable,
}

impl AuthorityRefusal {
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::SubjectMismatch => "CONTRACT_SUBJECT_MISMATCH",
            Self::IssuerUnverified => "CONTRACT_ISSUER_UNVERIFIED",
            Self::IssuerNotIndependent => "CONTRACT_ISSUER_NOT_INDEPENDENT",
            Self::Revoked => "CONTRACT_REVOKED",
            Self::Unavailable => "CONTRACT_AUTHORITY_UNAVAILABLE",
        }
    }
}

#[async_trait]
pub trait ContractAuthorityProvider: Send + Sync {
    /// Authenticate exact digest/scope and resolve current authority state.
    /// Never echo document claims into an authenticated proof. Errors must be
    /// typed and sanitized; provider credentials must not enter diagnostics.
    async fn authenticate(
        &self,
        binding: &ContractBinding,
        scope: &WorkItemScope,
    ) -> Result<AuthenticatedContractAuthority, AuthorityRefusal>;
}

/// Production default until the existing Auth/KC owners publish a task-run
/// instrument and its authentic verification/current-generation interface.
pub struct UnavailableContractAuthority;

#[async_trait]
impl ContractAuthorityProvider for UnavailableContractAuthority {
    async fn authenticate(
        &self,
        _binding: &ContractBinding,
        _scope: &WorkItemScope,
    ) -> Result<AuthenticatedContractAuthority, AuthorityRefusal> {
        Err(AuthorityRefusal::Unavailable)
    }
}

/// Only admission constructs this token. A digest-only binding cannot call
/// the work-item continuation. This is not a transferable/live effect lease.
pub struct AdmittedContract {
    binding: ContractBinding,
}

impl AdmittedContract {
    #[must_use]
    pub fn binding(&self) -> &ContractBinding {
        &self.binding
    }
}

fn qualify(
    binding: &ContractBinding,
    scope: &WorkItemScope,
    trust: Option<&AuthorityTrust>,
    proof: &AuthenticatedContractAuthority,
) -> Result<(), AuthorityRefusal> {
    let trust = trust.ok_or(AuthorityRefusal::Unavailable)?;
    let project = scope.project_id.as_deref().filter(|v| !v.is_empty());
    let subject = scope.subject_id.as_deref().filter(|v| !v.is_empty());
    let (Some(project), Some(subject)) = (project, subject) else {
        return Err(AuthorityRefusal::Unavailable);
    };
    if !proof.signature_verified
        || !proof.standing_verified
        || proof.issuer_principal.is_empty()
        || proof.issuer_incarnation.is_empty()
        || trust.issuer.is_empty()
        || trust.audience.is_empty()
        || trust.verifier_pin.is_empty()
        || proof.issuer != trust.issuer
        || proof.audience != trust.audience
        || proof.verifier_pin != trust.verifier_pin
        || proof.contract_digest != binding.digest()
    {
        return Err(AuthorityRefusal::IssuerUnverified);
    }
    if scope.task_id.is_empty()
        || proof.task_id != scope.task_id
        || proof.project_id != project
        || proof.subject_id != subject
    {
        return Err(AuthorityRefusal::SubjectMismatch);
    }
    // Both principal and incarnation must be independent of BOTH lineages.
    if proof.proposer_lineage.is_empty()
        || proof.executor_lineage.is_empty()
        || proof
            .proposer_lineage
            .iter()
            .chain(&proof.executor_lineage)
            .any(String::is_empty)
    {
        return Err(AuthorityRefusal::Unavailable);
    }
    if proof
        .proposer_lineage
        .iter()
        .chain(&proof.executor_lineage)
        .any(|id| id == &proof.issuer_principal || id == &proof.issuer_incarnation)
    {
        return Err(AuthorityRefusal::IssuerNotIndependent);
    }
    let generation = proof
        .current_generation
        .ok_or(AuthorityRefusal::Unavailable)?;
    if proof.revoked || proof.issued_generation != generation {
        return Err(AuthorityRefusal::Revoked);
    }
    Ok(())
}

/// The continuation (including construction of a model client) cannot run
/// before successful authority verification. Tests can make it panic to prove
/// refusal ordering without constructing or contacting a provider.
///
/// # Errors
/// Returns a typed authority refusal without invoking `continue_run`.
pub async fn admit_then<F, Fut, T>(
    binding: ContractBinding,
    scope: &WorkItemScope,
    provider: &dyn ContractAuthorityProvider,
    trust: Option<&AuthorityTrust>,
    continue_run: F,
) -> Result<T, AuthorityRefusal>
where
    F: FnOnce(AdmittedContract) -> Fut,
    Fut: Future<Output = T>,
{
    let proof = provider.authenticate(&binding, scope).await?;
    qualify(&binding, scope, trust, &proof)?;
    Ok(continue_run(AdmittedContract { binding }).await)
}
