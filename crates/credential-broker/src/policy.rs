//! Capability policy and the authorization decision (D-REQ-03 / V-AC-3).
//!
//! The policy file contains **no credential**. It names who may ask for what;
//! the secret it gates is loaded only by the broker binary.

use crate::protocol::{
    is_exact, CapabilityRequest, Denial, ExactSet, ExecutorProfile, Generation, Operation,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::Deserialize;

/// What a single provider permits.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRule {
    /// Exact model identifiers this provider may be asked for.
    pub models: ExactSet,
    /// Operations permitted for this provider.
    pub operations: BTreeSet<Operation>,
    /// Trusted per-operation quota costs. A caller cannot reduce these.
    pub quota_costs: BTreeMap<Operation, u32>,
    /// The one upstream base URL this provider may talk to.
    pub upstream: String,
}

/// The complete capability policy in force for a broker generation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPolicy {
    /// Generation this policy belongs to.
    pub generation: Generation,
    /// The single uid permitted to call the broker.
    pub executor_uid: u32,
    /// Exact executable paths permitted to call the broker.
    pub executables: BTreeSet<PathBuf>,
    /// Executor profiles permitted to call the broker.
    pub profiles: BTreeSet<ExecutorProfile>,
    /// Sessions permitted to call the broker.
    pub sessions: BTreeSet<String>,
    /// Per-provider rules.
    pub providers: BTreeMap<String, ProviderRule>,
    /// Total quota units available for this generation.
    pub quota_limit: u32,
}

impl CapabilityPolicy {
    /// Validate the closed policy before a broker begins serving.
    ///
    /// # Errors
    /// Returns a status-only reason for empty scopes, wildcards, or incomplete
    /// trusted quota costs.
    pub fn validate(&self) -> Result<(), String> {
        if self.quota_limit == 0
            || self.executables.is_empty()
            || self.profiles.is_empty()
            || self.sessions.is_empty()
            || self.providers.is_empty()
        {
            return Err("policy contains an empty required scope or zero quota".to_owned());
        }
        for executable in &self.executables {
            if !executable.is_absolute() {
                return Err("policy executable paths must be absolute".to_owned());
            }
        }
        if self.profiles.iter().any(|profile| !is_exact(&profile.0))
            || self.sessions.iter().any(|session| !is_exact(session))
        {
            return Err("policy profile/session values must be exact".to_owned());
        }
        for (provider, rule) in &self.providers {
            if !is_exact(provider)
                || !is_exact(&rule.upstream)
                || rule.models.is_empty()
                || rule.operations.is_empty()
                || rule.models.iter().any(|model| !is_exact(model))
            {
                return Err("provider policy contains an empty or wildcard scope".to_owned());
            }
            let upstream = url::Url::parse(&rule.upstream)
                .map_err(|_| "provider upstream must be a valid URL".to_owned())?;
            if upstream.scheme() != "https"
                || upstream.host_str().is_none()
                || !upstream.username().is_empty()
                || upstream.password().is_some()
                || upstream.query().is_some()
                || upstream.fragment().is_some()
            {
                return Err("provider upstream must be credential-free absolute HTTPS".to_owned());
            }
            if rule.quota_costs.len() != rule.operations.len()
                || rule
                    .operations
                    .iter()
                    .any(|operation| rule.quota_costs.get(operation).copied().unwrap_or(0) == 0)
            {
                return Err(
                    "every allowed operation must have exactly one positive trusted quota cost"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    /// Validate a request against policy, independent of quota and replay.
    ///
    /// Ordering is deliberate: identity first, then generation, then scope, then
    /// time. A caller learns only that it was denied, and the audit record
    /// carries the precise reason.
    ///
    /// # Errors
    /// Returns the first [`Denial`] that applies.
    pub fn check(&self, req: &CapabilityRequest, now_unix: u64) -> Result<(), Denial> {
        // Every scope-bearing field must be an exact value. A wildcard is not a
        // broad grant here — it is a malformed request.
        if !is_exact(&req.provider) || !is_exact(&req.model) || !is_exact(&req.upstream) {
            return Err(Denial::WildcardOrEmpty);
        }
        if !is_exact(&req.profile.0) || !is_exact(&req.peer.session.0) {
            return Err(Denial::WildcardOrEmpty);
        }
        if req.idempotency.0.trim().is_empty() {
            return Err(Denial::MissingIdempotencyKey);
        }
        if req.idempotency.0.len() > 128
            || !req
                .idempotency
                .0
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(Denial::InvalidIdempotencyKey);
        }

        // Identity, from kernel-attested peer credentials.
        if req.peer.uid != self.executor_uid {
            return Err(Denial::PeerUid);
        }
        if !self.executables.contains(&req.peer.executable) {
            return Err(Denial::PeerExecutable);
        }
        if !self.profiles.contains(&req.profile) {
            return Err(Denial::Profile);
        }
        if !self.sessions.contains(&req.peer.session.0) {
            return Err(Denial::Session);
        }

        // Generation must match exactly. Older *and* newer both fail: a caller
        // claiming a future generation is as wrong as one claiming a past.
        if req.generation != self.generation {
            return Err(Denial::StaleGeneration);
        }

        // Scope.
        let rule = self.providers.get(&req.provider).ok_or(Denial::Provider)?;
        if !rule.models.contains(&req.model) {
            return Err(Denial::Model);
        }
        if !rule.operations.contains(&req.operation) {
            return Err(Denial::OperationNotAllowed);
        }
        if rule.quota_costs.get(&req.operation).copied() != Some(req.quota_units)
            || req.quota_units == 0
        {
            return Err(Denial::InvalidQuotaCost);
        }
        if req.upstream != rule.upstream {
            return Err(Denial::Upstream);
        }

        // Time.
        if req.expires_at <= now_unix {
            return Err(Denial::Expired);
        }

        Ok(())
    }

    /// Which providers this policy grants. Used by the packaging example test to
    /// assert the shipped policy contains no credential-shaped value.
    #[must_use]
    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.keys().map(String::as_str).collect()
    }

    /// Resolve a caller-independent quota cost from policy.
    #[must_use]
    pub fn quota_cost(&self, provider: &str, operation: Operation) -> Option<u32> {
        self.providers
            .get(provider)
            .and_then(|rule| rule.quota_costs.get(&operation))
            .copied()
            .filter(|cost| *cost > 0)
    }
}
