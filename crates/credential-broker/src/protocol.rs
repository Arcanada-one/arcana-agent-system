//! Closed protocol types (D-REQ-03).
//!
//! Every field an authorization decision depends on is present and typed. There
//! is deliberately no wildcard, no `Option` that means "any", and no free-form
//! escape hatch: a request that cannot name its provider, model and operation
//! exactly cannot be expressed, let alone authorised.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Monotonic broker generation. A request minted against an older generation is
/// stale and fails closed — this is what makes a restart invalidate in-flight
/// authority rather than silently honouring it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Generation(pub u64);

/// Opaque session or cgroup identifier for the calling executor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

/// Idempotency key. Two requests carrying the same key denote the *same*
/// operation, never two.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(pub String);

/// Stable digest of every authority- and side-effect-bearing request field.
/// A key may replay only when this digest is identical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub struct RequestFingerprint(pub String);

/// The named executor profile a request claims to run under.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ExecutorProfile(pub String);

/// What the caller wants to do. A closed set: adding an operation is a policy
/// change that must pass review, not a string a caller can invent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// A single model completion.
    Completion,
    /// A model listing / capability probe. No billable side effect.
    ListModels,
}

impl Operation {
    /// Whether a committed instance of this operation has a provider-side
    /// effect that must never be repeated by a retry.
    #[must_use]
    pub fn has_side_effect(self) -> bool {
        matches!(self, Self::Completion)
    }

    /// Stable identifier for audit records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completion => "completion",
            Self::ListModels => "list_models",
        }
    }
}

/// Kernel-attested identity of the calling peer.
///
/// These values MUST come from the socket's peer credentials, never from the
/// request body — a caller cannot be trusted to describe itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Peer uid as reported by the kernel.
    pub uid: u32,
    /// Peer pid as reported by the kernel.
    pub pid: i32,
    /// Resolved executable path of the peer.
    pub executable: PathBuf,
    /// Session or cgroup the peer belongs to.
    pub session: SessionId,
}

/// A fully-specified capability request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequest {
    /// Kernel-attested peer identity.
    pub peer: PeerIdentity,
    /// Executor profile the caller claims.
    pub profile: ExecutorProfile,
    /// Broker generation the caller believes it is talking to.
    pub generation: Generation,
    /// Provider key, exactly as named in policy.
    pub provider: String,
    /// Model identifier, exactly as named in policy.
    pub model: String,
    /// Requested operation.
    pub operation: Operation,
    /// Upstream base URL the operation will be sent to.
    pub upstream: String,
    /// Quota units this request will consume. This value is derived from the
    /// trusted policy, never accepted from the wire caller.
    pub quota_units: u32,
    /// Absolute expiry, unix seconds. A request is dead after this instant.
    pub expires_at: u64,
    /// Idempotency key.
    pub idempotency: IdempotencyKey,
    /// Digest binding the idempotency key to the complete request and peer.
    pub fingerprint: RequestFingerprint,
}

/// Why a request was refused. Every variant is a fail-closed outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Denial {
    #[error("peer uid is not the authorised executor uid")]
    PeerUid,
    #[error("peer executable is not in the policy allowlist")]
    PeerExecutable,
    #[error("executor profile is not in the policy allowlist")]
    Profile,
    #[error("session is not in the policy allowlist")]
    Session,
    #[error("request generation does not match the running broker generation")]
    StaleGeneration,
    #[error("provider is not in the policy allowlist")]
    Provider,
    #[error("model is not in the policy allowlist for this provider")]
    Model,
    #[error("operation is not in the policy allowlist for this provider")]
    OperationNotAllowed,
    #[error("upstream does not match the policy-declared upstream for this provider")]
    Upstream,
    #[error("request would exceed the remaining quota")]
    QuotaExceeded,
    #[error("request expiry has passed")]
    Expired,
    #[error("a field was empty or contained a wildcard")]
    WildcardOrEmpty,
    #[error("idempotency key is empty")]
    MissingIdempotencyKey,
    #[error("idempotency key is malformed or exceeds the size limit")]
    InvalidIdempotencyKey,
    #[error("idempotency key was already used for a different request")]
    IdempotencyConflict,
    #[error("idempotency ledger capacity is exhausted")]
    IdempotencyCapacity,
    #[error("policy quota cost is missing or zero")]
    InvalidQuotaCost,
}

/// An authorised lease. Carries no credential material: it is a *permission*,
/// not a secret. The broker performs the upstream call itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Broker generation that issued this lease.
    pub generation: Generation,
    /// The provider this lease is bound to.
    pub provider: String,
    /// The model this lease is bound to.
    pub model: String,
    /// The operation this lease permits.
    pub operation: Operation,
    /// Quota units charged.
    pub charged: u32,
    /// Stable identifier for correlating audit records.
    pub outcome_id: String,
    /// True when this lease replays an already-committed outcome.
    pub replayed: bool,
}

/// Tokens that may never appear in a request field.
const WILDCARDS: &[&str] = &["*", "**", "any", "ANY", "all", "ALL", "%", "?"];

/// Whether a policy-matched field is a usable exact value.
#[must_use]
pub fn is_exact(value: &str) -> bool {
    !value.trim().is_empty() && !WILDCARDS.contains(&value.trim())
}

/// A named set of exact values, used throughout policy.
pub type ExactSet = BTreeSet<String>;
