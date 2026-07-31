//! Privilege-separated local credential broker.
//!
//! The broker is the **sole holder** of provider credentials. Agents, shells,
//! the tmux server and arbitrary descendants hold none, and cannot obtain one:
//! they receive a [`protocol::Lease`], which is a permission, not a secret. The
//! broker performs the upstream call itself.
//!
//! # Why this library contains no secret-loading code
//!
//! Everything here — protocol, policy, ledger, audit — is safe for any process
//! to link. The code that reads the protected credential source lives only in
//! the `arcana-credential-broker` binary. That split is what makes the identity
//! boundary real rather than aspirational: linking this library cannot grant
//! provider authority, so co-location in one repository does not merge the
//! process or identity boundaries.
//!
//! # Phase gate-set
//!
//! Gates in force in this phase:
//!
//! - closed protocol types with no wildcard or free-form escape
//!   ([`protocol`]) — D-REQ-03;
//! - peer / executable / profile / session / generation / provider / model /
//!   operation / upstream / expiry validation ([`policy`]) — D-REQ-03 / V-AC-3;
//! - quota, duplicate and replay enforcement ([`ledger`]) — D-REQ-03 / V-AC-3;
//! - structurally secret-free metadata audit ([`audit`]) — D-REQ-06 / V-AC-5.
//!
//! Gates deferred to the next phase:
//!
//! - the permissioned local IPC transport and its kernel peer-credential
//!   attestation (`SO_PEERCRED` / `LOCAL_PEERCRED`) — D-REQ-03 / V-AC-7;
//! - the provider-neutral scoped upstream adapter and live provider calls;
//! - fail-closed health and backpressure signalling — D-REQ-11 / V-AC-10.
//!
//! Operator constraint: this crate MUST NOT be granted a real credential source
//! until the IPC transport attests peer identity from kernel-supplied socket
//! credentials. Until then it authorises against caller-supplied identity, which
//! is sound for tests and unsound for production.

pub mod audit;
pub mod ledger;
pub mod policy;
pub mod protocol;

pub use ledger::Ledger;
pub use policy::{CapabilityPolicy, ProviderRule};
pub use protocol::{
    CapabilityRequest, Denial, ExecutorProfile, Generation, IdempotencyKey, Lease, Operation,
    PeerIdentity, SessionId,
};

/// Authorise and commit a request in one fail-closed step.
///
/// Policy is checked before the ledger is touched, so a denied request never
/// consumes quota and never creates a committed outcome.
///
/// # Errors
/// The first [`Denial`] that applies.
pub fn authorize(
    policy: &CapabilityPolicy,
    ledger: &mut Ledger,
    req: &CapabilityRequest,
    now_unix: u64,
) -> Result<Lease, Denial> {
    policy.check(req, now_unix)?;
    ledger.commit(req)
}
