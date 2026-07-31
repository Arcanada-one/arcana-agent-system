//! Typed, fail-closed execution boundary for Agent Arcana.
//!
//! Every shipped-runtime subprocess crosses this crate. The agent, its shell,
//! the tmux server, the transcript writer and arbitrary descendants start from a
//! reconstructed credential-free environment; provider authentication is the
//! exclusive business of the separately-built credential broker.
//!
//! # Phase gate-set
//!
//! Gates in force in this phase:
//!
//! - clean-environment reconstruction ([`env_policy`]) — D-REQ-02 / V-AC-2;
//! - streaming output quarantine ([`scanner`]) — D-REQ-05 / V-AC-4;
//! - explicit API-versus-CLI routing ([`Route`]) — D-REQ-04 / V-AC-1.
//!
//! Gates deferred to the next phase:
//!
//! - the privilege-separated broker itself (`crates/credential-broker`),
//!   its permissioned local IPC, peer/generation/quota/expiry validation
//!   and metadata-only audit — D-REQ-03 / V-AC-3, V-AC-5;
//! - Linux systemd and macOS launchd packaging — D-REQ-08 / V-AC-7.
//!
//! Operator constraint: this crate MUST NOT be registered as the credentialed
//! execution path until the broker layer exists. Until then it provides
//! isolation and quarantine only, and no route may carry a provider credential.

pub mod codec;
pub mod env_policy;
pub mod scanner;

pub use env_policy::{CleanEnv, ALLOWLIST};
pub use scanner::{QuarantineScanner, ScanError, ScannerConfig};

/// How an authorised operation reaches its provider.
///
/// The two routes are disjoint by construction: [`Route::NativeApi`] carries no
/// program to execute, so an API-mode operation structurally cannot shell out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// In-process HTTP to the broker adapter. Never spawns a process.
    NativeApi {
        /// Provider identifier, e.g. the adapter key the broker authorises.
        provider: String,
    },
    /// A declared, supervised vendor CLI adapter.
    SupervisedCli {
        /// Absolute path of the single declared adapter executable.
        adapter: std::path::PathBuf,
    },
}

impl Route {
    /// Whether this route is permitted to spawn a process at all.
    #[must_use]
    pub fn may_spawn(&self) -> bool {
        matches!(self, Self::SupervisedCli { .. })
    }
}
