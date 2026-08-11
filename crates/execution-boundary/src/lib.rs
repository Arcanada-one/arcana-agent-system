//! Typed, fail-closed execution boundary for Agent Arcana.
//!
//! # Status — read this before trusting anything below
//!
//! Every shipped-runtime subprocess crosses this crate's typed process module.
//! The structural spawn gate prevents a caller from regaining direct access to
//! raw process construction.
//!
//! Saying this plainly matters more than it might seem: an earlier revision of
//! this docstring claimed in the present tense that every shipped subprocess
//! crossed this boundary, which was false and would have led an operator to
//! believe the incident vector was closed.
//!
//! # What the pieces do
//!
//! - [`env_policy`] constructs a credential-free child environment from
//!   constants and validated inputs. It inherits nothing — D-REQ-02 / V-AC-2.
//! - [`scanner`] quarantines output until it is proven free of a sentinel in
//!   the closed transform set — D-REQ-05 / V-AC-4. It is defence in depth, and
//!   its limits are documented in the module docs; do not treat it as the
//!   credential boundary.
//! - [`Route`] separates API mode from supervised-CLI mode so that API mode
//!   carries no program and structurally cannot spawn — D-REQ-04 / V-AC-1.
//!
//! # Phase gate-set
//!
//! Gates owned outside this crate:
//!
//! - the privilege-separated broker, its permissioned IPC, and
//!   peer/generation/quota/expiry validation (`crates/credential-broker`);
//! - Linux systemd and macOS launchd packaging.
//!
//! Operator constraint: this crate MUST NOT be registered as the credentialed
//! execution path until the broker exists and descendants run under a distinct
//! uid. Same-uid descendants can read `/proc/<parent>/environ` and `ptrace`
//! the parent, so environment reconstruction alone does not isolate a secret
//! held by the supervisor.

pub mod codec;
pub mod env_policy;
#[cfg(unix)]
pub mod process;
pub mod scanner;
#[cfg(unix)]
pub mod transcript;

pub use env_policy::{CleanEnv, EnvError, ALLOWED_TERMS, ALLOWLIST};
#[cfg(unix)]
pub use process::{
    spawn_piped, spawn_pty, spawn_supervised, BoundaryChild, BoundaryError, BoundaryOutput,
    OutputPolicy, ProcessSpec, PtyChild, TerminalSize, Termination, SAFE_SYSTEM_PATH,
};
pub use scanner::{QuarantineScanner, ScanError, ScannerConfig, ScannerInit, Stream};
#[cfg(unix)]
pub use transcript::{TranscriptChunk, TranscriptError, TranscriptPolicy, TranscriptWriter};

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
