//! Error surface for the supervisor crate.

use arcana_core::hooks::audit::AuditHookError;
use thiserror::Error;

/// Failure modes surfaced by [`crate::Supervisor`] and its primitives.
#[derive(Debug, Error)]
pub enum SupervisorError {
    /// The child process could not be spawned.
    #[error("failed to spawn child process: {0}")]
    Spawn(#[source] std::io::Error),
    /// A lifecycle event could not be written to the shared audit log.
    ///
    /// The audit sink is fail-closed; this error is propagated, never dropped.
    #[error("audit record failed: {0}")]
    Audit(#[from] AuditHookError),
    /// The aggregate-cost budget was exceeded; the spawn was refused and an
    /// `escalate` event was recorded.
    #[error("cost budget exceeded; spawn refused and escalated")]
    BudgetExceeded,
    /// A signal could not be delivered to the child process group.
    #[error("signal delivery failed: {0}")]
    Signal(#[source] nix::errno::Errno),
    /// The child's process-group id could not be resolved.
    #[error("process-group resolution failed: {0}")]
    ProcessGroup(#[source] nix::errno::Errno),
}
