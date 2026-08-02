//! Error surface for the supervisor crate.

use arcana_core::hooks::audit::AuditHookError;
use arcana_execution_boundary::BoundaryError;
use thiserror::Error;

/// Failure modes surfaced by [`crate::Supervisor`] and its primitives.
#[derive(Debug, Error)]
pub enum SupervisorError {
    /// The central execution boundary rejected or failed the spawn.
    #[error("execution boundary rejected child process: {0}")]
    Boundary(#[from] BoundaryError),
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
    /// Waiting for the direct child failed before a trustworthy reap result.
    #[error("child wait failed during {phase}: {source}")]
    ChildWait {
        /// Termination phase in which the wait failed.
        phase: &'static str,
        /// Operating-system wait error.
        #[source]
        source: std::io::Error,
    },
    /// The direct child was still unreaped after the post-SIGKILL deadline.
    #[error("child reap timed out after SIGKILL")]
    ReapTimeout,
    /// The child's process-group id could not be resolved.
    #[error("process-group resolution failed: {0}")]
    ProcessGroup(#[source] nix::errno::Errno),
}
