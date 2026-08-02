//! Process-group-owning spawn primitive.

use std::path::Path;
use std::process::ExitStatus;
use std::time::Duration;

use arcana_execution_boundary::{
    spawn_supervised, BoundaryChild, BoundaryError, CleanEnv, ProcessSpec, SAFE_SYSTEM_PATH,
};
use nix::unistd::{getpgid, Pid};
use tokio::process::ChildStdout;

use crate::error::SupervisorError;
use crate::policy::ChildSpec;

/// A spawned child that owns its own process group.
///
/// The child is made a **process-group leader** at spawn (`process_group(0)`),
/// so its pgid equals its pid and the terminate sequence can signal the whole
/// group — no forked grandchild escapes shutdown.
#[derive(Debug)]
pub struct SpawnedChild {
    id: u64,
    pid: Pid,
    pgid: Pid,
    child: BoundaryChild,
    stdout: Option<ChildStdout>,
}

impl SpawnedChild {
    /// Supervisor-assigned child id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// OS process id.
    #[must_use]
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// OS process-group id (equals [`Self::pid`] for a fresh group leader).
    #[must_use]
    pub fn pgid(&self) -> Pid {
        self.pgid
    }

    /// Take the piped stdout handle for the heartbeat reader (once).
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    /// Observe leader exit without reaping the process-group leader.
    ///
    /// # Errors
    /// Propagates execution-boundary exit-observation failure.
    pub async fn wait_for_exit(&mut self) -> Result<(), SupervisorError> {
        self.child.wait_for_exit().await.map_err(Into::into)
    }

    /// Final-signal the pinned process group, reap its leader, and prove the
    /// numeric group id disappeared.
    ///
    /// # Errors
    /// Propagates execution-boundary lifecycle failure.
    pub async fn finalize_after_exit(&mut self) -> Result<ExitStatus, SupervisorError> {
        self.child.finalize_after_exit().await.map_err(Into::into)
    }

    /// Terminate the complete process group through the execution boundary.
    ///
    /// # Errors
    /// Propagates execution-boundary signal, observation, reap, or proof
    /// failure.
    pub async fn terminate(&mut self, grace: Duration) -> Result<ExitStatus, SupervisorError> {
        self.child.terminate(grace).await.map_err(Into::into)
    }
}

/// Spawn `spec` as a new process-group leader with piped stdout.
///
/// # Errors
///
/// Returns [`SupervisorError::Spawn`] if the process cannot be created,
/// or [`SupervisorError::ProcessGroup`] if its pgid cannot be resolved.
// `pid` / `pgid` are the standard process-group domain names; the similarity is
// intentional and clearer than an artificial rename.
#[allow(clippy::similar_names)]
pub fn spawn_process_group(id: u64, spec: &ChildSpec) -> Result<SpawnedChild, SupervisorError> {
    let env = CleanEnv::build(
        Path::new("/tmp/arcana-runtime/supervisor"),
        SAFE_SYSTEM_PATH,
    )
    .map_err(BoundaryError::from)?;
    let cwd = std::env::current_dir().map_err(|error| BoundaryError::Io {
        phase: "resolve supervisor working directory",
        reason: error.to_string(),
    })?;
    let boundary_spec = ProcessSpec::new(Path::new(spec.program()), env)
        .args(spec.args().iter().cloned())
        .cwd(cwd);
    let mut child = spawn_supervised(&boundary_spec)?;
    let raw_pid = child.pid();
    let pid = Pid::from_raw(pid_to_raw(raw_pid));
    let pgid = getpgid(Some(pid)).map_err(SupervisorError::ProcessGroup)?;
    let stdout = child.take_stdout();

    Ok(SpawnedChild {
        id,
        pid,
        pgid,
        child,
        stdout,
    })
}

/// Convert an OS pid from `u32` to the signed `pid_t` domain without a lossy
/// cast lint; real pids are always inside `i32::MAX`.
fn pid_to_raw(raw: u32) -> i32 {
    i32::try_from(raw).unwrap_or(i32::MAX)
}
