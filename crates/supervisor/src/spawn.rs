//! Process-group-owning spawn primitive.

use std::process::Stdio;

use nix::unistd::{getpgid, Pid};
use tokio::process::{ChildStdout, Command};

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
    child: tokio::process::Child,
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

    /// Mutable access to the underlying tokio child (for wait/terminate).
    pub fn child_mut(&mut self) -> &mut tokio::process::Child {
        &mut self.child
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
    let mut command = Command::new(spec.program());
    command
        .args(spec.args())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Own a fresh process group at exec (safe wrapper; setpgid(0,0)).
        .process_group(0)
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(SupervisorError::Spawn)?;
    let raw_pid = child.id().ok_or_else(|| {
        SupervisorError::Spawn(std::io::Error::other("child exited before pid capture"))
    })?;
    let pid = Pid::from_raw(pid_to_raw(raw_pid));
    let pgid = getpgid(Some(pid)).map_err(SupervisorError::ProcessGroup)?;
    let stdout = child.stdout.take();

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
