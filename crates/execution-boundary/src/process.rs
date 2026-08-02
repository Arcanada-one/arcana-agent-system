//! The sole shipped-runtime owner of subprocess construction.
//!
//! Callers provide a declarative [`ProcessSpec`]. They cannot add inherited
//! environment entries, choose ambient stdio, or opt out of process-group
//! ownership. Higher-level callers should use [`ProcessSpec::run`], which also
//! provides timeout/cancellation cleanup and output quarantine. The supervisor
//! uses [`spawn_piped`] because it owns a longer-lived heartbeat lifecycle.

#![cfg(unix)]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
#[cfg(not(target_os = "macos"))]
use std::sync::Condvar;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use nix::errno::Errno;
use nix::pty::{openpty, Winsize as NixWinsize};
#[cfg(target_os = "macos")]
use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue};
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::{getpgid, Pid};
use rustix::process::{waitid, Pid as RustixPid, WaitId, WaitIdOptions};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    CleanEnv, EnvError, QuarantineScanner, ScanError, ScannerConfig, Stream, TranscriptChunk,
    TranscriptError, TranscriptWriter,
};

/// Deterministic executable search path used by shipped callers.
///
/// Executables themselves must still be supplied as absolute paths. `PATH` is
/// retained for declared helpers that those executables may invoke.
pub const SAFE_SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_GRACE: Duration = Duration::from_secs(2);
const DEFAULT_OUTPUT_LIMIT: usize = 1024 * 1024;

/// Shell wrapper used only as a safe, portable close-from primitive. Target
/// argv is passed through `"$@"` and is never parsed as shell source. Each fd
/// token comes from the kernel-owned descriptor directory and is accepted only
/// after a decimal-digit check.
const FD_SWEEP_SCRIPT: &str = r#"
kill -STOP $$
for arcana_fd_path in /proc/self/fd/* /dev/fd/*; do
  [ -e "$arcana_fd_path" ] || continue
  arcana_fd=${arcana_fd_path##*/}
  case "$arcana_fd" in ''|*[!0-9]*) continue ;; esac
  [ "$arcana_fd" -le 2 ] && continue
  eval "exec ${arcana_fd}>&-"
done
exec /usr/bin/env -u PWD -u OLDPWD -u SHLVL "$@"
"#;

/// The group anchor follows the same close-from contract as the target. Its
/// readiness stop happens only after SIGTERM is ignored and ambient
/// descriptors are closed, so the parent never mistakes a half-armed anchor
/// for a trusted group member.
const GROUP_ANCHOR_SCRIPT: &str = r#"
trap '' TERM
for arcana_fd_path in /proc/self/fd/* /dev/fd/*; do
  [ -e "$arcana_fd_path" ] || continue
  arcana_fd=${arcana_fd_path##*/}
  case "$arcana_fd" in ''|*[!0-9]*) continue ;; esac
  [ "$arcana_fd" -le 2 ] && continue
  eval "exec ${arcana_fd}>&-"
done
kill -STOP $$
exec /bin/sleep 2147483647
"#;

/// Whether captured bytes need a credential-sentinel quarantine scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum OutputPolicy {
    /// For a process that never receives or owns a credential.
    #[default]
    Capture,
    /// Hold all output until it is proven free of each sentinel.
    Quarantine { sentinels: Vec<Vec<u8>> },
}

/// Declarative process recipe. There is intentionally no ambient-env escape
/// hatch and no arbitrary stdio configuration.
#[derive(Debug, Clone)]
pub struct ProcessSpec {
    program: PathBuf,
    args: Vec<OsString>,
    env: CleanEnv,
    cwd: Option<PathBuf>,
    timeout: Duration,
    termination_grace: Duration,
    output_limit: usize,
    output_policy: OutputPolicy,
    transcript: Option<(TranscriptWriter, String)>,
}

impl ProcessSpec {
    /// Construct a recipe with bounded defaults.
    #[must_use]
    pub fn new(program: &Path, env: CleanEnv) -> Self {
        Self {
            program: program.to_path_buf(),
            args: Vec::new(),
            env,
            cwd: None,
            timeout: DEFAULT_TIMEOUT,
            termination_grace: DEFAULT_GRACE,
            output_limit: DEFAULT_OUTPUT_LIMIT,
            output_policy: OutputPolicy::Capture,
            transcript: None,
        }
    }

    /// Append one literal argv element.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append literal argv elements.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an absolute working directory. The sandbox home is the default.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set the wall-clock deadline.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the SIGTERM-to-SIGKILL grace period.
    #[must_use]
    pub fn termination_grace(mut self, grace: Duration) -> Self {
        self.termination_grace = grace;
        self
    }

    /// Set the aggregate stdout/stderr byte cap.
    #[must_use]
    pub fn output_limit(mut self, bytes: usize) -> Self {
        self.output_limit = bytes;
        self
    }

    /// Set output handling.
    #[must_use]
    pub fn output_policy(mut self, policy: OutputPolicy) -> Self {
        self.output_policy = policy;
        self
    }

    /// Persist observation-ordered output through the restrictive transcript
    /// writer after quarantine succeeds.
    #[must_use]
    pub fn transcript(mut self, writer: TranscriptWriter, identifier: impl Into<String>) -> Self {
        self.transcript = Some((writer, identifier.into()));
        self
    }

    /// Execute with bounded lifecycle ownership.
    ///
    /// # Errors
    /// Fails closed for invalid paths/argv, spawn or I/O failure, oversized
    /// output, or quarantine rejection.
    pub async fn run(
        &self,
        cancellation: CancellationToken,
    ) -> Result<BoundaryOutput, BoundaryError> {
        validate(self)?;
        let mut child = spawn_piped(self)?;
        let stdout = child.take_stdout().ok_or_else(|| BoundaryError::Io {
            phase: "capture stdout",
            reason: "stdout pipe absent".to_owned(),
        })?;
        let stderr = child.take_stderr().ok_or_else(|| BoundaryError::Io {
            phase: "capture stderr",
            reason: "stderr pipe absent".to_owned(),
        })?;
        let (sender, receiver) = mpsc::channel(16);
        let stdout_task = spawn_output_reader(stdout, Stream::Stdout, sender.clone());
        let stderr_task = spawn_output_reader(stderr, Stream::Stderr, sender);
        let internal_cancel = CancellationToken::new();
        let collector_cancel = internal_cancel.clone();
        let collector = collect_output(
            receiver,
            self.output_limit,
            self.output_policy.clone(),
            collector_cancel,
        );

        let deadline = tokio::time::sleep(self.timeout);
        tokio::pin!(deadline);
        let lifecycle = async {
            tokio::select! {
                result = wait_and_close_group(&mut child) => {
                    Ok::<_, BoundaryError>((result?, None))
                }
                () = cancellation.cancelled() => {
                    let status = terminate_group(&mut child, self.termination_grace).await?;
                    Ok::<_, BoundaryError>((status, Some(Termination::Cancelled)))
                }
                () = internal_cancel.cancelled() => {
                    let status = terminate_group(&mut child, self.termination_grace).await?;
                    Ok::<_, BoundaryError>((status, Some(Termination::Cancelled)))
                }
                () = &mut deadline => {
                    let status = terminate_group(&mut child, self.termination_grace).await?;
                    Ok::<_, BoundaryError>((status, Some(Termination::TimedOut)))
                }
            }
        };
        let total_deadline = self
            .timeout
            .saturating_add(self.termination_grace)
            .saturating_add(POST_KILL_REAP_TIMEOUT)
            .saturating_add(GROUP_DISAPPEAR_TIMEOUT)
            .saturating_add(Duration::from_millis(250));
        let joined =
            tokio::time::timeout(total_deadline, async { tokio::join!(lifecycle, collector) })
                .await;
        let Ok((lifecycle_result, collected_result)) = joined else {
            internal_cancel.cancel();
            cleanup_after_output_deadline(&mut child).await?;
            stdout_task.abort();
            stderr_task.abort();
            return Err(BoundaryError::Io {
                phase: "drain child output",
                reason: "output streams remained open beyond the lifecycle deadline".to_owned(),
            });
        };
        stdout_task.abort();
        stderr_task.abort();
        let collected = collected_result?;
        let (status, forced) = lifecycle_result?;

        let transcript_artifact = if let Some((writer, identifier)) = &self.transcript {
            let writer = writer.clone();
            let identifier = identifier.clone();
            let chunks = collected.ordered.clone();
            Some(
                tokio::task::spawn_blocking(move || {
                    let borrowed: Vec<_> = chunks
                        .iter()
                        .map(|chunk| TranscriptChunk::new(chunk.stream, &chunk.bytes))
                        .collect();
                    writer.write(&identifier, &borrowed)
                })
                .await
                .map_err(|error| BoundaryError::Io {
                    phase: "join transcript writer",
                    reason: error.to_string(),
                })??,
            )
        } else {
            None
        };

        let termination = forced.unwrap_or_else(|| termination_from_status(status));
        Ok(BoundaryOutput {
            success: status.success() && matches!(termination, Termination::Exited(0)),
            exit_code: status.code(),
            stdout: collected.stdout,
            stderr: collected.stderr,
            termination,
            transcript_artifact,
        })
    }
}

/// Result of a bounded process invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub termination: Termination,
    /// Opaque identifier retrievable only through the originating
    /// [`TranscriptWriter`] capability; it is not a filesystem pathname.
    pub transcript_artifact: Option<String>,
}

/// Unambiguous terminal cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Exited(i32),
    Signal(i32),
    TimedOut,
    Cancelled,
}

/// Fail-closed boundary error.
#[derive(Debug, thiserror::Error)]
pub enum BoundaryError {
    #[error("clean environment rejected: {0}")]
    Environment(#[from] EnvError),
    #[error("program path must be absolute")]
    ProgramNotAbsolute,
    #[error("program path is absent, not a regular file, or not executable")]
    ProgramInvalid,
    #[error("working directory must be absolute")]
    CwdNotAbsolute,
    #[error("working directory does not exist or is not a directory")]
    CwdInvalid,
    #[error("terminal rows and columns must both be non-zero")]
    InvalidTerminalSize,
    #[error("PTY output cannot bypass quarantine or transcript policy")]
    PtyOutputPolicyUnsupported,
    #[error("sandbox home is a symbolic link")]
    HomeIsSymlink,
    #[error("sandbox home path is not owned by the executor identity")]
    HomeOwnerMismatch,
    #[error("credential sentinel found in argv element {index}")]
    CredentialInArgument { index: usize },
    #[error("process output exceeded the {limit}-byte limit")]
    OutputLimitExceeded { limit: usize },
    #[error("process output quarantined: {0}")]
    OutputQuarantined(#[from] ScanError),
    #[error("transcript persistence failed: {0}")]
    Transcript(#[from] TranscriptError),
    #[error("failed to initialise output quarantine: {0}")]
    QuarantineInit(String),
    #[error("{phase} failed: {reason}")]
    Io { phase: &'static str, reason: String },
}

/// A process-group-owned child for the long-lived supervisor path.
#[derive(Debug)]
pub struct BoundaryChild {
    pid: u32,
    child: Option<Child>,
    anchor: Option<Child>,
    exit_observer: Option<watch::Receiver<ExitObservation>>,
    exit_observed: bool,
    final_signal: Option<Result<(), Errno>>,
    cleanup_complete: bool,
}

/// A validated terminal size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    rows: u16,
    columns: u16,
}

impl TerminalSize {
    #[must_use]
    pub const fn new(rows: u16, columns: u16) -> Self {
        Self { rows, columns }
    }
}

/// A real pseudo-terminal child. The master descriptor is retained for input
/// and resize while a separate clone is exposed for async output reads.
#[derive(Debug)]
pub struct PtyChild {
    child: BoundaryChild,
    control: File,
    output: Option<tokio::fs::File>,
}

impl PtyChild {
    pub fn take_output(&mut self) -> Option<tokio::fs::File> {
        self.output.take()
    }

    /// Resize the real PTY. Zero dimensions are refused.
    ///
    /// # Errors
    /// Returns a boundary error for a zero dimension or terminal ioctl failure.
    pub fn resize(&self, size: TerminalSize) -> Result<(), BoundaryError> {
        validate_terminal_size(size)?;
        rustix::termios::tcsetwinsize(
            &self.control,
            rustix::termios::Winsize {
                ws_row: size.rows,
                ws_col: size.columns,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .map_err(|error| BoundaryError::Io {
            phase: "resize pseudo-terminal",
            reason: error.to_string(),
        })
    }

    /// Write literal input bytes to the PTY master.
    ///
    /// # Errors
    /// Returns a boundary error if the terminal write or flush fails.
    pub fn write_input(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
        self.control
            .write_all(bytes)
            .and_then(|()| self.control.flush())
            .map_err(|error| BoundaryError::Io {
                phase: "write pseudo-terminal input",
                reason: error.to_string(),
            })
    }

    /// Wait for the PTY child to exit.
    ///
    /// # Errors
    /// Returns a boundary error when the OS wait operation fails.
    pub async fn wait(&mut self) -> Result<ExitStatus, BoundaryError> {
        self.child.wait_for_exit().await?;
        self.child.finalize_after_exit().await
    }

    /// Terminate the PTY child's complete process group.
    ///
    /// # Errors
    /// Returns a boundary error when signalling or reaping fails.
    pub async fn terminate(&mut self, grace: Duration) -> Result<ExitStatus, BoundaryError> {
        terminate_group(&mut self.child, grace).await
    }
}

impl BoundaryChild {
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.as_mut()?.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<tokio::process::ChildStderr> {
        self.child.as_mut()?.stderr.take()
    }

    /// Observe direct-child exit without reaping the process-group leader.
    ///
    /// The retained zombie pins PID=PGID until the boundary has issued its
    /// final destructive group signal, preventing numeric-PGID reuse.
    ///
    /// # Errors
    /// Returns an I/O error when the platform's non-reaping exit observer
    /// cannot observe the owned direct child.
    pub async fn wait_for_exit(&mut self) -> Result<(), BoundaryError> {
        if self.exit_observed {
            return Ok(());
        }
        let observer = self
            .exit_observer
            .as_mut()
            .ok_or_else(|| BoundaryError::Io {
                phase: "observe child exit without reaping",
                reason: "exit observer is unavailable".to_owned(),
            })?;
        loop {
            let state = observer.borrow().clone();
            match state {
                ExitObservation::Waiting => {}
                ExitObservation::Exited => {
                    self.exit_observed = true;
                    return Ok(());
                }
                ExitObservation::Failed(reason) => {
                    return Err(BoundaryError::Io {
                        phase: "observe child exit without reaping",
                        reason,
                    });
                }
            }
            observer.changed().await.map_err(|_| BoundaryError::Io {
                phase: "observe child exit without reaping",
                reason: "exit observer ended without a terminal state".to_owned(),
            })?;
        }
    }

    /// Issue the last destructive group signal while PID=PGID is pinned, then
    /// reap the direct child and prove the group disappeared using signal 0.
    ///
    /// # Errors
    /// Returns an I/O error for signalling, reaping, or disappearance failure.
    pub async fn finalize_after_exit(&mut self) -> Result<ExitStatus, BoundaryError> {
        if !self.exit_observed {
            return Err(BoundaryError::Io {
                phase: "finalize process group",
                reason: "direct child has not reached an observable exit state".to_owned(),
            });
        }
        finalize_group_and_reap(self).await
    }

    /// Terminate the complete owned process group and reap its leader.
    ///
    /// # Errors
    /// Returns an I/O error for signalling, exit observation, reaping, or
    /// post-reap disappearance failure.
    pub async fn terminate(&mut self, grace: Duration) -> Result<ExitStatus, BoundaryError> {
        terminate_group(self, grace).await
    }
}

impl Drop for BoundaryChild {
    fn drop(&mut self) {
        if self.cleanup_complete {
            return;
        }
        let child_pid = self.pid;
        let (mut child, mut anchor) = match (self.child.take(), self.anchor.take()) {
            (Some(child), Some(anchor)) => (child, anchor),
            (Some(mut child), None) => {
                let _ = child.start_kill();
                return;
            }
            (None, Some(mut anchor)) => {
                let _ = anchor.start_kill();
                return;
            }
            (None, None) => return,
        };
        let owned_group = Pid::from_raw(i32::try_from(child_pid).unwrap_or(i32::MAX));
        let final_signal = issue_final_group_signal(&mut self.final_signal, owned_group);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ =
                    finalize_owned_group(&mut child, &mut anchor, child_pid, final_signal).await;
            });
            return;
        }

        // Runtime teardown fallback: preserve final-signal-before-reap order.
        // Both direct-child handles are still covered by kill-on-drop.
        if final_signal.is_ok() {
            let _ = child.try_wait();
            let _ = anchor.try_wait();
        } else {
            let _ = child.start_kill();
            let _ = anchor.start_kill();
        }
    }
}

/// Spawn a clean-environment process-group leader with captured output.
///
/// This lower-level function exists for `arcana-supervisor`, which owns its
/// own heartbeat, restart, and termination state machine.
///
/// # Errors
/// Returns a boundary error for invalid configuration or spawn failure.
pub fn spawn_piped(spec: &ProcessSpec) -> Result<BoundaryChild, BoundaryError> {
    spawn_with_stderr(spec, true)
}

/// Spawn a clean-environment process attached to a real pseudo-terminal.
///
/// # Errors
/// Fails closed for invalid process or terminal configuration and for any PTY
/// or spawn failure.
pub fn spawn_pty(spec: &ProcessSpec, size: TerminalSize) -> Result<PtyChild, BoundaryError> {
    validate(spec)?;
    if matches!(spec.output_policy, OutputPolicy::Quarantine { .. }) || spec.transcript.is_some() {
        return Err(BoundaryError::PtyOutputPolicyUnsupported);
    }
    validate_terminal_size(size)?;
    let home = spec.env.home();
    prepare_home(&home)?;
    let cwd = spec.cwd.as_deref().unwrap_or(&home);
    if !cwd.is_absolute() {
        return Err(BoundaryError::CwdNotAbsolute);
    }
    if !cwd.is_dir() {
        return Err(BoundaryError::CwdInvalid);
    }

    let dimensions = NixWinsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pair = openpty(Some(&dimensions), None).map_err(|error| BoundaryError::Io {
        phase: "open pseudo-terminal",
        reason: error.to_string(),
    })?;
    let control = File::from(pair.master);
    let output_file = control.try_clone().map_err(|error| BoundaryError::Io {
        phase: "clone pseudo-terminal master",
        reason: error.to_string(),
    })?;
    let slave = File::from(pair.slave);
    let stdin = slave.try_clone().map_err(|error| BoundaryError::Io {
        phase: "clone pseudo-terminal slave",
        reason: error.to_string(),
    })?;
    let stdout = slave.try_clone().map_err(|error| BoundaryError::Io {
        phase: "clone pseudo-terminal slave",
        reason: error.to_string(),
    })?;

    let mut command = swept_command(spec);
    command
        .current_dir(cwd)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(slave))
        .process_group(0)
        .kill_on_drop(true);
    spec.env.apply(command.as_std_mut());
    let child = command.spawn().map_err(|error| BoundaryError::Io {
        phase: "spawn pseudo-terminal child",
        reason: error.to_string(),
    })?;
    let pid = child.id().ok_or_else(|| BoundaryError::Io {
        phase: "capture pseudo-terminal child pid",
        reason: "child exited before pid capture".to_owned(),
    })?;
    Ok(PtyChild {
        child: arm_owned_process_group(child, pid)?,
        control,
        output: Some(tokio::fs::File::from_std(output_file)),
    })
}

/// Spawn for the heartbeat supervisor. Stderr is discarded so an unconsumed
/// pipe cannot deadlock a long-lived child.
///
/// # Errors
/// Returns a boundary error for invalid configuration or spawn failure.
pub fn spawn_supervised(spec: &ProcessSpec) -> Result<BoundaryChild, BoundaryError> {
    spawn_with_stderr(spec, false)
}

fn spawn_with_stderr(
    spec: &ProcessSpec,
    capture_stderr: bool,
) -> Result<BoundaryChild, BoundaryError> {
    validate(spec)?;
    let home = spec.env.home();
    prepare_home(&home)?;
    let cwd = spec.cwd.as_deref().unwrap_or(&home);
    if !cwd.is_absolute() {
        return Err(BoundaryError::CwdNotAbsolute);
    }
    if !cwd.is_dir() {
        return Err(BoundaryError::CwdInvalid);
    }

    let mut command = swept_command(spec);
    command
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    command.stderr(if capture_stderr {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    spec.env.apply(command.as_std_mut());
    let child = command.spawn().map_err(|err| BoundaryError::Io {
        phase: "spawn",
        reason: err.to_string(),
    })?;
    let pid = child.id().ok_or_else(|| BoundaryError::Io {
        phase: "capture pid",
        reason: "child exited before pid capture".to_owned(),
    })?;
    arm_owned_process_group(child, pid)
}

fn arm_owned_process_group(mut child: Child, pid: u32) -> Result<BoundaryChild, BoundaryError> {
    let owned_group = Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX));
    if let Err(error) = wait_for_launch_stop(pid) {
        let _ = killpg(owned_group, Signal::SIGKILL);
        let _ = child.start_kill();
        return Err(error);
    }
    let mut anchor = match spawn_group_anchor(owned_group) {
        Ok(anchor) => anchor,
        Err(error) => {
            let _ = killpg(owned_group, Signal::SIGKILL);
            let _ = child.start_kill();
            return Err(error);
        }
    };
    let observer = match spawn_exit_observer(pid) {
        Ok(observer) => observer,
        Err(error) => {
            let _ = killpg(owned_group, Signal::SIGKILL);
            let _ = child.start_kill();
            let _ = anchor.start_kill();
            return Err(error);
        }
    };
    if let Err(error) = kill(owned_group, Signal::SIGCONT) {
        let _ = killpg(owned_group, Signal::SIGKILL);
        let _ = child.start_kill();
        let _ = anchor.start_kill();
        return Err(BoundaryError::Io {
            phase: "resume process-group leader after anchor join",
            reason: error.to_string(),
        });
    }
    Ok(BoundaryChild {
        pid,
        child: Some(child),
        anchor: Some(anchor),
        exit_observer: Some(observer),
        exit_observed: false,
        final_signal: None,
        cleanup_complete: false,
    })
}

fn wait_for_launch_stop(pid: u32) -> Result<(), BoundaryError> {
    let raw_pid = i32::try_from(pid).unwrap_or(i32::MAX);
    let wait_pid = RustixPid::from_raw(raw_pid).ok_or_else(|| BoundaryError::Io {
        phase: "wait for process-group launch barrier",
        reason: "child pid must be positive".to_owned(),
    })?;
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    loop {
        match waitid(
            WaitId::Pid(wait_pid),
            WaitIdOptions::STOPPED | WaitIdOptions::NOHANG,
        ) {
            Ok(Some(status)) if status.stopped() => return Ok(()),
            Ok(Some(_)) => {
                return Err(BoundaryError::Io {
                    phase: "wait for process-group launch barrier",
                    reason: "child reported a non-stop state before anchor join".to_owned(),
                });
            }
            Ok(None) | Err(rustix::io::Errno::INTR) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(None) | Err(rustix::io::Errno::INTR) => {
                return Err(BoundaryError::Io {
                    phase: "wait for process-group launch barrier",
                    reason: "child did not stop before the bounded deadline".to_owned(),
                });
            }
            Err(error) => {
                return Err(BoundaryError::Io {
                    phase: "wait for process-group launch barrier",
                    reason: error.to_string(),
                });
            }
        }
    }
}

fn spawn_group_anchor(owned_group: Pid) -> Result<Child, BoundaryError> {
    let mut command = Command::new("/bin/bash");
    command
        .arg("-c")
        .arg(GROUP_ANCHOR_SCRIPT)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(owned_group.as_raw())
        .kill_on_drop(true);
    let mut anchor = command.spawn().map_err(|error| BoundaryError::Io {
        phase: "spawn process-group anchor",
        reason: error.to_string(),
    })?;
    let anchor_pid = anchor.id().ok_or_else(|| BoundaryError::Io {
        phase: "capture process-group anchor pid",
        reason: "anchor exited before pid capture".to_owned(),
    })?;
    let actual_group = getpgid(Some(Pid::from_raw(
        i32::try_from(anchor_pid).unwrap_or(i32::MAX),
    )))
    .map_err(|error| BoundaryError::Io {
        phase: "verify process-group anchor membership",
        reason: error.to_string(),
    })?;
    if actual_group != owned_group {
        let _ = anchor.start_kill();
        return Err(BoundaryError::Io {
            phase: "verify process-group anchor membership",
            reason: "anchor joined an unexpected process group".to_owned(),
        });
    }
    if let Err(error) = wait_for_launch_stop(anchor_pid) {
        let _ = anchor.start_kill();
        return Err(error);
    }
    if let Err(error) = kill(
        Pid::from_raw(i32::try_from(anchor_pid).unwrap_or(i32::MAX)),
        Signal::SIGCONT,
    ) {
        let _ = anchor.start_kill();
        return Err(BoundaryError::Io {
            phase: "resume process-group anchor after readiness barrier",
            reason: error.to_string(),
        });
    }
    Ok(anchor)
}

fn validate(spec: &ProcessSpec) -> Result<(), BoundaryError> {
    if !spec.program.is_absolute() {
        return Err(BoundaryError::ProgramNotAbsolute);
    }
    let program = std::fs::metadata(&spec.program).map_err(|_| BoundaryError::ProgramInvalid)?;
    if !program.is_file() || program.permissions().mode() & 0o111 == 0 {
        return Err(BoundaryError::ProgramInvalid);
    }
    if spec.cwd.as_ref().is_some_and(|cwd| !cwd.is_absolute()) {
        return Err(BoundaryError::CwdNotAbsolute);
    }
    if let OutputPolicy::Quarantine { sentinels } = &spec.output_policy {
        for (index, arg) in spec.args.iter().enumerate() {
            let value = os_bytes(arg.as_os_str());
            if sentinels
                .iter()
                .any(|sentinel| !sentinel.is_empty() && contains(&value, sentinel))
            {
                return Err(BoundaryError::CredentialInArgument { index });
            }
        }
    }
    Ok(())
}

fn swept_command(spec: &ProcessSpec) -> Command {
    let mut command = Command::new("/bin/bash");
    command
        .arg("-c")
        .arg(FD_SWEEP_SCRIPT)
        .arg("arcana-fd-sweep")
        .arg(&spec.program)
        .args(&spec.args);
    command
}

fn validate_terminal_size(size: TerminalSize) -> Result<(), BoundaryError> {
    if size.rows == 0 || size.columns == 0 {
        return Err(BoundaryError::InvalidTerminalSize);
    }
    Ok(())
}

fn prepare_home(home: &Path) -> Result<(), BoundaryError> {
    match std::fs::symlink_metadata(home) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(BoundaryError::HomeIsSymlink)
        }
        Ok(metadata) if !metadata.is_dir() => return Err(BoundaryError::CwdInvalid),
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(home).map_err(|err| BoundaryError::Io {
                phase: "create sandbox home",
                reason: err.to_string(),
            })?;
        }
        Err(err) => {
            return Err(BoundaryError::Io {
                phase: "inspect sandbox home",
                reason: err.to_string(),
            });
        }
    }
    std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
        BoundaryError::Io {
            phase: "restrict sandbox home",
            reason: err.to_string(),
        }
    })?;

    // `create_dir_all` follows intermediate symlinks. Validate the resulting
    // sandbox and its direct parent so a pre-created runtime path owned by
    // another account cannot redirect HOME into attacker-controlled storage.
    // Broader ancestors may legitimately use container id mapping, so they are
    // outside this per-runtime ownership invariant.
    let canonical = std::fs::canonicalize(home).map_err(|err| BoundaryError::Io {
        phase: "canonicalize sandbox home",
        reason: err.to_string(),
    })?;
    let executor_uid = nix::unistd::geteuid().as_raw();
    for component in canonical.ancestors().take(2) {
        let metadata = std::fs::symlink_metadata(component).map_err(|err| BoundaryError::Io {
            phase: "inspect sandbox home ownership",
            reason: err.to_string(),
        })?;
        if metadata.uid() != executor_uid && metadata.uid() != 0 {
            return Err(BoundaryError::HomeOwnerMismatch);
        }
    }
    Ok(())
}

const POST_KILL_REAP_TIMEOUT: Duration = Duration::from_millis(500);
const GROUP_DISAPPEAR_TIMEOUT: Duration = Duration::from_millis(500);
const GROUP_PROBE_POLL: Duration = Duration::from_millis(5);

async fn terminate_group(
    child: &mut BoundaryChild,
    grace: Duration,
) -> Result<ExitStatus, BoundaryError> {
    let pid = Pid::from_raw(i32::try_from(child.pid).unwrap_or(i32::MAX));
    let initial_signal_error = killpg(pid, Signal::SIGTERM).err();
    let cleanup = match tokio::time::timeout(grace, child.wait_for_exit()).await {
        Ok(Ok(())) | Err(_) => finalize_group_and_reap(child).await,
        Ok(Err(wait_error)) => {
            let cleanup = finalize_group_and_reap(child).await;
            return match cleanup {
                Ok(_) => Err(wait_error),
                Err(cleanup_error) => Err(combined_lifecycle_error(
                    "terminate after exit-observation failure",
                    &wait_error.to_string(),
                    &cleanup_error.to_string(),
                )),
            };
        }
    };
    let status = match cleanup {
        Ok(status) => status,
        Err(cleanup_error) => {
            return match initial_signal_error {
                Some(signal_error) => Err(combined_lifecycle_error(
                    "terminate after initial-signal failure",
                    &signal_error.to_string(),
                    &cleanup_error.to_string(),
                )),
                None => Err(cleanup_error),
            };
        }
    };
    match initial_signal_error {
        None | Some(Errno::EPERM | Errno::ESRCH) => Ok(status),
        Some(error) => Err(BoundaryError::Io {
            phase: "initial signal process group",
            reason: error.to_string(),
        }),
    }
}

async fn wait_and_close_group(child: &mut BoundaryChild) -> Result<ExitStatus, BoundaryError> {
    child.wait_for_exit().await?;
    child.finalize_after_exit().await
}

async fn cleanup_after_output_deadline(child: &mut BoundaryChild) -> Result<(), BoundaryError> {
    finalize_group_and_reap(child)
        .await
        .map(|_| ())
        .map_err(|error| BoundaryError::Io {
            phase: "cleanup after child output deadline",
            reason: format!(
                "output streams remained open beyond the lifecycle deadline; cleanup failed: {error}"
            ),
        })
}

fn combined_lifecycle_error(phase: &'static str, primary: &str, cleanup: &str) -> BoundaryError {
    BoundaryError::Io {
        phase,
        reason: format!("primary failure: {primary}; cleanup failure: {cleanup}"),
    }
}

#[derive(Debug, Clone)]
enum ExitObservation {
    Waiting,
    Exited,
    Failed(String),
}

fn spawn_exit_observer(pid: u32) -> Result<watch::Receiver<ExitObservation>, BoundaryError> {
    // One process-wide native service owns all exit observations: Darwin uses
    // EVFILT_PROC/NOTE_EXIT registered before SIGCONT, while other Unix hosts
    // poll waitid(EXITED|WNOWAIT|WNOHANG). Neither path reaps the leader.
    let (sender, receiver) = watch::channel(ExitObservation::Waiting);
    let service = EXIT_OBSERVER_SERVICE
        .get_or_init(ExitObserverService::start)
        .as_ref()
        .map_err(|reason| BoundaryError::Io {
            phase: "start child exit observer service",
            reason: reason.clone(),
        })?;
    service.register(pid, sender)?;
    Ok(receiver)
}

const MAX_ACTIVE_EXIT_OBSERVERS: usize = 256;
#[cfg(not(target_os = "macos"))]
const EXIT_OBSERVER_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Default)]
struct ExitSubscriberState {
    senders: HashMap<u32, watch::Sender<ExitObservation>>,
    fatal: Option<String>,
}

type ExitSubscribers = Arc<Mutex<ExitSubscriberState>>;

static EXIT_OBSERVER_SERVICE: OnceLock<Result<ExitObserverService, String>> = OnceLock::new();

#[cfg(target_os = "macos")]
struct ExitObserverService {
    queue: Arc<Kqueue>,
    subscribers: ExitSubscribers,
}

#[cfg(target_os = "macos")]
impl ExitObserverService {
    fn start() -> Result<Self, String> {
        let queue = Arc::new(Kqueue::new().map_err(|error| error.to_string())?);
        let subscribers = Arc::new(Mutex::new(ExitSubscriberState::default()));
        let worker_queue = queue.clone();
        let worker_subscribers = subscribers.clone();
        std::thread::Builder::new()
            .name("arcana-child-exit-observer".to_owned())
            .spawn(move || darwin_exit_observer_loop(&worker_queue, &worker_subscribers))
            .map_err(|error| error.to_string())?;
        Ok(Self { queue, subscribers })
    }

    fn register(
        &self,
        pid: u32,
        sender: watch::Sender<ExitObservation>,
    ) -> Result<(), BoundaryError> {
        insert_exit_subscriber(&self.subscribers, pid, sender)?;
        let change = KEvent::new(
            pid as usize,
            EventFilter::EVFILT_PROC,
            EventFlag::EV_ADD | EventFlag::EV_ONESHOT,
            FilterFlag::NOTE_EXIT,
            0,
            0,
        );
        if let Err(error) = self.queue.kevent(&[change], &mut [], None) {
            lock_exit_subscribers(&self.subscribers)
                .senders
                .remove(&pid);
            return Err(BoundaryError::Io {
                phase: "register Darwin process-exit observer",
                reason: error.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn darwin_exit_observer_loop(queue: &Kqueue, subscribers: &ExitSubscribers) {
    let placeholder = KEvent::new(
        0,
        EventFilter::EVFILT_PROC,
        EventFlag::empty(),
        FilterFlag::empty(),
        0,
        0,
    );
    let mut events = [placeholder; 64];
    loop {
        let count = match queue.kevent(&[], &mut events, None) {
            Ok(count) => count,
            Err(Errno::EINTR) => continue,
            Err(error) => {
                fail_all_exit_subscribers(subscribers, &error.to_string());
                return;
            }
        };
        for event in &events[..count] {
            let Ok(pid) = u32::try_from(event.ident()) else {
                fail_all_exit_subscribers(
                    subscribers,
                    "kqueue returned a process identifier outside u32",
                );
                return;
            };
            let state = if event.flags().contains(EventFlag::EV_ERROR) {
                ExitObservation::Failed(format!("kqueue process-exit error: {}", event.data()))
            } else if event.filter() == Ok(EventFilter::EVFILT_PROC)
                && event.fflags().contains(FilterFlag::NOTE_EXIT)
            {
                ExitObservation::Exited
            } else {
                ExitObservation::Failed("kqueue returned an unexpected process event".to_owned())
            };
            send_exit_observation(subscribers, pid, state);
        }
    }
}

#[cfg(not(target_os = "macos"))]
struct ExitObserverService {
    subscribers: ExitSubscribers,
    wake: Arc<Condvar>,
}

#[cfg(not(target_os = "macos"))]
impl ExitObserverService {
    fn start() -> Result<Self, String> {
        let subscribers = Arc::new(Mutex::new(ExitSubscriberState::default()));
        let wake = Arc::new(Condvar::new());
        let worker_subscribers = subscribers.clone();
        let worker_wake = wake.clone();
        std::thread::Builder::new()
            .name("arcana-child-exit-observer".to_owned())
            .spawn(move || polling_exit_observer_loop(&worker_subscribers, &worker_wake))
            .map_err(|error| error.to_string())?;
        Ok(Self { subscribers, wake })
    }

    fn register(
        &self,
        pid: u32,
        sender: watch::Sender<ExitObservation>,
    ) -> Result<(), BoundaryError> {
        insert_exit_subscriber(&self.subscribers, pid, sender)?;
        self.wake.notify_one();
        Ok(())
    }
}

fn insert_exit_subscriber(
    subscribers: &ExitSubscribers,
    pid: u32,
    sender: watch::Sender<ExitObservation>,
) -> Result<(), BoundaryError> {
    let mut subscribers = lock_exit_subscribers(subscribers);
    if let Some(reason) = &subscribers.fatal {
        return Err(BoundaryError::Io {
            phase: "register child exit observer",
            reason: format!("observer service is unavailable: {reason}"),
        });
    }
    if subscribers.senders.len() >= MAX_ACTIVE_EXIT_OBSERVERS {
        return Err(BoundaryError::Io {
            phase: "register child exit observer",
            reason: format!(
                "observer capacity of {MAX_ACTIVE_EXIT_OBSERVERS} active children is exhausted"
            ),
        });
    }
    if subscribers.senders.contains_key(&pid) {
        return Err(BoundaryError::Io {
            phase: "register child exit observer",
            reason: "process identifier already has an active observer".to_owned(),
        });
    }
    subscribers.senders.insert(pid, sender);
    Ok(())
}

fn lock_exit_subscribers(
    subscribers: &ExitSubscribers,
) -> std::sync::MutexGuard<'_, ExitSubscriberState> {
    subscribers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn send_exit_observation(subscribers: &ExitSubscribers, pid: u32, state: ExitObservation) {
    if let Some(sender) = lock_exit_subscribers(subscribers).senders.remove(&pid) {
        let _ = sender.send(state);
    }
}

#[cfg(target_os = "macos")]
fn fail_all_exit_subscribers(subscribers: &ExitSubscribers, reason: &str) {
    let senders: Vec<_> = {
        let mut state = lock_exit_subscribers(subscribers);
        state.fatal = Some(reason.to_owned());
        state.senders.drain().map(|(_, sender)| sender).collect()
    };
    for sender in senders {
        let _ = sender.send(ExitObservation::Failed(reason.to_owned()));
    }
}

#[cfg(not(target_os = "macos"))]
fn polling_exit_observer_loop(subscribers: &ExitSubscribers, wake: &Condvar) {
    loop {
        let pids = {
            let mut active = lock_exit_subscribers(subscribers);
            while active.senders.is_empty() {
                active = wake
                    .wait(active)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            active.senders.keys().copied().collect::<Vec<_>>()
        };
        for pid in pids {
            if let Some(state) = poll_exit_without_reaping(pid) {
                send_exit_observation(subscribers, pid, state);
            }
        }
        let active = lock_exit_subscribers(subscribers);
        let (active, _) = wake
            .wait_timeout(active, EXIT_OBSERVER_POLL_INTERVAL)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(active);
    }
}

#[cfg(not(target_os = "macos"))]
fn poll_exit_without_reaping(pid: u32) -> Option<ExitObservation> {
    let raw_pid = i32::try_from(pid).unwrap_or(i32::MAX);
    let Some(wait_pid) = RustixPid::from_raw(raw_pid) else {
        return Some(ExitObservation::Failed(
            "child pid must be positive".to_owned(),
        ));
    };
    match waitid(
        WaitId::Pid(wait_pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
    ) {
        Ok(Some(status)) if status.exited() || status.killed() || status.dumped() => {
            Some(ExitObservation::Exited)
        }
        Ok(Some(_) | None) | Err(rustix::io::Errno::INTR) => None,
        Err(error) => Some(ExitObservation::Failed(error.to_string())),
    }
}

async fn finalize_group_and_reap(child: &mut BoundaryChild) -> Result<ExitStatus, BoundaryError> {
    child.exit_observer.take();
    let pid = child.pid;
    let owned_group = Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX));
    let final_signal = issue_final_group_signal(&mut child.final_signal, owned_group);
    let owned_child = child.child.as_mut().ok_or_else(|| BoundaryError::Io {
        phase: "finalize process group",
        reason: "child ownership is unavailable".to_owned(),
    })?;
    let owned_anchor = child.anchor.as_mut().ok_or_else(|| BoundaryError::Io {
        phase: "finalize process group",
        reason: "group anchor ownership is unavailable".to_owned(),
    })?;

    // The destructive group signal is issued and cached before the first
    // await. Cleanup retries reuse that exact result; they never signal a
    // numeric PGID after either direct child may have been reaped.
    let result = finalize_owned_group(owned_child, owned_anchor, pid, final_signal).await;
    if result.is_ok() {
        child.cleanup_complete = true;
    }
    result
}

async fn finalize_owned_group(
    child: &mut Child,
    anchor: &mut Child,
    child_pid: u32,
    final_signal: Result<(), Errno>,
) -> Result<ExitStatus, BoundaryError> {
    let owned_group = Pid::from_raw(i32::try_from(child_pid).unwrap_or(i32::MAX));
    let mut failures = Vec::new();
    if let Err(error) = validate_final_signal(final_signal) {
        failures.push(error);
        if let Err(error) = child.start_kill() {
            failures.push(BoundaryError::Io {
                phase: "fallback signal process-group leader",
                reason: error.to_string(),
            });
        }
        if let Err(error) = anchor.start_kill() {
            failures.push(BoundaryError::Io {
                phase: "fallback signal process-group anchor",
                reason: error.to_string(),
            });
        }
    }

    let status = match tokio::time::timeout(POST_KILL_REAP_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => Some(status),
        Ok(Err(error)) => {
            failures.push(BoundaryError::Io {
                phase: "reap process-group leader",
                reason: error.to_string(),
            });
            None
        }
        Err(_) => {
            failures.push(BoundaryError::Io {
                phase: "reap process-group leader",
                reason: "direct child remained unreaped beyond the bounded deadline".to_owned(),
            });
            None
        }
    };

    match tokio::time::timeout(POST_KILL_REAP_TIMEOUT, anchor.wait()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            failures.push(BoundaryError::Io {
                phase: "reap process-group anchor",
                reason: error.to_string(),
            });
        }
        Err(_) => {
            failures.push(BoundaryError::Io {
                phase: "reap process-group anchor",
                reason: "anchor remained unreaped beyond the bounded deadline".to_owned(),
            });
        }
    }

    if let Err(error) = require_group_disappeared(owned_group).await {
        failures.push(error);
    }

    if failures.is_empty() {
        return status.ok_or_else(|| BoundaryError::Io {
            phase: "finalize owned process group",
            reason: "leader status is unavailable after successful cleanup".to_owned(),
        });
    }
    if failures.len() == 1 {
        return Err(failures.remove(0));
    }
    Err(BoundaryError::Io {
        phase: "finalize owned process group",
        reason: failures
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; "),
    })
}

fn issue_final_group_signal(
    final_signal: &mut Option<Result<(), Errno>>,
    owned_group: Pid,
) -> Result<(), Errno> {
    if let Some(result) = *final_signal {
        return result;
    }
    let result = killpg(owned_group, Signal::SIGKILL);
    *final_signal = Some(result);
    result
}

fn validate_final_signal(final_signal: Result<(), Errno>) -> Result<(), BoundaryError> {
    match final_signal {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(BoundaryError::Io {
            phase: "final signal process group before reap",
            reason: error.to_string(),
        }),
    }
}

async fn require_group_disappeared(pgid: Pid) -> Result<(), BoundaryError> {
    let deadline = tokio::time::Instant::now() + GROUP_DISAPPEAR_TIMEOUT;
    loop {
        match killpg(pgid, None) {
            Err(Errno::ESRCH) => return Ok(()),
            Ok(()) | Err(Errno::EPERM) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(GROUP_PROBE_POLL).await;
            }
            Ok(()) => {
                return Err(BoundaryError::Io {
                    phase: "verify process-group disappearance",
                    reason: "process group remained present beyond the bounded deadline".to_owned(),
                });
            }
            Err(error) => {
                return Err(BoundaryError::Io {
                    phase: "verify process-group disappearance",
                    reason: error.to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use std::sync::{Arc, Mutex};

    use super::{
        insert_exit_subscriber, issue_final_group_signal, validate_final_signal, BoundaryError,
        ExitObservation, ExitSubscriberState, MAX_ACTIVE_EXIT_OBSERVERS,
    };
    use nix::errno::Errno;
    use nix::unistd::Pid;
    use tokio::sync::watch;

    #[test]
    fn refused_final_signal_never_promotes_to_success() {
        assert!(matches!(
            validate_final_signal(Err(Errno::EPERM)),
            Err(BoundaryError::Io {
                phase: "final signal process group before reap",
                ..
            })
        ));
    }

    #[test]
    fn absent_group_is_safe_only_after_disappearance_proof() {
        assert!(validate_final_signal(Err(Errno::ESRCH)).is_ok());
    }

    #[test]
    fn cached_final_signal_is_never_reissued_against_a_numeric_pgid() {
        let mut cached = Some(Err(Errno::EPERM));
        assert_eq!(
            issue_final_group_signal(&mut cached, Pid::from_raw(i32::MAX)),
            Err(Errno::EPERM)
        );
        assert_eq!(cached, Some(Err(Errno::EPERM)));
    }

    #[test]
    fn observer_capacity_and_fatal_state_fail_closed() {
        let subscribers = Arc::new(Mutex::new(ExitSubscriberState::default()));
        let mut receivers = Vec::new();
        let capacity = u32::try_from(MAX_ACTIVE_EXIT_OBSERVERS).unwrap_or(u32::MAX);
        for pid in 1..=capacity {
            let (sender, receiver) = watch::channel(ExitObservation::Waiting);
            assert!(insert_exit_subscriber(&subscribers, pid, sender).is_ok());
            receivers.push(receiver);
        }
        let (overflow, _) = watch::channel(ExitObservation::Waiting);
        assert!(matches!(
            insert_exit_subscriber(&subscribers, u32::MAX, overflow),
            Err(BoundaryError::Io {
                phase: "register child exit observer",
                ..
            })
        ));

        subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fatal = Some("native observer stopped".to_owned());
        subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .senders
            .clear();
        let (after_fatal, _) = watch::channel(ExitObservation::Waiting);
        assert!(matches!(
            insert_exit_subscriber(&subscribers, 1, after_fatal),
            Err(BoundaryError::Io {
                phase: "register child exit observer",
                ..
            })
        ));
        drop(receivers);
    }
}

#[derive(Clone)]
struct ObservedChunk {
    stream: Stream,
    bytes: Vec<u8>,
}

struct CollectedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    ordered: Vec<ObservedChunk>,
}

enum OutputEvent {
    Chunk(ObservedChunk),
    Done(Result<(), String>),
}

fn spawn_output_reader<R>(
    mut reader: R,
    stream: Stream,
    sender: mpsc::Sender<OutputEvent>,
) -> tokio::task::JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    let _ = sender.send(OutputEvent::Done(Ok(()))).await;
                    break;
                }
                Ok(count) => {
                    if sender
                        .send(OutputEvent::Chunk(ObservedChunk {
                            stream,
                            bytes: buffer[..count].to_vec(),
                        }))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.send(OutputEvent::Done(Err(error.to_string()))).await;
                    break;
                }
            }
        }
    })
}

async fn collect_output(
    mut receiver: mpsc::Receiver<OutputEvent>,
    limit: usize,
    policy: OutputPolicy,
    cancellation: CancellationToken,
) -> Result<CollectedOutput, BoundaryError> {
    let mut scanner = match policy {
        OutputPolicy::Capture => None,
        OutputPolicy::Quarantine { sentinels } => Some(
            QuarantineScanner::new(sentinels, ScannerConfig::default())
                .map_err(|error| BoundaryError::QuarantineInit(error.to_string()))?,
        ),
    };
    let mut collected = CollectedOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
        ordered: Vec::new(),
    };
    let mut total = 0usize;
    let mut completed = 0usize;
    while let Some(event) = receiver.recv().await {
        match event {
            OutputEvent::Chunk(chunk) => {
                total = total.checked_add(chunk.bytes.len()).ok_or_else(|| {
                    cancellation.cancel();
                    BoundaryError::OutputLimitExceeded { limit }
                })?;
                if total > limit {
                    cancellation.cancel();
                    return Err(BoundaryError::OutputLimitExceeded { limit });
                }
                if let Some(scanner) = &mut scanner {
                    if let Err(error) = scanner.push_stream(chunk.stream, &chunk.bytes) {
                        cancellation.cancel();
                        return Err(BoundaryError::OutputQuarantined(error));
                    }
                }
                match chunk.stream {
                    Stream::Stdout => collected.stdout.extend_from_slice(&chunk.bytes),
                    Stream::Stderr => collected.stderr.extend_from_slice(&chunk.bytes),
                }
                collected.ordered.push(chunk);
            }
            OutputEvent::Done(result) => {
                if let Err(reason) = result {
                    cancellation.cancel();
                    return Err(BoundaryError::Io {
                        phase: "read child output",
                        reason,
                    });
                }
                completed += 1;
                if completed == 2 {
                    break;
                }
            }
        }
    }
    if completed != 2 {
        cancellation.cancel();
        return Err(BoundaryError::Io {
            phase: "read child output",
            reason: "output channels closed before both streams completed".to_owned(),
        });
    }
    if let Some(scanner) = &mut scanner {
        if let Err(error) = scanner.check_distributed(&collected.stdout, &collected.stderr) {
            cancellation.cancel();
            return Err(BoundaryError::OutputQuarantined(error));
        }
        if let Err(error) = scanner.finish() {
            cancellation.cancel();
            return Err(BoundaryError::OutputQuarantined(error));
        }
    }
    Ok(collected)
}

fn termination_from_status(status: ExitStatus) -> Termination {
    if let Some(code) = status.code() {
        Termination::Exited(code)
    } else {
        Termination::Signal(status.signal().unwrap_or_default())
    }
}

fn os_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
