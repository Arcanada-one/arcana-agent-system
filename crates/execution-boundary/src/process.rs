//! The sole shipped-runtime owner of subprocess construction.
//!
//! Callers provide a declarative [`ProcessSpec`]. They cannot add inherited
//! environment entries, choose ambient stdio, or opt out of process-group
//! ownership. Higher-level callers should use [`ProcessSpec::run`], which also
//! provides timeout/cancellation cleanup and output quarantine. The supervisor
//! uses [`spawn_piped`] because it owns a longer-lived heartbeat lifecycle.

#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use nix::errno::Errno;
use nix::pty::{openpty, Winsize as NixWinsize};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use rustix::process::{waitid, Pid as RustixPid, WaitId, WaitIdOptions};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::mpsc;
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
for arcana_fd_path in /proc/self/fd/* /dev/fd/*; do
  [ -e "$arcana_fd_path" ] || continue
  arcana_fd=${arcana_fd_path##*/}
  case "$arcana_fd" in ''|*[!0-9]*) continue ;; esac
  [ "$arcana_fd" -le 2 ] && continue
  eval "exec ${arcana_fd}>&-"
done
exec /usr/bin/env -u PWD -u OLDPWD -u SHLVL "$@"
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
            let _ = finalize_group_and_reap(&mut child).await;
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
    child: Child,
    group_closed: bool,
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
        self.child.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<tokio::process::ChildStderr> {
        self.child.stderr.take()
    }

    /// Observe direct-child exit without reaping the process-group leader.
    ///
    /// The retained zombie pins PID=PGID until the boundary has issued its
    /// final destructive group signal, preventing numeric-PGID reuse.
    ///
    /// # Errors
    /// Returns an I/O error when `waitid(WNOWAIT)` cannot observe the owned
    /// direct child.
    pub async fn wait_for_exit(&self) -> Result<(), BoundaryError> {
        wait_for_exit_unreaped(self.pid).await
    }

    /// Issue the last destructive group signal while PID=PGID is pinned, then
    /// reap the direct child and prove the group disappeared using signal 0.
    ///
    /// # Errors
    /// Returns an I/O error for signalling, reaping, or disappearance failure.
    pub async fn finalize_after_exit(&mut self) -> Result<ExitStatus, BoundaryError> {
        if !child_exit_is_observable(self.pid)? {
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
        // `tokio::process::Child::kill_on_drop` covers the leader. Explicitly
        // signal the owned process group as well so dropping a future cannot
        // strand ordinary descendants merely because async cleanup was not
        // polled to completion.
        if !self.group_closed {
            let pgid = Pid::from_raw(i32::try_from(self.pid).unwrap_or(i32::MAX));
            let _ = killpg(pgid, Signal::SIGKILL);
            self.group_closed = true;
        }
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.start_kill();
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
        child: BoundaryChild {
            pid,
            child,
            group_closed: false,
        },
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
    Ok(BoundaryChild {
        pid,
        child,
        group_closed: false,
    })
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

const EXIT_OBSERVATION_POLL: Duration = Duration::from_millis(5);
const POST_KILL_REAP_TIMEOUT: Duration = Duration::from_millis(500);
const GROUP_DISAPPEAR_TIMEOUT: Duration = Duration::from_millis(500);

async fn terminate_group(
    child: &mut BoundaryChild,
    grace: Duration,
) -> Result<ExitStatus, BoundaryError> {
    let pid = Pid::from_raw(i32::try_from(child.pid).unwrap_or(i32::MAX));
    if let Err(signal_error) = send_group_signal(pid, Signal::SIGTERM) {
        let cleanup = finalize_group_and_reap(child).await;
        return match cleanup {
            Ok(_) => Err(signal_error),
            Err(cleanup_error) => Err(cleanup_error),
        };
    }
    match tokio::time::timeout(grace, child.wait_for_exit()).await {
        Ok(Ok(())) | Err(_) => finalize_group_and_reap(child).await,
        Ok(Err(wait_error)) => {
            let cleanup = finalize_group_and_reap(child).await;
            match cleanup {
                Ok(_) => Err(wait_error),
                Err(cleanup_error) => Err(cleanup_error),
            }
        }
    }
}

async fn wait_and_close_group(child: &mut BoundaryChild) -> Result<ExitStatus, BoundaryError> {
    child.wait_for_exit().await?;
    child.finalize_after_exit().await
}

fn send_group_signal(pgid: Pid, signal: Signal) -> Result<(), BoundaryError> {
    match killpg(pgid, signal) {
        Ok(()) => Ok(()),
        Err(err) => Err(BoundaryError::Io {
            phase: "signal process group",
            reason: err.to_string(),
        }),
    }
}

fn child_exit_is_observable(pid: u32) -> Result<bool, BoundaryError> {
    let raw_pid = i32::try_from(pid).unwrap_or(i32::MAX);
    let wait_pid = RustixPid::from_raw(raw_pid).ok_or_else(|| BoundaryError::Io {
        phase: "observe child exit without reaping",
        reason: "child pid must be positive".to_owned(),
    })?;
    match waitid(
        WaitId::Pid(wait_pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Ok(Some(_)) => Ok(true),
        Ok(None) | Err(rustix::io::Errno::INTR) => Ok(false),
        Err(error) => Err(BoundaryError::Io {
            phase: "observe child exit without reaping",
            reason: error.to_string(),
        }),
    }
}

async fn wait_for_exit_unreaped(pid: u32) -> Result<(), BoundaryError> {
    loop {
        if child_exit_is_observable(pid)? {
            return Ok(());
        }
        tokio::time::sleep(EXIT_OBSERVATION_POLL).await;
    }
}

async fn finalize_group_and_reap(child: &mut BoundaryChild) -> Result<ExitStatus, BoundaryError> {
    let pgid = Pid::from_raw(i32::try_from(child.pid).unwrap_or(i32::MAX));
    let final_signal = if child.group_closed {
        Ok(())
    } else {
        let result = killpg(pgid, Signal::SIGKILL);
        // This is the last nonzero signal permitted for this numeric PGID. Set
        // the fence even when delivery fails so Drop never signals post-reap.
        child.group_closed = true;
        result
    };
    if final_signal.is_err() {
        // Direct-child handles remain PID-stable until wait. This fallback
        // cannot contain descendants, but ensures the leader itself is reaped
        // before the signalling error is returned.
        let _ = child.child.start_kill();
    }

    let status = match tokio::time::timeout(POST_KILL_REAP_TIMEOUT, child.child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            return Err(BoundaryError::Io {
                phase: "reap process-group leader",
                reason: error.to_string(),
            });
        }
        Err(_) => {
            return Err(BoundaryError::Io {
                phase: "reap process-group leader",
                reason: "direct child remained unreaped beyond the bounded deadline".to_owned(),
            });
        }
    };

    require_group_disappeared(pgid).await?;
    match final_signal {
        Ok(()) | Err(Errno::EPERM) => Ok(status),
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
                tokio::time::sleep(EXIT_OBSERVATION_POLL).await;
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
