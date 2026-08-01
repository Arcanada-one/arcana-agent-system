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
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStdout, Command};
use tokio_util::sync::CancellationToken;

use crate::{CleanEnv, EnvError, QuarantineScanner, ScanError, ScannerConfig, Stream};

/// Deterministic executable search path used by shipped callers.
///
/// Executables themselves must still be supplied as absolute paths. `PATH` is
/// retained for declared helpers that those executables may invoke.
pub const SAFE_SYSTEM_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

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
        let read_limit = u64::try_from(self.output_limit.saturating_add(1)).unwrap_or(u64::MAX);
        let stdout_task = tokio::spawn(async move {
            let mut data = Vec::new();
            stdout
                .take(read_limit)
                .read_to_end(&mut data)
                .await
                .map(|_| data)
        });
        let stderr_task = tokio::spawn(async move {
            let mut data = Vec::new();
            stderr
                .take(read_limit)
                .read_to_end(&mut data)
                .await
                .map(|_| data)
        });

        let deadline = tokio::time::sleep(self.timeout);
        tokio::pin!(deadline);
        let (status, forced) = tokio::select! {
            result = child.child_mut().wait() => {
                (result.map_err(|err| BoundaryError::Io {
                    phase: "wait",
                    reason: err.to_string(),
                })?, None)
            }
            () = cancellation.cancelled() => {
                let status = terminate_group(&mut child, self.termination_grace).await?;
                (status, Some(Termination::Cancelled))
            }
            () = &mut deadline => {
                let status = terminate_group(&mut child, self.termination_grace).await?;
                (status, Some(Termination::TimedOut))
            }
        };

        let stdout = join_reader(stdout_task, "read stdout").await?;
        let stderr = join_reader(stderr_task, "read stderr").await?;
        if stdout.len().saturating_add(stderr.len()) > self.output_limit {
            return Err(BoundaryError::OutputLimitExceeded {
                limit: self.output_limit,
            });
        }
        scan_before_release(&self.output_policy, &stdout, &stderr)?;

        let termination = forced.unwrap_or_else(|| termination_from_status(status));
        Ok(BoundaryOutput {
            success: status.success() && matches!(termination, Termination::Exited(0)),
            exit_code: status.code(),
            stdout,
            stderr,
            termination,
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
        self.child
            .child_mut()
            .wait()
            .await
            .map_err(|error| BoundaryError::Io {
                phase: "wait for pseudo-terminal child",
                reason: error.to_string(),
            })
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

    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
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
        child: BoundaryChild { pid, child },
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
    Ok(BoundaryChild { pid, child })
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

async fn terminate_group(
    child: &mut BoundaryChild,
    grace: Duration,
) -> Result<ExitStatus, BoundaryError> {
    let pid = Pid::from_raw(i32::try_from(child.pid).unwrap_or(i32::MAX));
    send_group_signal(pid, Signal::SIGTERM)?;
    if let Ok(result) = tokio::time::timeout(grace, child.child_mut().wait()).await {
        result.map_err(|err| BoundaryError::Io {
            phase: "wait after SIGTERM",
            reason: err.to_string(),
        })
    } else {
        send_group_signal(pid, Signal::SIGKILL)?;
        child
            .child_mut()
            .wait()
            .await
            .map_err(|err| BoundaryError::Io {
                phase: "wait after SIGKILL",
                reason: err.to_string(),
            })
    }
}

fn send_group_signal(pgid: Pid, signal: Signal) -> Result<(), BoundaryError> {
    match killpg(pgid, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(err) => Err(BoundaryError::Io {
            phase: "signal process group",
            reason: err.to_string(),
        }),
    }
}

async fn join_reader(
    task: tokio::task::JoinHandle<Result<Vec<u8>, std::io::Error>>,
    phase: &'static str,
) -> Result<Vec<u8>, BoundaryError> {
    task.await
        .map_err(|err| BoundaryError::Io {
            phase,
            reason: err.to_string(),
        })?
        .map_err(|err| BoundaryError::Io {
            phase,
            reason: err.to_string(),
        })
}

fn scan_before_release(
    policy: &OutputPolicy,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), BoundaryError> {
    let OutputPolicy::Quarantine { sentinels } = policy else {
        return Ok(());
    };
    let mut scanner = QuarantineScanner::new(sentinels.clone(), ScannerConfig::default())
        .map_err(|err| BoundaryError::QuarantineInit(err.to_string()))?;
    let _ = scanner.push_stream(Stream::Stdout, stdout)?;
    let _ = scanner.push_stream(Stream::Stderr, stderr)?;
    let _ = scanner.finish()?;
    Ok(())
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
