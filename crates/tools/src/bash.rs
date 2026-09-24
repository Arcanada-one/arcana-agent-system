//! `BashTool` — shell command execution with timeout and stderr capture.
//!
//! Phase 1 ships the tool behind a schema-only gate (Layer 1 of the
//! permission cascade). `BashTool::new()` keeps that pre-Layer-3 behaviour
//! unchanged — no rule checking, fully backward compatible — and remains
//! genuinely unguarded: it MUST NOT be registered in a cascade that relies
//! on `bash` respecting `permissions.toml`.
//!
//! `BashTool::with_rules` layers Layer 3 (`RuleLayer` / `permissions.toml`
//! `[tool.bash] allow_commands` / `deny_commands`) directly onto `execute()`
//! as a hard denylist backstop: an explicit `Deny` verdict blocks the
//! command before `/bin/sh` is ever spawned. `Allow`, `Defer`, and
//! `ReplaceInput` all fall through to normal execution — this is
//! intentionally not a full re-implementation of the Schema/HookBridge/
//! Interactive cascade, just the tool-local enforcement point Layer 3
//! needs.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arcana_core::permission::{LayerDecision, PermissionLayer, RuleLayer};
use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use arcana_execution_boundary::{CleanEnv, ProcessSpec, Termination, SAFE_SYSTEM_PATH};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Deserialize)]
struct BashInput {
    command: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    env_vars: BTreeMap<String, String>,
}

/// The sandbox `HOME` a `BashTool` uses when the caller names none.
///
/// A fixed path under the world-writable `/tmp`, shared by every run on the
/// host. [`BashTool::with_home`] is how a caller stops sharing it; see that
/// method for why a headless run must.
const FALLBACK_SANDBOX_HOME: &str = "/tmp/arcana-runtime/bash";

#[derive(Default)]
pub struct BashTool {
    rules: Option<Arc<RuleLayer>>,
    cwd: Option<PathBuf>,
    home: Option<PathBuf>,
}

impl BashTool {
    /// Construct a `BashTool` with no Layer-3 enforcement. Pre-Layer-3
    /// behaviour: every command reaches `/bin/sh` unchecked, in the process
    /// working directory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: None,
            cwd: None,
            home: None,
        }
    }

    /// Construct a `BashTool` that consults `rules` before spawning a
    /// shell. A `Deny` verdict from the `RuleLayer` short-circuits
    /// `execute()` with `ToolError::PermissionDenied` before `/bin/sh` is
    /// invoked.
    #[must_use]
    pub fn with_rules(rules: Arc<RuleLayer>) -> Self {
        Self {
            rules: Some(rules),
            cwd: None,
            home: None,
        }
    }

    /// Spawn the shell in `cwd` instead of the ambient process working
    /// directory.
    ///
    /// The directory a command runs in IS most of its blast radius, and a
    /// headless run is told which one to use on its command line. Reading it
    /// from `std::env::current_dir()` makes that radius depend on global
    /// mutable state shared with every other task in the process.
    #[must_use]
    pub fn in_directory(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Hand the shell `home` as `HOME` instead of [`FALLBACK_SANDBOX_HOME`].
    ///
    /// # Why the default is not good enough for a headless run (A2-253)
    ///
    /// `/tmp/arcana-runtime/bash` is a **fixed, predictable path inside a
    /// world-writable directory**, and it is the same path for every run and
    /// every workspace on the host. Two consequences, both measured on
    /// arcana-devs on 2026-09-24 rather than assumed:
    ///
    /// * It is shared state. Two concurrent runs — the normal way this fleet
    ///   works — get one `HOME`, so anything one of them writes to `~` is
    ///   visible to, and clobberable by, the other.
    /// * Its creation is a race nobody owns. On this host the directory
    ///   already existed, `drwx------ dev dev`, dated 2026-08-01, created by
    ///   something outside this run; `/tmp` itself is `drwxrwxrwt`, and the
    ///   sticky bit stops a local user deleting another's entry but does
    ///   nothing to stop one pre-creating a path that does not exist yet. A
    ///   `HOME` the agent did not create is a `HOME` whose contents it cannot
    ///   reason about.
    ///
    /// The caller is responsible for the directory existing before the first
    /// command runs; `arcana run` creates one per run under its own state
    /// directory. That the directory exists is worth stating separately from
    /// the above, because it is NOT what fixes `git config --global`: measured
    /// side by side, git reports `unable to read config file
    /// '$HOME/.gitconfig': No such file or directory` identically whether
    /// `HOME` exists or not — that message is about the config file, which a
    /// credential-free lane has by design. What an existing `HOME` does fix is
    /// everything that needs the directory itself: a bare `cd`, and any tool
    /// that writes under `~`.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }
}

#[async_trait]
impl Tool for BashTool {
    fn name(&self) -> &'static str {
        "bash"
    }

    fn description(&self) -> &'static str {
        "Run a shell command via /bin/sh -c with a timeout."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["command"],
            "properties": {
                "command": { "type": "string", "minLength": 1 },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 600 },
                "env_vars": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        if let Some(rules) = &self.rules {
            if let LayerDecision::Deny(reason) = rules.evaluate("bash", &input).await {
                return Err(ToolError::PermissionDenied(reason));
            }
        }

        let parsed: BashInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        let timeout_secs = parsed.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECS);
        let home = self
            .home
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new(FALLBACK_SANDBOX_HOME));
        let env = CleanEnv::build(home, SAFE_SYSTEM_PATH)
            .and_then(|env| env.with_declared_vars(&parsed.env_vars))
            .map_err(|err| ToolError::ExecutionFailed(format!("clean environment: {err}")))?;
        let cwd = crate::path_guard::working_directory(self.cwd.as_deref())?;
        let output = ProcessSpec::new(std::path::Path::new("/bin/sh"), env)
            .args(["-c", parsed.command.as_str()])
            .cwd(cwd)
            .timeout(Duration::from_secs(timeout_secs))
            .run(CancellationToken::new())
            .await
            .map_err(|err| ToolError::ExecutionFailed(format!("execution boundary: {err}")))?;

        if output.termination == Termination::TimedOut {
            return Err(ToolError::ExecutionFailed(format!(
                "timeout after {timeout_secs}s"
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let exit_code = output.exit_code.unwrap_or(-1);
        let success = output.success;

        let metadata = json!({
            "exit_code": exit_code,
            "stderr": stderr,
            "timed_out": false
        });

        if success {
            Ok(ToolOutput {
                content: stdout,
                metadata: Some(metadata),
            })
        } else {
            let cause = match output.termination {
                Termination::Signal(signal) => format!("signal {signal}"),
                _ => format!("exit {exit_code}"),
            };
            Err(ToolError::ExecutionFailed(format!(
                "{cause}: {}",
                stderr.trim()
            )))
        }
    }
}
