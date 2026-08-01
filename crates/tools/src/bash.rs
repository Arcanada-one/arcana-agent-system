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

#[derive(Default)]
pub struct BashTool {
    rules: Option<Arc<RuleLayer>>,
}

impl BashTool {
    /// Construct a `BashTool` with no Layer-3 enforcement. Pre-Layer-3
    /// behaviour: every command reaches `/bin/sh` unchecked.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: None }
    }

    /// Construct a `BashTool` that consults `rules` before spawning a
    /// shell. A `Deny` verdict from the `RuleLayer` short-circuits
    /// `execute()` with `ToolError::PermissionDenied` before `/bin/sh` is
    /// invoked.
    #[must_use]
    pub fn with_rules(rules: Arc<RuleLayer>) -> Self {
        Self { rules: Some(rules) }
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
        if !parsed.env_vars.is_empty() {
            return Err(ToolError::InvalidInput(
                "env_vars are disabled: subprocesses receive only the constructed clean environment"
                    .to_owned(),
            ));
        }

        let env = CleanEnv::build(
            std::path::Path::new("/tmp/arcana-runtime/bash"),
            SAFE_SYSTEM_PATH,
        )
        .map_err(|err| ToolError::ExecutionFailed(format!("clean environment: {err}")))?;
        let output = ProcessSpec::new(std::path::Path::new("/bin/sh"), env)
            .args(["-c", parsed.command.as_str()])
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
            Err(ToolError::ExecutionFailed(format!(
                "exit {exit_code}: {}",
                stderr.trim()
            )))
        }
    }
}
