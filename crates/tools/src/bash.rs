//! `BashTool` — shell command execution with timeout and stderr capture.
//!
//! Phase 1 ships the tool behind a schema-only gate (Layer 1 of the
//! permission cascade). Runtime allow/deny rules belong to Layer 3 and
//! land in a subsequent task. Operators MUST NOT register `BashTool` in a
//! cascade that lacks Layer 3 enforcement.

use std::collections::BTreeMap;
use std::time::Duration;

use arcana_core::tool::{Tool, ToolError, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::process::Command;

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
pub struct BashTool;

impl BashTool {
    #[must_use]
    pub fn new() -> Self {
        Self
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

    async fn execute(&self, input: Value) -> Result<ToolOutput, ToolError> {
        let parsed: BashInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        let timeout_secs = parsed.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECS);

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(&parsed.command);
        for (key, value) in &parsed.env_vars {
            cmd.env(key, value);
        }

        let exec = cmd.output();
        let output = tokio::time::timeout(Duration::from_secs(timeout_secs), exec)
            .await
            .map_err(|_| ToolError::ExecutionFailed(format!("timeout after {timeout_secs}s")))?
            .map_err(|err| ToolError::ExecutionFailed(format!("spawn: {err}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let exit_code = output.status.code().unwrap_or(-1);
        let success = output.status.success();

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
