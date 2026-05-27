//! `WriteTool` — create or overwrite a file at the given path.
//!
//! The constructor takes an `Arc<ToolRuleSet>` so the path-traversal guard
//! (`path_guard::check`, CWE-22) can short-circuit denied paths before any
//! filesystem I/O. [`WriteTool::default`] ships a permissive rule set;
//! production cascade wiring lands in the CLI bootstrap step.

use std::sync::Arc;

use arcana_core::permission::rule::ToolRuleSet;
use arcana_core::tool::{Tool, ToolError, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::path_guard;

#[derive(Debug, Deserialize)]
struct WriteInput {
    path: String,
    content: String,
    #[serde(default)]
    create_parent_dirs: bool,
}

pub struct WriteTool {
    rules: Arc<ToolRuleSet>,
}

impl Default for WriteTool {
    fn default() -> Self {
        Self {
            rules: Arc::new(ToolRuleSet::default()),
        }
    }
}

impl WriteTool {
    #[must_use]
    pub fn new(rules: Arc<ToolRuleSet>) -> Self {
        Self { rules }
    }
}

#[async_trait]
impl Tool for WriteTool {
    fn name(&self) -> &'static str {
        "write"
    }

    fn description(&self) -> &'static str {
        "Write `content` to a file at `path`, creating or overwriting it."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["path", "content"],
            "properties": {
                "path": { "type": "string", "minLength": 1 },
                "content": { "type": "string" },
                "create_parent_dirs": { "type": "boolean" }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolOutput, ToolError> {
        let parsed: WriteInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        let cwd = std::env::current_dir()
            .map_err(|err| ToolError::ExecutionFailed(format!("cwd unavailable: {err}")))?;
        let canonical = path_guard::check(&parsed.path, &self.rules, &cwd)?;

        let existed = tokio::fs::metadata(&canonical).await.is_ok();

        if parsed.create_parent_dirs {
            if let Some(parent) = canonical.parent() {
                if !parent.as_os_str().is_empty() {
                    tokio::fs::create_dir_all(parent).await.map_err(|err| {
                        ToolError::ExecutionFailed(format!(
                            "create_dir_all {}: {err}",
                            parent.display()
                        ))
                    })?;
                }
            }
        }

        let bytes_written = parsed.content.len();
        tokio::fs::write(&canonical, parsed.content.as_bytes())
            .await
            .map_err(|err| {
                ToolError::ExecutionFailed(format!("write {}: {err}", canonical.display()))
            })?;

        Ok(ToolOutput {
            content: format!("wrote {bytes_written} bytes to {}", canonical.display()),
            metadata: Some(json!({
                "path": canonical.to_string_lossy(),
                "bytes_written": bytes_written,
                "created": !existed
            })),
        })
    }
}
