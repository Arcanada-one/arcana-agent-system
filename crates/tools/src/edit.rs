//! `EditTool` — replace a unique substring inside a file.
//!
//! The constructor takes an `Arc<ToolRuleSet>` so the path-traversal guard
//! (`path_guard::check`, CWE-22) can short-circuit denied paths before any
//! filesystem I/O. [`EditTool::default`] ships a permissive rule set;
//! production cascade wiring lands in the CLI bootstrap step.

use std::sync::Arc;

use arcana_core::permission::rule::ToolRuleSet;
use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::path_guard;

#[derive(Debug, Deserialize)]
struct EditInput {
    path: String,
    old_string: String,
    new_string: String,
}

pub struct EditTool {
    rules: Arc<ToolRuleSet>,
}

impl Default for EditTool {
    fn default() -> Self {
        Self {
            rules: Arc::new(ToolRuleSet::default()),
        }
    }
}

impl EditTool {
    #[must_use]
    pub fn new(rules: Arc<ToolRuleSet>) -> Self {
        Self { rules }
    }
}

#[async_trait]
impl Tool for EditTool {
    fn name(&self) -> &'static str {
        "edit"
    }

    fn description(&self) -> &'static str {
        "Replace a unique substring inside a file. Fails on zero or multiple matches."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["path", "old_string", "new_string"],
            "properties": {
                "path": { "type": "string", "minLength": 1 },
                "old_string": { "type": "string", "minLength": 1 },
                "new_string": { "type": "string" }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        let parsed: EditInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        let cwd = std::env::current_dir()
            .map_err(|err| ToolError::ExecutionFailed(format!("cwd unavailable: {err}")))?;
        let canonical = path_guard::check(&parsed.path, &self.rules, &cwd)?;
        let contents = tokio::fs::read_to_string(&canonical).await.map_err(|err| {
            ToolError::ExecutionFailed(format!("read {}: {err}", canonical.display()))
        })?;
        let occurrences = contents.matches(&parsed.old_string).count();
        match occurrences {
            0 => Err(ToolError::ExecutionFailed(format!(
                "old_string not found in {}",
                canonical.display()
            ))),
            1 => {
                let updated = contents.replacen(&parsed.old_string, &parsed.new_string, 1);
                tokio::fs::write(&canonical, updated.as_bytes())
                    .await
                    .map_err(|err| {
                        ToolError::ExecutionFailed(format!("write {}: {err}", canonical.display()))
                    })?;
                Ok(ToolOutput {
                    content: format!("edited {}", canonical.display()),
                    metadata: Some(json!({
                        "path": canonical.to_string_lossy(),
                        "replacements": 1
                    })),
                })
            }
            n => Err(ToolError::ExecutionFailed(format!(
                "old_string is not unique in {}: {n} occurrences",
                canonical.display()
            ))),
        }
    }
}
