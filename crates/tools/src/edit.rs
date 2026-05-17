//! `EditTool` — replace a unique substring inside a file.

use arcana_core::tool::{Tool, ToolError, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
struct EditInput {
    path: String,
    old_string: String,
    new_string: String,
}

#[derive(Default)]
pub struct EditTool;

impl EditTool {
    #[must_use]
    pub fn new() -> Self {
        Self
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

    async fn execute(&self, input: Value) -> Result<ToolOutput, ToolError> {
        let parsed: EditInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        let contents = tokio::fs::read_to_string(&parsed.path)
            .await
            .map_err(|err| ToolError::ExecutionFailed(format!("read {}: {err}", parsed.path)))?;
        let occurrences = contents.matches(&parsed.old_string).count();
        match occurrences {
            0 => Err(ToolError::ExecutionFailed(format!(
                "old_string not found in {}",
                parsed.path
            ))),
            1 => {
                let updated = contents.replacen(&parsed.old_string, &parsed.new_string, 1);
                tokio::fs::write(&parsed.path, updated.as_bytes())
                    .await
                    .map_err(|err| {
                        ToolError::ExecutionFailed(format!("write {}: {err}", parsed.path))
                    })?;
                Ok(ToolOutput {
                    content: format!("edited {}", parsed.path),
                    metadata: Some(json!({ "path": parsed.path, "replacements": 1 })),
                })
            }
            n => Err(ToolError::ExecutionFailed(format!(
                "old_string is not unique in {}: {n} occurrences",
                parsed.path
            ))),
        }
    }
}
