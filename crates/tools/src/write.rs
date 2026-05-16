//! `WriteTool` — create or overwrite a file at the given path.

use std::path::Path;

use arcana_core::tool::{Tool, ToolError, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
struct WriteInput {
    path: String,
    content: String,
    #[serde(default)]
    create_parent_dirs: bool,
}

#[derive(Default)]
pub struct WriteTool;

impl WriteTool {
    #[must_use]
    pub fn new() -> Self {
        Self
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

        let existed = tokio::fs::metadata(&parsed.path).await.is_ok();

        if parsed.create_parent_dirs {
            if let Some(parent) = Path::new(&parsed.path).parent() {
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
        tokio::fs::write(&parsed.path, parsed.content.as_bytes())
            .await
            .map_err(|err| ToolError::ExecutionFailed(format!("write {}: {err}", parsed.path)))?;

        Ok(ToolOutput {
            content: format!("wrote {bytes_written} bytes to {}", parsed.path),
            metadata: Some(json!({
                "path": parsed.path,
                "bytes_written": bytes_written,
                "created": !existed
            })),
        })
    }
}
