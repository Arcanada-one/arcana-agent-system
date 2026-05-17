//! `ReadTool` — read the UTF-8 contents of a file with an optional size cap.

use arcana_core::tool::{Tool, ToolError, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct ReadInput {
    path: String,
    #[serde(default)]
    max_bytes: Option<u64>,
}

#[derive(Default)]
pub struct ReadTool;

impl ReadTool {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Tool for ReadTool {
    fn name(&self) -> &'static str {
        "read"
    }

    fn description(&self) -> &'static str {
        "Read the UTF-8 contents of a file at the given path."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": { "type": "string", "minLength": 1 },
                "max_bytes": { "type": "integer", "minimum": 1 }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolOutput, ToolError> {
        let parsed: ReadInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        let cap = parsed.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
        let metadata = tokio::fs::metadata(&parsed.path)
            .await
            .map_err(|err| ToolError::ExecutionFailed(format!("stat {}: {err}", parsed.path)))?;
        let size = metadata.len();
        if size > cap {
            return Err(ToolError::ExecutionFailed(format!(
                "file {} is {size} bytes, exceeds cap {cap}",
                parsed.path
            )));
        }
        let content = tokio::fs::read_to_string(&parsed.path)
            .await
            .map_err(|err| ToolError::ExecutionFailed(format!("read {}: {err}", parsed.path)))?;
        Ok(ToolOutput {
            content,
            metadata: Some(json!({ "path": parsed.path, "size_bytes": size })),
        })
    }
}
