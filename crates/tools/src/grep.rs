//! `GrepTool` — regex search across a single file or a directory tree.

use std::path::{Path, PathBuf};

use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use regex::RegexBuilder;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
struct GrepInput {
    pattern: String,
    #[serde(default = "default_path")]
    path: String,
    #[serde(default = "default_recursive")]
    recursive: bool,
    #[serde(default)]
    case_insensitive: bool,
}

fn default_path() -> String {
    ".".to_owned()
}

fn default_recursive() -> bool {
    true
}

#[derive(Default)]
pub struct GrepTool;

impl GrepTool {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

async fn collect_files(
    root: &Path,
    recursive: bool,
    out: &mut Vec<PathBuf>,
) -> std::io::Result<()> {
    let metadata = tokio::fs::metadata(root).await?;
    if metadata.is_file() {
        out.push(root.to_path_buf());
        return Ok(());
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let entry_type = entry.file_type().await?;
            if entry_type.is_dir() {
                if recursive {
                    stack.push(path);
                }
            } else if entry_type.is_file() {
                out.push(path);
            }
        }
    }
    Ok(())
}

#[async_trait]
impl Tool for GrepTool {
    fn name(&self) -> &'static str {
        "grep"
    }

    fn description(&self) -> &'static str {
        "Search files for lines matching a regex pattern."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["pattern"],
            "properties": {
                "pattern": { "type": "string", "minLength": 1 },
                "path": { "type": "string", "minLength": 1 },
                "recursive": { "type": "boolean" },
                "case_insensitive": { "type": "boolean" }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        let parsed: GrepInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        let regex = RegexBuilder::new(&parsed.pattern)
            .case_insensitive(parsed.case_insensitive)
            .build()
            .map_err(|err| ToolError::InvalidInput(format!("invalid regex: {err}")))?;

        let mut files = Vec::new();
        collect_files(Path::new(&parsed.path), parsed.recursive, &mut files)
            .await
            .map_err(|err| ToolError::ExecutionFailed(format!("walk {}: {err}", parsed.path)))?;

        let mut matches = Vec::new();
        let mut count: usize = 0;
        for file in &files {
            let Ok(body) = tokio::fs::read_to_string(file).await else {
                continue; // skip non-UTF-8 / unreadable files silently
            };
            for (idx, line) in body.lines().enumerate() {
                if regex.is_match(line) {
                    matches.push(format!("{}:{}:{}", file.display(), idx + 1, line));
                    count += 1;
                }
            }
        }

        Ok(ToolOutput {
            content: matches.join("\n"),
            metadata: Some(json!({
                "match_count": count,
                "files_scanned": files.len()
            })),
        })
    }
}
