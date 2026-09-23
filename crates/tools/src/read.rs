//! `ReadTool` — read the UTF-8 contents of a file with an optional size cap.
//!
//! The constructor takes an `Arc<ToolRuleSet>` so the path-traversal guard
//! (`path_guard::check`, CWE-22) can short-circuit denied paths before any
//! filesystem I/O. The shipped [`ReadTool::default`] ships a permissive rule
//! set; production cascade wiring lands in the CLI bootstrap step (see
//! `docs/reference/architecture.md` § Permission layer).

use std::path::PathBuf;
use std::sync::Arc;

use arcana_core::permission::rule::ToolRuleSet;
use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::path_guard;

const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct ReadInput {
    path: String,
    #[serde(default)]
    max_bytes: Option<u64>,
}

pub struct ReadTool {
    rules: Arc<ToolRuleSet>,
    root: Option<PathBuf>,
}

impl Default for ReadTool {
    fn default() -> Self {
        Self {
            rules: Arc::new(ToolRuleSet::default()),
            root: None,
        }
    }
}

impl ReadTool {
    /// Construct a tool with an explicit rule set. Relative paths resolve
    /// against the process working directory.
    #[must_use]
    pub fn new(rules: Arc<ToolRuleSet>) -> Self {
        Self { rules, root: None }
    }

    /// Construct a tool that resolves relative paths against `root` instead of
    /// the ambient process working directory.
    ///
    /// A headless run is given one working directory on the command line and
    /// may share a process with other work; resolving against `std::env::
    /// current_dir()` makes the tool's reach depend on global mutable state
    /// nobody in the call chain can see.
    #[must_use]
    pub fn with_root(rules: Arc<ToolRuleSet>, root: impl Into<PathBuf>) -> Self {
        Self {
            rules,
            root: Some(root.into()),
        }
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

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        let parsed: ReadInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        let cwd = crate::path_guard::working_directory(self.root.as_deref())?;
        let canonical: PathBuf = path_guard::check(&parsed.path, &self.rules, &cwd)?;
        let cap = parsed.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
        let metadata = tokio::fs::metadata(&canonical).await.map_err(|err| {
            ToolError::ExecutionFailed(format!("stat {}: {err}", canonical.display()))
        })?;
        let size = metadata.len();
        if size > cap {
            return Err(ToolError::ExecutionFailed(format!(
                "file {} is {size} bytes, exceeds cap {cap}",
                canonical.display()
            )));
        }
        let content = tokio::fs::read_to_string(&canonical).await.map_err(|err| {
            ToolError::ExecutionFailed(format!("read {}: {err}", canonical.display()))
        })?;
        Ok(ToolOutput {
            content,
            metadata: Some(json!({
                "path": canonical.to_string_lossy(),
                "size_bytes": size
            })),
        })
    }
}
