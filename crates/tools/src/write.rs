//! `WriteTool` — create or overwrite a file at the given path.
//!
//! The constructor takes an `Arc<ToolRuleSet>` so the path-traversal guard
//! (`path_guard::check`, CWE-22) can short-circuit denied paths before any
//! filesystem I/O. [`WriteTool::default`] ships a permissive rule set;
//! production cascade wiring lands in the CLI bootstrap step.

use std::path::PathBuf;
use std::sync::Arc;

use arcana_core::hooks::audit::BYTES_WRITTEN;
use arcana_core::permission::rule::ToolRuleSet;
use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::path_guard;

/// Why an empty `write` is refused rather than performed.
///
/// Measured in the A2-285 live run: the model called `write` twice, each call
/// created the same 0-byte file, each was recorded `outcome: success` in the
/// audit log, and the run's effect check read the changed tree digest as
/// progress. The page it was asked for did not exist. Nothing in the tool, the
/// log or the verdict could tell "wrote the deliverable" from "wrote nothing",
/// because the tool did not look and the log kept only a hash.
///
/// Emptying a file is a real operation, so this is a refusal with a declared
/// exception, not a prohibition: `allow_empty: true` performs it. The flag is in
/// the schema the model is shown, because an enforced rule nobody stated is the
/// defect of A2-231 with a different noun.
const REFUSE_EMPTY: &str =
    "refusing to write empty content: `content` is empty or whitespace only, \
which is what a write looks like when the task has been lost rather than done. Send the whole file \
in one call. To empty a file on purpose, pass `allow_empty: true`.";

#[derive(Debug, Deserialize)]
struct WriteInput {
    path: String,
    content: String,
    #[serde(default)]
    create_parent_dirs: bool,
    /// Write nothing on purpose: truncate a file, or create an empty one.
    ///
    /// A DECLARATION by the caller, in the same shape as `arcana run
    /// --read-only`. Without it, empty content is refused — see
    /// [`REFUSE_EMPTY`].
    #[serde(default)]
    allow_empty: bool,
}

pub struct WriteTool {
    rules: Arc<ToolRuleSet>,
    root: Option<PathBuf>,
}

impl Default for WriteTool {
    fn default() -> Self {
        Self {
            rules: Arc::new(ToolRuleSet::default()),
            root: None,
        }
    }
}

impl WriteTool {
    #[must_use]
    pub fn new(rules: Arc<ToolRuleSet>) -> Self {
        Self { rules, root: None }
    }

    /// Resolve relative paths against `root` rather than the ambient process
    /// working directory. See [`crate::read::ReadTool::with_root`].
    #[must_use]
    pub fn with_root(rules: Arc<ToolRuleSet>, root: impl Into<PathBuf>) -> Self {
        Self {
            rules,
            root: Some(root.into()),
        }
    }
}

#[async_trait]
impl Tool for WriteTool {
    fn name(&self) -> &'static str {
        "write"
    }

    fn description(&self) -> &'static str {
        "Write `content` to a file at `path`, creating or overwriting it. Empty or \
         whitespace-only `content` is refused unless `allow_empty` is true."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["path", "content"],
            "properties": {
                "path": { "type": "string", "minLength": 1 },
                "content": { "type": "string" },
                "create_parent_dirs": { "type": "boolean" },
                "allow_empty": { "type": "boolean" }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        let parsed: WriteInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        // Before the path guard and before any I/O: a refused call must leave
        // nothing behind, not even a created parent directory.
        if !parsed.allow_empty && parsed.content.trim().is_empty() {
            return Err(ToolError::InvalidInput(REFUSE_EMPTY.to_owned()));
        }
        let cwd = crate::path_guard::working_directory(self.root.as_deref())?;
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
                // Keyed by the constant the audit log reads, so the log cannot
                // lose the number by a rename here.
                BYTES_WRITTEN: bytes_written,
                "created": !existed
            })),
        })
    }
}
