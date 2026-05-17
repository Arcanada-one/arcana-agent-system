//! Append-only audit log hook.
//!
//! Writes one JSON line per hook invocation describing the tool name, a
//! Blake3-truncated hash of the input, the phase, an RFC 3339 timestamp, and
//! the decision returned. Writes go through a non-blocking writer; errors are
//! demoted to warning traces so that audit failures cannot terminate the
//! agent loop.

use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use crate::hooks::{HookContext, HookError, HookResult, ToolHook};
use crate::tool::ToolOutput;

const INPUT_HASH_HEX_PREFIX: usize = 16;

/// Construction failures for [`AuditHook`].
#[derive(Debug, Error)]
pub enum AuditHookError {
    /// The parent directory for the audit log could not be created.
    #[error("audit directory setup failed: {0}")]
    DirectoryFailed(std::io::Error),
    /// The audit log file could not be opened.
    #[error("audit file open failed: {0}")]
    FileOpenFailed(std::io::Error),
}

/// Pino-style structured-log hook.
///
/// The hook owns a [`WorkerGuard`] to keep the background writer alive for
/// the lifetime of the hook; dropping the hook flushes the queue.
pub struct AuditHook {
    writer: Mutex<NonBlocking>,
    _guard: WorkerGuard,
}

impl AuditHook {
    /// Construct an audit hook writing to `<dir>/audit.log`.
    ///
    /// The parent directory is created if missing.
    ///
    /// # Errors
    ///
    /// Returns [`AuditHookError::DirectoryFailed`] when the directory
    /// cannot be created, or [`AuditHookError::FileOpenFailed`] when the
    /// log file cannot be opened.
    pub fn new(dir: &Path) -> Result<Self, AuditHookError> {
        std::fs::create_dir_all(dir).map_err(AuditHookError::DirectoryFailed)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("audit.log"))
            .map_err(AuditHookError::FileOpenFailed)?;
        let (writer, guard) = tracing_appender::non_blocking(file);
        Ok(Self {
            writer: Mutex::new(writer),
            _guard: guard,
        })
    }

    fn emit(&self, line: &str) {
        use std::io::Write as _;
        let Ok(mut writer) = self.writer.lock() else {
            tracing::warn!("audit writer lock poisoned, dropping record");
            return;
        };
        if let Err(err) = writeln!(writer, "{line}") {
            tracing::warn!(error = %err, "audit write failed, dropping record");
        }
    }

    fn hash_input(input: &Value) -> String {
        // serde_json never errors on owned Values; fall back to "{}" for the
        // theoretical Err arm to avoid `unwrap`.
        let bytes = serde_json::to_vec(input).unwrap_or_else(|_| b"{}".to_vec());
        let hash = blake3::hash(&bytes);
        hash.to_hex().as_str()[..INPUT_HASH_HEX_PREFIX].to_string()
    }

    fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
    }

    fn render(phase: &str, tool: &str, input_hash: &str, decision: &str) -> String {
        let record = serde_json::json!({
            "ts": Self::now_rfc3339(),
            "phase": phase,
            "tool": tool,
            "input_hash": input_hash,
            "decision": decision,
        });
        record.to_string()
    }
}

#[async_trait]
impl ToolHook for AuditHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        tool: &str,
        input: &Value,
    ) -> Result<HookResult, HookError> {
        let hash = Self::hash_input(input);
        let line = Self::render("pre", tool, &hash, "Continue");
        self.emit(&line);
        Ok(HookResult::Continue)
    }

    async fn post_tool(
        &self,
        _ctx: &HookContext,
        tool: &str,
        output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        let hash = Self::hash_input(&serde_json::Value::String(output.content.clone()));
        let line = Self::render("post", tool, &hash, "Continue");
        self.emit(&line);
        Ok(HookResult::Continue)
    }
}
