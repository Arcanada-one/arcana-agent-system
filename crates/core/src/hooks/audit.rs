//! Synchronous, fail-closed capability audit log.
//!
//! Records are versioned and contain hashes only: raw inputs, outputs,
//! credentials, and error strings are never persisted. The capability
//! executor owns this sink directly, so audit cannot be accidentally omitted
//! or double-bridged through a hook chain.

use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde_json::Value;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::tool::ToolOutput;

const AUDIT_VERSION: u8 = 2;
const HASH_HEX_PREFIX: usize = 16;

/// Construction and durable-write failures for [`AuditLog`].
#[derive(Debug, Error)]
pub enum AuditHookError {
    #[error("audit directory setup failed: {0}")]
    DirectoryFailed(std::io::Error),
    #[error("audit file open failed: {0}")]
    FileOpenFailed(std::io::Error),
    #[error("audit writer lock poisoned")]
    LockPoisoned,
    #[error("audit write failed: {0}")]
    WriteFailed(std::io::Error),
}

/// Mandatory append-only sink owned by [`crate::execution::CapabilityExecutor`].
pub struct AuditLog {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl AuditLog {
    /// Open `<dir>/audit.log` for synchronous append.
    ///
    /// # Errors
    ///
    /// Returns [`AuditHookError`] when the directory or file cannot be opened.
    pub fn new(dir: &Path) -> Result<Self, AuditHookError> {
        std::fs::create_dir_all(dir).map_err(AuditHookError::DirectoryFailed)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("audit.log"))
            .map_err(AuditHookError::FileOpenFailed)?;
        Ok(Self::from_writer(Box::new(file)))
    }

    /// Construct over an already-open writer.
    ///
    /// This seam supports supervised embeddings and deterministic failure
    /// tests. Every record is synchronously written and flushed; any failure
    /// is returned to the executor and closes execution.
    #[must_use]
    pub fn from_writer(writer: Box<dyn Write + Send>) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }

    /// Audit a permission decision that intentionally does not execute a tool
    /// (for example the CLI's `whoami` bootstrap probe).
    ///
    /// # Errors
    ///
    /// Returns [`AuditHookError`] if either correlated record cannot be
    /// synchronously written and flushed.
    pub fn record_decision_only(
        &self,
        invocation_id: u64,
        tool: &str,
        input: &Value,
        decision: &str,
        layer: &str,
    ) -> Result<(), AuditHookError> {
        self.record_decision(invocation_id, tool, input, decision, layer)?;
        self.record_result(invocation_id, tool, "decision_only", None)
    }

    pub(crate) fn record_decision(
        &self,
        invocation_id: u64,
        tool: &str,
        input: &Value,
        decision: &str,
        layer: &str,
    ) -> Result<(), AuditHookError> {
        self.append(&serde_json::json!({
            "version": AUDIT_VERSION,
            "ts": now_rfc3339(),
            "phase": "decision",
            "invocation_id": invocation_id,
            "tool": tool,
            "input_hash": hash_value(input),
            "decision": decision,
            "layer": layer,
        }))
    }

    pub(crate) fn record_result(
        &self,
        invocation_id: u64,
        tool: &str,
        outcome: &str,
        output: Option<&ToolOutput>,
    ) -> Result<(), AuditHookError> {
        let output_hash = output.map(|value| {
            hash_value(&serde_json::json!({
                "content": value.content,
                "metadata": value.metadata,
            }))
        });
        self.append(&serde_json::json!({
            "version": AUDIT_VERSION,
            "ts": now_rfc3339(),
            "phase": "result",
            "invocation_id": invocation_id,
            "tool": tool,
            "outcome": outcome,
            "output_hash": output_hash,
        }))
    }

    fn append(&self, record: &Value) -> Result<(), AuditHookError> {
        let mut bytes = serde_json::to_vec(&record)
            .map_err(|err| AuditHookError::WriteFailed(std::io::Error::other(err.to_string())))?;
        bytes.push(b'\n');
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| AuditHookError::LockPoisoned)?;
        writer
            .write_all(&bytes)
            .map_err(AuditHookError::WriteFailed)?;
        writer.flush().map_err(AuditHookError::WriteFailed)
    }
}

/// Backward-compatible type name for callers constructing the audit sink.
pub type AuditHook = AuditLog;

fn hash_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    blake3::hash(&bytes).to_hex().as_str()[..HASH_HEX_PREFIX].to_owned()
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}
