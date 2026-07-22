//! Synchronous, fail-closed capability audit log.
//!
//! Records are versioned and contain hashes only: raw inputs, outputs,
//! credentials, and error strings are never persisted. The capability
//! executor owns this sink directly, so audit cannot be accidentally omitted
//! or double-bridged through a hook chain.

use std::fs::File;
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
    #[error("audit directory must be a private directory owned by the running user")]
    DirectorySecurity,
    #[error("audit file open failed: {0}")]
    FileOpenFailed(std::io::Error),
    #[error("audit path must be a regular non-symlink file")]
    FileType,
    #[error("audit file has insecure permissions: {mode:o}")]
    FilePermissions { mode: u32 },
    #[error("audit file owner does not match the running user")]
    FileOwner,
    #[error("audit metadata durability failed: {0}")]
    MetadataSyncFailed(std::io::Error),
    #[error("audit writer lock poisoned")]
    LockPoisoned,
    #[error("audit write failed: {0}")]
    WriteFailed(std::io::Error),
}

/// Mandatory append-only sink owned by [`crate::execution::CapabilityExecutor`].
pub struct AuditLog {
    writer: Mutex<Box<dyn DurableAuditWriter>>,
}

/// Write seam whose success includes persistence to the backing store.
///
/// Production uses [`File::sync_data`]. The public seam exists so the fused
/// executor's fail-closed durability behavior can be tested deterministically.
pub trait DurableAuditWriter: Write + Send {
    /// Persist all prior bytes before the audit append is acknowledged.
    ///
    /// # Errors
    /// Returns the backing store's durability error when the record cannot be
    /// synchronously committed.
    fn sync_data(&mut self) -> std::io::Result<()>;
}

impl DurableAuditWriter for File {
    fn sync_data(&mut self) -> std::io::Result<()> {
        File::sync_data(self)
    }
}

impl AuditLog {
    /// Open `<dir>/audit.log` for synchronous append.
    ///
    /// # Errors
    ///
    /// Returns [`AuditHookError`] when the directory or file cannot be opened.
    pub fn new(dir: &Path) -> Result<Self, AuditHookError> {
        let file = open_secure_audit_file(dir)?;
        Ok(Self::from_durable_writer(Box::new(file)))
    }

    /// Construct over an already-open writer.
    ///
    /// This seam supports supervised embeddings and deterministic failure
    /// tests. Every record is synchronously written and flushed; any failure
    /// is returned to the executor and closes execution.
    #[must_use]
    pub fn from_durable_writer(writer: Box<dyn DurableAuditWriter>) -> Self {
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
        writer.sync_data().map_err(AuditHookError::WriteFailed)
    }
}

#[cfg(unix)]
fn open_secure_audit_file(dir: &Path) -> Result<File, AuditHookError> {
    open_secure_audit_file_with_sync(dir, &mut |file, _transition| {
        file.sync_all().map_err(AuditHookError::MetadataSyncFailed)
    })
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MetadataTransition {
    DirectoryMode,
    AuditFileMode,
    AuditFileDirectoryEntry,
}

#[cfg(unix)]
fn open_secure_audit_file_with_sync(
    dir: &Path,
    sync: &mut impl FnMut(&File, MetadataTransition) -> Result<(), AuditHookError>,
) -> Result<File, AuditHookError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    std::fs::create_dir_all(dir).map_err(AuditHookError::DirectoryFailed)?;
    let directory_fd = rustix::fs::open(
        dir,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| AuditHookError::DirectoryFailed(errno_to_io(error)))?;
    let directory = File::from(directory_fd);
    let metadata = directory
        .metadata()
        .map_err(AuditHookError::DirectoryFailed)?;
    let expected_uid = rustix::process::geteuid().as_raw();
    if !metadata.is_dir() || metadata.uid() != expected_uid {
        return Err(AuditHookError::DirectorySecurity);
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        directory
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(AuditHookError::DirectoryFailed)?;
        sync(&directory, MetadataTransition::DirectoryMode)?;
    }
    let secured = directory
        .metadata()
        .map_err(AuditHookError::DirectoryFailed)?;
    if secured.permissions().mode() & 0o777 != 0o700 {
        return Err(AuditHookError::DirectorySecurity);
    }

    let descriptor = rustix::fs::openat(
        &directory,
        "audit.log",
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::APPEND
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            AuditHookError::FileType
        } else {
            AuditHookError::FileOpenFailed(errno_to_io(error))
        }
    })?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(AuditHookError::FileOpenFailed)?;
    validate_file_security(
        metadata.is_file(),
        metadata.permissions().mode() & 0o777,
        metadata.uid(),
        expected_uid,
    )?;
    sync(&file, MetadataTransition::AuditFileMode)?;
    sync(&directory, MetadataTransition::AuditFileDirectoryEntry)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_file_security(
    is_regular: bool,
    mode: u32,
    uid: u32,
    expected_uid: u32,
) -> Result<(), AuditHookError> {
    if !is_regular {
        return Err(AuditHookError::FileType);
    }
    if mode != 0o600 {
        return Err(AuditHookError::FilePermissions { mode });
    }
    if uid != expected_uid {
        return Err(AuditHookError::FileOwner);
    }
    Ok(())
}

#[cfg(unix)]
fn errno_to_io(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(not(unix))]
fn open_secure_audit_file(dir: &Path) -> Result<File, AuditHookError> {
    std::fs::create_dir_all(dir).map_err(AuditHookError::DirectoryFailed)?;
    let metadata = std::fs::symlink_metadata(dir).map_err(AuditHookError::DirectoryFailed)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AuditHookError::DirectorySecurity);
    }
    let path = dir.join("audit.log");
    if path.exists() {
        let metadata = std::fs::symlink_metadata(&path).map_err(AuditHookError::FileOpenFailed)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AuditHookError::FileType);
        }
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(AuditHookError::FileOpenFailed)
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

#[cfg(all(test, unix))]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn file_owner_mismatch_is_rejected() {
        assert!(matches!(
            validate_file_security(true, 0o600, 41, 42),
            Err(AuditHookError::FileOwner)
        ));
    }

    #[test]
    fn secure_open_persists_mode_and_directory_entry_transitions() {
        let root = tempfile::tempdir().expect("tempdir");
        let audit_dir = root.path().join("audit");
        std::fs::create_dir(&audit_dir).expect("create audit dir");
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o755))
            .expect("set initial directory mode");
        let mut transitions = Vec::new();

        let _file = open_secure_audit_file_with_sync(&audit_dir, &mut |_file, transition| {
            transitions.push(transition);
            Ok(())
        })
        .expect("secure audit open");

        assert_eq!(
            transitions,
            [
                MetadataTransition::DirectoryMode,
                MetadataTransition::AuditFileMode,
                MetadataTransition::AuditFileDirectoryEntry,
            ]
        );
    }
}
