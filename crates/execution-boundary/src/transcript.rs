//! Restrictive, quarantine-first transcript persistence (V-AC-5).

#![cfg(unix)]

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use nix::unistd::geteuid;

use crate::{QuarantineScanner, ScanError, ScannerConfig, ScannerInit, Stream};

/// Retention and quarantine policy for one transcript directory.
#[derive(Clone)]
pub struct TranscriptPolicy {
    pub directory: PathBuf,
    pub sentinels: Vec<Vec<u8>>,
    pub max_files: usize,
    pub max_age: Duration,
}

impl fmt::Debug for TranscriptPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TranscriptPolicy")
            .field("directory", &self.directory)
            .field("sentinel_count", &self.sentinels.len())
            .field("sentinels", &"<redacted>")
            .field("max_files", &self.max_files)
            .field("max_age", &self.max_age)
            .finish()
    }
}

/// One ordered stream fragment. Chunks from stdout and stderr must be supplied
/// in observation order so one scanner sees cross-stream splits.
pub struct TranscriptChunk<'a> {
    stream: Stream,
    bytes: &'a [u8],
}

impl<'a> TranscriptChunk<'a> {
    #[must_use]
    pub const fn new(stream: Stream, bytes: &'a [u8]) -> Self {
        Self { stream, bytes }
    }
}

/// A writer rooted in one owner-only, local-only directory.
pub struct TranscriptWriter {
    policy: TranscriptPolicy,
}

impl fmt::Debug for TranscriptWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TranscriptWriter")
            .field("directory", &self.policy.directory)
            .field("policy", &"<redacted>")
            .finish()
    }
}

impl TranscriptWriter {
    /// Prepare and validate the transcript directory.
    ///
    /// # Errors
    /// Refuses relative paths, symlinks, foreign ownership, empty quarantine
    /// configuration, and unbounded retention.
    pub fn new(policy: TranscriptPolicy) -> Result<Self, TranscriptError> {
        if policy.max_files == 0 || policy.max_age.is_zero() {
            return Err(TranscriptError::InvalidRetention);
        }
        if !policy.directory.is_absolute() {
            return Err(TranscriptError::PathNotAbsolute);
        }
        let _ = QuarantineScanner::new(policy.sentinels.clone(), ScannerConfig::default())?;
        ensure_secure_directory(&policy.directory)?;
        create_marker(&policy.directory.join(".metadata_never_index"), b"")?;
        create_marker(&policy.directory.join(".nosync"), b"")?;
        create_marker(
            &policy.directory.join(".stignore"),
            b"# Managed by Arcana transcript policy.\n*\n",
        )?;
        let writer = Self { policy };
        writer.prune()?;
        Ok(writer)
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.policy.directory
    }

    /// Quarantine all chunks and atomically claim a new transcript filename.
    /// No transcript file is created until the complete scan succeeds.
    ///
    /// # Errors
    /// Refuses unsafe identifiers, collisions/symlinks, unsafe directory
    /// state, output quarantine failures, and persistence/retention errors.
    pub fn write(
        &self,
        identifier: &str,
        chunks: &[TranscriptChunk<'_>],
    ) -> Result<PathBuf, TranscriptError> {
        validate_identifier(identifier)?;
        ensure_secure_directory(&self.policy.directory)?;
        let mut scanner =
            QuarantineScanner::new(self.policy.sentinels.clone(), ScannerConfig::default())?;
        for chunk in chunks {
            let _ = scanner
                .push_stream(chunk.stream, chunk.bytes)
                .map_err(TranscriptError::Quarantined)?;
        }
        let _ = scanner.finish().map_err(TranscriptError::Quarantined)?;

        self.prune()?;
        let path = self.policy.directory.join(format!("{identifier}.log"));
        reject_existing_destination(&path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| TranscriptError::Io {
                action: "create transcript",
                reason: error.to_string(),
            })?;
        for chunk in chunks {
            let label = match chunk.stream {
                Stream::Stdout => b"[stdout]\n".as_slice(),
                Stream::Stderr => b"[stderr]\n".as_slice(),
            };
            file.write_all(label)
                .and_then(|()| file.write_all(chunk.bytes))
                .and_then(|()| {
                    if chunk.bytes.ends_with(b"\n") {
                        Ok(())
                    } else {
                        file.write_all(b"\n")
                    }
                })
                .map_err(|error| TranscriptError::Io {
                    action: "write transcript",
                    reason: error.to_string(),
                })?;
        }
        file.sync_all().map_err(|error| TranscriptError::Io {
            action: "sync transcript",
            reason: error.to_string(),
        })?;
        validate_owned_mode(&path, 0o600)?;
        self.prune()?;
        Ok(path)
    }

    fn prune(&self) -> Result<(), TranscriptError> {
        let mut entries = transcript_entries(&self.policy.directory)?;
        let now = SystemTime::now();
        for entry in &entries {
            if now.duration_since(entry.modified).unwrap_or_default() > self.policy.max_age {
                std::fs::remove_file(&entry.path).map_err(|error| TranscriptError::Io {
                    action: "remove expired transcript",
                    reason: error.to_string(),
                })?;
            }
        }
        entries = transcript_entries(&self.policy.directory)?;
        entries.sort_by_key(|entry| entry.modified);
        let excess = entries.len().saturating_sub(self.policy.max_files);
        for entry in entries.into_iter().take(excess) {
            std::fs::remove_file(entry.path).map_err(|error| TranscriptError::Io {
                action: "enforce transcript count",
                reason: error.to_string(),
            })?;
        }
        Ok(())
    }
}

struct Entry {
    path: PathBuf,
    modified: SystemTime,
}

/// Transcript persistence failure. No variant contains transcript or sentinel
/// bytes, so logging the error cannot become a secondary disclosure.
#[derive(Debug, thiserror::Error)]
pub enum TranscriptError {
    #[error("transcript directory must be absolute")]
    PathNotAbsolute,
    #[error("transcript retention must have a positive file count and age")]
    InvalidRetention,
    #[error("transcript identifier is not a safe filename token")]
    InvalidIdentifier,
    #[error("symbolic link rejected at {path}")]
    SymlinkRejected { path: PathBuf },
    #[error("transcript path is not owned by the current service identity: {path}")]
    ForeignOwner { path: PathBuf },
    #[error("transcript destination already exists")]
    AlreadyExists,
    #[error("output quarantine rejected the transcript: {0}")]
    Quarantined(ScanError),
    #[error("output quarantine configuration rejected: {0}")]
    QuarantineInit(#[from] ScannerInit),
    #[error("{action} failed: {reason}")]
    Io {
        action: &'static str,
        reason: String,
    },
}

fn validate_identifier(identifier: &str) -> Result<(), TranscriptError> {
    if identifier.is_empty()
        || identifier.len() > 64
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(TranscriptError::InvalidIdentifier);
    }
    Ok(())
}

fn ensure_secure_directory(path: &Path) -> Result<(), TranscriptError> {
    reject_symlink_components(path)?;
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|error| TranscriptError::Io {
            action: "create transcript directory",
            reason: error.to_string(),
        })?;
    }
    reject_symlink_components(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        TranscriptError::Io {
            action: "restrict transcript directory",
            reason: error.to_string(),
        }
    })?;
    validate_owned_mode(path, 0o700)
}

fn reject_symlink_components(path: &Path) -> Result<(), TranscriptError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(part) => current.push(part),
            Component::CurDir => continue,
            Component::Prefix(_) | Component::ParentDir => {
                return Err(TranscriptError::PathNotAbsolute)
            }
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(TranscriptError::SymlinkRejected { path: current })
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(TranscriptError::Io {
                    action: "inspect transcript path",
                    reason: error.to_string(),
                })
            }
        }
    }
    Ok(())
}

fn validate_owned_mode(path: &Path, mode: u32) -> Result<(), TranscriptError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| TranscriptError::Io {
        action: "inspect transcript ownership",
        reason: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(TranscriptError::SymlinkRejected {
            path: path.to_path_buf(),
        });
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err(TranscriptError::ForeignOwner {
            path: path.to_path_buf(),
        });
    }
    if metadata.permissions().mode() & 0o777 != mode {
        return Err(TranscriptError::Io {
            action: "validate transcript permissions",
            reason: format!("expected mode {mode:o}"),
        });
    }
    Ok(())
}

fn create_marker(path: &Path, body: &[u8]) -> Result<(), TranscriptError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(TranscriptError::SymlinkRejected {
                path: path.to_path_buf(),
            })
        }
        Ok(_) => return validate_owned_mode(path, 0o600),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(TranscriptError::Io {
                action: "inspect transcript marker",
                reason: error.to_string(),
            })
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| TranscriptError::Io {
            action: "create transcript marker",
            reason: error.to_string(),
        })?;
    file.write_all(body).map_err(|error| TranscriptError::Io {
        action: "write transcript marker",
        reason: error.to_string(),
    })?;
    file.sync_all().map_err(|error| TranscriptError::Io {
        action: "sync transcript marker",
        reason: error.to_string(),
    })?;
    validate_owned_mode(path, 0o600)
}

fn reject_existing_destination(path: &Path) -> Result<(), TranscriptError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(TranscriptError::SymlinkRejected {
                path: path.to_path_buf(),
            })
        }
        Ok(_) => Err(TranscriptError::AlreadyExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TranscriptError::Io {
            action: "inspect transcript destination",
            reason: error.to_string(),
        }),
    }
}

fn transcript_entries(directory: &Path) -> Result<Vec<Entry>, TranscriptError> {
    let iter = std::fs::read_dir(directory).map_err(|error| TranscriptError::Io {
        action: "read transcript directory",
        reason: error.to_string(),
    })?;
    let mut entries = Vec::new();
    for item in iter {
        let item = item.map_err(|error| TranscriptError::Io {
            action: "read transcript entry",
            reason: error.to_string(),
        })?;
        let path = item.path();
        if path.extension().is_none_or(|extension| extension != "log") {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| TranscriptError::Io {
            action: "inspect transcript entry",
            reason: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() {
            return Err(TranscriptError::SymlinkRejected { path });
        }
        if !metadata.is_file() {
            continue;
        }
        validate_owned_mode(&path, 0o600)?;
        let modified = metadata.modified().map_err(|error| TranscriptError::Io {
            action: "read transcript timestamp",
            reason: error.to_string(),
        })?;
        entries.push(Entry { path, modified });
    }
    Ok(entries)
}
