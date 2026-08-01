//! Restrictive, quarantine-first transcript persistence (V-AC-5).

#![cfg(unix)]

use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use nix::unistd::geteuid;

use crate::{QuarantineScanner, ScanError, ScannerConfig, ScannerInit, Stream};

const TRANSCRIPT_HEADER: &[u8] = b"ARCANA-TRANSCRIPT-V1\0";
const RECORD_OVERHEAD: usize = 1 + std::mem::size_of::<u64>();

/// Retention and quarantine policy for one transcript directory.
#[derive(Clone)]
pub struct TranscriptPolicy {
    pub directory: PathBuf,
    pub sentinels: Vec<Vec<u8>>,
    pub max_files: usize,
    pub max_age: Duration,
    /// Maximum serialized bytes in one transcript, including framing.
    pub max_bytes: usize,
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
            .field("max_bytes", &self.max_bytes)
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
#[derive(Clone)]
pub struct TranscriptWriter {
    policy: TranscriptPolicy,
    directory: Arc<File>,
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
        if policy.max_files == 0 || policy.max_age.is_zero() || policy.max_bytes == 0 {
            return Err(TranscriptError::InvalidRetention);
        }
        if !policy.directory.is_absolute() {
            return Err(TranscriptError::PathNotAbsolute);
        }
        let _ = QuarantineScanner::new(policy.sentinels.clone(), ScannerConfig::default())?;
        let directory = Arc::new(open_or_create_directory(&policy.directory)?);
        create_marker(
            &directory,
            ".metadata_never_index",
            &policy.directory.join(".metadata_never_index"),
            b"",
        )?;
        create_marker(
            &directory,
            ".nosync",
            &policy.directory.join(".nosync"),
            b"",
        )?;
        create_marker(
            &directory,
            ".stignore",
            &policy.directory.join(".stignore"),
            b"# Managed by Arcana transcript policy.\n*\n",
        )?;
        let writer = Self { policy, directory };
        writer.prune()?;
        Ok(writer)
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.policy.directory
    }

    /// Quarantine all chunks and atomically claim a new transcript artifact.
    /// No transcript file is created until the complete scan succeeds.
    ///
    /// # Errors
    /// Refuses unsafe identifiers, collisions/symlinks, unsafe directory
    /// state, output quarantine failures, and persistence/retention errors.
    pub fn write(
        &self,
        identifier: &str,
        chunks: &[TranscriptChunk<'_>],
    ) -> Result<String, TranscriptError> {
        validate_identifier(identifier)?;
        validate_directory(&self.directory, &self.policy.directory)?;
        validate_namespace_identity(&self.directory, &self.policy.directory)?;
        let mut scanner =
            QuarantineScanner::new(self.policy.sentinels.clone(), ScannerConfig::default())?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for chunk in chunks {
            let _ = scanner
                .push_stream(chunk.stream, chunk.bytes)
                .map_err(TranscriptError::Quarantined)?;
            match chunk.stream {
                Stream::Stdout => stdout.extend_from_slice(chunk.bytes),
                Stream::Stderr => stderr.extend_from_slice(chunk.bytes),
            }
        }
        scanner
            .check_distributed(&stdout, &stderr)
            .map_err(TranscriptError::Quarantined)?;
        let _ = scanner.finish().map_err(TranscriptError::Quarantined)?;

        let byte_count = chunks
            .iter()
            .try_fold(TRANSCRIPT_HEADER.len(), |total, chunk| {
                total
                    .checked_add(RECORD_OVERHEAD)
                    .and_then(|value| value.checked_add(chunk.bytes.len()))
            })
            .ok_or(TranscriptError::SizeLimitExceeded)?;
        if byte_count > self.policy.max_bytes {
            return Err(TranscriptError::SizeLimitExceeded);
        }

        self.prune()?;
        let path = self.policy.directory.join(format!("{identifier}.log"));
        let filename = format!("{identifier}.log");
        reject_existing_destination(&self.directory, &filename, &path)?;
        let descriptor = rustix::fs::openat(
            &self.directory,
            filename.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| TranscriptError::Io {
            action: "create transcript",
            reason: error.to_string(),
        })?;
        let mut file = File::from(descriptor);
        file.write_all(TRANSCRIPT_HEADER)
            .map_err(|error| TranscriptError::Io {
                action: "write transcript",
                reason: error.to_string(),
            })?;
        for chunk in chunks {
            let stream_tag = match chunk.stream {
                Stream::Stdout => 1u8,
                Stream::Stderr => 2u8,
            };
            let length =
                u64::try_from(chunk.bytes.len()).map_err(|_| TranscriptError::SizeLimitExceeded)?;
            file.write_all(&[stream_tag])
                .and_then(|()| file.write_all(&length.to_be_bytes()))
                .and_then(|()| file.write_all(chunk.bytes))
                .map_err(|error| TranscriptError::Io {
                    action: "write transcript",
                    reason: error.to_string(),
                })?;
        }
        file.sync_all().map_err(|error| TranscriptError::Io {
            action: "sync transcript",
            reason: error.to_string(),
        })?;
        validate_file(&file, &path, 0o600)?;
        if let Err(error) = validate_namespace_identity(&self.directory, &self.policy.directory) {
            let _ = rustix::fs::unlinkat(
                &self.directory,
                filename.as_str(),
                rustix::fs::AtFlags::empty(),
            );
            return Err(error);
        }
        self.prune()?;
        Ok(identifier.to_owned())
    }

    /// Read one artifact relative to the retained directory descriptor.
    ///
    /// The returned identifier is deliberately not a pathname. Keeping the
    /// writer capability and resolving with `openat` prevents a later ancestor
    /// replacement from redirecting retrieval to an attacker-controlled file.
    ///
    /// # Errors
    /// Refuses unsafe identifiers, symlinks, foreign files, unsafe modes, and
    /// files larger than the configured serialized-byte limit.
    pub fn read_artifact(&self, identifier: &str) -> Result<Vec<u8>, TranscriptError> {
        validate_identifier(identifier)?;
        let filename = format!("{identifier}.log");
        let path = self.policy.directory.join(&filename);
        let descriptor = rustix::fs::openat(
            &self.directory,
            filename.as_str(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::LOOP {
                TranscriptError::SymlinkRejected { path: path.clone() }
            } else {
                TranscriptError::Io {
                    action: "open transcript artifact",
                    reason: error.to_string(),
                }
            }
        })?;
        let mut file = File::from(descriptor);
        validate_file(&file, &path, 0o600)?;
        let read_limit = u64::try_from(self.policy.max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut body = Vec::new();
        Read::take(&mut file, read_limit)
            .read_to_end(&mut body)
            .map_err(|error| TranscriptError::Io {
                action: "read transcript artifact",
                reason: error.to_string(),
            })?;
        if body.len() > self.policy.max_bytes {
            return Err(TranscriptError::SizeLimitExceeded);
        }
        Ok(body)
    }

    fn prune(&self) -> Result<(), TranscriptError> {
        let mut entries = transcript_entries(&self.directory, &self.policy.directory)?;
        let now = SystemTime::now();
        for entry in &entries {
            if now.duration_since(entry.modified).unwrap_or_default() > self.policy.max_age {
                rustix::fs::unlinkat(&self.directory, &entry.name, rustix::fs::AtFlags::empty())
                    .map_err(|error| TranscriptError::Io {
                        action: "remove expired transcript",
                        reason: error.to_string(),
                    })?;
            }
        }
        entries = transcript_entries(&self.directory, &self.policy.directory)?;
        entries.sort_by_key(|entry| entry.modified);
        let excess = entries.len().saturating_sub(self.policy.max_files);
        for entry in entries.into_iter().take(excess) {
            rustix::fs::unlinkat(&self.directory, &entry.name, rustix::fs::AtFlags::empty())
                .map_err(|error| TranscriptError::Io {
                    action: "enforce transcript count",
                    reason: error.to_string(),
                })?;
        }
        Ok(())
    }
}

struct Entry {
    name: CString,
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
    #[error("transcript exceeded the configured byte limit")]
    SizeLimitExceeded,
    #[error("transcript identifier is not a safe filename token")]
    InvalidIdentifier,
    #[error("symbolic link rejected at {path}")]
    SymlinkRejected { path: PathBuf },
    #[error("transcript path is not owned by the current service identity: {path}")]
    ForeignOwner { path: PathBuf },
    #[error("transcript destination already exists")]
    AlreadyExists,
    #[error("transcript directory namespace changed while the writer was active")]
    NamespaceChanged,
    #[error("transcript path has an unsafe file type: {path}")]
    UnsafeFileType { path: PathBuf },
    #[error("transcript no-sync marker has unexpected content: {path}")]
    MarkerMismatch { path: PathBuf },
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

fn validate_file(file: &File, path: &Path, mode: u32) -> Result<(), TranscriptError> {
    let metadata = file.metadata().map_err(|error| TranscriptError::Io {
        action: "inspect transcript descriptor",
        reason: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(TranscriptError::UnsafeFileType {
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

fn open_or_create_directory(path: &Path) -> Result<File, TranscriptError> {
    if !path.is_absolute() {
        return Err(TranscriptError::PathNotAbsolute);
    }
    let root =
        rustix::fs::open("/", directory_flags(), rustix::fs::Mode::empty()).map_err(|error| {
            TranscriptError::Io {
                action: "open filesystem root",
                reason: error.to_string(),
            }
        })?;
    let mut directory = File::from(root);
    let mut resolved = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(TranscriptError::PathNotAbsolute);
        };
        resolved.push(name);
        let descriptor = match rustix::fs::openat(
            &directory,
            name,
            directory_flags(),
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => {
                match rustix::fs::mkdirat(
                    &directory,
                    name,
                    rustix::fs::Mode::from_bits_truncate(0o700),
                ) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => {
                        return Err(TranscriptError::Io {
                            action: "create transcript path component",
                            reason: error.to_string(),
                        });
                    }
                }
                rustix::fs::openat(
                    &directory,
                    name,
                    directory_flags(),
                    rustix::fs::Mode::empty(),
                )
                .map_err(|error| component_open_error(error, &resolved))?
            }
            Err(error) => return Err(component_open_error(error, &resolved)),
        };
        directory = File::from(descriptor);
    }
    let metadata = directory.metadata().map_err(|error| TranscriptError::Io {
        action: "inspect transcript directory descriptor",
        reason: error.to_string(),
    })?;
    if !metadata.is_dir() {
        return Err(TranscriptError::UnsafeFileType {
            path: path.to_path_buf(),
        });
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err(TranscriptError::ForeignOwner {
            path: path.to_path_buf(),
        });
    }
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|error| TranscriptError::Io {
            action: "restrict transcript directory",
            reason: error.to_string(),
        })?;
    validate_directory(&directory, path)?;
    Ok(directory)
}

fn directory_flags() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC
}

fn component_open_error(error: rustix::io::Errno, path: &Path) -> TranscriptError {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        TranscriptError::SymlinkRejected {
            path: path.to_path_buf(),
        }
    } else {
        TranscriptError::Io {
            action: "open transcript path component",
            reason: error.to_string(),
        }
    }
}

fn validate_directory(directory: &File, path: &Path) -> Result<(), TranscriptError> {
    let metadata = directory.metadata().map_err(|error| TranscriptError::Io {
        action: "inspect transcript directory descriptor",
        reason: error.to_string(),
    })?;
    if !metadata.is_dir() {
        return Err(TranscriptError::UnsafeFileType {
            path: path.to_path_buf(),
        });
    }
    if metadata.uid() != geteuid().as_raw() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(TranscriptError::ForeignOwner {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_namespace_identity(directory: &File, path: &Path) -> Result<(), TranscriptError> {
    let descriptor =
        rustix::fs::open(path, directory_flags(), rustix::fs::Mode::empty()).map_err(|error| {
            if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
                TranscriptError::NamespaceChanged
            } else {
                TranscriptError::Io {
                    action: "reopen transcript namespace",
                    reason: error.to_string(),
                }
            }
        })?;
    let namespace = File::from(descriptor);
    let held_metadata = directory.metadata().map_err(|error| TranscriptError::Io {
        action: "inspect held transcript directory",
        reason: error.to_string(),
    })?;
    let namespace_metadata = namespace.metadata().map_err(|error| TranscriptError::Io {
        action: "inspect transcript namespace",
        reason: error.to_string(),
    })?;
    if held_metadata.dev() != namespace_metadata.dev()
        || held_metadata.ino() != namespace_metadata.ino()
    {
        return Err(TranscriptError::NamespaceChanged);
    }
    Ok(())
}

fn create_marker(
    directory: &File,
    name: &str,
    path: &Path,
    body: &[u8],
) -> Result<(), TranscriptError> {
    let existing = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    );
    if let Ok(descriptor) = existing {
        let mut file = File::from(descriptor);
        validate_file(&file, path, 0o600)?;
        let mut actual = Vec::new();
        file.read_to_end(&mut actual)
            .map_err(|error| TranscriptError::Io {
                action: "read transcript marker",
                reason: error.to_string(),
            })?;
        if actual != body {
            return Err(TranscriptError::MarkerMismatch {
                path: path.to_path_buf(),
            });
        }
        return Ok(());
    }
    match existing {
        Err(rustix::io::Errno::NOENT) => {}
        Err(rustix::io::Errno::LOOP) => {
            return Err(TranscriptError::SymlinkRejected {
                path: path.to_path_buf(),
            });
        }
        Err(error) => {
            return Err(TranscriptError::Io {
                action: "open transcript marker",
                reason: error.to_string(),
            });
        }
        Ok(_) => unreachable!(),
    }
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| TranscriptError::Io {
        action: "create transcript marker",
        reason: error.to_string(),
    })?;
    let mut file = File::from(descriptor);
    file.write_all(body).map_err(|error| TranscriptError::Io {
        action: "write transcript marker",
        reason: error.to_string(),
    })?;
    file.sync_all().map_err(|error| TranscriptError::Io {
        action: "sync transcript marker",
        reason: error.to_string(),
    })?;
    validate_file(&file, path, 0o600)
}

fn reject_existing_destination(
    directory: &File,
    name: &str,
    path: &Path,
) -> Result<(), TranscriptError> {
    match rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(_) => Err(TranscriptError::AlreadyExists),
        Err(rustix::io::Errno::LOOP) => Err(TranscriptError::SymlinkRejected {
            path: path.to_path_buf(),
        }),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(TranscriptError::Io {
            action: "inspect transcript destination",
            reason: error.to_string(),
        }),
    }
}

fn transcript_entries(directory: &File, path_root: &Path) -> Result<Vec<Entry>, TranscriptError> {
    let iter = rustix::fs::Dir::read_from(directory).map_err(|error| TranscriptError::Io {
        action: "read transcript directory",
        reason: error.to_string(),
    })?;
    let mut entries = Vec::new();
    for item in iter {
        let item = item.map_err(|error| TranscriptError::Io {
            action: "read transcript entry",
            reason: error.to_string(),
        })?;
        let name = item.file_name().to_owned();
        let bytes = name.as_bytes();
        if matches!(bytes, b"." | b"..") || !bytes.ends_with(b".log") {
            continue;
        }
        let path = path_root.join(std::ffi::OsStr::from_bytes(bytes));
        let descriptor = rustix::fs::openat(
            directory,
            &name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::LOOP {
                TranscriptError::SymlinkRejected { path: path.clone() }
            } else {
                TranscriptError::Io {
                    action: "open transcript entry",
                    reason: error.to_string(),
                }
            }
        })?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(|error| TranscriptError::Io {
            action: "inspect transcript entry descriptor",
            reason: error.to_string(),
        })?;
        if !metadata.is_file() {
            continue;
        }
        validate_file(&file, &path, 0o600)?;
        let modified = metadata.modified().map_err(|error| TranscriptError::Io {
            action: "read transcript timestamp",
            reason: error.to_string(),
        })?;
        entries.push(Entry { name, modified });
    }
    Ok(entries)
}
