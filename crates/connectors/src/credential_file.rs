//! One descriptor-based file policy shared by Auth Arcana and Muneral.

use secrecy::SecretString;
use std::path::Path;

#[cfg(unix)]
const MAX_SECRET_BYTES: u64 = 4096;

/// File-policy failures never contain the credential value or its path.
#[derive(Debug, thiserror::Error)]
pub enum CredentialFileError {
    #[error("credential file is missing")]
    Missing,
    #[error("credential file is unavailable (I/O or invalid UTF-8)")]
    Unavailable(#[source] std::io::Error),
    #[error("credential path must be a regular non-symlink file")]
    Type,
    #[error("credential file has insecure permissions: {mode:o}; group/other access is forbidden")]
    Permissions { mode: u32 },
    #[error("credential file owner does not match the running user")]
    Owner,
    #[error("credential file is empty or exceeds the size limit (1..4096 bytes; non-whitespace)")]
    Size,
    #[error("credential file validation is supported only on Unix")]
    Unsupported,
}

impl CredentialFileError {
    /// Stable reason for callers that emit machine-readable refusals.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Missing => "CREDENTIAL_FILE_MISSING",
            Self::Unavailable(_) => "CREDENTIAL_FILE_UNAVAILABLE",
            Self::Type => "CREDENTIAL_FILE_UNSAFE_TYPE",
            Self::Permissions { .. } => "CREDENTIAL_FILE_UNSAFE_PERMISSIONS",
            Self::Owner => "CREDENTIAL_FILE_UNSAFE_OWNER",
            Self::Size => "CREDENTIAL_FILE_UNSAFE_SIZE",
            Self::Unsupported => "CREDENTIAL_FILE_UNSUPPORTED_PLATFORM",
        }
    }
}

pub(crate) fn read(path: &Path) -> Result<SecretString, CredentialFileError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(CredentialFileError::Unsupported)
    }
    #[cfg(unix)]
    {
        use std::fs::File;
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;

        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|err| match err {
            rustix::io::Errno::NOENT => CredentialFileError::Missing,
            rustix::io::Errno::LOOP => CredentialFileError::Type,
            other => CredentialFileError::Unavailable(std::io::Error::from_raw_os_error(
                other.raw_os_error(),
            )),
        })?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(CredentialFileError::Unavailable)?;
        if !metadata.file_type().is_file() {
            return Err(CredentialFileError::Type);
        }
        if metadata.len() == 0 || metadata.len() > MAX_SECRET_BYTES {
            return Err(CredentialFileError::Size);
        }
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(CredentialFileError::Permissions { mode });
        }
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(CredentialFileError::Owner);
        }
        let mut raw = String::new();
        file.take(MAX_SECRET_BYTES + 1)
            .read_to_string(&mut raw)
            .map_err(CredentialFileError::Unavailable)?;
        if raw.len() as u64 > MAX_SECRET_BYTES || raw.trim().is_empty() {
            return Err(CredentialFileError::Size);
        }
        Ok(SecretString::from(raw.trim().to_owned()))
    }
}
