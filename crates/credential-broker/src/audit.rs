//! Metadata-only causal audit (D-REQ-06 / V-AC-5).
//!
//! The secret-safety property here is **structural, not procedural**. An audit
//! record has no free-form payload field, so there is nowhere for a credential
//! value, response body or transcript excerpt to be placed — not by a careless
//! caller, not by a future edit that "just needs to log the response". Every
//! field is an identifier, a timestamp, a status, a count or a hash.

use crate::protocol::{Denial, Generation, Operation};
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The causal identifiers a record carries. Any of these may be absent for a
/// given event, but none of them can hold content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CausalIds {
    /// Incident this event belongs to.
    pub incident: Option<String>,
    /// Execution (agent turn / job) identifier.
    pub execution: Option<String>,
    /// Host boot identifier, so pre- and post-restart events are separable.
    pub host_boot: Option<String>,
    /// Process-tree identifier.
    pub process_tree: Option<String>,
    /// Pane or session identifier.
    pub pane_session: Option<String>,
    /// Credential identifier and version — never the credential.
    pub credential_id: Option<String>,
    /// Credential version.
    pub credential_version: Option<u32>,
    /// Broker lease identifier.
    pub lease: Option<String>,
    /// Broker generation.
    pub generation: Option<Generation>,
    /// Output-scan identifier.
    pub output_scan: Option<String>,
    /// Transcript artifact identifier.
    pub transcript_artifact: Option<String>,
    /// Provider request identifier.
    pub provider_request: Option<String>,
    /// Provider revocation identifier.
    pub provider_revocation: Option<String>,
    /// Vault accessor identifier (accessor, never token material).
    pub vault_accessor: Option<String>,
    /// Deployment identifier.
    pub deployment: Option<String>,
    /// Canary identifier.
    pub canary: Option<String>,
}

/// What happened. A closed set — an event kind cannot be invented at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    PolicyAllow,
    PolicyDeny,
    QuotaCharge,
    ReplayServed,
    ReplayPending,
    OutputScanBlock,
    OutputScanPass,
    ProviderRequestRejected,
    ProviderOutcomeUnknown,
    ProviderResponseSuccess,
    ProviderResponseError,
    BrokerStart,
    BrokerStop,
    GenerationRejected,
}

impl EventKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAllow => "policy_allow",
            Self::PolicyDeny => "policy_deny",
            Self::QuotaCharge => "quota_charge",
            Self::ReplayServed => "replay_served",
            Self::ReplayPending => "replay_pending",
            Self::OutputScanBlock => "output_scan_block",
            Self::OutputScanPass => "output_scan_pass",
            Self::ProviderRequestRejected => "provider_request_rejected",
            Self::ProviderOutcomeUnknown => "provider_outcome_unknown",
            Self::ProviderResponseSuccess => "provider_response_success",
            Self::ProviderResponseError => "provider_response_error",
            Self::BrokerStart => "broker_start",
            Self::BrokerStop => "broker_stop",
            Self::GenerationRejected => "generation_rejected",
        }
    }
}

/// A single metadata-only audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Unix seconds.
    pub at: u64,
    /// What happened.
    pub kind: EventKind,
    /// Causal identifiers.
    pub ids: CausalIds,
    /// Provider name (a policy key, not a secret).
    pub provider: Option<String>,
    /// Model name (a policy key, not a secret).
    pub model: Option<String>,
    /// Operation, if applicable.
    pub operation: Option<Operation>,
    /// Denial reason, if this is a denial.
    pub denial: Option<Denial>,
    /// Quota units charged by this event.
    pub charged: Option<u32>,
    /// A count, e.g. bytes scanned or copies found.
    pub count: Option<u64>,
    /// Known provider HTTP status. Never response bytes.
    pub status: Option<u16>,
    /// A hex digest of an artifact — never the artifact.
    pub artifact_sha256: Option<String>,
}

impl AuditRecord {
    /// A record of the given kind at the given time.
    #[must_use]
    pub fn new(at: u64, kind: EventKind) -> Self {
        Self {
            at,
            kind,
            ids: CausalIds::default(),
            provider: None,
            model: None,
            operation: None,
            denial: None,
            charged: None,
            count: None,
            status: None,
            artifact_sha256: None,
        }
    }

    fn validate(&self) -> Result<(), AuditError> {
        let ids = &self.ids;
        for value in [
            &ids.incident,
            &ids.execution,
            &ids.host_boot,
            &ids.process_tree,
            &ids.pane_session,
            &ids.credential_id,
            &ids.lease,
            &ids.output_scan,
            &ids.transcript_artifact,
            &ids.provider_request,
            &ids.provider_revocation,
            &ids.vault_accessor,
            &ids.deployment,
            &ids.canary,
            &self.provider,
            &self.model,
            &self.artifact_sha256,
        ] {
            if value.as_deref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 128
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
                    })
            }) {
                return Err(AuditError::InvalidIdentifier);
            }
        }
        if self.artifact_sha256.as_deref().is_some_and(|digest| {
            digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return Err(AuditError::InvalidIdentifier);
        }
        Ok(())
    }
}

/// Owner-only, append-only metadata audit sink.
pub struct AuditWriter {
    path: PathBuf,
    file: File,
}

impl fmt::Debug for AuditWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditWriter")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl AuditWriter {
    /// Open a broker-owned, mode-0600 non-symlink audit file.
    ///
    /// # Errors
    /// Refuses relative paths, symlinks, foreign ownership and weak modes.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        if !path.is_absolute() {
            return Err(AuditError::PathNotAbsolute);
        }
        let parent = path.parent().ok_or(AuditError::PathNotAbsolute)?;
        std::fs::create_dir_all(parent).map_err(|error| AuditError::Io(error.to_string()))?;
        let parent_metadata =
            std::fs::symlink_metadata(parent).map_err(|error| AuditError::Io(error.to_string()))?;
        let uid = nix::unistd::geteuid().as_raw();
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.uid() != uid
        {
            return Err(AuditError::UnsafeOwnership);
        }
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| AuditError::Io(error.to_string()))?;
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::APPEND
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| AuditError::Io(error.to_string()))?;
        let file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|error| AuditError::Io(error.to_string()))?;
        if !metadata.is_file() || metadata.uid() != uid {
            return Err(AuditError::UnsafeOwnership);
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(AuditError::UnsafeMode);
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Append and durably sync one validated metadata-only record.
    ///
    /// # Errors
    /// Refuses unbounded/unsafe identifiers and any write or sync failure.
    pub fn append(&mut self, record: &AuditRecord) -> Result<(), AuditError> {
        record.validate()?;
        writeln!(self.file, "{record}").map_err(|error| AuditError::Io(error.to_string()))?;
        self.file
            .sync_data()
            .map_err(|error| AuditError::Io(error.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit path must be absolute")]
    PathNotAbsolute,
    #[error("audit path ownership is unsafe")]
    UnsafeOwnership,
    #[error("audit file mode must be exactly 0600")]
    UnsafeMode,
    #[error("audit identifier is malformed or exceeds its bound")]
    InvalidIdentifier,
    #[error("audit I/O failed: {0}")]
    Io(String),
}

/// Render as a stable, greppable key=value line.
///
/// Only typed fields are rendered; there is no path by which arbitrary bytes
/// reach this output.
impl fmt::Display for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at={} event={}", self.at, self.kind.as_str())?;
        let i = &self.ids;
        for (k, v) in [
            ("incident", &i.incident),
            ("execution", &i.execution),
            ("host_boot", &i.host_boot),
            ("process_tree", &i.process_tree),
            ("pane_session", &i.pane_session),
            ("credential_id", &i.credential_id),
            ("lease", &i.lease),
            ("output_scan", &i.output_scan),
            ("transcript_artifact", &i.transcript_artifact),
            ("provider_request", &i.provider_request),
            ("provider_revocation", &i.provider_revocation),
            ("vault_accessor", &i.vault_accessor),
            ("deployment", &i.deployment),
            ("canary", &i.canary),
        ] {
            if let Some(val) = v {
                write!(f, " {k}={val}")?;
            }
        }
        if let Some(v) = i.credential_version {
            write!(f, " credential_version={v}")?;
        }
        if let Some(Generation(g)) = i.generation {
            write!(f, " generation={g}")?;
        }
        if let Some(v) = &self.provider {
            write!(f, " provider={v}")?;
        }
        if let Some(v) = &self.model {
            write!(f, " model={v}")?;
        }
        if let Some(v) = self.operation {
            write!(f, " operation={}", v.as_str())?;
        }
        if let Some(v) = &self.denial {
            write!(f, " denial={v}")?;
        }
        if let Some(v) = self.charged {
            write!(f, " charged={v}")?;
        }
        if let Some(v) = self.count {
            write!(f, " count={v}")?;
        }
        if let Some(v) = self.status {
            write!(f, " status={v}")?;
        }
        if let Some(v) = &self.artifact_sha256 {
            write!(f, " artifact_sha256={v}")?;
        }
        Ok(())
    }
}
