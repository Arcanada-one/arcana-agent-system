//! G07: a durable, private, versioned **model-operation intent record**.
//!
//! One bounded local profile on the real `ModelConnector` call boundary of
//! `arcana-core`. It is a recovery witness and an idempotency binding, and
//! nothing more: not a task tracker, not a budget authority, not a
//! cross-service transaction manager, and not a second Model Connector intent
//! store. No database; one small JSON file per task in a private directory.
//!
//! ## Borrowed, not shared
//!
//! The write ordering is the one `arcana-credential-broker` uses for its state
//! file: stage a temp file with `create_new`, write, `fsync` the file, `rename`
//! over the target, `fsync` the parent directory, and fail closed on any step.
//! Phase-specific durability: **before** the rename, a failed step leaves the
//! prior target bytes unchanged; **after** a successful rename, a directory
//! fsync failure means persistence is uncertain (the target may already hold
//! the new bytes) and must not be treated as a confirmed prior-Pending state.
//! The broker's quota ledger, committed-key types, policy grants and status
//! vocabulary are deliberately NOT reused; this module has its own record.
//!
//! ## Order of operations (the caller is `agent_loop`)
//!
//! 1. [`IntentStore::open`] — validate the native binding, verify the private
//!    path, take the exclusive lock, read and validate any retained record.
//!    On a restart this happens **before any key is minted or any dispatch**.
//! 2. [`IntentStore::persist_pending`] — durably write the new `pending`
//!    intent. Only after it returns `Ok` may the request be dispatched.
//! 3. [`IntentStore::mark`] — `unknown` when a dispatch produced no reply,
//!    `reconciled` when a reply was observed by this process.
//!
//! The record holds ids, hashes and closed scalars only. It never holds prompt
//! text, tokens or credentials: every free-form field is checked against a
//! closed character set and a length cap before it can be written.
//!
//! ## What this does NOT establish
//!
//! `reconciled` means "this process observed a reply for the key". It is not an
//! authoritative settlement and no task state may advance from it alone. The
//! native Model Connector intent, the provider effect, the cost reservation and
//! the reconcile join with Muneral are not measured here.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Record schema version for Pending / Unknown / Reconciled. A record with
/// another value is refused, not guessed. Retained v1 bytes keep their meaning.
pub const RECORD_VERSION: u32 = 1;
/// Compatible schema version for a terminal proven-no-dispatch resolution
/// ([`Disposition::NoDispatch`] + `refusal_reason`). Readers accept both
/// [`RECORD_VERSION`] and this value; writers bump only when recording
/// no-dispatch. No contract digest is pinned to this schema in-tree.
pub const RECORD_VERSION_NO_DISPATCH: u32 = 2;
/// Largest record file accepted or written, in bytes.
pub const MAX_RECORD_BYTES: usize = 4096;
/// Largest number of directory entries the private store directory may hold.
pub const MAX_STORE_ENTRIES: usize = 256;
/// Longest value of any free-form scalar field.
pub const MAX_FIELD_BYTES: usize = 128;

/// The native identity of one model operation, as the **caller** has it.
///
/// ARAS has no source for these on the `Driver` path: `Driver::run` takes task
/// text, not a task id, and `TurnIntentSeries` knows only its own run UUID and
/// turn. Every field is therefore supplied by the composition root, and a
/// missing one makes the operation refuse ([`IntentError::MissingField`]); no
/// value is ever invented here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationBinding {
    /// Native task id (e.g. a Muneral task UUID).
    pub task_id: Option<String>,
    /// Plan revision the attempt was admitted under.
    pub plan_revision: Option<String>,
    /// Attempt id / incarnation.
    pub attempt_id: Option<String>,
    /// Lease or fencing token of the attempt.
    pub lease_fence: Option<String>,
    /// Authoritative deadline, seconds since the Unix epoch. A process-local
    /// `Instant` cannot stand in for it.
    pub deadline_epoch_s: Option<u64>,
    /// Provider/model dialect capability revision the route was admitted at.
    pub dialect_revision: Option<String>,
    /// Reservation or intention reference held for this operation, if the
    /// caller has one. ARAS itself holds none (`CostTracker` is process-local),
    /// so this stays optional and is recorded as absent rather than invented.
    pub reservation_ref: Option<String>,
}

/// Where the record lives and how the connector's idempotency is trusted.
#[derive(Debug, Clone)]
pub struct OperationIntentConfig {
    /// Absolute path of the private store directory (owner-only, no symlink in
    /// any component).
    pub store_dir: PathBuf,
    /// The native identity of this attempt.
    pub binding: OperationBinding,
    /// `true` only when the composition root has verified that the connector
    /// replays a stored response for the SAME key and request. Default `false`:
    /// an unresolved earlier operation then stays unknown and the request is
    /// refused, even if the text is identical.
    pub same_key_replay_verified: bool,
    /// Test-only seam: when true, the next durable write of a `NoDispatch`
    /// record fails after rename at the directory-sync step. Production
    /// configs leave this false; behaviour is unchanged when unset.
    pub test_fail_no_dispatch_dir_sync_after_rename: bool,
}

impl OperationIntentConfig {
    /// A config that refuses unknown-outcome replays (the fail-closed default).
    #[must_use]
    pub fn new(store_dir: impl Into<PathBuf>, binding: OperationBinding) -> Self {
        Self {
            store_dir: store_dir.into(),
            binding,
            same_key_replay_verified: false,
            test_fail_no_dispatch_dir_sync_after_rename: false,
        }
    }
}

/// Where an operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Persisted before dispatch. After a process death this means "may have
    /// been sent".
    Pending,
    /// A dispatch under the key produced no reply; the provider may have
    /// executed and charged it.
    Unknown,
    /// A reply was observed for the key by a process of this attempt.
    Reconciled,
    /// Terminal proven-no-dispatch (G05): this exact operation was refused
    /// before any connector/executor handoff. Not an observed reply. Carries
    /// [`IntentRecord::refusal_reason`]. Written only as
    /// [`RECORD_VERSION_NO_DISPATCH`].
    NoDispatch,
}

impl Disposition {
    /// True while the operation may still have an effect nobody has seen.
    ///
    /// [`Self::NoDispatch`] is terminal (proven unused), so it is not
    /// unresolved — unlike a recovered [`Self::Pending`].
    #[must_use]
    pub const fn is_unresolved(self) -> bool {
        matches!(self, Self::Pending | Self::Unknown)
    }
}

/// The record body: ids, hashes and closed scalars only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentRecord {
    pub version: u32,
    /// `blake3(task_id)` as hex; also the file name stem.
    pub scope: String,
    /// Bumped by every write; lets a writer notice state it did not write.
    pub generation: u64,
    pub task_id: String,
    pub plan_revision: String,
    pub attempt_id: String,
    pub lease_fence: String,
    pub deadline_epoch_s: u64,
    /// The run UUID of the process that minted the key (hex).
    pub run_id: String,
    pub turn: u64,
    /// `ExecuteRequest.connector`.
    pub provider: String,
    /// `ExecuteRequest.model`, when the request named one.
    pub model: Option<String>,
    pub dialect_revision: String,
    /// `ExecuteRequest::intent_fingerprint`, hex.
    pub request_fingerprint: String,
    /// The original `Idempotency-Key`.
    pub idempotency_key: String,
    pub reservation_ref: Option<String>,
    pub disposition: Disposition,
    /// `blake3` of the connector response id, hex, once a reply was observed.
    pub outcome_ref: Option<String>,
    /// Typed refusal code retained with [`Disposition::NoDispatch`] (e.g.
    /// `EFFECT_PRECONDITION_UNDISCHARGED`). Absent on every other disposition.
    /// Skipped when `None` so v1 sealed bytes re-serialize identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
}

impl IntentRecord {
    /// The request fingerprint as bytes; `None` if the field is not a 32-byte hex.
    #[must_use]
    pub fn fingerprint_bytes(&self) -> Option<[u8; 32]> {
        if !is_hex(&self.request_fingerprint, 64) {
            return None;
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out
            .iter_mut()
            .zip(self.request_fingerprint.as_bytes().chunks(2))
        {
            let text = std::str::from_utf8(pair).ok()?;
            *slot = u8::from_str_radix(text, 16).ok()?;
        }
        Some(out)
    }
}

/// What a caller supplies to start a new operation.
#[derive(Debug, Clone)]
pub struct NewIntent {
    pub run_id: String,
    pub turn: u64,
    pub provider: String,
    pub model: Option<String>,
    pub request_fingerprint: [u8; 32],
    pub idempotency_key: String,
}

/// Typed refusals. Every one means: nothing was dispatched.
#[derive(Debug, thiserror::Error)]
pub enum IntentError {
    #[error("INTENT_FIELD_MISSING: native field `{field}` is not available; the operation that needs it refuses")]
    MissingField { field: &'static str },
    #[error("INTENT_FIELD_INVALID: field `{field}` is empty, too long or outside the closed character set")]
    InvalidField { field: &'static str },
    #[error("INTENT_PATH_INSECURE: {reason}")]
    InsecurePath { reason: &'static str },
    #[error("INTENT_STORE_LOCKED: another driver holds this operation's lock")]
    Locked,
    #[error("INTENT_STORE_IO: {operation} failed ({kind})")]
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    #[error("INTENT_RECORD_CORRUPT: {reason}")]
    Corrupt { reason: &'static str },
    #[error("INTENT_RECORD_OVERSIZE: record exceeds {MAX_RECORD_BYTES} bytes")]
    Oversize,
    #[error("INTENT_STORE_FULL: more than {MAX_STORE_ENTRIES} entries in the store directory")]
    TooManyEntries,
    #[error("INTENT_RECORD_MISFILED: the record does not belong to this scope")]
    Misfiled,
    #[error("INTENT_BINDING_CONFLICT: retained operation was bound to a different `{field}`")]
    BindingConflict { field: &'static str },
    #[error("INTENT_DEADLINE_EXPIRED: the authoritative deadline has passed")]
    DeadlineExpired,
    #[error("INTENT_PARENT_CHANGED: the store directory is no longer the one that was verified")]
    ParentChanged,
    #[error("INTENT_STATE_COMPETING: the record changed under this writer")]
    Competing,
    #[error("INTENT_UNSUPPORTED_PLATFORM: durable intent needs a unix filesystem")]
    UnsupportedPlatform,
    #[error("INTENT_NO_DISPATCH_INELIGIBLE: {reason}")]
    NoDispatchIneligible { reason: &'static str },
    /// Rename published the new bytes; directory sync did not confirm durability.
    /// On-disk disposition may already be the new record or still the prior one
    /// after a crash; callers must not treat this as known-[`Disposition::Pending`]
    /// or as a durable terminal success.
    #[error(
        "INTENT_PUBLISH_DURABILITY_UNCERTAIN: rename succeeded; directory sync failed; \
         on-disk disposition may be the new or prior record"
    )]
    PublishDurabilityUncertain,
}

impl IntentError {
    /// Closed identifier, the part of the message before the colon.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingField { .. } => "INTENT_FIELD_MISSING",
            Self::InvalidField { .. } => "INTENT_FIELD_INVALID",
            Self::InsecurePath { .. } => "INTENT_PATH_INSECURE",
            Self::Locked => "INTENT_STORE_LOCKED",
            Self::Io { .. } => "INTENT_STORE_IO",
            Self::Corrupt { .. } => "INTENT_RECORD_CORRUPT",
            Self::Oversize => "INTENT_RECORD_OVERSIZE",
            Self::TooManyEntries => "INTENT_STORE_FULL",
            Self::Misfiled => "INTENT_RECORD_MISFILED",
            Self::BindingConflict { .. } => "INTENT_BINDING_CONFLICT",
            Self::DeadlineExpired => "INTENT_DEADLINE_EXPIRED",
            Self::ParentChanged => "INTENT_PARENT_CHANGED",
            Self::Competing => "INTENT_STATE_COMPETING",
            Self::UnsupportedPlatform => "INTENT_UNSUPPORTED_PLATFORM",
            Self::NoDispatchIneligible { .. } => "INTENT_NO_DISPATCH_INELIGIBLE",
            Self::PublishDurabilityUncertain => "INTENT_PUBLISH_DURABILITY_UNCERTAIN",
        }
    }
}

/// A binding whose every required field is present and clean.
#[derive(Debug, Clone)]
pub(crate) struct ValidBinding {
    task_id: String,
    plan_revision: String,
    attempt_id: String,
    lease_fence: String,
    deadline_epoch_s: u64,
    dialect_revision: String,
    reservation_ref: Option<String>,
}

fn closed(field: &'static str, value: &str) -> Result<(), IntentError> {
    let ok = !value.is_empty()
        && value.len() <= MAX_FIELD_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-' | b'/'));
    if ok {
        Ok(())
    } else {
        Err(IntentError::InvalidField { field })
    }
}

fn required(field: &'static str, value: Option<&String>) -> Result<String, IntentError> {
    let value = value.ok_or(IntentError::MissingField { field })?;
    closed(field, value)?;
    Ok(value.clone())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn now_epoch_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl ValidBinding {
    pub(crate) fn from(binding: &OperationBinding) -> Result<Self, IntentError> {
        let deadline = binding.deadline_epoch_s.ok_or(IntentError::MissingField {
            field: "deadline_epoch_s",
        })?;
        if let Some(reference) = binding.reservation_ref.as_ref() {
            closed("reservation_ref", reference)?;
        }
        Ok(Self {
            task_id: required("task_id", binding.task_id.as_ref())?,
            plan_revision: required("plan_revision", binding.plan_revision.as_ref())?,
            attempt_id: required("attempt_id", binding.attempt_id.as_ref())?,
            lease_fence: required("lease_fence", binding.lease_fence.as_ref())?,
            deadline_epoch_s: deadline,
            dialect_revision: required("dialect_revision", binding.dialect_revision.as_ref())?,
            reservation_ref: binding.reservation_ref.clone(),
        })
    }

    fn scope(&self) -> String {
        hex(blake3::hash(self.task_id.as_bytes()).as_bytes())
    }

    /// The first field of a retained, unresolved record that disagrees with
    /// this binding. A retained operation is held under the identity it was
    /// started with; a renewed lease, a new attempt, a revised plan or a moved
    /// deadline cannot inherit it.
    fn first_conflict(&self, record: &IntentRecord) -> Option<&'static str> {
        [
            ("task_id", self.task_id == record.task_id),
            ("plan_revision", self.plan_revision == record.plan_revision),
            ("attempt_id", self.attempt_id == record.attempt_id),
            ("lease_fence", self.lease_fence == record.lease_fence),
            (
                "deadline_epoch_s",
                self.deadline_epoch_s == record.deadline_epoch_s,
            ),
            (
                "dialect_revision",
                self.dialect_revision == record.dialect_revision,
            ),
            (
                "reservation_ref",
                self.reservation_ref == record.reservation_ref,
            ),
        ]
        .into_iter()
        .find_map(|(field, same)| (!same).then_some(field))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body: IntentRecord,
    /// `blake3` of the canonical serialization of `body`, hex.
    check: String,
}

fn seal(body: &IntentRecord) -> Result<Vec<u8>, IntentError> {
    let canonical = serde_json::to_vec(body).map_err(|_| IntentError::Corrupt {
        reason: "record does not serialize",
    })?;
    let envelope = Envelope {
        body: body.clone(),
        check: hex(blake3::hash(&canonical).as_bytes()),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| IntentError::Corrupt {
        reason: "record does not serialize",
    })?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(IntentError::Oversize);
    }
    Ok(bytes)
}

/// Disposition / `outcome_ref` / `refusal_reason` pairs the store may persist.
/// Shared by [`unseal`] (reject a retained record) and mark paths (refuse
/// before write). v1 `Reconciled` still requires `outcome_ref` and forbids a
/// forged no-dispatch shape.
fn disposition_outcome_valid(
    version: u32,
    disposition: Disposition,
    outcome_ref: Option<&str>,
    refusal_reason: Option<&str>,
) -> bool {
    match disposition {
        Disposition::Pending | Disposition::Unknown => {
            outcome_ref.is_none() && refusal_reason.is_none()
        }
        Disposition::Reconciled => outcome_ref.is_some() && refusal_reason.is_none(),
        Disposition::NoDispatch => {
            version == RECORD_VERSION_NO_DISPATCH
                && outcome_ref.is_none()
                && refusal_reason.is_some_and(|r| !r.is_empty() && r.len() <= MAX_FIELD_BYTES)
        }
    }
}

fn unseal(bytes: &[u8], scope: &str) -> Result<IntentRecord, IntentError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(IntentError::Oversize);
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| IntentError::Corrupt {
        reason: "record is truncated or not the expected JSON",
    })?;
    let canonical = serde_json::to_vec(&envelope.body).map_err(|_| IntentError::Corrupt {
        reason: "record does not re-serialize",
    })?;
    if hex(blake3::hash(&canonical).as_bytes()) != envelope.check {
        return Err(IntentError::Corrupt {
            reason: "integrity check does not match",
        });
    }
    let record = envelope.body;
    if record.version != RECORD_VERSION && record.version != RECORD_VERSION_NO_DISPATCH {
        return Err(IntentError::Corrupt {
            reason: "unsupported record version",
        });
    }
    // v1 bytes cannot carry NoDispatch; that disposition exists only at v2.
    if record.version == RECORD_VERSION && matches!(record.disposition, Disposition::NoDispatch) {
        return Err(IntentError::Corrupt {
            reason: "unsupported record version",
        });
    }
    if record.scope != scope {
        return Err(IntentError::Misfiled);
    }
    if !is_hex(&record.request_fingerprint, 64)
        || !is_hex(&record.run_id, 32)
        || record
            .outcome_ref
            .as_deref()
            .is_some_and(|r| !is_hex(r, 64))
        || crate::connector::IdempotencyKey::from_persisted(&record.idempotency_key).is_none()
        || !disposition_outcome_valid(
            record.version,
            record.disposition,
            record.outcome_ref.as_deref(),
            record.refusal_reason.as_deref(),
        )
    {
        return Err(IntentError::Corrupt {
            reason: "record field outside its closed shape",
        });
    }
    for (field, value) in [
        ("task_id", &record.task_id),
        ("plan_revision", &record.plan_revision),
        ("attempt_id", &record.attempt_id),
        ("lease_fence", &record.lease_fence),
        ("provider", &record.provider),
        ("dialect_revision", &record.dialect_revision),
    ] {
        closed(field, value).map_err(|_| IntentError::Corrupt {
            reason: "record text field outside its closed set",
        })?;
    }
    if record
        .model
        .as_deref()
        .is_some_and(|m| closed("model", m).is_err())
        || record
            .reservation_ref
            .as_deref()
            .is_some_and(|r| closed("reservation_ref", r).is_err())
    {
        return Err(IntentError::Corrupt {
            reason: "record text field outside its closed set",
        });
    }
    Ok(record)
}

#[cfg(unix)]
mod fsio {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

    use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};

    use super::{
        closed, disposition_outcome_valid, hex, now_epoch_s, seal, unseal, Disposition,
        IntentError, IntentRecord, NewIntent, ValidBinding, MAX_RECORD_BYTES, MAX_STORE_ENTRIES,
        RECORD_VERSION, RECORD_VERSION_NO_DISPATCH,
    };

    fn io_error(operation: &'static str, error: rustix::io::Errno) -> IntentError {
        IntentError::Io {
            operation,
            kind: std::io::Error::from_raw_os_error(error.raw_os_error()).kind(),
        }
    }

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// Walk `path` from `/`, one component at a time, refusing a symlink in
    /// any of them.
    fn open_dir_without_symlinks(path: &Path) -> Result<OwnedFd, IntentError> {
        if !path.is_absolute() {
            return Err(IntentError::InsecurePath {
                reason: "store directory must be an absolute path",
            });
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut current = rustix::fs::open("/", flags, Mode::empty())
            .map_err(|e| io_error("open store root", e))?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    current = rustix::fs::openat(&current, name, flags, Mode::empty()).map_err(
                        |e| {
                            if e == rustix::io::Errno::LOOP || e == rustix::io::Errno::NOTDIR {
                                IntentError::InsecurePath {
                                    reason: "a component of the store path is a symlink or not a directory",
                                }
                            } else {
                                io_error("open store directory", e)
                            }
                        },
                    )?;
                }
                _ => {
                    return Err(IntentError::InsecurePath {
                        reason: "store path must be normalized (no `.` or `..`)",
                    })
                }
            }
        }
        Ok(current)
    }

    fn verify_private_dir(dir: &OwnedFd) -> Result<(u64, u64), IntentError> {
        let file = File::from(dir.try_clone().map_err(|e| IntentError::Io {
            operation: "duplicate store directory handle",
            kind: e.kind(),
        })?);
        let meta = file.metadata().map_err(|e| IntentError::Io {
            operation: "stat store directory",
            kind: e.kind(),
        })?;
        if !meta.is_dir() {
            return Err(IntentError::InsecurePath {
                reason: "store path is not a directory",
            });
        }
        if meta.uid() != euid() {
            return Err(IntentError::InsecurePath {
                reason: "store directory is not owned by the running user",
            });
        }
        if meta.mode() & 0o077 != 0 {
            return Err(IntentError::InsecurePath {
                reason: "store directory is accessible to group or others",
            });
        }
        Ok((meta.dev(), meta.ino()))
    }

    /// A file inside the store: regular, ours, owner-only, single link.
    fn verify_private_file(file: &File) -> Result<u64, IntentError> {
        let meta = file.metadata().map_err(|e| IntentError::Io {
            operation: "stat store file",
            kind: e.kind(),
        })?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(IntentError::InsecurePath {
                reason: "store file is not a regular single-link file",
            });
        }
        if meta.uid() != euid() || meta.mode() & 0o077 != 0 {
            return Err(IntentError::InsecurePath {
                reason: "store file is not owner-only",
            });
        }
        Ok(meta.len())
    }

    fn scope_entry(name: &str, scope: &str) -> Option<Entry> {
        let rest = name.strip_prefix(scope)?;
        match rest {
            ".json" => Some(Entry::Record),
            ".lock" => Some(Entry::Lock),
            _ if rest.starts_with(".tmp-") => Some(Entry::Staged),
            _ => None,
        }
    }

    enum Entry {
        Record,
        Lock,
        Staged,
    }

    fn is_store_name(name: &str) -> bool {
        let Some((stem, rest)) = name.split_once('.') else {
            return false;
        };
        super::is_hex(stem, 64) && (rest == "json" || rest == "lock" || rest.starts_with("tmp-"))
    }

    /// The open private store for one task scope. Holds the exclusive lock for
    /// as long as it lives, so a second driver cannot act on the same
    /// operation, and the kernel releases it if this process dies.
    pub struct IntentStore {
        dir: OwnedFd,
        dir_path: std::path::PathBuf,
        dir_identity: (u64, u64),
        binding: ValidBinding,
        scope: String,
        _lock: File,
        /// Digest of the bytes this writer last read or wrote; `None` means it
        /// saw no record.
        last_seen: Option<[u8; 32]>,
        generation: u64,
        current: Option<IntentRecord>,
        /// One-shot test seam from [`super::OperationIntentConfig`]. When set,
        /// the next `NoDispatch` write fails after rename at directory sync.
        fail_no_dispatch_dir_sync_after_rename: bool,
    }

    impl std::fmt::Debug for IntentStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("IntentStore")
                .field("scope", &self.scope)
                .field("generation", &self.generation)
                .finish_non_exhaustive()
        }
    }

    impl IntentStore {
        /// Verify, lock and read. Returns the store and the retained record,
        /// if one exists and is still unresolved or settled.
        ///
        /// # Errors
        /// Any [`IntentError`]; none of them has dispatched anything.
        pub(crate) fn open(
            dir: &Path,
            binding: &ValidBinding,
        ) -> Result<(Self, Option<IntentRecord>), IntentError> {
            let scope = binding.scope();
            // Shape first: nothing is created for a path that is refused.
            if !dir.is_absolute()
                || dir
                    .components()
                    .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            {
                return Err(IntentError::InsecurePath {
                    reason: "store directory must be an absolute, normalized path",
                });
            }
            if std::fs::symlink_metadata(dir).is_err() {
                // One level only: the parent must already exist and be sound.
                let mut builder = std::fs::DirBuilder::new();
                std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
                builder.create(dir).map_err(|e| IntentError::Io {
                    operation: "create store directory",
                    kind: e.kind(),
                })?;
            }
            let dir_fd = open_dir_without_symlinks(dir)?;
            let dir_identity = verify_private_dir(&dir_fd)?;
            Self::check_entries(&dir_fd)?;

            let lock_name = format!("{scope}.lock");
            let lock_fd = rustix::fs::openat(
                &dir_fd,
                lock_name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|e| io_error("open lock file", e))?;
            let lock = File::from(lock_fd);
            verify_private_file(&lock)?;
            rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
                if e == rustix::io::Errno::WOULDBLOCK {
                    IntentError::Locked
                } else {
                    io_error("lock the store", e)
                }
            })?;

            let mut store = Self {
                dir: dir_fd,
                dir_path: dir.to_path_buf(),
                dir_identity,
                binding: binding.clone(),
                scope,
                _lock: lock,
                last_seen: None,
                generation: 0,
                current: None,
                fail_no_dispatch_dir_sync_after_rename: false,
            };
            store.discard_staged_leftovers()?;
            let retained = store.read_record()?;
            if let Some(record) = retained.as_ref() {
                store.generation = record.generation;
                if record.disposition.is_unresolved() {
                    if let Some(field) = store.binding.first_conflict(record) {
                        return Err(IntentError::BindingConflict { field });
                    }
                }
            }
            store.current.clone_from(&retained);
            // Checked after the retained record so that a held identity is
            // named by the conflict above before a clock refuses the call.
            if store.binding.deadline_epoch_s <= now_epoch_s() {
                return Err(IntentError::DeadlineExpired);
            }
            Ok((store, retained))
        }

        fn check_entries(dir: &OwnedFd) -> Result<(), IntentError> {
            let reader = rustix::fs::Dir::read_from(dir.as_fd())
                .map_err(|e| io_error("list store directory", e))?;
            let mut count = 0usize;
            for entry in reader {
                let entry = entry.map_err(|e| io_error("list store directory", e))?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                count += 1;
                if count > MAX_STORE_ENTRIES {
                    return Err(IntentError::TooManyEntries);
                }
                let known = std::str::from_utf8(name).is_ok_and(is_store_name);
                if !known {
                    return Err(IntentError::InsecurePath {
                        reason: "store directory holds an entry this profile did not write",
                    });
                }
            }
            Ok(())
        }

        /// With the lock held, any staged file of this scope belongs to a dead
        /// writer that never reached its rename; it was never authoritative.
        fn discard_staged_leftovers(&self) -> Result<(), IntentError> {
            let reader = rustix::fs::Dir::read_from(self.dir.as_fd())
                .map_err(|e| io_error("list store directory", e))?;
            let mut stale = Vec::new();
            for entry in reader {
                let entry = entry.map_err(|e| io_error("list store directory", e))?;
                if let Ok(name) = entry.file_name().to_str() {
                    if matches!(scope_entry(name, &self.scope), Some(Entry::Staged)) {
                        stale.push(name.to_owned());
                    }
                }
            }
            for name in stale {
                rustix::fs::unlinkat(&self.dir, name.as_str(), AtFlags::empty())
                    .map_err(|e| io_error("discard staged leftover", e))?;
            }
            Ok(())
        }

        fn record_name(&self) -> String {
            format!("{}.json", self.scope)
        }

        fn read_bytes(&self) -> Result<Option<Vec<u8>>, IntentError> {
            let name = self.record_name();
            let fd = match rustix::fs::openat(
                &self.dir,
                name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
                Err(e) => return Err(io_error("open retained record", e)),
            };
            let file = File::from(fd);
            let len = verify_private_file(&file)?;
            if len > MAX_RECORD_BYTES as u64 {
                return Err(IntentError::Oversize);
            }
            let mut bytes = Vec::new();
            file.take(MAX_RECORD_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| IntentError::Io {
                    operation: "read retained record",
                    kind: e.kind(),
                })?;
            Ok(Some(bytes))
        }

        fn read_record(&mut self) -> Result<Option<IntentRecord>, IntentError> {
            let Some(bytes) = self.read_bytes()? else {
                self.last_seen = None;
                return Ok(None);
            };
            let record = unseal(&bytes, &self.scope)?;
            self.last_seen = Some(*blake3::hash(&bytes).as_bytes());
            Ok(Some(record))
        }

        fn assert_parent_unchanged(&self) -> Result<(), IntentError> {
            let meta = std::fs::symlink_metadata(&self.dir_path)
                .map_err(|_| IntentError::ParentChanged)?;
            if (meta.dev(), meta.ino()) != self.dir_identity || !meta.is_dir() {
                return Err(IntentError::ParentChanged);
            }
            let held = verify_private_dir(&self.dir)?;
            if held != self.dir_identity {
                return Err(IntentError::ParentChanged);
            }
            Ok(())
        }

        fn assert_not_competing(&self) -> Result<(), IntentError> {
            let now = self.read_bytes()?;
            let seen = now.as_deref().map(|b| *blake3::hash(b).as_bytes());
            if seen == self.last_seen {
                Ok(())
            } else {
                Err(IntentError::Competing)
            }
        }

        fn write(&mut self, record: &IntentRecord) -> Result<(), IntentError> {
            self.assert_parent_unchanged()?;
            self.assert_not_competing()?;
            let bytes = seal(record)?;
            let staged = format!(
                "{}.tmp-{}",
                self.scope,
                hex(&uuid::Uuid::new_v4().as_bytes()[..8])
            );
            let fd = rustix::fs::openat(
                &self.dir,
                staged.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|e| io_error("stage record", e))?;
            let mut file = File::from(fd);
            // Pre-rename phase: any failure here leaves the prior target bytes.
            if let Err(error) = (|| -> Result<(), IntentError> {
                file.write_all(&bytes).map_err(|e| IntentError::Io {
                    operation: "write staged record",
                    kind: e.kind(),
                })?;
                file.sync_all().map_err(|e| IntentError::Io {
                    operation: "fsync staged record",
                    kind: e.kind(),
                })?;
                Ok(())
            })() {
                let _ = rustix::fs::unlinkat(&self.dir, staged.as_str(), AtFlags::empty());
                return Err(error);
            }
            if let Err(error) = rustix::fs::renameat(
                &self.dir,
                staged.as_str(),
                &self.dir,
                self.record_name().as_str(),
            ) {
                let _ = rustix::fs::unlinkat(&self.dir, staged.as_str(), AtFlags::empty());
                return Err(io_error("publish record", error));
            }
            // Rename succeeded: the target may already expose `bytes`. Do not
            // unlink the staged name (it was consumed by rename). Directory
            // sync confirms durability; failure is uncertain persistence.
            if record.disposition == Disposition::NoDispatch
                && self.fail_no_dispatch_dir_sync_after_rename
            {
                self.fail_no_dispatch_dir_sync_after_rename = false;
                self.refresh_last_seen_from_target();
                return Err(IntentError::PublishDurabilityUncertain);
            }
            if rustix::fs::fsync(&self.dir).is_err() {
                self.refresh_last_seen_from_target();
                return Err(IntentError::PublishDurabilityUncertain);
            }
            self.last_seen = Some(*blake3::hash(&bytes).as_bytes());
            self.generation = record.generation;
            self.current = Some(record.clone());
            Ok(())
        }

        /// After a post-rename directory-sync failure, align `last_seen` with
        /// the live target so a later under-lock retry is not false-Competing.
        /// Does not adopt the write as durable success (`current` / generation
        /// stay pre-publish).
        fn refresh_last_seen_from_target(&mut self) {
            if let Ok(Some(on_disk)) = self.read_bytes() {
                self.last_seen = Some(*blake3::hash(&on_disk).as_bytes());
            }
        }

        /// Durably persist a new `pending` intent. The caller dispatches only
        /// after this returns `Ok`.
        ///
        /// An unresolved retained record (any key or fingerprint) is refused:
        /// the store itself holds the key↔fingerprint↔disposition invariant so
        /// a caller cannot overwrite K/A with K/B, reset `unknown` to
        /// `pending`, or orphan the held identity. Replay of the same key is
        /// decided by [`OperationSession`] / the composition root and never by
        /// rewriting the retained bytes here.
        ///
        /// # Errors
        /// Any [`IntentError`]; the request must then NOT be dispatched.
        pub fn persist_pending(&mut self, new: &NewIntent) -> Result<(), IntentError> {
            if self.binding.deadline_epoch_s <= now_epoch_s() {
                return Err(IntentError::DeadlineExpired);
            }
            if let Some(record) = self.current.as_ref() {
                if record.disposition.is_unresolved() {
                    // Same key with a changed fingerprint, same key after
                    // Unknown, or a different key: all would replace the held
                    // proof. Refuse before any write.
                    return Err(IntentError::Competing);
                }
            }
            for (field, value) in [
                ("provider", Some(&new.provider)),
                ("model", new.model.as_ref()),
            ] {
                if let Some(value) = value {
                    closed(field, value)?;
                }
            }
            let record = IntentRecord {
                version: RECORD_VERSION,
                scope: self.scope.clone(),
                generation: self.generation.saturating_add(1),
                task_id: self.binding.task_id.clone(),
                plan_revision: self.binding.plan_revision.clone(),
                attempt_id: self.binding.attempt_id.clone(),
                lease_fence: self.binding.lease_fence.clone(),
                deadline_epoch_s: self.binding.deadline_epoch_s,
                run_id: new.run_id.clone(),
                turn: new.turn,
                provider: new.provider.clone(),
                model: new.model.clone(),
                dialect_revision: self.binding.dialect_revision.clone(),
                request_fingerprint: hex(&new.request_fingerprint),
                idempotency_key: new.idempotency_key.clone(),
                reservation_ref: self.binding.reservation_ref.clone(),
                disposition: Disposition::Pending,
                outcome_ref: None,
                refusal_reason: None,
            };
            self.write(&record)
        }

        /// Move the current operation to `unknown` or `reconciled`.
        ///
        /// Transitions are validated with the same disposition and `outcome_ref`
        /// rule [`unseal`] applies on restart, so an invalid record is never
        /// published. [`Disposition::NoDispatch`] is refused here — use
        /// [`Self::mark_no_dispatch`] so the fresh-pending / zero-handoff
        /// fence stays in one place.
        ///
        /// # Errors
        /// Any [`IntentError`]. A failed transition leaves the stricter
        /// earlier disposition on disk, which is the safe side.
        pub fn mark(
            &mut self,
            disposition: Disposition,
            outcome: Option<&str>,
        ) -> Result<(), IntentError> {
            if matches!(disposition, Disposition::NoDispatch) {
                return Err(IntentError::NoDispatchIneligible {
                    reason: "use mark_no_dispatch for the terminal no-dispatch path",
                });
            }
            let Some(mut record) = self.current.clone() else {
                return Err(IntentError::Corrupt {
                    reason: "no operation to mark",
                });
            };
            if matches!(record.disposition, Disposition::NoDispatch) {
                return Err(IntentError::NoDispatchIneligible {
                    reason: "terminal no-dispatch cannot be re-marked",
                });
            }
            let outcome_ref = outcome.map(|o| hex(blake3::hash(o.as_bytes()).as_bytes()));
            if !disposition_outcome_valid(record.version, disposition, outcome_ref.as_deref(), None)
            {
                return Err(IntentError::Corrupt {
                    reason: "record field outside its closed shape",
                });
            }
            record.generation = self.generation.saturating_add(1);
            record.disposition = disposition;
            record.outcome_ref = outcome_ref;
            record.refusal_reason = None;
            self.write(&record)
        }

        /// Durably resolve a **fresh** `pending` intent as terminal no-dispatch.
        ///
        /// Allowed only while this store still holds the exclusive lock, the
        /// current record is `pending`, and the caller has established
        /// zero connector/executor handoff for this operation (enforced by
        /// [`super::OperationSession::mark_no_dispatch`]). Uses stage → fsync
        /// → rename → dir fsync via [`Self::write`]. **Before** the rename, a
        /// failed step leaves the prior `pending` bytes. **After** a successful
        /// rename, a directory-sync failure returns
        /// [`IntentError::PublishDurabilityUncertain`]: the target may already
        /// hold `no_dispatch` bytes and must not be forced back to pending.
        ///
        /// # Errors
        /// Any [`IntentError`]; the caller must not acknowledge terminal
        /// no-dispatch success. On pre-rename failure the prior
        /// [`Disposition::Pending`] remains; on post-rename directory-sync
        /// failure persistence is uncertain.
        pub fn mark_no_dispatch(&mut self, refusal_reason: &str) -> Result<(), IntentError> {
            closed("refusal_reason", refusal_reason)?;
            let Some(mut record) = self.current.clone() else {
                return Err(IntentError::Corrupt {
                    reason: "no operation to mark",
                });
            };
            if record.disposition != Disposition::Pending {
                return Err(IntentError::NoDispatchIneligible {
                    reason: "no-dispatch requires a current pending record",
                });
            }
            if !disposition_outcome_valid(
                RECORD_VERSION_NO_DISPATCH,
                Disposition::NoDispatch,
                None,
                Some(refusal_reason),
            ) {
                return Err(IntentError::Corrupt {
                    reason: "record field outside its closed shape",
                });
            }
            record.generation = self.generation.saturating_add(1);
            record.version = RECORD_VERSION_NO_DISPATCH;
            record.disposition = Disposition::NoDispatch;
            record.outcome_ref = None;
            record.refusal_reason = Some(refusal_reason.to_owned());
            // Exact original identity/key retained; only disposition/version/
            // generation/refusal_reason change.
            self.write(&record)
        }

        /// The record this writer last read or wrote, if any.
        #[must_use]
        pub(crate) fn current_record(&self) -> Option<&IntentRecord> {
            self.current.as_ref()
        }

        /// Arm the one-shot post-rename directory-sync fault for the next
        /// `NoDispatch` write. Used only from [`super::OperationSession::open`]
        /// when the test config requests it.
        pub(crate) fn arm_no_dispatch_directory_sync_after_rename(&mut self) {
            self.fail_no_dispatch_dir_sync_after_rename = true;
        }
    }
}

#[cfg(unix)]
pub use fsio::IntentStore;

/// Non-unix builds cannot give the private-path guarantees; they refuse.
#[cfg(not(unix))]
#[derive(Debug)]
pub struct IntentStore;

#[cfg(not(unix))]
impl IntentStore {
    pub(crate) fn open(
        _dir: &std::path::Path,
        _binding: &ValidBinding,
    ) -> Result<(Self, Option<IntentRecord>), IntentError> {
        Err(IntentError::UnsupportedPlatform)
    }
    /// # Errors
    /// Always: unsupported platform.
    pub fn persist_pending(&mut self, _new: &NewIntent) -> Result<(), IntentError> {
        Err(IntentError::UnsupportedPlatform)
    }
    /// # Errors
    /// Always: unsupported platform.
    pub fn mark(&mut self, _d: Disposition, _o: Option<&str>) -> Result<(), IntentError> {
        Err(IntentError::UnsupportedPlatform)
    }
    /// # Errors
    /// Always: unsupported platform.
    pub fn mark_no_dispatch(&mut self, _reason: &str) -> Result<(), IntentError> {
        Err(IntentError::UnsupportedPlatform)
    }
}

/// One run's view of the store: the open store, the retained unresolved
/// operation (if any) and the replay trust.
#[derive(Debug)]
pub struct OperationSession {
    pub(crate) store: IntentStore,
    pub(crate) held: Option<IntentRecord>,
    /// Terminal no-dispatch retained for this scope, if any. Used to return
    /// the same refusal for a repeated closed operation (ND05 / ND08).
    pub(crate) closed_no_dispatch: Option<IntentRecord>,
    pub(crate) replay_verified: bool,
    /// `true` only after [`Self::persist_pending`] succeeds in this session
    /// and before any mark / handoff. Recovered Pending/Unknown never sets it.
    fresh_pending: bool,
    /// Connector/executor handoffs counted for the fresh pending operation.
    handoff_count: u64,
}

impl OperationSession {
    /// Validate, lock and read. Called by `Driver::run` before any key is
    /// minted or any dispatch is made.
    ///
    /// # Errors
    /// Any [`IntentError`]; nothing has been dispatched.
    pub fn open(config: &OperationIntentConfig) -> Result<Self, IntentError> {
        let binding = ValidBinding::from(&config.binding)?;
        let (mut store, retained) = IntentStore::open(&config.store_dir, &binding)?;
        if config.test_fail_no_dispatch_dir_sync_after_rename {
            store.arm_no_dispatch_directory_sync_after_rename();
        }
        let closed_no_dispatch = retained
            .clone()
            .filter(|r| matches!(r.disposition, Disposition::NoDispatch));
        Ok(Self {
            store,
            held: retained.filter(|r| r.disposition.is_unresolved()),
            closed_no_dispatch,
            replay_verified: config.same_key_replay_verified,
            fresh_pending: false,
            handoff_count: 0,
        })
    }

    /// The retained unresolved operation, if the previous process left one.
    #[must_use]
    pub const fn held(&self) -> Option<&IntentRecord> {
        self.held.as_ref()
    }

    /// The retained terminal no-dispatch, if a previous process wrote one.
    #[must_use]
    pub const fn closed_no_dispatch(&self) -> Option<&IntentRecord> {
        self.closed_no_dispatch.as_ref()
    }

    /// Count a connector or executor handoff for the current fresh pending.
    /// After this, [`Self::mark_no_dispatch`] refuses (ND02 / ND06 fence).
    pub fn note_handoff(&mut self) {
        self.handoff_count = self.handoff_count.saturating_add(1);
    }

    /// Durably persist a new `pending` intent (see [`IntentStore::persist_pending`]).
    ///
    /// # Errors
    /// Any [`IntentError`]; the request must then not be dispatched.
    pub fn persist_pending(&mut self, new: &NewIntent) -> Result<(), IntentError> {
        self.store.persist_pending(new)?;
        self.fresh_pending = true;
        self.handoff_count = 0;
        self.closed_no_dispatch = None;
        self.held = None;
        Ok(())
    }

    /// Move the current operation to `unknown` or `reconciled`.
    ///
    /// # Errors
    /// Any [`IntentError`]; the stricter earlier disposition stays on disk.
    pub fn mark(
        &mut self,
        disposition: Disposition,
        outcome: Option<&str>,
    ) -> Result<(), IntentError> {
        self.store.mark(disposition, outcome)?;
        self.fresh_pending = false;
        if matches!(disposition, Disposition::Reconciled) {
            self.held = None;
            self.closed_no_dispatch = None;
        }
        Ok(())
    }

    /// Durably resolve this session's fresh pending as proven-no-dispatch.
    ///
    /// Requires: pending created in this session (`fresh_pending`), zero
    /// handoffs, exclusive store lock held. Pre-rename write failure leaves
    /// the prior [`Disposition::Pending`]; post-rename directory-sync failure
    /// is [`IntentError::PublishDurabilityUncertain`] (persistence may already
    /// show [`Disposition::NoDispatch`] — do not invent a fresh key or erase
    /// evidence).
    ///
    /// # Errors
    /// [`IntentError::NoDispatchIneligible`] when the fence is not met;
    /// any store [`IntentError`] when the durable write fails.
    pub fn mark_no_dispatch(&mut self, refusal_reason: &str) -> Result<(), IntentError> {
        if !self.fresh_pending {
            return Err(IntentError::NoDispatchIneligible {
                reason: "no-dispatch requires a fresh pending created in this invocation",
            });
        }
        if self.handoff_count != 0 {
            return Err(IntentError::NoDispatchIneligible {
                reason: "no-dispatch requires zero connector/executor handoff",
            });
        }
        if self.held.is_some() {
            return Err(IntentError::NoDispatchIneligible {
                reason: "recovered unresolved intent cannot become no-dispatch",
            });
        }
        self.store.mark_no_dispatch(refusal_reason)?;
        self.fresh_pending = false;
        self.closed_no_dispatch = self.store.current_record().cloned();
        self.held = None;
        Ok(())
    }
}
