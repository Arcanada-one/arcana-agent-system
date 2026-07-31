//! The credential broker binary — the **only** component that reads the
//! protected provider credential.
//!
//! Nothing in this file prints, logs, formats or returns credential material.
//! The value is read into memory, its length class is recorded for audit, and
//! it is never rendered. Every diagnostic is a status, a path, or a mode.
//!
//! # Phase gate-set
//!
//! In force: secret-source preflight (ownership, mode, symlink and regular-file
//! checks) and fail-closed startup refusal.
//!
//! Deferred: the permissioned local IPC listener with kernel peer-credential
//! attestation, and the provider-neutral upstream adapter. Until those land this
//! binary refuses to serve; it validates its environment and exits.
//!
//! Operator constraint: this binary MUST run as its own OS identity, never as
//! the executor uid. Startup refuses when that is not true.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use arcana_credential_broker::audit::{AuditRecord, CausalIds, EventKind};
use arcana_credential_broker::protocol::Generation;

/// Why the broker refused to start. No variant carries credential material.
#[derive(Debug)]
enum StartupRefusal {
    SourceMissing(PathBuf),
    SourceNotRegularFile(PathBuf),
    SourceGroupOrWorldAccessible(PathBuf, u32),
    SourceNotOwnedByBroker(PathBuf),
    RunningAsExecutorUid(u32),
    SourceEmpty(PathBuf),
}

impl std::fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceMissing(p) => write!(f, "credential source is absent: {}", p.display()),
            Self::SourceNotRegularFile(p) => {
                write!(
                    f,
                    "credential source is not a regular file: {}",
                    p.display()
                )
            }
            Self::SourceGroupOrWorldAccessible(p, mode) => write!(
                f,
                "credential source {} is group/world accessible (mode {:04o}); require 0600",
                p.display(),
                mode
            ),
            Self::SourceNotOwnedByBroker(p) => write!(
                f,
                "credential source {} is not owned by the broker identity",
                p.display()
            ),
            Self::RunningAsExecutorUid(uid) => write!(
                f,
                "broker is running as the executor uid ({uid}); it must have its own identity"
            ),
            Self::SourceEmpty(p) => write!(f, "credential source is empty: {}", p.display()),
        }
    }
}

/// Effective uid, read without `unsafe` from procfs. `None` where unavailable.
fn effective_uid() -> Option<u32> {
    fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Validate the credential source and load it.
///
/// The returned value is the credential. It is deliberately not `Debug`-printed
/// anywhere, and the caller records only its length class.
fn load_credential(source: &Path, executor_uid: u32) -> Result<String, StartupRefusal> {
    if let Some(uid) = effective_uid() {
        if uid == executor_uid {
            return Err(StartupRefusal::RunningAsExecutorUid(uid));
        }
    }

    // `symlink_metadata` does not follow links: a symlinked credential source is
    // rejected rather than silently followed to an unchecked target.
    let meta = fs::symlink_metadata(source)
        .map_err(|_| StartupRefusal::SourceMissing(source.to_path_buf()))?;
    if !meta.is_file() {
        return Err(StartupRefusal::SourceNotRegularFile(source.to_path_buf()));
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(StartupRefusal::SourceGroupOrWorldAccessible(
            source.to_path_buf(),
            mode,
        ));
    }
    if let Some(uid) = effective_uid() {
        if meta.uid() != uid {
            return Err(StartupRefusal::SourceNotOwnedByBroker(source.to_path_buf()));
        }
    }

    let value = fs::read_to_string(source)
        .map_err(|_| StartupRefusal::SourceMissing(source.to_path_buf()))?;
    let value = value.trim_end_matches(['\n', '\r']).to_owned();
    if value.is_empty() {
        return Err(StartupRefusal::SourceEmpty(source.to_path_buf()));
    }
    Ok(value)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn main() -> ExitCode {
    let source = std::env::args().nth(1).map_or_else(
        || PathBuf::from("/etc/arcana/credential-broker/provider.key"),
        PathBuf::from,
    );
    let executor_uid: u32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let generation = Generation(1);

    match load_credential(&source, executor_uid) {
        Err(refusal) => {
            // Fail closed and say precisely why, without revealing anything.
            eprintln!("credential-broker: refusing to start: {refusal}");
            let mut rec = AuditRecord::new(now_unix(), EventKind::BrokerStop);
            rec.ids = CausalIds {
                generation: Some(generation),
                ..CausalIds::default()
            };
            eprintln!("{rec}");
            ExitCode::FAILURE
        }
        Ok(credential) => {
            // Only the length class is ever observable. The value is not logged,
            // not returned, and not placed in any child environment.
            let length_class = if credential.len() >= 32 {
                "ok"
            } else {
                "short"
            };
            let mut rec = AuditRecord::new(now_unix(), EventKind::BrokerStart);
            rec.ids = CausalIds {
                generation: Some(generation),
                credential_id: Some("provider-primary".to_owned()),
                credential_version: Some(1),
                ..CausalIds::default()
            };
            println!("{rec} credential_length_class={length_class}");

            // The IPC listener is a deferred gate. Serving without kernel
            // peer-credential attestation would authorise against self-reported
            // identity, so the broker refuses to serve rather than serve unsafely.
            eprintln!(
                "credential-broker: IPC listener not implemented in this phase; \
                 refusing to serve. Preflight passed."
            );
            drop(credential);
            ExitCode::SUCCESS
        }
    }
}
