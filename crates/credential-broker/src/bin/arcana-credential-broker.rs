//! Credential broker entrypoint. This is the only compilation unit that reads
//! provider credential material.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use arcana_credential_broker::audit::{AuditRecord, AuditWriter, CausalIds, EventKind};
use arcana_credential_broker::CapabilityPolicy;
use secrecy::zeroize::Zeroizing;

#[path = "../broker/broker_runtime.rs"]
mod broker_runtime;

use broker_runtime::{AdapterMode, Credential, ServerConfig};

const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;
const MAX_POLICY_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
enum StartupRefusal {
    Arguments(String),
    Policy(String),
    SourceMissing(PathBuf),
    SourceNotRegularFile(PathBuf),
    SourcePermissions(PathBuf, u32),
    SourceNotOwnedByBroker(PathBuf),
    SourceInvalidSize(PathBuf),
    RunningAsExecutorUid(u32),
    SourceEmpty(PathBuf),
    UnsupportedCredentialAttestation(&'static str),
}

impl std::fmt::Display for StartupRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Arguments(reason) => write!(formatter, "invalid arguments: {reason}"),
            Self::Policy(reason) => write!(formatter, "capability policy rejected: {reason}"),
            Self::SourceMissing(path) => {
                write!(formatter, "credential source is absent: {}", path.display())
            }
            Self::SourceNotRegularFile(path) => write!(
                formatter,
                "credential source is not a regular file: {}",
                path.display()
            ),
            Self::SourcePermissions(path, mode) => write!(
                formatter,
                "credential source {} has mode {mode:04o}; require exactly 0600",
                path.display()
            ),
            Self::SourceNotOwnedByBroker(path) => write!(
                formatter,
                "credential source {} is not owned by the broker identity",
                path.display()
            ),
            Self::SourceInvalidSize(path) => write!(
                formatter,
                "credential source {} is empty or exceeds the size limit",
                path.display()
            ),
            Self::RunningAsExecutorUid(uid) => write!(
                formatter,
                "broker is running as the executor uid ({uid}); it must have its own identity"
            ),
            Self::SourceEmpty(path) => {
                write!(formatter, "credential source is empty: {}", path.display())
            }
            Self::UnsupportedCredentialAttestation(platform) => write!(
                formatter,
                "credentialed broker mode is unsupported on {platform}: the required per-message attestation backend is not installed"
            ),
        }
    }
}

struct Args {
    policy: PathBuf,
    socket: PathBuf,
    credential_source: PathBuf,
    mock_provider: bool,
    max_connections: usize,
    state_file: PathBuf,
    audit_file: PathBuf,
}

fn parse_args() -> Result<Args, StartupRefusal> {
    let mut policy = PathBuf::from("/etc/arcana/credential-broker/capability-policy.toml");
    let mut socket = PathBuf::from("/run/arcana-credential-broker/broker.sock");
    let mut credential_source = PathBuf::from("/etc/arcana/credential-broker/provider.key");
    let mut mock_provider = false;
    let mut max_connections = 32usize;
    let mut state_file = PathBuf::from("/var/lib/arcana-credential-broker/broker-state.json");
    let mut audit_file = PathBuf::from("/var/lib/arcana-credential-broker/audit.log");
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--policy" => {
                policy = PathBuf::from(args.next().ok_or_else(|| {
                    StartupRefusal::Arguments("--policy requires a path".to_owned())
                })?);
            }
            "--socket" => {
                socket = PathBuf::from(args.next().ok_or_else(|| {
                    StartupRefusal::Arguments("--socket requires a path".to_owned())
                })?);
            }
            "--credential-source" => {
                credential_source = PathBuf::from(args.next().ok_or_else(|| {
                    StartupRefusal::Arguments("--credential-source requires a path".to_owned())
                })?);
            }
            "--max-connections" => {
                max_connections = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| {
                        StartupRefusal::Arguments(
                            "--max-connections requires a positive integer".to_owned(),
                        )
                    })?;
            }
            "--state" => {
                state_file = PathBuf::from(args.next().ok_or_else(|| {
                    StartupRefusal::Arguments("--state requires a path".to_owned())
                })?);
            }
            "--audit" => {
                audit_file = PathBuf::from(args.next().ok_or_else(|| {
                    StartupRefusal::Arguments("--audit requires a path".to_owned())
                })?);
            }
            "--mock-provider" => mock_provider = true,
            unknown => {
                return Err(StartupRefusal::Arguments(format!(
                    "unknown option {unknown}"
                )))
            }
        }
    }
    Ok(Args {
        policy,
        socket,
        credential_source,
        mock_provider,
        max_connections,
        state_file,
        audit_file,
    })
}

fn effective_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn credential_attestation_ready() -> bool {
    // Deliberately false until the platform-specific backends described at
    // the call site exist and pass their live falsification suites.
    false
}

fn load_credential(source: &Path, executor_uid: u32) -> Result<Credential, StartupRefusal> {
    let uid = effective_uid();
    if uid == executor_uid {
        return Err(StartupRefusal::RunningAsExecutorUid(uid));
    }
    let descriptor = rustix::fs::open(
        source,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            StartupRefusal::SourceNotRegularFile(source.to_path_buf())
        } else {
            StartupRefusal::SourceMissing(source.to_path_buf())
        }
    })?;
    let file = fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| StartupRefusal::SourceMissing(source.to_path_buf()))?;
    if !metadata.file_type().is_file() {
        return Err(StartupRefusal::SourceNotRegularFile(source.to_path_buf()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(StartupRefusal::SourcePermissions(
            source.to_path_buf(),
            mode,
        ));
    }
    if metadata.uid() != uid {
        return Err(StartupRefusal::SourceNotOwnedByBroker(source.to_path_buf()));
    }
    if metadata.len() == 0 || metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(StartupRefusal::SourceInvalidSize(source.to_path_buf()));
    }
    let mut value = Zeroizing::new(String::new());
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_string(&mut value)
        .map_err(|_| StartupRefusal::SourceMissing(source.to_path_buf()))?;
    if value.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(StartupRefusal::SourceInvalidSize(source.to_path_buf()));
    }
    let exposed_len = value.trim_end_matches(['\n', '\r']).len();
    if exposed_len == 0 {
        return Err(StartupRefusal::SourceEmpty(source.to_path_buf()));
    }
    Ok(Credential::new(std::mem::take(&mut *value), exposed_len))
}

fn load_policy(path: &Path) -> Result<CapabilityPolicy, StartupRefusal> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| StartupRefusal::Policy(format!("open protected file: {error}")))?;
    let file = fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| StartupRefusal::Policy(format!("read metadata: {error}")))?;
    if !metadata.file_type().is_file() {
        return Err(StartupRefusal::Policy(
            "policy must be a non-symlink regular file".to_owned(),
        ));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(StartupRefusal::Policy(
            "policy must not be group/world writable".to_owned(),
        ));
    }
    if metadata.uid() != effective_uid() && metadata.uid() != 0 {
        return Err(StartupRefusal::Policy(
            "policy must be owned by the broker identity or root".to_owned(),
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_POLICY_BYTES {
        return Err(StartupRefusal::Policy(
            "policy is empty or exceeds the size limit".to_owned(),
        ));
    }
    let mut body = String::new();
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|error| StartupRefusal::Policy(format!("read: {error}")))?;
    if body.len() as u64 > MAX_POLICY_BYTES {
        return Err(StartupRefusal::Policy(
            "policy exceeds the size limit".to_owned(),
        ));
    }
    let policy: CapabilityPolicy =
        toml::from_str(&body).map_err(|error| StartupRefusal::Policy(error.to_string()))?;
    policy.validate().map_err(StartupRefusal::Policy)?;
    Ok(policy)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = async {
        let args = parse_args()?;
        let policy = load_policy(&args.policy)?;
        let generation = policy.generation;
        let adapter = if args.mock_provider {
            AdapterMode::Mock
        } else {
            // A stream UDS plus sampled PID/path identity is insufficient: a
            // connected descriptor can be handed off and `/proc`/proc_pidpath
            // is mutable post-event state. Until Linux SCM_CREDENTIALS plus an
            // enforcing per-message LSM label, or macOS XPC audit-token code
            // validation, is implemented, secret-bearing mode must not start.
            if !credential_attestation_ready() {
                return Err(StartupRefusal::UnsupportedCredentialAttestation(
                    std::env::consts::OS,
                ));
            }
            AdapterMode::Http(load_credential(
                &args.credential_source,
                policy.executor_uid,
            )?)
        };
        let mut record = AuditRecord::new(now_unix(), EventKind::BrokerStart);
        record.ids = CausalIds {
            generation: Some(generation),
            credential_id: (!args.mock_provider).then(|| "provider-primary".to_owned()),
            ..CausalIds::default()
        };
        let mut audit = AuditWriter::open(&args.audit_file)
            .map_err(|error| StartupRefusal::Arguments(error.to_string()))?;
        audit
            .append(&record)
            .map_err(|error| StartupRefusal::Arguments(error.to_string()))?;
        broker_runtime::serve(ServerConfig {
            socket: args.socket,
            policy,
            adapter,
            max_connections: args.max_connections,
            state_file: args.state_file,
            audit,
        })
        .await
        .map_err(StartupRefusal::Arguments)
    }
    .await;

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(refusal) => {
            eprintln!("credential-broker: refusing to serve: {refusal}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn credential_loader_uses_owner_only_nofollow_descriptor() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let secret = dir.path().join("provider.key");
        fs::write(&secret, "test-only-sentinel\n").expect("write fixture");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("set mode");
        let executor_uid = effective_uid().wrapping_add(1);
        assert_eq!(
            load_credential(&secret, executor_uid)
                .expect("secure credential")
                .expose(),
            "test-only-sentinel"
        );

        fs::set_permissions(&secret, fs::Permissions::from_mode(0o400)).expect("set mode");
        assert!(matches!(
            load_credential(&secret, executor_uid),
            Err(StartupRefusal::SourcePermissions(_, 0o400))
        ));

        let link = dir.path().join("credential-link");
        symlink(&secret, &link).expect("symlink fixture");
        assert!(matches!(
            load_credential(&link, executor_uid),
            Err(StartupRefusal::SourceNotRegularFile(_))
        ));
    }

    #[test]
    fn policy_loader_rejects_symlink_and_oversize_before_parse() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let policy = dir.path().join("policy.toml");
        let oversize = usize::try_from(MAX_POLICY_BYTES + 1).expect("policy limit fits usize");
        fs::write(&policy, vec![b'x'; oversize]).expect("write fixture");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).expect("set mode");
        assert!(matches!(
            load_policy(&policy),
            Err(StartupRefusal::Policy(_))
        ));

        let link = dir.path().join("policy-link");
        symlink(&policy, &link).expect("symlink fixture");
        assert!(matches!(load_policy(&link), Err(StartupRefusal::Policy(_))));
    }
}
