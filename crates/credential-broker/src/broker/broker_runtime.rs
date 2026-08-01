//! Permissioned local IPC and scoped provider adapter.

use std::collections::BTreeMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arcana_credential_broker::{
    authorize, CapabilityPolicy, CapabilityRequest, ExecutorProfile, Generation, IdempotencyKey,
    Ledger, Operation, PeerIdentity, SessionId,
};
use arcana_execution_boundary::{QuarantineScanner, ScannerConfig, Stream};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore};

const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

/// Secret wrapper with no `Debug`, `Display`, serialization, or clone surface.
pub struct Credential(String);

impl Credential {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

pub enum AdapterMode {
    Mock,
    Http(Credential),
}

pub struct ServerConfig {
    pub socket: PathBuf,
    pub policy: CapabilityPolicy,
    pub adapter: AdapterMode,
    pub max_connections: usize,
}

struct State {
    policy: CapabilityPolicy,
    ledger: Mutex<Ledger>,
    cached: Mutex<BTreeMap<IdempotencyKey, WireResponse>>,
    adapter: Adapter,
}

enum Adapter {
    Mock {
        calls: AtomicU64,
    },
    Http {
        client: reqwest::Client,
        credential: Credential,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    profile: ExecutorProfile,
    generation: Generation,
    provider: String,
    model: String,
    operation: Operation,
    upstream: String,
    quota_units: u32,
    expires_at: u64,
    idempotency: IdempotencyKey,
    #[serde(default)]
    payload: Value,
}

#[derive(Debug, Clone, Serialize)]
struct WireResponse {
    ok: bool,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome_id: Option<String>,
    replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl WireResponse {
    fn error(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            code,
            outcome_id: None,
            replayed: false,
            status: None,
            body: None,
            reason: Some(reason.into()),
        }
    }
}

/// Serve until the process is terminated.
pub async fn serve(config: ServerConfig) -> Result<(), String> {
    if config.max_connections == 0 {
        return Err("max connections must be positive".to_owned());
    }
    let listener = listener(&config.socket)?;
    let generation = config.policy.generation;
    let quota = config.policy.quota_limit;
    let adapter = match config.adapter {
        AdapterMode::Mock => Adapter::Mock {
            calls: AtomicU64::new(0),
        },
        AdapterMode::Http(credential) => Adapter::Http {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(REQUEST_DEADLINE)
                .build()
                .map_err(|error| format!("build provider client: {error}"))?,
            credential,
        },
    };
    let state = Arc::new(State {
        policy: config.policy,
        ledger: Mutex::new(Ledger::new(generation, quota)),
        cached: Mutex::new(BTreeMap::new()),
        adapter,
    });
    let permits = Arc::new(Semaphore::new(config.max_connections));

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("accept IPC connection: {error}"))?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tokio::spawn(write_response(
                stream,
                WireResponse::error("backpressure", "broker connection limit reached"),
            ));
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle(stream, state).await {
                eprintln!("credential-broker: request failed: {error}");
            }
        });
    }
}

async fn handle(mut stream: UnixStream, state: Arc<State>) -> Result<(), String> {
    let peer = attest_peer(&stream)?;
    let request = match read_request(&mut stream).await {
        Ok(request) => request,
        Err(error) => {
            return write_response(stream, WireResponse::error("invalid_request", error)).await;
        }
    };
    let response = process(request, peer, &state).await;
    write_response(stream, response).await
}

async fn read_request(stream: &mut UnixStream) -> Result<WireRequest, String> {
    let mut bytes = Vec::new();
    let mut reader = BufReader::new(stream).take((MAX_REQUEST_BYTES + 1) as u64);
    let read = tokio::time::timeout(REQUEST_DEADLINE, reader.read_until(b'\n', &mut bytes))
        .await
        .map_err(|_| "request read timed out".to_owned())?
        .map_err(|error| format!("read request: {error}"))?;
    if read == 0 || bytes.len() > MAX_REQUEST_BYTES || !bytes.ends_with(b"\n") {
        return Err("request is empty, oversized, or incomplete".to_owned());
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid request: {error}"))
}

async fn process(request: WireRequest, peer: PeerIdentity, state: &State) -> WireResponse {
    let capability = CapabilityRequest {
        peer,
        profile: request.profile,
        generation: request.generation,
        provider: request.provider,
        model: request.model,
        operation: request.operation,
        upstream: request.upstream,
        quota_units: request.quota_units,
        expires_at: request.expires_at,
        idempotency: request.idempotency.clone(),
    };
    let lease = {
        let mut ledger = state.ledger.lock().await;
        match authorize(&state.policy, &mut ledger, &capability, now_unix()) {
            Ok(lease) => lease,
            Err(denial) => return WireResponse::error("denied", denial.to_string()),
        }
    };

    if lease.replayed {
        let cache = state.cached.lock().await;
        if let Some(prior) = cache.get(&request.idempotency) {
            let mut replay = prior.clone();
            replay.replayed = true;
            return replay;
        }
        return WireResponse::error(
            "in_progress",
            "the idempotent operation is committed but its outcome is not ready",
        );
    }

    let response = match state.adapter.call(&capability, request.payload).await {
        Ok((status, body)) => WireResponse {
            ok: (200..300).contains(&status),
            code: if (200..300).contains(&status) {
                "ok"
            } else {
                "upstream_status"
            },
            outcome_id: Some(lease.outcome_id),
            replayed: false,
            status: Some(status),
            body: Some(body),
            reason: None,
        },
        Err(error) => WireResponse {
            ok: false,
            code: "upstream_failure",
            outcome_id: Some(lease.outcome_id),
            replayed: false,
            status: None,
            body: None,
            reason: Some(error),
        },
    };
    state
        .cached
        .lock()
        .await
        .insert(request.idempotency, response.clone());
    response
}

impl Adapter {
    async fn call(
        &self,
        request: &CapabilityRequest,
        mut payload: Value,
    ) -> Result<(u16, Value), String> {
        match self {
            Self::Mock { calls } => {
                let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
                Ok((
                    200,
                    json!({
                        "provider": request.provider,
                        "model": request.model,
                        "operation": request.operation,
                        "provider_calls": count,
                    }),
                ))
            }
            Self::Http { client, credential } => {
                let mut base = url::Url::parse(&request.upstream)
                    .map_err(|_| "policy upstream is not a valid URL".to_owned())?;
                if base.scheme() != "https"
                    || !base.username().is_empty()
                    || base.password().is_some()
                    || base.query().is_some()
                    || base.fragment().is_some()
                {
                    return Err("policy upstream is not a credential-safe HTTPS base".to_owned());
                }
                if !base.path().ends_with('/') {
                    base.set_path(&format!("{}/", base.path()));
                }
                let response = match request.operation {
                    Operation::Completion => {
                        let object = payload
                            .as_object_mut()
                            .ok_or_else(|| "completion payload must be a JSON object".to_owned())?;
                        if object
                            .get("model")
                            .is_some_and(|value| value.as_str() != Some(&request.model))
                        {
                            return Err("payload model does not match authorised model".to_owned());
                        }
                        object.insert("model".to_owned(), Value::String(request.model.clone()));
                        let endpoint = base
                            .join("chat/completions")
                            .map_err(|_| "cannot construct completion endpoint".to_owned())?;
                        client
                            .post(endpoint)
                            .bearer_auth(credential.expose())
                            .json(&payload)
                            .send()
                            .await
                    }
                    Operation::ListModels => {
                        let endpoint = base
                            .join("models")
                            .map_err(|_| "cannot construct models endpoint".to_owned())?;
                        client
                            .get(endpoint)
                            .bearer_auth(credential.expose())
                            .send()
                            .await
                    }
                }
                .map_err(|error| format!("provider transport failed: {error}"))?;
                let status = response.status().as_u16();
                let bytes = bounded_body(response).await?;
                quarantine_response(credential.expose().as_bytes(), &bytes)?;
                let body = serde_json::from_slice(&bytes).unwrap_or_else(
                    |_| json!({"non_json_response": true, "byte_count": bytes.len()}),
                );
                Ok((status, body))
            }
        }
    }
}

async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err("provider response exceeds the output limit".to_owned());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("read provider response: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err("provider response exceeds the output limit".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn quarantine_response(sentinel: &[u8], body: &[u8]) -> Result<(), String> {
    let mut scanner = QuarantineScanner::new(vec![sentinel.to_vec()], ScannerConfig::default())
        .map_err(|error| format!("initialise output quarantine: {error}"))?;
    let _ = scanner
        .push_stream(Stream::Stdout, body)
        .map_err(|error| format!("provider output quarantined: {error}"))?;
    let _ = scanner
        .finish()
        .map_err(|error| format!("provider output quarantined: {error}"))?;
    Ok(())
}

async fn write_response(mut stream: UnixStream, response: WireResponse) -> Result<(), String> {
    let mut bytes =
        serde_json::to_vec(&response).map_err(|error| format!("serialize response: {error}"))?;
    bytes.push(b'\n');
    tokio::time::timeout(REQUEST_DEADLINE, stream.write_all(&bytes))
        .await
        .map_err(|_| "response write timed out".to_owned())?
        .map_err(|error| format!("write response: {error}"))
}

fn attest_peer(stream: &UnixStream) -> Result<PeerIdentity, String> {
    let credentials = stream
        .peer_cred()
        .map_err(|error| format!("read kernel peer credentials: {error}"))?;
    let pid = credentials
        .pid()
        .ok_or_else(|| "kernel did not provide a peer pid".to_owned())?;
    let uid = credentials.uid();
    let executable = peer_executable(pid)?;
    let session = peer_session(pid, uid);
    Ok(PeerIdentity {
        uid,
        pid,
        executable,
        session: SessionId(session),
    })
}

#[cfg(target_os = "linux")]
fn peer_executable(pid: i32) -> Result<PathBuf, String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|error| format!("resolve peer executable: {error}"))
}

#[cfg(target_os = "macos")]
fn peer_executable(pid: i32) -> Result<PathBuf, String> {
    use sysinfo::{Pid, ProcessesToUpdate, System};
    let mut system = System::new();
    let process_id = Pid::from_u32(u32::try_from(pid).map_err(|_| "invalid peer pid")?);
    system.refresh_processes(ProcessesToUpdate::Some(&[process_id]), true);
    system
        .process(process_id)
        .and_then(|process| process.exe())
        .map(Path::to_path_buf)
        .ok_or_else(|| "resolve peer executable: process path unavailable".to_owned())
}

#[cfg(target_os = "linux")]
fn peer_session(pid: i32, uid: u32) -> String {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
    cgroup
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .flat_map(|path| path.split('/').rev())
        .find(|component| !component.is_empty())
        .map_or_else(|| format!("uid:{uid}"), ToOwned::to_owned)
}

#[cfg(target_os = "macos")]
fn peer_session(_pid: i32, uid: u32) -> String {
    // launchd does not expose a cgroup equivalent on the peer socket. This is
    // still kernel-derived and exact; executable + profile remain separate axes.
    format!("uid:{uid}")
}

fn listener(path: &Path) -> Result<UnixListener, String> {
    let mut inherited = listenfd::ListenFd::from_env();
    if inherited.len() > 1 {
        return Err("more than one inherited listener was supplied".to_owned());
    }
    if let Some(listener) = inherited
        .take_unix_listener(0)
        .map_err(|error| format!("take inherited listener: {error}"))?
    {
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("configure inherited listener: {error}"))?;
        return UnixListener::from_std(listener)
            .map_err(|error| format!("adopt inherited listener: {error}"));
    }

    if !path.is_absolute() {
        return Err("socket path must be absolute".to_owned());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create socket directory: {error}"))?;
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|error| format!("inspect socket directory: {error}"))?;
        if metadata.file_type().is_symlink() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err("socket directory must be a broker-owned real directory".to_owned());
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == nix::unistd::geteuid().as_raw() =>
        {
            std::fs::remove_file(path).map_err(|error| format!("remove stale socket: {error}"))?;
        }
        Ok(_) => {
            return Err("socket destination is not a broker-owned stale socket".to_owned());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect socket destination: {error}")),
    }
    let listener = UnixListener::bind(path).map_err(|error| format!("bind IPC socket: {error}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|error| format!("set IPC socket mode: {error}"))?;
    Ok(listener)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
