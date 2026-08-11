//! Permissioned local IPC and scoped provider adapter.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arcana_credential_broker::audit::{AuditRecord, AuditWriter, CausalIds, EventKind};
use arcana_credential_broker::{
    authorize, CapabilityPolicy, CapabilityRequest, ExecutorProfile, Generation, IdempotencyKey,
    Ledger, Operation, PeerIdentity, RequestFingerprint, SessionId,
};
use arcana_execution_boundary::{QuarantineScanner, ScannerConfig, Stream};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore};

const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

/// Secret wrapper with no `Debug`, `Display`, serialization, or clone surface.
pub struct Credential {
    value: SecretBox<String>,
    exposed_len: usize,
}

impl Credential {
    pub(super) fn new(value: String, exposed_len: usize) -> Self {
        Self {
            value: SecretBox::new(Box::new(value)),
            exposed_len,
        }
    }

    pub(super) fn expose(&self) -> &str {
        &self.value.expose_secret()[..self.exposed_len]
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
    pub state_file: PathBuf,
    pub audit: AuditWriter,
}

struct State {
    policy: CapabilityPolicy,
    durable: Mutex<DurableState>,
    durable_path: PathBuf,
    audit: Mutex<AuditWriter>,
    adapter: Adapter,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableState {
    ledger: Ledger,
    cached: BTreeMap<IdempotencyKey, WireResponse>,
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

#[derive(Debug, thiserror::Error)]
enum AdapterFailure {
    #[error("{0}")]
    RequestRejected(String),
    #[error("{0}")]
    OutcomeUnknown(String),
    #[error("provider output quarantine rejected the response")]
    OutputQuarantined,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    profile: ExecutorProfile,
    generation: Generation,
    provider: String,
    model: String,
    operation: Operation,
    upstream: String,
    expires_at: u64,
    idempotency: IdempotencyKey,
    #[serde(default)]
    payload: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct WireResponse {
    ok: bool,
    code: String,
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
    fn error(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: code.into(),
            outcome_id: None,
            replayed: false,
            status: None,
            body: None,
            reason: Some(reason.into()),
        }
    }

    fn leased_error(code: impl Into<String>, reason: impl Into<String>, outcome_id: &str) -> Self {
        let mut response = Self::error(code, reason);
        response.outcome_id = Some(outcome_id.to_owned());
        response
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
        durable: Mutex::new(load_state(&config.state_file, generation, quota)?),
        durable_path: config.state_file,
        audit: Mutex::new(config.audit),
        adapter,
    });
    let permits = Arc::new(Semaphore::new(config.max_connections));

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("accept IPC connection: {error}"))?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            // Refuse without creating another task: overload must remain
            // bounded by `max_connections` rather than allocating one delayed
            // writer per rejected peer.
            drop(stream);
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
    let fingerprint = match fingerprint_request(&request, &peer) {
        Ok(fingerprint) => fingerprint,
        Err(error) => return WireResponse::error("invalid_request", error),
    };
    let quota_units = state
        .policy
        .quota_cost(&request.provider, request.operation)
        .unwrap_or(0);
    let capability = CapabilityRequest {
        peer,
        profile: request.profile,
        generation: request.generation,
        provider: request.provider,
        model: request.model,
        operation: request.operation,
        upstream: request.upstream,
        quota_units,
        expires_at: request.expires_at,
        idempotency: request.idempotency.clone(),
        fingerprint,
    };
    let authorization = {
        let mut durable = state.durable.lock().await;
        match authorize(&state.policy, &mut durable.ledger, &capability, now_unix()) {
            Ok(lease) => {
                if !lease.replayed {
                    if let Err(error) = persist_state(&state.durable_path, &durable) {
                        return WireResponse::error("state_failure", error);
                    }
                }
                Ok(lease)
            }
            Err(denial) => Err(denial),
        }
    };
    let lease = match authorization {
        Ok(lease) => lease,
        Err(denial) => {
            if let Err(error) = audit_denial(state, &capability, denial.clone()).await {
                return WireResponse::error("audit_failure", error);
            }
            return WireResponse::error("denied", denial.to_string());
        }
    };
    if let Err(error) = audit_authorized(state, &capability, &lease).await {
        return WireResponse::leased_error("audit_failure", error, &lease.outcome_id);
    }

    if lease.replayed {
        let prior = {
            let durable = state.durable.lock().await;
            durable.cached.get(&request.idempotency).cloned()
        };
        let replay_kind = if prior.is_some() {
            EventKind::ReplayServed
        } else {
            EventKind::ReplayPending
        };
        if let Err(error) = audit_replay(state, &capability, &lease, replay_kind).await {
            return WireResponse::leased_error("audit_failure", error, &lease.outcome_id);
        }
        if let Some(mut replay) = prior {
            replay.replayed = true;
            return replay;
        }
        return WireResponse::leased_error(
            "in_progress",
            "the idempotent operation is committed but its outcome is not ready",
            &lease.outcome_id,
        );
    }

    let response = perform_provider_call(state, &capability, &lease, request.payload).await;
    if response.outcome_id.as_deref() != Some(lease.outcome_id.as_str()) {
        return WireResponse::error(
            "state_failure",
            "provider outcome is missing its durable identity",
        );
    }
    {
        let mut durable = state.durable.lock().await;
        if durable.cached.len() >= 4096 {
            return WireResponse::error(
                "state_capacity",
                "idempotency response capacity is exhausted",
            );
        }
        durable.cached.insert(request.idempotency, response.clone());
        if let Err(error) = persist_state(&state.durable_path, &durable) {
            // The provider may already have observed the request. The pending
            // reservation was persisted first, so a restart refuses to repeat
            // it; do not claim a replayable response when the second sync fails.
            return WireResponse::error("state_failure", error);
        }
    }
    response
}

async fn perform_provider_call(
    state: &State,
    capability: &CapabilityRequest,
    lease: &arcana_credential_broker::Lease,
    payload: Value,
) -> WireResponse {
    match state.adapter.call(capability, payload).await {
        Ok((status, body)) => {
            let byte_count = serde_json::to_vec(&body).map_or(0, |bytes| bytes.len());
            if let Err(error) = audit_output(state, capability, lease, true, byte_count).await {
                return WireResponse::leased_error("audit_failure", error, &lease.outcome_id);
            }
            if let Err(error) = audit_provider_response(state, capability, lease, status).await {
                return WireResponse::leased_error("audit_failure", error, &lease.outcome_id);
            }
            WireResponse {
                ok: (200..300).contains(&status),
                code: if (200..300).contains(&status) {
                    "ok".to_owned()
                } else {
                    "upstream_status".to_owned()
                },
                outcome_id: Some(lease.outcome_id.clone()),
                replayed: false,
                status: Some(status),
                body: Some(body),
                reason: None,
            }
        }
        Err(AdapterFailure::OutputQuarantined) => {
            if let Err(error) = audit_output(state, capability, lease, false, 0).await {
                return WireResponse::leased_error("audit_failure", error, &lease.outcome_id);
            }
            WireResponse {
                ok: false,
                code: "output_quarantined".to_owned(),
                outcome_id: Some(lease.outcome_id.clone()),
                replayed: false,
                status: None,
                body: None,
                reason: Some("provider output quarantine rejected the response".to_owned()),
            }
        }
        Err(failure @ (AdapterFailure::RequestRejected(_) | AdapterFailure::OutcomeUnknown(_))) => {
            if let Err(error) = audit_provider_failure(state, capability, lease, &failure).await {
                return WireResponse::leased_error("audit_failure", error, &lease.outcome_id);
            }
            WireResponse {
                ok: false,
                code: "upstream_failure".to_owned(),
                outcome_id: Some(lease.outcome_id.clone()),
                replayed: false,
                status: None,
                body: None,
                reason: Some(failure.to_string()),
            }
        }
    }
}

async fn audit_denial(
    state: &State,
    request: &CapabilityRequest,
    denial: arcana_credential_broker::Denial,
) -> Result<(), String> {
    let mut record = audit_record(EventKind::PolicyDeny, request);
    // Provider and model are caller claims until policy authorization succeeds.
    // A denied peer can put secret-shaped bytes in either field, so denial
    // audit records retain only broker-attested identity and closed metadata.
    record.provider = None;
    record.model = None;
    record.denial = Some(denial);
    state
        .audit
        .lock()
        .await
        .append(&record)
        .map_err(|error| error.to_string())
}

async fn audit_authorized(
    state: &State,
    request: &CapabilityRequest,
    lease: &arcana_credential_broker::Lease,
) -> Result<(), String> {
    let mut audit = state.audit.lock().await;
    let mut allowed = audit_record(EventKind::PolicyAllow, request);
    allowed.ids.lease = Some(lease.outcome_id.clone());
    audit.append(&allowed).map_err(|error| error.to_string())?;
    if lease.replayed {
        return Ok(());
    }
    let mut charge = audit_record(EventKind::QuotaCharge, request);
    charge.ids.lease = Some(lease.outcome_id.clone());
    charge.charged = Some(lease.charged);
    audit.append(&charge).map_err(|error| error.to_string())
}

async fn audit_replay(
    state: &State,
    request: &CapabilityRequest,
    lease: &arcana_credential_broker::Lease,
    kind: EventKind,
) -> Result<(), String> {
    let mut record = audit_record(kind, request);
    record.ids.lease = Some(lease.outcome_id.clone());
    state
        .audit
        .lock()
        .await
        .append(&record)
        .map_err(|error| error.to_string())
}

fn audit_record(kind: EventKind, request: &CapabilityRequest) -> AuditRecord {
    let mut record = AuditRecord::new(now_unix(), kind);
    record.ids = CausalIds {
        process_tree: Some(request.peer.pid.to_string()),
        pane_session: Some(request.peer.session.0.clone()),
        generation: Some(request.generation),
        ..CausalIds::default()
    };
    record.provider = Some(request.provider.clone());
    record.model = Some(request.model.clone());
    record.operation = Some(request.operation);
    record
}

async fn audit_output(
    state: &State,
    request: &CapabilityRequest,
    lease: &arcana_credential_broker::Lease,
    passed: bool,
    byte_count: usize,
) -> Result<(), String> {
    let mut record = audit_record(
        if passed {
            EventKind::OutputScanPass
        } else {
            EventKind::OutputScanBlock
        },
        request,
    );
    record.ids.lease = Some(lease.outcome_id.clone());
    record.count = Some(u64::try_from(byte_count).unwrap_or(u64::MAX));
    state
        .audit
        .lock()
        .await
        .append(&record)
        .map_err(|error| error.to_string())
}

async fn audit_provider_failure(
    state: &State,
    request: &CapabilityRequest,
    lease: &arcana_credential_broker::Lease,
    failure: &AdapterFailure,
) -> Result<(), String> {
    let kind = match failure {
        AdapterFailure::RequestRejected(_) => EventKind::ProviderRequestRejected,
        AdapterFailure::OutcomeUnknown(_) => EventKind::ProviderOutcomeUnknown,
        AdapterFailure::OutputQuarantined => EventKind::OutputScanBlock,
    };
    let mut record = audit_record(kind, request);
    record.ids.lease = Some(lease.outcome_id.clone());
    state
        .audit
        .lock()
        .await
        .append(&record)
        .map_err(|error| error.to_string())
}

async fn audit_provider_response(
    state: &State,
    request: &CapabilityRequest,
    lease: &arcana_credential_broker::Lease,
    status: u16,
) -> Result<(), String> {
    let mut record = audit_record(
        if (200..300).contains(&status) {
            EventKind::ProviderResponseSuccess
        } else {
            EventKind::ProviderResponseError
        },
        request,
    );
    record.ids.lease = Some(lease.outcome_id.clone());
    record.status = Some(status);
    state
        .audit
        .lock()
        .await
        .append(&record)
        .map_err(|error| error.to_string())
}

fn load_state(path: &Path, generation: Generation, quota: u32) -> Result<DurableState, String> {
    validate_state_parent(path)?;
    match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => {
            let file = std::fs::File::from(descriptor);
            validate_state_file(&file)?;
            let mut bytes = Vec::new();
            file.take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("read durable state: {error}"))?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err("durable state exceeds the size limit".to_owned());
            }
            let state: DurableState = serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse durable state: {error}"))?;
            if !state.ledger.matches_policy(generation, quota) {
                return Err("durable state generation or quota does not match policy".to_owned());
            }
            if !state.ledger.durable_invariants_hold() {
                return Err("durable ledger invariants are inconsistent".to_owned());
            }
            if state.cached.len() > state.ledger.committed_count()
                || state.cached.iter().any(|(key, response)| {
                    !matches!(
                        (state.ledger.outcome_id_for(key), response.outcome_id.as_deref()),
                        (Some(outcome), Some(cached)) if cached == outcome
                    )
                })
            {
                return Err("durable response cache is inconsistent with the ledger".to_owned());
            }
            Ok(state)
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(DurableState {
            ledger: Ledger::new(generation, quota),
            cached: BTreeMap::new(),
        }),
        Err(error) => Err(format!("read durable state: {error}")),
    }
}

fn persist_state(path: &Path, state: &DurableState) -> Result<(), String> {
    validate_state_parent(path)?;
    match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => validate_state_file(&std::fs::File::from(descriptor))?,
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(error) => return Err(format!("inspect durable state destination: {error}")),
    }
    let bytes = serde_json::to_vec(state).map_err(|error| format!("serialize state: {error}"))?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("durable state exceeds the size limit".to_owned());
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("create durable state transaction: {error}"))?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|error| format!("write durable state: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync durable state: {error}"))?;
        std::fs::rename(&temporary, path)
            .map_err(|error| format!("publish durable state: {error}"))?;
        let parent = path
            .parent()
            .ok_or_else(|| "durable state path has no parent".to_owned())?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync durable state directory: {error}"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn validate_state_file(file: &std::fs::File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect durable state: {error}"))?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err("durable state must be a broker-owned regular file with mode 0600".to_owned());
    }
    Ok(())
}

fn validate_state_parent(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("durable state path must be absolute".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "durable state path has no parent".to_owned())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create durable state directory: {error}"))?;
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect durable state directory: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err("durable state directory must be a broker-owned real directory".to_owned());
    }
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("restrict durable state directory: {error}"))?;
    Ok(())
}

fn fingerprint_request(
    request: &WireRequest,
    peer: &PeerIdentity,
) -> Result<RequestFingerprint, String> {
    use std::os::unix::ffi::OsStrExt;

    // JSON encoding is deterministic here: the tuple has a fixed field order,
    // maps inside `payload` are represented by serde_json's stable map order.
    // The executable uses raw Unix path bytes so lossy UTF-8 cannot collide.
    let encoded = serde_json::to_vec(&(
        peer.uid,
        peer.pid,
        peer.executable.as_os_str().as_bytes(),
        &peer.session,
        &request.profile,
        request.generation,
        &request.provider,
        &request.model,
        request.operation,
        &request.upstream,
        request.expires_at,
        &request.payload,
    ))
    .map_err(|error| format!("fingerprint request: {error}"))?;
    Ok(RequestFingerprint(format!("{:x}", Sha256::digest(encoded))))
}

impl Adapter {
    async fn call(
        &self,
        request: &CapabilityRequest,
        mut payload: Value,
    ) -> Result<(u16, Value), AdapterFailure> {
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
                let mut base = url::Url::parse(&request.upstream).map_err(|_| {
                    AdapterFailure::RequestRejected("policy upstream is not a valid URL".to_owned())
                })?;
                if base.scheme() != "https"
                    || !base.username().is_empty()
                    || base.password().is_some()
                    || base.query().is_some()
                    || base.fragment().is_some()
                {
                    return Err(AdapterFailure::RequestRejected(
                        "policy upstream is not a credential-safe HTTPS base".to_owned(),
                    ));
                }
                if !base.path().ends_with('/') {
                    base.set_path(&format!("{}/", base.path()));
                }
                let response = match request.operation {
                    Operation::Completion => {
                        let object = payload.as_object_mut().ok_or_else(|| {
                            AdapterFailure::RequestRejected(
                                "completion payload must be a JSON object".to_owned(),
                            )
                        })?;
                        if object
                            .get("model")
                            .is_some_and(|value| value.as_str() != Some(&request.model))
                        {
                            return Err(AdapterFailure::RequestRejected(
                                "payload model does not match authorised model".to_owned(),
                            ));
                        }
                        object.insert("model".to_owned(), Value::String(request.model.clone()));
                        let endpoint = base.join("chat/completions").map_err(|_| {
                            AdapterFailure::RequestRejected(
                                "cannot construct completion endpoint".to_owned(),
                            )
                        })?;
                        client
                            .post(endpoint)
                            .bearer_auth(credential.expose())
                            .json(&payload)
                            .send()
                            .await
                    }
                    Operation::ListModels => {
                        let endpoint = base.join("models").map_err(|_| {
                            AdapterFailure::RequestRejected(
                                "cannot construct models endpoint".to_owned(),
                            )
                        })?;
                        client
                            .get(endpoint)
                            .bearer_auth(credential.expose())
                            .send()
                            .await
                    }
                }
                .map_err(|error| {
                    AdapterFailure::OutcomeUnknown(format!("provider transport failed: {error}"))
                })?;
                let status = response.status().as_u16();
                let bytes = bounded_body(response)
                    .await
                    .map_err(AdapterFailure::OutcomeUnknown)?;
                quarantine_response(credential.expose().as_bytes(), &bytes)
                    .map_err(|_| AdapterFailure::OutputQuarantined)?;
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
        validate_inherited_listener(&listener, path)?;
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
        if cfg!(target_os = "macos") && metadata.permissions().mode() & 0o007 != 0 {
            return Err("macOS socket directory must deny all access to other users".to_owned());
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
    // Linux delegates group ownership and mode to systemd socket activation.
    // A direct macOS bind lives inside a broker-owned, executor-group-traversable
    // 0750 directory; 0666 on the socket therefore grants access only to the two
    // identities that can traverse that directory, without making the broker's
    // primary group the wider executor group.
    let mode = if cfg!(target_os = "macos") {
        0o666
    } else {
        0o660
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set IPC socket mode: {error}"))?;
    Ok(listener)
}

fn validate_inherited_listener(
    listener: &std::os::unix::net::UnixListener,
    expected_path: &Path,
) -> Result<(), String> {
    let socket_type = rustix::net::sockopt::socket_type(listener)
        .map_err(|error| format!("inspect inherited listener type: {error}"))?;
    if socket_type != rustix::net::SocketType::SEQPACKET {
        return Err("inherited listener must be SOCK_SEQPACKET".to_owned());
    }
    let address = rustix::net::getsockname(listener)
        .map_err(|error| format!("inspect inherited listener address: {error}"))?;
    let unix = rustix::net::SocketAddrUnix::try_from(address)
        .map_err(|_| "inherited listener is not an AF_UNIX socket".to_owned())?;
    let actual_path = unix
        .path()
        .map(|path| std::ffi::OsStr::from_bytes(path.to_bytes()).to_owned())
        .ok_or_else(|| "inherited listener has no filesystem path".to_owned())?;
    if Path::new(&actual_path) != expected_path {
        return Err("inherited listener path differs from configured socket".to_owned());
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::validate_inherited_listener;
    use super::WireResponse;

    #[test]
    fn post_provider_errors_retain_the_durable_outcome_identity() {
        let response = WireResponse::leased_error("audit_failure", "synthetic failure", "out-7");
        assert_eq!(response.outcome_id.as_deref(), Some("out-7"));
        assert!(!response.ok);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inherited_listener_requires_exact_seqpacket_path() {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let path = directory.path().join("broker.sock");
        let descriptor = rustix::net::socket(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            None,
        )
        .expect("create seqpacket socket");
        let address = rustix::net::SocketAddrUnix::new(&path).expect("socket address");
        rustix::net::bind(&descriptor, &address).expect("bind seqpacket socket");
        rustix::net::listen(&descriptor, 1).expect("listen");
        let listener = std::os::unix::net::UnixListener::from(descriptor);
        validate_inherited_listener(&listener, &path).expect("valid inherited listener");
        assert!(validate_inherited_listener(&listener, &directory.path().join("other")).is_err());

        let stream_path = directory.path().join("stream.sock");
        let stream = std::os::unix::net::UnixListener::bind(&stream_path).expect("stream listener");
        assert!(validate_inherited_listener(&stream, &stream_path).is_err());
    }
}
