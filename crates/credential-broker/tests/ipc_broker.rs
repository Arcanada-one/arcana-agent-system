//! Live local-IPC broker contract with kernel-attested peer identity (V-AC-3/7).

#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tempfile::TempDir;

struct BrokerGuard(Child);

impl Drop for BrokerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
fn session_for(pid: u32, uid: u32) -> String {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
    cgroup
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .flat_map(|path| path.split('/').rev())
        .find(|component| !component.is_empty())
        .map_or_else(|| format!("uid:{uid}"), ToOwned::to_owned)
}

#[cfg(target_os = "macos")]
fn session_for(_pid: u32, uid: u32) -> String {
    format!("uid:{uid}")
}

#[cfg(target_os = "linux")]
fn peer_executable(pid: u32) -> PathBuf {
    std::fs::read_link(format!("/proc/{pid}/exe")).expect("peer exe")
}

#[cfg(target_os = "macos")]
fn peer_executable(_pid: u32) -> PathBuf {
    std::fs::canonicalize(std::env::current_exe().expect("current exe")).expect("canonical exe")
}

fn write_policy(path: &Path) -> (u32, String) {
    let uid = nix::unistd::geteuid().as_raw();
    let pid = std::process::id();
    let executable = peer_executable(pid);
    let session = session_for(pid, uid);
    let body = format!(
        r#"generation = 7
executor_uid = {uid}
quota_limit = 10
executables = [{executable:?}]
profiles = ["supervised-executor"]
sessions = [{session:?}]

[providers.mockprovider]
upstream = "https://api.example-provider.test/v1"
models = ["model-small"]
operations = ["completion", "list_models"]
quota_costs = {{ completion = 1, list_models = 1 }}
"#,
        executable = executable.display(),
    );
    std::fs::write(path, body).expect("write policy");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).expect("policy mode");
    (uid, session)
}

fn start_broker(dir: &TempDir) -> (BrokerGuard, PathBuf) {
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private broker socket directory");
    let policy = dir.path().join("policy.toml");
    let _ = write_policy(&policy);
    let socket = dir.path().join("broker.sock");
    if socket.exists() {
        std::fs::remove_file(&socket).expect("remove stale test socket");
    }
    let state = dir.path().join("state/broker-state.json");
    let audit = dir.path().join("state/audit.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_arcana-credential-broker"))
        .args([
            "--mock-provider",
            "--policy",
            policy.to_str().expect("policy path"),
            "--socket",
            socket.to_str().expect("socket path"),
            "--state",
            state.to_str().expect("state path"),
            "--audit",
            audit.to_str().expect("audit path"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn broker");
    for _ in 0..100 {
        if socket.exists() {
            return (BrokerGuard(child), socket);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("broker socket did not appear");
}

fn request(socket: &Path, value: &Value) -> Value {
    let mut stream = UnixStream::connect(socket).expect("connect");
    serde_json::to_writer(&mut stream, value).expect("write json");
    stream.write_all(b"\n").expect("write newline");
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .expect("read response");
    serde_json::from_str(&line).expect("response json")
}

fn valid_request(idempotency: &str) -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    json!({
        "profile": "supervised-executor",
        "generation": 7,
        "provider": "mockprovider",
        "model": "model-small",
        "operation": "completion",
        "upstream": "https://api.example-provider.test/v1",
        "expires_at": now + 60,
        "idempotency": idempotency,
        "payload": {"messages": [{"role": "user", "content": "hello"}]}
    })
}

#[test]
fn permissioned_ipc_attests_peer_and_replays_without_second_provider_call() {
    let dir = TempDir::new().expect("tempdir");
    let (broker, socket) = start_broker(&dir);
    let expected_mode = if cfg!(target_os = "macos") {
        0o666
    } else {
        0o660
    };
    assert_eq!(
        std::fs::metadata(&socket)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777,
        expected_mode
    );

    let retry_request = valid_request("ipc-idem-1");
    let first = request(&socket, &retry_request);
    assert_eq!(first["ok"], true);
    assert_eq!(first["replayed"], false);
    assert_eq!(first["body"]["provider_calls"], 1);

    let replay = request(&socket, &retry_request);
    assert_eq!(replay["ok"], true);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["body"]["provider_calls"], 1);
    assert_eq!(replay["outcome_id"], first["outcome_id"]);
    drop(broker);
    let audit =
        std::fs::read_to_string(dir.path().join("state/audit.log")).expect("read terminal audit");
    assert!(audit.contains("event=provider_response_success"));
    assert!(audit.contains("status=200"));
    assert!(audit.contains("event=replay_served"));
    assert!(!audit.contains("event=replay_pending"));
}

#[test]
fn idempotent_response_survives_broker_restart_without_second_provider_call() {
    let dir = TempDir::new().expect("tempdir");
    let (broker, socket) = start_broker(&dir);
    let retry_request = valid_request("restart-idem-1");
    let first = request(&socket, &retry_request);
    assert_eq!(first["body"]["provider_calls"], 1);
    drop(broker);

    let (_restarted, socket) = start_broker(&dir);
    let replay = request(&socket, &retry_request);
    assert_eq!(replay["ok"], true);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["body"]["provider_calls"], 1);
    assert_eq!(replay["outcome_id"], first["outcome_id"]);
}

#[test]
fn committed_reservation_without_cached_outcome_audits_replay_pending() {
    let dir = TempDir::new().expect("tempdir");
    let (broker, socket) = start_broker(&dir);
    let retry_request = valid_request("pending-idem-1");
    assert_eq!(request(&socket, &retry_request)["ok"], true);
    drop(broker);

    let state = dir.path().join("state/broker-state.json");
    let mut encoded: Value =
        serde_json::from_slice(&std::fs::read(&state).expect("read durable state"))
            .expect("parse durable state");
    encoded["cached"] = serde_json::json!({});
    std::fs::write(
        &state,
        serde_json::to_vec(&encoded).expect("serialize pending state"),
    )
    .expect("write pending state");

    let (_restarted, socket) = start_broker(&dir);
    let pending = request(&socket, &retry_request);
    assert_eq!(pending["ok"], false);
    assert_eq!(pending["code"], "in_progress");
    assert!(pending["outcome_id"].is_string());
    let audit =
        std::fs::read_to_string(dir.path().join("state/audit.log")).expect("read terminal audit");
    assert!(audit.contains("event=replay_pending"));
}

#[test]
fn committed_cache_without_matching_outcome_id_fails_closed_on_restart() {
    let dir = TempDir::new().expect("tempdir");
    let (broker, socket) = start_broker(&dir);
    let first = request(&socket, &valid_request("corrupt-outcome-1"));
    assert_eq!(first["ok"], true);
    drop(broker);

    let state = dir.path().join("state/broker-state.json");
    let mut encoded: Value =
        serde_json::from_slice(&std::fs::read(&state).expect("read durable state"))
            .expect("parse durable state");
    let cached = encoded["cached"]
        .as_object_mut()
        .and_then(|entries| entries.values_mut().next())
        .expect("cached response");
    cached["outcome_id"] = Value::Null;
    std::fs::write(
        &state,
        serde_json::to_vec(&encoded).expect("serialize corrupted state"),
    )
    .expect("write corrupted state");

    let policy = dir.path().join("policy.toml");
    let socket = dir.path().join("broker.sock");
    if socket.exists() {
        std::fs::remove_file(&socket).expect("remove stale socket");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_arcana-credential-broker"))
        .args([
            "--mock-provider",
            "--policy",
            policy.to_str().expect("policy path"),
            "--socket",
            socket.to_str().expect("socket path"),
            "--state",
            state.to_str().expect("state path"),
            "--audit",
            dir.path()
                .join("state/audit.log")
                .to_str()
                .expect("audit path"),
        ])
        .output()
        .expect("restart broker");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("durable response cache is inconsistent with the ledger"));
}

#[test]
fn reused_idempotency_key_with_changed_payload_is_denied() {
    let dir = TempDir::new().expect("tempdir");
    let (_broker, socket) = start_broker(&dir);
    let original = valid_request("conflict-idem-1");
    let first = request(&socket, &original);
    assert_eq!(first["ok"], true);

    let mut changed = original;
    changed["payload"]["messages"][0]["content"] = json!("different");
    let conflict = request(&socket, &changed);
    assert_eq!(conflict["ok"], false);
    assert_eq!(conflict["code"], "denied");
    assert!(conflict["reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("different request")));
}

#[test]
fn credentialed_mode_refuses_sampled_stream_identity_before_reading_a_secret() {
    let dir = TempDir::new().expect("tempdir");
    let policy = dir.path().join("policy.toml");
    let _ = write_policy(&policy);
    let socket = dir.path().join("credentialed.sock");
    let credential = dir.path().join("must-not-be-read");
    let state = dir.path().join("state/broker-state.json");
    let audit = dir.path().join("state/audit.log");
    let output = Command::new(env!("CARGO_BIN_EXE_arcana-credential-broker"))
        .args([
            "--policy",
            policy.to_str().expect("policy path"),
            "--socket",
            socket.to_str().expect("socket path"),
            "--credential-source",
            credential.to_str().expect("credential path"),
            "--state",
            state.to_str().expect("state path"),
            "--audit",
            audit.to_str().expect("audit path"),
        ])
        .output()
        .expect("run broker");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("per-message attestation backend is not installed"));
    assert!(!stderr.contains("credential source is absent"));
    assert!(!socket.exists());
}

#[test]
fn self_reported_peer_fields_and_wrong_scope_fail_closed() {
    let dir = TempDir::new().expect("tempdir");
    let (_broker, socket) = start_broker(&dir);
    let mut forged = valid_request("forged");
    forged["peer_uid"] = json!(0);
    let response = request(&socket, &forged);
    assert_eq!(response["ok"], false);
    assert_eq!(response["code"], "invalid_request");

    let mut wrong_model = valid_request("wrong-model");
    wrong_model["model"] = json!("unapproved-model");
    let response = request(&socket, &wrong_model);
    assert_eq!(response["ok"], false);
    assert_eq!(response["code"], "denied");
}
