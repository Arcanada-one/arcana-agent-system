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
"#,
        executable = executable.display(),
    );
    std::fs::write(path, body).expect("write policy");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).expect("policy mode");
    (uid, session)
}

fn start_broker(dir: &TempDir) -> (BrokerGuard, PathBuf) {
    let policy = dir.path().join("policy.toml");
    let _ = write_policy(&policy);
    let socket = dir.path().join("broker.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_arcana-credential-broker"))
        .args([
            "--mock-provider",
            "--policy",
            policy.to_str().expect("policy path"),
            "--socket",
            socket.to_str().expect("socket path"),
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
        "quota_units": 1,
        "expires_at": now + 60,
        "idempotency": idempotency,
        "payload": {"messages": [{"role": "user", "content": "hello"}]}
    })
}

#[test]
fn permissioned_ipc_attests_peer_and_replays_without_second_provider_call() {
    let dir = TempDir::new().expect("tempdir");
    let (_broker, socket) = start_broker(&dir);
    assert_eq!(
        std::fs::metadata(&socket)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o660
    );

    let first = request(&socket, &valid_request("ipc-idem-1"));
    assert_eq!(first["ok"], true);
    assert_eq!(first["replayed"], false);
    assert_eq!(first["body"]["provider_calls"], 1);

    let replay = request(&socket, &valid_request("ipc-idem-1"));
    assert_eq!(replay["ok"], true);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["body"]["provider_calls"], 1);
    assert_eq!(replay["outcome_id"], first["outcome_id"]);
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
