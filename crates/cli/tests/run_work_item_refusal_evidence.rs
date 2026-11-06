//! KCLIVE-11 refusal path, driven through the real `arcana` binary.
//!
//! Each case names what it counts: Muneral requests come from the mock server's
//! own record, "no model call" is `ARCANA_MC_TOKEN` absent from stderr (the model
//! client is never built) plus an empty working directory and no `receipts/`.
//! When `KCLIVE11_EVIDENCE_DIR` is set each case also retains its stdout, stderr
//! and request counts there as non-secret evidence. All bytes are synthetic: no
//! live Muneral, Argana, Auth or Model Connector is contacted.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arcana_core::contract::digest_of;
use assert_cmd::Command;
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TASK: &str = "7c1f2a40-6d1e-4b57-9b0a-3f5d8f1e2a11";
const BYTES: &str = r#"{"role":"reviewer"}{"revisions":[]}"#;
const BYTES_B64: &str = "eyJyb2xlIjoicmV2aWV3ZXIifXsicmV2aXNpb25zIjpbXX0=";

struct Seen {
    stdout: String,
    stderr: String,
    failed: bool,
    readiness_requests: usize,
    work_entries: usize,
    receipts: bool,
}

impl Seen {
    fn refused_with(&self, code: &str) {
        assert!(self.failed, "must refuse: {}", self.stdout);
        let line = self.stderr.lines().find(|l| l.starts_with("arcana run:"));
        assert!(
            line.is_some_and(|l| l.starts_with(&format!("arcana run: {code}:"))),
            "expected {code}: {}",
            self.stderr
        );
        assert!(self.stdout.contains(&format!("\"code\":\"{code}\"")));
        // Nothing downstream of the gate happened.
        assert!(!self.stderr.contains("ARCANA_MC_TOKEN"));
        assert!(!self.stdout.contains("\"completed\":true"));
        assert_eq!(self.work_entries, 0);
        assert!(!self.receipts);
    }
}

async fn run_case(name: &str, document: Value) -> Seen {
    let server = MockServer::start().await;
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let inputs = TempDir::new().unwrap();
    let key = inputs.path().join("muneral.key");
    std::fs::write(&key, "mun_sk_fixture_only\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let contract_file = inputs.path().join("contract.json");
    std::fs::write(&contract_file, document.to_string()).unwrap();
    let row = json!({"id": TASK, "projectId": "fixture-project", "title": "fixture",
        "contractDigest": digest_of(BYTES.as_bytes())});
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(row))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}/readiness")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {"taskId": TASK, "ready": true, "dependencyCount": 0, "blockedBy": []}
        )))
        .mount(&server)
        .await;
    let output = Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", &key)
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--work-item", TASK, "--contract-file"])
        .arg(&contract_file)
        .output()
        .unwrap();
    let readiness_requests = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/readiness"))
        .count();
    let seen = Seen {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        failed: !output.status.success(),
        readiness_requests,
        work_entries: std::fs::read_dir(work.path()).unwrap().count(),
        receipts: work.path().join("receipts").exists(),
    };
    if let Ok(dir) = std::env::var("KCLIVE11_EVIDENCE_DIR") {
        let dir = std::path::Path::new(&dir).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stdout.txt"), &seen.stdout).unwrap();
        std::fs::write(dir.join("stderr.txt"), &seen.stderr).unwrap();
        std::fs::write(dir.join("contract-document.json"), document.to_string()).unwrap();
        std::fs::write(
            dir.join("observed.json"),
            json!({"exit_failure": seen.failed, "readiness_requests": seen.readiness_requests,
                   "work_dir_entries": seen.work_entries, "receipts_dir": seen.receipts,
                   "synthetic": true})
            .to_string(),
        )
        .unwrap();
    }
    seen
}

fn argana_shaped() -> Value {
    json!({
        "digest": digest_of(BYTES.as_bytes()),
        "projection": {"body": {"role": "reviewer"}, "closure_manifest": {"revisions": []}},
        "canonical": {"bytes_b64": BYTES_B64, "length": BYTES.len()},
    })
}

#[tokio::test]
async fn real_shaped_contract_stops_at_the_authority_gate_with_the_honest_code() {
    let seen = run_case("authority-unavailable", argana_shaped()).await;
    seen.refused_with("CONTRACT_AUTHORITY_UNAVAILABLE");
    // Binding and readiness ran; authority is the first thing that stopped it.
    assert_eq!(seen.readiness_requests, 1);
    assert!(
        seen.stdout.contains("derived-from-canonical-bytes"),
        "{}",
        seen.stdout
    );
}

#[tokio::test]
async fn same_bytes_with_a_swapped_projection_stops_before_readiness() {
    let mut doc = argana_shaped();
    doc["projection"] =
        json!({"body": {"role": "deployer"}, "closure_manifest": {"revisions": []}});
    let seen = run_case("policy-unbound-projection", doc).await;
    seen.refused_with("CONTRACT_POLICY_UNBOUND");
    assert_eq!(seen.readiness_requests, 0);
}

#[tokio::test]
async fn same_bytes_with_a_widened_tool_list_stops_before_readiness() {
    let mut doc = argana_shaped();
    doc["tools"] = json!({"allow": ["read", "write", "bash"]});
    let seen = run_case("policy-unbound-tools", doc).await;
    seen.refused_with("CONTRACT_POLICY_UNBOUND");
    assert_eq!(seen.readiness_requests, 0);
}

#[tokio::test]
async fn corrupt_contract_bytes_stop_before_readiness() {
    let mut doc = argana_shaped();
    doc["canonical"]["bytes_b64"] = json!("!!! not base64 !!!");
    let seen = run_case("corrupt-bytes", doc).await;
    seen.refused_with("CONTRACT_UNVERIFIABLE");
    assert_eq!(seen.readiness_requests, 0);
}
