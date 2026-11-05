//! `arcana run --work-item` asks Muneral for dependency readiness after the
//! contract binding is verified and before the authority gate.
//!
//! Every case counts what it claims. The readiness request count is read from
//! the mock server's own record of received requests (a missing log line is not
//! proof of zero calls). The Model Connector is never configured:
//! `ARCANA_MC_TOKEN` is absent, so constructing the model client would put
//! `ARCANA_MC_TOKEN` on stderr; its absence there, an empty working directory
//! and no `receipts/` are the counters for "zero model calls and no executor
//! continuation". The authority gate is the continuation boundary: a run that
//! reached it prints `CONTRACT_AUTHORITY_UNAVAILABLE`, a run refused earlier
//! does not.
//!
//! No case calls the live Muneral API.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arcana_core::contract::digest_of;
use assert_cmd::Command;
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TASK: &str = "7c1f2a40-6d1e-4b57-9b0a-3f5d8f1e2a11";
const OTHER: &str = "0d9d5e2e-1a2b-4c3d-8e4f-5a6b7c8d9e0f";
const PROJECTION: &str = "Role: reviewer. Deliverable: one review note.";

const AUTHORITY: &str = "CONTRACT_AUTHORITY_UNAVAILABLE";
const NOT_READY: &str = "WORK_ITEM_NOT_READY";
const UNKNOWN: &str = "WORK_ITEM_READINESS_UNKNOWN";

fn readiness_body(task: &str, ready: bool, dependencies: u64, blocked: usize) -> Value {
    json!({
        "taskId": task, "ready": ready, "dependencyCount": dependencies,
        "blockedBy": vec![json!({"id": "dep"}); blocked],
    })
}

/// What the run did, as seen from outside.
struct Observed {
    stderr: String,
    stdout: String,
    exit_failure: bool,
    readiness_requests: usize,
    task_requests: usize,
    work_dir_entries: usize,
    receipts_dir: bool,
}

impl Observed {
    /// The executor continuation (and therefore the model client) was never
    /// reached: no connector token error, no receipt, nothing written.
    fn assert_no_model_and_no_continuation(&self) {
        assert!(self.exit_failure, "must refuse; stdout: {}", self.stdout);
        assert!(!self.stderr.contains("ARCANA_MC_TOKEN"), "{}", self.stderr);
        assert!(!self.stdout.contains("\"completed\":true"));
        assert_eq!(self.work_dir_entries, 0);
        assert!(!self.receipts_dir);
    }

    fn refused_with(&self, code: &str) {
        let first = self.stderr.lines().find(|l| l.starts_with("arcana run:"));
        assert!(
            first.is_some_and(|l| l.starts_with(&format!("arcana run: {code}:"))),
            "expected {code}, stderr: {}",
            self.stderr
        );
        assert!(
            self.stdout.contains(&format!("\"code\":\"{code}\"")),
            "marker for {code}, stdout: {}",
            self.stdout
        );
    }

    fn reached_authority(&self) {
        self.refused_with(AUTHORITY);
    }

    fn stopped_before_authority(&self) {
        assert!(!self.stderr.contains(AUTHORITY), "{}", self.stderr);
    }
}

enum Contract {
    Valid,
    Missing,
    Mismatch,
}

async fn run_case(contract: Contract, readiness: ResponseTemplate) -> Observed {
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
    let digest = digest_of(PROJECTION.as_bytes());
    let contract_file = inputs.path().join("contract.json");
    let (named, document) = match contract {
        Contract::Valid => (
            Some(digest.clone()),
            json!({"digest": digest, "projection": PROJECTION}),
        ),
        Contract::Missing => (None, json!({"digest": digest, "projection": PROJECTION})),
        Contract::Mismatch => (
            Some(digest.clone()),
            json!({"digest": digest, "projection": "Role: deployer."}),
        ),
    };
    std::fs::write(&contract_file, document.to_string()).unwrap();
    // Deliberately no `dependencies` field: the task row is not readiness.
    let mut row = json!({"id": TASK, "projectId": "fixture-project", "title": "fixture"});
    if let Some(named) = named {
        row["contractDigest"] = json!(named);
    }
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(row))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}/readiness")))
        .respond_with(readiness)
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

    let requests = server.received_requests().await.unwrap();
    let count = |suffix: &str| {
        requests
            .iter()
            .filter(|r| r.url.path() == format!("/api/v1/tasks/{TASK}{suffix}"))
            .count()
    };
    Observed {
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        exit_failure: !output.status.success(),
        readiness_requests: count("/readiness"),
        task_requests: count(""),
        work_dir_entries: std::fs::read_dir(work.path()).unwrap().count(),
        receipts_dir: work.path().join("receipts").exists(),
    }
}

fn json_200(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

// ---- precedence: contract refusals come first and cost zero readiness requests

#[tokio::test]
async fn a_missing_contract_digest_keeps_its_precedence_and_asks_no_readiness() {
    let seen = run_case(
        Contract::Missing,
        json_200(readiness_body(TASK, false, 1, 1)),
    )
    .await;
    seen.refused_with("CONTRACT_MISSING");
    assert_eq!(seen.task_requests, 1);
    assert_eq!(seen.readiness_requests, 0);
    seen.assert_no_model_and_no_continuation();
}

#[tokio::test]
async fn a_digest_mismatch_keeps_its_precedence_and_asks_no_readiness() {
    let seen = run_case(
        Contract::Mismatch,
        json_200(readiness_body(TASK, false, 1, 1)),
    )
    .await;
    seen.refused_with("CONTRACT_DIGEST_MISMATCH");
    assert_eq!(seen.readiness_requests, 0);
    seen.assert_no_model_and_no_continuation();
}

// ---- the verdict

#[tokio::test]
async fn not_ready_is_refused_with_its_own_code_before_the_authority_gate() {
    let seen = run_case(Contract::Valid, json_200(readiness_body(TASK, false, 2, 1))).await;
    seen.refused_with(NOT_READY);
    assert_eq!(seen.readiness_requests, 1);
    seen.stopped_before_authority();
    seen.assert_no_model_and_no_continuation();
    assert!(seen.stderr.contains("1 of 2"), "{}", seen.stderr);
}

#[tokio::test]
async fn ready_with_zero_dependencies_continues_to_the_authority_gate() {
    let seen = run_case(Contract::Valid, json_200(readiness_body(TASK, true, 0, 0))).await;
    assert_eq!(seen.readiness_requests, 1);
    seen.reached_authority();
    seen.assert_no_model_and_no_continuation();
    assert!(seen
        .stdout
        .contains("readiness: ready=true dependencies=0 blocked_by=0"));
}

#[tokio::test]
async fn ready_with_fulfilled_dependencies_keeps_the_count_and_reaches_the_gate() {
    let seen = run_case(Contract::Valid, json_200(readiness_body(TASK, true, 3, 0))).await;
    assert_eq!(seen.readiness_requests, 1);
    seen.reached_authority();
    seen.assert_no_model_and_no_continuation();
    // Fulfilled is not absent: the count survives into the evidence.
    assert!(seen
        .stdout
        .contains("readiness: ready=true dependencies=3 blocked_by=0"));
}

// ---- unknown readiness is never readiness

async fn unknown(template: ResponseTemplate) {
    let seen = run_case(Contract::Valid, template).await;
    seen.refused_with(UNKNOWN);
    assert_eq!(seen.readiness_requests, 1);
    seen.stopped_before_authority();
    seen.assert_no_model_and_no_continuation();
}

#[tokio::test]
async fn every_non_200_status_is_unknown_readiness() {
    for status in [401_u16, 403, 404, 500, 503] {
        unknown(ResponseTemplate::new(status).set_body_string("{}")).await;
    }
}

#[tokio::test]
async fn forbidden_is_not_an_empty_graph() {
    let seen = run_case(
        Contract::Valid,
        ResponseTemplate::new(403).set_body_json(json!({"message": "not assigned"})),
    )
    .await;
    seen.refused_with(UNKNOWN);
    assert!(seen.stderr.contains("403"), "{}", seen.stderr);
    seen.stopped_before_authority();
}

#[tokio::test]
async fn a_201_with_a_plausible_verdict_is_not_evidence_of_readiness() {
    unknown(ResponseTemplate::new(201).set_body_json(readiness_body(TASK, true, 0, 0))).await;
}

#[tokio::test]
async fn a_204_is_not_evidence_of_readiness() {
    unknown(ResponseTemplate::new(204)).await;
}

#[tokio::test]
async fn incomplete_malformed_and_foreign_answers_are_unknown() {
    unknown(ResponseTemplate::new(200).set_body_json(json!({"taskId": TASK, "ready": true}))).await;
    unknown(
        ResponseTemplate::new(200)
            .set_body_json(json!({"ready": true, "dependencyCount": 0, "blockedBy": []})),
    )
    .await;
    unknown(ResponseTemplate::new(200).set_body_string("{\"taskId\":")).await;
    unknown(ResponseTemplate::new(200).set_body_string("")).await;
    unknown(ResponseTemplate::new(200).set_body_json(readiness_body(OTHER, true, 0, 0))).await;
}

#[tokio::test]
async fn a_verdict_that_contradicts_itself_is_unknown() {
    unknown(ResponseTemplate::new(200).set_body_json(readiness_body(TASK, true, 1, 1))).await;
    unknown(ResponseTemplate::new(200).set_body_json(readiness_body(TASK, false, 0, 1))).await;
    unknown(ResponseTemplate::new(200).set_body_json(readiness_body(TASK, false, 2, 0))).await;
}

/// The real timeout (the client's request budget is 30 s): run with `cargo test -p arcana-cli --test
/// run_work_item_readiness -- --ignored`. Takes ~30 s.
#[tokio::test]
#[ignore = "waits out the 30 s request budget"]
async fn a_readiness_timeout_is_unknown_not_ready() {
    unknown(
        ResponseTemplate::new(200)
            .set_body_json(readiness_body(TASK, true, 0, 0))
            .set_delay(std::time::Duration::from_secs(35)),
    )
    .await;
}
