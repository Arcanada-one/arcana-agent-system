//! A contract-bound run attaches its own receipt to its work item, and a run
//! whose receipt did not land does not exit `0`.
//!
//! NR-0016 (found by A2-332): A2-297c's second run wrote
//! `receipts/ReadinessReceipt-d931525f-….json`, exited `0`, and the receipt
//! never reached Muneral — `arcana` had no code that could put it there, and
//! the hand-made `POST` was skipped. The work item went to `done` with two of
//! its three receipts.
//!
//! Two halves:
//!
//! * [`conclude_with_evidence`] — the end of `arcana run --work-item` — driven
//!   with a REAL run summary (the production driver, cascade and tools against
//!   a scripted model, as `run_effect.rs` does) and the REAL receipt that
//!   A2-297c's run 2 wrote, byte for byte, against a mock Muneral. The run
//!   above it needs the live Model Connector, whose origin is pinned, so this
//!   is the closest an offline test gets to the call site.
//! * `arcana attach-receipt`, the binary, for the retry path and the exit
//!   codes an operator sees.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_cli::effect::EffectExpectation;
use arcana_cli::evidence::{sha256_hex, EXIT_NOT_ATTACHED};
use arcana_cli::run::{assemble, driver_config, summarize, RunRequest, RunSummary};
use arcana_cli::work_item::conclude_with_evidence;
use arcana_cli::workspace::WorkspacePolicy;
use arcana_connectors::muneral::MuneralClient;
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use assert_cmd::Command;
use async_trait::async_trait;
use predicates::prelude::*;
use secrecy::SecretString;
use serde_json::json;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use url::Url;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The work item A2-297c ran, and the receipt its run 2 wrote — arcana's own
/// output, not a fixture written for this test. sha256 347c0e69…, the digest
/// A2-332 attached by hand.
const TASK: &str = "d931525f-c134-4c6b-85e1-9cdf94e8ab8b";
const REAL_RECEIPT: &[u8] =
    include_bytes!("fixtures/evidence/ReadinessReceipt-d931525f-c134-4c6b-85e1-9cdf94e8ab8b.json");
const REAL_RECEIPT_SHA: &str = "347c0e6920f9d34310f09308fd2d039afee8f89deeaac10e561a55392a0db94d";

struct ScriptedModel {
    replies: Vec<String>,
    turn: AtomicUsize,
}

#[async_trait]
impl ModelConnector for ScriptedModel {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let index = self.turn.fetch_add(1, Ordering::SeqCst);
        Ok(ConnectorResponse {
            id: format!("scripted-{index}"),
            connector: "scripted".to_owned(),
            model: "scripted-model".to_owned(),
            result: self
                .replies
                .get(index)
                .cloned()
                .unwrap_or_else(|| "out of script".to_owned()),
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
                total_tokens: 2,
                cost_usd: 0.0,
            },
            latency_ms: 0,
            status: "success".to_owned(),
            error: None,
            first_dispatch_observation: None,
        })
    }
}

/// A real run: the model writes the page, then says which path it wrote.
/// `write_page: false` gives a run that only claims, which is `NoEffect`.
async fn real_run(root: &Path, audit: &Path, write_page: bool) -> RunSummary {
    let write = format!(
        "```tool_call\n{}\n```",
        json!({"name": "write", "input": {"path": "page.md", "content": "# page\n"}})
    );
    let replies: Vec<String> = if write_page {
        vec![write, "I wrote `page.md`.".to_owned()]
    } else {
        vec!["I wrote `page.md`.".to_owned()]
    };
    let policy = Arc::new(WorkspacePolicy::new(root).unwrap());
    let workspace = assemble(
        root,
        &policy,
        Box::new(ScriptedModel {
            replies,
            turn: AtomicUsize::new(0),
        }),
        audit.to_path_buf(),
        None,
    )
    .expect("compose the headless run");
    let request = RunRequest {
        cwd: root.to_path_buf(),
        prompt: "write page.md".to_owned(),
        max_turns: 4,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
        request_timeout: None,
        context_budget: None,
        tool_result_budget: None,
        save_transcript: None,
        contract: None,
        expect_effect: EffectExpectation::Artefact,
    };
    let config = driver_config(&request, &workspace.tools, root);
    let before = arcana_cli::effect::snapshot(root);
    let out = workspace
        .session
        .run_task(&request.prompt, config, CancellationToken::new())
        .await;
    summarize(root, &before, out, EffectExpectation::Artefact)
}

/// Put the real receipt where `receipt::write` puts one.
fn place_receipt(root: &Path) -> PathBuf {
    let dir = root.join("receipts");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("ReadinessReceipt-{TASK}.json"));
    std::fs::write(&path, REAL_RECEIPT).unwrap();
    path
}

fn client_at(base: &str) -> MuneralClient {
    MuneralClient::new(
        Url::parse(&format!("{base}/api/v1")).unwrap(),
        SecretString::from("mun_sk_test".to_owned()),
    )
    .unwrap()
}

/// The record Muneral answers with, shaped as production's real 201
/// (`crates/connectors/tests/fixtures/muneral-evidence-attach-201.json`),
/// naming the digest actually sent.
fn record_for(sha: &str, uri: &str, idempotent: bool) -> serde_json::Value {
    json!({
        "schema": "WorkItemEvidenceAttachment/v1",
        "evidence_id": "3632d426-78c9-4800-829b-010f3b0f5e77",
        "task_id": TASK,
        "uri": uri,
        "sha256": sha,
        "content_type": "application/json",
        "created_by_agent_id": "1e40d8c4-3b1c-4b81-8eed-3db22460cc27",
        "created_at": "2026-09-25T12:53:19.022Z",
        "idempotent": idempotent,
    })
}

fn sidecar(receipt: &Path) -> serde_json::Value {
    let path = receipt.with_file_name(format!("ReadinessReceipt-{TASK}.evidence.json"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("sidecar written")).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_successful_run_attaches_the_sha_of_its_receipt_bytes_on_disk_exactly_once() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let summary = real_run(work.path(), audit.path(), true).await;
    let receipt = place_receipt(work.path());
    let on_disk = sha256_hex(&std::fs::read(&receipt).unwrap());
    assert_eq!(
        on_disk, REAL_RECEIPT_SHA,
        "fixture is arcana's real receipt"
    );
    let uri = Url::from_file_path(receipt.canonicalize().unwrap())
        .unwrap()
        .to_string();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/tasks/{TASK}/evidence")))
        .and(header("authorization", "Bearer mun_sk_test"))
        .respond_with(ResponseTemplate::new(201).set_body_json(record_for(&on_disk, &uri, false)))
        .expect(1)
        .mount(&server)
        .await;

    let code = conclude_with_evidence(
        &client_at(&server.uri()),
        TASK,
        &receipt,
        None,
        &summary,
        work.path(),
    )
    .await;

    assert_eq!(code, 0, "run completed and evidence attached");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "attached exactly once");
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["sha256"], on_disk, "the digest of the bytes on disk");
    assert_eq!(body["contentType"], "application/json");
    assert_eq!(body["uri"], uri, "file:// of the receipt by default");
    let recorded = sidecar(&receipt);
    assert_eq!(recorded["attached"], true);
    assert_eq!(recorded["idempotent"], false);
    assert_eq!(recorded["sha256"], on_disk);
    // Attaching must not rewrite the receipt it attached.
    assert_eq!(std::fs::read(&receipt).unwrap(), REAL_RECEIPT);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_successful_run_whose_attach_is_refused_exits_three_and_keeps_its_receipt() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let summary = real_run(work.path(), audit.path(), true).await;
    let receipt = place_receipt(work.path());

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/tasks/{TASK}/evidence")))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "code": "EVIDENCE_DIGEST_CONFLICT", "statusCode": 409
        })))
        .expect(1)
        .mount(&server)
        .await;

    let code = conclude_with_evidence(
        &client_at(&server.uri()),
        TASK,
        &receipt,
        None,
        &summary,
        work.path(),
    )
    .await;

    assert_eq!(code, EXIT_NOT_ATTACHED, "never 0 without the evidence");
    assert_eq!(
        std::fs::read(&receipt).unwrap(),
        REAL_RECEIPT,
        "receipt kept"
    );
    let recorded = sidecar(&receipt);
    assert_eq!(recorded["attached"], false);
    assert_eq!(recorded["code"], "EVIDENCE_NOT_ATTACHED");
    assert!(recorded["error"]
        .as_str()
        .unwrap()
        .contains("EVIDENCE_DIGEST_CONFLICT"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_successful_run_with_muneral_unreachable_exits_three() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let summary = real_run(work.path(), audit.path(), true).await;
    let receipt = place_receipt(work.path());

    let code = conclude_with_evidence(
        &client_at("http://127.0.0.1:1"),
        TASK,
        &receipt,
        None,
        &summary,
        work.path(),
    )
    .await;

    assert_eq!(code, EXIT_NOT_ATTACHED);
    let recorded = sidecar(&receipt);
    assert_eq!(recorded["attached"], false);
    assert!(!recorded.to_string().contains("mun_sk_test"), "no key");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_run_keeps_its_own_code_and_still_offers_its_receipt() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    // Claims a page and runs no tool: `NoAction`, exit 1.
    let summary = real_run(work.path(), audit.path(), false).await;
    let receipt = place_receipt(work.path());

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/tasks/{TASK}/evidence")))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    let code = conclude_with_evidence(
        &client_at(&server.uri()),
        TASK,
        &receipt,
        None,
        &summary,
        work.path(),
    )
    .await;
    assert_eq!(code, 1, "the run's failure is the verdict that stands");
    assert_eq!(sidecar(&receipt)["attached"], false);
}

// --- the binary: `arcana attach-receipt` ------------------------------------

fn key_file(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("muneral.key");
    std::fs::write(&path, "mun_sk_test\n").unwrap();
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_receipt_repeats_a_landed_claim_idempotently_and_exits_zero() {
    let keys = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let receipt = place_receipt(work.path());
    let uri = "https://example.invalid/receipts/ReadinessReceipt.json";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/tasks/{TASK}/evidence")))
        .and(wiremock::matchers::body_json(json!({
            "uri": uri, "sha256": REAL_RECEIPT_SHA, "contentType": "application/json"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(record_for(
            REAL_RECEIPT_SHA,
            uri,
            true,
        )))
        .expect(1)
        .mount(&server)
        .await;

    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", key_file(&keys))
        .args(["attach-receipt", "--work-item", TASK, "--receipt"])
        .arg(&receipt)
        .args(["--evidence-uri", uri])
        .assert()
        .success()
        .stdout(predicate::str::contains("idempotent repeat"))
        .stdout(predicate::str::contains(REAL_RECEIPT_SHA));
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_receipt_refused_by_the_route_says_so_and_exits_three() {
    let keys = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let receipt = place_receipt(work.path());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/tasks/{TASK}/evidence")))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "agent is not assigned to this task", "statusCode": 403
        })))
        .mount(&server)
        .await;

    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", key_file(&keys))
        .args(["attach-receipt", "--work-item", TASK, "--receipt"])
        .arg(&receipt)
        .assert()
        .code(EXIT_NOT_ATTACHED)
        .stderr(predicate::str::contains("EVIDENCE_NOT_ATTACHED"))
        .stderr(predicate::str::contains("not assigned"))
        .stderr(predicate::str::contains("mun_sk_test").not());
}

#[test]
fn attach_receipt_with_muneral_unreachable_exits_three() {
    let keys = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let receipt = place_receipt(work.path());

    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MUNERAL_URL", "http://127.0.0.1:1/api/v1")
        .env("ARCANA_MUNERAL_KEY_FILE", key_file(&keys))
        .args(["attach-receipt", "--work-item", TASK, "--receipt"])
        .arg(&receipt)
        .assert()
        .code(EXIT_NOT_ATTACHED)
        .stderr(predicate::str::contains("EVIDENCE_NOT_ATTACHED"))
        .stderr(predicate::str::contains("could not be reached"));
}
