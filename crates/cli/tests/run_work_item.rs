//! `arcana run --work-item` refuses before it spends anything.
//!
//! Every case here ends before the first model call, and that is the point: a
//! run bound to nothing, or bound to a contract that is not the one the work
//! item names, must cost zero. The evidence is negative and has to be stated
//! as such — `ARCANA_MC_TOKEN` is absent in every case, so a refusal that
//! happened at or after the connector would say `ARCANA_MC_TOKEN` on stderr.
//! Asserting that it does NOT is what makes "before any model call" a
//! measurement rather than a claim.
//!
//! The run that DOES happen is not here: it needs the live Model Connector and
//! costs money, so it is the card's single real run and its receipt.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TASK: &str = "b1227e82-da2b-4fee-aff6-b4ba8c6b01e3";
const PROJECTION: &str = "Role: reviewer. Deliverable: one review note.";

/// The same helper the binary uses, so the fixtures cannot drift from the rule
/// under test.
use arcana_core::contract::digest_of;

fn key_file(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("muneral.key");
    std::fs::write(&path, "mun_sk_test\n").unwrap();
    path
}

async fn muneral_serving(task: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(task))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn a_work_item_without_a_contract_digest_is_refused_before_any_model_call() {
    let server = muneral_serving(json!({"id": TASK, "title": "an unbound work item"})).await;
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let keys = TempDir::new().unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", key_file(&keys))
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--work-item", TASK])
        .assert()
        .failure()
        .stderr(predicate::str::contains("CONTRACT_MISSING"))
        // The negative half: the Model Connector was never asked for.
        .stderr(predicate::str::contains("ARCANA_MC_TOKEN").not())
        .stdout(predicate::str::contains("\"completed\":false"));

    // And nothing was written where a receipt would go.
    assert!(!work.path().join("receipts").exists());
}

#[tokio::test]
async fn a_contract_whose_bytes_do_not_hash_to_the_digest_is_refused_before_any_model_call() {
    let named = digest_of(PROJECTION.as_bytes());
    let server = muneral_serving(json!({
        "id": TASK, "title": "a bound work item", "contractDigest": named,
    }))
    .await;
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let keys = TempDir::new().unwrap();

    // The file claims the digest the work item names and holds other bytes —
    // a contract edited after it was stamped.
    let contract = keys.path().join("contract.json");
    std::fs::write(
        &contract,
        json!({"digest": named, "projection": "Role: deployer. Production access."}).to_string(),
    )
    .unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", key_file(&keys))
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--work-item", TASK])
        .arg("--contract-file")
        .arg(&contract)
        .assert()
        .failure()
        .stderr(predicate::str::contains("CONTRACT_DIGEST_MISMATCH"))
        .stderr(predicate::str::contains("ARCANA_MC_TOKEN").not());

    assert!(!work.path().join("receipts").exists());
}

#[tokio::test]
async fn a_contract_the_source_does_not_hold_is_a_not_found_not_a_mismatch() {
    let named = digest_of(b"a contract nobody stored");
    let server = muneral_serving(json!({
        "id": TASK, "title": "a bound work item", "contractDigest": named,
    }))
    .await;
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let keys = TempDir::new().unwrap();
    let contract = keys.path().join("contract.json");
    std::fs::write(
        &contract,
        json!({"digest": digest_of(PROJECTION.as_bytes()), "projection": PROJECTION}).to_string(),
    )
    .unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", key_file(&keys))
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--work-item", TASK])
        .arg("--contract-file")
        .arg(&contract)
        .assert()
        .failure()
        .stderr(predicate::str::contains("CONTRACT_NOT_FOUND"));
}

#[tokio::test]
async fn with_no_contract_source_configured_the_run_says_what_would_fix_it() {
    let server = muneral_serving(json!({
        "id": TASK, "title": "a bound work item",
        "contractDigest": digest_of(PROJECTION.as_bytes()),
    }))
    .await;
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let keys = TempDir::new().unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env_remove("ARCANA_ARGANA_URL")
        .env("XDG_STATE_HOME", state.path())
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", key_file(&keys))
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--work-item", TASK])
        .assert()
        .failure()
        .stderr(predicate::str::contains("CONTRACT_SOURCE_UNAVAILABLE"))
        .stderr(predicate::str::contains("--contract-file"));
}

#[tokio::test]
async fn a_foreign_work_item_is_refused_with_the_servers_reason() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "agent is not assigned to this task", "statusCode": 403
        })))
        .mount(&server)
        .await;
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let keys = TempDir::new().unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", key_file(&keys))
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--work-item", TASK])
        .assert()
        .failure()
        .stderr(predicate::str::contains("WORK_ITEM_UNREADABLE"))
        .stderr(predicate::str::contains("not assigned"));
}

#[test]
fn a_work_item_and_a_literal_prompt_cannot_both_be_given() {
    let work = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--prompt", "do nothing", "--work-item", TASK])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}
