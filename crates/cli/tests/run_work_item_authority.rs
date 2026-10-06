//! Native pre-provider regression: a matching digest is not admission authority.
//! All authority-looking fields below are deliberately untrusted fixture claims.
//! No provider token, issuer key, grant, live contract store or model call is used.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arcana_core::contract::digest_of;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TASK: &str = "6aaa720c-233e-4f84-bcd5-b8770e93aef0";

async fn untrusted_claims_refuse_before_provider(claims: serde_json::Value) {
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
    let projection = json!({"tools": {"allow": ["read"]}, "untrusted_admission": claims}).to_string();
    let digest = digest_of(projection.as_bytes());
    let contract = inputs.path().join("contract.json");
    std::fs::write(&contract, json!({
        "digest": digest, "projection": projection,
        "tools": {"allow": ["read"]},
    }).to_string()).unwrap();
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": TASK, "projectId": "fixture-project", "title": "Read-only fixture",
            "contractDigest": digest,
        })))
        .expect(1)
        .mount(&server).await;
    Command::cargo_bin("arcana").unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", &key)
        .args(["run", "--cwd"]).arg(work.path())
        .args(["--work-item", TASK, "--contract-file"]).arg(&contract)
        .assert().failure()
        .stderr(predicate::str::contains("CONTRACT_AUTHORITY_UNAVAILABLE"))
        .stderr(predicate::str::contains("ARCANA_MC_TOKEN").not());
    assert!(!work.path().join("receipts").exists());
    assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn another_tasks_valid_digest_cannot_supply_its_own_admission() {
    untrusted_claims_refuse_before_provider(json!({"task_id": "different-task"})).await;
}

#[tokio::test]
async fn a_different_subject_in_digest_claims_does_not_supply_authority() {
    untrusted_claims_refuse_before_provider(json!({"task_id": TASK, "subject_id": "other-subject"})).await;
}

#[tokio::test]
async fn a_self_declared_issuer_cannot_authorize_a_work_item() {
    untrusted_claims_refuse_before_provider(json!({"task_id": TASK, "issuer": "executor-self-issued"})).await;
}

#[tokio::test]
async fn a_self_declared_current_generation_cannot_authorize_a_work_item() {
    untrusted_claims_refuse_before_provider(json!({"task_id": TASK, "generation": 1, "current_generation": 1})).await;
}
