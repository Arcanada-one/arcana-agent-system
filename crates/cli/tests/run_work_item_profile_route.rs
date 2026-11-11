//! R2 at the binary: `arcana run --work-item` with and without `--contract-profile`.
//!
//! A producer-generated profile contract served over the Argana HTTP shape (`canonical.bytes_b64`):
//! - flag omitted: refused `CONTRACT_PROFILE_ROUTE_REQUIRED` at the binding step - no readiness
//!   request, no authority attempt, nothing written;
//! - flag present: the strict route binds it and the run proceeds to the authority gate, which in
//!   this build is the unavailable default (`CONTRACT_AUTHORITY_UNAVAILABLE`);
//! - actual legacy bytes, flag omitted: unchanged, they reach the same authority gate.
//!
//! No provider token, grant or model call is used; the authority gate refuses every run here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arcana_core::contract::digest_of;
use assert_cmd::Command;
use base64::Engine as _;
use predicates::prelude::*;
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TASK: &str = "6aaa720c-233e-4f84-bcd5-b8770e93aef0";
const PRODUCER: &str =
    include_str!("../../core/tests/fixtures/kc2_tools_producer/producer_positives.json");

fn halves(section: &Value) -> String {
    format!(
        "{}{}",
        section["body_text"].as_str().unwrap(),
        section["manifest_text"].as_str().unwrap()
    )
}

/// Returns (stdout+stderr success?, readiness requests seen).
async fn run_arcana(
    preimage: &str,
    flag: Option<&str>,
) -> (assert_cmd::assert::Assert, usize, TempDir) {
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
    let digest = digest_of(preimage.as_bytes());
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": TASK, "projectId": "fixture-project", "title": "Fixture", "contractDigest": digest,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}/readiness")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "taskId": TASK, "ready": true, "dependencyCount": 0, "blockedBy": [],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/contract/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "digest": digest,
            "canonical": {"bytes_b64": base64::engine::general_purpose::STANDARD.encode(preimage.as_bytes())},
        })))
        .mount(&server)
        .await;
    let mut command = Command::cargo_bin("arcana").unwrap();
    command
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MUNERAL_KEY_FILE", &key)
        .env("ARCANA_ARGANA_URL", server.uri())
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--work-item", TASK]);
    if let Some(profile) = flag {
        command.args(["--contract-profile", profile]);
    }
    let assert = command.assert();
    let readiness = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/readiness"))
        .count();
    (assert, readiness, work)
}

#[tokio::test]
async fn omitting_the_flag_refuses_a_profile_contract_before_readiness_and_authority() {
    let all: Value = serde_json::from_str(PRODUCER).unwrap();
    let preimage = halves(&all["cases"]["rw"]);
    let (assert, readiness, work) = run_arcana(&preimage, None).await;
    assert
        .failure()
        .stderr(predicate::str::contains("CONTRACT_PROFILE_ROUTE_REQUIRED"))
        .stderr(predicate::str::contains("CONTRACT_AUTHORITY_UNAVAILABLE").not());
    assert_eq!(
        readiness, 0,
        "refused at the binding step, before readiness"
    );
    assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn the_flag_selects_the_strict_route_which_reaches_the_authority_gate() {
    let all: Value = serde_json::from_str(PRODUCER).unwrap();
    let preimage = halves(&all["cases"]["rw"]);
    let (assert, readiness, work) = run_arcana(&preimage, Some("arcanada-kc2-tools/v1")).await;
    assert
        .failure()
        .stderr(predicate::str::contains("CONTRACT_AUTHORITY_UNAVAILABLE"))
        .stderr(predicate::str::contains("CONTRACT_PROFILE_ROUTE_REQUIRED").not());
    assert_eq!(readiness, 1);
    assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn actual_legacy_bytes_without_the_flag_are_unchanged() {
    let all: Value = serde_json::from_str(PRODUCER).unwrap();
    let preimage = halves(&all["legacy_v2"]);
    let (assert, readiness, _work) = run_arcana(&preimage, None).await;
    assert
        .failure()
        .stderr(predicate::str::contains("CONTRACT_AUTHORITY_UNAVAILABLE"))
        .stderr(predicate::str::contains("CONTRACT_PROFILE_ROUTE_REQUIRED").not());
    assert_eq!(readiness, 1);
}
