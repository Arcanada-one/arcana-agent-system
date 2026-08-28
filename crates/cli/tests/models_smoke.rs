//! `arcana models` against a mock Model Connector (ARAS-0065).
//!
//! A mock because the assertions are about behaviour a live catalogue cannot be
//! driven into on demand — an empty catalogue, a provider with more than the
//! cap, an unreachable connector. Proving the command talks to the REAL
//! connector is ARAS-0070's job, not this file's.

#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn entry(connector: &str, model: &str, input: f64, output: f64) -> serde_json::Value {
    serde_json::json!({
        "connector": connector,
        "model": model,
        "input_per_m_tok": input,
        "output_per_m_tok": output,
        "tier": "paid",
        "free": false,
    })
}

async fn mount(server: &MockServer, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/connectors/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

fn arcana(server: &MockServer, state: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.env("ARCANA_MC_BASE_URL", server.uri())
        .env("ARCANA_MC_TOKEN", "test-token")
        .env("XDG_STATE_HOME", state.path());
    cmd
}

#[tokio::test]
async fn lists_models_with_prices_and_marks_the_default() {
    let server = MockServer::start().await;
    mount(
        &server,
        serde_json::json!([entry("groq", "llama-fast", 0.5, 1.5)]),
    )
    .await;
    let state = TempDir::new().unwrap();

    arcana(&server, &state)
        .arg("models")
        .assert()
        .success()
        .stdout(predicate::str::contains("llama-fast"))
        // Price beside the model is the point of the command.
        .stdout(predicate::str::contains("per 1M tok"))
        // With no choice saved, the documented default must be shown.
        .stdout(predicate::str::contains("deepseek-v4-flash"));
}

#[tokio::test]
async fn caps_the_list_at_ten_per_provider() {
    let server = MockServer::start().await;
    let many: Vec<_> = (0..25)
        .map(|i| entry("groq", &format!("m{i:02}"), f64::from(i), 0.0))
        .collect();
    mount(&server, serde_json::json!(many)).await;
    let state = TempDir::new().unwrap();

    let output = arcana(&server, &state).arg("models").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let shown = (0..25)
        .filter(|i| stdout.contains(&format!("m{i:02} ")))
        .count();

    assert_eq!(shown, 10, "expected the per-provider cap, saw {shown}");
}

#[tokio::test]
async fn a_saved_choice_persists_and_is_marked() {
    let server = MockServer::start().await;
    mount(
        &server,
        serde_json::json!([entry("groq", "llama-fast", 0.5, 1.5)]),
    )
    .await;
    let state = TempDir::new().unwrap();

    arcana(&server, &state)
        .args(["models", "use", "llama-fast"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Model set to llama-fast"));

    // A choice that does not survive the process is not a choice.
    arcana(&server, &state)
        .arg("models")
        .assert()
        .success()
        .stdout(predicate::str::contains("Selected: llama-fast"));
}

#[tokio::test]
async fn use_accepts_a_model_the_curated_list_does_not_show() {
    // Curation is presentational. It must never become a whitelist that stops
    // an operator selecting a model they know exists.
    let server = MockServer::start().await;
    mount(
        &server,
        serde_json::json!([entry("groq", "listed", 1.0, 1.0)]),
    )
    .await;
    let state = TempDir::new().unwrap();

    arcana(&server, &state)
        .args(["models", "use", "some-unlisted-model"])
        .assert()
        .success();

    arcana(&server, &state)
        .arg("models")
        .assert()
        .success()
        .stdout(predicate::str::contains("Selected: some-unlisted-model"));
}

#[tokio::test]
async fn an_unreachable_connector_is_reported_not_panicked() {
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MC_BASE_URL", "http://127.0.0.1:1")
        .env("ARCANA_MC_TOKEN", "test-token")
        .env("XDG_STATE_HOME", state.path())
        .arg("models")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot reach"))
        .stderr(predicate::str::contains("panicked").not());
}

#[tokio::test]
async fn a_missing_token_says_so_rather_than_showing_a_stale_list() {
    // The list is never hard-coded, so without a token there is genuinely
    // nothing to show — saying that is better than inventing a fallback.
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .arg("models")
        .assert()
        .failure()
        .stderr(predicate::str::contains("ARCANA_MC_TOKEN"));
}

/// The choice must reach the agent loop, not just a file.
///
/// A preference nothing reads is the failure this asserts against: `use` would
/// report success, the list would show the new model as selected, and the agent
/// would keep calling the old one.
#[tokio::test]
async fn the_chosen_model_reaches_the_agent_loop() {
    let server = MockServer::start().await;
    mount(
        &server,
        serde_json::json!([entry("groq", "listed", 1.0, 1.0)]),
    )
    .await;
    let state = TempDir::new().unwrap();

    arcana(&server, &state)
        .args(["models", "use", "chosen-by-operator"])
        .assert()
        .success();

    // The interactive session reports the models it selected per turn.
    arcana(&server, &state)
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .write_stdin("implement a greeting in rust: echo the world back\nexit\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("chosen-by-operator"));
}

#[tokio::test]
async fn an_empty_catalogue_is_an_error_not_a_blank_success() {
    let server = MockServer::start().await;
    mount(&server, serde_json::json!([])).await;
    let state = TempDir::new().unwrap();

    arcana(&server, &state)
        .arg("models")
        .assert()
        .failure()
        .stdout(predicate::str::contains("empty catalogue"));
}
