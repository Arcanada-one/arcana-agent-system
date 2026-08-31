//! `arcana models` against a mock Model Connector (ARAS-0065).
//!
//! A mock because the assertions are about behaviour a live catalogue cannot be
//! driven into on demand — an empty catalogue, a provider with more than the
//! cap, an unreachable connector. Proving the command talks to the REAL
//! connector is ARAS-0070's job, not this file's.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// One entry in the shape the real route sends: tariffs nested under
/// `pricing`, camelCase, no `tier` field. The previous helper here emitted flat
/// `snake_case` keys that the server has never produced.
fn entry(connector: &str, model: &str, input: f64, output: f64) -> serde_json::Value {
    serde_json::json!({
        "connector": connector,
        "model": model,
        "modality": "chat",
        "free": false,
        "pricing": {
            "inputPerMTok": input,
            "outputPerMTok": output,
            "unit": "per_1m_tokens",
        },
        "available": true,
    })
}

/// Wrap entries in the envelope the route returns. `mount` takes the bare array
/// so the call sites read naturally; the envelope is applied here, in one place,
/// because it is a property of the transport rather than of any one test.
async fn mount(server: &MockServer, models: serde_json::Value) {
    let count = models.as_array().map_or(0, Vec::len);
    mount_raw(
        server,
        serde_json::json!({
            "models": models,
            "generatedAt": "2026-08-31T07:30:18.079Z",
            "count": count,
        }),
    )
    .await;
}

/// Mount an exact body, envelope and all — for asserting on the transport shape
/// itself.
async fn mount_raw(server: &MockServer, body: serde_json::Value) {
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

#[tokio::test]
async fn a_bare_array_is_reported_not_silently_accepted() {
    // The shape the client used to expect. The server has never sent it, and if
    // it ever did, saying so beats guessing.
    let server = MockServer::start().await;
    mount_raw(&server, serde_json::json!([entry("groq", "m", 1.0, 1.0)])).await;
    let state = TempDir::new().unwrap();

    arcana(&server, &state)
        .arg("models")
        .assert()
        .failure()
        .stderr(predicate::str::contains("could not be read"))
        .stderr(predicate::str::contains("models"))
        .stderr(predicate::str::contains("panicked").not());
}

#[tokio::test]
async fn prices_from_the_real_nested_shape_reach_the_screen() {
    // The second half of the defect: with the envelope fixed but the entry
    // shape still flat, every model would list as "price unknown" -- a silent
    // wrong answer rather than an error.
    let server = MockServer::start().await;
    mount(
        &server,
        serde_json::json!([entry("orq", "grok-3-latest", 3.0, 15.0)]),
    )
    .await;
    let state = TempDir::new().unwrap();

    arcana(&server, &state)
        .arg("models")
        .assert()
        .success()
        .stdout(predicate::str::contains("in $3.00 / out $15.00 per 1M tok"))
        .stdout(predicate::str::contains("price unknown").not());
}

#[tokio::test]
async fn a_model_the_connector_cannot_dispatch_is_not_offered() {
    // Listing an unavailable model invites the operator to choose it and get a
    // dispatch failure the list already knew about.
    let server = MockServer::start().await;
    let mut down = entry("deepgram-tts", "aura-asteria-en", 1.0, 1.0);
    down["available"] = serde_json::json!(false);
    mount(
        &server,
        serde_json::json!([entry("orq", "reachable", 1.0, 1.0), down]),
    )
    .await;
    let state = TempDir::new().unwrap();

    arcana(&server, &state)
        .arg("models")
        .assert()
        .success()
        .stdout(predicate::str::contains("reachable"))
        .stdout(predicate::str::contains("aura-asteria-en").not());
}
