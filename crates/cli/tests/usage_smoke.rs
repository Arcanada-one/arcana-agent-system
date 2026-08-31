//! `arcana usage` and the per-turn spend line (ARAS-0066).

#![allow(clippy::unwrap_used, clippy::unreadable_literal)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn usage_reports_the_connectors_numbers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stats/requests/daily"))
        .and(wiremock::matchers::header_exists("x-stats-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"date": "2026-08-28", "requests": 3, "total_tokens": 1_500, "cost_usd": 0.001234},
            {"date": "2026-08-27", "requests": 1, "total_tokens": 500,  "cost_usd": 0.000500},
        ])))
        .mount(&server)
        .await;
    let state = TempDir::new().unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MC_BASE_URL", server.uri())
        .env("ARCANA_STATS_TOKEN", "t")
        .env("XDG_STATE_HOME", state.path())
        .arg("usage")
        .assert()
        .success()
        .stdout(predicate::str::contains("2026-08-28"))
        // Sub-cent figures must survive to the screen.
        .stdout(predicate::str::contains("0.001234"))
        .stdout(predicate::str::contains("TOTAL"))
        // The total must be the SUM, not the last row.
        .stdout(predicate::str::contains("0.001734"))
        .stdout(predicate::str::contains("Model Connector"));
}

#[tokio::test]
async fn usage_without_a_token_refuses_rather_than_guessing_locally() {
    // A locally computed figure printed next to a balance would look
    // authoritative while disagreeing with what was actually charged.
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_STATS_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .arg("usage")
        .assert()
        .failure()
        .stderr(predicate::str::contains("ARCANA_STATS_TOKEN"))
        .stderr(predicate::str::contains("no local figure"));
}

#[tokio::test]
async fn usage_reports_an_unreachable_connector_rather_than_panicking() {
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MC_BASE_URL", "http://127.0.0.1:1")
        .env("ARCANA_STATS_TOKEN", "t")
        .env("XDG_STATE_HOME", state.path())
        .arg("usage")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot reach"))
        .stderr(predicate::str::contains("panicked").not());
}

#[tokio::test]
async fn the_session_prints_spend_for_each_turn() {
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .env("XDG_STATE_HOME", state.path())
        .write_stdin("implement a greeting in rust: echo the world back\nexit\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("this turn"))
        .stdout(predicate::str::contains("session"))
        .stdout(predicate::str::contains("tokens"));
}

#[tokio::test]
async fn successive_turns_each_report_their_own_spend() {
    // The session cost tracker is cumulative; a per-turn line that simply
    // echoed it would bill every later turn for everything before it. Two
    // turns must produce two spend lines.
    let state = TempDir::new().unwrap();
    let output = Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .env("XDG_STATE_HOME", state.path())
        .write_stdin(
            "implement a greeting in rust: echo the world back\n\
             implement another greeting in rust: echo it back\n\
             exit\n",
        )
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.matches("this turn").count(),
        2,
        "expected one spend line per turn, got: {stdout}"
    );
}
