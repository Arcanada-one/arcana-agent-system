//! `arcana usage` and the per-turn spend line (ARAS-0066).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A response body in the shape `GET /stats/requests/daily` ACTUALLY returns.
///
/// Captured from the live route, not written from the Rust struct. The previous
/// fixture here invented `date`/`total_tokens`/`cost_usd`; the server sends
/// `day`/`totalTokens`/`costUsd` and aggregates by (connector, model, day). The
/// fixture agreed with the code, the code disagreed with the server, and the
/// test passed anyway — which is how `usage` shipped never having worked.
fn live_shaped_body() -> serde_json::Value {
    serde_json::json!([
        {"connector": "orq", "model": "grok-3-latest",
         "day": "2026-08-28T00:00:00.000Z", "requests": 2,
         "inputTokens": 400, "outputTokens": 100, "totalTokens": 1_000, "costUsd": 0.001000},
        {"connector": "orq", "model": "deepseek-v4-flash",
         "day": "2026-08-28T00:00:00.000Z", "requests": 1,
         "inputTokens": 200, "outputTokens": 300, "totalTokens": 500, "costUsd": 0.000234},
        {"connector": "orq", "model": "grok-3-latest",
         "day": "2026-08-27T00:00:00.000Z", "requests": 1,
         "inputTokens": 200, "outputTokens": 300, "totalTokens": 500, "costUsd": 0.000500},
    ])
}

#[tokio::test]
async fn usage_reports_the_connectors_numbers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stats/requests/daily"))
        .and(wiremock::matchers::header_exists("x-stats-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(live_shaped_body()))
        .mount(&server)
        .await;
    let state = TempDir::new().unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MC_BASE_URL", server.uri())
        .env("ARCANA_STATS_TOKEN", "t")
        .env("XDG_STATE_HOME", state.path())
        .arg("usage")
        .arg("--since")
        .arg("2026-08-27")
        .arg("--until")
        .arg("2026-08-28")
        .assert()
        .success()
        .stdout(predicate::str::contains("2026-08-28"))
        // The two model rows for the 28th must fold into ONE line summing to
        // 0.001234 — printing them separately would repeat the date and show
        // no day total.
        .stdout(predicate::str::contains("0.001234"))
        .stdout(predicate::str::contains("TOTAL"))
        // The total must be the SUM, not the last row.
        .stdout(predicate::str::contains("0.001734"))
        .stdout(predicate::str::contains("Model Connector"));
}

#[tokio::test]
async fn usage_always_sends_the_window_the_route_requires() {
    // The defect this test exists for: the command sent neither `since` nor
    // `until`, and the route rejects that with an unconditional HTTP 400. The
    // matchers below fail the request unless BOTH are present, so a regression
    // to a bare GET cannot pass.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stats/requests/daily"))
        .and(wiremock::matchers::query_param("since", "2026-08-27"))
        .and(wiremock::matchers::query_param("until", "2026-08-28"))
        .respond_with(ResponseTemplate::new(200).set_body_json(live_shaped_body()))
        .mount(&server)
        .await;
    let state = TempDir::new().unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MC_BASE_URL", server.uri())
        .env("ARCANA_STATS_TOKEN", "t")
        .env("XDG_STATE_HOME", state.path())
        .args(["usage", "--since", "2026-08-27", "--until", "2026-08-28"])
        .assert()
        .success();
}

#[tokio::test]
async fn the_default_window_is_sent_even_when_the_user_passes_nothing() {
    // The no-flags path is the one a first-time user takes, and the one that
    // was broken. Assert against the request the server actually received, so
    // the dates are checked rather than assumed.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stats/requests/daily"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
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
        .success();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "exactly one call");
    let pairs: std::collections::HashMap<_, _> = requests[0].url.query_pairs().collect();
    let since = pairs.get("since").expect("since must be sent");
    let until = pairs.get("until").expect("until must be sent");
    // Both are real ISO dates, and the span is the documented 30 inclusive days.
    let day = |d: &str| {
        let parts: Vec<i64> = d.split('-').map(|p| p.parse().unwrap()).collect();
        (parts[0], parts[1], parts[2])
    };
    let (sy, sm, sd) = day(since);
    let (uy, um, ud) = day(until);
    assert!((1..=12).contains(&sm) && (1..=31).contains(&sd), "{since}");
    assert!((1..=12).contains(&um) && (1..=31).contains(&ud), "{until}");
    assert!(
        (uy, um, ud) >= (sy, sm, sd),
        "window must not run backwards: {since}..{until}"
    );
}

#[tokio::test]
async fn a_server_rejection_shows_what_the_server_said() {
    // A bare "HTTP 400" is what hid the missing parameters for the whole life
    // of this command. The validation body names the fields; print it.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stats/requests/daily"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "message": "Validation failed",
            "errors": ["since: Invalid input: expected string, received undefined"],
        })))
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
        .failure()
        // Assert the PROPERTY, not the phrasing: the status and the server's
        // own words must both reach the user. An earlier version of this test
        // pinned the literal sentence that introduced the body, and broke when
        // the rendering moved into a shared helper while the behaviour it cares
        // about was unchanged.
        .stderr(predicate::str::contains("HTTP 400"))
        .stderr(predicate::str::contains("Validation failed"))
        // The validation array names WHICH parameter was wrong; that is the
        // part worth having, so pin it rather than the wrapper text.
        .stderr(predicate::str::contains("since: Invalid input"));
}

#[tokio::test]
async fn an_impossible_window_is_refused_without_calling_the_server() {
    // No mock is mounted: if the command reached out, it would fail on
    // connection rather than on the message asserted here.
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MC_BASE_URL", "http://127.0.0.1:1")
        .env("ARCANA_STATS_TOKEN", "t")
        .env("XDG_STATE_HOME", state.path())
        .args(["usage", "--since", "2026-08-31", "--until", "2026-08-01"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("runs backwards"));
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
