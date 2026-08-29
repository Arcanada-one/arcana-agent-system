//! End-to-end checks for `arcana login` (ARAS-0060) against a mock identity
//! provider.
//!
//! A mock rather than the real `IdP` on purpose: these must pin the CLI's
//! behaviour on every code path — pending-then-approved, denial, a provider
//! with no device grant — and a real provider cannot be driven into those
//! states on demand. The one thing a mock cannot prove (that the real
//! auth.arcanada offers the grant at all) is ARAS-0069's job, not this file's.

#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Discovery document pointing every endpoint at the mock.
fn discovery(base: &str, with_device: bool) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "issuer": base,
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
    });
    if with_device {
        doc["device_authorization_endpoint"] = serde_json::json!(format!("{base}/device/auth"));
    }
    doc
}

async fn mount_discovery(server: &MockServer, with_device: bool) {
    let body = discovery(&server.uri(), with_device);
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn mount_device_auth(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/device/auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "dev-code-123",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://auth.example/device",
            "interval": 1,
            "expires_in": 60,
        })))
        .mount(server)
        .await;
}

fn arcana(server: &MockServer, state: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.env("ARCANA_AUTH_ISSUER", server.uri())
        .env("XDG_STATE_HOME", state.path())
        .arg("login");
    cmd
}

/// A provider without the device grant must say so precisely and exit 2 —
/// the live state of auth.arcanada.* before ARAS-0069 is rolled out.
#[tokio::test]
async fn a_provider_without_the_device_grant_fails_closed() {
    let server = MockServer::start().await;
    mount_discovery(&server, false).await;
    let state = TempDir::new().unwrap();

    arcana(&server, &state)
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "does not offer the device-authorization grant",
        ));

    // Fail-closed means no credential is left behind.
    assert!(!state.path().join("arcana/credentials.json").exists());
}

/// An unreachable issuer is an error with a sentence, never a panic.
#[tokio::test]
async fn an_unreachable_issuer_is_reported_not_panicked() {
    let state = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.env("ARCANA_AUTH_ISSUER", "http://127.0.0.1:1")
        .env("XDG_STATE_HOME", state.path())
        .arg("login")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot reach"))
        .stderr(predicate::str::contains("panicked").not());
}

/// The whole point: poll through `authorization_pending`, then store on approval.
#[tokio::test]
async fn polls_through_pending_then_stores_credentials() {
    let server = MockServer::start().await;
    mount_discovery(&server, true).await;
    mount_device_auth(&server).await;

    // First poll pending, then approved — proves the CLI actually polls rather
    // than succeeding only when the provider is instantly ready.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "authorization_pending"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-secret-value",
            "refresh_token": "rt-secret-value",
            "token_type": "Bearer",
            "expires_in": 900,
        })))
        .mount(&server)
        .await;

    let state = TempDir::new().unwrap();
    arcana(&server, &state)
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .success()
        .stdout(predicate::str::contains("ABCD-EFGH"))
        .stdout(predicate::str::contains("Signed in"))
        // The token must never be echoed to the terminal.
        .stdout(predicate::str::contains("at-secret-value").not());

    let creds = state.path().join("arcana/credentials.json");
    assert!(creds.exists(), "credentials were not written");
    let body = std::fs::read_to_string(&creds).unwrap();
    assert!(body.contains("at-secret-value"));
    assert!(body.contains("rt-secret-value"));

    // A credential file readable by anyone else on the host is a defect, so
    // assert the mode rather than trusting the umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&creds).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credentials must be owner-only, got {mode:o}");
    }
}

/// A declined approval is reported and stores nothing.
#[tokio::test]
async fn a_declined_request_stores_nothing() {
    let server = MockServer::start().await;
    mount_discovery(&server, true).await;
    mount_device_auth(&server).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "access_denied"
        })))
        .mount(&server)
        .await;

    let state = TempDir::new().unwrap();
    arcana(&server, &state)
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stderr(predicate::str::contains("declined"));

    assert!(!state.path().join("arcana/credentials.json").exists());
}

/// An expired code must say so plainly, whichever error the provider uses.
///
/// The live provider answers an expired device code with `invalid_grant`, not
/// the `expired_token` that RFC 8628 specifies. Before this was handled, the operator
/// saw `sign-in failed (invalid_grant)`, which does
/// not tell them the one thing they need to do — ask for a new code.
#[tokio::test]
async fn an_expired_code_tells_the_operator_to_get_a_new_one() {
    for provider_error in ["expired_token", "invalid_grant"] {
        let server = MockServer::start().await;
        mount_discovery(&server, true).await;
        mount_device_auth(&server).await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": provider_error
            })))
            .mount(&server)
            .await;

        let state = TempDir::new().unwrap();
        arcana(&server, &state)
            .timeout(std::time::Duration::from_secs(60))
            .assert()
            .failure()
            .stderr(predicate::str::contains("expired or was already used"))
            .stderr(predicate::str::contains("again"));

        assert!(!state.path().join("arcana/credentials.json").exists());
    }
}

/// A success envelope carrying no token is a failure, not a success —
/// the control-plane-green/data-plane-dead trap.
#[tokio::test]
async fn a_success_envelope_without_a_token_is_a_failure() {
    let server = MockServer::start().await;
    mount_discovery(&server, true).await;
    mount_device_auth(&server).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let state = TempDir::new().unwrap();
    arcana(&server, &state)
        .timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stderr(predicate::str::contains("no access token"));

    assert!(!state.path().join("arcana/credentials.json").exists());
}
