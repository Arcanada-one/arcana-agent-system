#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::sync::Arc;

use arcana_connectors::auth_arcana::{
    AuthTokenError, BearerTokenProvider, ClientCredentialsConfig, ClientCredentialsTokenProvider,
};
use secrecy::ExposeSecret;
use tempfile::tempdir;
use url::Url;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn config(server: &MockServer, secret_file: std::path::PathBuf) -> ClientCredentialsConfig {
    ClientCredentialsConfig {
        token_url: Url::parse(&format!("{}/oidc/token", server.uri())).unwrap(),
        client_id: "arcana-agent-kb-reader".into(),
        secret_file,
        resource: "urn:arcanada:scrutator:ltm".into(),
        scope: "kb:ltm.read".into(),
        refresh_margin_seconds: 30,
    }
}

fn secure_secret_file(value: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let path = dir.path().join("reader-secret");
    fs::write(&path, value).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    (dir, path)
}

#[tokio::test]
async fn mints_exact_client_credentials_profile_and_caches_singleflight() {
    let server = MockServer::start().await;
    let (_dir, secret_file) = secure_secret_file("super-secret-value");
    Mock::given(method("POST"))
        .and(path("/oidc/token"))
        .and(header(
            "authorization",
            "Basic YXJjYW5hLWFnZW50LWtiLXJlYWRlcjpzdXBlci1zZWNyZXQtdmFsdWU=",
        ))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("scope=kb%3Altm.read"))
        .and(body_string_contains(
            "resource=urn%3Aarcanada%3Ascrutator%3Altm",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "signed-jwt",
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": "kb:ltm.read"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        Arc::new(ClientCredentialsTokenProvider::new(config(&server, secret_file)).unwrap());
    let (first, second) = tokio::join!(provider.bearer_token(), provider.bearer_token());

    assert_eq!(first.unwrap().expose_secret(), "signed-jwt");
    assert_eq!(second.unwrap().expose_secret(), "signed-jwt");
}

#[tokio::test]
async fn rejects_insecure_secret_file_before_network() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    let (_dir, secret_file) = secure_secret_file("never-send-me");
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o644)).unwrap();
    let provider = ClientCredentialsTokenProvider::new(config(&server, secret_file)).unwrap();

    assert!(matches!(
        provider.bearer_token().await,
        Err(AuthTokenError::SecretFilePermissions { .. })
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_symlinked_secret_file_before_network() {
    use std::os::unix::fs::symlink;

    let server = MockServer::start().await;
    let (dir, real_file) = secure_secret_file("never-send-me");
    let link = dir.path().join("reader-secret-link");
    symlink(real_file, &link).unwrap();
    let provider = ClientCredentialsTokenProvider::new(config(&server, link)).unwrap();

    assert!(matches!(
        provider.bearer_token().await,
        Err(AuthTokenError::SecretFileType)
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn endpoint_failure_never_echoes_client_secret() {
    let server = MockServer::start().await;
    let (_dir, secret_file) = secure_secret_file("must-not-appear-in-errors");
    Mock::given(method("POST"))
        .and(path("/oidc/token"))
        .respond_with(
            ResponseTemplate::new(401).set_body_string("reflected must-not-appear-in-errors"),
        )
        .mount(&server)
        .await;
    let provider = ClientCredentialsTokenProvider::new(config(&server, secret_file)).unwrap();

    let rendered = provider.bearer_token().await.unwrap_err().to_string();
    assert!(!rendered.contains("must-not-appear-in-errors"));
    assert!(rendered.contains("HTTP 401"));
}

#[tokio::test]
async fn token_mint_does_not_follow_redirects() {
    let source = MockServer::start().await;
    let target = MockServer::start().await;
    let (_dir, secret_file) = secure_secret_file("never-forward-me");
    Mock::given(method("POST"))
        .and(path("/oidc/token"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/oidc/token", target.uri())),
        )
        .mount(&source)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "redirected-token",
            "token_type": "Bearer",
            "expires_in": 300
        })))
        .mount(&target)
        .await;
    let provider = ClientCredentialsTokenProvider::new(config(&source, secret_file)).unwrap();

    assert!(matches!(
        provider.bearer_token().await,
        Err(AuthTokenError::EndpointStatus(307))
    ));
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[test]
fn production_config_rejects_unapproved_https_token_endpoint() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var(
        "ARCANA_AUTH_TOKEN_URL",
        "https://other.example.test/oidc/token",
    );
    std::env::set_var("ARCANA_KB_CLIENT_SECRET_FILE", "/tmp/unused-reader-secret");
    let result = ClientCredentialsConfig::from_env();
    std::env::remove_var("ARCANA_AUTH_TOKEN_URL");
    std::env::remove_var("ARCANA_KB_CLIENT_SECRET_FILE");
    assert!(
        result.is_err(),
        "production config accepted an arbitrary HTTPS endpoint"
    );
}
