//! V-AC-21 — contract tests for `OpsBotClient::emit` against a mock
//! `POST /events` endpoint. Three cases pin the fail-soft no-token path (zero
//! HTTP calls, `Ok(())`), the authenticated success path (body shape +
//! bearer auth), and the authenticated-but-rejected error path (401 must
//! surface as `Err`, never be swallowed).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::unreadable_literal
)]

use arcana_connectors::model_connector::ApiKey;
use arcana_connectors::ops_bot::{EventCategory, OpsBotClient, OpsBotError};
use serde_json::json;
use url::Url;
use wiremock::matchers::{bearer_token, body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn base_url(server: &MockServer) -> Url {
    Url::parse(&server.uri()).expect("mock uri parses")
}

#[tokio::test]
async fn fail_soft_without_token_makes_zero_requests_and_returns_ok() {
    let server = MockServer::start().await;
    // expect(0): if `emit` makes any HTTP call in the no-token path, this
    // mock's verification (run on `MockServer` drop) fails the test.
    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let client = OpsBotClient::new(base_url(&server), None).expect("client builds");

    let result = client
        .emit(EventCategory::ToolInvocation, json!({"tool": "bash"}))
        .await;

    assert!(
        result.is_ok(),
        "fail-soft path must return Ok, got {result:?}"
    );
}

#[tokio::test]
async fn success_path_posts_bearer_auth_and_category_payload() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/events"))
        .and(bearer_token("ops-test-token"))
        .and(body_json(json!({
            "category": "cost_threshold",
            "payload": {"amount_usd": 12.5}
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = OpsBotClient::new(base_url(&server), Some(ApiKey::new("ops-test-token")))
        .expect("client builds");

    let result = client
        .emit(EventCategory::CostThreshold, json!({"amount_usd": 12.5}))
        .await;

    assert!(
        result.is_ok(),
        "success path must return Ok, got {result:?}"
    );
}

#[tokio::test]
async fn error_path_401_surfaces_as_err_never_swallowed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "invalid token",
            "error": "Unauthorized",
            "statusCode": 401
        })))
        .mount(&server)
        .await;

    let client = OpsBotClient::new(base_url(&server), Some(ApiKey::new("bad-token")))
        .expect("client builds");

    match client
        .emit(EventCategory::PermissionDenied, json!({}))
        .await
    {
        Err(OpsBotError::Http { status, message }) => {
            assert_eq!(status, 401);
            assert_eq!(message, "invalid token");
        }
        other => panic!("expected OpsBotError::Http{{401}}, got {other:?}"),
    }
}
