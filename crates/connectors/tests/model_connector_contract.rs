//! V-AC-18 — contract tests for `ModelConnectorClient::execute` against a
//! mock `POST /execute` endpoint. Four cases pin the HTTP-201 success path, the
//! logical-error path, the upstream 5xx path, and the defensive 200 rejection.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::unreadable_literal
)]

use arcana_connectors::ModelConnectorClient;
use arcana_core::connector::{ConnectorError, ExecuteRequest, ModelConnector};
use serde_json::json;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a client pointed at the mock server. The mock uses http://, so
/// `https_only` is disabled automatically by `new`.
fn client_for(server: &MockServer) -> ModelConnectorClient {
    let base = Url::parse(&server.uri()).expect("mock uri parses");
    ModelConnectorClient::new(
        base,
        arcana_connectors::model_connector::ApiKey::new("mc-test"),
    )
    .expect("client builds")
}

fn ping() -> ExecuteRequest {
    ExecuteRequest::new("claude-code", "ping")
}

fn success_body() -> serde_json::Value {
    json!({
        "id": "5f2a1c9b-3e8d-4c0a-9e7f-1a2b3c4d5e6f",
        "connector": "claude-code",
        "model": "sonnet-4.6",
        "result": "pong",
        "usage": {"inputTokens": 4, "outputTokens": 1, "totalTokens": 5, "costUsd": 0.0000123},
        "latencyMs": 187,
        "status": "success"
    })
}

#[tokio::test]
async fn case_a_http_201_success_returns_ok() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(201).set_body_json(success_body()))
        .mount(&server)
        .await;

    let resp = client_for(&server)
        .execute(ping())
        .await
        .expect("201 success must be Ok");
    assert_eq!(resp.status, "success");
    assert_eq!(resp.result, "pong");
    assert_eq!(resp.usage.total_tokens, 5);
}

#[tokio::test]
async fn case_b_http_201_logical_error_returns_err_logical() {
    let server = MockServer::start().await;
    let body = json!({
        "id": "00000000-0000-0000-0000-000000000000",
        "connector": "claude-code",
        "model": "sonnet-4.6",
        "result": "",
        "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0, "costUsd": 0.0},
        "latencyMs": 12,
        "status": "error",
        "error": {
            "type": "circuit_open",
            "message": "circuit breaker open for claude-code/sonnet-4.6",
            "retryable": false,
            "recommendation": "wait"
        }
    });
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(201).set_body_json(body))
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::Logical {
            kind,
            retryable,
            recommendation,
            ..
        }) => {
            assert_eq!(kind, "circuit_open");
            assert!(!retryable);
            assert_eq!(recommendation, "wait");
        }
        other => panic!("expected ConnectorError::Logical, got {other:?}"),
    }
}

#[tokio::test]
async fn case_c_http_503_returns_err_http() {
    let server = MockServer::start().await;
    let body = json!({
        "message": "all upstream providers unavailable",
        "error": "Service Unavailable",
        "statusCode": 503
    });
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(503).set_body_json(body))
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::Http {
            status, message, ..
        }) => {
            assert_eq!(status, 503);
            assert_eq!(message, "all upstream providers unavailable");
        }
        other => panic!("expected ConnectorError::Http{{503}}, got {other:?}"),
    }
}

#[tokio::test]
async fn case_d_http_200_returns_err_unexpected_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(200).set_body_json(success_body()))
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::UnexpectedStatus(200)) => {}
        other => panic!("expected UnexpectedStatus(200), got {other:?}"),
    }
}
