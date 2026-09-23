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
use arcana_core::connector::{
    ConnectorError, ExecuteRequest, FirstDispatchMeasurementV0, ModelConnector, PromptVariantV0,
};
use serde_json::json;
use url::Url;
use wiremock::matchers::{body_json, method, path};
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

fn observation_body() -> serde_json::Value {
    json!({
        "version": "first-dispatch-observation/v0",
        "observationId": "00000000-0000-4000-8000-000000000001",
        "authorization": "NOT_AUTHORIZED",
        "evidenceStatus": "PERSISTED_PRE_ADAPTER_OBSERVATION",
        "usage": {"source": "CONNECTOR_RESPONSE_UNVERIFIED"},
        "receiptDigestSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
async fn opted_in_first_dispatch_context_reaches_the_exact_http_boundary() {
    let server = MockServer::start().await;
    let mut response = success_body();
    response["firstDispatchObservation"] = observation_body();
    Mock::given(method("POST"))
        .and(path("/execute"))
        .and(body_json(json!({
            "connector": "claude-code",
            "prompt": "ping",
            // The client's default model budget travels with every request.
            "timeout": 120_000,
            "firstDispatchMeasurement": {
                "version": "first-dispatch-measurement/v0",
                "corpusId": "corpus-v0",
                "caseId": "case-007",
                "roleId": "developer",
                "taskClassId": "code-change",
                "commandId": "implement",
                "replayIndex": 1,
                "variant": "baseline",
                "adapterBoundary": "arcana-agent-system/driver/first-dispatch-v0"
            }
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(response))
        .mount(&server)
        .await;

    let mut request = ping();
    request.first_dispatch_measurement = Some(
        FirstDispatchMeasurementV0::try_new(
            "corpus-v0",
            "case-007",
            "developer",
            "code-change",
            "implement",
            1,
            PromptVariantV0::Baseline,
        )
        .expect("valid measurement context"),
    );

    let response = client_for(&server)
        .execute(request)
        .await
        .expect("the exact request body must match the first-dispatch contract");
    let observation = response
        .first_dispatch_observation
        .expect("the originating caller must retain the correlation receipt");
    assert_eq!(
        observation.observation_id(),
        Some("00000000-0000-4000-8000-000000000001")
    );
    assert_eq!(
        observation.receipt_digest_sha256(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[tokio::test]
async fn case_b_http_503_logical_error_retains_observation() {
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
        },
        "firstDispatchObservation": observation_body()
    });
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(503).set_body_json(body))
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::Logical {
            http_status,
            kind,
            retryable,
            recommendation,
            first_dispatch_observation,
            ..
        }) => {
            assert_eq!(http_status, 503);
            assert_eq!(kind, "circuit_open");
            assert!(!retryable);
            assert_eq!(recommendation, "wait");
            assert_eq!(
                first_dispatch_observation
                    .as_ref()
                    .and_then(|observation| observation.observation_id()),
                Some("00000000-0000-4000-8000-000000000001")
            );
        }
        other => panic!("expected ConnectorError::Logical, got {other:?}"),
    }
}

#[tokio::test]
async fn http_429_logical_error_retains_status_and_observation() {
    let server = MockServer::start().await;
    let body = json!({
        "id": "00000000-0000-0000-0000-000000000000",
        "connector": "openrouter",
        "model": "bounded-model",
        "result": "",
        "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0, "costUsd": 0.0},
        "latencyMs": 12,
        "status": "rate_limited",
        "error": {
            "type": "rate_limited",
            "message": "try later",
            "retryable": true,
            "recommendation": "wait",
            "retryAfter": 5
        },
        "firstDispatchObservation": observation_body()
    });
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(429).set_body_json(body))
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::Logical {
            http_status,
            kind,
            retry_after,
            first_dispatch_observation,
            ..
        }) => {
            assert_eq!(http_status, 429);
            assert_eq!(kind, "rate_limited");
            assert_eq!(retry_after, Some(5));
            assert_eq!(
                first_dispatch_observation
                    .as_ref()
                    .and_then(|observation| observation.observation_id()),
                Some("00000000-0000-4000-8000-000000000001")
            );
        }
        other => panic!("expected ConnectorError::Logical, got {other:?}"),
    }
}

#[tokio::test]
async fn http_201_timeout_retains_observation() {
    let server = MockServer::start().await;
    let mut body = success_body();
    body["status"] = json!("timeout");
    body["result"] = json!("");
    body["error"] = json!({
        "type": "timeout",
        "message": "provider timed out",
        "retryable": true,
        "recommendation": "retry"
    });
    body["firstDispatchObservation"] = observation_body();
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(201).set_body_json(body))
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::Logical {
            http_status,
            kind,
            first_dispatch_observation,
            ..
        }) => {
            assert_eq!(http_status, 201);
            assert_eq!(kind, "timeout");
            assert!(first_dispatch_observation.is_some());
        }
        other => panic!("expected timeout Logical error, got {other:?}"),
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

#[tokio::test]
async fn http_201_unknown_envelope_status_fails_closed() {
    let server = MockServer::start().await;
    let mut body = success_body();
    body["status"] = json!("pending");
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(201).set_body_json(body))
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::UnexpectedEnvelopeStatus) => {}
        other => panic!("expected UnexpectedEnvelopeStatus, got {other:?}"),
    }
}

#[tokio::test]
async fn http_429_unknown_envelope_status_fails_closed_without_body_fallback() {
    let server = MockServer::start().await;
    let mut body = success_body();
    body["status"] = json!("pending");
    body["result"] = json!("secret-model-output-sentinel");
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(429).set_body_json(body))
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::UnexpectedEnvelopeStatus) => {}
        other => panic!("expected UnexpectedEnvelopeStatus, got {other:?}"),
    }
}

/// A malformed body is reported as a bounded excerpt, not as a bare byte
/// count and not as upstream text taken at face value.
///
/// This assertion used to be the opposite — the body was never copied at all,
/// on the grounds that it may be model output. A2-202 narrowed that rule
/// rather than keeping it: the same redaction hid the one line that said which
/// request field Model Connector had rejected, so a whole class of 400s became
/// undiagnosable. The excerpt is bounded to 200 bytes and stripped of control
/// characters (see `model_connector_error_body_excerpt.rs`); the headline
/// still names it as non-contract, so nothing downstream reads it as contract
/// text.
#[tokio::test]
async fn malformed_error_body_is_reported_as_a_bounded_excerpt() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(502).set_body_string("secret-model-output-sentinel"))
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::Http {
            status, message, ..
        }) => {
            assert_eq!(status, 502);
            assert_eq!(
                message,
                "upstream returned a non-contract error body (28 bytes): \
                 secret-model-output-sentinel"
            );
        }
        other => panic!("expected ConnectorError::Http, got {other:?}"),
    }
}

#[tokio::test]
async fn partial_json_error_body_is_never_treated_as_a_nest_exception() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(
            ResponseTemplate::new(502)
                .set_body_json(json!({ "message": "secret-model-output-sentinel" })),
        )
        .mount(&server)
        .await;

    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::Http {
            status, message, ..
        }) => {
            assert_eq!(status, 502);
            assert!(
                message.starts_with("upstream returned a non-contract error body ("),
                "a partial envelope stays labelled non-contract: {message}"
            );
            assert!(
                !message.starts_with("secret-model-output-sentinel"),
                "its `message` field is never promoted to the error headline: {message}"
            );
        }
        other => panic!("expected redacted ConnectorError::Http, got {other:?}"),
    }
}

// --- the model budget on the wire (A2-203) ---------------------------------
//
// Measured 2026-09-23 against the production Model Connector: a `/execute`
// without a `timeout` field is given the connector's own default — 30 s for
// deepseek — and retried once, so a long turn dies server-side however patient
// the client is. The budget is therefore part of the request, not only a
// property of the HTTP client.

/// The request body a mock recorded, for assertions on single fields.
async fn recorded_body(server: &MockServer) -> serde_json::Value {
    let requests = server.received_requests().await.expect("requests recorded");
    assert_eq!(requests.len(), 1, "exactly one dispatch");
    serde_json::from_slice(&requests[0].body).expect("request body is JSON")
}

#[tokio::test]
async fn the_default_model_budget_is_stated_on_the_wire() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(201).set_body_json(success_body()))
        .mount(&server)
        .await;

    client_for(&server)
        .execute(ping())
        .await
        .expect("201 is Ok");

    assert_eq!(
        recorded_body(&server).await.get("timeout"),
        Some(&json!(120_000)),
        "the client's default budget must reach the server, or the server \
         silently applies its own 30 s default"
    );
}

#[tokio::test]
async fn the_configured_budget_reaches_the_wire_and_the_client() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(201).set_body_json(success_body()))
        .mount(&server)
        .await;

    let base = Url::parse(&server.uri()).expect("mock uri parses");
    let client = ModelConnectorClient::with_request_timeout(
        base,
        arcana_connectors::model_connector::ApiKey::new("mc-test"),
        std::time::Duration::from_secs(300),
    )
    .expect("client builds");

    assert_eq!(
        client.request_timeout(),
        std::time::Duration::from_secs(300)
    );
    // 60 s queue + two server attempts of 300 s + 10 s backoff.
    assert_eq!(client.http_wait(), std::time::Duration::from_secs(670));

    client.execute(ping()).await.expect("201 is Ok");
    assert_eq!(
        recorded_body(&server).await.get("timeout"),
        Some(&json!(300_000))
    );
}

#[tokio::test]
async fn a_budget_the_caller_stated_is_never_overwritten() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(201).set_body_json(success_body()))
        .mount(&server)
        .await;

    let mut req = ping();
    req.timeout_ms = Some(45_000);
    client_for(&server).execute(req).await.expect("201 is Ok");

    assert_eq!(
        recorded_body(&server).await.get("timeout"),
        Some(&json!(45_000))
    );
}

#[tokio::test]
async fn a_budget_outside_the_upstream_range_is_refused_before_any_request() {
    let base = Url::parse("https://connector.arcanada.ai").expect("url parses");
    let err = ModelConnectorClient::with_request_timeout(
        base,
        arcana_connectors::model_connector::ApiKey::new("mc-test"),
        std::time::Duration::from_secs(900),
    )
    .expect_err("900s is above the 600s the upstream accepts");
    assert!(
        matches!(&err, ConnectorError::Transport(message) if message.contains("600s")),
        "{err}"
    );
}

#[tokio::test]
async fn a_stalled_response_is_a_retryable_timeout_not_a_fatal_transport_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(success_body())
                .set_delay(std::time::Duration::from_secs(30)),
        )
        .mount(&server)
        .await;

    let base = Url::parse(&server.uri()).expect("mock uri parses");
    // A stated wait: the point under test is the classification, and deriving
    // the wait from the minimum budget would make this test take 80 s.
    let client = ModelConnectorClient::with_timeouts(
        base,
        arcana_connectors::model_connector::ApiKey::new("mc-test"),
        std::time::Duration::from_secs(5),
        std::time::Duration::from_millis(250),
    )
    .expect("client builds");

    let err = client
        .execute(ping())
        .await
        .expect_err("a response that never arrives is an error");
    assert!(
        matches!(err, ConnectorError::Timeout(_)),
        "a stall must be Timeout, not {err:?}"
    );
    assert!(
        err.is_transient(),
        "a timeout says nothing about the request and must be retryable"
    );
    assert!(
        err.to_string().contains("timed out after 0s"),
        "the message names the budget the failing client actually had: {err}"
    );
}
