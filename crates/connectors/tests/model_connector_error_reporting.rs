//! What a failing `POST /execute` actually says to the operator.
//!
//! Every case here is a shape the live Model Connector can return. The
//! assertions are on the rendered `Display` of [`ConnectorError`], because
//! that string is what the CLI prints — a field that is parsed correctly and
//! then never shown is indistinguishable, from the customer's seat, from one
//! that was never parsed at all.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use arcana_connectors::{ApiKey, ModelConnectorClient};
use arcana_core::connector::{ExecuteRequest, ModelConnector};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(base: &str) -> ModelConnectorClient {
    ModelConnectorClient::new(Url::parse(base).unwrap(), ApiKey::new("mc-test")).unwrap()
}

/// A contract-shaped logical-error envelope, as `parse_error_envelope` expects.
fn logical_envelope(
    kind: &str,
    message: &str,
    recommendation: &str,
    retry_after: Option<u64>,
) -> serde_json::Value {
    let mut error = serde_json::json!({
        "type": kind,
        "message": message,
        "retryable": retry_after.is_some(),
        "recommendation": recommendation,
    });
    if let Some(seconds) = retry_after {
        error["retryAfter"] = serde_json::json!(seconds);
    }
    serde_json::json!({
        "id": "req-1",
        "connector": "deepseek",
        "model": "deepseek-v4-flash",
        "result": "",
        "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0, "costUsd": 0.0},
        "latencyMs": 5,
        "status": "error",
        "error": error,
    })
}

async fn execute_against(status: u16, body: serde_json::Value) -> String {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(&server)
        .await;
    client(&server.uri())
        .execute(ExecuteRequest::new("claude-code", "ping"))
        .await
        .expect_err("the stub only returns failures")
        .to_string()
}

#[tokio::test]
async fn out_of_credit_tells_the_customer_where_to_top_up() {
    let rendered = execute_against(
        402,
        logical_envelope(
            "insufficient_credit",
            "Insufficient credit: balance 0.00 USD",
            "Top up your balance at https://billing.arcanada.ai",
            None,
        ),
    )
    .await;
    assert!(
        rendered.contains("Top up your balance at https://billing.arcanada.ai"),
        "the remediation the connector supplied never reached the operator: {rendered}"
    );
    assert!(rendered.contains("Insufficient credit"), "{rendered}");
}

#[tokio::test]
async fn a_rate_limit_reports_how_long_to_wait() {
    let rendered = execute_against(
        429,
        logical_envelope(
            "rate_limited",
            "Rate limit exceeded for deepseek-v4-flash",
            "Retry shortly or pick another model",
            Some(30),
        ),
    )
    .await;
    assert!(
        rendered.contains("Retry after 30s."),
        "retryAfter was parsed and dropped: {rendered}"
    );
}

#[tokio::test]
async fn a_logical_error_on_201_renders_the_same_way_as_on_4xx() {
    // The live connector returns HTTP 201 with `status:"error"` for logical
    // failures; the 4xx form is the other half of the same contract. They must
    // not read differently to the operator.
    let rendered = execute_against(
        201,
        logical_envelope(
            "model_unavailable",
            "Upstream provider is down",
            "Try another model",
            None,
        ),
    )
    .await;
    assert!(rendered.contains("Upstream provider is down"), "{rendered}");
    assert!(rendered.contains("Try another model"), "{rendered}");
}

#[tokio::test]
async fn a_nest_exception_body_surfaces_its_message() {
    let rendered = execute_against(
        500,
        serde_json::json!({
            "message": "Internal server error",
            "error": "Internal Server Error",
            "statusCode": 500,
        }),
    )
    .await;
    assert!(rendered.contains("HTTP 500"), "{rendered}");
    assert!(rendered.contains("Internal server error"), "{rendered}");
}

#[tokio::test]
async fn an_unreachable_connector_names_the_refusal() {
    // Port 1 on loopback refuses immediately. This is the case that used to
    // render identically to a 120-second stall.
    let rendered = client("http://127.0.0.1:1")
        .execute(ExecuteRequest::new("claude-code", "ping"))
        .await
        .expect_err("port 1 must refuse")
        .to_string();
    assert!(rendered.contains("could not connect"), "{rendered}");
    assert!(
        rendered.to_lowercase().contains("refused"),
        "the OS cause was dropped from the chain: {rendered}"
    );
}

#[tokio::test]
async fn a_transport_failure_never_reads_as_a_bare_url() {
    // Regression guard for the exact prior text: eleven words that named no
    // cause at all.
    let rendered = client("http://127.0.0.1:1")
        .execute(ExecuteRequest::new("claude-code", "ping"))
        .await
        .expect_err("port 1 must refuse")
        .to_string();
    assert_ne!(
        rendered,
        "transport error: error sending request for url (http://127.0.0.1:1/execute)"
    );
}
