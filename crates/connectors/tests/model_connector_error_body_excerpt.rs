//! ARAS A2-202 — a non-contract upstream error body must say WHY, not only how
//! long it was.
//!
//! Model Connector answers a schema violation with a `ZodValidationPipe`
//! envelope (`{message, errors[], statusCode}`, model-connector
//! `src/common/zod-validation.pipe.ts`). That shape is not the
//! `NestJS` `HttpException` contract this client parses, so it used to be
//! reported as `upstream returned a non-contract error body (91 bytes)` — a
//! byte count where the diagnosis was.
//!
//! The body is untrusted upstream text, so it is echoed under three limits:
//! bounded length, control characters stripped, body only (never headers,
//! never the API key).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_connectors::ModelConnectorClient;
use arcana_core::connector::{ConnectorError, ExecuteRequest, ModelConnector};
use serde_json::json;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

/// Drive one error body through the client and return the `Http` message.
async fn message_for(status: u16, body: ResponseTemplate) -> (u16, String) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/execute"))
        .respond_with(body)
        .mount(&server)
        .await;
    match client_for(&server).execute(ping()).await {
        Err(ConnectorError::Http {
            status: got,
            message,
            ..
        }) => {
            assert_eq!(got, status);
            (got, message)
        }
        other => panic!("expected ConnectorError::Http, got {other:?}"),
    }
}

#[tokio::test]
async fn a_zod_validation_400_tells_the_operator_which_field_was_rejected() {
    // Verbatim shape of the body that killed `arcana run --max-turns 120`.
    let body = json!({
        "message": "Validation failed",
        "errors": ["maxTurns: Too big: expected number to be <=100"],
        "statusCode": 400,
    });
    let (_, message) = message_for(400, ResponseTemplate::new(400).set_body_json(body)).await;

    assert!(
        message.contains("maxTurns"),
        "the rejected field must reach the operator: {message}"
    );
    assert!(
        message.contains("<=100"),
        "the violated bound must reach the operator: {message}"
    );
}

#[tokio::test]
async fn the_excerpt_is_bounded_and_marked_as_truncated() {
    let long = "x".repeat(5_000);
    let (_, message) = message_for(502, ResponseTemplate::new(502).set_body_string(&long)).await;

    assert!(
        message.len() < 320,
        "a 5000-byte body must not be echoed whole ({} chars): {message}",
        message.len()
    );
    assert!(
        message.contains('…'),
        "a truncated excerpt must say so: {message}"
    );
    assert!(
        message.contains("5000 bytes"),
        "the full length stays visible: {message}"
    );
}

#[tokio::test]
async fn control_characters_never_reach_the_operators_terminal() {
    // Newlines, NUL and an ANSI escape sequence: a body that could forge log
    // lines or repaint the terminal if echoed raw.
    let hostile = "line one\n\r\tsecond\u{0}\u{1b}[31mRED";
    let (_, message) = message_for(502, ResponseTemplate::new(502).set_body_string(hostile)).await;

    assert!(
        !message.chars().any(char::is_control),
        "no control character may survive into the message: {message:?}"
    );
    assert!(
        message.contains("line one"),
        "printable text still reaches the operator: {message}"
    );
    assert!(
        message.contains("[31mRED"),
        "only the escape byte is dropped, not the following text: {message}"
    );
}

#[tokio::test]
async fn a_multibyte_body_is_truncated_on_a_character_boundary() {
    // 3-byte characters: a naive byte slice at 200 would split one and panic.
    let body = "ы".repeat(1_000);
    let (_, message) = message_for(502, ResponseTemplate::new(502).set_body_string(&body)).await;
    assert!(message.contains('ы'), "excerpt survives: {message}");
    assert!(message.contains('…'), "and is truncated: {message}");
}

#[tokio::test]
async fn an_empty_body_adds_no_excerpt() {
    let (_, message) = message_for(500, ResponseTemplate::new(500).set_body_string("")).await;
    assert_eq!(
        message,
        "upstream returned a non-contract error body (0 bytes)"
    );
}

#[tokio::test]
async fn the_api_key_is_never_part_of_the_error_message() {
    let (_, message) = message_for(
        400,
        ResponseTemplate::new(400).set_body_string("rejected by upstream"),
    )
    .await;
    assert!(!message.contains("mc-test"), "no credential: {message}");
}
