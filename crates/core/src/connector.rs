//! Model-connector contract: the `ModelConnector` trait plus the request /
//! response DTOs and error type shared across the agent loop.
//!
//! The agent loop (`crates/core`) depends only on this abstraction, never on a
//! concrete HTTP client. Concrete implementations live in `crates/connectors`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A connector that executes a single unary request against an upstream model
/// router and returns a fully-formed response.
///
/// Phase 1 is request/response only — there is no streaming surface, because
/// the upstream endpoint is unary JSON (`POST /execute` → HTTP 201).
#[async_trait]
pub trait ModelConnector: Send + Sync {
    /// Execute one request. Transport, HTTP-status, and decode failures map to
    /// [`ConnectorError`]; an upstream logical error (HTTP 201 with
    /// `status: "error"`) also maps to [`ConnectorError::Logical`].
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError>;
}

/// Request body for `POST /execute`.
///
/// Field names mirror the upstream Zod schema; camelCase wire names are pinned
/// with explicit `rename` so the Rust `snake_case` API is independent of the
/// wire contract.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ExecuteRequest {
    /// Connector id, e.g. `"claude-code"`. Required.
    pub connector: String,
    /// The prompt — a bare string in Phase 1.
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "systemPrompt")]
    pub system_prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "maxTurns")]
    pub max_turns: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "maxBudgetUsd")]
    pub max_budget_usd: Option<f64>,
}

impl ExecuteRequest {
    /// Minimal request: connector id + prompt, all optionals unset.
    #[must_use]
    pub fn new(connector: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            prompt: prompt.into(),
            model: None,
            system_prompt: None,
            max_turns: None,
            max_budget_usd: None,
        }
    }
}

/// Success body returned on HTTP 201. `status` is `"success"` or `"error"`;
/// the latter is a logical error surfaced by the caller as
/// [`ConnectorError::Logical`], so a `ConnectorResponse` in hand always means
/// `status == "success"`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ConnectorResponse {
    pub id: String,
    pub connector: String,
    pub model: String,
    pub result: String,
    pub usage: Usage,
    #[serde(rename = "latencyMs")]
    pub latency_ms: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<LogicalError>,
}

/// Token / cost accounting attached to every response.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Usage {
    #[serde(rename = "inputTokens")]
    pub input_tokens: u64,
    #[serde(rename = "outputTokens")]
    pub output_tokens: u64,
    #[serde(rename = "totalTokens")]
    pub total_tokens: u64,
    #[serde(rename = "costUsd")]
    pub cost_usd: f64,
}

/// Logical-error payload carried inside a 201 response whose `status` is
/// `"error"` (e.g. an open circuit breaker upstream).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LogicalError {
    #[serde(rename = "type")]
    pub kind: String,
    pub message: String,
    pub retryable: bool,
    pub recommendation: String,
    #[serde(rename = "retryAfter", skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

/// Every way a connector call can fail. Phase 1 does not retry — pressure
/// signals (`429`, logical `retryable`) are propagated to the agent loop.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// `ARCANA_MC_TOKEN` is unset or empty.
    #[error("missing API key (set ARCANA_MC_TOKEN)")]
    MissingApiKey,
    /// Transport-level failure (DNS, TLS, connect, timeout, body read).
    #[error("transport error: {0}")]
    Transport(String),
    /// Upstream returned a 4xx/5xx `NestJS` exception envelope.
    #[error("HTTP {status}: {message}")]
    Http {
        status: u16,
        message: String,
        retry_after: Option<u64>,
    },
    /// Body was not the JSON shape we expect for the given status.
    #[error("upstream returned non-JSON body (content-type: {content_type:?}, {bytes} bytes)")]
    UpstreamNonJson {
        content_type: Option<String>,
        bytes: usize,
    },
    /// HTTP status other than 201 on the success path (e.g. a stray 200).
    #[error("unexpected HTTP status {0} (expected 201)")]
    UnexpectedStatus(u16),
    /// HTTP 201 with `status: "error"` — an application-level failure.
    #[error("upstream logical error [{kind}]: {message}")]
    Logical {
        kind: String,
        message: String,
        retryable: bool,
        recommendation: String,
        retry_after: Option<u64>,
    },
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal
)]
mod tests {
    use super::*;

    #[test]
    fn execute_request_omits_unset_optionals() {
        let req = ExecuteRequest::new("claude-code", "ping");
        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["connector"], "claude-code");
        assert_eq!(json["prompt"], "ping");
        assert!(json.get("model").is_none(), "unset optional must be absent");
        assert!(json.get("systemPrompt").is_none());
        assert!(json.get("maxTurns").is_none());
    }

    #[test]
    fn execute_request_renames_camel_case_wire_fields() {
        let mut req = ExecuteRequest::new("claude-code", "ping");
        req.system_prompt = Some("be terse".into());
        req.max_turns = Some(3);
        req.max_budget_usd = Some(0.5);
        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["systemPrompt"], "be terse");
        assert_eq!(json["maxTurns"], 3);
        assert_eq!(json["maxBudgetUsd"], 0.5);
    }

    #[test]
    fn connector_response_round_trips() {
        let raw = serde_json::json!({
            "id": "5f2a1c9b-3e8d-4c0a-9e7f-1a2b3c4d5e6f",
            "connector": "claude-code",
            "model": "sonnet-4.6",
            "result": "pong",
            "usage": {
                "inputTokens": 4, "outputTokens": 1, "totalTokens": 5, "costUsd": 0.0000123
            },
            "latencyMs": 187,
            "status": "success"
        });
        let parsed: ConnectorResponse =
            serde_json::from_value(raw.clone()).expect("deserialize canonical success");
        assert_eq!(parsed.status, "success");
        assert_eq!(parsed.result, "pong");
        assert_eq!(parsed.usage.total_tokens, 5);
        assert_eq!(parsed.latency_ms, 187);
        assert!(parsed.error.is_none());
        let reser = serde_json::to_value(&parsed).expect("serialize back");
        assert_eq!(reser["latencyMs"], 187);
        assert_eq!(reser["usage"]["totalTokens"], 5);
    }

    #[test]
    fn connector_response_parses_logical_error_payload() {
        let raw = serde_json::json!({
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
        let parsed: ConnectorResponse =
            serde_json::from_value(raw).expect("deserialize logical-error envelope");
        assert_eq!(parsed.status, "error");
        let err = parsed.error.expect("error payload present");
        assert_eq!(err.kind, "circuit_open");
        assert!(!err.retryable);
        assert_eq!(err.recommendation, "wait");
    }
}
