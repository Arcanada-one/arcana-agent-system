//! `WebFetchTool` — HTTP GET with size cap, timeout, and content-type filter.

use std::time::Duration;

use arcana_core::tool::{Tool, ToolError, ToolOutput};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_MAX_BYTES: u64 = 1_048_576;
const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Deserialize)]
struct WebFetchInput {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

#[derive(Default)]
pub struct WebFetchTool;

impl WebFetchTool {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &'static str {
        "webfetch"
    }

    fn description(&self) -> &'static str {
        "HTTP GET a URL and return text content with size cap."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": { "type": "string", "format": "uri", "minLength": 1 },
                "method": { "type": "string", "enum": ["GET"] },
                "max_bytes": { "type": "integer", "minimum": 1 },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 600 }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, input: Value) -> Result<ToolOutput, ToolError> {
        let parsed: WebFetchInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        if let Some(method) = parsed.method.as_deref() {
            if method != "GET" {
                return Err(ToolError::InvalidInput(format!(
                    "only GET supported in Phase 1, got {method}"
                )));
            }
        }
        let cap = parsed.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
        let timeout = Duration::from_secs(parsed.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECS));

        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|err| ToolError::ExecutionFailed(format!("client build: {err}")))?;

        let response = client
            .get(&parsed.url)
            .send()
            .await
            .map_err(|err| ToolError::ExecutionFailed(format!("GET {}: {err}", parsed.url)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(ToolError::ExecutionFailed(format!(
                "GET {} returned HTTP {}",
                parsed.url, status
            )));
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_default();

        let bytes = response
            .bytes()
            .await
            .map_err(|err| ToolError::ExecutionFailed(format!("body: {err}")))?;

        let received = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if received > cap {
            return Err(ToolError::ExecutionFailed(format!(
                "body {received} bytes exceeds cap {cap}"
            )));
        }

        let body = String::from_utf8_lossy(&bytes).into_owned();

        Ok(ToolOutput {
            content: body,
            metadata: Some(json!({
                "status": status.as_u16(),
                "content_type": content_type,
                "bytes": received
            })),
        })
    }
}
