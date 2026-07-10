//! `WebFetchTool` — HTTP GET with size cap, timeout, content-type filter,
//! and host allowlist enforcement.
//!
//! ## Host allowlist precedence
//!
//! 1. If the tool was constructed via [`WebFetchTool::with_rules`], every
//!    call is routed through [`RuleLayer::evaluate`] under the `webfetch`
//!    tool name first. A [`LayerDecision::Deny`] short-circuits `execute`
//!    with [`ToolError::PermissionDenied`] *before* any HTTP request is
//!    made. `Allow`, `Defer`, and `ReplaceInput` all let the fetch proceed
//!    (this tool does not currently consume a replaced payload).
//! 2. Only when no `RuleLayer` is configured at all (`WebFetchTool::new()`)
//!    does the tool fall back to the `ARCANA_WEBFETCH_ALLOW_HOSTS`
//!    environment variable: a comma-separated list of regex patterns
//!    matched against the request's host (same `Regex::is_match` semantics
//!    `RuleLayer` uses for `allow_hosts` — a partial/substring match, not a
//!    full-string equality check). A host that matches none of the
//!    patterns is denied.
//! 3. If neither a `RuleLayer` nor the environment variable is present,
//!    behavior is unchanged from before this module gained allowlisting:
//!    no host restriction is applied.
//!
//! The `RuleLayer` path always takes priority; the environment variable is
//! only ever consulted as a standalone fallback for a tool instance that
//! has no rule layer wired in at all.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use arcana_core::permission::{LayerDecision, PermissionLayer, RuleLayer};
use arcana_core::tool::{Tool, ToolError, ToolOutput};
use async_trait::async_trait;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_MAX_BYTES: u64 = 1_048_576;
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Environment variable consulted for the host allowlist fallback when no
/// [`RuleLayer`] is wired into the tool. See the module doc for precedence.
pub const ENV_ALLOW_HOSTS: &str = "ARCANA_WEBFETCH_ALLOW_HOSTS";

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
pub struct WebFetchTool {
    rules: Option<Arc<RuleLayer>>,
}

impl WebFetchTool {
    /// Construct a tool with no permission wiring at all. Falls back to the
    /// [`ENV_ALLOW_HOSTS`] environment variable (see module docs); if that
    /// is also unset, no host restriction applies — matches pre-allowlist
    /// behavior.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: None }
    }

    /// Construct a tool that consults `rules` (via `PermissionLayer`,
    /// evaluated as tool `"webfetch"`) before every request. Takes priority
    /// over the environment-variable fallback.
    #[must_use]
    pub fn with_rules(rules: Arc<RuleLayer>) -> Self {
        Self { rules: Some(rules) }
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
        if let Some(rules) = &self.rules {
            match rules.evaluate("webfetch", &input).await {
                LayerDecision::Deny(reason) => return Err(ToolError::PermissionDenied(reason)),
                LayerDecision::Allow | LayerDecision::Defer | LayerDecision::ReplaceInput(_) => {}
            }
        }

        let parsed: WebFetchInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;
        if let Some(method) = parsed.method.as_deref() {
            if method != "GET" {
                return Err(ToolError::InvalidInput(format!(
                    "only GET supported in Phase 1, got {method}"
                )));
            }
        }

        if self.rules.is_none() {
            enforce_env_allow_hosts(&parsed.url)?;
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

/// Standalone fallback gate consulted only when the tool has no
/// [`RuleLayer`] at all. No-op unless [`ENV_ALLOW_HOSTS`] is set.
fn enforce_env_allow_hosts(url: &str) -> Result<(), ToolError> {
    let Ok(raw) = env::var(ENV_ALLOW_HOSTS) else {
        return Ok(());
    };
    let patterns = compile_allow_host_patterns(&raw)?;
    if patterns.is_empty() {
        return Ok(());
    }
    let host = extract_host(url)
        .ok_or_else(|| ToolError::InvalidInput(format!("could not parse host from url `{url}`")))?;
    if patterns.iter().any(|re| re.is_match(&host)) {
        Ok(())
    } else {
        Err(ToolError::PermissionDenied(format!(
            "host `{host}` does not match any {ENV_ALLOW_HOSTS} pattern"
        )))
    }
}

/// Parses the comma-separated `ARCANA_WEBFETCH_ALLOW_HOSTS` value into
/// compiled regexes. Pure function (no env access) so it is unit-testable
/// without touching process-global state.
fn compile_allow_host_patterns(raw: &str) -> Result<Vec<Regex>, ToolError> {
    raw.split(',')
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .map(|pattern| {
            Regex::new(pattern).map_err(|err| {
                ToolError::InvalidInput(format!(
                    "invalid {ENV_ALLOW_HOSTS} regex `{pattern}`: {err}"
                ))
            })
        })
        .collect()
}

/// Extracts the host component of `url`, mirroring
/// `RuleLayer`'s own host-matching target (host only, no port — see
/// `crates/core/src/permission/rule.rs::extract_host`). Uses `url::Url`
/// rather than hand-rolled string slicing.
fn extract_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_owned))
}
