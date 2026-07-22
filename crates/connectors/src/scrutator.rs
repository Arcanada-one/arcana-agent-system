//! `ScrutatorClient` — thin `reqwest` wrapper around Scrutator's hybrid
//! search endpoint (`POST /v1/search`).
//!
//! The request/response shapes mirror the upstream Pydantic model
//! `scrutator.db.models.SearchRequest` verbatim. Per SRCH-0031 there is no
//! rerank parameter on `/v1/search` — this client does not add one; it
//! forwards the hybrid-search contract as-is.

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::auth_arcana::{AuthTokenError, BearerTokenProvider, ClientCredentialsTokenProvider};

/// Default Scrutator mesh endpoint (Tailscale-only, host `arcana-kb`).
/// Confirmed live 2026-07 — do not point at the retired `arcana-db`
/// hostname.
const DEFAULT_BASE_URL: &str = "http://100.70.137.104:8310";
const ENV_BASE_URL: &str = "ARCANA_SCRUTATOR_URL";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Request body for `POST /v1/search`. Field names and defaults mirror
/// `scrutator.db.models.SearchRequest`; only `query` is required.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SearchQuery {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_content: Option<bool>,
}

impl SearchQuery {
    /// Minimal query: just the search string, all optionals unset (server
    /// applies its own defaults: `limit=10`, `min_score=0.0`,
    /// `include_content=true`).
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            namespace: None,
            project: None,
            source_type: None,
            limit: None,
            min_score: None,
            include_content: None,
        }
    }
}

/// One hybrid-search hit.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SearchHit {
    pub chunk_id: String,
    #[serde(default)]
    pub content: String,
    pub source_path: String,
    pub source_type: String,
    pub chunk_index: i64,
    pub score: f64,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

/// `POST /v1/search` response envelope.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct SearchResponse {
    #[serde(default)]
    pub results: Vec<SearchHit>,
}

/// Every way a `/v1/search` call can fail.
#[derive(Debug, thiserror::Error)]
pub enum ScrutatorError {
    /// Dedicated reader credential setup or refresh failed.
    #[error("authentication failed: {0}")]
    Authentication(#[from] AuthTokenError),
    /// Transport-level failure (DNS, TLS, connect, timeout, body read).
    #[error("transport error: {0}")]
    Transport(String),
    /// Upstream returned a non-2xx status.
    #[error("HTTP {status}: {message}")]
    Http { status: u16, message: String },
    /// Body was not the JSON shape expected for a successful response.
    #[error("upstream returned non-JSON body (content-type: {content_type:?}, {bytes} bytes)")]
    UpstreamNonJson {
        content_type: Option<String>,
        bytes: usize,
    },
}

/// HTTP client for the Scrutator `POST /v1/search` endpoint.
pub struct ScrutatorClient {
    http: reqwest::Client,
    base_url: Url,
    token_provider: Arc<dyn BearerTokenProvider>,
}

impl std::fmt::Debug for ScrutatorClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScrutatorClient")
            .field("base_url", &self.base_url)
            .field("token_provider", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ScrutatorClient {
    /// Build a client from `ARCANA_SCRUTATOR_URL` (falls back to the
    /// default mesh endpoint when unset or blank — the endpoint is
    /// Tailscale-only and has no API key in Phase 1).
    ///
    /// # Errors
    /// Returns [`ScrutatorError::Transport`] if the resolved base URL fails
    /// to parse or the underlying `reqwest` client fails to build.
    pub fn try_from_env() -> Result<Self, ScrutatorError> {
        let base_url = Self::base_url_from_env()?;
        let token_provider = ClientCredentialsTokenProvider::try_from_env()?;
        Self::new(base_url, token_provider)
    }

    fn base_url_from_env() -> Result<Url, ScrutatorError> {
        let raw = std::env::var(ENV_BASE_URL).unwrap_or_default();
        let raw = if raw.trim().is_empty() {
            DEFAULT_BASE_URL.to_owned()
        } else {
            raw
        };
        let base_url =
            Url::parse(&raw).map_err(|err| ScrutatorError::Transport(err.to_string()))?;
        let approved = Url::parse(DEFAULT_BASE_URL)
            .map_err(|err| ScrutatorError::Transport(err.to_string()))?;
        if base_url != approved {
            return Err(ScrutatorError::Transport(
                "production Scrutator base URL is not approved".into(),
            ));
        }
        Ok(base_url)
    }

    /// Build a client with an explicit base `URL` (used by tests and any
    /// non-default deployment).
    ///
    /// # Errors
    /// Returns [`ScrutatorError::Transport`] if the underlying `reqwest`
    /// client fails to build.
    pub fn new(
        base_url: Url,
        token_provider: Arc<dyn BearerTokenProvider>,
    ) -> Result<Self, ScrutatorError> {
        validate_base_url(&base_url)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("arcana/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| ScrutatorError::Transport(err.to_string()))?;
        Ok(Self {
            http,
            base_url,
            token_provider,
        })
    }

    fn search_url(&self) -> Result<Url, ScrutatorError> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| ScrutatorError::Transport("base URL cannot be a base".into()))?
            .push("v1")
            .push("search");
        Ok(url)
    }

    /// Execute one hybrid-search request against `POST /v1/search`.
    ///
    /// # Errors
    /// Transport, HTTP-status, and decode failures map to
    /// [`ScrutatorError`].
    pub async fn search(&self, query: &SearchQuery) -> Result<SearchResponse, ScrutatorError> {
        let url = self.search_url()?;
        let mut refreshed = false;
        let resp = loop {
            let token = self.token_provider.bearer_token().await?;
            let response = self
                .http
                .post(url.clone())
                .header(reqwest::header::ACCEPT, "application/json")
                .bearer_auth(token.expose_secret())
                .json(query)
                .send()
                .await
                .map_err(|err| ScrutatorError::Transport(format!("POST {url}: {err}")))?;
            if response.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {
                self.token_provider.invalidate().await;
                refreshed = true;
                continue;
            }
            break response;
        };

        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = resp
            .bytes()
            .await
            .map_err(|err| ScrutatorError::Transport(format!("body: {err}")))?;

        if status.is_success() {
            return serde_json::from_slice(&bytes).map_err(|_| ScrutatorError::UpstreamNonJson {
                content_type,
                bytes: bytes.len(),
            });
        }

        let message = serde_json::from_slice::<ErrorEnvelope>(&bytes)
            .ok()
            .map(|env| env.detail_or_message())
            .filter(|msg| !msg.is_empty())
            .unwrap_or_else(|| String::from_utf8_lossy(&bytes).trim().to_owned());
        Err(ScrutatorError::Http {
            status: status.as_u16(),
            message,
        })
    }
}

fn validate_base_url(base_url: &Url) -> Result<(), ScrutatorError> {
    let host = base_url
        .host_str()
        .ok_or_else(|| ScrutatorError::Transport("Scrutator base URL has no host".into()))?;
    let has_credentials = !base_url.username().is_empty() || base_url.password().is_some();
    if has_credentials || base_url.query().is_some() || base_url.fragment().is_some() {
        return Err(ScrutatorError::Transport(
            "Scrutator base URL must not contain credentials, query, or fragment".into(),
        ));
    }

    let loopback = match base_url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    let exact_mesh = host == "100.70.137.104"
        && base_url.port_or_known_default() == Some(8310)
        && base_url.path() == "/";
    if base_url.scheme() == "https" || (base_url.scheme() == "http" && (loopback || exact_mesh)) {
        return Ok(());
    }

    Err(ScrutatorError::Transport(
        "Scrutator base URL must use HTTPS, loopback HTTP, or the approved mesh endpoint".into(),
    ))
}

/// FastAPI-style validation error envelope: `{"detail": ...}`, where
/// `detail` is either a plain string or a structured list of field errors.
/// Falls back to the raw body text when the shape doesn't match.
#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    #[serde(default)]
    detail: Option<Value>,
}

impl ErrorEnvelope {
    fn detail_or_message(&self) -> String {
        match &self.detail {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct TestToken;

    #[async_trait::async_trait]
    impl BearerTokenProvider for TestToken {
        async fn bearer_token(&self) -> Result<secrecy::SecretString, AuthTokenError> {
            Ok(secrecy::SecretString::from("test-token"))
        }
    }

    fn test_provider() -> Arc<dyn BearerTokenProvider> {
        Arc::new(TestToken)
    }

    #[test]
    fn search_query_new_leaves_optionals_unset() {
        let query = SearchQuery::new("hello world");
        let json = serde_json::to_value(&query).expect("serialize");
        assert_eq!(json["query"], "hello world");
        assert!(json.get("namespace").is_none());
        assert!(json.get("limit").is_none());
        assert!(json.get("min_score").is_none());
        assert!(json.get("include_content").is_none());
    }

    #[test]
    fn search_url_appends_v1_search_segments() {
        let client = ScrutatorClient::new(
            Url::parse("http://100.70.137.104:8310").unwrap(),
            test_provider(),
        )
        .expect("client builds");
        assert_eq!(
            client.search_url().unwrap().as_str(),
            "http://100.70.137.104:8310/v1/search"
        );
    }

    #[test]
    fn try_from_env_falls_back_to_default_mesh_url_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: single-threaded within this test's own assertions; the var
        // is scoped to this crate's tests only (mirrors the existing
        // `model_connector` convention for env-based construction tests).
        std::env::remove_var(ENV_BASE_URL);
        let base_url = ScrutatorClient::base_url_from_env().expect("default URL resolves");
        assert_eq!(base_url.as_str(), "http://100.70.137.104:8310/");
    }

    #[test]
    fn try_from_env_rejects_nonproduction_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_BASE_URL, "https://other.example.test");
        let result = ScrutatorClient::base_url_from_env();
        std::env::remove_var(ENV_BASE_URL);
        assert!(result.is_err(), "production constructor accepted override");
    }

    #[test]
    fn search_response_default_is_empty_results() {
        let empty: SearchResponse = serde_json::from_value(serde_json::json!({ "results": [] }))
            .expect("deserialize empty results");
        assert!(empty.results.is_empty());
    }
}
