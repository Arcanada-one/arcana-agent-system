//! `ModelConnectorClient` — `reqwest` implementation of
//! [`arcana_core::connector::ModelConnector`] against the upstream
//! `POST /execute` endpoint (unary JSON, HTTP 201 on success).

use std::time::Duration;

use arcana_core::connector::{ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector};
use async_trait::async_trait;
use url::Url;

const DEFAULT_BASE_URL: &str = "https://connector.arcanada.ai";
const ENV_API_KEY: &str = "ARCANA_MC_TOKEN";
/// Optional base-URL override — lets a smoke harness point the probe at a
/// loopback replay fixture (`http://127.0.0.1:PORT`) without a live mesh.
const ENV_BASE_URL: &str = "ARCANA_MC_BASE_URL";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// An API key wrapper whose `Debug`/`Display` redact the secret so it can never
/// leak into logs or error chains.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    #[must_use]
    pub fn secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(mc-***)")
    }
}

impl std::fmt::Display for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mc-***")
    }
}

/// HTTP client for the Model Connector `POST /execute` endpoint.
#[derive(Debug)]
pub struct ModelConnectorClient {
    http: reqwest::Client,
    base_url: Url,
    api_key: ApiKey,
}

impl ModelConnectorClient {
    /// Build a client from the `ARCANA_MC_TOKEN` env var and the default base
    /// `URL`.
    ///
    /// A non-empty [`ENV_BASE_URL`] is accepted only when it is exactly the
    /// canonical production origin. Loopback replay belongs exclusively to
    /// [`Self::try_from_probe_env`].
    ///
    /// # Errors
    /// Returns [`ConnectorError::MissingApiKey`] if `ARCANA_MC_TOKEN` is unset
    /// or empty, or [`ConnectorError::Transport`] if the base URL fails to
    /// parse or the client fails to build.
    pub fn try_from_env() -> Result<Self, ConnectorError> {
        let token = std::env::var(ENV_API_KEY).map_err(|_| ConnectorError::MissingApiKey)?;
        if token.trim().is_empty() {
            return Err(ConnectorError::MissingApiKey);
        }
        let base = std::env::var(ENV_BASE_URL)
            .ok()
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let base_url =
            Url::parse(&base).map_err(|err| ConnectorError::Transport(err.to_string()))?;
        let approved = Url::parse(DEFAULT_BASE_URL)
            .map_err(|err| ConnectorError::Transport(err.to_string()))?;
        if base_url != approved {
            return Err(ConnectorError::Transport(
                "Model Connector production base URL is not approved".into(),
            ));
        }
        Self::new(base_url, ApiKey::new(token))
    }

    /// Build the hidden diagnostic probe client, allowing the explicit
    /// loopback replay override used by the offline production-gate harness.
    /// Agent capability composition must use [`Self::try_from_env`] instead.
    ///
    /// # Errors
    /// Returns the same credential, URL parsing, and HTTP-client errors as the
    /// production constructor.
    pub fn try_from_probe_env() -> Result<Self, ConnectorError> {
        let token = std::env::var(ENV_API_KEY).map_err(|_| ConnectorError::MissingApiKey)?;
        if token.trim().is_empty() {
            return Err(ConnectorError::MissingApiKey);
        }
        let base = std::env::var(ENV_BASE_URL)
            .ok()
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let base_url =
            Url::parse(&base).map_err(|err| ConnectorError::Transport(err.to_string()))?;
        Self::new(base_url, ApiKey::new(token))
    }

    /// Build a client with an explicit base `URL` and key (used by tests and
    /// any non-default deployment).
    ///
    /// # Errors
    /// Returns [`ConnectorError::Transport`] if the underlying `reqwest` client
    /// fails to build.
    pub fn new(base_url: Url, api_key: ApiKey) -> Result<Self, ConnectorError> {
        let http = reqwest::Client::builder()
            .https_only(base_url.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("arcana/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| ConnectorError::Transport(err.to_string()))?;
        Ok(Self {
            http,
            base_url,
            api_key,
        })
    }

    fn execute_url(&self) -> Result<Url, ConnectorError> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| ConnectorError::Transport("base URL cannot be a base".into()))?
            .push("execute");
        Ok(url)
    }
}

#[async_trait]
impl ModelConnector for ModelConnectorClient {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let url = self.execute_url()?;
        let resp = self
            .http
            .post(url)
            .bearer_auth(self.api_key.secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&req)
            .send()
            .await
            .map_err(|err| ConnectorError::Transport(err.to_string()))?;

        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = resp
            .bytes()
            .await
            .map_err(|err| ConnectorError::Transport(err.to_string()))?;

        match status {
            201 => parse_success_envelope(&bytes, content_type),
            200 => Err(ConnectorError::UnexpectedStatus(200)),
            s if s >= 400 => parse_error_envelope(s, &bytes),
            s => Err(ConnectorError::UnexpectedStatus(s)),
        }
    }
}

/// Parse a 201 body: a [`ConnectorResponse`] whose `status` is `"success"` is
/// returned as-is; `status: "error"` maps to [`ConnectorError::Logical`].
fn parse_success_envelope(
    bytes: &[u8],
    content_type: Option<String>,
) -> Result<ConnectorResponse, ConnectorError> {
    let parsed: ConnectorResponse =
        serde_json::from_slice(bytes).map_err(|_| ConnectorError::UpstreamNonJson {
            content_type,
            bytes: bytes.len(),
        })?;
    match parsed.status.as_str() {
        "success" => Ok(parsed),
        "error" | "timeout" | "rate_limited" => logical_error(201, parsed),
        _ => Err(ConnectorError::UnexpectedEnvelopeStatus),
    }
}

fn logical_error(
    http_status: u16,
    parsed: ConnectorResponse,
) -> Result<ConnectorResponse, ConnectorError> {
    let envelope_status = parsed.status.clone();
    let first_dispatch_observation = parsed.first_dispatch_observation.map(Box::new);
    let logical = parsed
        .error
        .unwrap_or_else(|| arcana_core::connector::LogicalError {
            kind: envelope_status.clone(),
            message: format!(
                "upstream reported status={envelope_status} with no logical error payload"
            ),
            retryable: false,
            recommendation: String::new(),
            retry_after: None,
        });
    Err(ConnectorError::Logical {
        http_status,
        kind: logical.kind,
        message: logical.message,
        retryable: logical.retryable,
        recommendation: logical.recommendation,
        retry_after: logical.retry_after,
        first_dispatch_observation,
    })
}

/// Parse a 4xx/5xx body. Model Connector maps structured logical failures to
/// their HTTP status while preserving the full [`ConnectorResponse`] body, so
/// parse that shape first to retain the observation receipt. Other `NestJS`
/// exception envelopes become [`ConnectorError::Http`].
fn parse_error_envelope(status: u16, bytes: &[u8]) -> Result<ConnectorResponse, ConnectorError> {
    if let Ok(parsed) = serde_json::from_slice::<ConnectorResponse>(bytes) {
        return match parsed.status.as_str() {
            "error" | "timeout" | "rate_limited" => logical_error(status, parsed),
            _ => Err(ConnectorError::UnexpectedEnvelopeStatus),
        };
    }
    let message = match serde_json::from_slice::<NestExceptionEnvelope>(bytes) {
        Ok(envelope) if envelope.status_code == status => envelope.message,
        _ => format!(
            "upstream returned a non-contract error body ({} bytes)",
            bytes.len()
        ),
    };
    Err(ConnectorError::Http {
        status,
        message,
        retry_after: None,
    })
}

/// Exact `NestJS` `HttpException` body shape `{message, error, statusCode}`.
/// Partial, extended, or status-mismatched bodies are non-contract and never
/// contribute operator-visible text.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NestExceptionEnvelope {
    message: String,
    #[serde(rename = "error")]
    _error: String,
    status_code: u16,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn api_key_debug_and_display_are_redacted() {
        let key = ApiKey::new("mc-supersecret-value");
        assert_eq!(format!("{key:?}"), "ApiKey(mc-***)");
        assert_eq!(format!("{key}"), "mc-***");
        assert!(!format!("{key:?}").contains("supersecret"));
        assert_eq!(key.secret(), "mc-supersecret-value");
    }

    #[test]
    fn try_from_env_errors_when_var_missing() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: single-threaded test; we restore by removing.
        std::env::remove_var(ENV_API_KEY);
        match ModelConnectorClient::try_from_env() {
            Err(ConnectorError::MissingApiKey) => {}
            other => panic!("expected MissingApiKey, got {other:?}"),
        }
    }

    #[test]
    fn try_from_env_errors_when_var_empty() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_API_KEY, "   ");
        let result = ModelConnectorClient::try_from_env();
        std::env::remove_var(ENV_API_KEY);
        match result {
            Err(ConnectorError::MissingApiKey) => {}
            other => panic!("expected MissingApiKey for whitespace, got {other:?}"),
        }
    }

    #[test]
    fn production_constructor_rejects_loopback_base_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_API_KEY, "staging");
        std::env::set_var(ENV_BASE_URL, "http://127.0.0.1:9999");
        let result = ModelConnectorClient::try_from_env();
        std::env::remove_var(ENV_BASE_URL);
        std::env::remove_var(ENV_API_KEY);
        assert!(
            result.is_err(),
            "production constructor accepted replay URL"
        );
    }

    #[test]
    fn execute_url_appends_path_segment() {
        let client = ModelConnectorClient::new(
            Url::parse("https://connector.arcanada.ai").unwrap(),
            ApiKey::new("mc-test"),
        )
        .unwrap();
        assert_eq!(
            client.execute_url().unwrap().as_str(),
            "https://connector.arcanada.ai/execute"
        );
    }
}
