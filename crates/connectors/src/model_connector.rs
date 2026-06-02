//! `ModelConnectorClient` — `reqwest` implementation of
//! [`arcana_core::connector::ModelConnector`] against the upstream
//! `POST /execute` endpoint (unary JSON, HTTP 201 on success).

use std::time::Duration;

use arcana_core::connector::{ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector};
use async_trait::async_trait;
use url::Url;

const DEFAULT_BASE_URL: &str = "https://connector.arcanada.one";
const ENV_API_KEY: &str = "ARCANA_MC_TOKEN";
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
    /// # Errors
    /// Returns [`ConnectorError::MissingApiKey`] if `ARCANA_MC_TOKEN` is unset
    /// or empty, or [`ConnectorError::Transport`] if the client fails to build.
    pub fn try_from_env() -> Result<Self, ConnectorError> {
        let token = std::env::var(ENV_API_KEY).map_err(|_| ConnectorError::MissingApiKey)?;
        if token.trim().is_empty() {
            return Err(ConnectorError::MissingApiKey);
        }
        let base_url = Url::parse(DEFAULT_BASE_URL)
            .map_err(|err| ConnectorError::Transport(err.to_string()))?;
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
    if parsed.status == "error" {
        let logical = parsed
            .error
            .unwrap_or_else(|| arcana_core::connector::LogicalError {
                kind: "unknown".into(),
                message: "upstream reported status=error with no error payload".into(),
                retryable: false,
                recommendation: String::new(),
                retry_after: None,
            });
        return Err(ConnectorError::Logical {
            kind: logical.kind,
            message: logical.message,
            retryable: logical.retryable,
            recommendation: logical.recommendation,
            retry_after: logical.retry_after,
        });
    }
    Ok(parsed)
}

/// Parse a 4xx/5xx `NestJS` exception envelope `{message, error, statusCode}`
/// into [`ConnectorError::Http`]. Falls back to a generic message if the body
/// is not the expected `JSON` shape.
fn parse_error_envelope(status: u16, bytes: &[u8]) -> Result<ConnectorResponse, ConnectorError> {
    let message = serde_json::from_slice::<NestExceptionEnvelope>(bytes).map_or_else(
        |_| String::from_utf8_lossy(bytes).trim().to_owned(),
        |env| env.message,
    );
    Err(ConnectorError::Http {
        status,
        message,
        retry_after: None,
    })
}

/// `NestJS` `HttpException` body shape: `{message, error, statusCode}`.
#[derive(serde::Deserialize)]
struct NestExceptionEnvelope {
    message: String,
    #[allow(dead_code)]
    error: Option<String>,
    #[serde(rename = "statusCode")]
    #[allow(dead_code)]
    status_code: Option<u16>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
        // SAFETY: single-threaded test; we restore by removing.
        std::env::remove_var(ENV_API_KEY);
        match ModelConnectorClient::try_from_env() {
            Err(ConnectorError::MissingApiKey) => {}
            other => panic!("expected MissingApiKey, got {other:?}"),
        }
    }

    #[test]
    fn try_from_env_errors_when_var_empty() {
        std::env::set_var(ENV_API_KEY, "   ");
        let result = ModelConnectorClient::try_from_env();
        std::env::remove_var(ENV_API_KEY);
        match result {
            Err(ConnectorError::MissingApiKey) => {}
            other => panic!("expected MissingApiKey for whitespace, got {other:?}"),
        }
    }

    #[test]
    fn execute_url_appends_path_segment() {
        let client = ModelConnectorClient::new(
            Url::parse("https://connector.arcanada.one").unwrap(),
            ApiKey::new("mc-test"),
        )
        .unwrap();
        assert_eq!(
            client.execute_url().unwrap().as_str(),
            "https://connector.arcanada.one/execute"
        );
    }
}
