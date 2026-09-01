//! `OpsBotClient` — `reqwest` implementation of the Ops Bot events emitter
//! against `POST /events`.
//!
//! Fail-soft, hard rule (per memory `feedback_authenticated_emit_endpoints_fail_soft`):
//! when no API token is configured, [`OpsBotClient::emit`] returns `Ok(())`
//! and logs a single [`tracing::warn!`] — it never makes an HTTP call in that
//! path (never blind-emit unauthenticated). This mirrors the contract already
//! established by the stub hook in `arcana_core::hooks::ops_bot`, which keeps
//! the agent loop functional and observable until this connector is wired in
//! at the composition root (tracked separately). A configured
//! token that the server rejects (e.g. HTTP 401) is a real error and is
//! surfaced as `Err` — fail-soft applies only to the missing-token case.

use std::time::Duration;

use serde::Serialize;
use url::Url;

use crate::model_connector::ApiKey;

// The host that SERVES the API, not one that redirects to it.
// `ops.arcanada.one` answers 301 -> `ops.arcanada.ai`, and a redirect that
// changes host makes reqwest drop the `Authorization` header (measured
// against an echo service: survived=false across hosts, survived=true
// within one). Every authenticated emit would therefore have arrived
// unauthenticated and come back 401 -- which `emit` reports as a real
// error, by design. A `curl -L` check hides this: curl keeps the header.
const DEFAULT_BASE_URL: &str = "https://ops.arcanada.ai";
const ENV_TOKEN: &str = "ARCANA_OPS_BOT_TOKEN";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Event category emitted to Ops Bot. `SelfHeal` is L4-future (no special
/// handling yet — just a reserved variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    ToolInvocation,
    CostThreshold,
    PermissionDenied,
    SelfHeal,
}

/// Every way an `OpsBotClient::emit` call can fail. Note there is no
/// "missing token" variant — that path is fail-soft and returns `Ok(())`.
#[derive(Debug, thiserror::Error)]
pub enum OpsBotError {
    /// Transport-level failure (DNS, TLS, connect, timeout, body read).
    #[error("transport error: {0}")]
    Transport(String),
    /// Upstream returned a non-2xx status.
    #[error("HTTP {status}: {message}")]
    Http { status: u16, message: String },
}

/// Wire body for `POST /events`: `{"category": "<snake_case>", "payload": <value>}`.
#[derive(Serialize)]
struct EmitBody {
    category: EventCategory,
    payload: serde_json::Value,
}

/// HTTP client for the Ops Bot `POST /events` endpoint.
#[derive(Debug)]
pub struct OpsBotClient {
    http: reqwest::Client,
    base_url: Url,
    /// `None` means no token is configured — every `emit` call in that state
    /// is fail-soft (`Ok(())`, single warn, zero HTTP calls).
    token: Option<ApiKey>,
}

impl OpsBotClient {
    /// Build a client from the `ARCANA_OPS_BOT_TOKEN` env var and the
    /// default base `URL`. Unlike [`crate::model_connector::ModelConnectorClient::try_from_env`],
    /// a missing/empty token is NOT an error here — it is deferred to
    /// fail-soft handling inside [`Self::emit`].
    ///
    /// # Errors
    /// Returns [`OpsBotError::Transport`] if the underlying `reqwest` client
    /// fails to build.
    pub fn try_from_env() -> Result<Self, OpsBotError> {
        let token = std::env::var(ENV_TOKEN)
            .ok()
            .filter(|t| !t.trim().is_empty())
            .map(ApiKey::new);
        let base_url =
            Url::parse(DEFAULT_BASE_URL).map_err(|err| OpsBotError::Transport(err.to_string()))?;
        Self::new(base_url, token)
    }

    /// Build a client with an explicit base `URL` and optional token (used by
    /// tests and any non-default deployment). `token: None` puts the client
    /// in fail-soft mode.
    ///
    /// # Errors
    /// Returns [`OpsBotError::Transport`] if the underlying `reqwest` client
    /// fails to build.
    pub fn new(base_url: Url, token: Option<ApiKey>) -> Result<Self, OpsBotError> {
        let http = reqwest::Client::builder()
            .https_only(base_url.scheme() == "https")
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("arcana/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| OpsBotError::Transport(err.to_string()))?;
        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    fn events_url(&self) -> Result<Url, OpsBotError> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| OpsBotError::Transport("base URL cannot be a base".into()))?
            .push("events");
        Ok(url)
    }

    /// Emit one Ops Bot event. Fail-soft: with no token configured this
    /// returns `Ok(())` and logs a single warning, making zero HTTP calls.
    /// With a token configured, a rejected request (e.g. HTTP 401) is a real
    /// error and is returned as `Err` — fail-soft never swallows an
    /// authenticated rejection.
    ///
    /// # Errors
    /// Returns [`OpsBotError::Transport`] on a network/TLS/timeout failure,
    /// or [`OpsBotError::Http`] on a non-2xx response.
    pub async fn emit(
        &self,
        category: EventCategory,
        payload: serde_json::Value,
    ) -> Result<(), OpsBotError> {
        let Some(token) = self.token.as_ref() else {
            tracing::warn!(
                ?category,
                "Ops Bot API key missing — skipping event emit (fail-soft, no HTTP call made)"
            );
            return Ok(());
        };

        let url = self.events_url()?;
        let body = EmitBody { category, payload };
        let resp = self
            .http
            .post(url)
            .bearer_auth(token.secret())
            .json(&body)
            .send()
            .await
            .map_err(|err| OpsBotError::Transport(err.to_string()))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        let status_code = status.as_u16();
        let bytes = resp.bytes().await.unwrap_or_default();
        let message = serde_json::from_slice::<NestExceptionEnvelope>(&bytes).map_or_else(
            |_| String::from_utf8_lossy(&bytes).trim().to_owned(),
            |env| env.message,
        );
        Err(OpsBotError::Http {
            status: status_code,
            message,
        })
    }
}

/// `NestJS` `HttpException` body shape `{message, error, statusCode}`. Only
/// `message` is surfaced; mirrors `model_connector::NestExceptionEnvelope`
/// (kept as a private local copy to avoid coupling the two connector
/// modules).
#[derive(serde::Deserialize)]
struct NestExceptionEnvelope {
    message: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn event_category_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventCategory::ToolInvocation).unwrap(),
            "\"tool_invocation\""
        );
        assert_eq!(
            serde_json::to_string(&EventCategory::CostThreshold).unwrap(),
            "\"cost_threshold\""
        );
        assert_eq!(
            serde_json::to_string(&EventCategory::PermissionDenied).unwrap(),
            "\"permission_denied\""
        );
        assert_eq!(
            serde_json::to_string(&EventCategory::SelfHeal).unwrap(),
            "\"self_heal\""
        );
    }

    #[test]
    fn events_url_appends_path_segment() {
        let client =
            OpsBotClient::new(Url::parse("https://ops.arcanada.ai").unwrap(), None).unwrap();
        assert_eq!(
            client.events_url().unwrap().as_str(),
            "https://ops.arcanada.ai/events"
        );
    }

    /// The default host must serve the API directly, never redirect to it.
    ///
    /// A cross-host redirect is not a harmless convenience here: reqwest drops
    /// `Authorization` when a redirect changes host, so a default pointing at a
    /// redirecting alias turns every authenticated emit into a 401 that `emit`
    /// then reports as a real error. The failure is invisible to a `curl -L`
    /// check, which keeps the header, so it is pinned by a test instead.
    #[test]
    fn default_base_url_is_not_a_redirecting_alias() {
        assert_eq!(DEFAULT_BASE_URL, "https://ops.arcanada.ai");
        assert!(
            !DEFAULT_BASE_URL.contains("arcanada.one"),
            "ops.arcanada.one 301s to ops.arcanada.ai, and a cross-host \
             redirect strips the Authorization header"
        );
    }
}
