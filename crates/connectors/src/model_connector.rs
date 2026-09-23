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
/// Optional per-attempt model budget override, in whole seconds.
const ENV_REQUEST_TIMEOUT: &str = "ARCANA_MC_TIMEOUT_SECS";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-attempt budget this client asks Model Connector to spend on the model,
/// sent as `ExecuteRequest.timeout` (ms) and used to size the HTTP wait.
///
/// 120 s, from what the server actually does (measured 2026-09-23 against
/// production, and read off model-connector `main` 3911773):
///
/// * `src/connectors/dto/execute.dto.ts:62` — `/execute` accepts `timeout`
///   between `5_000` and `600_000` ms. Absent, the connector's own default
///   applies: `src/connectors/base-api.connector.ts:131` returns `30_000` for
///   every API connector that does not override it — `deepseek` does not —
///   and `src/connectors/orq/orq.connector.ts:88` returns `120_000`.
///   A live dispatch of a 3000-word essay with no `timeout` field came back
///   `latencyMs: 30002`, `attempt: 2 of 2`, `network_error`: the 30 s default
///   is the wall a long turn hits first, and no client-side budget can move
///   it. Naming the budget is therefore part of the fix, not a nicety.
/// * `nginx` in front of the origin allows 600 s
///   (`deploy/nginx/connector.arcanada.ai.conf:24-26`), but the public origin
///   also sits behind Cloudflare, which cut three separate `/execute` calls at
///   125.1 s, 125.2 s and 125.3 s with HTTP 524. 120 s is the largest
///   per-attempt budget whose FIRST attempt can still return through that
///   edge; anything above it buys nothing on `connector.arcanada.ai` and is
///   available for deployments reached without the edge in the path.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Lower/upper bounds the upstream Zod schema accepts for `timeout`
/// (`src/connectors/dto/execute.dto.ts:62`). Refused here rather than sent and
/// bounced as a 400 in the middle of a run.
const MIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

/// Longest a dispatch may sit in Model Connector's per-connector queue before
/// it starts (`CONNECTOR_QUEUE_TIMEOUT_MS`, default `60_000` —
/// `src/config/env.schema.ts:38`). Queue time is invisible to the caller and
/// is not part of the model budget, so the HTTP wait has to carry it.
const UPSTREAM_QUEUE_SLACK: Duration = Duration::from_secs(60);

/// Attempts Model Connector makes before it answers
/// (`CONNECTOR_MAX_RETRIES`, default 1 → two attempts,
/// `src/config/env.schema.ts:39`), plus its exponential backoff between them.
const UPSTREAM_ATTEMPTS: u32 = 2;
const UPSTREAM_BACKOFF: Duration = Duration::from_secs(10);

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
    /// Per-attempt model budget sent upstream and used to size the HTTP wait.
    request_timeout: Duration,
    /// How long this client waits for the response.
    http_wait: Duration,
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
    /// or empty, [`ConnectorError::InvalidApiKey`] if it holds a byte that is
    /// illegal in an HTTP header, or [`ConnectorError::Transport`] if the base
    /// URL fails to parse or the client fails to build.
    pub fn try_from_env() -> Result<Self, ConnectorError> {
        Self::try_from_env_with_timeout(None)
    }

    /// Build the production client with an explicit per-attempt budget.
    ///
    /// `request_timeout` is the operator's flag; `None` falls back to
    /// [`ENV_REQUEST_TIMEOUT`] and then to [`DEFAULT_REQUEST_TIMEOUT`].
    ///
    /// # Errors
    /// Returns the same credential and URL errors as [`Self::try_from_env`],
    /// plus [`ConnectorError::Transport`] when the budget — from either source
    /// — is outside the range `/execute` accepts.
    pub fn try_from_env_with_timeout(
        request_timeout: Option<Duration>,
    ) -> Result<Self, ConnectorError> {
        let request_timeout = match request_timeout {
            Some(explicit) => explicit,
            None => request_timeout_from_env()?,
        };
        let api_key = read_api_key()?;
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
        Self::with_request_timeout(base_url, api_key, request_timeout)
    }

    /// Build the hidden diagnostic probe client, allowing the explicit
    /// loopback replay override used by the offline production-gate harness.
    /// Agent capability composition must use [`Self::try_from_env`] instead.
    ///
    /// # Errors
    /// Returns the same credential, URL parsing, and HTTP-client errors as the
    /// production constructor.
    pub fn try_from_probe_env() -> Result<Self, ConnectorError> {
        let request_timeout = request_timeout_from_env()?;
        let api_key = read_api_key()?;
        let base = std::env::var(ENV_BASE_URL)
            .ok()
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let base_url =
            Url::parse(&base).map_err(|err| ConnectorError::Transport(err.to_string()))?;
        Self::with_request_timeout(base_url, api_key, request_timeout)
    }

    /// Build a client with an explicit base `URL` and key (used by tests and
    /// any non-default deployment).
    ///
    /// # Errors
    /// Returns [`ConnectorError::Transport`] if the underlying `reqwest` client
    /// fails to build.
    pub fn new(base_url: Url, api_key: ApiKey) -> Result<Self, ConnectorError> {
        Self::with_request_timeout(base_url, api_key, DEFAULT_REQUEST_TIMEOUT)
    }

    /// Build a client whose upstream budget is `request_timeout`.
    ///
    /// Two numbers come out of the one the operator chose. The budget itself
    /// travels on the wire as `ExecuteRequest.timeout`, telling Model
    /// Connector how long the model may take. The HTTP client waits
    /// [`http_wait`] — that budget plus what the server may spend around it
    /// (queue, its own second attempt, backoff), because a client that gives
    /// up first turns a turn the server is still working on into a dead run,
    /// which is the whole defect this constructor exists for.
    ///
    /// # Errors
    /// [`ConnectorError::Transport`] when `request_timeout` is outside the
    /// 5 s..=600 s range `/execute` accepts, or when the HTTP client fails to
    /// build.
    pub fn with_request_timeout(
        base_url: Url,
        api_key: ApiKey,
        request_timeout: Duration,
    ) -> Result<Self, ConnectorError> {
        let wait = http_wait(request_timeout);
        Self::with_timeouts(base_url, api_key, request_timeout, wait)
    }

    /// Build a client whose HTTP wait is stated instead of derived.
    ///
    /// The derived wait in [`Self::with_request_timeout`] assumes the server's
    /// documented worst case is reachable. A deployment that knows its own
    /// ceiling — a proxy that cuts every request at a fixed point, a loopback
    /// replay with no queue at all — states the wait it actually has.
    ///
    /// # Errors
    /// [`ConnectorError::Transport`] when `request_timeout` is outside the
    /// 5 s..=600 s range `/execute` accepts, or when the client fails to build.
    pub fn with_timeouts(
        base_url: Url,
        api_key: ApiKey,
        request_timeout: Duration,
        wait: Duration,
    ) -> Result<Self, ConnectorError> {
        if request_timeout < MIN_REQUEST_TIMEOUT || request_timeout > MAX_REQUEST_TIMEOUT {
            return Err(ConnectorError::Transport(format!(
                "request timeout {}s is outside the {}s..{}s the Model Connector accepts",
                request_timeout.as_secs(),
                MIN_REQUEST_TIMEOUT.as_secs(),
                MAX_REQUEST_TIMEOUT.as_secs(),
            )));
        }
        let http = reqwest::Client::builder()
            .https_only(base_url.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(wait)
            .user_agent(concat!("arcana/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| {
                ConnectorError::Transport(describe_reqwest(&err, CONNECT_TIMEOUT, wait))
            })?;
        Ok(Self {
            http,
            base_url,
            api_key,
            request_timeout,
            http_wait: wait,
        })
    }

    /// The per-attempt model budget this client sends upstream.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// How long this client waits for a response before giving up.
    #[must_use]
    pub const fn http_wait(&self) -> Duration {
        self.http_wait
    }

    fn execute_url(&self) -> Result<Url, ConnectorError> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| ConnectorError::Transport("base URL cannot be a base".into()))?
            .push("execute");
        Ok(url)
    }
}

/// How long the HTTP client waits for one `/execute` response.
///
/// The server may legitimately spend more than the model budget: up to
/// [`UPSTREAM_QUEUE_SLACK`] queueing before the first attempt starts, then
/// [`UPSTREAM_ATTEMPTS`] attempts of that budget with backoff between them.
/// Measured at the default 120 s budget this is 310 s — against the 120 s the
/// client used to allow while the server's own worst case was already ~121 s,
/// which is how a healthy slow turn became `ConnectorFatal`.
fn http_wait(request_timeout: Duration) -> Duration {
    UPSTREAM_QUEUE_SLACK
        .saturating_add(request_timeout.saturating_mul(UPSTREAM_ATTEMPTS))
        .saturating_add(UPSTREAM_BACKOFF)
}

/// Read the optional per-attempt budget from [`ENV_REQUEST_TIMEOUT`].
///
/// # Errors
/// [`ConnectorError::Transport`] when the value is not a whole number of
/// seconds. A mistyped budget is reported rather than silently replaced by the
/// default, because the run it governs may cost money either way.
fn request_timeout_from_env() -> Result<Duration, ConnectorError> {
    let Some(raw) = std::env::var(ENV_REQUEST_TIMEOUT)
        .ok()
        .filter(|raw| !raw.trim().is_empty())
    else {
        return Ok(DEFAULT_REQUEST_TIMEOUT);
    };
    raw.trim()
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| {
            ConnectorError::Transport(format!(
                "{ENV_REQUEST_TIMEOUT} must be a whole number of seconds"
            ))
        })
}

/// Read and validate `ARCANA_MC_TOKEN`.
///
/// Two things go wrong with a pasted credential often enough to deserve their
/// own message. Surrounding whitespace: the old code trimmed only for the
/// emptiness test and then sent the token untrimmed, so a stray space produced
/// a puzzling 401. And an embedded control byte: `reqwest` rejects it inside
/// `bearer_auth`, and `reqwest::Error::to_string()` renders that as the two
/// words "builder error", which names neither the token nor the newline.
///
/// The returned error never contains the credential — only the offending
/// byte's identity and offset.
///
/// # Errors
/// [`ConnectorError::MissingApiKey`] when unset or blank;
/// [`ConnectorError::InvalidApiKey`] when a control byte survives trimming.
fn read_api_key() -> Result<ApiKey, ConnectorError> {
    let raw = std::env::var(ENV_API_KEY).map_err(|_| ConnectorError::MissingApiKey)?;
    let token = raw.trim();
    if token.is_empty() {
        return Err(ConnectorError::MissingApiKey);
    }
    if let Some(offset) = token.bytes().position(|byte| byte < 0x20 || byte == 0x7f) {
        let named = match token.as_bytes().get(offset) {
            Some(b'\r') => "a carriage return",
            Some(b'\n') => "a newline",
            Some(0) => "a NUL byte",
            _ => "a control character",
        };
        return Err(ConnectorError::InvalidApiKey {
            reason: format!(
                "{ENV_API_KEY} contains {named} at byte {offset}, which cannot go in an HTTP \
                 header. This usually means the token was read from a file with a CRLF line \
                 ending, or that two values were concatenated. Re-export it without the \
                 embedded newline."
            ),
        });
    }
    Ok(ApiKey::new(token))
}

/// Describe a `reqwest` failure in terms an operator can act on.
///
/// `reqwest::Error::to_string()` renders every network failure as
/// `error sending request for url (...)` — the same eleven words for a
/// connection refused in 8 ms and a stall that burned the full
/// [`REQUEST_TIMEOUT`]. The distinguishing facts are all present: the typed
/// `is_timeout` / `is_connect` predicates, and the cause chain hanging off
/// [`std::error::Error::source`]. This walks both.
///
/// The two timeout budgets are parameters rather than reads of the module
/// constants so the emitted duration is always the one the failing client was
/// actually built with — a test that injects a 100 ms budget must not be told
/// the request timed out after 120 s.
/// Map a `reqwest` failure to the error class the driver reasons about.
///
/// A timeout is the one transport failure that says nothing about the request
/// — the server may still be working on it — so it gets its own variant and
/// becomes retryable. Connect refusals, TLS and DNS failures stay
/// [`ConnectorError::Transport`] and stay fatal.
fn classify_reqwest(err: &reqwest::Error, connect: Duration, request: Duration) -> ConnectorError {
    let described = describe_reqwest(err, connect, request);
    if err.is_timeout() {
        ConnectorError::Timeout(described)
    } else {
        ConnectorError::Transport(described)
    }
}

fn describe_reqwest(err: &reqwest::Error, connect: Duration, request: Duration) -> String {
    let headline = if err.is_timeout() {
        let budget = if err.is_connect() { connect } else { request };
        format!("timed out after {}s", budget.as_secs())
    } else if err.is_connect() {
        "could not connect".to_owned()
    } else if err.is_decode() || err.is_body() {
        "could not read the response body".to_owned()
    } else if err.is_builder() {
        "the request could not be built".to_owned()
    } else {
        "the request failed".to_owned()
    };

    let mut parts = vec![headline, err.to_string()];
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(cause) = source {
        let rendered = cause.to_string();
        // Nested `reqwest`/`hyper` errors frequently restate their child
        // verbatim; repeating it adds length and no information.
        if parts.last().is_none_or(|last| last != &rendered) {
            parts.push(rendered);
        }
        source = cause.source();
    }
    parts.join(": ")
}

#[async_trait]
impl ModelConnector for ModelConnectorClient {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let url = self.execute_url()?;
        let mut req = req;
        // The caller may state its own budget; otherwise the client's applies.
        // Left unset, the server silently uses the connector's default — 30 s
        // for deepseek — and no client-side timeout can widen it.
        if req.timeout_ms.is_none() {
            req.timeout_ms = u64::try_from(self.request_timeout.as_millis()).ok();
        }
        let wait = self.http_wait;
        let resp = self
            .http
            .post(url)
            .bearer_auth(self.api_key.secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&req)
            .send()
            .await
            .map_err(|err| classify_reqwest(&err, CONNECT_TIMEOUT, wait))?;

        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = resp
            .bytes()
            .await
            .map_err(|err| classify_reqwest(&err, CONNECT_TIMEOUT, wait))?;

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
        _ => {
            let headline = format!(
                "upstream returned a non-contract error body ({} bytes)",
                bytes.len()
            );
            match error_body_excerpt(bytes) {
                Some(excerpt) => format!("{headline}: {excerpt}"),
                None => headline,
            }
        }
    };
    Err(ConnectorError::Http {
        status,
        message,
        retry_after: None,
    })
}

/// Bytes of an untrusted upstream error body shown to the operator.
const ERROR_BODY_EXCERPT_LIMIT: usize = 200;

/// Render an untrusted error body as a bounded, sanitised excerpt.
///
/// The byte count alone was a verdict with no evidence: Model Connector answers
/// a schema violation with a `ZodValidationPipe` envelope
/// (`{message, errors[], statusCode}`) that this client cannot parse, so the
/// one line naming the offending field — `maxTurns: ... <=100` — was replaced
/// by `(91 bytes)` and cost a bisect to recover (A2-202).
///
/// Echoing upstream text is a deliberate, narrowed reversal of the earlier
/// "never copy a malformed body" rule, recorded here so the change stays
/// visible: the body may be model output, so it is bounded to
/// [`ERROR_BODY_EXCERPT_LIMIT`] bytes, truncated on a character boundary, and
/// stripped of control characters (no forged log lines, no ANSI escapes
/// repainting the terminal). Only the body is used — never response headers,
/// never the request, never the API key.
///
/// `None` when nothing printable survives, so the caller keeps its bare
/// headline rather than appending an empty excerpt.
fn error_body_excerpt(bytes: &[u8]) -> Option<String> {
    let lossy = String::from_utf8_lossy(bytes);
    let mut excerpt = String::new();
    let mut truncated = false;
    for character in lossy.chars().filter(|c| !c.is_control()) {
        if excerpt.len() + character.len_utf8() > ERROR_BODY_EXCERPT_LIMIT {
            truncated = true;
            break;
        }
        excerpt.push(character);
    }
    if excerpt.is_empty() {
        return None;
    }
    if truncated {
        excerpt.push('\u{2026}');
    }
    Some(excerpt)
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

    // --- credential validation (issue #107) --------------------------------

    #[test]
    fn surrounding_whitespace_is_trimmed_off_the_credential() {
        // The old code trimmed only for the emptiness test and then sent the
        // token untrimmed, so a trailing space came back as a puzzling 401.
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_API_KEY, "  mc-live-abc \n");
        let key = read_api_key();
        std::env::remove_var(ENV_API_KEY);
        assert_eq!(key.unwrap().secret(), "mc-live-abc");
    }

    #[test]
    fn embedded_newline_is_rejected_by_name_and_offset() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_API_KEY, "mc-abc\ndef");
        let result = read_api_key();
        std::env::remove_var(ENV_API_KEY);
        match result {
            Err(ConnectorError::InvalidApiKey { reason }) => {
                assert!(reason.contains("a newline"), "reason={reason}");
                assert!(reason.contains("byte 6"), "reason={reason}");
                assert!(reason.contains(ENV_API_KEY), "reason={reason}");
            }
            other => panic!("expected InvalidApiKey, got {other:?}"),
        }
    }

    #[test]
    fn embedded_carriage_return_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_API_KEY, "mc-abc\rdef");
        let result = read_api_key();
        std::env::remove_var(ENV_API_KEY);
        match result {
            Err(ConnectorError::InvalidApiKey { reason }) => {
                assert!(reason.contains("a carriage return"), "reason={reason}");
            }
            other => panic!("expected InvalidApiKey, got {other:?}"),
        }
    }

    #[test]
    fn invalid_credential_error_never_echoes_the_credential() {
        // The whole point of `ApiKey`'s redacted Debug/Display is defeated if
        // the validation error prints the secret instead.
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_API_KEY, "mc-supersecret\nvalue");
        let result = read_api_key();
        std::env::remove_var(ENV_API_KEY);
        let err = result.expect_err("embedded newline must be rejected");
        let rendered = format!("{err:?} {err}");
        assert!(!rendered.contains("supersecret"), "leaked: {rendered}");
    }

    // --- transport-error description (issue #96) ---------------------------

    #[tokio::test]
    async fn connection_refused_names_the_cause_not_just_the_url() {
        // Port 1 on loopback refuses immediately. Before this change every
        // transport failure — refusal, DNS, TLS, a 120s stall — rendered as
        // the same "error sending request for url (...)".
        let client = ModelConnectorClient::new(
            Url::parse("http://127.0.0.1:1").unwrap(),
            ApiKey::new("mc-test"),
        )
        .unwrap();
        let err = client
            .execute(ExecuteRequest::new("claude-code", "ping"))
            .await
            .expect_err("port 1 must refuse");
        let rendered = err.to_string();
        assert!(
            rendered.contains("could not connect"),
            "expected a connect headline, got: {rendered}"
        );
        assert!(
            rendered.to_lowercase().contains("refused"),
            "expected the OS cause in the chain, got: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_stalled_response_reports_the_timeout_and_its_budget() {
        // A listener that accepts and never answers. The budget is injected so
        // the assertion is about the message, not about waiting 120 seconds.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream); // accept, never respond, never close
            }
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let err = client
            .get(format!("http://{addr}/execute"))
            .send()
            .await
            .expect_err("a stalled server must time out");

        let rendered = describe_reqwest(&err, Duration::from_secs(10), Duration::from_secs(120));
        assert!(
            rendered.starts_with("timed out after 120s"),
            "expected the request budget in the headline, got: {rendered}"
        );
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
