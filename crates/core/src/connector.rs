//! Model-connector contract: the `ModelConnector` trait plus the request /
//! response DTOs and error type shared across the agent loop.
//!
//! The agent loop (`crates/core`) depends only on this abstraction, never on a
//! concrete HTTP client. Concrete implementations live in `crates/connectors`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Wire-contract version for opt-in first-dispatch measurement metadata.
pub const FIRST_DISPATCH_MEASUREMENT_VERSION: &str = "first-dispatch-measurement/v0";
/// The only ARAS call site allowed to label a request as a first dispatch.
pub const FIRST_DISPATCH_ADAPTER_BOUNDARY: &str = "arcana-agent-system/driver/first-dispatch-v0";

/// The header Model Connector reads a caller-supplied intent key from.
///
/// Spelling and semantics are Model Connector's, not ours: `IDEMPOTENCY_HEADER`
/// in its `src/billing/intent.ts`, lifted onto the request by
/// `src/connectors/connectors.controller.ts`. It is a HEADER and never a body
/// field — the body is validated by a Zod schema that does not carry the key,
/// and the key is deliberately excluded from the payload fingerprint the
/// server hashes, or a key could never match its own replay.
pub const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";

/// Longest key Model Connector will store (`MAX_IDEMPOTENCY_KEY_LENGTH`).
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;

/// The `error.type` Model Connector answers when the first request under this
/// key is still running. HTTP 409, and the one idempotency outcome it marks
/// `retryable` — the answer genuinely exists shortly.
pub const IDEMPOTENCY_CONFLICT: &str = "idempotency_conflict";

/// The `error.type` Model Connector answers when the key was already claimed
/// by a DIFFERENT payload. HTTP 422, not retryable, and on our side always a
/// defect in the caller: a key that is stable per attempt-series must be sent
/// with a payload that is stable per attempt-series.
pub const IDEMPOTENCY_KEY_REUSED: &str = "idempotency_key_reused";

/// The `error.type` Model Connector answers when the request completed but its
/// response was too large to store for replay. HTTP 409, not retryable, and
/// the one idempotency outcome that states the request WAS charged.
pub const IDEMPOTENCY_REPLAY_UNAVAILABLE: &str = "idempotency_replay_unavailable";

/// A caller-minted key that identifies one logical request across however many
/// times the wire drops while asking for it.
///
/// A newtype rather than a `String` because the server validates the value and
/// rejects rather than sanitises (`normalizeIdempotencyKey`): printable ASCII
/// with no spaces, at most [`MAX_IDEMPOTENCY_KEY_BYTES`]. A value that fails
/// that test is also not a legal HTTP header value, so an unchecked `String`
/// has two ways to turn a retry into a hard transport failure. Making the
/// invalid value unrepresentable removes both, and means the client can send
/// the header without a fallible path of its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

/// Longest key [`IdempotencyKey::for_turn`] can produce: the fixed prefix, a
/// uuid as 32 hex digits, a separator, and `u64::MAX` in decimal.
const MAX_MINTED_KEY_BYTES: usize = "arcana.".len() + 32 + 1 + 20;

/// A change to the key's shape that outgrew the server's column would be
/// rejected at run time, one dispatch at a time, as a 400. Caught here instead.
const _: () = assert!(MAX_MINTED_KEY_BYTES <= MAX_IDEMPOTENCY_KEY_BYTES);

impl IdempotencyKey {
    /// The key for one logical turn's attempt-series of one run.
    ///
    /// `run` is a per-process uuid and `turn` counts logical turns within it,
    /// so the value is unique across runs, across hosts and across processes,
    /// while every re-dispatch of one turn reuses it. That is the whole
    /// contract: the server keys the charge on what the caller wanted done,
    /// "not the number of times the wire dropped while they asked for it"
    /// (`src/billing/intent.ts`).
    ///
    /// Total by construction. A uuid renders as hex and a turn index as
    /// decimal digits, so no input can produce a byte outside the printable
    /// ASCII the server accepts, and [`MAX_MINTED_KEY_BYTES`] is checked
    /// against the server's ceiling at compile time. There is deliberately no
    /// fallible constructor beside it: a `Result` here would invite an
    /// `unwrap_or(None)` at the call site, and a dropped key means believing
    /// you have an at-most-once guarantee you do not have — which is how the
    /// caller finds out by being charged twice.
    #[must_use]
    pub fn for_turn(run: u128, turn: u64) -> Self {
        Self(format!("arcana.{run:032x}.{turn}"))
    }

    /// The key as the header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Which side of a paired prompt comparison produced the dispatched payload.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromptVariantV0 {
    Baseline,
    Compiled,
}

/// Closed, identifier-only context attached to an opted-in first dispatch.
///
/// This type deliberately carries no prompt content, token counts, provider
/// output, credentials, tokenizer claim, or authorization decision. The model
/// and exact prompt remain on [`ExecuteRequest`]; the receiving model boundary
/// owns observation persistence and provider-usage provenance.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FirstDispatchMeasurementV0 {
    version: &'static str,
    corpus_id: String,
    case_id: String,
    role_id: String,
    task_class_id: String,
    command_id: String,
    replay_index: u16,
    variant: PromptVariantV0,
    adapter_boundary: &'static str,
}

/// Construction failures for [`FirstDispatchMeasurementV0`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FirstDispatchMeasurementError {
    #[error("{field} must be 1..=128 bytes of ASCII identifier characters")]
    InvalidIdentifier { field: &'static str },
    #[error("replay_index must be greater than zero")]
    InvalidReplayIndex,
}

impl FirstDispatchMeasurementV0 {
    /// Build a closed first-dispatch context from bounded opaque identifiers.
    ///
    /// Allowed identifier characters are ASCII alphanumeric plus `-._:/`.
    /// This excludes whitespace, controls, bidi markers, and JSON delimiters.
    ///
    /// # Errors
    ///
    /// Returns [`FirstDispatchMeasurementError::InvalidIdentifier`] when any
    /// identifier is empty, oversized, or contains a disallowed byte. Returns
    /// [`FirstDispatchMeasurementError::InvalidReplayIndex`] when
    /// `replay_index` is zero.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        corpus_id: impl Into<String>,
        case_id: impl Into<String>,
        role_id: impl Into<String>,
        task_class_id: impl Into<String>,
        command_id: impl Into<String>,
        replay_index: u16,
        variant: PromptVariantV0,
    ) -> Result<Self, FirstDispatchMeasurementError> {
        if replay_index == 0 {
            return Err(FirstDispatchMeasurementError::InvalidReplayIndex);
        }
        Ok(Self {
            version: FIRST_DISPATCH_MEASUREMENT_VERSION,
            corpus_id: Self::identifier("corpus_id", corpus_id.into())?,
            case_id: Self::identifier("case_id", case_id.into())?,
            role_id: Self::identifier("role_id", role_id.into())?,
            task_class_id: Self::identifier("task_class_id", task_class_id.into())?,
            command_id: Self::identifier("command_id", command_id.into())?,
            replay_index,
            variant,
            adapter_boundary: FIRST_DISPATCH_ADAPTER_BOUNDARY,
        })
    }

    fn identifier(
        field: &'static str,
        value: String,
    ) -> Result<String, FirstDispatchMeasurementError> {
        let valid = !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':' | b'/')
            });
        if !valid {
            return Err(FirstDispatchMeasurementError::InvalidIdentifier { field });
        }
        Ok(value)
    }
}

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
#[derive(Clone, Serialize, PartialEq)]
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
    /// Upstream per-attempt budget in milliseconds, wire name `timeout`.
    ///
    /// Model Connector accepts `5_000..=600_000` and falls back to the
    /// connector's own default when the field is absent — 30 s for every
    /// `BaseApiConnector` that does not override it (deepseek among them),
    /// 120 s for orq. Those defaults are what a long turn actually runs into,
    /// so the client states the budget instead of inheriting it.
    #[serde(skip_serializing_if = "Option::is_none", rename = "timeout")]
    pub timeout_ms: Option<u64>,
    /// Opt-in, metadata-only context for the real first model dispatch.
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "firstDispatchMeasurement"
    )]
    pub first_dispatch_measurement: Option<FirstDispatchMeasurementV0>,
    /// The intent this request belongs to, sent as the [`IDEMPOTENCY_HEADER`].
    ///
    /// `#[serde(skip)]` is load-bearing twice over: the field travels as a
    /// header, and the body it would otherwise appear in is validated by a Zod
    /// schema that does not declare it. It is also why every `PartialEq` on
    /// this type still compares it — two requests that differ only by key are
    /// two intents, not one.
    #[serde(skip)]
    pub idempotency_key: Option<IdempotencyKey>,
}

impl std::fmt::Debug for ExecuteRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecuteRequest")
            .field("connector", &self.connector)
            .field("prompt", &"[REDACTED]")
            .field("model", &self.model)
            .field(
                "system_prompt",
                &self.system_prompt.as_ref().map(|_| "[REDACTED]"),
            )
            .field("max_turns", &self.max_turns)
            .field("max_budget_usd", &self.max_budget_usd)
            .field("timeout_ms", &self.timeout_ms)
            .field(
                "first_dispatch_measurement",
                &self.first_dispatch_measurement,
            )
            // Not redacted: the key is a nonce this process minted, carries no
            // prompt content and no credential, and is the one field an
            // operator reconciling a double charge needs to see.
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
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
            timeout_ms: None,
            first_dispatch_measurement: None,
            idempotency_key: None,
        }
    }

    /// What "the same request" means for idempotency purposes, on our side.
    ///
    /// Mirrors Model Connector's `ConnectorsService.requestFingerprint`:
    /// everything that changes what the provider is asked to do, and nothing
    /// that does not. The two exclusions are the server's and are copied
    /// deliberately —
    ///
    /// * [`Self::idempotency_key`], or a key could never match its own replay;
    /// * [`Self::first_dispatch_measurement`], which is metadata-only and is
    ///   set on the FIRST attempt of a run and absent from its re-dispatches.
    ///   Counting it would make the first turn's retry look like a different
    ///   request to us while the server replayed it — the one turn where the
    ///   two views must not disagree.
    ///
    /// Hashed field by field rather than through `serde_json`: serialising
    /// returns a `Result` whose only sane fallback is an empty buffer, and an
    /// empty buffer hashes every request to the same value — a fingerprint
    /// that silently stops distinguishing anything. This cannot fail, and the
    /// field list is visible where the exclusions are argued.
    #[must_use]
    pub fn intent_fingerprint(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        let mut field = |bytes: &[u8]| {
            // Length-prefixed, so ("ab", "c") and ("a", "bc") differ.
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        field(self.connector.as_bytes());
        field(self.prompt.as_bytes());
        field(self.model.as_deref().unwrap_or_default().as_bytes());
        field(self.system_prompt.as_deref().unwrap_or_default().as_bytes());
        field(&self.max_turns.unwrap_or_default().to_le_bytes());
        field(
            &self
                .max_budget_usd
                .unwrap_or_default()
                .to_bits()
                .to_le_bytes(),
        );
        field(&self.timeout_ms.unwrap_or_default().to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Opaque first-dispatch receipt returned by Model Connector.
///
/// This value is intentionally named unverified: it is useful only for
/// correlating the caller with the `PostgreSQL` authority row. It is never an
/// authorization decision or provider-authenticated usage evidence.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct UnverifiedFirstDispatchObservationV0(serde_json::Value);

impl UnverifiedFirstDispatchObservationV0 {
    /// Read the opaque wire value for persistence/correlation tooling.
    #[must_use]
    pub const fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    /// Model Connector observation id, when the opaque envelope has that key.
    #[must_use]
    pub fn observation_id(&self) -> Option<&str> {
        self.0
            .get("observationId")
            .and_then(serde_json::Value::as_str)
    }

    /// Receipt digest, when the opaque envelope has that key.
    #[must_use]
    pub fn receipt_digest_sha256(&self) -> Option<&str> {
        self.0
            .get("receiptDigestSha256")
            .and_then(serde_json::Value::as_str)
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
    #[serde(
        default,
        rename = "firstDispatchObservation",
        skip_serializing_if = "Option::is_none"
    )]
    pub first_dispatch_observation: Option<UnverifiedFirstDispatchObservationV0>,
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

/// Logical-error payload carried inside a connector response whose `status` is
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

/// Headline of an error body that is neither the connector response envelope
/// nor a `NestJS` exception envelope — i.e. nothing Model Connector itself
/// speaks.
///
/// Declared here rather than at the formatting site because two parties depend
/// on the exact words: `arcana-connectors` writes it when it gives up parsing a
/// 4xx/5xx body, and [`ConnectorError::is_edge_gateway_failure`] reads it to
/// tell a Cloudflare verdict apart from a refusal Model Connector authored. A
/// silent edit to one half would silently reclassify production failures, so
/// the string has one home and a test that pins the round trip
/// (`crates/connectors/tests/model_connector_error_reporting.rs`).
pub const NON_CONTRACT_BODY_HEADLINE: &str = "upstream returned a non-contract error body";

/// Every way a connector call can fail. Phase 1 does not retry — pressure
/// signals (`429`, logical `retryable`) are propagated to the agent loop.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// `ARCANA_MC_TOKEN` is unset or empty.
    #[error("missing API key (set ARCANA_MC_TOKEN)")]
    MissingApiKey,
    /// `ARCANA_MC_TOKEN` is set but cannot be used as an HTTP credential.
    ///
    /// `reason` is written for the operator and NEVER contains the credential
    /// itself — only a description of the offending byte and its position.
    #[error("{reason}")]
    InvalidApiKey { reason: String },
    /// The request ran out of time: no response arrived within the client's
    /// budget, or the connection stalled mid-body.
    ///
    /// Split out of [`Self::Transport`] because it is the one transport class
    /// that says nothing about whether the request was bad — the server may
    /// simply still be working. Measured 2026-09-23 against the production
    /// Model Connector: a `deepseek` dispatch is given 30 s per attempt and
    /// retried once, and `connector.arcanada.ai` sits behind a Cloudflare edge
    /// that cuts every `/execute` at ~125 s. A client budget under either
    /// number turns a slow-but-healthy turn into a dead run.
    #[error("{0}")]
    Timeout(String),
    /// Transport-level failure (DNS, TLS, connect, body read).
    ///
    /// The payload already leads with its own headline ("could not connect",
    /// "timed out after 120s", …) followed by the `reqwest`/`hyper` cause
    /// chain, so this variant adds no prefix of its own.
    #[error("{0}")]
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
    /// A 201 response used a status other than the closed `success`/`error`
    /// envelope vocabulary. The upstream value is intentionally not retained
    /// in the error so an untrusted string cannot leak into logs.
    #[error("upstream returned an unexpected connector response status")]
    UnexpectedEnvelopeStatus,
    /// A connector response with `status: "error"` — an application-level
    /// failure. `http_status` retains the actual mapped HTTP status (for
    /// example 429 or 503) while the structured receipt remains available.
    #[error("{}", render_logical(.kind, .message, .recommendation, .retry_after.as_ref()))]
    Logical {
        http_status: u16,
        kind: String,
        message: String,
        retryable: bool,
        recommendation: String,
        retry_after: Option<u64>,
        first_dispatch_observation: Option<Box<UnverifiedFirstDispatchObservationV0>>,
    },
}

/// Render a logical-error envelope as one operator-facing sentence.
///
/// The wire contract carries a `recommendation` (what the caller should DO)
/// and a `retryAfter` (when it is worth trying again). Both used to be parsed
/// and then dropped by the `Display` impl, so the single field whose whole
/// purpose is remediation never reached the person who needed it. The wire
/// `kind` is kept, but as a trailing parenthetical for support rather than as
/// the headline — it is an enum name, not a sentence.
fn render_logical(
    kind: &str,
    message: &str,
    recommendation: &str,
    retry_after: Option<&u64>,
) -> String {
    use std::fmt::Write as _;
    let mut out = format!("the request was rejected — {}", end_sentence(message));
    if let Some(seconds) = retry_after {
        let _ = write!(out, " Retry after {seconds}s.");
    }
    let recommendation = recommendation.trim();
    if !recommendation.is_empty() {
        out.push(' ');
        out.push_str(&end_sentence(recommendation));
    }
    let _ = write!(out, " ({kind})");
    out
}

/// Terminate a clause so two upstream-supplied sentences do not run together.
///
/// The connector's `message` and `recommendation` are independent strings, and
/// neither is guaranteed to end in punctuation; concatenating them raw produces
/// "…balance 0.00 USD Top up your balance…".
fn end_sentence(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.ends_with(['.', '!', '?', ':', ';']) {
        return trimmed.to_owned();
    }
    format!("{trimmed}.")
}

impl ConnectorError {
    /// Return an opaque first-dispatch receipt retained from a logical-error
    /// envelope. All other error classes have no completed observation.
    #[must_use]
    pub fn first_dispatch_observation(&self) -> Option<&UnverifiedFirstDispatchObservationV0> {
        match self {
            Self::Logical {
                first_dispatch_observation,
                ..
            } => first_dispatch_observation.as_deref(),
            _ => None,
        }
    }

    /// True when the same request, sent again, could plausibly succeed.
    ///
    /// The distinction is about the REQUEST, not about the caller's patience:
    /// a missing key, a 404 connector id or a policy refusal will fail
    /// identically forever, while a timeout, a gateway status or an envelope
    /// the upstream itself marked `retryable` are all statements about this
    /// attempt. Callers use it to decide between another dispatch and
    /// [`crate::agent_loop::TerminalReason::ConnectorFatal`].
    ///
    /// `Transport` stays non-transient: a refused connection or a TLS failure
    /// is a configuration fact, and retrying it three times only delays the
    /// message the operator needs.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        match self {
            Self::Timeout(_) => true,
            // 408/425 are the request's own clock; 429 and 5xx are the
            // server's. 520..=524 are Cloudflare's edge verdicts — 524 is
            // exactly what the production origin returns when a long model
            // turn outlives the edge budget.
            Self::Http { status, .. } => matches!(
                *status,
                408 | 425 | 429 | 500 | 502 | 503 | 504 | 520..=524 | 529
            ),
            Self::Logical { retryable, .. } => *retryable,
            Self::MissingApiKey
            | Self::InvalidApiKey { .. }
            | Self::Transport(_)
            | Self::UpstreamNonJson { .. }
            | Self::UnexpectedStatus(_)
            | Self::UnexpectedEnvelopeStatus => false,
        }
    }

    /// True when a transient failure was produced by the network edge in
    /// front of Model Connector rather than by Model Connector itself.
    ///
    /// The distinction is about WHO refused. Model Connector answers in one of
    /// two shapes it authors — the connector-response envelope (which reaches
    /// us as [`Self::Logical`]) or a `NestJS` exception envelope (whose
    /// `message` becomes [`Self::Http::message`] verbatim). A gateway status
    /// whose body is neither is nobody's contract: measured on pilot
    /// A2-204c5 (2026-09-23) the body was the 16 bytes `error code: 502`,
    /// which is Cloudflare's, not ours.
    ///
    /// Why it earns its own class: an edge verdict says the request never
    /// reached a decision at all, and the edge heals in tens of seconds, so it
    /// is worth waiting out. A `retryable` envelope Model Connector authored
    /// already has Model Connector's own server-side attempts behind it, so a
    /// long client-side wait on top buys much less. The two therefore get
    /// different retry budgets in [`crate::agent_loop`].
    ///
    /// Narrow on purpose: the status must be a gateway status AND the body
    /// must have defeated both parsers. A 500 is excluded — an unhandled
    /// exception inside Model Connector is Model Connector's, and retrying it
    /// five times only delays the report.
    #[must_use]
    pub fn is_edge_gateway_failure(&self) -> bool {
        match self {
            Self::Http {
                status, message, ..
            } => {
                matches!(*status, 502 | 503 | 504 | 520..=524)
                    && message.contains(NON_CONTRACT_BODY_HEADLINE)
            }
            _ => false,
        }
    }

    /// True when the request may nevertheless have been carried out upstream.
    ///
    /// This is a billing fact, not a transport one, and it decides what the
    /// retry log is allowed to claim. Model Connector opens a hold, calls the
    /// provider, and settles the charge in the same transaction as the request
    /// row **before** the response is written to the socket
    /// (`src/connectors/connectors.service.ts`, `ARAS-0058`: "nothing is
    /// returned to the caller until the row and the charge have committed
    /// together"; a provider that throws goes down the `releaseIntent` path and
    /// is not charged). So:
    ///
    /// * an edge verdict or a client-side timeout cut a response that may
    ///   already have been produced, billed and lost;
    /// * an envelope Model Connector authored means the provider call failed
    ///   and the hold was released, so nothing was charged and a retry is
    ///   clean.
    ///
    /// Since A2-234 this is a statement about the FIRST attempt only. A
    /// re-dispatch carries the same [`IDEMPOTENCY_HEADER`], so a request that
    /// was executed and billed comes back as a stored replay — one provider
    /// call and one ledger row however many times the client re-POSTs
    /// (`src/billing/billing.service.ts`, `resolveReplay`). What this now
    /// decides is which sentence the retry log prints, not whether the money
    /// is spent twice; see [`crate::agent_loop`]'s `retry_line`.
    #[must_use]
    pub fn response_may_have_been_completed_upstream(&self) -> bool {
        matches!(self, Self::Timeout(_)) || self.is_edge_gateway_failure()
    }

    /// The `error.type` of an envelope Model Connector authored, if this is
    /// one. `None` for every transport-, status- or parse-level failure.
    #[must_use]
    pub fn logical_kind(&self) -> Option<&str> {
        match self {
            Self::Logical { kind, .. } => Some(kind),
            _ => None,
        }
    }

    /// True when Model Connector refused because the FIRST attempt under this
    /// turn's key is still running.
    ///
    /// Not a failure of this turn and not a reason to mint a new key: Model
    /// Connector's own words are "Retry shortly to receive its result; do not
    /// reissue it under a new key or it will be dispatched and charged twice."
    /// The right response is to wait on the answer we have already paid for,
    /// which is why [`crate::agent_loop`] gives this the patient schedule
    /// rather than the two flat re-dispatches a connector envelope gets.
    #[must_use]
    pub fn is_idempotency_conflict(&self) -> bool {
        self.logical_kind() == Some(IDEMPOTENCY_CONFLICT)
    }

    /// True when the key was already claimed by a different payload.
    ///
    /// On our side this can only be a defect in this runner — the key is
    /// stable across an attempt-series precisely because the payload is — so
    /// it is reported as one rather than retried. Nothing was dispatched and
    /// nothing was charged under it.
    #[must_use]
    pub fn is_idempotency_key_reused(&self) -> bool {
        self.logical_kind() == Some(IDEMPOTENCY_KEY_REUSED)
    }

    /// True when the request completed and was charged exactly once, but its
    /// answer was too large to store for replay.
    ///
    /// The one failure class that is terminal AND paid for. Retrying it would
    /// buy a second execution of work already bought, which is why Model
    /// Connector marks it non-retryable and why the verdict has to say the
    /// money is gone rather than implying the turn never ran.
    #[must_use]
    pub fn is_idempotency_replay_unavailable(&self) -> bool {
        self.logical_kind() == Some(IDEMPOTENCY_REPLAY_UNAVAILABLE)
    }

    /// The status an operator can act on, whatever shape the failure took.
    ///
    /// [`Self::Logical`]'s `Display` deliberately leads with the upstream's
    /// own words and never names the HTTP status; a terminal verdict has to
    /// name it anyway, so the label is derived here once.
    #[must_use]
    pub fn status_label(&self) -> String {
        match self {
            Self::MissingApiKey => "no API key".to_owned(),
            Self::InvalidApiKey { .. } => "unusable API key".to_owned(),
            Self::Timeout(_) => "client timeout".to_owned(),
            Self::Transport(_) => "transport failure".to_owned(),
            Self::Http { status, .. } | Self::UnexpectedStatus(status) => format!("HTTP {status}"),
            Self::UpstreamNonJson { .. } => "non-JSON body".to_owned(),
            Self::UnexpectedEnvelopeStatus => "unexpected envelope status".to_owned(),
            Self::Logical {
                http_status, kind, ..
            } => format!("HTTP {http_status} {kind}"),
        }
    }

    /// The failure's own words, without the status [`Self::status_label`]
    /// already states.
    #[must_use]
    pub fn detail_text(&self) -> String {
        match self {
            Self::Http { message, .. } => message.clone(),
            other => other.to_string(),
        }
    }

    /// True when the upstream refused the request for its size rather than
    /// for anything about its content.
    ///
    /// Two shapes, both measured against production Model Connector on
    /// 2026-09-23 (A2-205, and the pilot run this exists for):
    ///
    /// * a field over its Zod ceiling —
    ///   `HTTP 400 {"message":"Validation failed","errors":["prompt: Too big:
    ///   expected string to have <=100000 characters"]}`. Fastify's own
    ///   `NestJS` envelope is not used for it, so the text arrives inside the
    ///   "non-contract error body" excerpt rather than as `message`, and the
    ///   match has to look at the whole rendered string.
    /// * the whole body over the server's limit — `HTTP 413
    ///   {"statusCode":413,"message":"Request body is too large"}`.
    ///
    /// Matching on text is a last line of defence, not the mechanism: the
    /// loop's own budget is what keeps requests inside the contract. This
    /// exists so that if the ceiling ever moves down under us, the run says so
    /// instead of blaming the connector — and so it is deliberately narrow,
    /// requiring a size word and not merely a 400.
    #[must_use]
    pub fn is_request_too_large(&self) -> bool {
        match self {
            Self::Http {
                status, message, ..
            } => {
                if *status == 413 {
                    return true;
                }
                if *status != 400 {
                    return false;
                }
                let text = message.to_ascii_lowercase();
                text.contains("too big") || text.contains("too large")
            }
            _ => false,
        }
    }

    /// How long the upstream asked the caller to wait before trying again.
    #[must_use]
    pub const fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Self::Http { retry_after, .. } | Self::Logical { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
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

    // --- logical-error rendering (issue #109) ------------------------------

    fn logical(recommendation: &str, retry_after: Option<u64>) -> ConnectorError {
        ConnectorError::Logical {
            http_status: 402,
            kind: "insufficient_credit".into(),
            message: "Insufficient credit: balance 0.00 USD".into(),
            retryable: retry_after.is_some(),
            recommendation: recommendation.into(),
            retry_after,
            first_dispatch_observation: None,
        }
    }

    #[test]
    fn logical_display_shows_the_recommendation() {
        // The recommendation is the one field on the wire whose entire purpose
        // is to tell the caller what to DO. It used to be parsed and dropped.
        let rendered =
            logical("Top up your balance at https://billing.arcanada.ai", None).to_string();
        assert!(
            rendered.contains("Top up your balance at https://billing.arcanada.ai"),
            "recommendation missing from: {rendered}"
        );
        assert!(rendered.contains("Insufficient credit: balance 0.00 USD"));
    }

    #[test]
    fn logical_display_shows_the_retry_interval() {
        let rendered = logical("Retry or pick another model", Some(30)).to_string();
        assert!(
            rendered.contains("Retry after 30s."),
            "retry_after missing from: {rendered}"
        );
    }

    #[test]
    fn logical_display_leads_with_the_message_not_the_wire_enum() {
        // `kind` is an enum name, useful to support and meaningless to a
        // customer, so it must not be the headline.
        let rendered = logical("", None).to_string();
        assert!(
            rendered.starts_with("the request was rejected — Insufficient credit"),
            "unexpected headline: {rendered}"
        );
        assert!(
            rendered.ends_with("(insufficient_credit)"),
            "kind should survive as a trailing parenthetical: {rendered}"
        );
    }

    #[test]
    fn logical_display_omits_an_absent_recommendation_cleanly() {
        // An empty recommendation must not leave a dangling separator.
        let rendered = logical("   ", None).to_string();
        assert_eq!(
            rendered,
            "the request was rejected — Insufficient credit: balance 0.00 USD. (insufficient_credit)"
        );
    }

    #[test]
    fn two_upstream_sentences_do_not_run_together() {
        // "…balance 0.00 USD Top up your balance…" — the message and the
        // recommendation are separate strings and neither is punctuated.
        let rendered = logical("Top up your balance", None).to_string();
        assert!(
            rendered.contains("USD. Top up your balance."),
            "sentences ran together: {rendered}"
        );
    }

    #[test]
    fn transport_display_carries_no_redundant_prefix() {
        let rendered =
            ConnectorError::Transport("could not connect: tcp connect error".into()).to_string();
        assert_eq!(rendered, "could not connect: tcp connect error");
    }

    #[test]
    fn execute_request_omits_unset_optionals() {
        let req = ExecuteRequest::new("claude-code", "ping");
        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["connector"], "claude-code");
        assert_eq!(json["prompt"], "ping");
        assert!(json.get("model").is_none(), "unset optional must be absent");
        assert!(json.get("systemPrompt").is_none());
        assert!(json.get("maxTurns").is_none());
        assert!(json.get("firstDispatchMeasurement").is_none());
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
