//! `ScrutatorClient` — thin `reqwest` wrapper around Scrutator's hybrid
//! search endpoint (`POST /v1/search`).
//!
//! The request/response shapes mirror the upstream Pydantic model
//! `scrutator.db.models.SearchRequest` verbatim. there is no
//! rerank parameter on `/v1/search` — this client does not add one; it
//! forwards the hybrid-search contract as-is.

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use serde::de::DeserializeOwned;
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
    /// The **server-side** maturity floor (`"production"`) for skill
    /// discovery. Additive with `skip_serializing_if` — omitted for every
    /// pre-existing caller, so the wire shape is unchanged unless discovery sets
    /// it. The server excludes any skill below this maturity before ranking, so
    /// draft/validated plans are never returned (no client-side post-filter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maturity: Option<String>,
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
            maturity: None,
        }
    }

    /// the skill-discovery query shape — scoped to the skills
    /// namespace with a **server-side** `maturity` floor, ranked metadata only
    /// (no document bodies, since discovery only proposes). The returned hits'
    /// `metadata` carries `{name, version, maturity}` and their `content_hash`
    /// the SHA-256 staleness signal — never a run-path anchor.
    #[must_use]
    pub fn for_skill_discovery(
        intent: impl Into<String>,
        maturity_floor: impl Into<String>,
        limit: u32,
    ) -> Self {
        Self {
            query: intent.into(),
            namespace: Some("skills".to_owned()),
            project: None,
            source_type: None,
            limit: Some(limit),
            min_score: None,
            include_content: Some(false),
            maturity: Some(maturity_floor.into()),
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
    /// the KB's SHA-256 ingest-bound content digest. A cache /
    /// staleness signal only — **never** a run-path trust anchor. Additive with
    /// `#[serde(default)]` for back-compat with responses that predate it.
    #[serde(default)]
    pub content_hash: String,
    /// the opaque `source_id` a caller can later pin and re-fetch
    /// via `POST /v1/fetch`. Additive with `#[serde(default)]`.
    #[serde(default)]
    pub source_id: String,
}

/// `POST /v1/search` response envelope.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct SearchResponse {
    #[serde(default)]
    pub results: Vec<SearchHit>,
}

/// The `range` selector for `POST /v1/fetch`. Mirrors the upstream
/// Pydantic union `Literal["full"] | ParentOfChunkRange`: serialises to either
/// the bare string `"full"` (whole document) or the object
/// `{"parent_of_chunk": "<chunk_uuid>"}` (the native server-side
/// auto-merge-to-parent slice —). `Serialize`-only, like [`FetchQuery`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchRangeSpec {
    /// Whole document. Wire form: the string literal `"full"`.
    Full,
    /// The whole parent document of the chunk `chunk_id` (native
    /// auto-merge-to-parent). Wire form:
    /// `{"parent_of_chunk": "<chunk_uuid>"}`.
    ParentOfChunk(String),
}

impl Serialize for FetchRangeSpec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            FetchRangeSpec::Full => serializer.serialize_str("full"),
            FetchRangeSpec::ParentOfChunk(chunk_id) => {
                use serde::ser::SerializeStruct;
                let mut range = serializer.serialize_struct("ParentOfChunkRange", 1)?;
                range.serialize_field("parent_of_chunk", chunk_id)?;
                range.end()
            }
        }
    }
}

/// Request body for `POST /v1/fetch`. Fetches an exact document by
/// an opaque key (`source_id` / `document_id` / `chunk_id`) — never a path-like
/// id. Field names mirror the endpoint spec.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FetchQuery {
    /// The key kind: `"source_id"`, `"document_id"`, or `"chunk_id"`.
    pub by: String,
    /// The opaque id to fetch.
    pub id: String,
    /// The range selector: `"full"` (whole doc) or a native `parent_of_chunk`
    /// range.
    pub range: FetchRangeSpec,
    /// Which sections to include (e.g. `["content", "provenance"]`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
}

impl FetchQuery {
    /// A whole-document fetch by pinned `source_id`, including content and
    /// provenance (the run-path shape).
    #[must_use]
    pub fn by_source_id(id: impl Into<String>) -> Self {
        Self {
            by: "source_id".to_owned(),
            id: id.into(),
            range: FetchRangeSpec::Full,
            include: vec!["content".to_owned(), "provenance".to_owned()],
        }
    }

    /// a NATIVE server-side parent-of-chunk fetch. Pins the opaque
    /// `source_id` and requests the whole parent document of `chunk_id` via the
    /// `range: {parent_of_chunk}` selector — instead of a whole-document
    /// `range="full"` fetch windowed agent-side. The top-level `by`/`id` pin the
    /// source; the server resolves the parent from the `parent_of_chunk` chunk id
    /// (the selector is validated but the parent range overrides resolution).
    #[must_use]
    pub fn parent_of_chunk(source_id: impl Into<String>, chunk_id: impl Into<String>) -> Self {
        Self {
            by: "source_id".to_owned(),
            id: source_id.into(),
            range: FetchRangeSpec::ParentOfChunk(chunk_id.into()),
            include: vec!["content".to_owned(), "provenance".to_owned()],
        }
    }
}

/// One entry of a `POST /v1/fetch` chunk manifest.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ChunkManifestEntry {
    pub chunk_id: String,
    pub offset_start: u64,
    pub offset_end: u64,
}

/// `POST /v1/fetch` response envelope. All fields beyond
/// `source_id` are `#[serde(default)]` so the shape tolerates a partial
/// `include`. In Phase 1 the type only **deserialises** `trust_class` — the
/// pre-parse `trust_class` fence (`WrongTrustClass`, V-AC-12) is Phase-2 scope.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct FetchResponse {
    pub source_id: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub content_len_tokens: u64,
    /// KB SHA-256 ingest digest — cache/staleness signal, not a trust anchor.
    #[serde(default)]
    pub content_hash: String,
    #[serde(default)]
    pub index_snapshot_id: String,
    #[serde(default)]
    pub indexed_at: String,
    #[serde(default)]
    pub embedding_model_id: String,
    #[serde(default)]
    pub namespace: String,
    /// The KB's trust classification (`"skill"`, `"evidence"`, …). Deserialised
    /// only this cycle; the run-path fence is Phase 2.
    #[serde(default)]
    pub trust_class: String,
    #[serde(default)]
    pub chunk_manifest: Vec<ChunkManifestEntry>,
    #[serde(default)]
    pub stale: bool,
    /// 1a: `true` when `content` is the EXACT stored source bytes
    /// (skills namespace — `sha256(content) == content_hash` by construction at
    /// `range="full"`); `false` when `content` is a best-effort, lossy
    /// reassembly of embedding chunks (evidence namespace). Additive, defaulted
    /// `false` (conservative: absent ⇒ best-effort) — non-breaking. The skills
    /// run path does not gate on this: the store's config-pinned blake3 keystone
    /// independently rejects any lossy body (a lossy reassembly cannot match the
    /// pinned blake3), so `content_exact` is carried for observability only.
    #[serde(default)]
    pub content_exact: bool,
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
        self.endpoint_url("search")
    }

    fn fetch_url(&self) -> Result<Url, ScrutatorError> {
        self.endpoint_url("fetch")
    }

    fn endpoint_url(&self, endpoint: &str) -> Result<Url, ScrutatorError> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| ScrutatorError::Transport("base URL cannot be a base".into()))?
            .push("v1")
            .push(endpoint);
        Ok(url)
    }

    /// Execute one hybrid-search request against `POST /v1/search`.
    ///
    /// # Errors
    /// Transport, HTTP-status, and decode failures map to
    /// [`ScrutatorError`].
    pub async fn search(&self, query: &SearchQuery) -> Result<SearchResponse, ScrutatorError> {
        self.post_json(self.search_url()?, query).await
    }

    /// Fetch one exact document by opaque id against `POST /v1/fetch`
    ///. The run-path shape pins `source_id` and requests the whole
    /// document; the returned `content` bytes are the input to the interpreter's
    /// local blake3 verify-before-parse keystone (in `arcana-skills`).
    ///
    /// # Errors
    /// Transport, HTTP-status, and decode failures map to [`ScrutatorError`]
    /// (e.g. a cross-namespace `403` surfaces as [`ScrutatorError::Http`], never
    /// a silent empty document — F5).
    pub async fn fetch(&self, query: &FetchQuery) -> Result<FetchResponse, ScrutatorError> {
        self.post_json(self.fetch_url()?, query).await
    }

    /// Shared `POST`-JSON transport: bearer auth with a single 401-triggered
    /// token refresh, no redirects, typed success/error decode. Used verbatim
    /// by both `search` and `fetch` so their wire semantics stay identical.
    async fn post_json<B, R>(&self, url: Url, body: &B) -> Result<R, ScrutatorError>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let mut refreshed = false;
        let resp = loop {
            let token = self.token_provider.bearer_token().await?;
            let response = self
                .http
                .post(url.clone())
                .header(reqwest::header::ACCEPT, "application/json")
                .bearer_auth(token.expose_secret())
                .json(body)
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

/// Why a production skills-store could not be constructed at composition time
///. Distinct arms so the driver can tell an operator-config error
/// (bad `ARCANA_SKILLS_SOURCE`) from a live-KB client build failure.
#[derive(Debug, thiserror::Error)]
pub enum SkillStoreInitError {
    /// The `ARCANA_SKILLS_SOURCE` selector was set to an unrecognised value.
    #[error(transparent)]
    Selector(#[from] arcana_skills::UnknownSkillSource),
    /// Production mode was selected but the live `ScrutatorClient` (base URL /
    /// OAuth credentials) could not be built. Fails closed — the driver must NOT
    /// silently degrade to the trusted `FileStore`.
    #[error("production skills source selected but the Scrutator client is unavailable: {0}")]
    Client(#[from] ScrutatorError),
}

/// production cutover: build the skills byte-acquisition
/// [`arcana_skills::SkillStore`] the agent driver loads plans from, selected by
/// the `ARCANA_SKILLS_SOURCE` environment variable (see
/// [`arcana_skills::SkillSourceMode`]).
///
/// * **Production** (the fail-closed default — unset/blank selector): delegates
///   to [`arcana_skills::select_skill_store`] with a real
///   [`ScrutatorClient::try_from_env`], so every skill load runs the full 0047
///   gate chain (`trust_class` fence → config-pinned blake3 keystone → parse →
///   schema validate) over the untrusted KB. If the client cannot be built the
///   call fails closed with [`SkillStoreInitError::Client`] — it never falls back
///   to the trusted local [`arcana_skills::FileStore`].
/// * **Bootstrap** (`ARCANA_SKILLS_SOURCE=bootstrap|file|offline`): returns the
///   trusted `FileStore` for bundled/offline ids and constructs **no** network
///   client (offline-safe — bootstrap must not require OAuth reachability).
///
/// # Errors
///
/// Returns [`SkillStoreInitError::Selector`] for an unrecognised selector, or
/// [`SkillStoreInitError::Client`] if the production Scrutator client cannot be
/// constructed.
pub fn skill_store_from_env() -> Result<Box<dyn arcana_skills::SkillStore>, SkillStoreInitError> {
    let mode = arcana_skills::SkillSourceMode::from_env()?;
    match mode {
        arcana_skills::SkillSourceMode::Production => {
            let client = Arc::new(ScrutatorClient::try_from_env()?);
            Ok(arcana_skills::select_skill_store(mode, client))
        }
        // Offline path: never build a network client. FileStore is the trust
        // root for bundled ids; `select_skill_store` would ignore the connector
        // in this arm anyway, so we short-circuit to keep bootstrap OAuth-free.
        arcana_skills::SkillSourceMode::Bootstrap => Ok(Box::new(arcana_skills::FileStore)),
    }
}

/// Live adapter: bridges the `arcana-skills` `FetchConn` seam to the real
/// `POST /v1/fetch` endpoint. A `ScrutatorStore` wraps an
/// `Arc<ScrutatorClient>` and drives the skill run path through this impl.
///
/// The adapter is a pure transport + shape mapping: it pins the opaque
/// `source_id` for a whole-document fetch, forwards the exact `content` bytes
/// (UTF-8) plus the server-derived `trust_class` / `namespace` envelope, and
/// maps every [`ScrutatorError`] — transport, non-2xx (incl. a cross-namespace
/// `403`), non-JSON — to a fail-closed `FetchUnavailable` (never a silent empty
/// document — F5). All *policy* — the `trust_class` fence, the config-pinned
/// blake3 keystone, parse — lives in the `ScrutatorStore`, never here. The
/// SHA-256 `content_hash` in the response is deliberately NOT consulted as a
/// trust anchor: it is an ingest-bound provenance/staleness signal of a
/// different algorithm and role from the store's blake3 run-path anchor.
#[async_trait::async_trait]
impl arcana_skills::FetchConn for ScrutatorClient {
    async fn fetch(
        &self,
        source_id: &str,
    ) -> Result<arcana_skills::FetchedContent, arcana_skills::FetchUnavailable> {
        let query = FetchQuery::by_source_id(source_id);
        let resp = ScrutatorClient::fetch(self, &query)
            .await
            .map_err(|err| arcana_skills::FetchUnavailable(err.to_string()))?;
        Ok(arcana_skills::FetchedContent {
            bytes: resp.content.into_bytes(),
            trust_class: resp.trust_class,
            namespace: resp.namespace,
        })
    }
}

/// Live adapter: bridges the `arcana-core` KB-cascade `EvidenceFetch` seam
/// to the real `POST /v1/fetch` endpoint. A `KbCascade`
/// wraps an `Arc<ScrutatorClient>` and drives the evidence read path through
/// this impl.
///
/// Like the skills [`arcana_skills::FetchConn`] adapter, this is a pure
/// transport + shape mapping: it forwards the server-derived `trust_class` /
/// `namespace` / `content_hash` envelope untouched (all *policy* — the
/// `trust_class` fence, size-guard, fence/datamark — lives in the cascade,
/// never here) and maps every [`ScrutatorError`] to a fail-closed
/// `FetchUnavailable`.
///
/// **Native parent-range mapping.** `FetchRange::Full` issues a
/// whole-document fetch (`by_source_id`, `range="full"`); `FetchRange::ParentOfChunk`
/// now issues the NATIVE server-side `range: {parent_of_chunk}` selector
/// so the KB — not the agent — scopes the parent, reducing over-fetch.
/// For either range the answer offset is recovered from the response
/// `chunk_manifest`, so rerank-to-edge still targets the right span within the
/// returned body.
///
/// **Backward compatibility.** An older index that cannot satisfy the object-form
/// range rejects it with `422 Unprocessable Entity`; on exactly that status this
/// adapter falls back to the path — a whole-document fetch windowed
/// agent-side via the size-guard. Every other failure — transport, `403`
/// cross-namespace, `404`, `5xx` — fails closed to `FetchUnavailable` (never a
/// silent empty document, never a fallback that masks a real error — F5). This is
/// an additive change to WHAT is fetched; the `trust_class` fence and size-guard
/// stay in the cascade, untouched here.
#[async_trait::async_trait]
impl arcana_core::kb::EvidenceFetch for ScrutatorClient {
    async fn fetch(
        &self,
        source_id: &str,
        range: arcana_core::kb::FetchRange,
    ) -> Result<arcana_core::kb::FetchedEvidence, arcana_core::kb::FetchUnavailable> {
        let resp = match &range {
            arcana_core::kb::FetchRange::Full => {
                ScrutatorClient::fetch(self, &FetchQuery::by_source_id(source_id))
                    .await
                    .map_err(|err| arcana_core::kb::FetchUnavailable(err.to_string()))?
            }
            arcana_core::kb::FetchRange::ParentOfChunk(chunk_id) => {
                // ARAS-0052: request the NATIVE server-side parent range first.
                match ScrutatorClient::fetch(
                    self,
                    &FetchQuery::parent_of_chunk(source_id, chunk_id),
                )
                .await
                {
                    Ok(resp) => resp,
                    // 422 = older index cannot satisfy the object-form range →
                    // fall back to whole-doc + agent-side windowing (0049 path).
                    Err(ScrutatorError::Http { status: 422, .. }) => {
                        ScrutatorClient::fetch(self, &FetchQuery::by_source_id(source_id))
                            .await
                            .map_err(|err| arcana_core::kb::FetchUnavailable(err.to_string()))?
                    }
                    // Every other error fails closed as before (F5).
                    Err(err) => {
                        return Err(arcana_core::kb::FetchUnavailable(err.to_string()));
                    }
                }
            }
        };
        let answer_offset = match &range {
            arcana_core::kb::FetchRange::ParentOfChunk(chunk_id) => resp
                .chunk_manifest
                .iter()
                .find(|entry| &entry.chunk_id == chunk_id)
                .map_or(0, |entry| entry.offset_start),
            arcana_core::kb::FetchRange::Full => 0,
        };
        Ok(arcana_core::kb::FetchedEvidence {
            source_id: resp.source_id,
            path: resp.path,
            content: resp.content,
            content_hash: resp.content_hash,
            index_snapshot_id: resp.index_snapshot_id,
            namespace: resp.namespace,
            trust_class: resp.trust_class,
            answer_offset,
        })
    }
}

/// Live adapter: bridges the `arcana-skills` `SkillSearch` seam to
/// the real `POST /v1/search` endpoint. A `SkillDiscovery` wraps an
/// `Arc<ScrutatorClient>` and drives semantic skill discovery through this impl.
///
/// The adapter is a pure transport + shape mapping: it issues a
/// [`SearchQuery::for_skill_discovery`] carrying the skills namespace and the
/// **server-side** `maturity` floor (so draft/validated plans are excluded by
/// the service, never post-filtered here), and maps each ranked [`SearchHit`]'s
/// `metadata` (`{name, version, maturity}`) + `content_hash` + `score` to a
/// non-authorizing `SkillHit`. A hit whose metadata is missing/malformed is
/// dropped (it cannot be proposed as a candidate). All *authorization* — the
/// config-pinned blake3 keystone, the `trust_class` fence — lives on the
/// run-path `ScrutatorStore`, never here: discovery only proposes. Every
/// [`ScrutatorError`] maps to a fail-closed `SearchUnavailable` (never a silent
/// empty proposal that hides a backend outage as "no matches").
#[async_trait::async_trait]
impl arcana_skills::SkillSearch for ScrutatorClient {
    async fn search(
        &self,
        query: &arcana_skills::DiscoverQuery,
    ) -> Result<Vec<arcana_skills::SkillHit>, arcana_skills::SearchUnavailable> {
        let floor = maturity_wire(query.min_maturity);
        let request = SearchQuery::for_skill_discovery(&query.intent, floor, query.limit);
        let response = ScrutatorClient::search(self, &request)
            .await
            .map_err(|err| arcana_skills::SearchUnavailable(err.to_string()))?;
        Ok(response
            .results
            .into_iter()
            .filter_map(|hit| skill_hit_from(&hit))
            .collect())
    }
}

/// The lowercase wire token for a maturity floor (mirrors `Maturity`'s serde
/// `rename_all = "lowercase"`).
fn maturity_wire(maturity: arcana_skills::Maturity) -> &'static str {
    match maturity {
        arcana_skills::Maturity::Draft => "draft",
        arcana_skills::Maturity::Validated => "validated",
        arcana_skills::Maturity::Production => "production",
    }
}

/// Map one `/v1/search` hit to a non-authorizing `SkillHit`, reading
/// `{name, version, maturity}` from the hit's server-side `metadata` envelope.
/// Returns `None` (dropping the hit) if the required proposal fields are absent
/// or malformed — a candidate can only be proposed from complete metadata.
fn skill_hit_from(hit: &SearchHit) -> Option<arcana_skills::SkillHit> {
    let meta = hit.metadata.as_ref()?;
    let name = meta.get("name")?.as_str()?.to_owned();
    let version = u32::try_from(meta.get("version")?.as_u64()?).ok()?;
    let maturity: arcana_skills::Maturity =
        serde_json::from_value(meta.get("maturity")?.clone()).ok()?;
    Some(arcana_skills::SkillHit {
        name,
        version,
        content_hash: hit.content_hash.clone(),
        maturity,
        score: hit.score,
    })
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
    fn fetch_url_appends_v1_fetch_on_the_approved_mesh_host() {
        let client = ScrutatorClient::new(
            Url::parse("http://100.70.137.104:8310").unwrap(),
            test_provider(),
        )
        .expect("client builds");
        assert_eq!(
            client.fetch_url().unwrap().as_str(),
            "http://100.70.137.104:8310/v1/fetch"
        );
    }

    #[test]
    fn fetch_query_by_source_id_matches_f1_shape() {
        let query = FetchQuery::by_source_id("kb:skill:codegen-review:3:9f2c");
        let json = serde_json::to_value(&query).expect("serialize");
        assert_eq!(json["by"], "source_id");
        assert_eq!(json["id"], "kb:skill:codegen-review:3:9f2c");
        assert_eq!(json["range"], "full");
        assert_eq!(
            json["include"],
            serde_json::json!(["content", "provenance"])
        );
    }

    #[test]
    fn fetch_query_parent_of_chunk_serialises_native_range_object() {
        // ARAS-0052: the parent escalation emits the object-form range
        // `{parent_of_chunk: <uuid>}`, NOT the `"full"` string — the wire shape
        // that lets the server scope the parent instead of the agent windowing
        // the whole doc.
        let query = FetchQuery::parent_of_chunk(
            "kb:evidence:runbook-x:5:1a2b",
            "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        );
        let json = serde_json::to_value(&query).expect("serialize");
        assert_eq!(json["by"], "source_id");
        assert_eq!(json["id"], "kb:evidence:runbook-x:5:1a2b");
        assert_eq!(
            json["range"]["parent_of_chunk"],
            "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
        );
        assert!(
            json["range"].as_str().is_none(),
            "parent range must be an object, never the \"full\" string"
        );
        assert_eq!(
            json["include"],
            serde_json::json!(["content", "provenance"])
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

    #[test]
    fn search_query_new_omits_maturity_on_the_wire() {
        // ARAS-0050: the additive `maturity` field must not appear for the
        // pre-existing minimal query — the wire shape is unchanged.
        let query = SearchQuery::new("hello");
        let json = serde_json::to_value(&query).expect("serialize");
        assert!(json.get("maturity").is_none());
    }

    #[test]
    fn for_skill_discovery_carries_namespace_and_production_floor() {
        // The discovery request expresses the maturity floor SERVER-SIDE (a
        // request field the service filters on) — not a client post-filter.
        let query = SearchQuery::for_skill_discovery("review my pr diff", "production", 5);
        let json = serde_json::to_value(&query).expect("serialize");
        assert_eq!(json["query"], "review my pr diff");
        assert_eq!(json["namespace"], "skills");
        assert_eq!(json["maturity"], "production");
        assert_eq!(json["limit"], 5);
        assert_eq!(json["include_content"], false);
    }

    #[test]
    fn skill_hit_from_maps_server_side_metadata() {
        let hit = SearchHit {
            chunk_id: "c1".into(),
            content: String::new(),
            source_path: "kb:skill:codegen-review:3".into(),
            source_type: "skill".into(),
            chunk_index: 0,
            score: 0.91,
            namespace: Some("skills".into()),
            project: None,
            metadata: Some(serde_json::json!({
                "name": "codegen-review", "version": 3, "maturity": "production"
            })),
            content_hash: "sha256:deadbeef".into(),
            source_id: "kb:skill:codegen-review:3".into(),
        };
        let mapped = skill_hit_from(&hit).expect("complete metadata maps");
        assert_eq!(mapped.name, "codegen-review");
        assert_eq!(mapped.version, 3);
        assert_eq!(mapped.maturity, arcana_skills::Maturity::Production);
        assert_eq!(mapped.content_hash, "sha256:deadbeef");
        assert!((mapped.score - 0.91).abs() < f64::EPSILON);
    }

    #[test]
    fn skill_hit_from_drops_incomplete_metadata() {
        // A hit missing the maturity field cannot be proposed as a candidate.
        let hit = SearchHit {
            chunk_id: "c1".into(),
            content: String::new(),
            source_path: "p".into(),
            source_type: "skill".into(),
            chunk_index: 0,
            score: 0.5,
            namespace: Some("skills".into()),
            project: None,
            metadata: Some(serde_json::json!({ "name": "x", "version": 1 })),
            content_hash: "sha256:00".into(),
            source_id: "s".into(),
        };
        assert!(skill_hit_from(&hit).is_none());
        // …and a hit with no metadata at all.
        let mut bare = hit;
        bare.metadata = None;
        assert!(skill_hit_from(&bare).is_none());
    }
}
