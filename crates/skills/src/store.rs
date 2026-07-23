//! The skill-storage seam — a pluggable byte-acquisition backend behind the
//! interpreter.
//!
//! A [`SkillStore`] turns a config-authored [`SkillPin`] into a validated
//! [`SkillPlan`]. Two backends exist this cycle:
//!
//! * [`FileStore`] — the trusted local path (today's `fs::read` + parse,
//!   byte-identical). The local file *is* the trust root, so it performs no
//!   blake3 verification.
//! * [`ScrutatorStore`] — the untrusted KB path. Bytes fetched over the network
//!   are rejected **before parse** unless their locally-recomputed full blake3
//!   equals the config-pinned hash (the trust keystone). A blake3-content-
//!   addressed [`BlakeCache`] short-circuits the network; a store failure with
//!   no verified cache entry fails closed to [`SkillError::StoreUnavailable`] —
//!   it never falls back to a different or stale skill.
//!
//! **Two-phase firewall.** A [`SkillCandidate`] (a fuzzy search proposal) can
//! only *propose*; it carries no `blake3` and no authorization to run. A
//! [`SkillPin`] (the authorization to run) is config-authored. There is
//! deliberately no `SkillCandidate` → `SkillPin` conversion: search proposes,
//! config authorizes.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use crate::interpreter::SkillError;
use crate::plan::{Maturity, SkillPlan};

/// A config-authored, pinned reference to a skill's exact bytes.
///
/// `blake3` and `source_id` are supplied from **trusted config** at
/// pin-authoring time — never derived from a fuzzy [`SkillCandidate`]. This is
/// the load-bearing half of the two-phase firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillPin {
    /// Human-readable skill name (informational).
    pub name: String,
    /// Pinned content version (informational).
    pub version: u32,
    /// Full blake3 hex of the exact content bytes — the sole run-path trust
    /// anchor. Empty for a [`FileStore`] pin (the local file is trusted).
    pub blake3: String,
    /// Opaque KB `source_id` (or, for [`FileStore`], the local file path).
    pub source_id: String,
}

impl SkillPin {
    /// Construct a network pin from trusted config values.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: u32,
        blake3: impl Into<String>,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version,
            blake3: blake3.into(),
            source_id: source_id.into(),
        }
    }

    /// Construct a pin for a trusted local file: no network hash anchor is
    /// required because the local filesystem is the trust root.
    #[must_use]
    pub fn local(path: impl Into<String>) -> Self {
        Self {
            name: String::new(),
            version: 0,
            blake3: String::new(),
            source_id: path.into(),
        }
    }
}

/// A fuzzy search proposal for a skill. Deliberately carries **no** `blake3`
/// and **no** run authorization.
///
/// `content_hash` is the KB's SHA-256 ingest-bound digest — a cache/staleness
/// signal only, of a different algorithm and role from the run-path blake3
/// trust anchor. There is intentionally no path from a `SkillCandidate` to a
/// [`SkillPin`]: a candidate can only *propose* a skill to a human/config
/// author, who then pins it (search proposes, config authorizes).
///
/// The firewall is **type-level**: there is no `From<SkillCandidate>` for
/// [`SkillPin`] and no method returning one, so a candidate can never be turned
/// directly into run authorization. The following does not compile:
///
/// ```compile_fail
/// use arcana_skills::{Maturity, SkillCandidate, SkillPin};
/// let candidate = SkillCandidate {
///     name: "codegen-review".into(),
///     version: 3,
///     content_hash: "sha256:deadbeef".into(),
///     maturity: Maturity::Production,
///     score: 0.94,
/// };
/// // ERROR[E0277]: the trait `From<SkillCandidate>` is not implemented for
/// // `SkillPin` — search proposes, config authorizes.
/// let _pin: SkillPin = candidate.into();
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SkillCandidate {
    /// Proposed skill name.
    pub name: String,
    /// Proposed skill version.
    pub version: u32,
    /// SHA-256 ingest digest — a staleness signal, **never** a trust anchor.
    pub content_hash: String,
    /// Proposed maturity (advisory; the run-path floor is re-checked on load).
    pub maturity: Maturity,
    /// Relevance score from the search backend.
    pub score: f64,
}

/// A pluggable byte-acquisition backend for skill plans.
#[async_trait::async_trait]
pub trait SkillStore: Send + Sync {
    /// Resolve `pin` to a validated [`SkillPlan`].
    ///
    /// # Errors
    ///
    /// Returns [`SkillError`] on read/fetch failure, a blake3 mismatch (before
    /// parse), a parse failure, or intrinsic-validation failure.
    async fn load(&self, pin: &SkillPin) -> Result<SkillPlan, SkillError>;
}

/// The trusted local-filesystem store: reads and parses the plan file at
/// `pin.source_id`, byte-identical to the legacy `fs::read` + `from_slice`.
///
/// Performs **no** blake3 verification — the local file is the trust root
/// (GAP-2: the blake3 keystone anchors the *untrusted* network path only).
#[derive(Debug, Default, Clone, Copy)]
pub struct FileStore;

#[async_trait::async_trait]
impl SkillStore for FileStore {
    async fn load(&self, pin: &SkillPin) -> Result<SkillPlan, SkillError> {
        let bytes = std::fs::read(&pin.source_id).map_err(|source| SkillError::Read {
            path: pin.source_id.clone(),
            source,
        })?;
        let plan: SkillPlan = serde_json::from_slice(&bytes).map_err(SkillError::Parse)?;
        plan.validate()?;
        Ok(plan)
    }
}

/// The per-agent **enforced** tool ceiling. A plan stage may only declare tools
/// within this set — it can narrow the authority, never widen it (V-AC-4). When
/// no ceiling is configured on the interpreter the declared `tools` remain
/// advisory (the Phase-1 minimal-vertical behaviour), preserving back-compat.
#[derive(Debug, Clone, Default)]
pub struct ToolCeiling {
    allowed: BTreeSet<String>,
}

impl ToolCeiling {
    /// Build a ceiling from an iterator of allowed tool names.
    pub fn new<I, S>(tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: tools.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether `tool` is within the ceiling.
    #[must_use]
    pub fn permits(&self, tool: &str) -> bool {
        self.allowed.contains(tool)
    }
}

/// The per-agent model-endpoint allowlist (V-AC-5). A stage's *resolved* model
/// id must be a member. When unconfigured, model routing is unrestricted (the
/// Phase-1 minimal-vertical behaviour).
#[derive(Debug, Clone, Default)]
pub struct ModelAllowlist {
    allowed: BTreeSet<String>,
}

impl ModelAllowlist {
    /// Build an allowlist from an iterator of allowed model ids/endpoints.
    pub fn new<I, S>(models: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: models.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether `model` is on the allowlist.
    #[must_use]
    pub fn permits(&self, model: &str) -> bool {
        self.allowed.contains(model)
    }
}

/// The KB namespace a runnable skill document MUST be served from. Scrutator
/// binds `trust_class == "skill"` to this namespace server-side (SRCH-0038 D5);
/// the store checks both (defense in depth) in its pre-parse `trust_class`
/// fence.
pub const SKILLS_NAMESPACE: &str = "skills";

/// The only `trust_class` a runnable skill document may carry (SRCH-0038 D5).
/// A non-`skill` document is rejected before the blake3 keystone and parse.
pub const SKILL_TRUST_CLASS: &str = "skill";

/// The content bytes plus the server-derived KB trust metadata a
/// [`ScrutatorStore`] needs to apply its pre-parse `trust_class` fence.
///
/// `trust_class` and `namespace` are Scrutator response-*envelope* fields
/// derived server-side from the document's namespace — they are **never** the
/// document body, so a plan whose body literally contains
/// `"trust_class":"skill"` cannot forge them (SRCH-0038 S4).
#[derive(Debug, Clone)]
pub struct FetchedContent {
    /// The exact document body bytes — the input to the blake3 keystone.
    pub bytes: Vec<u8>,
    /// The KB's non-authorizing trust classification (expected
    /// [`SKILL_TRUST_CLASS`]).
    pub trust_class: String,
    /// The KB namespace the document was served from (expected
    /// [`SKILLS_NAMESPACE`]).
    pub namespace: String,
}

/// The single fetch primitive a [`ScrutatorStore`] needs.
///
/// Kept minimal and crate-local so `arcana-skills` takes **no** dependency on
/// `arcana-connectors`; the direction of the edge is deliberately reversed —
/// the live adapter (`impl FetchConn for arcana_connectors::ScrutatorClient`)
/// lives in `arcana-connectors`, which depends on this crate. Tests inject
/// fixture content.
#[async_trait::async_trait]
pub trait FetchConn: Send + Sync {
    /// Fetch the full content and trust metadata for an opaque `source_id`.
    ///
    /// # Errors
    ///
    /// Returns [`FetchUnavailable`] on any transport/status failure — the store
    /// maps this to [`SkillError::StoreUnavailable`] (never a silent fallback).
    async fn fetch(&self, source_id: &str) -> Result<FetchedContent, FetchUnavailable>;
}

/// Marker error: a [`FetchConn`] could not produce content (network down,
/// non-2xx, timeout, decode failure). Carries a human-readable reason for the
/// typed [`SkillError::StoreUnavailable`].
#[derive(Debug, Clone)]
pub struct FetchUnavailable(pub String);

/// The untrusted KB-backed store.
///
/// Content returned by the injected [`FetchConn`] passes, in order, a pre-parse
/// `trust_class` fence (only a `skill`-class document in the skills namespace is
/// admitted — V-AC-12) and then a local full-blake3 verify **before** any parse
/// (the trust keystone, V-AC-3). A fetch failure with no verified cache entry
/// fails closed to [`SkillError::StoreUnavailable`] — the store never falls back
/// to a different or stale skill (V-AC-6). The optional blake3-content-addressed
/// [`BlakeCache`] (wired via [`ScrutatorStore::with_cache`]) short-circuits the
/// network on a hit (V-AC-7); a cache entry was `trust_class`-fenced and
/// blake3-verified at write time, so the hit path re-runs only the blake3 check.
pub struct ScrutatorStore<C: FetchConn> {
    conn: Arc<C>,
    cache: Option<BlakeCache>,
    expected_namespace: String,
}

impl<C: FetchConn> ScrutatorStore<C> {
    /// Build a store over an injected fetch connector, with no cache (every
    /// load fetches). The `trust_class` fence expects the default
    /// [`SKILLS_NAMESPACE`].
    #[must_use]
    pub fn new(conn: Arc<C>) -> Self {
        Self {
            conn,
            cache: None,
            expected_namespace: SKILLS_NAMESPACE.to_owned(),
        }
    }

    /// Enable the blake3-content-addressed cache: a hit short-circuits the
    /// network (V-AC-7), a verified fetch is written back.
    #[must_use]
    pub fn with_cache(mut self, cache: BlakeCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Override the expected skills namespace for the `trust_class` fence
    /// (defaults to [`SKILLS_NAMESPACE`]).
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.expected_namespace = namespace.into();
        self
    }
}

/// A blake3-content-addressed byte cache under the XDG cache directory.
///
/// Entries are keyed by the **full blake3 hex** of their content, so a cache
/// hit is verifiable by construction — and is re-verified on read, failing
/// closed if an on-disk entry was tampered. Only hex-charset keys are accepted,
/// so a key can never escape the cache root (no path traversal).
#[derive(Debug, Clone)]
pub struct BlakeCache {
    root: PathBuf,
}

impl BlakeCache {
    /// Open the XDG-rooted cache (`$XDG_CACHE_HOME/arcana/skills/blake3`),
    /// creating the directory if needed.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] if the XDG base directories cannot be
    /// resolved or the cache directory cannot be created.
    pub fn open() -> std::io::Result<Self> {
        let base =
            xdg::BaseDirectories::with_prefix("arcana/skills").map_err(std::io::Error::other)?;
        let root = base.create_cache_directory("blake3")?;
        Ok(Self { root })
    }

    /// Build a cache rooted at an explicit directory (used by tests to stay off
    /// the operator's real `$XDG_CACHE_HOME`).
    #[must_use]
    pub fn with_root(root: PathBuf) -> Self {
        Self { root }
    }

    /// Read the cached bytes for `blake3_hex`, or `None` on a miss or a
    /// non-hex (rejected) key.
    #[must_use]
    pub fn get(&self, blake3_hex: &str) -> Option<Vec<u8>> {
        let path = self.path_for(blake3_hex)?;
        std::fs::read(path).ok()
    }

    /// Write `bytes` under `blake3_hex`.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] on a non-hex key or a write failure.
    pub fn put(&self, blake3_hex: &str, bytes: &[u8]) -> std::io::Result<()> {
        let path = self
            .path_for(blake3_hex)
            .ok_or_else(|| std::io::Error::other("refusing non-hex cache key"))?;
        std::fs::write(path, bytes)
    }

    /// Resolve a hex key to a path inside the cache root, rejecting any key that
    /// is empty or contains a non-hex byte (path-traversal defence).
    fn path_for(&self, hex: &str) -> Option<PathBuf> {
        if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(self.root.join(hex))
        } else {
            None
        }
    }
}

/// Recompute the full blake3 of `bytes` and compare it to the config-pinned
/// hex. Rejects mismatches **before** the caller parses — the keystone.
fn verify_blake3(bytes: &[u8], pinned_hex: &str, source_id: &str) -> Result<(), SkillError> {
    let actual = blake3::hash(bytes);
    if actual.to_hex().as_str() == pinned_hex {
        Ok(())
    } else {
        Err(SkillError::HashMismatch {
            source_id: source_id.to_owned(),
        })
    }
}

#[async_trait::async_trait]
impl<C: FetchConn> SkillStore for ScrutatorStore<C> {
    async fn load(&self, pin: &SkillPin) -> Result<SkillPlan, SkillError> {
        // Cache first: a hit short-circuits the network. The entry is keyed by
        // blake3, but re-verified so a tampered cache file fails closed.
        if let Some(cache) = &self.cache {
            if let Some(cached) = cache.get(&pin.blake3) {
                verify_blake3(&cached, &pin.blake3, &pin.source_id)?;
                return parse_and_validate(&cached);
            }
        }
        // Miss: fetch. A store failure fails closed to StoreUnavailable — never
        // a silent fallback to a different or stale skill.
        let fetched =
            self.conn
                .fetch(&pin.source_id)
                .await
                .map_err(|err| SkillError::StoreUnavailable {
                    source_id: pin.source_id.clone(),
                    reason: err.0,
                })?;
        // GATE 0 — trust_class fence (V-AC-12). Only a `skill`-class document in
        // the expected skills namespace is admitted, and this runs BEFORE the
        // blake3 keystone and before parse. `trust_class`/`namespace` are
        // server-derived envelope fields, so a plan body cannot forge them.
        if fetched.trust_class != SKILL_TRUST_CLASS || fetched.namespace != self.expected_namespace
        {
            return Err(SkillError::WrongTrustClass {
                source_id: pin.source_id.clone(),
                trust_class: fetched.trust_class,
                namespace: fetched.namespace,
            });
        }
        let bytes = fetched.bytes;
        // GATE 1 — local full-blake3 verify BEFORE parse (trust keystone).
        verify_blake3(&bytes, &pin.blake3, &pin.source_id)?;
        // Cache the verified bytes (best-effort — a write failure must not
        // change the run result; the bytes in hand are already verified).
        if let Some(cache) = &self.cache {
            let _ = cache.put(&pin.blake3, &bytes);
        }
        // GATE 2 — parse, then intrinsic schema validation.
        parse_and_validate(&bytes)
    }
}

/// Parse verified bytes into a validated plan (GATE 2 — schema).
fn parse_and_validate(bytes: &[u8]) -> Result<SkillPlan, SkillError> {
    let plan: SkillPlan = serde_json::from_slice(bytes).map_err(SkillError::Parse)?;
    plan.validate()?;
    Ok(plan)
}

// ===========================================================================
// ARAS-0050 — Phase-3 semantic skill DISCOVERY (the proposing half of the
// two-phase firewall). Discovery ranks candidate skills over Scrutator's
// `POST /v1/search` scoped to the skills namespace; it only *proposes* — it can
// never construct a [`SkillPin`] or run anything. Admission to a run still
// requires the full 0047 gate chain (config-authored pin → `trust_class` fence
// → blake3 keystone → parse) on the run-path [`ScrutatorStore`].
// ===========================================================================

/// A semantic skill-discovery query issued by [`SkillDiscovery::discover`] to a
/// [`SkillSearch`] backend.
///
/// Carries the skills-namespace scoping and the **server-side** maturity floor:
/// the backend MUST exclude any hit below `min_maturity` *before* ranking, so
/// draft/validated skills never cross the seam. Discovery therefore never
/// post-filters candidates client-side — the floor is a property of the search
/// service, not of this crate (defence-in-depth: Scrutator also binds a runnable
/// skill's `trust_class`/`namespace` server-side, per SRCH-0038 D5).
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoverQuery {
    /// The free-text intent to rank skills against.
    pub intent: String,
    /// The KB namespace to scope discovery to (always [`SKILLS_NAMESPACE`]).
    pub namespace: String,
    /// The **server-side** maturity floor. Discovery always pins
    /// [`Maturity::Production`]; the backend excludes anything below it.
    pub min_maturity: Maturity,
    /// The maximum number of ranked hits to return.
    pub limit: u32,
}

/// One raw ranked skill hit returned by a [`SkillSearch`] backend.
///
/// Mirrors the non-authorizing proposal fields; [`SkillDiscovery::discover`]
/// maps it to a [`SkillCandidate`] verbatim — still no `blake3`, still no run
/// authorization. `content_hash` is the KB's SHA-256 ingest digest (a cache /
/// staleness signal), **never** a run-path trust anchor.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillHit {
    /// Proposed skill name.
    pub name: String,
    /// Proposed skill version.
    pub version: u32,
    /// SHA-256 ingest digest — a staleness signal, never a trust anchor.
    pub content_hash: String,
    /// The backend-reported maturity (expected [`Maturity::Production`] — the
    /// backend filters server-side, so a lower maturity should never appear).
    pub maturity: Maturity,
    /// Relevance score from the backend's ranker (higher is better).
    pub score: f64,
}

/// Marker error: a [`SkillSearch`] backend could not produce ranked hits
/// (network down, non-2xx, decode failure). The store maps it to
/// [`SkillError::StoreUnavailable`] — discovery fails closed, never fabricating
/// candidates.
#[derive(Debug, Clone)]
pub struct SearchUnavailable(pub String);

/// The single semantic-search primitive a [`SkillDiscovery`] needs.
///
/// Kept minimal and crate-local so `arcana-skills` takes **no** dependency on
/// `arcana-connectors` — the edge is deliberately reversed, exactly like
/// [`FetchConn`]: the live adapter (`impl SkillSearch for
/// arcana_connectors::ScrutatorClient`, mapping to `POST /v1/search`) lives in
/// `arcana-connectors`, which depends on this crate. Tests inject a fixture
/// in-memory ranker.
#[async_trait::async_trait]
pub trait SkillSearch: Send + Sync {
    /// Rank skills in the skills namespace against `query.intent`, applying the
    /// `query.min_maturity` floor **server-side** (before ranking).
    ///
    /// # Errors
    ///
    /// Returns [`SearchUnavailable`] on any transport/status/decode failure —
    /// [`SkillDiscovery::discover`] maps this to
    /// [`SkillError::StoreUnavailable`] (never a silent empty proposal that
    /// hides a backend outage as "no matches").
    async fn search(&self, query: &DiscoverQuery) -> Result<Vec<SkillHit>, SearchUnavailable>;
}

/// The semantic **discovery** counterpart to [`ScrutatorStore`].
///
/// Deliberately a SEPARATE type from the run-path store. A discovery handle
/// exposes only [`discover`](Self::discover) — which returns non-authorizing
/// [`SkillCandidate`]s — and has **no** `load`/run method, so it *structurally*
/// cannot execute a skill. Admission to a run still requires a config-authored
/// [`SkillPin`] driven through a [`SkillStore`] (the blake3 keystone +
/// `trust_class` fence). This is the two-phase firewall expressed at the type
/// level: search proposes here, config authorizes there — there is no bridge and
/// no `SkillCandidate → SkillPin` conversion (a `compile_fail` doctest on
/// [`SkillCandidate`] proves the absence).
pub struct SkillDiscovery<S: SkillSearch> {
    search: Arc<S>,
    namespace: String,
}

impl<S: SkillSearch> SkillDiscovery<S> {
    /// Build a discovery handle over an injected search backend, scoped to the
    /// default [`SKILLS_NAMESPACE`].
    #[must_use]
    pub fn new(search: Arc<S>) -> Self {
        Self {
            search,
            namespace: SKILLS_NAMESPACE.to_owned(),
        }
    }

    /// Override the discovery namespace (defaults to [`SKILLS_NAMESPACE`]).
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Propose up to `limit` **production**-maturity skills semantically
    /// relevant to `intent`, ranked best-first.
    ///
    /// The issued [`DiscoverQuery`] pins `namespace = skills` and
    /// `min_maturity = Production`; the backend applies BOTH server-side, so
    /// draft/validated skills never cross the seam and are never post-filtered
    /// here. The returned [`SkillCandidate`]s only PROPOSE — none carries a
    /// `blake3` anchor and none can authorize a run; a human/config author must
    /// pin one before the run path will load it.
    ///
    /// Ranking is the backend's responsibility; this method applies a stable
    /// `score`-desc, `name`-asc tie-break and truncates to `limit` (a
    /// deterministic ordering, **not** a re-filter).
    ///
    /// # Errors
    ///
    /// Returns [`SkillError::StoreUnavailable`] if the backend cannot rank —
    /// discovery fails closed rather than returning a misleading empty list.
    pub async fn discover(
        &self,
        intent: &str,
        limit: u32,
    ) -> Result<Vec<SkillCandidate>, SkillError> {
        let query = DiscoverQuery {
            intent: intent.to_owned(),
            namespace: self.namespace.clone(),
            min_maturity: Maturity::Production,
            limit,
        };
        let mut hits =
            self.search
                .search(&query)
                .await
                .map_err(|err| SkillError::StoreUnavailable {
                    source_id: format!("search:{}", self.namespace),
                    reason: err.0,
                })?;
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
        hits.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(hits
            .into_iter()
            .map(|hit| SkillCandidate {
                name: hit.name,
                version: hit.version,
                content_hash: hit.content_hash,
                maturity: hit.maturity,
                score: hit.score,
            })
            .collect())
    }
}
