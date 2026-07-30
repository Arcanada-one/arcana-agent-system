//! ARAS-0051 — LIVE Scrutator end-to-end (`V-AC-10/11/14` + the ARAS-0050
//! discover live arm). `#[ignore]` by default so `cargo test --workspace` stays
//! offline; run it explicitly against a RUNNING Scrutator:
//!
//! ```text
//! ARCANA_SCRUTATOR_URL=http://100.70.137.104:8310 \
//! ARCANA_SCRUTATOR_TOKEN=<skills-or-authorized-namespace bearer> \
//! cargo test -p arcana-connectors --test live_scrutator -- --ignored --nocapture
//! ```
//!
//! It never fabricates a result: with no token it prints a skip line and
//! returns. With a token it does a REAL round trip — `POST /v1/search` then a
//! byte-exact `POST /v1/fetch` by the discovered `source_id`, and a
//! skills-namespace `discover(intent)` arm — asserting the transport / auth /
//! request-shape / fail-closed error mapping against the live service. The
//! skills `discover` arm is best-effort: it tolerates a typed `StoreUnavailable`
//! (e.g. the caller's namespace claim excludes `skills`) as an honest,
//! non-panicking outcome, never a silent empty proposal.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use arcana_connectors::auth_arcana::{AuthTokenError, BearerTokenProvider};
use arcana_connectors::scrutator::ScrutatorError;
use arcana_connectors::ScrutatorClient;
use arcana_skills::SkillDiscovery;
use async_trait::async_trait;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use url::Url;

/// A fixed bearer read from the environment. The value is never logged.
struct EnvToken(SecretString);

#[async_trait]
impl BearerTokenProvider for EnvToken {
    async fn bearer_token(&self) -> Result<SecretString, AuthTokenError> {
        Ok(self.0.clone())
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn live_client() -> Option<ScrutatorClient> {
    let token = std::env::var("ARCANA_SCRUTATOR_TOKEN")
        .ok()
        .filter(|v| !v.trim().is_empty())?;
    let base = env_or("ARCANA_SCRUTATOR_URL", "http://100.70.137.104:8310");
    let url = Url::parse(&base).expect("ARCANA_SCRUTATOR_URL must parse");
    let client = ScrutatorClient::new(url, Arc::new(EnvToken(SecretString::from(token))))
        .expect("Scrutator client builds for the approved endpoint");
    Some(client)
}

/// V-AC-10/14 — a real search + byte-exact fetch-by-id round trip against the
/// live deployed Scrutator (whatever namespace the token authorizes).
#[tokio::test]
#[ignore = "live: requires a running Scrutator + ARCANA_SCRUTATOR_TOKEN"]
async fn live_search_then_fetch_by_id_roundtrip() {
    let Some(client) = live_client() else {
        eprintln!("SKIP live_search_then_fetch_by_id_roundtrip: ARCANA_SCRUTATOR_TOKEN unset");
        return;
    };
    let query_text = env_or("ARCANA_SCRUTATOR_LIVE_QUERY", "arcanada");
    let mut query = arcana_connectors::scrutator::SearchQuery::new(&query_text);
    query.limit = Some(5);
    if let Ok(ns) = std::env::var("ARCANA_SCRUTATOR_LIVE_NS") {
        if !ns.trim().is_empty() {
            query.namespace = Some(ns);
        }
    }

    let results = client
        .search(&query)
        .await
        .expect("live /v1/search must succeed for an authorized caller");
    eprintln!(
        "live search: query={query_text:?} results={} (first ns={:?})",
        results.results.len(),
        results.results.first().and_then(|h| h.namespace.clone())
    );
    assert!(
        !results.results.is_empty(),
        "expected the live index to return at least one hit for {query_text:?}"
    );

    let top = &results.results[0];
    let source_id = if top.source_id.is_empty() {
        eprintln!("top hit carries no source_id; skipping fetch leg");
        return;
    } else {
        top.source_id.clone()
    };

    let fetch = arcana_connectors::scrutator::FetchQuery::by_source_id(&source_id);
    let doc = client
        .fetch(&fetch)
        .await
        .expect("live /v1/fetch by source_id must succeed");
    eprintln!(
        "live fetch: source_id={:?} ns={:?} trust_class={:?} content_exact={} bytes={}",
        doc.source_id,
        doc.namespace,
        doc.trust_class,
        doc.content_exact,
        doc.content.len()
    );
    assert_eq!(doc.source_id, source_id, "fetch must echo the pinned id");
    assert!(
        !doc.content.is_empty(),
        "fetched document must carry content"
    );
    // `content_exact` marks a byte-exact (skills-namespace) body vs. a lossy
    // evidence reassembly — the guarantee the run-path blake3 keystone relies on.
    // Recorded here for observability; the keystone itself is exercised offline.
    eprintln!(
        "live fetch: content_exact={} content_hash_present={}",
        doc.content_exact,
        !doc.content_hash.is_empty()
    );
}

/// ARAS-0050 discover live arm — a real skills-namespace `discover(intent)`.
/// Best-effort: an authorized caller yields production candidates; a caller
/// whose claim excludes `skills` yields a typed fail-closed error (never a
/// silent empty list, never a panic). Both are recorded honestly.
#[tokio::test]
#[ignore = "live: requires a running Scrutator + ARCANA_SCRUTATOR_TOKEN"]
async fn live_skills_discover_production_arm() {
    let Some(client) = live_client() else {
        eprintln!("SKIP live_skills_discover_production_arm: ARCANA_SCRUTATOR_TOKEN unset");
        return;
    };
    let intent = env_or(
        "ARCANA_SCRUTATOR_DISCOVER_INTENT",
        "review my pull request diff",
    );
    let discovery = SkillDiscovery::new(Arc::new(client));

    match discovery.discover(&intent, 5).await {
        Ok(candidates) => {
            eprintln!(
                "live discover(skills, production): {} candidate(s) for {intent:?}",
                candidates.len()
            );
            for c in &candidates {
                eprintln!(
                    "  candidate: {} v{} score={:.3}",
                    c.name, c.version, c.score
                );
                assert_eq!(
                    c.maturity,
                    arcana_skills::Maturity::Production,
                    "the server-side floor must exclude sub-production skills"
                );
            }
        }
        Err(err) => {
            // A typed, fail-closed outcome (e.g. the caller's namespace claim
            // excludes `skills` → 403 → StoreUnavailable) — honest, not a silent
            // empty proposal.
            eprintln!("live discover(skills, production): fail-closed typed error: {err}");
            assert!(
                matches!(err, arcana_skills::SkillError::StoreUnavailable { .. }),
                "a discover failure must be the typed StoreUnavailable, got {err:?}"
            );
        }
    }
}

/// ARAS-0057 — a single production skill through discovery → exact fetch,
/// proving the bytes that the live KB holds match the committed artifact.
///
/// Fail-closed: the test uses [`ScrutatorClient::try_from_env`] (restrictive
/// credential-file checks via [`ClientCredentialsTokenProvider`]) and **never**
/// the permissive raw-bearer `live_client()`. It must fail — not skip — on
/// missing credentials, 401/403, empty results, missing target, lossy content,
/// hash mismatch, or byte mismatch. Every Scrutator failure is mapped to a
/// safe category/status diagnostic so response bodies cannot print.
///
/// Run only when prerequisites are live and authorized:
///
/// ```text
/// cargo test -p arcana-connectors --test live_scrutator \
///   live_production_skill_discover_and_exact_fetch -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "live: requires configured OAuth credentials + running Scrutator + indexed artifact"]
#[allow(clippy::too_many_lines)]
async fn live_production_skill_discover_and_exact_fetch() {
    const ARTIFACT_BYTES: &[u8] =
        include_bytes!("../../skills/data/skills-kb-discovery-probe.json");
    const TARGET_NAME: &str = "skills-kb-discovery-probe";
    const TARGET_VERSION: u32 = 1;

    // ---- locally computed SHA-256 trust anchor ----
    let expected_hash = {
        let digest = Sha256::digest(ARTIFACT_BYTES);
        format!("sha256:{digest:x}")
    };

    // ---- build client with restrictive credential-file checks ----
    let client = Arc::new(
        ScrutatorClient::try_from_env()
            .expect("ScrutatorClient::try_from_env must succeed (credentials configured)"),
    );

    // ---- search arm: discover the production skill via /v1/search ----
    let search_query = arcana_connectors::scrutator::SearchQuery::for_skill_discovery(
        "production skill retrieval contract discovery probe",
        "production",
        10,
    );
    let search_resp = match client.search(&search_query).await {
        Ok(r) => r,
        Err(ScrutatorError::Authentication(e)) => {
            panic!("live search: authentication failed: {e}")
        }
        Err(ScrutatorError::Transport(e)) => panic!("live search: transport error: {e}"),
        Err(ScrutatorError::Http { status, .. }) => panic!("live search: HTTP {status}"),
        Err(ScrutatorError::UpstreamNonJson { .. }) => panic!("live search: non-JSON response"),
    };

    assert!(
        !search_resp.results.is_empty(),
        "search must return at least one hit for the skills namespace"
    );

    let hit = search_resp
        .results
        .iter()
        .find(|h| {
            let meta = h.metadata.as_ref();
            meta.and_then(|m| m.get("name")?.as_str()) == Some(TARGET_NAME)
                && meta.and_then(|m| m.get("version")?.as_u64()) == Some(u64::from(TARGET_VERSION))
        })
        .expect("search results must contain skills-kb-discovery-probe v1");

    // Require complete top-level proposal metadata.
    let meta = hit
        .metadata
        .as_ref()
        .expect("search hit must carry metadata");
    assert_eq!(meta.get("name").and_then(|v| v.as_str()), Some(TARGET_NAME));
    assert_eq!(
        meta.get("version").and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        meta.get("schema_version")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(meta.get("kind").and_then(|v| v.as_str()), Some("instance"));
    assert_eq!(
        meta.get("maturity").and_then(|v| v.as_str()),
        Some("production")
    );
    assert!(!hit.source_id.is_empty(), "search hit must carry source_id");
    assert_eq!(
        hit.namespace.as_deref(),
        Some("skills"),
        "search hit must be scoped to the skills namespace"
    );
    assert!(
        hit.content_hash.starts_with("sha256:"),
        "search hit content_hash must use the sha256: prefix, got {:?}",
        hit.content_hash
    );
    assert_eq!(
        hit.content_hash, expected_hash,
        "search hit content_hash must match locally computed sha256 of the committed artifact"
    );

    let search_source_id = hit.source_id.clone();
    let search_content_hash = hit.content_hash.clone();

    // ---- discovery arm: independent SkillDiscovery::discover path ----
    let discovery = SkillDiscovery::new(Arc::clone(&client));
    let candidates = match discovery
        .discover("production skill retrieval contract discovery probe", 10)
        .await
    {
        Ok(c) => c,
        Err(err) => panic!("live discover: fail-closed typed error: {err}"),
    };

    let candidate = candidates
        .iter()
        .find(|c| c.name == TARGET_NAME && c.version == TARGET_VERSION)
        .expect("discover must yield the same skills-kb-discovery-probe v1 candidate");
    assert_eq!(
        candidate.maturity,
        arcana_skills::Maturity::Production,
        "discovered candidate must be production maturity"
    );
    assert!(
        candidate.content_hash.starts_with("sha256:"),
        "discovered candidate content_hash must use the sha256: prefix, got {:?}",
        candidate.content_hash
    );
    assert_eq!(
        candidate.content_hash, expected_hash,
        "discovered candidate content_hash must match locally computed sha256"
    );
    assert_eq!(
        candidate.content_hash, search_content_hash,
        "discovered candidate content_hash must match the search hit's content_hash"
    );
    // The search-proposes/config-authorizes firewall: a SkillCandidate has no
    // blake3, source_id, or conversion to SkillPin — it can only propose.

    // ---- fetch arm: exact byte retrieval by opaque source_id ----
    let fetch_query = arcana_connectors::scrutator::FetchQuery::by_source_id(&search_source_id);
    let doc = match client.fetch(&fetch_query).await {
        Ok(d) => d,
        Err(ScrutatorError::Authentication(e)) => {
            panic!("live fetch: authentication failed: {e}")
        }
        Err(ScrutatorError::Transport(e)) => panic!("live fetch: transport error: {e}"),
        Err(ScrutatorError::Http { status, .. }) => panic!("live fetch: HTTP {status}"),
        Err(ScrutatorError::UpstreamNonJson { .. }) => panic!("live fetch: non-JSON response"),
    };
    assert_eq!(
        doc.source_id, search_source_id,
        "fetched source_id must match the search hit's source_id"
    );
    assert_eq!(
        doc.namespace, "skills",
        "fetched document must be in the skills namespace"
    );
    assert_eq!(
        doc.trust_class, "skill",
        "fetched document must carry trust_class=skill"
    );
    assert!(
        doc.content_exact,
        "fetched content must be byte-exact (skills namespace guarantee)"
    );
    assert!(
        doc.content_hash.starts_with("sha256:"),
        "fetched document content_hash must use the sha256: prefix, got {:?}",
        doc.content_hash
    );
    assert_eq!(
        doc.content_hash, expected_hash,
        "fetched document content_hash must match locally computed sha256"
    );
    assert_eq!(
        doc.content_hash, search_content_hash,
        "fetch content_hash must match the search hit's content_hash"
    );

    // Boolean + length diagnostic only — response body must not appear in
    // panic output.
    let artifact_str =
        core::str::from_utf8(ARTIFACT_BYTES).expect("committed artifact is valid UTF-8");
    assert!(!doc.content.is_empty(), "fetched content must not be empty");
    assert_eq!(
        doc.content.len(),
        artifact_str.len(),
        "fetched content length must match the committed artifact"
    );
    assert!(
        doc.content.as_bytes() == ARTIFACT_BYTES,
        "fetched bytes differ from the committed artifact at identical length"
    );
}
