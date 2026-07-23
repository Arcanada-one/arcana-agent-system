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
use arcana_connectors::ScrutatorClient;
use arcana_skills::SkillDiscovery;
use async_trait::async_trait;
use secrecy::SecretString;
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
