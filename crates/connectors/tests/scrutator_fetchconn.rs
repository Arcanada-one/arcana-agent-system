//! Phase-2 integration: the live `impl FetchConn for ScrutatorClient` adapter
//! wired end-to-end into a real `ScrutatorStore` over a mock `POST /v1/fetch`
//! (the now-frozen SRCH-0038 contract, merged to Scrutator `main`).
//!
//! These reuse the S5 fixture shape (`fetch_contract.rs` / the SRCH-0038
//! response envelope) but drive the *store* rather than the bare client, proving
//! the real byte-acquisition path: adapter → `trust_class` fence → config-pinned
//! blake3 keystone → parse → validated `SkillPlan`.
//!
//! The `/v1/fetch` endpoint is fixture-mocked here; the live-Scrutator round
//! trip (V-AC-10, deploy-deferred) is a residual follow-up requiring a running
//! instance, not a fixture.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use arcana_connectors::auth_arcana::{AuthTokenError, BearerTokenProvider};
use arcana_connectors::ScrutatorClient;
use arcana_skills::{
    FetchConn, FetchUnavailable, FetchedContent, ScrutatorStore, SkillError, SkillPin, SkillStore,
};
use async_trait::async_trait;
use secrecy::SecretString;
use serde_json::json;
use url::Url;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct StaticToken(&'static str);

#[async_trait]
impl BearerTokenProvider for StaticToken {
    async fn bearer_token(&self) -> Result<SecretString, AuthTokenError> {
        Ok(SecretString::from(self.0))
    }
}

fn client_for(server: &MockServer) -> ScrutatorClient {
    let base = Url::parse(&server.uri()).expect("mock uri parses");
    ScrutatorClient::new(base, Arc::new(StaticToken("test-token"))).expect("client builds")
}

const SOURCE_ID: &str = "kb:skill:codegen-review:3:9f2c";

/// A minimal runnable production plan; its serialised bytes are the exact
/// document body the KB stores and returns for a skills-namespace fetch.
fn plan_bytes() -> Vec<u8> {
    let plan = json!({
        "schema_version": 1,
        "name": "codegen-review",
        "version": 3,
        "kind": "instance",
        "maturity": "production",
        "stages": [{
            "id": "s1",
            "model": { "literal": "m-default" },
            "agent_count": 1,
            "limits": { "max_turns": 4, "max_cost_usd": 0.5, "context_budget_chars": 40000 },
            "tools": ["echo"],
            "metrics": [],
            "action": { "capability": "echo", "input": { "marker": "keystone" } }
        }],
        "defaults": { "model": { "literal": "m-default" } }
    });
    serde_json::to_vec(&plan).unwrap()
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().as_str().to_owned()
}

/// A full `POST /v1/fetch` skills response whose `content` is exactly `body`
/// (so `content.into_bytes()` fed to the blake3 keystone equals `body`).
fn skills_fetch_response(body: &str, trust_class: &str, namespace: &str) -> serde_json::Value {
    json!({
        "source_id": SOURCE_ID,
        "path": "skills/codegen-review.json",
        "content": body,
        "content_len_tokens": 512,
        "content_hash": "sha256:3b1f4e...ingest-bound-by-feeder",
        "index_snapshot_id": "snap-2026-07-22T10:00:00Z",
        "indexed_at": "2026-07-22T10:00:00Z",
        "embedding_model_id": "bge-m3",
        "namespace": namespace,
        "trust_class": trust_class,
        "chunk_manifest": [
            { "chunk_id": "kb:skill:codegen-review:3:9f2c#0", "offset_start": 0, "offset_end": 512 }
        ],
        "stale": false,
        "content_exact": true
    })
}

/// The adapter maps a skills `POST /v1/fetch` response to `FetchedContent`:
/// exact body bytes + the server-derived `trust_class` / `namespace` envelope.
#[tokio::test]
async fn adapter_returns_content_and_trust_metadata() {
    let server = MockServer::start().await;
    let body = String::from_utf8(plan_bytes()).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_json(json!({
            "by": "source_id",
            "id": SOURCE_ID,
            "range": "full",
            "include": ["content", "provenance"]
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(skills_fetch_response(&body, "skill", "skills")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    // Call the trait method explicitly: `ScrutatorClient`'s inherent
    // `fetch(&FetchQuery)` otherwise shadows `FetchConn::fetch(&str)`.
    let fetched: FetchedContent = FetchConn::fetch(&client, SOURCE_ID)
        .await
        .expect("adapter fetch ok");
    assert_eq!(fetched.bytes, plan_bytes(), "bytes must be the exact body");
    assert_eq!(fetched.trust_class, "skill");
    assert_eq!(fetched.namespace, "skills");
}

/// A cross-namespace `403` maps to a fail-closed `FetchUnavailable`, never a
/// silent empty document — the store then surfaces it as `StoreUnavailable`.
#[tokio::test]
async fn adapter_maps_403_to_fetch_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({ "detail": "namespace 'skills' not authorized for caller" })),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err: FetchUnavailable = FetchConn::fetch(&client, SOURCE_ID)
        .await
        .expect_err("a 403 must fail closed, never an empty document");
    assert!(
        err.0.contains("403"),
        "reason should carry the status: {}",
        err.0
    );
}

/// Phase-2 keystone — the REAL `ScrutatorStore` over the live adapter loads a
/// pinned skill end-to-end from `POST /v1/fetch`: adapter → `trust_class` fence →
/// config-pinned blake3 → parse → validated `SkillPlan`.
#[tokio::test]
async fn scrutator_store_loads_pinned_skill_over_fetch() {
    let server = MockServer::start().await;
    let bytes = plan_bytes();
    let body = String::from_utf8(bytes.clone()).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(skills_fetch_response(&body, "skill", "skills")),
        )
        .mount(&server)
        .await;

    let store = ScrutatorStore::new(Arc::new(client_for(&server)));
    // Config-authored pin: the trust anchor is a LOCAL blake3 of the exact
    // bytes, independent of Scrutator's SHA-256 `content_hash`.
    let pin = SkillPin::new("codegen-review", 3, blake3_hex(&bytes), SOURCE_ID);

    let plan = store
        .load(&pin)
        .await
        .expect("real store loads the pinned skill");
    assert_eq!(plan.version, 3);
    assert_eq!(plan.name, "codegen-review");
}

/// The store rejects an `evidence`-class `POST /v1/fetch` response with
/// `WrongTrustClass`, before the blake3 keystone — even though the pinned blake3
/// would otherwise match the returned bytes.
#[tokio::test]
async fn scrutator_store_rejects_evidence_trust_class() {
    let server = MockServer::start().await;
    let bytes = plan_bytes();
    let body = String::from_utf8(bytes.clone()).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(skills_fetch_response(&body, "evidence", "skills")),
        )
        .mount(&server)
        .await;

    let store = ScrutatorStore::new(Arc::new(client_for(&server)));
    let pin = SkillPin::new("codegen-review", 3, blake3_hex(&bytes), SOURCE_ID);

    match store
        .load(&pin)
        .await
        .expect_err("evidence class must be rejected")
    {
        SkillError::WrongTrustClass { trust_class, .. } => assert_eq!(trust_class, "evidence"),
        other => panic!("expected WrongTrustClass, got {other:?}"),
    }
}

/// A store failure (adapter → `FetchUnavailable`) surfaces as the fail-closed
/// `StoreUnavailable`, never a silent fallback.
#[tokio::test]
async fn scrutator_store_maps_fetch_failure_to_store_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream boom"))
        .mount(&server)
        .await;

    let store = ScrutatorStore::new(Arc::new(client_for(&server)));
    let pin = SkillPin::new("codegen-review", 3, blake3_hex(&plan_bytes()), SOURCE_ID);

    match store.load(&pin).await.expect_err("a 5xx must fail closed") {
        SkillError::StoreUnavailable { source_id, .. } => assert_eq!(source_id, SOURCE_ID),
        other => panic!("expected StoreUnavailable, got {other:?}"),
    }
}
