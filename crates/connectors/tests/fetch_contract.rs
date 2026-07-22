//! Contract tests for `ScrutatorClient::fetch` against a mock `POST /v1/fetch`
//! endpoint (SRCH-0038). Asserts the F1 request shape, the F2 typed response
//! round-trip (`source_id` / `content` / `content_hash` / `trust_class` /
//! `stale`), and the F4 augmented `SearchHit` (`content_hash` + `source_id`).
//!
//! The `/v1/fetch` endpoint is owned by the pending keystone SRCH-0038 and is
//! NOT live; these fixtures are the contract shapes from
//! `datarim/tasks/ARAS-0047-fixtures.md`. The Phase-2 live round-trip (V-AC-10,
//! deploy-deferred) re-verifies against the real endpoint once SRCH-0038 ships.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::float_cmp
)]

use std::sync::Arc;

use arcana_connectors::auth_arcana::{AuthTokenError, BearerTokenProvider};
use arcana_connectors::scrutator::{FetchQuery, SearchHit};
use arcana_connectors::ScrutatorClient;
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

/// V-AC-8 — the F1 request serialises to the exact SRCH-0038 shape and the F2
/// response deserialises into the typed `FetchResponse`.
#[tokio::test]
async fn fetch_by_source_id_round_trips_f1_f2() {
    let server = MockServer::start().await;

    // F1 — exact request body the run path emits.
    let f1_request = json!({
        "by": "source_id",
        "id": SOURCE_ID,
        "range": "full",
        "include": ["content", "provenance"]
    });
    // F2 — happy-path response, trust_class:"skill".
    let f2_response = json!({
        "source_id": SOURCE_ID,
        "path": "skills/codegen-review.json",
        "content": "{\"schema_version\":1,\"name\":\"codegen-review\"}",
        "content_len_tokens": 512,
        "content_hash": "sha256:3b1f4e...ingest-bound-by-feeder",
        "index_snapshot_id": "snap-2026-07-22T10:00:00Z",
        "indexed_at": "2026-07-22T10:00:00Z",
        "embedding_model_id": "bge-m3",
        "namespace": "skills",
        "trust_class": "skill",
        "chunk_manifest": [
            { "chunk_id": "kb:skill:codegen-review:3:9f2c#0", "offset_start": 0, "offset_end": 512 }
        ],
        "stale": false
    });

    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_json(&f1_request))
        .respond_with(ResponseTemplate::new(200).set_body_json(&f2_response))
        .expect(1)
        .mount(&server)
        .await;

    let resp = client_for(&server)
        .fetch(&FetchQuery::by_source_id(SOURCE_ID))
        .await
        .expect("F1 request must match and F2 must decode");

    assert_eq!(resp.source_id, SOURCE_ID);
    assert_eq!(resp.namespace, "skills");
    assert_eq!(resp.trust_class, "skill");
    assert_eq!(resp.content_hash, "sha256:3b1f4e...ingest-bound-by-feeder");
    assert!(resp.content.contains("codegen-review"));
    assert!(!resp.stale);
    assert_eq!(resp.chunk_manifest.len(), 1);
    assert_eq!(resp.chunk_manifest[0].offset_end, 512);
}

/// V-AC-8 — the augmented `SearchHit` (F4) deserialises the two new mandatory
/// SRCH-0038 fields; a pre-SRCH-0038 hit without them still decodes (defaulted).
#[test]
fn search_hit_deserializes_f4_new_fields() {
    let f4 = json!({
        "chunk_id": "kb:skill:codegen-review:3:9f2c#0",
        "content": "…chunk text…",
        "source_path": "skills/codegen-review.json",
        "source_type": "skill",
        "chunk_index": 0,
        "score": 0.94,
        "namespace": "skills",
        "project": null,
        "metadata": { "name": "codegen-review", "version": 3, "maturity": "production" },
        "content_hash": "sha256:3b1f4e...ingest-bound-by-feeder",
        "source_id": SOURCE_ID
    });
    let hit: SearchHit = serde_json::from_value(f4).expect("F4 hit decodes");
    assert_eq!(hit.content_hash, "sha256:3b1f4e...ingest-bound-by-feeder");
    assert_eq!(hit.source_id, SOURCE_ID);

    // Back-compat: a pre-SRCH-0038 hit (no new fields) still decodes.
    let legacy = json!({
        "chunk_id": "c1",
        "content": "x",
        "source_path": "p",
        "source_type": "markdown",
        "chunk_index": 0,
        "score": 0.5
    });
    let legacy_hit: SearchHit = serde_json::from_value(legacy).expect("legacy hit decodes");
    assert_eq!(legacy_hit.content_hash, "");
    assert_eq!(legacy_hit.source_id, "");
}

/// F5 — a cross-namespace `403` surfaces as a typed error, never a silent empty
/// document. (V-AC-11 live-verifies this in Phase 2; here we pin the shape.)
#[tokio::test]
async fn fetch_403_surfaces_as_typed_http_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({ "detail": "namespace 'skills' not authorized for caller" })),
        )
        .mount(&server)
        .await;

    match client_for(&server)
        .fetch(&FetchQuery::by_source_id(SOURCE_ID))
        .await
    {
        Err(arcana_connectors::scrutator::ScrutatorError::Http { status, message }) => {
            assert_eq!(status, 403);
            assert_eq!(message, "namespace 'skills' not authorized for caller");
        }
        other => panic!("expected ScrutatorError::Http{{403}}, got {other:?}"),
    }
}
