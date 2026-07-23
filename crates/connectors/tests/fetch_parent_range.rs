//! ARAS-0052 — the KB-cascade `EvidenceFetch` adapter issues the NATIVE
//! server-side `range: {parent_of_chunk}` request (SRCH-0038) for a
//! parent-section escalation, instead of the ARAS-0049 thin-v1 whole-document
//! `range="full"` fetch windowed agent-side. Backward-compatible: an older index
//! that rejects the object-form range with `422` falls back to whole-doc +
//! agent-side windowing. Every other failure fails closed (F5), and the
//! server-side `trust_class` envelope is forwarded untouched.
//!
//! These drive the live `impl EvidenceFetch for ScrutatorClient` adapter over a
//! mock `POST /v1/fetch`; the wiremock `body_json` matcher is what proves the
//! exact wire shape the connector emits (native parent vs whole-doc).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::float_cmp
)]

use std::sync::Arc;

use arcana_connectors::auth_arcana::{AuthTokenError, BearerTokenProvider};
use arcana_connectors::ScrutatorClient;
use arcana_core::kb::{EvidenceFetch, FetchRange};
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

const SOURCE_ID: &str = "kb:evidence:runbook-x:5:1a2b";
const CHUNK_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

/// The exact request body the run path emits for a NATIVE parent-of-chunk range.
fn native_parent_request() -> serde_json::Value {
    json!({
        "by": "source_id",
        "id": SOURCE_ID,
        "range": { "parent_of_chunk": CHUNK_ID },
        "include": ["content", "provenance"]
    })
}

/// The whole-document request body (ARAS-0049 shape) — used as the fallback and
/// as the `Full`-escalation shape.
fn whole_doc_request() -> serde_json::Value {
    json!({
        "by": "source_id",
        "id": SOURCE_ID,
        "range": "full",
        "include": ["content", "provenance"]
    })
}

/// A parent-document `POST /v1/fetch` response whose manifest places the target
/// chunk at a non-zero offset, so the derived `answer_offset` is observable.
fn parent_response() -> serde_json::Value {
    json!({
        "source_id": SOURCE_ID,
        "path": "runbooks/runbook-x.md",
        "content": "…parent section body containing the answer span…",
        "content_len_tokens": 64,
        "content_hash": "sha256:evidence-ingest-bound",
        "index_snapshot_id": "snap-2026-07-23",
        "indexed_at": "2026-07-23T09:00:00Z",
        "embedding_model_id": "bge-m3",
        "namespace": "evidence",
        "trust_class": "evidence",
        "chunk_manifest": [
            { "chunk_id": "sibling-0", "offset_start": 0, "offset_end": 120 },
            { "chunk_id": CHUNK_ID, "offset_start": 120, "offset_end": 300 }
        ],
        "stale": false
    })
}

/// A parent escalation issues the NATIVE `{parent_of_chunk}` range and NEVER the
/// whole-doc `range="full"` request, then derives the answer offset from the
/// returned manifest and forwards the server `trust_class` untouched.
#[tokio::test]
async fn parent_escalation_issues_native_range_not_whole_doc() {
    let server = MockServer::start().await;

    // The native parent range MUST be requested exactly once…
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_json(native_parent_request()))
        .respond_with(ResponseTemplate::new(200).set_body_json(parent_response()))
        .expect(1)
        .mount(&server)
        .await;
    // …and the whole-doc range MUST NOT be requested when the parent suffices.
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .and(body_json(whole_doc_request()))
        .respond_with(ResponseTemplate::new(200).set_body_json(parent_response()))
        .expect(0)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let fetched = EvidenceFetch::fetch(
        &client,
        SOURCE_ID,
        FetchRange::ParentOfChunk(CHUNK_ID.to_owned()),
    )
    .await
    .expect("native parent range must be honoured");

    assert_eq!(fetched.source_id, SOURCE_ID);
    // trust_class envelope forwarded untouched (fence policy stays in the cascade).
    assert_eq!(fetched.trust_class, "evidence");
    assert_eq!(fetched.namespace, "evidence");
    assert_eq!(fetched.content_hash, "sha256:evidence-ingest-bound");
    // answer_offset recovered from the returned manifest (rerank-to-edge target).
    assert_eq!(fetched.answer_offset, 120);
    assert!(fetched.content.contains("answer span"));
}

/// A full-source escalation still issues the whole-document `range="full"`
/// request (unchanged from ARAS-0049).
#[tokio::test]
async fn full_source_escalation_still_issues_whole_doc_range() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .and(body_json(whole_doc_request()))
        .respond_with(ResponseTemplate::new(200).set_body_json(parent_response()))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let fetched = EvidenceFetch::fetch(&client, SOURCE_ID, FetchRange::Full)
        .await
        .expect("full-source fetch must decode");
    assert_eq!(fetched.answer_offset, 0, "full source is anchored at 0");
    assert_eq!(fetched.trust_class, "evidence");
}

/// Backward-compat: an older index that cannot satisfy the object-form parent
/// range (`422`) falls back to whole-doc + agent-side windowing (answer offset
/// from the manifest), never failing the escalation.
#[tokio::test]
async fn parent_range_unsupported_falls_back_to_whole_doc() {
    let server = MockServer::start().await;
    // Older server rejects the object-form range with a validation 422…
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .and(body_json(native_parent_request()))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_json(json!({ "detail": "range: unexpected value; permitted: 'full'" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    // …and the connector falls back to the whole-doc fetch.
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .and(body_json(whole_doc_request()))
        .respond_with(ResponseTemplate::new(200).set_body_json(parent_response()))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let fetched = EvidenceFetch::fetch(
        &client,
        SOURCE_ID,
        FetchRange::ParentOfChunk(CHUNK_ID.to_owned()),
    )
    .await
    .expect("fallback to whole-doc must succeed");

    // The 0049 path: whole-doc body windowed agent-side around the answer chunk.
    assert_eq!(fetched.answer_offset, 120);
    assert_eq!(fetched.trust_class, "evidence");
}

/// Fail-closed unchanged: a non-recoverable error on the parent request (e.g. a
/// cross-namespace `403`) surfaces as a fetch failure — NOT a fallback, NOT a
/// silent empty document (F5).
#[tokio::test]
async fn parent_range_403_fails_closed_no_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .and(body_json(native_parent_request()))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({ "detail": "namespace 'evidence' not authorized" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    // A fallback whole-doc request MUST NOT be issued for a genuine 403.
    Mock::given(method("POST"))
        .and(path("/v1/fetch"))
        .and(body_json(whole_doc_request()))
        .respond_with(ResponseTemplate::new(200).set_body_json(parent_response()))
        .expect(0)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let result = EvidenceFetch::fetch(
        &client,
        SOURCE_ID,
        FetchRange::ParentOfChunk(CHUNK_ID.to_owned()),
    )
    .await;
    assert!(
        result.is_err(),
        "a 403 must fail closed, never fall back or return an empty document"
    );
}
