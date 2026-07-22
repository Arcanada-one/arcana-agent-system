//! Contract tests for `ScrutatorClient::search` against a mock
//! `POST /v1/search` endpoint. Pins the request shape (only `query` sent
//! when optionals are unset), the 200 success path with multiple hits, the
//! empty-results path, and the 4xx/5xx error paths.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::float_cmp
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_connectors::auth_arcana::{AuthTokenError, BearerTokenProvider};
use arcana_connectors::scrutator::{ScrutatorError, SearchQuery};
use arcana_connectors::ScrutatorClient;
use async_trait::async_trait;
use secrecy::SecretString;
use serde_json::json;
use url::Url;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_for(server: &MockServer) -> ScrutatorClient {
    let base = Url::parse(&server.uri()).expect("mock uri parses");
    ScrutatorClient::new(base, Arc::new(StaticToken("test-token"))).expect("client builds")
}

#[test]
fn base_url_policy_allows_https_loopback_and_the_exact_mesh_endpoint() {
    let token: Arc<dyn BearerTokenProvider> = Arc::new(StaticToken("test-token"));
    for raw in [
        "https://kb.example.test",
        "http://localhost:8310",
        "http://127.0.0.1:8310",
        "http://[::1]:8310",
        "http://100.70.137.104:8310",
    ] {
        ScrutatorClient::new(Url::parse(raw).unwrap(), token.clone())
            .unwrap_or_else(|err| panic!("expected approved base {raw}: {err}"));
    }
}

#[test]
fn base_url_policy_rejects_every_other_plain_http_endpoint() {
    let token: Arc<dyn BearerTokenProvider> = Arc::new(StaticToken("test-token"));
    for raw in [
        "http://100.70.137.105:8310",
        "http://100.70.137.104:8311",
        "http://192.0.2.10:8310",
        "http://example.test:8310",
    ] {
        let result = ScrutatorClient::new(Url::parse(raw).unwrap(), token.clone());
        assert!(result.is_err(), "unapproved plaintext base accepted: {raw}");
    }
}

struct StaticToken(&'static str);

#[async_trait]
impl BearerTokenProvider for StaticToken {
    async fn bearer_token(&self) -> Result<SecretString, AuthTokenError> {
        Ok(SecretString::from(self.0))
    }
}

struct RefreshingToken {
    calls: AtomicUsize,
    invalidations: AtomicUsize,
}

#[async_trait]
impl BearerTokenProvider for RefreshingToken {
    async fn bearer_token(&self) -> Result<SecretString, AuthTokenError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(SecretString::from(if call == 0 {
            "stale-token"
        } else {
            "fresh-token"
        }))
    }

    async fn invalidate(&self) {
        self.invalidations.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn search_200_returns_results() {
    let server = MockServer::start().await;
    let body = json!({
        "results": [
            {
                "chunk_id": "c1",
                "content": "Scrutator is a hybrid search service.",
                "source_path": "documentation/architecture/scrutator.md",
                "source_type": "markdown",
                "chunk_index": 0,
                "score": 0.83,
                "namespace": "arcanada",
                "project": "Scrutator",
                "metadata": {"heading": "Overview"}
            },
            {
                "chunk_id": "c2",
                "content": "It uses pgvector RRF ranking.",
                "source_path": "documentation/architecture/scrutator.md",
                "source_type": "markdown",
                "chunk_index": 1,
                "score": 0.61,
                "namespace": "arcanada",
                "project": "Scrutator",
                "metadata": null
            }
        ]
    });
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let resp = client_for(&server)
        .search(&SearchQuery::new("what is scrutator"))
        .await
        .expect("200 must be Ok");
    assert_eq!(resp.results.len(), 2);
    assert_eq!(resp.results[0].chunk_id, "c1");
    assert_eq!(resp.results[0].score, 0.83);
    assert_eq!(resp.results[1].metadata, None);
}

#[tokio::test]
async fn search_rejects_unauthenticated_fallback_and_refreshes_once_on_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("authorization", "Bearer stale-token"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("authorization", "Bearer fresh-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = Arc::new(RefreshingToken {
        calls: AtomicUsize::new(0),
        invalidations: AtomicUsize::new(0),
    });
    let client =
        ScrutatorClient::new(Url::parse(&server.uri()).unwrap(), provider.clone()).unwrap();
    let response = client.search(&SearchQuery::new("ground me")).await.unwrap();

    assert!(response.results.is_empty());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    assert_eq!(provider.invalidations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn search_does_not_follow_redirects() {
    let source = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/v1/search", target.uri())),
        )
        .mount(&source)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
        .mount(&target)
        .await;

    assert!(matches!(
        client_for(&source).search(&SearchQuery::new("q")).await,
        Err(ScrutatorError::Http { status: 307, .. })
    ));
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn search_sends_only_query_when_optionals_unset() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(body_json(json!({ "query": "bare query" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
        .mount(&server)
        .await;

    let resp = client_for(&server)
        .search(&SearchQuery::new("bare query"))
        .await
        .expect("must match the bare-query mock");
    assert!(resp.results.is_empty());
}

#[tokio::test]
async fn search_forwards_optional_fields() {
    let server = MockServer::start().await;
    let mut query = SearchQuery::new("ARAS tools");
    query.namespace = Some("arcanada".into());
    query.project = Some("ARAS".into());
    query.source_type = Some("markdown".into());
    query.limit = Some(5);
    query.min_score = Some(0.4);
    query.include_content = Some(false);

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(body_json(json!({
            "query": "ARAS tools",
            "namespace": "arcanada",
            "project": "ARAS",
            "source_type": "markdown",
            "limit": 5,
            "min_score": 0.4,
            "include_content": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
        .mount(&server)
        .await;

    client_for(&server)
        .search(&query)
        .await
        .expect("must match the full-payload mock");
}

#[tokio::test]
async fn search_empty_results_is_ok_not_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
        .mount(&server)
        .await;

    let resp = client_for(&server)
        .search(&SearchQuery::new("no matches for this"))
        .await
        .expect("empty results must still be Ok");
    assert!(resp.results.is_empty());
}

#[tokio::test]
async fn search_422_becomes_err_http_with_detail_message() {
    let server = MockServer::start().await;
    let body = json!({ "detail": "limit must be between 1 and 50" });
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(422).set_body_json(body))
        .mount(&server)
        .await;

    match client_for(&server).search(&SearchQuery::new("q")).await {
        Err(ScrutatorError::Http { status, message }) => {
            assert_eq!(status, 422);
            assert_eq!(message, "limit must be between 1 and 50");
        }
        other => panic!("expected ScrutatorError::Http{{422}}, got {other:?}"),
    }
}

#[tokio::test]
async fn search_503_becomes_err_http() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(503).set_body_string("service unavailable"))
        .mount(&server)
        .await;

    match client_for(&server).search(&SearchQuery::new("q")).await {
        Err(ScrutatorError::Http { status, message }) => {
            assert_eq!(status, 503);
            assert_eq!(message, "service unavailable");
        }
        other => panic!("expected ScrutatorError::Http{{503}}, got {other:?}"),
    }
}
