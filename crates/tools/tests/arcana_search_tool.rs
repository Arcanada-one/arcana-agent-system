#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_connectors::auth_arcana::{AuthTokenError, BearerTokenProvider};
use arcana_connectors::ScrutatorClient;
use arcana_tools::arcana_search::ArcanaSearchTool;
use async_trait::async_trait;
use secrecy::SecretString;
use serde_json::json;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn tool_for(server: &MockServer) -> common::Harness {
    let base = Url::parse(&server.uri()).expect("mock uri parses");
    let client = ScrutatorClient::new(base, Arc::new(TestToken)).expect("client builds");
    common::Harness::new(ArcanaSearchTool::with_client(client))
}

struct TestToken;

#[async_trait]
impl BearerTokenProvider for TestToken {
    async fn bearer_token(&self) -> Result<SecretString, AuthTokenError> {
        Ok(SecretString::from("test-token"))
    }
}

#[tokio::test]
async fn arcana_search_200_renders_summary_and_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {
                    "chunk_id": "c1",
                    "content": "ARAS-0011 wraps Scrutator hybrid search as an agent tool.",
                    "source_path": "documentation/architecture/aras.md",
                    "source_type": "markdown",
                    "chunk_index": 3,
                    "score": 0.77,
                    "namespace": "arcanada",
                    "project": "ARAS",
                    "metadata": {"heading": "Tools"}
                }
            ]
        })))
        .mount(&server)
        .await;

    let tool = tool_for(&server);
    let output = tool
        .execute(json!({ "query": "arcana_search tool" }))
        .await
        .expect("search ok");

    assert!(output.content.contains("aras.md"));
    assert!(output.content.contains("0.770"));
    let meta = output.metadata.expect("metadata present");
    assert_eq!(meta["count"], 1);
    assert_eq!(meta["results"][0]["chunk_id"], "c1");
    assert_eq!(meta["results"][0]["namespace"], "arcanada");
}

#[tokio::test]
async fn arcana_search_empty_results_says_no_results() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
        .mount(&server)
        .await;

    let tool = tool_for(&server);
    let output = tool
        .execute(json!({ "query": "no such thing" }))
        .await
        .expect("search ok");
    assert!(output.content.contains("No results"));
    assert_eq!(output.metadata.expect("metadata")["count"], 0);
}

#[tokio::test]
async fn arcana_search_forwards_optional_params() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(wiremock::matchers::body_json(json!({
            "query": "scoped query",
            "namespace": "arcanada",
            "limit": 3,
            "min_score": 0.5
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
        .mount(&server)
        .await;

    let tool = tool_for(&server);
    tool.execute(json!({
        "query": "scoped query",
        "namespace": "arcanada",
        "limit": 3,
        "min_score": 0.5
    }))
    .await
    .expect("must match the scoped-payload mock");
}

#[tokio::test]
async fn arcana_search_upstream_error_becomes_execution_failed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({ "detail": "db unreachable" })),
        )
        .mount(&server)
        .await;

    let tool = tool_for(&server);
    let err = tool
        .execute(json!({ "query": "q" }))
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("db unreachable"), "{err}");
}

#[tokio::test]
async fn arcana_search_schema_rejects_missing_query() {
    let server = MockServer::start().await;
    let tool = tool_for(&server);
    let err = tool
        .validate_input(&json!({}))
        .expect_err("schema must reject");
    assert!(err.to_string().to_lowercase().contains("query"), "{err}");
}

#[tokio::test]
async fn arcana_search_schema_rejects_out_of_range_limit() {
    let server = MockServer::start().await;
    let tool = tool_for(&server);
    let err = tool
        .validate_input(&json!({ "query": "q", "limit": 999 }))
        .expect_err("schema must reject limit > 50");
    assert!(!err.to_string().is_empty());
}
