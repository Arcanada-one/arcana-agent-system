#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use arcana_core::tool::Tool;
use arcana_tools::webfetch::WebFetchTool;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn webfetch_200_returns_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string("hello, arcana"),
        )
        .mount(&server)
        .await;

    let tool = WebFetchTool::new();
    let url = format!("{}/hello", server.uri());
    let output = tool.execute(json!({ "url": url })).await.expect("fetch ok");
    assert_eq!(output.content, "hello, arcana");
    let meta = output.metadata.expect("metadata");
    assert_eq!(meta["status"], 200);
    assert_eq!(meta["content_type"], "text/plain");
}

#[tokio::test]
async fn webfetch_404_becomes_execution_failed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let tool = WebFetchTool::new();
    let url = format!("{}/missing", server.uri());
    let err = tool
        .execute(json!({ "url": url }))
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("404"), "{err}");
}

#[tokio::test]
async fn webfetch_body_over_cap_rejected() {
    let server = MockServer::start().await;
    let big = "x".repeat(100);
    Mock::given(method("GET"))
        .and(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_string(big))
        .mount(&server)
        .await;

    let tool = WebFetchTool::new();
    let url = format!("{}/big", server.uri());
    let err = tool
        .execute(json!({ "url": url, "max_bytes": 10 }))
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("exceeds cap"), "{err}");
}

#[tokio::test]
async fn webfetch_non_get_method_rejected() {
    let tool = WebFetchTool::new();
    let err = tool
        .execute(json!({ "url": "http://example.invalid/", "method": "POST" }))
        .await
        .expect_err("must reject");
    assert!(err.to_string().contains("only GET"), "{err}");
}

#[tokio::test]
async fn webfetch_schema_rejects_missing_url() {
    let tool = WebFetchTool::new();
    let err = tool
        .validate_input(&json!({}))
        .await
        .expect_err("schema must reject");
    assert!(err.to_string().to_lowercase().contains("url"), "{err}");
}
