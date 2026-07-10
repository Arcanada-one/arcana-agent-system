#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use std::io::Write;
use std::sync::Arc;

use arcana_core::permission::RuleLayer;
use arcana_core::tool::{Tool, ToolError};
use arcana_tools::webfetch::{WebFetchTool, ENV_ALLOW_HOSTS};
use serde_json::json;
use tempfile::NamedTempFile;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn write_permissions_toml(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("tmpfile");
    file.write_all(content.as_bytes()).expect("write");
    file
}

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

#[tokio::test]
async fn webfetch_rule_layer_denies_host_outside_allowlist() {
    let server = MockServer::start().await;
    // No responder is mounted: if the tool made a real HTTP call despite the
    // deny, wiremock would answer 404 (no matcher) rather than propagate the
    // PermissionDenied error, which would also fail the assertion below.
    let permissions_file = write_permissions_toml(
        r#"schema_version = 1

[tool.webfetch]
allow_hosts = ["allowed\\.example\\.com"]
"#,
    );
    let rules = Arc::new(RuleLayer::load(Some(permissions_file.path()), None).expect("load rules"));
    let tool = WebFetchTool::with_rules(rules);

    let url = format!("{}/x", server.uri());
    let err = tool
        .execute(json!({ "url": url }))
        .await
        .expect_err("host outside allow_hosts must be denied");
    match err {
        ToolError::PermissionDenied(reason) => {
            assert!(reason.contains("allow_hosts"), "{reason}");
        }
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty(),
        "deny must short-circuit before any HTTP call"
    );
}

#[tokio::test]
async fn webfetch_rule_layer_allows_matching_host() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hi"))
        .mount(&server)
        .await;

    // wiremock binds to 127.0.0.1:<port>; match on the loopback host.
    let permissions_file = write_permissions_toml(
        r#"schema_version = 1

[tool.webfetch]
allow_hosts = ["^127\\.0\\.0\\.1(:\\d+)?$"]
"#,
    );
    let rules = Arc::new(RuleLayer::load(Some(permissions_file.path()), None).expect("load rules"));
    let tool = WebFetchTool::with_rules(rules);

    let url = format!("{}/hello", server.uri());
    let output = tool
        .execute(json!({ "url": url }))
        .await
        .expect("matching host must be allowed");
    assert_eq!(output.content, "hi");
}

// --- ENV_ALLOW_HOSTS fallback -------------------------------------------
//
// This workspace `forbid`s `unsafe_code`, and `std::env::set_var`/
// `remove_var` require an `unsafe` block (process-global env mutation is
// unsound under concurrent access). Mutating the current test process's
// environment is therefore not an option here — and would additionally
// race against the other `#[tokio::test]` fns above, which run on parallel
// threads within this same binary and also exercise bare
// `WebFetchTool::new()`.
//
// Instead, the two cases below spawn this same compiled test binary as a
// *child* process via `std::process::Command`, setting `ENV_ALLOW_HOSTS`
// only for that child via the safe `Command::env` API. Each child runs a
// single `#[ignore]`d helper test (selected with `--exact --ignored`) that
// performs the real fetch and asserts the outcome; the parent test just
// checks the child's exit status. This is both unsafe-free and race-free:
// no process-global state is ever mutated in the running test process.
//
// Both helper tests use the static pattern `127\.0\.0\.1` because every
// local `wiremock::MockServer` binds to that loopback host regardless of
// its (randomly assigned) port, and `WebFetchTool`'s host extraction drops
// the port (mirrors `RuleLayer::extract_host`) — so no port needs to be
// threaded from parent to child.

#[tokio::test]
#[ignore = "invoked as a subprocess by webfetch_env_var_fallback_gates_when_no_rule_layer"]
async fn env_var_fallback_denies_when_host_excluded_child() {
    let server = MockServer::start().await;
    // No responder mounted: a real call here would 404 rather than
    // PermissionDenied, which also fails the assertion below.
    let tool = WebFetchTool::new();
    let url = format!("{}/hello", server.uri());
    let err = tool
        .execute(json!({ "url": url }))
        .await
        .expect_err("host excluded by env allowlist must be denied");
    assert!(matches!(err, ToolError::PermissionDenied(_)), "{err}");
}

#[tokio::test]
#[ignore = "invoked as a subprocess by webfetch_env_var_fallback_gates_when_no_rule_layer"]
async fn env_var_fallback_allows_when_host_included_child() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hi"))
        .mount(&server)
        .await;
    let tool = WebFetchTool::new();
    let url = format!("{}/hello", server.uri());
    let output = tool
        .execute(json!({ "url": url }))
        .await
        .expect("host included by env allowlist must be allowed");
    assert_eq!(output.content, "hi");
}

#[test]
fn webfetch_env_var_fallback_gates_when_no_rule_layer() {
    let exe = std::env::current_exe().expect("current test exe path");

    let deny_status = std::process::Command::new(&exe)
        .args([
            "env_var_fallback_denies_when_host_excluded_child",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env(ENV_ALLOW_HOSTS, "not-a-real-host\\.invalid")
        .status()
        .expect("spawn deny-case child test process");
    assert!(
        deny_status.success(),
        "env-var deny-case child test failed: {deny_status:?}"
    );

    let allow_status = std::process::Command::new(&exe)
        .args([
            "env_var_fallback_allows_when_host_included_child",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env(ENV_ALLOW_HOSTS, r"^127\.0\.0\.1$")
        .status()
        .expect("spawn allow-case child test process");
    assert!(
        allow_status.success(),
        "env-var allow-case child test failed: {allow_status:?}"
    );
}
