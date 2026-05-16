#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use arcana_core::tool::Tool;
use arcana_tools::grep::GrepTool;
use serde_json::json;
use tempfile::tempdir;

#[tokio::test]
async fn grep_matches_single_line_in_file() {
    let tool = GrepTool::new();
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("a.txt");
    tokio::fs::write(&path, b"alpha\nBETA\ngamma\n")
        .await
        .expect("seed");
    let output = tool
        .execute(json!({
            "pattern": "BETA",
            "path": path.to_string_lossy(),
            "recursive": false
        }))
        .await
        .expect("grep ok");
    assert!(output.content.contains("BETA"));
    assert_eq!(output.metadata.unwrap()["match_count"], 1);
}

#[tokio::test]
async fn grep_no_match_returns_empty() {
    let tool = GrepTool::new();
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("a.txt");
    tokio::fs::write(&path, b"alpha\n").await.expect("seed");
    let output = tool
        .execute(json!({
            "pattern": "ZZZ",
            "path": path.to_string_lossy(),
            "recursive": false
        }))
        .await
        .expect("grep ok");
    assert!(output.content.is_empty());
    assert_eq!(output.metadata.unwrap()["match_count"], 0);
}

#[tokio::test]
async fn grep_recursive_walks_subdirs() {
    let tool = GrepTool::new();
    let dir = tempdir().expect("tempdir");
    let nested = dir.path().join("sub");
    tokio::fs::create_dir_all(&nested).await.expect("mkdir");
    tokio::fs::write(nested.join("deep.txt"), b"NEEDLE\n")
        .await
        .expect("seed");
    tokio::fs::write(dir.path().join("top.txt"), b"haystack\n")
        .await
        .expect("seed");

    let output = tool
        .execute(json!({
            "pattern": "NEEDLE",
            "path": dir.path().to_string_lossy(),
            "recursive": true
        }))
        .await
        .expect("grep ok");
    assert_eq!(output.metadata.unwrap()["match_count"], 1);
    assert!(output.content.contains("deep.txt"));
}

#[tokio::test]
async fn grep_case_insensitive_flag_works() {
    let tool = GrepTool::new();
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("a.txt");
    tokio::fs::write(&path, b"Hello World\n")
        .await
        .expect("seed");
    let output = tool
        .execute(json!({
            "pattern": "hello",
            "path": path.to_string_lossy(),
            "recursive": false,
            "case_insensitive": true
        }))
        .await
        .expect("grep ok");
    assert_eq!(output.metadata.unwrap()["match_count"], 1);
}

#[tokio::test]
async fn grep_schema_rejects_missing_pattern() {
    let tool = GrepTool::new();
    let err = tool
        .validate_input(&json!({}))
        .await
        .expect_err("schema must reject");
    assert!(err.to_string().to_lowercase().contains("pattern"), "{err}");
}
