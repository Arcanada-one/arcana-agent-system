#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use arcana_core::tool::Tool;
use arcana_tools::write::WriteTool;
use serde_json::json;
use tempfile::tempdir;

#[tokio::test]
async fn write_creates_new_file() {
    let tool = WriteTool::new();
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("new.txt").to_string_lossy().into_owned();
    let output = tool
        .execute(json!({ "path": path, "content": "hello" }))
        .await
        .expect("write ok");
    assert!(output.content.contains("wrote 5 bytes"));
    let meta = output.metadata.expect("metadata");
    assert_eq!(meta["created"], true);
    let actual = tokio::fs::read_to_string(&meta["path"].as_str().unwrap_or_default())
        .await
        .expect("read back");
    assert_eq!(actual, "hello");
}

#[tokio::test]
async fn write_overwrites_existing_file() {
    let tool = WriteTool::new();
    let dir = tempdir().expect("tempdir");
    let path = dir
        .path()
        .join("overwrite.txt")
        .to_string_lossy()
        .into_owned();
    tokio::fs::write(&path, b"old").await.expect("seed");

    let output = tool
        .execute(json!({ "path": path, "content": "new content" }))
        .await
        .expect("write ok");

    let meta = output.metadata.expect("metadata");
    assert_eq!(meta["created"], false);
    let actual = tokio::fs::read_to_string(meta["path"].as_str().unwrap_or_default())
        .await
        .expect("read");
    assert_eq!(actual, "new content");
}

#[tokio::test]
async fn write_creates_parent_dirs_when_requested() {
    let tool = WriteTool::new();
    let dir = tempdir().expect("tempdir");
    let nested = dir.path().join("a/b/c/leaf.txt");
    let path = nested.to_string_lossy().into_owned();

    tool.execute(json!({
        "path": path,
        "content": "x",
        "create_parent_dirs": true
    }))
    .await
    .expect("write ok");

    let actual = tokio::fs::read_to_string(&nested).await.expect("read");
    assert_eq!(actual, "x");
}

#[tokio::test]
async fn write_schema_rejects_missing_content() {
    let tool = WriteTool::new();
    let err = tool
        .validate_input(&json!({ "path": "/tmp/x" }))
        .await
        .expect_err("must reject");
    assert!(err.to_string().to_lowercase().contains("content"), "{err}");
}
