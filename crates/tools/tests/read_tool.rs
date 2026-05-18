#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use arcana_core::tool::Tool;
use arcana_tools::read::ReadTool;
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;

async fn write_temp(content: &[u8]) -> NamedTempFile {
    let file = NamedTempFile::new().expect("create temp");
    let mut handle = tokio::fs::File::from_std(file.reopen().expect("reopen"));
    handle.write_all(content).await.expect("write");
    handle.flush().await.expect("flush");
    file
}

#[tokio::test]
async fn read_existing_file_returns_content() {
    let tool = ReadTool::default();
    let file = write_temp(b"hello world").await;
    let path = file.path().to_string_lossy().into_owned();
    let output = tool
        .execute(json!({ "path": path }))
        .await
        .expect("read ok");
    assert_eq!(output.content, "hello world");
    let meta = output.metadata.expect("metadata");
    assert_eq!(meta["size_bytes"], 11);
}

#[tokio::test]
async fn read_missing_file_returns_execution_failed() {
    let tool = ReadTool::default();
    let err = tool
        .execute(json!({ "path": "/nonexistent/arcana/test/file.txt" }))
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("stat"), "got {err}");
}

#[tokio::test]
async fn read_rejects_oversized_file() {
    let tool = ReadTool::default();
    let file = write_temp(b"abcdefghij").await; // 10 bytes
    let path = file.path().to_string_lossy().into_owned();
    let err = tool
        .execute(json!({ "path": path, "max_bytes": 5 }))
        .await
        .expect_err("cap exceeded");
    assert!(err.to_string().contains("exceeds cap"), "got {err}");
}

#[tokio::test]
async fn read_schema_rejects_missing_path() {
    let tool = ReadTool::default();
    let err = tool
        .validate_input(&json!({}))
        .await
        .expect_err("schema rejection");
    assert!(err.to_string().to_lowercase().contains("path"), "{err}");
}
