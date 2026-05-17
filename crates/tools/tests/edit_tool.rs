#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use arcana_core::tool::Tool;
use arcana_tools::edit::EditTool;
use serde_json::json;
use tempfile::tempdir;

async fn seed(dir: &tempfile::TempDir, body: &str) -> String {
    let path = dir.path().join("target.txt");
    tokio::fs::write(&path, body.as_bytes())
        .await
        .expect("seed file");
    path.to_string_lossy().into_owned()
}

#[tokio::test]
async fn edit_unique_substring_succeeds() {
    let tool = EditTool::new();
    let dir = tempdir().expect("tempdir");
    let path = seed(&dir, "alpha BETA gamma").await;
    let output = tool
        .execute(json!({
            "path": path,
            "old_string": "BETA",
            "new_string": "delta"
        }))
        .await
        .expect("edit ok");
    assert!(output.content.starts_with("edited"));
    let body = tokio::fs::read_to_string(output.metadata.unwrap()["path"].as_str().unwrap())
        .await
        .expect("read");
    assert_eq!(body, "alpha delta gamma");
}

#[tokio::test]
async fn edit_fails_when_old_string_not_found() {
    let tool = EditTool::new();
    let dir = tempdir().expect("tempdir");
    let path = seed(&dir, "abc").await;
    let err = tool
        .execute(json!({
            "path": path,
            "old_string": "missing",
            "new_string": "x"
        }))
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("not found"), "got {err}");
}

#[tokio::test]
async fn edit_fails_when_old_string_not_unique() {
    let tool = EditTool::new();
    let dir = tempdir().expect("tempdir");
    let path = seed(&dir, "x x x").await;
    let err = tool
        .execute(json!({
            "path": path,
            "old_string": "x",
            "new_string": "y"
        }))
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("not unique"), "got {err}");
}

#[tokio::test]
async fn edit_fails_when_file_missing() {
    let tool = EditTool::new();
    let err = tool
        .execute(json!({
            "path": "/nonexistent/arcana/edit-target.txt",
            "old_string": "a",
            "new_string": "b"
        }))
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("read"), "got {err}");
}
