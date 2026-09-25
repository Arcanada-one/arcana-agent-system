#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use arcana_tools::write::WriteTool;
use serde_json::json;
use tempfile::tempdir;

#[tokio::test]
async fn write_creates_new_file() {
    let tool = common::Harness::new(WriteTool::default());
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
    let tool = common::Harness::new(WriteTool::default());
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
    let tool = common::Harness::new(WriteTool::default());
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
    let tool = common::Harness::new(WriteTool::default());
    let err = tool
        .validate_input(&json!({ "path": "/tmp/x" }))
        .expect_err("must reject");
    assert!(err.to_string().to_lowercase().contains("content"), "{err}");
}

/// A `write` with nothing in it is a failed deliverable, not a success.
///
/// Measured in the A2-285 live run: the model called `write` twice, both calls
/// reported `outcome: success` in the audit log, and both left the same 0-byte
/// file on disk. The run's own effect check then read the changed digest as
/// progress. `content: ""` is not the shape of "here is the page"; it is the
/// shape of a model that has lost its task.
#[tokio::test]
async fn write_refuses_empty_content() {
    let tool = common::Harness::new(WriteTool::default());
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("empty.md").to_string_lossy().into_owned();

    let err = tool
        .execute(json!({ "path": path.clone(), "content": "" }))
        .await
        .expect_err("an empty write must be refused");

    let message = err.to_string();
    assert!(
        message.to_lowercase().contains("empty"),
        "the refusal says what was wrong: {message}"
    );
    assert!(
        message.contains("allow_empty"),
        "and how to ask for it on purpose: {message}"
    );
    assert!(
        !tokio::fs::try_exists(&path).await.unwrap_or(true),
        "a refused write leaves no file behind"
    );
}

/// Whitespace is not content either.
///
/// A single newline is what a model writes when it means to write nothing, and
/// a one-byte file passes any "did the digest change" test as easily as a
/// hundred-kilobyte one.
#[tokio::test]
async fn write_refuses_whitespace_only_content() {
    let tool = common::Harness::new(WriteTool::default());
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("blank.md").to_string_lossy().into_owned();

    let err = tool
        .execute(json!({ "path": path, "content": "\n  \t\n" }))
        .await
        .expect_err("a whitespace-only write must be refused");
    assert!(err.to_string().contains("allow_empty"), "{err}");
}

/// Emptying a file on purpose is still possible, and it is declared.
#[tokio::test]
async fn write_allows_empty_content_when_asked_explicitly() {
    let tool = common::Harness::new(WriteTool::default());
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("truncate.txt");
    tokio::fs::write(&path, b"old").await.expect("seed");

    let output = tool
        .execute(json!({
            "path": path.to_string_lossy(),
            "content": "",
            "allow_empty": true
        }))
        .await
        .expect("an explicitly empty write is allowed");

    let meta = output.metadata.expect("metadata");
    assert_eq!(meta["bytes_written"], 0);
    let actual = tokio::fs::read_to_string(&path).await.expect("read back");
    assert_eq!(actual, "", "the file was truncated, as asked");
}

/// The refusal is a refusal, not a rule nobody stated.
///
/// A2-231: an enforced-but-undisclosed restriction costs a run 78 turns. The
/// flag has to be in the schema the model is shown, or the model cannot obey
/// the rule it is being held to.
#[tokio::test]
async fn the_write_schema_shows_the_empty_content_flag() {
    let tool = common::Harness::new(WriteTool::default());
    let schema = tool.schema().to_string();
    assert!(
        schema.contains("allow_empty"),
        "the flag the refusal names must be in the schema: {schema}"
    );
}

/// The audit log of a real `write`, end to end: the count is in the record.
#[tokio::test]
async fn the_audit_log_records_how_many_bytes_a_write_wrote() {
    let tool = common::Harness::new(WriteTool::default());
    let dir = tempdir().expect("tempdir");
    let page = dir.path().join("page.md").to_string_lossy().into_owned();

    tool.execute(json!({ "path": page, "content": "# Page\n\nbody\n" }))
        .await
        .expect("write ok");

    let records = tool.audit_records();
    let result = records
        .iter()
        .find(|record| record["phase"] == "result")
        .expect("a result record");
    assert_eq!(result["outcome"], "success");
    assert_eq!(
        result["bytes_written"], 13,
        "the log says how much was written, not just that it succeeded: {result}"
    );
}

/// And a refused empty write is recorded as a failure, with no count.
#[tokio::test]
async fn the_audit_log_records_a_refused_empty_write_as_a_failure() {
    let tool = common::Harness::new(WriteTool::default());
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("nothing.md").to_string_lossy().into_owned();

    let _ = tool
        .execute(json!({ "path": path, "content": "" }))
        .await
        .expect_err("refused");

    let records = tool.audit_records();
    let result = records
        .iter()
        .find(|record| record["phase"] == "result")
        .expect("a result record");
    assert_ne!(
        result["outcome"], "success",
        "the call that wrote nothing must not read as a success: {result}"
    );
    assert!(result["bytes_written"].is_null(), "{result}");
}
