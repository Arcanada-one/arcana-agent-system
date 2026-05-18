//! Integration tests for the path-traversal guard (CWE-22) on the
//! filesystem tools.
//!
//! The DoD canonical for ARAS' path-traversal task: `Read`/`Write`/`Edit`
//! reject `/etc/passwd` both directly and through a `..` traversal that
//! canonicalizes to the same inode. A permissive default (`Tool::default`)
//! must still allow legitimate paths so unrelated tool consumers are not
//! regressed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use std::sync::Arc;

use arcana_core::permission::rule::ToolRuleSet;
use arcana_core::tool::{Tool, ToolError};
use regex::Regex;
use serde_json::json;

use arcana_tools::edit::EditTool;
use arcana_tools::read::ReadTool;
use arcana_tools::write::WriteTool;

/// Production-realistic deny rule: matches `/etc/passwd` on Linux and
/// `/private/etc/passwd` on macOS (where `/etc` is a symlink). The guard
/// canonicalizes input paths before matching, so the rule MUST cover the
/// canonical form on every supported platform.
const ETC_PASSWD_PATTERN: &str = r"^/(private/)?etc/passwd$";

fn deny_etc_passwd() -> Arc<ToolRuleSet> {
    Arc::new(ToolRuleSet {
        deny_paths: vec![Regex::new(ETC_PASSWD_PATTERN).expect("regex")],
        ..Default::default()
    })
}

fn assert_permission_denied<T>(result: Result<T, ToolError>) {
    match result {
        Err(ToolError::PermissionDenied(_)) => {}
        Err(other) => panic!("expected PermissionDenied, got {other:?}"),
        Ok(_) => panic!("expected PermissionDenied, got Ok"),
    }
}

#[tokio::test]
#[cfg(unix)]
async fn read_rejects_direct_etc_passwd() {
    let tool = ReadTool::new(deny_etc_passwd());
    let result = tool.execute(json!({ "path": "/etc/passwd" })).await;
    assert_permission_denied(result);
}

#[tokio::test]
#[cfg(unix)]
async fn read_rejects_canonicalized_traversal() {
    // /private/etc/../etc/passwd canonicalizes to /private/etc/passwd
    // (and equivalently /etc/passwd resolves to /private/etc/passwd on macOS).
    let tool = ReadTool::new(deny_etc_passwd());
    let result = tool
        .execute(json!({ "path": "/private/etc/../etc/passwd" }))
        .await;
    assert_permission_denied(result);
}

#[tokio::test]
#[cfg(unix)]
async fn write_rejects_etc_passwd_variants() {
    let tool = WriteTool::new(deny_etc_passwd());
    let direct = tool
        .execute(json!({ "path": "/etc/passwd", "content": "hacked" }))
        .await;
    assert_permission_denied(direct);
    let traversal = tool
        .execute(json!({
            "path": "/private/etc/../etc/passwd",
            "content": "hacked"
        }))
        .await;
    assert_permission_denied(traversal);
}

#[tokio::test]
#[cfg(unix)]
async fn edit_rejects_etc_passwd_variants() {
    let tool = EditTool::new(deny_etc_passwd());
    let direct = tool
        .execute(json!({
            "path": "/etc/passwd",
            "old_string": "root",
            "new_string": "pwn"
        }))
        .await;
    assert_permission_denied(direct);
    let traversal = tool
        .execute(json!({
            "path": "/private/etc/../etc/passwd",
            "old_string": "root",
            "new_string": "pwn"
        }))
        .await;
    assert_permission_denied(traversal);
}

#[tokio::test]
async fn read_allows_when_no_deny_match() {
    // ReadTool::default ships permissive rules; a benign tempfile read must
    // succeed unchanged.
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("hello.txt");
    tokio::fs::write(&target, b"hello arcana")
        .await
        .expect("seed file");
    let tool = ReadTool::default();
    let result = tool
        .execute(json!({ "path": target.to_string_lossy().to_string() }))
        .await
        .expect("permissive read");
    assert_eq!(result.content, "hello arcana");
}
