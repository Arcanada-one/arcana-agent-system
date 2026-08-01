#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::io::Write;
use std::sync::Arc;

use arcana_core::permission::RuleLayer;
use arcana_core::tool::ToolError;
use arcana_tools::bash::BashTool;
use serde_json::json;
use tempfile::NamedTempFile;

fn write_toml(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("tmpfile");
    file.write_all(content.as_bytes()).expect("write");
    file
}

#[tokio::test]
async fn bash_exit_zero_captures_stdout() {
    let tool = common::Harness::new(BashTool::new());
    let output = tool
        .execute(json!({ "command": "echo hello" }))
        .await
        .expect("bash ok");
    assert!(output.content.contains("hello"));
    assert_eq!(output.metadata.unwrap()["exit_code"], 0);
}

#[tokio::test]
async fn bash_non_zero_exit_becomes_execution_failed() {
    let tool = common::Harness::new(BashTool::new());
    let err = tool
        .execute(json!({ "command": "exit 7" }))
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("exit 7"), "{err}");
}

#[tokio::test]
async fn bash_timeout_aborts_long_command() {
    let tool = common::Harness::new(BashTool::new());
    let err = tool
        .execute(json!({
            "command": "sleep 5",
            "timeout_seconds": 1
        }))
        .await
        .expect_err("must time out");
    assert!(err.to_string().contains("timeout"), "{err}");
}

#[tokio::test]
async fn bash_rejects_ambient_environment_injection() {
    let tool = common::Harness::new(BashTool::new());
    let error = tool
        .execute(json!({
            "command": "printf %s \"$MY_VAR\"",
            "env_vars": { "MY_VAR": "the-answer" }
        }))
        .await
        .expect_err("environment injection must fail closed");
    assert!(error.to_string().contains("env_vars are disabled"));
}

#[tokio::test]
async fn bash_schema_rejects_missing_command() {
    let tool = common::Harness::new(BashTool::new());
    let err = tool
        .validate_input(&json!({}))
        .expect_err("schema must reject");
    assert!(err.to_string().to_lowercase().contains("command"), "{err}");
}

#[tokio::test]
async fn bash_with_rules_denies_configured_deny_command() {
    let file = write_toml(
        r"schema_version = 1

[tool.bash]
deny_commands = ['rm -rf /']
",
    );
    let rules = RuleLayer::load(Some(file.path()), None).expect("load rules");
    let tool = common::Harness::new(BashTool::with_rules(Arc::new(rules)));

    let err = tool
        .execute(json!({ "command": "rm -rf /" }))
        .await
        .expect_err("deny_commands rule must block execution");
    assert!(
        matches!(err, ToolError::PermissionDenied(_)),
        "expected PermissionDenied, got {err:?}"
    );
}

#[tokio::test]
async fn bash_with_rules_allows_non_matching_command() {
    let file = write_toml(
        r"schema_version = 1

[tool.bash]
deny_commands = ['rm -rf /']
",
    );
    let rules = RuleLayer::load(Some(file.path()), None).expect("load rules");
    let tool = common::Harness::new(BashTool::with_rules(Arc::new(rules)));

    let output = tool
        .execute(json!({ "command": "echo hi" }))
        .await
        .expect("harmless command must still execute");
    assert!(output.content.contains("hi"));
}
