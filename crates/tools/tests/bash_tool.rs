#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use arcana_core::tool::Tool;
use arcana_tools::bash::BashTool;
use serde_json::json;

#[tokio::test]
async fn bash_exit_zero_captures_stdout() {
    let tool = BashTool::new();
    let output = tool
        .execute(json!({ "command": "echo hello" }))
        .await
        .expect("bash ok");
    assert!(output.content.contains("hello"));
    assert_eq!(output.metadata.unwrap()["exit_code"], 0);
}

#[tokio::test]
async fn bash_non_zero_exit_becomes_execution_failed() {
    let tool = BashTool::new();
    let err = tool
        .execute(json!({ "command": "exit 7" }))
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("exit 7"), "{err}");
}

#[tokio::test]
async fn bash_timeout_aborts_long_command() {
    let tool = BashTool::new();
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
async fn bash_env_var_propagation_works() {
    let tool = BashTool::new();
    let output = tool
        .execute(json!({
            "command": "printf %s \"$MY_VAR\"",
            "env_vars": { "MY_VAR": "the-answer" }
        }))
        .await
        .expect("bash ok");
    assert_eq!(output.content, "the-answer");
}

#[tokio::test]
async fn bash_schema_rejects_missing_command() {
    let tool = BashTool::new();
    let err = tool
        .validate_input(&json!({}))
        .await
        .expect_err("schema must reject");
    assert!(err.to_string().to_lowercase().contains("command"), "{err}");
}
