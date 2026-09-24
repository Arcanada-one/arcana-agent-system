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
async fn bash_rejects_values_even_under_benign_environment_names() {
    let tool = common::Harness::new(BashTool::new());
    let error = tool
        .execute(json!({
            "command": "printf %s \"$MY_VAR\"",
            "env_vars": { "MY_VAR": "the-answer" }
        }))
        .await
        .expect_err("a benign name cannot prove a value is non-secret");
    assert!(error.to_string().contains("variables are disabled"));
}

#[tokio::test]
async fn bash_rejects_shell_and_loader_control_environment_names() {
    let tool = common::Harness::new(BashTool::new());
    for name in ["BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH"] {
        let error = tool
            .execute(json!({
                "command": "true",
                "env_vars": { (name): "synthetic-value" }
            }))
            .await
            .expect_err("execution-control variables must fail closed");
        assert!(error.to_string().contains("variables are disabled"));
    }
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

// ---------------------------------------------------------------------------
// A2-253: the quoted integer, and the sandbox HOME
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_quoted_integer_is_refused_and_the_message_carries_the_corrected_spelling() {
    // Turn 52 of pilot A2-240c sent `"timeout_seconds": "400"`
    // (`/home/dev/aup/arc2/wt/A2-240c/.arcana/denied/0010-turn52.json`). The
    // RULE is that this is refused, never coerced: the schema is where the
    // type contract lives, and the same pilot measured that the correction
    // works — the very next call carried an unquoted `300`. What the message
    // did not carry was the corrected text, and now it does.
    let tool = common::Harness::new(BashTool::new());
    let err = tool
        .execute(json!({ "command": "ls", "timeout_seconds": "400" }))
        .await
        .expect_err("a quoted integer must not run");
    let ToolError::InvalidInput(message) = err else {
        panic!("expected a schema refusal, got {err:?}");
    };
    assert!(
        message.contains("/timeout_seconds"),
        "the message names the field: {message}"
    );
    assert!(
        message.contains("is not of type \"integer\""),
        "the message names the expected type: {message}"
    );
    assert!(
        message.contains("send it unquoted, as `400`"),
        "the message gives the exact shape to send: {message}"
    );
}

#[tokio::test]
async fn a_string_that_is_not_a_scalar_gets_no_spelling_it_cannot_use() {
    // The paired negative for the hint: there is only one corrected spelling
    // when the quoted text IS the value. `"soon"` is not a number in
    // disguise, and inventing one would be the coercion this rule refuses.
    let tool = common::Harness::new(BashTool::new());
    let err = tool
        .execute(json!({ "command": "ls", "timeout_seconds": "soon" }))
        .await
        .expect_err("a non-numeric timeout must not run");
    let ToolError::InvalidInput(message) = err else {
        panic!("expected a schema refusal, got {err:?}");
    };
    assert!(
        message.contains("/timeout_seconds") && message.contains("is not of type \"integer\""),
        "the fault is still named: {message}"
    );
    assert!(
        !message.contains("send it unquoted"),
        "no spelling is offered when there is no single one: {message}"
    );
}

#[tokio::test]
async fn the_shell_runs_with_the_home_the_caller_named() {
    // A2-253: `HOME` is per-run state, not a fixed path in `/tmp` shared by
    // every run on the host. The directory exists, so a bare `cd` works —
    // which is the half a non-existent `HOME` actually breaks.
    let home = tempfile::TempDir::new().expect("home tempdir");
    let canonical = home.path().canonicalize().expect("canonical home");
    let tool = common::Harness::new(BashTool::new().with_home(&canonical));
    let output = tool
        .execute(json!({ "command": "printf '%s\\n' \"$HOME\"; cd && pwd" }))
        .await
        .expect("bash ok");
    let expected = canonical.display().to_string();
    assert_eq!(
        output
            .content
            .lines()
            .filter(|line| *line == expected)
            .count(),
        2,
        "both `$HOME` and a bare `cd` land in the named directory: {}",
        output.content
    );
}

#[tokio::test]
async fn without_a_named_home_the_shell_falls_back_to_the_shared_tmp_path() {
    // The paired negative, and the reason `with_home` exists: the default is
    // one fixed path under a world-writable directory, identical for every
    // run on the host. A test that only checked the happy path could not
    // tell the two apart.
    let tool = common::Harness::new(BashTool::new());
    let output = tool
        .execute(json!({ "command": "printf '%s\\n' \"$HOME\"" }))
        .await
        .expect("bash ok");
    assert_eq!(output.content.trim(), "/tmp/arcana-runtime/bash");
}
