//! RuleLayer covers permissions.toml semantics:
//!   * TOML parsing + schema_version invariant
//!   * Size cap (MAX_RULE_FILE_BYTES)
//!   * Regex compile errors surface diagnostics
//!   * deny_* precedes allow_* per slot
//!   * MCP tools default-deny without explicit allow
//!   * Project rules merge additively over user rules
//!   * Empty RuleLayer defers all built-ins, denies all MCP

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::match_wildcard_for_single_variants,
    clippy::doc_markdown,
    clippy::needless_raw_string_hashes
)]

use std::io::Write;

use serde_json::json;
use tempfile::NamedTempFile;

use arcana_core::permission::{LayerDecision, PermissionLayer, RuleLayer, RuleLoadError};

fn write_toml(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("tmpfile");
    file.write_all(content.as_bytes()).expect("write");
    file
}

#[tokio::test]
async fn empty_layer_defers_builtin_tools() {
    let layer = RuleLayer::empty();
    let decision = layer.evaluate("read", &json!({"path": "/tmp/x"})).await;
    matches!(decision, LayerDecision::Defer)
        .then_some(())
        .expect("expected Defer when no rules registered");
}

#[tokio::test]
async fn empty_layer_denies_mcp_tools() {
    let layer = RuleLayer::empty();
    let decision = layer.evaluate("mcp:linear/list", &json!({})).await;
    match decision {
        LayerDecision::Deny(reason) => assert!(reason.contains("no explicit allow for MCP")),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn mcp_allow_pattern_grants_access() {
    let file = write_toml(
        r#"schema_version = 1

[mcp]
allow = ["^linear/", "^slack/list-channels$"]
"#,
    );
    let layer = RuleLayer::load(Some(file.path()), None).expect("load");

    let allowed = layer.evaluate("mcp:linear/list-issues", &json!({})).await;
    matches!(allowed, LayerDecision::Allow)
        .then_some(())
        .expect("expected Allow for matching MCP pattern");

    let denied = layer.evaluate("mcp:slack/post", &json!({})).await;
    matches!(denied, LayerDecision::Deny(_))
        .then_some(())
        .expect("expected Deny for non-matching MCP pattern");
}

#[tokio::test]
async fn deny_command_short_circuits_before_allow() {
    let file = write_toml(
        r#"schema_version = 1

[tool.bash]
allow_commands = ['^git ']
deny_commands = ['rm -rf']
"#,
    );
    let layer = RuleLayer::load(Some(file.path()), None).expect("load");

    let allowed = layer
        .evaluate("bash", &json!({"command": "git status"}))
        .await;
    matches!(allowed, LayerDecision::Allow)
        .then_some(())
        .expect("git status should match allow_commands");

    let denied = layer
        .evaluate("bash", &json!({"command": "rm -rf /home"}))
        .await;
    match denied {
        LayerDecision::Deny(reason) => assert!(reason.contains("deny_commands")),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn allow_commands_missing_match_denies() {
    let file = write_toml(
        r#"schema_version = 1

[tool.bash]
allow_commands = ['^git ']
"#,
    );
    let layer = RuleLayer::load(Some(file.path()), None).expect("load");
    let denied = layer.evaluate("bash", &json!({"command": "ls -la"})).await;
    match denied {
        LayerDecision::Deny(reason) => assert!(reason.contains("allow_commands")),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn host_allowlist_filters_webfetch() {
    let file = write_toml(
        r#"schema_version = 1

[tool.webfetch]
allow_hosts = ['^docs\.rs$', '\.github\.com$']
"#,
    );
    let layer = RuleLayer::load(Some(file.path()), None).expect("load");

    let allowed = layer
        .evaluate("webfetch", &json!({"url": "https://docs.rs/serde"}))
        .await;
    matches!(allowed, LayerDecision::Allow)
        .then_some(())
        .expect("docs.rs should pass allow_hosts");

    let denied = layer
        .evaluate("webfetch", &json!({"url": "https://evil.example.com/x"}))
        .await;
    matches!(denied, LayerDecision::Deny(_))
        .then_some(())
        .expect("evil.example.com should be denied");
}

#[tokio::test]
async fn path_deny_overrides_path_allow() {
    let file = write_toml(
        r#"schema_version = 1

[tool.read]
allow_paths = ['^/Users/']
deny_paths = ['\.pem$']
"#,
    );
    let layer = RuleLayer::load(Some(file.path()), None).expect("load");

    let denied = layer
        .evaluate("read", &json!({"path": "/Users/dev/secrets/server.pem"}))
        .await;
    match denied {
        LayerDecision::Deny(reason) => assert!(reason.contains("deny_paths")),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn project_rules_extend_user_deny_patterns() {
    let user = write_toml(
        r#"schema_version = 1

[tool.read]
allow_paths = ['^/Users/']
"#,
    );
    let project = write_toml(
        r#"schema_version = 1

[tool.read]
deny_paths = ['secret']
"#,
    );
    let layer = RuleLayer::load(Some(user.path()), Some(project.path())).expect("load");

    let denied = layer
        .evaluate("read", &json!({"path": "/Users/dev/secret/config"}))
        .await;
    match denied {
        LayerDecision::Deny(reason) => assert!(reason.contains("deny_paths")),
        other => panic!("expected project deny to win, got {other:?}"),
    }
}

#[tokio::test]
async fn schema_version_mismatch_rejected() {
    let file = write_toml(
        r#"schema_version = 999

[tool.read]
"#,
    );
    let err = RuleLayer::load(Some(file.path()), None).expect_err("should reject");
    assert!(matches!(
        err,
        RuleLoadError::SchemaVersion { found: 999, .. }
    ));
}

#[tokio::test]
async fn bad_regex_surfaces_diagnostic() {
    let file = write_toml(
        r#"schema_version = 1

[tool.bash]
allow_commands = ['(unclosed']
"#,
    );
    let err = RuleLayer::load(Some(file.path()), None).expect_err("should reject");
    match err {
        RuleLoadError::BadRegex {
            pattern, section, ..
        } => {
            assert_eq!(pattern, "(unclosed");
            assert_eq!(section, "tool.bash");
        }
        other => panic!("expected BadRegex, got {other:?}"),
    }
}

#[tokio::test]
async fn rule_file_size_cap_enforced() {
    let mut content = String::from("schema_version = 1\n\n[tool.bash]\nallow_commands = [\n");
    while content.len() < 70_000 {
        content.push_str("  '^git ',\n");
    }
    content.push_str("]\n");
    let file = write_toml(&content);
    let err = RuleLayer::load(Some(file.path()), None).expect_err("should reject");
    assert!(matches!(err, RuleLoadError::TooLarge(_)));
}

#[tokio::test]
async fn missing_files_tolerated() {
    let layer = RuleLayer::load(
        Some(std::path::Path::new("/nonexistent/user.toml")),
        Some(std::path::Path::new("/nonexistent/project.toml")),
    )
    .expect("missing files should be tolerated");
    let decision = layer.evaluate("read", &json!({"path": "/x"})).await;
    matches!(decision, LayerDecision::Defer)
        .then_some(())
        .expect("expected Defer when no rules");
}

#[cfg(unix)]
#[tokio::test]
async fn project_path_via_symlink_loads_correctly() {
    use tempfile::TempDir;

    let dir = TempDir::new().expect("tempdir");
    let real_target = dir.path().join("real-permissions.toml");
    std::fs::write(
        &real_target,
        r#"schema_version = 1

[mcp]
allow = ['^linear/']
"#,
    )
    .expect("write real file");

    let symlink = dir.path().join(".arcana-permissions.toml");
    std::os::unix::fs::symlink(&real_target, &symlink).expect("symlink");

    let layer = RuleLayer::load(None, Some(&symlink)).expect("load via symlink");

    let allowed = layer.evaluate("mcp:linear/list", &json!({})).await;
    matches!(allowed, LayerDecision::Allow)
        .then_some(())
        .expect("symlinked project rules must reach evaluation path identically to direct path");

    let denied = layer.evaluate("mcp:slack/post", &json!({})).await;
    matches!(denied, LayerDecision::Deny(_))
        .then_some(())
        .expect("MCP default-deny invariant must survive symlinked load");
}

#[cfg(unix)]
#[tokio::test]
async fn bad_regex_through_symlink_reports_canonical_path() {
    use tempfile::TempDir;

    let dir = TempDir::new().expect("tempdir");
    let real_target = dir.path().join("real-permissions.toml");
    std::fs::write(
        &real_target,
        r#"schema_version = 1

[tool.bash]
allow_commands = ['(unclosed']
"#,
    )
    .expect("write real file");
    let canonical_target = std::fs::canonicalize(&real_target).expect("canonicalize");

    let symlink = dir.path().join(".arcana-permissions.toml");
    std::os::unix::fs::symlink(&real_target, &symlink).expect("symlink");

    let err = RuleLayer::load(None, Some(&symlink)).expect_err("bad regex must surface");
    match err {
        RuleLoadError::BadRegex { path, .. } => {
            assert_eq!(
                path, canonical_target,
                "diagnostic path must be canonical, not the symlink alias \
                 (operator copies the path from the error to debug)"
            );
        }
        other => panic!("expected BadRegex, got {other:?}"),
    }
}
