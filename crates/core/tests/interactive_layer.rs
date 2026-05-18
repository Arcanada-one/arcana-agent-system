//! InteractiveLayer (AutoFromEnv) — directive matrix.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::match_wildcard_for_single_variants,
    clippy::doc_markdown
)]

use serde_json::json;

use arcana_core::permission::{AutoFromEnv, InteractiveDirective, LayerDecision, PermissionLayer};

#[tokio::test]
async fn allow_directive_resolves_to_allow() {
    let layer = AutoFromEnv::with_directive(InteractiveDirective::Allow);
    let decision = layer.evaluate("read", &json!({})).await;
    matches!(decision, LayerDecision::Allow)
        .then_some(())
        .expect("expected Allow");
}

#[tokio::test]
async fn deny_directive_resolves_to_deny() {
    let layer = AutoFromEnv::with_directive(InteractiveDirective::Deny);
    let decision = layer.evaluate("read", &json!({})).await;
    match decision {
        LayerDecision::Deny(reason) => assert_eq!(reason, "auto-deny"),
        other => panic!("expected Deny(auto-deny), got {other:?}"),
    }
}

#[tokio::test]
async fn ask_directive_without_terminal_denies() {
    let layer = AutoFromEnv::with_directive(InteractiveDirective::Ask);
    let decision = layer.evaluate("read", &json!({})).await;
    match decision {
        LayerDecision::Deny(reason) => {
            assert!(reason.contains("no terminal for interactive prompt"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn parse_directive_lowercases_and_falls_back() {
    assert_eq!(
        InteractiveDirective::parse("Allow"),
        InteractiveDirective::Allow
    );
    assert_eq!(
        InteractiveDirective::parse("  DENY  "),
        InteractiveDirective::Deny
    );
    assert_eq!(
        InteractiveDirective::parse("ask"),
        InteractiveDirective::Ask
    );
    assert_eq!(
        InteractiveDirective::parse("nonsense"),
        InteractiveDirective::Ask
    );
    assert_eq!(InteractiveDirective::parse(""), InteractiveDirective::Ask);
}

#[tokio::test]
async fn directive_unaffected_by_tool_name_or_input() {
    let layer = AutoFromEnv::with_directive(InteractiveDirective::Allow);
    let with_payload = layer
        .evaluate("bash", &json!({"command": "rm -rf /"}))
        .await;
    matches!(with_payload, LayerDecision::Allow)
        .then_some(())
        .expect("AutoFromEnv must not inspect input");
}
