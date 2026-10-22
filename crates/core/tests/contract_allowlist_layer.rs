//! The contract's allowlist, as the cascade sees it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_core::contract::{digest_of, verify, ContractDocument, ContractTools};
use arcana_core::permission::{ContractAllowlistLayer, LayerDecision, PermissionLayer};
use serde_json::json;

fn binding_admitting(tools: &[&str]) -> arcana_core::contract::ContractBinding {
    let projection = "Role: reviewer.";
    let doc = ContractDocument {
        digest: digest_of(projection.as_bytes()),
        projection: json!(projection),
        tools: Some(ContractTools {
            allow: tools.iter().map(|t| (*t).to_owned()).collect(),
        }),
        ..ContractDocument::default()
    };
    verify(&doc.digest.clone(), &doc).expect("binds")
}

#[tokio::test]
async fn a_tool_outside_the_allowlist_is_denied_with_the_digest_named() {
    let layer = ContractAllowlistLayer::new(binding_admitting(&["read", "grep"]));

    let decision = layer.evaluate("bash", &json!({"command": "ls"})).await;

    match decision {
        LayerDecision::Deny(reason) => {
            assert!(reason.contains("`bash`"), "names the tool: {reason}");
            assert!(reason.contains("sha256:"), "names the contract: {reason}");
            assert!(
                reason.contains("grep, read"),
                "names what IS admitted (sorted): {reason}"
            );
        }
        other => panic!("an out-of-contract tool must be denied, got {other:?}"),
    }
    assert_eq!(layer.name(), "contract-allowlist");
}

#[tokio::test]
async fn an_admitted_tool_defers_so_the_rest_of_the_cascade_still_decides() {
    let layer = ContractAllowlistLayer::new(binding_admitting(&["read"]));

    // Defer, never Allow: a contract admits a tool, it does not license a
    // particular call of it. The workspace boundary and the destructive floor
    // must still see this.
    match layer.evaluate("read", &json!({"path": "README.md"})).await {
        LayerDecision::Defer => {}
        other => panic!("an admitted tool must defer, got {other:?}"),
    }
}

#[test]
fn initial_admission_cannot_supply_effect_authority() {
    let error = arcana_core::permission::require_contract_effect_authority().unwrap_err();
    assert_eq!(error.code(), "CONTRACT_EFFECT_AUTHORITY_UNAVAILABLE");
}

#[tokio::test]
async fn missing_effect_authority_precedes_a_downstream_allow() {
    use arcana_core::permission::{
        CascadeOutcome, ContractEffectAuthorityLayer, PermissionCascade,
    };
    use std::sync::Arc;
    struct Allow;
    #[async_trait::async_trait]
    impl PermissionLayer for Allow {
        fn name(&self) -> &'static str {
            "test-allow"
        }
        async fn evaluate(&self, _: &str, _: &serde_json::Value) -> LayerDecision {
            LayerDecision::Allow
        }
    }
    let cascade = PermissionCascade::new(vec![
        Arc::new(ContractAllowlistLayer::new(binding_admitting(&["read"]))),
        Arc::new(ContractEffectAuthorityLayer),
        Arc::new(Allow),
    ]);
    match cascade.evaluate("read", json!({"path": "README.md"})).await {
        CascadeOutcome::Denied { layer, reason } => {
            assert_eq!(layer, "contract-effect-authority");
            assert!(reason.contains("CONTRACT_EFFECT_AUTHORITY_UNAVAILABLE"));
        }
        other @ CascadeOutcome::Allowed { .. } => {
            panic!("downstream allow bypassed the gate: {other:?}")
        }
    }
    match cascade.evaluate("bash", json!({"command": "ls"})).await {
        CascadeOutcome::Denied { layer, .. } => assert_eq!(layer, "contract-allowlist"),
        other @ CascadeOutcome::Allowed { .. } => {
            panic!("static allowlist no longer refuses first: {other:?}")
        }
    }
}
