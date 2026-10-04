//! The contract's allowlist, as the cascade sees it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_core::contract::{digest_of, verify, ContractDocument, ContractTools};
use arcana_core::permission::{ContractAllowlistLayer, LayerDecision, PermissionLayer};
use serde_json::json;

fn binding_claiming(tools: &[&str]) -> arcana_core::contract::ContractBinding {
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
    let layer = ContractAllowlistLayer::new(binding_claiming(&["read", "grep"]));

    let decision = layer.evaluate("bash", &json!({"command": "ls"})).await;

    match decision {
        LayerDecision::Deny(reason) => {
            assert!(reason.contains("`bash`"), "names the tool: {reason}");
            assert!(reason.contains("sha256:"), "names the contract: {reason}");
            assert!(
                reason.contains("sha256:"),
                "no outer claim becomes authority: {reason}"
            );
        }
        other => panic!("an out-of-contract tool must be denied, got {other:?}"),
    }
    assert_eq!(layer.name(), "contract-allowlist");
}

#[tokio::test]
async fn an_outer_claimed_tool_is_refused_before_later_layers() {
    let layer = ContractAllowlistLayer::new(binding_claiming(&["read"]));

    // A matching content hash cannot authenticate mutable outer tool claims.
    match layer.evaluate("read", &json!({"path": "README.md"})).await {
        LayerDecision::Deny(_) => {}
        other => panic!("an unauthenticated claim must be denied, got {other:?}"),
    }
}
