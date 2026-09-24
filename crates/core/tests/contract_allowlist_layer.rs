//! The contract's allowlist, as the cascade sees it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_core::contract::{digest_of, verify, ContractDocument, ContractTools};
use arcana_core::permission::{ContractAllowlistLayer, LayerDecision, PermissionLayer};
use serde_json::json;

fn binding_admitting(tools: &[&str]) -> arcana_core::contract::ContractBinding {
    let projection = "Role: reviewer.";
    let doc = ContractDocument {
        digest: digest_of(projection.as_bytes()),
        projection: projection.to_owned(),
        canonical_bytes: None,
        kc2_revision: None,
        kc2_snapshot: None,
        tools: Some(ContractTools {
            allow: tools.iter().map(|t| (*t).to_owned()).collect(),
        }),
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
            assert!(reason.contains("grep, read"), "names what IS admitted (sorted): {reason}");
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
