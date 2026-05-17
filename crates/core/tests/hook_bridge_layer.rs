//! HookBridgeLayer maps HookChain outcomes onto cascade vocabulary.
//!
//! Four invariants:
//!   1. `Continue` passthrough → `LayerDecision::Defer`.
//!   2. `ReplaceInput` mutation surfaces as `LayerDecision::ReplaceInput`.
//!   3. `StopExecution` short-circuits as `LayerDecision::Deny(reason)`.
//!   4. Cancellation token observed mid-chain surfaces as `Deny("cancelled")`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::match_wildcard_for_single_variants,
    clippy::doc_markdown
)]

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use arcana_core::cost::CostTracker;
use arcana_core::hooks::{HookChain, HookContext, HookError, HookResult, ToolHook};
use arcana_core::permission::{HookBridgeLayer, LayerDecision, PermissionLayer};
use arcana_core::tool::ToolOutput;

struct ScriptedHook {
    pre: HookResult,
}

#[async_trait]
impl ToolHook for ScriptedHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
        Ok(self.pre.clone())
    }

    async fn post_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::Continue)
    }
}

fn make_bridge(hooks: Vec<HookResult>, cancel: CancellationToken) -> HookBridgeLayer {
    let mut chain = HookChain::new();
    for pre in hooks {
        chain.push(Arc::new(ScriptedHook { pre }));
    }
    HookBridgeLayer::new(Arc::new(chain), cancel, Arc::new(CostTracker::new()))
}

#[tokio::test]
async fn continue_chain_maps_to_defer() {
    let bridge = make_bridge(vec![HookResult::Continue], CancellationToken::new());
    let decision = bridge.evaluate("read", &json!({"path": "/tmp/x"})).await;
    matches!(decision, LayerDecision::Defer)
        .then_some(())
        .expect("expected Defer for Continue passthrough");
}

#[tokio::test]
async fn replace_input_surfaces_as_replace_input() {
    let bridge = make_bridge(
        vec![HookResult::ReplaceInput(json!({"path": "/tmp/clean"}))],
        CancellationToken::new(),
    );
    let decision = bridge.evaluate("read", &json!({"path": "/tmp/raw"})).await;
    match decision {
        LayerDecision::ReplaceInput(v) => assert_eq!(v, json!({"path": "/tmp/clean"})),
        other => panic!("expected ReplaceInput, got {other:?}"),
    }
}

#[tokio::test]
async fn stop_execution_maps_to_deny_with_reason() {
    let bridge = make_bridge(
        vec![HookResult::StopExecution("over budget".to_string())],
        CancellationToken::new(),
    );
    let decision = bridge.evaluate("read", &json!({})).await;
    match decision {
        LayerDecision::Deny(reason) => assert_eq!(reason, "over budget"),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn pre_cancelled_token_yields_deny_cancelled() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let bridge = make_bridge(vec![HookResult::Continue], cancel);
    let decision = bridge.evaluate("read", &json!({})).await;
    match decision {
        LayerDecision::Deny(reason) => assert_eq!(reason, "cancelled"),
        other => panic!("expected Deny(cancelled), got {other:?}"),
    }
}
