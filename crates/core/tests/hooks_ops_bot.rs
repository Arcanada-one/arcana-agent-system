//! AC-6: OpsBotEmitterHook is a fail-soft stub — without an API key it
//! returns `Continue` and performs no HTTP work. The absence of an HTTP
//! client in `crates/core` deps is the structural guarantee; this test
//! asserts the runtime contract.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::match_wildcard_for_single_variants
)]

use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::hooks::ops_bot::OpsBotEmitterHook;
use arcana_core::hooks::{HookContext, HookResult, ToolHook};
use arcana_core::tool::ToolOutput;
use tokio_util::sync::CancellationToken;

fn ctx() -> HookContext {
    HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()))
}

#[tokio::test]
async fn stub_pre_returns_continue_without_api_key() {
    let hook = OpsBotEmitterHook::new(None);
    let outcome = hook
        .pre_tool(&ctx(), "read", &serde_json::json!({}))
        .await
        .expect("pre_tool returned an error");
    assert_eq!(outcome, HookResult::Continue);
}

#[tokio::test]
async fn stub_post_returns_continue_without_api_key() {
    let hook = OpsBotEmitterHook::new(None);
    let output = ToolOutput {
        content: "ok".to_string(),
        metadata: None,
    };
    let outcome = hook
        .post_tool(&ctx(), "read", &output)
        .await
        .expect("post_tool returned an error");
    assert_eq!(outcome, HookResult::Continue);
}

#[tokio::test]
async fn stub_with_key_still_returns_continue_no_http() {
    // Stub does not attempt HTTP even with a key; full HTTP wiring lands
    // in a follow-up. The structural guarantee is reinforced by the
    // absence of an HTTP client crate in `crates/core` dependencies.
    let hook = OpsBotEmitterHook::new(Some("placeholder".to_string()));
    let outcome = hook
        .pre_tool(&ctx(), "read", &serde_json::json!({}))
        .await
        .expect("pre_tool returned an error");
    assert_eq!(outcome, HookResult::Continue);
}
