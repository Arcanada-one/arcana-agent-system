//! AC-5: CostBudgetHook stops the chain when the running cost exceeds the
//! configured cap, and is a no-op when no cap is set.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::match_wildcard_for_single_variants
)]

use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::hooks::cost_budget::CostBudgetHook;
use arcana_core::hooks::{HookContext, HookResult, ToolHook};
use tokio_util::sync::CancellationToken;

fn ctx_with(cost: Arc<CostTracker>) -> HookContext {
    HookContext::new(CancellationToken::new(), cost)
}

#[tokio::test]
async fn over_cap_stops_with_documented_reason() {
    let cost = Arc::new(CostTracker::new());
    cost.record_llm_call("test-model", 100, 100, 0.50);
    cost.record_llm_call("test-model", 100, 100, 0.50);

    let hook = CostBudgetHook::new(Some(0.80));
    let outcome = hook
        .pre_tool(&ctx_with(Arc::clone(&cost)), "read", &serde_json::json!({}))
        .await
        .expect("pre_tool returned an error");

    match outcome {
        HookResult::StopExecution(reason) => assert_eq!(reason, "cost_budget_exceeded"),
        other => panic!("expected StopExecution, got {other:?}"),
    }
}

#[tokio::test]
async fn under_cap_continues() {
    let cost = Arc::new(CostTracker::new());
    cost.record_llm_call("test-model", 100, 100, 0.10);

    let hook = CostBudgetHook::new(Some(1.00));
    let outcome = hook
        .pre_tool(&ctx_with(Arc::clone(&cost)), "read", &serde_json::json!({}))
        .await
        .expect("pre_tool returned an error");
    assert_eq!(outcome, HookResult::Continue);
}

#[tokio::test]
async fn no_cap_continues_unconditionally() {
    let cost = Arc::new(CostTracker::new());
    cost.record_llm_call("test-model", 100, 100, 1_000.0);

    let hook = CostBudgetHook::new(None);
    let outcome = hook
        .pre_tool(&ctx_with(Arc::clone(&cost)), "read", &serde_json::json!({}))
        .await
        .expect("pre_tool returned an error");
    assert_eq!(outcome, HookResult::Continue);
}
