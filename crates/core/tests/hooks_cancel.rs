//! AC-7: cancelling the `HookContext` token mid-chain short-circuits the
//! remaining hooks with `Stop { reason: "cancelled" }` and does not
//! deadlock.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::match_wildcard_for_single_variants
)]

use std::sync::Arc;
use std::time::Duration;

use arcana_core::cost::CostTracker;
use arcana_core::hooks::{HookChain, HookContext, HookError, HookResult, PreToolOutcome, ToolHook};
use arcana_core::tool::ToolOutput;
use async_trait::async_trait;
use serde_json::Value;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

struct SlowHook {
    delay: Duration,
}

#[async_trait]
impl ToolHook for SlowHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
        tokio::time::sleep(self.delay).await;
        Ok(HookResult::Continue)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_between_hooks_stops_chain() {
    let token = CancellationToken::new();
    let cost = Arc::new(CostTracker::new());
    let ctx = HookContext::new(token.clone(), cost);

    let mut chain = HookChain::new();
    chain.push(Arc::new(SlowHook {
        delay: Duration::from_millis(20),
    }));
    chain.push(Arc::new(SlowHook {
        delay: Duration::from_millis(20),
    }));
    chain.push(Arc::new(SlowHook {
        delay: Duration::from_millis(20),
    }));

    let canceller = token.clone();
    let cancel_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        canceller.cancel();
    });

    let outcome = timeout(
        Duration::from_millis(200),
        chain.pre_tool(&ctx, "read", &serde_json::json!({})),
    )
    .await
    .expect("chain pre_tool deadlocked")
    .expect("pre_tool returned an error");

    cancel_task.await.expect("cancellation task panicked");

    match outcome {
        PreToolOutcome::Stop { reason } => assert_eq!(reason, "cancelled"),
        PreToolOutcome::Proceed { .. } => panic!("expected Stop, got Proceed"),
    }
}

#[tokio::test]
async fn pre_existing_cancellation_short_circuits_immediately() {
    let token = CancellationToken::new();
    token.cancel();
    let cost = Arc::new(CostTracker::new());
    let ctx = HookContext::new(token, cost);

    let mut chain = HookChain::new();
    chain.push(Arc::new(SlowHook {
        delay: Duration::from_secs(5),
    }));

    let outcome = timeout(
        Duration::from_millis(50),
        chain.pre_tool(&ctx, "read", &serde_json::json!({})),
    )
    .await
    .expect("chain pre_tool deadlocked")
    .expect("pre_tool returned an error");

    match outcome {
        PreToolOutcome::Stop { reason } => assert_eq!(reason, "cancelled"),
        PreToolOutcome::Proceed { .. } => panic!("expected Stop, got Proceed"),
    }
}
