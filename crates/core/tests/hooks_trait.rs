//! AC-1: the `ToolHook` trait and `HookResult` enum compile, and a minimal
//! no-op implementation returns `Continue` from both phases.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::match_wildcard_for_single_variants
)]

use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::hooks::{HookContext, HookError, HookResult, ToolHook};
use arcana_core::tool::ToolOutput;
use async_trait::async_trait;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

struct NopHook;

#[async_trait]
impl ToolHook for NopHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
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

fn ctx() -> HookContext {
    HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()))
}

#[tokio::test]
async fn nop_hook_pre_continues() {
    let hook = NopHook;
    let result = hook
        .pre_tool(&ctx(), "read", &serde_json::json!({"path": "/dev/null"}))
        .await
        .expect("pre_tool returned an error");
    assert_eq!(result, HookResult::Continue);
}

#[tokio::test]
async fn nop_hook_post_continues() {
    let hook = NopHook;
    let output = ToolOutput {
        content: "ok".to_string(),
        metadata: None,
    };
    let result = hook
        .post_tool(&ctx(), "read", &output)
        .await
        .expect("post_tool returned an error");
    assert_eq!(result, HookResult::Continue);
}
