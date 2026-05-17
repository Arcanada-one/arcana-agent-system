//! Cost-budget circuit-breaker hook.
//!
//! Compares the accumulated cost in `HookContext::cost` against an optional
//! cap. When the cap is set and breached, the hook short-circuits the chain
//! via `HookResult::StopExecution("cost_budget_exceeded")`. A `None` cap
//! disables the gate.

use async_trait::async_trait;
use serde_json::Value;

use crate::hooks::{HookContext, HookError, HookResult, ToolHook};
use crate::tool::ToolOutput;

const STOP_REASON: &str = "cost_budget_exceeded";

/// Hook enforcing an optional USD cost cap.
#[derive(Debug, Clone, Copy)]
pub struct CostBudgetHook {
    cap_usd: Option<f64>,
}

impl CostBudgetHook {
    /// Construct a hook with the given cap. `None` disables enforcement.
    #[must_use]
    pub fn new(cap_usd: Option<f64>) -> Self {
        Self { cap_usd }
    }

    fn evaluate(&self, ctx: &HookContext) -> HookResult {
        match ctx.cost.check_budget(self.cap_usd) {
            Ok(()) => HookResult::Continue,
            Err(_) => HookResult::StopExecution(STOP_REASON.to_string()),
        }
    }
}

#[async_trait]
impl ToolHook for CostBudgetHook {
    async fn pre_tool(
        &self,
        ctx: &HookContext,
        _tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
        Ok(self.evaluate(ctx))
    }

    async fn post_tool(
        &self,
        ctx: &HookContext,
        _tool: &str,
        _output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        Ok(self.evaluate(ctx))
    }
}
