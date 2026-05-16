//! Ops Bot emitter hook — fail-soft stub.
//!
//! In its stub form the hook receives an optional API key at construction
//! time. When no key is configured the hook records a single warning trace
//! and afterwards returns `HookResult::Continue` for every invocation
//! without performing any HTTP work. The real emitter lives in a dedicated
//! connector crate added later; the stub keeps the agent loop functional
//! and observable until that connector is wired in.

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use serde_json::Value;

use crate::hooks::{HookContext, HookError, HookResult, ToolHook};
use crate::tool::ToolOutput;

/// Stub of the Ops Bot emitter hook.
pub struct OpsBotEmitterHook {
    api_key: Option<String>,
    warned: AtomicBool,
}

impl OpsBotEmitterHook {
    /// Construct a stub with the given API key. `None` triggers fail-soft
    /// mode (no HTTP, single warning trace).
    #[must_use]
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key,
            warned: AtomicBool::new(false),
        }
    }

    fn maybe_warn(&self) {
        if self.api_key.is_none()
            && self
                .warned
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            tracing::warn!("Ops Bot API key missing — emitter hook running in stub mode");
        }
    }
}

#[async_trait]
impl ToolHook for OpsBotEmitterHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _input: &Value,
    ) -> Result<HookResult, HookError> {
        self.maybe_warn();
        Ok(HookResult::Continue)
    }

    async fn post_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        self.maybe_warn();
        Ok(HookResult::Continue)
    }
}
