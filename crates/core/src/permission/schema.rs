//! Layer 1: JSON-Schema validation gate.
//!
//! `SchemaLayer` defers when the schema accepts the input — letting
//! `HookBridge` / `Rule` / `Interactive` layers carry the rest of the
//! decision. It denies when the tool is unknown or when the payload
//! violates the schema, short-circuiting the cascade.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::{LayerDecision, PermissionLayer};
use crate::tool::ToolDispatcher;

pub struct SchemaLayer {
    dispatcher: Arc<ToolDispatcher>,
}

impl SchemaLayer {
    #[must_use]
    pub fn new(dispatcher: Arc<ToolDispatcher>) -> Self {
        Self { dispatcher }
    }
}

#[async_trait]
impl PermissionLayer for SchemaLayer {
    fn name(&self) -> &'static str {
        "schema"
    }

    async fn evaluate(&self, tool: &str, input: &Value) -> LayerDecision {
        let Some(handle) = self.dispatcher.get(tool) else {
            return LayerDecision::Deny(format!("unknown tool: {tool}"));
        };
        match handle.validate_input(input).await {
            Ok(()) => LayerDecision::Defer,
            Err(err) => LayerDecision::Deny(format!("schema: {err}")),
        }
    }
}
