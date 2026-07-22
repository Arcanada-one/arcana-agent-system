//! Coverage for the schema-validation permission layer.
//!
//! The layer reads each tool's declared `input_schema` through the
//! dispatcher and short-circuits the cascade with a `Deny` when the
//! payload does not match the schema. A valid payload yields `Defer`
//! so downstream layers (PreHook, Rule, Interactive) keep deciding.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use std::sync::Arc;

use arcana_core::permission::{
    CascadeOutcome, LayerDecision, PermissionCascade, PermissionLayer, SchemaLayer,
};
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{json, Value};

struct StrictTool;

#[async_trait]
impl Tool for StrictTool {
    fn name(&self) -> &'static str {
        "strict"
    }

    fn description(&self) -> &'static str {
        "demands an object with required `path` string"
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": { "type": "string" }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, _invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            content: "ok".to_owned(),
            metadata: None,
        })
    }
}

fn dispatcher_with_strict() -> Arc<ToolDispatcher> {
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(StrictTool))
        .expect("register strict tool");
    Arc::new(dispatcher)
}

#[tokio::test]
async fn defers_when_payload_satisfies_schema() {
    let layer = SchemaLayer::new(dispatcher_with_strict());
    let decision = layer
        .evaluate("strict", &json!({ "path": "/etc/hosts" }))
        .await;
    assert!(matches!(decision, LayerDecision::Defer), "got {decision:?}");
}

#[tokio::test]
async fn denies_when_required_field_missing() {
    let layer = SchemaLayer::new(dispatcher_with_strict());
    let decision = layer.evaluate("strict", &json!({})).await;
    match decision {
        LayerDecision::Deny(reason) => {
            assert!(
                reason.starts_with("schema:"),
                "reason missing prefix: {reason}"
            );
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn denies_unknown_tool() {
    let layer = SchemaLayer::new(dispatcher_with_strict());
    let decision = layer.evaluate("ghost", &json!({})).await;
    match decision {
        LayerDecision::Deny(reason) => {
            assert!(
                reason.contains("unknown tool"),
                "reason missing prefix: {reason}"
            );
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[tokio::test]
async fn cascade_short_circuits_on_schema_deny() {
    let layer: Arc<dyn PermissionLayer> = Arc::new(SchemaLayer::new(dispatcher_with_strict()));
    let cascade = PermissionCascade::new(vec![layer]);
    let verdict = cascade.evaluate("strict", json!({ "extra": true })).await;
    match verdict {
        CascadeOutcome::Denied { layer, reason } => {
            assert_eq!(layer, "schema");
            assert!(reason.starts_with("schema:"), "{reason}");
        }
        CascadeOutcome::Allowed { .. } => panic!("expected Denied, got Allowed"),
    }
}
