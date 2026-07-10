//! End-to-end check: every built-in tool ships a compilable JSON Schema
//! and the cascade's schema layer denies payloads that violate it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use std::sync::Arc;

use arcana_connectors::ScrutatorClient;
use arcana_core::permission::{CascadeOutcome, PermissionCascade, PermissionLayer, SchemaLayer};
use arcana_core::tool::ToolDispatcher;
use arcana_tools::arcana_search::ArcanaSearchTool;
use arcana_tools::bash::BashTool;
use arcana_tools::edit::EditTool;
use arcana_tools::grep::GrepTool;
use arcana_tools::read::ReadTool;
use arcana_tools::webfetch::WebFetchTool;
use arcana_tools::write::WriteTool;
use serde_json::json;
use url::Url;

fn registered_dispatcher() -> Arc<ToolDispatcher> {
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(ReadTool::default()))
        .expect("read");
    dispatcher
        .register(Arc::new(WriteTool::default()))
        .expect("write");
    dispatcher
        .register(Arc::new(EditTool::default()))
        .expect("edit");
    dispatcher
        .register(Arc::new(GrepTool::new()))
        .expect("grep");
    dispatcher
        .register(Arc::new(BashTool::new()))
        .expect("bash");
    dispatcher
        .register(Arc::new(WebFetchTool::new()))
        .expect("webfetch");
    // arcana_search never dials out during schema-only checks — point it at
    // an inert base URL rather than the real Scrutator mesh endpoint.
    let scrutator = ScrutatorClient::new(Url::parse("http://127.0.0.1:0").unwrap())
        .expect("scrutator client builds");
    dispatcher
        .register(Arc::new(ArcanaSearchTool::with_client(scrutator)))
        .expect("arcana_search");
    Arc::new(dispatcher)
}

#[tokio::test]
async fn every_tool_schema_compiles() {
    let dispatcher = registered_dispatcher();
    for name in [
        "read",
        "write",
        "edit",
        "grep",
        "bash",
        "webfetch",
        "arcana_search",
    ] {
        let tool = dispatcher.get(name).expect("registered");
        let schema = tool.input_schema();
        assert!(
            jsonschema::validator_for(&schema).is_ok(),
            "tool {name} schema failed to compile"
        );
    }
}

#[tokio::test]
async fn cascade_denies_malformed_payload_per_tool() {
    let dispatcher = registered_dispatcher();
    let schema_layer: Arc<dyn PermissionLayer> = Arc::new(SchemaLayer::new(dispatcher));
    let cascade = PermissionCascade::new(vec![schema_layer]);

    // empty object trips the required-field check for every Tool above.
    for name in [
        "read",
        "write",
        "edit",
        "grep",
        "bash",
        "webfetch",
        "arcana_search",
    ] {
        let verdict = cascade.evaluate(name, json!({})).await;
        match verdict {
            CascadeOutcome::Denied { layer, .. } => assert_eq!(layer, "schema"),
            CascadeOutcome::Allowed { transformed_input } => {
                panic!("tool {name} accepted empty payload: {transformed_input}")
            }
        }
    }
}

#[tokio::test]
async fn cascade_allows_valid_payload_for_every_tool() {
    let dispatcher = registered_dispatcher();
    let schema_layer: Arc<dyn PermissionLayer> = Arc::new(SchemaLayer::new(dispatcher));
    let cascade = PermissionCascade::new(vec![schema_layer]);

    let cases = [
        ("read", json!({ "path": "/etc/hosts" })),
        ("write", json!({ "path": "/tmp/x", "content": "y" })),
        (
            "edit",
            json!({ "path": "/tmp/x", "old_string": "a", "new_string": "b" }),
        ),
        ("grep", json!({ "pattern": "abc" })),
        ("bash", json!({ "command": "true" })),
        ("webfetch", json!({ "url": "http://example.org/" })),
        ("arcana_search", json!({ "query": "hello" })),
    ];

    for (name, payload) in cases {
        let verdict = cascade.evaluate(name, payload).await;
        match verdict {
            CascadeOutcome::Allowed { .. } => {}
            CascadeOutcome::Denied { layer, reason } => {
                panic!("tool {name} unexpectedly denied by {layer}: {reason}")
            }
        }
    }
}

#[tokio::test]
async fn cascade_denies_unknown_tool() {
    let dispatcher = registered_dispatcher();
    let schema_layer: Arc<dyn PermissionLayer> = Arc::new(SchemaLayer::new(dispatcher));
    let cascade = PermissionCascade::new(vec![schema_layer]);
    let verdict = cascade.evaluate("ghost", json!({})).await;
    match verdict {
        CascadeOutcome::Denied { layer, reason } => {
            assert_eq!(layer, "schema");
            assert!(reason.contains("unknown tool"), "{reason}");
        }
        CascadeOutcome::Allowed { .. } => panic!("unknown tool must be denied"),
    }
}
