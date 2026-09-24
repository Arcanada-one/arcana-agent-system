//! A2-253: the premise the `input`-envelope unwrap rests on, pinned.
//!
//! `arcana_core::tool_dialect` reads an arguments object whose ONLY key is
//! `input` (or `arguments` / `parameters` / `args`) as the wrapper key applied
//! twice, and unwraps it. That is a reading rather than a guess for exactly
//! one reason, and the reason is a fact about the tools this binary ships:
//!
//! **no registered tool declares a property with one of those names, and every
//! tool schema sets `additionalProperties: false`** — so such an object is
//! invalid for every tool in the registry and cannot be a call to anything.
//!
//! `tool_dialect` cannot check that: it has no registry. This test does, over
//! the list `assemble` actually builds, so a tool added later with an `input`
//! argument turns the licence red here instead of quietly widening it. Nothing
//! here is a style rule — delete the assertion and the unwrap becomes capable
//! of changing which call runs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use arcana_cli::run::{assemble, WorkspaceSession};
use arcana_cli::workspace::WorkspacePolicy;
use arcana_core::connector::{ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector};
use arcana_core::tool::Tool;
use arcana_core::tool_dialect::INPUT_KEYS;
use async_trait::async_trait;
use tempfile::TempDir;

/// A connector that is never dispatched: this test only wants the tool list.
struct NeverCalled;

#[async_trait]
impl ModelConnector for NeverCalled {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        panic!("the premise test never dispatches")
    }
}

fn shipped_tools(root: &TempDir, audit: &TempDir) -> Vec<Arc<dyn Tool>> {
    let policy = Arc::new(WorkspacePolicy::new(root.path()).unwrap());
    let WorkspaceSession { tools, .. } = assemble(
        root.path(),
        &policy,
        Box::new(NeverCalled),
        audit.path().to_path_buf(),
        None,
    )
    .expect("compose the headless run");
    tools
}

#[test]
fn no_shipped_tool_takes_an_argument_named_like_the_wrapper_key() {
    let root = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    for tool in shipped_tools(&root, &audit) {
        let schema = tool.input_schema();
        let properties = schema
            .get("properties")
            .and_then(|value| value.as_object())
            .unwrap_or_else(|| panic!("{} has no `properties`: {schema}", tool.name()));
        for key in INPUT_KEYS {
            assert!(
                !properties.contains_key(key),
                "`{}` declares an argument named `{key}` — the A2-253 envelope unwrap would now \
                 be able to change which call runs, and must be narrowed before this tool ships",
                tool.name()
            );
        }
    }
}

#[test]
fn every_shipped_tool_schema_is_closed() {
    // The other half of the premise. With `additionalProperties` open, an
    // object carrying a stray `input` key would VALIDATE for some tool, and
    // "invalid for every tool in the registry" would stop being true.
    let root = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    for tool in shipped_tools(&root, &audit) {
        let schema = tool.input_schema();
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&serde_json::Value::Bool(false)),
            "`{}` has an open schema: {schema}",
            tool.name()
        );
    }
}
