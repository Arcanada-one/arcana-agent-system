//! V-AC-4: routed-through-connector, no bypass. When the policy selects model
//! `X` for a turn, the `ExecuteRequest` observed by `ModelConnector::execute`
//! has `model == Some("X")` — the selection is set on the request the connector
//! sees, not out-of-band. Fully offline.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::dispatch::{ModelPolicy, TaskType};
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use tokio_util::sync::CancellationToken;

use common::{response, ScriptedConnector};

#[tokio::test]
async fn dispatch_request_carries_selected_model() {
    // A code-signal task forces the `Code` classification on the first turn; the
    // connector answers immediately (final), so exactly one selection happens.
    let connector = ScriptedConnector::new(vec![response("done", 0.0)]);
    let dispatcher = ToolDispatcher::new();
    let cascade = PermissionCascade::new(vec![]);
    let hooks = HookChain::new();
    let cost = Arc::new(CostTracker::new());

    let driver = Driver::new(
        &connector,
        &dispatcher,
        &cascade,
        &hooks,
        cost,
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    );
    let out = driver.run("implement this rust function").await;
    assert_eq!(out.reason, TerminalReason::Completed);

    // The model the policy would pick for a Code step is what the connector saw.
    let expected = ModelPolicy::new().select(TaskType::Code).model_id;
    let requests = connector.requests();
    assert_eq!(
        requests.first().and_then(|r| r.model.clone()),
        Some(expected.clone()),
        "the selected model is set on the ExecuteRequest the connector observes"
    );
    assert_eq!(
        out.selected_models.first(),
        Some(&expected),
        "the selection trace records the same model"
    );
}
