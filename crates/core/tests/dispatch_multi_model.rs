//! V-AC-1 (DoD): multi-model dispatch is exercised in one run. A scripted,
//! fully-offline run classifies its two turns as distinct task-types (a code
//! step, then a summarize step after a tool result); the captured sequence of
//! `ExecuteRequest.model` values contains ≥2 distinct model ids, mirrored on
//! `RunOutput.selected_models`. No network, no DEVS, no `ARCANA_MC_TOKEN`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, EchoTool, ScriptedConnector};

#[tokio::test]
async fn dispatch_two_distinct_models_in_one_run() {
    // Turn 0: a code-signal task → Code → expensive model. The model asks for
    // the echo tool. Turn 1: a trailing tool-result → Summarize → cheap model.
    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("echo", json!({ "text": "world" })), 0.001),
        response("all done", 0.001),
    ]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo tool");
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

    // Each turn's ExecuteRequest carries the per-turn selected model.
    let requests = connector.requests();
    assert!(
        requests.len() >= 2,
        "expected ≥2 connector calls, got {}",
        requests.len()
    );
    let req_models: Vec<String> = requests.iter().filter_map(|r| r.model.clone()).collect();
    let distinct_req: HashSet<&String> = req_models.iter().collect();
    assert!(
        distinct_req.len() >= 2,
        "≥2 distinct models on ExecuteRequest.model, got {req_models:?}"
    );

    // The run mirrors the ordered selection trace, also ≥2 distinct.
    let distinct_sel: HashSet<&String> = out.selected_models.iter().collect();
    assert!(
        distinct_sel.len() >= 2,
        "≥2 distinct models on RunOutput.selected_models, got {:?}",
        out.selected_models
    );

    // The selection trace and the requests observed by the connector agree in order.
    assert_eq!(
        out.selected_models, req_models,
        "RunOutput.selected_models mirrors the models routed through the connector"
    );

    // Both calls accrued in the aggregate cost snapshot.
    assert!(
        out.cost.total_calls >= 2,
        "both calls recorded in CostTracker"
    );
}
