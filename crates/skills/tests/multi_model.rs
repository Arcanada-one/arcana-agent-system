//! P4 / V-AC-5 — two stages declaring two distinct models each route through
//! the `model_call` capability; the run records >= 2 distinct model ids.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::dispatch::ModelPolicy;
use arcana_core::tool::Tool;
use arcana_skills::SkillInterpreter;
use arcana_tools::model_call::ModelCallTool;
use serde_json::json;

use common::{executor_with, hook_ctx, FakeConnector};

#[tokio::test]
async fn skill_per_stage_multi_model() {
    let dir = tempfile::tempdir().unwrap();
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir(&audit_dir).unwrap();
    let plan_path = dir.path().join("plan.json");

    // Stage A pins a literal model; stage B resolves TaskType::Code through the
    // policy to "arcana-code-strong" — two distinct model selections.
    let plan = json!({
        "schema_version": 1,
        "name": "multi-model",
        "version": 1,
        "kind": "instance",
        "maturity": "production",
        "stages": [
            {
                "id": "a",
                "model": { "literal": "m-a" },
                "agent_count": 1,
                "limits": { "max_turns": 1, "max_cost_usd": 0.0, "context_budget_chars": 512 },
                "tools": [],
                "metrics": [],
                "action": { "capability": "model_call", "input": { "prompt": "draft" } }
            },
            {
                "id": "b",
                "model": { "by_task_type": "code" },
                "agent_count": 1,
                "limits": { "max_turns": 1, "max_cost_usd": 0.0, "context_budget_chars": 512 },
                "tools": [],
                "metrics": [],
                "action": { "capability": "model_call", "input": { "prompt": "review" } }
            }
        ],
        "defaults": { "model": { "by_task_type": "default" } }
    });
    std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();

    let model_call: Arc<dyn Tool> = Arc::new(ModelCallTool::new(
        Arc::new(FakeConnector),
        Arc::new(CostTracker::new()),
        "test-connector",
    ));
    let executor = executor_with(vec![model_call], &audit_dir);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    let out = interpreter.run(&plan_path, &ctx).await.expect("run ok");

    // Both stages routed through model_call; the fake echoes the routed model.
    assert_eq!(out.stages.len(), 2);
    assert_eq!(out.selected_models[0], "m-a");
    assert_eq!(out.selected_models[1], "arcana-code-strong");
    assert!(out.stages[0].output.content.contains("echo:m-a"));
    assert!(out.stages[1]
        .output
        .content
        .contains("echo:arcana-code-strong"));

    // >= 2 distinct model ids exercised in one run.
    let distinct: HashSet<&String> = out.selected_models.iter().collect();
    assert!(
        distinct.len() >= 2,
        "expected >= 2 distinct model selections, got {:?}",
        out.selected_models
    );
}
