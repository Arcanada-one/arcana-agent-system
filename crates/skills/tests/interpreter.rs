//! P2 / V-AC-1 — the interpreter reads a plan from disk and runs its stages in
//! declared order with deterministic, observable output.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::sync::Arc;

use arcana_core::dispatch::ModelPolicy;
use arcana_skills::SkillInterpreter;
use serde_json::json;

use common::{executor_with, hook_ctx, EchoTool};

fn write_plan(path: &std::path::Path, body: serde_json::Value) {
    std::fs::write(path, serde_json::to_vec(&body).unwrap()).unwrap();
}

fn two_stage_echo_plan() -> serde_json::Value {
    json!({
        "schema_version": 1,
        "name": "ordered",
        "version": 1,
        "kind": "instance",
        "maturity": "production",
        "stages": [
            {
                "id": "first",
                "model": { "literal": "m-1" },
                "agent_count": 1,
                "limits": { "max_turns": 1, "max_cost_usd": 0.0, "context_budget_chars": 1024 },
                "tools": [],
                "metrics": [],
                "action": { "capability": "echo", "input": { "marker": "stage-first" } }
            },
            {
                "id": "second",
                "model": { "literal": "m-2" },
                "agent_count": 1,
                "limits": { "max_turns": 1, "max_cost_usd": 0.0, "context_budget_chars": 1024 },
                "tools": [],
                "metrics": [],
                "action": { "capability": "echo", "input": { "marker": "stage-second" } }
            }
        ],
        "defaults": { "model": { "by_task_type": "default" } }
    })
}

#[tokio::test]
async fn skill_load_and_run() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let plan_path = dir.path().join("plan.json");
    write_plan(&plan_path, two_stage_echo_plan());

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    let out = interpreter.run(&plan_path, &ctx).await.expect("run ok");

    // Two stages ran, in declared order.
    assert_eq!(out.stages.len(), 2);
    assert_eq!(out.stages[0].stage_id, "first");
    assert_eq!(out.stages[1].stage_id, "second");
    // Deterministic echoed output proves the declared order + data path.
    assert!(out.stages[0].output.content.contains("stage-first"));
    assert!(out.stages[1].output.content.contains("stage-second"));
    // Selected models recorded in order.
    assert_eq!(out.selected_models, vec!["m-1", "m-2"]);
    assert_eq!(out.version, 1);
}

#[tokio::test]
async fn unregistered_capability_is_typed_error_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let plan_path = dir.path().join("plan.json");
    let mut body = two_stage_echo_plan();
    body["stages"][0]["action"]["capability"] = json!("not_registered");
    write_plan(&plan_path, body);

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    let result = interpreter.run(&plan_path, &ctx).await;
    assert!(result.is_err(), "unknown capability must surface as Err");
}
