//! P7 / V-AC-7 — the run path refuses a template and a sub-production maturity
//! with a typed error, and accepts an instantiated Production instance.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::pedantic)]

mod common;

use std::sync::Arc;

use arcana_core::dispatch::ModelPolicy;
use arcana_skills::{Maturity, SkillError, SkillInterpreter};
use serde_json::{json, Value};

use common::{executor_with, hook_ctx, EchoTool};

fn plan(kind: &str, maturity: &str) -> Value {
    json!({
        "schema_version": 1,
        "name": "gated",
        "version": 1,
        "kind": kind,
        "maturity": maturity,
        "stages": [{
            "id": "only",
            "model": { "literal": "m-1" },
            "agent_count": 1,
            "limits": { "max_turns": 1, "max_cost_usd": 0.0, "context_budget_chars": 512 },
            "tools": [],
            "metrics": [],
            "action": { "capability": "echo", "input": { "marker": "gate" } }
        }],
        "defaults": { "model": { "by_task_type": "default" } }
    })
}

#[tokio::test]
async fn skill_maturity_and_template_gate() {
    let dir = tempfile::tempdir().unwrap();
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir(&audit_dir).unwrap();
    let plan_path = dir.path().join("plan.json");

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit_dir);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    let run = |body: Value| {
        let plan_path = plan_path.clone();
        let interpreter = &interpreter;
        let ctx = &ctx;
        async move {
            std::fs::write(&plan_path, serde_json::to_vec(&body).unwrap()).unwrap();
            interpreter.run(&plan_path, ctx).await
        }
    };

    // A template (even at Production) is refused as not-runnable.
    let err = run(plan("template", "production")).await.unwrap_err();
    assert!(
        matches!(err, SkillError::TemplateNotRunnable),
        "template must be refused, got {err:?}"
    );

    // A Draft instance is below the production floor → refused.
    let err = run(plan("instance", "draft")).await.unwrap_err();
    assert!(
        matches!(err, SkillError::ImmatureForRun(Maturity::Draft)),
        "draft must be refused, got {err:?}"
    );

    // A Validated instance is still below the production floor → refused.
    let err = run(plan("instance", "validated")).await.unwrap_err();
    assert!(
        matches!(err, SkillError::ImmatureForRun(Maturity::Validated)),
        "validated must be refused, got {err:?}"
    );

    // An instantiated Production instance runs.
    let out = run(plan("instance", "production")).await.expect("production runs");
    assert_eq!(out.stages.len(), 1);
    assert_eq!(out.stages[0].stage_id, "only");
}
