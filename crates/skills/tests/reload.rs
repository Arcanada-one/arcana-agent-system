//! P5 / V-AC-2 (load-bearing DoD) — the same interpreter instance / same
//! binary picks up a bumped on-disk plan version on the next run. This is a
//! data reload, not a recompile: the test does no `cargo build` between runs
//! and the interpreter holds no cached parse (proven by the observed change).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::pedantic)]

mod common;

use std::sync::Arc;

use arcana_core::dispatch::ModelPolicy;
use arcana_skills::SkillInterpreter;
use serde_json::{json, Value};

use common::{executor_with, hook_ctx, EchoTool};

fn plan_at(version: u32, marker: &str) -> Value {
    json!({
        "schema_version": 1,
        "name": "reloadable",
        "version": version,
        "kind": "instance",
        "maturity": "production",
        "stages": [{
            "id": "only",
            "model": { "literal": "m-1" },
            "agent_count": 1,
            "limits": { "max_turns": 1, "max_cost_usd": 0.0, "context_budget_chars": 512 },
            "tools": [],
            "metrics": [],
            "action": { "capability": "echo", "input": { "marker": marker } }
        }],
        "defaults": { "model": { "by_task_type": "default" } }
    })
}

#[tokio::test]
async fn skill_new_version_picked_up_next_run() {
    let dir = tempfile::tempdir().unwrap();
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir(&audit_dir).unwrap();
    let plan_path = dir.path().join("plan.json");

    // One interpreter instance for the whole test — the "same binary" surface.
    let executor = executor_with(vec![Arc::new(EchoTool)], &audit_dir);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    // Run 1: version 1.
    std::fs::write(&plan_path, serde_json::to_vec(&plan_at(1, "behaviour-v1")).unwrap()).unwrap();
    let first = interpreter.run(&plan_path, &ctx).await.expect("run v1");
    assert_eq!(first.version, 1);
    assert!(first.stages[0].output.content.contains("behaviour-v1"));

    // Bump the SAME file to version 2 with changed stage behaviour. No rebuild.
    std::fs::write(&plan_path, serde_json::to_vec(&plan_at(2, "behaviour-v2")).unwrap()).unwrap();

    // Run 2: the SAME interpreter observes the new version + new behaviour.
    let second = interpreter.run(&plan_path, &ctx).await.expect("run v2");
    assert_eq!(second.version, 2, "bumped version must be picked up next run");
    assert!(second.stages[0].output.content.contains("behaviour-v2"));

    // The change is real: v1 behaviour is gone on run 2 (no cached parse).
    assert!(!second.stages[0].output.content.contains("behaviour-v1"));
    assert_ne!(first.version, second.version);
}
