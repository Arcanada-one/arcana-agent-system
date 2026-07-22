//! Store-seam tests for ARAS-0047 Phase-1: the `SkillStore` trait, the trusted
//! `FileStore`, the blake3 verify-before-parse keystone, the tool-ceiling and
//! model-allowlist gates, the no-silent-fallback `StoreUnavailable` behaviour,
//! the blake3-content-addressed cache, and the two-phase type-level firewall.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::sync::Arc;

use arcana_core::dispatch::ModelPolicy;
use arcana_skills::{FileStore, SkillInterpreter, SkillPin, SkillStore};
use serde_json::json;

use common::{executor_with, hook_ctx, EchoTool};

fn production_echo_plan() -> serde_json::Value {
    json!({
        "schema_version": 1,
        "name": "codegen-review",
        "version": 3,
        "kind": "instance",
        "maturity": "production",
        "stages": [
            {
                "id": "s1",
                "model": { "literal": "m-default" },
                "agent_count": 1,
                "limits": { "max_turns": 4, "max_cost_usd": 0.5, "context_budget_chars": 40000 },
                "tools": ["echo"],
                "metrics": [],
                "action": { "capability": "echo", "input": { "marker": "keystone" } }
            }
        ],
        "defaults": { "model": { "literal": "m-default" } }
    })
}

/// V-AC-2 — a plan loaded through `FileStore::load` is byte-for-byte the same
/// `SkillPlan` the legacy `fs::read` + `serde_json::from_slice` produced.
#[tokio::test]
async fn filestore_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let plan_path = dir.path().join("plan.json");
    let bytes = serde_json::to_vec(&production_echo_plan()).unwrap();
    std::fs::write(&plan_path, &bytes).unwrap();

    // Legacy path.
    let legacy: arcana_skills::SkillPlan = serde_json::from_slice(&bytes).unwrap();

    // Seam path.
    let store = FileStore;
    let pin = SkillPin::local(plan_path.display().to_string());
    let via_store = store.load(&pin).await.expect("FileStore load ok");

    assert_eq!(legacy, via_store, "FileStore load must be byte-identical");
}

/// V-AC-1 (seam) — the extracted `run(&Path)` wrapper still runs a plan
/// end-to-end through a `FileStore`, preserving the legacy entry point.
#[tokio::test]
async fn run_wrapper_still_executes() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let plan_path = dir.path().join("plan.json");
    std::fs::write(&plan_path, serde_json::to_vec(&production_echo_plan()).unwrap()).unwrap();

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    let out = interpreter.run(&plan_path, &ctx).await.expect("run ok");
    assert_eq!(out.stages.len(), 1);
    assert!(out.stages[0].output.content.contains("keystone"));
    assert_eq!(out.selected_models, vec!["m-default"]);
}
