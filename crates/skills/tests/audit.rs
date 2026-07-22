//! P3 / V-AC-4 — a stage executes through `CapabilityExecutor`, producing
//! exactly one decision+result audit pair via the executor-owned `AuditLog`.
//! The engine opens no sink of its own (grep guard enforced separately).
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
use serde_json::{json, Value};

use common::{executor_with, hook_ctx, EchoTool};

#[tokio::test]
async fn skill_stage_single_audit_via_executor() {
    let dir = tempfile::tempdir().unwrap();
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir(&audit_dir).unwrap();
    let plan_path = dir.path().join("plan.json");

    let plan = json!({
        "schema_version": 1,
        "name": "single-audit",
        "version": 1,
        "kind": "instance",
        "maturity": "production",
        "stages": [{
            "id": "only",
            "model": { "literal": "m-1" },
            "agent_count": 1,
            "limits": { "max_turns": 1, "max_cost_usd": 0.0, "context_budget_chars": 512 },
            "tools": [],
            "metrics": [],
            "action": { "capability": "echo", "input": { "marker": "audit-me" } }
        }],
        "defaults": { "model": { "by_task_type": "default" } }
    });
    std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit_dir);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    interpreter.run(&plan_path, &ctx).await.expect("run ok");

    // The executor owns exactly one audit sink: <audit_dir>/audit.log.
    let log = std::fs::read_to_string(audit_dir.join("audit.log")).expect("audit.log exists");
    let lines: Vec<&str> = log.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        2,
        "one invocation must emit exactly one decision + one result line, got {lines:?}"
    );

    let decision: Value = serde_json::from_str(lines[0]).unwrap();
    let result: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(decision["phase"], "decision");
    assert_eq!(decision["decision"], "Allowed");
    assert!(
        decision["input_hash"]
            .as_str()
            .is_some_and(|h| !h.is_empty()),
        "decision record carries a Blake3 input_hash"
    );
    assert_eq!(result["phase"], "result");
    assert_eq!(result["outcome"], "success");
    assert!(
        result["output_hash"]
            .as_str()
            .is_some_and(|h| !h.is_empty()),
        "result record carries a Blake3 output_hash"
    );
    // Same invocation id correlates the pair.
    assert_eq!(decision["invocation_id"], result["invocation_id"]);
}
