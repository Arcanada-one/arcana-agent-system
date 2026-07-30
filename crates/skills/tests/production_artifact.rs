//! ARAS-0057 — production plan artifact parse + validate coverage.
//!
//! Proves that the committed `source-grounded-summary.json` deserialises to a
//! valid [`SkillPlan`] matching the declared shape: schema 1, Instance kind,
//! Production maturity, one model_call stage, and the source-grounding metric.
//!
//! The artifact itself is a useful, bounded, production-reviewed plan — not a
//! test-only placeholder — and contains no secrets, endpoints, task IDs, or
//! environment-specific paths.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_skills::plan::{
    Maturity, ModelSpec, PlanKind, SkillPlan, StageLimits, SUPPORTED_SCHEMA_VERSION,
};
use arcana_skills::TaskType;

const ARTIFACT_BYTES: &[u8] = include_bytes!("../data/source-grounded-summary.json");

#[test]
fn deserialises_to_skillplan() {
    let plan: SkillPlan =
        serde_json::from_slice(ARTIFACT_BYTES).expect("must deserialise to SkillPlan");
    plan.validate().expect("must pass intrinsic validation");

    // --- top-level identity ---
    assert_eq!(plan.schema_version, SUPPORTED_SCHEMA_VERSION);
    assert_eq!(plan.name, "source-grounded-summary");
    assert_eq!(plan.version, 1);
    assert_eq!(plan.kind, PlanKind::Instance);
    assert_eq!(plan.maturity, Maturity::Production);

    // --- exactly one stage ---
    assert_eq!(plan.stages.len(), 1);

    let stage = &plan.stages[0];
    assert_eq!(stage.id, "summarize");
    let ModelSpec::ByTaskType(task_type) = &stage.model else {
        panic!("expected model by task type, got {:?}", stage.model);
    };
    assert_eq!(*task_type, TaskType::Summarize);
    assert_eq!(stage.agent_count, 1);

    // --- limits ---
    let limits = &stage.limits;
    let expected_limits = StageLimits {
        max_turns: 1,
        max_cost_usd: 0.2,
        context_budget_chars: 32_768,
    };
    assert_eq!(*limits, expected_limits);

    // --- empty tool allowlist ---
    assert!(stage.tools.is_empty());

    // --- metrics ---
    assert_eq!(stage.metrics.len(), 1);
    assert_eq!(stage.metrics[0].name, "grounded_claim_ratio");
    assert!((stage.metrics[0].goal - 1.0).abs() < f64::EPSILON);

    // --- model_call capability ---
    assert_eq!(stage.action.capability, "model_call");
    assert!(!stage.action.input.as_object().unwrap().is_empty());
    let prompt = stage.action.input["prompt"]
        .as_str()
        .expect("prompt must be a string");
    assert!(!prompt.is_empty());

    // --- defaults ---
    assert_eq!(
        plan.defaults.model,
        ModelSpec::ByTaskType(TaskType::Summarize)
    );
}
