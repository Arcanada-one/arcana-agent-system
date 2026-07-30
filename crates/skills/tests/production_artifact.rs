//! ARAS-0057 — production plan artifact parse + validate + captured-execution
//! coverage.
//!
//! Proves that the committed `skills-kb-discovery-probe.json` deserialises to a
//! valid [`SkillPlan`] matching the declared arcana_search shape, and that the
//! [`SkillInterpreter`] dispatches the exact safe input to the `arcana_search`
//! capability without any network call (captured via an offline echo probe).
//!
//! The artifact itself is a bounded, production-reviewed skills-KB discovery
//! probe — not a test-only placeholder — and contains no secrets, endpoints,
//! task IDs, or environment-specific paths.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::sync::Arc;

use arcana_core::dispatch::ModelPolicy;
use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use arcana_skills::plan::{
    Maturity, ModelSpec, PlanKind, SkillPlan, StageLimits, SUPPORTED_SCHEMA_VERSION,
};
use arcana_skills::{SkillInterpreter, TaskType};
use async_trait::async_trait;
use common::{executor_with, hook_ctx};

const ARTIFACT_BYTES: &[u8] = include_bytes!("../data/skills-kb-discovery-probe.json");

/// An offline echo tool registered as `"arcana_search"` so the interpreter
/// can dispatch a probe stage against it without touching the network. The
/// tool echoes its JSON input verbatim — captured by the test to prove the
/// exact dispatched fields.
struct ArcanaSearchEcho;

#[async_trait]
impl Tool for ArcanaSearchEcho {
    fn name(&self) -> &'static str {
        "arcana_search"
    }
    fn description(&self) -> &'static str {
        "offline echo probe for arcana_search capability tests"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object"})
    }
    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            content: invocation.into_input().to_string(),
            metadata: None,
        })
    }
}

#[test]
fn deserialises_and_validates_skills_kb_discovery_probe() {
    let plan: SkillPlan =
        serde_json::from_slice(ARTIFACT_BYTES).expect("must deserialise to SkillPlan");
    plan.validate().expect("must pass intrinsic validation");

    // --- top-level identity ---
    assert_eq!(plan.schema_version, SUPPORTED_SCHEMA_VERSION);
    assert_eq!(plan.name, "skills-kb-discovery-probe");
    assert_eq!(plan.version, 1);
    assert_eq!(plan.kind, PlanKind::Instance);
    assert_eq!(plan.maturity, Maturity::Production);

    // --- exactly one stage ---
    assert_eq!(plan.stages.len(), 1);

    let stage = &plan.stages[0];
    assert_eq!(stage.id, "probe");
    let ModelSpec::ByTaskType(task_type) = &stage.model else {
        panic!("expected model by task type, got {:?}", stage.model);
    };
    assert_eq!(*task_type, TaskType::Default);
    assert_eq!(stage.agent_count, 1);

    // --- limits: zero-cost probe ---
    let limits = &stage.limits;
    let expected_limits = StageLimits {
        max_turns: 1,
        max_cost_usd: 0.0,
        context_budget_chars: 4096,
    };
    assert_eq!(*limits, expected_limits);

    // --- tool allowlist: only arcana_search ---
    assert_eq!(stage.tools, vec!["arcana_search"]);

    // --- no metrics (this is a probe, not an eval plan) ---
    assert!(stage.metrics.is_empty());

    // --- arcana_search capability ---
    assert_eq!(stage.action.capability, "arcana_search");
    let expected_input = serde_json::json!({
        "query": "production skill retrieval contract source-grounded-summary",
        "namespace": "skills",
        "limit": 1,
        "include_content": false
    });
    assert_eq!(
        stage.action.input, expected_input,
        "action input must match the declared probe exactly — no undeclared or missing fields"
    );

    // --- defaults ---
    assert_eq!(
        plan.defaults.model,
        ModelSpec::ByTaskType(TaskType::Default)
    );
}

/// Prove the [`SkillInterpreter`] dispatches the exact safe `arcana_search`
/// input declared in the artifact, using an offline echo probe — no network
/// call, no Scrutator dependency.
#[tokio::test]
async fn captured_execution_dispatches_exact_arcana_search_input() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let plan_path = dir.path().join("skills-kb-discovery-probe.json");
    std::fs::write(&plan_path, ARTIFACT_BYTES).unwrap();

    let executor = executor_with(vec![Arc::new(ArcanaSearchEcho)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    let out = interpreter
        .run(&plan_path, &ctx)
        .await
        .expect("probe plan must execute successfully");

    assert_eq!(out.stages.len(), 1);
    let stage_result = &out.stages[0];
    assert_eq!(stage_result.stage_id, "probe");

    // The echoed input must match the declared probe shape exactly.
    let echoed: serde_json::Value =
        serde_json::from_str(&stage_result.output.content).expect("echoed content must be JSON");
    let expected_input = serde_json::json!({
        "query": "production skill retrieval contract source-grounded-summary",
        "namespace": "skills",
        "limit": 1,
        "include_content": false
    });
    assert_eq!(
        echoed, expected_input,
        "dispatched input must match the declared probe exactly — no undeclared or missing fields"
    );

    // Resolved model: ByTaskType(Default) → the default policy arm.
    assert_eq!(stage_result.selected_model, "arcana-default");
}
