//! P1 / V-AC-3 — plan schema carries every declared dimension and round-trips;
//! malformed / unknown-schema-version plans are rejected with a typed error,
//! never a panic.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use arcana_skills::{
    Maturity, MetricSpec, ModelSpec, PlanDefaults, PlanKind, SkillPlan, Stage, StageAction,
    StageLimits, TaskType,
};
use serde_json::json;

fn sample_plan(kind: PlanKind, maturity: Maturity) -> SkillPlan {
    SkillPlan {
        schema_version: 1,
        name: "sample".to_owned(),
        version: 3,
        kind,
        maturity,
        stages: vec![
            Stage {
                id: "draft".to_owned(),
                model: ModelSpec::Literal("m-literal".to_owned()),
                agent_count: 2,
                limits: StageLimits {
                    max_turns: 4,
                    max_cost_usd: 0.25,
                    context_budget_chars: 8192,
                },
                tools: vec!["read".to_owned(), "grep".to_owned()],
                metrics: vec![MetricSpec {
                    name: "coverage".to_owned(),
                    goal: 0.9,
                }],
                action: StageAction {
                    capability: "model_call".to_owned(),
                    input: json!({ "prompt": "draft it" }),
                },
            },
            Stage {
                id: "review".to_owned(),
                model: ModelSpec::ByTaskType(TaskType::Code),
                agent_count: 1,
                limits: StageLimits {
                    max_turns: 2,
                    max_cost_usd: 0.10,
                    context_budget_chars: 4096,
                },
                tools: Vec::new(),
                metrics: Vec::new(),
                action: StageAction {
                    capability: "model_call".to_owned(),
                    input: json!({ "prompt": "review it" }),
                },
            },
        ],
        defaults: PlanDefaults {
            model: ModelSpec::ByTaskType(TaskType::Default),
        },
    }
}

#[test]
fn skill_plan_schema_roundtrip() {
    // Every declared dimension present on the instance form.
    let plan = sample_plan(PlanKind::Instance, Maturity::Production);
    let text = serde_json::to_string(&plan).expect("serialize");
    let back: SkillPlan = serde_json::from_str(&text).expect("deserialize");
    assert_eq!(plan, back, "round-trip must be lossless");

    // Dimensions: stages / models / agent-count / limits / tools / metrics.
    assert_eq!(back.stages.len(), 2);
    assert_eq!(
        back.stages[0].model,
        ModelSpec::Literal("m-literal".to_owned())
    );
    assert_eq!(back.stages[1].model, ModelSpec::ByTaskType(TaskType::Code));
    assert_eq!(back.stages[0].agent_count, 2);
    assert_eq!(back.stages[0].limits.max_turns, 4);
    assert!((back.stages[0].limits.max_cost_usd - 0.25).abs() < f64::EPSILON);
    assert_eq!(back.stages[0].limits.context_budget_chars, 8192);
    assert_eq!(back.stages[0].tools, vec!["read", "grep"]);
    assert_eq!(back.stages[0].metrics[0].name, "coverage");
    assert_eq!(back.stages[0].action.capability, "model_call");

    // template↔instance distinction round-trips both ways.
    let tmpl = sample_plan(PlanKind::Template, Maturity::Draft);
    let tmpl_back: SkillPlan =
        serde_json::from_str(&serde_json::to_string(&tmpl).unwrap()).unwrap();
    assert_eq!(tmpl_back.kind, PlanKind::Template);
    assert_eq!(back.kind, PlanKind::Instance);

    // maturity ladder: Draft < Validated < Production (Ord) and all serialize.
    assert!(Maturity::Draft < Maturity::Validated);
    assert!(Maturity::Validated < Maturity::Production);
    for m in [Maturity::Draft, Maturity::Validated, Maturity::Production] {
        let p = sample_plan(PlanKind::Instance, m);
        let rt: SkillPlan = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(rt.maturity, m);
    }

    // A well-formed plan validates.
    assert!(plan.validate().is_ok());
}

#[test]
fn skill_plan_rejects_invalid() {
    // Empty-stages fixture → typed Err (not a panic).
    let empty_stages = json!({
        "schema_version": 1,
        "name": "broken",
        "version": 1,
        "kind": "instance",
        "maturity": "production",
        "stages": [],
        "defaults": { "model": { "by_task_type": "default" } }
    });
    let plan: SkillPlan = serde_json::from_value(empty_stages).expect("parses structurally");
    assert!(plan.validate().is_err(), "empty stages must be rejected");

    // Unknown schema_version fixture → typed Err.
    let mut bad = sample_plan(PlanKind::Instance, Maturity::Production);
    bad.schema_version = 999;
    assert!(
        bad.validate().is_err(),
        "unknown schema_version must be rejected"
    );

    // agent_count == 0 → typed Err.
    let mut zero = sample_plan(PlanKind::Instance, Maturity::Production);
    zero.stages[0].agent_count = 0;
    assert!(zero.validate().is_err(), "agent_count 0 must be rejected");
}
