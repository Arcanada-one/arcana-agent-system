//! Minimal deterministic skill-builder.
//!
//! [`SkillBuilder::draft_stub`] materialises a schema-valid `Draft`/`Template`
//! skeleton plan fast — the "draft a missing skill quickly" entry point of the
//! maturity ladder, as a deterministic emit (no LLM, no background loop). The
//! full LLM-drafted builder and the background-improvement loop are deferred to
//! ARAS-0046.

use serde_json::json;

use crate::plan::{
    Maturity, ModelSpec, PlanDefaults, PlanKind, SkillPlan, Stage, StageAction, StageLimits,
    TaskType, SUPPORTED_SCHEMA_VERSION,
};

/// Emits skeleton skill plans.
pub struct SkillBuilder;

impl SkillBuilder {
    /// Return a schema-valid one-stage `Draft`/`Template` skeleton plan named
    /// `name`. It passes [`SkillPlan::validate`]; instantiate + promote it to
    /// reach the run path.
    #[must_use]
    pub fn draft_stub(name: &str) -> SkillPlan {
        SkillPlan {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            name: name.to_owned(),
            version: 1,
            kind: PlanKind::Template,
            maturity: Maturity::Draft,
            stages: vec![Stage {
                id: "stage-0".to_owned(),
                model: ModelSpec::ByTaskType(TaskType::Default),
                agent_count: 1,
                limits: StageLimits {
                    max_turns: 1,
                    max_cost_usd: 0.0,
                    context_budget_chars: 4096,
                },
                tools: Vec::new(),
                metrics: Vec::new(),
                action: StageAction {
                    capability: "model_call".to_owned(),
                    input: json!({ "prompt": "TODO: describe what this skill should do" }),
                },
            }],
            defaults: PlanDefaults {
                model: ModelSpec::ByTaskType(TaskType::Default),
            },
        }
    }
}
