//! The read-on-invoke skill interpreter.
//!
//! [`SkillInterpreter::run`] reads and deserialises the plan **from disk on
//! every call** (the data-reload boundary — no parsed plan is cached across
//! runs), validates it, refuses a template or a sub-production plan on the run
//! path, then executes each stage in declared order through the borrowed
//! `CapabilityExecutor`. It opens no audit sink and no dispatch path of its
//! own: the executor is the sole execution authority and the single Blake3
//! `AuditLog` owner.

use std::path::Path;
use std::sync::Arc;

use arcana_core::dispatch::ModelPolicy;
use arcana_core::execution::{CapabilityError, CapabilityExecutor};
use arcana_core::hooks::HookContext;
use arcana_core::tool::ToolOutput;
use serde_json::Value;
use thiserror::Error;

use crate::plan::{Maturity, ModelSpec, PlanKind, SkillPlan, SkillPlanError, Stage};

/// Loads skill plans from data files and executes their stages through a
/// borrowed [`CapabilityExecutor`]. Holds no cached plan.
pub struct SkillInterpreter {
    executor: Arc<CapabilityExecutor>,
    policy: ModelPolicy,
}

/// The observable result of one [`SkillInterpreter::run`].
#[derive(Debug, Clone)]
pub struct SkillRunOutput {
    /// The plan `version` that was loaded for this run (data-reload evidence).
    pub version: u32,
    /// Per-stage results, in declared execution order.
    pub stages: Vec<StageResult>,
    /// The model id selected for each stage, in order.
    pub selected_models: Vec<String>,
}

/// The result of a single executed stage.
#[derive(Debug, Clone)]
pub struct StageResult {
    /// The stage's declared id.
    pub stage_id: String,
    /// The model id resolved and used for this stage.
    pub selected_model: String,
    /// The capability output produced by the stage.
    pub output: ToolOutput,
}

/// Typed failure surface for a skill run. Never a panic on untrusted plan data.
#[derive(Debug, Error)]
pub enum SkillError {
    /// The plan file could not be read.
    #[error("failed to read skill plan `{path}`: {source}")]
    Read {
        /// The path that failed to read.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The plan file could not be deserialised.
    #[error("failed to parse skill plan: {0}")]
    Parse(#[source] serde_json::Error),
    /// The plan failed intrinsic validation.
    #[error("invalid skill plan: {0}")]
    Invalid(#[from] SkillPlanError),
    /// A template plan was submitted to the run path.
    #[error("a template plan cannot be executed; instantiate it first")]
    TemplateNotRunnable,
    /// The plan's maturity is below the production run floor.
    #[error("plan maturity {0:?} is below the production run floor")]
    ImmatureForRun(Maturity),
    /// A stage's capability execution failed (e.g. an unregistered tool).
    #[error("stage `{stage_id}` failed: {source}")]
    Stage {
        /// The failing stage's id.
        stage_id: String,
        /// The underlying capability error.
        #[source]
        source: CapabilityError,
    },
}

impl SkillInterpreter {
    /// Construct an interpreter over a shared executor and a model policy.
    #[must_use]
    pub fn new(executor: Arc<CapabilityExecutor>, policy: ModelPolicy) -> Self {
        Self { executor, policy }
    }

    /// Load the plan at `plan_path` from disk and run its stages in order.
    ///
    /// Reads and deserialises the file on **every** call (read-on-invoke), so a
    /// bumped on-disk version is observed on the next run without a rebuild.
    ///
    /// # Errors
    ///
    /// Returns [`SkillError`] if the file cannot be read or parsed, the plan
    /// fails validation, a template / sub-production plan reaches the run path,
    /// or a stage's capability execution fails.
    pub async fn run(
        &self,
        plan_path: &Path,
        ctx: &HookContext,
    ) -> Result<SkillRunOutput, SkillError> {
        let bytes = std::fs::read(plan_path).map_err(|source| SkillError::Read {
            path: plan_path.display().to_string(),
            source,
        })?;
        let plan: SkillPlan = serde_json::from_slice(&bytes).map_err(SkillError::Parse)?;
        plan.validate()?;
        Self::gate_run_path(&plan)?;

        let mut stages = Vec::with_capacity(plan.stages.len());
        let mut selected_models = Vec::with_capacity(plan.stages.len());
        for stage in &plan.stages {
            let selected_model = self.resolve_model(&stage.model);
            let input = build_capability_input(stage, &selected_model);
            let executed = self
                .executor
                .execute(ctx, &stage.action.capability, input)
                .await
                .map_err(|source| SkillError::Stage {
                    stage_id: stage.id.clone(),
                    source,
                })?;
            selected_models.push(selected_model.clone());
            stages.push(StageResult {
                stage_id: stage.id.clone(),
                selected_model,
                output: executed.output,
            });
        }
        Ok(SkillRunOutput {
            version: plan.version,
            stages,
            selected_models,
        })
    }

    /// Refuse a template or a below-production plan on the run path.
    fn gate_run_path(plan: &SkillPlan) -> Result<(), SkillError> {
        if plan.kind == PlanKind::Template {
            return Err(SkillError::TemplateNotRunnable);
        }
        if plan.maturity < Maturity::Production {
            return Err(SkillError::ImmatureForRun(plan.maturity));
        }
        Ok(())
    }

    /// Resolve a stage's model: a literal id verbatim, or a task-type routed
    /// through the reused `ModelPolicy`.
    fn resolve_model(&self, spec: &ModelSpec) -> String {
        match spec {
            ModelSpec::Literal(id) => id.clone(),
            ModelSpec::ByTaskType(task) => self.policy.select((*task).into()).model_id,
        }
    }
}

/// Build the capability input for a stage. For a `model_call` stage the
/// resolved model id is injected so the plan never carries a hard-coded model
/// that could diverge from the declared `ModelSpec`.
fn build_capability_input(stage: &Stage, resolved_model: &str) -> Value {
    let mut input = stage.action.input.clone();
    if stage.action.capability == "model_call" {
        if let Value::Object(map) = &mut input {
            map.insert("model".to_owned(), Value::String(resolved_model.to_owned()));
        }
    }
    input
}
