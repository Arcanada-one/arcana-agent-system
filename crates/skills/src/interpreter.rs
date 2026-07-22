//! The read-on-invoke skill interpreter.
//!
//! [`SkillInterpreter::run_pinned`] resolves a [`SkillPin`] through a
//! [`SkillStore`] backend (the byte-acquisition seam), then executes the
//! validated plan's stages in declared order through the borrowed
//! `CapabilityExecutor`. The legacy [`SkillInterpreter::run`] is preserved as a
//! thin wrapper over a [`FileStore`], so a bumped on-disk version is still
//! observed on the next run without a rebuild.
//!
//! **Gate order (fail-closed).** Every run path enforces, in this exact order:
//! `blake3 hash → schema validate → maturity gate → tool-ceiling → model_spec
//! allowlist`. The first two live in the store's [`SkillStore::load`] (hash is
//! checked *before* parse — the trust keystone); the last three live in
//! [`SkillInterpreter::execute`]. The interpreter opens no audit sink and no
//! dispatch path of its own: the executor is the sole execution authority and
//! the single Blake3 `AuditLog` owner.

use std::path::Path;
use std::sync::Arc;

use arcana_core::dispatch::ModelPolicy;
use arcana_core::execution::{CapabilityError, CapabilityExecutor};
use arcana_core::hooks::HookContext;
use arcana_core::tool::ToolOutput;
use serde_json::Value;
use thiserror::Error;

use crate::plan::{Maturity, ModelSpec, PlanKind, SkillPlan, SkillPlanError, Stage};
use crate::store::{FileStore, ModelAllowlist, SkillPin, SkillStore, ToolCeiling};

/// Loads skill plans from a [`SkillStore`] backend and executes their stages
/// through a borrowed [`CapabilityExecutor`]. Holds no cached plan.
pub struct SkillInterpreter {
    executor: Arc<CapabilityExecutor>,
    policy: ModelPolicy,
    tool_ceiling: Option<ToolCeiling>,
    model_allowlist: Option<ModelAllowlist>,
}

/// The observable result of one skill run.
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
    /// The plan bytes could not be deserialised.
    #[error("failed to parse skill plan: {0}")]
    Parse(#[source] serde_json::Error),
    /// The plan failed intrinsic validation.
    #[error("invalid skill plan: {0}")]
    Invalid(#[from] SkillPlanError),
    /// The fetched bytes' locally-recomputed blake3 did not match the
    /// config-pinned hash. The content is rejected **before** any parse — the
    /// run-path trust keystone.
    #[error("blake3 mismatch for source `{source_id}`: content rejected before parse")]
    HashMismatch {
        /// The `source_id` whose bytes failed verification.
        source_id: String,
    },
    /// The store could not produce the pinned bytes and no verified cache entry
    /// exists. Fails closed — never falls back to a different or stale skill.
    #[error("skill store unavailable for source `{source_id}`: {reason}")]
    StoreUnavailable {
        /// The `source_id` that could not be fetched.
        source_id: String,
        /// The underlying reason (transport/status text).
        reason: String,
    },
    /// A stage declared a tool outside the per-agent enforced ceiling.
    #[error("stage `{stage_id}`: tool `{tool}` exceeds the per-agent tool ceiling")]
    ToolCeilingExceeded {
        /// The offending stage's id.
        stage_id: String,
        /// The tool that exceeded the ceiling.
        tool: String,
    },
    /// A stage's resolved model endpoint is outside the per-agent allowlist.
    #[error("stage `{stage_id}`: model `{model}` is not in the per-agent allowlist")]
    ModelNotAllowed {
        /// The offending stage's id.
        stage_id: String,
        /// The resolved model id that is not allowed.
        model: String,
    },
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
    /// Construct an interpreter over a shared executor and a model policy, with
    /// no tool ceiling or model allowlist configured (declared `tools` and
    /// model routing remain advisory — the Phase-1 minimal-vertical behaviour).
    #[must_use]
    pub fn new(executor: Arc<CapabilityExecutor>, policy: ModelPolicy) -> Self {
        Self {
            executor,
            policy,
            tool_ceiling: None,
            model_allowlist: None,
        }
    }

    /// Enable the per-agent enforced tool ceiling (V-AC-4).
    #[must_use]
    pub fn with_tool_ceiling(mut self, ceiling: ToolCeiling) -> Self {
        self.tool_ceiling = Some(ceiling);
        self
    }

    /// Enable the per-agent model-endpoint allowlist (V-AC-5).
    #[must_use]
    pub fn with_model_allowlist(mut self, allowlist: ModelAllowlist) -> Self {
        self.model_allowlist = Some(allowlist);
        self
    }

    /// Load the plan at `plan_path` from the local filesystem and run its
    /// stages in order (read-on-invoke via a [`FileStore`]).
    ///
    /// # Errors
    ///
    /// Returns [`SkillError`] if the file cannot be read or parsed, the plan
    /// fails validation, a template / sub-production plan reaches the run path,
    /// a gate rejects the plan, or a stage's capability execution fails.
    pub async fn run(
        &self,
        plan_path: &Path,
        ctx: &HookContext,
    ) -> Result<SkillRunOutput, SkillError> {
        let store = FileStore;
        let pin = SkillPin::local(plan_path.display().to_string());
        self.run_pinned(&store, &pin, ctx).await
    }

    /// Resolve `pin` through `store`, then execute the validated plan.
    ///
    /// The store enforces the hash keystone (before parse) and schema
    /// validation; [`Self::execute`] enforces the maturity, tool-ceiling, and
    /// model-allowlist gates before running any stage.
    ///
    /// # Errors
    ///
    /// Returns [`SkillError`] on any load-path failure (read/fetch,
    /// [`SkillError::HashMismatch`], [`SkillError::StoreUnavailable`], parse,
    /// validation) or any gate/stage failure during execution.
    pub async fn run_pinned(
        &self,
        store: &dyn SkillStore,
        pin: &SkillPin,
        ctx: &HookContext,
    ) -> Result<SkillRunOutput, SkillError> {
        let plan = store.load(pin).await?;
        self.execute(&plan, ctx).await
    }

    /// Enforce the run-path gates (maturity → tool-ceiling → model allowlist)
    /// and then execute each stage in declared order. No stage executes if any
    /// gate rejects the plan (fail-closed before side effects).
    async fn execute(
        &self,
        plan: &SkillPlan,
        ctx: &HookContext,
    ) -> Result<SkillRunOutput, SkillError> {
        Self::gate_run_path(plan)?;
        self.gate_tool_ceiling(plan)?;
        let selected = self.gate_model_allowlist(plan)?;

        let mut stages = Vec::with_capacity(plan.stages.len());
        let mut selected_models = Vec::with_capacity(plan.stages.len());
        for (stage, selected_model) in plan.stages.iter().zip(selected) {
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

    /// Reject any stage declaring a tool outside the enforced ceiling. A plan
    /// may only *narrow* the per-agent authority; it can never widen it. When
    /// no ceiling is configured the declared `tools` stay advisory.
    fn gate_tool_ceiling(&self, plan: &SkillPlan) -> Result<(), SkillError> {
        let Some(ceiling) = &self.tool_ceiling else {
            return Ok(());
        };
        for stage in &plan.stages {
            for tool in &stage.tools {
                if !ceiling.permits(tool) {
                    return Err(SkillError::ToolCeilingExceeded {
                        stage_id: stage.id.clone(),
                        tool: tool.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Resolve every stage's model and, if an allowlist is configured, reject
    /// the whole run when any resolved model is off-list (before any stage
    /// executes). Returns the resolved model ids in stage order.
    fn gate_model_allowlist(&self, plan: &SkillPlan) -> Result<Vec<String>, SkillError> {
        let resolved: Vec<String> = plan
            .stages
            .iter()
            .map(|stage| self.resolve_model(&stage.model))
            .collect();
        if let Some(allow) = &self.model_allowlist {
            for (stage, model) in plan.stages.iter().zip(&resolved) {
                if !allow.permits(model) {
                    return Err(SkillError::ModelNotAllowed {
                        stage_id: stage.id.clone(),
                        model: model.clone(),
                    });
                }
            }
        }
        Ok(resolved)
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
