//! The declarative skill-plan schema (data, not code).
//!
//! A [`SkillPlan`] is deserialised from an on-disk data file and carries the
//! six declared dimensions — stages / models / agent-count / limits / tools /
//! metrics — plus a [`PlanKind`] template↔instance distinction and a
//! [`Maturity`] `draft → validated → production` ladder. [`SkillPlan::validate`]
//! performs the plan's **intrinsic** checks and returns a typed
//! [`SkillPlanError`] — it never panics on malformed data.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The single schema version this build understands. A plan declaring any
/// other value is rejected by [`SkillPlan::validate`].
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// A declarative skill plan — the unit of data the interpreter loads and runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillPlan {
    /// Schema version the document was authored against.
    pub schema_version: u32,
    /// Human-readable skill name.
    pub name: String,
    /// Monotonic content version; a bump is what the next run picks up.
    pub version: u32,
    /// Template (a reusable blueprint) or a runnable instance.
    pub kind: PlanKind,
    /// Position on the `draft → validated → production` ladder.
    pub maturity: Maturity,
    /// Ordered stages executed top-to-bottom.
    pub stages: Vec<Stage>,
    /// Plan-level defaults (currently the fallback model).
    pub defaults: PlanDefaults,
}

/// Template↔instance distinction. A [`PlanKind::Template`] is a valid document
/// but is refused on the run path — it must be instantiated first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanKind {
    /// A reusable blueprint; not directly runnable.
    Template,
    /// A concrete, runnable instance.
    Instance,
}

/// The maturity ladder. Declaration order defines the [`Ord`] ordering
/// (`Draft < Validated < Production`), which the run-path floor relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Maturity {
    /// Freshly drafted; not production-runnable.
    Draft,
    /// Validated against its metrics; still below the production floor.
    Validated,
    /// Production-ready — the only maturity the run path accepts.
    Production,
}

/// One ordered stage of a skill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stage {
    /// Stable stage identifier.
    pub id: String,
    /// Which model this stage uses (a literal id or a task-type to resolve).
    pub model: ModelSpec,
    /// Declared agent fan-out. Validated `>= 1`; the minimal vertical runs 1.
    pub agent_count: u32,
    /// Per-stage budget limits.
    pub limits: StageLimits,
    /// Declared tool allowlist for the stage (advisory in the minimal vertical).
    pub tools: Vec<String>,
    /// Declared success metrics (consumed by the deferred improvement loop).
    pub metrics: Vec<MetricSpec>,
    /// The capability + input template executed once through the executor.
    pub action: StageAction,
}

/// How a stage's model is chosen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSpec {
    /// A verbatim abstract model id.
    Literal(String),
    /// A task-type resolved through `arcana_core::dispatch::ModelPolicy`.
    ByTaskType(TaskType),
}

/// Task-type carried in a plan. Mirrors `arcana_core::dispatch::TaskType` with a
/// serde representation; converts into the core type for policy selection.
///
/// A local mirror is used (rather than the core enum) because the core
/// `TaskType` intentionally derives no serde traits; this keeps the engine
/// self-contained with zero edits to `arcana-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskType {
    /// A code / reasoning step.
    Code,
    /// A summarize / interpret step.
    Summarize,
    /// Fallback for any unrecognised context.
    Default,
}

impl From<TaskType> for arcana_core::dispatch::TaskType {
    fn from(value: TaskType) -> Self {
        match value {
            TaskType::Code => arcana_core::dispatch::TaskType::Code,
            TaskType::Summarize => arcana_core::dispatch::TaskType::Summarize,
            TaskType::Default => arcana_core::dispatch::TaskType::Default,
        }
    }
}

/// Per-stage budget envelope (mirrors the driver's budget fields).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StageLimits {
    /// Maximum agent turns for the stage.
    pub max_turns: u32,
    /// Maximum spend for the stage, in USD.
    pub max_cost_usd: f64,
    /// Context budget in characters.
    pub context_budget_chars: u64,
}

/// The capability a stage invokes, plus its input template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StageAction {
    /// Capability (tool) name executed through the `CapabilityExecutor`.
    pub capability: String,
    /// Input template passed to the capability (the resolved model is injected
    /// for `model_call` stages).
    pub input: serde_json::Value,
}

/// A declared success metric for a stage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSpec {
    /// Metric name.
    pub name: String,
    /// Target value.
    pub goal: f64,
}

/// Plan-level defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanDefaults {
    /// The fallback model for the plan.
    pub model: ModelSpec,
}

/// Typed rejection reasons from [`SkillPlan::validate`]. Never a panic.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SkillPlanError {
    /// The plan's `schema_version` is not [`SUPPORTED_SCHEMA_VERSION`].
    #[error("unknown schema_version {found} (supported: {supported})")]
    UnknownSchemaVersion {
        /// The version the document declared.
        found: u32,
        /// The version this build supports.
        supported: u32,
    },
    /// The plan carries no stages.
    #[error("plan has no stages")]
    EmptyStages,
    /// A stage declared `agent_count == 0`.
    #[error("stage `{0}`: agent_count must be >= 1")]
    ZeroAgentCount(String),
    /// A stage's `action.capability` is empty.
    #[error("stage `{0}`: action.capability must not be empty")]
    EmptyCapability(String),
}

impl SkillPlan {
    /// Run the plan's intrinsic validity checks.
    ///
    /// Checks the `schema_version`, a non-empty stage list, and per-stage
    /// `agent_count >= 1` and non-empty `action.capability`. Template/maturity
    /// gating is a *run-path* concern (a template is a valid document), so it
    /// is enforced by the interpreter, not here.
    ///
    /// # Errors
    ///
    /// Returns a [`SkillPlanError`] describing the first violation found.
    pub fn validate(&self) -> Result<(), SkillPlanError> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(SkillPlanError::UnknownSchemaVersion {
                found: self.schema_version,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
        if self.stages.is_empty() {
            return Err(SkillPlanError::EmptyStages);
        }
        for stage in &self.stages {
            if stage.agent_count == 0 {
                return Err(SkillPlanError::ZeroAgentCount(stage.id.clone()));
            }
            if stage.action.capability.trim().is_empty() {
                return Err(SkillPlanError::EmptyCapability(stage.id.clone()));
            }
        }
        Ok(())
    }

    /// Return an instance clone of this plan (`kind = Instance`).
    #[must_use]
    pub fn instantiate(&self) -> SkillPlan {
        let mut instance = self.clone();
        instance.kind = PlanKind::Instance;
        instance
    }

    /// Return a clone promoted to the given maturity.
    #[must_use]
    pub fn promote(&self, to: Maturity) -> SkillPlan {
        let mut promoted = self.clone();
        promoted.maturity = to;
        promoted
    }
}
