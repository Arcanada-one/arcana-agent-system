//! Multi-model dispatch policy (D-REQ-01/02/04). Pure data + deterministic
//! classification — no I/O, no network. The driver consumes `select` + `classify`
//! once per turn to choose `ExecuteRequest.model`; vendors stay abstracted
//! server-side by the Model Connector (this names only an abstract model id).

use crate::agent_loop::HistoryEntry;

/// Cost class of a selected model (D-REQ-04). The two exercised task-types
/// resolve to two DISTINCT tiers, so selection is keyed on task-type AND cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostTier {
    /// Strong / reasoning model — a code or reasoning step.
    Expensive,
    /// Cheap / fast model — a summarize or interpret step.
    Cheap,
}

/// The step task-type the classifier distinguishes (D-REQ-02). Fails closed to
/// [`TaskType::Default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskType {
    /// A code / reasoning step → expensive model.
    Code,
    /// A summarize / interpret step (typically after a tool result) → cheap model.
    Summarize,
    /// Fallback for any unrecognised context.
    Default,
}

/// The policy's per-turn output: which abstract model id, at which cost tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelChoice {
    /// Abstract model id written onto `ExecuteRequest.model`.
    pub model_id: String,
    /// The cost tier this choice belongs to.
    pub tier: CostTier,
}

/// Data-driven, deterministic model-selection policy (D-REQ-01). The table maps a
/// [`TaskType`] to a `(model_id, CostTier)`; an unmapped type falls back to the
/// default arm. Built from data — tunable without touching the loop.
#[derive(Debug, Clone)]
pub struct ModelPolicy {
    code: ModelChoice,
    summarize: ModelChoice,
    default: ModelChoice,
}

/// Model the built-in policy dispatches to when the caller pins nothing.
///
/// A real catalogue entry, not an abstract tier name: `DriverConfig::policy`
/// ids are sent to the Model Connector verbatim.
const DEFAULT_MODEL_ID: &str = "deepseek-v4-flash";

impl ModelPolicy {
    /// Built-in default table.
    ///
    /// These ids go on the wire. They previously read `arcana-code-strong`,
    /// `arcana-cheap-fast` and `arcana-default`, none of which is a model —
    /// once the connector id was corrected the provider said so outright:
    /// `Model 'arcana-code-strong' not found or is not available`. Every live
    /// run that did not pin a model with `models use` failed on this.
    ///
    /// All three now name `deepseek-v4-flash`: the only model with real traffic
    /// on this connector, the one `kb-read` pins, and genuinely priced rather
    /// than one of the catalogue's `0/0` rows — a zero there is ambiguous
    /// between free-tier, unpriced and never-computed, and picking one would
    /// set spend policy by accident.
    ///
    /// The COST TIERS ARE THEREFORE NOMINAL: `Code` is still declared expensive
    /// and `Summarize` cheap, but both resolve to the same model, so tiering
    /// changes no bill today. That is deliberate — a fabricated cheap/expensive
    /// split would look like a cost policy while being a guess. Choosing real
    /// per-tier models, or resolving them from the live catalogue as
    /// `models.rs` argues for, is a spend decision left to the operator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            code: ModelChoice {
                model_id: DEFAULT_MODEL_ID.to_owned(),
                tier: CostTier::Expensive,
            },
            summarize: ModelChoice {
                model_id: DEFAULT_MODEL_ID.to_owned(),
                tier: CostTier::Cheap,
            },
            default: ModelChoice {
                model_id: DEFAULT_MODEL_ID.to_owned(),
                tier: CostTier::Cheap,
            },
        }
    }

    /// Pin every task class to one abstract model id.
    ///
    /// This is the fail-closed policy for purpose-built loops whose approved
    /// provider/model is part of the capability contract rather than a
    /// per-turn routing decision.
    #[must_use]
    pub fn single_model(model_id: impl Into<String>) -> Self {
        let model_id = model_id.into();
        let choice = ModelChoice {
            model_id,
            tier: CostTier::Cheap,
        };
        Self {
            code: choice.clone(),
            summarize: choice.clone(),
            default: choice,
        }
    }

    /// Override the `Default`-arm model id — the former static
    /// `DriverConfig.model` becomes the policy fallback (D-REQ-03).
    #[must_use]
    pub fn with_default_model(mut self, model_id: impl Into<String>) -> Self {
        self.default.model_id = model_id.into();
        self
    }

    /// Deterministic, table-driven selection (V-AC-2). Same task → same choice.
    #[must_use]
    pub fn select(&self, task: TaskType) -> ModelChoice {
        match task {
            TaskType::Code => self.code.clone(),
            TaskType::Summarize => self.summarize.clone(),
            TaskType::Default => self.default.clone(),
        }
    }
}

impl Default for ModelPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Read-only view the classifier keys on: the driver's conversation history plus
/// the current turn index. Borrows the driver-owned `history`; performs no I/O.
pub struct SelectionContext<'a> {
    /// The ordered conversation log composed so far this run.
    pub history: &'a [HistoryEntry],
    /// The zero-based turn index this selection is for.
    pub turn: u32,
}

/// Deterministic step classification (V-AC-3), fail-closed to [`TaskType::Default`].
///
/// Rule (priority order):
///  1. a trailing [`HistoryEntry::ToolResult`] — the model's next turn interprets
///     a tool output → [`TaskType::Summarize`];
///  2. else a code-signal in the latest `Task` / `Assistant` text →
///     [`TaskType::Code`];
///  3. else (incl. empty history) → [`TaskType::Default`].
///
/// Pure and total: never panics, never performs I/O.
#[must_use]
pub fn classify(ctx: &SelectionContext) -> TaskType {
    match ctx.history.last() {
        Some(HistoryEntry::ToolResult { .. }) => TaskType::Summarize,
        Some(HistoryEntry::Task(text) | HistoryEntry::Assistant(text)) if has_code_signal(text) => {
            TaskType::Code
        }
        _ => TaskType::Default,
    }
}

/// Fixed code-signal vocabulary scanned case-insensitively by [`has_code_signal`].
const CODE_SIGNALS: &[&str] = &["code", "rust", "function", "fn ", "compile", "implement"];

/// Deterministic code-signal detector: case-insensitive substring scan over a
/// fixed vocabulary. Pure — allocates only the lowercased haystack.
fn has_code_signal(text: &str) -> bool {
    let lowered = text.to_lowercase();
    CODE_SIGNALS.iter().any(|kw| lowered.contains(kw))
}
