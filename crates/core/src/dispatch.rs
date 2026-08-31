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

/// Cheap-tier model for the built-in policy.
///
/// A real catalogue entry, not an abstract tier name: `DriverConfig::policy`
/// ids go to the Model Connector verbatim. 0.14/0.28 USD per million
/// tokens, and the
/// model the overwhelming majority of live traffic already uses.
const CHEAP_MODEL_ID: &str = "deepseek-v4-flash";

/// Expensive-tier model for the built-in policy.
///
/// 3.00/15.00 USD per million tokens — about 21x the cheap tier on input,
/// so
/// `CostTier::Expensive` states a fact about the bill rather than a label.
///
/// Deliberately DISTINCT from the cheap id: `capstone_vertical_prototype`
/// asserts that a Code turn and a Summarize turn resolve to different models,
/// which is how tiered dispatch is proven to route at all. Both ids are also
/// priced in `model_catalog`, so neither tier meters as `unpriced` — routing
/// default traffic through an unpriced model would re-open the revenue leak
/// CONN-0271 was opened to close.
///
/// Note the name: `grok-3` (without the suffix) dispatches but is absent from
/// the provider listing, so its catalogue row has no price. The suffixed
/// variants are the ones the provider actually publishes.
const EXPENSIVE_MODEL_ID: &str = "grok-3-latest";

impl ModelPolicy {
    /// Built-in default table: distinct ids and distinct tiers for the two
    /// exercised task-types (`Code` → expensive, `Summarize` → cheap).
    ///
    /// These ids previously read `arcana-code-strong`, `arcana-cheap-fast` and
    /// `arcana-default`. None is a model, and once the connector ids were
    /// corrected the provider said so outright — `Model 'arcana-code-strong'
    /// not found or is not available` — so every live run that did not pin a
    /// model with `models use` failed here.
    #[must_use]
    pub fn new() -> Self {
        Self {
            code: ModelChoice {
                model_id: EXPENSIVE_MODEL_ID.to_owned(),
                tier: CostTier::Expensive,
            },
            summarize: ModelChoice {
                model_id: CHEAP_MODEL_ID.to_owned(),
                tier: CostTier::Cheap,
            },
            default: ModelChoice {
                model_id: CHEAP_MODEL_ID.to_owned(),
                tier: CostTier::Cheap,
            },
        }
    }

    /// Every model id this policy can dispatch to, in tier order, deduplicated.
    ///
    /// Exposed so a catalogue listing can guarantee the models the agent will
    /// actually route to are visible. Deriving them from the policy rather than
    /// restating the ids at the call site is the point: a hard-coded copy in the
    /// CLI would silently drift the first time this table changed, which is
    /// exactly how the listing came to omit both of them.
    #[must_use]
    pub fn routed_model_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = Vec::new();
        for choice in [&self.code, &self.summarize, &self.default] {
            if !ids.contains(&choice.model_id.as_str()) {
                ids.push(choice.model_id.as_str());
            }
        }
        ids
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
