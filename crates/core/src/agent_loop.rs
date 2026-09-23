//! Agent loop state machine.
//!
//! The agent loop is modelled as a tagged transition: every turn either
//! emits a [`ContinueReason`] (we owe the model another roundtrip) or a
//! [`TerminalReason`] (this run is done). A sealed enum is used on
//! purpose — the driver pattern-matches `TurnOutcome` exhaustively, so
//! adding a variant is a compile-time obligation to handle it, not a
//! convention the next reader might forget.
//!
//! The [`Driver`] wires the sealed outcomes to the mature capability core —
//! [`crate::connector::ModelConnector`], [`crate::execution::CapabilityExecutor`], and
//! [`crate::cost::CostTracker`] — driving a task through
//! attempt → interpret → (tool turn | final) until a `Terminal` outcome. It
//! adds no new `Tool`/`PermissionLayer`/`ToolHook`; every collaborator is
//! consumed through its existing signature.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, FirstDispatchMeasurementV0, ModelConnector,
    UnverifiedFirstDispatchObservationV0,
};
use crate::cost::{CostSnapshot, CostTracker};
use crate::dispatch::{classify, ModelPolicy, SelectionContext};
use crate::execution::{AuditFailurePhase, CapabilityError, CapabilityExecutor};
use crate::hooks::HookContext;

/// Maximum exact first-dispatch prompt size accepted by the driver.
pub const MAX_FIRST_DISPATCH_PROMPT_BYTES: usize = 1_048_576;
/// Upstream Model Connector prompt limit, measured as JavaScript UTF-16 code units.
pub const MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS: usize = 100_000;

/// Re-dispatches allowed after a transient connector failure, per turn.
///
/// Two, because the failure this exists for is a slow turn, and Model
/// Connector has already spent its own attempts by the time the client sees
/// one: measured 2026-09-23, a `deepseek` dispatch is tried twice server-side
/// (30 s each) before the caller is told anything. A third client attempt
/// after that is a genuine second chance; a tenth is a way to spend an hour
/// and a budget on an upstream that is simply down.
pub const DEFAULT_CONNECTOR_RETRY_LIMIT: u32 = 2;

/// Pause before re-dispatching when the upstream named no `retryAfter`.
pub const DEFAULT_CONNECTOR_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Ceiling on an upstream-named `retryAfter`, so a hostile or mistaken value
/// cannot park an unattended run for hours.
///
/// Not hypothetical: measured 2026-09-23, an open circuit breaker upstream
/// answers `retryAfter: 15681` for a cooldown of 15.7 SECONDS — the value is
/// milliseconds on that path while the field is read as seconds everywhere
/// else. Without this cap a run would wait four hours on a route that heals in
/// half a minute.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Bounded prompt bytes for an explicitly measured first dispatch.
///
/// The inner text is deliberately absent from `Debug` so configuration logs
/// cannot disclose the baseline or compiled corpus payload.
#[derive(Clone, PartialEq, Eq)]
pub struct FirstDispatchPromptV0(String);

impl FirstDispatchPromptV0 {
    /// Capture a non-empty UTF-8 prompt within both model-boundary caps.
    ///
    /// # Errors
    ///
    /// Returns [`FirstDispatchPromptValidationError`] when the prompt is empty
    /// or exceeds [`MAX_FIRST_DISPATCH_PROMPT_BYTES`] or
    /// [`MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS`].
    pub fn try_new(value: String) -> Result<Self, FirstDispatchPromptValidationError> {
        if value.is_empty()
            || value.len() > MAX_FIRST_DISPATCH_PROMPT_BYTES
            || value
                .encode_utf16()
                .take(MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS + 1)
                .count()
                > MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS
        {
            return Err(FirstDispatchPromptValidationError);
        }
        Ok(Self(value))
    }

    /// Borrow the exact captured bytes as UTF-8 text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for FirstDispatchPromptV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FirstDispatchPromptV0([REDACTED])")
    }
}

/// Validation error for a first-dispatch prompt outside the closed byte cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstDispatchPromptValidationError;

impl std::fmt::Display for FirstDispatchPromptValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid first-dispatch prompt")
    }
}

impl std::error::Error for FirstDispatchPromptValidationError {}

/// Reasons a turn yields control back to the driver for another LLM call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContinueReason {
    /// Tool dispatch completed; feed results back to the model.
    ToolResultsReady,
    /// Response was truncated by `max_output_tokens`; continue from cursor.
    MaxOutputTokensRecovery,
    /// Context overflowed; compaction ran, retry with the compacted history.
    ReactiveCompactRetry,
    /// Streaming stalled; the buffer was drained and we retry.
    CollapseDrainRetry,
    /// A post-tool hook injected additional context that needs another pass.
    HookContinuation,
    /// A microcompact pass completed inline; proceed with the trimmed window.
    MicrocompactCompleted,
    /// The model answered without calling a tool while the run requires an
    /// action. It has been told once that nothing was executed and asked to
    /// act; this buys it exactly one more dispatch.
    NoActionRetry,
    /// The connector attempt failed in a way that says nothing about the
    /// request — a timeout, a gateway status, or an envelope the upstream
    /// itself marked retryable. The turn is re-dispatched, bounded by
    /// [`DriverConfig::connector_retry_limit`] and paid for out of the same
    /// `--max-turns` and cost budget as any other attempt.
    ConnectorRetry,
    /// The permission cascade refused the call at a layer whose refusal is a
    /// correctable mistake in the call itself (a schema violation, an unknown
    /// tool name, a path outside the workspace). The reason was handed back as
    /// a tool result so the model can correct it; nothing was executed.
    ToolCallRejected,
}

/// Cascade layers whose refusal is a defect in the model's own tool call, and
/// is therefore handed back to it as a tool result instead of ending the run.
///
/// The discriminator is not severity, it is **agency**: does a corrected call
/// exist that the model could write on its next turn, and does naming the
/// violated constraint tell it anything it should not have?
///
/// | layer | produced by | folded back | why |
/// |---|---|---|---|
/// | `schema` | [`crate::execution::CapabilityExecutor::prepare`] and `SchemaLayer` | yes | The arguments did not match the tool's published JSON schema. The schema is already in the model's tool list, so the reason discloses nothing new, and the corrected call is a one-token edit. |
/// | `registry` | `CapabilityExecutor::prepare`, unknown tool | yes | The model named a tool that does not exist. Same disclosure argument: the tool list is already in its prompt. |
/// | `workspace_boundary` | `arcana-cli`'s workspace policy, path half | yes | "that path is outside the working directory" names a directory the model was given as its cwd. The correct recovery — work inside — is the behaviour we want, and cannot be reached by a model that is never told. |
/// | `destructive_command_floor` | `arcana-cli`'s workspace policy, command half | **no** | A closed list of refused commands (`sudo`, `dd`, `git push --force`, …). Naming the refused word to a model that wants the effect invites a hunt for a synonym the list does not carry, which is a bypass of a safety control conducted through our own error message. |
/// | `hook_bridge` | an operator-installed pre-tool hook | **no** | A considered refusal by operator-owned code. It is policy, not a typo. |
/// | `rule` | the operator's `permissions.toml` | **no** | Same: the operator wrote this rule down. A model arguing with it is not recovery. |
/// | `interactive_auto` | `ARCANA_PERMISSION_AUTO=deny`, or no terminal to ask at | **no** | This layer's answer does not depend on the call. Every retry gets the same denial, so folding back buys nothing and spends the operator's money to prove it. |
/// | `workspace_auto_allow` | allow-only half of the workspace policy | **no** | Cannot deny; listed so the table covers the shipped cascade. |
/// | `cascade` | the fail-closed tail: no layer allowed | **no** | Nothing about the call was wrong; nothing about it was authorized either. There is no corrected form. |
/// | `hook` | audited name for a pre-tool hook abort | **no** | Reaches the loop as [`CapabilityError::HookAborted`], never as a denial; listed for completeness. |
///
/// Anything not on this list is terminal. The default is the safe one on
/// purpose: a layer added later — by this crate or by a downstream cascade —
/// is treated as a policy refusal until somebody decides otherwise, rather
/// than becoming recoverable by omission.
const RECOVERABLE_DENIAL_LAYERS: [&str; 3] = ["schema", "registry", "workspace_boundary"];

/// Consecutive folded-back denials a run may accumulate before it ends on
/// [`TerminalReason::PermissionDenied`].
///
/// The counter resets on any tool call that actually executes, so this bounds
/// a model hammering one wall, not a long run that makes occasional mistakes.
/// Without it, "fold the denial back" would be an unbounded retry against a
/// refusal that never changes, paid for one dispatch at a time up to
/// `max_turns`.
///
/// It is executed work that clears the streak, and nothing else — in particular
/// **not** a [`ContinueReason::ConnectorRetry`] in the middle of it. The two
/// budgets are independent: `RunState::connector_retries` asks "is the upstream
/// answering", this asks "is the model writing callable calls", and a run that
/// is failing at both must still stop. The reverse direction is deliberately
/// not symmetric: any reply resets the retry budget, including a reply the
/// cascade then refused, because a refused call is still proof the upstream is
/// up. Pinned by `crates/core/tests/driver_retry_denial_independence.rs`.
pub const MAX_CONSECUTIVE_DENIALS: u32 = 3;

/// Whether a cascade denial at `layer` is handed back to the model.
///
/// See [`RECOVERABLE_DENIAL_LAYERS`] for the per-layer justification. Unknown
/// layers are terminal.
#[must_use]
pub fn denial_is_recoverable(layer: &str) -> bool {
    RECOVERABLE_DENIAL_LAYERS.contains(&layer)
}

/// Reasons a turn terminates the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalReason {
    /// Model emitted a final response without tool calls.
    Completed,
    /// Hit the operator's `--max-turns` cap.
    MaxTurns,
    /// Hit the operator's `--max-cost` cap (cost circuit breaker).
    MaxCostUsd,
    /// Operator-side abort (Ctrl-C / SIGINT).
    AbortedByOperator,
    /// A pre-tool hook returned a stop signal.
    AbortedByHook,
    /// Permission cascade refused the call; no recovery path.
    PermissionDenied,
    /// Even after compaction the request exceeded the model context window.
    ContextWindowExhausted,
    /// Upstream connector returned a non-recoverable error.
    ConnectorFatal,
    /// Mandatory capability audit failed; executor is latched closed.
    AuditFatal,
    /// The run required an action and the model never executed a tool call.
    ///
    /// Distinct from [`Self::Completed`] on purpose. A model asked to create a
    /// file answered `The file has been created successfully.` in one turn,
    /// called nothing, and the run reported success and exited `0` — a receipt
    /// for work that no tool ever did. Only [`DriverConfig::require_action`]
    /// runs can end here; an interactive turn is allowed to be a conversation.
    NoAction,
}

impl TerminalReason {
    /// One sentence a paying customer can act on.
    ///
    /// The three CLI print sites used to format this enum with `{:?}`, so the
    /// operator was shown `ConnectorFatal` and `ContextWindowExhausted`
    /// verbatim. A variant name is an implementation detail; it is fine as a
    /// trailing parenthetical for support, but it cannot be the whole message.
    #[must_use]
    pub const fn explain(&self) -> &'static str {
        match self {
            Self::Completed => "the run completed",
            Self::MaxTurns => "stopped at the turn limit",
            Self::MaxCostUsd => "stopped at the cost limit",
            Self::AbortedByOperator => "aborted by the operator",
            Self::AbortedByHook => "stopped by a hook",
            Self::PermissionDenied => "the permission cascade refused the tool call",
            Self::ContextWindowExhausted => {
                "the input is longer than the model's context window; shorten it, \
                 or choose a model with a larger window"
            }
            Self::ConnectorFatal => "the Model Connector could not complete the request",
            Self::AuditFatal => "the capability audit failed and the executor is latched closed",
            Self::NoAction => {
                "the model answered without running a single tool, so nothing was done"
            }
        }
    }

    /// True when the run reached its intended end.
    ///
    /// Callers turn this into a process exit code, so it lives beside
    /// [`Self::explain`] rather than being re-derived as `!= Completed` at each
    /// site — the interactive session and `demo` disagreed on exactly that
    /// comparison, and the session reported success on a run where every turn
    /// had failed.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl std::fmt::Display for TerminalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.explain())
    }
}

/// Tagged outcome of a single turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TurnOutcome {
    Continue(ContinueReason),
    Terminal(TerminalReason),
}

impl TurnOutcome {
    /// True when this turn ends the run.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal(_))
    }

    /// True when another turn should be scheduled.
    #[must_use]
    pub const fn is_continue(&self) -> bool {
        matches!(self, Self::Continue(_))
    }
}

// ---------------------------------------------------------------------------
// Turn-interpretation seam (D-REQ-06 / V-AC-5)
// ---------------------------------------------------------------------------

/// Deterministic classification of a connector response into the driver's
/// next action.
///
/// The Phase-1 connector returns a bare text `result: String` — there is no
/// structured tool-call channel on the wire — so the driver owns this small
/// seam that maps a response to *either* an intended tool call *or* a final
/// answer. It is pure and side-effect free; the encoding it parses is a
/// driver-owned convention (see [`interpret`]) that can be swapped for a
/// structured wire schema later without touching the loop.
///
/// `input` is a [`serde_json::Value`], which is not [`Eq`] (it may carry an
/// `f64`), so this type derives only [`PartialEq`].
#[derive(Debug, Clone, PartialEq)]
pub enum AssistantAction {
    /// The model asked to call `name` with `input`.
    ToolCall { name: String, input: Value },
    /// The model produced a final answer; `text` is the whole response.
    Final { text: String },
}

/// Fence that opens a tool-call block inside a bare text response.
const TOOL_CALL_FENCE: &str = "```tool_call";
/// Generic Markdown code fence — closes the tool-call block.
const CODE_FENCE: &str = "```";

/// Classify a [`ConnectorResponse`] into an [`AssistantAction`] (D-REQ-06).
///
/// Convention: a single fenced block tagged `tool_call` whose body parses as
/// `{"name": <string>, "input": <json>}` is an intended tool call. Anything
/// else — no block, malformed JSON, a missing `name` — **fails closed** to
/// [`AssistantAction::Final`], never to an unchecked dispatch. The tool call,
/// when present, is still subjected to the full permission cascade downstream;
/// this seam only classifies, it never executes.
#[must_use]
pub fn interpret(resp: &ConnectorResponse) -> AssistantAction {
    parse_tool_call(&resp.result).unwrap_or_else(|| AssistantAction::Final {
        text: resp.result.clone(),
    })
}

/// Attempt to extract a `tool_call` block; `None` on any anomaly (fail-closed).
fn parse_tool_call(result: &str) -> Option<AssistantAction> {
    let after_fence = result.find(TOOL_CALL_FENCE)? + TOOL_CALL_FENCE.len();
    let rest = result.get(after_fence..)?;
    let close = rest.find(CODE_FENCE)?;
    let body = rest.get(..close)?.trim();
    let value: Value = serde_json::from_str(body).ok()?;
    let name = value.get("name")?.as_str()?.to_owned();
    let input = value.get("input").cloned().unwrap_or(Value::Null);
    Some(AssistantAction::ToolCall { name, input })
}

// ---------------------------------------------------------------------------
// Conversation history (D-REQ-03)
// ---------------------------------------------------------------------------

/// One entry in the ordered conversation log that composes each next request.
///
/// [`HistoryEntry::Task`] carries the initial task framing and is **never**
/// trimmed by the context guard; [`HistoryEntry::ToolResult`] payloads are the
/// only compaction target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryEntry {
    /// The initial task / system framing (never trimmed).
    Task(String),
    /// The model's raw `result` text for a turn.
    Assistant(String),
    /// An intended tool call; `input` is compact JSON.
    ToolCall { name: String, input: String },
    /// A tool's output — the trimmable compaction target.
    ToolResult { name: String, content: String },
    /// A post-tool hook `InjectContext` line folded into the next turn.
    Injected(String),
}

/// Serialize the history into the connector prompt string (also the size
/// measure used by the context guard, so guard and prompt agree byte-for-byte).
fn serialize_history(history: &[HistoryEntry]) -> String {
    let mut out = String::new();
    for entry in history {
        match entry {
            HistoryEntry::Task(text) => {
                out.push_str("[task] ");
                out.push_str(text);
            }
            HistoryEntry::Assistant(text) => {
                out.push_str("[assistant] ");
                out.push_str(text);
            }
            HistoryEntry::ToolCall { name, input } => {
                out.push_str("[tool_call] ");
                out.push_str(name);
                out.push(' ');
                out.push_str(input);
            }
            HistoryEntry::ToolResult { name, content } => {
                out.push_str("[tool_result] ");
                out.push_str(name);
                out.push(' ');
                out.push_str(content);
            }
            HistoryEntry::Injected(text) => {
                out.push_str("[injected] ");
                out.push_str(text);
            }
        }
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Context-window guard (D-REQ-04 / V-AC-4)
// ---------------------------------------------------------------------------

/// Verdict of the context-window guard. Public so the V-AC-4 test can assert
/// the compaction classification directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextVerdict {
    /// History is within budget; no compaction needed.
    Ok,
    /// A single oldest tool-result was trimmed and history now fits.
    Microcompacted,
    /// More than one tool-result was trimmed to fit.
    ReactiveCompacted,
    /// History still overflows with no tool-result left to trim.
    Irreducible,
}

/// Trim oldest [`HistoryEntry::ToolResult`] payloads until `history` serializes
/// within `budget` chars, and report the classification (D-REQ-04). The
/// [`HistoryEntry::Task`] framing is never removed.
#[must_use]
pub fn guard_context(history: &mut Vec<HistoryEntry>, budget: usize) -> ContextVerdict {
    if serialize_history(history).len() <= budget {
        return ContextVerdict::Ok;
    }
    let mut trimmed: usize = 0;
    while serialize_history(history).len() > budget {
        match history
            .iter()
            .position(|entry| matches!(entry, HistoryEntry::ToolResult { .. }))
        {
            Some(index) => {
                history.remove(index);
                trimmed = trimmed.saturating_add(1);
            }
            None => return ContextVerdict::Irreducible,
        }
    }
    match trimmed {
        0 => ContextVerdict::Ok,
        1 => ContextVerdict::Microcompacted,
        _ => ContextVerdict::ReactiveCompacted,
    }
}

/// Map a compaction verdict to the `Continue` reason the driver emits for it.
/// `Ok`/`Irreducible` are not compaction re-loops and map to `None`.
#[must_use]
pub const fn compaction_continue(verdict: ContextVerdict) -> Option<ContinueReason> {
    match verdict {
        ContextVerdict::Microcompacted => Some(ContinueReason::MicrocompactCompleted),
        ContextVerdict::ReactiveCompacted => Some(ContinueReason::ReactiveCompactRetry),
        ContextVerdict::Ok | ContextVerdict::Irreducible => None,
    }
}

// ---------------------------------------------------------------------------
// Driver (D-REQ-01/02/05/07)
// ---------------------------------------------------------------------------

/// Immutable driver configuration.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// `ExecuteRequest.connector` id, e.g. `"claude-code"`.
    pub connector_id: String,
    /// Optional model override passed to the connector.
    pub model: Option<String>,
    /// Optional system prompt passed to the connector.
    pub system_prompt: Option<String>,
    /// Hard connector-attempt cap → [`TerminalReason::MaxTurns`].
    pub max_turns: u32,
    /// Optional cost cap (USD) → [`TerminalReason::MaxCostUsd`].
    pub max_cost_usd: Option<f64>,
    /// Serialized-history ceiling (chars) → compaction / `ContextWindowExhausted`.
    pub context_budget_chars: usize,
    /// Opt-in paired-corpus metadata. The driver attaches it only to the first
    /// connector attempt; later tool-loop turns never inherit it.
    pub first_dispatch_measurement: Option<FirstDispatchMeasurementV0>,
    /// Exact prompt override applied only to the measured first connector
    /// attempt. It is invalid without `first_dispatch_measurement`.
    pub first_dispatch_prompt: Option<FirstDispatchPromptV0>,
    /// Per-turn model-selection policy (D-REQ-01). The classifier keys a
    /// [`crate::dispatch::TaskType`] off the turn context and the policy maps it
    /// to the model id written onto `ExecuteRequest.model`. The former static
    /// `model` above seeds this policy's `Default` fallback in [`Driver::new`].
    pub policy: ModelPolicy,
    /// Require at least one executed tool call before the run may be called
    /// completed.
    ///
    /// Off by default: an interactive turn may legitimately be a question
    /// answered in prose. Headless runs set it, because there nobody reads the
    /// prose and the only thing downstream sees is the exit code.
    pub require_action: bool,
    /// Consecutive transient connector failures the loop will re-dispatch
    /// before it gives up with [`TerminalReason::ConnectorFatal`].
    ///
    /// Bounded on purpose, and reset by any attempt that returns a response:
    /// an upstream that is down stays down, and burning the whole turn budget
    /// on it would replace one honest error with a slow one. Each retry
    /// consumes a turn and is checked against the cost cap like any other
    /// attempt, so neither budget can be exceeded by retrying.
    pub connector_retry_limit: u32,
    /// Pause before a re-dispatch when the upstream named no `retryAfter`.
    pub connector_retry_backoff: Duration,
}

impl DriverConfig {
    /// Config for `connector_id` with defensive defaults (8 connector
    /// attempts, no cost cap, a generous context budget). Callers tune
    /// individual fields.
    #[must_use]
    pub fn new(connector_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
            model: None,
            system_prompt: None,
            max_turns: 8,
            max_cost_usd: None,
            context_budget_chars: 1_000_000,
            first_dispatch_measurement: None,
            first_dispatch_prompt: None,
            policy: ModelPolicy::new(),
            require_action: false,
            connector_retry_limit: DEFAULT_CONNECTOR_RETRY_LIMIT,
            connector_retry_backoff: DEFAULT_CONNECTOR_RETRY_BACKOFF,
        }
    }

    /// Map an invalid budget to the existing fail-closed terminal reason that
    /// owns that budget. Validation happens before any connector attempt.
    fn invalid_reason(&self) -> Option<TerminalReason> {
        if self.max_turns == 0 {
            return Some(TerminalReason::MaxTurns);
        }
        if self
            .max_cost_usd
            .is_some_and(|cap| !cap.is_finite() || cap < 0.0)
        {
            return Some(TerminalReason::MaxCostUsd);
        }
        if self.context_budget_chars == 0 {
            return Some(TerminalReason::ContextWindowExhausted);
        }
        if self.first_dispatch_prompt.is_some() && self.first_dispatch_measurement.is_none() {
            return Some(TerminalReason::ConnectorFatal);
        }
        None
    }
}

/// Result of a completed run.
#[derive(Debug, Clone)]
pub struct RunOutput {
    /// The terminal cause the run ended on.
    pub reason: TerminalReason,
    /// The model's final text — `Some` only when `reason == Completed`.
    pub final_text: Option<String>,
    /// Number of connector attempts consumed.
    pub turns: u32,
    /// Tool calls the executor actually carried out in this run.
    ///
    /// Evidence, not intent: a call the permission cascade refused, or one the
    /// model only described in prose, is not counted. Zero here means the run
    /// changed nothing through a tool, whatever its final text claims.
    pub tool_calls: u32,
    /// Cost accounting snapshot at termination.
    pub cost: CostSnapshot,
    /// The ordered sequence of model ids selected, one per connector call
    /// (D-REQ-05). Mirrors each `ExecuteRequest.model` in call order, making the
    /// ≥2-distinct-selections property runtime-verifiable.
    pub selected_models: Vec<String>,
    /// Opaque, explicitly unverified receipt returned for the first dispatch.
    /// `PostgreSQL` remains authoritative; this value is correlation-only.
    pub first_dispatch_observation: Option<UnverifiedFirstDispatchObservationV0>,
}

/// The agent-loop driver. Borrows its collaborators; owns only run config and
/// the shared cost/cancel handles.
///
/// It adds **no new** `Tool`/`PermissionLayer`/`ToolHook` — every collaborator
/// is consumed through its existing signature (D-REQ-05 / V-AC-7).
pub struct Driver<'a> {
    connector: &'a dyn ModelConnector,
    executor: &'a CapabilityExecutor,
    cost: Arc<CostTracker>,
    cancel: CancellationToken,
    config: DriverConfig,
}

/// Internal per-step result: a `Continue` reason, or a terminal cause carrying
/// the final text (only for `Completed`).
enum StepResult {
    Continue(ContinueReason),
    Terminal(TerminalReason, Option<String>),
}

/// What the loop tells a model that answered without acting.
///
/// Phrased as a fact about the machine, not as encouragement: the model is
/// told what did NOT happen and what encoding would make it happen. An earlier
/// live transcript had the model insisting the file existed; asking it to
/// verify with a tool call gives it a way to be right that still produces
/// evidence.
const NO_ACTION_NUDGE: &str =
    "NOTHING WAS EXECUTED. Your last reply contained no tool call, so no \
command ran, no file was written, and the task is NOT done — printing a sentence is not an action. \
Reply now with exactly one fenced `tool_call` block that does the work. If you believe the task is \
already satisfied, prove it with a tool call (for example `read` the file you say you wrote) \
before you answer in prose.";

/// Mutable state threaded through every step of one run.
///
/// It exists so a new per-run fact (the executed-tool-call count, the spent
/// nudge) is added in one place rather than as another `&mut` parameter on a
/// signature that already had four.
struct RunState {
    history: Vec<HistoryEntry>,
    /// Connector attempts consumed; enforces `max_turns`.
    attempts: u32,
    /// Ordered per-step model ids.
    selected: Vec<String>,
    first_dispatch_observation: Option<UnverifiedFirstDispatchObservationV0>,
    /// Tool calls the executor actually carried out.
    tool_calls: u32,
    /// Whether the one no-action nudge has been used.
    nudge_spent: bool,
    /// Consecutive transient connector failures since the last response.
    connector_retries: u32,
    /// Folded-back denials since the last tool call that actually executed.
    consecutive_denials: u32,
}

impl RunState {
    fn new(task: &str) -> Self {
        Self {
            history: vec![HistoryEntry::Task(task.to_owned())],
            attempts: 0,
            selected: Vec::new(),
            first_dispatch_observation: None,
            tool_calls: 0,
            nudge_spent: false,
            connector_retries: 0,
            consecutive_denials: 0,
        }
    }
}

/// What the exhaustive `reduce` tells the run loop to do.
enum LoopControl {
    Reloop,
    Stop(TerminalReason),
}

impl<'a> Driver<'a> {
    /// Construct a driver over the given collaborators.
    #[must_use]
    pub fn new(
        connector: &'a dyn ModelConnector,
        executor: &'a CapabilityExecutor,
        cost: Arc<CostTracker>,
        cancel: CancellationToken,
        mut config: DriverConfig,
    ) -> Self {
        // The former static `model` becomes the policy's `Default` fallback, so a
        // caller that only sets `model` keeps its single-model behaviour on the
        // `Default` arm while task-typed turns still route to the tiered models.
        if let Some(model) = config.model.clone() {
            config.policy = config.policy.with_default_model(model);
        }
        Self {
            connector,
            executor,
            cost,
            cancel,
            config,
        }
    }

    /// Drive `task` to a terminal outcome — the single public entrypoint.
    pub async fn run(&self, task: &str) -> RunOutput {
        if let Some(reason) = self.config.invalid_reason() {
            return RunOutput {
                reason,
                final_text: None,
                turns: 0,
                tool_calls: 0,
                cost: self.cost.snapshot(),
                selected_models: Vec::new(),
                first_dispatch_observation: None,
            };
        }
        let mut state = RunState::new(task);
        loop {
            let step = self.step(&mut state).await;
            let outcome = match &step {
                StepResult::Continue(reason) => TurnOutcome::Continue(*reason),
                StepResult::Terminal(reason, _) => TurnOutcome::Terminal(*reason),
            };
            match reduce(outcome) {
                LoopControl::Reloop => {}
                LoopControl::Stop(reason) => {
                    let final_text = match step {
                        StepResult::Terminal(_, text) => text,
                        StepResult::Continue(_) => None,
                    };
                    let cost = self.cost.snapshot();
                    let reason = if reason == TerminalReason::AbortedByOperator {
                        self.record_abort(state.attempts, &state.selected, &cost)
                    } else {
                        reason
                    };
                    return RunOutput {
                        reason,
                        final_text,
                        turns: state.attempts,
                        tool_calls: state.tool_calls,
                        cost,
                        selected_models: state.selected,
                        first_dispatch_observation: state.first_dispatch_observation,
                    };
                }
            }
        }
    }

    /// Write the operator-abort record, and report whether the audit held.
    ///
    /// A Ctrl-C used to leave nothing behind at all: the dispatch had been sent
    /// and would be charged, and the only local evidence of it was a dead
    /// process. The tool-level `decision`/`result` pair cannot cover this,
    /// because an abort during the connector call has no tool to attribute to.
    ///
    /// Returns [`TerminalReason::AuditFatal`] when the append fails. An abort
    /// the operator was told about but that was never recorded is precisely the
    /// state Law-5 forbids, and the driver already treats a failed audit append
    /// as fatal everywhere else; reporting a clean abort over a broken log
    /// would make this one site the exception.
    fn record_abort(
        &self,
        attempts: u32,
        selected: &[String],
        cost: &crate::cost::CostSnapshot,
    ) -> TerminalReason {
        // Both figures are named for their scope, because they do not share
        // one. `attempts` counts connector calls in THIS run; the `CostTracker`
        // is owned by the session and shared across every run in it, so its
        // snapshot is cumulative. A field called plainly `cost_usd_micros`
        // beside a per-run turn count reads as the cost of the aborted turn —
        // measured live, an abort on the second turn of a session recorded 20
        // micro-USD next to `turns: 1` when that turn had cost 11.
        let fields = serde_json::json!({
            "reason": "aborted_by_operator",
            "run_turns": attempts,
            "run_models": selected,
            "session_cost_usd_micros": cost.total_cost_usd_micros,
        });
        match self.executor.record_run_event("run_aborted", &fields) {
            Ok(()) => TerminalReason::AbortedByOperator,
            Err(_) => TerminalReason::AuditFatal,
        }
    }

    /// One step: guards → select model → connector attempt → interpret → (tool
    /// turn | final). `attempts` is the shared connector-attempt counter that
    /// enforces `max_turns`; `selected` accumulates the ordered per-step model
    /// ids.
    async fn step(&self, state: &mut RunState) -> StepResult {
        let history = &mut state.history;
        let attempts = &mut state.attempts;
        if self.cancel.is_cancelled() {
            return StepResult::Terminal(TerminalReason::AbortedByOperator, None);
        }
        if *attempts >= self.config.max_turns {
            return StepResult::Terminal(TerminalReason::MaxTurns, None);
        }
        if self.cost.check_budget(self.config.max_cost_usd).is_err() {
            return StepResult::Terminal(TerminalReason::MaxCostUsd, None);
        }
        match guard_context(history, self.config.context_budget_chars) {
            ContextVerdict::Ok => {}
            ContextVerdict::Irreducible => {
                return StepResult::Terminal(TerminalReason::ContextWindowExhausted, None);
            }
            verdict => {
                if let Some(reason) = compaction_continue(verdict) {
                    return StepResult::Continue(reason);
                }
            }
        }
        let first_dispatch = *attempts == 0;
        let prompt = if first_dispatch {
            self.config.first_dispatch_prompt.clone().map_or_else(
                || serialize_history(history),
                FirstDispatchPromptV0::into_inner,
            )
        } else {
            serialize_history(history)
        };
        if prompt.len() > self.config.context_budget_chars {
            return StepResult::Terminal(TerminalReason::ContextWindowExhausted, None);
        }
        // Per-step multi-model dispatch (D-REQ-01/03/05): classify the step
        // context, select the model, record it, and route it through the
        // connector on `ExecuteRequest.model`. Selection keys off the current
        // connector-attempt index (`*attempts`) before that counter is consumed
        // by the `max_turns`-enforcing increment below, preserving the
        // zero-based turn index the classifier expects on the first attempt.
        let ctx = SelectionContext {
            history,
            turn: *attempts,
        };
        let choice = self.config.policy.select(classify(&ctx));
        state.selected.push(choice.model_id.clone());
        *attempts = attempts.saturating_add(1);
        let resp = match self
            .call_connector(prompt, Some(choice.model_id), first_dispatch)
            .await
        {
            Ok(resp) => {
                // A response — of any shape — means the upstream is answering
                // again, so the retry budget starts over. Counting retries
                // across a whole run would let three slow turns spread over an
                // hour end it as if the connector had failed three times in a
                // row.
                state.connector_retries = 0;
                resp
            }
            Err(error) => return self.recover_or_stop(state, &error, first_dispatch).await,
        };
        if first_dispatch {
            state
                .first_dispatch_observation
                .clone_from(&resp.first_dispatch_observation);
        }
        if self.cost.check_budget(self.config.max_cost_usd).is_err() {
            return StepResult::Terminal(TerminalReason::MaxCostUsd, None);
        }
        state
            .history
            .push(HistoryEntry::Assistant(resp.result.clone()));
        match interpret(&resp) {
            AssistantAction::Final { text } => {
                // An answer that arrived is DELIVERED even when the operator
                // interrupted: it is already paid for, and withholding it would
                // be a second harm. But the verdict still says they stopped the
                // run, so the exit code is 130 and the abort is audited. The
                // alternative — reporting a clean `Completed` — makes Ctrl-C
                // inert on the commonest shape there is, a task answered in one
                // dispatch, and tells a wrapper script the run was never
                // interrupted at all.
                if self.cancel.is_cancelled() {
                    return StepResult::Terminal(TerminalReason::AbortedByOperator, Some(text));
                }
                // A run that required an action and executed nothing did not
                // complete, whatever its prose says. Tell the model once that
                // nothing ran — measured live, most models then act — and end
                // on `NoAction` if the second answer is empty too.
                if self.config.require_action && state.tool_calls == 0 {
                    if state.nudge_spent {
                        return StepResult::Terminal(TerminalReason::NoAction, Some(text));
                    }
                    state.nudge_spent = true;
                    state
                        .history
                        .push(HistoryEntry::Injected(NO_ACTION_NUDGE.to_owned()));
                    return StepResult::Continue(ContinueReason::NoActionRetry);
                }
                StepResult::Terminal(TerminalReason::Completed, Some(text))
            }
            AssistantAction::ToolCall { name, input } => {
                // Re-check between the answer and the side effect. The
                // top-of-step check already stops the NEXT billable dispatch,
                // but a tool turn is where the run touches the world — an
                // operator who pressed Ctrl-C while the model was deciding
                // should not then watch a bash command run. The final-text
                // branch above deliberately does NOT check: that answer is
                // already paid for, and discarding it would be a second harm.
                if self.cancel.is_cancelled() {
                    return StepResult::Terminal(TerminalReason::AbortedByOperator, None);
                }
                state.history.push(HistoryEntry::ToolCall {
                    name: name.clone(),
                    input: input.to_string(),
                });
                self.run_tool_turn(state, &name, input).await
            }
        }
    }

    /// Decide what a failed connector attempt means for the run: another
    /// dispatch, or the end of it.
    ///
    /// Retrying is safe here because a `/execute` dispatch has no local side
    /// effect — the tools run on this side of the wire, and the only thing a
    /// second attempt can spend twice is money, which the cost cap already
    /// bounds. It is NOT a guarantee about the upstream: a connector that runs
    /// tools server-side could act twice on a request whose answer never
    /// arrived, which is why the retry is bounded and the upstream's own
    /// `retryable` flag is respected rather than second-guessed.
    async fn recover_or_stop(
        &self,
        state: &mut RunState,
        error: &ConnectorError,
        first_dispatch: bool,
    ) -> StepResult {
        if first_dispatch {
            state.first_dispatch_observation = error.first_dispatch_observation().cloned();
        }
        // The connector's own message is the diagnosis — `ConnectorError`
        // carries `HTTP {status}: {message}`, e.g. `HTTP 404: Connector
        // "arcana-repl" not found`. Mapping to `ConnectorFatal` without it left
        // the operator a verdict and no evidence, and cost a four-commit bisect
        // and two wrong root causes to recover what this one line says.
        // `eprintln!` rather than `tracing`: the CLI installs no subscriber, so
        // a log line here is discarded.
        eprintln!("arcana: connector dispatch failed: {error}");
        if !error.is_transient() || state.connector_retries >= self.config.connector_retry_limit {
            return StepResult::Terminal(TerminalReason::ConnectorFatal, None);
        }
        state.connector_retries = state.connector_retries.saturating_add(1);
        let wait = retry_pause(error, self.config.connector_retry_backoff);
        eprintln!(
            "arcana: retrying this turn in {}s ({} of {})",
            wait.as_secs(),
            state.connector_retries,
            self.config.connector_retry_limit
        );
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        // The next step re-checks it too, but an operator who pressed Ctrl-C
        // during the pause should not then watch another dispatch go out.
        if self.cancel.is_cancelled() {
            return StepResult::Terminal(TerminalReason::AbortedByOperator, None);
        }
        StepResult::Continue(ContinueReason::ConnectorRetry)
    }

    /// Build the request, call the connector, and record its cost.
    ///
    /// The error is returned whole rather than pre-mapped to a terminal
    /// reason: only the caller knows how many re-dispatches this turn has
    /// already had, and the decision between a retry and
    /// [`TerminalReason::ConnectorFatal`] needs both facts.
    async fn call_connector(
        &self,
        prompt: String,
        model: Option<String>,
        first_dispatch: bool,
    ) -> Result<ConnectorResponse, ConnectorError> {
        let mut req = ExecuteRequest::new(self.config.connector_id.clone(), prompt);
        req.model = model;
        req.system_prompt = self.config.system_prompt.clone();
        // `self.config.max_turns` is deliberately NOT forwarded as the wire
        // field `maxTurns`. They are two different quantities: the config value
        // caps how many connector attempts THIS loop makes, while `maxTurns` is
        // a per-request passthrough that Model Connector validates as
        // `z.number().int().min(1).max(100)` and hands to CLI connectors
        // (`claude-code --max-turns`) for one invocation. Conflating them made
        // every `arcana run --max-turns 120` die on its first dispatch with an
        // HTTP 400 before the model was ever reached — a run-level budget
        // rejected as a per-request one (A2-202).
        //
        // Nothing is substituted for it: no run-level number is a correct
        // per-request cap, the upstream work of one request stays bounded by
        // `maxBudgetUsd` below, and a caller who genuinely wants to cap an
        // upstream agentic CLI sets `max_turns` explicitly on its own request
        // (`arcana_tools::model_call`).
        req.max_budget_usd = self.remaining_cost_budget();
        if first_dispatch {
            req.first_dispatch_measurement = self.config.first_dispatch_measurement.clone();
        }
        match self.connector.execute(req).await {
            Ok(resp) => {
                // `record_llm_call` takes u32; `Usage` fields are u64 — saturate.
                let tokens_in = u32::try_from(resp.usage.input_tokens).unwrap_or(u32::MAX);
                let tokens_out = u32::try_from(resp.usage.output_tokens).unwrap_or(u32::MAX);
                self.cost
                    .record_llm_call(&resp.model, tokens_in, tokens_out, resp.usage.cost_usd);
                Ok(resp)
            }
            Err(error) => Err(error),
        }
    }

    /// Budget still available to the next connector request. The tracker uses
    /// integer micro-USD, so repeated requests cannot receive a fresh copy of
    /// the original allowance.
    #[allow(clippy::cast_precision_loss)]
    fn remaining_cost_budget(&self) -> Option<f64> {
        self.config.max_cost_usd.map(|cap| {
            let spent = self.cost.snapshot().total_cost_usd_micros as f64 / 1_000_000.0;
            (cap - spent).max(0.0)
        })
    }

    /// Decide what a cascade denial does to the run.
    ///
    /// A denial used to be terminal at every layer, including `schema` — which
    /// only ever means the arguments did not match the tool's published JSON
    /// schema. Measured on 2026-09-23 with `deepseek-flash`: turn 1 called
    /// `bash` with arguments the schema rejected, the run ended on
    /// `PermissionDenied` with `tool_calls: 0` and `rc 1`, and the model was
    /// never told what was wrong, so it had no way to be right. The doc comment
    /// on [`Self::run_tool_turn`] already promised that a dispatch error folds
    /// back as a recoverable tool result; a malformed call is the same kind of
    /// mistake and now follows the same rule.
    ///
    /// Two bounds keep that from becoming an unbounded retry against a wall:
    /// only [`RECOVERABLE_DENIAL_LAYERS`] fold back at all, and a run may
    /// accumulate at most [`MAX_CONSECUTIVE_DENIALS`] of them in a row.
    ///
    /// Nothing executed either way: `tool_calls` is not incremented here, so a
    /// run whose every call was refused still reports zero work done.
    fn fold_denial(
        state: &mut RunState,
        name: &str,
        layer: &'static str,
        reason: &str,
    ) -> StepResult {
        if !denial_is_recoverable(layer) {
            return StepResult::Terminal(TerminalReason::PermissionDenied, None);
        }
        state.consecutive_denials = state.consecutive_denials.saturating_add(1);
        if state.consecutive_denials >= MAX_CONSECUTIVE_DENIALS {
            return StepResult::Terminal(TerminalReason::PermissionDenied, None);
        }
        let remaining = MAX_CONSECUTIVE_DENIALS - state.consecutive_denials;
        // Phrased as a fact about the machine, like `NO_ACTION_NUDGE`: what did
        // not happen, why, and how many attempts are left. The budget is stated
        // because a model that does not know it is on a counter cannot choose
        // to spend its last attempt on a different approach.
        state.history.push(HistoryEntry::ToolResult {
            name: name.to_owned(),
            content: format!(
                "REJECTED at the {layer} layer — the call was NOT executed and nothing happened: \
{reason}. Fix the call itself and send exactly one corrected `tool_call` block. \
{remaining} rejected call(s) remain before this run is stopped."
            ),
        });
        StepResult::Continue(ContinueReason::ToolCallRejected)
    }

    /// Reuse-only tool turn: cascade → `pre_tool` → dispatch → `post_tool`, folding
    /// results into `history`. A dispatch error folds back as a tool-result
    /// string (recoverable, bounded by `max_turns`) rather than terminating,
    /// and so does a denial at one of the [`RECOVERABLE_DENIAL_LAYERS`].
    async fn run_tool_turn(&self, state: &mut RunState, name: &str, input: Value) -> StepResult {
        let ctx = HookContext::new(self.cancel.clone(), self.cost.clone());
        let capability = match self.executor.execute(&ctx, name, input).await {
            Ok(capability) => capability,
            Err(CapabilityError::Denied { layer, reason }) => {
                return Self::fold_denial(state, name, layer, &reason);
            }
            Err(CapabilityError::HookAborted) => {
                return StepResult::Terminal(TerminalReason::AbortedByHook, None);
            }
            Err(
                CapabilityError::AuditFailure {
                    phase: AuditFailurePhase::Decision | AuditFailurePhase::Result,
                    ..
                }
                | CapabilityError::AuditLatched,
            ) => {
                return StepResult::Terminal(TerminalReason::AuditFatal, None);
            }
            Err(CapabilityError::Tool(err)) => {
                state.history.push(HistoryEntry::ToolResult {
                    name: name.to_owned(),
                    content: format!("dispatch error: {err}"),
                });
                return StepResult::Continue(ContinueReason::ToolResultsReady);
            }
        };
        // Counted here and nowhere else: the executor returned, so the tool
        // ran. A denied or hook-aborted call left through an arm above, and a
        // dispatch error folds back as a tool result without reaching this
        // line, because a tool that failed to dispatch did no work either.
        state.tool_calls = state.tool_calls.saturating_add(1);
        // The streak counts consecutive refusals, so a call that ran clears it.
        // Otherwise a long, mostly-healthy run would accumulate three scattered
        // typos over twenty turns and die on the third.
        state.consecutive_denials = 0;
        state.history.push(HistoryEntry::ToolResult {
            name: name.to_owned(),
            content: capability.output.content,
        });
        let injected_context = !capability.injected.is_empty();
        for line in capability.injected {
            state.history.push(HistoryEntry::Injected(line));
        }
        if injected_context {
            StepResult::Continue(ContinueReason::HookContinuation)
        } else {
            StepResult::Continue(ContinueReason::ToolResultsReady)
        }
    }
}

/// How long to wait before re-dispatching a transient failure.
///
/// An upstream that named a `retryAfter` knows better than we do — up to
/// [`MAX_RETRY_AFTER`], past which an unattended run would be parked for
/// longer than any operator expects a single turn to take.
fn retry_pause(error: &ConnectorError, fallback: Duration) -> Duration {
    error.retry_after_secs().map_or(fallback, |secs| {
        Duration::from_secs(secs).min(MAX_RETRY_AFTER)
    })
}

/// Exhaustive reduction of a [`TurnOutcome`] to a loop directive.
///
/// Delegates to per-branch matchers so that adding a `ContinueReason` or a
/// `TerminalReason` variant is a compile error the driver must resolve
/// (D-REQ-02).
fn reduce(outcome: TurnOutcome) -> LoopControl {
    match outcome {
        TurnOutcome::Continue(reason) => reduce_continue(reason),
        TurnOutcome::Terminal(reason) => reduce_terminal(reason),
    }
}

/// Exhaustive over all 9 `ContinueReason` variants.
fn reduce_continue(reason: ContinueReason) -> LoopControl {
    match reason {
        ContinueReason::ToolResultsReady
        | ContinueReason::HookContinuation
        | ContinueReason::ReactiveCompactRetry
        | ContinueReason::MicrocompactCompleted
        | ContinueReason::NoActionRetry
        | ContinueReason::ConnectorRetry
        | ContinueReason::ToolCallRejected => LoopControl::Reloop,
        // Inert under the unary Phase-C connector (no streaming, no token
        // cursor): a documented no-op re-loop — never
        // `unreachable!`/`panic!` (clippy `panic = warn` under `-D warnings`).
        ContinueReason::MaxOutputTokensRecovery | ContinueReason::CollapseDrainRetry => {
            tracing::debug!(
                ?reason,
                "inert streaming Continue variant under unary connector; no-op re-loop"
            );
            LoopControl::Reloop
        }
    }
}

/// Exhaustive over all 10 `TerminalReason` variants.
fn reduce_terminal(reason: TerminalReason) -> LoopControl {
    match reason {
        TerminalReason::Completed
        | TerminalReason::MaxTurns
        | TerminalReason::MaxCostUsd
        | TerminalReason::AbortedByOperator
        | TerminalReason::AbortedByHook
        | TerminalReason::PermissionDenied
        | TerminalReason::ContextWindowExhausted
        | TerminalReason::ConnectorFatal
        | TerminalReason::AuditFatal
        | TerminalReason::NoAction => LoopControl::Stop(reason),
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod terminal_reason_tests {
    use super::TerminalReason;

    /// Every variant, so a new one cannot be added without deciding what the
    /// operator is told when it fires.
    const ALL: [TerminalReason; 10] = [
        TerminalReason::Completed,
        TerminalReason::MaxTurns,
        TerminalReason::MaxCostUsd,
        TerminalReason::AbortedByOperator,
        TerminalReason::AbortedByHook,
        TerminalReason::PermissionDenied,
        TerminalReason::ContextWindowExhausted,
        TerminalReason::ConnectorFatal,
        TerminalReason::AuditFatal,
        TerminalReason::NoAction,
    ];

    #[test]
    fn every_variant_explains_itself_in_prose() {
        for reason in ALL {
            let explained = reason.explain();
            assert!(!explained.is_empty(), "{reason:?} has no explanation");
            // The whole defect was showing the variant name instead of a
            // sentence, so the sentence must not merely BE the variant name.
            assert_ne!(
                explained,
                format!("{reason:?}"),
                "{reason:?} explains itself with its own variant name"
            );
            assert!(
                explained.chars().any(char::is_whitespace),
                "{reason:?} explains itself with a single word: {explained}"
            );
        }
    }

    #[test]
    fn explanations_are_distinct() {
        for (index, reason) in ALL.iter().enumerate() {
            for other in &ALL[index + 1..] {
                assert_ne!(
                    reason.explain(),
                    other.explain(),
                    "{reason:?} and {other:?} share an explanation"
                );
            }
        }
    }

    #[test]
    fn display_matches_explain() {
        for reason in ALL {
            assert_eq!(reason.to_string(), reason.explain());
        }
    }

    #[test]
    fn completed_is_the_only_success() {
        for reason in ALL {
            assert_eq!(
                reason.is_success(),
                matches!(reason, TerminalReason::Completed),
                "{reason:?} disagrees about success"
            );
        }
    }

    #[test]
    fn the_context_window_verdict_tells_the_user_what_to_do() {
        // Measured: a 1 MB prompt is rejected locally in 35 ms with no network
        // call, which is the right decision — but the operator was shown only
        // `ContextWindowExhausted` and no way to act on it.
        let explained = TerminalReason::ContextWindowExhausted.explain();
        assert!(explained.contains("context window"), "{explained}");
        assert!(explained.contains("shorten"), "{explained}");
    }
}
