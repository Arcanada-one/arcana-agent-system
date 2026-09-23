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
use crate::prompt_budget::{
    self, DEFAULT_CONTEXT_BUDGET_UTF16_UNITS, DEFAULT_TOOL_RESULT_BUDGET_UTF16_UNITS,
    MC_FIELD_MAX_UTF16_UNITS,
};
use crate::tool_dialect::{self, DialectMatch};

/// Maximum exact first-dispatch prompt size accepted by the driver.
pub const MAX_FIRST_DISPATCH_PROMPT_BYTES: usize = 1_048_576;
/// Upstream Model Connector prompt limit, measured as JavaScript UTF-16 code units.
///
/// The same wall every dispatch of this loop is held to; it lives in
/// [`crate::prompt_budget`] with the live probes that established it, and is
/// re-exported here under the name the first-dispatch path already used.
pub const MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS: usize = MC_FIELD_MAX_UTF16_UNITS;

/// Re-dispatches allowed after a transient connector failure, per turn.
///
/// Two, because the failure this exists for is a slow turn, and Model
/// Connector has already spent its own attempts by the time the client sees
/// one: measured 2026-09-23, a `deepseek` dispatch is tried twice server-side
/// (30 s each) before the caller is told anything. A third client attempt
/// after that is a genuine second chance; a tenth is a way to spend an hour
/// and a budget on an upstream that is simply down.
pub const DEFAULT_CONNECTOR_RETRY_LIMIT: u32 = 2;

/// Pause before re-dispatching when the upstream named no `retryAfter`, and
/// the first step of the gateway schedule below.
pub const DEFAULT_CONNECTOR_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Re-dispatches allowed after a transient GATEWAY failure, per turn.
///
/// Five, against two for the failures Model Connector itself reports, because
/// the two classes fail for different reasons and heal on different clocks —
/// see [`ConnectorError::is_edge_gateway_failure`]. Measured on pilot A2-204c5
/// (2026-09-23): a 94-turn run with the work already done — the test written,
/// four mutants run — died on **three** consecutive `HTTP 502 … error code:
/// 502` from `connector.arcanada.ai`, 16 bytes of Cloudflare, spread over
/// about four seconds because the policy was two retries two seconds apart.
/// Four seconds is not a serious attempt to outlast an edge.
///
/// The schedule below is what makes five affordable: the run now spends about
/// a minute finding out, instead of four seconds.
pub const DEFAULT_EDGE_RETRY_LIMIT: u32 = 5;

/// Ceiling on one pause of the gateway backoff schedule.
///
/// The schedule doubles, so without a ceiling the fifth pause would be 32 s
/// and a sixth — if the limit is ever raised — 64 s, which is longer than most
/// edges take to heal and longer than an operator expects one turn to stall.
const MAX_EDGE_RETRY_PAUSE: Duration = Duration::from_secs(30);

/// Total time one turn may spend ASLEEP between re-dispatches, across every
/// retry class.
///
/// A per-pause cap bounds one wait; this bounds the sum, which is the number
/// an unattended run's operator actually cares about. It binds hardest on the
/// path the per-pause cap cannot reach: an upstream-named `retryAfter` is
/// honoured up to [`MAX_RETRY_AFTER`] (60 s) each, so five of them would park
/// a turn for five minutes. Two are as long as this budget allows.
///
/// The default gateway schedule does NOT reach it: 2 + 4 + 8 + 16 + 30 = 60 s
/// nominal, and jitter only ever shortens a pause (see
/// [`edge_backoff_pause`]), so the worst case added wall time for five
/// gateway re-dispatches is 60 s of sleep on top of the five dispatches
/// themselves. The budget is the backstop for the schedules this file does
/// not control.
pub const DEFAULT_CONNECTOR_RETRY_PAUSE_BUDGET: Duration = Duration::from_secs(120);

/// Consecutive re-dispatches allowed after a reply that the model's output
/// limit cut off, per run.
///
/// One. The re-dispatch carries an instruction to work in smaller pieces, so
/// it is a genuinely different request rather than the same one sent twice;
/// but a model that is cut off again immediately after being told why is not
/// going to split the work on the third ask either, and every attempt costs a
/// turn and real money. The counter resets on any reply that parses, because a
/// long run may legitimately hit the limit twice an hour apart — only
/// back-to-back cut-offs mean the model cannot do what was asked.
const TRUNCATION_RETRY_LIMIT: u32 = 1;

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
    /// The reply ran out of output tokens part-way through a `tool_call`
    /// block. Nothing was executed and the fragment was discarded; the turn is
    /// re-dispatched once with an instruction to do the work in smaller
    /// pieces, bounded by [`TRUNCATION_RETRY_LIMIT`] and paid for out of the
    /// same `--max-turns` and cost budget as any other attempt.
    ///
    /// The variant predates the behaviour: it was reserved for a streaming
    /// connector that could resume from a token cursor, and sat inert under
    /// the unary connector while the case it names — a reply cut off by the
    /// output limit — was silently classified as an answer. It is the same
    /// event, so it keeps the name rather than gaining a twin.
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
    /// The reply carried a recognisable tool-call attempt this runner cannot
    /// execute as written — a native markup, a bare JSON object, a canonical
    /// block whose body is not a usable call. The expected format was named
    /// back to the model, bounded by [`MAX_DIALECT_CORRECTIONS`]; nothing was
    /// executed, and the attempt is explicitly NOT a final answer.
    ToolCallFormatRejected,
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

/// Times one distinct tool call may be refused at a correctable layer before
/// the run ends on [`TerminalReason::PermissionDenied`].
///
/// One. A refusal at a correctable layer is a fact the model did not have when
/// it wrote the call, and it is told exactly what the fact is; sending the same
/// call again is the one thing that proves the fold-back is not working.
///
/// This replaced a flat cap of three *consecutive* refusals of any kind
/// (A2-225). The cap was the wrong shape twice over. It ended runs over
/// correctable mistakes — pilot A2-204c4 died on its 31st turn having done
/// twenty tool calls of real work, because three refusals happened to land in
/// a row — while a model alternating between two different bad calls was never
/// caught by it at all. Distinct mistakes are now bounded by `max_turns` and
/// the cost cap, like every other way a run can spend money; a repeat is
/// terminal immediately, and says so.
///
/// The memory is cleared by executed work and nothing else — in particular
/// **not** by a [`ContinueReason::ConnectorRetry`] in the middle of it. The two
/// budgets are independent: `RunState::connector_retries` asks "is the upstream
/// answering", this asks "is the model writing callable calls", and a run that
/// is failing at both must still stop. The reverse direction is deliberately
/// not symmetric: any reply resets the retry budget, including a reply the
/// cascade then refused, because a refused call is still proof the upstream is
/// up. Pinned by `crates/core/tests/driver_retry_denial_independence.rs`.
///
/// Until A2-230 this constant was documentation and nothing else: the rule was
/// carried by a `HashSet::insert` in `fold_denial`, which can only ever mean
/// "one", so editing the number here changed no behaviour and broke no test —
/// the worst kind of comment, one that reads like a knob. `RunState` now
/// counts refusals per distinct call and this is the bound it is checked
/// against, which is what makes
/// `re_sending_an_already_refused_call_ends_the_run_and_says_why` go red if
/// the number moves.
pub const MAX_DENIALS_PER_DISTINCT_CALL: u32 = 1;

/// Replies in an unexecutable tool-call format a run tolerates before it ends
/// on [`TerminalReason::UnsupportedToolCallFormat`].
///
/// Two, so the model gets exactly one correction — one fewer than
/// a schema refusal's allowance, and on purpose. A schema denial tells the model
/// something it could not have known before it called; the wire format is
/// already stated verbatim in the system prompt, and the correction states it
/// again with the offending reply in view. A model that ignores it twice is
/// not going to read it the third time, and each attempt is a paid dispatch.
///
/// Like the denial streak, the counter is consecutive: any tool call that
/// actually executes clears it, so a long run is not killed by two unrelated
/// format slips an hour apart.
pub const MAX_DIALECT_CORRECTIONS: u32 = 2;

/// History entries at the newest end of the transcript that compaction folds
/// only as a last resort.
///
/// The newest turns are the ones the next reply answers. Folding them into a
/// summary hands the model a description of the question instead of the
/// question — which is what the second compaction of pilot run A2-204c4 did on
/// 2026-09-23 when it folded 73 of 74 foldable entries and left a
/// 7 098-character request.
///
/// Six: a reply, a call and its result, twice over. Enough to see what was
/// just tried and what it returned. The guard will still fold into this tail
/// if the transcript does not otherwise fit the hard budget at all — a run
/// that stops is worse than a run that forgets — but only then, and
/// [`CompactionReport::verdict`] says so by landing below
/// [`crate::prompt_budget::compaction_floor`].
pub const KEEP_RECENT_ENTRIES: usize = 6;

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
    /// Two replies in a row were cut off by the model's output limit before
    /// the `tool_call` block they had opened was complete.
    ///
    /// Distinct from [`Self::NoAction`] on purpose, and the reason this
    /// variant exists. Measured 2026-09-23: asked for a 3000-word file,
    /// `DeepSeek` emitted ~9148 output tokens of `tool_call` and stopped without
    /// a closing fence; the loop read the fragment as prose, reported that the
    /// model had answered without acting, and charged for it. "It would not
    /// act" and "it was not allowed to finish" call for opposite responses —
    /// the second is fixed by asking for smaller pieces or a model with a
    /// larger output limit, never by telling the model to try harder.
    ResponseTruncated,
    /// The model kept asking for a tool in a format this runner cannot
    /// execute, after being told the one it reads.
    ///
    /// Distinct from [`Self::NoAction`] on purpose, and the reason this
    /// variant exists. "The model would not act" and "the model acted in a
    /// dialect we threw away" look identical in a marker line and call for
    /// opposite fixes — the second is fixed in the runner or the prompt, never
    /// by telling the model to try harder. Measured 2026-09-23 on
    /// `deepseek-v4-flash`: the first turn of a real task arrived as `DeepSeek`'s
    /// own `invoke` markup, was read as prose, and the run reported
    /// `{"completed":true,"reason":"Completed"}` with nothing done.
    UnsupportedToolCallFormat,
    /// The request could not be made to fit the connector's request contract.
    ///
    /// Distinct from [`Self::ContextWindowExhausted`] on purpose. That one is
    /// about the MODEL — its context window — and is answered by choosing a
    /// model with a bigger one. This one is about the WIRE: Model Connector's
    /// `/execute` caps `prompt` and `systemPrompt` at
    /// [`crate::prompt_budget::MC_FIELD_MAX_UTF16_UNITS`] UTF-16 units each and
    /// rejects an over-long field with an HTTP 400 before any model is
    /// reached, so a larger model would not help and the run is charged
    /// nothing for the refusal.
    ///
    /// Measured 2026-09-23: a pilot run that had executed five tool calls and
    /// cloned a repository died at turn 10 on exactly that 400, reported as
    /// `ConnectorFatal` — a verdict that names the connector for a limit the
    /// caller had overrun and could have honoured.
    RequestTooLarge,
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
            Self::RequestTooLarge => {
                "the transcript no longer fits the Model Connector's 100 000-character \
                 per-field request limit even after compaction; run the task in smaller \
                 pieces, or with tools that return less output"
            }
            Self::AuditFatal => "the capability audit failed and the executor is latched closed",
            Self::NoAction => {
                "the model answered without running a single tool, so nothing was done"
            }
            Self::ResponseTruncated => {
                "the model's reply was cut off by its output limit part-way through a tool \
                 call, twice in a row; nothing was executed — ask for the work in smaller \
                 steps, or choose a model with a larger output limit"
            }
            Self::UnsupportedToolCallFormat => {
                "the model asked for a tool in a format this runner cannot execute, and \
                 repeated it after being told the expected one; nothing was executed"
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
    /// The model opened a `tool_call` block and the reply ended before the
    /// block closed — the signature of an answer stopped by the output-token
    /// limit. `bytes` is the length of the fragment that arrived.
    ///
    /// Neither an action nor an answer. It is never dispatched, however
    /// complete the JSON inside it happens to look: a call the model did not
    /// finish emitting is not a call it asked for.
    Truncated { bytes: usize },
    /// The reply is a recognisable attempt to call a tool that this runner
    /// will not dispatch as written.
    ///
    /// Neither an action nor an answer, and it is the third outcome because
    /// two were not enough: a model that asks for a shell command in its own
    /// native markup has not answered the question, and calling that a final
    /// answer is how a run ends `Completed` with nothing done. `dialect` names
    /// what was recognised and `detail` says what made it uncallable; the
    /// driver folds both back so the model can send the call again in the
    /// format that works.
    MalformedToolCall {
        /// Human-readable name of the dialect that was recognised.
        dialect: &'static str,
        /// What specifically made the attempt uncallable.
        detail: String,
    },
}

/// Fence that opens a tool-call block inside a bare text response.
const TOOL_CALL_FENCE: &str = "```tool_call";
/// Generic Markdown code fence — closes the tool-call block.
const CODE_FENCE: &str = "```";

/// Label for this runner's own encoding, used in corrections and log lines.
const CANONICAL_DIALECT: &str = "a fenced `tool_call` block";

/// Classify a [`ConnectorResponse`] into an [`AssistantAction`] (D-REQ-06).
///
/// Convention: a single fenced block tagged `tool_call` whose body parses as
/// `{"name": <string>, "input": <json>}` is an intended tool call. A block
/// that was opened and never closed is [`AssistantAction::Truncated`].
///
/// Four outcomes, not two. A reply that names a tool in a way we recognise —
/// this runner's fence with an unusable body, `DeepSeek`'s native `invoke`
/// markup, a bare `OpenAI`-shaped JSON object — is an
/// [`AssistantAction::MalformedToolCall`], never an answer. Reading such a
/// reply as prose is what let a run end `Completed` having done nothing
/// (`crate::tool_dialect`). Only a reply with no tool-call attempt in it at
/// all is [`AssistantAction::Final`].
///
/// Fail-closed still holds where it matters: the fallback is never an
/// unchecked dispatch. A [`AssistantAction::MalformedToolCall`] executes
/// nothing, and a translated call is subjected to the full permission cascade
/// downstream exactly like a canonical one — this seam only classifies.
#[must_use]
pub fn interpret(resp: &ConnectorResponse) -> AssistantAction {
    match scan_tool_call(&resp.result) {
        // An open fence is the only local evidence of truncation there is.
        // Model Connector's response carries no finish/stop reason to read
        // instead: its `ConnectorResponse` has no such field
        // (`src/connectors/interfaces/connector.interface.ts:42`), and the
        // DeepSeek adapter does not even decode the provider's
        // `choices[].finish_reason` — its response interface omits the key and
        // `parseResponse` returns only the message content
        // (`src/connectors/deepseek/deepseek.connector.ts:4,82`). Read
        // 2026-09-23 on model-connector `3911773`. If that contract ever grows
        // the field, it belongs here as the primary signal and this scan
        // becomes the fallback.
        ToolCallBlock::Unterminated => AssistantAction::Truncated {
            bytes: resp.result.len(),
        },
        ToolCallBlock::Closed(body) => parse_tool_call(body),
        // No canonical block at all: the reply may still be a tool call
        // written in a dialect the model was trained on rather than the one it
        // was told. Only here — a canonical block, however broken, is judged
        // as a canonical block.
        ToolCallBlock::Absent => match tool_dialect::recognise(&resp.result) {
            Some(DialectMatch::Call { name, input, .. }) => {
                AssistantAction::ToolCall { name, input }
            }
            Some(DialectMatch::Attempt { dialect, detail }) => {
                AssistantAction::MalformedToolCall { dialect, detail }
            }
            None => AssistantAction::Final {
                text: resp.result.clone(),
            },
        },
    }
}

/// The operator's line for a reply rejected as an unreadable tool call.
///
/// A pure function and not an inline `format!` because the part that matters
/// is the tail: `saved` is where the reply itself was kept, and an operator
/// who cannot find that path has the same nothing the A2-204c3 post-mortem
/// had. Pinning the line in a test is only possible if building it is separate
/// from printing it.
#[must_use]
pub fn rejected_format_line(dialect: &str, detail: &str, saved: Option<&str>) -> String {
    format!(
        "arcana: the model asked for a tool as {dialect} — {detail}; nothing was executed{}",
        saved_clause(saved)
    )
}

/// The operator's line for a reply the model's output limit cut off.
#[must_use]
pub fn truncated_reply_line(bytes: usize, saved: Option<&str>) -> String {
    format!(
        "arcana: the model's reply was cut off after {bytes} bytes with an unclosed \
         `tool_call` block — nothing was executed{}",
        saved_clause(saved)
    )
}

/// Name the file the rejected reply was kept in, when there is one.
fn saved_clause(saved: Option<&str>) -> String {
    saved.map_or_else(String::new, |path| {
        format!(" — the reply as the model sent it is in {path}")
    })
}

/// What a scan of a reply found where a `tool_call` block would be.
enum ToolCallBlock<'a> {
    /// No `tool_call` fence in the reply at all.
    Absent,
    /// A fence that opened and closed; the payload is its body, trimmed.
    Closed(&'a str),
    /// A fence that opened and never closed.
    Unterminated,
}

/// Locate the first `tool_call` block and report whether it is complete.
///
/// The three outcomes used to be two: a missing closing fence returned `None`
/// exactly like malformed JSON, so the one anomaly that means "the model was
/// interrupted" was indistinguishable from the ones that mean "the model wrote
/// something we cannot use".
fn scan_tool_call(result: &str) -> ToolCallBlock<'_> {
    let Some(open) = result.find(TOOL_CALL_FENCE) else {
        return ToolCallBlock::Absent;
    };
    // `find` returns a char boundary and the fence is ASCII, so the slice is
    // always valid; `get` keeps that an ordinary `Absent` rather than a panic.
    let Some(rest) = result.get(open + TOOL_CALL_FENCE.len()..) else {
        return ToolCallBlock::Absent;
    };
    match rest.find(CODE_FENCE) {
        Some(close) => rest.get(..close).map_or(ToolCallBlock::Absent, |body| {
            ToolCallBlock::Closed(body.trim())
        }),
        None => ToolCallBlock::Unterminated,
    }
}

/// Judge a complete block body.
///
/// Always a verdict, never a fall-through: either the call, or a
/// [`AssistantAction::MalformedToolCall`] that says what was wrong. It used to
/// return `None` for a body that was not valid JSON or had no `name`, and the
/// caller turned that `None` into [`AssistantAction::Final`] — the runner's
/// own format, misspelt, delivered as an answer to the operator's question.
fn parse_tool_call(body: &str) -> AssistantAction {
    let malformed = |detail: String| AssistantAction::MalformedToolCall {
        dialect: CANONICAL_DIALECT,
        detail,
    };
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return malformed("the body of your `tool_call` block is not valid JSON".to_owned());
    };
    let Some(name) = value.get("name").and_then(Value::as_str) else {
        return malformed(
            "the body of your `tool_call` block has no `name` string, so no tool was named"
                .to_owned(),
        );
    };
    // `arguments` / `parameters` / `args` are accepted as `input`, and so are
    // arguments written as plain siblings of `name`. The reader here was
    // `value.get("input").cloned().unwrap_or(Value::Null)`, so a model that
    // used any other spelling had its arguments silently discarded and its
    // call dispatched empty — a `bash` with no command, refused for a reason
    // that was never the model's mistake.
    //
    // The sibling form is safe to dispatch *here* because the model opened
    // this runner's own `tool_call` fence: inside markup whose only purpose is
    // to carry a call, the keys that are not `name` are the call's arguments
    // and can be nothing else (`crate::tool_dialect`, A2-219). Measured live
    // the same day on `deepseek-flash`: `{"name": "bash", "command": …,
    // "timeout_seconds": 600}` in a correct fence, corrected instead of run.
    //
    // No spelling and no siblings is the same defect with nothing to recover:
    // a `null` dispatched into a tool that wants an object is a schema denial
    // we can see coming, and the model is better served by being told its call
    // has no arguments than by being told `null` is not an object. Measured
    // live on 2026-09-23 — audit `input_hash 03f88b99c3d8073b`,
    // `blake3("null")` — this is the one remaining way that hash could still
    // be written.
    let Some(input) = tool_dialect::declared_call_arguments(&value) else {
        return malformed(format!(
            "your `tool_call` block named `{name}` but carried no arguments; put them in an \
             `input` object (send `\"input\": {{}}` if the tool genuinely takes none)"
        ));
    };
    AssistantAction::ToolCall {
        name: name.to_owned(),
        input,
    }
}

// ---------------------------------------------------------------------------
// Conversation history (D-REQ-03)
// ---------------------------------------------------------------------------

/// A run of older history entries replaced by one line that says what they
/// were.
///
/// Compaction used to be deletion: the oldest tool result was `Vec::remove`d
/// and nothing anywhere recorded that it had existed. A model whose earlier
/// work silently stops being in the transcript re-does it — and an operator
/// reading the log cannot tell a run that never called a tool from one whose
/// call was quietly dropped. The span therefore keeps the *shape* of what it
/// swallowed: how many entries, how many were the model's own turns, which
/// tools ran and how often, and how much text went away.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompactedSpan {
    /// History entries folded into this span.
    pub entries: usize,
    /// How many of them were the model's own replies.
    pub assistant_turns: usize,
    /// Tool call counts by tool name, in name order.
    pub tool_calls: std::collections::BTreeMap<String, usize>,
    /// UTF-16 units of transcript this span replaced.
    pub units: usize,
}

impl CompactedSpan {
    /// Fold one entry into the span, keeping what a later turn may need.
    fn absorb(&mut self, entry: &HistoryEntry) {
        self.entries = self.entries.saturating_add(1);
        self.units = self
            .units
            .saturating_add(prompt_budget::utf16_units(&serialize_entry(entry)));
        match entry {
            HistoryEntry::Assistant(_) => {
                self.assistant_turns = self.assistant_turns.saturating_add(1);
            }
            HistoryEntry::ToolCall { name, .. } => {
                *self.tool_calls.entry(name.clone()).or_insert(0) += 1;
            }
            HistoryEntry::Compacted(other) => {
                // Folding into an existing span must not lose its tally.
                self.entries = self.entries.saturating_add(other.entries - 1);
                self.assistant_turns = self.assistant_turns.saturating_add(other.assistant_turns);
                self.units = self.units.saturating_add(other.units);
                for (name, count) in &other.tool_calls {
                    *self.tool_calls.entry(name.clone()).or_insert(0) += count;
                }
            }
            HistoryEntry::Task(_) | HistoryEntry::ToolResult { .. } | HistoryEntry::Injected(_) => {
            }
        }
    }

    /// The one line the model reads in place of the folded entries.
    fn render(&self) -> String {
        let mut calls: Vec<String> = self
            .tool_calls
            .iter()
            .map(|(name, count)| format!("{name}×{count}"))
            .collect();
        if calls.is_empty() {
            calls.push("none".to_owned());
        }
        format!(
            "EARLIER TRANSCRIPT COMPACTED by the runner to fit the request budget: \
{entries} entries ({units} characters) were replaced by this line — {turns} of your own \
replies and these executed tool calls: {calls}. Their output is NOT in this request any \
more. Nothing was undone: the work those calls did is still on disk. If you need a fact \
from them, get it again with a tool call rather than assuming it.",
            entries = self.entries,
            units = self.units,
            turns = self.assistant_turns,
            calls = calls.join(", "),
        )
    }
}

/// One entry in the ordered conversation log that composes each next request.
///
/// [`HistoryEntry::Task`] carries the initial task framing and is **never**
/// trimmed by the context guard; [`HistoryEntry::ToolResult`] payloads are
/// elided first, and whole older entries are folded into a
/// [`HistoryEntry::Compacted`] span only when eliding is not enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryEntry {
    /// The initial task / system framing (never trimmed).
    Task(String),
    /// The model's raw `result` text for a turn.
    Assistant(String),
    /// An intended tool call; `input` is compact JSON.
    ToolCall { name: String, input: String },
    /// A tool's output — elided first when the transcript overflows.
    ToolResult { name: String, content: String },
    /// A post-tool hook `InjectContext` line folded into the next turn.
    Injected(String),
    /// Older entries the guard replaced with a statement of what they were.
    Compacted(CompactedSpan),
}

/// Render one entry exactly as [`serialize_history`] renders it, trailing
/// newline included, so a size taken per entry sums to the size of the whole.
fn serialize_entry(entry: &HistoryEntry) -> String {
    let mut out = String::new();
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
        HistoryEntry::Compacted(span) => {
            out.push_str("[compacted] ");
            out.push_str(&span.render());
        }
    }
    out.push('\n');
    out
}

/// Serialize the history into the connector prompt string (also the size
/// measure used by the context guard, so guard and prompt agree exactly).
fn serialize_history(history: &[HistoryEntry]) -> String {
    let mut out = String::new();
    for entry in history {
        out.push_str(&serialize_entry(entry));
    }
    out
}

/// Size of the serialized history in the unit the connector counts in.
fn history_units(history: &[HistoryEntry]) -> usize {
    history
        .iter()
        .map(|entry| prompt_budget::utf16_units(&serialize_entry(entry)))
        .sum()
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
    /// One compaction action was enough.
    Microcompacted,
    /// More than one compaction action was needed to fit.
    ReactiveCompacted,
    /// History still overflows with nothing left to compact.
    Irreducible,
}

/// What the guard did, so the run can state it rather than change the request
/// behind the model's back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionReport {
    /// The classification the driver maps to a `Continue` reason.
    pub verdict: ContextVerdict,
    /// Tool results shortened in place.
    pub elided_results: usize,
    /// Entries that are not tool results — model replies, tool-call arguments,
    /// injected context — shortened in place because one of them alone was a
    /// large share of the budget.
    ///
    /// Non-zero means the transcript overflowed partly because the *model*
    /// wrote too much in one turn, which no ingestion bound covers. It is a
    /// different fact from `elided_results` and a reader should not have to
    /// guess which one happened.
    pub bounded_entries: usize,
    /// Entries folded into a [`HistoryEntry::Compacted`] span.
    pub folded_entries: usize,
    /// Serialized size before the guard ran, in UTF-16 units.
    pub units_before: usize,
    /// Serialized size after it ran.
    pub units_after: usize,
    /// The ceiling it was working to.
    pub budget: usize,
    /// The size it was aiming for — [`crate::prompt_budget::compaction_target`]
    /// of `budget`. Stated so "how much did it cut" has an answer that is not
    /// just "enough".
    pub target: usize,
}

impl CompactionReport {
    /// The sentence the run prints when it changed the transcript.
    ///
    /// Only when it changed something: a guard that narrates every no-op turn
    /// teaches the operator to skip its lines, including the one that matters.
    #[must_use]
    pub fn stated(&self) -> Option<String> {
        if self.verdict == ContextVerdict::Ok {
            return None;
        }
        Some(format!(
            "arcana: transcript compacted to fit the {budget}-character request budget \
(target {target}) — {elided} tool result(s) shortened, {bounded} oversized entr(ies) \
shortened, {folded} earlier entr(ies) folded into a summary ({before} → {after} characters)",
            budget = self.budget,
            target = self.target,
            elided = self.elided_results,
            bounded = self.bounded_entries,
            folded = self.folded_entries,
            before = self.units_before,
            after = self.units_after,
        ))
    }
}

/// The text of one entry, when the guard is allowed to shorten it.
///
/// [`HistoryEntry::Task`] is excluded because the task statement is the one
/// thing a run cannot afford to lose — a run that forgets what it was asked is
/// worse than a run that stops — and [`HistoryEntry::Compacted`] because a
/// summary of folded entries is already the short form of something.
fn shrinkable_text(entry: &mut HistoryEntry) -> Option<(&mut String, bool)> {
    match entry {
        HistoryEntry::Task(_) | HistoryEntry::Compacted(_) => None,
        HistoryEntry::ToolResult { content, .. } => Some((content, true)),
        HistoryEntry::Assistant(text) | HistoryEntry::Injected(text) => Some((text, false)),
        HistoryEntry::ToolCall { input, .. } => Some((input, false)),
    }
}

/// How short one entry has to become for the transcript to reach its target,
/// never shorter than `hard_floor` and never shorter than a usable elision.
///
/// This is the whole anti-overshoot rule, in one line: cut what the transcript
/// is over by, not everything the entry has. The guard that produced the
/// 7 098-character request cut to a fixed floor whether or not the floor was
/// needed, so each step removed far more than the step's own arithmetic asked
/// for.
fn shrink_to(entry_units: usize, excess: usize, hard_floor: usize) -> usize {
    entry_units
        .saturating_sub(excess)
        .max(hard_floor)
        .max(prompt_budget::MIN_ELISION_BUDGET)
}

/// Bring `history` within `budget` UTF-16 units, degrading in authority order,
/// and report what that cost (D-REQ-04).
///
/// The order is not arbitrary. A tool result is the cheapest thing to lose
/// part of — its full text is on disk and the model is told where — so results
/// are elided first, oldest first, keeping head and tail. Only when that is
/// not enough are whole older entries folded into a
/// [`HistoryEntry::Compacted`] span, again oldest first, because the newest
/// turns are the ones the next reply answers. The [`HistoryEntry::Task`]
/// framing is never touched at all: a run that forgets its own task is worse
/// than a run that stops.
///
/// # The band (A2-225)
///
/// Every stage aims at [`crate::prompt_budget::compaction_target`] and stops
/// at the first moment it is reached, and no single stage may remove more than
/// [`crate::prompt_budget::entry_ceiling`] at once. Together those two say the
/// pass lands at or above [`crate::prompt_budget::compaction_floor`] whenever
/// there was that much material to keep — which the old guard did not, and on
/// 2026-09-23 it took a 179 037-character transcript to 7 098 by folding 73
/// entries to reach one oversized entry at the newest end.
///
/// That oversized entry is the reason for stage 0. A tool result is bounded at
/// ingestion; a model reply is not, and an entry larger than the whole budget
/// cannot be compensated for by folding anything else. The guard now shortens
/// it — keeping head and tail, saying how much went — instead of deleting the
/// rest of the run and still not fitting.
#[must_use]
pub fn guard_context(history: &mut Vec<HistoryEntry>, budget: usize) -> CompactionReport {
    let units_before = history_units(history);
    let mut report = CompactionReport {
        verdict: ContextVerdict::Ok,
        elided_results: 0,
        bounded_entries: 0,
        folded_entries: 0,
        units_before,
        units_after: units_before,
        budget,
        target: prompt_budget::compaction_target(budget),
    };
    if units_before <= budget {
        return report;
    }
    // One index set across both eliding stages: an entry shortened by stage 0
    // for being oversized and again by stage 1 for still not fitting is ONE
    // tool result that lost text, and the line the operator reads says so.
    let mut elided: Vec<usize> = Vec::new();
    bound_oversized_entries(history, &mut report, &mut elided);
    elide_tool_results(history, &mut report, &mut elided);
    report.elided_results = elided.len();
    fold_oldest_entries(history, &mut report);
    if report.units_after > budget {
        report.verdict = ContextVerdict::Irreducible;
        return report;
    }
    let actions = report.elided_results + report.bounded_entries + report.folded_entries;
    report.verdict = match actions {
        0 => ContextVerdict::Ok,
        1 => ContextVerdict::Microcompacted,
        _ => ContextVerdict::ReactiveCompacted,
    };
    report
}

/// Stage 0 — no single entry may be a large share of the budget.
///
/// Whole-history stages cannot fix an entry that is itself bigger than the
/// budget, and trying is what destroys the transcript: folding is oldest-first,
/// so reaching one oversized entry at the newest end costs every entry in front
/// of it. Order here is oldest-first only for determinism; an entry is touched
/// because of its own size, wherever it sits.
///
/// A tool result shortened here is reported as an elided result, not a bounded
/// entry: it is the same act stage 1 performs, and a reader counting "how many
/// tool results lost text" should get one number. `bounded_entries` is
/// therefore exactly the count of *model-written* entries that were too big,
/// which is the fact nothing else in the report carries.
fn bound_oversized_entries(
    history: &mut [HistoryEntry],
    report: &mut CompactionReport,
    elided: &mut Vec<usize>,
) {
    let ceiling = prompt_budget::entry_ceiling(report.budget);
    for index in 0..history.len() {
        if report.units_after <= report.target {
            return;
        }
        let excess = report.units_after - report.target;
        let Some((text, is_result)) = shrinkable_text(&mut history[index]) else {
            continue;
        };
        let text_units = prompt_budget::utf16_units(text);
        if text_units <= ceiling {
            continue;
        }
        let keep = shrink_to(text_units, excess, ceiling);
        if keep >= text_units {
            continue;
        }
        *text = prompt_budget::elide_middle(text, keep, None);
        if is_result {
            elided.push(index);
        } else {
            report.bounded_entries = report.bounded_entries.saturating_add(1);
        }
        report.units_after = history_units(history);
    }
}

/// Stage 1 — shorten tool results, oldest first, and only as far as the
/// arithmetic asks.
///
/// A tool result is the cheapest thing to lose part of: its full text is on
/// disk and the elision marker names the file. The floor is what is left when
/// the transcript has to survive at all; reaching it is not the goal, fitting
/// is. The guard this replaced cut every result to a fixed floor whether or not
/// the floor was needed.
fn elide_tool_results(
    history: &mut [HistoryEntry],
    report: &mut CompactionReport,
    elided: &mut Vec<usize>,
) {
    let floor = report.budget / 64;
    for index in 0..history.len() {
        if report.units_after <= report.target {
            return;
        }
        let excess = report.units_after - report.target;
        let HistoryEntry::ToolResult { content, .. } = &mut history[index] else {
            continue;
        };
        let content_units = prompt_budget::utf16_units(content);
        let keep = shrink_to(content_units, excess, floor);
        if keep >= content_units {
            continue;
        }
        *content = prompt_budget::elide_middle(content, keep, None);
        if !elided.contains(&index) {
            elided.push(index);
        }
        report.units_after = history_units(history);
    }
}

/// Stage 2 — fold the oldest entries after the task framing into ONE span.
///
/// One, not one per entry: the summary line costs a few hundred characters of
/// its own, so a row of them would grow the request it is supposed to shrink.
/// Each iteration removes exactly one entry, so this terminates.
///
/// Two passes, with different stopping rules. The first keeps the newest
/// [`KEEP_RECENT_ENTRIES`] entries out of the summary and stops at the target:
/// a model handed a summary of the turn it is answering has nothing left to
/// answer. The second runs only if the transcript still does not fit the hard
/// budget, and then the tail is fair game too — a run that stops is worse than
/// a run that forgets, and a `units_after` below
/// [`crate::prompt_budget::compaction_floor`] is how the operator sees it came
/// to that.
fn fold_oldest_entries(history: &mut Vec<HistoryEntry>, report: &mut CompactionReport) {
    let Some(start) = history
        .iter()
        .position(|entry| !matches!(entry, HistoryEntry::Task(_)))
    else {
        return;
    };
    for (limit, keep_recent) in [(report.target, KEEP_RECENT_ENTRIES), (report.budget, 1)] {
        if report.units_after <= limit || history.len() <= start + keep_recent {
            continue;
        }
        if report.folded_entries == 0 {
            let mut span = CompactedSpan::default();
            span.absorb(&history[start]);
            history[start] = HistoryEntry::Compacted(span);
            report.folded_entries = 1;
            report.units_after = history_units(history);
        }
        while report.units_after > limit && history.len() > start + 1 + keep_recent {
            let entry = history.remove(start + 1);
            if let HistoryEntry::Compacted(span) = &mut history[start] {
                span.absorb(&entry);
            }
            report.folded_entries = report.folded_entries.saturating_add(1);
            report.units_after = history_units(history);
        }
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
    /// Serialized-history ceiling, in UTF-16 code units → compaction, then
    /// [`TerminalReason::RequestTooLarge`].
    ///
    /// Units, not bytes: `String::len` is what this used to be measured in,
    /// and it is the wrong number by a factor of three on Russian or Chinese
    /// text and by a factor of two on emoji — in the direction that sends an
    /// over-limit request. See [`crate::prompt_budget`].
    pub context_budget_units: usize,
    /// Ceiling on one tool result carried into the transcript, in UTF-16 code
    /// units. Output past it is elided head-and-tail with a marker that says
    /// how much went and where the whole of it still is.
    pub tool_result_budget_units: usize,
    /// Where a tool result too large to carry is kept in full.
    ///
    /// `None` — the default, and what every test gets — means nothing is
    /// written to disk and the elision marker tells the model to narrow its
    /// call instead. A headless run sets it to a directory inside the
    /// workspace, so the path in the marker is one the model is allowed to
    /// read.
    pub tool_output_spill_dir: Option<std::path::PathBuf>,
    /// Where a reply this loop refused to act on is kept, verbatim.
    ///
    /// `None` — the default, and what every test gets unless it says
    /// otherwise — means a rejected reply survives only as the log line saying
    /// it was rejected. That is exactly what a live run had when it died
    /// `UnsupportedToolCallFormat` on the one call that mattered: the audit log
    /// keeps `input_hash`/`output_hash` and no text, the transcript is never
    /// written to disk, and the reply the runner threw away was therefore
    /// unknowable afterwards — so the defect could be described but not
    /// diagnosed (A2-219, `/home/dev/aup/arc2/runs/A2-204c3/log`). A headless
    /// run sets this to a directory inside the workspace.
    ///
    /// It holds what the *model* sent, not what the runner made of it. A
    /// correction is only ever as good as the reply it was written against.
    pub rejected_reply_dir: Option<std::path::PathBuf>,
    /// Append the exact request of every dispatch to this file.
    ///
    /// Off unless the operator names a path: a transcript is the whole
    /// conversation in clear text, so keeping one is a decision about their
    /// disk, not something a runner should start doing on its own.
    ///
    /// Appended per dispatch rather than written once at the end, because
    /// compaction means the last request is not a superset of the earlier
    /// ones — the turns a run folds away are precisely the ones a
    /// post-mortem cannot otherwise see.
    pub transcript_path: Option<std::path::PathBuf>,
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
    /// Consecutive transient GATEWAY failures the loop will re-dispatch before
    /// it gives up. Separate from `connector_retry_limit` because an edge
    /// verdict and a refusal Model Connector authored are different facts.
    pub edge_retry_limit: u32,
    /// Pause before a re-dispatch when the upstream named no `retryAfter`, and
    /// the first step of the gateway backoff schedule.
    pub connector_retry_backoff: Duration,
    /// Total time one turn may spend asleep between re-dispatches. Reached, the
    /// run ends [`TerminalReason::ConnectorFatal`] saying so rather than
    /// sleeping on.
    pub connector_retry_pause_budget: Duration,
}

impl DriverConfig {
    /// Config for `connector_id` with defensive defaults (8 connector
    /// attempts, no cost cap, and a context budget derived from the
    /// connector's own request contract rather than guessed). Callers tune
    /// individual fields.
    #[must_use]
    pub fn new(connector_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
            model: None,
            system_prompt: None,
            max_turns: 8,
            max_cost_usd: None,
            context_budget_units: DEFAULT_CONTEXT_BUDGET_UTF16_UNITS,
            tool_result_budget_units: DEFAULT_TOOL_RESULT_BUDGET_UTF16_UNITS,
            tool_output_spill_dir: None,
            rejected_reply_dir: None,
            transcript_path: None,
            first_dispatch_measurement: None,
            first_dispatch_prompt: None,
            policy: ModelPolicy::new(),
            require_action: false,
            connector_retry_limit: DEFAULT_CONNECTOR_RETRY_LIMIT,
            edge_retry_limit: DEFAULT_EDGE_RETRY_LIMIT,
            connector_retry_backoff: DEFAULT_CONNECTOR_RETRY_BACKOFF,
            connector_retry_pause_budget: DEFAULT_CONNECTOR_RETRY_PAUSE_BUDGET,
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
        if self.context_budget_units == 0 {
            return Some(TerminalReason::ContextWindowExhausted);
        }
        // A system prompt over the wall fails every dispatch of the run
        // identically, and it is known before the first one is sent.
        if self
            .system_prompt
            .as_deref()
            .is_some_and(|text| !prompt_budget::fits(text, MC_FIELD_MAX_UTF16_UNITS))
        {
            return Some(TerminalReason::RequestTooLarge);
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
    /// Turns on which the transcript had to be compacted to stay inside the
    /// connector's request contract. Non-zero means the model answered from a
    /// summary of part of its own history.
    pub compactions: u32,
    /// What ended the run, in the words of whatever refused it.
    ///
    /// [`TerminalReason`] is a closed set of causes; this is the one detail
    /// that cause carried — which cascade layer refused, which tool, and the
    /// validation error itself. Pilot run A2-204c4 ended `PermissionDenied`
    /// with `error: null` in its done-marker and `the permission cascade
    /// refused the tool call` on stderr, and an operator reading that could not
    /// tell a policy refusal from a misspelt argument.
    pub terminal_detail: Option<String>,
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

/// What the loop tells a model whose reply the output limit cut off.
///
/// It names the cause, because the model cannot see it: from where the model
/// sits the turn simply ended. Without that, the obvious next move is to send
/// the same oversized block again and be cut off at the same token.
const TRUNCATION_NUDGE: &str =
    "YOUR LAST REPLY WAS CUT OFF by your own output limit in the middle of a `tool_call` block. \
Nothing ran, and the half-written call was discarded — do not try to continue it. \
Do the same work in SMALLER pieces: send one complete `tool_call` block that you are sure fits \
inside a single reply (for example write the first part of the file now and append the rest in \
later turns), and keep every later reply small too.";
/// What the loop tells a model whose tool call it could not execute.
///
/// Phrased as a fact about the machine, like [`NO_ACTION_NUDGE`]: what was
/// recognised, what did not happen, and the one encoding that does happen. The
/// format is restated in full rather than referred back to, because the reply
/// that triggered this is proof the model is not working from the copy in the
/// system prompt.
const TOOL_FORMAT_CORRECTION: &str = "NOTHING WAS EXECUTED. Your last reply asked for a tool in \
a format this runner cannot execute";

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
    /// Time already slept between re-dispatches of the current turn.
    connector_retry_pause_spent: Duration,
    /// When the current streak of connector failures began. `None` while the
    /// upstream is answering; the terminal verdict reports its elapsed time.
    connector_failure_since: Option<std::time::Instant>,
    /// How often each call refused at a correctable layer has been sent since
    /// the last tool call that actually executed. A call whose count passes
    /// [`MAX_DENIALS_PER_DISTINCT_CALL`] ends the run.
    ///
    /// A map rather than a set because the bound is a NUMBER of refusals per
    /// distinct call, and a set can only ever express "one". The constant used
    /// to be documented as the rule while the code was a `HashSet::insert`, so
    /// editing it changed nothing and no test noticed (A2-230).
    refused_calls: std::collections::HashMap<String, u32>,
    /// What refused the run, carried out of the step that decided to stop.
    terminal_detail: Option<String>,
    /// Consecutive replies cut off by the output limit since the last one that
    /// parsed.
    truncation_retries: u32,
    /// Unexecutable tool-call formats since the last call that executed.
    malformed_calls: u32,
    /// Turns on which the guard changed the transcript to fit the request
    /// contract. Reported, because a compacted run answers from less than it
    /// was given and a reader of the marker line deserves to know.
    compactions: u32,
    /// Tool results spilled to disk so far; also the spill file's number.
    spilled: u32,
    /// Replies the loop refused to act on and wrote out; also the rejected
    /// file's number.
    rejected: u32,
    /// Whether a transcript append has already failed and been reported.
    /// One line per run, not one per turn: a full disk is one fact.
    transcript_broken: bool,
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
            connector_retry_pause_spent: Duration::ZERO,
            connector_failure_since: None,
            refused_calls: std::collections::HashMap::new(),
            truncation_retries: 0,
            malformed_calls: 0,
            compactions: 0,
            terminal_detail: None,
            spilled: 0,
            rejected: 0,
            transcript_broken: false,
        }
    }

    /// Record a reply the loop could read.
    ///
    /// It goes into the history verbatim, and it is proof the model can still
    /// finish a turn — so the truncation budget starts over here rather than
    /// counting cut-offs across a whole run.
    fn accept_reply(&mut self, text: &str) {
        self.truncation_retries = 0;
        self.history.push(HistoryEntry::Assistant(text.to_owned()));
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
                compactions: 0,
                terminal_detail: None,
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
                        compactions: state.compactions,
                        terminal_detail: state.terminal_detail.take(),
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

    /// Bring the transcript inside this run's budget, and say so when that
    /// changed the request.
    ///
    /// Returns `Some` when the step is over: a compaction that re-loops
    /// without spending a turn, or a transcript that cannot be made to fit.
    fn fit_request(&self, state: &mut RunState) -> Option<StepResult> {
        let report = guard_context(&mut state.history, self.config.context_budget_units);
        // The run says what it did. A model whose earlier turns were
        // summarised behind its back, and an operator reading only the log,
        // otherwise have no way to know the request changed shape — and a
        // shorter answer from a compacted transcript would look like a worse
        // model rather than a smaller question.
        if let Some(line) = report.stated() {
            eprintln!("{line}");
        }
        state.compactions = state
            .compactions
            .saturating_add(u32::from(report.verdict != ContextVerdict::Ok));
        match report.verdict {
            ContextVerdict::Ok => None,
            ContextVerdict::Irreducible => {
                Some(StepResult::Terminal(TerminalReason::RequestTooLarge, None))
            }
            verdict => compaction_continue(verdict).map(StepResult::Continue),
        }
    }

    /// Serialize the transcript into the request this turn will send, and
    /// refuse it if it is over the wall.
    ///
    /// The wall, not the budget. [`Self::fit_request`] has already compacted
    /// to `context_budget_units`; this is the contract Model Connector will
    /// enforce with an HTTP 400, and the only request that can reach it is one
    /// the guard could not shrink or an exact first-dispatch prompt the caller
    /// supplied. Refusing here costs nothing and names the limit; sending it
    /// spends a roundtrip to be told the same thing by a validator that calls
    /// it `ConnectorFatal`.
    ///
    /// # Errors
    /// The terminal step to return when the request cannot be sent.
    fn compose_request(
        &self,
        state: &RunState,
        first_dispatch: bool,
    ) -> Result<String, StepResult> {
        let prompt = if first_dispatch {
            self.config.first_dispatch_prompt.clone().map_or_else(
                || serialize_history(&state.history),
                FirstDispatchPromptV0::into_inner,
            )
        } else {
            serialize_history(&state.history)
        };
        let ceiling = self
            .config
            .context_budget_units
            .min(MC_FIELD_MAX_UTF16_UNITS);
        if !prompt_budget::fits(&prompt, ceiling) {
            eprintln!(
                "arcana: the request is {} characters, over the {ceiling}-character ceiling \
                 for this run — not sent",
                prompt_budget::utf16_units(&prompt),
            );
            return Err(StepResult::Terminal(TerminalReason::RequestTooLarge, None));
        }
        Ok(prompt)
    }

    /// One step: guards → select model → connector attempt → interpret → (tool
    /// turn | final). `attempts` is the shared connector-attempt counter that
    /// enforces `max_turns`; `selected` accumulates the ordered per-step model
    /// ids.
    async fn step(&self, state: &mut RunState) -> StepResult {
        if self.cancel.is_cancelled() {
            return StepResult::Terminal(TerminalReason::AbortedByOperator, None);
        }
        if state.attempts >= self.config.max_turns {
            return StepResult::Terminal(TerminalReason::MaxTurns, None);
        }
        if self.cost.check_budget(self.config.max_cost_usd).is_err() {
            return StepResult::Terminal(TerminalReason::MaxCostUsd, None);
        }
        if let Some(step) = self.fit_request(state) {
            return step;
        }
        let first_dispatch = state.attempts == 0;
        let prompt = match self.compose_request(state, first_dispatch) {
            Ok(prompt) => prompt,
            Err(step) => return step,
        };
        let history = &mut state.history;
        let attempts = &mut state.attempts;
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
        let turn = *attempts;
        self.save_transcript(state, turn, &prompt);
        // Before the dispatch, not after: a request whose size was never
        // recorded must not be one that was nevertheless paid for.
        if let Some(step) = self.record_dispatch(turn, &choice.model_id, &prompt) {
            return step;
        }
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
                state.connector_retry_pause_spent = Duration::ZERO;
                state.connector_failure_since = None;
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
        match interpret(&resp) {
            // Handled before the history is written: the fragment is
            // deliberately NOT kept. Feeding a half-emitted call back would
            // put words in the model's mouth that it never finished saying,
            // and the fragment is large by construction — the live one was
            // ~9148 output tokens — so carrying it would shrink the window for
            // the retry that has to succeed.
            AssistantAction::Truncated { bytes } => {
                self.recover_from_truncation(state, bytes, &resp.result)
            }
            AssistantAction::Final { text } => {
                state.accept_reply(&resp.result);
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
                state.accept_reply(&resp.result);
                if self.cancel.is_cancelled() {
                    return StepResult::Terminal(TerminalReason::AbortedByOperator, None);
                }
                state.history.push(HistoryEntry::ToolCall {
                    name: name.clone(),
                    input: input.to_string(),
                });
                self.run_tool_turn(state, &name, input).await
            }
            // Recognised, not executed, and NOT the end of the run.
            AssistantAction::MalformedToolCall { dialect, detail } => {
                // The reply is kept, unlike a truncated fragment: the model
                // finished saying it, and hiding it would make the correction
                // that follows read as an answer to nothing.
                state.accept_reply(&resp.result);
                self.correct_tool_format(state, dialect, &detail, &resp.result)
            }
        }
    }

    /// Decide what a reply cut off by the output limit means for the run:
    /// one more ask for smaller pieces, or a verdict that names the cause.
    ///
    /// Not a connector retry — the connector did its job and the answer is
    /// paid for. What failed is that the model could not say what it wanted to
    /// say inside one reply, so re-sending the same request unchanged would
    /// buy the same cut-off at the same token. The re-dispatch is a different
    /// request: it carries [`TRUNCATION_NUDGE`], and the fragment is dropped
    /// rather than echoed back.
    fn recover_from_truncation(
        &self,
        state: &mut RunState,
        bytes: usize,
        reply: &str,
    ) -> StepResult {
        // Saved before anything else is decided. The fragment is deliberately
        // kept out of the transcript below, so without this write the only
        // surviving evidence of a cut-off reply would be its length.
        let saved = self.save_rejected_reply(state, reply);
        // `eprintln!` rather than `tracing`: the CLI installs no subscriber.
        eprintln!("{}", truncated_reply_line(bytes, saved.as_deref()));
        if state.truncation_retries >= TRUNCATION_RETRY_LIMIT {
            return StepResult::Terminal(TerminalReason::ResponseTruncated, None);
        }
        state.truncation_retries = state.truncation_retries.saturating_add(1);
        // The discarded fragment is still recorded — as a fact about the turn,
        // not as something the model said. Without this line the next prompt
        // would show a task, a nudge, and no trace of the reply between them.
        state.history.push(HistoryEntry::Injected(format!(
            "The previous reply was cut off after {bytes} bytes and was discarded; nothing ran."
        )));
        state
            .history
            .push(HistoryEntry::Injected(TRUNCATION_NUDGE.to_owned()));
        eprintln!("arcana: asking for the same work in smaller pieces (1 of 1)");
        StepResult::Continue(ContinueReason::MaxOutputTokensRecovery)
    }

    /// Decide what an unexecutable tool-call format does to the run: one
    /// correction naming the encoding that works, or a verdict that says the
    /// model asked for a tool in a dialect this runner threw away.
    ///
    /// Not a `NoAction` nudge, though it lands near one. [`NO_ACTION_NUDGE`]
    /// answers a model that produced no call at all; this answers a model that
    /// produced one we could not read, and the difference is the whole point —
    /// told "nothing was executed, so call a tool", a model that has just
    /// called a tool has no way to work out what to change.
    ///
    /// Nothing executed: `tool_calls` is not incremented here, so a run whose
    /// every reply was in the wrong dialect still reports zero work done.
    fn correct_tool_format(
        &self,
        state: &mut RunState,
        dialect: &str,
        detail: &str,
        reply: &str,
    ) -> StepResult {
        // The reply, verbatim, before the run is allowed to end on it. What
        // the runner made of the reply is already in `detail`; what the model
        // actually sent is only here, and a correction can only be judged
        // against the text it was written for.
        let saved = self.save_rejected_reply(state, reply);
        // `eprintln!` rather than `tracing`: the CLI installs no subscriber.
        // The operator needs this line — it is the difference between "the
        // model refused to work" and "this runner cannot read what the model
        // sent", and only one of those is the model's fault.
        eprintln!(
            "{}",
            rejected_format_line(dialect, detail, saved.as_deref())
        );
        state.malformed_calls = state.malformed_calls.saturating_add(1);
        if state.malformed_calls >= MAX_DIALECT_CORRECTIONS {
            return StepResult::Terminal(TerminalReason::UnsupportedToolCallFormat, None);
        }
        let remaining = MAX_DIALECT_CORRECTIONS - state.malformed_calls;
        state.history.push(HistoryEntry::Injected(format!(
            "{TOOL_FORMAT_CORRECTION} — {detail}. No command ran and no file was written. \
Send the SAME call again as exactly one fenced block tagged `tool_call`, whose body is one \
JSON object with the keys `name` and `input`:\n\
```tool_call\n\
{{\"name\": \"<tool name>\", \"input\": {{ ... }}}}\n\
```\n\
No other markup is executed, whatever your training says. \
{remaining} more reply(ies) in a format this runner cannot execute will stop this run."
        )));
        StepResult::Continue(ContinueReason::ToolCallFormatRejected)
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
        // The clock the terminal verdict reports. Started at the first failure
        // of the streak, not at the start of the run: "94 turns" and "three
        // 502s over four seconds" are different facts and the second one is
        // what says whether the retry policy was a serious attempt.
        let started = *state
            .connector_failure_since
            .get_or_insert_with(std::time::Instant::now);
        // A size refusal is not a connector failure: the request was ours and
        // it was too big. Retrying sends the same oversized body again, and
        // reporting `ConnectorFatal` points the operator at a service that did
        // exactly what its contract says.
        if error.is_request_too_large() {
            return StepResult::Terminal(TerminalReason::RequestTooLarge, None);
        }
        let edge = error.is_edge_gateway_failure();
        let limit = if edge {
            self.config.edge_retry_limit
        } else {
            self.config.connector_retry_limit
        };
        // Attempts of THIS turn, the failed first dispatch included — the
        // number an operator counts in the log, not the retry counter.
        let attempts = state.connector_retries.saturating_add(1);
        if !error.is_transient() {
            state.terminal_detail = Some(connector_fatal_detail(
                error,
                attempts,
                started.elapsed(),
                FatalCause::NotRetryable,
            ));
            return StepResult::Terminal(TerminalReason::ConnectorFatal, None);
        }
        if state.connector_retries >= limit {
            state.terminal_detail = Some(connector_fatal_detail(
                error,
                attempts,
                started.elapsed(),
                FatalCause::RetriesSpent { limit, edge },
            ));
            return StepResult::Terminal(TerminalReason::ConnectorFatal, None);
        }
        let requested = retry_pause(
            error,
            state.connector_retries.saturating_add(1),
            self.config.connector_retry_backoff,
            edge,
        );
        let Some(wait) = plan_retry_pause(
            requested,
            state.connector_retry_pause_spent,
            self.config.connector_retry_pause_budget,
        ) else {
            state.terminal_detail = Some(connector_fatal_detail(
                error,
                attempts,
                started.elapsed(),
                FatalCause::PauseBudgetSpent {
                    budget: self.config.connector_retry_pause_budget,
                },
            ));
            return StepResult::Terminal(TerminalReason::ConnectorFatal, None);
        };
        state.connector_retries = state.connector_retries.saturating_add(1);
        state.connector_retry_pause_spent = state.connector_retry_pause_spent.saturating_add(wait);
        eprintln!(
            "{}",
            retry_line(error, wait, state.connector_retries, limit, edge)
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
    /// A2-225 changed what bounds the fold-back. It used to be a count —
    /// three consecutive refusals of any kind and the run was over — and pilot
    /// A2-204c4 died on it after twenty executed tool calls, because three
    /// refusals happened to land in a row at the end. The bound is now the
    /// **repeat**: a call already refused at this layer, sent again
    /// unchanged, ends the run, because the fold-back has demonstrably not
    /// worked. Genuinely new mistakes keep getting answered, bounded by
    /// `max_turns` and the cost cap like everything else a run spends.
    ///
    /// Only [`RECOVERABLE_DENIAL_LAYERS`] fold back at all; a policy layer is
    /// terminal on its first refusal, as before.
    ///
    /// Nothing executed either way: `tool_calls` is not incremented here, so a
    /// run whose every call was refused still reports zero work done.
    fn fold_denial(
        state: &mut RunState,
        name: &str,
        layer: &'static str,
        reason: &str,
        input: &Value,
    ) -> StepResult {
        // Whatever ends the run says which layer refused, which tool, and what
        // the error was. `PermissionDenied` alone made a misspelt argument and
        // an operator-written policy rule read identically in the done-marker,
        // where the pilot reported `"error": null`.
        let detail = format!("{layer} layer refused `{name}`: {reason}");
        if !denial_is_recoverable(layer) {
            state.terminal_detail = Some(detail);
            return StepResult::Terminal(TerminalReason::PermissionDenied, None);
        }
        // The fingerprint is the call, not the message: two different bad
        // arguments can produce the same validation sentence, and that is a
        // model still trying rather than a model stuck.
        let fingerprint = format!("{layer}\u{1f}{name}\u{1f}{input}");
        let refusals = state
            .refused_calls
            .entry(fingerprint)
            .and_modify(|n| *n = n.saturating_add(1))
            .or_insert(1);
        if *refusals > MAX_DENIALS_PER_DISTINCT_CALL {
            state.terminal_detail = Some(format!(
                "{detail} — and this is the same call again, unchanged, for the \
{refusals}(th) time, after being told that"
            ));
            return StepResult::Terminal(TerminalReason::PermissionDenied, None);
        }
        // Phrased as a fact about the machine, like `NO_ACTION_NUDGE`: what did
        // not happen, why, and what the model has to change. The one rule it is
        // on is stated, because a model that does not know re-sending is fatal
        // cannot choose to try something else instead.
        state.history.push(HistoryEntry::ToolResult {
            name: name.to_owned(),
            content: format!(
                "REJECTED at the {layer} layer — the call was NOT executed and nothing happened: \
{reason}. Fix the call itself and send exactly one corrected `tool_call` block. Sending this \
same call again, unchanged, ends the run."
            ),
        });
        StepResult::Continue(ContinueReason::ToolCallRejected)
    }

    /// Bound one tool result before it enters the transcript, keeping the
    /// whole of it where the model can still get at it.
    ///
    /// A single command decides whether the rest of the run happens: `git
    /// clone`, `cargo test` and `find` all return more text than an entire
    /// request may contain, and the old loop carried every character of it
    /// into every later turn until the connector refused the request. Bounding
    /// at ingestion — rather than trimming later, when the transcript is
    /// already too big — is what makes the request fit *by construction*.
    ///
    /// Nothing is destroyed. With a spill directory configured the untouched
    /// output is written to a file inside the workspace and the elision marker
    /// names it, so "read the last 200 lines of that output" is one tool call
    /// away. A failed write is not fatal: the result is still carried, elided,
    /// with a marker that does not promise a file that is not there.
    fn carry_tool_result(&self, state: &mut RunState, name: &str, content: String) -> String {
        let budget = self.config.tool_result_budget_units;
        if prompt_budget::fits(&content, budget) {
            return content;
        }
        let spilled = self.spill_tool_result(state, name, &content);
        prompt_budget::elide_middle(&content, budget, spilled.as_deref())
    }

    /// Keep a reply the loop refused to act on, exactly as it arrived.
    ///
    /// Returns the path to name in the log line, or `None` when no directory
    /// is configured or the write failed. A failed write is not fatal: the
    /// run was already going to correct or end on this reply, and turning a
    /// full disk into a second, different failure would hide the first.
    ///
    /// The file is named for the turn it belongs to, so it lines up with the
    /// `dispatch` audit records and with the `turns` count in the done
    /// marker. The reply is written as bytes with nothing prepended — a
    /// header would mean the file is no longer what the model sent, which is
    /// the one property it exists to have.
    fn save_rejected_reply(&self, state: &mut RunState, reply: &str) -> Option<String> {
        let dir = self.config.rejected_reply_dir.as_ref()?;
        state.rejected = state.rejected.saturating_add(1);
        let file = dir.join(format!("{:04}-turn{}.txt", state.rejected, state.attempts));
        std::fs::create_dir_all(dir).ok()?;
        std::fs::write(&file, reply).ok()?;
        Some(file.display().to_string())
    }

    /// Record the size of the request this turn is about to send.
    ///
    /// Sizes, never text: this crate's audit log is hashes-only for anything
    /// that could carry prompt content, and that rule is what makes it safe to
    /// keep under `$XDG_STATE_HOME` forever. But "how big was the request"
    /// is not content, and without it a run that died against the connector's
    /// 100 000-unit field limit left nothing at all to reconstruct from —
    /// the A2-216 post-mortem had to estimate the split from a token count and
    /// say so (`/home/dev/aup/arc2/runs/A2-216/report.md`, § 2).
    ///
    /// Written BEFORE the dispatch and fail-closed, like every other append in
    /// this crate: a turn whose size could not be recorded must not be one the
    /// operator is nevertheless charged for.
    fn record_dispatch(&self, turn: u32, model: &str, prompt: &str) -> Option<StepResult> {
        let fields = serde_json::json!({
            "turn": turn,
            "model": model,
            "prompt_utf16": prompt_budget::utf16_units(prompt),
            // `null`, not `0`, when there is no system prompt: an absent field
            // and an empty one are different requests.
            "system_prompt_utf16": self
                .config
                .system_prompt
                .as_deref()
                .map(prompt_budget::utf16_units),
        });
        match self.executor.record_run_event("dispatch", &fields) {
            Ok(()) => None,
            Err(_) => Some(StepResult::Terminal(TerminalReason::AuditFatal, None)),
        }
    }

    /// Append this dispatch's exact request to the operator's transcript file.
    ///
    /// Only when they asked for one. The system prompt is written with the
    /// first dispatch alone — it does not change during a run, and repeating
    /// it every turn would treble a file whose reason for existing is that it
    /// is readable.
    fn save_transcript(&self, state: &mut RunState, turn: u32, prompt: &str) {
        let Some(path) = self.config.transcript_path.as_ref() else {
            return;
        };
        if state.transcript_broken {
            return;
        }
        let system = self.config.system_prompt.as_deref().unwrap_or("");
        let mut block = format!(
            "===== dispatch {turn} — prompt {} units, systemPrompt {} units =====\n",
            prompt_budget::utf16_units(prompt),
            prompt_budget::utf16_units(system),
        );
        if turn == 1 {
            block.push_str("--- systemPrompt ---\n");
            block.push_str(system);
            block.push_str("\n--- prompt ---\n");
        }
        block.push_str(prompt);
        block.push('\n');
        let written = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| std::io::Write::write_all(&mut file, block.as_bytes()));
        if let Err(err) = written {
            // Once per run. A disk that cannot take the first block cannot
            // take the thirtieth either, and one fact deserves one line.
            state.transcript_broken = true;
            eprintln!(
                "arcana: the transcript could not be written to {}: {err} — the run continues \
                 without one",
                path.display()
            );
        }
    }

    /// Write the full output to the spill directory; return the path to name
    /// in the marker, relative to the spill root's parent when it is inside
    /// the workspace the model works in.
    fn spill_tool_result(&self, state: &mut RunState, name: &str, content: &str) -> Option<String> {
        let dir = self.config.tool_output_spill_dir.as_ref()?;
        state.spilled = state.spilled.saturating_add(1);
        // The tool name reaches this through the model; a call named
        // `../../etc/cron.d/x` must not choose the path. Only the characters a
        // tool name may legally contain survive.
        let safe: String = name
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
            .take(32)
            .collect();
        let file = dir.join(format!("{:04}-{}.txt", state.spilled, safe));
        std::fs::create_dir_all(dir).ok()?;
        std::fs::write(&file, content).ok()?;
        Some(file.display().to_string())
    }

    /// Reuse-only tool turn: cascade → `pre_tool` → dispatch → `post_tool`, folding
    /// results into `history`. A dispatch error folds back as a tool-result
    /// string (recoverable, bounded by `max_turns`) rather than terminating,
    /// and so does a denial at one of the [`RECOVERABLE_DENIAL_LAYERS`].
    async fn run_tool_turn(&self, state: &mut RunState, name: &str, input: Value) -> StepResult {
        let ctx = HookContext::new(self.cancel.clone(), self.cost.clone());
        // The call as the model wrote it, kept for the refusal fingerprint.
        // The executor consumes the value, and a denial has to be able to say
        // whether this is the same call the model already sent.
        let attempted = input.clone();
        let capability = match self.executor.execute(&ctx, name, input).await {
            Ok(capability) => capability,
            Err(CapabilityError::Denied { layer, reason }) => {
                return Self::fold_denial(state, name, layer, &reason, &attempted);
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
        // The refusal memory is consecutive, so a call that ran clears it.
        // Otherwise a long, mostly-healthy run that made the same slip twice an
        // hour apart would die on the second — and the bound is meant for a
        // model stuck in one place, not for a run with a long memory.
        state.refused_calls.clear();
        // Same argument for the format streak: a call that executed is proof
        // the model can write one this runner reads.
        state.malformed_calls = 0;
        let content = self.carry_tool_result(state, name, capability.output.content);
        state.history.push(HistoryEntry::ToolResult {
            name: name.to_owned(),
            content,
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
/// longer than any operator expects a single turn to take. It wins over both
/// schedules below, because it is the only one of the three that is a
/// statement about this particular upstream at this particular moment.
///
/// Failing that: a gateway failure gets the exponential schedule, and anything
/// else keeps the flat `fallback` it has always had. `retry` is 1-based — the
/// first re-dispatch of the turn is 1.
fn retry_pause(error: &ConnectorError, retry: u32, fallback: Duration, edge: bool) -> Duration {
    if let Some(secs) = error.retry_after_secs() {
        return Duration::from_secs(secs).min(MAX_RETRY_AFTER);
    }
    if edge {
        return edge_backoff_pause(retry, fallback, jitter_permille());
    }
    fallback
}

/// One pause of the bounded exponential gateway schedule, with jitter.
///
/// Nominal is `base * 2^(retry - 1)`, capped at [`MAX_EDGE_RETRY_PAUSE`]: with
/// the shipped 2 s base that is **2 s, 4 s, 8 s, 16 s, 30 s** — 60 s of sleep
/// across the five re-dispatches [`DEFAULT_EDGE_RETRY_LIMIT`] allows, which is
/// the worst-case wall time this schedule adds to a turn.
///
/// Jitter only ever SHORTENS a pause (the factor is `0.5 ..= 1.0` of nominal),
/// so the worst case above is a real ceiling rather than an average. Jitter is
/// not decoration: an edge that drops a burst of requests hands every client
/// the same failure at the same instant, and a fleet of runs that all wake at
/// exactly 2 s re-creates the burst that took the edge down. `permille` is the
/// randomness, passed in so the schedule is a pure function and can be pinned.
fn edge_backoff_pause(retry: u32, base: Duration, permille: u32) -> Duration {
    let steps = retry.saturating_sub(1).min(16);
    let nominal = base
        .saturating_mul(1_u32 << steps)
        .min(MAX_EDGE_RETRY_PAUSE);
    // 500..=1000 permille of nominal. Integer arithmetic on nanos: the pauses
    // are seconds-scale, so u128 cannot overflow and no float rounding can
    // push a pause above nominal.
    let factor = 500 + u128::from(permille.min(1000)) / 2;
    let nanos = nominal.as_nanos() * factor / 1000;
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

/// Jitter source: the sub-second part of the wall clock.
///
/// Deliberately not a `rand` dependency. The property needed here is that two
/// runners failing on the same edge burst do not wake together, and the
/// nanosecond the process reaches this line is already uncorrelated between
/// them. A clock that refuses to answer yields the full pause, which is the
/// conservative direction.
fn jitter_permille() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1000, |since| since.subsec_nanos() % 1001)
}

/// Clamp a requested pause to what is left of the turn's sleep budget.
///
/// `None` means the budget is spent and the run must stop instead of sleeping
/// again — a bound on the sum of pauses, which no per-pause cap can express.
fn plan_retry_pause(requested: Duration, spent: Duration, budget: Duration) -> Option<Duration> {
    let remaining = budget.checked_sub(spent).unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return None;
    }
    Some(requested.min(remaining))
}

/// Why the loop stopped re-dispatching.
#[derive(Debug, Clone, Copy)]
enum FatalCause {
    /// The same request would fail the same way — a 404 connector id, a bad
    /// key, an envelope the upstream marked non-retryable.
    NotRetryable,
    /// Every re-dispatch this class is allowed has been made.
    RetriesSpent { limit: u32, edge: bool },
    /// The turn has slept as long as it may.
    PauseBudgetSpent { budget: Duration },
}

/// The line a run that died on the connector leaves behind, in the marker's
/// `error` field and on stderr.
///
/// Pilot A2-204c5 ended `ConnectorFatal` with `"error": null` and the single
/// stderr line `the Model Connector could not complete the request` — which
/// named neither the status, nor how many times it had been tried, nor over
/// how long. Three 502s in four seconds and an upstream down for an hour read
/// identically, and only one of them is a retry policy that was too short.
/// A2-225 gave denials this treatment; this is the connector's half.
fn connector_fatal_detail(
    error: &ConnectorError,
    attempts: u32,
    elapsed: Duration,
    cause: FatalCause,
) -> String {
    let why = match cause {
        FatalCause::NotRetryable => {
            "not retryable — the same request would fail the same way".to_owned()
        }
        FatalCause::RetriesSpent { limit, edge } => {
            let class = if edge {
                "transient gateway failure in front of the Model Connector"
            } else {
                "transient connector failure"
            };
            format!("the {limit} re-dispatch(es) allowed for a {class} are spent")
        }
        FatalCause::PauseBudgetSpent { budget } => format!(
            "the {}s this turn may spend waiting between re-dispatches are spent",
            budget.as_secs()
        ),
    };
    format!(
        "{} after {attempts} attempt(s) over {} — {why}: {}",
        error.status_label(),
        format_elapsed(elapsed),
        error.detail_text()
    )
}

/// The line printed before each re-dispatch.
///
/// Pure so its shape can be pinned without capturing stdio. It says one thing
/// the old line did not: whether this re-dispatch may be paid for twice. See
/// [`ConnectorError::response_may_have_been_completed_upstream`] — Model
/// Connector settles the charge before the response reaches the socket, and
/// `arcana` sends no `Idempotency-Key`, so a request the edge cut may already
/// have been executed and billed. An operator reconciling a bill needs that in
/// the log, not in a mandate nobody reads at 3 a.m.
fn retry_line(
    error: &ConnectorError,
    wait: Duration,
    retry: u32,
    limit: u32,
    edge: bool,
) -> String {
    let class = if edge {
        format!(
            "{} is the gateway in front of the Model Connector, not the Model Connector — ",
            error.status_label()
        )
    } else {
        String::new()
    };
    let duplicate = if error.response_may_have_been_completed_upstream() {
        " — the cut request may already have been executed and charged upstream, \
so this re-dispatch may be a paid duplicate"
    } else {
        ""
    };
    format!(
        "arcana: {class}retrying this turn in {} ({retry} of {limit}){duplicate}",
        format_elapsed(wait)
    )
}

/// A duration as an operator reads it: whole seconds past ten, one decimal
/// below, so `0.3s` and `63s` both say something.
fn format_elapsed(d: Duration) -> String {
    if d.as_secs() >= 10 {
        // Rounded through the integer parts rather than through `f64`: this
        // string ends up in a done-marker a script may parse.
        let rounded = d.as_secs() + u64::from(d.subsec_millis() >= 500);
        format!("{rounded}s")
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
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

/// Exhaustive over all 10 `ContinueReason` variants.
fn reduce_continue(reason: ContinueReason) -> LoopControl {
    match reason {
        ContinueReason::ToolResultsReady
        | ContinueReason::HookContinuation
        | ContinueReason::ReactiveCompactRetry
        | ContinueReason::MicrocompactCompleted
        | ContinueReason::NoActionRetry
        | ContinueReason::ConnectorRetry
        | ContinueReason::ToolCallRejected
        | ContinueReason::MaxOutputTokensRecovery
        | ContinueReason::ToolCallFormatRejected => LoopControl::Reloop,
        // Inert under the unary Phase-C connector (no streaming, no token
        // cursor): a documented no-op re-loop — never
        // `unreachable!`/`panic!` (clippy `panic = warn` under `-D warnings`).
        ContinueReason::CollapseDrainRetry => {
            tracing::debug!(
                ?reason,
                "inert streaming Continue variant under unary connector; no-op re-loop"
            );
            LoopControl::Reloop
        }
    }
}

/// Exhaustive over every `TerminalReason` variant.
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
        | TerminalReason::NoAction
        | TerminalReason::ResponseTruncated
        | TerminalReason::UnsupportedToolCallFormat
        | TerminalReason::RequestTooLarge => LoopControl::Stop(reason),
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod terminal_reason_tests {
    use super::TerminalReason;

    /// Every variant, so a new one cannot be added without deciding what the
    /// operator is told when it fires.
    /// The list said "every variant" and held ten of them while the enum had
    /// twelve: `ResponseTruncated` and `UnsupportedToolCallFormat` were added
    /// with their explanations and never checked here, because a `const` array
    /// with an explicit length is not an exhaustive match and the compiler has
    /// nothing to say about it. Kept as an array rather than a match on a
    /// sample value so the length is visible; the test below asserts it
    /// against the enum's own count.
    const ALL: [TerminalReason; 13] = [
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
        TerminalReason::ResponseTruncated,
        TerminalReason::UnsupportedToolCallFormat,
        TerminalReason::RequestTooLarge,
    ];

    /// A variant added to the enum without being added to [`ALL`] is a
    /// compile error here, not a silently unchecked variant.
    #[test]
    fn the_list_holds_every_variant() {
        fn count(reason: TerminalReason) -> usize {
            // Exhaustive by construction: adding a variant fails to compile
            // until it is given an index, and the indices must cover 0..N.
            match reason {
                TerminalReason::Completed => 0,
                TerminalReason::MaxTurns => 1,
                TerminalReason::MaxCostUsd => 2,
                TerminalReason::AbortedByOperator => 3,
                TerminalReason::AbortedByHook => 4,
                TerminalReason::PermissionDenied => 5,
                TerminalReason::ContextWindowExhausted => 6,
                TerminalReason::ConnectorFatal => 7,
                TerminalReason::AuditFatal => 8,
                TerminalReason::NoAction => 9,
                TerminalReason::ResponseTruncated => 10,
                TerminalReason::UnsupportedToolCallFormat => 11,
                TerminalReason::RequestTooLarge => 12,
            }
        }
        let mut seen = [false; ALL.len()];
        for reason in ALL {
            seen[count(reason)] = true;
        }
        assert!(
            seen.iter().all(|hit| *hit),
            "ALL does not cover every TerminalReason variant"
        );
    }

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod connector_retry_tests {
    use super::{
        connector_fatal_detail, edge_backoff_pause, jitter_permille, plan_retry_pause, retry_line,
        retry_pause, FatalCause, DEFAULT_CONNECTOR_RETRY_PAUSE_BUDGET, DEFAULT_EDGE_RETRY_LIMIT,
        MAX_EDGE_RETRY_PAUSE, MAX_RETRY_AFTER,
    };
    use crate::connector::ConnectorError;
    use std::time::Duration;

    const BASE: Duration = Duration::from_secs(2);

    fn edge_502() -> ConnectorError {
        ConnectorError::Http {
            status: 502,
            message: "upstream returned a non-contract error body (16 bytes): error code: 502"
                .into(),
            retry_after: None,
        }
    }

    /// The schedule, stated: 2, 4, 8, 16, 30 seconds. Written out rather than
    /// computed, so a change to the arithmetic has to change the number an
    /// operator was promised.
    #[test]
    fn the_gateway_schedule_is_two_four_eight_sixteen_thirty() {
        let nominal: Vec<u64> = (1..=DEFAULT_EDGE_RETRY_LIMIT)
            .map(|retry| edge_backoff_pause(retry, BASE, 1000).as_secs())
            .collect();
        assert_eq!(nominal, vec![2, 4, 8, 16, 30]);
    }

    /// The number the card asks for: worst-case wall time this schedule adds.
    #[test]
    fn the_worst_case_added_wall_time_is_sixty_seconds_of_sleep() {
        let worst: u64 = (1..=DEFAULT_EDGE_RETRY_LIMIT)
            .map(|retry| edge_backoff_pause(retry, BASE, 1000).as_secs())
            .sum();
        assert_eq!(worst, 60, "five gateway re-dispatches sleep at most 60s");
        assert!(
            Duration::from_secs(worst) <= DEFAULT_CONNECTOR_RETRY_PAUSE_BUDGET,
            "the shipped schedule must fit inside the total budget without ever \
             reaching it, or the budget would silently truncate it"
        );
    }

    /// Jitter shortens, never lengthens — which is what makes the 60 s above a
    /// ceiling rather than an average.
    #[test]
    fn jitter_only_ever_shortens_a_pause() {
        for retry in 1..=DEFAULT_EDGE_RETRY_LIMIT {
            let nominal = edge_backoff_pause(retry, BASE, 1000);
            for permille in [0_u32, 1, 250, 499, 500, 750, 999, 1000, 9999] {
                let pause = edge_backoff_pause(retry, BASE, permille);
                assert!(pause <= nominal, "retry {retry}, permille {permille}");
                assert!(
                    pause * 2 >= nominal,
                    "a pause below half of nominal is not jitter, it is a \
                     different schedule: retry {retry}, permille {permille}"
                );
            }
        }
    }

    /// The doubling is capped, so raising the limit cannot produce a pause
    /// nobody chose.
    #[test]
    fn no_single_pause_exceeds_the_cap_however_far_the_schedule_runs() {
        for retry in 1..=64 {
            assert!(edge_backoff_pause(retry, BASE, 1000) <= MAX_EDGE_RETRY_PAUSE);
        }
    }

    /// A zero base flattens the schedule — the property the integration tests
    /// rely on to run without sleeping.
    #[test]
    fn a_zero_base_yields_no_pause_at_all() {
        for retry in 1..=DEFAULT_EDGE_RETRY_LIMIT {
            assert!(edge_backoff_pause(retry, Duration::ZERO, 1000).is_zero());
        }
    }

    #[test]
    fn the_clock_jitter_source_stays_inside_its_range() {
        for _ in 0..1000 {
            assert!(jitter_permille() <= 1000);
        }
    }

    /// An upstream that named a `retryAfter` wins over both schedules, still
    /// capped.
    #[test]
    fn a_named_retry_after_overrides_the_schedule() {
        let named = ConnectorError::Http {
            status: 503,
            message: "upstream returned a non-contract error body (4 bytes): busy".into(),
            retry_after: Some(7),
        };
        assert_eq!(
            retry_pause(&named, 1, BASE, true),
            Duration::from_secs(7),
            "the upstream knows its own cooldown"
        );
        let absurd = ConnectorError::Http {
            status: 503,
            message: "upstream returned a non-contract error body (4 bytes): busy".into(),
            retry_after: Some(15_681),
        };
        assert_eq!(retry_pause(&absurd, 1, BASE, true), MAX_RETRY_AFTER);
    }

    /// Anything that is not a gateway verdict keeps the flat pause it has
    /// always had.
    #[test]
    fn a_non_gateway_failure_keeps_the_flat_backoff() {
        let logical = ConnectorError::Logical {
            http_status: 201,
            kind: "network_error".into(),
            message: "The operation was aborted due to timeout".into(),
            retryable: true,
            recommendation: "retry".into(),
            retry_after: None,
            first_dispatch_observation: None,
        };
        for retry in 1..=4 {
            assert_eq!(retry_pause(&logical, retry, BASE, false), BASE);
        }
    }

    /// The sum of the pauses is bounded, and the bound is reported rather than
    /// silently turning a wait into no wait.
    #[test]
    fn the_pause_budget_clamps_then_refuses() {
        let budget = Duration::from_secs(120);
        assert_eq!(
            plan_retry_pause(Duration::from_secs(60), Duration::ZERO, budget),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            plan_retry_pause(Duration::from_secs(60), Duration::from_secs(90), budget),
            Some(Duration::from_secs(30)),
            "the last pause is shortened to what is left, not granted in full"
        );
        assert_eq!(
            plan_retry_pause(Duration::from_secs(60), Duration::from_secs(120), budget),
            None
        );
        assert_eq!(
            plan_retry_pause(Duration::from_secs(1), Duration::ZERO, Duration::ZERO),
            None,
            "a zero budget buys no re-dispatch at all"
        );
    }

    /// Two 60 s `retryAfter` values are all the budget allows — the case the
    /// per-pause cap cannot express.
    #[test]
    fn a_hostile_retry_after_cannot_park_a_turn_past_the_budget() {
        let mut spent = Duration::ZERO;
        let mut granted = 0;
        while let Some(pause) =
            plan_retry_pause(MAX_RETRY_AFTER, spent, DEFAULT_CONNECTOR_RETRY_PAUSE_BUDGET)
        {
            spent += pause;
            granted += 1;
        }
        assert_eq!(granted, 2);
        assert_eq!(spent, DEFAULT_CONNECTOR_RETRY_PAUSE_BUDGET);
    }

    /// The retry log says the thing an operator reconciling a bill needs.
    #[test]
    fn a_gateway_retry_warns_that_the_re_dispatch_may_be_paid_for_twice() {
        let line = retry_line(&edge_502(), Duration::from_secs(4), 2, 5, true);
        assert!(line.contains("HTTP 502"), "{line}");
        assert!(line.contains("(2 of 5)"), "{line}");
        assert!(line.contains("gateway"), "{line}");
        assert!(
            line.contains("may be a paid duplicate"),
            "Model Connector settles the charge before the response reaches the \
             socket, and we send no Idempotency-Key: {line}"
        );
    }

    /// An envelope Model Connector authored means the provider call failed and
    /// the hold was released — nothing was charged, so the line must not cry
    /// duplicate.
    #[test]
    fn a_retry_of_a_failure_model_connector_reported_claims_no_duplicate() {
        let logical = ConnectorError::Logical {
            http_status: 201,
            kind: "network_error".into(),
            message: "The operation was aborted due to timeout".into(),
            retryable: true,
            recommendation: "retry".into(),
            retry_after: None,
            first_dispatch_observation: None,
        };
        let line = retry_line(&logical, Duration::from_secs(2), 1, 2, false);
        assert!(!line.contains("duplicate"), "{line}");
        assert!(line.contains("(1 of 2)"), "{line}");
    }

    /// A client-side timeout is the other way a completed, billed turn can be
    /// lost on the wire.
    #[test]
    fn a_client_timeout_also_warns_about_a_duplicate() {
        let timeout = ConnectorError::Timeout("timed out after 290s".into());
        let line = retry_line(&timeout, Duration::from_secs(2), 1, 2, false);
        assert!(line.contains("may be a paid duplicate"), "{line}");
    }

    /// The three facts the pilot's `"error": null` did not carry.
    #[test]
    fn the_fatal_detail_carries_status_attempts_and_elapsed() {
        let detail = connector_fatal_detail(
            &edge_502(),
            6,
            Duration::from_millis(63_400),
            FatalCause::RetriesSpent {
                limit: 5,
                edge: true,
            },
        );
        assert!(detail.contains("HTTP 502"), "{detail}");
        assert!(detail.contains("6 attempt(s)"), "{detail}");
        assert!(detail.contains("over 63s"), "{detail}");
        assert!(detail.contains("5 re-dispatch(es)"), "{detail}");
        assert!(detail.contains("error code: 502"), "{detail}");
    }

    /// Sub-ten-second elapsed times keep a decimal, because "three 502s over
    /// 4.1s" is the whole diagnosis and "over 4s" loses half of it.
    #[test]
    fn a_short_streak_is_reported_with_a_decimal() {
        let detail = connector_fatal_detail(
            &edge_502(),
            3,
            Duration::from_millis(4_100),
            FatalCause::RetriesSpent {
                limit: 2,
                edge: false,
            },
        );
        assert!(detail.contains("over 4.1s"), "{detail}");
    }
}

/// Pins the *exact* recoverable-denial policy against every layer name a
/// shipped cascade (or the executor itself) can hand to the agent loop as a
/// denial.
///
/// The constant this checks is a fail-closed default: a name that is not on
/// it is terminal. That is the safe direction, but it is also silent. A future
/// edit could add `hook_bridge` or `rule` to the set and make an
/// operator-owned refusal retryable without any test turning red. Measured on
/// `92a4a7a`, before this test existed: adding `destructive_command_floor`
/// broke three tests, adding `hook_bridge` or `rule` broke none.
///
/// The table below is that decision written down once: every name, the site
/// that emits it, and whether folding it back to the model is intended. The
/// set of recoverable names is compared against this table, not against a copy
/// of the constant, so an edit on either side — in the constant or in the
/// layer that produces the name — fails here.
#[cfg(test)]
#[allow(clippy::panic)]
mod recoverable_denial_layer_tests {
    use super::{denial_is_recoverable, RECOVERABLE_DENIAL_LAYERS};

    /// One layer name that can reach `denial_is_recoverable`.
    struct EmittedLayer {
        /// The exact string carried in `EvaluatedCapability::Denied::layer`.
        name: &'static str,
        /// Where the string is produced (or, for the executor's own literals,
        /// where the denial is built).
        emitted_at: &'static str,
        /// Whether `denial_is_recoverable(name)` must be true.
        recoverable: bool,
    }

    /// Every layer name the cascade can emit, and the decision for each.
    ///
    /// A name belongs here as soon as some code can hand it to the agent loop
    /// as a denial: a `PermissionLayer::name`, the executor's `registry` or
    /// `schema` literals, the fail-closed `cascade` tail, or the audited `hook`
    /// abort. Marking a layer recoverable is a claim that a corrected call
    /// exists; the operator-owned layers below are terminal because their
    /// answer does not change on a retry, and retrying one is a probe of a
    /// safety hook.
    const EMITTED_LAYERS: &[EmittedLayer] = &[
        EmittedLayer {
            name: "schema",
            emitted_at: "crates/core/src/execution.rs:146,154; permission/schema.rs:30",
            recoverable: true,
        },
        EmittedLayer {
            name: "registry",
            emitted_at: "crates/core/src/execution.rs:143",
            recoverable: true,
        },
        EmittedLayer {
            name: "workspace_boundary",
            emitted_at: "crates/cli/src/workspace.rs:486",
            recoverable: true,
        },
        EmittedLayer {
            name: "destructive_command_floor",
            emitted_at: "crates/cli/src/workspace.rs:455",
            recoverable: false,
        },
        EmittedLayer {
            name: "workspace_auto_allow",
            emitted_at: "crates/cli/src/workspace.rs:517",
            recoverable: false,
        },
        EmittedLayer {
            name: "hook_bridge",
            emitted_at: "crates/core/src/permission/hook_bridge.rs:50",
            recoverable: false,
        },
        EmittedLayer {
            name: "rule",
            emitted_at: "crates/core/src/permission/rule.rs:169",
            recoverable: false,
        },
        EmittedLayer {
            name: "interactive_auto",
            emitted_at: "crates/core/src/permission/interactive.rs:84",
            recoverable: false,
        },
        EmittedLayer {
            name: "interactive_readline",
            emitted_at: "crates/cli/src/permission_prompt.rs:281",
            recoverable: false,
        },
        EmittedLayer {
            name: "kb-read-canonical-input",
            emitted_at: "crates/cli/src/kb_read.rs:252",
            recoverable: false,
        },
        EmittedLayer {
            name: "kb-read-exact-allow",
            emitted_at: "crates/cli/src/kb_read.rs:271",
            recoverable: false,
        },
        EmittedLayer {
            name: "cascade",
            emitted_at: "crates/core/src/permission/mod.rs:121; execution.rs:215",
            recoverable: false,
        },
        EmittedLayer {
            name: "hook",
            emitted_at: "crates/core/src/execution.rs:269",
            recoverable: false,
        },
        EmittedLayer {
            name: "suspend",
            emitted_at: "crates/mcp/src/suspend.rs:84",
            recoverable: false,
        },
        EmittedLayer {
            name: "mcp_proceed",
            emitted_at: "crates/mcp/src/server.rs:325",
            recoverable: false,
        },
    ];

    #[test]
    fn recoverable_denial_layers_are_exactly_pinned() {
        // 1. Every name the cascade can emit has the decided answer.
        for layer in EMITTED_LAYERS {
            assert_eq!(
                denial_is_recoverable(layer.name),
                layer.recoverable,
                "layer `{}` (emitted at {}) must be {} but `denial_is_recoverable` says {}",
                layer.name,
                layer.emitted_at,
                if layer.recoverable {
                    "recoverable"
                } else {
                    "terminal"
                },
                if denial_is_recoverable(layer.name) {
                    "recoverable"
                } else {
                    "terminal"
                },
            );
        }

        // 2. The constant holds exactly the names this table marks recoverable:
        //    not one fewer (a layer silently made terminal) and not one more
        //    (a layer silently made retryable — the hole this test closes).
        let mut actual: Vec<&str> = RECOVERABLE_DENIAL_LAYERS.to_vec();
        actual.sort_unstable();
        let mut expected: Vec<&str> = EMITTED_LAYERS
            .iter()
            .filter(|layer| layer.recoverable)
            .map(|layer| layer.name)
            .collect();
        expected.sort_unstable();
        assert_eq!(
            actual, expected,
            "RECOVERABLE_DENIAL_LAYERS and the pinned table disagree"
        );

        // 3. The default stays closed: a name nobody decided on is terminal.
        for unknown in ["", "Schema", "hook-bridge", "no_such_layer"] {
            assert!(
                !denial_is_recoverable(unknown),
                "unknown layer `{unknown}` must be terminal, not recoverable"
            );
        }
    }
}
