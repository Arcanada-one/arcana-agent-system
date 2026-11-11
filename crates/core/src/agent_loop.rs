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
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, FirstDispatchMeasurementV0, IdempotencyKey,
    ModelConnector, UnverifiedFirstDispatchObservationV0,
};
use crate::cost::{CostSnapshot, CostTracker};
use crate::dispatch::{classify, ModelPolicy, SelectionContext};
use crate::execution::{AuditFailurePhase, CapabilityError, CapabilityExecutor, CapabilityOutput};
use crate::hooks::HookContext;
use crate::operation_intent::{
    Disposition, IntentError, IntentRecord, NewIntent, OperationIntentConfig, OperationSession,
};
use crate::prompt_budget::{
    self, DEFAULT_CONTEXT_BUDGET_UTF16_UNITS, DEFAULT_TOOL_RESULT_BUDGET_UTF16_UNITS,
    MC_FIELD_MAX_UTF16_UNITS,
};
use crate::tool_dialect::{self, DialectMatch};

mod in_flight;
mod recovery;

use self::recovery::{
    connector_fatal_detail, in_flight_poll_pause, jitter_permille, retry_line, FatalCause,
    RetryBudget, RetryClass,
};

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
/// Two: Model Connector has already spent its own server-side attempts by the
/// time the client sees a failure (a `deepseek` dispatch is tried twice, 30 s
/// each), so a third attempt is a genuine second chance and a tenth only
/// spends time and budget on an upstream that is down.
pub const DEFAULT_CONNECTOR_RETRY_LIMIT: u32 = 2;

/// Pause before re-dispatching when the upstream named no `retryAfter`, and
/// the first step of the gateway schedule below.
pub const DEFAULT_CONNECTOR_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Re-dispatches allowed after a transient GATEWAY failure, per turn.
///
/// Five, against two for failures Model Connector itself reports: the classes
/// heal on different clocks (see [`ConnectorError::is_edge_gateway_failure`]).
/// A gateway failure is a few bytes of Cloudflare, and two retries two seconds
/// apart are not a serious attempt to outlast an edge. The backoff schedule
/// makes five affordable: about a minute of sleep instead of four seconds.
pub const DEFAULT_EDGE_RETRY_LIMIT: u32 = 5;

/// Ceiling on one pause of the gateway backoff schedule.
///
/// The schedule doubles, so without a ceiling the fifth pause would be 32 s
/// and a sixth 64 s, longer than most edges take to heal and than an operator
/// expects one turn to stall.
const MAX_EDGE_RETRY_PAUSE: Duration = Duration::from_secs(30);

/// Total time one turn may spend ASLEEP between re-dispatches, across every
/// retry class.
///
/// A per-pause cap bounds one wait; this bounds the sum, which is what an
/// unattended run's operator cares about. It binds hardest where the per-pause
/// cap cannot reach: an upstream-named `retryAfter` is honoured up to
/// [`MAX_RETRY_AFTER`] (60 s) each, so two exhaust this budget.
///
/// The default gateway schedule does NOT reach it: 2 + 4 + 8 + 16 + 30 = 60 s
/// nominal, and jitter only shortens a pause (see [`edge_backoff_pause`]). The
/// budget is the backstop for schedules this file does not control.
pub const DEFAULT_CONNECTOR_RETRY_PAUSE_BUDGET: Duration = Duration::from_secs(120);

/// What one dispatch is assumed to be allowed upstream when the connector
/// states nothing ([`crate::connector::ModelConnector::upstream_dispatch_budget`]).
///
/// Two minutes: the largest per-request default Model Connector applies to a
/// connector that names none (`src/connectors/orq/orq.connector.ts:88`,
/// `120_000` ms; the plain API base is `30_000`). It is a floor for the decision
/// it feeds (how long to wait for an answer already paid for): understating it
/// abandons paid turns, so the real client states its own.
pub const ASSUMED_UPSTREAM_DISPATCH_BUDGET: Duration = Duration::from_secs(120);

/// Grace on top of the upstream's own budget before the loop stops waiting for
/// an answer it has already bought.
///
/// Model Connector settles an intent (`state: 'completed'` with the stored
/// response) in the SAME transaction that writes the request row
/// (`src/connectors/connectors.service.ts:1355-1385`), so the answer is
/// replayable one database round trip after the provider returns. Thirty
/// seconds covers that, and waiting it is free: the hold that makes a retry a
/// replay lives for thirty MINUTES (`src/billing/intent.ts:36`,
/// `BILLING_HOLD_TTL_MS`), so this margin cannot risk paying twice.
pub const IN_FLIGHT_SETTLE_MARGIN: Duration = Duration::from_secs(30);

/// First pause of the in-flight poll schedule, and the step it doubles from.
///
/// Deliberately NOT `DriverConfig::connector_retry_backoff`: that is how long
/// to wait before asking a failed request AGAIN, this is how often to ask
/// whether an answer being produced has landed. A caller that zeroes the retry
/// backoff must not turn the in-flight wait into a hot loop.
const IN_FLIGHT_POLL_BASE: Duration = Duration::from_secs(2);

/// Ceiling on one pause of the in-flight poll schedule.
///
/// Shorter than [`MAX_EDGE_RETRY_PAUSE`] on purpose: a poll is a cheap 409 and
/// the answer arrives at an unpredictable moment, so a long pause only delays
/// a turn that is already finished.
const MAX_IN_FLIGHT_POLL_PAUSE: Duration = Duration::from_secs(15);

/// Consecutive re-dispatches allowed after a reply that the model's output
/// limit cut off, per run.
///
/// One. The re-dispatch tells the model to work in smaller pieces, so it is a
/// different request; a model cut off again right after being told why will not
/// split the work on a third ask, and every attempt costs a turn and money. The
/// counter resets on any reply that parses: only back-to-back cut-offs mean the
/// model cannot do what was asked.
const TRUNCATION_RETRY_LIMIT: u32 = 1;

/// Ceiling on an upstream-named `retryAfter`, so a hostile or mistaken value
/// cannot park an unattended run for hours.
///
/// Not hypothetical: an open circuit breaker upstream answers
/// `retryAfter: 15681` for a cooldown of 15.7 SECONDS (milliseconds on that
/// path, read as seconds everywhere else); uncapped, a run would wait hours.
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
    /// The variant was reserved for a streaming connector that could resume
    /// from a token cursor; the unary connector uses it for the same event (a
    /// reply cut off by the output limit), so it keeps the name.
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
/// it wrote the call, and it is told exactly what it is; sending the same call
/// again proves the fold-back is not working.
///
/// Refusals are counted per distinct call, not as a flat cap of consecutive
/// refusals of any kind: a flat cap ends runs over correctable mistakes yet
/// never catches a model alternating between two bad calls. Distinct mistakes
/// are bounded by `max_turns` and the cost cap; a repeat is terminal at once.
///
/// The memory is cleared by executed work and nothing else, in particular
/// **not** by a [`ContinueReason::ConnectorRetry`]. The two budgets are
/// independent: `RunState::connector_retries` asks "is the upstream answering",
/// this asks "is the model writing callable calls", and a run failing at both
/// must still stop. The reverse is deliberately not symmetric: any reply resets
/// the retry budget, including one the cascade then refused, because a refused
/// call proves the upstream is up. Pinned by
/// `crates/core/tests/driver_retry_denial_independence.rs`; the bound is
/// checked by `re_sending_an_already_refused_call_ends_the_run_and_says_why`.
pub const MAX_DENIALS_PER_DISTINCT_CALL: u32 = 1;

/// Replies in an unexecutable tool-call format a run tolerates before it ends
/// on [`TerminalReason::UnsupportedToolCallFormat`].
///
/// Two, so the model gets exactly one correction, one fewer than a schema
/// refusal's allowance: a schema denial tells the model something it could not
/// have known, while the wire format is already in the system prompt and the
/// correction restates it with the offending reply in view. A model that
/// ignores it twice will not read it a third time, and each attempt is a paid
/// dispatch.
///
/// Like the denial streak, the counter is consecutive: any tool call that
/// actually executes clears it, so a long run is not killed by two unrelated
/// format slips an hour apart.
pub const MAX_DIALECT_CORRECTIONS: u32 = 2;

/// History entries at the newest end of the transcript that compaction folds
/// only as a last resort.
///
/// The newest turns are the ones the next reply answers; folding them into a
/// summary hands the model a description of the question instead of the
/// question.
///
/// Six: a reply, a call and its result, twice over. The guard still folds into
/// this tail if the transcript does not otherwise fit the hard budget (a run
/// that stops is worse than a run that forgets), and
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
    /// Distinct from [`Self::Completed`] on purpose: a model that answers "The
    /// file has been created" without calling a tool must not yield a success
    /// receipt for work no tool did. Only [`DriverConfig::require_action`]
    /// runs can end here; an interactive turn may be a conversation.
    NoAction,
    /// Two replies in a row were cut off by the model's output limit before
    /// the `tool_call` block they had opened was complete.
    ///
    /// Distinct from [`Self::NoAction`] on purpose: "it would not act" and "it
    /// was not allowed to finish" call for opposite responses. The second is
    /// fixed by asking for smaller pieces or a model with a larger output
    /// limit, never by telling the model to try harder.
    ResponseTruncated,
    /// The model kept asking for a tool in a format this runner cannot
    /// execute, after being told the one it reads.
    ///
    /// Distinct from [`Self::NoAction`] on purpose: "the model would not act"
    /// and "the model acted in a dialect we threw away" look identical in a
    /// marker line but are fixed differently (in the runner or the prompt, never
    /// by telling the model to try harder).
    UnsupportedToolCallFormat,
    /// The request could not be made to fit the connector's request contract.
    ///
    /// Distinct from [`Self::ContextWindowExhausted`] on purpose. That one is
    /// about the MODEL's context window and is answered by a bigger model. This
    /// one is about the WIRE: Model Connector's `/execute` caps `prompt` and
    /// `systemPrompt` at [`crate::prompt_budget::MC_FIELD_MAX_UTF16_UNITS`]
    /// UTF-16 units each and rejects an over-long field with an HTTP 400 before
    /// any model is reached, so a larger model would not help and the refusal
    /// is not charged. Reporting it as `ConnectorFatal` would blame the
    /// connector for a limit the caller overran.
    RequestTooLarge,
}

impl TerminalReason {
    /// One sentence a paying customer can act on.
    ///
    /// A variant name is an implementation detail: fine as a trailing
    /// parenthetical for support, not as the whole message.
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
    /// site, where the call sites can disagree.
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
// Turn-interpretation seam
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

/// Classify a [`ConnectorResponse`] into an [`AssistantAction`].
/// Classify a [`ConnectorResponse`] into an [`AssistantAction`].
/// Convention: a single fenced block tagged `tool_call` whose body parses as
/// `{"name": <string>, "input": <json>}` is an intended tool call. A block
/// that was opened and never closed is [`AssistantAction::Truncated`].
///
/// Four outcomes, not two. A reply that names a tool in a way we recognise
/// (this runner's fence with an unusable body, `DeepSeek`'s native `invoke`
/// markup, a bare `OpenAI`-shaped JSON object) is an
/// [`AssistantAction::MalformedToolCall`], never an answer: reading it as prose
/// would end a run `Completed` having done nothing (`crate::tool_dialect`).
/// Only a reply with no tool-call attempt in it is [`AssistantAction::Final`].
///
/// Fail-closed still holds where it matters: the fallback is never an
/// unchecked dispatch. A [`AssistantAction::MalformedToolCall`] executes
/// nothing, and a translated call is subjected to the full permission cascade
/// downstream exactly like a canonical one — this seam only classifies.
#[must_use]
pub fn interpret(resp: &ConnectorResponse) -> AssistantAction {
    match scan_tool_call(&resp.result) {
        // An open fence is the only local evidence of truncation: Model
        // Connector's `ConnectorResponse` has no finish/stop reason
        // (`src/connectors/interfaces/connector.interface.ts:42`) and the
        // DeepSeek adapter drops the provider's `choices[].finish_reason`
        // (`src/connectors/deepseek/deepseek.connector.ts:4,82`). If that
        // contract grows the field, it becomes the primary signal and this scan
        // the fallback.
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
/// A pure function so the line can be pinned in a test. The tail matters:
/// `saved` is where the reply itself was kept, and an operator who cannot find
/// that path has nothing to diagnose from.
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

/// The operator's line for a tool call the permission cascade refused.
///
/// A denial must reach the operator's log: the reason goes to the model as a
/// tool result, so without this line the log shows a silent gap between turns.
#[must_use]
pub fn denied_call_line(layer: &str, tool: &str, reason: &str, saved: Option<&str>) -> String {
    format!(
        "arcana: the {layer} layer refused `{tool}` — {reason}; nothing was executed{}",
        saved.map_or_else(String::new, |path| format!(
            " — the call as the model wrote it is in {path}"
        ))
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
/// Three outcomes: a missing closing fence is distinct from malformed JSON,
/// because only the former means "the model was interrupted".
fn scan_tool_call(result: &str) -> ToolCallBlock<'_> {
    let Some(open) = result.find(TOOL_CALL_FENCE) else {
        return ToolCallBlock::Absent;
    };
    // `find` returns a char boundary and the fence is ASCII, so the slice is
    // always valid; `get` keeps that an ordinary `Absent` rather than a panic.
    let Some(rest) = result.get(open + TOOL_CALL_FENCE.len()..) else {
        return ToolCallBlock::Absent;
    };
    match closing_fence(rest) {
        Some(close) => rest.get(..close).map_or(ToolCallBlock::Absent, |body| {
            ToolCallBlock::Closed(body.trim())
        }),
        None => ToolCallBlock::Unterminated,
    }
}

/// Offset of the fence that CLOSES the block, or `None` if it never closed.
///
/// The closing fence is the first ```` ``` ```` that starts a line, not the
/// first one anywhere: a payload may contain fences, and since the body is JSON
/// a real newline cannot occur inside one of its string literals, so "at the
/// start of a line" is exactly the line between the model's markup and its
/// data. Taking the first fence anywhere cuts a valid `write` call whose
/// `content` holds ```` ```json ```` and leaves a slice that is not JSON.
fn closing_fence(rest: &str) -> Option<usize> {
    let mut from = 0usize;
    while let Some(hit) = rest.get(from..)?.find(CODE_FENCE) {
        let at = from + hit;
        // Line-initial: the very start of the body, or right after a newline.
        if at == 0 || rest.as_bytes().get(at.wrapping_sub(1)) == Some(&b'\n') {
            return Some(at);
        }
        from = at + CODE_FENCE.len();
    }
    None
}

/// Judge a complete block body.
///
/// Always a verdict, never a fall-through: either the call, or a
/// [`AssistantAction::MalformedToolCall`] that says what was wrong. Returning
/// `None` for invalid JSON or a missing `name` would deliver the runner's own
/// misspelt format as [`AssistantAction::Final`].
fn parse_tool_call(body: &str) -> AssistantAction {
    let malformed = |detail: String| AssistantAction::MalformedToolCall {
        dialect: CANONICAL_DIALECT,
        detail,
    };
    let value = match serde_json::from_str::<Value>(body) {
        Ok(value) => value,
        // A body that does not parse whole gets exactly one more reading, and
        // it is a truncation, never an edit: the JSON value at the front, kept
        // only when everything after it is surplus closing punctuation. See
        // [`tool_dialect::value_before_surplus_closers`] for why that is the
        // whole of the licence.
        Err(err) => {
            let Some(value) = tool_dialect::value_before_surplus_closers(body) else {
                return malformed(format!(
                    "the body of your `tool_call` block is not valid JSON ({err})"
                ));
            };
            value
        }
    };
    let Some(name) = value.get("name").and_then(Value::as_str) else {
        return malformed(
            "the body of your `tool_call` block has no `name` string, so no tool was named"
                .to_owned(),
        );
    };
    // `arguments` / `parameters` / `args` are accepted as `input`, and so are
    // arguments written as plain siblings of `name`; reading only `input` would
    // silently discard them and dispatch an empty call.
    //
    // The sibling form is safe to dispatch *here* because the model opened
    // this runner's own `tool_call` fence: inside markup whose only purpose is
    // to carry a call, the keys that are not `name` are the call's arguments
    // (`crate::tool_dialect`).
    //
    // No spelling and no siblings leaves nothing to recover: a `null` dispatched
    // into a tool that wants an object is a schema denial we can see coming, and
    // telling the model its call has no arguments serves it better than
    // "`null` is not an object".
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
// Conversation history
// ---------------------------------------------------------------------------

/// A run of older history entries replaced by one line that says what they
/// were.
///
/// Compaction records what it removed instead of deleting silently: a model
/// whose earlier work vanishes from the transcript re-does it, and an operator
/// cannot tell a run that never called a tool from one whose call was dropped.
/// The span keeps the *shape* of what it swallowed: how many entries, how many
/// were the model's own turns, which tools ran and how often, and how much text
/// went away.
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
// Context-window guard
// ---------------------------------------------------------------------------

/// Verdict of the context-window guard. Public so tests can assert the
/// compaction classification directly.
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
    /// Entries that are not tool results (model replies, tool-call arguments,
    /// injected context) shortened in place because one alone was a large share
    /// of the budget.
    ///
    /// Non-zero means the *model* wrote too much in one turn, which no ingestion
    /// bound covers; it is a different fact from `elided_results`.
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
    /// teaches the operator to skip its lines.
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
/// [`HistoryEntry::Task`] is excluded because a run that forgets what it was
/// asked is worse than a run that stops, and [`HistoryEntry::Compacted`]
/// because a summary is already the short form of something.
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
/// The anti-overshoot rule: cut what the transcript is over by, not everything
/// the entry has. Cutting to a fixed floor whether or not it is needed removes
/// far more than the arithmetic asks for.
fn shrink_to(entry_units: usize, excess: usize, hard_floor: usize) -> usize {
    entry_units
        .saturating_sub(excess)
        .max(hard_floor)
        .max(prompt_budget::MIN_ELISION_BUDGET)
}

/// Bring `history` within `budget` UTF-16 units, degrading in authority order,
/// and report what that cost.
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
/// # The band
///
/// Every stage aims at [`crate::prompt_budget::compaction_target`] and stops
/// at the first moment it is reached, and no single stage may remove more than
/// [`crate::prompt_budget::entry_ceiling`] at once. Together those two land
/// the pass at or above [`crate::prompt_budget::compaction_floor`] whenever
/// there was that much material to keep.
///
/// Stage 0 exists because a tool result is bounded at ingestion but a model
/// reply is not, and an entry larger than the whole budget cannot be
/// compensated for by folding anything else. The guard shortens it, keeping
/// head and tail and saying how much went, instead of deleting the rest of the
/// run and still not fitting.
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
/// budget: folding is oldest-first, so reaching one oversized entry at the
/// newest end costs every entry in front of it. Order here is oldest-first only
/// for determinism; an entry is touched because of its own size.
///
/// A tool result shortened here is reported as an elided result, not a bounded
/// entry (the same act as stage 1), so `bounded_entries` is exactly the count
/// of *model-written* entries that were too big.
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
/// is.
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
// Driver
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
    /// Units, not bytes: `String::len` is off by a factor of three on Russian
    /// or Chinese text and two on emoji, in the direction that sends an
    /// over-limit request. See [`crate::prompt_budget`].
    pub context_budget_units: usize,
    /// Ceiling on one tool result carried into the transcript, in UTF-16 code
    /// units. Output past it is elided head-and-tail with a marker that says
    /// how much went and where the whole of it still is.
    pub tool_result_budget_units: usize,
    /// Where a tool result too large to carry is kept in full.
    ///
    /// `None` (the default) means nothing is written to disk and the elision
    /// marker tells the model to narrow its call instead. A headless run sets
    /// it to a directory inside the workspace, so the path in the marker is one
    /// the model is allowed to read.
    pub tool_output_spill_dir: Option<std::path::PathBuf>,
    /// Where a reply this loop refused to act on is kept, verbatim.
    ///
    /// `None` (the default) means a rejected reply survives only as the log
    /// line saying it was rejected: the audit log keeps `input_hash` /
    /// `output_hash` and no text, and the transcript is never written to disk,
    /// so the discarded reply could not be diagnosed afterwards. A headless run
    /// sets this to a directory inside the workspace.
    ///
    /// It holds what the *model* sent, not what the runner made of it; a
    /// correction is only as good as the reply it was written against.
    pub rejected_reply_dir: Option<std::path::PathBuf>,
    /// Where a tool call the permission cascade refused is kept, with the
    /// reason it was refused for.
    ///
    /// `None` (the default) means a denial survives as `decision` / `layer` /
    /// `input_hash` and a `reason_hash` in the audit log, and the call itself is
    /// gone. A headless run sets this to a directory inside the workspace.
    ///
    /// It holds what the *model* wrote and what the cascade said back, the two
    /// halves a correction is judged against. It is the workspace counterpart
    /// of [`Self::rejected_reply_dir`], and the reason text lives here because
    /// the audit log refuses it: a refusal sentence quotes the argument or path
    /// that caused it.
    pub denied_call_dir: Option<std::path::PathBuf>,
    /// Append the exact request of every dispatch to this file.
    ///
    /// Off unless the operator names a path: a transcript is the whole
    /// conversation in clear text, so keeping one is a decision about their
    /// disk.
    ///
    /// Appended per dispatch rather than written once at the end, because
    /// compaction means the last request is not a superset of the earlier
    /// ones, and the folded turns are what a post-mortem cannot otherwise see.
    pub transcript_path: Option<std::path::PathBuf>,
    /// Opt-in paired-corpus metadata. The driver attaches it only to the first
    /// connector attempt; later tool-loop turns never inherit it.
    pub first_dispatch_measurement: Option<FirstDispatchMeasurementV0>,
    /// Exact prompt override applied only to the measured first connector
    /// attempt. It is invalid without `first_dispatch_measurement`.
    pub first_dispatch_prompt: Option<FirstDispatchPromptV0>,
    /// Per-turn model-selection policy. The classifier keys a
    /// [`crate::dispatch::TaskType`] off the turn context and the policy maps it
    /// to the model id written onto `ExecuteRequest.model`; the static `model`
    /// seeds this policy's `Default` fallback in [`Driver::new`].
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
    /// an upstream that is down stays down. Each retry consumes a turn and is
    /// checked against the cost cap like any other attempt.
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
    /// G07: durable model-operation intent. `None` (the default) keeps the
    /// in-process identity only, which a restart loses; `Some` makes every
    /// dispatch go through the private intent record
    /// ([`crate::operation_intent`]) and refuses when a native field is missing.
    pub operation_intent: Option<OperationIntentConfig>,
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
            denied_call_dir: None,
            transcript_path: None,
            first_dispatch_measurement: None,
            first_dispatch_prompt: None,
            policy: ModelPolicy::new(),
            require_action: false,
            connector_retry_limit: DEFAULT_CONNECTOR_RETRY_LIMIT,
            edge_retry_limit: DEFAULT_EDGE_RETRY_LIMIT,
            connector_retry_backoff: DEFAULT_CONNECTOR_RETRY_BACKOFF,
            connector_retry_pause_budget: DEFAULT_CONNECTOR_RETRY_PAUSE_BUDGET,
            operation_intent: None,
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
    /// Tool calls that reached the capability executor in this run.
    ///
    /// Intent, where [`Self::tool_calls`] is evidence: it counts the refused
    /// and the failed as well as the executed, so a model that called tools
    /// constantly with wrong arguments shows a large number here and a small
    /// one there.
    ///
    /// A reply this runner could not parse as a call never reached the
    /// executor and is not counted; a separate field would make this number
    /// mean two things.
    pub tool_calls_attempted: u32,
    /// Tool calls the permission cascade or a pre-tool hook refused.
    ///
    /// `tool_calls_attempted - tool_calls_denied - tool_calls` is what
    /// reached a tool and failed inside it.
    pub tool_calls_denied: u32,
    /// The tools that actually executed, by name, in call order.
    ///
    /// [`Self::tool_calls`] is this list's length, and a count cannot tell
    /// reading from writing: a run of nine `read`/`grep` calls with nothing
    /// written must not be reported as completed work; the names can.
    ///
    /// Names, not effects. `bash` can change a file and `read` cannot, but a
    /// `write` that produced the bytes already there changed nothing; what the
    /// run DID is decided by comparing the tree, not by reading this list.
    pub executed_tools: Vec<String>,
    /// Cost accounting snapshot at termination.
    pub cost: CostSnapshot,
    /// The ordered sequence of model ids selected, one per connector call
    /// The ordered sequence of model ids selected, one per connector call.
    /// Mirrors each `ExecuteRequest.model` in call order, making the
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
    /// that cause carried (which cascade layer refused, which tool, the
    /// validation error itself), so an operator can tell a policy refusal from
    /// a misspelt argument.
    pub terminal_detail: Option<String>,
}

/// The agent-loop driver. Borrows its collaborators; owns only run config and
/// the shared cost/cancel handles.
///
/// It adds **no new** `Tool`/`PermissionLayer`/`ToolHook` — every collaborator
/// is consumed through its existing signature.
pub struct Driver<'a> {
    connector: &'a dyn ModelConnector,
    executor: &'a CapabilityExecutor,
    cost: Arc<CostTracker>,
    cancel: CancellationToken,
    config: DriverConfig,
}

/// The request one dispatch of this turn carries, kept whole.
///
/// A poll for an answer the turn has already bought re-sends exactly this,
/// rather than rebuilding it from the history: the two must be the same
/// bytes (the key only replays while they are), and rebuilding costs a prompt
/// build and a transcript block per poll.
struct Dispatch<'a> {
    prompt: &'a str,
    model: &'a str,
}

/// What the recovery path made of a failed dispatch.
enum Recovered {
    /// The answer arrived after all — on a poll inside the in-flight wait,
    /// under the key the turn was dispatched with. It is a response like any
    /// other and takes the ordinary path through the step.
    Answered(Box<ConnectorResponse>),
    /// The step is over: a re-dispatch to make, or a verdict to report.
    Step(StepResult),
}

/// What one in-flight wait made of the turn it was waiting for.
enum Polled {
    /// The answer landed.
    Answered(Box<ConnectorResponse>),
    /// The wait ended the step — its deadline ran out, or the operator
    /// interrupted it.
    Stop(StepResult),
    /// A poll was refused by something other than "still in flight". The wait
    /// has no opinion on it; the ordinary recovery decides, with the counters
    /// it owns.
    Refused(ConnectorError),
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
/// told what did NOT happen and what encoding would make it happen. Asking it
/// to verify with a tool call gives it a way to be right that still produces
/// evidence.
const NO_ACTION_NUDGE: &str =
    "NOTHING WAS EXECUTED. Your last reply contained no tool call, so no \
command ran, no file was written, and the task is NOT done — printing a sentence is not an action. \
Reply now with exactly one fenced `tool_call` block that does the work. If you believe the task is \
already satisfied, prove it with a tool call (for example `read` the file you say you wrote) \
before you answer in prose.";

/// What the loop tells a model whose reply the output limit cut off.
///
/// It names the cause, because the model cannot see it: from where it sits the
/// turn simply ended, and the obvious next move is to send the same oversized
/// block again and be cut off at the same token.
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

/// The `Idempotency-Key` series one run dispatches under.
///
/// ## What the key buys
///
/// Model Connector opens a hold, calls the provider and settles the charge in
/// the same transaction as the request row **before** the response is written
/// to the socket. A turn the edge cut may therefore already have been executed
/// and billed, and without a key every re-dispatch is a second provider call
/// and a second charge.
///
/// A caller-supplied key closes it. `src/billing/intent.ts`: "An intent key is
/// supplied by the CALLER and identifies the thing they wanted done, not the
/// number of times the wire dropped while they asked for it." A repeat of a
/// key whose first attempt completed replays the stored response — one
/// provider call and one ledger row, however many times the client re-POSTs.
///
/// ## What "the same request" has to mean
///
/// The server checks the payload fingerprint BEFORE the intent state, and
/// answers a key reused for a different payload with `idempotency_key_reused`
/// rather than replaying the first one. So a key stable across an
/// attempt-series is only correct if the payload is too, and this type does
/// not assume it: it records [`ExecuteRequest::intent_fingerprint`] alongside
/// the key. If the payload changes under a key whose dispatch has had no reply
/// (G07: unknown outcome) it mints nothing and refuses with
/// `ConnectorError::ReconcileRequired`; a changed payload is a new operation.
///
/// The invariant is not local: the prompt is recomposed from history on every
/// attempt, the model id comes from a policy keyed on the turn index, and the
/// remaining cost budget is recomputed — three values with three owners that
/// must all be unchanged between a failed attempt and its re-dispatch. A
/// fingerprint that disagrees is a defect upstream of here, and this turns it
/// into a named refusal instead of a silent second paid dispatch.
/// What [`TurnIntentSeries::stamp`] did with the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentDecision {
    /// A new logical turn opened a new series. The ordinary case.
    New,
    /// This turn's key was reused, so an attempt that already completed
    /// upstream is replayed rather than charged again. The point of all this.
    Reused,
    /// A series was in force — a dispatch under its key produced no reply, so
    /// its outcome is unknown — and the payload changed under it. G07: the
    /// request is NOT dispatched and no key is minted; the original key and
    /// fingerprint stay in force and the operation must be reconciled first.
    Refused,
}

struct TurnIntentSeries {
    /// This run's half of the key. A v4 uuid, so the key is unique across
    /// runs, processes and hosts — two runs that happened to reach turn 7 with
    /// the same prompt must not replay each other's answers.
    run: u128,
    /// Logical turns started so far. Re-dispatches of one turn do not advance
    /// it; that is the entire point.
    turn: u64,
    /// The key in force, with the payload it was minted against.
    active: Option<(IdempotencyKey, [u8; 32])>,
    /// Dispatches stamped under the key in force. More than one means an
    /// earlier dispatch under it ended without a reply (outcome unknown).
    dispatches: u32,
    /// When the request the key in force identifies FIRST left this client.
    ///
    /// Lives here rather than in [`RunState`] because it measures the same
    /// thing the key does (one upstream request) and the two are minted and
    /// released together. A re-dispatch under the SAME key does not move it; it
    /// is the clock the in-flight wait is bounded against.
    dispatched_at: Option<Instant>,
    /// G07: the durable intent record of this run, when one is configured.
    session: Option<OperationSession>,
}

impl TurnIntentSeries {
    fn new() -> Self {
        Self {
            run: uuid::Uuid::new_v4().as_u128(),
            turn: 0,
            active: None,
            dispatches: 0,
            dispatched_at: None,
            session: None,
        }
    }

    /// [`Self::stamp`] behind the durable intent record.
    ///
    /// Order: reconcile what a previous process left, then (for a new
    /// operation) persist `pending`, and only then let the caller dispatch.
    /// Every `Err` means nothing may be sent.
    fn stamp_durable(
        &mut self,
        req: &mut ExecuteRequest,
        now: Instant,
    ) -> Result<IntentDecision, ConnectorError> {
        let refuse = |error: IntentError| ConnectorError::IntentRefused {
            code: error.code(),
            detail: error.to_string(),
        };
        let Some(session) = self.session.as_mut() else {
            return Ok(self.stamp(req, now));
        };
        let fingerprint = req.intent_fingerprint();
        if let Some(held) = session.held.clone() {
            // An unresolved operation from an earlier process holds the
            // identity. Never a fresh key, even for identical text.
            let held_fingerprint = IntentRecord::fingerprint_bytes(&held);
            if held_fingerprint != Some(fingerprint) {
                return Err(ConnectorError::ReconcileRequired {
                    key: held.idempotency_key,
                });
            }
            if !session.replay_verified {
                return Err(ConnectorError::IntentRefused {
                    code: "INTENT_UNKNOWN_OUTCOME_HELD",
                    detail: format!(
                        "an earlier dispatch under Idempotency-Key {} has an unknown outcome and \
                         connector replay of the same key is not verified",
                        held.idempotency_key
                    ),
                });
            }
            let Some(key) = IdempotencyKey::from_persisted(&held.idempotency_key) else {
                return Err(ConnectorError::IntentRefused {
                    code: "INTENT_RECORD_CORRUPT",
                    detail: "retained key is not in the shape this crate mints".to_owned(),
                });
            };
            // The SAME key and the same request: the connector replays the
            // stored response (verified by the composition root) instead of
            // charging again. Counted as a re-dispatch of the held operation.
            self.dispatches = self.dispatches.max(2);
            if self.active.is_none() {
                self.dispatched_at = Some(now);
            }
            self.active = Some((key.clone(), fingerprint));
            req.idempotency_key = Some(key);
            return Ok(IntentDecision::Reused);
        }
        let decision = self.stamp(req, now);
        if decision == IntentDecision::New {
            let key = req
                .idempotency_key
                .as_ref()
                .map(|key| key.as_str().to_owned())
                .unwrap_or_default();
            let intent = NewIntent {
                run_id: format!("{:032x}", self.run),
                turn: self.turn,
                provider: req.connector.clone(),
                model: req.model.clone(),
                request_fingerprint: fingerprint,
                idempotency_key: key,
            };
            let persisted = self
                .session
                .as_mut()
                .map_or(Ok(()), |session| session.persist_pending(&intent));
            if let Err(error) = persisted {
                // Not persisted, so not dispatched, so no key is in force.
                self.finish_turn();
                return Err(refuse(error));
            }
        }
        Ok(decision)
    }

    /// A dispatch produced no reply: record that its outcome is unknown.
    /// Best effort by design: `pending` is already the strict state on disk.
    fn note_no_reply(&mut self) {
        if let Some(session) = self.session.as_mut() {
            let _ = session.mark(Disposition::Unknown, None);
        }
    }

    /// A reply was observed for the key in force.
    fn note_reply(&mut self, response_id: &str) {
        if let Some(session) = self.session.as_mut() {
            if session
                .mark(Disposition::Reconciled, Some(response_id))
                .is_ok()
            {
                session.held = None;
            }
        }
    }

    /// Stamp `req` with the key its attempt-series is dispatched under, and say
    /// which of the three things happened.
    ///
    /// Returned rather than logged in place, because only the caller can print
    /// and the cases differ in newsworthiness: [`IntentDecision::New`] is every
    /// ordinary turn and must be silent, while [`IntentDecision::Refused`] is
    /// a refusal and must not be. Deciding that here with an `eprintln!` would
    /// make the difference unobservable from a test.
    fn stamp(&mut self, req: &mut ExecuteRequest, now: Instant) -> IntentDecision {
        let fingerprint = req.intent_fingerprint();
        let (key, decision) = match self.active.as_ref() {
            // Same payload as the attempt before it: the same key, and the
            // server replays rather than charges.
            Some((key, seen)) if *seen == fingerprint => {
                self.dispatches = self.dispatches.saturating_add(1);
                (key.clone(), IntentDecision::Reused)
            }
            // G07: a key is in force only while its dispatch has had no reply
            // (`finish_turn` clears it on any response), so its outcome is
            // unknown. A changed payload is a new operation and must not be
            // sent as an invisible retry under a fresh key.
            Some(_) => return IntentDecision::Refused,
            None => {
                let decision = IntentDecision::New;
                self.dispatches = 1;
                self.turn = self.turn.saturating_add(1);
                let key = IdempotencyKey::for_turn(self.run, self.turn);
                self.active = Some((key.clone(), fingerprint));
                // A fresh key is a fresh upstream request, so its wait clock
                // starts here.
                self.dispatched_at = Some(now);
                (key, decision)
            }
        };
        req.idempotency_key = Some(key);
        decision
    }

    /// A reply arrived, so the next dispatch is a new logical turn.
    ///
    /// Called on any response of any shape, for the same reason the retry
    /// budget resets there: the key identifies the question, and an answered
    /// question is not asked again. Carrying the key past a reply would make the
    /// next turn replay the previous turn's answer.
    fn finish_turn(&mut self) {
        self.active = None;
        self.dispatches = 0;
        self.dispatched_at = None;
    }

    /// When the request in force first left this client, if one is in force.
    const fn dispatched_at(&self) -> Option<Instant> {
        self.dispatched_at
    }

    /// Drop the key in force without ending the turn, so the next attempt of
    /// this same turn mints a fresh one.
    ///
    /// The one caller is the `idempotency_key_reused` path: the key belongs to
    /// a different payload, so nothing of ours was dispatched or charged under
    /// it and reusing it can only be refused again.
    ///
    /// G07: returns `false`, keeping the key, when more than one dispatch went
    /// out under it. Then an earlier one ended without a reply and may have been
    /// executed and charged, so a fresh-key redispatch could pay twice.
    fn abandon_key(&mut self) -> bool {
        if self.dispatches > 1 {
            return false;
        }
        self.active = None;
        self.dispatches = 0;
        self.dispatched_at = None;
        true
    }

    /// The key in force, for naming it in a refusal.
    fn active_key(&self) -> Option<&IdempotencyKey> {
        self.active.as_ref().map(|(key, _)| key)
    }
}

/// Mutable state threaded through every step of one run.
///
/// It exists so a new per-run fact is added in one place rather than as
/// another `&mut` parameter on a signature that already had four.
struct RunState {
    history: Vec<HistoryEntry>,
    /// Connector attempts consumed; enforces `max_turns`.
    attempts: u32,
    /// Ordered per-step model ids.
    selected: Vec<String>,
    first_dispatch_observation: Option<UnverifiedFirstDispatchObservationV0>,
    /// Tool calls the executor actually carried out.
    tool_calls: u32,
    /// The name of each of them, in call order.
    executed_tools: Vec<String>,
    /// Whether the one no-action nudge has been used.
    nudge_spent: bool,
    /// Consecutive transient connector failures since the last response.
    ///
    /// Counts the re-dispatches of a request that FAILED — a refusal Model
    /// Connector authored, or an edge verdict in front of it. It deliberately
    /// does not count the polls of `in_flight_polls`: sharing one counter would
    /// let the edge failure that preceded a conflict shrink the wait for the
    /// answer it interrupted.
    connector_retries: u32,
    /// Polls made over the whole run, for the `max_turns` exemption below.
    ///
    /// Separate from `in_flight_polls` because that one resets on every
    /// response, and the exemption has to hold across turns.
    in_flight_polls_total: u32,
    /// Polls made while THIS turn's answer is still being produced upstream.
    ///
    /// Its own counter because it measures a different fact (how often we
    /// asked whether the answer has landed, not how often the upstream refused
    /// us) and is not what bounds the wait; the clock is: see
    /// [`Driver::wait_out_in_flight`].
    in_flight_polls: u32,
    /// Time already slept between re-dispatches of the current turn.
    connector_retry_pause_spent: Duration,
    /// When the current streak of connector failures began. `None` while the
    /// upstream is answering; the terminal verdict reports its elapsed time.
    connector_failure_since: Option<Instant>,
    /// How often each call refused at a correctable layer has been sent since
    /// the last tool call that actually executed. A call whose count passes
    /// [`MAX_DENIALS_PER_DISTINCT_CALL`] ends the run.
    ///
    /// A map rather than a set because the bound is a NUMBER of refusals per
    /// distinct call, and a set can only express "one".
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
    /// Calls the cascade refused and the loop wrote out; also the denied
    /// file's number. Counted even when no directory is configured, so the
    /// number in the done-marker does not depend on where the run keeps its
    /// evidence.
    denied: u32,
    /// Calls that reached the executor, whatever became of them.
    tool_calls_attempted: u32,
    /// Whether a transcript append has already failed and been reported.
    /// One line per run, not one per turn: a full disk is one fact.
    transcript_broken: bool,
    /// The `Idempotency-Key` series this run dispatches under.
    intent: TurnIntentSeries,
}

impl RunState {
    fn new(task: &str) -> Self {
        Self {
            history: vec![HistoryEntry::Task(task.to_owned())],
            attempts: 0,
            selected: Vec::new(),
            first_dispatch_observation: None,
            tool_calls: 0,
            executed_tools: Vec::new(),
            nudge_spent: false,
            connector_retries: 0,
            in_flight_polls_total: 0,
            in_flight_polls: 0,
            connector_retry_pause_spent: Duration::ZERO,
            connector_failure_since: None,
            refused_calls: std::collections::HashMap::new(),
            truncation_retries: 0,
            malformed_calls: 0,
            compactions: 0,
            terminal_detail: None,
            spilled: 0,
            rejected: 0,
            denied: 0,
            tool_calls_attempted: 0,
            transcript_broken: false,
            intent: TurnIntentSeries::new(),
        }
    }

    /// Attempts this turn has made, the failed first dispatch included — the
    /// number an operator counts in the log.
    ///
    /// The sum of both counters, so the terminal verdict reports every attempt.
    fn turn_attempts(&self) -> u32 {
        self.connector_retries
            .saturating_add(self.in_flight_polls)
            .saturating_add(1)
    }

    /// Record a reply the loop could read.
    ///
    /// It is proof the model can still finish a turn, so the truncation budget
    /// starts over here rather than counting cut-offs across a whole run.
    ///
    /// A reply is bounded here, before it enters the transcript: tool results
    /// are bounded at ingestion, and an unbounded reply would only meet
    /// `entry_ceiling` inside compaction, after the budget was blown and the
    /// history folded to make room for one turn's output.
    ///
    /// `ceiling` is [`prompt_budget::entry_ceiling`] of the run's budget: the
    /// same number compaction would impose, applied before the damage. Nothing
    /// else changes: the call the loop executes and the answer it delivers are
    /// both taken from the complete reply, which this function is given after
    /// both have been read.
    fn accept_reply(&mut self, text: &str, ceiling: usize) {
        self.truncation_retries = 0;
        self.history
            .push(HistoryEntry::Assistant(prompt_budget::elide_reply(
                text, ceiling,
            )));
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

    /// Empty output for a config that must not start a run.
    fn invalid_run_output(&self, reason: TerminalReason) -> RunOutput {
        RunOutput {
            reason,
            final_text: None,
            turns: 0,
            tool_calls: 0,
            executed_tools: Vec::new(),
            tool_calls_attempted: 0,
            tool_calls_denied: 0,
            cost: self.cost.snapshot(),
            selected_models: Vec::new(),
            first_dispatch_observation: None,
            compactions: 0,
            terminal_detail: None,
        }
    }

    /// Build the terminal [`RunOutput`] once the loop has decided to stop.
    ///
    /// An operator abort is recorded here (not in the step that noticed it), so
    /// a Ctrl-C during a connector call still leaves an audit line even when no
    /// tool ran.
    fn finish_run(
        &self,
        mut state: RunState,
        step: StepResult,
        reason: TerminalReason,
    ) -> RunOutput {
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
        RunOutput {
            reason,
            final_text,
            turns: state.attempts,
            tool_calls: state.tool_calls,
            executed_tools: std::mem::take(&mut state.executed_tools),
            tool_calls_attempted: state.tool_calls_attempted,
            tool_calls_denied: state.denied,
            cost,
            selected_models: state.selected,
            first_dispatch_observation: state.first_dispatch_observation,
            compactions: state.compactions,
            terminal_detail: state.terminal_detail.take(),
        }
    }

    /// Drive `task` to a terminal outcome — the single public entrypoint.
    pub async fn run(&self, task: &str) -> RunOutput {
        if let Some(reason) = self.config.invalid_reason() {
            return self.invalid_run_output(reason);
        }
        let mut state = RunState::new(task);
        if let Some(config) = self.config.operation_intent.as_ref() {
            // Restart rule: read, validate and reconcile the retained record
            // BEFORE any key is minted or anything is dispatched.
            match OperationSession::open(config) {
                Ok(session) => state.intent.session = Some(session),
                Err(error) => {
                    eprintln!("arcana: operation intent refused the run: {error}");
                    state.terminal_detail = Some(error.to_string());
                    return self.finish_run(
                        state,
                        StepResult::Terminal(TerminalReason::ConnectorFatal, None),
                        TerminalReason::ConnectorFatal,
                    );
                }
            }
        }
        loop {
            let step = self.step(&mut state).await;
            let outcome = match &step {
                StepResult::Continue(reason) => TurnOutcome::Continue(*reason),
                StepResult::Terminal(reason, _) => TurnOutcome::Terminal(*reason),
            };
            match reduce(outcome) {
                LoopControl::Reloop => {}
                LoopControl::Stop(reason) => {
                    return self.finish_run(state, step, reason);
                }
            }
        }
    }

    /// Write the operator-abort record, and report whether the audit held.
    ///
    /// A Ctrl-C otherwise leaves no record: the dispatch was sent and will be
    /// charged. The tool-level `decision`/`result` pair cannot cover it, because
    /// an abort during the connector call has no tool to attribute to.
    ///
    /// Returns [`TerminalReason::AuditFatal`] when the append fails. An abort
    /// the operator was told about but that was never recorded is the state
    /// Law-5 forbids, and a failed audit append is fatal everywhere else.
    fn record_abort(
        &self,
        attempts: u32,
        selected: &[String],
        cost: &crate::cost::CostSnapshot,
    ) -> TerminalReason {
        // Both figures are named for their scope: `attempts` counts connector
        // calls in THIS run, while the `CostTracker` is owned by the session and
        // shared across every run in it, so its snapshot is cumulative. A
        // plainly named `cost_usd_micros` beside a per-run turn count would read
        // as the cost of the aborted turn.
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
        // The run says what it did: a model whose earlier turns were
        // summarised behind its back, and an operator reading only the log,
        // would otherwise take a shorter answer for a worse model rather than a
        // smaller question.
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
    /// to `context_budget_units`; this is the contract Model Connector enforces
    /// with an HTTP 400, reachable only by a request the guard could not shrink
    /// or an exact first-dispatch prompt the caller supplied. Refusing here
    /// costs nothing and names the limit; sending it spends a roundtrip to be
    /// told the same thing as `ConnectorFatal`.
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

    /// Refuse a step that must not spend another connector ask.
    ///
    /// `max_turns` caps the QUESTIONS this run may ask. A poll under a key
    /// already in flight asks nothing: it collects an answer that has been
    /// bought, and the 409 it gets back is not charged. Counting polls would
    /// make the wait eat the budget it is waiting inside (one wait can span
    /// two dozen polls), trading `ConnectorFatal` for `MaxTurns` and
    /// abandoning the same paid-for answer.
    ///
    /// `RunOutput::turns` still reports `attempts` in full: the exemption is
    /// about what the run is ALLOWED, not about hiding what it did.
    fn refuse_before_ask(&self, state: &RunState) -> Option<StepResult> {
        if self.cancel.is_cancelled() {
            return Some(StepResult::Terminal(
                TerminalReason::AbortedByOperator,
                None,
            ));
        }
        if state.attempts.saturating_sub(state.in_flight_polls_total) >= self.config.max_turns {
            return Some(StepResult::Terminal(TerminalReason::MaxTurns, None));
        }
        if self.cost.check_budget(self.config.max_cost_usd).is_err() {
            return Some(StepResult::Terminal(TerminalReason::MaxCostUsd, None));
        }
        None
    }

    /// One step: guards → select model → connector attempt → interpret → (tool
    /// turn | final). `attempts` is the shared connector-attempt counter that
    /// enforces `max_turns`; `selected` accumulates the ordered per-step model
    /// ids.
    async fn step(&self, state: &mut RunState) -> StepResult {
        if let Some(step) = self.refuse_before_ask(state) {
            return step;
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
        // Per-step multi-model dispatch: classify the step context, select the
        // model, record it, and route it through the connector on
        // `ExecuteRequest.model`. Selection keys off the current
        // connector-attempt index (`*attempts`) before the `max_turns`-enforcing
        // increment below consumes it, preserving the zero-based turn index the
        // classifier expects on the first attempt.
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
        // The request this turn is sending, kept for as long as the turn may
        // need to send it again: a poll under the same key re-sends these bytes
        // instead of rebuilding them.
        let dispatch = Dispatch {
            prompt: &prompt,
            model: &choice.model_id,
        };
        let resp = match self.dispatch_turn(state, &dispatch, first_dispatch).await {
            Ok(resp) => resp,
            Err(step) => return step,
        };
        if first_dispatch {
            state
                .first_dispatch_observation
                .clone_from(&resp.first_dispatch_observation);
        }
        if self.cost.check_budget(self.config.max_cost_usd).is_err() {
            return StepResult::Terminal(TerminalReason::MaxCostUsd, None);
        }
        self.settle_reply(state, &resp).await
    }

    /// Turn a connector reply into the step's continue/terminal outcome.
    ///
    /// Owns the post-dispatch branches that used to sit inline in [`Self::step`]:
    /// truncation recovery, final text (with abort delivery and the no-action
    /// nudge), tool admission, and malformed-tool correction.
    async fn settle_reply(&self, state: &mut RunState, resp: &ConnectorResponse) -> StepResult {
        match interpret(resp) {
            // Handled before the history is written: the fragment is
            // deliberately NOT kept. Feeding a half-emitted call back would put
            // words in the model's mouth, and it is large by construction, so
            // carrying it would shrink the window for the retry that has to
            // succeed.
            AssistantAction::Truncated { bytes } => {
                self.recover_from_truncation(state, bytes, &resp.result)
            }
            AssistantAction::Final { text } => {
                state.accept_reply(&resp.result, self.reply_ceiling());
                // An answer that arrived is DELIVERED even when the operator
                // interrupted: it is already paid for, and withholding it would
                // be a second harm. The verdict still says they stopped the run,
                // so the exit code is 130 and the abort is audited; reporting a
                // clean `Completed` would make Ctrl-C inert on a task answered in
                // one dispatch.
                if self.cancel.is_cancelled() {
                    return StepResult::Terminal(TerminalReason::AbortedByOperator, Some(text));
                }
                // A run that required an action and executed nothing did not
                // complete, whatever its prose says. Tell the model once that
                // nothing ran, and end on `NoAction` if the second answer is
                // empty too.
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
                // Re-check between the answer and the side effect: a tool turn
                // is where the run touches the world, so Ctrl-C while the model
                // was deciding must not let a bash command run. The final-text
                // branch above deliberately does NOT check: that answer is
                // already paid for.
                state.accept_reply(&resp.result, self.reply_ceiling());
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
                state.accept_reply(&resp.result, self.reply_ceiling());
                self.correct_tool_format(state, dialect, &detail, &resp.result)
            }
        }
    }

    /// Decide what a reply cut off by the output limit means for the run:
    /// one more ask for smaller pieces, or a verdict that names the cause.
    ///
    /// Not a connector retry: the connector did its job and the answer is paid
    /// for. The model could not say what it wanted inside one reply, so
    /// re-sending the same request would buy the same cut-off at the same
    /// token. The re-dispatch carries [`TRUNCATION_NUDGE`], and the fragment is
    /// dropped rather than echoed back.
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
    /// Not a `NoAction` nudge: [`NO_ACTION_NUDGE`] answers a model that
    /// produced no call at all, while this answers one that produced a call we
    /// could not read. Told "nothing was executed, so call a tool", a model that
    /// just called a tool cannot work out what to change.
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
        // The reply, verbatim, before the run may end on it: what the model
        // actually sent is only here, and a correction can only be judged
        // against the text it was written for.
        let saved = self.save_rejected_reply(state, reply);
        // `eprintln!` rather than `tracing`: the CLI installs no subscriber.
        // The operator needs this line to tell "the model refused to work" from
        // "this runner cannot read what the model sent".
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

    /// Send this turn's request and hand back the response the loop will
    /// interpret, or the step that ends the turn without one.
    ///
    /// The dispatch, the recovery and the "a response arrived" bookkeeping live
    /// together: the response may come from the first call or from a poll inside
    /// the in-flight wait, and a counter reset on only one of those paths would
    /// be a defect no single test could see.
    ///
    /// # Errors
    /// The step to return when there is no response to interpret.
    async fn dispatch_turn(
        &self,
        state: &mut RunState,
        dispatch: &Dispatch<'_>,
        first_dispatch: bool,
    ) -> Result<ConnectorResponse, StepResult> {
        let resp = match self
            .call_connector(
                &mut state.intent,
                dispatch.prompt,
                Some(dispatch.model),
                first_dispatch,
            )
            .await
        {
            Ok(resp) => resp,
            Err(error) => {
                match self
                    .recover_or_stop(state, &error, first_dispatch, dispatch)
                    .await
                {
                    // The in-flight wait collected the answer itself, under the
                    // key the turn was dispatched with. From here it is a
                    // response like any other.
                    Recovered::Answered(resp) => *resp,
                    Recovered::Step(step) => return Err(step),
                }
            }
        };
        // A response of any shape means the upstream is answering again, so the
        // retry budget starts over; counting retries across a whole run would
        // end it after three slow turns spread over an hour.
        state.connector_retries = 0;
        state.in_flight_polls = 0;
        state.connector_retry_pause_spent = Duration::ZERO;
        state.connector_failure_since = None;
        // The question was answered, so the next dispatch is a new one and gets
        // a new key. A replayed response counts: it is the answer, arriving
        // late and already paid for.
        state.intent.finish_turn();
        Ok(resp)
    }

    /// Build the request, call the connector, and record its cost.
    ///
    /// The error is returned whole rather than pre-mapped to a terminal
    /// reason: only the caller knows how many re-dispatches this turn has
    /// already had, and the decision between a retry and
    /// [`TerminalReason::ConnectorFatal`] needs both facts.
    async fn call_connector(
        &self,
        intent: &mut TurnIntentSeries,
        prompt: &str,
        model: Option<&str>,
        first_dispatch: bool,
    ) -> Result<ConnectorResponse, ConnectorError> {
        // Borrowed, not moved: the caller keeps the request so a poll can send
        // it again without rebuilding it. The copy made here is the one the
        // wire needs either way.
        let mut req = ExecuteRequest::new(self.config.connector_id.clone(), prompt);
        req.model = model.map(ToOwned::to_owned);
        req.system_prompt = self.config.system_prompt.clone();
        // `self.config.max_turns` is deliberately NOT forwarded as the wire
        // field `maxTurns`. The config value caps how many connector attempts
        // THIS loop makes, while `maxTurns` is a per-request passthrough that
        // Model Connector validates as `z.number().int().min(1).max(100)` and
        // hands to CLI connectors (`claude-code --max-turns`); forwarding it
        // makes a run-level budget fail as a per-request one with an HTTP 400.
        //
        // Nothing is substituted: no run-level number is a correct per-request
        // cap, the upstream work of one request stays bounded by `maxBudgetUsd`
        // below, and a caller who wants to cap an upstream agentic CLI sets
        // `max_turns` on its own request (`arcana_tools::model_call`).
        req.max_budget_usd = self.remaining_cost_budget();
        if first_dispatch {
            req.first_dispatch_measurement = self.config.first_dispatch_measurement.clone();
        }
        // Last, so the fingerprint it records covers the finished request.
        if intent.stamp_durable(&mut req, Instant::now())? == IntentDecision::Refused {
            // G07: an earlier dispatch under the key in force has an unknown
            // outcome and the payload changed. Do not dispatch; keep the
            // original key. Not a `tracing` call: the CLI installs no
            // subscriber, so the error line is the only way it is ever seen.
            return Err(ConnectorError::ReconcileRequired {
                key: intent
                    .active_key()
                    .map(|key| key.as_str().to_owned())
                    .unwrap_or_default(),
            });
        }
        match self.connector.execute(req).await {
            Ok(resp) => {
                intent.note_reply(&resp.id);
                // `record_llm_call` takes u32; `Usage` fields are u64 — saturate.
                let tokens_in = u32::try_from(resp.usage.input_tokens).unwrap_or(u32::MAX);
                let tokens_out = u32::try_from(resp.usage.output_tokens).unwrap_or(u32::MAX);
                self.cost
                    .record_llm_call(&resp.model, tokens_in, tokens_out, resp.usage.cost_usd);
                Ok(resp)
            }
            Err(error) => {
                intent.note_no_reply();
                Err(error)
            }
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
    /// `schema` only ever means the arguments did not match the tool's
    /// published JSON schema, so a malformed call folds back as a recoverable
    /// tool result, the same rule [`Self::run_tool_turn`] documents for a
    /// dispatch error. The model is told what was wrong; otherwise it cannot be
    /// right.
    ///
    /// The bound on the fold-back is the **repeat**: a call already refused at
    /// this layer, sent again unchanged, ends the run, because the fold-back has
    /// demonstrably not worked. Genuinely new mistakes keep getting answered,
    /// bounded by `max_turns` and the cost cap.
    ///
    /// Only [`RECOVERABLE_DENIAL_LAYERS`] fold back at all; a policy layer is
    /// terminal on its first refusal.
    ///
    /// Nothing executed either way: `tool_calls` is not incremented here, so a
    /// run whose every call was refused still reports zero work done. It is
    /// counted in `tool_calls_denied` and written out instead, because "the
    /// model called tools and every call was refused" and "the model never
    /// called a tool" are opposite facts.
    fn fold_denial(
        &self,
        state: &mut RunState,
        name: &str,
        layer: &'static str,
        reason: &str,
        input: &Value,
    ) -> StepResult {
        // Counted and written out before the run decides what the denial
        // means, so a terminal policy refusal leaves the same evidence as a
        // correctable one; the refused call matters most when the run ends.
        state.denied = state.denied.saturating_add(1);
        let saved = self.save_denied_call(state, name, layer, reason, input);
        // `eprintln!` rather than `tracing`: the CLI installs no subscriber.
        // Without this line a refused turn is a gap in the operator's log.
        eprintln!(
            "{}",
            denied_call_line(layer, name, reason, saved.as_deref())
        );
        // Whatever ends the run says which layer refused, which tool, and what
        // the error was; `PermissionDenied` alone makes a misspelt argument and
        // an operator-written policy rule read identically.
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
        // not happen, why, and what the model has to change. The rule it is on is
        // stated, because a model that does not know re-sending is fatal cannot
        // choose to try something else.
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
    /// A single command (`git clone`, `cargo test`, `find`) can return more text
    /// than an entire request may contain. Bounding at ingestion, rather than
    /// trimming once the transcript is already too big, makes the request fit
    /// *by construction*.
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
    /// `dispatch` audit records and the `turns` count in the done marker. The
    /// reply is written as bytes with nothing prepended: a header would mean the
    /// file is no longer what the model sent, the one property it exists to
    /// have.
    fn save_rejected_reply(&self, state: &mut RunState, reply: &str) -> Option<String> {
        let dir = self.config.rejected_reply_dir.as_ref()?;
        state.rejected = state.rejected.saturating_add(1);
        let file = dir.join(format!("{:04}-turn{}.txt", state.rejected, state.attempts));
        std::fs::create_dir_all(dir).ok()?;
        std::fs::write(&file, reply).ok()?;
        Some(file.display().to_string())
    }

    /// The most one model reply may contribute to the transcript.
    ///
    /// [`prompt_budget::entry_ceiling`] of this run's budget, and deliberately
    /// the same number compaction already imposes on an oversized entry: the
    /// cap at intake changes WHEN a reply that size is shortened, not how
    /// much of it survives.
    fn reply_ceiling(&self) -> usize {
        prompt_budget::entry_ceiling(self.config.context_budget_units)
    }

    /// Keep a call the cascade refused, with the reason it was refused for.
    ///
    /// Returns the path to name in the log line, or `None` when no directory
    /// is configured or the write failed. A failed write is not fatal, for the
    /// same reason a failed rejected-reply write is not: the run was already
    /// going to correct or end on this call, and a full disk must not become a
    /// second, different failure that hides the first.
    ///
    /// JSON rather than verbatim bytes, because the input reaching here has
    /// been parsed out of the reply, and the reply itself is already what
    /// `.arcana/rejected/` holds. The record is a statement about the denial
    /// (turn, tool, layer, reason, input) plus the audit's own `input_hash`,
    /// the only way to join this file to the `decision` record that refused it.
    ///
    /// This is where the reason text lives. The audit log stores its hash and
    /// not the sentence, because the sentence quotes what the model wrote (the
    /// schema layer's `"…" is not of type "integer"`, the workspace boundary's
    /// path). That log is under `$XDG_STATE_HOME` and never rotated; this file
    /// is in the workspace the run was confined to.
    fn save_denied_call(
        &self,
        state: &mut RunState,
        name: &str,
        layer: &str,
        reason: &str,
        input: &Value,
    ) -> Option<String> {
        let dir = self.config.denied_call_dir.as_ref()?;
        let file = dir.join(format!("{:04}-turn{}.json", state.denied, state.attempts));
        let record = serde_json::json!({
            "turn": state.attempts,
            "tool": name,
            "layer": layer,
            "reason": reason,
            "input": input,
            "input_hash": crate::hooks::audit::hash_value(input),
        });
        let text = serde_json::to_string_pretty(&record).ok()?;
        std::fs::create_dir_all(dir).ok()?;
        std::fs::write(&file, text).ok()?;
        Some(file.display().to_string())
    }

    /// Record the size of the request this turn is about to send.
    ///
    /// Sizes, never text: this crate's audit log is hashes-only for anything
    /// that could carry prompt content, which is what makes it safe to keep
    /// under `$XDG_STATE_HOME` forever. "How big was the request" is not
    /// content, and without it a run that died against the connector's
    /// 100 000-unit field limit leaves nothing to reconstruct from.
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
    /// first dispatch alone: it does not change during a run, and repeating it
    /// every turn would treble a file whose reason for existing is that it is
    /// readable.
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
    /// Map a capability-executor failure onto the step outcome for this turn.
    fn fold_capability_error(
        &self,
        state: &mut RunState,
        name: &str,
        err: CapabilityError,
        attempted: &Value,
    ) -> StepResult {
        match err {
            CapabilityError::Cancelled => {
                StepResult::Terminal(TerminalReason::AbortedByOperator, None)
            }
            CapabilityError::Denied { layer, reason } => {
                self.fold_denial(state, name, layer, &reason, attempted)
            }
            CapabilityError::HookAborted => {
                // A refusal by operator-owned code, audited as `Denied` at the
                // `hook` layer, so counted as one. No file: the abort reaches
                // this loop without the hook's reason, and an invented `reason`
                // would be worse than no record.
                state.denied = state.denied.saturating_add(1);
                StepResult::Terminal(TerminalReason::AbortedByHook, None)
            }
            CapabilityError::AuditFailure {
                phase: AuditFailurePhase::Decision | AuditFailurePhase::Result,
                ..
            }
            | CapabilityError::AuditLatched => {
                StepResult::Terminal(TerminalReason::AuditFatal, None)
            }
            CapabilityError::Tool(err) => {
                state.history.push(HistoryEntry::ToolResult {
                    name: name.to_owned(),
                    content: format!("dispatch error: {err}"),
                });
                StepResult::Continue(ContinueReason::ToolResultsReady)
            }
        }
    }

    /// Fold a successful capability into history and continue the run.
    fn accept_tool_capability(
        &self,
        state: &mut RunState,
        name: &str,
        capability: CapabilityOutput,
    ) -> StepResult {
        // Counted here and nowhere else: the executor returned, so the tool
        // ran. A denied or hook-aborted call left through an arm above, and a
        // dispatch error folds back as a tool result without reaching this
        // line, because a tool that failed to dispatch did no work either.
        state.tool_calls = state.tool_calls.saturating_add(1);
        state.executed_tools.push(name.to_owned());
        // The refusal memory is consecutive, so a call that ran clears it:
        // the bound is meant for a model stuck in one place, not a long run
        // that made the same slip twice an hour apart.
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

    async fn run_tool_turn(&self, state: &mut RunState, name: &str, input: Value) -> StepResult {
        let ctx = HookContext::new(self.cancel.clone(), self.cost.clone());
        // The call as the model wrote it, kept for the refusal fingerprint.
        // The executor consumes the value, and a denial has to be able to say
        // whether this is the same call the model already sent.
        let attempted = input.clone();
        // Counted before the attempt, not after it: this is the number that
        // says what the model tried, and a call that is about to be refused
        // was still a call.
        state.tool_calls_attempted = state.tool_calls_attempted.saturating_add(1);
        match self.executor.execute(&ctx, name, input).await {
            Ok(capability) => self.accept_tool_capability(state, name, capability),
            Err(err) => self.fold_capability_error(state, name, err, &attempted),
        }
    }
}

/// Exhaustive reduction of a [`TurnOutcome`] to a loop directive.
///
/// Delegates to per-branch matchers so that adding a `ContinueReason` or a
/// `TerminalReason` variant is a compile error the driver must resolve.
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
    /// A `const` array with an explicit length is not an exhaustive match, so
    /// the compiler cannot flag a missing variant; the test below asserts the
    /// length against the enum's own count.
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
        // A 1 MB prompt is rejected locally with no network call, which is the
        // right decision, but the operator must be shown a way to act on it.
        let explained = TerminalReason::ContextWindowExhausted.explain();
        assert!(explained.contains("context window"), "{explained}");
        assert!(explained.contains("shorten"), "{explained}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod connector_retry_tests {
    use super::recovery::{
        connector_fatal_detail, edge_backoff_pause, in_flight_poll_pause, jitter_permille,
        plan_retry_pause, retry_line, retry_pause, FatalCause, RetryBudget, RetryClass,
    };
    use super::{
        Instant, IntentDecision, TurnIntentSeries, DEFAULT_CONNECTOR_RETRY_PAUSE_BUDGET,
        DEFAULT_EDGE_RETRY_LIMIT, MAX_EDGE_RETRY_PAUSE, MAX_IN_FLIGHT_POLL_PAUSE, MAX_RETRY_AFTER,
    };
    use crate::connector::{
        ConnectorError, ExecuteRequest, FirstDispatchMeasurementV0, IdempotencyKey,
    };
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

    /// One of Model Connector's idempotency outcomes, in the envelope shape
    /// `gateErrorResponse` builds and `parse_error_envelope` parses. The
    /// `retryable` / `recommendation` pair is the server's, from
    /// `ERROR_ACTION_MAP` in `src/connectors/interfaces/connector.interface.ts`.
    fn idempotency_outcome(kind: &str, retryable: bool, recommendation: &str) -> ConnectorError {
        ConnectorError::Logical {
            http_status: if kind == "idempotency_key_reused" {
                422
            } else {
                409
            },
            kind: kind.into(),
            message: "…".into(),
            retryable,
            recommendation: recommendation.into(),
            retry_after: None,
            first_dispatch_observation: None,
        }
    }

    fn idempotency_conflict() -> ConnectorError {
        idempotency_outcome("idempotency_conflict", true, "wait")
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
            retry_pause(&named, 1, BASE, RetryClass::EdgeGateway),
            Duration::from_secs(7),
            "the upstream knows its own cooldown"
        );
        let absurd = ConnectorError::Http {
            status: 503,
            message: "upstream returned a non-contract error body (4 bytes): busy".into(),
            retry_after: Some(15_681),
        };
        assert_eq!(
            retry_pause(&absurd, 1, BASE, RetryClass::EdgeGateway),
            MAX_RETRY_AFTER
        );
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
            assert_eq!(
                retry_pause(&logical, retry, BASE, RetryClass::Connector),
                BASE
            );
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
    ///
    /// With a key sent on every attempt, the line states the outcome (the
    /// re-dispatch is replayed) rather than warning of a paid duplicate; a line
    /// that still warned would send an operator hunting a second charge that is
    /// not there.
    #[test]
    fn a_gateway_retry_says_the_re_dispatch_is_replayed_not_charged_again() {
        let line = retry_line(
            &edge_502(),
            Duration::from_secs(4),
            RetryClass::EdgeGateway,
            RetryBudget::Counted {
                attempt: 2,
                limit: 5,
            },
        );
        assert!(line.contains("HTTP 502"), "{line}");
        assert!(line.contains("(2 of 5)"), "{line}");
        assert!(line.contains("gateway"), "{line}");
        assert!(line.contains("Idempotency-Key"), "{line}");
        assert!(
            line.contains("replayed rather than charged again"),
            "{line}"
        );
        assert!(!line.contains("paid duplicate"), "{line}");
    }

    /// An envelope Model Connector authored means the provider call failed and
    /// the hold was released — nothing was charged, so the line says nothing
    /// about charges at all.
    #[test]
    fn a_retry_of_a_failure_model_connector_reported_says_nothing_about_charges() {
        let logical = ConnectorError::Logical {
            http_status: 201,
            kind: "network_error".into(),
            message: "The operation was aborted due to timeout".into(),
            retryable: true,
            recommendation: "retry".into(),
            retry_after: None,
            first_dispatch_observation: None,
        };
        let line = retry_line(
            &logical,
            Duration::from_secs(2),
            RetryClass::Connector,
            RetryBudget::Counted {
                attempt: 1,
                limit: 2,
            },
        );
        assert!(!line.contains("charged"), "{line}");
        assert!(!line.contains("Idempotency-Key"), "{line}");
        assert!(line.contains("(1 of 2)"), "{line}");
    }

    /// A client-side timeout is the other way a completed, billed turn can be
    /// lost on the wire, and the same key covers it.
    #[test]
    fn a_client_timeout_also_says_the_re_dispatch_is_replayed() {
        let timeout = ConnectorError::Timeout("timed out after 290s".into());
        let line = retry_line(
            &timeout,
            Duration::from_secs(2),
            RetryClass::Connector,
            RetryBudget::Counted {
                attempt: 1,
                limit: 2,
            },
        );
        assert!(
            line.contains("replayed rather than charged again"),
            "{line}"
        );
    }

    /// A conflict is not a failure of this turn and the line must not read like
    /// one: the answer is being produced upstream and is already paid for.
    /// Model Connector's own instruction — do not reissue under a new key — is
    /// what the wait implements.
    ///
    /// The parenthetical reports the budget that will actually end the wait: an
    /// edge-schedule counter ("3 of 5") would tell an operator the turn had two
    /// tries left when what it had was a clock.
    #[test]
    fn an_in_flight_conflict_line_says_it_is_waiting_not_re_asking() {
        let line = retry_line(
            &idempotency_conflict(),
            Duration::from_secs(8),
            RetryClass::InFlight,
            RetryBudget::Deadline {
                poll: 3,
                waited: Duration::from_secs(27),
                budget: Duration::from_secs(140),
            },
        );
        assert!(line.contains("still running upstream"), "{line}");
        assert!(
            line.contains("rather than dispatching a second paid one"),
            "{line}"
        );
        assert!(line.contains("poll 3"), "{line}");
        assert!(line.contains("27s of the 140s"), "{line}");
        assert!(
            !line.contains(" of 5)"),
            "the line still reports a re-dispatch count as the bound: {line}"
        );
    }

    /// The in-flight schedule is its own: its own base, its own ceiling, and no
    /// dependence on `connector_retry_backoff`, which tests set to zero and
    /// which would otherwise turn the wait into a hot loop.
    #[test]
    fn the_in_flight_poll_schedule_doubles_to_its_own_ceiling() {
        let nominal: Vec<Duration> = (1..=6)
            .map(|poll| in_flight_poll_pause(poll, 1000))
            .collect();
        assert_eq!(
            nominal,
            vec![
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                MAX_IN_FLIGHT_POLL_PAUSE,
                MAX_IN_FLIGHT_POLL_PAUSE,
                MAX_IN_FLIGHT_POLL_PAUSE,
            ],
            "{nominal:?}"
        );
        // Jitter only ever shortens, and never to zero.
        for poll in 1..=6 {
            let jittered = in_flight_poll_pause(poll, 0);
            assert!(jittered <= nominal[(poll - 1) as usize], "{jittered:?}");
            assert!(!jittered.is_zero(), "poll {poll} would spin");
        }
    }

    /// The verdict names BOTH budgets: a line that only said "re-dispatches
    /// are spent" would send an operator to raise a limit unrelated to why the
    /// turn was abandoned.
    #[test]
    fn the_in_flight_verdict_names_the_clock_and_the_untouched_counter() {
        let detail = connector_fatal_detail(
            &idempotency_conflict(),
            12,
            Duration::from_secs(139),
            FatalCause::InFlightWaitSpent {
                waited: Duration::from_secs(140),
                budget: Duration::from_secs(140),
                polls: 11,
                redispatches: 1,
                redispatch_limit: DEFAULT_EDGE_RETRY_LIMIT,
            },
        );
        assert!(detail.contains("140s"), "{detail}");
        assert!(detail.contains("11 poll(s)"), "{detail}");
        assert!(detail.contains("5 re-dispatch(es)"), "{detail}");
        assert!(detail.contains("untouched at 1"), "{detail}");
        assert!(detail.contains("it is the clock that ran out"), "{detail}");
    }

    /// The three idempotency outcomes are three different things, and the
    /// loop's whole response to each hangs on telling them apart.
    #[test]
    fn the_idempotency_outcomes_are_classified_apart() {
        let conflict = idempotency_conflict();
        assert!(conflict.is_idempotency_conflict());
        assert!(!conflict.is_idempotency_key_reused());
        assert_eq!(RetryClass::of(&conflict), RetryClass::InFlight);
        // The one idempotency outcome Model Connector marks retryable, and the
        // patient class: the answer genuinely arrives shortly.
        assert!(conflict.is_transient());
        assert!(RetryClass::of(&conflict).is_patient());

        let reused = idempotency_outcome("idempotency_key_reused", false, "abort");
        assert!(reused.is_idempotency_key_reused());
        assert!(!reused.is_transient());
        // Classified as a plain connector failure: the recovery is a fresh
        // key, not a longer wait.
        assert_eq!(RetryClass::of(&reused), RetryClass::Connector);

        let unavailable = idempotency_outcome("idempotency_replay_unavailable", false, "abort");
        assert!(unavailable.is_idempotency_replay_unavailable());
        assert!(!unavailable.is_transient());

        // And an edge 502 is none of them — the classifier must not reach for
        // an idempotency verdict on a body Cloudflare wrote.
        assert_eq!(RetryClass::of(&edge_502()), RetryClass::EdgeGateway);
        assert!(edge_502().logical_kind().is_none());
    }

    /// A turn's key is stable across its re-dispatches and fresh on the next
    /// turn. Both halves matter: the first makes the retry free, the second
    /// stops turn two replaying turn one's answer for the rest of the run.
    #[test]
    fn one_turn_keeps_its_key_and_the_next_turn_gets_a_new_one() {
        let mut series = TurnIntentSeries::new();
        let mut first = ExecuteRequest::new("deepseek", "what is the answer");
        assert_eq!(
            series.stamp(&mut first, Instant::now()),
            IntentDecision::New
        );
        let mut retry = ExecuteRequest::new("deepseek", "what is the answer");
        assert_eq!(
            series.stamp(&mut retry, Instant::now()),
            IntentDecision::Reused
        );
        assert_eq!(
            first.idempotency_key, retry.idempotency_key,
            "a re-dispatch of the same request is the same intent"
        );

        series.finish_turn();
        let mut next_turn = ExecuteRequest::new("deepseek", "and the next question");
        // `New`, not `Refused`: an ordinary turn boundary is not a refusal. A
        // `finish_turn` that failed to release the key would still mint a fresh
        // key here (the payload differs) and put the defect line on every turn
        // of every run, which is the mutant this assertion exists to kill.
        assert_eq!(
            series.stamp(&mut next_turn, Instant::now()),
            IntentDecision::New
        );
        assert_ne!(first.idempotency_key, next_turn.idempotency_key);
    }

    /// G07: after a dispatch that produced no reply the outcome is unknown, so
    /// a payload that then changes must NOT be stamped with a fresh key.
    /// Nothing is minted, the request carries no key, and the original
    /// identity stays in force for an unchanged retry.
    #[test]
    fn g07_a_changed_payload_after_an_unknown_outcome_is_not_given_a_fresh_key() {
        let mut series = TurnIntentSeries::new();
        let mut first = ExecuteRequest::new("deepseek", "what is the answer");
        assert_eq!(
            series.stamp(&mut first, Instant::now()),
            IntentDecision::New
        );
        // No `finish_turn`: the first dispatch never got a reply.
        let mut changed = ExecuteRequest::new("deepseek", "a different question entirely");
        let decision = series.stamp(&mut changed, Instant::now());
        assert_eq!(
            decision,
            IntentDecision::Refused,
            "a fresh key was minted over an unknown outcome"
        );
        assert_ne!(
            changed.idempotency_key, first.idempotency_key,
            "the changed payload must not ride the original key either"
        );
        assert!(
            changed.idempotency_key.is_none(),
            "a refused request must carry no key: {:?}",
            changed.idempotency_key
        );
        // The original identity survives: an unchanged retry still replays.
        let mut again = ExecuteRequest::new("deepseek", "what is the answer");
        assert_eq!(
            series.stamp(&mut again, Instant::now()),
            IntentDecision::Reused
        );
        assert_eq!(again.idempotency_key, first.idempotency_key);
    }

    /// The fingerprint copies the server's two exclusions. The measurement one
    /// is the load-bearing case: it is present on a run's FIRST attempt and
    /// absent from its re-dispatch, so counting it would split the very first
    /// turn's series in two while the server replayed it.
    #[test]
    fn the_first_dispatch_measurement_does_not_change_the_intent() {
        let plain = ExecuteRequest::new("deepseek", "ping");
        let mut measured = ExecuteRequest::new("deepseek", "ping");
        measured.first_dispatch_measurement = Some(
            FirstDispatchMeasurementV0::try_new(
                "corpus",
                "case",
                "role",
                "task",
                "command",
                1,
                crate::connector::PromptVariantV0::Baseline,
            )
            .expect("a well-formed measurement"),
        );
        assert_eq!(plain.intent_fingerprint(), measured.intent_fingerprint());

        // And a field that DOES change what the provider is asked to do still
        // changes it, or the guard above would be inert.
        let mut other_model = ExecuteRequest::new("deepseek", "ping");
        other_model.model = Some("grok-3-latest".to_owned());
        assert_ne!(plain.intent_fingerprint(), other_model.intent_fingerprint());
    }

    /// Every key the loop can mint is one `normalizeIdempotencyKey` accepts:
    /// printable ASCII, no spaces, at most 255 characters. A key the server
    /// rejects is a 400 on every dispatch of the run.
    #[test]
    fn a_minted_key_is_one_the_server_accepts() {
        for (run, turn) in [(0_u128, 0_u64), (u128::MAX, u64::MAX), (1, 7)] {
            let key = IdempotencyKey::for_turn(run, turn);
            let raw = key.as_str();
            assert_ne!(raw, "");
            assert!(
                raw.len() <= crate::connector::MAX_IDEMPOTENCY_KEY_BYTES,
                "{raw}"
            );
            assert!(
                raw.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
                "{raw}"
            );
        }
    }

    /// The three facts the done-marker error field must carry.
    #[test]
    fn the_fatal_detail_carries_status_attempts_and_elapsed() {
        let detail = connector_fatal_detail(
            &edge_502(),
            6,
            Duration::from_millis(63_400),
            FatalCause::RetriesSpent {
                limit: 5,
                class: RetryClass::EdgeGateway,
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
                class: RetryClass::Connector,
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
/// it is terminal. That is the safe direction, but it is also silent: adding
/// `hook_bridge` or `rule` to the set would make an operator-owned refusal
/// retryable without any test turning red.
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
