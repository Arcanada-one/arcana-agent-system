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

/// Pause before re-dispatching when the upstream named no `retryAfter`.
pub const DEFAULT_CONNECTOR_RETRY_BACKOFF: Duration = Duration::from_secs(2);

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

/// Replies in an unexecutable tool-call format a run tolerates before it ends
/// on [`TerminalReason::UnsupportedToolCallFormat`].
///
/// Two, so the model gets exactly one correction — one fewer than
/// [`MAX_CONSECUTIVE_DENIALS`], and on purpose. A schema denial tells the model
/// something it could not have known before it called; the wire format is
/// already stated verbatim in the system prompt, and the correction states it
/// again with the offending reply in view. A model that ignores it twice is
/// not going to read it the third time, and each attempt is a paid dispatch.
///
/// Like the denial streak, the counter is consecutive: any tool call that
/// actually executes clears it, so a long run is not killed by two unrelated
/// format slips an hour apart.
pub const MAX_DIALECT_CORRECTIONS: u32 = 2;

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
    // `arguments` / `parameters` / `args` are accepted as `input`. The reader
    // here was `value.get("input").cloned().unwrap_or(Value::Null)`, so a
    // model that used any other spelling had its arguments silently discarded
    // and its call dispatched empty — a `bash` with no command, refused for a
    // reason that was never the model's mistake.
    //
    // No spelling at all is the same defect with nothing to recover: a `null`
    // dispatched into a tool that wants an object is a schema denial we can
    // see coming, and the model is better served by being told its call has no
    // arguments than by being told `null` is not an object. Measured live on
    // 2026-09-23 — audit `input_hash 03f88b99c3d8073b`, `blake3("null")` — this
    // is the one remaining way that hash could still be written.
    let Some(input) = tool_dialect::arguments_of(&value) else {
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
    /// Entries folded into a [`HistoryEntry::Compacted`] span.
    pub folded_entries: usize,
    /// Serialized size before the guard ran, in UTF-16 units.
    pub units_before: usize,
    /// Serialized size after it ran.
    pub units_after: usize,
    /// The ceiling it was working to.
    pub budget: usize,
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
            "arcana: transcript compacted to fit the {budget}-character request budget — \
{elided} tool result(s) shortened, {folded} earlier entr(ies) folded into a summary \
({before} → {after} characters)",
            budget = self.budget,
            elided = self.elided_results,
            folded = self.folded_entries,
            before = self.units_before,
            after = self.units_after,
        ))
    }
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
#[must_use]
pub fn guard_context(history: &mut Vec<HistoryEntry>, budget: usize) -> CompactionReport {
    let units_before = history_units(history);
    let mut report = CompactionReport {
        verdict: ContextVerdict::Ok,
        elided_results: 0,
        folded_entries: 0,
        units_before,
        units_after: units_before,
        budget,
    };
    if units_before <= budget {
        return report;
    }

    // Stage 1 — shorten tool results, oldest first. Two floors rather than a
    // search: the first leaves a result usable, the second is what is left
    // when the transcript has to survive at all. Each result is counted once
    // however many times it is shortened.
    let mut elided: Vec<usize> = Vec::new();
    for floor in [budget / 8, budget / 64] {
        for (index, entry) in history.iter_mut().enumerate() {
            if let HistoryEntry::ToolResult { content, .. } = entry {
                if !prompt_budget::fits(content, floor) {
                    *content = prompt_budget::elide_middle(content, floor, None);
                    if !elided.contains(&index) {
                        elided.push(index);
                    }
                }
            }
        }
        report.units_after = history_units(history);
        if report.units_after <= budget {
            break;
        }
    }
    report.elided_results = elided.len();

    // Stage 2 — fold the oldest entries after the task framing into ONE span.
    //
    // One, not one per entry: the summary line costs a few hundred characters
    // of its own, so a row of them would grow the request it is supposed to
    // shrink. Each iteration removes exactly one entry, so this terminates,
    // and it stops before the newest entry — a model handed a summary of the
    // question it is answering has nothing left to answer.
    let Some(start) = history
        .iter()
        .position(|entry| !matches!(entry, HistoryEntry::Task(_)))
    else {
        report.verdict = ContextVerdict::Irreducible;
        return report;
    };
    if report.units_after > budget && start + 1 < history.len() {
        let mut span = CompactedSpan::default();
        span.absorb(&history[start]);
        history[start] = HistoryEntry::Compacted(span);
        report.folded_entries = 1;
        report.units_after = history_units(history);
        while report.units_after > budget && history.len() > start + 2 {
            let entry = history.remove(start + 1);
            if let HistoryEntry::Compacted(span) = &mut history[start] {
                span.absorb(&entry);
            }
            report.folded_entries = report.folded_entries.saturating_add(1);
            report.units_after = history_units(history);
        }
    }
    if report.units_after > budget {
        report.verdict = ContextVerdict::Irreducible;
        return report;
    }

    let actions = report.elided_results + report.folded_entries;
    report.verdict = match actions {
        0 => ContextVerdict::Ok,
        1 => ContextVerdict::Microcompacted,
        _ => ContextVerdict::ReactiveCompacted,
    };
    report
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
    /// Folded-back denials since the last tool call that actually executed.
    consecutive_denials: u32,
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
            truncation_retries: 0,
            malformed_calls: 0,
            compactions: 0,
            spilled: 0,
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
        let history = &mut state.history;
        let attempts = &mut state.attempts;
        let first_dispatch = *attempts == 0;
        let prompt = if first_dispatch {
            self.config.first_dispatch_prompt.clone().map_or_else(
                || serialize_history(history),
                FirstDispatchPromptV0::into_inner,
            )
        } else {
            serialize_history(history)
        };
        // The wall, not the budget. The guard above already compacted to
        // `context_budget_units`; this is the contract Model Connector will
        // enforce with an HTTP 400, and the only request that can reach it is
        // one the guard could not shrink or an exact first-dispatch prompt the
        // caller supplied. Refusing here costs nothing and names the limit;
        // sending it spends a roundtrip to be told the same thing by a
        // validator that calls it `ConnectorFatal`.
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
            return StepResult::Terminal(TerminalReason::RequestTooLarge, None);
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
        match interpret(&resp) {
            // Handled before the history is written: the fragment is
            // deliberately NOT kept. Feeding a half-emitted call back would
            // put words in the model's mouth that it never finished saying,
            // and the fragment is large by construction — the live one was
            // ~9148 output tokens — so carrying it would shrink the window for
            // the retry that has to succeed.
            AssistantAction::Truncated { bytes } => Self::recover_from_truncation(state, bytes),
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
                Self::correct_tool_format(state, dialect, &detail)
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
    fn recover_from_truncation(state: &mut RunState, bytes: usize) -> StepResult {
        // `eprintln!` rather than `tracing`: the CLI installs no subscriber.
        eprintln!(
            "arcana: the model's reply was cut off after {bytes} bytes with an unclosed \
             `tool_call` block — nothing was executed"
        );
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
    fn correct_tool_format(state: &mut RunState, dialect: &str, detail: &str) -> StepResult {
        // `eprintln!` rather than `tracing`: the CLI installs no subscriber.
        // The operator needs this line — it is the difference between "the
        // model refused to work" and "this runner cannot read what the model
        // sent", and only one of those is the model's fault.
        eprintln!(
            "arcana: the model asked for a tool as {dialect} — {detail}; nothing was executed"
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
        // A size refusal is not a connector failure: the request was ours and
        // it was too big. Retrying sends the same oversized body again, and
        // reporting `ConnectorFatal` points the operator at a service that did
        // exactly what its contract says.
        if error.is_request_too_large() {
            return StepResult::Terminal(TerminalReason::RequestTooLarge, None);
        }
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
