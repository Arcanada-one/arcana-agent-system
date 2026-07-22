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
//! [`crate::connector::ModelConnector`], [`crate::permission::PermissionCascade`],
//! [`crate::hooks::HookChain`], [`crate::tool::ToolDispatcher`], and
//! [`crate::cost::CostTracker`] — driving a task through
//! attempt → interpret → (tool turn | final) until a `Terminal` outcome. It
//! adds no new `Tool`/`PermissionLayer`/`ToolHook`; every collaborator is
//! consumed through its existing signature.

use std::sync::Arc;

use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::connector::{ConnectorResponse, ExecuteRequest, ModelConnector};
use crate::cost::{CostSnapshot, CostTracker};
use crate::hooks::{HookChain, HookContext, PostToolOutcome, PreToolOutcome};
use crate::permission::{CascadeOutcome, PermissionCascade};
use crate::tool::ToolDispatcher;

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
    /// Hard turn cap → [`TerminalReason::MaxTurns`].
    pub max_turns: u32,
    /// Optional cost cap (USD) → [`TerminalReason::MaxCostUsd`].
    pub max_cost_usd: Option<f64>,
    /// Serialized-history ceiling (chars) → compaction / `ContextWindowExhausted`.
    pub context_budget_chars: usize,
}

impl DriverConfig {
    /// Config for `connector_id` with defensive defaults (8 turns, no cost cap,
    /// a generous context budget). Callers tune individual fields.
    #[must_use]
    pub fn new(connector_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
            model: None,
            system_prompt: None,
            max_turns: 8,
            max_cost_usd: None,
            context_budget_chars: 1_000_000,
        }
    }
}

/// Result of a completed run.
#[derive(Debug, Clone)]
pub struct RunOutput {
    /// The terminal cause the run ended on.
    pub reason: TerminalReason,
    /// The model's final text — `Some` only when `reason == Completed`.
    pub final_text: Option<String>,
    /// Number of turns consumed.
    pub turns: u32,
    /// Cost accounting snapshot at termination.
    pub cost: CostSnapshot,
}

/// The agent-loop driver. Borrows its collaborators; owns only run config and
/// the shared cost/cancel handles.
///
/// It adds **no new** `Tool`/`PermissionLayer`/`ToolHook` — every collaborator
/// is consumed through its existing signature (D-REQ-05 / V-AC-7).
pub struct Driver<'a> {
    connector: &'a dyn ModelConnector,
    dispatcher: &'a ToolDispatcher,
    cascade: &'a PermissionCascade,
    hooks: &'a HookChain,
    cost: Arc<CostTracker>,
    cancel: CancellationToken,
    config: DriverConfig,
}

/// Internal per-turn result: a `Continue` reason, or a terminal cause carrying
/// the final text (only for `Completed`).
enum StepResult {
    Continue(ContinueReason),
    Terminal(TerminalReason, Option<String>),
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
        dispatcher: &'a ToolDispatcher,
        cascade: &'a PermissionCascade,
        hooks: &'a HookChain,
        cost: Arc<CostTracker>,
        cancel: CancellationToken,
        config: DriverConfig,
    ) -> Self {
        Self {
            connector,
            dispatcher,
            cascade,
            hooks,
            cost,
            cancel,
            config,
        }
    }

    /// Drive `task` to a terminal outcome — the single public entrypoint.
    pub async fn run(&self, task: &str) -> RunOutput {
        let mut history = vec![HistoryEntry::Task(task.to_owned())];
        let mut turn: u32 = 0;
        loop {
            let step = self.step(&mut history, turn).await;
            let outcome = match &step {
                StepResult::Continue(reason) => TurnOutcome::Continue(*reason),
                StepResult::Terminal(reason, _) => TurnOutcome::Terminal(*reason),
            };
            match reduce(outcome) {
                LoopControl::Reloop => turn = turn.saturating_add(1),
                LoopControl::Stop(reason) => {
                    let final_text = match step {
                        StepResult::Terminal(_, text) => text,
                        StepResult::Continue(_) => None,
                    };
                    return RunOutput {
                        reason,
                        final_text,
                        turns: turn,
                        cost: self.cost.snapshot(),
                    };
                }
            }
        }
    }

    /// One turn: guards → connector call → interpret → (tool turn | final).
    async fn step(&self, history: &mut Vec<HistoryEntry>, turn: u32) -> StepResult {
        if self.cancel.is_cancelled() {
            return StepResult::Terminal(TerminalReason::AbortedByOperator, None);
        }
        if turn >= self.config.max_turns {
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
        let prompt = serialize_history(history);
        let resp = match self.call_connector(prompt).await {
            Ok(resp) => resp,
            Err(reason) => return StepResult::Terminal(reason, None),
        };
        history.push(HistoryEntry::Assistant(resp.result.clone()));
        match interpret(&resp) {
            AssistantAction::Final { text } => {
                StepResult::Terminal(TerminalReason::Completed, Some(text))
            }
            AssistantAction::ToolCall { name, input } => {
                history.push(HistoryEntry::ToolCall {
                    name: name.clone(),
                    input: input.to_string(),
                });
                self.run_tool_turn(history, &name, input).await
            }
        }
    }

    /// Build the request, call the connector, and record its cost. Maps a
    /// connector error to [`TerminalReason::ConnectorFatal`].
    async fn call_connector(&self, prompt: String) -> Result<ConnectorResponse, TerminalReason> {
        let mut req = ExecuteRequest::new(self.config.connector_id.clone(), prompt);
        req.model = self.config.model.clone();
        req.system_prompt = self.config.system_prompt.clone();
        req.max_turns = Some(self.config.max_turns);
        req.max_budget_usd = self.config.max_cost_usd;
        match self.connector.execute(req).await {
            Ok(resp) => {
                // `record_llm_call` takes u32; `Usage` fields are u64 — saturate.
                let tokens_in = u32::try_from(resp.usage.input_tokens).unwrap_or(u32::MAX);
                let tokens_out = u32::try_from(resp.usage.output_tokens).unwrap_or(u32::MAX);
                self.cost
                    .record_llm_call(&resp.model, tokens_in, tokens_out, resp.usage.cost_usd);
                Ok(resp)
            }
            Err(_) => Err(TerminalReason::ConnectorFatal),
        }
    }

    /// Reuse-only tool turn: cascade → `pre_tool` → dispatch → `post_tool`, folding
    /// results into `history`. A dispatch error folds back as a tool-result
    /// string (recoverable, bounded by `max_turns`) rather than terminating.
    async fn run_tool_turn(
        &self,
        history: &mut Vec<HistoryEntry>,
        name: &str,
        input: Value,
    ) -> StepResult {
        let approved = match self.cascade.evaluate(name, input).await {
            CascadeOutcome::Allowed { transformed_input } => transformed_input,
            CascadeOutcome::Denied { .. } => {
                return StepResult::Terminal(TerminalReason::PermissionDenied, None);
            }
        };
        let ctx = HookContext::new(self.cancel.clone(), self.cost.clone());
        let dispatched_input = match self.hooks.pre_tool(&ctx, name, &approved).await {
            Ok(PreToolOutcome::Proceed { input }) => input,
            Ok(PreToolOutcome::Stop { .. }) | Err(_) => {
                return StepResult::Terminal(TerminalReason::AbortedByHook, None);
            }
        };
        let output = match self.dispatcher.dispatch(name, dispatched_input).await {
            Ok(output) => output,
            Err(err) => {
                history.push(HistoryEntry::ToolResult {
                    name: name.to_owned(),
                    content: format!("dispatch error: {err}"),
                });
                return StepResult::Continue(ContinueReason::ToolResultsReady);
            }
        };
        history.push(HistoryEntry::ToolResult {
            name: name.to_owned(),
            content: output.content.clone(),
        });
        match self.hooks.post_tool(&ctx, name, &output).await {
            Ok(PostToolOutcome::Proceed { injected }) => {
                let injected_context = !injected.is_empty();
                for line in injected {
                    history.push(HistoryEntry::Injected(line));
                }
                if injected_context {
                    StepResult::Continue(ContinueReason::HookContinuation)
                } else {
                    StepResult::Continue(ContinueReason::ToolResultsReady)
                }
            }
            Ok(PostToolOutcome::Stop { .. }) | Err(_) => {
                StepResult::Terminal(TerminalReason::AbortedByHook, None)
            }
        }
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

/// Exhaustive over all 6 `ContinueReason` variants.
fn reduce_continue(reason: ContinueReason) -> LoopControl {
    match reason {
        ContinueReason::ToolResultsReady
        | ContinueReason::HookContinuation
        | ContinueReason::ReactiveCompactRetry
        | ContinueReason::MicrocompactCompleted => LoopControl::Reloop,
        // Inert under the unary Phase-C connector (no streaming, no token
        // cursor): a documented no-op re-loop bounded by `max_turns` — never
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

/// Exhaustive over all 8 `TerminalReason` variants.
fn reduce_terminal(reason: TerminalReason) -> LoopControl {
    match reason {
        TerminalReason::Completed
        | TerminalReason::MaxTurns
        | TerminalReason::MaxCostUsd
        | TerminalReason::AbortedByOperator
        | TerminalReason::AbortedByHook
        | TerminalReason::PermissionDenied
        | TerminalReason::ContextWindowExhausted
        | TerminalReason::ConnectorFatal => LoopControl::Stop(reason),
    }
}
