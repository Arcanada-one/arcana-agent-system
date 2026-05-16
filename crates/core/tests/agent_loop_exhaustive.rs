//! Agent loop state machine exhaustiveness.
//!
//! Contract: `enum TurnOutcome { Continue(ContinueReason), Terminal(TerminalReason) }`
//! has 6 `ContinueReason` and 8 `TerminalReason` variants. Regression is
//! blocked two independent ways:
//!   1. Compile-time exhaustive match — adding a variant without updating
//!      the driver produces a «non-exhaustive patterns» error.
//!   2. Run-time enumeration — the explicit per-variant list confirms the
//!      driver still covers the documented 6/8 surface.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use arcana_core::agent_loop::{ContinueReason, TerminalReason, TurnOutcome};

const CONTINUE_VARIANTS: usize = 6;
const TERMINAL_VARIANTS: usize = 8;

fn classify_continue(reason: ContinueReason) -> &'static str {
    match reason {
        ContinueReason::ToolResultsReady => "tool_results_ready",
        ContinueReason::MaxOutputTokensRecovery => "max_output_tokens_recovery",
        ContinueReason::ReactiveCompactRetry => "reactive_compact_retry",
        ContinueReason::CollapseDrainRetry => "collapse_drain_retry",
        ContinueReason::HookContinuation => "hook_continuation",
        ContinueReason::MicrocompactCompleted => "microcompact_completed",
    }
}

fn classify_terminal(reason: TerminalReason) -> &'static str {
    match reason {
        TerminalReason::Completed => "completed",
        TerminalReason::MaxTurns => "max_turns",
        TerminalReason::MaxCostUsd => "max_cost_usd",
        TerminalReason::AbortedByOperator => "aborted_by_operator",
        TerminalReason::AbortedByHook => "aborted_by_hook",
        TerminalReason::PermissionDenied => "permission_denied",
        TerminalReason::ContextWindowExhausted => "context_window_exhausted",
        TerminalReason::ConnectorFatal => "connector_fatal",
    }
}

fn drive(outcome: TurnOutcome) -> &'static str {
    match outcome {
        TurnOutcome::Continue(reason) => classify_continue(reason),
        TurnOutcome::Terminal(reason) => classify_terminal(reason),
    }
}

#[test]
fn all_continue_variants_are_distinct() {
    let all = [
        ContinueReason::ToolResultsReady,
        ContinueReason::MaxOutputTokensRecovery,
        ContinueReason::ReactiveCompactRetry,
        ContinueReason::CollapseDrainRetry,
        ContinueReason::HookContinuation,
        ContinueReason::MicrocompactCompleted,
    ];
    assert_eq!(all.len(), CONTINUE_VARIANTS);

    let mut tags: Vec<&'static str> = all.into_iter().map(classify_continue).collect();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), CONTINUE_VARIANTS);
}

#[test]
fn all_terminal_variants_are_distinct() {
    let all = [
        TerminalReason::Completed,
        TerminalReason::MaxTurns,
        TerminalReason::MaxCostUsd,
        TerminalReason::AbortedByOperator,
        TerminalReason::AbortedByHook,
        TerminalReason::PermissionDenied,
        TerminalReason::ContextWindowExhausted,
        TerminalReason::ConnectorFatal,
    ];
    assert_eq!(all.len(), TERMINAL_VARIANTS);

    let mut tags: Vec<&'static str> = all.into_iter().map(classify_terminal).collect();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), TERMINAL_VARIANTS);
}

#[test]
fn driver_handles_both_outcome_branches() {
    let cont = TurnOutcome::Continue(ContinueReason::ToolResultsReady);
    let term = TurnOutcome::Terminal(TerminalReason::Completed);

    assert_eq!(drive(cont), "tool_results_ready");
    assert_eq!(drive(term), "completed");
}

#[test]
fn turn_outcome_is_terminal_and_is_continue_reflect_branch() {
    let cont = TurnOutcome::Continue(ContinueReason::HookContinuation);
    let term = TurnOutcome::Terminal(TerminalReason::MaxCostUsd);

    assert!(cont.is_continue());
    assert!(!cont.is_terminal());
    assert!(term.is_terminal());
    assert!(!term.is_continue());
}
