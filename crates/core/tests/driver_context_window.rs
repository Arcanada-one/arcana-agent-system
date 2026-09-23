//! V-AC-4 (D-REQ-04): the context-window guard, and the request contract it
//! exists to honour.
//!
//! The guard degrades in authority order — tool results are elided head-and-
//! tail first, then whole older entries are folded into one `Compacted` span —
//! and reports `Microcompacted`/`ReactiveCompacted` (mapped to the
//! `MicrocompactCompleted` / `ReactiveCompactRetry` continue reasons). A
//! history that cannot be brought inside the budget reports `Irreducible`,
//! which the driver maps to `Terminal(RequestTooLarge)`. The `Task` framing is
//! never removed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{
    compaction_continue, guard_context, ContextVerdict, ContinueReason, Driver, DriverConfig,
    HistoryEntry, TerminalReason, KEEP_RECENT_ENTRIES,
};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::prompt_budget::{compaction_floor, utf16_units, MC_FIELD_MAX_UTF16_UNITS};
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, ScriptedConnector};

/// A tool whose output is larger than any transcript may carry — a `git
/// clone`, a `cargo test`, a `find /`. The whole point of the guard is that a
/// run survives one.
struct FloodTool;

#[async_trait::async_trait]
impl arcana_core::tool::Tool for FloodTool {
    fn name(&self) -> &'static str {
        "flood"
    }

    fn description(&self) -> &'static str {
        "returns more output than a request may hold"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({ "type": "object" })
    }

    async fn execute(
        &self,
        _invocation: arcana_core::tool::ToolInvocation,
    ) -> Result<arcana_core::tool::ToolOutput, arcana_core::tool::ToolError> {
        Ok(arcana_core::tool::ToolOutput {
            content: format!("BEGIN{}END", "0123456789".repeat(40_000)),
            metadata: None,
        })
    }
}

fn tool_result(content_len: usize) -> HistoryEntry {
    HistoryEntry::ToolResult {
        name: "echo".to_string(),
        content: "A".repeat(content_len),
    }
}

/// The size the driver will hand the connector, measured the way the
/// connector measures it.
fn rendered_units(history: &[HistoryEntry]) -> usize {
    history
        .iter()
        .map(|entry| match entry {
            HistoryEntry::Task(text) => utf16_units(text) + utf16_units("[task] \n"),
            HistoryEntry::Assistant(text) => utf16_units(text) + utf16_units("[assistant] \n"),
            HistoryEntry::ToolCall { name, input } => {
                utf16_units(name) + utf16_units(input) + utf16_units("[tool_call]  \n")
            }
            HistoryEntry::ToolResult { name, content } => {
                utf16_units(name) + utf16_units(content) + utf16_units("[tool_result]  \n")
            }
            HistoryEntry::Injected(text) => utf16_units(text) + utf16_units("[injected] \n"),
            HistoryEntry::Compacted(_) => 0,
        })
        .sum()
}

#[test]
fn driver_context_window() {
    // Within budget → Ok, history untouched.
    let mut fits = vec![HistoryEntry::Task("small".to_string())];
    assert_eq!(guard_context(&mut fits, 1_000).verdict, ContextVerdict::Ok);
    assert_eq!(fits.len(), 1, "Ok must not mutate history");

    // One oversized tool-result: eliding it is enough → Microcompacted, and
    // the entry survives with its head, its tail and a statement of the gap.
    let mut single = vec![
        HistoryEntry::Task("t".to_string()),
        HistoryEntry::ToolResult {
            name: "echo".to_string(),
            content: format!("HEAD{}TAIL", "A".repeat(40_000)),
        },
    ];
    let report = guard_context(&mut single, 8_000);
    assert_eq!(report.verdict, ContextVerdict::Microcompacted);
    assert_eq!(report.elided_results, 1);
    assert_eq!(report.folded_entries, 0);
    assert_eq!(single.len(), 2, "the tool result is shortened, not deleted");
    let HistoryEntry::ToolResult { content, .. } = &single[1] else {
        panic!("the tool result must still be a tool result");
    };
    assert!(content.starts_with("HEAD"), "the head is kept");
    assert!(content.ends_with("TAIL"), "the tail is kept");
    assert!(
        content.contains("elided by the runner"),
        "the gap is stated, not hidden: {content}"
    );
    assert!(report.units_after <= 8_000);

    // Many entries the guard cannot shrink far enough by eliding alone: the
    // oldest are folded into one span that says what they were.
    let mut multi = vec![HistoryEntry::Task("t".to_string())];
    for turn in 0..12 {
        multi.push(HistoryEntry::Assistant(format!(
            "turn {turn}: {}",
            "z".repeat(400)
        )));
        multi.push(HistoryEntry::ToolCall {
            name: "echo".to_string(),
            input: json!({ "text": "x" }).to_string(),
        });
        multi.push(tool_result(400));
    }
    let before = rendered_units(&multi);
    let report = guard_context(&mut multi, 2_000);
    assert_eq!(report.verdict, ContextVerdict::ReactiveCompacted);
    assert!(report.folded_entries > 0, "older entries were folded");
    assert!(report.units_after <= 2_000, "{report:?}");
    assert!(report.units_before == before, "{report:?}");
    assert!(
        matches!(multi[0], HistoryEntry::Task(_)),
        "Task framing is never folded"
    );
    let spans: Vec<_> = multi
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::Compacted(span) => Some(span),
            _ => None,
        })
        .collect();
    assert_eq!(spans.len(), 1, "one summary line, not a row of them");
    assert!(
        spans[0].tool_calls.get("echo").copied().unwrap_or(0) > 0,
        "the summary names the tools that ran: {:?}",
        spans[0]
    );
    assert!(spans[0].assistant_turns > 0);

    // Irreducible: the Task alone still overflows and nothing is foldable.
    let mut irreducible = vec![HistoryEntry::Task("a long task framing string".to_string())];
    assert_eq!(
        guard_context(&mut irreducible, 4).verdict,
        ContextVerdict::Irreducible
    );
    assert_eq!(irreducible.len(), 1, "Task is never removed");

    // Verdict → ContinueReason mapping the driver uses.
    assert_eq!(
        compaction_continue(ContextVerdict::Microcompacted),
        Some(ContinueReason::MicrocompactCompleted)
    );
    assert_eq!(
        compaction_continue(ContextVerdict::ReactiveCompacted),
        Some(ContinueReason::ReactiveCompactRetry)
    );
    assert_eq!(compaction_continue(ContextVerdict::Ok), None);
    assert_eq!(compaction_continue(ContextVerdict::Irreducible), None);
}

/// The defect this card exists for, as arithmetic: a transcript of ordinary
/// turns whose serialized size passes the connector's per-field ceiling must
/// come back under it, by construction, before anything is sent.
#[test]
fn a_transcript_past_the_connector_ceiling_is_brought_back_under_it() {
    let mut history = vec![HistoryEntry::Task("the card".to_string())];
    // Ten turns the size the live pilot produced: ~11 000 characters of model
    // text per reply, plus a tool result nobody bounded.
    for turn in 0..10 {
        history.push(HistoryEntry::Assistant(format!(
            "turn {turn} {}",
            "reasoning ".repeat(1_100)
        )));
        history.push(HistoryEntry::ToolCall {
            name: "bash".to_string(),
            input: json!({ "command": "git clone …" }).to_string(),
        });
        history.push(tool_result(30_000));
    }
    let before = rendered_units(&history);
    assert!(
        before > MC_FIELD_MAX_UTF16_UNITS,
        "the fixture must actually overflow: {before} units"
    );

    let report = guard_context(&mut history, 90_000);

    assert_ne!(report.verdict, ContextVerdict::Irreducible, "{report:?}");
    assert!(report.units_after <= 90_000, "{report:?}");
    assert!(
        report
            .stated()
            .is_some_and(|line| line.contains("compacted")),
        "the run must be able to say what it did"
    );
}

#[tokio::test]
async fn driver_context_window_irreducible_terminates() {
    // End-to-end: a budget below the task framing terminates before any call.
    let connector = ScriptedConnector::new(vec![response("unused", 0.0)]);
    let dispatcher = ToolDispatcher::new();
    let cascade = common::allow_cascade();
    let hooks = HookChain::new();
    let cost = Arc::new(CostTracker::new());
    let mut config = DriverConfig::new("scripted");
    config.context_budget_units = 4;

    let (executor, _audit_dir) = common::test_executor(dispatcher, cascade, hooks);
    let driver = Driver::new(
        &connector,
        &executor,
        cost,
        CancellationToken::new(),
        config,
    );
    let out = driver
        .run("a task that will not fit in four characters")
        .await;

    assert_eq!(out.reason, TerminalReason::RequestTooLarge);
    assert!(
        connector.requests().is_empty(),
        "irreducible budget must terminate before any connector call"
    );
}

#[tokio::test]
async fn driver_compaction_consumes_no_turn() {
    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("flood", json!({ "text": "x" })), 0.0),
        response("done", 0.0),
    ]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(FloodTool))
        .expect("register flood");
    let cascade = common::allow_cascade();
    let hooks = HookChain::new();
    let cost = Arc::new(CostTracker::new());
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 2;
    // The first request fits. The 400 000-character tool result does not, and
    // eliding it is enough to bring the transcript back under this ceiling.
    config.context_budget_units = 8_000;
    config.tool_result_budget_units = 8_000;

    let (executor, _audit_dir) = common::test_executor(dispatcher, cascade, hooks);
    let driver = Driver::new(
        &connector,
        &executor,
        cost,
        CancellationToken::new(),
        config,
    );
    let out = driver.run("x").await;

    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(out.turns, 2, "only the two connector attempts count");
    let requests = connector.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        utf16_units(&requests[1].prompt) <= 8_000,
        "the second request must be inside the budget: {} units",
        utf16_units(&requests[1].prompt)
    );
    assert!(
        requests[1].prompt.contains("elided by the runner"),
        "and it must say so rather than pretend the output was that short"
    );
    assert!(
        requests[1].prompt.contains("BEGIN") && requests[1].prompt.contains("END"),
        "both ends of the output survive"
    );
}

/// A tool result is bounded when it ENTERS the transcript, and the untouched
/// output is written where the model is allowed to read it.
#[tokio::test]
async fn an_oversized_tool_result_is_bounded_and_spilled_to_disk() {
    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("flood", json!({ "text": "x" })), 0.0),
        response("done", 0.0),
    ]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(FloodTool))
        .expect("register flood");
    let spill = tempfile::tempdir().expect("spill dir");
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 2;
    config.tool_result_budget_units = 4_000;
    config.tool_output_spill_dir = Some(spill.path().to_path_buf());

    let (executor, _audit_dir) =
        common::test_executor(dispatcher, common::allow_cascade(), HookChain::new());
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    let out = driver.run("x").await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let requests = connector.requests();
    assert!(
        utf16_units(&requests[1].prompt) < 10_000,
        "the 400 000-character result did not enter the transcript whole"
    );
    let spilled: Vec<_> = std::fs::read_dir(spill.path())
        .expect("read spill dir")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(spilled.len(), 1, "the full output was kept");
    let path = spilled[0].path();
    let kept = std::fs::read_to_string(&path).expect("read spill file");
    assert_eq!(kept.len(), 400_008, "kept whole, not the elided copy");
    assert!(
        requests[1].prompt.contains(&path.display().to_string()),
        "the marker names the file the model may read"
    );
}

/// A2-225: the pilot's shape — one unbounded model reply, at the newest end of
/// a long transcript, is what made compaction collapse the run.
///
/// Measured on run A2-204c4 (audit `~/.local/state/arcana/run/audit.log`,
/// dispatches turn 29 → turn 30): the request went 78 234 → 179 037 characters
/// in a single turn, which only one entry can explain — a model reply of some
/// 100 000 characters, a kind of entry nothing bounded. The guard then folded
/// **73** earlier entries and handed the model a 7 098-character request: 8% of
/// its budget, with every fact the run had gathered gone. Folding is strictly
/// oldest-first, so reaching the one oversized entry meant destroying
/// everything in front of it, and the loop's only other stop was "two entries
/// left".
///
/// The contract this pins: an over-budget transcript lands inside a stated band
/// — at or under the budget, at or above [`compaction_floor`] — and still
/// carries its task statement verbatim.
#[test]
fn one_oversized_recent_entry_does_not_collapse_the_whole_transcript() {
    const BUDGET: usize = 90_000;
    const TASK: &str = "A2-225: find why compaction folds a long run to nothing";

    let mut history = vec![HistoryEntry::Task(TASK.to_string())];
    // 24 ordinary turns: a reply, a call, a result already bounded at
    // ingestion the way `carry_tool_result` bounds it.
    for turn in 0..24 {
        history.push(HistoryEntry::Assistant(format!(
            "turn {turn}: {}",
            "looking at the file ".repeat(60)
        )));
        history.push(HistoryEntry::ToolCall {
            name: "bash".to_string(),
            input: json!({ "command": format!("rg -n pattern{turn} crates/") }).to_string(),
        });
        history.push(tool_result(1_800));
    }
    // The newest reply: the one entry nothing bounds.
    history.push(HistoryEntry::Assistant(format!(
        "FINAL PLAN {}",
        "z".repeat(100_000)
    )));

    let before = rendered_units(&history);
    assert!(before > BUDGET, "the fixture must overflow: {before}");

    let report = guard_context(&mut history, BUDGET);

    assert_ne!(report.verdict, ContextVerdict::Irreducible, "{report:?}");
    assert!(
        report.units_after <= BUDGET,
        "over the budget it was working to: {report:?}"
    );
    assert!(
        report.units_after >= compaction_floor(BUDGET),
        "compaction landed near zero instead of near its target: {report:?}"
    );
    // The task statement, verbatim, is what a run needs to still be the same
    // run after compaction.
    assert!(
        history
            .iter()
            .any(|entry| matches!(entry, HistoryEntry::Task(text) if text == TASK)),
        "the task statement did not survive compaction verbatim"
    );
    assert!(
        matches!(history[0], HistoryEntry::Task(_)),
        "the Task entry is never folded"
    );
    // The most recent turns are what the next reply answers; they stay as
    // entries of their own rather than being swallowed by the summary.
    let recent = history.len()
        - history
            .iter()
            .position(|entry| matches!(entry, HistoryEntry::Compacted(_)))
            .map_or(0, |index| index + 1);
    assert!(
        recent >= KEEP_RECENT_ENTRIES,
        "only {recent} entries survived the fold, expected at least {KEEP_RECENT_ENTRIES}"
    );
}

/// The band, stated as a property over many shapes rather than one fixture.
#[test]
fn compaction_lands_in_the_stated_band_whatever_overflowed() {
    const BUDGET: usize = 40_000;
    for (label, giant_at) in [("oldest", 1usize), ("middle", 20), ("newest", 39)] {
        let mut history = vec![HistoryEntry::Task("the task".to_string())];
        for turn in 0..40 {
            history.push(HistoryEntry::Assistant(format!(
                "turn {turn} {}",
                "a".repeat(900)
            )));
        }
        let HistoryEntry::Assistant(text) = &mut history[giant_at] else {
            panic!("fixture");
        };
        *text = "G".repeat(120_000);

        let report = guard_context(&mut history, BUDGET);
        assert_ne!(
            report.verdict,
            ContextVerdict::Irreducible,
            "{label}: {report:?}"
        );
        assert!(report.units_after <= BUDGET, "{label}: {report:?}");
        assert!(
            report.units_after >= compaction_floor(BUDGET),
            "{label}: collapsed below the floor: {report:?}"
        );
    }
}
