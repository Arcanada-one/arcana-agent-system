//! A2-249 / D2: one reply may not erase the history of a run.
//!
//! A tool result is bounded when it enters the transcript —
//! `Driver::carry_tool_result` caps it at `tool_result_budget_units`. A model
//! **reply** was not: it entered whole, and `prompt_budget::entry_ceiling`
//! only reached it later, from inside compaction, once the budget had already
//! been blown and the guard's only remaining move was to fold earlier turns
//! away.
//!
//! Measured on pilot A2-240b (`/home/dev/aup/arc2/runs/A2-248/report.md` § 6,
//! D2): between turn 36 and turn 37 the transcript grew 63 485 → 111 713
//! UTF-16 units — **+48 228 from a single reply, 54 % of the whole budget** —
//! and the compaction that followed folded 28 earlier entries into a summary.
//! Thirty-six turns of history were destroyed by one turn's output.
//!
//! What is pinned here: a reply that large is cut at intake, the cut says so,
//! and the turns before it are still in the next request.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::prompt_budget::{entry_ceiling, utf16_units, DEFAULT_CONTEXT_BUDGET_UTF16_UNITS};
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{allow_cascade, response, tool_call_result, EchoTool, ScriptedConnector};

/// The pilot's number: what one reply added to the transcript on turn 37.
const A2_240B_REPLY_UNITS: usize = 48_228;

/// A marker the test can find at both ends of a reply, so "the head and the
/// tail survived" is checkable rather than assumed.
const HEAD: &str = "HEAD-OF-THE-REPLY";
const TAIL: &str = "TAIL-OF-THE-REPLY";

/// A reply of `units` UTF-16 units with findable ends.
fn huge_reply(units: usize) -> String {
    let filler = units - utf16_units(HEAD) - utf16_units(TAIL);
    format!("{HEAD}{}{TAIL}", "x".repeat(filler))
}

async fn drive(replies: Vec<String>) -> (RunOutput, Vec<String>) {
    let connector = ScriptedConnector::new(replies.iter().map(|t| response(t, 0.0)).collect());
    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(EchoTool))
        .expect("register echo");
    let (executor, _audit_dir) = common::test_executor(registry, allow_cascade(), HookChain::new());
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 12;
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    let out = driver.run("do a long task").await;
    let prompts = connector
        .requests()
        .into_iter()
        .map(|req| req.prompt)
        .collect();
    (out, prompts)
}

fn echo(text: &str) -> String {
    tool_call_result("echo", json!({ "text": text }))
}

/// The `[assistant] …` entry of a serialized transcript that contains `needle`,
/// cut at the next entry header. Entries may span lines, so `lines()` would
/// measure a fragment of one and call it the entry.
fn entry_holding<'a>(prompt: &'a str, needle: &str) -> &'a str {
    let at = prompt.find(needle).expect("the reply is in the transcript");
    let start = prompt[..at]
        .rfind("[assistant] ")
        .expect("the reply is an assistant entry");
    let end = prompt[start..]
        .find("\n[tool_call] ")
        .map_or(prompt.len(), |offset| start + offset);
    &prompt[start..end]
}

#[tokio::test]
async fn a_reply_the_size_of_the_pilots_is_cut_at_intake_and_says_so() {
    let ceiling = entry_ceiling(DEFAULT_CONTEXT_BUDGET_UTF16_UNITS);
    let big = format!("{}\n{}", huge_reply(A2_240B_REPLY_UNITS), echo("after"));
    let (out, prompts) = drive(vec![echo("before"), big, echo("last"), "done".to_owned()]).await;
    assert_eq!(out.reason, TerminalReason::Completed, "{out:?}");

    // The request that follows the huge reply is the one that used to carry
    // all 48 228 units of it.
    let after = &prompts[2];
    let assistant = entry_holding(after, HEAD);
    assert!(
        utf16_units(assistant) <= ceiling + 32,
        "one reply took {} units of a {ceiling}-unit ceiling",
        utf16_units(assistant)
    );
    assert!(
        assistant.contains("elided by the runner"),
        "the cut must state itself, like every other elision"
    );
    assert!(assistant.contains(HEAD), "the head is kept");
    assert!(assistant.contains(TAIL), "the tail is kept");
}

#[tokio::test]
async fn the_history_of_earlier_turns_survives_a_reply_that_size() {
    let big = format!("{}\n{}", huge_reply(A2_240B_REPLY_UNITS), echo("after"));
    let (out, prompts) = drive(vec![
        echo("first-call-marker"),
        big,
        echo("last"),
        "done".to_owned(),
    ])
    .await;
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(
        out.compactions, 0,
        "63 485 + a capped reply is inside the 90 000-unit budget, so nothing \
         had to be folded — this is the whole point of capping at intake"
    );
    let last = prompts.last().expect("a last request");
    assert!(
        last.contains("first-call-marker"),
        "the turn before the huge reply must still be in the transcript"
    );
    assert!(
        last.contains("[task] do a long task"),
        "and so must the task"
    );
}

#[tokio::test]
async fn an_ordinary_reply_is_carried_verbatim() {
    // The cap must be invisible to every reply that is not pathological, or
    // it is a second, silent rewrite of what the model said.
    let text = "I read the file and it says 42.";
    let (out, prompts) = drive(vec![echo("x"), text.to_owned()]).await;
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(out.final_text.as_deref(), Some(text));
    assert!(
        prompts[1].contains("[assistant] ```tool_call"),
        "an ordinary reply enters the transcript untouched: {}",
        prompts[1]
    );
    assert!(
        !prompts.iter().any(|p| p.contains("elided by the runner")),
        "nothing ordinary is elided"
    );
}

#[tokio::test]
async fn the_final_answer_is_delivered_whole_even_when_the_transcript_cut_it() {
    // The cap bounds what the RUN carries forward, not what the operator is
    // given. A run whose last reply is enormous must still hand over all of
    // it — it is already paid for.
    let big = huge_reply(A2_240B_REPLY_UNITS);
    let (out, _prompts) = drive(vec![echo("x"), big.clone()]).await;
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(
        out.final_text.as_deref(),
        Some(big.as_str()),
        "the answer is delivered as the model wrote it"
    );
}
