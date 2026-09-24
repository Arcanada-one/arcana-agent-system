//! A2-248: a complete call followed by a surplus `}` is that call, not garbage.
//!
//! `a2-248-surplus-brace-reply.txt` is byte-for-byte turn 62 of pilot run
//! A2-240b (`/home/dev/aup/arc2/wt/A2-240b/.arcana/rejected/0001-turn62.txt`,
//! sha256 `252d444b5fe0dd…`, ARAS `53ff117`, `deepseek-flash` through Model
//! Connector, 2026-09-24T00:28:13Z). The body of its `tool_call` fence is a
//! **complete, valid** JSON object — `{"name":"write","path":…,
//! "create_parent_dirs":true,"content":…}`, the A2-219 flat form this runner
//! already accepts — and then one more `}`. `serde_json::from_str` refuses
//! trailing data, so the whole reply became "not valid JSON", nothing ran, and
//! the turn was spent on a correction. One character, one of the hundred turns
//! that run was allowed.
//!
//! # The rule, stated once
//!
//! A body that does not parse whole is re-read as *a JSON value followed by a
//! remainder*, and the value is used **only when the remainder is nothing but
//! `}`, `]` and whitespace**. Surplus closing punctuation cannot name a tool,
//! add an argument or change a value — dropping it leaves exactly one reading
//! of the text, so accepting the prefix cannot dispatch anything other than
//! what the model wrote.
//!
//! Everything else stays a correction, and the tests below are what keeps that
//! true:
//!
//!   * a **second JSON object** after the first is a second call. Running the
//!     first and saying nothing about the second would silently drop work the
//!     model asked for — a different meaning, not a repaired one.
//!   * a **trailing comma** (`{"name":"bash",}`) is not reachable by this rule
//!     at all, and deliberately so: it fails *inside* the braces, so there is
//!     no prefix to take, and repairing it would mean editing the object
//!     rather than truncating a suffix. Once a parser edits inside the object
//!     it is guessing at intent.
//!   * a prefix that is not a call (`"hello"}`) still fails, on the reason it
//!     actually has — no `name` — not on the punctuation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use arcana_core::agent_loop::{interpret, AssistantAction};

use common::response;

/// Turn 62 of pilot A2-240b, as the model sent it.
const SURPLUS_BRACE_REPLY: &str = include_str!("fixtures/a2-248-surplus-brace-reply.txt");

// ---------------------------------------------------------------------------
// The live reply
// ---------------------------------------------------------------------------

#[test]
fn the_live_reply_with_one_surplus_brace_is_the_call_the_model_wrote() {
    match interpret(&response(SURPLUS_BRACE_REPLY, 0.0)) {
        AssistantAction::ToolCall { name, input } => {
            assert_eq!(name, "write");
            assert_eq!(
                input["path"], "runs/A2-240b/diag/probe2.sh",
                "the path arrives as sent: {input}"
            );
            assert_eq!(
                input["create_parent_dirs"],
                serde_json::json!(true),
                "a non-string argument keeps its type: {input}"
            );
            let content = input["content"].as_str().expect("a content argument");
            assert!(
                content.contains("== env names ==") && content.ends_with("echo OK\n"),
                "the content arrives whole, head and tail: {content}"
            );
            assert_eq!(
                input.as_object().expect("an object").len(),
                3,
                "`name` is the tool, never one of its arguments: {input}"
            );
        }
        other => panic!("one surplus brace must not cost a turn: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The rule, and its edges
// ---------------------------------------------------------------------------

#[test]
fn surplus_closers_of_either_kind_and_trailing_space_are_dropped() {
    let body = "{\"name\": \"bash\", \"input\": {\"command\": \"ls\"}}}] \n";
    match interpret(&response(&format!("```tool_call\n{body}\n```"), 0.0)) {
        AssistantAction::ToolCall { name, input } => {
            assert_eq!(name, "bash");
            assert_eq!(input["command"], "ls");
        }
        other => panic!("only closers followed the call: {other:?}"),
    }
}

#[test]
fn a_second_object_after_the_first_stays_a_correction() {
    // Both are well-formed calls. Taking the first would run one command and
    // drop the other without saying so.
    let body = "{\"name\": \"bash\", \"input\": {\"command\": \"ls\"}}\
                {\"name\": \"bash\", \"input\": {\"command\": \"rm -rf .\"}}";
    match interpret(&response(&format!("```tool_call\n{body}\n```"), 0.0)) {
        AssistantAction::MalformedToolCall { detail, .. } => assert!(
            detail.contains("not valid JSON"),
            "the model is told its block did not parse: {detail}"
        ),
        other => panic!("a dropped second call is a changed meaning: {other:?}"),
    }
}

#[test]
fn a_trailing_comma_is_not_reachable_by_this_rule() {
    let body = "{\"name\": \"bash\", \"input\": {\"command\": \"ls\"},}";
    match interpret(&response(&format!("```tool_call\n{body}\n```"), 0.0)) {
        AssistantAction::MalformedToolCall { detail, .. } => assert!(
            detail.contains("not valid JSON"),
            "a repair inside the braces is a guess, not a truncation: {detail}"
        ),
        other => panic!("the object itself is malformed here: {other:?}"),
    }
}

#[test]
fn a_prefix_that_is_not_a_call_fails_on_the_reason_it_has() {
    match interpret(&response("```tool_call\n\"hello\"}\n```", 0.0)) {
        AssistantAction::MalformedToolCall { detail, .. } => assert!(
            detail.contains("`name`"),
            "the punctuation is not the complaint; the missing tool is: {detail}"
        ),
        other => panic!("a bare string names no tool: {other:?}"),
    }
}

#[test]
fn a_body_that_parses_whole_is_untouched_by_any_of_this() {
    match interpret(&response(
        "```tool_call\n{\"name\": \"bash\", \"input\": {\"command\": \"ls\"}}\n```",
        0.0,
    )) {
        AssistantAction::ToolCall { name, .. } => assert_eq!(name, "bash"),
        other => panic!("the ordinary path must not move: {other:?}"),
    }
}

#[test]
fn the_correction_names_the_parse_error_so_the_model_can_fix_it() {
    // "not valid JSON" alone told a model nothing about *where*. The serde
    // message carries a line and column; a model that is handed them can send
    // the same call corrected instead of guessing at a rewrite.
    match interpret(&response("```tool_call\n{\"name\": \"bash\",}\n```", 0.0)) {
        AssistantAction::MalformedToolCall { detail, .. } => assert!(
            detail.contains("line") && detail.contains("column"),
            "the correction must locate the fault: {detail}"
        ),
        other => panic!("a trailing comma is a correction: {other:?}"),
    }
}
