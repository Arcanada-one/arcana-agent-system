//! A2-219: arguments written as siblings of `name` are the call's arguments,
//! not a missing `input` object.
//!
//! Both fixtures here are byte-for-byte replies a live `deepseek-flash` run
//! sent on 2026-09-23 and this runner threw away. They exist only because the
//! same card taught the runner to keep a rejected reply
//! (`crates/core/src/agent_loop.rs`, `save_rejected_reply`) — before that, a
//! run that died `UnsupportedToolCallFormat` left `input_hash`/`output_hash`
//! in the audit log and no text anywhere, so the defect could be reported and
//! not diagnosed.
//!
//! The two replies are deliberately not the same verdict:
//!
//!   * `a2-219-flat-arguments-reply.txt` — this runner's own fence, the right
//!     tool, the right arguments, no wrapper object around them. Unambiguous,
//!     so it is accepted and dispatched.
//!   * `a2-219-no-name-reply.txt` — the same fence with no `name` key at all.
//!     Nothing names a tool, nothing can be inferred, so it stays a
//!     correction. Pinned here so "accept the flat form" cannot quietly widen
//!     into "accept anything in a fence".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{interpret, AssistantAction, Driver, DriverConfig, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use arcana_core::tool_dialect::{arguments_of, declared_call_arguments, flat_arguments};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use common::{allow_cascade, response, EchoTool, ScriptedConnector};

/// Turn 1 of the A2-219 repro run: `bash`, with `command` and
/// `timeout_seconds` as plain siblings of `name`.
const FLAT_REPLY: &str = include_str!("fixtures/a2-219-flat-arguments-reply.txt");
/// Turn 12 of the same run: a fenced object with no `name` at all.
const NO_NAME_REPLY: &str = include_str!("fixtures/a2-219-no-name-reply.txt");

// ---------------------------------------------------------------------------
// The two live replies, classified
// ---------------------------------------------------------------------------

#[test]
fn the_live_flat_reply_is_a_call_with_the_arguments_the_model_sent() {
    match interpret(&response(FLAT_REPLY, 0.0)) {
        AssistantAction::ToolCall { name, input } => {
            assert_eq!(name, "bash");
            let command = input["command"].as_str().expect("a command argument");
            assert!(
                command.contains("git clone") && command.contains("git log --oneline -3"),
                "the command must arrive whole: {command}"
            );
            assert_eq!(
                input["timeout_seconds"],
                json!(600),
                "a non-string argument keeps its type"
            );
            assert_eq!(
                input.as_object().expect("an object").len(),
                2,
                "`name` is the tool, never one of its arguments: {input}"
            );
        }
        other => panic!("the reply that cost the pilot its run is a call: {other:?}"),
    }
}

#[test]
fn the_live_reply_with_no_name_is_still_a_correction() {
    match interpret(&response(NO_NAME_REPLY, 0.0)) {
        AssistantAction::MalformedToolCall { detail, .. } => {
            assert!(
                detail.contains("`name`"),
                "the correction must say what is missing: {detail}"
            );
        }
        other => panic!("nothing names a tool here, so nothing may be dispatched: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The reader itself
// ---------------------------------------------------------------------------

#[test]
fn siblings_of_name_are_the_arguments_and_name_is_not() {
    let value = json!({ "name": "bash", "command": "ls", "timeout_seconds": 60 });
    assert_eq!(
        flat_arguments(&value),
        Some(json!({ "command": "ls", "timeout_seconds": 60 }))
    );
    // The wrapper reader still knows nothing about this shape; only the
    // combined reader used by declared markup does.
    assert_eq!(arguments_of(&value), None);
    assert_eq!(declared_call_arguments(&value), flat_arguments(&value));
}

#[test]
fn a_wrapper_key_wins_over_the_siblings_it_sits_beside() {
    let value = json!({ "name": "bash", "input": { "command": "ls" }, "id": "call_1" });
    assert_eq!(
        declared_call_arguments(&value),
        Some(json!({ "command": "ls" })),
        "a model that sent both meant the object it wrapped"
    );
}

#[test]
fn a_declined_null_wrapper_key_is_not_smuggled_back_in_as_a_sibling() {
    let value = json!({ "name": "bash", "input": Value::Null, "command": "ls" });
    assert_eq!(
        declared_call_arguments(&value),
        Some(json!({ "command": "ls" })),
        "`input: null` was declined as a wrapper; it is not an argument either"
    );
}

#[test]
fn a_call_with_nothing_but_a_name_still_has_no_arguments() {
    let value = json!({ "name": "edit" });
    assert_eq!(flat_arguments(&value), None);
    assert_eq!(declared_call_arguments(&value), None);
    match interpret(&response("```tool_call\n{\"name\": \"edit\"}\n```", 0.0)) {
        AssistantAction::MalformedToolCall { detail, .. } => assert!(
            detail.contains("carried no arguments"),
            "the model is told its call is empty, not handed an empty object: {detail}"
        ),
        other => panic!("an empty call is a correction: {other:?}"),
    }
}

#[test]
fn a_plain_json_answer_in_prose_is_not_read_as_a_call_to_its_name_field() {
    // The negative control for the whole change. Outside markup that exists
    // only to carry a call, an object with a `name` is just an object.
    let reply = "Here is the record you asked for:\n\n{\"name\": \"Alice\", \"age\": 30}";
    match interpret(&response(reply, 0.0)) {
        AssistantAction::Final { .. } => {}
        other => panic!("an answer must not cost a correction turn: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// End to end: the flat call actually executes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_flat_call_runs_the_tool_it_names() {
    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(EchoTool))
        .expect("register echo");
    let connector = ScriptedConnector::new(vec![
        response(
            "```tool_call\n{\"name\": \"echo\", \"text\": \"hello\"}\n```",
            0.0,
        ),
        response("done", 0.0),
    ]);
    let (executor, _audit) = common::test_executor(registry, allow_cascade(), HookChain::new());
    let mut config = DriverConfig::new("scripted");
    config.require_action = true;
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    let out = driver.run("say hello").await;

    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(out.tool_calls, 1, "the call ran, it was not corrected");
    let second = &connector.requests()[1].prompt;
    assert!(
        second.contains("echo:{\"text\":\"hello\"}"),
        "the tool saw the siblings as its input: {second}"
    );
}
