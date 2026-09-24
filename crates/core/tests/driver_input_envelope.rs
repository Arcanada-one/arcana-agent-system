//! A2-253: the `input` key applied twice is one call, not seven corrections.
//!
//! Pilot A2-240c (arcana `17cffe0`, `deepseek-flash` through Model Connector,
//! 2026-09-24T02:20Z, log `/home/dev/aup/arc2/runs/A2-240c/log`) ran 68 turns
//! and 63 attempted tool calls. Thirteen were refused, and **seven** of the
//! thirteen were one shape: a `bash` call whose `command` was already correct,
//! wrapped in a second `input` key —
//!
//! ```text
//! {"name": "bash", "input": {"input": {"command": "…", "timeout_seconds": 300}}}
//! ```
//!
//! — refused at the `schema` layer with `Additional properties are not allowed
//! ('input' was unexpected); "command" is a required property`
//! (`/home/dev/aup/arc2/wt/A2-240c/.arcana/denied/`, turns 11, 25, 30, 42, 43,
//! 54, 65).
//!
//! # Why this is unwrapped rather than corrected harder
//!
//! The runner already corrected it. `fold_denial` hands a `schema` refusal
//! back naming the unexpected key and the missing one, and the model wrote the
//! envelope again, seven times, across 63 calls. The same run is also the
//! control: a quoted integer (`"timeout_seconds": "400"`, turn 52) was refused
//! once and the very next call carried an unquoted `300` (turn 53). A
//! correction that works, and a correction that does not, measured in one run.
//!
//! The licence is a property of the shipped tool set, not a guess about
//! intent: no tool declares a property named `input`, `arguments`,
//! `parameters` or `args`, and every tool schema sets `additionalProperties:
//! false`. An arguments object whose ONLY key is one of those spellings is
//! therefore invalid for every tool in the registry — it cannot be a call to
//! anything — so reading it as the envelope it is cannot change which call
//! runs. `crates/cli/tests/run_envelope_premise.rs` pins that premise against
//! the registry the CLI actually assembles.
//!
//! # The fixtures
//!
//! Both are **reconstructions**, and are labelled so on purpose. This class
//! never reached `.arcana/rejected/` — the reply parsed, produced a call, and
//! was refused downstream — so the only surviving artefact is the denied
//! record, which stores the arguments *after* `tool_dialect` read them. Each
//! fixture is the fence body that yields its record's `input` byte-for-byte;
//! the prose around the fence is ours.
//!
//! The string-valued fixture carries the detail that decided four of the seven
//! repeats: the inner JSON string ends with one surplus `}` (all four
//! string-valued records parse after dropping exactly one trailing
//! character), so a strict `serde_json::from_str` reads it as "not JSON" and
//! leaves the envelope standing. The surplus-closer licence A2-248 wrote for
//! the fence body is reused for it, which is why that helper now lives in
//! `tool_dialect` beside the reader that needs it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use arcana_core::agent_loop::{interpret, AssistantAction};
use serde_json::json;

use common::response;

/// Turn 43 of pilot A2-240c: the envelope holding an object.
const ENVELOPE_OBJECT: &str = include_str!("fixtures/a2-253-envelope-object-reply.txt");
/// Turn 11 of pilot A2-240c: the envelope holding a JSON string, surplus `}`
/// and all.
const ENVELOPE_STRING: &str = include_str!("fixtures/a2-253-envelope-string-reply.txt");

/// The call `interpret` produced, or a panic naming what it produced instead.
fn call(reply: &str) -> (String, serde_json::Value) {
    match interpret(&response(reply, 0.0)) {
        AssistantAction::ToolCall { name, input } => (name, input),
        other => panic!("expected a dispatched call, got {other:?}"),
    }
}

/// What `interpret` said, for the cases that must NOT become a call.
fn not_a_call(reply: &str) -> AssistantAction {
    let action = interpret(&response(reply, 0.0));
    assert!(
        !matches!(&action, AssistantAction::ToolCall { input, .. } if input.get("command").is_some()),
        "this shape must not dispatch a command: {action:?}"
    );
    action
}

/// Wrap `body` in the canonical fence, as a reply.
fn fenced(body: &str) -> String {
    format!("```tool_call\n{body}\n```\n")
}

// ---------------------------------------------------------------------------
// The live shapes
// ---------------------------------------------------------------------------

#[test]
fn the_live_envelope_around_an_object_is_the_call_the_model_meant() {
    let (name, input) = call(ENVELOPE_OBJECT);
    assert_eq!(name, "bash");
    assert_eq!(
        input["timeout_seconds"], 200,
        "the arguments arrive with their types: {input}"
    );
    let command = input["command"].as_str().expect("a command argument");
    assert!(
        command.starts_with("cd runs/A2-240c &&") && command.ends_with("cat netfinal.out"),
        "the command arrives whole, head and tail: {command}"
    );
    assert!(
        input.get("input").is_none(),
        "the wrapper key is gone, not carried into the call: {input}"
    );
    assert_eq!(
        input.as_object().expect("an object").len(),
        2,
        "exactly the two arguments the model wrote: {input}"
    );
}

#[test]
fn the_live_envelope_around_a_json_string_with_a_surplus_brace_is_that_call() {
    let (name, input) = call(ENVELOPE_STRING);
    assert_eq!(name, "bash");
    assert_eq!(input["timeout_seconds"], 120, "{input}");
    assert!(
        input["command"]
            .as_str()
            .expect("a command argument")
            .contains("existing clones in worktree"),
        "the command arrives decoded, not as a string blob: {input}"
    );
    assert_eq!(input.as_object().expect("an object").len(), 2, "{input}");
}

#[test]
fn the_surplus_brace_alone_is_what_kept_four_of_the_seven_wrapped() {
    // The same text without the stray `}` was already readable; with it, the
    // strict parse fails. Both must now produce the identical call, which is
    // the whole claim of reusing the A2-248 licence here.
    let inner = json!({"command": "ls -la", "timeout_seconds": 30}).to_string();
    let with_surplus_brace = inner.clone() + "}";
    let clean = fenced(&json!({"name": "bash", "input": {"input": inner}}).to_string());
    let surplus =
        fenced(&json!({"name": "bash", "input": {"input": with_surplus_brace}}).to_string());
    assert_eq!(call(&clean), call(&surplus));
    assert_eq!(call(&surplus).1["command"], "ls -la");
}

// ---------------------------------------------------------------------------
// The edges the licence deliberately does not cover
// ---------------------------------------------------------------------------

#[test]
fn an_envelope_beside_a_real_argument_is_not_an_envelope() {
    // Two keys: one of them is an argument the model wrote, and choosing
    // which half to keep would be deciding for it. Stays a correction.
    //
    // Both key orders are here on purpose. `serde_json`'s default map is
    // sorted, so a case where the wrapper key sorts LAST (`input` after
    // `command`) is refused by the sort and would still pass if the
    // single-key guard were deleted; only `input` before `timeout_seconds`
    // actually reaches the guard. A test that cannot go red is not a test.
    let wrapper_sorts_last = fenced(
        &json!({"name": "bash", "input": {"input": {"command": "rm x"}, "command": "ls"}})
            .to_string(),
    );
    let (_, input) = call(&wrapper_sorts_last);
    assert!(
        input.get("input").is_some() && input["command"] == "ls",
        "both keys survive untouched for the schema layer to refuse: {input}"
    );

    let wrapper_sorts_first = fenced(
        &json!({"name": "bash", "input": {"input": {"command": "rm x"}, "timeout_seconds": 5}})
            .to_string(),
    );
    let (_, input) = call(&wrapper_sorts_first);
    assert_eq!(
        input,
        json!({"input": {"command": "rm x"}, "timeout_seconds": 5}),
        "neither half is dropped: {input}"
    );
}

#[test]
fn an_inner_value_that_is_not_an_object_carries_no_call_to_unwrap() {
    for inner in [json!(5), json!("soon"), json!(["ls"]), json!(true)] {
        let reply = fenced(&json!({"name": "bash", "input": {"input": inner}}).to_string());
        let action = not_a_call(&reply);
        if let AssistantAction::ToolCall { input, .. } = action {
            assert!(
                input.get("input").is_some(),
                "the envelope is left standing for the schema layer: {input}"
            );
        }
    }
}

#[test]
fn only_one_level_is_unwrapped() {
    // A second envelope is not a spelling of the documented format; it is a
    // model that has lost the shape, and nothing in the pilot measured it.
    let reply = fenced(
        &json!({"name": "bash", "input": {"input": {"input": {"command": "ls"}}}}).to_string(),
    );
    let (_, input) = call(&reply);
    assert_eq!(
        input,
        json!({"input": {"command": "ls"}}),
        "one level off, the rest is the schema layer's to refuse: {input}"
    );
}

#[test]
fn a_tool_called_with_a_single_ordinary_argument_is_untouched() {
    // The rule keys on the wrapper spellings and nothing else. A one-key
    // arguments object whose key is a real argument must not be disturbed.
    let reply = fenced(&json!({"name": "read", "input": {"path": "notes.md"}}).to_string());
    let (name, input) = call(&reply);
    assert_eq!(name, "read");
    assert_eq!(input, json!({"path": "notes.md"}));
}
