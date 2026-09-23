//! A2-212: a turn that asks for a tool is never reported as a finished run,
//! whatever markup the model wrote it in.
//!
//! Measured 2026-09-23 on `deepseek-v4-flash` through Model Connector
//! (`/home/dev/aup/arc2/runs/A2-204c/log`): the first turn of a real task came
//! back as DeepSeek's native `invoke` markup, the loop read it as prose, and
//! the run printed
//! `ARCANA_RUN_DONE {"completed":true,"reason":"Completed","tool_calls":2}`
//! having executed nothing. The bug is not that the model was wrong — it asked
//! for a shell command in the only dialect it knew — it is that a request to
//! act was recorded as an answer.
//!
//! Two behaviours are pinned here:
//!   1. `invoke` markup is translated into a real call and the tool runs.
//!   2. A recognisable attempt we will NOT translate costs the model exactly
//!      one correction naming the expected format, and then ends the run on
//!      `UnsupportedToolCallFormat` with `tool_calls: 0` — never `Completed`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{
    Driver, DriverConfig, RunOutput, TerminalReason, MAX_DIALECT_CORRECTIONS,
};
use arcana_core::connector::ConnectorResponse;
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{allow_cascade, response, tool_call_result, EchoTool, ScriptedConnector};

/// The live A2-204c reply shape, with `echo` in place of `bash` so the run can
/// execute offline. The fullwidth sentinels are byte-for-byte what DeepSeek
/// emitted.
fn dsml_call(name: &str, parameter: &str, value: &str) -> String {
    format!(
        "<｜｜DSML｜｜ calls>\n\
         <｜｜DSML｜｜ invoke name=\"{name}\">\n\
         <｜｜DSML｜｜ parameter name=\"{parameter}\" string=\"true\">{value}\
         </｜｜DSML｜｜ parameter>\n\
         </｜｜DSML｜｜ invoke>\n\
         </｜｜DSML｜｜ calls>"
    )
}

fn echo_dispatcher() -> ToolDispatcher {
    let mut disp = ToolDispatcher::new();
    disp.register(Arc::new(EchoTool)).expect("register echo");
    disp
}

/// Drive one script to a terminal outcome; returns the outcome and every
/// prompt the connector was sent, so a test can read what the model was told.
async fn run_script(
    responses: Vec<ConnectorResponse>,
    cascade: PermissionCascade,
) -> (RunOutput, Vec<String>) {
    let connector = ScriptedConnector::new(responses);
    let cost = Arc::new(CostTracker::new());
    let (executor, _audit_dir) =
        common::test_executor(echo_dispatcher(), cascade, HookChain::new());
    let mut config = DriverConfig::new("scripted");
    config.require_action = true;
    let driver = Driver::new(
        &connector,
        &executor,
        cost,
        CancellationToken::new(),
        config,
    );
    let out = driver.run("do a small task").await;
    let prompts = connector
        .requests()
        .into_iter()
        .map(|req| req.prompt)
        .collect();
    (out, prompts)
}

#[tokio::test]
async fn native_invoke_markup_executes_the_tool_it_names() {
    let (out, _) = run_script(
        vec![
            response(&dsml_call("echo", "text", "hello"), 0.0),
            response("done", 0.0),
        ],
        allow_cascade(),
    )
    .await;

    assert_eq!(
        out.tool_calls, 1,
        "the tool the model asked for must actually run: {out:?}"
    );
    assert_eq!(out.reason, TerminalReason::Completed);
}

#[tokio::test]
async fn an_unexecutable_dialect_is_corrected_once_then_ends_the_run() {
    // A bare OpenAI-shaped object, repeated: recognisable as a call, not
    // something we are willing to dispatch.
    let bare = "{\"name\":\"echo\",\"arguments\":{\"text\":\"hello\"}}";
    let (out, prompts) = run_script(
        vec![
            response(bare, 0.0),
            response(bare, 0.0),
            response(bare, 0.0),
        ],
        allow_cascade(),
    )
    .await;

    assert_eq!(
        out.reason,
        TerminalReason::UnsupportedToolCallFormat,
        "a run that only ever asked for tools in an unreadable dialect did not complete"
    );
    assert_eq!(out.tool_calls, 0, "nothing ran");
    assert_eq!(
        out.turns, MAX_DIALECT_CORRECTIONS,
        "one correction, then the verdict — the model is not asked a third time"
    );

    // The correction has to be actionable: it names the format, in full.
    let second = prompts.get(1).expect("a second dispatch was made");
    assert!(
        second.contains("NOTHING WAS EXECUTED"),
        "the model must be told nothing ran: {second}"
    );
    assert!(
        second.contains("```tool_call"),
        "the correction must restate the encoding that works: {second}"
    );
}

#[tokio::test]
async fn a_call_that_executes_clears_the_format_streak() {
    // The bound counts CONSECUTIVE failures. A long run that slips into the
    // wrong dialect twice, an hour and a dozen successful calls apart, is not
    // the failure this stops.
    let bare = "{\"name\":\"echo\",\"arguments\":{\"text\":\"hello\"}}";
    let good = tool_call_result("echo", json!({ "text": "x" }));
    let (out, _) = run_script(
        vec![
            response(bare, 0.0),
            response(&good, 0.0),
            response(bare, 0.0),
            response(&good, 0.0),
            response("all done", 0.0),
        ],
        allow_cascade(),
    )
    .await;

    assert_eq!(out.reason, TerminalReason::Completed, "{out:?}");
    assert_eq!(out.tool_calls, 2);
}

#[tokio::test]
async fn a_misspelt_canonical_block_is_corrected_not_delivered_as_the_answer() {
    // The regression that hid inside `parse_tool_call` returning `None`: our
    // OWN format with a broken body was handed to the operator as the run's
    // final answer.
    let broken = "```tool_call\n{\"name\": \"echo\", \"input\": {oops}}\n```";
    let (out, prompts) = run_script(
        vec![response(broken, 0.0), response(broken, 0.0)],
        allow_cascade(),
    )
    .await;

    assert_eq!(out.reason, TerminalReason::UnsupportedToolCallFormat);
    assert!(
        out.final_text.is_none(),
        "a broken call is not an answer to deliver: {out:?}"
    );
    let second = prompts.get(1).expect("a second dispatch was made");
    assert!(
        second.contains("not valid JSON"),
        "the correction must say what was wrong: {second}"
    );
}

// ---------------------------------------------------------------------------
// A2-218 — the `<tool_call>` XML wrapper
// ---------------------------------------------------------------------------

/// The reply that ended the A2-216 live run, byte for byte.
///
/// `runs/A2-216/live.log:9-12` on ARAS `92a4a7a`, model `deepseek-flash`
/// through Model Connector. It is a complete, valid call — tool `bash`, an
/// `input` object with the command — wrapped in the `<tool_call>` XML tags
/// Qwen/Hermes-style templates train a model to emit. `interpret` did not know
/// the wrapper, read the whole thing as prose, and the run printed
/// `ARCANA_RUN_DONE {"completed":true,"reason":"Completed"}` with that text as
/// the operator's answer.
const LIVE_WRAPPER_REPLY: &str = include_str!("fixtures/a2-216-tool-call-wrapper-reply.txt");

#[tokio::test]
async fn the_live_a2_216_wrapper_reply_is_a_call_not_a_final_answer() {
    let action = arcana_core::agent_loop::interpret(&response(LIVE_WRAPPER_REPLY, 0.0));

    let arcana_core::agent_loop::AssistantAction::ToolCall { name, input } = action else {
        panic!("the live reply is a complete tool call, not an answer: {action:?}");
    };
    assert_eq!(name, "bash");
    assert!(
        input["command"]
            .as_str()
            .is_some_and(|cmd| cmd.starts_with("cd aras && cat rust-toolchain.toml")),
        "the command the model asked for must survive the unwrap: {input}"
    );
    // The model sent this key alongside `command`; dropping it would silently
    // change the call it asked for.
    assert_eq!(input["timeout_seconds"], 120);
}

#[tokio::test]
async fn a_tool_call_wrapper_executes_the_tool_it_names() {
    let wrapped =
        "<tool_call>\n{\"name\": \"echo\", \"arguments\": {\"text\": \"hello\"}}\n</tool_call>";
    let (out, _) = run_script(
        vec![response(wrapped, 0.0), response("done", 0.0)],
        allow_cascade(),
    )
    .await;

    assert_eq!(
        out.tool_calls, 1,
        "the tool the model asked for must actually run: {out:?}"
    );
    assert_eq!(out.reason, TerminalReason::Completed);
}

#[tokio::test]
async fn an_unclosed_wrapper_is_corrected_never_delivered_as_the_answer() {
    // The output limit cut the reply mid-wrapper. Complete-looking JSON inside
    // an unclosed wrapper is not a call the model finished asking for.
    let cut = "<tool_call>\n{\"name\": \"echo\", \"input\": {\"text\": \"hello\"}}";
    let (out, prompts) = run_script(
        vec![response(cut, 0.0), response(cut, 0.0)],
        allow_cascade(),
    )
    .await;

    assert_eq!(
        out.reason,
        TerminalReason::UnsupportedToolCallFormat,
        "{out:?}"
    );
    assert_eq!(out.tool_calls, 0, "nothing ran");
    assert!(
        out.final_text.is_none(),
        "an unfinished call is not an answer to deliver: {out:?}"
    );
    let second = prompts.get(1).expect("a second dispatch was made");
    assert!(
        second.contains("</tool_call>"),
        "the correction must say what was missing: {second}"
    );
}

#[tokio::test]
async fn a_wrapper_around_something_that_is_not_a_call_is_corrected() {
    let junk = "<tool_call>\nsorry, I cannot do that\n</tool_call>";
    let (out, prompts) = run_script(
        vec![response(junk, 0.0), response(junk, 0.0)],
        allow_cascade(),
    )
    .await;

    assert_eq!(
        out.reason,
        TerminalReason::UnsupportedToolCallFormat,
        "{out:?}"
    );
    assert_eq!(out.tool_calls, 0);
    let second = prompts.get(1).expect("a second dispatch was made");
    assert!(
        second.contains("```tool_call"),
        "the correction must restate the encoding that works: {second}"
    );
}

#[tokio::test]
async fn prose_that_merely_names_the_wrapper_in_backticks_stays_prose() {
    // The negative control. A model explaining the format it was told about is
    // answering, not calling — and an answer must not cost a correction turn.
    let prose = "Some templates want `<tool_call>` tags around the JSON, but this \
                 runner wants a fenced block. I checked and nothing else uses \
                 `</tool_call>` here.";
    let action = arcana_core::agent_loop::interpret(&response(prose, 0.0));

    assert!(
        matches!(
            action,
            arcana_core::agent_loop::AssistantAction::Final { .. }
        ),
        "prose about the wrapper is prose: {action:?}"
    );
}
