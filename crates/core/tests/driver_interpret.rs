//! V-AC-5 (D-REQ-06): the `interpret` seam is a pure, deterministic
//! classification of a `ConnectorResponse`. A fenced ```tool_call``` block
//! carrying `{name, input}` maps to `AssistantAction::ToolCall`.
//!
//! A2-208 added the third answer: a block that opened and never closed is
//! `AssistantAction::Truncated`, not a final answer. That case used to share
//! the fail-closed arm with malformed JSON, which made a reply the output
//! limit cut off indistinguishable from prose.
//!
//! A2-212 adds the fourth. A reply that is a recognisable *attempt* to call a
//! tool — this runner's fence with an unusable body, DeepSeek's native
//! `invoke` markup, a bare OpenAI-shaped JSON object — is
//! `AssistantAction::MalformedToolCall`, never `Final`. Only a reply with no
//! tool-call attempt in it is a final answer. Fail-closed is unchanged where
//! it matters: nothing here ever becomes an unchecked dispatch.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use arcana_core::agent_loop::{interpret, AssistantAction};
use arcana_core::connector::{ConnectorResponse, Usage};

fn response_with(result: &str) -> ConnectorResponse {
    ConnectorResponse {
        id: "id".to_string(),
        connector: "scripted".to_string(),
        model: "test-model".to_string(),
        result: result.to_string(),
        usage: Usage {
            input_tokens: 1,
            output_tokens: 1,
            total_tokens: 2,
            cost_usd: 0.0,
        },
        latency_ms: 1,
        status: "success".to_string(),
        error: None,
        first_dispatch_observation: None,
    }
}

/// The classification, flattened to a tag, so a case can assert on the arm it
/// expects without a five-line `match` each time.
fn tag(action: &AssistantAction) -> &'static str {
    match action {
        AssistantAction::ToolCall { .. } => "tool_call",
        AssistantAction::Final { .. } => "final",
        AssistantAction::MalformedToolCall { .. } => "malformed",
        AssistantAction::Truncated { .. } => "truncated",
    }
}

#[test]
fn driver_interpret() {
    // 1. A fenced tool_call block classifies to ToolCall{name, input}.
    let tool_resp = response_with(
        "Let me look that up.\n```tool_call\n{\"name\":\"echo\",\"input\":{\"text\":\"hi\"}}\n```\n",
    );
    match interpret(&tool_resp) {
        AssistantAction::ToolCall { name, input } => {
            assert_eq!(name, "echo");
            assert_eq!(input["text"], "hi");
        }
        other => panic!("expected ToolCall, got {}", tag(&other)),
    }

    // 2. A plain response classifies to Final{text} carrying the whole result.
    let final_resp = response_with("The answer is 42.");
    match interpret(&final_resp) {
        AssistantAction::Final { text } => assert_eq!(text, "The answer is 42."),
        other => panic!("expected Final, got {}", tag(&other)),
    }

    // 3. A malformed tool_call block is an attempt, not an answer. It used to
    //    be delivered as the run's final answer — the runner's own format,
    //    misspelt, read as prose.
    let malformed = response_with("```tool_call\n{not valid json}\n```");
    assert_eq!(tag(&interpret(&malformed)), "malformed");

    // 4. So is a block missing the required `name` key.
    let missing_name = response_with("```tool_call\n{\"input\":{\"x\":1}}\n```");
    assert_eq!(tag(&interpret(&missing_name)), "malformed");

    // 5. A block that opened and never closed is a cut-off reply, not an
    // answer — whatever the fragment inside it looks like.
    let cut_off_mid_json =
        response_with("Writing it now.\n```tool_call\n{\"name\":\"echo\",\"input\":{\"te");
    assert_eq!(
        tag(&interpret(&cut_off_mid_json)),
        "truncated",
        "an unclosed tool_call fence must not be read as prose"
    );

    // 6. Even a syntactically complete call is truncated while its fence is
    // open: the model never said it had finished, so we must not act on it.
    let cut_off_after_json =
        response_with("```tool_call\n{\"name\":\"echo\",\"input\":{\"text\":\"hi\"}}\n");
    match interpret(&cut_off_after_json) {
        AssistantAction::Truncated { bytes } => assert_eq!(
            bytes,
            cut_off_after_json.result.len(),
            "the fragment's size is reported so the operator can see how much was lost"
        ),
        other => panic!("expected Truncated, got {}", tag(&other)),
    }

    // 7. The closing fence is what distinguishes the two: the same body,
    // terminated, is an ordinary tool call.
    assert_eq!(
        tag(&interpret(&response_with(
            "```tool_call\n{\"name\":\"echo\",\"input\":{\"text\":\"hi\"}}\n```"
        ))),
        "tool_call",
        "a closed block is still a call"
    );

    // 8. A malformed body inside a CLOSED block is an attempt, not truncation
    // and not prose: the model finished writing our own format, badly.
    assert_eq!(
        tag(&interpret(&malformed)),
        "malformed",
        "truncation detection must not swallow the misspelt-format arm"
    );

    // 9. A block that names a tool but carries no arguments is an attempt
    // too. It used to dispatch JSON `null` — audit `input_hash
    // 03f88b99c3d8073b`, blake3("null"), the hash on record from the live
    // A2-204 denial — into a tool whose schema wants an object.
    let no_arguments = response_with("```tool_call\n{\"name\":\"echo\"}\n```");
    assert_eq!(tag(&interpret(&no_arguments)), "malformed");

    // 10. Determinism: repeated calls on the same input yield equal results.
    assert_eq!(interpret(&tool_resp), interpret(&tool_resp));
    assert_eq!(interpret(&final_resp), interpret(&final_resp));
    assert_eq!(interpret(&malformed), interpret(&malformed));
    assert_eq!(interpret(&missing_name), interpret(&missing_name));
    assert_eq!(interpret(&cut_off_mid_json), interpret(&cut_off_mid_json));
}

#[test]
fn arguments_under_any_spelling_reach_the_tool() {
    // `value.get("input").cloned().unwrap_or(Value::Null)` dropped everything
    // that was not spelt `input`, dispatching an argument-less call the cascade
    // then refused — for a mistake the model had not made.
    for body in [
        "{\"name\":\"echo\",\"input\":{\"text\":\"hi\"}}",
        "{\"name\":\"echo\",\"arguments\":{\"text\":\"hi\"}}",
        "{\"name\":\"echo\",\"parameters\":{\"text\":\"hi\"}}",
        "{\"name\":\"echo\",\"args\":{\"text\":\"hi\"}}",
        // OpenAI's own wire shape: `arguments` is a JSON-encoded string.
        "{\"name\":\"echo\",\"arguments\":\"{\\\"text\\\":\\\"hi\\\"}\"}",
    ] {
        let resp = response_with(&format!("```tool_call\n{body}\n```"));
        match interpret(&resp) {
            AssistantAction::ToolCall { name, input } => {
                assert_eq!(name, "echo", "{body}");
                assert_eq!(input["text"], "hi", "{body}");
            }
            other => panic!("expected ToolCall for {body}, got {}", tag(&other)),
        }
    }
}

#[test]
fn deepseek_native_markup_is_translated_not_answered() {
    // Verbatim shape of the live A2-204c failure (runs/A2-204c/log): the model
    // asked for a shell command in DeepSeek's own markup and the run ended
    // {"completed":true,"reason":"Completed"} with nothing done.
    let resp = response_with(
        "<｜｜DSML｜｜ calls>\n\
         <｜｜DSML｜｜ invoke name=\"bash\">\n\
         <｜｜DSML｜｜ parameter name=\"command\" string=\"true\">ls -la && echo \"x\"\
         </｜｜DSML｜｜ parameter>\n\
         </｜｜DSML｜｜ invoke>\n\
         </｜｜DSML｜｜ calls>\n",
    );
    match interpret(&resp) {
        AssistantAction::ToolCall { name, input } => {
            assert_eq!(name, "bash");
            assert_eq!(input["command"], "ls -la && echo \"x\"");
        }
        other => panic!("expected ToolCall, got {}", tag(&other)),
    }

    // The same grammar without the DeepSeek sentinel — what Anthropic-trained
    // models emit — reads through the same parser.
    let bare =
        response_with("<invoke name=\"echo\">\n<parameter name=\"text\">hi</parameter>\n</invoke>");
    match interpret(&bare) {
        AssistantAction::ToolCall { name, input } => {
            assert_eq!(name, "echo");
            assert_eq!(input["text"], "hi");
        }
        other => panic!("expected ToolCall, got {}", tag(&other)),
    }
}

#[test]
fn an_unclosed_invoke_block_is_corrected_never_dispatched() {
    // Half a call is not a call. Translating this would run a command the
    // model never finished asking for.
    let resp = response_with(
        "<｜｜DSML｜｜ invoke name=\"bash\">\n\
         <｜｜DSML｜｜ parameter name=\"command\" string=\"true\">rm -rf /tm",
    );
    assert_eq!(tag(&interpret(&resp)), "malformed");
}

#[test]
fn bare_openai_json_is_corrected_never_dispatched() {
    // Recognisable, so not an answer; plausibly prose, so not executed.
    let whole_reply = response_with("{\"name\":\"bash\",\"arguments\":{\"command\":\"ls\"}}");
    assert_eq!(tag(&interpret(&whole_reply)), "malformed");

    let fenced = response_with(
        "Here is the call:\n```json\n{\"name\":\"bash\",\"arguments\":{\"command\":\"ls\"}}\n```",
    );
    assert_eq!(tag(&interpret(&fenced)), "malformed");
}

#[test]
fn prose_about_tool_calling_stays_a_final_answer() {
    // The reason a bare JSON object is only recognised as a WHOLE candidate.
    // A model explaining the format must not have its explanation executed,
    // and must not have its answer withheld either.
    let explaining = response_with(
        "A tool call is a JSON object such as {\"name\": \"bash\", \"arguments\": {}} \
         placed inside a fenced block. That is all there is to it.",
    );
    assert_eq!(tag(&interpret(&explaining)), "final");

    // `invoke` as an English word, not a tag.
    let english = response_with("I will invoke the linter next, once the build is green.");
    assert_eq!(tag(&interpret(&english)), "final");
}
