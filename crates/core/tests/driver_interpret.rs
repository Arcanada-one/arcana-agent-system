//! V-AC-5 (D-REQ-06): the `interpret` seam is a pure, deterministic
//! classification of a `ConnectorResponse` into either an intended tool call
//! or a final answer. A fenced ```tool_call``` block carrying
//! `{name, input}` maps to `AssistantAction::ToolCall`; anything else (no
//! block, malformed JSON, missing keys) fails closed to
//! `AssistantAction::Final` — never to an unchecked dispatch.
//!
//! A2-208 adds the third answer: a block that opened and never closed is
//! `AssistantAction::Truncated`, not a final answer. That case used to share
//! the fail-closed arm with malformed JSON, which made a reply the output
//! limit cut off indistinguishable from prose.

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
        other => panic!("expected ToolCall, got {other:?}"),
    }

    // 2. A plain response classifies to Final{text} carrying the whole result.
    let final_resp = response_with("The answer is 42.");
    match interpret(&final_resp) {
        AssistantAction::Final { text } => assert_eq!(text, "The answer is 42."),
        other => panic!("expected Final, got {other:?}"),
    }

    // 3. A malformed tool_call block (invalid JSON) fails closed to Final.
    let malformed = response_with("```tool_call\n{not valid json}\n```");
    assert!(
        matches!(interpret(&malformed), AssistantAction::Final { .. }),
        "malformed tool_call block must fail closed to Final"
    );

    // 4. A block missing the required `name` key fails closed to Final.
    let missing_name = response_with("```tool_call\n{\"input\":{\"x\":1}}\n```");
    assert!(
        matches!(interpret(&missing_name), AssistantAction::Final { .. }),
        "tool_call block missing name must fail closed to Final"
    );

    // 5. A block that opened and never closed is a cut-off reply, not an
    // answer — whatever the fragment inside it looks like.
    let cut_off_mid_json =
        response_with("Writing it now.\n```tool_call\n{\"name\":\"echo\",\"input\":{\"te");
    assert!(
        matches!(
            interpret(&cut_off_mid_json),
            AssistantAction::Truncated { .. }
        ),
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
        other => panic!("expected Truncated, got {other:?}"),
    }

    // 7. The closing fence is what distinguishes the two: the same body,
    // terminated, is an ordinary tool call.
    assert!(
        matches!(
            interpret(&response_with(
                "```tool_call\n{\"name\":\"echo\",\"input\":{\"text\":\"hi\"}}\n```"
            )),
            AssistantAction::ToolCall { .. }
        ),
        "a closed block is still a call"
    );

    // 8. A malformed body inside a CLOSED block keeps failing closed to Final
    // rather than being reclassified as truncation.
    assert!(
        matches!(interpret(&malformed), AssistantAction::Final { .. }),
        "truncation detection must not swallow the fail-closed arm"
    );

    // 9. Determinism: repeated calls on the same input yield equal results.
    assert_eq!(interpret(&tool_resp), interpret(&tool_resp));
    assert_eq!(interpret(&final_resp), interpret(&final_resp));
    assert_eq!(interpret(&cut_off_mid_json), interpret(&cut_off_mid_json));
}
