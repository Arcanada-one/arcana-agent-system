//! V-AC-5 (D-REQ-06): the `interpret` seam is a pure, deterministic
//! classification of a `ConnectorResponse` into either an intended tool call
//! or a final answer. A fenced ```tool_call``` block carrying
//! `{name, input}` maps to `AssistantAction::ToolCall`; anything else (no
//! block, malformed JSON, missing keys) fails closed to
//! `AssistantAction::Final` — never to an unchecked dispatch.

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
        AssistantAction::Final { text } => {
            panic!("expected ToolCall, got Final({text})");
        }
    }

    // 2. A plain response classifies to Final{text} carrying the whole result.
    let final_resp = response_with("The answer is 42.");
    match interpret(&final_resp) {
        AssistantAction::Final { text } => assert_eq!(text, "The answer is 42."),
        AssistantAction::ToolCall { name, .. } => panic!("expected Final, got ToolCall({name})"),
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

    // 5. Determinism: repeated calls on the same input yield equal results.
    assert_eq!(interpret(&tool_resp), interpret(&tool_resp));
    assert_eq!(interpret(&final_resp), interpret(&final_resp));
}
