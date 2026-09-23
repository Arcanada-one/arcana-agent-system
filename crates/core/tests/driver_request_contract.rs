//! The connector's request contract, enforced from this side of the wire.
//!
//! Model Connector's `/execute` caps `prompt` and `systemPrompt` at 100 000
//! UTF-16 code units each and answers an over-long field with an HTTP 400
//! before the model is reached. Measured on 2026-09-23: a pilot run that had
//! already executed five tool calls and cloned a repository died at turn 10 on
//! exactly that 400, reported as `ConnectorFatal`.
//!
//! The double below is the contract, not a mock of a response: it accepts a
//! request only when the request is one Model Connector would accept.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use common::tool_call_result;

/// What Model Connector counts: JavaScript `String.length`.
fn units(text: &str) -> usize {
    text.encode_utf16().count()
}

const FIELD_MAX_UNITS: usize = 100_000;

/// A connector that refuses exactly what the real one refuses, and in the same
/// shape: the Zod report arrives as a non-contract error body, not as the
/// `NestJS` envelope the client parses.
struct ContractEnforcingConnector {
    replies: Mutex<Vec<String>>,
    prompt_units: Mutex<Vec<usize>>,
}

impl ContractEnforcingConnector {
    fn new(replies: Vec<String>) -> Self {
        Self {
            replies: Mutex::new(replies),
            prompt_units: Mutex::new(Vec::new()),
        }
    }

    /// The size of every request that was accepted, in call order.
    fn prompt_units(&self) -> Vec<usize> {
        self.prompt_units.lock().unwrap().clone()
    }
}

#[async_trait]
impl ModelConnector for ContractEnforcingConnector {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        for (field, text) in [
            ("prompt", Some(req.prompt.clone())),
            ("systemPrompt", req.system_prompt.clone()),
        ] {
            let Some(text) = text else { continue };
            if units(&text) > FIELD_MAX_UNITS {
                return Err(ConnectorError::Http {
                    status: 400,
                    message: format!(
                        "upstream returned a non-contract error body (105 bytes): \
                         {{\"message\":\"Validation failed\",\"errors\":[\"{field}: Too big: \
                         expected string to have <={FIELD_MAX_UNITS} characters\"]}}"
                    ),
                    retry_after: None,
                });
            }
        }
        self.prompt_units.lock().unwrap().push(units(&req.prompt));
        let mut replies = self.replies.lock().unwrap();
        let result = if replies.is_empty() {
            "done".to_owned()
        } else {
            replies.remove(0)
        };
        Ok(ConnectorResponse {
            id: "contract".to_string(),
            connector: "scripted".to_string(),
            model: "test-model".to_string(),
            result,
            usage: Usage {
                input_tokens: 3,
                output_tokens: 5,
                total_tokens: 8,
                cost_usd: 0.0,
            },
            latency_ms: 1,
            status: "success".to_string(),
            error: None,
            first_dispatch_observation: None,
        })
    }
}

/// A real tool whose output is larger than any single request may hold — a
/// `git clone`, a `cargo test`, a `find /`.
struct FloodTool;

#[async_trait]
impl Tool for FloodTool {
    fn name(&self) -> &'static str {
        "flood"
    }

    fn description(&self) -> &'static str {
        "returns more output than one request may hold"
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }

    async fn execute(&self, _invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            content: format!("BEGIN{}END", "0123456789".repeat(40_000)),
            metadata: None,
        })
    }
}

/// The card's defect, end to end: three tool turns whose output does not fit
/// one request must still produce a run that finishes.
///
/// On the tree this was written against, the second dispatch carried the whole
/// 400 008-character tool result and came back `ConnectorFatal`.
#[tokio::test]
async fn a_run_whose_tools_flood_the_transcript_stays_inside_the_request_contract() {
    let connector = ContractEnforcingConnector::new(vec![
        tool_call_result("flood", json!({ "path": "." })),
        tool_call_result("flood", json!({ "path": "crates" })),
        tool_call_result("flood", json!({ "path": "docs" })),
        "all three listings read".to_owned(),
    ]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher.register(Arc::new(FloodTool)).expect("register");
    let (executor, _audit) =
        common::test_executor(dispatcher, common::allow_cascade(), HookChain::new());
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 8;

    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    let out = driver.run("read three listings and summarise them").await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "1 200 000 characters of tool output must not end the run"
    );
    assert_eq!(out.tool_calls, 3);
    let sizes = connector.prompt_units();
    assert_eq!(sizes.len(), 4, "every dispatch was accepted: {sizes:?}");
    assert!(
        sizes.iter().all(|units| *units <= FIELD_MAX_UNITS),
        "no request may exceed the contract: {sizes:?}"
    );
}

/// A system prompt that cannot fit is known before the first dispatch, and is
/// not reported as a failure of the connector that never saw it.
#[tokio::test]
async fn an_oversized_system_prompt_is_refused_before_any_request_is_sent() {
    let connector = ContractEnforcingConnector::new(Vec::new());
    let (executor, _audit) = common::test_executor(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
    );
    let mut config = DriverConfig::new("scripted");
    config.system_prompt = Some("s".repeat(FIELD_MAX_UNITS + 1));

    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    let out = driver.run("a task").await;

    assert_eq!(out.reason, TerminalReason::RequestTooLarge);
    assert_eq!(out.turns, 0);
    assert!(connector.prompt_units().is_empty());
}
