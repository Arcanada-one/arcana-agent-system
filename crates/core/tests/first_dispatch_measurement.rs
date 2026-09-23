//! Contract for opt-in first-dispatch measurement metadata.
//!
//! The metadata is attached to exactly the first model-boundary request. It is
//! absent from later tool-loop requests and carries identifiers only, never
//! prompt content, credentials, provider output, or an authorization claim.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{
    Driver, DriverConfig, FirstDispatchPromptV0, TerminalReason, MAX_FIRST_DISPATCH_PROMPT_BYTES,
    MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS,
};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, FirstDispatchMeasurementV0, ModelConnector,
    PromptVariantV0, UnverifiedFirstDispatchObservationV0,
};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, EchoTool, ScriptedConnector};

struct LogicalErrorConnector;

#[async_trait::async_trait]
impl ModelConnector for LogicalErrorConnector {
    async fn execute(&self, _request: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let observation: UnverifiedFirstDispatchObservationV0 = serde_json::from_value(json!({
            "observationId": "00000000-0000-4000-8000-000000000002",
            "authorization": "NOT_AUTHORIZED",
            "receiptDigestSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }))
        .expect("opaque receipt deserializes");
        Err(ConnectorError::Logical {
            http_status: 429,
            kind: "rate_limited".into(),
            message: "try later".into(),
            retryable: true,
            recommendation: "wait".into(),
            retry_after: Some(1),
            first_dispatch_observation: Some(Box::new(observation)),
        })
    }
}

fn measurement() -> FirstDispatchMeasurementV0 {
    FirstDispatchMeasurementV0::try_new(
        "corpus-v0",
        "case-007",
        "developer",
        "code-change",
        "implement",
        2,
        PromptVariantV0::Compiled,
    )
    .expect("valid measurement context")
}

#[test]
fn measurement_serializes_as_closed_identifier_only_wire_contract() {
    let value = serde_json::to_value(measurement()).expect("serialize measurement");

    assert_eq!(
        value,
        json!({
            "version": "first-dispatch-measurement/v0",
            "corpusId": "corpus-v0",
            "caseId": "case-007",
            "roleId": "developer",
            "taskClassId": "code-change",
            "commandId": "implement",
            "replayIndex": 2,
            "variant": "compiled",
            "adapterBoundary": "arcana-agent-system/driver/first-dispatch-v0"
        })
    );
    let encoded = value.to_string();
    assert!(!encoded.contains("prompt"));
    assert!(!encoded.contains("token"));
    assert!(!encoded.contains("authorized"));
}

#[test]
fn measurement_rejects_unsafe_or_ambiguous_identifiers_and_zero_replay() {
    assert!(FirstDispatchMeasurementV0::try_new(
        "corpus-v0",
        "case with spaces",
        "developer",
        "code-change",
        "implement",
        1,
        PromptVariantV0::Baseline,
    )
    .is_err());
    assert!(FirstDispatchMeasurementV0::try_new(
        "corpus-v0",
        "case-007",
        "developer",
        "code-change",
        "implement",
        0,
        PromptVariantV0::Baseline,
    )
    .is_err());
}

#[test]
fn first_dispatch_prompt_is_bounded_and_debug_redacted() {
    let prompt =
        FirstDispatchPromptV0::try_new("secret-compiled-prompt".to_owned()).expect("valid prompt");
    assert_eq!(prompt.as_str(), "secret-compiled-prompt");
    assert!(!format!("{prompt:?}").contains("secret-compiled-prompt"));
    assert!(FirstDispatchPromptV0::try_new(String::new()).is_err());
    assert!(
        FirstDispatchPromptV0::try_new("x".repeat(MAX_FIRST_DISPATCH_PROMPT_BYTES + 1)).is_err()
    );

    assert!(
        FirstDispatchPromptV0::try_new("x".repeat(MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS))
            .is_ok()
    );
    assert!(FirstDispatchPromptV0::try_new(
        "x".repeat(MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS + 1)
    )
    .is_err());
    assert!(FirstDispatchPromptV0::try_new(
        "🧪".repeat(MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS / 2)
    )
    .is_ok());
    assert!(FirstDispatchPromptV0::try_new(
        "🧪".repeat(MAX_FIRST_DISPATCH_PROMPT_UTF16_CODE_UNITS / 2 + 1)
    )
    .is_err());
}

#[test]
fn execute_request_debug_redacts_prompt_and_system_prompt() {
    let mut request = ExecuteRequest::new("claude-code", "secret-compiled-prompt");
    request.system_prompt = Some("secret-system-prompt".to_owned());
    request.first_dispatch_measurement = Some(measurement());

    let debug = format!("{request:?}");
    assert!(!debug.contains("secret-compiled-prompt"));
    assert!(!debug.contains("secret-system-prompt"));
    assert!(debug.contains("[REDACTED]"));
    assert!(debug.contains("case-007"));
}

#[tokio::test]
async fn driver_attaches_measurement_only_to_the_real_first_dispatch() {
    let mut first_response = response(&tool_call_result("echo", json!({ "text": "marker" })), 0.0);
    first_response.first_dispatch_observation = Some(
        serde_json::from_value(json!({
            "observationId": "00000000-0000-4000-8000-000000000001",
            "authorization": "NOT_AUTHORIZED",
            "receiptDigestSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .expect("opaque receipt deserializes"),
    );
    let connector = ScriptedConnector::new(vec![first_response, response("done", 0.0)]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo tool");
    let (executor, _audit_dir) =
        common::test_executor(dispatcher, common::allow_cascade(), HookChain::new());
    let mut config = DriverConfig::new("scripted");
    config.first_dispatch_measurement = Some(measurement());
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );

    let output = driver.run("use the tool then answer").await;
    assert_eq!(output.reason, TerminalReason::Completed);
    assert_eq!(
        output
            .first_dispatch_observation
            .as_ref()
            .and_then(|observation| observation.observation_id()),
        Some("00000000-0000-4000-8000-000000000001")
    );

    let requests = connector.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].first_dispatch_measurement, Some(measurement()));
    assert_eq!(requests[1].first_dispatch_measurement, None);
}

#[tokio::test]
async fn driver_applies_exact_prompt_only_to_the_real_first_dispatch() {
    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("echo", json!({ "text": "marker" })), 0.0),
        response("done", 0.0),
    ]);
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo tool");
    let (executor, _audit_dir) =
        common::test_executor(dispatcher, common::allow_cascade(), HookChain::new());
    let mut config = DriverConfig::new("scripted");
    config.first_dispatch_measurement = Some(measurement());
    config.first_dispatch_prompt = Some(
        FirstDispatchPromptV0::try_new("exact-compiled-provider-boundary".to_owned())
            .expect("valid prompt"),
    );
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );

    let output = driver.run("ordinary task history").await;
    assert_eq!(output.reason, TerminalReason::Completed);
    let requests = connector.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].prompt, "exact-compiled-provider-boundary");
    assert!(!requests[1]
        .prompt
        .contains("exact-compiled-provider-boundary"));
    assert!(requests[1].prompt.contains("ordinary task history"));
}

#[tokio::test]
async fn driver_rejects_prompt_without_measurement_before_connector_io() {
    let connector = ScriptedConnector::new(vec![response("must not run", 0.0)]);
    let (executor, _audit_dir) = common::test_executor(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
    );
    let mut config = DriverConfig::new("scripted");
    config.first_dispatch_prompt =
        Some(FirstDispatchPromptV0::try_new("orphan-prompt".to_owned()).expect("valid prompt"));
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );

    let output = driver.run("task").await;
    assert_eq!(output.reason, TerminalReason::ConnectorFatal);
    assert_eq!(output.turns, 0);
    assert!(connector.requests().is_empty());
}

#[tokio::test]
async fn driver_rejects_first_dispatch_prompt_over_context_budget_before_io() {
    // The budget is in UTF-16 code units. `"🧪".repeat(13)` is 13 scalar
    // values, 26 units and 52 bytes — the three numbers a guard could be
    // counting, and only the middle one is what Model Connector enforces.
    let connector = ScriptedConnector::new(vec![response("must not run", 0.0)]);
    let (executor, _audit_dir) = common::test_executor(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
    );
    let mut config = DriverConfig::new("scripted");
    config.context_budget_units = 20;
    config.first_dispatch_measurement = Some(measurement());
    config.first_dispatch_prompt =
        Some(FirstDispatchPromptV0::try_new("🧪".repeat(13)).expect("valid bounded prompt"));
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );

    let output = driver.run("task").await;
    assert_eq!(output.reason, TerminalReason::RequestTooLarge);
    assert_eq!(output.turns, 0);
    assert!(connector.requests().is_empty());
}

/// The negative control for the unit above: the SAME prompt, under a budget
/// that its 26 UTF-16 units fit and its 52 bytes do not, is sent. A guard that
/// had gone on counting `String::len` would refuse it here.
#[tokio::test]
async fn a_first_dispatch_prompt_is_measured_in_utf16_units_not_bytes() {
    let connector = ScriptedConnector::new(vec![response("sent", 0.0)]);
    let (executor, _audit_dir) = common::test_executor(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
    );
    let mut config = DriverConfig::new("scripted");
    config.context_budget_units = 30;
    config.first_dispatch_measurement = Some(measurement());
    config.first_dispatch_prompt =
        Some(FirstDispatchPromptV0::try_new("🧪".repeat(13)).expect("valid bounded prompt"));
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );

    let output = driver.run("task").await;
    assert_eq!(
        connector.requests().len(),
        1,
        "26 units under a 30-unit budget must be sent, whatever its 52 bytes say"
    );
    assert_eq!(output.turns, 1);
}

#[tokio::test]
async fn driver_retains_receipt_from_a_logical_error() {
    let (executor, _audit_dir) = common::test_executor(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
    );
    let mut config = DriverConfig::new("scripted");
    config.first_dispatch_measurement = Some(measurement());
    let driver = Driver::new(
        &LogicalErrorConnector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );

    let output = driver.run("first dispatch fails logically").await;

    assert_eq!(output.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        output
            .first_dispatch_observation
            .as_ref()
            .and_then(|observation| observation.observation_id()),
        Some("00000000-0000-4000-8000-000000000002")
    );
}
