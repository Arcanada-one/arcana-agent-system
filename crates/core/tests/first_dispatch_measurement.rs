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

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
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
