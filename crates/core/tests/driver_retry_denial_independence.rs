//! A2-204b: the connector-retry counter and the rejected-call counter are two
//! separate budgets, and neither spends or refills the other.
//!
//! Both bounds landed in the same week and both live on `RunState`: A2-203
//! re-dispatches a transient connector failure up to
//! `DriverConfig::connector_retry_limit` times, A2-204 hands a correctable
//! cascade denial back to the model until the model re-sends one unchanged
//! (`MAX_DENIALS_PER_DISTINCT_CALL`).
//! They protect against opposite things — an upstream that is down, and a model
//! that cannot write a valid call — and a run that hits both must still stop.
//!
//! The dangerous direction is the rejection streak: if a re-dispatch in the
//! middle of it cleared the streak, a model hammering one wall could keep the
//! run alive indefinitely by being unlucky with the network in between. It does
//! not, and these tests are what says so.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput, TerminalReason};
use arcana_core::connector::{ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, CountingTool};

/// One scripted connector attempt.
enum Step {
    /// A reply the model could plausibly send.
    Reply(String),
    /// A transient failure — the shape A2-203 re-dispatches: HTTP 201,
    /// `status: "error"`, `retryable: true`.
    Transient,
}

/// Plays a fixed script of attempts, one per `execute` call, and counts them.
/// A drained script answers in prose, which ends the run as `Completed`.
struct ScriptedFlaky {
    steps: Vec<Step>,
    calls: AtomicUsize,
}

impl ScriptedFlaky {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            steps,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ModelConnector for ScriptedFlaky {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        match self.steps.get(index) {
            Some(Step::Reply(text)) => Ok(response(text, 0.0)),
            Some(Step::Transient) => Err(ConnectorError::Logical {
                http_status: 201,
                kind: "network_error".into(),
                message: "The operation was aborted due to timeout".into(),
                retryable: true,
                recommendation: "retry".into(),
                retry_after: None,
                first_dispatch_observation: None,
            }),
            None => Ok(response("out of script", 0.0)),
        }
    }
}

/// A `counting` call the tool's own JSON schema rejects: `value` must be an
/// integer. This is the production denial path of the live A2-201 failure —
/// `CapabilityExecutor::prepare` validates the input and denies at the
/// `schema` layer, one of the three layers that fold back.
/// A malformed `counting` call. The `nonce` is what makes one refusal
/// different from another: A2-225 bounds the fold-back on the *repeat* of a
/// call already refused, so a test about streaks has to say whether the model
/// is making a new mistake or the same one again.
fn schema_violating_call(nonce: &str) -> Step {
    Step::Reply(tool_call_result("counting", json!({ "value": nonce })))
}

/// A `counting` call that executes.
fn valid_call() -> Step {
    Step::Reply(tool_call_result("counting", json!({ "value": 1 })))
}

async fn drive(connector: &ScriptedFlaky, executions: &Arc<AtomicUsize>) -> RunOutput {
    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(CountingTool::new(Arc::clone(executions))))
        .expect("register the counting tool");
    let (executor, _audit_dir) =
        common::test_executor(registry, common::allow_cascade(), HookChain::new());
    let mut config = DriverConfig::new("scripted");
    // Real time in an unattended run, dead time here.
    config.connector_retry_backoff = Duration::ZERO;
    config.connector_retry_limit = 2;
    config.max_turns = 12;
    let driver = Driver::new(
        connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    driver.run("count something").await
}

#[tokio::test]
async fn a_connector_retry_does_not_clear_the_rejection_streak() {
    // Rejection, a re-dispatched transient failure, then the SAME rejected
    // call again. The repeat must end the run — the re-dispatch in the middle
    // is a fact about the network, not evidence that the model has improved,
    // and it must not have wiped the memory of what was already refused.
    //
    // The fourth step is a call that WOULD execute, and exists so this check
    // can go red: an implementation that cleared the memory on a retry would
    // reach it, report `tool_calls: 1` and complete.
    let executions = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedFlaky::new(vec![
        schema_violating_call("same"),
        Step::Transient,
        schema_violating_call("same"),
        valid_call(),
    ]);
    let out = drive(&connector, &executions).await;

    assert_eq!(
        out.reason,
        TerminalReason::PermissionDenied,
        "the repeated call must still stop the run: {:?}",
        out.reason
    );
    assert_eq!(out.tool_calls, 0, "nothing was ever executed");
    assert_eq!(executions.load(Ordering::SeqCst), 0, "the tool never ran");
    assert_eq!(
        connector.calls(),
        3,
        "two rejections plus the one re-dispatched failure, and no attempt more"
    );
    assert_eq!(out.turns, 3, "every attempt is a turn, the re-dispatch too");
    assert!(
        out.terminal_detail
            .as_deref()
            .is_some_and(|detail| detail.contains("schema") && detail.contains("counting")),
        "the stop must name what refused it: {:?}",
        out.terminal_detail
    );
}

#[tokio::test]
async fn a_rejection_does_not_spend_the_connector_retry_budget() {
    // The other direction, and the reset is deliberate: the retry counter
    // measures "is the upstream answering at all", so ANY reply resets it —
    // including a reply the cascade then refused. Two failures, a rejected
    // call, two more failures: the second pair gets a full budget again, and
    // the run survives to execute.
    let executions = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedFlaky::new(vec![
        Step::Transient,
        Step::Transient,
        schema_violating_call("one"),
        Step::Transient,
        Step::Transient,
        valid_call(),
        Step::Reply("counted".to_owned()),
    ]);
    let out = drive(&connector, &executions).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "a refused call is still proof the upstream is up: {:?}",
        out.reason
    );
    assert_eq!(out.tool_calls, 1, "the well-formed call ran");
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    assert_eq!(connector.calls(), 7, "every scripted attempt was made");
}

#[tokio::test]
async fn an_executed_call_after_a_retry_still_clears_the_rejection_streak() {
    // The memory is cleared by work, not by time or by luck. Two rejections, a
    // transient failure, a call that runs, then the SAME two rejected calls
    // again: the run must survive, because the executed call in the middle
    // made them new again. Without the clear, the fifth step is a repeat and
    // the run dies there — which is what makes this check able to go red.
    let executions = Arc::new(AtomicUsize::new(0));
    let connector = ScriptedFlaky::new(vec![
        schema_violating_call("one"),
        schema_violating_call("two"),
        Step::Transient,
        valid_call(),
        schema_violating_call("one"),
        schema_violating_call("two"),
        Step::Reply("counted".to_owned()),
    ]);
    let out = drive(&connector, &executions).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "four rejections in a run, no call refused twice since work was done: {:?}",
        out.reason
    );
    assert_eq!(out.tool_calls, 1);
    assert_eq!(executions.load(Ordering::SeqCst), 1);
    assert_eq!(connector.calls(), 7);
}
