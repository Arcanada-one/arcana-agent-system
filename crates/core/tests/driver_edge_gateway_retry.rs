//! A2-230: three 502s from the edge in four seconds are not a verdict on the
//! Model Connector, and a run that dies on them says what killed it.
//!
//! Measured on pilot A2-204c5 (`arcana` c24cd49, sha256 2830536b…,
//! `/home/dev/aup/arc2/runs/A2-204c5/log`): 94 turns, 61 tool calls, the test
//! written and four mutants run — all of it thrown away when three consecutive
//! `HTTP 502: upstream returned a non-contract error body (16 bytes): error
//! code: 502` arrived from `connector.arcanada.ai`. The retry policy was two
//! re-dispatches two seconds apart, so the run spent about four seconds
//! finding out whether a Cloudflare edge would come back, and the done-marker
//! it left behind said `"error": null`.
//!
//! Two separate defects, pinned separately here:
//!   * the budget — a gateway verdict now gets a bounded exponential schedule
//!     with jitter (2, 4, 8, 16, 30 s; 60 s of sleep at worst), while an
//!     envelope Model Connector itself authored keeps the conservative two,
//!     because Model Connector has already spent its own attempts server-side;
//!   * the verdict — `ConnectorFatal` now names the status, the attempts and
//!     the elapsed time, in `terminal_detail` and therefore in the marker.

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

use arcana_core::agent_loop::{
    Driver, DriverConfig, RunOutput, TerminalReason, DEFAULT_EDGE_RETRY_LIMIT,
};
use arcana_core::connector::{ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use tokio_util::sync::CancellationToken;

use common::response;

/// Fails `failures` times with `error`, then answers.
struct FlakyConnector {
    failures: usize,
    calls: AtomicUsize,
    error: fn() -> ConnectorError,
}

impl FlakyConnector {
    fn new(failures: usize, error: fn() -> ConnectorError) -> Self {
        Self {
            failures,
            calls: AtomicUsize::new(0),
            error,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ModelConnector for FlakyConnector {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call < self.failures {
            return Err((self.error)());
        }
        Ok(response("done at last", 0.0))
    }
}

/// The pilot's failure, byte for byte: Cloudflare's 16-byte body, which is
/// neither the connector-response envelope nor a `NestJS` exception envelope.
fn edge_502() -> ConnectorError {
    ConnectorError::Http {
        status: 502,
        message: "upstream returned a non-contract error body (16 bytes): error code: 502".into(),
        retry_after: None,
    }
}

/// The same status, but spoken by Model Connector: a `NestJS` envelope whose
/// `message` the client parsed. Not an edge verdict, and not entitled to the
/// edge's longer budget.
fn model_connector_502() -> ConnectorError {
    ConnectorError::Http {
        status: 502,
        message: "Upstream provider refused the request".into(),
        retry_after: None,
    }
}

/// A retryable envelope Model Connector authored — the A-203 shape.
fn retryable_upstream_timeout() -> ConnectorError {
    ConnectorError::Logical {
        http_status: 201,
        kind: "network_error".into(),
        message: "The operation was aborted due to timeout".into(),
        retryable: true,
        recommendation: "retry".into(),
        retry_after: None,
        first_dispatch_observation: None,
    }
}

fn config() -> DriverConfig {
    let mut config = DriverConfig::new("scripted");
    // The pause is real time in an unattended run and dead time in a test. It
    // is also the base of the gateway schedule, so zero here flattens the
    // whole schedule to zero — the schedule's arithmetic is pinned by the unit
    // tests in `agent_loop.rs`, not by sleeping through it.
    config.connector_retry_backoff = Duration::ZERO;
    config.max_turns = 32;
    config
}

async fn drive(connector: &FlakyConnector, config: DriverConfig) -> RunOutput {
    let (executor, _audit_dir) = common::test_executor(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
    );
    let driver = Driver::new(
        connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    );
    driver.run("write something long").await
}

/// The pilot, replayed: three 502s from the edge, then the answer.
#[tokio::test]
async fn the_three_gateway_502s_that_killed_a_94_turn_run_are_survived() {
    let connector = FlakyConnector::new(3, edge_502);
    let out = drive(&connector, config()).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "three edge 502s threw away 94 turns of finished work: {:?}",
        out.terminal_detail
    );
    assert_eq!(out.final_text.as_deref(), Some("done at last"));
    assert_eq!(connector.calls(), 4, "three re-dispatches, then the answer");
}

/// The budget is a budget: an edge that never comes back still ends the run,
/// and it ends after exactly the number of attempts the constant names.
#[tokio::test]
async fn the_gateway_budget_is_bounded_and_then_the_run_ends() {
    let connector = FlakyConnector::new(usize::MAX, edge_502);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        u32::try_from(connector.calls()).unwrap(),
        DEFAULT_EDGE_RETRY_LIMIT + 1,
        "the first attempt plus exactly {DEFAULT_EDGE_RETRY_LIMIT} re-dispatches"
    );
}

/// `"error": null` was the pilot's whole post-mortem. The verdict now carries
/// the three facts that distinguish "the retry policy was too short" from
/// "the upstream is down": which status, how many attempts, over how long.
#[tokio::test]
async fn a_run_that_dies_on_the_connector_names_status_attempts_and_elapsed() {
    let connector = FlakyConnector::new(usize::MAX, edge_502);
    let out = drive(&connector, config()).await;

    let detail = out
        .terminal_detail
        .as_deref()
        .expect("ConnectorFatal must say what killed it, not just that something did");
    assert!(detail.contains("HTTP 502"), "no status: {detail}");
    assert!(
        detail.contains(&format!("{} attempt(s)", DEFAULT_EDGE_RETRY_LIMIT + 1)),
        "no attempt count: {detail}"
    );
    assert!(
        detail.contains(" over ") && detail.contains('s'),
        "no elapsed time: {detail}"
    );
    assert!(
        detail.contains("gateway"),
        "the class of failure is not named: {detail}"
    );
    // And the upstream's own words survive, so the operator can tell a 16-byte
    // Cloudflare page from a real upstream refusal.
    assert!(detail.contains("error code: 502"), "body lost: {detail}");
}

/// A failure that will never succeed says so too, rather than sharing the
/// "budget spent" sentence with a genuine outage.
#[tokio::test]
async fn a_non_retryable_failure_says_it_was_never_retried() {
    let connector = FlakyConnector::new(usize::MAX, || ConnectorError::Http {
        status: 404,
        message: "Connector \"arcana-repl\" not found".into(),
        retry_after: None,
    });
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(connector.calls(), 1);
    let detail = out.terminal_detail.as_deref().unwrap_or_default();
    assert!(detail.contains("HTTP 404"), "{detail}");
    assert!(detail.contains("1 attempt(s)"), "{detail}");
    assert!(
        detail.contains("not retryable"),
        "a 404 on the connector id must not read as an exhausted budget: {detail}"
    );
}

/// The whole point of the new class: a 502 Model Connector itself authored is
/// NOT given the edge's budget. Model Connector has already spent its own
/// server-side attempts by the time the client sees one.
#[tokio::test]
async fn a_gateway_status_that_model_connector_authored_keeps_the_short_budget() {
    let connector = FlakyConnector::new(usize::MAX, model_connector_502);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        connector.calls(),
        3,
        "a parsed NestJS envelope is the Model Connector speaking; it keeps the \
         conservative two re-dispatches"
    );
    let detail = out.terminal_detail.as_deref().unwrap_or_default();
    assert!(
        !detail.contains("gateway"),
        "an envelope Model Connector authored must not be reported as an edge \
         verdict: {detail}"
    );
}

/// And the A-203 shape is untouched by all of this.
#[tokio::test]
async fn a_retryable_envelope_keeps_its_two_re_dispatches() {
    let connector = FlakyConnector::new(usize::MAX, retryable_upstream_timeout);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(connector.calls(), 3);
}

/// The sum of the pauses is bounded, not just each one. With no budget to
/// sleep out of, the run stops and says that is why — it does not silently
/// retry for free.
#[tokio::test]
async fn an_exhausted_pause_budget_ends_the_run_and_says_so() {
    let connector = FlakyConnector::new(usize::MAX, edge_502);
    let mut config = config();
    config.connector_retry_pause_budget = Duration::ZERO;
    let out = drive(&connector, config).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(connector.calls(), 1, "no re-dispatch may be made for free");
    let detail = out.terminal_detail.as_deref().unwrap_or_default();
    assert!(
        detail.contains("waiting between re-dispatches"),
        "the spent sleep budget is not named: {detail}"
    );
}

/// The retry budget is per turn, not per run: an edge that flaps every few
/// turns of a long run must not accumulate into a death sentence.
#[tokio::test]
async fn the_gateway_budget_starts_over_after_any_reply() {
    // Five failures with a reply in the middle: 3, answer, 2, answer. Under a
    // per-run counter the sixth call would be past the limit of five.
    struct Flapping {
        calls: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl ModelConnector for Flapping {
        async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            // calls 0,1,2 fail; 3 answers with a tool call; 4,5 fail; 6 answers.
            match call {
                0..=2 | 4..=5 => Err(edge_502()),
                3 => Ok(response(
                    "```tool_call\n{\"name\": \"counting\", \"input\": {\"value\": 1}}\n```",
                    0.0,
                )),
                _ => Ok(response("done", 0.0)),
            }
        }
    }
    let connector = Flapping {
        calls: AtomicUsize::new(0),
    };
    let (executor, _audit_dir) = common::test_executor(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
    );
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config(),
    );
    let out = driver.run("flap").await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "the retry budget must reset on a reply: {:?}",
        out.terminal_detail
    );
    assert_eq!(connector.calls.load(Ordering::SeqCst), 7);
}
