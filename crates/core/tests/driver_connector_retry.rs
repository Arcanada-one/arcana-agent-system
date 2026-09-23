//! A-203: a turn the upstream could not finish in time is re-dispatched, not
//! a death sentence for the run.
//!
//! Measured 2026-09-23 on `arcana` 0.2.0: an hour-long run ended on turn 3
//! because one dispatch took longer than the client's fixed 120 s budget. The
//! loop had exactly one answer for every connector error — `ConnectorFatal` —
//! so a stall the server was still working on and a 404 on the connector id
//! were treated identically.
//!
//! The retry is bounded and paid for: each re-dispatch consumes a turn from
//! `--max-turns` and passes the same cost check as any other attempt, so a
//! connector that is simply down cannot spend an unattended run's whole
//! budget.

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
use tokio_util::sync::CancellationToken;

use common::response;

/// Fails `failures` times with `error`, then answers. Counts every call.
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

/// The shape of a Model Connector reply whose upstream call ran out of time:
/// HTTP 201, `status: "error"`, `retryable: true`. Measured against production
/// on 2026-09-23 with a dispatch that took longer than the connector's own
/// 30 s budget.
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

/// Model Connector's refusal of an over-long field, as it actually arrives.
///
/// Measured 2026-09-23: the body is Fastify's Zod report, not the `NestJS`
/// exception envelope the client parses, so the text reaches the error inside
/// the "non-contract error body" excerpt rather than as `message`.
fn field_over_the_size_limit() -> ConnectorError {
    ConnectorError::Http {
        status: 400,
        message: "upstream returned a non-contract error body (105 bytes): \
                  {\"message\":\"Validation failed\",\"errors\":[\"prompt: Too big: expected \
                  string to have <=100000 characters\"]}"
            .into(),
        retry_after: None,
    }
}

/// A connector id that does not exist fails the same way forever.
fn fatal_not_found() -> ConnectorError {
    ConnectorError::Http {
        status: 404,
        message: "Connector \"arcana-repl\" not found".into(),
        retry_after: None,
    }
}

fn config() -> DriverConfig {
    let mut config = DriverConfig::new("scripted");
    // The pause is real time in an unattended run and dead time in a test.
    config.connector_retry_backoff = Duration::ZERO;
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

#[tokio::test]
async fn a_timed_out_turn_is_re_dispatched_and_the_run_completes() {
    let connector = FlakyConnector::new(2, retryable_upstream_timeout);
    let out = drive(&connector, config()).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "two slow turns must not end an hour of work"
    );
    assert_eq!(out.final_text.as_deref(), Some("done at last"));
    assert_eq!(connector.calls(), 3, "two retries, then the answer");
    assert_eq!(out.turns, 3, "every attempt is a turn, retries included");
}

#[tokio::test]
async fn retries_are_bounded_and_the_run_then_ends_fatal() {
    let connector = FlakyConnector::new(usize::MAX, retryable_upstream_timeout);
    let mut config = config();
    config.connector_retry_limit = 2;
    config.max_turns = 24;
    let out = drive(&connector, config).await;

    assert_eq!(
        out.reason,
        TerminalReason::ConnectorFatal,
        "an upstream that never answers still ends the run"
    );
    assert_eq!(
        connector.calls(),
        3,
        "the first attempt plus exactly two retries"
    );
    assert_eq!(out.turns, 3);
}

#[tokio::test]
async fn retries_are_paid_for_out_of_max_turns() {
    let connector = FlakyConnector::new(usize::MAX, retryable_upstream_timeout);
    let mut config = config();
    config.connector_retry_limit = 8;
    config.max_turns = 2;
    let out = drive(&connector, config).await;

    assert_eq!(
        out.reason,
        TerminalReason::MaxTurns,
        "the retry budget cannot outlive the turn budget"
    );
    assert_eq!(connector.calls(), 2, "--max-turns bounds the re-dispatches");
    assert_eq!(out.turns, 2);
}

#[tokio::test]
async fn an_error_that_will_never_succeed_is_not_retried() {
    let connector = FlakyConnector::new(usize::MAX, fatal_not_found);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        connector.calls(),
        1,
        "a 404 on the connector id is a configuration fact; retrying it only \
         delays the message the operator needs"
    );
    assert_eq!(out.turns, 1);
}

/// A size refusal is the caller's fault and its own terminal reason.
///
/// It must not be retried — the second attempt sends the same oversized body —
/// and it must not be reported as `ConnectorFatal`, which names the connector
/// for a contract the connector kept. This is the failure that ended a pilot
/// run at turn 10 with five tool calls of real work already done.
#[tokio::test]
async fn an_over_size_refusal_is_terminal_and_names_the_limit() {
    let connector = FlakyConnector::new(usize::MAX, field_over_the_size_limit);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::RequestTooLarge);
    assert_eq!(connector.calls(), 1, "an oversized body is not sent twice");
    assert!(
        out.reason.explain().contains("100 000"),
        "the operator is told which limit: {}",
        out.reason.explain()
    );
}

/// A 413 — the whole body past the server's limit — is the same class.
#[tokio::test]
async fn a_body_too_large_refusal_is_terminal_too() {
    let connector = FlakyConnector::new(usize::MAX, || ConnectorError::Http {
        status: 413,
        message: "Request body is too large".into(),
        retry_after: None,
    });
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::RequestTooLarge);
    assert_eq!(connector.calls(), 1);
}
