//! A2-290: a model that cannot answer inside its per-attempt budget ends the
//! turn at once, and the verdict names the budget and the model.
//!
//! Measured 2026-09-24 on A2-278 run 5: `deepseek-v4-pro` on a ~37 000-token
//! turn, dispatched with the client's 120 s per-attempt budget. Model
//! Connector aborted the provider call for exhausting that budget, reported
//! `status: "timeout"` with `retryable: true` — its blanket action map marks
//! every `timeout` that way — and the loop, reading only the flag, re-dispatched
//! byte-identical bytes under the identical budget twice more. The run ended
//! `ConnectorFatal` after 15 attempts with no answer and $0.086584 spent.
//!
//! The re-dispatches are the expensive part and their expense is invisible: an
//! aborted attempt comes back as `usage: 0` although the provider has already
//! been fed the whole prompt, so `max_cost_usd` cannot bound this class at all.
//!
//! The distinction being tested is narrow. `queue_timeout` — the request never
//! left Model Connector's queue — is genuinely worth another dispatch and must
//! keep getting one.

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

/// The per-attempt budget the connector under test says it sends, so the
/// verdict has a figure to quote.
const ATTEMPT_BUDGET: Duration = Duration::from_secs(120);

/// Always refuses with `error`, counting every call, and states an attempt
/// budget the way the real client does.
struct AlwaysFails {
    calls: AtomicUsize,
    error: fn() -> ConnectorError,
    states_attempt_budget: bool,
}

impl AlwaysFails {
    const fn new(error: fn() -> ConnectorError) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            error,
            states_attempt_budget: true,
        }
    }

    const fn silent_about_its_budget(error: fn() -> ConnectorError) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            error,
            states_attempt_budget: false,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ModelConnector for AlwaysFails {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err((self.error)())
    }

    fn upstream_attempt_budget(&self) -> Option<Duration> {
        self.states_attempt_budget.then_some(ATTEMPT_BUDGET)
    }
}

/// Fails `failures` times, then answers — the shape that proves a class is
/// still being retried.
struct FlakyConnector {
    failures: usize,
    calls: AtomicUsize,
    error: fn() -> ConnectorError,
}

impl FlakyConnector {
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

/// What A2-278 run 5 actually received: HTTP 201, envelope `status: "timeout"`,
/// `error.type: "timeout"`, and `retryable: true`.
fn upstream_attempt_timeout() -> ConnectorError {
    ConnectorError::Logical {
        http_status: 201,
        kind: "timeout".into(),
        message: "The operation was aborted due to timeout".into(),
        retryable: true,
        recommendation: "retry".into(),
        retry_after: None,
        first_dispatch_observation: None,
    }
}

/// The neighbouring class that MUST keep its re-dispatches: the request never
/// reached the provider, so nothing was computed and nothing was charged.
fn queue_timeout() -> ConnectorError {
    ConnectorError::Logical {
        http_status: 201,
        kind: "queue_timeout".into(),
        message: "Queue wait exceeded".into(),
        retryable: true,
        recommendation: "wait".into(),
        retry_after: None,
        first_dispatch_observation: None,
    }
}

fn config() -> DriverConfig {
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_backoff = Duration::ZERO;
    config.connector_retry_limit = 2;
    config
}

async fn drive(connector: &dyn ModelConnector, config: DriverConfig) -> RunOutput {
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
async fn an_exhausted_attempt_budget_ends_the_turn_on_the_first_refusal() {
    let connector = AlwaysFails::new(upstream_attempt_timeout);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        connector.calls(),
        1,
        "the same prompt under the same budget can only be aborted again — \
         each repeat costs a full budget of provider compute that Model \
         Connector reports as usage 0"
    );
}

#[tokio::test]
async fn the_verdict_names_the_budget_and_the_model() {
    let connector = AlwaysFails::new(upstream_attempt_timeout);
    let mut config = config();
    config.model = Some("deepseek-v4-pro".to_owned());
    let out = drive(&connector, config).await;

    let detail = out
        .terminal_detail
        .as_deref()
        .expect("a fatal connector verdict carries its detail");
    assert!(
        detail.contains("120s"),
        "an operator must be told what ran out, got: {detail}"
    );
    assert!(
        detail.contains("deepseek-v4-pro"),
        "an operator must be told which model to change, got: {detail}"
    );
    assert!(
        detail.contains("not retryable"),
        "the verdict must not read as a transient failure, got: {detail}"
    );
}

#[tokio::test]
async fn a_connector_that_states_no_budget_says_so_instead_of_inventing_one() {
    let connector = AlwaysFails::silent_about_its_budget(upstream_attempt_timeout);
    let out = drive(&connector, config()).await;

    let detail = out.terminal_detail.as_deref().expect("detail");
    assert!(
        detail.contains("the per-attempt budget"),
        "an unstated budget is named as unstated, got: {detail}"
    );
    assert!(
        !detail.contains("this client allows one upstream attempt"),
        "a budget nothing stated must not be quoted as a figure, got: {detail}"
    );
}

#[tokio::test]
async fn a_queue_timeout_is_still_re_dispatched() {
    let connector = FlakyConnector {
        failures: 2,
        calls: AtomicUsize::new(0),
        error: queue_timeout,
    };
    let out = drive(&connector, config()).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "a request that never left the queue was never computed and is worth \
         asking again"
    );
    assert_eq!(connector.calls(), 3, "two re-dispatches, then the answer");
}
