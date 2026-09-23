//! A2-234: the four answers Model Connector gives a repeated
//! `Idempotency-Key`, and what the loop does with each.
//!
//! `src/billing/billing.service.ts`, `resolveReplay`, gives "four honest
//! answers, and deliberately no fifth that guesses". Two of them are the happy
//! path and are measured end-to-end over HTTP in
//! `crates/connectors/tests/idempotent_turn_retry.rs` — a completed intent
//! replays, and an intent still `held` answers `idempotency_conflict`. The
//! other two are refusals, and they are measured here, at the driver, because
//! what matters about them is the loop's decision rather than the wire:
//!
//!   * `idempotency_key_reused` — the key belongs to a DIFFERENT payload.
//!     Nothing of ours was dispatched or charged under it, and the server's
//!     own remedy is "Use a fresh key for a new request".
//!   * `idempotency_replay_unavailable` — the request completed and was
//!     charged exactly once, but its answer was too large to store. The one
//!     failure class that is terminal AND already paid for.
//!
//! Plus the budget: a conflict is the most patient class there is, because the
//! answer is being produced upstream and the alternative to waiting is
//! abandoning a turn that has already been bought.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcana_core::agent_loop::{
    Driver, DriverConfig, RunOutput, TerminalReason, DEFAULT_CONNECTOR_RETRY_LIMIT,
    DEFAULT_EDGE_RETRY_LIMIT,
};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, IdempotencyKey, ModelConnector,
};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use tokio_util::sync::CancellationToken;

use common::response;

/// An idempotency outcome in the envelope `gateErrorResponse` builds, with the
/// `retryable` / `recommendation` pair Model Connector's own `ERROR_ACTION_MAP`
/// assigns it and the HTTP status `HTTP_ERROR_STATUS` maps it to.
fn outcome(kind: &str, http_status: u16, retryable: bool, recommendation: &str) -> ConnectorError {
    ConnectorError::Logical {
        http_status,
        kind: kind.to_owned(),
        message: match kind {
            "idempotency_key_reused" => {
                "This Idempotency-Key was already used for a DIFFERENT request. Replaying the \
                 first request's response would hide the mismatch, so it is reported instead. \
                 Use a fresh key for a new request."
            }
            "idempotency_replay_unavailable" => {
                "This request completed, but its response was too large to store for replay. It \
                 has been dispatched and charged exactly once; retrieve the result from the \
                 original call rather than reissuing it."
            }
            _ => {
                "A request with this Idempotency-Key is still in flight. Retry shortly to \
                  receive its result; do not reissue it under a new key or it will be dispatched \
                  and charged twice."
            }
        }
        .to_owned(),
        retryable,
        recommendation: recommendation.to_owned(),
        retry_after: None,
        first_dispatch_observation: None,
    }
}

fn conflict() -> ConnectorError {
    outcome("idempotency_conflict", 409, true, "wait")
}

fn key_reused() -> ConnectorError {
    outcome("idempotency_key_reused", 422, false, "abort")
}

fn replay_unavailable() -> ConnectorError {
    outcome("idempotency_replay_unavailable", 409, false, "abort")
}

/// Fails `failures` times with `error`, recording the key on every attempt.
struct KeyRecordingConnector {
    failures: usize,
    calls: AtomicUsize,
    keys: Mutex<Vec<Option<IdempotencyKey>>>,
    error: fn() -> ConnectorError,
}

impl KeyRecordingConnector {
    fn new(failures: usize, error: fn() -> ConnectorError) -> Self {
        Self {
            failures,
            calls: AtomicUsize::new(0),
            keys: Mutex::new(Vec::new()),
            error,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn keys(&self) -> Vec<Option<IdempotencyKey>> {
        self.keys.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ModelConnector for KeyRecordingConnector {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.keys.lock().unwrap().push(req.idempotency_key.clone());
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call < self.failures {
            return Err((self.error)());
        }
        Ok(response("done at last", 0.0))
    }
}

fn config() -> DriverConfig {
    let mut config = DriverConfig::new("scripted");
    // Real sleeping is dead time here; the schedule itself is pinned by the
    // unit tests in `agent_loop.rs`.
    config.connector_retry_backoff = Duration::ZERO;
    config.max_turns = 32;
    config
}

async fn drive(connector: &KeyRecordingConnector, config: DriverConfig) -> RunOutput {
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
    driver.run("answer the question").await
}

// ---------------------------------------------------------------------------

/// A conflict is retried under the SAME key, which is the only response that
/// does not pay twice. Model Connector says so in the refusal itself: "do not
/// reissue it under a new key or it will be dispatched and charged twice."
#[tokio::test]
async fn an_in_flight_conflict_is_retried_under_the_same_key() {
    let connector = KeyRecordingConnector::new(2, conflict);
    let out = drive(&connector, config()).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "{:?}",
        out.terminal_detail
    );
    let keys = connector.keys();
    assert_eq!(keys.len(), 3, "{keys:?}");
    assert!(
        keys.iter().all(Option::is_some),
        "a dispatch carried no key: {keys:?}"
    );
    assert!(
        keys.windows(2).all(|pair| pair[0] == pair[1]),
        "the key changed while waiting on the request it identifies: {keys:?}"
    );
}

/// A conflict gets the patient budget, not the flat two a connector-authored
/// envelope gets. The difference is what the wait is FOR: an envelope Model
/// Connector wrote has its server-side attempts already behind it, while a
/// conflict means an answer we have paid for is still being produced.
#[tokio::test]
async fn an_in_flight_conflict_is_waited_out_on_the_patient_budget() {
    let connector = KeyRecordingConnector::new(usize::MAX, conflict);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        u32::try_from(connector.calls()).unwrap(),
        DEFAULT_EDGE_RETRY_LIMIT + 1,
        "a conflict was given the flat connector budget ({DEFAULT_CONNECTOR_RETRY_LIMIT}) \
         instead of the patient one"
    );
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("still in flight"),
        "the verdict must say a paid-for answer was abandoned, not just that something failed: \
         {detail}"
    );
}

/// The key was claimed by a different payload, so ours was never dispatched
/// and never charged. Retrying it unchanged can only be refused again; the
/// server's own remedy is a fresh key, and taking it saves the run.
///
/// It should never fire — `TurnIntentSeries::stamp` compares the payload and
/// mints a new key before the server has to — so this measures the backstop.
#[tokio::test]
async fn a_key_the_server_says_belongs_to_another_request_is_replaced_not_repeated() {
    let connector = KeyRecordingConnector::new(1, key_reused);
    let out = drive(&connector, config()).await;

    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "a key collision cost the whole run: {:?}",
        out.terminal_detail
    );
    let keys = connector.keys();
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert_ne!(
        keys[0], keys[1],
        "the refused key was sent again, which can only be refused again: {keys:?}"
    );
}

/// And the replacement is bounded like everything else: a server that refuses
/// every key does not get an unbounded supply of them.
#[tokio::test]
async fn replacing_a_reused_key_is_bounded_by_the_ordinary_retry_budget() {
    let connector = KeyRecordingConnector::new(usize::MAX, key_reused);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        u32::try_from(connector.calls()).unwrap(),
        DEFAULT_CONNECTOR_RETRY_LIMIT + 1,
        "a fresh key is a retry, not an exemption from the retry budget"
    );
}

/// The request ran and was charged; only its answer is gone. Retrying would
/// buy a second execution of work already bought, so the run stops — and the
/// verdict has to say the money is spent, or an operator reads a dead turn as
/// a turn that never happened.
#[tokio::test]
async fn an_answer_too_large_to_replay_stops_the_run_and_says_it_was_already_charged() {
    let connector = KeyRecordingConnector::new(usize::MAX, replay_unavailable);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    assert_eq!(
        connector.calls(),
        1,
        "a request that was charged exactly once must not be dispatched again"
    );
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("charged exactly once"),
        "the verdict does not say the turn was paid for: {detail}"
    );
    assert!(
        detail.contains("not retryable"),
        "the verdict does not say why it stopped: {detail}"
    );
}

/// Every dispatch carries a key. A turn dispatched without one has no
/// at-most-once guarantee at all, and the failure is silent: the run looks
/// identical and the bill does not.
#[tokio::test]
async fn every_dispatch_of_a_run_carries_a_key() {
    let connector = KeyRecordingConnector::new(0, conflict);
    let out = drive(&connector, config()).await;

    assert_eq!(out.reason, TerminalReason::Completed);
    let keys = connector.keys();
    assert!(!keys.is_empty());
    assert!(keys.iter().all(Option::is_some), "{keys:?}");
}
