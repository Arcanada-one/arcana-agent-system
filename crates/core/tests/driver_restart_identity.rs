//! G07 stage 2: operation identity across a process restart.
//!
//! "Restart" here means what a real restart is: a NEW `Driver` and a NEW
//! executor built from nothing but what the previous process left on disk (the
//! audit directory is shared, nothing else is). No in-memory object crosses.
//!
//! The first run ends with an UNKNOWN outcome: every dispatch is cut by a
//! client timeout, so the provider may have executed and charged it. The second
//! run is the "resume".
//!
//! **These tests pin a GAP, not a guarantee.** ARAS persists no operation
//! identity (the `dispatch` audit record holds turn, model
//! and sizes only; `Driver::run` is the sole entry point and mints a new run
//! UUID). Each test asserts what happens TODAY after a restart. The same tests
//! written as the safe property ("no fresh identity", "no dispatch", "original
//! key") were red on 9f122d7d; flipping an assertion here is the signal that a
//! durable identity store has landed. Not measured until then.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, IdempotencyKey, ModelConnector,
};
use arcana_core::cost::CostTracker;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::response;

/// Cuts every dispatch while `cut` is set (outcome unknown), then answers.
/// Records the key of every dispatch it receives.
struct Cutting {
    cut: std::sync::atomic::AtomicBool,
    calls: AtomicUsize,
    keys: Mutex<Vec<Option<IdempotencyKey>>>,
}

impl Cutting {
    fn new() -> Self {
        Self {
            cut: std::sync::atomic::AtomicBool::new(true),
            calls: AtomicUsize::new(0),
            keys: Mutex::new(Vec::new()),
        }
    }
    fn heal(&self) {
        self.cut.store(false, Ordering::SeqCst);
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn keys(&self) -> Vec<Option<IdempotencyKey>> {
        self.keys.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ModelConnector for Cutting {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.keys.lock().unwrap().push(req.idempotency_key.clone());
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.cut.load(Ordering::SeqCst) {
            return Err(ConnectorError::Timeout("cut".into()));
        }
        Ok(response("done at last", 0.0))
    }
}

fn config() -> DriverConfig {
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_backoff = Duration::ZERO;
    config.max_turns = 32;
    config
}

/// One "process": a fresh executor over the shared audit directory and a fresh
/// Driver. Returns when the run ends.
async fn process(connector: &dyn ModelConnector, audit_dir: &TempDir, task: &str) -> RunOutput {
    let audit = AuditLog::new(audit_dir.path()).expect("audit log");
    let executor = CapabilityExecutor::new(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
        audit,
    );
    Driver::new(
        connector,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config(),
    )
    .run(task)
    .await
}

/// Run 1 ends with every dispatch cut. Returns the key it dispatched under.
async fn first_process_ends_unknown(connector: &Cutting, audit: &TempDir) -> IdempotencyKey {
    let out = process(connector, audit, "answer the question").await;
    assert!(
        connector.calls() >= 1,
        "run 1 must have dispatched at least once: {out:?}"
    );
    let first = connector.keys();
    let key = first[0].clone().expect("run 1 dispatches carry a key");
    assert!(
        first.iter().all(|k| k.as_ref() == Some(&key)),
        "run 1 kept one key across its own retries: {first:?}"
    );
    key
}

/// (a) Unknown outcome, restart, resume with the same task.
/// GAP: the restart mints a fresh identity for the same effect.
#[tokio::test(start_paused = true)]
async fn gap_restart_after_unknown_outcome_mints_a_fresh_identity() {
    let connector = Cutting::new();
    let audit = TempDir::new().unwrap();
    let original = first_process_ends_unknown(&connector, &audit).await;
    let before = connector.calls();
    connector.heal();

    let _ = process(&connector, &audit, "answer the question").await;

    let after: Vec<_> = connector.keys().split_off(before);
    assert_eq!(after.len(), 1, "the restart dispatched: {after:?}");
    let fresh = after[0].clone().expect("the dispatch carries a key");
    assert_ne!(fresh, original, "the key survived a restart");
}

/// (b) Unknown outcome, restart, resume with a CHANGED payload.
/// GAP: dispatched, under a fresh key, with no refusal and no reconcile state.
#[tokio::test(start_paused = true)]
async fn gap_restart_with_a_changed_payload_after_unknown_outcome_is_dispatched() {
    let connector = Cutting::new();
    let audit = TempDir::new().unwrap();
    let original = first_process_ends_unknown(&connector, &audit).await;
    let before = connector.calls();
    connector.heal();

    let out = process(&connector, &audit, "answer a DIFFERENT question").await;

    assert_eq!(connector.calls(), before + 1);
    assert_ne!(connector.keys()[before].clone().unwrap(), original);
    assert_eq!(
        out.reason,
        arcana_core::agent_loop::TerminalReason::Completed
    );
}

/// (c) Unknown outcome, restart, UNCHANGED payload replay.
/// GAP: the replay does not carry the original key, so the server cannot
/// replay the possibly-executed first request; it is charged as a new one.
#[tokio::test(start_paused = true)]
async fn gap_restart_replay_of_an_unchanged_payload_does_not_use_the_original_key() {
    let connector = Cutting::new();
    let audit = TempDir::new().unwrap();
    let original = first_process_ends_unknown(&connector, &audit).await;
    let before = connector.calls();
    connector.heal();

    let _ = process(&connector, &audit, "answer the question").await;

    let after: Vec<_> = connector.keys().split_off(before);
    assert_ne!(after.first().cloned().flatten(), Some(original));
}

/// Why (a)-(c) cannot be fixed by reading existing persistence: nothing the
/// first process left on disk contains its key or request digest.
#[tokio::test(start_paused = true)]
async fn gap_the_state_a_process_leaves_behind_holds_no_operation_identity() {
    let connector = Cutting::new();
    let audit = TempDir::new().unwrap();
    let original = first_process_ends_unknown(&connector, &audit).await;
    let key = format!("{original:?}");
    let uuid = key.split('.').nth(1).expect("key shape").to_string();

    let mut files = 0;
    for entry in std::fs::read_dir(audit.path()).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !text.contains(&uuid) && !text.contains("idempotency"),
            "{} carries identity",
            path.display()
        );
    }
    assert!(
        files >= 1,
        "the audit directory is the persisted state under test"
    );
}
