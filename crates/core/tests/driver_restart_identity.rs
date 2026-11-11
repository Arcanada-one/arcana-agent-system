//! G07: operation identity across a process restart, as SAFETY assertions.
//!
//! "Restart" is what a real restart is: a NEW `Driver` and a NEW executor built
//! from nothing but what the previous process left on disk (the audit
//! directory and the private intent-record directory; nothing else is shared).
//! A "crash" is a task whose connector panics or whose future is dropped: the
//! kernel releases its lock and whatever it had made durable stays.
//!
//! MOCKS: every connector here is an in-test double. No Model Connector and no
//! provider is called. The mocks stand in for the native Model Connector intent
//! and for the provider effect, so those are `NOT_MEASURED` by this file:
//! native intent, provider effect, cost reservation, and the Muneral reconcile
//! join.
//!
//! The first four tests (`restart_*`, `state_*`) are PR #276's four
//! characterization tests flipped from "passes while reproducing the defect"
//! into the safe property. Against `fa51b8e7` (and `e69c368e`, PR #275) they are
//! red; the only line that touches the new API is [`durable`].

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput, TerminalReason};
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

const TASK: &str = "answer the question";
const CHANGED: &str = "answer a DIFFERENT question";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Every dispatch is cut by a client timeout (outcome unknown).
    Cut,
    /// The process dies inside the dispatch: the task panics.
    Die,
    /// Answers.
    Heal,
}

/// Cuts, dies or answers. Records the key of every dispatch it receives.
struct Cutting {
    mode: Mutex<Mode>,
    calls: AtomicUsize,
    keys: Mutex<Vec<Option<IdempotencyKey>>>,
}

impl Cutting {
    fn new() -> Self {
        Self {
            mode: Mutex::new(Mode::Cut),
            calls: AtomicUsize::new(0),
            keys: Mutex::new(Vec::new()),
        }
    }
    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
    fn heal(&self) {
        self.set(Mode::Heal);
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
        let mode = *self.mode.lock().unwrap();
        match mode {
            Mode::Cut => Err(ConnectorError::Timeout("cut".into())),
            Mode::Die => panic!("process died inside the dispatch"),
            Mode::Heal => Ok(response("done at last", 0.0)),
        }
    }
}

/// One authoritative deadline for the whole test binary: the caller supplies it
/// and it does not move between processes of one attempt.
fn now_s() -> u64 {
    static START: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *START.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    })
}

fn binding() -> arcana_core::operation_intent::OperationBinding {
    arcana_core::operation_intent::OperationBinding {
        task_id: Some("task-0001".into()),
        plan_revision: Some("plan-r7".into()),
        attempt_id: Some("attempt-3".into()),
        lease_fence: Some("lease-41".into()),
        deadline_epoch_s: Some(now_s() + 3600),
        dialect_revision: Some("dialect-2026-11".into()),
        reservation_ref: None,
    }
}

/// The ONLY place that touches the durable-intent API. The red run against the
/// pre-store trees replaces this body with a no-op.
fn durable(
    config: &mut DriverConfig,
    store: &Path,
    binding: arcana_core::operation_intent::OperationBinding,
    replay_verified: bool,
) {
    let mut intent = arcana_core::operation_intent::OperationIntentConfig::new(store, binding);
    intent.same_key_replay_verified = replay_verified;
    config.operation_intent = Some(intent);
}

fn config(
    store: &Path,
    binding: arcana_core::operation_intent::OperationBinding,
    verified: bool,
) -> DriverConfig {
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_backoff = Duration::ZERO;
    config.max_turns = 32;
    durable(&mut config, store, binding, verified);
    config
}

struct World {
    audit: TempDir,
    store: PathBuf,
    _store_root: TempDir,
}

impl World {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        // TempDir on macOS sits under `/var/folders/...` (`/var` → `private/var`).
        // IntentStore refuses symlink ancestors; a private-directory fixture must
        // therefore use the canonical path.
        let store = std::fs::canonicalize(root.path())
            .expect("canonical temporary root")
            .join("intents");
        Self {
            audit: TempDir::new().unwrap(),
            store,
            _store_root: root,
        }
    }
}

/// One "process": a fresh executor over the shared audit directory and a fresh
/// Driver. Returns when the run ends.
async fn process_with(
    connector: &dyn ModelConnector,
    world: &World,
    task: &str,
    binding: arcana_core::operation_intent::OperationBinding,
    verified: bool,
) -> RunOutput {
    let audit = AuditLog::new(world.audit.path()).expect("audit log");
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
        config(&world.store, binding, verified),
    )
    .run(task)
    .await
}

async fn process(
    connector: &dyn ModelConnector,
    world: &World,
    task: &str,
    verified: bool,
) -> RunOutput {
    process_with(connector, world, task, binding(), verified).await
}

/// Run 1 ends with every dispatch cut. Returns the key it dispatched under.
async fn first_process_ends_unknown(connector: &Cutting, world: &World) -> IdempotencyKey {
    let out = process(connector, world, TASK, false).await;
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

fn record_files(world: &World) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(&world.store)
        .map(|d| {
            d.map(|e| e.unwrap().path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

fn record_text(world: &World) -> String {
    let files = record_files(world);
    assert_eq!(files.len(), 1, "exactly one retained record: {files:?}");
    std::fs::read_to_string(&files[0]).unwrap()
}

fn record_json(world: &World) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(&record_text(world)).unwrap()["body"].clone()
}

fn detail(out: &RunOutput) -> String {
    out.terminal_detail.clone().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// D08: PR #276's four characterization tests, flipped into safety assertions.
// ---------------------------------------------------------------------------

/// (a) Unknown outcome, restart, resume with the same task. A restart must not
/// mint a fresh identity for the possibly-executed effect: with connector
/// replay unverified it holds the original key and dispatches NOTHING.
#[tokio::test(start_paused = true)]
async fn restart_after_unknown_outcome_does_not_mint_a_fresh_identity() {
    let connector = Cutting::new();
    let world = World::new();
    let original = first_process_ends_unknown(&connector, &world).await;
    let before = connector.calls();
    connector.heal();

    let out = process(&connector, &world, TASK, false).await;

    assert_eq!(connector.calls(), before, "no fresh dispatch: {out:?}");
    assert_ne!(out.reason, TerminalReason::Completed);
    assert!(
        detail(&out).contains(original.as_str()),
        "the refusal names the ORIGINAL key: {}",
        detail(&out)
    );
    assert_eq!(record_json(&world)["idempotency_key"], original.as_str());
}

/// (b) Unknown outcome, restart, resume with a CHANGED payload: typed refusal,
/// zero calls, original bytes and key retained.
#[tokio::test(start_paused = true)]
async fn restart_with_a_changed_payload_after_unknown_outcome_is_refused() {
    let connector = Cutting::new();
    let world = World::new();
    let original = first_process_ends_unknown(&connector, &world).await;
    let before = connector.calls();
    let record_before = record_text(&world);
    connector.heal();

    let out = process(&connector, &world, CHANGED, true).await;

    assert_eq!(connector.calls(), before, "changed payload not dispatched");
    assert_ne!(out.reason, TerminalReason::Completed);
    assert!(
        detail(&out).contains("reconcile required") && detail(&out).contains(original.as_str()),
        "{}",
        detail(&out)
    );
    assert_eq!(record_text(&world), record_before, "original bytes kept");
}

/// (c) Unknown outcome, restart, UNCHANGED payload. The key is reused ONLY
/// where connector replay is verified; otherwise the operation stays unknown.
#[tokio::test(start_paused = true)]
async fn restart_replay_of_an_unchanged_payload_uses_the_original_key_only_when_verified() {
    let connector = Cutting::new();
    let world = World::new();
    let original = first_process_ends_unknown(&connector, &world).await;
    let before = connector.calls();
    connector.heal();

    // Unverified: stays unknown, refuses, zero dispatch.
    let refused = process(&connector, &world, TASK, false).await;
    assert_eq!(connector.calls(), before);
    assert!(
        detail(&refused).contains("INTENT_UNKNOWN_OUTCOME_HELD"),
        "{}",
        detail(&refused)
    );

    // Verified: the SAME key, nothing fresh.
    let out = process(&connector, &world, TASK, true).await;
    let after: Vec<_> = connector.keys().split_off(before);
    assert_eq!(after.len(), 1, "one replay dispatch: {after:?}");
    assert_eq!(after[0].as_ref(), Some(&original));
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(record_json(&world)["disposition"], "reconciled");
    assert_eq!(record_json(&world)["idempotency_key"], original.as_str());
}

/// The state a process leaves behind now holds the operation identity, and
/// only hashes and closed scalars: no prompt text.
#[tokio::test(start_paused = true)]
async fn state_a_process_leaves_behind_holds_the_operation_identity_and_no_prompt_text() {
    let connector = Cutting::new();
    let world = World::new();
    let original = first_process_ends_unknown(&connector, &world).await;

    let text = record_text(&world);
    assert!(text.contains(original.as_str()), "key retained");
    for needle in ["answer", "question", "prompt\":"] {
        assert!(!text.contains(needle), "record carries `{needle}`: {text}");
    }
    let body = record_json(&world);
    assert_eq!(body["disposition"], "unknown");
    assert_eq!(body["task_id"], "task-0001");
    assert_eq!(body["attempt_id"], "attempt-3");
    assert_eq!(body["request_fingerprint"].as_str().unwrap().len(), 64);
}

// ---------------------------------------------------------------------------
// D01..D06 at the Driver level (mock connector).
// ---------------------------------------------------------------------------

/// D01a: the intent cannot be made durable -> no provider dispatch, no
/// fabricated outcome. (Mock: the store directory is made read-only.)
#[tokio::test(start_paused = true)]
async fn d01_intent_not_durable_means_no_dispatch() {
    use std::os::unix::fs::PermissionsExt;
    let connector = Cutting::new();
    connector.heal();
    let world = World::new();
    // Create the store and its lock file, then make the directory read-only so
    // the lock opens but the staged record cannot be created.
    drop(
        arcana_core::operation_intent::OperationSession::open(
            &arcana_core::operation_intent::OperationIntentConfig::new(&world.store, binding()),
        )
        .unwrap(),
    );
    std::fs::set_permissions(&world.store, std::fs::Permissions::from_mode(0o500)).unwrap();

    let out = process(&connector, &world, TASK, false).await;

    std::fs::set_permissions(&world.store, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(connector.calls(), 0, "nothing dispatched: {out:?}");
    assert_ne!(out.reason, TerminalReason::Completed);
    assert!(out.final_text.is_none(), "no fabricated outcome");
    assert_eq!(
        record_files(&world),
        Vec::<PathBuf>::new(),
        "no record was published"
    );
}

/// D01b: a writer died after staging, before the rename. The staged file was
/// never authoritative: it is discarded, nothing is held, nothing is invented.
#[tokio::test(start_paused = true)]
async fn d01_staged_leftover_of_a_dead_writer_is_not_authority() {
    let connector = Cutting::new();
    connector.heal();
    let world = World::new();
    let session = arcana_core::operation_intent::OperationSession::open(
        &arcana_core::operation_intent::OperationIntentConfig::new(&world.store, binding()),
    )
    .unwrap();
    drop(session);
    let scope = std::fs::read_dir(&world.store)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("lock"))
        })
        .unwrap();
    let stem = scope.trim_end_matches(".lock");
    let leftover = world.store.join(format!("{stem}.tmp-deadbeefdeadbeef"));
    std::fs::write(&leftover, b"{\"half\":").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let out = process(&connector, &world, TASK, false).await;

    assert_eq!(out.reason, TerminalReason::Completed, "{out:?}");
    assert!(!leftover.exists(), "dead writer's staged file discarded");
    assert_eq!(record_json(&world)["disposition"], "reconciled");
}

/// D02: crash after the intent is persisted and before the provider answered.
/// The pending identity is known; a restart reconciles/refuses and never mints
/// a new key.
#[tokio::test(start_paused = true)]
async fn d02_crash_after_persisted_intent_holds_the_pending_identity() {
    let connector = Arc::new(Cutting::new());
    connector.set(Mode::Die);
    let world = Arc::new(World::new());
    let (c, w) = (connector.clone(), world.clone());
    let crashed = tokio::spawn(async move { process(&*c, &w, TASK, false).await }).await;
    assert!(crashed.is_err(), "run 1 died inside the dispatch");
    let original = connector.keys()[0].clone().unwrap();
    assert_eq!(record_json(&world)["disposition"], "pending");
    assert_eq!(record_json(&world)["idempotency_key"], original.as_str());

    connector.heal();
    let before = connector.calls();
    let same = process(&*connector, &world, TASK, false).await;
    let changed = process(&*connector, &world, CHANGED, true).await;

    assert_eq!(connector.calls(), before, "no new dispatch, no new key");
    assert!(
        detail(&same).contains("INTENT_UNKNOWN_OUTCOME_HELD"),
        "{}",
        detail(&same)
    );
    assert!(
        detail(&changed).contains("reconcile required"),
        "{}",
        detail(&changed)
    );
    assert_eq!(record_json(&world)["idempotency_key"], original.as_str());
}

/// D03: cut after the provider may have charged, before the response. Restart
/// with the same request keeps the original identity; zero fresh dispatch
/// without verified replay. (The charge HOLD itself is `NOT_MEASURED`: ARAS has
/// no reservation.)
#[tokio::test(start_paused = true)]
async fn d03_cut_before_response_keeps_identity_and_dispatches_nothing_fresh() {
    let connector = Cutting::new();
    let world = World::new();
    let original = first_process_ends_unknown(&connector, &world).await;
    let before = connector.calls();
    connector.heal();

    let out = process(&connector, &world, TASK, false).await;

    assert_eq!(connector.calls(), before);
    assert_ne!(out.reason, TerminalReason::Completed);
    assert_eq!(record_json(&world)["idempotency_key"], original.as_str());
    assert_eq!(record_json(&world)["disposition"], "unknown");
}

/// A connector double with a server-side settlement table: a key that was
/// settled replays its stored response and is never charged again.
struct Settling {
    settled: Mutex<HashMap<String, ConnectorResponse>>,
    charges: AtomicUsize,
    calls: AtomicUsize,
    kill_switch: AtomicBool,
}

#[async_trait::async_trait]
impl ModelConnector for Settling {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let key = req.idempotency_key.as_ref().unwrap().as_str().to_owned();
        if let Some(stored) = self.settled.lock().unwrap().get(&key) {
            return Ok(stored.clone());
        }
        self.charges.fetch_add(1, Ordering::SeqCst);
        let resp = response("settled", 0.0);
        self.settled.lock().unwrap().insert(key, resp.clone());
        assert!(
            !self.kill_switch.load(Ordering::SeqCst),
            "process died after the effect, before the receipt"
        );
        Ok(resp)
    }
}

/// D05: the effect settled upstream but the process died before its local
/// receipt. A restart on a connector whose replay is verified retrieves the
/// settled result under the ORIGINAL key and is never charged twice; where
/// replay is not verified it stays unknown.
#[tokio::test(start_paused = true)]
async fn d05_settled_before_receipt_is_retrieved_not_recharged() {
    let connector = Arc::new(Settling {
        settled: Mutex::new(HashMap::new()),
        charges: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
        kill_switch: AtomicBool::new(true),
    });
    let world = Arc::new(World::new());
    let (c, w) = (connector.clone(), world.clone());
    let crashed = tokio::spawn(async move { process(&*c, &w, TASK, false).await }).await;
    assert!(crashed.is_err());
    let original = record_json(&world)["idempotency_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(record_json(&world)["disposition"], "pending");

    connector.kill_switch.store(false, Ordering::SeqCst);
    let calls = connector.calls.load(Ordering::SeqCst);
    let refused = process(&*connector, &world, TASK, false).await;
    assert_eq!(
        connector.calls.load(Ordering::SeqCst),
        calls,
        "unverified: no dispatch"
    );
    assert_ne!(refused.reason, TerminalReason::Completed);

    let out = process(&*connector, &world, TASK, true).await;
    assert_eq!(out.reason, TerminalReason::Completed, "{out:?}");
    assert_eq!(
        connector.charges.load(Ordering::SeqCst),
        1,
        "never charged twice"
    );
    assert_eq!(record_json(&world)["idempotency_key"], original.as_str());
    assert_eq!(record_json(&world)["disposition"], "reconciled");
}

/// D06: conflicting task lease / attempt / plan / deadline after restart:
/// typed refusal, no dispatch, and the retained identity is untouched (no
/// renewed deadline, no reset).
#[tokio::test(start_paused = true)]
async fn d06_conflicting_binding_after_restart_is_refused() {
    let connector = Cutting::new();
    let world = World::new();
    let _ = first_process_ends_unknown(&connector, &world).await;
    let before = connector.calls();
    let record_before = record_text(&world);
    connector.heal();

    let mut cases: Vec<(&str, arcana_core::operation_intent::OperationBinding)> = Vec::new();
    let mut b = binding();
    b.attempt_id = Some("attempt-4".into());
    cases.push(("attempt_id", b));
    let mut b = binding();
    b.lease_fence = Some("lease-42".into());
    cases.push(("lease_fence", b));
    let mut b = binding();
    b.plan_revision = Some("plan-r8".into());
    cases.push(("plan_revision", b));
    let mut b = binding();
    b.deadline_epoch_s = b.deadline_epoch_s.map(|d| d + 7200);
    cases.push(("deadline_epoch_s", b));

    for (field, conflicting) in cases {
        let out = process_with(&connector, &world, TASK, conflicting, true).await;
        assert_eq!(connector.calls(), before, "{field}: no dispatch");
        assert!(
            detail(&out).contains("INTENT_BINDING_CONFLICT") && detail(&out).contains(field),
            "{field}: {}",
            detail(&out)
        );
        assert_eq!(
            record_text(&world),
            record_before,
            "{field}: identity untouched"
        );
    }

    // An expired authoritative deadline refuses too, even on an identical request.
    let mut expired = binding();
    expired.deadline_epoch_s = Some(1);
    let out = process_with(&connector, &world, TASK, expired, true).await;
    assert_eq!(connector.calls(), before);
    assert!(
        detail(&out).contains("INTENT_BINDING_CONFLICT")
            || detail(&out).contains("INTENT_DEADLINE_EXPIRED"),
        "{}",
        detail(&out)
    );
}

/// Where ARAS has no native field, the operation refuses with a typed error;
/// nothing is invented.
#[tokio::test(start_paused = true)]
async fn a_missing_or_unclean_native_field_refuses_the_operation() {
    let connector = Cutting::new();
    connector.heal();
    let world = World::new();
    for (field, mutate) in [
        (
            "task_id",
            (|b: &mut arcana_core::operation_intent::OperationBinding| b.task_id = None)
                as fn(&mut _),
        ),
        ("plan_revision", |b| b.plan_revision = None),
        ("attempt_id", |b| b.attempt_id = None),
        ("lease_fence", |b| b.lease_fence = None),
        ("deadline_epoch_s", |b| b.deadline_epoch_s = None),
        ("dialect_revision", |b| b.dialect_revision = None),
    ] {
        let mut b = binding();
        mutate(&mut b);
        let out = process_with(&connector, &world, TASK, b, false).await;
        assert!(
            detail(&out).contains("INTENT_FIELD_MISSING") && detail(&out).contains(field),
            "{field}: {}",
            detail(&out)
        );
    }
    let mut b = binding();
    b.attempt_id = Some("answer the question and Bearer sk-secret".into());
    let out = process_with(&connector, &world, TASK, b, false).await;
    assert!(
        detail(&out).contains("INTENT_FIELD_INVALID"),
        "{}",
        detail(&out)
    );
    assert_eq!(connector.calls(), 0);
    assert_eq!(record_files(&world), Vec::<PathBuf>::new());
}

/// The ordinary path: a completed run leaves a reconciled record, and a later
/// run of the same attempt is a NEW operation with its own key.
#[tokio::test(start_paused = true)]
async fn a_reconciled_operation_does_not_block_the_next_one() {
    let connector = Cutting::new();
    connector.heal();
    let world = World::new();
    let out = process(&connector, &world, TASK, false).await;
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(record_json(&world)["disposition"], "reconciled");
    let first = connector.keys()[0].clone();

    let again = process(&connector, &world, CHANGED, false).await;
    assert_eq!(again.reason, TerminalReason::Completed);
    assert_ne!(
        connector.keys()[1],
        first,
        "settled operation: a new one is a new key"
    );
}

/// D07a: two drivers against one pending key -> at most one operation.
///
/// Wall-clock bound (not `start_paused`): if the first driver cannot open the
/// store it finishes without entering `execute`, and the old `join!` on
/// `entered.notified()` waited forever. Fail closed with the first driver's
/// typed outcome instead of hanging the hosted job.
#[tokio::test]
async fn d07_two_concurrent_drivers_yield_one_authority_consistent_operation() {
    struct Gate {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        calls: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl ModelConnector for Gate {
        async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            Ok(response("one", 0.0))
        }
    }
    let gate = Gate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        calls: AtomicUsize::new(0),
    };
    let world = World::new();
    let first = process(&gate, &world, TASK, false);
    tokio::pin!(first);
    tokio::select! {
        out = &mut first => {
            panic!(
                "first driver finished before entering execute (store open failed?): reason={:?} detail={}",
                out.reason,
                detail(&out)
            );
        }
        () = gate.entered.notified() => {
            let b = process(&gate, &world, TASK, false).await;
            gate.release.notify_one();
            let a = first.await;
            assert_eq!(a.reason, TerminalReason::Completed, "{a:?}");
            assert_ne!(b.reason, TerminalReason::Completed);
            assert!(
                detail(&b).contains("INTENT_STORE_LOCKED"),
                "{}",
                detail(&b)
            );
            assert_eq!(gate.calls.load(Ordering::SeqCst), 1, "exactly one dispatch");
        }
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("first driver did not enter execute within 5s (bounded wait)");
        }
    }
}

/// D07b: truncated / corrupt / oversized / misfiled state fails closed.
#[tokio::test(start_paused = true)]
async fn d07_truncated_or_corrupt_state_fails_closed() {
    for damage in ["truncate", "flip", "oversize", "garbage"] {
        let connector = Cutting::new();
        let world = World::new();
        let _ = first_process_ends_unknown(&connector, &world).await;
        let path = record_files(&world).remove(0);
        let mut bytes = std::fs::read(&path).unwrap();
        match damage {
            "truncate" => bytes.truncate(bytes.len() / 2),
            "flip" => {
                let i = bytes.iter().position(|b| *b == b'3').unwrap_or(40);
                bytes[i] = b'4';
            }
            "oversize" => bytes.extend(std::iter::repeat_n(b' ', 8192)),
            _ => bytes = b"not json at all".to_vec(),
        }
        std::fs::write(&path, bytes).unwrap();
        let before = connector.calls();
        connector.heal();

        let out = process(&connector, &world, TASK, true).await;

        assert_eq!(connector.calls(), before, "{damage}: no dispatch");
        assert_ne!(out.reason, TerminalReason::Completed, "{damage}");
        assert!(
            detail(&out).contains("INTENT_RECORD_CORRUPT")
                || detail(&out).contains("INTENT_RECORD_OVERSIZE"),
            "{damage}: {}",
            detail(&out)
        );
    }
}
