//! G05 round 2 — discriminating controls ND01–ND12 (protected route + durable
//! proven-no-dispatch). Decision:
//! `G05-ROLLOUT-AND-PRE-EFFECT-RESOLUTION.md` §§3–7.
//!
//! MOCKS: every connector is an in-test double. No Model Connector and no
//! provider is called. Fixtures stay visibly synthetic. ND09 and ND10 are
//! recorded as `NOT_MEASURED` — ARAS has no native witness adapter or real
//! handoff fence beyond the local recheck (see module footer).
//!
//! RED on `ab3e5d42`: protected-route refusal and durable `no_dispatch` do not
//! exist; a guard refusal after Pending leaves Pending forever. GREEN after
//! this branch's implementation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
use arcana_core::connector::{ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector};
use arcana_core::cost::CostTracker;
use arcana_core::effective_dispatch::{
    CoverageState, CurrentAuthority, DischargeAssessment, EffectiveDispatchConfig,
    EffectiveDispatchState, MandatoryMember, RouteProtection,
};
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::HookChain;
use arcana_core::operation_intent::{
    Disposition, NewIntent, OperationBinding, OperationIntentConfig, OperationSession,
    RECORD_VERSION, RECORD_VERSION_NO_DISPATCH,
};
use arcana_core::tool::ToolDispatcher;
use serde_json::Value;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{allow_cascade, response, test_executor, EchoTool};

const TASK: &str = "answer with a tool when needed";

fn now_s() -> u64 {
    static START: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *START.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    })
}

fn binding() -> OperationBinding {
    OperationBinding {
        task_id: Some("task-g05-nd-0001".into()),
        plan_revision: Some("plan-r1".into()),
        attempt_id: Some("attempt-1".into()),
        lease_fence: Some("lease-1".into()),
        deadline_epoch_s: Some(now_s() + 3600),
        dialect_revision: Some("dialect-2026-11".into()),
        reservation_ref: None,
    }
}

fn pass(id: &str) -> DischargeAssessment {
    DischargeAssessment::Pass {
        witness_id: format!("w-{id}"),
        evaluated_at_epoch_s: now_s(),
    }
}

fn member(id: &str, discharge: DischargeAssessment) -> MandatoryMember {
    MandatoryMember {
        id: id.to_owned(),
        coverage: CoverageState::PresentExact,
        discharge,
    }
}

fn authority_ok() -> CurrentAuthority {
    CurrentAuthority::Current {
        epoch: 1,
        expires_at_epoch_s: Some(now_s() + 3600),
        revoked: false,
    }
}

fn state_all_pass() -> EffectiveDispatchState {
    EffectiveDispatchState {
        members: vec![member("A", pass("A")), member("B", pass("B"))],
        authority: authority_ok(),
        now_epoch_s: now_s(),
    }
}

fn state_undischarged() -> EffectiveDispatchState {
    let mut s = state_all_pass();
    s.members[1].discharge = DischargeAssessment::Unknown;
    s
}

fn durable(config: &mut DriverConfig, store: &Path) {
    config.operation_intent = Some(OperationIntentConfig::new(store, binding()));
}

fn gate(config: &mut DriverConfig, ed: EffectiveDispatchConfig) {
    config.effective_dispatch = Some(ed);
}

struct CountingConnector {
    calls: AtomicUsize,
    reply: Mutex<String>,
}

impl CountingConnector {
    fn prose(text: &str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            reply: Mutex::new(text.to_owned()),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ModelConnector for CountingConnector {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(response(&self.reply.lock().unwrap(), 0.0))
    }
}

struct World {
    store: PathBuf,
    _store_root: TempDir,
    executor: CapabilityExecutor,
    _hooks_keep: TempDir,
}

impl World {
    fn new() -> Self {
        let mut registry = ToolDispatcher::new();
        let _ = registry.register(Arc::new(EchoTool));
        let (executor, hooks_keep) = test_executor(registry, allow_cascade(), HookChain::new());
        let store_root = TempDir::new().unwrap();
        let store = store_root.path().join("intents");
        Self {
            store,
            _store_root: store_root,
            executor,
            _hooks_keep: hooks_keep,
        }
    }

    fn driver<'a>(
        &'a self,
        connector: &'a dyn ModelConnector,
        mut config: DriverConfig,
    ) -> Driver<'a> {
        if config.operation_intent.is_none() {
            durable(&mut config, &self.store);
        }
        Driver::new(
            connector,
            &self.executor,
            Arc::new(CostTracker::new()),
            CancellationToken::new(),
            config,
        )
    }

    fn record_json(&self) -> Value {
        let files: Vec<PathBuf> = std::fs::read_dir(&self.store)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        assert_eq!(files.len(), 1, "expected one intent record");
        let bytes = std::fs::read(&files[0]).unwrap();
        let envelope: Value = serde_json::from_slice(&bytes).unwrap();
        envelope["body"].clone()
    }
}

/// ND01: protected + gate None → typed unavailable, zero connector calls;
/// legacy + gate None → unchanged positive control; request cannot switch
/// protection off (protection lives only on `DriverConfig`).
#[tokio::test]
async fn nd01_protected_gate_none_refuses_legacy_positive_control() {
    let world = World::new();

    // Protected + gate None → refuse before effect.
    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    config.route_protection = RouteProtection::Protected;
    config.effective_dispatch = None;
    // Intentionally no durable intent either — both missing are unavailable.
    config.operation_intent = None;
    let out = Driver::new(
        &connector,
        &world.executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        config,
    )
    .run(TASK)
    .await;
    assert_eq!(connector.calls(), 0, "ND01: zero model effects");
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap();
    assert!(
        detail.contains("EFFECT_PROTECTED_GATE_UNAVAILABLE"),
        "typed protected refusal, got {detail}"
    );

    // Legacy + gate None → positive control (pre-G05 path).
    let connector2 = CountingConnector::prose("legacy-ok");
    let mut legacy = DriverConfig::new("scripted");
    assert_eq!(
        legacy.route_protection,
        RouteProtection::LegacyOutsideGuarantee
    );
    legacy.effective_dispatch = None;
    durable(&mut legacy, &world.store);
    let out2 = Driver::new(
        &connector2,
        &world.executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        legacy,
    )
    .run(TASK)
    .await;
    assert_eq!(out2.reason, TerminalReason::Completed);
    assert_eq!(connector2.calls(), 1, "ND01: legacy positive control");

    // Request field cannot switch protection off: ExecuteRequest has no
    // route_protection; only DriverConfig carries it.
    let req = ExecuteRequest::new("scripted", "hi");
    let encoded = serde_json::to_value(&req).unwrap_or(Value::Null);
    assert!(
        encoded.get("route_protection").is_none(),
        "ExecuteRequest must not carry route_protection"
    );
}

/// ND02: fresh Pending; final guard refuses before handoff → durable
/// `no_dispatch` for that identity; zero scoped dispatch.
#[tokio::test]
async fn nd02_fresh_pending_guard_refuse_writes_no_dispatch() {
    let world = World::new();
    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    gate(
        &mut config,
        EffectiveDispatchConfig::new(state_undischarged()),
    );
    durable(&mut config, &world.store);
    let out = world.driver(&connector, config).run(TASK).await;
    assert_eq!(connector.calls(), 0);
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap();
    assert!(
        detail.contains("EFFECT_PRECONDITION_UNDISCHARGED"),
        "{detail}"
    );
    assert!(
        !detail.contains("INTENT_NO_DISPATCH_UNRESOLVED"),
        "ND02 requires durable no-dispatch, got {detail}"
    );
    let body = world.record_json();
    assert_eq!(body["disposition"], "no_dispatch");
    assert_eq!(body["version"], RECORD_VERSION_NO_DISPATCH);
    assert_eq!(body["refusal_reason"], "EFFECT_PRECONDITION_UNDISCHARGED");
    assert!(body["outcome_ref"].is_null());
    assert!(!body["idempotency_key"].as_str().unwrap().is_empty());
}

/// ND03: previous attempt Unknown; current guard refuses before its own call →
/// remains unresolved under the original key; no false no-dispatch.
#[tokio::test]
async fn nd03_recovered_unknown_never_becomes_no_dispatch() {
    let world = World::new();
    // Seed an Unknown retained record via store API (synthetic prior attempt).
    {
        let mut session =
            OperationSession::open(&OperationIntentConfig::new(&world.store, binding())).unwrap();
        session
            .persist_pending(&NewIntent {
                run_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                turn: 1,
                provider: "scripted".into(),
                model: None,
                request_fingerprint: {
                    // Fingerprint of the same task text the driver will build.
                    // We mark Unknown then reopen — held path refuses before
                    // a new persist, so no-dispatch must stay ineligible.
                    let req = ExecuteRequest::new("scripted", TASK);
                    req.intent_fingerprint()
                },
                idempotency_key: "arcana.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.1".into(),
            })
            .unwrap();
        session.mark(Disposition::Unknown, None).unwrap();
    }
    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_limit = 0;
    config.connector_retry_backoff = Duration::ZERO;
    gate(
        &mut config,
        EffectiveDispatchConfig::new(state_undischarged()),
    );
    durable(&mut config, &world.store);
    let out = world.driver(&connector, config).run(TASK).await;
    assert_eq!(connector.calls(), 0);
    let body = world.record_json();
    assert_eq!(
        body["disposition"], "unknown",
        "ND03: recovered Unknown must not become no_dispatch; got {body}"
    );
    assert_ne!(body["version"], RECORD_VERSION_NO_DISPATCH);
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("INTENT_UNKNOWN_OUTCOME_HELD")
            || detail.contains("unknown outcome")
            || detail.contains("ReconcileRequired")
            || detail.contains("reconcile"),
        "expected held/unresolved path, got {detail}"
    );
}

/// ND04: crash after Pending, before terminal no-dispatch → restart preserves
/// ambiguous Pending (G07 crash-after-Pending); no fresh-key retry.
#[tokio::test]
async fn nd04_crash_after_pending_before_no_dispatch_stays_pending() {
    let world = World::new();
    {
        let mut session =
            OperationSession::open(&OperationIntentConfig::new(&world.store, binding())).unwrap();
        let req = ExecuteRequest::new("scripted", TASK);
        session
            .persist_pending(&NewIntent {
                run_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                turn: 1,
                provider: "scripted".into(),
                model: None,
                request_fingerprint: req.intent_fingerprint(),
                idempotency_key: "arcana.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.1".into(),
            })
            .unwrap();
        // Drop without mark_no_dispatch — simulates crash after Pending.
    }
    let body = world.record_json();
    assert_eq!(body["disposition"], "pending");
    assert_eq!(body["version"], RECORD_VERSION);

    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_limit = 0;
    config.connector_retry_backoff = Duration::ZERO;
    gate(&mut config, EffectiveDispatchConfig::new(state_all_pass()));
    durable(&mut config, &world.store);
    let out = world.driver(&connector, config).run(TASK).await;
    assert_eq!(
        connector.calls(),
        0,
        "ND04: no dispatch while prior Pending held"
    );
    let body2 = world.record_json();
    assert_eq!(
        body2["disposition"], "pending",
        "ND04: must not become no_dispatch from a recovered Pending"
    );
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("INTENT_UNKNOWN_OUTCOME_HELD")
            || detail.contains("unknown outcome")
            || detail.contains("ReconcileRequired")
            || detail.contains("reconcile"),
        "{detail}"
    );
}

/// ND05: crash after durable no-dispatch, before response → restart reports
/// retained resolution, no dispatch.
#[tokio::test]
async fn nd05_restart_after_no_dispatch_returns_retained_refusal() {
    let world = World::new();
    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    gate(
        &mut config,
        EffectiveDispatchConfig::new(state_undischarged()),
    );
    durable(&mut config, &world.store);
    let _ = world.driver(&connector, config).run(TASK).await;
    assert_eq!(connector.calls(), 0);
    assert_eq!(world.record_json()["disposition"], "no_dispatch");

    // Fresh driver (= restart) on the same store / same task text.
    let connector2 = CountingConnector::prose("still never");
    let mut config2 = DriverConfig::new("scripted");
    gate(&mut config2, EffectiveDispatchConfig::new(state_all_pass()));
    durable(&mut config2, &world.store);
    let out2 = world.driver(&connector2, config2).run(TASK).await;
    assert_eq!(
        connector2.calls(),
        0,
        "ND05: no dispatch after retained no-dispatch"
    );
    let detail = out2.terminal_detail.unwrap();
    assert!(
        detail.contains("INTENT_NO_DISPATCH_RETAINED")
            && detail.contains("EFFECT_PRECONDITION_UNDISCHARGED"),
        "{detail}"
    );
}

/// ND06: after no-dispatch, a late/racing attempt under the same closed key
/// cannot dispatch. Dispatch paths named: model (`call_connector` →
/// `connector.execute`) and tool (`run_tool_turn` → `executor.execute`);
/// connector retries re-enter `call_connector`. No background queue path in
/// arcana-core.
#[tokio::test]
async fn nd06_late_attempt_under_closed_key_cannot_dispatch() {
    let world = World::new();
    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    gate(
        &mut config,
        EffectiveDispatchConfig::new(state_undischarged()),
    );
    durable(&mut config, &world.store);
    let _ = world.driver(&connector, config).run(TASK).await;
    let closed_key = world.record_json()["idempotency_key"]
        .as_str()
        .unwrap()
        .to_owned();

    let connector2 = CountingConnector::prose("race");
    let mut config2 = DriverConfig::new("scripted");
    gate(&mut config2, EffectiveDispatchConfig::new(state_all_pass()));
    durable(&mut config2, &world.store);
    let out2 = world.driver(&connector2, config2).run(TASK).await;
    assert_eq!(connector2.calls(), 0, "ND06: late attempt fenced");
    assert!(
        out2.terminal_detail
            .as_deref()
            .unwrap_or("")
            .contains(&closed_key)
            || out2
                .terminal_detail
                .as_deref()
                .unwrap_or("")
                .contains("INTENT_NO_DISPATCH_RETAINED"),
        "{:?}",
        out2.terminal_detail
    );
}

/// ND07: terminal write fails (directory made read-only after Pending) → no
/// terminal acknowledgement; record stays inspectable as pending.
#[tokio::test]
async fn nd07_terminal_write_failure_leaves_pending_inspectable() {
    use std::os::unix::fs::PermissionsExt;
    let world = World::new();
    let mut session =
        OperationSession::open(&OperationIntentConfig::new(&world.store, binding())).unwrap();
    session
        .persist_pending(&NewIntent {
            run_id: "cccccccccccccccccccccccccccccccc".into(),
            turn: 1,
            provider: "scripted".into(),
            model: None,
            request_fingerprint: [9u8; 32],
            idempotency_key: "arcana.cccccccccccccccccccccccccccccccc.1".into(),
        })
        .unwrap();
    std::fs::set_permissions(&world.store, std::fs::Permissions::from_mode(0o500)).unwrap();
    let err = session
        .mark_no_dispatch("EFFECT_PRECONDITION_UNDISCHARGED")
        .unwrap_err();
    std::fs::set_permissions(&world.store, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(
            err.code(),
            "INTENT_STORE_IO" | "INTENT_PATH_INSECURE" | "INTENT_PARENT_CHANGED"
        ),
        "ND07: expected write failure, got {}",
        err.code()
    );
    // Drop session (release lock) and re-open to inspect.
    drop(session);
    let body = world.record_json();
    assert_eq!(
        body["disposition"], "pending",
        "ND07: pending must remain inspectable"
    );
    assert!(body["refusal_reason"].is_null());
}

/// ND08: same closed operation repeated → retained refusal; genuinely new
/// operation with its own identity may proceed exactly once.
#[tokio::test]
async fn nd08_closed_repeat_refuses_new_op_may_proceed() {
    let world = World::new();
    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    gate(
        &mut config,
        EffectiveDispatchConfig::new(state_undischarged()),
    );
    durable(&mut config, &world.store);
    let _ = world.driver(&connector, config).run(TASK).await;

    // Same closed operation (same task text / fingerprint).
    let connector_r = CountingConnector::prose("repeat");
    let mut config_r = DriverConfig::new("scripted");
    gate(
        &mut config_r,
        EffectiveDispatchConfig::new(state_all_pass()),
    );
    durable(&mut config_r, &world.store);
    let out_r = world.driver(&connector_r, config_r).run(TASK).await;
    assert_eq!(connector_r.calls(), 0);
    assert!(out_r
        .terminal_detail
        .unwrap()
        .contains("INTENT_NO_DISPATCH_RETAINED"));

    // Genuinely new operation (different prompt → different fingerprint).
    let connector_n = CountingConnector::prose("new-op-ok");
    let mut config_n = DriverConfig::new("scripted");
    gate(
        &mut config_n,
        EffectiveDispatchConfig::new(state_all_pass()),
    );
    durable(&mut config_n, &world.store);
    let out_n = world
        .driver(&connector_n, config_n)
        .run("a genuinely new admitted operation")
        .await;
    assert_eq!(out_n.reason, TerminalReason::Completed);
    assert_eq!(connector_n.calls(), 1, "ND08: new op dispatches once");
}

/// ND11: intent file never releases or asserts a native budget reservation.
#[tokio::test]
async fn nd11_intent_file_does_not_assert_budget_reservation() {
    let world = World::new();
    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    gate(
        &mut config,
        EffectiveDispatchConfig::new(state_undischarged()),
    );
    durable(&mut config, &world.store);
    let _ = world.driver(&connector, config).run(TASK).await;
    let body = world.record_json();
    assert_eq!(body["disposition"], "no_dispatch");
    assert!(
        body["reservation_ref"].is_null(),
        "ND11: reservation_ref must stay absent/unchanged; got {body}"
    );
}

/// ND12: v1 Reconciled semantics preserved; unknown version refuses.
#[test]
fn nd12_v1_reconciled_and_unknown_version_refused() {
    let (_root, dir) = {
        let root = TempDir::new().unwrap();
        let dir = root.path().join("intents");
        (root, dir)
    };
    // v1 Reconciled still requires outcome_ref and remains readable.
    let mut session = OperationSession::open(&OperationIntentConfig::new(&dir, binding())).unwrap();
    session
        .persist_pending(&NewIntent {
            run_id: "dddddddddddddddddddddddddddddddd".into(),
            turn: 1,
            provider: "scripted".into(),
            model: None,
            request_fingerprint: [1u8; 32],
            idempotency_key: "arcana.dddddddddddddddddddddddddddddddd.1".into(),
        })
        .unwrap();
    session
        .mark(Disposition::Reconciled, Some("observed-reply"))
        .unwrap();
    drop(session);
    let session2 = OperationSession::open(&OperationIntentConfig::new(&dir, binding())).unwrap();
    assert!(session2.held().is_none());
    assert!(session2.closed_no_dispatch().is_none());
    drop(session2);

    // Unknown version: corrupt the sealed body version field and expect refuse.
    let json_path = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap();
    let bytes = std::fs::read(&json_path).unwrap();
    let mut envelope: Value = serde_json::from_slice(&bytes).unwrap();
    envelope["body"]["version"] = Value::from(99u64);
    // Re-seal with a matching check so unseal reaches the version gate.
    let body = envelope["body"].clone();
    let canonical = serde_json::to_vec(&body).unwrap();
    let check = {
        use std::fmt::Write as _;
        let hash = blake3::hash(&canonical);
        hash.as_bytes().iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    };
    envelope["check"] = Value::from(check);
    let rewritten = serde_json::to_vec(&envelope).unwrap();
    std::fs::write(&json_path, rewritten).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&json_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let err = OperationSession::open(&OperationIntentConfig::new(&dir, binding())).unwrap_err();
    assert_eq!(err.code(), "INTENT_RECORD_CORRUPT", "{err}");
}

/*
NOT_MEASURED (precise missing native input):

ND09 — Synthetic Pass/NotApplicable with empty/wrong-scope witness; model proof
       reused for a tool effect. Missing native input: an authenticated
       composition-root witness adapter that validates witness_id scope and
       refuses reuse of a model-request discharge for a tool effect. Pure-enum
       fixtures in effective_dispatch.rs do not count as native evidence.

ND10 — Expiry/revocation or request change after the local check and before
       actual handoff. Missing native input: a real connector/executor handoff
       fence ordered with authority revocation (the local between_checks recheck
       is not an atomic revocation/effect fence across network scheduling).
*/
