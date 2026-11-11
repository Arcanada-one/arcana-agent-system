//! G05: final effective-dispatch guard at the model/tool effect boundary.
//!
//! MOCKS: every connector here is an in-test double. No Model Connector and no
//! provider is called. Authority is an explicit synthetic
//! [`CurrentAuthority::Current`] supplied by the test (native effect-time
//! authority on the Driver path is unavailable and refuse-coded). The mocks
//! stand in for provider effect, so these are `NOT_MEASURED` by this file:
//! native authority, provider effect, cost reservation, Muneral reconcile join.
//!
//! Red against `b3ac795` (no `effective_dispatch` module / gate): each negative
//! case below would dispatch. Green after the G05 gate.

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
    EffectiveDispatchState, MandatoryMember,
};
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::HookChain;
use arcana_core::operation_intent::{OperationBinding, OperationIntentConfig};
use arcana_core::tool::ToolDispatcher;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{allow_cascade, response, test_executor, tool_call_result, EchoTool};

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
        task_id: Some("task-g05-0001".into()),
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
    fn tool_echo() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            reply: Mutex::new(tool_call_result(
                "echo",
                serde_json::json!({ "text": "hi" }),
            )),
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

/// Cuts the first dispatch so the durable intent stays unresolved (AC5).
struct CutOnce {
    calls: AtomicUsize,
    keys: Mutex<Vec<Option<String>>>,
}

#[async_trait::async_trait]
impl ModelConnector for CutOnce {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.keys
            .lock()
            .unwrap()
            .push(req.idempotency_key.as_ref().map(|k| k.as_str().to_owned()));
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ConnectorError::Timeout("cut".into()))
    }
}

struct World {
    audit: TempDir,
    /// Private intent store path. Must NOT be the `TempDir` root: on CI that
    /// directory is group-readable and `IntentStore` refuses it
    /// (`INTENT_PATH_INSECURE`). A child `intents/` is created owner-only by
    /// the store on first open (same pattern as `driver_restart_identity`).
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
        // macOS TempDir is under `/var/folders` (`/var` → `private/var`); the
        // store refuses symlink ancestors, so fixtures use the canonical path.
        let store = std::fs::canonicalize(store_root.path())
            .expect("canonical temporary root")
            .join("intents");
        Self {
            audit: TempDir::new().unwrap(),
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
        durable(&mut config, &self.store);
        let cost = Arc::new(CostTracker::new());
        let _ = &self.audit;
        Driver::new(
            connector,
            &self.executor,
            cost,
            CancellationToken::new(),
            config,
        )
    }
}

/// AC1: A proven / B unknown → zero consequential effects.
#[tokio::test]
async fn ac1_a_proven_b_unknown_zero_effects() {
    let world = World::new();
    let connector = CountingConnector::prose("should never run");
    let mut ed_state = state_all_pass();
    ed_state.members[1].discharge = DischargeAssessment::Unknown;
    let ed = EffectiveDispatchConfig::new(ed_state);
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 2;
    gate(&mut config, ed);
    let out = world.driver(&connector, config).run(TASK).await;
    assert_eq!(connector.calls(), 0, "AC1: zero model effects");
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap();
    assert!(
        detail.contains("EFFECT_PRECONDITION_UNDISCHARGED"),
        "typed refusal, got {detail}"
    );
    assert!(
        detail.contains('B') || detail.contains("member `B`"),
        "{detail}"
    );
}

/// AC2: delivered (covered) but undischarged obligation → typed refusal.
#[tokio::test]
async fn ac2_covered_but_undischarged_typed_refusal() {
    let world = World::new();
    let connector = CountingConnector::prose("should never run");
    let ed_state = EffectiveDispatchState {
        members: vec![member("obl-1", DischargeAssessment::AttributedOnly)],
        authority: authority_ok(),
        now_epoch_s: now_s(),
    };
    let mut config = DriverConfig::new("scripted");
    gate(&mut config, EffectiveDispatchConfig::new(ed_state));
    let out = world.driver(&connector, config).run(TASK).await;
    assert_eq!(connector.calls(), 0);
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap();
    assert!(
        detail.contains("EFFECT_PRECONDITION_UNDISCHARGED"),
        "{detail}"
    );
    assert!(
        detail.contains("attributed_only") || detail.contains("obl-1"),
        "{detail}"
    );
}

/// AC3: all predicates true under explicit synthetic authority → exactly one dispatch.
#[tokio::test]
async fn ac3_positive_control_dispatches_once() {
    let world = World::new();
    let connector = CountingConnector::prose("done");
    let mut config = DriverConfig::new("scripted");
    gate(&mut config, EffectiveDispatchConfig::new(state_all_pass()));
    let out = world.driver(&connector, config).run(TASK).await;
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(connector.calls(), 1, "AC3: exactly one model dispatch");
}

/// AC4: expiry or revocation across an await → refusal before effect.
#[tokio::test]
async fn ac4_revocation_across_await_refuses_before_effect() {
    let world = World::new();
    let connector = CountingConnector::prose("should never run");
    let mut ed = EffectiveDispatchConfig::new(state_all_pass());
    let state = Arc::clone(&ed.state);
    ed.between_checks = Some(Arc::new(move || {
        let state = Arc::clone(&state);
        Box::pin(async move {
            let mut g = state.lock().unwrap();
            if let CurrentAuthority::Current { revoked, .. } = &mut g.authority {
                *revoked = true;
            }
        })
    }));
    let mut config = DriverConfig::new("scripted");
    gate(&mut config, ed);
    let out = world.driver(&connector, config).run(TASK).await;
    assert_eq!(connector.calls(), 0, "AC4: revoked before effect");
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap();
    assert!(detail.contains("EFFECT_AUTHORITY_REVOKED"), "{detail}");
}

/// AC4 (expiry): wall-clock expiry across the await.
#[tokio::test]
async fn ac4_expiry_across_await_refuses_before_effect() {
    let world = World::new();
    let connector = CountingConnector::prose("should never run");
    let mut ed_state = state_all_pass();
    ed_state.authority = CurrentAuthority::Current {
        epoch: 1,
        expires_at_epoch_s: Some(now_s() + 10),
        revoked: false,
    };
    ed_state.now_epoch_s = now_s();
    let mut ed = EffectiveDispatchConfig::new(ed_state);
    let state = Arc::clone(&ed.state);
    ed.between_checks = Some(Arc::new(move || {
        let state = Arc::clone(&state);
        Box::pin(async move {
            let mut g = state.lock().unwrap();
            g.now_epoch_s = now_s() + 11;
        })
    }));
    let mut config = DriverConfig::new("scripted");
    gate(&mut config, ed);
    let out = world.driver(&connector, config).run(TASK).await;
    assert_eq!(connector.calls(), 0);
    let detail = out.terminal_detail.unwrap();
    assert!(detail.contains("EFFECT_AUTHORITY_EXPIRED"), "{detail}");
}

/// AC5: unresolved prior intent → no fresh-key redispatch.
#[tokio::test]
async fn ac5_unresolved_prior_intent_no_fresh_key_redispatch() {
    let world = World::new();
    // First run: pass the gate, then the connector "cuts" so outcome is unknown.
    let cut = CutOnce {
        calls: AtomicUsize::new(0),
        keys: Mutex::new(Vec::new()),
    };
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_backoff = Duration::ZERO;
    config.connector_retry_limit = 0;
    config.max_turns = 2;
    gate(&mut config, EffectiveDispatchConfig::new(state_all_pass()));
    let _ = world.driver(&cut, config).run(TASK).await;
    assert_eq!(cut.calls.load(Ordering::SeqCst), 1);
    let first_key = cut.keys.lock().unwrap()[0].clone().unwrap();

    // Second driver on the same store: gate would pass, but unresolved intent
    // must refuse a fresh-key dispatch.
    let cut2 = CutOnce {
        calls: AtomicUsize::new(0),
        keys: Mutex::new(Vec::new()),
    };
    let mut config2 = DriverConfig::new("scripted");
    config2.connector_retry_backoff = Duration::ZERO;
    config2.max_turns = 2;
    gate(&mut config2, EffectiveDispatchConfig::new(state_all_pass()));
    // Reuse the SAME store directory from world — rebuild driver manually.
    let mut registry = ToolDispatcher::new();
    let _ = registry.register(Arc::new(EchoTool));
    let (executor, _keep) = test_executor(registry, allow_cascade(), HookChain::new());
    let mut cfg = config2;
    durable(&mut cfg, &world.store);
    let out = Driver::new(
        &cut2,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        cfg,
    )
    .run(TASK)
    .await;
    assert_eq!(
        cut2.calls.load(Ordering::SeqCst),
        0,
        "AC5: no fresh-key redispatch while prior intent unresolved"
    );
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap();
    assert!(
        detail.contains("INTENT_UNKNOWN_OUTCOME_HELD")
            || detail.contains("unknown outcome")
            || detail.contains("INTENT_STATE_COMPETING"),
        "expected held-intent refusal, got {detail}"
    );
    // Original key identity preserved in the first cut.
    assert_ne!(first_key, "");
}

/// AC6: legitimate reconciliation → a later valid operation remains possible.
#[tokio::test]
async fn ac6_after_reconcile_later_operation_still_possible() {
    let world = World::new();
    let connector = CountingConnector::prose("first");
    let mut config = DriverConfig::new("scripted");
    gate(&mut config, EffectiveDispatchConfig::new(state_all_pass()));
    let out = world.driver(&connector, config).run(TASK).await;
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(connector.calls(), 1);

    // Same store, new driver, new operation after reconcile.
    let connector2 = CountingConnector::prose("second");
    let mut config2 = DriverConfig::new("scripted");
    gate(&mut config2, EffectiveDispatchConfig::new(state_all_pass()));
    let mut registry = ToolDispatcher::new();
    let _ = registry.register(Arc::new(EchoTool));
    let (executor, _keep) = test_executor(registry, allow_cascade(), HookChain::new());
    let mut cfg = config2;
    durable(&mut cfg, &world.store);
    let out2 = Driver::new(
        &connector2,
        &executor,
        Arc::new(CostTracker::new()),
        CancellationToken::new(),
        cfg,
    )
    .run("a later valid operation")
    .await;
    assert_eq!(out2.reason, TerminalReason::Completed);
    assert_eq!(connector2.calls(), 1, "AC6: later op dispatches once");
}

/// Tool-effect boundary: undischarged obligation refuses before the tool runs.
#[tokio::test]
async fn tool_effect_boundary_refuses_undischarged() {
    let world = World::new();
    let connector = CountingConnector::tool_echo();
    // Pass all for the model call, then poison B before the tool-effect admit.
    let admit_n = Arc::new(AtomicUsize::new(0));
    let mut ed = EffectiveDispatchConfig::new(state_all_pass());
    let state = Arc::clone(&ed.state);
    let admit_n2 = Arc::clone(&admit_n);
    ed.between_checks = Some(Arc::new(move || {
        let state = Arc::clone(&state);
        let admit_n = Arc::clone(&admit_n2);
        Box::pin(async move {
            let n = admit_n.fetch_add(1, Ordering::SeqCst);
            if n >= 1 {
                // After the model request's admit, poison B for the tool effect.
                let mut g = state.lock().unwrap();
                if let Some(m) = g.members.iter_mut().find(|m| m.id == "B") {
                    m.discharge = DischargeAssessment::Unknown;
                }
            }
        })
    }));
    let mut config = DriverConfig::new("scripted");
    config.require_action = true;
    gate(&mut config, ed);
    let out = world.driver(&connector, config).run(TASK).await;
    // Model ran once; tool must not have executed.
    assert_eq!(connector.calls(), 1, "model request admitted once");
    assert_eq!(out.tool_calls, 0, "tool effect refused");
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap();
    assert!(
        detail.contains("EFFECT_PRECONDITION_UNDISCHARGED"),
        "{detail}"
    );
}

/// Read-only clarification text is not free permission: missing authority still
/// refuses a model/network call.
#[tokio::test]
async fn clarification_is_not_free_model_permission() {
    let world = World::new();
    let connector = CountingConnector::prose("clarification");
    let ed_state = EffectiveDispatchState {
        members: vec![member("A", pass("A"))],
        authority: CurrentAuthority::Unavailable,
        now_epoch_s: now_s(),
    };
    let mut config = DriverConfig::new("scripted");
    gate(&mut config, EffectiveDispatchConfig::new(ed_state));
    let out = world
        .driver(&connector, config)
        .run("please clarify B")
        .await;
    assert_eq!(connector.calls(), 0);
    let detail = out.terminal_detail.unwrap();
    assert!(detail.contains("EFFECT_AUTHORITY_UNAVAILABLE"), "{detail}");
}
