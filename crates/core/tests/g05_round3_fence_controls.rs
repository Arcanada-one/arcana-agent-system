//! G05 round 3 — discriminate the two no-dispatch fences that round 2 left
//! untested (coordinator verification on PR #277, issuecomment 6724713247).
//!
//! Mutations these cases must catch:
//! - **M1**: `fresh_pending` and `held` checks in `OperationSession::mark_no_dispatch`
//!   disabled → recovered Pending/Unknown must not silently become `no_dispatch`.
//! - **M2**: `handoff_count != 0` check disabled → a counted connector/executor
//!   handoff must still block proven-no-dispatch.
//!
//! MOCKS only. No Model Connector and no provider is called.

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
use arcana_core::operation_intent::{
    Disposition, IntentError, NewIntent, OperationBinding, OperationIntentConfig, OperationSession,
    RECORD_VERSION, RECORD_VERSION_NO_DISPATCH,
};
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{
    allow_cascade, response, test_executor, tool_call_result, DenyLayer, EchoTool, StopHook,
};

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
        task_id: Some("task-g05-r3-0001".into()),
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

fn parse_fingerprint_hex(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "fingerprint hex");
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let text = std::str::from_utf8(pair).unwrap();
        *slot = u8::from_str_radix(text, 16).unwrap();
    }
    out
}

fn durable(config: &mut DriverConfig, store: &Path) {
    config.operation_intent = Some(OperationIntentConfig::new(store, binding()));
}

fn durable_replay(config: &mut DriverConfig, store: &Path) {
    let mut intent = OperationIntentConfig::new(store, binding());
    intent.same_key_replay_verified = true;
    config.operation_intent = Some(intent);
}

fn gate(config: &mut DriverConfig, ed: EffectiveDispatchConfig) {
    config.effective_dispatch = Some(ed);
}

fn record_path(store: &Path) -> PathBuf {
    let files: Vec<PathBuf> = std::fs::read_dir(store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    assert_eq!(files.len(), 1, "expected one intent record");
    files[0].clone()
}

fn record_bytes(store: &Path) -> Vec<u8> {
    std::fs::read(record_path(store)).unwrap()
}

fn record_json(store: &Path) -> Value {
    let envelope: Value = serde_json::from_slice(&record_bytes(store)).unwrap();
    envelope["body"].clone()
}

fn seed_pending(store: &Path, run_hex: &str, fingerprint: [u8; 32]) {
    let mut session =
        OperationSession::open(&OperationIntentConfig::new(store, binding())).unwrap();
    session
        .persist_pending(&NewIntent {
            run_id: run_hex.into(),
            turn: 1,
            provider: "scripted".into(),
            model: None,
            request_fingerprint: fingerprint,
            idempotency_key: format!("arcana.{run_hex}.1"),
        })
        .unwrap();
}

fn seed_unknown(store: &Path, run_hex: &str, fingerprint: [u8; 32]) {
    let mut session =
        OperationSession::open(&OperationIntentConfig::new(store, binding())).unwrap();
    session
        .persist_pending(&NewIntent {
            run_id: run_hex.into(),
            turn: 1,
            provider: "scripted".into(),
            model: None,
            request_fingerprint: fingerprint,
            idempotency_key: format!("arcana.{run_hex}.1"),
        })
        .unwrap();
    session.mark(Disposition::Unknown, None).unwrap();
}

/// Capture the exact fingerprint the live driver stamps for `TASK` (includes
/// the policy-selected model and composed prompt fields).
async fn capture_live_task_fingerprint() -> [u8; 32] {
    let world = World::new();
    let connector = CountingConnector::timeout("cut-for-fingerprint");
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_limit = 0;
    config.connector_retry_backoff = Duration::ZERO;
    gate(&mut config, EffectiveDispatchConfig::new(state_all_pass()));
    durable(&mut config, &world.store);
    let _ = world.driver(&connector, config).run(TASK).await;
    let body = record_json(&world.store);
    let hex = body["request_fingerprint"].as_str().expect("fingerprint");
    parse_fingerprint_hex(hex)
}

struct CountingConnector {
    calls: AtomicUsize,
    mode: Mutex<ConnMode>,
}

enum ConnMode {
    Prose(String),
    Transport(&'static str),
    Timeout(&'static str),
    ToolEcho,
}

impl CountingConnector {
    fn prose(text: &str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode: Mutex::new(ConnMode::Prose(text.to_owned())),
        }
    }
    fn transport_err(message: &'static str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode: Mutex::new(ConnMode::Transport(message)),
        }
    }
    fn timeout(message: &'static str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode: Mutex::new(ConnMode::Timeout(message)),
        }
    }
    fn tool_echo() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode: Mutex::new(ConnMode::ToolEcho),
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
        match &*self.mode.lock().unwrap() {
            ConnMode::Prose(text) => Ok(response(text, 0.0)),
            ConnMode::Transport(message) => Err(ConnectorError::Transport((*message).into())),
            ConnMode::Timeout(message) => Err(ConnectorError::Timeout((*message).into())),
            ConnMode::ToolEcho => Ok(response(
                &tool_call_result("echo", json!({ "text": "hi" })),
                0.0,
            )),
        }
    }
}

/// Tool that fails after the driver has already counted the executor handoff.
struct BoomTool;

#[async_trait]
impl Tool for BoomTool {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn description(&self) -> &'static str {
        "fails after admission"
    }
    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }
    async fn execute(&self, _invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        Err(ToolError::ExecutionFailed("mock executor error".into()))
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
        Self::with_executor(allow_cascade(), HookChain::new(), Arc::new(EchoTool))
    }

    fn with_deny_tool() -> Self {
        let cascade = PermissionCascade::new(vec![Arc::new(DenyLayer)]);
        Self::with_executor(cascade, HookChain::new(), Arc::new(EchoTool))
    }

    fn with_stop_hook() -> Self {
        let mut hooks = HookChain::new();
        hooks.push(Arc::new(StopHook));
        Self::with_executor(allow_cascade(), hooks, Arc::new(EchoTool))
    }

    fn with_boom_tool() -> Self {
        Self::with_executor(allow_cascade(), HookChain::new(), Arc::new(BoomTool))
    }

    fn with_executor(cascade: PermissionCascade, hooks: HookChain, tool: Arc<dyn Tool>) -> Self {
        let mut registry = ToolDispatcher::new();
        let _ = registry.register(tool);
        let (executor, hooks_keep) = test_executor(registry, cascade, hooks);
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
}

fn assert_fence_ineligible(err: &IntentError) {
    assert_eq!(err.code(), "INTENT_NO_DISPATCH_INELIGIBLE", "{err}");
    let text = err.to_string();
    assert!(
        text.contains("fresh pending")
            || text.contains("recovered unresolved")
            || text.contains("zero connector/executor handoff"),
        "expected session fence reason (M1/M2), got {text}"
    );
}

fn assert_no_retained_shortcut(detail: &str) {
    assert!(
        !detail.contains("INTENT_NO_DISPATCH_RETAINED"),
        "must not take retained-refusal shortcut, got {detail}"
    );
}

// ---------------------------------------------------------------------------
// T1 — recovered Pending / Unknown: mark_no_dispatch is ineligible (M1)
// ---------------------------------------------------------------------------

/// T1 session: recovered Pending → `mark_no_dispatch` refuses; bytes unchanged.
#[test]
fn t1_session_recovered_pending_mark_no_dispatch_ineligible() {
    let root = TempDir::new().unwrap();
    let store = root.path().join("intents");
    // Session-level: any closed fingerprint is fine; the fence is session state.
    let fingerprint = [0x11u8; 32];
    seed_pending(&store, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", fingerprint);
    let before = record_bytes(&store);

    let mut session =
        OperationSession::open(&OperationIntentConfig::new(&store, binding())).unwrap();
    assert!(session.held().is_some());
    let err = session
        .mark_no_dispatch("EFFECT_PRECONDITION_UNDISCHARGED")
        .unwrap_err();
    assert_fence_ineligible(&err);
    drop(session);

    assert_eq!(
        record_bytes(&store),
        before,
        "record bytes must be unchanged"
    );
    let body = record_json(&store);
    assert_eq!(body["disposition"], "pending");
    assert_eq!(body["version"], RECORD_VERSION);
    assert!(body["refusal_reason"].is_null());
}

/// T1 session: recovered Unknown → `mark_no_dispatch` refuses; bytes unchanged.
#[test]
fn t1_session_recovered_unknown_mark_no_dispatch_ineligible() {
    let root = TempDir::new().unwrap();
    let store = root.path().join("intents");
    let fingerprint = [0x22u8; 32];
    seed_unknown(&store, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", fingerprint);
    let before = record_bytes(&store);

    let mut session =
        OperationSession::open(&OperationIntentConfig::new(&store, binding())).unwrap();
    assert!(session.held().is_some());
    let err = session
        .mark_no_dispatch("EFFECT_PRECONDITION_UNDISCHARGED")
        .unwrap_err();
    assert_fence_ineligible(&err);
    drop(session);

    assert_eq!(
        record_bytes(&store),
        before,
        "record bytes must be unchanged"
    );
    let body = record_json(&store);
    assert_eq!(body["disposition"], "unknown");
    assert_ne!(body["version"], RECORD_VERSION_NO_DISPATCH);
    assert!(body["refusal_reason"].is_null());
}

/// T1 driver: recovered Pending under the same key reaches `mark_no_dispatch`
/// (replay-verified reuse + undischarged gate) → ineligible; zero dispatch.
#[tokio::test]
async fn t1_driver_recovered_pending_refusal_stays_pending() {
    let fingerprint = capture_live_task_fingerprint().await;
    let world = World::new();
    seed_pending(
        &world.store,
        "cccccccccccccccccccccccccccccccc",
        fingerprint,
    );
    let before = record_bytes(&world.store);

    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_limit = 0;
    config.connector_retry_backoff = Duration::ZERO;
    gate(
        &mut config,
        EffectiveDispatchConfig::new(state_undischarged()),
    );
    durable_replay(&mut config, &world.store);
    let out = world.driver(&connector, config).run(TASK).await;

    assert_eq!(
        connector.calls(),
        0,
        "T1: zero dispatch on recovered Pending"
    );
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("INTENT_NO_DISPATCH_INELIGIBLE")
            || detail.contains("INTENT_NO_DISPATCH_UNRESOLVED"),
        "expected mark_no_dispatch ineligibility, got {detail}"
    );
    assert_no_retained_shortcut(&detail);
    assert_eq!(record_bytes(&world.store), before);
    assert_eq!(record_json(&world.store)["disposition"], "pending");
}

/// T1 driver: recovered Unknown under the same key → ineligible; stays unknown.
#[tokio::test]
async fn t1_driver_recovered_unknown_refusal_stays_unknown() {
    let fingerprint = capture_live_task_fingerprint().await;
    let world = World::new();
    seed_unknown(
        &world.store,
        "dddddddddddddddddddddddddddddddd",
        fingerprint,
    );
    let before = record_bytes(&world.store);

    let connector = CountingConnector::prose("should never run");
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_limit = 0;
    config.connector_retry_backoff = Duration::ZERO;
    gate(
        &mut config,
        EffectiveDispatchConfig::new(state_undischarged()),
    );
    durable_replay(&mut config, &world.store);
    let out = world.driver(&connector, config).run(TASK).await;

    assert_eq!(
        connector.calls(),
        0,
        "T1: zero dispatch on recovered Unknown"
    );
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let detail = out.terminal_detail.unwrap_or_default();
    assert!(
        detail.contains("INTENT_NO_DISPATCH_INELIGIBLE")
            || detail.contains("INTENT_NO_DISPATCH_UNRESOLVED"),
        "expected mark_no_dispatch ineligibility, got {detail}"
    );
    assert_no_retained_shortcut(&detail);
    assert_eq!(record_bytes(&world.store), before);
    assert_eq!(record_json(&world.store)["disposition"], "unknown");
}

// ---------------------------------------------------------------------------
// T2 — model path after note_handoff (M2)
// ---------------------------------------------------------------------------

/// Session-level M2 discriminator: after `note_handoff`, no-dispatch is
/// ineligible and the pending bytes stay pending.
#[test]
fn t2_session_handoff_blocks_mark_no_dispatch() {
    let root = TempDir::new().unwrap();
    let store = root.path().join("intents");
    let mut session =
        OperationSession::open(&OperationIntentConfig::new(&store, binding())).unwrap();
    session
        .persist_pending(&NewIntent {
            run_id: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(),
            turn: 1,
            provider: "scripted".into(),
            model: None,
            request_fingerprint: [0x33u8; 32],
            idempotency_key: "arcana.eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.1".into(),
        })
        .unwrap();
    session.note_handoff();
    let before = record_bytes(&store);
    let err = session
        .mark_no_dispatch("EFFECT_PRECONDITION_UNDISCHARGED")
        .unwrap_err();
    assert_eq!(err.code(), "INTENT_NO_DISPATCH_INELIGIBLE");
    assert!(
        err.to_string().contains("zero connector/executor handoff"),
        "{}",
        err
    );
    drop(session);
    assert_eq!(record_bytes(&store), before);
    assert_eq!(record_json(&store)["disposition"], "pending");
}

async fn t2_driver_model_post_handoff_failure(connector: CountingConnector, label: &str) {
    let world = World::new();
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_limit = 0;
    config.connector_retry_backoff = Duration::ZERO;
    config.max_turns = 1;
    gate(&mut config, EffectiveDispatchConfig::new(state_all_pass()));
    durable(&mut config, &world.store);
    let out = world.driver(&connector, config).run(TASK).await;

    assert_eq!(
        connector.calls(),
        1,
        "{label}: connector was handed off exactly once"
    );
    assert_eq!(out.reason, TerminalReason::ConnectorFatal);
    let body = record_json(&world.store);
    assert_ne!(
        body["disposition"], "no_dispatch",
        "{label}: must never become no_dispatch after post-handoff failure; got {body}"
    );
    assert!(
        body["disposition"] == "unknown" || body["disposition"] == "pending",
        "{label}: expected pending/unknown, got {body}"
    );
    assert!(body["refusal_reason"].is_null());
    let key = body["idempotency_key"].as_str().unwrap().to_owned();

    // Next attempt under the same fingerprint: no retained-refusal shortcut,
    // no fresh key (held unresolved blocks).
    let connector2 = CountingConnector::prose("must not run");
    let mut config2 = DriverConfig::new("scripted");
    config2.connector_retry_limit = 0;
    config2.connector_retry_backoff = Duration::ZERO;
    gate(&mut config2, EffectiveDispatchConfig::new(state_all_pass()));
    durable(&mut config2, &world.store);
    let out2 = world.driver(&connector2, config2).run(TASK).await;
    assert_eq!(connector2.calls(), 0, "{label}: zero dispatch on restart");
    let detail = out2.terminal_detail.unwrap_or_default();
    assert_no_retained_shortcut(&detail);
    assert!(
        detail.contains("INTENT_UNKNOWN_OUTCOME_HELD")
            || detail.contains("unknown outcome")
            || detail.contains("ReconcileRequired")
            || detail.contains("reconcile"),
        "{label}: expected held/unresolved path, got {detail}"
    );
    let body2 = record_json(&world.store);
    assert_eq!(
        body2["idempotency_key"].as_str().unwrap(),
        key,
        "{label}: must not mint a fresh key"
    );
    assert_ne!(body2["disposition"], "no_dispatch");
}

/// T2 driver: connector transport error after `note_handoff`.
#[tokio::test]
async fn t2_driver_model_connector_error_keeps_unresolved() {
    t2_driver_model_post_handoff_failure(
        CountingConnector::transport_err("mock connector error"),
        "T2-error",
    )
    .await;
}

/// T2 driver: connector timeout after `note_handoff` (unknown outcome).
#[tokio::test]
async fn t2_driver_model_connector_timeout_keeps_unresolved() {
    t2_driver_model_post_handoff_failure(
        CountingConnector::timeout("mock connector timeout"),
        "T2-timeout",
    )
    .await;
}

// ---------------------------------------------------------------------------
// T3 — tool path after note_handoff (M2 behavioural sibling of T2)
// ---------------------------------------------------------------------------

async fn t3_driver_tool_post_handoff_failure(world: World, label: &str) {
    let connector = CountingConnector::tool_echo();
    let mut config = DriverConfig::new("scripted");
    config.connector_retry_limit = 0;
    config.connector_retry_backoff = Duration::ZERO;
    config.max_turns = 2;
    config.require_action = true;
    gate(&mut config, EffectiveDispatchConfig::new(state_all_pass()));
    durable(&mut config, &world.store);
    let out = world.driver(&connector, config).run(TASK).await;

    assert_eq!(connector.calls(), 1, "{label}: model handoff occurred");
    assert_eq!(out.tool_calls, 0, "{label}: tool effect did not complete");
    let body = record_json(&world.store);
    assert_ne!(
        body["disposition"], "no_dispatch",
        "{label}: must never become no_dispatch; got {body}"
    );
    assert!(
        body["disposition"] == "unknown" || body["disposition"] == "pending",
        "{label}: expected pending/unknown, got {body}"
    );
    let key = body["idempotency_key"].as_str().unwrap().to_owned();

    let connector2 = CountingConnector::prose("must not run");
    let mut config2 = DriverConfig::new("scripted");
    config2.connector_retry_limit = 0;
    config2.connector_retry_backoff = Duration::ZERO;
    gate(&mut config2, EffectiveDispatchConfig::new(state_all_pass()));
    durable(&mut config2, &world.store);
    let out2 = world.driver(&connector2, config2).run(TASK).await;
    assert_eq!(connector2.calls(), 0, "{label}: zero dispatch on restart");
    let detail = out2.terminal_detail.unwrap_or_default();
    assert_no_retained_shortcut(&detail);
    assert!(
        detail.contains("INTENT_UNKNOWN_OUTCOME_HELD")
            || detail.contains("unknown outcome")
            || detail.contains("ReconcileRequired")
            || detail.contains("reconcile"),
        "{label}: expected held/unresolved path, got {detail}"
    );
    let body2 = record_json(&world.store);
    assert_eq!(
        body2["idempotency_key"].as_str().unwrap(),
        key,
        "{label}: must not mint a fresh key"
    );
    assert_ne!(body2["disposition"], "no_dispatch");
}

/// T3 driver: mock executor denial after tool `note_handoff`.
#[tokio::test]
async fn t3_driver_tool_executor_error_keeps_unresolved() {
    t3_driver_tool_post_handoff_failure(World::with_deny_tool(), "T3-deny").await;
}

/// T3 driver: tool execution failure after tool `note_handoff`.
#[tokio::test]
async fn t3_driver_tool_execution_failed_keeps_unresolved() {
    t3_driver_tool_post_handoff_failure(World::with_boom_tool(), "T3-boom").await;
}

/// T3 driver: hook abort after tool `note_handoff` (timeout/unknown class).
#[tokio::test]
async fn t3_driver_tool_hook_abort_keeps_unresolved() {
    t3_driver_tool_post_handoff_failure(World::with_stop_hook(), "T3-hook").await;
}
