//! C4 structural security contract for the fused capability executor.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::doc_markdown
)]

mod common;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use arcana_core::cost::CostTracker;
use arcana_core::execution::{AuditFailurePhase, CapabilityError, CapabilityExecutor};
use arcana_core::hooks::audit::{AuditLog, DurableAuditWriter};
use arcana_core::hooks::{HookChain, HookContext};
use arcana_core::permission::{LayerDecision, PermissionCascade, PermissionLayer};
use arcana_core::tool::ToolDispatcher;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use common::{AllowLayer, CountingTool, InvalidReplaceLayer, ReplaceInputHook};

#[derive(Clone)]
struct ControlledWriter {
    state: Arc<Mutex<WriterState>>,
}

struct WriterState {
    bytes: Vec<u8>,
    successful_records: usize,
    fail_after_records: Option<usize>,
    fail_once: bool,
    failure_injected: bool,
    fail_sync: bool,
}

impl ControlledWriter {
    fn recording() -> (Self, Arc<Mutex<WriterState>>) {
        let state = Arc::new(Mutex::new(WriterState {
            bytes: Vec::new(),
            successful_records: 0,
            fail_after_records: None,
            fail_once: false,
            failure_injected: false,
            fail_sync: false,
        }));
        (
            Self {
                state: Arc::clone(&state),
            },
            state,
        )
    }

    fn fail_after(records: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(WriterState {
                bytes: Vec::new(),
                successful_records: 0,
                fail_after_records: Some(records),
                fail_once: false,
                failure_injected: false,
                fail_sync: false,
            })),
        }
    }

    fn fail_once_after(records: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(WriterState {
                bytes: Vec::new(),
                successful_records: 0,
                fail_after_records: Some(records),
                fail_once: true,
                failure_injected: false,
                fail_sync: false,
            })),
        }
    }

    fn fail_sync() -> Self {
        Self {
            state: Arc::new(Mutex::new(WriterState {
                bytes: Vec::new(),
                successful_records: 0,
                fail_after_records: None,
                fail_once: false,
                failure_injected: false,
                fail_sync: true,
            })),
        }
    }
}

impl DurableAuditWriter for ControlledWriter {
    fn sync_data(&mut self) -> io::Result<()> {
        if self.state.lock().expect("writer state lock").fail_sync {
            Err(io::Error::other("injected audit sync failure"))
        } else {
            Ok(())
        }
    }
}

impl Write for ControlledWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().expect("writer state lock");
        let should_fail = state
            .fail_after_records
            .is_some_and(|limit| state.successful_records >= limit)
            && (!state.fail_once || !state.failure_injected);
        if should_fail {
            state.failure_injected = true;
            return Err(io::Error::other("injected audit failure"));
        }
        state.bytes.extend_from_slice(buf);
        state.successful_records += usize::from(buf.last() == Some(&b'\n'));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn context() -> HookContext {
    HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()))
}

fn executor(
    counter: Arc<std::sync::atomic::AtomicUsize>,
    cascade: PermissionCascade,
    audit: AuditLog,
) -> CapabilityExecutor {
    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(CountingTool::new(counter)))
        .expect("register counting tool");
    CapabilityExecutor::new(registry, cascade, HookChain::new(), audit)
}

#[tokio::test]
async fn all_defer_cascade_denies_and_executes_zero_tools() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (writer, state) = ControlledWriter::recording();
    let executor = executor(
        Arc::clone(&count),
        PermissionCascade::new(vec![]),
        AuditLog::from_durable_writer(Box::new(writer)),
    );

    let err = executor
        .execute(&context(), "counting", json!({ "value": 1 }))
        .await
        .expect_err("all-defer cascade must deny");

    assert!(matches!(
        err,
        CapabilityError::Denied {
            layer: "cascade",
            ..
        }
    ));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
    let records = audit_records(&state);
    assert_eq!(records.len(), 2, "decision plus terminal denial");
    assert_eq!(records[0]["phase"], "decision");
    assert_eq!(records[1]["phase"], "result");
    assert_eq!(records[0]["invocation_id"], records[1]["invocation_id"]);
}

// A post-cascade hook that returns `ReplaceInput` models the F-dispatch(security)-1
// bypass: an executor-owned hook trying to transform the payload *after* the
// cascade already authorized it, sidestepping the Rule-deny and Interactive
// human-approval gates. The compile-time guarantee (a `PreToolGate` carries no
// input, so the executor cannot route such a transform into execution) is pinned
// by the `compile_fail` doctest on `arcana_core::hooks::PreToolGate`; this test
// pins the runtime companion: the attempt aborts fail-closed and executes zero
// tools rather than silently applying an ungoverned transform.
#[tokio::test]
async fn post_cascade_replaceinput_hook_aborts_and_executes_zero_tools() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (writer, state) = ControlledWriter::recording();

    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(CountingTool::new(Arc::clone(&count))))
        .expect("register counting tool");
    let mut hooks = HookChain::new();
    hooks.push(Arc::new(ReplaceInputHook));
    let executor = CapabilityExecutor::new(
        registry,
        PermissionCascade::new(vec![Arc::new(AllowLayer)]),
        hooks,
        AuditLog::from_durable_writer(Box::new(writer)),
    );

    let err = executor
        .execute(&context(), "counting", json!({ "value": 1 }))
        .await
        .expect_err("post-cascade transform must abort fail-closed");

    assert!(matches!(err, CapabilityError::HookAborted));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);

    // The abort is audited as a hook-layer denial: decision + terminal result,
    // one correlated pair, no execution.
    let records = audit_records(&state);
    assert_eq!(records.len(), 2, "decision plus terminal denial");
    assert_eq!(records[0]["decision"], "Denied");
    assert_eq!(records[0]["layer"], "hook");
    assert_eq!(records[0]["invocation_id"], records[1]["invocation_id"]);
}

#[tokio::test]
async fn transformed_input_is_revalidated_immediately_before_execution() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (writer, _state) = ControlledWriter::recording();
    let cascade = PermissionCascade::new(vec![
        Arc::new(InvalidReplaceLayer) as Arc<dyn PermissionLayer>,
        Arc::new(AllowLayer),
    ]);
    let executor = executor(
        Arc::clone(&count),
        cascade,
        AuditLog::from_durable_writer(Box::new(writer)),
    );

    let err = executor
        .execute(&context(), "counting", json!({ "value": 1 }))
        .await
        .expect_err("post-transform schema must reject");

    assert!(matches!(
        err,
        CapabilityError::Denied {
            layer: "schema",
            ..
        }
    ));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pre_audit_failure_executes_zero_tools() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let executor = executor(
        Arc::clone(&count),
        PermissionCascade::new(vec![Arc::new(AllowLayer)]),
        AuditLog::from_durable_writer(Box::new(ControlledWriter::fail_after(0))),
    );

    let err = executor
        .execute(&context(), "counting", json!({ "value": 1 }))
        .await
        .expect_err("pre-audit write must fail closed");

    assert!(matches!(
        err,
        CapabilityError::AuditFailure {
            phase: AuditFailurePhase::Decision,
            ..
        }
    ));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn decision_audit_failure_latches_executor_closed() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let executor = executor(
        Arc::clone(&count),
        PermissionCascade::new(vec![Arc::new(AllowLayer)]),
        AuditLog::from_durable_writer(Box::new(ControlledWriter::fail_once_after(0))),
    );

    let first = executor
        .execute(&context(), "counting", json!({ "value": 1 }))
        .await
        .expect_err("decision audit failure must fail closed");
    assert!(matches!(
        first,
        CapabilityError::AuditFailure {
            phase: AuditFailurePhase::Decision,
            ..
        }
    ));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);

    let second = executor
        .execute(&context(), "counting", json!({ "value": 2 }))
        .await
        .expect_err("decision audit failure must permanently latch the executor");
    assert!(matches!(second, CapabilityError::AuditLatched));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn audit_sync_failure_executes_zero_tools() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let executor = executor(
        Arc::clone(&count),
        PermissionCascade::new(vec![Arc::new(AllowLayer)]),
        AuditLog::from_durable_writer(Box::new(ControlledWriter::fail_sync())),
    );

    let err = executor
        .execute(&context(), "counting", json!({ "value": 1 }))
        .await
        .expect_err("decision sync must fail closed");

    assert!(matches!(
        err,
        CapabilityError::AuditFailure {
            phase: AuditFailurePhase::Decision,
            ..
        }
    ));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn post_audit_failure_is_fatal_and_latches_executor_closed() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let executor = executor(
        Arc::clone(&count),
        PermissionCascade::new(vec![Arc::new(AllowLayer)]),
        AuditLog::from_durable_writer(Box::new(ControlledWriter::fail_after(1))),
    );

    let first = executor
        .execute(&context(), "counting", json!({ "value": 1 }))
        .await
        .expect_err("terminal audit write must be fatal");
    assert!(matches!(
        first,
        CapabilityError::AuditFailure {
            phase: AuditFailurePhase::Result,
            ..
        }
    ));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);

    let second = executor
        .execute(&context(), "counting", json!({ "value": 2 }))
        .await
        .expect_err("latched executor must stay closed");
    assert!(matches!(second, CapabilityError::AuditLatched));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_attempts_have_unique_correlated_audit_pairs() {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (writer, state) = ControlledWriter::recording();
    let executor = Arc::new(executor(
        Arc::clone(&count),
        PermissionCascade::new(vec![Arc::new(AllowLayer)]),
        AuditLog::from_durable_writer(Box::new(writer)),
    ));

    let mut tasks = Vec::new();
    for value in 0..16 {
        let executor = Arc::clone(&executor);
        tasks.push(tokio::spawn(async move {
            executor
                .execute(&context(), "counting", json!({ "value": value }))
                .await
        }));
    }
    for task in tasks {
        task.await.expect("join").expect("execution");
    }

    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 16);
    let records = audit_records(&state);
    assert_eq!(records.len(), 32);
    let mut ids = std::collections::BTreeMap::<u64, Vec<String>>::new();
    for record in records {
        ids.entry(record["invocation_id"].as_u64().expect("id"))
            .or_default()
            .push(record["phase"].as_str().expect("phase").to_owned());
        assert!(
            record.get("input").is_none(),
            "raw input must not be logged"
        );
        assert!(
            record.get("output").is_none(),
            "raw output must not be logged"
        );
    }
    assert_eq!(ids.len(), 16);
    for phases in ids.values_mut() {
        phases.sort();
        assert_eq!(phases, &["decision", "result"]);
    }
}

fn audit_records(state: &Arc<Mutex<WriterState>>) -> Vec<Value> {
    let bytes = state.lock().expect("writer state lock").bytes.clone();
    String::from_utf8(bytes)
        .expect("utf8 audit")
        .lines()
        .map(|line| serde_json::from_str(line).expect("json audit record"))
        .collect()
}

// Keep a compile-time reference to the permission vocabulary used by custom
// layers in the shared test module; this also prevents accidental removal of
// the explicit-allow decision that makes the production cascade fail closed.
#[allow(dead_code)]
fn _allow_decision() -> LayerDecision {
    LayerDecision::Allow
}
