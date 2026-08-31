//! Operator abort (SIGINT): what a Ctrl-C mid-turn actually does.
//!
//! Before this, `TerminalReason::AbortedByOperator` was unreachable in
//! production — every caller handed `Driver::new` a `CancellationToken::new()`
//! it kept no handle to — so nothing pinned what a cancellation *means*. These
//! tests fix the three decisions that matter to a paying user:
//!
//! 1. a cancel that lands while the request is on the wire stops the run
//!    before the next billable dispatch and before any tool side effect;
//! 2. an answer that already arrived (and was therefore already charged) is
//!    still delivered, because throwing it away is a second harm, not a mercy;
//! 3. the abort is written to the audit log, so the charge the operator is
//!    about to see on their bill has a local record.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, RunOutput, TerminalReason};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result};

/// A connector that cancels the run *while its own call is in flight*.
///
/// This is the real shape of the bug: the SIGINT does not arrive between
/// turns, it arrives during the dispatch that is already being billed. A
/// pre-cancelled token cannot exercise that path — it never reaches the wire.
struct CancelsMidCall {
    cancel: CancellationToken,
    reply: ConnectorResponse,
    calls: AtomicUsize,
}

#[async_trait]
impl ModelConnector for CancelsMidCall {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.cancel.cancel();
        Ok(self.reply.clone())
    }
}

/// A tool that records whether it was ever asked to do anything.
struct RecordingTool {
    runs: Arc<AtomicUsize>,
}

#[async_trait]
impl Tool for RecordingTool {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "records that it ran"
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let input = invocation.into_input();
        Ok(ToolOutput {
            content: format!("echo:{input}"),
            metadata: None,
        })
    }
}

/// A priced reply, so the abort record has a non-zero figure to carry.
fn priced(result: &str) -> ConnectorResponse {
    let mut reply = response(result, 0.004_121);
    reply.usage = Usage {
        input_tokens: 120,
        output_tokens: 40,
        total_tokens: 160,
        cost_usd: 0.004_121,
    };
    reply
}

/// Every `phase: "run"` record in the audit log, in write order.
fn run_records(dir: &TempDir) -> Vec<Value> {
    let raw = std::fs::read_to_string(dir.path().join("audit.log")).expect("audit log");
    raw.lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit record is JSON"))
        .filter(|record| record.get("phase").and_then(Value::as_str) == Some("run"))
        .collect()
}

async fn drive(
    connector: &dyn ModelConnector,
    dispatcher: ToolDispatcher,
    cancel: CancellationToken,
) -> (RunOutput, TempDir) {
    let (executor, audit_dir) =
        common::test_executor(dispatcher, common::allow_cascade(), HookChain::new());
    let cost = Arc::new(CostTracker::new());
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 10;
    let driver = Driver::new(connector, &executor, cost, cancel, config);
    let out = driver.run("do a small task").await;
    (out, audit_dir)
}

#[tokio::test]
async fn a_cancel_landing_during_the_dispatch_stops_before_the_tool_runs() {
    // The model came back asking for a tool. The operator had already pressed
    // Ctrl-C. Running the tool anyway is the worst outcome available: the abort
    // is the one control that is supposed to stop the agent touching anything.
    let cancel = CancellationToken::new();
    let connector = CancelsMidCall {
        cancel: cancel.clone(),
        reply: priced(&tool_call_result("echo", json!({ "text": "x" }))),
        calls: AtomicUsize::new(0),
    };
    let runs = Arc::new(AtomicUsize::new(0));
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(RecordingTool {
            runs: Arc::clone(&runs),
        }))
        .expect("register");

    let (out, _audit) = drive(&connector, dispatcher, cancel).await;

    assert_eq!(out.reason, TerminalReason::AbortedByOperator);
    assert_eq!(runs.load(Ordering::SeqCst), 0, "the tool must not have run");
    assert_eq!(
        connector.calls.load(Ordering::SeqCst),
        1,
        "exactly one dispatch — the abort must not start another"
    );
    assert_eq!(out.turns, 1, "the dispatch that happened is still counted");
    assert_eq!(
        out.cost.total_cost_usd_micros, 4121,
        "the in-flight request was charged; the run must report what it cost, \
         not zero"
    );
}

#[tokio::test]
async fn an_answer_that_already_arrived_is_delivered_but_the_run_is_still_an_abort() {
    // Two properties at once, and they pull in opposite directions.
    //
    // The answer is already paid for, so discarding it would charge the
    // operator and then withhold what they bought — the reason the abort waits
    // for the reply instead of racing it.
    //
    // The verdict is nonetheless an abort. Reporting `Completed` here would
    // make Ctrl-C inert on the single commonest shape in this product — a task
    // the model answers in one dispatch — leaving no audit record, exit 0, and
    // a wrapper script that cannot tell it was interrupted. Measured against
    // the live connector before this was fixed: `demo --live` interrupted at
    // t=2.0s of a 5.1s turn still exited 0 and wrote nothing.
    let cancel = CancellationToken::new();
    let connector = CancelsMidCall {
        cancel: cancel.clone(),
        reply: priced("the answer you paid for"),
        calls: AtomicUsize::new(0),
    };

    let (out, audit) = drive(&connector, ToolDispatcher::new(), cancel).await;

    assert_eq!(out.reason, TerminalReason::AbortedByOperator);
    assert_eq!(
        out.final_text.as_deref(),
        Some("the answer you paid for"),
        "the paid-for answer must survive the abort"
    );
    assert_eq!(run_records(&audit).len(), 1, "the abort is still recorded");
}

#[tokio::test]
async fn the_abort_is_written_to_the_audit_log_with_what_it_cost() {
    // Issue #105's first complaint: a real, billable model call left no local
    // trace whatsoever. A `phase: "run"` record is that trace.
    let cancel = CancellationToken::new();
    let connector = CancelsMidCall {
        cancel: cancel.clone(),
        reply: priced(&tool_call_result("echo", json!({ "text": "x" }))),
        calls: AtomicUsize::new(0),
    };
    let runs = Arc::new(AtomicUsize::new(0));
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(RecordingTool { runs }))
        .expect("register");

    let (out, audit) = drive(&connector, dispatcher, cancel).await;
    assert_eq!(out.reason, TerminalReason::AbortedByOperator);

    let records = run_records(&audit);
    assert_eq!(records.len(), 1, "exactly one abort record: {records:?}");
    let record = &records[0];
    assert_eq!(record["kind"], "run_aborted");
    assert_eq!(record["fields"]["reason"], "aborted_by_operator");
    assert_eq!(record["fields"]["run_turns"], 1);
    assert_eq!(
        record["fields"]["session_cost_usd_micros"], 4121,
        "the record has to carry the figure, or it cannot answer the only \
         question it exists to answer"
    );
    // The models RECORDED are the ones the policy selected, not the one the
    // reply reported: an abort can happen with no reply at all, and the record
    // has to say what we dispatched either way. Pinned against the run output
    // rather than a literal id, so a policy change cannot silently de-sync the
    // two without failing here.
    assert!(!out.selected_models.is_empty());
    assert_eq!(
        record["fields"]["run_models"],
        serde_json::to_value(&out.selected_models).expect("models encode")
    );
}

#[tokio::test]
async fn a_run_nobody_interrupted_writes_no_abort_record() {
    // Guards the mutation that would make the test above pass for free: an
    // abort record written on every run is not evidence of an abort.
    let connector = CancelsMidCall {
        // Cancels a token the driver is not holding, so the run is untouched.
        cancel: CancellationToken::new(),
        reply: priced("done"),
        calls: AtomicUsize::new(0),
    };

    let (out, audit) = drive(&connector, ToolDispatcher::new(), CancellationToken::new()).await;

    assert_eq!(out.reason, TerminalReason::Completed);
    assert!(
        run_records(&audit).is_empty(),
        "a completed run must leave no abort record"
    );
}

#[tokio::test]
async fn an_abort_before_the_first_dispatch_is_still_recorded() {
    // Ctrl-C in the gap between pressing Enter and the request leaving. Nothing
    // was charged, but "you interrupted and nothing was billed" is itself the
    // answer the operator needs from the log.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let connector = CancelsMidCall {
        cancel: CancellationToken::new(),
        reply: priced("unreached"),
        calls: AtomicUsize::new(0),
    };

    let (out, audit) = drive(&connector, ToolDispatcher::new(), cancel).await;

    assert_eq!(out.reason, TerminalReason::AbortedByOperator);
    assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    let records = run_records(&audit);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["fields"]["run_turns"], 0);
    assert_eq!(records[0]["fields"]["session_cost_usd_micros"], 0);
}

/// A sink that accepts nothing, so the abort record cannot be persisted.
struct DeadWriter;

impl std::io::Write for DeadWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected audit failure"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl arcana_core::hooks::audit::DurableAuditWriter for DeadWriter {
    fn sync_data(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn an_abort_that_could_not_be_recorded_is_not_reported_as_a_clean_abort() {
    // The whole point of the record is that the operator can later prove what
    // they were charged for. Printing "aborted by the operator" over a log that
    // took nothing would be exactly the false-green this product treats as
    // fatal everywhere else it touches the audit sink.
    use arcana_core::execution::CapabilityExecutor;
    use arcana_core::hooks::audit::AuditLog;
    use arcana_core::permission::PermissionCascade;

    let cancel = CancellationToken::new();
    cancel.cancel();
    let connector = CancelsMidCall {
        cancel: CancellationToken::new(),
        reply: priced("unreached"),
        calls: AtomicUsize::new(0),
    };
    let executor = CapabilityExecutor::new(
        ToolDispatcher::new(),
        PermissionCascade::new(vec![]),
        HookChain::new(),
        AuditLog::from_durable_writer(Box::new(DeadWriter)),
    );
    let driver = Driver::new(
        &connector,
        &executor,
        Arc::new(CostTracker::new()),
        cancel,
        DriverConfig::new("scripted"),
    );

    let out = driver.run("do a small task").await;

    assert_eq!(
        out.reason,
        TerminalReason::AuditFatal,
        "a failed abort append must degrade the verdict, not be swallowed"
    );
}

#[tokio::test]
async fn the_recorded_cost_is_the_session_total_and_says_so() {
    // Measured live and nearly shipped mislabelled: an abort on the SECOND turn
    // of a session recorded 20 micro-USD beside `turns: 1`, when that turn had
    // cost 11. The `CostTracker` belongs to the session and is shared across
    // every run in it; the turn count belongs to the run. Two scopes, so two
    // names — a reader who assumes the figure is the aborted turn's is reading
    // a number that was never that.
    let (executor, audit) = common::test_executor(
        ToolDispatcher::new(),
        common::allow_cascade(),
        HookChain::new(),
    );
    let cost = Arc::new(CostTracker::new());

    let first = CancelsMidCall {
        cancel: CancellationToken::new(),
        reply: priced("answer one"),
        calls: AtomicUsize::new(0),
    };
    let out = Driver::new(
        &first,
        &executor,
        Arc::clone(&cost),
        CancellationToken::new(),
        DriverConfig::new("scripted"),
    )
    .run("first task")
    .await;
    assert_eq!(out.reason, TerminalReason::Completed);
    assert!(run_records(&audit).is_empty());

    let cancel = CancellationToken::new();
    let second = CancelsMidCall {
        cancel: cancel.clone(),
        reply: priced("answer two"),
        calls: AtomicUsize::new(0),
    };
    let out = Driver::new(
        &second,
        &executor,
        Arc::clone(&cost),
        cancel,
        DriverConfig::new("scripted"),
    )
    .run("second task")
    .await;
    assert_eq!(out.reason, TerminalReason::AbortedByOperator);

    let records = run_records(&audit);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["fields"]["run_turns"], 1,
        "one connector attempt in the aborted RUN"
    );
    assert_eq!(
        records[0]["fields"]["session_cost_usd_micros"], 8242,
        "both turns of the SESSION, not just the aborted one"
    );
}
