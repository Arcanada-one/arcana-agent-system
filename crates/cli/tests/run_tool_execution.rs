//! `arcana run` really executes its tools, and really refuses to leave the
//! working directory.
//!
//! The defect this covers was not a broken tool and not a broken cascade: a
//! live session was asked to use its bash tool to redirect `echo` into
//! `proof.txt`, the model answered with a fenced shell block, `proof.txt` was
//! never created, and the process exited `0`. Nothing in the loop had told the
//! model that the driver recognises exactly one tool-call encoding, and the
//! session had no tools registered beyond a demo echo fixture.
//!
//! These tests therefore judge by the FILE ON DISK, never by printed text, and
//! every one of them has a paired negative that must leave no file — a check
//! that cannot go red is not a check.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_cli::run::{assemble, driver_config, RunRequest};
use arcana_cli::workspace::WorkspacePolicy;
use arcana_core::agent_loop::{RunOutput, TerminalReason};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use async_trait::async_trait;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// A connector that replays a fixed script of model replies, one per turn.
///
/// The model is the only thing faked here: the driver, the permission
/// cascade, the tool dispatcher, the audit log and the tools themselves are
/// the production ones, so a test that sees a file appear has seen the real
/// path create it.
struct ScriptedModel {
    replies: Vec<String>,
    turn: AtomicUsize,
}

impl ScriptedModel {
    fn new(replies: &[&str]) -> Self {
        Self {
            replies: replies.iter().map(|reply| (*reply).to_owned()).collect(),
            turn: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ModelConnector for ScriptedModel {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let index = self.turn.fetch_add(1, Ordering::SeqCst);
        let result = self
            .replies
            .get(index)
            .cloned()
            .unwrap_or_else(|| "out of script".to_owned());
        Ok(ConnectorResponse {
            id: format!("scripted-{index}"),
            connector: "scripted".to_owned(),
            model: "scripted-model".to_owned(),
            result,
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
                total_tokens: 2,
                cost_usd: 0.0,
            },
            latency_ms: 0,
            status: "success".to_owned(),
            error: None,
            first_dispatch_observation: None,
        })
    }
}

/// A [`ScriptedModel`] that also keeps every prompt it was handed.
///
/// The fold-back is only observable from outside the driver as text in the
/// NEXT prompt, so a test that asks "was the model actually told?" needs the
/// prompts, not just the terminal reason.
#[derive(Clone)]
struct RecordingModel {
    replies: Vec<String>,
    turn: Arc<AtomicUsize>,
    prompts: Arc<std::sync::Mutex<Vec<String>>>,
}

impl RecordingModel {
    fn new(replies: &[&str]) -> Self {
        Self {
            replies: replies.iter().map(|reply| (*reply).to_owned()).collect(),
            turn: Arc::new(AtomicUsize::new(0)),
            prompts: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn prompts(&self) -> Vec<String> {
        self.prompts.lock().unwrap().clone()
    }
}

#[async_trait]
impl ModelConnector for RecordingModel {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.prompts.lock().unwrap().push(req.prompt.clone());
        let index = self.turn.fetch_add(1, Ordering::SeqCst);
        let result = self
            .replies
            .get(index)
            .cloned()
            .unwrap_or_else(|| "out of script".to_owned());
        Ok(ConnectorResponse {
            id: format!("recording-{index}"),
            connector: "recording".to_owned(),
            model: "scripted-model".to_owned(),
            result,
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
                total_tokens: 2,
                cost_usd: 0.0,
            },
            latency_ms: 0,
            status: "success".to_owned(),
            error: None,
            first_dispatch_observation: None,
        })
    }
}

fn tool_call(name: &str, input: serde_json::Value) -> String {
    format!(
        "```tool_call\n{}\n```",
        serde_json::json!({ "name": name, "input": input })
    )
}

/// Drive one scripted run inside `root` and return its terminal reason.
async fn drive(root: &Path, audit: &Path, replies: &[&str]) -> TerminalReason {
    drive_out(root, audit, replies).await.reason
}

/// Drive one scripted run inside `root` and return the whole outcome.
///
/// The tool-call count is part of the verdict now, so a test that judges
/// "did anything actually run?" needs more than the terminal reason.
async fn drive_out(root: &Path, audit: &Path, replies: &[&str]) -> RunOutput {
    drive_out_turns(root, audit, replies, 6).await
}

/// As [`drive_out`], with the connector-attempt cap named explicitly.
async fn drive_out_turns(root: &Path, audit: &Path, replies: &[&str], max_turns: u32) -> RunOutput {
    let policy = Arc::new(WorkspacePolicy::new(root).unwrap());
    let workspace = assemble(
        root,
        &policy,
        Box::new(ScriptedModel::new(replies)),
        audit.to_path_buf(),
    )
    .expect("compose the headless run");
    let request = RunRequest {
        cwd: root.to_path_buf(),
        prompt: "do the thing".to_owned(),
        max_turns,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
        // The scripted connector in this test is not the HTTP client, so the
        // budget is inert here; stated rather than defaulted so a future
        // change to the default cannot silently change this fixture.
        request_timeout: None,
        // Default budget: these fixtures are about tool execution, not about
        // the transcript ceiling.
        context_budget: None,
        tool_result_budget: None,
        save_transcript: None,
    };
    let config = driver_config(&request, &workspace.tools, root);
    workspace
        .session
        .run_task(&request.prompt, config, CancellationToken::new())
        .await
}

#[tokio::test]
async fn the_bash_tool_really_runs_and_leaves_the_file_on_disk() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let reason = drive(
        work.path(),
        audit.path(),
        &[
            &tool_call(
                "bash",
                serde_json::json!({ "command": "echo HELLO_FROM_ARCANA > proof.txt" }),
            ),
            "wrote proof.txt",
        ],
    )
    .await;

    // The file first, deliberately: the verdict is what the run SAYS, and the
    // defect this covers was a run that said the right thing and did nothing.
    let proof = work.path().join("proof.txt");
    let contents = std::fs::read_to_string(&proof).unwrap_or_else(|err| {
        panic!(
            "proof.txt missing at {} ({reason:?}): {err}",
            proof.display()
        )
    });
    assert_eq!(contents.trim(), "HELLO_FROM_ARCANA");
    assert_eq!(reason, TerminalReason::Completed, "run did not complete");
}

#[tokio::test]
async fn a_fenced_bash_block_is_prose_and_creates_nothing() {
    // The red half of the test above, and the defect verbatim: the same
    // command, in the encoding the driver does NOT recognise. It must be read
    // as a final answer and leave the directory untouched.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let reason = drive(
        work.path(),
        audit.path(),
        &["```bash\necho HELLO_FROM_ARCANA > proof.txt\n```"],
    )
    .await;

    // Prose, so nothing ran — and a run in which nothing ran is not a
    // completed run, however confidently the prose is phrased.
    assert_eq!(format!("{reason:?}"), "NoAction", "{reason:?}");
    assert!(!reason.is_success(), "{reason:?}");
    assert!(
        !work.path().join("proof.txt").exists(),
        "a ```bash block must not execute"
    );
}

#[tokio::test]
async fn the_write_tool_really_writes_inside_the_workspace() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let reason = drive(
        work.path(),
        audit.path(),
        &[
            &tool_call(
                "write",
                serde_json::json!({ "path": "notes/out.txt", "content": "INSIDE", "create_parent_dirs": true }),
            ),
            "done",
        ],
    )
    .await;

    assert_eq!(reason, TerminalReason::Completed);
    let written = std::fs::read_to_string(work.path().join("notes/out.txt")).unwrap();
    assert_eq!(written, "INSIDE");
}

#[tokio::test]
async fn writing_outside_the_workspace_is_refused_and_writes_nothing() {
    let work = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let target = outside.path().join("outside-proof.txt");

    let reason = drive(
        work.path(),
        audit.path(),
        &[&tool_call(
            "write",
            serde_json::json!({ "path": target.to_string_lossy(), "content": "ESCAPED" }),
        )],
    )
    .await;

    // The refusal is now handed BACK to the model (A2-204) instead of ending
    // the run, so the verdict is no longer `PermissionDenied`: the scripted
    // model has nothing more to say, never executes anything, and the run ends
    // on `NoAction`. What this test is for is the line below it — the escape
    // did not happen — and that is unchanged.
    assert_eq!(reason, TerminalReason::NoAction, "{reason:?}");
    assert!(
        !target.exists(),
        "the policy let a write escape the workspace"
    );
}

#[tokio::test]
async fn a_relative_path_that_climbs_out_of_the_workspace_is_refused() {
    // `..` is the interesting case: the string is relative and looks harmless,
    // and only canonicalization shows where it lands.
    let work = TempDir::new().unwrap();
    let nested = work.path().join("inner");
    std::fs::create_dir(&nested).unwrap();
    let audit = TempDir::new().unwrap();

    let reason = drive(
        &nested,
        audit.path(),
        &[&tool_call(
            "write",
            serde_json::json!({ "path": "../escaped.txt", "content": "ESCAPED" }),
        )],
    )
    .await;

    // The refusal is now handed BACK to the model (A2-204) instead of ending
    // the run, so the verdict is no longer `PermissionDenied`: the scripted
    // model has nothing more to say, never executes anything, and the run ends
    // on `NoAction`. What this test is for is the line below it — the escape
    // did not happen — and that is unchanged.
    assert_eq!(reason, TerminalReason::NoAction, "{reason:?}");
    assert!(!work.path().join("escaped.txt").exists());
}

#[tokio::test]
async fn a_shell_command_writing_outside_the_workspace_is_refused() {
    let work = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let target = outside.path().join("outside-proof");

    let reason = drive(
        work.path(),
        audit.path(),
        &[&tool_call(
            "bash",
            serde_json::json!({ "command": format!("echo ESCAPED > {}", target.display()) }),
        )],
    )
    .await;

    // The refusal is now handed BACK to the model (A2-204) instead of ending
    // the run, so the verdict is no longer `PermissionDenied`: the scripted
    // model has nothing more to say, never executes anything, and the run ends
    // on `NoAction`. What this test is for is the line below it — the escape
    // did not happen — and that is unchanged.
    assert_eq!(reason, TerminalReason::NoAction, "{reason:?}");
    assert!(!target.exists(), "the policy let a shell write escape");
}

#[tokio::test]
async fn a_destructive_command_is_refused_before_the_shell_is_spawned() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let victim = work.path().join("keep/me.txt");
    std::fs::create_dir(work.path().join("keep")).unwrap();
    std::fs::write(&victim, "still here").unwrap();

    let reason = drive(
        work.path(),
        audit.path(),
        &[&tool_call(
            "bash",
            serde_json::json!({ "command": "rm -rf keep" }),
        )],
    )
    .await;

    assert_eq!(reason, TerminalReason::PermissionDenied);
    assert!(victim.exists(), "recursive force delete was not refused");
}

#[tokio::test]
async fn an_unregistered_tool_is_refused_and_never_dispatched() {
    // The tool set is closed: `webfetch` exists in the binary but is not
    // registered for a headless run, and the cascade must say so rather than
    // dispatch it. Since A2-204 that refusal is handed back to the model, so
    // the verdict is `NoAction` — the scripted model never names a real tool —
    // rather than `PermissionDenied`. Nothing was dispatched either way, which
    // is what the test is for.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let reason = drive(
        work.path(),
        audit.path(),
        &[&tool_call(
            "webfetch",
            serde_json::json!({ "url": "https://example.com" }),
        )],
    )
    .await;

    assert_eq!(reason, TerminalReason::NoAction, "{reason:?}");
    assert!(!reason.is_success(), "{reason:?}");
}

#[tokio::test]
async fn every_tool_call_is_written_to_the_audit_log() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let _ = drive(
        work.path(),
        audit.path(),
        &[
            &tool_call("bash", serde_json::json!({ "command": "echo audited" })),
            "done",
        ],
    )
    .await;

    let log = std::fs::read_to_string(audit.path().join("audit.log")).unwrap();
    assert!(log.contains("\"tool\":\"bash\""), "audit log: {log}");
}

// ---------------------------------------------------------------------------
// A claimed completion with no evidence (A2-003b)
//
// The transcript below is the live failure verbatim: asked in plain language
// to create a file, the model answered in ONE turn, called nothing, and
// `arcana run` printed `{"completed":true,"reason":"Completed","turns":1}` and
// exited 0. Judging that run by its own sentence is exactly the lie the whole
// command exists to prevent.

/// The model's exact words in the failing live run.
const CLAIMED_WITHOUT_DOING: &str = "The file has been created successfully.";

#[tokio::test]
async fn a_claim_of_success_with_zero_tool_calls_is_not_a_completed_run() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let out = drive_out(work.path(), audit.path(), &[CLAIMED_WITHOUT_DOING]).await;

    assert!(
        !work.path().join("verified.txt").exists(),
        "the transcript created no file — that is the premise of this test"
    );
    assert!(
        !out.reason.is_success(),
        "a run that executed nothing reported success: {:?}",
        out.reason
    );
    assert_eq!(
        format!("{:?}", out.reason),
        "NoAction",
        "the verdict must name what went wrong, not be a generic failure"
    );
    assert_eq!(out.tool_calls, 0, "nothing was executed");
}

#[tokio::test]
async fn the_loop_asks_once_for_action_and_a_model_that_then_acts_completes() {
    // The `Better, in addition` half of the card: the first answer is the same
    // empty claim, and the run still succeeds because the loop told the model
    // that nothing had been executed and asked it to act.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let out = drive_out(
        work.path(),
        audit.path(),
        &[
            CLAIMED_WITHOUT_DOING,
            &tool_call(
                "bash",
                serde_json::json!({ "command": "echo TOKEN > verified.txt" }),
            ),
            "wrote verified.txt",
        ],
    )
    .await;

    let written = std::fs::read_to_string(work.path().join("verified.txt"))
        .unwrap_or_else(|err| panic!("verified.txt missing ({:?}): {err}", out.reason));
    assert_eq!(written.trim(), "TOKEN");
    assert_eq!(out.reason, TerminalReason::Completed);
    assert_eq!(out.tool_calls, 1, "exactly one tool call was executed");
    // Pins the arithmetic a live run is read by: one dispatch per tool call,
    // one for the final answer, and one more only when the nudge fired. So
    // `turns == tool_calls + 2` in a live table means the model had to be told
    // that nothing was executed, and `+ 1` means it acted unprompted.
    assert_eq!(out.turns, out.tool_calls + 2, "the nudge cost one dispatch");
}

#[tokio::test]
async fn the_nudge_is_spent_once_and_does_not_loop_forever() {
    // Two empty claims in a row must end the run, not buy a third dispatch.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let out = drive_out(
        work.path(),
        audit.path(),
        &[CLAIMED_WITHOUT_DOING, CLAIMED_WITHOUT_DOING],
    )
    .await;

    assert_eq!(format!("{:?}", out.reason), "NoAction");
    assert_eq!(out.turns, 2, "the nudge costs exactly one extra dispatch");
}

#[tokio::test]
async fn a_refused_tool_call_does_not_count_as_an_executed_one() {
    // `tool_calls` is evidence of work done, so it counts dispatches the
    // executor carried out — not ones the cascade refused.
    let work = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let out = drive_out(
        work.path(),
        audit.path(),
        &[&tool_call(
            "write",
            serde_json::json!({
                "path": outside.path().join("escaped.txt").to_string_lossy(),
                "content": "ESCAPED",
            }),
        )],
    )
    .await;

    // Since A2-204 the boundary refusal is handed back to the model, so the
    // scripted model runs out of script and the verdict is `NoAction`. The
    // point of the test is the count below, and it is unchanged: a refused
    // call is not evidence of work.
    assert_eq!(out.reason, TerminalReason::NoAction, "{:?}", out.reason);
    assert_eq!(out.tool_calls, 0, "a refused call executed nothing");
}

// ---------------------------------------------------------------------------
// A malformed tool call ends the whole run (A2-204)
//
// Measured by the control session on 2026-09-23, `arcana` 0.2.0 at ARAS
// 14a8fc95, card A2-201, model `deepseek-flash`: on turn 1 the model called
// `bash`, the audit log recorded
//   {"decision":"Denied","layer":"schema","tool":"bash",...}
// and the run ended `PermissionDenied`, `tool_calls: 0`, `rc 1`. The `schema`
// layer means only that the ARGUMENTS did not match the tool's published JSON
// schema — and the model was never told which constraint it had violated, so
// it had no way to correct itself. One typo, and the whole task was lost.
//
// The exact denied input IS recoverable, and it is JSON `null`. The audit log
// stores `blake3(serde_json::to_vec(input))[..16]`; `blake3("null")` is
// `03f88b99c3d8073b`, the hash on record. Confirmed live on 2026-09-23: the
// same model on a DIFFERENT task produced the same hash again, because the
// input never depended on the task.
//
// `null` gets there through `interpret`/`parse_tool_call`, which reads
// `{"name": ..., "input": ...}` and does
//     let input = value.get("input").cloned().unwrap_or(Value::Null);
// so a model that puts its arguments under `arguments`, `parameters` or
// `args` — a common convention, and not ours — has them silently dropped,
// dispatches `bash` with `null`, and fails `"type": "object"`.
//
// That silent default was a second defect, deliberately left to the tool-call
// convention rather than fixed in the permission cascade. A2-212 fixed it
// there: `arguments`, `parameters` and `args` are now read as the arguments
// they are, so this block no longer becomes a `null` dispatch at all. The
// recovery A2-204 built is still what catches a call the schema really does
// refuse — `schema_violating_bash` below is such a call, and the tests either
// side of this comment are its coverage.

/// The failure verbatim: a tool-call block naming `bash` whose arguments are
/// under `arguments` rather than `input`.
///
/// This is the exact shape behind audit hash `03f88b99c3d8073b` — the hash of
/// the `null` the driver used to dispatch instead — not an analogue of it.
fn tool_call_with_arguments_key(name: &str, input: serde_json::Value) -> String {
    format!(
        "```tool_call\n{}\n```",
        serde_json::json!({ "name": name, "arguments": input })
    )
}

/// A `bash` call the tool's own schema refuses: `additionalProperties: false`,
/// and `timeout` is not `timeout_seconds`. A plausible model mistake, not a
/// contrived one.
fn schema_violating_bash(command: &str) -> String {
    tool_call(
        "bash",
        serde_json::json!({ "command": command, "timeout": 30 }),
    )
}

#[tokio::test]
async fn a_schema_rejected_call_does_not_end_the_run_and_the_model_can_correct_it() {
    // The whole card in one test: turn 1 is the malformed call that used to be
    // fatal, turn 2 is the same work spelled correctly. The FILE is the
    // verdict — the run must not merely survive, it must do the job.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let out = drive_out(
        work.path(),
        audit.path(),
        &[
            &schema_violating_bash("echo RECOVERED > proof.txt"),
            &tool_call(
                "bash",
                serde_json::json!({ "command": "echo RECOVERED > proof.txt" }),
            ),
            "wrote proof.txt",
        ],
    )
    .await;

    let written = std::fs::read_to_string(work.path().join("proof.txt"))
        .unwrap_or_else(|err| panic!("proof.txt missing ({:?}): {err}", out.reason));
    assert_eq!(written.trim(), "RECOVERED");
    assert_eq!(out.reason, TerminalReason::Completed, "{:?}", out.reason);
    assert_eq!(
        out.tool_calls, 1,
        "the rejected call executed nothing, so exactly one tool call ran"
    );
}

#[tokio::test]
async fn the_rejected_call_is_told_to_the_model_and_names_the_violated_constraint() {
    // A denial the model cannot read is the defect itself: the run continuing
    // is worthless if the next call is the same malformed one. The connector
    // records the prompt it was handed on the turn AFTER the rejection, which
    // is the only place the fold-back can be observed from outside.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let policy = Arc::new(WorkspacePolicy::new(work.path()).unwrap());
    let model = RecordingModel::new(&[&schema_violating_bash("echo HI > proof.txt"), "gave up"]);
    let workspace = assemble(
        work.path(),
        &policy,
        Box::new(model.clone()),
        audit.path().to_path_buf(),
    )
    .expect("compose the headless run");
    let request = RunRequest {
        cwd: work.path().to_path_buf(),
        prompt: "do the thing".to_owned(),
        max_turns: 6,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
        // Inert against a scripted connector; stated so a change to the
        // client default cannot silently change this fixture.
        request_timeout: None,
        // Default budget: these fixtures are about tool execution, not about
        // the transcript ceiling.
        context_budget: None,
        tool_result_budget: None,
        save_transcript: None,
    };
    let config = driver_config(&request, &workspace.tools, work.path());
    let _ = workspace
        .session
        .run_task(&request.prompt, config, CancellationToken::new())
        .await;

    let prompts = model.prompts();
    assert!(
        prompts.len() >= 2,
        "the run stopped at the denial: {prompts:?}"
    );
    let second = &prompts[1];
    assert!(
        second.contains("REJECTED at the schema layer"),
        "the model was not told the call was rejected: {second}"
    );
    assert!(
        second.contains("NOT executed"),
        "the model was not told nothing ran: {second}"
    );
    // The violated constraint itself, carried through from the JSON schema.
    assert!(
        second.contains("timeout"),
        "the reason does not name the offending property: {second}"
    );
}

#[tokio::test]
async fn re_sending_a_refused_call_unchanged_ends_the_run() {
    // The bound on the fold-back, A2-225 shape. Without one, a model that
    // cannot write a valid call spends `max_turns` dispatches of the
    // operator's money proving it; with the old flat cap of three consecutive
    // refusals, a model making three *different* correctable mistakes lost a
    // run that was going fine. The repeat is the honest signal: the model was
    // told what was wrong and sent the same bytes anyway.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let bad = schema_violating_bash("echo NOPE > proof.txt");
    let out = drive_out(
        work.path(),
        audit.path(),
        &[&bad, &bad, &bad, &bad, &bad, &bad],
    )
    .await;

    assert_eq!(out.reason, TerminalReason::PermissionDenied);
    assert_eq!(out.tool_calls, 0, "nothing was ever executed");
    assert_eq!(
        out.turns, 2,
        "the second identical call ends it, not the third"
    );
    assert!(!work.path().join("proof.txt").exists());
    let detail = out
        .terminal_detail
        .as_deref()
        .expect("the run must name what refused it");
    assert!(detail.contains("schema"), "{detail}");
    assert!(detail.contains("bash"), "{detail}");
    assert!(
        detail.contains("timeout"),
        "the validation error must be carried, not summarised away: {detail}"
    );
}

#[tokio::test]
async fn three_different_correctable_mistakes_do_not_end_the_run() {
    // The regression the old cap was: pilot A2-204c4 had done twenty executed
    // tool calls when three refusals landed in a row and killed it. Three
    // distinct malformed calls, then the work spelled correctly — the FILE is
    // the verdict.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let out = drive_out_turns(
        work.path(),
        audit.path(),
        &[
            &schema_violating_bash("echo one"),
            &schema_violating_bash("echo two"),
            &schema_violating_bash("echo three"),
            &tool_call("bash", serde_json::json!({ "command": "echo OK > ok.txt" })),
            "done",
        ],
        8,
    )
    .await;

    assert_eq!(out.reason, TerminalReason::Completed, "{:?}", out.reason);
    assert_eq!(out.tool_calls, 1, "the corrected call ran");
    assert_eq!(
        std::fs::read_to_string(work.path().join("ok.txt"))
            .unwrap()
            .trim(),
        "OK"
    );
}

#[tokio::test]
async fn a_tool_call_that_runs_clears_the_rejection_streak() {
    // The memory of refused calls is CONSECUTIVE. A long, mostly-healthy run
    // that makes the same typo three times, with real work in between, must
    // not die on the second occurrence.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let bad = schema_violating_bash("echo NOPE > nope.txt");
    let good = tool_call(
        "bash",
        serde_json::json!({ "command": "echo OK >> ok.txt" }),
    );
    // Seven dispatches: three rejections of the SAME call, three executed
    // calls, one answer. Each executed call clears the memory, so no refusal
    // is ever a repeat; under a memory that outlived work, the third `bad`
    // would end the run.
    let out = drive_out_turns(
        work.path(),
        audit.path(),
        &[&bad, &good, &bad, &good, &bad, &good, "done"],
        8,
    )
    .await;

    assert_eq!(out.reason, TerminalReason::Completed, "{:?}", out.reason);
    assert_eq!(out.tool_calls, 3, "every well-formed call ran");
    let written = std::fs::read_to_string(work.path().join("ok.txt")).unwrap();
    assert_eq!(written.lines().count(), 3);
    assert!(!work.path().join("nope.txt").exists());
}

#[tokio::test]
async fn a_destructive_command_denial_stays_terminal() {
    // The security half of the split. `rm -rf` is refused by the closed
    // destructive-command floor, and that refusal must NOT be handed back:
    // telling a model that wants the effect which word is on the list invites
    // a hunt for one that is not. The run ends, as it did before this card.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let victim = work.path().join("keep/me.txt");
    std::fs::create_dir(work.path().join("keep")).unwrap();
    std::fs::write(&victim, "still here").unwrap();

    let out = drive_out(
        work.path(),
        audit.path(),
        &[
            &tool_call("bash", serde_json::json!({ "command": "rm -rf keep" })),
            &tool_call(
                "bash",
                serde_json::json!({ "command": "echo AFTER > after.txt" }),
            ),
            "done",
        ],
    )
    .await;

    assert_eq!(out.reason, TerminalReason::PermissionDenied);
    assert_eq!(out.tool_calls, 0);
    assert!(victim.exists(), "recursive force delete was not refused");
    assert!(
        !work.path().join("after.txt").exists(),
        "the run continued past a destructive-command refusal"
    );
}

#[tokio::test]
async fn the_destructive_floor_reason_never_reaches_the_model() {
    // The disclosure half, asserted directly rather than inferred from the
    // terminal reason: the refused word must not appear in any prompt.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let policy = Arc::new(WorkspacePolicy::new(work.path()).unwrap());
    let model = RecordingModel::new(&[
        &tool_call("bash", serde_json::json!({ "command": "sudo id" })),
        "gave up",
    ]);
    let workspace = assemble(
        work.path(),
        &policy,
        Box::new(model.clone()),
        audit.path().to_path_buf(),
    )
    .expect("compose the headless run");
    let request = RunRequest {
        cwd: work.path().to_path_buf(),
        prompt: "do the thing".to_owned(),
        max_turns: 6,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
        // Inert against a scripted connector; stated so a change to the
        // client default cannot silently change this fixture.
        request_timeout: None,
        // Default budget: these fixtures are about tool execution, not about
        // the transcript ceiling.
        context_budget: None,
        tool_result_budget: None,
        save_transcript: None,
    };
    let config = driver_config(&request, &workspace.tools, work.path());
    let out = workspace
        .session
        .run_task(&request.prompt, config, CancellationToken::new())
        .await;

    assert_eq!(out.reason, TerminalReason::PermissionDenied);
    assert_eq!(
        model.prompts().len(),
        1,
        "the run bought a second dispatch after a floor refusal"
    );
    for prompt in model.prompts() {
        assert!(
            !prompt.contains("privilege escalation"),
            "the floor's reason was disclosed to the model: {prompt}"
        );
    }
}

#[tokio::test]
async fn a_write_outside_the_workspace_is_handed_back_and_the_model_can_stay_inside() {
    // `workspace_boundary` is the third folded-back layer. "that path is
    // outside the working directory" names a directory the model was given as
    // its cwd, and the recovery — work inside — is the behaviour we want.
    let work = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let target = outside.path().join("outside-proof.txt");

    let out = drive_out(
        work.path(),
        audit.path(),
        &[
            &tool_call(
                "write",
                serde_json::json!({ "path": target.to_string_lossy(), "content": "ESCAPED" }),
            ),
            &tool_call(
                "write",
                serde_json::json!({ "path": "inside.txt", "content": "STAYED" }),
            ),
            "wrote inside.txt",
        ],
    )
    .await;

    assert!(
        !target.exists(),
        "the policy let a write escape the workspace"
    );
    assert_eq!(out.reason, TerminalReason::Completed, "{:?}", out.reason);
    assert_eq!(out.tool_calls, 1);
    assert_eq!(
        std::fs::read_to_string(work.path().join("inside.txt")).unwrap(),
        "STAYED"
    );
}

#[tokio::test]
async fn an_unknown_tool_name_is_handed_back_and_the_model_can_pick_a_real_one() {
    // The `registry` layer. Same disclosure argument as `schema`: the tool
    // list is already in the model's prompt, so naming the mistake tells it
    // nothing it did not have.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let out = drive_out(
        work.path(),
        audit.path(),
        &[
            &tool_call(
                "webfetch",
                serde_json::json!({ "url": "https://example.com" }),
            ),
            &tool_call(
                "bash",
                serde_json::json!({ "command": "echo REAL > proof.txt" }),
            ),
            "done",
        ],
    )
    .await;

    assert_eq!(out.reason, TerminalReason::Completed, "{:?}", out.reason);
    assert_eq!(out.tool_calls, 1);
    assert_eq!(
        std::fs::read_to_string(work.path().join("proof.txt"))
            .unwrap()
            .trim(),
        "REAL"
    );
}

#[tokio::test]
async fn a_rejected_call_is_still_recorded_as_denied_in_the_audit_log() {
    // The run recovering must not cost the operator the record of what was
    // refused. Law 5: the refusal stays auditable whether or not it was fatal.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let _ = drive_out(
        work.path(),
        audit.path(),
        &[
            &schema_violating_bash("echo HI > proof.txt"),
            &tool_call(
                "bash",
                serde_json::json!({ "command": "echo HI > proof.txt" }),
            ),
            "done",
        ],
    )
    .await;

    let log = std::fs::read_to_string(audit.path().join("audit.log")).unwrap();
    assert!(
        log.contains(r#""decision":"Denied""#) && log.contains(r#""layer":"schema""#),
        "the folded-back denial left no audit record: {log}"
    );
    assert!(log.contains(r#""outcome":"denied""#), "audit log: {log}");
}

#[tokio::test]
async fn the_exact_live_failure_is_reproduced_and_the_run_survives_it() {
    // Audit hash `03f88b99c3d8073b` is `blake3("null")`: the input the driver
    // dispatched for a block whose arguments it never read. A2-204 made that
    // denial survivable — the model was told, and could correct itself on the
    // next turn. A2-212 removes the denial: `arguments` IS the arguments, so
    // the first block does the work and there is nothing to recover from.
    //
    // The test keeps its name and its single scripted block on purpose. It is
    // the live failure, and the assertion that used to say "the run recovered"
    // now says "the run never had to".
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let out = drive_out(
        work.path(),
        audit.path(),
        &[
            &tool_call_with_arguments_key(
                "bash",
                serde_json::json!({ "command": "echo LIVE > proof.txt" }),
            ),
            "wrote proof.txt",
        ],
    )
    .await;

    assert_eq!(
        std::fs::read_to_string(work.path().join("proof.txt"))
            .unwrap_or_else(|err| panic!("proof.txt missing ({:?}): {err}", out.reason))
            .trim(),
        "LIVE"
    );
    assert_eq!(out.reason, TerminalReason::Completed, "{:?}", out.reason);
    assert_eq!(
        out.tool_calls, 1,
        "the arguments the model sent must reach the tool on the FIRST turn: {:?}",
        out.reason
    );

    // The `null` dispatch is gone, not merely recovered from: the hash that
    // identified the live failure never appears, and nothing was denied.
    let log = std::fs::read_to_string(audit.path().join("audit.log")).unwrap();
    assert!(
        !log.contains(r#""input_hash":"03f88b99c3d8073b""#),
        "`arguments` was still dropped and `null` dispatched: {log}"
    );
    assert!(
        !log.contains(r#""decision":"Denied""#),
        "a call carrying its arguments must not be denied: {log}"
    );
}
