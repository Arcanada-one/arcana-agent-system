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
use arcana_core::agent_loop::TerminalReason;
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

fn tool_call(name: &str, input: serde_json::Value) -> String {
    format!(
        "```tool_call\n{}\n```",
        serde_json::json!({ "name": name, "input": input })
    )
}

/// Drive one scripted run inside `root` and return its terminal reason.
async fn drive(root: &Path, audit: &Path, replies: &[&str]) -> TerminalReason {
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
        max_turns: 6,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
    };
    let config = driver_config(&request, &workspace.tools, root);
    workspace
        .session
        .run_task(&request.prompt, config, CancellationToken::new())
        .await
        .reason
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

    assert_eq!(reason, TerminalReason::Completed);
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

    assert_eq!(reason, TerminalReason::PermissionDenied);
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

    assert_eq!(reason, TerminalReason::PermissionDenied);
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

    assert_eq!(reason, TerminalReason::PermissionDenied);
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
async fn an_unregistered_tool_is_refused_at_the_schema_layer() {
    // The tool set is closed: `webfetch` exists in the binary but is not
    // registered for a headless run, and the cascade must say so rather than
    // dispatch it.
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

    assert_eq!(reason, TerminalReason::PermissionDenied);
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
