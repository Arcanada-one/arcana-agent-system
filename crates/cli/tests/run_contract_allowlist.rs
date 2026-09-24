//! A contract-bound run cannot call a tool its contract did not admit — and
//! the refusal is on disk afterwards.
//!
//! The paired-negative discipline of `run_tool_execution.rs` applies: each case
//! judges by the FILE ON DISK, and each has a twin that must leave no file. A
//! denial that only appeared in a counter would be indistinguishable from a
//! model that never tried.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_cli::run::{assemble, driver_config, RunRequest, DENIED_DIR};
use arcana_cli::workspace::WorkspacePolicy;
use arcana_core::agent_loop::RunOutput;
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use arcana_core::contract::{digest_of, verify, ContractBinding, ContractDocument, ContractTools};
use async_trait::async_trait;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// Replays a fixed script of model replies, one per turn. Everything else in
/// the run — cascade, dispatcher, tools, audit log — is production code.
struct ScriptedModel {
    replies: Vec<String>,
    next: AtomicUsize,
}

impl ScriptedModel {
    fn new(replies: &[&str]) -> Self {
        Self {
            replies: replies.iter().map(|r| (*r).to_owned()).collect(),
            next: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ModelConnector for ScriptedModel {
    async fn execute(&self, _request: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let index = self.next.fetch_add(1, Ordering::SeqCst);
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
        serde_json::json!({"name": name, "input": input})
    )
}

fn binding(tools: &[&str]) -> ContractBinding {
    let projection = "Role: reviewer. Deliverable: one review note.";
    let document = ContractDocument {
        digest: digest_of(projection.as_bytes()),
        projection: serde_json::json!(projection),
        kc2_revision: Some("kc2-role-reviewer@r7".to_owned()),
        tools: Some(ContractTools {
            allow: tools.iter().map(|t| (*t).to_owned()).collect(),
        }),
        ..ContractDocument::default()
    };
    verify(&document.digest.clone(), &document).expect("the fixture binds")
}

async fn drive(
    root: &Path,
    audit: &Path,
    contract: Option<ContractBinding>,
    replies: &[&str],
) -> RunOutput {
    let policy = Arc::new(WorkspacePolicy::new(root).unwrap());
    let workspace = assemble(
        root,
        &policy,
        Box::new(ScriptedModel::new(replies)),
        audit.to_path_buf(),
        contract,
    )
    .expect("compose the headless run");
    let request = RunRequest {
        cwd: root.to_path_buf(),
        prompt: "do the thing".to_owned(),
        max_turns: 6,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
        request_timeout: None,
        context_budget: None,
        tool_result_budget: None,
        save_transcript: None,
        contract: None,
    };
    let config = driver_config(&request, &workspace.tools, root);
    workspace
        .session
        .run_task(&request.prompt, config, CancellationToken::new())
        .await
}

const WRITE_PROOF: &str = "echo HELLO > proof.txt";

#[tokio::test]
async fn a_tool_outside_the_contract_is_denied_and_the_refusal_is_on_disk() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();

    let out = drive(
        work.path(),
        audit.path(),
        Some(binding(&["read", "grep"])),
        &[
            &tool_call("bash", serde_json::json!({ "command": WRITE_PROOF })),
            "I cannot use that tool",
        ],
    )
    .await;

    // The file the shell would have made, first: a denial that let the command
    // run anyway would still count as denied everywhere else.
    assert!(
        !work.path().join("proof.txt").exists(),
        "the denied command must not have run"
    );
    assert_eq!(out.tool_calls, 0, "nothing executed");
    assert_eq!(out.tool_calls_denied, 1, "exactly one refusal");

    let denied = work.path().join(DENIED_DIR);
    let records: Vec<_> = std::fs::read_dir(&denied)
        .expect("the denial directory exists")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(records.len(), 1, "one record per refusal");
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(records[0].path()).unwrap()).unwrap();
    assert_eq!(record["tool"], "bash");
    assert_eq!(
        record["layer"], "contract-allowlist",
        "the refusal must be attributed to the contract, not to whatever else \
         the call would have tripped"
    );
    assert!(
        record["reason"].as_str().unwrap().contains("sha256:"),
        "the reason names the contract: {}",
        record["reason"]
    );
}

#[tokio::test]
async fn the_paired_negative_the_same_call_under_a_contract_that_admits_it_runs() {
    // Without this, the test above would pass just as well if `bash` were
    // broken, or if the workspace boundary were refusing everything.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();

    let out = drive(
        work.path(),
        audit.path(),
        Some(binding(&["bash"])),
        &[
            &tool_call("bash", serde_json::json!({ "command": WRITE_PROOF })),
            "wrote proof.txt",
        ],
    )
    .await;

    let contents = std::fs::read_to_string(work.path().join("proof.txt"))
        .expect("an admitted tool really runs");
    assert!(contents.contains("HELLO"), "got {contents:?}");
    assert_eq!(out.tool_calls, 1);
    assert_eq!(out.tool_calls_denied, 0);
    assert!(!work.path().join(DENIED_DIR).exists());
}

#[tokio::test]
async fn an_unbound_run_is_unchanged_by_this_layer() {
    // The layer is additive: `--prompt` runs have no contract, and inserting
    // the layer must not have narrowed them.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();

    let out = drive(
        work.path(),
        audit.path(),
        None,
        &[
            &tool_call("bash", serde_json::json!({ "command": WRITE_PROOF })),
            "wrote proof.txt",
        ],
    )
    .await;

    assert!(work.path().join("proof.txt").exists());
    assert_eq!(out.tool_calls, 1);
}
