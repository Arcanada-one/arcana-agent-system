//! Every dispatch in one run uses the model that was resolved for it — and the
//! receipt says where that model came from.
//!
//! The resolution ORDER is tested in `model_choice.rs`, against the real binary
//! with isolated XDG homes. What that file cannot show is what the loop then
//! does with the answer, because it never dispatches. This one does: a scripted
//! connector stands in for the model, and every other part of the run —
//! dispatcher, policy, cascade, tools — is production code. `RunOutput
//! .selected_models` mirrors each `ExecuteRequest.model` in call order, so
//! "every dispatch used it" is a property of measured output rather than of the
//! configuration that went in.
//!
//! The turns are deliberately of DIFFERENT task types. The tiered policy routes
//! a code turn and a summarize turn to two different models, so a run that
//! merely set `DriverConfig.model` — the policy's `Default` arm — would still
//! dispatch the code turn elsewhere, and a single-turn test would never see it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_cli::models::{ModelSource, ResolvedModel};
use arcana_cli::run::{assemble, driver_config, RunRequest};
use arcana_cli::workspace::WorkspacePolicy;
use arcana_core::agent_loop::RunOutput;
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use arcana_core::contract::{digest_of, verify, ContractBinding, ContractDocument, ContractTools};
use async_trait::async_trait;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// Records the model of every request it is handed, and replays a fixed script.
///
/// The recording is the point: `selected_models` is the driver's own account of
/// what it chose, and a connector that also saw those ids is a second witness
/// to the same fact from the far side of the seam.
struct RecordingModel {
    replies: Vec<String>,
    next: AtomicUsize,
    seen: std::sync::Mutex<Vec<Option<String>>>,
}

impl RecordingModel {
    fn new(replies: &[&str]) -> Self {
        Self {
            replies: replies.iter().map(|reply| (*reply).to_owned()).collect(),
            next: AtomicUsize::new(0),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }
}

/// A handle the test keeps while the session owns the connector.
///
/// `assemble` takes ownership of a boxed connector, and the assertion needs to
/// read what that connector saw afterwards — so the shared half is a local
/// newtype that delegates, rather than a second copy of the recorder.
struct Shared(Arc<RecordingModel>);

#[async_trait]
impl ModelConnector for Shared {
    async fn execute(&self, request: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.0.execute(request).await
    }
}

#[async_trait]
impl ModelConnector for RecordingModel {
    async fn execute(&self, request: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.seen.lock().unwrap().push(request.model.clone());
        let model = request.model.unwrap_or_default();
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        let result = self
            .replies
            .get(index)
            .cloned()
            .unwrap_or_else(|| "done".to_owned());
        Ok(ConnectorResponse {
            id: format!("recorded-{index}"),
            connector: "recording".to_owned(),
            model,
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

/// A two-turn script that crosses the tier boundary.
///
/// Turn 1 is classified `Code` (the task text says `rust`/`implement`); turn 2
/// follows a tool result and is classified `Summarize`. Under the tiered policy
/// those are `grok-3-latest` and `deepseek-v4-flash` — two different ids, which
/// is exactly what a pinned run must NOT produce.
const TASK: &str = "implement a note in rust and write it to notes.txt";

async fn drive(
    root: &Path,
    audit: &Path,
    model: Option<String>,
) -> (RunOutput, Vec<Option<String>>) {
    let policy = Arc::new(WorkspacePolicy::new(root).unwrap());
    let connector = Arc::new(RecordingModel::new(&[
        &tool_call(
            "write",
            serde_json::json!({"path": "notes.txt", "content": "hello"}),
        ),
        "the note is written",
    ]));
    let workspace = assemble(
        root,
        &policy,
        Box::new(Shared(Arc::clone(&connector))),
        audit.to_path_buf(),
        None,
    )
    .expect("compose the headless run");
    let request = RunRequest {
        cwd: root.to_path_buf(),
        prompt: TASK.to_owned(),
        max_turns: 6,
        max_cost_usd: None,
        model,
        request_timeout: None,
        context_budget: None,
        tool_result_budget: None,
        save_transcript: None,
        contract: None,
        expect_effect: arcana_cli::effect::EffectExpectation::default(),
    };
    let config = driver_config(&request, &workspace.tools, root);
    let out = workspace
        .session
        .run_task(&request.prompt, config, CancellationToken::new())
        .await;
    let seen = connector.seen.lock().unwrap().clone();
    (out, seen)
}

#[tokio::test]
async fn every_dispatch_in_one_run_uses_the_resolved_model() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();

    let (out, seen) = drive(work.path(), audit.path(), Some("lane-model".to_owned())).await;

    assert!(
        out.selected_models.len() >= 2,
        "need a run that dispatched more than once to say anything about \"every\", got {:?}",
        out.selected_models
    );
    let distinct: HashSet<&String> = out.selected_models.iter().collect();
    assert_eq!(
        distinct.len(),
        1,
        "one resolved model, one id on every dispatch — got {:?}",
        out.selected_models
    );
    assert_eq!(out.selected_models[0], "lane-model");
    let seen: Vec<String> = seen.into_iter().flatten().collect();
    assert_eq!(
        seen, out.selected_models,
        "the connector saw the same ids the driver reports"
    );
}

#[tokio::test]
async fn without_a_choice_the_tiered_policy_still_routes_per_turn() {
    // The negative control for the test above, and the reason pinning cannot
    // simply be the default: with nothing configured the two turns MUST reach
    // two different models, or "every dispatch used the resolved model" would
    // be true of a loop that had no policy left at all.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();

    let (out, _) = drive(work.path(), audit.path(), Some("tier".to_owned())).await;

    let distinct: HashSet<&String> = out.selected_models.iter().collect();
    assert!(
        distinct.len() >= 2,
        "the tiered policy must still route by task type, got {:?}",
        out.selected_models
    );
}

/// A contract binding for the receipt. Its contents are irrelevant here — the
/// assertion is about the model fields — but a receipt cannot be built without
/// one, and a fixture is cheaper than a live contract.
fn binding() -> ContractBinding {
    let projection = "Role: reviewer. Deliverable: one review note.";
    let document = ContractDocument {
        digest: digest_of(projection.as_bytes()),
        projection: serde_json::json!(projection),
        tools: Some(ContractTools {
            allow: vec!["read".to_owned(), "write".to_owned()],
        }),
        ..ContractDocument::default()
    };
    verify(&document.digest.clone(), &document).expect("the fixture binds")
}

/// Pair a driven run with the effect it had, the way `arcana run` does.
///
/// These two tests assert about the model fields, so the tree is measured
/// either side of nothing at all — but the receipt is built from a
/// `RunSummary` now, and building one by hand here would let the two paths
/// drift apart.
fn summarize(root: &std::path::Path, out: &RunOutput) -> arcana_cli::run::RunSummary {
    let before = arcana_cli::effect::snapshot(root);
    arcana_cli::run::summarize(
        root,
        &before,
        out.clone(),
        arcana_cli::effect::EffectExpectation::default(),
    )
}

#[tokio::test]
async fn the_receipt_records_both_the_model_and_who_chose_it() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let (out, _) = drive(work.path(), audit.path(), Some("lane-model".to_owned())).await;

    let source = arcana_connectors::contract_source::FileContractSource::new(
        work.path().join("contract.json"),
    );
    let receipt = arcana_cli::receipt::build(
        "A2-276",
        &binding(),
        &source,
        work.path(),
        &summarize(work.path(), &out),
        &ResolvedModel {
            model: Some("lane-model".to_owned()),
            source: ModelSource::Env,
        },
        "test".to_owned(),
        "2026-09-24T00:00:00Z".to_owned(),
    );

    let json = serde_json::to_value(&receipt).unwrap();
    assert_eq!(json["mc_usage"]["model_source"], "env");
    assert_eq!(json["mc_usage"]["configured_model"], "lane-model");
    assert_eq!(json["mc_usage"]["selected_models"][0], "lane-model");
}

#[tokio::test]
async fn a_receipt_for_an_unconfigured_run_says_tier_policy_rather_than_a_model() {
    // `configured_model: null` is an answer. A receipt that filled it in with
    // whichever model happened to be dispatched first would report the tier
    // policy's pick as the operator's decision — which is how A2-272's receipt
    // read, and why it took a second look to see the defect at all.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    let (out, _) = drive(work.path(), audit.path(), Some("tier".to_owned())).await;

    let source = arcana_connectors::contract_source::FileContractSource::new(
        work.path().join("contract.json"),
    );
    let receipt = arcana_cli::receipt::build(
        "A2-276",
        &binding(),
        &source,
        work.path(),
        &summarize(work.path(), &out),
        &ResolvedModel {
            model: None,
            source: ModelSource::TierPolicy,
        },
        "test".to_owned(),
        "2026-09-24T00:00:00Z".to_owned(),
    );

    let json = serde_json::to_value(&receipt).unwrap();
    assert_eq!(json["mc_usage"]["model_source"], "tier-policy");
    assert!(json["mc_usage"]["configured_model"].is_null());
    assert!(
        json["mc_usage"]["selected_models"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );
}
