//! A2-259: a `..` refusal carries the way to write the path, and a model that
//! reads it recovers instead of spending the run on the same shape.
//!
//! ## What was measured
//!
//! Pilot A2-240d (`arcana` 5fc4684, 2026-09-24) was denied six calls. Three of
//! them — turns 15, 16 and 54, in
//! `/home/dev/aup/arc2/wt/A2-240d/.arcana/denied/` — are one misunderstanding:
//!
//! ```text
//! cd sup && git archive HEAD | tar -x -C ../snap
//! refused: `../snap` walks out of the workspace `/home/dev/aup/arc2/wt/A2-240d` with `..`
//! ```
//!
//! After `cd sup`, `../snap` IS inside the workspace. The check resolves `..`
//! against the workspace ROOT, not against the command's own `cd`, and that
//! stays — tracking a `cd` through a shell string has no single reading
//! (subshells, `cd -`, `cd "$VAR"`, `;` vs `&&` vs `||`), and a boundary that
//! guesses is not a boundary.
//!
//! What was wrong is that the refusal named the problem and no way to be
//! right. The model retried the same shape on the very next turn, and again
//! thirty-eight turns later. A boundary refusal IS handed back to the model
//! (`arcana_core::agent_loop::RECOVERABLE_DENIAL_LAYERS`), so it is a
//! correction, and a correction that does not say what to do instead is a
//! wall with a label on it.
//!
//! The red half below is the pilot: the same model, the same task, the same
//! policy — only the refusal's wording is the pre-A2-259 one. It does not
//! recover, and the file is never copied.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arcana_cli::run::{assemble, driver_config, system_prompt, RunRequest};
use arcana_cli::workspace::{WorkspacePolicy, RELATIVE_PATH_REMEDY};
use arcana_core::agent_loop::RunOutput;
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use async_trait::async_trait;
use serde_json::json;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// The whole of what a `..` refusal said before A2-259, quoted from
/// `crates/cli/src/workspace.rs` as it stood at `5fc4684`.
const OLD_REASON: &str =
    "refused: `../snap/proof.mjs` walks out of the workspace `<root>` with `..`";

/// The pilot's shape: `cd` into a sub-directory, then reach a sibling with
/// `..`. Refused, and rightly.
const RELATIVE_ATTEMPTS: [&str; 2] = [
    "cd sub && cp proof.mjs ../snap/proof.mjs",
    "cd sub && cp ./proof.mjs ../snap/proof.mjs",
];

/// What the remedy in the refusal tells a reader to write instead.
const WORKSPACE_RELATIVE: &str = "cp sub/proof.mjs snap/proof.mjs";

// ---------------------------------------------------------------------------
// The prompt states the rule before anybody trips over it
// ---------------------------------------------------------------------------

#[test]
fn the_prompt_says_a_cd_does_not_move_the_boundary() {
    let root = TempDir::new().unwrap();
    let prompt = prompt_for(root.path());
    assert!(
        prompt.contains("A `cd` earlier in the same command does NOT move this boundary"),
        "the prompt never mentions the `cd` case: {prompt}"
    );
    assert!(
        prompt.contains(RELATIVE_PATH_REMEDY),
        "the prompt and the refusal do not say the same thing: {prompt}"
    );
}

// ---------------------------------------------------------------------------
// Green: the refusal carries a remedy, and the model acts on it
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_model_told_how_to_write_the_path_recovers_on_the_next_turn() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    make_fixture(work.path());

    let model = RelativePathModel::new(None);
    let out = drive(work.path(), audit.path(), model.clone()).await;

    // The disk first: the verdict is what the run SAYS, this is what it DID.
    assert!(
        work.path().join("snap/proof.mjs").exists(),
        "the file was never copied ({:?}); attempts: {:?}",
        out.reason,
        model.attempts()
    );
    assert_eq!(
        model.attempts().get(1).map(String::as_str),
        Some(WORKSPACE_RELATIVE),
        "the model did not act on the remedy it was handed: {:?}",
        model.attempts()
    );
}

// ---------------------------------------------------------------------------
// Red: the pilot. Same model, pre-A2-259 wording, no recovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_same_model_given_the_old_wording_retries_the_same_shape_and_never_copies_the_file() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    make_fixture(work.path());

    let model = RelativePathModel::new(Some(OLD_REASON.to_owned()));
    drive(work.path(), audit.path(), model.clone()).await;

    let attempts = model.attempts();
    assert!(
        attempts.len() >= 2 && attempts.iter().all(|command| command.contains("..")),
        "the model was supposed to keep reaching for `..` here: {attempts:?}"
    );
    assert!(
        !work.path().join("snap/proof.mjs").exists(),
        "nothing should have been copied"
    );
}

// ---------------------------------------------------------------------------
// The model under test
// ---------------------------------------------------------------------------

/// One goal — copy `sub/proof.mjs` to `snap/` — written the way the pilot
/// wrote it, and re-written if the refusal says how.
///
/// Deliberately generic: it looks for a remedy in the refusal text and follows
/// it. It is not told that `..` is the problem, and feed it a refusal that
/// states no remedy and it has nothing to change but the spelling — which is
/// the pilot, and why the red half works at all.
#[derive(Clone)]
struct RelativePathModel {
    turn: Arc<AtomicUsize>,
    attempts: Arc<Mutex<Vec<String>>>,
    /// Replaces the refusal text the model gets to read, so the pre-A2-259
    /// wording can be put in front of the same model.
    reason_override: Option<String>,
}

impl RelativePathModel {
    fn new(reason_override: Option<String>) -> Self {
        Self {
            turn: Arc::new(AtomicUsize::new(0)),
            attempts: Arc::new(Mutex::new(Vec::new())),
            reason_override,
        }
    }

    fn attempts(&self) -> Vec<String> {
        self.attempts.lock().unwrap().clone()
    }

    /// The refusal this model is allowed to read, if the last turn was one.
    fn refusal<'a>(&'a self, transcript: &'a str) -> Option<&'a str> {
        let line = transcript
            .lines()
            .rev()
            .find(|line| line.contains("REJECTED at the workspace_boundary layer"))?;
        Some(self.reason_override.as_deref().unwrap_or(line))
    }
}

#[async_trait]
impl ModelConnector for RelativePathModel {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let index = self.turn.fetch_add(1, Ordering::SeqCst);
        let refusal = self.refusal(&req.prompt).map(str::to_owned);
        let result = match refusal {
            // Nothing was refused: either the first turn, or the copy ran.
            None if index == 0 => call(&self.attempts, RELATIVE_ATTEMPTS[0]),
            None => "copied the file".to_owned(),
            // Refused, and the refusal says what to write instead.
            Some(reason) if reason.contains("name the path from the workspace root") => {
                call(&self.attempts, WORKSPACE_RELATIVE)
            }
            // Refused, and the refusal says only that it was refused. All the
            // model can do is spell the same idea differently.
            Some(_) => match RELATIVE_ATTEMPTS
                .iter()
                .find(|candidate| !self.attempts().iter().any(|sent| sent == *candidate))
            {
                Some(candidate) => call(&self.attempts, candidate),
                None => "I cannot find a way to write this path".to_owned(),
            },
        };
        Ok(ConnectorResponse {
            id: format!("relative-path-{index}"),
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

fn call(attempts: &Arc<Mutex<Vec<String>>>, command: &str) -> String {
    attempts.lock().unwrap().push(command.to_owned());
    format!(
        "```tool_call\n{}\n```",
        json!({ "name": "bash", "input": { "command": command } })
    )
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn make_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::create_dir_all(root.join("snap")).unwrap();
    std::fs::write(root.join("sub/proof.mjs"), "// proof\n").unwrap();
}

fn prompt_for(root: &Path) -> String {
    let policy = Arc::new(WorkspacePolicy::new(root).unwrap());
    let audit = TempDir::new().unwrap();
    let workspace = assemble(
        root,
        &policy,
        Box::new(RelativePathModel::new(None)),
        audit.path().to_path_buf(),
        None,
    )
    .expect("compose the headless run");
    system_prompt(&workspace.tools, root)
}

async fn drive(root: &Path, audit: &Path, model: RelativePathModel) -> RunOutput {
    let policy = Arc::new(WorkspacePolicy::new(root).unwrap());
    let workspace = assemble(root, &policy, Box::new(model), audit.to_path_buf(), None)
        .expect("compose the headless run");
    let request = RunRequest {
        cwd: root.to_path_buf(),
        prompt: "copy sub/proof.mjs into snap/".to_owned(),
        max_turns: 8,
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
