//! A run is completed when the working tree says so, not when the model does.
//!
//! Pilot A2-278 dispatched one Muneral work item five times. Runs 2 and 4
//! (`deepseek-v4-flash`, live, $0.035 and $0.016) executed nine and three tool
//! calls — every single one a `read` or a `grep` — wrote nothing at all, and
//! ended:
//!
//! ```text
//! ARCANA_RUN_DONE {"completed":true,"reason":"Completed","tool_calls":9,...}
//! ```
//!
//! rc `0`, with the model's closing sentence describing "the documentation
//! page `docs/how-to/run-work-item.md`" and listing sections it did not have.
//! The file does not exist. The guard in
//! `docs/how-to/run-one-task-unattended.md` — "`completed` is never `true`
//! with `tool_calls` at `0`" — counted the reads and waved it through.
//!
//! Every test here drives the REAL driver, cascade, dispatcher, audit log and
//! tools against a scripted model, and judges by the directory afterwards.
//! Each has a paired opposite that must go the other way: a check that cannot
//! be red is a constant, not a check.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_pass_by_value
)]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_cli::effect::EffectExpectation;
use arcana_cli::run::{assemble, driver_config, summarize, verdict_of, RunRequest, RunSummary};
use arcana_cli::workspace::WorkspacePolicy;
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use async_trait::async_trait;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

/// Replays a fixed script of model replies, one per turn. The model is the
/// only thing faked.
struct ScriptedModel {
    replies: Vec<String>,
    turn: AtomicUsize,
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

/// Drive one scripted run and measure it exactly as `arcana run` does.
///
/// The before-snapshot is taken here and the after-snapshot inside
/// [`summarize`], which is the same function the live path calls — so a test
/// that sees `NoEffect` has seen the production verdict, not a re-derivation
/// of it.
async fn drive(
    root: &Path,
    audit: &Path,
    replies: &[&str],
    expectation: EffectExpectation,
) -> RunSummary {
    let policy = Arc::new(WorkspacePolicy::new(root).unwrap());
    let workspace = assemble(
        root,
        &policy,
        Box::new(ScriptedModel {
            replies: replies.iter().map(|reply| (*reply).to_owned()).collect(),
            turn: AtomicUsize::new(0),
        }),
        audit.to_path_buf(),
        None,
    )
    .expect("compose the headless run");
    let request = RunRequest {
        cwd: root.to_path_buf(),
        prompt: "write the how-to page for running a work item".to_owned(),
        max_turns: 8,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
        request_timeout: None,
        context_budget: None,
        tool_result_budget: None,
        save_transcript: None,
        contract: None,
        expect_effect: expectation,
    };
    let config = driver_config(&request, &workspace.tools, root);
    let before = arcana_cli::effect::snapshot(root);
    let out = workspace
        .session
        .run_task(&request.prompt, config, CancellationToken::new())
        .await;
    summarize(root, &before, out, expectation)
}

/// The corpus run 4 read its way around: a repository with something in it.
fn seed(root: &Path) {
    std::fs::create_dir_all(root.join("docs/how-to")).unwrap();
    std::fs::write(root.join("README.md"), "# arcana\n\nA CLI agent.\n").unwrap();
    std::fs::write(
        root.join("docs/how-to/run-one-task-unattended.md"),
        "# Run one task unattended\n\nThe marker is the last line.\n",
    )
    .unwrap();
}

/// Run 4, reproduced: reads and greps, then "the file has been created".
const RUN_FOUR_CLAIM: &str = "The documentation page `docs/how-to/run-work-item.md` has been \
created. It covers: the command, the exit codes, and the receipt.";

#[tokio::test]
async fn a_run_that_only_read_and_then_claimed_a_file_is_no_effect() {
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    seed(work.path());

    let summary = drive(
        work.path(),
        audit.path(),
        &[
            &tool_call("read", serde_json::json!({ "path": "README.md" })),
            &tool_call(
                "grep",
                serde_json::json!({ "pattern": "work-item", "path": "docs", "recursive": true }),
            ),
            &tool_call(
                "read",
                serde_json::json!({ "path": "docs/how-to/run-one-task-unattended.md" }),
            ),
            RUN_FOUR_CLAIM,
        ],
        EffectExpectation::Artefact,
    )
    .await;

    // The disk first, as the rest of this suite does.
    assert!(
        !work.path().join("docs/how-to/run-work-item.md").exists(),
        "the fixture is wrong: the model was not supposed to write anything"
    );

    // The driver is happy — three calls executed and the model answered. That
    // is precisely the state the old guard called `Completed`.
    assert_eq!(summary.out.tool_calls, 3);
    assert_eq!(
        summary.out.executed_tools,
        vec!["read".to_owned(), "grep".to_owned(), "read".to_owned()]
    );

    let (completed, reason) = verdict_of(&summary);
    assert!(!completed, "a run that wrote nothing is not completed");
    assert_eq!(reason, "NoEffect");

    let effect = &summary.effect;
    assert_eq!(effect.tree_changed, Some(false));
    assert_eq!(effect.tree_digest_before, effect.tree_digest_after);
    assert!(effect.writes.is_empty(), "{:?}", effect.writes);
    assert_eq!(
        effect.claimed_but_absent,
        vec!["docs/how-to/run-work-item.md".to_owned()],
        "the claim the disk denies must be named"
    );
}

#[tokio::test]
async fn the_same_run_that_actually_writes_the_page_completes() {
    // The green half. Same corpus, same closing sentence, one `write` added —
    // and now the sentence is true. Without this the test above would pass on
    // a `verdict_of` that returned `NoEffect` unconditionally.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    seed(work.path());

    let summary = drive(
        work.path(),
        audit.path(),
        &[
            &tool_call("read", serde_json::json!({ "path": "README.md" })),
            &tool_call(
                "write",
                serde_json::json!({
                    "path": "docs/how-to/run-work-item.md",
                    "content": "# Run a work item\n\n```bash\narcana run --work-item <id>\n```\n"
                }),
            ),
            RUN_FOUR_CLAIM,
        ],
        EffectExpectation::Artefact,
    )
    .await;

    let page = work.path().join("docs/how-to/run-work-item.md");
    assert!(page.exists(), "the write did not land: {:?}", summary.out);

    let (completed, reason) = verdict_of(&summary);
    assert!(completed, "{reason} — {:?}", summary.effect);
    assert_eq!(reason, "Completed");
    assert_eq!(summary.effect.tree_changed, Some(true));
    assert_eq!(summary.effect.writes, vec!["write".to_owned()]);
    assert_eq!(
        summary.effect.changed_paths,
        vec!["docs/how-to/run-work-item.md".to_owned()]
    );
    assert!(
        summary.effect.claimed_but_absent.is_empty(),
        "{:?}",
        summary.effect.claimed_but_absent
    );
}

#[tokio::test]
async fn an_incidental_write_does_not_buy_a_run_out_of_its_own_claim() {
    // Live run 1 under the tree digest, verbatim (2026-09-24,
    // deepseek-v4-flash, work item d931525f-…, $0.0339): six executed calls,
    // two of them `write`s that both created the same EMPTY probe file
    // `test-write-check.md`, and a closing message describing
    // `docs/how-to/run-work-item-under-kc2-contract.md` in four numbered
    // points. The page does not exist. The tree HAD changed — so the digest on
    // its own said `Completed`, and an incidental write would have been enough
    // to buy any run out of `NoEffect`.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    seed(work.path());

    let summary = drive(
        work.path(),
        audit.path(),
        &[
            &tool_call(
                "write",
                serde_json::json!({ "path": "test-write-check.md", "content": "" }),
            ),
            RUN_FOUR_CLAIM,
        ],
        EffectExpectation::Artefact,
    )
    .await;

    assert!(work.path().join("test-write-check.md").exists());
    assert_eq!(summary.effect.tree_changed, Some(true));
    assert_eq!(summary.effect.writes, vec!["write".to_owned()]);

    let (completed, reason) = verdict_of(&summary);
    assert!(!completed, "the page the model named is not on disk");
    assert_eq!(reason, "ClaimedButAbsent");
    assert_eq!(
        summary.effect.claimed_but_absent,
        vec!["docs/how-to/run-work-item.md".to_owned()]
    );
}

#[tokio::test]
async fn a_declared_read_only_run_completes_with_an_untouched_tree() {
    // An audit is finished when its answer is on stdout. The declaration is
    // the caller's, made before the run — nothing in the script below could
    // have produced it.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    seed(work.path());

    let summary = drive(
        work.path(),
        audit.path(),
        &[
            &tool_call("read", serde_json::json!({ "path": "README.md" })),
            "The README documents one command and no exit codes.",
        ],
        EffectExpectation::ReadOnly,
    )
    .await;

    let (completed, reason) = verdict_of(&summary);
    assert!(completed, "{reason}");
    assert_eq!(reason, "Completed");
    assert_eq!(summary.effect.tree_changed, Some(false));
    assert_eq!(summary.effect.expectation, "read-only");
}

#[tokio::test]
async fn a_run_that_only_filled_the_runners_own_scratch_directory_is_no_effect() {
    // `.arcana/` is where spilled output, rejected replies and refused calls
    // go. It is evidence ABOUT the run. A run whose only trace is its own
    // paperwork produced nothing — and this is the mutant that matters: drop
    // the `.arcana/` exclusion from the digest and this test goes green while
    // the runner goes back to accepting work nobody did.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    seed(work.path());

    let summary = drive(
        work.path(),
        audit.path(),
        &[
            // One real read, so the run reaches `Completed` and the old
            // `tool_calls > 0` guard is satisfied exactly as it was live…
            &tool_call("read", serde_json::json!({ "path": "README.md" })),
            // …a reply the runner cannot parse, which writes
            // `.arcana/rejected/…` and nothing else…
            "```tool_call\n{ not json at all\n```",
            // …and the claim.
            RUN_FOUR_CLAIM,
        ],
        EffectExpectation::Artefact,
    )
    .await;

    assert!(
        work.path().join(".arcana/rejected").exists(),
        "the fixture is wrong: nothing was written under .arcana/"
    );
    assert_eq!(summary.out.tool_calls, 1, "{:?}", summary.out.reason);
    assert_eq!(summary.effect.tree_changed, Some(false));
    assert_eq!(
        summary.effect.claimed_but_absent,
        vec!["docs/how-to/run-work-item.md".to_owned()]
    );
    let (completed, _) = verdict_of(&summary);
    assert!(!completed);
}

#[tokio::test]
async fn a_write_through_the_shell_is_an_effect_even_though_bash_is_not_a_write_tool() {
    // `writes` lists `write` and `edit` and deliberately not `bash`. The
    // verdict is the tree, so a page produced by a redirect still counts —
    // and if the verdict were ever moved onto the tool names, this test is
    // what goes red.
    let work = TempDir::new().unwrap();
    let audit = TempDir::new().unwrap();
    seed(work.path());

    let summary = drive(
        work.path(),
        audit.path(),
        &[
            &tool_call(
                "bash",
                serde_json::json!({ "command": "echo '# Run a work item' > docs/how-to/run-work-item.md" }),
            ),
            RUN_FOUR_CLAIM,
        ],
        EffectExpectation::Artefact,
    )
    .await;

    assert!(work.path().join("docs/how-to/run-work-item.md").exists());
    let (completed, reason) = verdict_of(&summary);
    assert!(completed, "{reason} — {:?}", summary.effect);
    assert!(
        summary.effect.writes.is_empty(),
        "bash is not a write tool: {:?}",
        summary.effect.writes
    );
    assert_eq!(summary.effect.tree_changed, Some(true));
}
