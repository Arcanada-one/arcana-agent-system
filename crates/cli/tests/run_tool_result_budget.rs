//! A2-219: `--tool-result-budget` and `--save-transcript` reach the driver,
//! and a value that cannot be honoured is refused before the run costs
//! anything. The workspace's rejected-reply directory is wired here too.
//!
//! The tool-result budget is the flag the elision-and-spill path of A2-216 was
//! missing: nothing an ordinary task does produces 8 000 UTF-16 units of
//! output cheaply, so that path had offline evidence and no live receipt
//! (A2-218 report, defect 4). Both refusals below are for values that would
//! otherwise fail SILENTLY — a budget under the marker's own length makes
//! every oversized result vanish behind the marker, and a budget over the
//! transcript ceiling simply never binds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use arcana_cli::run::{
    check_tool_result_budget, check_transcript_path, driver_config, RunRequest, REJECTED_DIR,
};
use arcana_core::prompt_budget::{
    DEFAULT_CONTEXT_BUDGET_UTF16_UNITS, DEFAULT_TOOL_RESULT_BUDGET_UTF16_UNITS, MIN_ELISION_BUDGET,
};

fn request(tool_result_budget: Option<usize>, save_transcript: Option<PathBuf>) -> RunRequest {
    RunRequest {
        cwd: PathBuf::from("."),
        prompt: "do the thing".to_owned(),
        max_turns: 4,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
        request_timeout: None,
        context_budget: None,
        tool_result_budget,
        save_transcript,
        contract: None,
        expect_effect: arcana_cli::effect::EffectExpectation::default(),
    }
}

#[test]
fn the_default_is_unchanged_when_the_flag_is_absent() {
    let config = driver_config(&request(None, None), &[], &PathBuf::from("."));
    assert_eq!(
        config.tool_result_budget_units, DEFAULT_TOOL_RESULT_BUDGET_UTF16_UNITS,
        "an operator who passes nothing must get exactly what they got before"
    );
    assert!(config.transcript_path.is_none());
}

#[test]
fn the_flags_reach_the_driver() {
    let path = PathBuf::from("/tmp/a2-219-transcript.txt");
    let config = driver_config(
        &request(Some(400), Some(path.clone())),
        &[],
        &PathBuf::from("."),
    );
    assert_eq!(config.tool_result_budget_units, 400);
    assert_eq!(config.transcript_path, Some(path));
}

#[test]
fn a_headless_run_always_keeps_its_rejected_replies_in_the_workspace() {
    let root = PathBuf::from("/tmp/a2-219-workspace");
    let config = driver_config(&request(None, None), &[], &root);
    assert_eq!(
        config.rejected_reply_dir,
        Some(root.join(REJECTED_DIR)),
        "the reply the runner threw away belongs where the run happened, and \
         it is not opt-in for an unattended run"
    );
}

#[test]
fn a_budget_under_the_elision_marker_is_refused() {
    let err = check_tool_result_budget(Some(MIN_ELISION_BUDGET - 1), 90_000)
        .expect_err("a budget that hides every result behind the marker must not start a run");
    assert!(
        err.contains("--tool-result-budget"),
        "the refusal names the flag: {err}"
    );
    assert!(err.contains(&MIN_ELISION_BUDGET.to_string()), "{err}");
    // The floor itself is legal.
    assert!(check_tool_result_budget(Some(MIN_ELISION_BUDGET), 90_000).is_ok());
}

#[test]
fn a_budget_above_this_runs_transcript_ceiling_is_refused() {
    // Judged against the ceiling THIS run uses, not against the default: the
    // two flags are set together and must be consistent with each other.
    let err = check_tool_result_budget(Some(20_000), 12_000)
        .expect_err("one tool result may not be allowed to fill the whole request");
    assert!(
        err.contains("12000"),
        "the refusal names the ceiling: {err}"
    );
    assert!(check_tool_result_budget(Some(12_000), 12_000).is_ok());
    assert!(check_tool_result_budget(
        Some(DEFAULT_CONTEXT_BUDGET_UTF16_UNITS),
        DEFAULT_CONTEXT_BUDGET_UTF16_UNITS
    )
    .is_ok());
}

#[test]
fn no_flag_is_never_an_error() {
    assert!(check_tool_result_budget(None, 90_000).is_ok());
    assert!(check_transcript_path(None).is_ok());
}

#[test]
fn a_transcript_path_that_cannot_be_written_is_refused_before_the_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("no-such-dir").join("transcript.txt");
    let err = check_transcript_path(Some(&missing))
        .expect_err("a run must not reach turn thirty to learn it has nowhere to write");
    assert!(err.contains("--save-transcript"), "{err}");

    let good = dir.path().join("transcript.txt");
    assert!(check_transcript_path(Some(&good)).is_ok());
    assert!(
        good.exists(),
        "the check opens the file it promised to append to"
    );
}
