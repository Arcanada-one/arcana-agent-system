//! A2-218: `--context-budget` reaches the driver, and a value the server
//! cannot honour is refused before the run costs anything.
//!
//! The flag exists for two reasons that are not the same. Operationally, a
//! model with a context window under Model Connector's 100 000-unit field
//! limit needs the lower ceiling and had no way to be given one. Evidentially,
//! the compaction path added by A2-216 could only be shown to work offline —
//! no ordinary task grows a transcript past 90 000 units cheaply — so its live
//! receipt was missing (A2-216 report, § 5).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use arcana_cli::run::{check_context_budget, driver_config, RunRequest};
use arcana_core::prompt_budget::{DEFAULT_CONTEXT_BUDGET_UTF16_UNITS, MC_FIELD_MAX_UTF16_UNITS};

fn request(context_budget: Option<usize>) -> RunRequest {
    RunRequest {
        cwd: PathBuf::from("."),
        prompt: "do the thing".to_owned(),
        max_turns: 4,
        max_cost_usd: None,
        model: Some("scripted-model".to_owned()),
        request_timeout: None,
        context_budget,
        tool_result_budget: None,
        save_transcript: None,
    }
}

#[test]
fn the_default_is_unchanged_when_the_flag_is_absent() {
    let config = driver_config(&request(None), &[], &PathBuf::from("."));
    assert_eq!(
        config.context_budget_units, DEFAULT_CONTEXT_BUDGET_UTF16_UNITS,
        "an operator who passes nothing must get exactly what they got before"
    );
}

#[test]
fn the_flag_reaches_the_driver() {
    let config = driver_config(&request(Some(12_000)), &[], &PathBuf::from("."));
    assert_eq!(config.context_budget_units, 12_000);
}

#[test]
fn a_budget_above_the_connector_limit_is_refused() {
    let err = check_context_budget(Some(MC_FIELD_MAX_UTF16_UNITS + 1))
        .expect_err("a budget the server will not honour must not start a run");
    assert!(
        err.contains("100000"),
        "the refusal must name the limit it is measured against: {err}"
    );
    // The wall itself is legal: it is the number Model Connector accepts, and
    // an operator who asks for exactly it is asking for something real.
    assert!(check_context_budget(Some(MC_FIELD_MAX_UTF16_UNITS)).is_ok());
}

#[test]
fn a_zero_budget_is_refused_with_a_sentence() {
    let err = check_context_budget(Some(0)).expect_err("zero leaves no room for the task");
    assert!(err.contains("--context-budget"), "{err}");
}

#[test]
fn no_flag_is_never_an_error() {
    assert!(check_context_budget(None).is_ok());
}
