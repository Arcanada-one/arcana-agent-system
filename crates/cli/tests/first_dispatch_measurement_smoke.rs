//! CLI activation checks for the opt-in first-dispatch measurement seam.

#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;

const MEASUREMENT: &str = r#"{"corpusId":"corpus-v0","caseId":"case-007","roleId":"developer","taskClassId":"code-change","commandId":"implement","replayIndex":1,"variant":"baseline"}"#;
const ROUTE_ARGS: [&str; 4] = [
    "--first-dispatch-connector",
    "claude-code",
    "--first-dispatch-model",
    "sonnet-4.6",
];

#[test]
fn measurement_option_requires_an_explicit_live_run() {
    Command::cargo_bin("arcana")
        .unwrap()
        .args([
            "demo",
            "measure this prompt",
            "--first-dispatch-measurement-json",
            MEASUREMENT,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--live"));
}

#[test]
fn measurement_never_falls_back_to_the_offline_demo() {
    let mut command = Command::cargo_bin("arcana").unwrap();
    command
        .args([
            "demo",
            "measure this prompt",
            "--live",
            "--first-dispatch-measurement-json",
            MEASUREMENT,
        ])
        .args(ROUTE_ARGS)
        .env_remove("ARCANA_MC_TOKEN")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("never falls back offline"));
}

#[test]
fn measurement_requires_an_explicit_connector_and_model_route() {
    Command::cargo_bin("arcana")
        .unwrap()
        .args([
            "demo",
            "measure this prompt",
            "--live",
            "--first-dispatch-measurement-json",
            MEASUREMENT,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--first-dispatch-connector"));
}

#[test]
fn prompt_stdin_requires_measurement_mode() {
    Command::cargo_bin("arcana")
        .unwrap()
        .args([
            "demo",
            "measure this prompt",
            "--live",
            "--first-dispatch-prompt-stdin",
        ])
        .write_stdin("secret-compiled-prompt")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("--first-dispatch-measurement-json")
                .and(predicate::str::contains("secret-compiled-prompt").not()),
        );
}

#[test]
fn prompt_stdin_is_consumed_without_echo_before_live_token_gate() {
    let mut command = Command::cargo_bin("arcana").unwrap();
    command
        .args([
            "demo",
            "measure this prompt",
            "--live",
            "--first-dispatch-measurement-json",
            MEASUREMENT,
            "--first-dispatch-prompt-stdin",
        ])
        .args(ROUTE_ARGS)
        .write_stdin("secret-compiled-prompt")
        .env_remove("ARCANA_MC_TOKEN")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("never falls back offline")
                .and(predicate::str::contains("secret-compiled-prompt").not()),
        );
}
