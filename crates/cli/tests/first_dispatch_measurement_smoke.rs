//! CLI activation checks for the opt-in first-dispatch measurement seam.

#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;

const MEASUREMENT: &str = r#"{"corpusId":"corpus-v0","caseId":"case-007","roleId":"developer","taskClassId":"code-change","commandId":"implement","replayIndex":1,"variant":"baseline"}"#;

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
    Command::cargo_bin("arcana")
        .unwrap()
        .args([
            "demo",
            "measure this prompt",
            "--live",
            "--first-dispatch-measurement-json",
            MEASUREMENT,
        ])
        .env_remove("ARCANA_MC_TOKEN")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("never falls back offline"));
}
