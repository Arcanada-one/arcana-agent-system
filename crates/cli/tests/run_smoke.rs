//! `arcana run` refuses to start rather than pretend, and always emits a
//! done-marker a runner can read.
//!
//! Every case here is a run that must NOT happen. The cases where a run does
//! happen live in `run_tool_execution.rs`, which needs no network because the
//! model — and only the model — is scripted there.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// Not a credential: a syntactically valid header value, present only so the
/// run gets past the "is a key set" check and reaches the base-URL pin.
const PLACEHOLDER_KEY: &str = "not-a-real-key";

#[test]
fn a_run_that_cannot_go_live_exits_non_zero() {
    // `--live` is not a preference. `demo --live` used to answer an
    // unreachable Model Connector by replaying its canned offline script and
    // exiting 0; `run` has no offline mode at all, so the only honest outcome
    // is a refusal to start.
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--prompt", "do nothing"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ARCANA_MC_TOKEN"))
        .stdout(predicate::str::contains("\"completed\":false"));
}

#[test]
fn an_unapproved_connector_origin_stops_the_run_instead_of_going_offline() {
    // The production base-URL pin is a control, not an obstacle: the fix for
    // "live silently became offline" is to report that the pin refused.
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_MC_TOKEN", PLACEHOLDER_KEY)
        .env("ARCANA_MC_BASE_URL", "http://127.0.0.1:9")
        .env("XDG_STATE_HOME", state.path())
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--prompt", "do nothing"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not approved"))
        .stdout(predicate::str::contains("\"completed\":false"));
}

#[test]
fn a_working_directory_that_does_not_exist_is_refused() {
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .args([
            "run",
            "--cwd",
            "/definitely/not/a/directory",
            "--prompt",
            "do nothing",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be resolved"));
}

#[test]
fn the_task_must_be_given_exactly_once() {
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .args(["run", "--cwd"])
        .arg(work.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("--prompt"));
}

#[test]
fn an_empty_task_on_stdin_is_refused_before_any_dispatch() {
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .args(["run", "--cwd"])
        .arg(work.path())
        .arg("--prompt-stdin")
        .write_stdin("   \n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("stdin was empty"));
}

#[test]
fn the_done_marker_is_the_last_line_and_parses_as_json() {
    // A runner reads this line and nothing else. It must be present even when
    // the run never started, or its absence would have to be interpreted —
    // and "no marker" is exactly what a crashed process also looks like.
    let work = TempDir::new().unwrap();
    let state = TempDir::new().unwrap();
    let output = Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .args(["run", "--cwd"])
        .arg(work.path())
        .args(["--prompt", "do nothing"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let last = stdout.lines().last().expect("stdout had no lines");
    let body = last
        .strip_prefix("ARCANA_RUN_DONE ")
        .expect("last line is not the done-marker");
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed["completed"], false);
    assert!(parsed["error"].is_string());
}

#[test]
fn run_help_says_it_is_always_live_and_costs_money() {
    Command::cargo_bin("arcana")
        .unwrap()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("costs money"));
}
