#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_subcommand_prints_version_sha_and_license() {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.arg("version").assert().success().stdout(
        predicate::str::is_match(r"^arcana 0\.1\.0 \([0-9a-f]{7}\) — MIT OR Apache-2\.0\n$")
            .unwrap(),
    );
}

#[test]
fn version_flag_prints_clap_version_line() {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("arcana 0.1.0"));
}

#[test]
fn bare_invocation_shows_repl_stub_banner() {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("REPL stub"));
}

#[test]
fn login_subcommand_prints_stub_notice() {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.arg("login")
        .assert()
        .success()
        .stdout(predicate::str::contains("OIDC device-code flow"))
        .stdout(predicate::str::contains("not yet implemented"));
}

#[test]
fn login_stub_omits_internal_task_ids() {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.arg("login")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\bARAS-\d{4}\b").unwrap().not())
        .stdout(predicate::str::is_match(r"\bAUTH-\d{4}\b").unwrap().not());
}
