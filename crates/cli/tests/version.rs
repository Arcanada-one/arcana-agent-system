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

// The former `bare_invocation_shows_repl_stub_banner` asserted the placeholder
// banner, i.e. it encoded the stub as intent and would have gone green forever
// while the REPL stayed unimplemented. ARAS-0059 replaced the stub with a real
// interactive session, so the assertion is inverted here — a stub banner is now
// a regression — and the session's behaviour is covered in `repl_smoke.rs`.
#[test]
fn bare_invocation_no_longer_shows_a_stub_banner() {
    // Redirect the session's audit log into a temporary state home so this test
    // neither touches the developer's real ~/.local/state nor races any other
    // test for the same audit file.
    let state = tempfile::TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.env("XDG_STATE_HOME", state.path())
        .write_stdin("exit\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("REPL stub").not());
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
