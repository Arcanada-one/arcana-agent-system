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

// Was `login_subcommand_prints_stub_notice`, which asserted the "not yet
// implemented" placeholder — i.e. it encoded the stub as intent and would have
// stayed green forever. ARAS-0060 implements the device-code flow, so the
// assertion is inverted: a stub notice is now a regression. The flow itself is
// covered against a mock provider in `login_smoke.rs`.
#[test]
fn login_subcommand_is_no_longer_a_stub() {
    let state = tempfile::TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    // Point at a closed port: hermetic, and no network call to the real IdP.
    cmd.env("ARCANA_AUTH_ISSUER", "http://127.0.0.1:1")
        .env("XDG_STATE_HOME", state.path())
        .arg("login")
        .assert()
        .failure()
        .stdout(predicate::str::contains("not yet implemented").not())
        .stderr(predicate::str::contains("not yet implemented").not());
}

// Public-surface hygiene: internal task IDs must never reach a user. This rule
// outlived the stub and caught a real leak — the first cut of the ARAS-0060
// fail-closed message named its own task ID in stderr. Kept, widened to stderr
// (where the message now lives), and made hermetic.
#[test]
fn login_output_omits_internal_task_ids() {
    let state = tempfile::TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.env("ARCANA_AUTH_ISSUER", "http://127.0.0.1:1")
        .env("XDG_STATE_HOME", state.path())
        .arg("login")
        .assert()
        .failure()
        .stdout(
            predicate::str::is_match(r"\b(ARAS|AUTH)-\d{4}\b")
                .unwrap()
                .not(),
        )
        .stderr(
            predicate::str::is_match(r"\b(ARAS|AUTH)-\d{4}\b")
                .unwrap()
                .not(),
        );
}
