#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_subcommand_prints_version_line() {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.arg("version")
        .assert()
        .success()
        .stdout("arcana 0.1.0\n");
}

#[test]
fn bare_invocation_shows_repl_stub_banner() {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("REPL stub"));
}
