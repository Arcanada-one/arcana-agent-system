//! Black-box smoke test for ARAS-0024: `arcana whoami` boots the canonical
//! default permission cascade (Schema -> HookBridge -> Rule -> Interactive)
//! and the `HookBridge` layer's `AuditHook` appends a record to
//! `<XDG_STATE_HOME>/arcana/audit.log`.
//!
//! The subprocess gets an isolated `XDG_STATE_HOME`/`XDG_CONFIG_HOME` per
//! test (via `Command::env`, not global `set_var`) so parallel test runs
//! never share — or fight over — a real audit log.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn whoami_smoke_creates_audit_log_with_whoami_record() {
    let state_home = tempdir().unwrap();
    let config_home = tempdir().unwrap();

    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.arg("whoami")
        .env("XDG_STATE_HOME", state_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .assert()
        .success();

    let audit_log = state_home.path().join("arcana").join("audit.log");
    assert!(
        audit_log.exists(),
        "expected audit.log at {}",
        audit_log.display()
    );

    let contents = fs::read_to_string(&audit_log).unwrap();
    assert!(
        contents.contains("\"tool\":\"whoami\""),
        "audit.log missing whoami record, got: {contents}"
    );
    assert!(
        contents.contains("\"phase\":\"pre\""),
        "audit.log missing pre-tool phase, got: {contents}"
    );
}

#[test]
fn whoami_smoke_prints_cascade_outcome() {
    let state_home = tempdir().unwrap();
    let config_home = tempdir().unwrap();

    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.arg("whoami")
        .env("XDG_STATE_HOME", state_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("audit log:"));
}
