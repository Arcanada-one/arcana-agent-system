//! Black-box smoke test for ARAS-0024 / ARAS-0040: `arcana whoami` boots the
//! canonical default permission cascade (Schema -> Rule -> Interactive) and the
//! bootstrap-owned `AuditLog` (C4 / ARAS-0033) appends a correlated
//! `decision`/`result` record pair to
//! `<XDG_STATE_HOME>/arcana/audit.log`.
//!
//! ARAS-0040 corrects the F3 defect: the old tests asserted `.success()` on a
//! cascade that (headless, no TTY) actually DENIES — masking that `run_whoami`
//! returned 0 on Denial. The allow paths now set `ARCANA_PERMISSION_AUTO=allow`
//! so the cascade legitimately Allows and assert on CONTENT; a new deny path
//! asserts exit 2 plus the terminal `Denied` decision record (C4 writes the
//! deciding layer in a separate `"layer"` field, not fused into `decision`).
//!
//! The subprocess gets an isolated `XDG_STATE_HOME`/`XDG_CONFIG_HOME` per test
//! (via `Command::env`, not global `set_var`) so parallel test runs never
//! share — or fight over — a real audit log.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn audit_log_path(state_home: &Path) -> PathBuf {
    state_home.join("arcana").join("audit.log")
}

#[test]
fn whoami_allow_creates_audit_log_with_whoami_and_allowed_records() {
    let state_home = tempdir().unwrap();
    let config_home = tempdir().unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .arg("whoami")
        .env("XDG_STATE_HOME", state_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .assert()
        .success();

    let audit_log = audit_log_path(state_home.path());
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
        contents.contains("\"phase\":\"decision\"")
            && contents.contains("\"phase\":\"result\"")
            && contents.contains("\"version\":2"),
        "audit.log missing v2 decision/result pair, got: {contents}"
    );
    assert!(
        contents.contains("\"decision\":\"Allowed\""),
        "audit.log missing terminal Allowed decision record, got: {contents}"
    );
}

#[test]
fn whoami_allow_prints_identity_and_not_denied() {
    let state_home = tempdir().unwrap();
    let config_home = tempdir().unwrap();
    let expected_identity = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    Command::cargo_bin("arcana")
        .unwrap()
        .arg("whoami")
        .env("XDG_STATE_HOME", state_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .assert()
        .success()
        .stdout(predicate::str::contains("audit log:"))
        .stdout(predicate::str::contains(expected_identity))
        .stdout(predicate::str::contains("cascade denied").not());
}

#[test]
fn whoami_deny_exits_2_and_audits_denied_layer() {
    // With the auto-directive set to `deny`, the cascade legitimately Denies at
    // the interactive tail (`interactive_auto`). run_whoami must return the
    // capability-assertion exit code (2) — NOT 0 (the F3 hole) — and the
    // bootstrap-owned `AuditLog` must have written a terminal `Denied` decision
    // record naming the deciding layer (C4 / ARAS-0033: `"decision":"Denied"`
    // plus a separate `"layer":"interactive_auto"` field).
    let state_home = tempdir().unwrap();
    let config_home = tempdir().unwrap();

    Command::cargo_bin("arcana")
        .unwrap()
        .arg("whoami")
        .env("XDG_STATE_HOME", state_home.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("ARCANA_PERMISSION_AUTO", "deny")
        .assert()
        .code(2)
        .stdout(predicate::str::contains("cascade denied"))
        .stdout(predicate::str::contains("audit log:"));

    let audit_log = audit_log_path(state_home.path());
    assert!(
        audit_log.exists(),
        "expected audit.log at {}",
        audit_log.display()
    );
    let contents = fs::read_to_string(&audit_log).unwrap();
    assert!(
        contents.contains("\"decision\":\"Denied\""),
        "audit.log missing terminal Denied decision record, got: {contents}"
    );
    assert!(
        contents.contains("\"layer\":\"interactive_auto\""),
        "Denied record must name the deciding layer, got: {contents}"
    );
}
