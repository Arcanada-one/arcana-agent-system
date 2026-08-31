//! `arcana demo` completes its loop (ARAS-0062).
//!
//! The command advertises itself as demonstrating "the full driver +
//! multi-model dispatch + tool dispatch + permission cascade + audit loop".
//! It shipped demonstrating a REFUSAL: its cascade was an empty layer list,
//! and `PermissionCascade` is fail-closed, so every run ended on
//! `PermissionDenied` without a tool ever executing.

#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn demo_completes_its_loop_when_the_tool_call_is_approved() {
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .env("XDG_STATE_HOME", state.path())
        .arg("demo")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "terminal verdict: the run completed (Completed)",
        ))
        // The point of the prototype: a tool actually ran.
        .stdout(predicate::str::contains("hello world"))
        .stdout(predicate::str::contains("PermissionDenied").not());
}

#[test]
fn demo_still_refuses_when_the_tool_call_is_not_approved() {
    // Fixing the demo must not turn it into the one path where permissions are
    // waived. Without an approval directive and without a terminal, the
    // cascade denies — same as everywhere else.
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_PERMISSION_AUTO")
        .env("XDG_STATE_HOME", state.path())
        .arg("demo")
        .assert()
        .failure()
        .stdout(predicate::str::contains("PermissionDenied"));
}

#[test]
fn demo_writes_its_audit_log_under_the_per_user_state_home() {
    // It used to write to a FIXED path under the shared temp dir. A stale
    // world-readable log left there by an earlier run broke every later demo,
    // because the audit writer rightly refuses an insecure file.
    let state = TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .env("XDG_STATE_HOME", state.path())
        .arg("demo")
        .assert()
        .success()
        .stdout(predicate::str::contains("insecure permissions").not());

    let log = state.path().join("arcana/demo/audit.log");
    assert!(log.exists(), "audit log not written under the state home");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit log must be owner-only, got {mode:o}");
    }
}
