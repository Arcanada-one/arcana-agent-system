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

/// `demo` must account for what it spent, and must not invent a charge.
///
/// It charged the account and printed nothing — on the command a first-time
/// user is told to run, dispatching on the expensive tier, so it was both the
/// priciest invocation and the only silent one. The interactive session had
/// shown per-turn spend all along.
///
/// The offline half matters just as much: the offline connector reports a
/// synthetic cost, and rendering that as money would invent a charge that never
/// happened. On a metered product that is the worse error of the two.
#[test]
fn an_offline_demo_states_that_nothing_was_charged() {
    let state = tempfile::TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env("XDG_STATE_HOME", state.path())
        .arg("demo")
        .assert()
        .stdout(predicate::str::contains("nothing was charged"))
        // No dollar figure anywhere: an offline run has no price.
        .stdout(predicate::str::contains("$").not());
}

/// `--live` that cannot go live must FAIL, not quietly go offline.
///
/// It used to print `(live requested but ARCANA_MC_TOKEN unset; using offline
/// demo)`, replay the canned offline script, and exit `0`. The first line said
/// so and every later line — including the terminal verdict and the exit code
/// a wrapper reads — described a live run that never happened. This test was
/// the one asserting that behaviour; it now asserts the opposite, which is the
/// only honest reading of an unmet requirement.
#[test]
fn live_requested_without_a_token_fails_instead_of_falling_back() {
    let state = tempfile::TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        .env_remove("ARCANA_MC_TOKEN")
        .env("XDG_STATE_HOME", state.path())
        .args(["demo", "--live"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ARCANA_MC_TOKEN"))
        // Nothing ran, so nothing may be reported about a run.
        .stdout(predicate::str::contains("ATTEMPT").not());
}

/// The same lie in its costlier costume: with a key present but the Model
/// Connector origin refused by the production pin, the offline replay also
/// produced a `$0.002000 this turn` billing line for a dispatch that never
/// left the machine.
#[test]
fn live_requested_against_an_unapproved_origin_fails_and_invents_no_charge() {
    let state = tempfile::TempDir::new().unwrap();
    Command::cargo_bin("arcana")
        .unwrap()
        // Not a credential: only long enough to reach the base-URL check.
        .env("ARCANA_MC_TOKEN", "not-a-real-key")
        .env("ARCANA_MC_BASE_URL", "http://127.0.0.1:9")
        .env("XDG_STATE_HOME", state.path())
        .args(["demo", "--live"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not approved"))
        .stdout(predicate::str::contains("$").not());
}
