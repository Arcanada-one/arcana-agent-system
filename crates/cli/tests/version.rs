#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_subcommand_prints_version_sha_and_license() {
    // Accepts both provenance states, because the test suite runs from clean
    // checkouts in CI and from working trees on a developer's box, and pinning
    // only the clean form would fail locally for a reason that is not a defect.
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    // Pin the SHAPE, not a literal version: hard-coding the number turns every
    // release bump into a spurious test failure, and a stale literal would let a
    // binary built at the wrong version pass.
    let version = env!("CARGO_PKG_VERSION").replace('.', r"\.");
    cmd.arg("version").assert().success().stdout(
        // Both halves are load-bearing. The version comes from CARGO_PKG_VERSION
        // so a release bump is not a spurious failure, and `-dirty` is optional
        // with no `$` anchor because a dirty build prints a second warning line.
        predicate::str::is_match(format!(
            r"^arcana {version} \([0-9a-f]{{7}}(-dirty)?\) — MIT OR Apache-2\.0\n"
        ))
        .unwrap(),
    );
}

/// The stamp and the warning must agree.
///
/// `arcana version` is the provenance primitive: signing, attestation and the
/// documented verified-install path all end with someone reading this line. It
/// used to print an identical string whether or not the tree carried
/// uncommitted changes, so a binary containing code present in no commit
/// claimed that commit (proved by building one: same version output, different
/// sha256, carrying a marker string absent from every commit).
///
/// Asserting the PAIRING rather than either half is what makes this hold in
/// both environments: a `-dirty` stamp without the warning, or a warning
/// without the stamp, is the regression.
#[test]
fn a_dirty_build_says_so_and_a_clean_one_does_not() {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    let output = cmd.arg("version").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let stamped_dirty = stdout.lines().next().unwrap().contains("-dirty");
    let warned = stdout.contains("does not correspond to");

    assert_eq!(
        stamped_dirty, warned,
        "the -dirty stamp and the provenance warning must agree; got: {stdout:?}"
    );
    if !stamped_dirty {
        assert!(
            stdout.lines().count() == 1,
            "a clean build must print exactly the one version line, got: {stdout:?}"
        );
    }
}

/// The rebuild triggers must be resolved through git, not hand-built.
///
/// In a linked worktree `.git` is a file, so the previous literal
/// `../../.git/HEAD` and `../../.git/refs/heads` resolved to nothing and the
/// `rerun-if-changed` they fed never fired — letting a cached stamp outlive the
/// commit it names. Worktrees are how this repo is built day to day.
#[test]
fn build_script_resolves_git_paths_instead_of_guessing_them() {
    let build_rs =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs"))
            .unwrap();
    // Comments necessarily NAME the old path to explain why it was replaced, so
    // assert against code lines only — otherwise the prose keeps this red.
    let code: String = build_rs
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(code.contains("--git-path"), "must ask git for the path");
    assert!(
        !code.contains("../../.git/"),
        "hand-built .git paths do not exist in a worktree"
    );
    // Fail-closed dirty detection: unable to consult git must mean "assume
    // dirty", never "assume clean".
    // `is_none_or` encodes it: None (git unavailable) => dirty, never clean.
    assert!(code.contains("is_none_or"), "dirty check must fail closed");
}

#[test]
fn version_flag_prints_clap_version_line() {
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with(format!(
            "arcana {}",
            env!("CARGO_PKG_VERSION")
        )));
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
