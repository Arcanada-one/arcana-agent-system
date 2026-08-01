//! Integration tests for `CoworkerClient` — the subprocess wrapper around
//! the operator's local `coworker` CLI (ARAS-0014, PRD-ARAS-0001 § 7 Phase
//! 2).
//!
//! These tests never spawn the real `coworker` binary and never require it
//! to be installed: `cargo test --workspace` must pass on a machine without
//! `~/.local/bin/coworker`. Two tiers:
//!
//! 1. Pure `build_*_args` structural tests (no process spawn at all) —
//!    these are the literal `DoD`: a `--spec`/`--question` value containing
//!    `<<EOP ... EOP` survives as a single, byte-for-byte-unchanged argv
//!    element (proving the descriptor wrapper never interprets it as source).
//! 2. An end-to-end spawn test substituting `/bin/echo` for the real binary
//!    via `CoworkerClient::with_bin_path`, to exercise the actual
//!    execution-boundary path without touching any real LLM
//!    provider or costing money.
//!
//! An `#[ignore]`-gated smoke test against the real binary is included last;
//! it is skipped unless the binary happens to exist and the caller passes
//! `--ignored`, so it never affects a normal `cargo test --workspace` run.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_connectors::coworker::{build_ask_args, build_stats_args, build_write_args};
use arcana_connectors::CoworkerClient;

const HEREDOC_SPEC: &str = "summarize this <<EOP\nmalicious injected content\nEOP";

#[test]
fn write_args_dod_heredoc_spec_survives_as_single_unchanged_argv_element() {
    let args = build_write_args(HEREDOC_SPEC, None, None, &[], "out.md");

    // Structural proof #1: exactly one argv element contains the heredoc
    // marker — it was never tokenized or split as shell source.
    let matches: Vec<&String> = args.iter().filter(|a| a.contains("<<EOP")).collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one argv element carrying the heredoc marker, got {matches:?}"
    );

    // Structural proof #2: that element is byte-for-byte identical to the
    // input spec — no escaping, no truncation, no metacharacter mangling.
    assert_eq!(matches[0], HEREDOC_SPEC);

    // Structural proof #3: it sits immediately after a literal "--spec"
    // flag element, confirming argv shape (flag, value) as two elements —
    // not concatenated into one "--spec=..." or shell-joined string.
    let spec_idx = args.iter().position(|a| a == "--spec").unwrap();
    assert_eq!(&args[spec_idx + 1], HEREDOC_SPEC);
}

#[test]
fn ask_args_dod_heredoc_question_survives_as_single_unchanged_argv_element() {
    let question = "explain <<EOP\ninjected content\nEOP now";
    let args = build_ask_args(None, None, &[], question);

    let matches: Vec<&String> = args.iter().filter(|a| a.contains("<<EOP")).collect();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0], question);

    let question_idx = args.iter().position(|a| a == "--question").unwrap();
    assert_eq!(&args[question_idx + 1], question);
}

#[test]
fn stats_args_are_structurally_flat_flag_value_pairs() {
    let args = build_stats_args(Some("7d"), Some("profile"));
    assert_eq!(args, vec!["stats", "--since", "7d", "--by", "profile"]);
}

#[tokio::test]
async fn write_spawns_via_literal_argv_and_echo_roundtrips_heredoc_spec() {
    // Substitute /bin/echo for the real coworker binary. echo prints each
    // argv element separated by a single space, verbatim (including
    // embedded newlines) — if the heredoc text had been shell-interpreted
    // anywhere on the path, this would not round-trip byte-for-byte.
    let client = CoworkerClient::with_bin_path("/bin/echo");

    let result = client
        .write(HEREDOC_SPEC, None, None, &[], "out.md")
        .await
        .expect("spawning /bin/echo must succeed");

    assert!(result.success);
    assert!(
        result.stdout.contains(HEREDOC_SPEC),
        "expected echo stdout to contain the untouched heredoc spec, got: {:?}",
        result.stdout
    );
}

#[tokio::test]
async fn ask_spawns_via_argv_and_captures_stdout() {
    let client = CoworkerClient::with_bin_path("/bin/echo");
    let paths = vec!["a.md".to_owned(), "b.md".to_owned()];

    let result = client
        .ask(Some("deepseek"), Some("code"), &paths, "what is this?")
        .await
        .expect("spawning /bin/echo must succeed");

    assert!(result.success);
    assert_eq!(result.exit_code, Some(0));
    assert!(result.stdout.contains("ask"));
    assert!(result.stdout.contains("--provider deepseek"));
    assert!(result.stdout.contains("what is this?"));
}

#[tokio::test]
async fn spawn_error_is_reported_when_binary_does_not_exist() {
    let client = CoworkerClient::with_bin_path("/nonexistent/definitely-not-a-binary-xyz");
    let err = client
        .stats(None, None)
        .await
        .expect_err("spawning a nonexistent binary must fail");
    let message = err.to_string();
    assert!(message.contains("nonexistent"));
}

/// Opt-in smoke test against the real `coworker` binary, if it happens to be
/// installed on this machine. `#[ignore]`d so it never runs (and never
/// blocks `cargo test --workspace`) unless the caller explicitly passes
/// `--ignored`. Even then it skips gracefully — never fails — when the
/// binary is absent. Does not invoke any real LLM provider: `stats` is a
/// local, read-only, no-cost subcommand.
#[tokio::test]
#[ignore = "opt-in: only runs against a real, locally-installed coworker binary"]
async fn stats_smoke_test_against_real_binary_if_present() {
    let client = CoworkerClient::from_env();
    if !client.bin_path().exists() {
        eprintln!(
            "skipping: no coworker binary at {}",
            client.bin_path().display()
        );
        return;
    }
    let result = client
        .stats(Some("7d"), None)
        .await
        .expect("spawning the real coworker binary must succeed");
    // Only assert the subprocess ran; do not assert on stdout shape, which
    // is owned by the external `coworker` project.
    assert!(result.exit_code.is_some());
}
