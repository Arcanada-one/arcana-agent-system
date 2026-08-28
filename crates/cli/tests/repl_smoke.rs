//! End-to-end checks for the interactive session (`arcana` with no subcommand).
//!
//! These drive the non-TTY path deliberately: `assert_cmd` gives the child a
//! pipe, not a terminal, which is exactly the branch that has to stay
//! predictable in CI. The TTY branch differs only in who supplies the line
//! (`rustyline`) and who answers a permission prompt (the operator).

#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// A task carrying the code signal the offline demo connector replies to.
const TASK: &str = "implement a greeting in rust: echo the world back";

/// An `arcana` command whose audit log is redirected into a per-test temporary
/// state home.
///
/// Cargo runs these tests in parallel, so they MUST NOT share an audit
/// directory: an earlier revision let every test write to one fixed path under
/// the system temp dir and they raced (`audit file open failed: No such file or
/// directory`) on macOS. Isolating per test also keeps the suite off the
/// developer's real `~/.local/state`.
fn arcana(state: &TempDir) -> Command {
    let mut command = Command::cargo_bin("arcana").unwrap();
    command.env("XDG_STATE_HOME", state.path());
    command
}

/// The REPL must no longer print the placeholder it shipped as through 0.1.0.
#[test]
fn bare_invocation_is_no_longer_a_stub() {
    let state = TempDir::new().unwrap();
    arcana(&state)
        .write_stdin("exit\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("REPL stub").not())
        .stdout(predicate::str::contains("coming soon").not());
}

/// The banner names the session and how to leave it.
#[test]
fn bare_invocation_opens_a_session() {
    let state = TempDir::new().unwrap();
    arcana(&state)
        .write_stdin("exit\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("interactive session"))
        .stdout(predicate::str::contains("audit log:"));
}

/// End of piped input is the non-TTY equivalent of Ctrl-D: a clean exit, not a
/// hang and not an error.
#[test]
fn end_of_input_exits_cleanly_without_an_exit_word() {
    let state = TempDir::new().unwrap();
    arcana(&state).write_stdin("").assert().success();
}

/// Each exit word ends the session on its own.
#[test]
fn every_exit_word_ends_the_session() {
    for word in ["exit", "quit", ":q"] {
        Command::cargo_bin("arcana")
            .unwrap()
            .write_stdin(format!("{word}\n"))
            .assert()
            .success();
    }
}

/// The whole point of the task: a line of input drives the REAL agent loop and
/// the operator sees the model's final text. `ARCANA_PERMISSION_AUTO=allow`
/// stands in for the operator approving the tool call at the interactive tail.
#[test]
fn a_task_line_runs_the_agent_loop_and_prints_the_result() {
    let state = TempDir::new().unwrap();
    arcana(&state)
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .write_stdin(format!("{TASK}\nexit\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("hello world"));
}

/// The cascade is fail-closed: with no directive and no terminal to ask, the
/// tool call is denied and the session says so rather than pretending to
/// succeed. This is the negative control for the test above — without it,
/// that test could pass on a cascade that allows everything.
#[test]
fn without_an_approval_directive_the_tool_call_is_denied() {
    let state = TempDir::new().unwrap();
    arcana(&state)
        .env_remove("ARCANA_PERMISSION_AUTO")
        .write_stdin(format!("{TASK}\nexit\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("hello world").not())
        .stdout(predicate::str::contains("PermissionDenied"));
}

/// An explicit deny directive is honoured too — proving the directive is read
/// rather than the allow case being a coincidence of some other default.
#[test]
fn an_explicit_deny_directive_is_honoured() {
    let state = TempDir::new().unwrap();
    arcana(&state)
        .env("ARCANA_PERMISSION_AUTO", "deny")
        .write_stdin(format!("{TASK}\nexit\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("hello world").not());
}

/// Blank lines cost nothing and do not end the session: the task after them
/// still runs.
#[test]
fn blank_lines_are_skipped_without_ending_the_session() {
    let state = TempDir::new().unwrap();
    arcana(&state)
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .write_stdin(format!("\n   \n{TASK}\nexit\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("hello world"));
}

/// Several tasks run against ONE session — the property that distinguishes a
/// session from a loop around `arcana demo`.
#[test]
fn successive_tasks_run_against_one_session() {
    let state = TempDir::new().unwrap();
    arcana(&state)
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .write_stdin(format!("{TASK}\n{TASK}\nexit\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("hello world").count(2));
}

/// Input after an exit word is not executed — `exit` means exit.
#[test]
fn input_after_an_exit_word_is_not_executed() {
    let state = TempDir::new().unwrap();
    arcana(&state)
        .env("ARCANA_PERMISSION_AUTO", "allow")
        .write_stdin(format!("exit\n{TASK}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("hello world").not());
}
