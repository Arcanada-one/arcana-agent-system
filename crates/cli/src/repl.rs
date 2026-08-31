//! `arcana` with no subcommand — the interactive REPL (ARAS-0059).
//!
//! This module owns the *interaction* only. The agent loop it drives is the
//! existing one: it builds a single [`Session`](crate::demo::Session) — the
//! same composition `arcana demo` uses (real [`Driver`], multi-model
//! `ModelPolicy`, fused `CapabilityExecutor` owning the tool dispatcher,
//! permission cascade and audit log) — and runs one task per line against it.
//! **No second agent-loop driver is introduced here**; that was the explicit
//! constraint on this work, since a parallel driver would immediately drift
//! from the audited one.
//!
//! Building the session ONCE (rather than per line) is what makes this a
//! session rather than a loop around `arcana demo`: the audit log is a single
//! append-only file for the whole conversation, and the `CostTracker`
//! accumulates spend across turns instead of resetting on each one.
//!
//! ## Terminal and non-terminal stdin
//!
//! On a TTY the prompt is `rustyline` (already a dependency, and already used
//! by the permission cascade), giving line editing and in-memory history.
//! When stdin is NOT a terminal — a pipe, a heredoc, CI — `rustyline` cannot
//! run, so the REPL reads plain lines from stdin instead. That path is what
//! keeps `echo 'task' | arcana` predictable rather than hanging or erroring,
//! and it is what the tests drive.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use arcana_core::agent_loop::DriverConfig;
use arcana_core::dispatch::ModelPolicy;

use crate::demo::{PermissionMode, Session};
use crate::usage::TurnSpend;

/// Fallback audit directory when the XDG state home cannot be resolved.
const FALLBACK_STATE_DIR: &str = ".arcana-state";

/// Resolve the directory the interactive session writes its audit log to.
///
/// This is the per-user XDG state home (`~/.local/state/arcana`, honouring
/// `XDG_STATE_HOME`) — the same place `bootstrap::assemble` puts `whoami`'s
/// log, and deliberately NOT a fixed path under the shared system temp dir. A
/// predictable `/tmp` path is both a multi-user hazard on a shared host and a
/// race between concurrent sessions: an earlier revision of this module used
/// one, and ten parallel integration tests promptly raced on it.
fn audit_dir() -> PathBuf {
    xdg::BaseDirectories::with_prefix("arcana").map_or_else(
        |_| PathBuf::from(FALLBACK_STATE_DIR),
        |base| base.get_state_home(),
    )
}

/// Connector id recorded on interactive turns.
/// Connector the interactive session dispatches through.
///
/// This is a CONNECTOR id, not a route label: `DriverConfig::connector_id` goes
/// straight onto the wire (`agent_loop.rs`, `ExecuteRequest::new`). It used to
/// read `arcana-repl`, which no connector answers to, so every live turn came
/// back `404 Connector "arcana-repl" not found` — collapsed to `ConnectorFatal`
/// with the message discarded, which is why the session appeared to fail for no
/// reason while `curl` to the same endpoint succeeded.
///
/// `orq` is the id every working path already uses: `kb_read.rs` names it as a
/// constant and asserts that every request it issues goes there.
const REPL_CONNECTOR_ID: &str = "orq";

/// The prompt shown on a terminal.
const PROMPT: &str = "arcana> ";

/// What a line of input asks the REPL to do.
///
/// Split out as a pure function so the control vocabulary is unit-testable
/// without a terminal, a connector, or an agent loop.
#[derive(Debug, PartialEq, Eq)]
pub enum Action<'a> {
    /// Blank or whitespace-only — redisplay the prompt, do not spend a turn.
    Skip,
    /// An explicit exit word.
    Exit,
    /// A task to drive through the agent loop.
    Task(&'a str),
}

/// Classify one line of REPL input.
///
/// `exit`, `quit` and `:q` are the exit words, matched case-insensitively
/// after trimming. Everything else that is not blank is a task — the REPL
/// deliberately has no command prefix, because its subject matter is
/// natural-language tasks and stealing a prefix from them would be a
/// long-lived papercut.
#[must_use]
pub fn classify(line: &str) -> Action<'_> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Action::Skip;
    }
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "exit" | "quit" | ":q"
    ) {
        return Action::Exit;
    }
    Action::Task(trimmed)
}

/// Entry point for the no-subcommand invocation. Returns a process exit code.
///
/// `0` when the session stood up and every turn it ran reached
/// [`TerminalReason::Completed`]. `1` when the session could not be built, or
/// when any turn ended on some other verdict.
///
/// This used to return `0` unconditionally on a clean session end, on the
/// argument that a failed task is a printed result rather than a failed
/// session. That reasoning does not survive contact with a script:
/// `printf 'task\n' | arcana --live` against an out-of-credit key printed
/// `ConnectorFatal` and exited `0`, so `arcana ... && deploy` deployed.
/// `arcana demo` already exits `1` on the identical condition, and two
/// commands wrapping the same driver must not disagree about what failure is.
#[must_use]
pub fn run_repl(live: bool) -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("arcana: failed to start async runtime: {err}");
            return 1;
        }
    };

    let Some(session) = Session::build(live, false, audit_dir(), PermissionMode::Interactive)
    else {
        return 1;
    };

    println!(
        "arcana {} — interactive session. `exit` or Ctrl-D to leave.",
        env!("CARGO_PKG_VERSION")
    );
    println!("audit log: {}", session.audit_log_path().display());

    if std::io::stdin().is_terminal() {
        run_terminal(&runtime, &session)
    } else {
        run_piped(&runtime, &session)
    }
}

/// Tracks whether any turn in the session ended on a non-`Completed` verdict.
///
/// Held by the reader loops and folded into the process exit code, so a
/// session whose turns all failed cannot report success.
#[derive(Default)]
struct SessionOutcome {
    any_turn_failed: bool,
}

impl SessionOutcome {
    /// `0` when every turn completed, `1` when any did not.
    const fn exit_code(&self) -> i32 {
        if self.any_turn_failed {
            1
        } else {
            0
        }
    }
}

/// Interactive path: `rustyline` owns the prompt, history and key handling.
fn run_terminal(runtime: &tokio::runtime::Runtime, session: &Session) -> i32 {
    use rustyline::error::ReadlineError;

    let mut spend = crate::usage::zero_snapshot();
    let mut outcome = SessionOutcome::default();

    let mut editor = match rustyline::DefaultEditor::new() {
        Ok(editor) => editor,
        Err(err) => {
            // A terminal that rustyline cannot drive is not a reason to die:
            // fall back to the plain reader rather than denying the operator a
            // session.
            eprintln!("arcana: line editor unavailable ({err}); falling back to plain input");
            return run_piped(runtime, session);
        }
    };

    loop {
        match editor.readline(PROMPT) {
            Ok(line) => {
                match classify(&line) {
                    Action::Skip => {}
                    Action::Exit => break,
                    Action::Task(task) => {
                        // Ignore a history-write failure: losing a history entry
                        // must never abort the operator's session.
                        let _ = editor.add_history_entry(task);
                        drive(runtime, session, task, &mut spend, &mut outcome);
                    }
                }
            }
            // Ctrl-C abandons the current line, as in every other REPL; it does
            // not end the session (Ctrl-D / `exit` do).
            Err(ReadlineError::Interrupted) => {}
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("arcana: input error: {err}");
                return 1;
            }
        }
    }
    println!("bye");
    outcome.exit_code()
}

/// Non-terminal path: plain line reads from stdin, no prompt, no history.
fn run_piped(runtime: &tokio::runtime::Runtime, session: &Session) -> i32 {
    let mut spend = crate::usage::zero_snapshot();
    let mut outcome = SessionOutcome::default();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("arcana: input error: {err}");
                return 1;
            }
        };
        match classify(&line) {
            Action::Skip => {}
            Action::Exit => break,
            Action::Task(task) => drive(runtime, session, task, &mut spend, &mut outcome),
        }
    }
    outcome.exit_code()
}

/// Run one task through the shared session and print the outcome.
///
/// `previous` carries the session's cumulative cost as of the last turn, so the
/// spend line can report THIS turn rather than everything so far.
fn drive(
    runtime: &tokio::runtime::Runtime,
    session: &Session,
    task: &str,
    previous: &mut arcana_core::cost::CostSnapshot,
    outcome: &mut SessionOutcome,
) {
    // ARAS-0065 — honour the operator's chosen model. Without this the
    // preference would be a file nothing reads: `arcana models use` would
    // report success and change nothing about what the agent actually calls.
    //
    // An EXPLICIT choice pins the policy to that single model. Setting
    // `config.model` alone is not enough: it only supplies the policy's
    // `Default` fallback, so task-typed turns keep routing to the tiered
    // models and the operator's choice is silently ignored on exactly the
    // turns that cost money.
    //
    // With no explicit choice, the tiered policy is left alone — defaulting
    // into single-model would disable cost-tiered dispatch for everyone who
    // never ran `models use`.
    let mut config = DriverConfig::new(REPL_CONNECTOR_ID);
    if let Some(chosen) = crate::models::explicit_model() {
        config.policy = ModelPolicy::single_model(&chosen);
        config.model = Some(chosen);
    }
    let out = runtime.block_on(session.run_task(task, config));

    // ARAS-0065 — say which model answered. Without this the operator's choice
    // is unobservable: `models use` could silently fail to reach the loop and
    // nothing on screen would differ.
    if !out.selected_models.is_empty() {
        println!("[{}]", out.selected_models.join(" -> "));
    }

    match out.final_text.as_deref() {
        Some(text) => println!("{text}"),
        // A run that ended without final text still has to say something, or
        // the operator is left staring at a silent prompt wondering whether
        // anything ran at all.
        None => println!("(no final text — {})", out.reason),
    }
    // ARAS-0066 — what this turn cost, and the session so far. Shown even on a
    // failed turn: a turn that burned tokens and then failed still spent money,
    // and hiding that would understate the bill.
    let turn = TurnSpend::between(previous, &out.cost);
    println!(
        "{}",
        crate::usage::turn_line(&turn, out.cost.total_cost_usd_micros)
    );
    *previous = out.cost;

    if !out.reason.is_success() {
        outcome.any_turn_failed = true;
        eprintln!("arcana: turn ended — {} ({:?})", out.reason, out.reason);
    }
    // Interactive output is read as it appears, so flush rather than waiting
    // for the buffer to fill.
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::{classify, Action};

    #[test]
    fn blank_and_whitespace_lines_are_skipped() {
        assert_eq!(classify(""), Action::Skip);
        assert_eq!(classify("   "), Action::Skip);
        assert_eq!(classify("\t \n"), Action::Skip);
    }

    #[test]
    fn exit_words_end_the_session_case_insensitively() {
        for word in ["exit", "quit", ":q", "EXIT", "Quit", "  exit  "] {
            assert_eq!(classify(word), Action::Exit, "expected {word:?} to exit");
        }
    }

    #[test]
    fn ordinary_input_is_a_task_and_is_trimmed() {
        assert_eq!(
            classify("  summarise the readme  "),
            Action::Task("summarise the readme")
        );
    }

    #[test]
    fn a_task_that_merely_contains_an_exit_word_is_not_an_exit() {
        // Guards the obvious over-match: substring testing here would silently
        // truncate a real task.
        assert_eq!(
            classify("explain how to exit vim"),
            Action::Task("explain how to exit vim")
        );
    }
}
