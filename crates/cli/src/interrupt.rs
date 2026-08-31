//! SIGINT handling for the billable commands (ARAS / issue #105).
//!
//! Before this module, nothing in the CLI installed a signal handler. Ctrl-C
//! during a live turn killed the process where it stood: the request already on
//! the wire completed at the Model Connector and was charged, the local audit
//! log gained nothing, and the operator was told nothing about either. The
//! `CancellationToken` the driver takes was always a freshly constructed one
//! that no caller kept a handle to, so `TerminalReason::AbortedByOperator` was
//! unreachable in production.
//!
//! ## What Ctrl-C now means
//!
//! **It does not unsend the request.** Nothing can: once the dispatch is on the
//! wire the connector runs it to completion and bills it whether or not this
//! process is alive to read the answer. Killing ourselves faster does not save
//! the money, it only destroys the evidence — and, measured on this product,
//! the charge lands in the ledger five to ten seconds *after* the process is
//! already gone.
//!
//! So the first Ctrl-C cancels the run and then WAITS for the in-flight reply,
//! which is what turns "you may have been charged" into an exact figure on the
//! spend line. The operator is told immediately that this is what is happening,
//! because a Ctrl-C that appears to do nothing for ten seconds is its own bug.
//! A second Ctrl-C exits at once, so the wait can never become a hang.
//!
//! ## Why a dedicated thread
//!
//! The signal listener runs its own current-thread runtime on its own thread.
//! The CLI's main runtime is only driven inside `block_on`, so a listener task
//! spawned there would be scheduled during a turn and nowhere else — including
//! while the piped reader is blocked on stdin, where an un-handled SIGINT is
//! the operator's only way out.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

/// Exit status for death by SIGINT, per the shell convention (128 + 2).
pub const EXIT_INTERRUPTED: i32 = 130;

/// Printed on the first Ctrl-C of a turn.
///
/// Says the three things the operator cannot otherwise know: that the request
/// is already gone and will be billed, that the wait is deliberate and bounded
/// by the reply, and how to leave immediately anyway.
const FIRST_NOTICE: &str = "\
arcana: interrupt received — stopping after the request already sent.
        That request will be charged whether or not this process waits, so it
        waits for the reply and reports the amount. Press Ctrl-C again to exit
        now (the charge still applies, you just will not be shown it).";

/// The slot the signal listener cancels, plus the process-wide install latch.
struct Shared {
    /// `Some` only while a turn is running. `None` between turns, where a
    /// Ctrl-C means "leave" rather than "abort this turn".
    turn: Mutex<Option<CancellationToken>>,
}

/// Handle to the installed SIGINT listener.
#[derive(Clone)]
pub struct Interrupt {
    shared: Arc<Shared>,
}

/// Marks a turn as interruptible for as long as it is held.
///
/// Clearing the slot on drop is what makes a Ctrl-C between turns exit instead
/// of cancelling a token nothing is reading, and what lets the NEXT turn start
/// from an uncancelled token — a `CancellationToken` is one-shot, so reusing
/// one across turns would abort every turn after the first.
pub struct TurnGuard {
    shared: Arc<Shared>,
}

impl Drop for TurnGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.shared.turn.lock() {
            *slot = None;
        }
    }
}

/// Set once the listener thread is running, so a second `install` is a no-op
/// rather than a second thread racing for the same signal.
static INSTALLED: AtomicBool = AtomicBool::new(false);

impl Interrupt {
    /// Install the SIGINT listener and return a handle to it.
    ///
    /// Returns `None` when the listener could not be started; the caller keeps
    /// working with the default disposition (Ctrl-C kills the process, as
    /// before) rather than refusing to run. Failing to arm an abort path is not
    /// a reason to deny the operator the command.
    #[must_use]
    pub fn install() -> Option<Self> {
        if INSTALLED.swap(true, Ordering::SeqCst) {
            return None;
        }
        let shared = Arc::new(Shared {
            turn: Mutex::new(None),
        });
        let listener = Arc::clone(&shared);
        let started = std::thread::Builder::new()
            .name("arcana-sigint".to_owned())
            .spawn(move || listen(&listener));
        match started {
            Ok(_handle) => Some(Self { shared }),
            Err(err) => {
                eprintln!("arcana: could not install the interrupt handler ({err}); Ctrl-C will end the process without reporting the spend");
                INSTALLED.store(false, Ordering::SeqCst);
                None
            }
        }
    }

    /// Arm a turn: returns the token to hand the driver, and the guard that
    /// disarms on drop.
    #[must_use]
    pub fn arm(&self) -> (CancellationToken, TurnGuard) {
        let token = CancellationToken::new();
        if let Ok(mut slot) = self.shared.turn.lock() {
            *slot = Some(token.clone());
        }
        (
            token,
            TurnGuard {
                shared: Arc::clone(&self.shared),
            },
        )
    }
}

/// What one SIGINT means, given what is running.
///
/// Split from the acting on it so all three cases are testable: the `Exit` arm
/// calls `process::exit`, which cannot be asserted from inside a test binary
/// without taking the whole harness down with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// A turn was armed and had not yet been cancelled: stop it and stay alive
    /// so the reply can be waited for and the spend reported.
    CancelTurn,
    /// Nothing is running, or this is the second Ctrl-C of the same turn.
    Leave,
}

/// The listener loop. One rule: if a live, not-yet-cancelled turn is armed,
/// cancel it; otherwise leave.
fn listen(shared: &Arc<Shared>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    runtime.block_on(async {
        let Ok(mut signals) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        else {
            return;
        };
        while signals.recv().await.is_some() {
            match decide(shared) {
                Decision::CancelTurn => {}
                Decision::Leave => std::process::exit(EXIT_INTERRUPTED),
            }
        }
    });
}

/// Decide what one SIGINT means, and cancel the turn if that is the answer.
fn decide(shared: &Arc<Shared>) -> Decision {
    let armed = match shared.turn.lock() {
        Ok(slot) => slot.clone(),
        // A poisoned lock means a turn panicked while holding it. Leaving is
        // the safe reading: we cannot prove a turn is still running, and
        // swallowing the signal here would make Ctrl-C do nothing at all.
        Err(_) => None,
    };
    match armed {
        Some(token) if !token.is_cancelled() => {
            eprintln!("{FIRST_NOTICE}");
            token.cancel();
            Decision::CancelTurn
        }
        // Either nothing is running, or this is the second Ctrl-C of a turn
        // whose reply has not come back yet.
        _ => Decision::Leave,
    }
}

/// Process exit code for a finished run.
///
/// Lives here because the abort code is the reason it exists: three commands
/// each derived their own code from `is_success()`, so an operator abort would
/// have surfaced as a plain `1` — indistinguishable from a connector failure,
/// and wrong for a shell that reads `130` as "the user stopped it".
#[must_use]
pub fn exit_code(reason: arcana_core::agent_loop::TerminalReason) -> i32 {
    use arcana_core::agent_loop::TerminalReason;
    match reason {
        TerminalReason::AbortedByOperator => EXIT_INTERRUPTED,
        other => i32::from(!other.is_success()),
    }
}

/// Arm a turn against an optional listener.
///
/// Returns the token to hand the driver and a guard to hold for the duration of
/// the run. With no listener (installation failed, or a second `install` in the
/// same process) the token is a plain uncancelled one, so the caller's code
/// path does not fork on whether signals are available.
#[must_use]
pub fn arm(interrupt: Option<&Interrupt>) -> (CancellationToken, Option<TurnGuard>) {
    interrupt.map_or_else(
        || (CancellationToken::new(), None),
        |listener| {
            let (token, guard) = listener.arm();
            (token, Some(guard))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{decide, Decision, Shared};
    use std::sync::{Arc, Mutex};
    use tokio_util::sync::CancellationToken;

    fn shared_with(token: Option<CancellationToken>) -> Arc<Shared> {
        Arc::new(Shared {
            turn: Mutex::new(token),
        })
    }

    #[test]
    fn the_first_interrupt_of_a_turn_cancels_it_instead_of_exiting() {
        let token = CancellationToken::new();
        let shared = shared_with(Some(token.clone()));
        assert_eq!(decide(&shared), Decision::CancelTurn);
        assert!(token.is_cancelled());
    }

    #[test]
    fn a_second_interrupt_of_the_same_turn_leaves() {
        // The waiting is bounded by the operator, not only by the connector.
        // Without this, an interrupt handler that waits for a reply IS a hang
        // whenever the reply never comes.
        let token = CancellationToken::new();
        let shared = shared_with(Some(token.clone()));
        assert_eq!(decide(&shared), Decision::CancelTurn);
        assert_eq!(decide(&shared), Decision::Leave);
    }

    #[test]
    fn an_interrupt_with_no_turn_running_leaves() {
        // At the prompt, Ctrl-C has always ended the process. Installing a
        // handler must not quietly turn that into a no-op — a session you
        // cannot Ctrl-C out of is a worse bug than the one being fixed.
        assert_eq!(decide(&shared_with(None)), Decision::Leave);
    }

    #[test]
    fn an_interrupt_after_the_turn_finished_leaves() {
        // The same property one step later: the guard has dropped, so the slot
        // is empty even though a turn ran a moment ago.
        let interrupt = super::Interrupt {
            shared: shared_with(None),
        };
        let (_token, guard) = interrupt.arm();
        drop(guard);
        assert_eq!(decide(&interrupt.shared), Decision::Leave);
    }

    #[test]
    fn arming_hands_out_a_fresh_token_each_turn() {
        // A `CancellationToken` is one-shot. Reusing one across turns would
        // make every turn after an abort terminate instantly with no dispatch,
        // which reads as a broken session rather than an abort.
        let interrupt = super::Interrupt {
            shared: shared_with(None),
        };
        let (first, guard) = interrupt.arm();
        first.cancel();
        drop(guard);
        let (second, _guard) = interrupt.arm();
        assert!(!second.is_cancelled());
    }

    #[test]
    fn an_operator_abort_exits_130_and_nothing_else_does() {
        use arcana_core::agent_loop::TerminalReason;
        assert_eq!(super::exit_code(TerminalReason::AbortedByOperator), 130);
        assert_eq!(super::exit_code(TerminalReason::Completed), 0);
        // A connector failure and an abort used to be the same `1`. The shell
        // convention is the whole point: `130` is how a wrapper script tells
        // "the human stopped this" from "this product broke".
        for reason in [
            TerminalReason::ConnectorFatal,
            TerminalReason::MaxTurns,
            TerminalReason::MaxCostUsd,
            TerminalReason::AbortedByHook,
            TerminalReason::PermissionDenied,
            TerminalReason::ContextWindowExhausted,
            TerminalReason::AuditFatal,
        ] {
            assert_eq!(super::exit_code(reason), 1, "{reason:?}");
        }
    }

    #[test]
    fn dropping_the_guard_disarms_the_slot() {
        // The slot must be empty between turns: that emptiness is what makes a
        // Ctrl-C at the prompt exit rather than cancel a token no one reads.
        let interrupt = super::Interrupt {
            shared: shared_with(None),
        };
        let (_token, guard) = interrupt.arm();
        assert!(interrupt
            .shared
            .turn
            .lock()
            .is_ok_and(|slot| slot.is_some()));
        drop(guard);
        assert!(interrupt
            .shared
            .turn
            .lock()
            .is_ok_and(|slot| slot.is_none()));
    }
}
