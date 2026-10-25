//! Ctrl-C at the prompt still ends the session — the regression this fix most
//! risks introducing.
//!
//! Installing a SIGINT listener replaces the kernel's default disposition for
//! the whole process. Get the "nothing is running" case wrong and the signal is
//! swallowed: the operator presses Ctrl-C at an idle session and nothing at all
//! happens, which is strictly worse than the bug being fixed. This drives the
//! real binary, sends a real signal, and requires it to die promptly.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Long enough that a swallowed signal is unambiguous, short enough that a
/// failure does not stall CI.
const DEADLINE: Duration = Duration::from_secs(20);

/// A failed readiness or exit assertion must not leave its session behind.
struct SessionChild(Child);

impl Drop for SessionChild {
    fn drop(&mut self) {
        let _ignored = self.0.kill();
        let _ignored = self.0.wait();
    }
}

#[test]
fn an_interrupt_at_the_prompt_ends_the_session_with_130() {
    let state = tempfile::TempDir::new().unwrap();
    // stdin stays an open pipe with nothing written to it, so the session is
    // parked on the read — the state a prompt is in when nobody is typing.
    let mut child = SessionChild(
        Command::new(assert_cmd::cargo::cargo_bin("arcana"))
            .env("XDG_STATE_HOME", state.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );

    // main prints a version before REPL setup. Only the full normal session
    // banner proves that the SIGINT listener confirmed registration; arbitrary
    // first bytes and the unarmed-session banner are not readiness signals.
    let stdout = child.0.stdout.take().unwrap();
    let ready_banner = format!(
        "arcana {} — interactive session. `exit` or Ctrl-D to leave.",
        env!("CARGO_PKG_VERSION")
    );
    let (ready_tx, ready_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line == ready_banner {
                let _ignored = ready_tx.send(());
            }
        }
    });
    ready_rx
        .recv_timeout(DEADLINE)
        .expect("the session never confirmed SIGINT listener readiness");

    let killed = Command::new("kill")
        .arg("-INT")
        .arg(child.0.id().to_string())
        .status()
        .unwrap();
    assert!(killed.success());

    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the session survived a Ctrl-C at the prompt — the listener \
             swallowed the signal"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    assert_eq!(
        status.code(),
        Some(130),
        "a session ended by Ctrl-C must report 130, not a signal death or a \
        success"
    );
    // Keep draining stdout through process exit: dropping the pipe at the
    // readiness line could make the following audit line fail with EPIPE.
    reader.join().unwrap();
}
