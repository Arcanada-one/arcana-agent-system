//! Ctrl-C at the prompt still ends the session — the regression this fix most
//! risks introducing.
//!
//! Installing a SIGINT listener replaces the kernel's default disposition for
//! the whole process. Get the "nothing is running" case wrong and the signal is
//! swallowed: the operator presses Ctrl-C at an idle session and nothing at all
//! happens, which is strictly worse than the bug being fixed. This drives the
//! real binary, sends a real signal, and requires it to die promptly.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Long enough that a swallowed signal is unambiguous, short enough that a
/// failure does not stall CI.
const DEADLINE: Duration = Duration::from_secs(20);

#[test]
fn an_interrupt_at_the_prompt_ends_the_session_with_130() {
    let state = tempfile::TempDir::new().unwrap();
    // stdin stays an open pipe with nothing written to it, so the session is
    // parked on the read — the state a prompt is in when nobody is typing.
    let mut child = Command::new(assert_cmd::cargo::cargo_bin("arcana"))
        .env("XDG_STATE_HOME", state.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for the banner: it is printed after the session is built, so its
    // arrival is proof the process has reached the read rather than a guess
    // dressed up as a sleep.
    let mut stdout = child.stdout.take().unwrap();
    let mut banner = [0_u8; 64];
    let read = stdout.read(&mut banner).unwrap();
    assert!(read > 0, "no banner; the session never started");

    let killed = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(killed.success());

    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
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
}
