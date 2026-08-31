//! A REAL SIGINT, delivered to this process, reaches the listener.
//!
//! The unit tests in `interrupt` exercise the decision with the signal stubbed
//! out. Everything between the kernel and that decision — the dedicated
//! listener thread, its own runtime, tokio's signal registration — is exactly
//! the part they cannot cover, and exactly the part that fails silently: a
//! listener that never receives leaves `Ctrl-C` doing nothing at all, and every
//! stubbed test still passes.
//!
//! Its own test binary because `Interrupt::install` is once per process, and
//! because a mistake here takes the whole harness down with it rather than
//! failing one case.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use arcana_cli::interrupt::Interrupt;

#[test]
fn a_real_sigint_cancels_the_armed_turn_without_killing_the_process() {
    let interrupt = Interrupt::install().expect("first install in this process");
    let (token, _guard) = interrupt.arm();

    let status = std::process::Command::new("kill")
        .arg("-INT")
        .arg(std::process::id().to_string())
        .status()
        .expect("kill");
    assert!(status.success(), "could not deliver the signal");

    // Poll rather than sleep a fixed interval: the listener is a separate
    // thread, so the only honest assertion is "within a bound", and a bound
    // that is also a lower bound would make the test slower for no reason.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !token.is_cancelled() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(
        token.is_cancelled(),
        "a real SIGINT did not reach the listener within 5s"
    );
    // Reaching this line at all is the second assertion: before this change the
    // signal killed the process outright, which is what it would still do if
    // the listener had failed to register.
}
