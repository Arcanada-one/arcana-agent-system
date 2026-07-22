//! Stdout heartbeat line-protocol reader.
//!
//! The supervisor owns each child's stdout pipe and runs an **independent**
//! async reader task per child. Because the readers are independent tasks, a
//! frozen (`SIGSTOP`'d) child whose pipe never yields a line cannot starve the
//! servicing of its siblings — the core non-blocking property (D-REQ-08).
//!
//! Protocol lines (prefix-matched): `READY`, `HEARTBEAT <seq>`, `STATUS <...>`.
//! Any recognised line republishes «now» as the child's last-liveness instant.

use std::time::Instant;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::ChildStdout;
use tokio::sync::watch;

/// Spawn a **detached** reader task that republishes liveness on each protocol
/// line. The task ends when the child closes its stdout (exit or pipe break).
pub fn spawn_reader(stdout: ChildStdout, liveness: watch::Sender<Instant>) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if is_liveness_line(&line) {
                // A closed receiver only means the child is no longer watched.
                let _ = liveness.send(Instant::now());
            }
        }
    });
}

/// `true` when `line` is a recognised heartbeat-protocol line.
fn is_liveness_line(line: &str) -> bool {
    line.starts_with("READY") || line.starts_with("HEARTBEAT") || line.starts_with("STATUS")
}
