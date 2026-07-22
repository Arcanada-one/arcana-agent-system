//! V-AC-2 (D-REQ-04): SIGTERM-ignoring child + grandchild are SIGKILLed by group.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::pedantic)]

mod common;

use std::time::Duration;

use arcana_supervisor::{spawn_process_group, terminate_group};
use tempfile::TempDir;

use common::{audit_log, child_spec, read_grandchild_pid, records, wait_until_gone};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_sigterm_then_sigkill() {
    let dir = TempDir::new().expect("tempdir");
    let audit = audit_log(&dir);

    let spec = child_spec()
        .arg("--ignore-term")
        .arg("--spawn-grandchild")
        .arg("--interval")
        .arg("50");
    let mut child = spawn_process_group(7, &spec).expect("spawn");
    let pid = child.pid();
    let pgid = child.pgid();

    let stdout = child.take_stdout().expect("stdout");
    let grandchild = read_grandchild_pid(stdout)
        .await
        .expect("grandchild pid line");

    // SIGTERM is blocked by the child; the group SIGKILL must still reap both.
    terminate_group(pgid, Duration::from_millis(150), &mut child, &audit, "corr-term")
        .await
        .expect("terminate");

    assert!(
        wait_until_gone(pid, Duration::from_secs(2)).await,
        "the SIGTERM-ignoring child must be SIGKILLed"
    );
    assert!(
        wait_until_gone(grandchild, Duration::from_secs(2)).await,
        "the grandchild in the same process group must be SIGKILLed"
    );

    assert!(records(&dir).iter().any(|r| r["kind"] == "terminate"));
}
