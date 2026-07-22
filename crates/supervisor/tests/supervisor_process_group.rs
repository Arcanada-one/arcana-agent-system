//! V-AC-1 (D-REQ-01): a spawned child owns its own process group.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::pedantic)]

mod common;

use arcana_supervisor::spawn_process_group;
use nix::unistd::getpgid;

use common::child_spec;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_process_group_ownership() {
    let spec = child_spec()
        .arg("--heartbeats")
        .arg("2")
        .arg("--interval")
        .arg("20");
    let mut child = spawn_process_group(1, &spec).expect("spawn");

    let pid = child.pid();
    let pgid = getpgid(Some(pid)).expect("getpgid");
    assert_eq!(
        pgid, pid,
        "the child must be the leader of its own process group"
    );

    // Reap the short-lived fixture.
    let _ = child.child_mut().wait().await;
}
