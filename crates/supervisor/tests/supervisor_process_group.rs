//! V-AC-1 (D-REQ-01): a spawned child owns its own process group.

#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::pedantic
)]

mod common;

use arcana_supervisor::spawn_process_group;
use nix::errno::Errno;
use nix::sys::signal::{kill, killpg};
use nix::unistd::getpgid;

use common::child_spec;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_process_group_ownership() {
    let iterations = if cfg!(target_os = "macos") { 20 } else { 3 };
    for iteration in 0..iterations {
        let spec = child_spec()
            .arg("--heartbeats")
            .arg("2")
            .arg("--interval")
            .arg("20");
        let mut child = spawn_process_group(iteration, &spec).expect("spawn");

        let pid = child.pid();
        let pgid = getpgid(Some(pid)).expect("getpgid");
        assert_eq!(pgid, child.pgid(), "target must join the owned group");
        assert_eq!(pgid, pid, "the target must remain its process-group leader");

        // Observe exit without consuming it. The zombie leader must retain the
        // numeric PID=PGID until the boundary's final destructive group signal.
        child.wait_for_exit().await.expect("observe target exit");
        assert!(
            kill(pid, None).is_ok(),
            "iteration {iteration}: WNOWAIT must retain the target as the PGID anchor"
        );
        let status = child
            .finalize_after_exit()
            .await
            .unwrap_or_else(|error| panic!("iteration {iteration} failed: {error}"));
        assert!(status.success(), "fixture target should exit successfully");
        assert_eq!(
            killpg(pgid, None),
            Err(Errno::ESRCH),
            "iteration {iteration}: finalization must empty the group"
        );
    }
}
