//! V-AC-4 (D-REQ-02): the wall-clock deadline fires independently of liveness.

#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::pedantic
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use arcana_core::cost::CostTracker;
use arcana_supervisor::{SupervisionOutcome, Supervisor, SupervisorConfig};
use tempfile::TempDir;

use common::{audit_log, child_spec, records, wait_until_gone};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_wall_clock_timeout() {
    let dir = TempDir::new().expect("tempdir");
    let config = SupervisorConfig {
        correlation_id: "corr-wall".to_string(),
        // Heartbeats never stop — only the wall-clock deadline should trip.
        heartbeat_timeout: Duration::from_secs(10),
        wall_clock: Duration::from_millis(300),
        grace: Duration::from_millis(150),
        ..SupervisorConfig::default()
    };
    let supervisor = Supervisor::new(config, audit_log(&dir), Arc::new(CostTracker::new()));

    let spec = child_spec().arg("--interval").arg("30");
    let handle = supervisor.spawn(spec).await.expect("spawn");
    let pid = handle.pid();

    let outcome = handle.wait().await;
    assert!(
        matches!(outcome, SupervisionOutcome::Escalated { .. }),
        "wall-clock deadline must terminate the child, got {outcome:?}"
    );

    let recs = records(&dir);
    assert!(
        recs.iter().any(|r| r["kind"] == "wall_clock_timeout"),
        "wall_clock_timeout event required even though heartbeats continued: {recs:?}"
    );
    assert!(wait_until_gone(pid, Duration::from_secs(2)).await);
}
