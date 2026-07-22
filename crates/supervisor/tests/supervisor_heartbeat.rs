//! V-AC-3 (D-REQ-03): a child that stops heartbeating is terminated.

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
async fn supervisor_heartbeat_watchdog() {
    let dir = TempDir::new().expect("tempdir");
    let config = SupervisorConfig {
        correlation_id: "corr-hb".to_string(),
        heartbeat_timeout: Duration::from_millis(300),
        wall_clock: Duration::from_secs(10),
        grace: Duration::from_millis(150),
        ..SupervisorConfig::default()
    };
    let supervisor = Supervisor::new(config, audit_log(&dir), Arc::new(CostTracker::new()));

    // Keeps running (never exits) but stops emitting heartbeats after 100ms.
    let spec = child_spec()
        .arg("--stop-heartbeat-after")
        .arg("100")
        .arg("--interval")
        .arg("30");
    let handle = supervisor.spawn(spec).await.expect("spawn");
    let pid = handle.pid();

    let outcome = handle.wait().await;
    assert!(
        matches!(outcome, SupervisionOutcome::Escalated { .. }),
        "silent child must be terminated, got {outcome:?}"
    );

    let recs = records(&dir);
    assert!(
        recs.iter().any(|r| r["kind"] == "heartbeat_timeout"),
        "heartbeat_timeout event required: {recs:?}"
    );
    assert!(
        wait_until_gone(pid, Duration::from_secs(2)).await,
        "child must be gone after heartbeat timeout"
    );
}
