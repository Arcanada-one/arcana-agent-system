//! V-AC-10 (scaffold half): a supervised child runs and completes cleanly.

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

use common::{audit_log, child_spec, records};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_smoke() {
    let dir = TempDir::new().expect("tempdir");
    let config = SupervisorConfig {
        correlation_id: "corr-smoke".to_string(),
        heartbeat_timeout: Duration::from_secs(5),
        wall_clock: Duration::from_secs(10),
        ..SupervisorConfig::default()
    };
    let supervisor = Supervisor::new(config, audit_log(&dir), Arc::new(CostTracker::new()));

    let spec = child_spec()
        .arg("--heartbeats")
        .arg("3")
        .arg("--interval")
        .arg("30")
        .arg("--exit-code")
        .arg("0");
    let handle = supervisor.spawn(spec).await.expect("spawn");

    let outcome = handle.wait().await;
    assert!(
        matches!(outcome, SupervisionOutcome::Completed { .. }),
        "expected clean completion, got {outcome:?}"
    );

    let recs = records(&dir);
    assert!(
        recs.iter().any(|r| r["kind"] == "spawn"),
        "spawn event must be recorded: {recs:?}"
    );
    assert!(recs.iter().all(|r| r["correlation_id"] == "corr-smoke"));
}
