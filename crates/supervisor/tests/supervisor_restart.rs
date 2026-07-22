//! V-AC-5 (D-REQ-05): bounded restarts then terminal escalation.

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
use arcana_supervisor::{RestartPolicy, SupervisionOutcome, Supervisor, SupervisorConfig};
use tempfile::TempDir;

use common::{audit_log, child_spec, count_kind, records};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_restart_escalation() {
    let dir = TempDir::new().expect("tempdir");
    let config = SupervisorConfig {
        correlation_id: "corr-restart".to_string(),
        heartbeat_timeout: Duration::from_secs(10),
        wall_clock: Duration::from_secs(10),
        grace: Duration::from_millis(100),
        restart: RestartPolicy {
            max_restarts: 2,
            backoff_base: Duration::from_millis(10),
            backoff_cap: Duration::from_millis(50),
            window: Duration::from_secs(60),
        },
        ..SupervisorConfig::default()
    };
    let supervisor = Supervisor::new(config, audit_log(&dir), Arc::new(CostTracker::new()));

    // Exits non-zero after a single heartbeat — always fails.
    let spec = child_spec()
        .arg("--heartbeats")
        .arg("1")
        .arg("--exit-code")
        .arg("1")
        .arg("--interval")
        .arg("20");
    let handle = supervisor.spawn(spec).await.expect("spawn");

    let outcome = handle.wait().await;
    assert!(
        matches!(outcome, SupervisionOutcome::Escalated { ref reason, .. } if reason == "restart_exhausted"),
        "must escalate after the restart budget, got {outcome:?}"
    );

    let recs = records(&dir);
    assert_eq!(
        count_kind(&recs, "restart"),
        2,
        "exactly 2 restarts: {recs:?}"
    );
    assert_eq!(
        count_kind(&recs, "escalate"),
        1,
        "exactly 1 escalate: {recs:?}"
    );
    // Escalation is a returned signal + audit event — no hard-gated action:
    // the crate has no network/deploy surface, so none is structurally possible.
    assert!(recs.iter().all(|r| r["correlation_id"] == "corr-restart"));
}
