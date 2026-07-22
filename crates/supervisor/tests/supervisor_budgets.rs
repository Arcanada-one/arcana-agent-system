//! V-AC-6 (D-REQ-06): concurrency semaphore + aggregate-cost breaker.

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
use arcana_supervisor::{Supervisor, SupervisorConfig, SupervisorError};
use tempfile::TempDir;

use common::{audit_log, child_spec, records};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn supervisor_budgets() {
    // (a) Concurrency budget — a third live child is gated by the semaphore.
    let dir = TempDir::new().expect("tempdir");
    let config = SupervisorConfig {
        correlation_id: "corr-budget".to_string(),
        max_concurrent_children: 2,
        heartbeat_timeout: Duration::from_secs(10),
        wall_clock: Duration::from_secs(10),
        grace: Duration::from_millis(100),
        ..SupervisorConfig::default()
    };
    let supervisor = Supervisor::new(config, audit_log(&dir), Arc::new(CostTracker::new()));

    let forever = || child_spec().arg("--interval").arg("30");
    let h0 = supervisor.spawn(forever()).await.expect("first spawn");
    let h1 = supervisor.spawn(forever()).await.expect("second spawn");

    // Two permits are held; the third spawn must block (never start a 3rd child).
    let gated = tokio::time::timeout(Duration::from_millis(400), supervisor.spawn(forever())).await;
    assert!(
        gated.is_err(),
        "the third concurrent spawn must be gated by the concurrency budget"
    );

    supervisor.cancel();
    let _ = h0.wait().await;
    let _ = h1.wait().await;

    // (b) Cost budget — a pre-charged tracker over the cap refuses the spawn.
    let dir2 = TempDir::new().expect("tempdir");
    let cost = Arc::new(CostTracker::new());
    cost.record_llm_call("model", 0, 0, 10.0);
    let config2 = SupervisorConfig {
        correlation_id: "corr-cost".to_string(),
        max_cost_usd: Some(1.0),
        ..SupervisorConfig::default()
    };
    let supervisor2 = Supervisor::new(config2, audit_log(&dir2), cost);

    let refused = supervisor2
        .spawn(child_spec().arg("--interval").arg("30"))
        .await
        .expect_err("cost breaker must refuse the spawn");
    assert!(
        matches!(refused, SupervisorError::BudgetExceeded),
        "expected BudgetExceeded, got {refused:?}"
    );
    assert!(
        records(&dir2).iter().any(|r| r["kind"] == "escalate"),
        "cost refusal must record an escalate event"
    );
}
