//! V-AC-8 (logic axis) + V-AC-9 (timing axis): SIGSTOP chaos.

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
use nix::sys::signal::{kill, Signal};
use tempfile::TempDir;

use common::{audit_log, child_spec, records, wait_until_gone, wait_until_group_gone};

/// V-AC-8: a frozen child does not starve its siblings, and is itself killed;
/// its spawn / *_timeout / terminate events land in the shared audit log.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn supervisor_chaos_sigstop() {
    let dir = TempDir::new().expect("tempdir");
    let config = SupervisorConfig {
        correlation_id: "corr-chaos".to_string(),
        heartbeat_timeout: Duration::from_millis(300),
        wall_clock: Duration::from_secs(30),
        grace: Duration::from_millis(100),
        max_concurrent_children: 8,
        tick: Duration::from_millis(20),
        ..SupervisorConfig::default()
    };
    let supervisor = Supervisor::new(config, audit_log(&dir), Arc::new(CostTracker::new()));

    let frozen = supervisor
        .spawn(child_spec().arg("--interval").arg("30"))
        .await
        .expect("frozen child");
    let sibling = supervisor
        .spawn(child_spec().arg("--interval").arg("30"))
        .await
        .expect("sibling child");
    let frozen_pid = frozen.pid();

    // Let both children heartbeat, then freeze one.
    tokio::time::sleep(Duration::from_millis(120)).await;
    let sibling_before = sibling.last_heartbeat();
    kill(frozen_pid, Signal::SIGSTOP).expect("sigstop the frozen child");

    // While the frozen child is stopped, the sibling keeps being serviced.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let sibling_after = sibling.last_heartbeat();
    assert!(
        sibling_after > sibling_before,
        "sibling heartbeat must keep advancing while a peer is frozen (non-starvation)"
    );

    // The frozen child hits the heartbeat timeout and is SIGKILLed.
    let outcome = frozen.wait().await;
    assert!(
        matches!(outcome, SupervisionOutcome::Escalated { .. }),
        "frozen child must be terminated, got {outcome:?}"
    );
    assert!(
        wait_until_gone(frozen_pid, Duration::from_secs(2)).await,
        "frozen child must be gone (ESRCH) after SIGKILL"
    );

    let recs = records(&dir);
    assert!(recs.iter().any(|r| r["kind"] == "spawn"), "spawn: {recs:?}");
    assert!(
        recs.iter()
            .any(|r| r["kind"].as_str().is_some_and(|k| k.ends_with("_timeout"))),
        "a *_timeout event is required: {recs:?}"
    );
    assert!(
        recs.iter().any(|r| r["kind"] == "terminate"),
        "terminate: {recs:?}"
    );
    assert!(
        recs.iter().all(|r| r["correlation_id"] == "corr-chaos"),
        "every event must carry the task correlation id"
    );

    supervisor.cancel();
    let _ = sibling.wait().await;
}

/// V-AC-9: a wedged (SIGSTOP'd) child — and a SIGTERM-blocking grandchild in its
/// process group — are SIGKILLed within a generous 10x budget.
///
/// The grandchild is the load-bearing part of this assertion. `spawn.rs`'
/// `kill_on_drop(true)` reaps the *direct* child pid when the `SuperviseTask`
/// drops, so a single-child variant would stay green even if the explicit group
/// `SIGKILL` were removed (finding F1). The grandchild blocks `SIGTERM` and is
/// never reached by `kill_on_drop`, so the whole group going `ESRCH` proves the
/// budgeted `killpg(pgid, SIGKILL)` escalation actually fired — mutation-verified
/// (neutering the SIGKILL step turns this test RED).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_chaos_sigkill_within_budget() {
    let dir = TempDir::new().expect("tempdir");
    let config = SupervisorConfig {
        correlation_id: "corr-kill-budget".to_string(),
        heartbeat_timeout: Duration::from_millis(200),
        wall_clock: Duration::from_secs(30),
        grace: Duration::from_millis(50),
        tick: Duration::from_millis(20),
        ..SupervisorConfig::default()
    };
    let supervisor = Supervisor::new(config, audit_log(&dir), Arc::new(CostTracker::new()));

    let handle = supervisor
        .spawn(
            child_spec()
                .arg("--spawn-grandchild")
                .arg("--interval")
                .arg("30"),
        )
        .await
        .expect("spawn");
    let pid = handle.pid();
    let pgid = handle.pgid();

    tokio::time::sleep(Duration::from_millis(60)).await;
    kill(pid, Signal::SIGSTOP).expect("sigstop");

    // 200ms heartbeat trip; assert termination within a 2s (10x margin) budget.
    let terminated = tokio::time::timeout(Duration::from_secs(2), handle.wait()).await;
    assert!(
        terminated.is_ok(),
        "the wedged child must be terminated within the 2s budget"
    );
    assert!(
        wait_until_gone(pid, Duration::from_millis(500)).await,
        "the wedged child must be SIGKILLed (ESRCH)"
    );
    // Isolates the explicit group SIGKILL: the SIGTERM-blocking grandchild
    // survives everything except `killpg(pgid, SIGKILL)`, and `kill_on_drop`
    // cannot reach it. Group ESRCH within budget ⇒ the escalation fired.
    assert!(
        wait_until_group_gone(pgid, Duration::from_secs(2)).await,
        "the whole process group (incl. the SIGTERM-blocking grandchild) must be SIGKILLed within budget"
    );
}
