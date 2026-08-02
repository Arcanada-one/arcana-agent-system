//! The [`Supervisor`] and its per-child supervision task.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arcana_core::cost::CostTracker;
use arcana_core::hooks::audit::AuditLog;
use nix::unistd::Pid;
use serde_json::json;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::SupervisorError;
use crate::heartbeat::spawn_reader;
use crate::policy::{ChildSpec, SupervisionOutcome, SupervisorConfig, TerminationCause};
use crate::spawn::{spawn_process_group, SpawnedChild};
use crate::terminate::terminate_group;

/// Supervises OS children with process-group ownership, liveness/deadline
/// watchdogs, bounded restarts, and concurrency/cost budgets, recording every
/// lifecycle event into the shared Blake3 audit log.
pub struct Supervisor {
    config: SupervisorConfig,
    audit: Arc<AuditLog>,
    cost: Arc<CostTracker>,
    semaphore: Arc<Semaphore>,
    cancel: CancellationToken,
    next_id: AtomicU64,
}

impl Supervisor {
    /// Construct a supervisor over a shared audit log and cost tracker.
    #[must_use]
    pub fn new(config: SupervisorConfig, audit: Arc<AuditLog>, cost: Arc<CostTracker>) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_children));
        Self {
            config,
            audit,
            cost,
            semaphore,
            cancel: CancellationToken::new(),
            next_id: AtomicU64::new(0),
        }
    }

    /// A clone of the cooperative-cancellation token.
    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Request cooperative shutdown of every supervised child.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Spawn and begin supervising `spec`.
    ///
    /// Blocks until a concurrency permit is free (the concurrency budget), then
    /// spawns a process-group-owning child, records a `spawn` event, and starts
    /// the per-child watchdog. If the aggregate-cost budget is already exceeded
    /// the spawn is refused with [`SupervisorError::BudgetExceeded`] after an
    /// `escalate` event.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError`] on budget refusal, spawn failure, or a
    /// fail-closed audit-write failure.
    // `pid` / `pgid` are the standard process-group domain names.
    #[allow(clippy::similar_names)]
    pub async fn spawn(&self, spec: ChildSpec) -> Result<ChildHandle, SupervisorError> {
        if self.cost.check_budget(self.config.max_cost_usd).is_err() {
            self.audit.record_event(
                &self.config.correlation_id,
                "escalate",
                &json!({ "reason": "budget_exceeded" }),
            )?;
            return Err(SupervisorError::BudgetExceeded);
        }

        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| SupervisorError::Spawn(std::io::Error::other("semaphore closed")))?;

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut child = spawn_process_group(id, &spec)?;
        let pid = child.pid();
        let pgid = child.pgid();
        self.audit.record_event(
            &self.config.correlation_id,
            "spawn",
            &json!({ "child_id": id, "pid": pid.as_raw() }),
        )?;

        let (liveness, hb_rx) = watch::channel(Instant::now());
        if let Some(out) = child.take_stdout() {
            spawn_reader(out, liveness.clone());
        }

        let task = SuperviseTask {
            child,
            spec,
            config: self.config.clone(),
            audit: self.audit.clone(),
            cancel: self.cancel.clone(),
            liveness,
            _permit: permit,
        };
        let join = tokio::spawn(task.run());

        Ok(ChildHandle {
            id,
            pid,
            pgid,
            hb_rx,
            join,
        })
    }
}

/// Observation + join handle for a single supervised child.
#[derive(Debug)]
pub struct ChildHandle {
    id: u64,
    pid: Pid,
    pgid: Pid,
    hb_rx: watch::Receiver<Instant>,
    join: JoinHandle<SupervisionOutcome>,
}

impl ChildHandle {
    /// Supervisor-assigned child id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// OS process id of the (current) child.
    #[must_use]
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// OS process-group id.
    #[must_use]
    pub fn pgid(&self) -> Pid {
        self.pgid
    }

    /// Last observed liveness instant (non-blocking read of the watch channel).
    #[must_use]
    pub fn last_heartbeat(&self) -> Instant {
        *self.hb_rx.borrow()
    }

    /// Await the terminal supervision outcome.
    #[must_use = "the supervision outcome should be inspected"]
    pub async fn wait(self) -> SupervisionOutcome {
        self.join.await.unwrap_or(SupervisionOutcome::Escalated {
            child_id: self.id,
            reason: "supervise task panicked".to_string(),
        })
    }
}

/// Internal per-child watchdog task.
struct SuperviseTask {
    child: SpawnedChild,
    spec: ChildSpec,
    config: SupervisorConfig,
    audit: Arc<AuditLog>,
    cancel: CancellationToken,
    liveness: watch::Sender<Instant>,
    _permit: OwnedSemaphorePermit,
}

/// One iteration's verdict from the watch loop.
enum Step {
    /// Nothing tripped; keep watching.
    Poll,
    /// The child must be force-terminated for the given cause.
    Terminate(TerminationCause),
    /// The child exited on its own but remains unreaped to pin PID=PGID.
    Exited,
    /// Exit observation failed before a trustworthy lifecycle result.
    WaitFailed(SupervisorError),
}

impl SuperviseTask {
    /// Watch the child until a terminal outcome.
    async fn run(mut self) -> SupervisionOutcome {
        let child_id = self.child.id();
        let mut restarts = 0u32;
        let mut window_start = Instant::now();
        let mut deadline = tokio::time::Instant::now() + self.config.wall_clock;
        let mut hb_rx = self.liveness.subscribe();

        loop {
            match self.next_step(&mut hb_rx, deadline).await {
                Step::Poll => {}
                Step::Terminate(cause) => {
                    self.emit(cause.audit_kind(), child_id);
                    if let Err(error) = self.terminate().await {
                        let reason = lifecycle_failure_reason(&error);
                        self.emit("escalate", child_id);
                        tracing::error!(error = %error, cause = cause.audit_kind(), reason, "supervisor termination failed");
                        return SupervisionOutcome::Escalated {
                            child_id,
                            reason: reason.to_string(),
                        };
                    }
                    return SupervisionOutcome::Escalated {
                        child_id,
                        reason: cause.audit_kind().to_string(),
                    };
                }
                Step::Exited => {
                    let status = match self.child.finalize_after_exit().await {
                        Ok(status) => status,
                        Err(error) => {
                            tracing::error!(error = %error, "supervisor process-group finalization failed");
                            self.emit("escalate", child_id);
                            return SupervisionOutcome::Escalated {
                                child_id,
                                reason: "process_group_cleanup_failed".to_string(),
                            };
                        }
                    };
                    if status.success() {
                        return SupervisionOutcome::Completed { child_id };
                    }
                    if let Some(outcome) = self
                        .handle_failure(child_id, &mut restarts, &mut window_start, &mut deadline)
                        .await
                    {
                        return outcome;
                    }
                }
                Step::WaitFailed(wait_error) => {
                    tracing::error!(error = %wait_error, "supervisor child-exit observation failed");
                    if let Err(error) = self.terminate().await {
                        tracing::error!(error = %error, "supervisor cleanup after exit-observation failure failed");
                        self.emit("escalate", child_id);
                    }
                    return SupervisionOutcome::Escalated {
                        child_id,
                        reason: "child_wait_failed".to_string(),
                    };
                }
            }
        }
    }

    /// Poll the child, deadline, cancellation, and heartbeat concurrently.
    ///
    /// The heartbeat is read **non-blockingly** from the watch channel, so a
    /// frozen child (whose pipe never yields) cannot starve this loop.
    async fn next_step(
        &mut self,
        hb_rx: &mut watch::Receiver<Instant>,
        deadline: tokio::time::Instant,
    ) -> Step {
        let tick = self.config.tick;
        let hb_timeout = self.config.heartbeat_timeout;
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Step::Terminate(TerminationCause::Cancelled),
            () = tokio::time::sleep_until(deadline) => Step::Terminate(TerminationCause::WallClockTimeout),
            result = self.child.wait_for_exit() => {
                match result {
                    Ok(()) => Step::Exited,
                    Err(error) => Step::WaitFailed(error),
                }
            }
            () = tokio::time::sleep(tick) => {
                if hb_rx.borrow().elapsed() > hb_timeout {
                    Step::Terminate(TerminationCause::HeartbeatTimeout)
                } else {
                    Step::Poll
                }
            }
        }
    }

    /// Apply the restart policy to a non-zero exit.
    ///
    /// Returns `Some(outcome)` when the child is terminal (restart budget
    /// exhausted or respawn failed), or `None` after a successful restart.
    async fn handle_failure(
        &mut self,
        child_id: u64,
        restarts: &mut u32,
        window_start: &mut Instant,
        deadline: &mut tokio::time::Instant,
    ) -> Option<SupervisionOutcome> {
        if window_start.elapsed() > self.config.restart.window {
            *restarts = 0;
            *window_start = Instant::now();
        }
        if *restarts >= self.config.restart.max_restarts {
            self.emit("escalate", child_id);
            return Some(SupervisionOutcome::Escalated {
                child_id,
                reason: "restart_exhausted".to_string(),
            });
        }
        tokio::time::sleep(self.config.restart.backoff(*restarts)).await;
        self.emit("restart", child_id);
        if self.respawn().is_err() {
            self.emit("escalate", child_id);
            return Some(SupervisionOutcome::Escalated {
                child_id,
                reason: "respawn_failed".to_string(),
            });
        }
        *restarts += 1;
        *deadline = tokio::time::Instant::now() + self.config.wall_clock;
        None
    }

    /// Re-spawn the child from its spec, keeping the same child id and liveness
    /// channel, and reset its liveness clock.
    fn respawn(&mut self) -> Result<(), SupervisorError> {
        let mut fresh = spawn_process_group(self.child.id(), &self.spec)?;
        if let Some(out) = fresh.take_stdout() {
            spawn_reader(out, self.liveness.clone());
        }
        let _ = self.liveness.send(Instant::now());
        self.child = fresh;
        Ok(())
    }

    /// Force-terminate the child's process group and record the terminal event.
    async fn terminate(&mut self) -> Result<(), SupervisorError> {
        let pgid = self.child.pgid();
        terminate_group(
            pgid,
            self.config.grace,
            &mut self.child,
            &self.audit,
            &self.config.correlation_id,
        )
        .await
    }

    /// Record a lifecycle event; log (do not silently drop) on a write failure.
    fn emit(&self, kind: &str, child_id: u64) {
        if let Err(err) = self.audit.record_event(
            &self.config.correlation_id,
            kind,
            &json!({ "child_id": child_id }),
        ) {
            tracing::error!(error = %err, kind, "supervisor audit write failed");
        }
    }
}

fn lifecycle_failure_reason(error: &SupervisorError) -> &'static str {
    match error {
        SupervisorError::Boundary(arcana_execution_boundary::BoundaryError::Io {
            phase, ..
        }) if phase.contains("reap") => "reap_failed",
        SupervisorError::Boundary(arcana_execution_boundary::BoundaryError::Io {
            phase, ..
        }) if phase.contains("disappearance") => "process_group_cleanup_failed",
        SupervisorError::Boundary(arcana_execution_boundary::BoundaryError::Io {
            phase, ..
        }) if phase.contains("observe") || phase.contains("observer") => "child_wait_failed",
        _ => "termination_failed",
    }
}
