//! Configuration, restart policy, and terminal outcome types.

use std::ffi::OsString;
use std::time::Duration;

/// Declarative recipe for a supervised child process.
///
/// Held by the supervisor so a crash-looping child can be **re-spawned**
/// identically under the [`RestartPolicy`]; a `tokio::process::Command` is not
/// clonable, so the invariant program + args are captured here instead.
#[derive(Debug, Clone)]
pub struct ChildSpec {
    program: OsString,
    args: Vec<OsString>,
}

impl ChildSpec {
    /// Start a spec for `program`.
    #[must_use]
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    /// Append a single argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// The program path.
    #[must_use]
    pub fn program(&self) -> &OsString {
        &self.program
    }

    /// The argument vector.
    #[must_use]
    pub fn args(&self) -> &[OsString] {
        &self.args
    }
}

/// Bounded restart budget: after `max_restarts` failures inside `window`, the
/// child is escalated instead of restarted.
#[derive(Debug, Clone)]
pub struct RestartPolicy {
    /// Maximum automatic restarts before escalation.
    pub max_restarts: u32,
    /// Base backoff; the delay grows exponentially from here.
    pub backoff_base: Duration,
    /// Upper bound on any single backoff delay.
    pub backoff_cap: Duration,
    /// Sliding window over which restarts are counted.
    pub window: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            backoff_base: Duration::from_millis(100),
            backoff_cap: Duration::from_secs(5),
            window: Duration::from_secs(60),
        }
    }
}

impl RestartPolicy {
    /// Exponentially-capped backoff for the given prior-restart count.
    #[must_use]
    pub fn backoff(&self, prior_restarts: u32) -> Duration {
        let factor = 1u32.checked_shl(prior_restarts.min(16)).unwrap_or(u32::MAX);
        self.backoff_base
            .saturating_mul(factor)
            .min(self.backoff_cap)
    }
}

/// Full supervisor configuration.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Task correlation id stamped onto every audit line.
    pub correlation_id: String,
    /// A child silent for longer than this is deemed wedged.
    pub heartbeat_timeout: Duration,
    /// Absolute per-child deadline measured from spawn.
    pub wall_clock: Duration,
    /// `SIGTERM`→`SIGKILL` grace window during termination.
    pub grace: Duration,
    /// Maximum simultaneously-live children.
    pub max_concurrent_children: usize,
    /// Optional aggregate-cost cap (USD); `None` disables the cost breaker.
    pub max_cost_usd: Option<f64>,
    /// Restart budget.
    pub restart: RestartPolicy,
    /// Watch-loop poll interval.
    pub tick: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            correlation_id: "supervisor".to_string(),
            heartbeat_timeout: Duration::from_secs(5),
            wall_clock: Duration::from_secs(60),
            grace: Duration::from_secs(2),
            max_concurrent_children: 8,
            max_cost_usd: None,
            restart: RestartPolicy::default(),
            tick: Duration::from_millis(20),
        }
    }
}

/// Why a child was forcibly terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationCause {
    /// No heartbeat within [`SupervisorConfig::heartbeat_timeout`].
    HeartbeatTimeout,
    /// The wall-clock deadline elapsed.
    WallClockTimeout,
    /// Cooperative cancellation was requested.
    Cancelled,
}

impl TerminationCause {
    /// Stable audit `kind` token for this cause.
    #[must_use]
    pub fn audit_kind(self) -> &'static str {
        match self {
            TerminationCause::HeartbeatTimeout => "heartbeat_timeout",
            TerminationCause::WallClockTimeout => "wall_clock_timeout",
            TerminationCause::Cancelled => "cancelled",
        }
    }
}

/// Terminal result of supervising a single child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisionOutcome {
    /// The child exited successfully.
    Completed {
        /// Supervisor-assigned child id.
        child_id: u64,
    },
    /// The child was terminated or exhausted its restart budget.
    Escalated {
        /// Supervisor-assigned child id.
        child_id: u64,
        /// Human-readable escalation reason.
        reason: String,
    },
}
