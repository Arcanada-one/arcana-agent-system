//! Bounded, noninteractive observation of stored task completion.
//!
//! Both Muneral reads must remain authorized and valid on every poll. This
//! consumer never registers tools, calls a model, reads stdin or writes task
//! state. Runtime heartbeat, cancellation fencing, notification delivery and
//! independent acceptance remain outside this observation-only gate set.

use serde_json::{json, Value};
use std::io::{self, Write};
use std::time::Duration;

/// Dispatch the existing single observation or the explicitly bounded watch.
#[must_use]
pub fn run_command(args: &crate::cli::StatusArgs) -> i32 {
    if args.watch {
        run(
            &args.work_item,
            args.timeout_secs.unwrap_or_default(),
            args.interval_secs.unwrap_or(5),
        )
    } else {
        crate::status::run(&args.work_item)
    }
}

struct Outcome {
    state: &'static str,
    reason: &'static str,
    message: &'static str,
    code: i32,
}

impl Outcome {
    fn unknown(reason: &'static str) -> Self {
        Self {
            state: "indeterminate",
            reason,
            message: "Could not determine stored task completion; see reason.",
            code: 3,
        }
    }
}

/// Watch until Muneral records done (0), cancelled (1), or the observation is
/// indeterminate (3). A finite deadline is required; no interactive input.
#[must_use]
pub fn run(id: &str, timeout_secs: u64, interval_secs: u64) -> i32 {
    let outcome = if !(1..=3600).contains(&timeout_secs) || !(1..=60).contains(&interval_secs) {
        Outcome::unknown("WATCH_CONFIGURATION_INVALID")
    } else {
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime.block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(timeout_secs),
                    watch(id, Duration::from_secs(interval_secs)),
                )
                .await
                .unwrap_or_else(|_| Outcome::unknown("WATCH_DEADLINE_EXPIRED"))
            }),
            Err(_) => Outcome::unknown("WATCH_RUNTIME_UNAVAILABLE"),
        }
    };
    let result = json!({"schema": "WorkItemWatchResult/v1", "work_item_id": id,
        "predicate": "stored_task_completion", "outcome": outcome.state,
        "reason": outcome.reason, "message": outcome.message,
        "independent_acceptance": "not_measured"});
    if emit(&result).is_err() {
        eprintln!("arcana status --watch: indeterminate: WATCH_OUTPUT_UNAVAILABLE");
        return 3;
    }
    outcome.code
}

fn emit(value: &Value) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{value}")?;
    stdout.flush()
}

async fn watch(id: &str, interval: Duration) -> Outcome {
    loop {
        let (observation, code) =
            match tokio::time::timeout(Duration::from_secs(5), crate::status::observe(id)).await {
                Ok(Ok(value)) => value,
                Ok(Err(reason)) => return Outcome::unknown(reason),
                Err(_) => return Outcome::unknown("STATUS_OBSERVATION_TIMEOUT"),
            };
        if emit(&observation).is_err() {
            return Outcome::unknown("WATCH_OUTPUT_UNAVAILABLE");
        }
        if code != 0 {
            return Outcome::unknown("DEPENDENCY_READINESS_UNDETERMINED");
        }
        match observation["task_status"].as_str() {
            Some("done") => {
                return Outcome {
                    state: "ready",
                    reason: "TASK_DONE",
                    message: "Ready: Muneral records the task as done; acceptance is not verified.",
                    code: 0,
                };
            }
            Some("cancelled") => {
                return Outcome {
                    state: "not_ready",
                    reason: "TASK_CANCELLED",
                    message: "Not ready: Muneral records the task as cancelled.",
                    code: 1,
                };
            }
            Some("archived") => return Outcome::unknown("ARCHIVED_COMPLETION_UNKNOWN"),
            Some("todo" | "in_progress" | "review" | "blocked") => {}
            _ => return Outcome::unknown("STATUS_INVALID_RESPONSE"),
        }
        tokio::time::sleep(interval).await;
    }
}
