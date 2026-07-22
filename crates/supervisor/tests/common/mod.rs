//! Shared offline-test helpers for the supervisor V-AC suite.

#![cfg(unix)]
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use arcana_core::hooks::audit::AuditLog;
use arcana_supervisor::ChildSpec;
use nix::errno::Errno;
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::Pid;
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::ChildStdout;

/// A `ChildSpec` for the in-repo `heartbeat-child` fixture binary.
pub fn child_spec() -> ChildSpec {
    ChildSpec::new(env!("CARGO_BIN_EXE_heartbeat-child"))
}

/// A supervised, secure `audit.log` inside `dir`.
pub fn audit_log(dir: &TempDir) -> Arc<AuditLog> {
    Arc::new(AuditLog::new(dir.path()).expect("audit log"))
}

/// Parse every JSON record currently in `dir/audit.log`.
pub fn records(dir: &TempDir) -> Vec<Value> {
    std::fs::read_to_string(dir.path().join("audit.log"))
        .map(|body| {
            body.lines()
                .map(|line| serde_json::from_str(line).expect("json record"))
                .collect()
        })
        .unwrap_or_default()
}

/// Count records whose `kind` equals `kind`.
pub fn count_kind(records: &[Value], kind: &str) -> usize {
    records.iter().filter(|r| r["kind"] == kind).count()
}

/// `true` while `pid` can be signalled (still exists to the kernel).
pub fn process_alive(pid: Pid) -> bool {
    kill(pid, None::<Signal>).is_ok()
}

/// Poll until `pid` is gone (`ESRCH`) or `budget` elapses. Returns whether the
/// process is confirmed gone.
pub async fn wait_until_gone(pid: Pid, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if kill(pid, None::<Signal>) == Err(Errno::ESRCH) {
            return true;
        }
        if Instant::now() >= deadline {
            return kill(pid, None::<Signal>) == Err(Errno::ESRCH);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Poll until the whole process group `pgid` is gone (a signal-0 group probe
/// returns `ESRCH`) or `budget` elapses. Returns whether the group is confirmed
/// empty.
///
/// Unlike [`wait_until_gone`], this observes *any* surviving group member — e.g.
/// a grandchild that the direct child's tokio `kill_on_drop` never reaches — so
/// it isolates the explicit group `SIGKILL` escalation from ambient reaping.
pub async fn wait_until_group_gone(pgid: Pid, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if killpg(pgid, None::<Signal>) == Err(Errno::ESRCH) {
            return true;
        }
        if Instant::now() >= deadline {
            return killpg(pgid, None::<Signal>) == Err(Errno::ESRCH);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Read the fixture's `STATUS grandchild=<pid>` line from its stdout.
pub async fn read_grandchild_pid(stdout: ChildStdout) -> Option<Pid> {
    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(rest) = line.strip_prefix("STATUS grandchild=") {
            if let Ok(raw) = rest.trim().parse::<i32>() {
                return Some(Pid::from_raw(raw));
            }
        }
    }
    None
}
