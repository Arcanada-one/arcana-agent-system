//! `SIGTERM`→grace→`SIGKILL` process-group termination.

use std::time::Duration;

use arcana_core::hooks::audit::AuditLog;
use nix::errno::Errno;
use nix::unistd::Pid;
use serde_json::json;

use crate::error::SupervisorError;
use crate::spawn::SpawnedChild;

/// Terminate the child's **entire process group**, then reap the direct child.
///
/// Sends `SIGTERM` to the group, waits up to `grace` for the direct child to
/// exit, and — if it is still alive — sends the un-blockable `SIGKILL`. The
/// direct child is bounded-awaited afterwards so ordinary exits are reaped
/// without allowing an uninterruptible child to wedge the supervisor. A
/// terminal `terminate` event is recorded only after trustworthy cleanup.
///
/// # Errors
///
/// Returns a boundary lifecycle error when signalling, observation, reaping,
/// or group-disappearance proof fails. Returns [`SupervisorError::Audit`] if
/// the terminal audit record fails.
pub async fn terminate_group(
    pgid: Pid,
    grace: Duration,
    child: &mut SpawnedChild,
    audit: &AuditLog,
    correlation_id: &str,
) -> Result<(), SupervisorError> {
    if pgid != child.pgid() {
        return Err(SupervisorError::ProcessGroup(Errno::EINVAL));
    }
    let child_id = child.id();
    let _status = child.terminate(grace).await?;

    audit.record_event(
        correlation_id,
        "terminate",
        &json!({ "child_id": child_id }),
    )?;
    Ok(())
}
