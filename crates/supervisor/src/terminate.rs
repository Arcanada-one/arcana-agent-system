//! `SIGTERM`→grace→`SIGKILL` process-group termination.

use std::time::Duration;

use arcana_core::hooks::audit::AuditLog;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use serde_json::json;

use crate::error::SupervisorError;
use crate::spawn::SpawnedChild;

/// Terminate the child's **entire process group**, then reap the direct child.
///
/// Sends `SIGTERM` to the group, waits up to `grace` for the direct child to
/// exit, and — if it is still alive — sends the un-blockable `SIGKILL`. The
/// direct child is always awaited afterwards so it is reaped (a zombie still
/// answers `kill(pid, 0)`, so reaping is required for an `ESRCH` liveness
/// probe to be meaningful). A terminal `terminate` event is recorded.
///
/// `ESRCH` from either signal is benign (the group already exited) and ignored.
///
/// # Errors
///
/// Returns [`SupervisorError::Audit`] if the terminal audit record fails.
pub async fn terminate_group(
    pgid: Pid,
    grace: Duration,
    child: &mut SpawnedChild,
    audit: &AuditLog,
    correlation_id: &str,
) -> Result<(), SupervisorError> {
    let child_id = child.id();
    let _ = killpg(pgid, Signal::SIGTERM);

    let exited_gracefully = tokio::time::timeout(grace, child.child_mut().wait())
        .await
        .is_ok();

    if exited_gracefully {
        // The leader exiting does not prove its group is empty. A descendant
        // may ignore SIGTERM after redirecting every inherited pipe.
        child.kill_process_group()?;
    } else {
        // SIGKILL cannot be blocked, ignored, or caught — law-4 guarantee.
        child.kill_process_group()?;
        // Reap the direct child so its pid stops answering signal probes.
        let _ = child.child_mut().wait().await;
    }

    audit.record_event(
        correlation_id,
        "terminate",
        &json!({ "child_id": child_id }),
    )?;
    Ok(())
}
