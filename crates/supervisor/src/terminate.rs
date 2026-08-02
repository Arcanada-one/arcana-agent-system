//! `SIGTERM`→grace→`SIGKILL` process-group termination.

use std::future::Future;
use std::time::Duration;

use arcana_core::hooks::audit::AuditLog;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use serde_json::json;

use crate::error::SupervisorError;
use crate::spawn::SpawnedChild;

const POST_KILL_REAP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
enum BoundedWaitError<E> {
    Wait(E),
    Timeout,
}

async fn bounded_wait<F, T, E>(deadline: Duration, future: F) -> Result<T, BoundedWaitError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(deadline, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(BoundedWaitError::Wait(error)),
        Err(_) => Err(BoundedWaitError::Timeout),
    }
}

async fn force_kill_and_reap(child: &mut SpawnedChild) -> Result<(), SupervisorError> {
    child.kill_process_group()?;
    match bounded_wait(POST_KILL_REAP_TIMEOUT, child.child_mut().wait()).await {
        Ok(_) => Ok(()),
        Err(BoundedWaitError::Wait(source)) => Err(SupervisorError::ChildWait {
            phase: "wait after SIGKILL",
            source,
        }),
        Err(BoundedWaitError::Timeout) => Err(SupervisorError::ReapTimeout),
    }
}

/// Terminate the child's **entire process group**, then reap the direct child.
///
/// Sends `SIGTERM` to the group, waits up to `grace` for the direct child to
/// exit, and — if it is still alive — sends the un-blockable `SIGKILL`. The
/// direct child is bounded-awaited afterwards so ordinary exits are reaped
/// without allowing an uninterruptible child to wedge the supervisor. A
/// terminal `terminate` event is recorded only after trustworthy cleanup.
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

    match bounded_wait(grace, child.child_mut().wait()).await {
        Ok(_) => {
            // The leader exiting does not prove its group is empty. A descendant
            // may ignore SIGTERM after redirecting every inherited pipe.
            child.kill_process_group()?;
        }
        Err(BoundedWaitError::Wait(source)) => {
            force_kill_and_reap(child).await?;
            return Err(SupervisorError::ChildWait {
                phase: "wait after SIGTERM",
                source,
            });
        }
        Err(BoundedWaitError::Timeout) => {
            // SIGKILL cannot be blocked, ignored, or caught — law-4 guarantee.
            force_kill_and_reap(child).await?;
        }
    }

    audit.record_event(
        correlation_id,
        "terminate",
        &json!({ "child_id": child_id }),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::io;
    use std::time::Duration;

    use super::{bounded_wait, BoundedWaitError};

    #[tokio::test]
    async fn bounded_wait_distinguishes_wait_failure() {
        let result = bounded_wait(
            Duration::from_secs(1),
            future::ready(Err::<(), _>(io::Error::other("injected wait failure"))),
        )
        .await;
        assert!(matches!(result, Err(BoundedWaitError::Wait(_))));
    }

    #[tokio::test]
    async fn bounded_wait_distinguishes_reap_timeout() {
        let result = bounded_wait(
            Duration::from_millis(1),
            future::pending::<Result<(), io::Error>>(),
        )
        .await;
        assert!(matches!(result, Err(BoundedWaitError::Timeout)));
    }
}
