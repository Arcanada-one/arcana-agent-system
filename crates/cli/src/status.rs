//! A read-only observation of Muneral, independent of the execution loop.
//!
//! The API enforces the agent's task scope on both reads. No write, model,
//! retrieval or tool dispatch is admitted here. Runtime progress, cancellation
//! and an atomic progress projection are outside this command's current scope.

use arcana_connectors::muneral::{MuneralClient, MuneralError};
use serde_json::{json, Value};
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(crate) struct ObservationError {
    pub code: &'static str,
    pub message: String,
}

impl From<&'static str> for ObservationError {
    fn from(code: &'static str) -> Self {
        Self {
            code,
            message: String::new(),
        }
    }
}

impl From<MuneralError> for ObservationError {
    fn from(error: MuneralError) -> Self {
        let code = error_code(&error);
        if let MuneralError::KeyFile(error) = error {
            Self {
                code,
                message: error.to_string(),
            }
        } else {
            code.into()
        }
    }
}

/// Print one JSON observation. Exit 0 means both reads succeeded, 3 means
/// dependency readiness is unknown, and 1 means no observation was emitted.
#[must_use]
pub fn run(id: &str) -> i32 {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ObservationError::from("STATUS_UNAVAILABLE"))
        .and_then(|runtime| {
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), observe(id))
                    .await
                    .map_err(|_| "STATUS_UNAVAILABLE")?
            })
        });
    match result {
        Ok((observation, code)) => {
            println!("{observation}");
            code
        }
        Err(error) => {
            if error.message.is_empty() {
                eprintln!("arcana status: {}", error.code);
            } else {
                eprintln!("arcana status: {}: {}", error.code, error.message);
            }
            1
        }
    }
}

fn now() -> Result<String, &'static str> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| "STATUS_UNAVAILABLE")
}

fn error_code(error: &MuneralError) -> &'static str {
    match error {
        MuneralError::Unauthorized | MuneralError::Forbidden(_) | MuneralError::NotFound(_) => {
            "STATUS_NOT_ACCESSIBLE"
        }
        MuneralError::Key(_) | MuneralError::BaseUrl(_) => "STATUS_CONFIGURATION_INVALID",
        MuneralError::KeyFile(error) => error.code(),
        MuneralError::Decode(_) => "STATUS_INVALID_RESPONSE",
        MuneralError::Transport(_) | MuneralError::Status { .. } => "STATUS_UNAVAILABLE",
    }
}

pub(crate) async fn observe(id: &str) -> Result<(Value, i32), ObservationError> {
    let client = MuneralClient::try_from_env().map_err(ObservationError::from)?;
    let task = client.work_item(id).await.map_err(|e| error_code(&e))?;
    let task_observed_at = now()?;
    let status = task.status.as_deref().ok_or("STATUS_INVALID_RESPONSE")?;
    if task.id != id
        || !matches!(
            status,
            "todo" | "in_progress" | "review" | "blocked" | "done" | "cancelled" | "archived"
        )
        || task.revision.is_some_and(|revision| revision < 0)
    {
        return Err("STATUS_INVALID_RESPONSE".into());
    }
    let (readiness, code) = match client.readiness(id).await {
        Ok(value)
            if value.task_id == id
                && value.ready == value.blocked_by.is_empty()
                && value.blocked_by.len() as u64 <= value.dependency_count =>
        {
            (
                json!({"state": "observed", "ready": value.ready,
                    "dependency_count": value.dependency_count,
                    "blocked_count": value.blocked_by.len(), "observed_at": now()?}),
                0,
            )
        }
        Err(error) if error_code(&error) == "STATUS_NOT_ACCESSIBLE" => {
            // Access can be revoked between reads. Suppress the earlier row too.
            return Err("STATUS_NOT_ACCESSIBLE".into());
        }
        Ok(_) | Err(_) => (json!({"state": "unknown", "ready": null}), 3),
    };
    Ok((
        json!({
            "schema": "WorkItemStatusObservation/v1", "work_item_id": id,
            "task_status": status, "task_revision": task.revision,
            "task_updated_at": task.updated_at, "task_observed_at": task_observed_at,
            "dependency_readiness": readiness, "consistency": "separate_reads",
            "runtime_progress": "not_measured", "runtime_freshness": "unknown"
        }),
        code,
    ))
}
