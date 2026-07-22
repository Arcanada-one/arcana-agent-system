//! Version-2 mandatory audit record contract.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::{HookChain, HookContext};
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::ToolDispatcher;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{AllowLayer, CountingTool, DenyLayer};

fn context() -> HookContext {
    HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()))
}

fn executor(dir: &TempDir, cascade: PermissionCascade) -> CapabilityExecutor {
    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(CountingTool::new(Arc::new(AtomicUsize::new(0)))))
        .expect("register tool");
    CapabilityExecutor::new(
        registry,
        cascade,
        HookChain::new(),
        AuditLog::new(dir.path()).expect("audit log"),
    )
}

#[tokio::test]
async fn successful_attempt_writes_correlated_decision_and_result() {
    let dir = TempDir::new().expect("tempdir");
    let executor = executor(&dir, PermissionCascade::new(vec![Arc::new(AllowLayer)]));

    executor
        .execute(&context(), "counting", json!({"value": 1}))
        .await
        .expect("execute");

    let records = records(&dir);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["version"], 2);
    assert_eq!(records[0]["phase"], "decision");
    assert_eq!(records[1]["phase"], "result");
    assert_eq!(records[0]["invocation_id"], records[1]["invocation_id"]);
    assert_eq!(records[0]["decision"], "Allowed");
    assert_eq!(records[1]["outcome"], "success");
    for record in records {
        assert!(record.get("input").is_none());
        assert!(record.get("output").is_none());
        assert!(record.get("reason").is_none());
    }
}

#[tokio::test]
async fn denied_attempt_writes_terminal_result_without_execution_payload() {
    let dir = TempDir::new().expect("tempdir");
    let executor = executor(&dir, PermissionCascade::new(vec![Arc::new(DenyLayer)]));

    let _ = executor
        .execute(&context(), "counting", json!({"value": 1}))
        .await
        .expect_err("denied");

    let records = records(&dir);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["decision"], "Denied");
    assert_eq!(records[1]["outcome"], "denied");
}

#[test]
fn audit_record_event() {
    let dir = TempDir::new().expect("tempdir");
    let audit = AuditLog::new(dir.path()).expect("audit log");

    audit
        .record_event("corr-1", "spawn", &json!({ "child_id": 7 }))
        .expect("record event");

    let records = records(&dir);
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record["version"], 2);
    assert_eq!(record["phase"], "supervisor");
    assert_eq!(record["kind"], "spawn");
    assert_eq!(record["correlation_id"], "corr-1");
    let fields_hash = record["fields_hash"]
        .as_str()
        .expect("fields_hash is a string");
    assert_eq!(fields_hash.len(), 16);
    assert!(fields_hash.chars().all(|c| c.is_ascii_hexdigit()));
    // Hashes-only invariant: the raw fields object is never persisted.
    assert!(record.get("fields").is_none());
}

fn records(dir: &TempDir) -> Vec<Value> {
    std::fs::read_to_string(dir.path().join("audit.log"))
        .expect("read audit")
        .lines()
        .map(|line| serde_json::from_str(line).expect("json record"))
        .collect()
}

#[cfg(unix)]
#[test]
fn audit_path_is_private_regular_and_owned_by_the_caller() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let outer = TempDir::new().expect("tempdir");
    let audit_dir = outer.path().join("audit");
    let _audit = AuditLog::new(&audit_dir).expect("secure audit log");
    let dir_metadata = std::fs::metadata(&audit_dir).expect("audit dir metadata");
    let file_metadata = std::fs::metadata(audit_dir.join("audit.log")).expect("audit metadata");

    assert_eq!(dir_metadata.permissions().mode() & 0o777, 0o700);
    assert_eq!(file_metadata.permissions().mode() & 0o777, 0o600);
    assert!(file_metadata.is_file());
    assert_eq!(file_metadata.uid(), rustix::process::geteuid().as_raw());
}

#[cfg(unix)]
#[test]
fn audit_log_rejects_symlink_target() {
    use std::os::unix::fs::symlink;

    let outer = TempDir::new().expect("tempdir");
    let audit_dir = outer.path().join("audit");
    std::fs::create_dir(&audit_dir).expect("audit dir");
    let victim = outer.path().join("victim");
    std::fs::write(&victim, "unchanged").expect("victim");
    symlink(&victim, audit_dir.join("audit.log")).expect("symlink");

    assert!(AuditLog::new(&audit_dir).is_err());
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "unchanged");
}

#[cfg(unix)]
#[test]
fn audit_log_rejects_existing_insecure_mode() {
    use std::os::unix::fs::PermissionsExt;

    let outer = TempDir::new().expect("tempdir");
    let audit_dir = outer.path().join("audit");
    std::fs::create_dir(&audit_dir).expect("audit dir");
    let path = audit_dir.join("audit.log");
    std::fs::write(&path, "prior\n").expect("audit file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    assert!(AuditLog::new(&audit_dir).is_err());
}
