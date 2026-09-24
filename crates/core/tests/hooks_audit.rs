//! Version-2 mandatory audit record contract.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::{AuditLog, BYTES_WRITTEN};
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

/// A tool that reports a byte count, the way a writing tool does.
struct WritingTool {
    bytes: u64,
}

#[async_trait::async_trait]
impl arcana_core::tool::Tool for WritingTool {
    fn name(&self) -> &'static str {
        "writing"
    }

    fn description(&self) -> &'static str {
        "reports a byte count"
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object", "properties": {}, "additionalProperties": false })
    }

    async fn execute(
        &self,
        _invocation: arcana_core::tool::ToolInvocation,
    ) -> Result<arcana_core::tool::ToolOutput, arcana_core::tool::ToolError> {
        Ok(arcana_core::tool::ToolOutput {
            content: format!("wrote {} bytes", self.bytes),
            metadata: Some(json!({ BYTES_WRITTEN: self.bytes })),
        })
    }
}

/// A write of nothing and a write of a page must not look alike in the log.
///
/// A2-285: two `write` calls, both `outcome: success`, both over the same 0-byte
/// file, and nothing in the log said so — `output_hash` is opaque and the
/// arguments were never kept. The count is the one field that separates them,
/// and it carries no file text and no model text, so it can be written in clear.
#[tokio::test]
async fn a_result_record_carries_the_byte_count_the_tool_reported() {
    for bytes in [0_u64, 4096] {
        let dir = TempDir::new().expect("tempdir");
        let mut registry = ToolDispatcher::new();
        registry
            .register(Arc::new(WritingTool { bytes }))
            .expect("register tool");
        let executor = CapabilityExecutor::new(
            registry,
            PermissionCascade::new(vec![Arc::new(AllowLayer)]),
            HookChain::new(),
            AuditLog::new(dir.path()).expect("audit log"),
        );

        executor
            .execute(&context(), "writing", json!({}))
            .await
            .expect("execute");

        let records = records(&dir);
        let result = &records[1];
        assert_eq!(result["phase"], "result");
        assert_eq!(result["outcome"], "success");
        assert_eq!(
            result[BYTES_WRITTEN], bytes,
            "the record must carry the count, including zero: {result}"
        );
        // Still hashes-only for everything that could carry text.
        assert!(result.get("output").is_none());
        assert!(result["output_hash"].is_string());
    }
}

/// A tool that writes nothing reports nothing, and `null` is not `0`.
#[tokio::test]
async fn a_non_writing_tool_leaves_the_byte_count_null() {
    let dir = TempDir::new().expect("tempdir");
    let executor = executor(&dir, PermissionCascade::new(vec![Arc::new(AllowLayer)]));

    executor
        .execute(&context(), "counting", json!({"value": 1}))
        .await
        .expect("execute");

    let result = &records(&dir)[1];
    assert!(
        result[BYTES_WRITTEN].is_null(),
        "a tool that does not write must not appear to have written 0 bytes: {result}"
    );
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
