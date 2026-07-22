//! Store-seam tests for ARAS-0047 Phase-1: the `SkillStore` trait, the trusted
//! `FileStore`, the blake3 verify-before-parse keystone, the tool-ceiling and
//! model-allowlist gates, the no-silent-fallback `StoreUnavailable` behaviour,
//! the blake3-content-addressed cache, and the two-phase type-level firewall.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_core::dispatch::ModelPolicy;
use arcana_skills::{
    FetchConn, FetchUnavailable, FileStore, ModelAllowlist, ScrutatorStore, SkillError,
    SkillInterpreter, SkillPin, SkillStore, ToolCeiling,
};
use async_trait::async_trait;
use serde_json::json;

use common::{executor_with, hook_ctx, EchoTool};

/// A `FetchConn` that returns fixed bytes and counts how many times it is
/// called (so a cache-hit test can assert zero network fetches).
struct FixedConn {
    bytes: Vec<u8>,
    calls: AtomicUsize,
}

impl FixedConn {
    fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl FetchConn for FixedConn {
    async fn fetch_bytes(&self, _source_id: &str) -> Result<Vec<u8>, FetchUnavailable> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.bytes.clone())
    }
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().as_str().to_owned()
}

fn production_echo_plan() -> serde_json::Value {
    json!({
        "schema_version": 1,
        "name": "codegen-review",
        "version": 3,
        "kind": "instance",
        "maturity": "production",
        "stages": [
            {
                "id": "s1",
                "model": { "literal": "m-default" },
                "agent_count": 1,
                "limits": { "max_turns": 4, "max_cost_usd": 0.5, "context_budget_chars": 40000 },
                "tools": ["echo"],
                "metrics": [],
                "action": { "capability": "echo", "input": { "marker": "keystone" } }
            }
        ],
        "defaults": { "model": { "literal": "m-default" } }
    })
}

/// V-AC-2 — a plan loaded through `FileStore::load` is byte-for-byte the same
/// `SkillPlan` the legacy `fs::read` + `serde_json::from_slice` produced.
#[tokio::test]
async fn filestore_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let plan_path = dir.path().join("plan.json");
    let bytes = serde_json::to_vec(&production_echo_plan()).unwrap();
    std::fs::write(&plan_path, &bytes).unwrap();

    // Legacy path.
    let legacy: arcana_skills::SkillPlan = serde_json::from_slice(&bytes).unwrap();

    // Seam path.
    let store = FileStore;
    let pin = SkillPin::local(plan_path.display().to_string());
    let via_store = store.load(&pin).await.expect("FileStore load ok");

    assert_eq!(legacy, via_store, "FileStore load must be byte-identical");
}

/// V-AC-1 (seam) — the extracted `run(&Path)` wrapper still runs a plan
/// end-to-end through a `FileStore`, preserving the legacy entry point.
#[tokio::test]
async fn run_wrapper_still_executes() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let plan_path = dir.path().join("plan.json");
    std::fs::write(&plan_path, serde_json::to_vec(&production_echo_plan()).unwrap()).unwrap();

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    let out = interpreter.run(&plan_path, &ctx).await.expect("run ok");
    assert_eq!(out.stages.len(), 1);
    assert!(out.stages[0].output.content.contains("keystone"));
    assert_eq!(out.selected_models, vec!["m-default"]);
}

/// V-AC-3 — the keystone rejects tampered bytes **before** parse. The bytes are
/// both (a) not the pinned blake3 and (b) invalid JSON; the store must return
/// `HashMismatch`, never `Parse` — proving `serde_json::from_slice` was never
/// reached.
#[tokio::test]
async fn hash_pin_rejects_before_parse() {
    let tampered = b"this is not json { and it is definitely not the pinned content".to_vec();
    // A pin for some *other* (legitimate) content — its blake3 will not match
    // the tampered bytes.
    let legit = serde_json::to_vec(&production_echo_plan()).unwrap();
    let pin = SkillPin::new("codegen-review", 3, blake3_hex(&legit), "kb:skill:codegen-review:3");

    let store = ScrutatorStore::new(Arc::new(FixedConn::new(tampered)));
    let err = store.load(&pin).await.expect_err("tampered bytes must be rejected");

    match err {
        SkillError::HashMismatch { source_id } => {
            assert_eq!(source_id, "kb:skill:codegen-review:3");
        }
        other => panic!("expected HashMismatch (before parse), got {other:?}"),
    }
}

/// Positive keystone path — bytes whose blake3 equals the pin load and run.
#[tokio::test]
async fn hash_pin_accepts_matching_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();

    let bytes = serde_json::to_vec(&production_echo_plan()).unwrap();
    let pin = SkillPin::new("codegen-review", 3, blake3_hex(&bytes), "kb:skill:codegen-review:3");
    let store = ScrutatorStore::new(Arc::new(FixedConn::new(bytes)));

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());
    let ctx = hook_ctx();

    let out = interpreter
        .run_pinned(&store, &pin, &ctx)
        .await
        .expect("matching bytes must load and run");
    assert_eq!(out.version, 3);
    assert!(out.stages[0].output.content.contains("keystone"));
}

/// A one-stage production plan with the given tool list and model id.
fn plan_with(tools: serde_json::Value, model: &str) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "name": "codegen-review",
        "version": 3,
        "kind": "instance",
        "maturity": "production",
        "stages": [{
            "id": "s1",
            "model": { "literal": model },
            "agent_count": 1,
            "limits": { "max_turns": 1, "max_cost_usd": 0.0, "context_budget_chars": 1024 },
            "tools": tools,
            "metrics": [],
            "action": { "capability": "echo", "input": { "marker": "gated" } }
        }],
        "defaults": { "model": { "literal": model } }
    })
}

/// Run `plan` through a guarded `interpreter` via a `FileStore` local pin.
async fn run_local(
    interpreter: &SkillInterpreter,
    plan: serde_json::Value,
    dir: &std::path::Path,
) -> Result<arcana_skills::SkillRunOutput, SkillError> {
    let plan_path = dir.join("plan.json");
    std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
    interpreter.run(&plan_path, &hook_ctx()).await
}

/// V-AC-4 — a plan declaring a tool outside the per-agent ceiling is rejected;
/// a plan whose tools are a subset of the ceiling runs (the ceiling can only be
/// narrowed, never widened).
#[tokio::test]
async fn tool_ceiling_cannot_widen() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new())
        .with_tool_ceiling(ToolCeiling::new(["echo", "read"]));

    // Outside the ceiling → rejected.
    let err = run_local(&interpreter, plan_with(json!(["echo", "bash"]), "m-default"), dir.path())
        .await
        .expect_err("a tool outside the ceiling must be rejected");
    match err {
        SkillError::ToolCeilingExceeded { stage_id, tool } => {
            assert_eq!(stage_id, "s1");
            assert_eq!(tool, "bash");
        }
        other => panic!("expected ToolCeilingExceeded, got {other:?}"),
    }

    // Subset of the ceiling → runs.
    let out = run_local(&interpreter, plan_with(json!(["echo"]), "m-default"), dir.path())
        .await
        .expect("a subset-of-ceiling plan must run");
    assert_eq!(out.stages.len(), 1);
}

/// V-AC-5 — a stage whose resolved model endpoint is outside the per-agent
/// allowlist is rejected with `ModelNotAllowed`; an allowed endpoint runs.
#[tokio::test]
async fn model_spec_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new())
        .with_model_allowlist(ModelAllowlist::new(["m-default", "m-review"]));

    // Off-list model → rejected before any stage executes.
    let err = run_local(&interpreter, plan_with(json!(["echo"]), "m-exfiltrator"), dir.path())
        .await
        .expect_err("an off-allowlist model must be rejected");
    match err {
        SkillError::ModelNotAllowed { stage_id, model } => {
            assert_eq!(stage_id, "s1");
            assert_eq!(model, "m-exfiltrator");
        }
        other => panic!("expected ModelNotAllowed, got {other:?}"),
    }

    // Allowed model → runs.
    let out = run_local(&interpreter, plan_with(json!(["echo"]), "m-review"), dir.path())
        .await
        .expect("an allowlisted model must run");
    assert_eq!(out.selected_models, vec!["m-review"]);
}
