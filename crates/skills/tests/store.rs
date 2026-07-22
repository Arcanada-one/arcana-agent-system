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
use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use arcana_skills::{
    BlakeCache, FetchConn, FetchUnavailable, FetchedContent, FileStore, ModelAllowlist,
    ScrutatorStore, SkillError, SkillInterpreter, SkillPin, SkillStore, ToolCeiling,
    SKILLS_NAMESPACE, SKILL_TRUST_CLASS,
};
use async_trait::async_trait;
use serde_json::{json, Value};

use common::{executor_with, hook_ctx, EchoTool};

/// A `FetchConn` that always fails — models a store that is down.
struct DownConn;

#[async_trait]
impl FetchConn for DownConn {
    async fn fetch(&self, _source_id: &str) -> Result<FetchedContent, FetchUnavailable> {
        Err(FetchUnavailable("connection refused".into()))
    }
}

/// A `FetchConn` that returns the given bytes under an attacker-chosen
/// `trust_class` / `namespace` — used to prove the store's pre-parse fence.
struct TrustConn {
    bytes: Vec<u8>,
    trust_class: String,
    namespace: String,
}

#[async_trait]
impl FetchConn for TrustConn {
    async fn fetch(&self, _source_id: &str) -> Result<FetchedContent, FetchUnavailable> {
        Ok(FetchedContent {
            bytes: self.bytes.clone(),
            trust_class: self.trust_class.clone(),
            namespace: self.namespace.clone(),
        })
    }
}

/// An `echo`-named tool that counts how many times the executor invoked it, so
/// a "no silent fallback" test can prove the executor ran zero stages.
struct CountingEcho {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Tool for CountingEcho {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn description(&self) -> &'static str {
        "counts invocations (test tool)"
    }
    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }
    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ToolOutput {
            content: invocation.into_input().to_string(),
            metadata: None,
        })
    }
}

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
    async fn fetch(&self, _source_id: &str) -> Result<FetchedContent, FetchUnavailable> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(FetchedContent {
            bytes: self.bytes.clone(),
            trust_class: SKILL_TRUST_CLASS.to_owned(),
            namespace: SKILLS_NAMESPACE.to_owned(),
        })
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
    std::fs::write(
        &plan_path,
        serde_json::to_vec(&production_echo_plan()).unwrap(),
    )
    .unwrap();

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
    let pin = SkillPin::new(
        "codegen-review",
        3,
        blake3_hex(&legit),
        "kb:skill:codegen-review:3",
    );

    let store = ScrutatorStore::new(Arc::new(FixedConn::new(tampered)));
    let err = store
        .load(&pin)
        .await
        .expect_err("tampered bytes must be rejected");

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
    let pin = SkillPin::new(
        "codegen-review",
        3,
        blake3_hex(&bytes),
        "kb:skill:codegen-review:3",
    );
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
    let err = run_local(
        &interpreter,
        plan_with(json!(["echo", "bash"]), "m-default"),
        dir.path(),
    )
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
    let out = run_local(
        &interpreter,
        plan_with(json!(["echo"]), "m-default"),
        dir.path(),
    )
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
    let err = run_local(
        &interpreter,
        plan_with(json!(["echo"]), "m-exfiltrator"),
        dir.path(),
    )
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
    let out = run_local(
        &interpreter,
        plan_with(json!(["echo"]), "m-review"),
        dir.path(),
    )
    .await
    .expect("an allowlisted model must run");
    assert_eq!(out.selected_models, vec!["m-review"]);
}

/// V-AC-6 — when the store is down **and** the cache misses, the run fails
/// closed to `StoreUnavailable`; the executor is invoked **zero** times (no
/// silent fallback to a different or stale skill).
#[tokio::test]
async fn store_unavailable_never_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir(&cache_dir).unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let executor = executor_with(
        vec![Arc::new(CountingEcho {
            calls: calls.clone(),
        })],
        &audit,
    );
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());

    // Store down + empty cache → miss → StoreUnavailable.
    let store =
        ScrutatorStore::new(Arc::new(DownConn)).with_cache(BlakeCache::with_root(cache_dir));
    let pin = SkillPin::new("codegen-review", 3, "00", "kb:skill:codegen-review:3");

    let err = interpreter
        .run_pinned(&store, &pin, &hook_ctx())
        .await
        .expect_err("a down store with no cache must fail closed");
    match err {
        SkillError::StoreUnavailable { source_id, .. } => {
            assert_eq!(source_id, "kb:skill:codegen-review:3");
        }
        other => panic!("expected StoreUnavailable, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the executor must run zero stages on a store failure"
    );
}

/// V-AC-7 — a blake3-keyed cache hit runs without any network fetch.
#[tokio::test]
async fn cache_hit_no_network() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir(&cache_dir).unwrap();

    let bytes = serde_json::to_vec(&production_echo_plan()).unwrap();
    let hash = blake3_hex(&bytes);
    let cache = BlakeCache::with_root(cache_dir);
    cache.put(&hash, &bytes).unwrap();

    // The connector would return the wrong bytes and counts its calls — it must
    // never be reached on a cache hit.
    let conn = Arc::new(FixedConn::new(b"SHOULD-NOT-BE-FETCHED".to_vec()));
    let store = ScrutatorStore::new(conn.clone()).with_cache(cache);
    let pin = SkillPin::new("codegen-review", 3, hash, "kb:skill:codegen-review:3");

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());

    let out = interpreter
        .run_pinned(&store, &pin, &hook_ctx())
        .await
        .expect("a cache hit must run");
    assert_eq!(out.version, 3);
    assert_eq!(
        conn.calls.load(Ordering::SeqCst),
        0,
        "a cache hit must perform zero network fetches"
    );
}

/// V-AC-9 — the two-phase firewall: a fuzzy `SkillCandidate` can never become a
/// `SkillPin` (that absence is proven at compile time by a `compile_fail`
/// doctest on `SkillCandidate`). Here we prove the *security consequence*: the
/// only field a candidate could offer as a hash is its SHA-256 `content_hash`,
/// which is not a blake3 anchor — so even if code naively fed it to a pin, the
/// run fails closed with `HashMismatch`, never executing the skill.
#[tokio::test]
async fn candidate_cannot_construct_pin() {
    use arcana_skills::{Maturity, SkillCandidate};

    let bytes = serde_json::to_vec(&production_echo_plan()).unwrap();

    // A search proposal. It carries a SHA-256 content_hash, no blake3.
    let candidate = SkillCandidate {
        name: "codegen-review".into(),
        version: 3,
        content_hash: format!("sha256:{}", "de".repeat(32)),
        maturity: Maturity::Production,
        score: 0.94,
    };

    // The ONLY way to reach a pin is to author one from trusted config. If an
    // attacker/naive caller instead tried to derive the pin's trust anchor from
    // the candidate's content_hash, the fetched bytes' real blake3 will not
    // match it → HashMismatch, before parse, before any execution.
    let forged_pin = SkillPin::new(
        candidate.name.clone(),
        candidate.version,
        candidate.content_hash.clone(), // SHA-256 masquerading as the blake3 anchor
        "kb:skill:codegen-review:3",
    );
    let store = ScrutatorStore::new(Arc::new(FixedConn::new(bytes.clone())));
    let err = store
        .load(&forged_pin)
        .await
        .expect_err("a candidate-derived hash can never authorize a run");
    assert!(
        matches!(err, SkillError::HashMismatch { .. }),
        "expected HashMismatch, got {err:?}"
    );

    // A correctly config-authored pin (real blake3) loads — proving the pin
    // itself is the authorization boundary, not the candidate.
    let real_pin = SkillPin::new(
        "codegen-review",
        3,
        blake3_hex(&bytes),
        "kb:skill:codegen-review:3",
    );
    ScrutatorStore::new(Arc::new(FixedConn::new(bytes)))
        .load(&real_pin)
        .await
        .expect("a config-authored pin loads");
}

/// V-AC-12 — an `evidence`-class document whose bytes would otherwise PASS the
/// blake3 keystone is rejected by the trust_class fence **before** blake3 and
/// before parse. The pin's blake3 matches the returned bytes exactly, so a
/// `HashMismatch` here would prove the fence ran too late; the store must return
/// `WrongTrustClass` instead.
#[tokio::test]
async fn wrong_trust_class_rejected_before_blake3() {
    let bytes = serde_json::to_vec(&production_echo_plan()).unwrap();
    // Pin matches the bytes byte-for-byte — the blake3 keystone WOULD accept.
    let pin = SkillPin::new(
        "codegen-review",
        3,
        blake3_hex(&bytes),
        "kb:skill:codegen-review:3",
    );
    let conn = TrustConn {
        bytes,
        trust_class: "evidence".into(),
        namespace: SKILLS_NAMESPACE.into(),
    };
    let store = ScrutatorStore::new(Arc::new(conn));

    match store
        .load(&pin)
        .await
        .expect_err("evidence class must be rejected")
    {
        SkillError::WrongTrustClass {
            source_id,
            trust_class,
            namespace,
        } => {
            assert_eq!(source_id, "kb:skill:codegen-review:3");
            assert_eq!(trust_class, "evidence");
            assert_eq!(namespace, SKILLS_NAMESPACE);
        }
        other => panic!("expected WrongTrustClass (before blake3), got {other:?}"),
    }
}

/// V-AC-12 — a `skill`-class document served from a namespace OTHER than the
/// expected skills namespace is rejected (defense in depth: the store checks the
/// namespace as well as the class, so a mislabelled/compromised feeder cannot
/// smuggle a skill trust_class on a foreign namespace).
#[tokio::test]
async fn wrong_namespace_rejected() {
    let bytes = serde_json::to_vec(&production_echo_plan()).unwrap();
    let pin = SkillPin::new(
        "codegen-review",
        3,
        blake3_hex(&bytes),
        "kb:skill:codegen-review:3",
    );
    let conn = TrustConn {
        bytes,
        trust_class: SKILL_TRUST_CLASS.into(),
        namespace: "evidence".into(),
    };
    let store = ScrutatorStore::new(Arc::new(conn));

    match store
        .load(&pin)
        .await
        .expect_err("foreign namespace must be rejected")
    {
        SkillError::WrongTrustClass { namespace, .. } => assert_eq!(namespace, "evidence"),
        other => panic!("expected WrongTrustClass, got {other:?}"),
    }
}

/// V-AC-12 — the trust_class fence is fail-closed end-to-end: a rejected
/// document runs **zero** stages through the interpreter (no silent fallback).
#[tokio::test]
async fn wrong_trust_class_runs_zero_stages() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    std::fs::create_dir(&audit).unwrap();

    let bytes = serde_json::to_vec(&production_echo_plan()).unwrap();
    let pin = SkillPin::new(
        "codegen-review",
        3,
        blake3_hex(&bytes),
        "kb:skill:codegen-review:3",
    );
    let conn = TrustConn {
        bytes,
        trust_class: "evidence".into(),
        namespace: SKILLS_NAMESPACE.into(),
    };
    let store = ScrutatorStore::new(Arc::new(conn));

    let calls = Arc::new(AtomicUsize::new(0));
    let executor = executor_with(
        vec![Arc::new(CountingEcho {
            calls: calls.clone(),
        })],
        &audit,
    );
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());

    interpreter
        .run_pinned(&store, &pin, &hook_ctx())
        .await
        .expect_err("a wrong-trust-class document must not run");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no stage may execute on a trust_class rejection"
    );
}
