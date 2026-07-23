//! ARAS-0051 — the production skills-store **cutover** seam (`V-AC-13`).
//!
//! The production agent driver selects its byte-acquisition backend from a
//! [`SkillSourceMode`]: `Production` routes every skill load through the
//! untrusted-KB [`ScrutatorStore`] (the full 0047 gate chain — `trust_class`
//! fence → blake3 keystone → schema validate; then the interpreter's maturity →
//! tool-ceiling → model allowlist), while `Bootstrap` uses the trusted
//! [`FileStore`] for bundled/offline ids only. The default is fail-closed
//! `Production`: a missing/blank selector never silently yields the trusted
//! local path, and a store outage in production mode surfaces as
//! `StoreUnavailable` — never a `FileStore` fallback.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::sync::Arc;

use arcana_core::dispatch::ModelPolicy;
use arcana_skills::{
    select_skill_store, FetchConn, FetchUnavailable, FetchedContent, SkillError, SkillInterpreter,
    SkillPin, SkillSourceMode, StoreKind, SKILLS_NAMESPACE, SKILL_TRUST_CLASS,
};
use async_trait::async_trait;
use serde_json::json;

use common::{executor_with, hook_ctx, EchoTool};

/// A `FetchConn` that always fails — models a store that is down.
struct DownConn;

#[async_trait]
impl FetchConn for DownConn {
    async fn fetch(&self, _source_id: &str) -> Result<FetchedContent, FetchUnavailable> {
        Err(FetchUnavailable("connection refused".into()))
    }
}

/// A `FetchConn` returning fixed skill-class bytes in the skills namespace.
struct FixedConn(Vec<u8>);

#[async_trait]
impl FetchConn for FixedConn {
    async fn fetch(&self, _source_id: &str) -> Result<FetchedContent, FetchUnavailable> {
        Ok(FetchedContent {
            bytes: self.0.clone(),
            trust_class: SKILL_TRUST_CLASS.to_owned(),
            namespace: SKILLS_NAMESPACE.to_owned(),
        })
    }
}

/// A `FetchConn` returning an attacker-chosen trust_class (to prove the gate
/// chain is intact on the *selected* production store).
struct EvidenceConn(Vec<u8>);

#[async_trait]
impl FetchConn for EvidenceConn {
    async fn fetch(&self, _source_id: &str) -> Result<FetchedContent, FetchUnavailable> {
        Ok(FetchedContent {
            bytes: self.0.clone(),
            trust_class: "evidence".to_owned(),
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
        "stages": [{
            "id": "s1",
            "model": { "literal": "m-default" },
            "agent_count": 1,
            "limits": { "max_turns": 4, "max_cost_usd": 0.5, "context_budget_chars": 40000 },
            "tools": ["echo"],
            "metrics": [],
            "action": { "capability": "echo", "input": { "marker": "keystone" } }
        }],
        "defaults": { "model": { "literal": "m-default" } }
    })
}

/// V-AC-13 — production mode selects the `ScrutatorStore`, never the `FileStore`.
#[tokio::test]
async fn production_mode_selects_scrutator_store() {
    let bytes = serde_json::to_vec(&production_echo_plan()).unwrap();
    let store = select_skill_store(SkillSourceMode::Production, Arc::new(FixedConn(bytes)));
    assert_eq!(
        store.kind(),
        StoreKind::Scrutator,
        "production mode must route skills through the untrusted-KB ScrutatorStore"
    );
}

/// V-AC-13 — bootstrap mode selects the trusted `FileStore` (bundled/offline).
#[tokio::test]
async fn bootstrap_mode_selects_file_store() {
    let store = select_skill_store(SkillSourceMode::Bootstrap, Arc::new(DownConn));
    assert_eq!(
        store.kind(),
        StoreKind::File,
        "bootstrap mode must serve bundled ids from the trusted FileStore"
    );
}

/// V-AC-13 fail-closed — a store outage in production mode surfaces as
/// `StoreUnavailable`; the selector never falls back to a `FileStore` that would
/// read a different (local, trusted-by-fiat) skill.
#[tokio::test]
async fn production_mode_store_unavailable_fails_closed_no_file_fallback() {
    let store = select_skill_store(SkillSourceMode::Production, Arc::new(DownConn));
    let pin = SkillPin::new("codegen-review", 3, "00", "kb:skill:codegen-review:3");
    match store
        .load(&pin)
        .await
        .expect_err("a down store must fail closed")
    {
        SkillError::StoreUnavailable { source_id, .. } => {
            assert_eq!(source_id, "kb:skill:codegen-review:3");
        }
        other => panic!("expected StoreUnavailable (no FileStore fallback), got {other:?}"),
    }
}

/// V-AC-13 gate-chain intact — the selected production store still enforces the
/// pre-parse `trust_class` fence: an `evidence`-class document whose bytes would
/// pass the blake3 keystone is rejected with `WrongTrustClass`, and the
/// interpreter runs **zero** stages (no silent fallback).
#[tokio::test]
async fn production_store_keeps_full_gate_chain() {
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
    let store = select_skill_store(SkillSourceMode::Production, Arc::new(EvidenceConn(bytes)));

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());

    // The fence rejects before `execute`, so no stage runs (fail-closed).
    match interpreter
        .run_pinned(store.as_ref(), &pin, &hook_ctx())
        .await
        .expect_err("evidence-class must be rejected by the selected production store")
    {
        SkillError::WrongTrustClass { trust_class, .. } => assert_eq!(trust_class, "evidence"),
        other => panic!("expected WrongTrustClass, got {other:?}"),
    }
}

/// V-AC-13 positive — the selected production store loads a correctly pinned
/// skill end-to-end through the full gate chain and runs it.
#[tokio::test]
async fn production_store_loads_and_runs_pinned_skill() {
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
    let store = select_skill_store(SkillSourceMode::Production, Arc::new(FixedConn(bytes)));

    let executor = executor_with(vec![Arc::new(EchoTool)], &audit);
    let interpreter = SkillInterpreter::new(executor, ModelPolicy::new());

    let out = interpreter
        .run_pinned(store.as_ref(), &pin, &hook_ctx())
        .await
        .expect("a correctly pinned skill loads and runs in production mode");
    assert_eq!(out.version, 3);
    assert!(out.stages[0].output.content.contains("keystone"));
}

/// V-AC-13 env selection — the mode resolves from `ARCANA_SKILLS_SOURCE`, and a
/// missing/blank value defaults **fail-closed** to `Production` (never silently
/// the trusted local `FileStore`). An unrecognised value is a hard error, not a
/// silent default.
#[test]
fn source_mode_from_str_is_fail_closed() {
    assert_eq!(
        SkillSourceMode::from_selector(None).unwrap(),
        SkillSourceMode::Production,
        "absent selector must default to Production (fail-closed)"
    );
    assert_eq!(
        SkillSourceMode::from_selector(Some("  ")).unwrap(),
        SkillSourceMode::Production,
        "blank selector must default to Production (fail-closed)"
    );
    assert_eq!(
        SkillSourceMode::from_selector(Some("production")).unwrap(),
        SkillSourceMode::Production
    );
    assert_eq!(
        SkillSourceMode::from_selector(Some("scrutator")).unwrap(),
        SkillSourceMode::Production
    );
    assert_eq!(
        SkillSourceMode::from_selector(Some("bootstrap")).unwrap(),
        SkillSourceMode::Bootstrap
    );
    assert_eq!(
        SkillSourceMode::from_selector(Some("file")).unwrap(),
        SkillSourceMode::Bootstrap
    );
    // Case-insensitive.
    assert_eq!(
        SkillSourceMode::from_selector(Some("PRODUCTION")).unwrap(),
        SkillSourceMode::Production
    );
    // An unknown value must NOT silently pick a mode.
    assert!(
        SkillSourceMode::from_selector(Some("filestore-please")).is_err(),
        "an unrecognised selector must be a hard error, not a silent default"
    );
}
