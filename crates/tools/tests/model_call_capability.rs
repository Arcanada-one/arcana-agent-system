//! V-AC-7 (D-REQ-04): "call an LLM" as a cascade-gated capability.
//!
//! Drives `ModelCallTool` through the sealed `CapabilityExecutor` so every
//! model invocation passes the same `Schema → Rule → dispatch` choke-point as
//! `bash` / `webfetch` / `arcana_search`. A `FakeModelConnector` stands in for
//! the network edge (no HTTP). Two legs of the DoD:
//!   T1 — an un-allowed model is denied at the `"rule"` layer, the connector is
//!        never reached, and no cost is recorded.
//!   T2 — an allowed model emits exactly one Blake3 audit decision record plus
//!        a `CostTracker` cost line.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use arcana_core::cost::CostTracker;
use arcana_core::execution::{CapabilityError, CapabilityExecutor};
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::{HookChain, HookContext};
use arcana_core::permission::{PermissionCascade, RuleLayer};
use arcana_core::tool::ToolDispatcher;
use arcana_tools::model_call::ModelCallTool;
use async_trait::async_trait;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const CANNED_RESULT: &str = "the-llm-answer";
/// `round(0.000_012_3 * 1e6) == 12` micro-USD — the asserted cost line.
const CANNED_COST_USD: f64 = 0.000_012_3;
const ALLOW_ONLY_CHEAP: &str =
    "schema_version = 1\n[tool.model_call]\nallow_models = [\"^arcana-cheap-fast$\"]\n";

/// In-test `ModelConnector` double: records call count and returns a canned
/// success response. Never touches the network.
struct FakeModelConnector {
    calls: Arc<AtomicUsize>,
}

impl FakeModelConnector {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

#[async_trait]
impl ModelConnector for FakeModelConnector {
    async fn execute(&self, req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ConnectorResponse {
            id: "fake-id".into(),
            connector: req.connector,
            model: req.model.unwrap_or_else(|| "unknown".into()),
            result: CANNED_RESULT.into(),
            usage: Usage {
                input_tokens: 11,
                output_tokens: 7,
                total_tokens: 18,
                cost_usd: CANNED_COST_USD,
            },
            latency_ms: 5,
            status: "success".into(),
            error: None,
        })
    }
}

/// Build a production-shaped executor whose only cascade layer is a real
/// `RuleLayer` loaded from `perms_toml`. Returns the executor plus the two
/// tempdirs (audit sink + rules dir) that must outlive it.
fn executor_with_rules(
    perms_toml: &str,
    cost: Arc<CostTracker>,
    connector: Arc<dyn ModelConnector>,
) -> (CapabilityExecutor, TempDir, TempDir) {
    let rules_dir = TempDir::new().expect("rules tempdir");
    let perms_path = rules_dir.path().join("permissions.toml");
    std::fs::write(&perms_path, perms_toml).expect("write permissions.toml");
    let rule_layer = RuleLayer::load(Some(&perms_path), None).expect("rule layer loads");
    let cascade = PermissionCascade::new(vec![Arc::new(rule_layer)]);

    let mut registry = ToolDispatcher::new();
    registry
        .register(Arc::new(ModelCallTool::new(connector, cost, "claude-code")))
        .expect("register model_call");

    let audit_dir = TempDir::new().expect("audit tempdir");
    let audit = AuditLog::new(audit_dir.path()).expect("audit log");
    let executor = CapabilityExecutor::new(registry, cascade, HookChain::new(), audit);
    (executor, audit_dir, rules_dir)
}

fn ctx() -> HookContext {
    HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()))
}

fn audit_lines(dir: &TempDir) -> Vec<Value> {
    let raw = std::fs::read_to_string(dir.path().join("audit.log")).expect("read audit.log");
    raw.lines()
        .map(|line| serde_json::from_str(line).expect("audit line is json"))
        .collect()
}

/// T1 — an un-allowed model is denied at the `"rule"` layer; the connector is
/// never reached; cost stays 0; the audit log carries Denied@rule + denied.
#[tokio::test]
async fn t1_unallowed_model_denied_at_rule_layer() {
    let cost = Arc::new(CostTracker::new());
    let (connector, calls) = FakeModelConnector::new();
    let (executor, audit_dir, _rules_dir) =
        executor_with_rules(ALLOW_ONLY_CHEAP, Arc::clone(&cost), Arc::new(connector));

    let err = executor
        .execute(
            &ctx(),
            "model_call",
            json!({ "prompt": "hello", "model": "forbidden-model" }),
        )
        .await
        .expect_err("un-allowed model must be denied");

    match err {
        CapabilityError::Denied { layer, .. } => {
            assert_eq!(layer, "rule", "deny must originate at the rule layer");
        }
        other => panic!("expected a rule-layer denial, got {other:?}"),
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "connector must never be reached on a denied call"
    );
    assert_eq!(
        cost.snapshot().total_calls,
        0,
        "no cost is recorded on a denied call"
    );

    let lines = audit_lines(&audit_dir);
    let denied_decision = lines
        .iter()
        .any(|v| v["phase"] == "decision" && v["decision"] == "Denied" && v["layer"] == "rule");
    let denied_result = lines
        .iter()
        .any(|v| v["phase"] == "result" && v["outcome"] == "denied");
    assert!(denied_decision, "audit must record Denied@rule: {lines:?}");
    assert!(
        denied_result,
        "audit must record a denied result: {lines:?}"
    );
}

/// T2 — an allowed model call emits exactly one Blake3 audit decision record
/// (`Allowed`@`cascade`, hashed input) plus a `success` result, and records
/// exactly one cost line (`total_calls == 1`, `12` micro-USD).
#[tokio::test]
async fn t2_allowed_model_emits_audit_and_cost() {
    let cost = Arc::new(CostTracker::new());
    let (connector, calls) = FakeModelConnector::new();
    let (executor, audit_dir, _rules_dir) =
        executor_with_rules(ALLOW_ONLY_CHEAP, Arc::clone(&cost), Arc::new(connector));

    let out = executor
        .execute(
            &ctx(),
            "model_call",
            json!({ "prompt": "hello", "model": "arcana-cheap-fast" }),
        )
        .await
        .expect("allowed model call succeeds");

    assert_eq!(out.output.content, CANNED_RESULT);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "connector called exactly once"
    );

    // The cost line.
    let snap = cost.snapshot();
    assert_eq!(snap.total_calls, 1, "exactly one cost line recorded");
    assert_eq!(
        snap.total_cost_usd_micros, 12,
        "round(0.0000123 * 1e6) == 12 micro-USD"
    );
    assert_eq!(snap.total_tokens_in, 11);
    assert_eq!(snap.total_tokens_out, 7);

    // The audit line: exactly one Allowed@cascade decision with a Blake3 hash,
    // plus exactly one success result.
    let lines = audit_lines(&audit_dir);
    let mut allowed_decisions = 0;
    let mut success_results = 0;
    for v in &lines {
        if v["phase"] == "decision" && v["decision"] == "Allowed" && v["layer"] == "cascade" {
            allowed_decisions += 1;
            let hash = v["input_hash"].as_str().expect("input_hash present");
            assert_eq!(hash.len(), 16, "Blake3 hex prefix is 16 chars");
            assert!(
                hash.chars().all(|c| c.is_ascii_hexdigit()),
                "input_hash must be hex: {hash}"
            );
        }
        if v["phase"] == "result" && v["outcome"] == "success" {
            success_results += 1;
        }
    }
    assert_eq!(
        allowed_decisions, 1,
        "exactly one Allowed@cascade audit record: {lines:?}"
    );
    assert_eq!(
        success_results, 1,
        "exactly one success result record: {lines:?}"
    );
}
