//! PermissionCascade contract.
//!
//! Four invariants are exercised:
//!   1. Layer order — Schema → PreHook → Rule → Interactive.
//!   2. First-`Deny` short-circuit — downstream layers do not run.
//!   3. `ReplaceInput` propagation — pre-hook may mutate the payload and
//!      every downstream layer sees the new value.
//!   4. All-`Defer` resolves fail-closed to `Denied { layer: "cascade" }` —
//!      no authority answered, so the call is refused, not auto-approved.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::match_wildcard_for_single_variants,
    clippy::doc_markdown
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use arcana_core::permission::{CascadeOutcome, LayerDecision, PermissionCascade, PermissionLayer};

/// Records call order so tests can assert layer ordering and short-circuits.
#[derive(Debug, Default)]
struct CallLog {
    order: std::sync::Mutex<Vec<&'static str>>,
}

impl CallLog {
    fn push(&self, name: &'static str) {
        self.order.lock().unwrap().push(name);
    }

    fn snapshot(&self) -> Vec<&'static str> {
        self.order.lock().unwrap().clone()
    }
}

struct FakeLayer {
    name: &'static str,
    decision: LayerDecision,
    log: Arc<CallLog>,
}

#[async_trait]
impl PermissionLayer for FakeLayer {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        self.log.push(self.name);
        self.decision.clone()
    }
}

/// Layer that asserts the input it observes matches an expected value.
struct AssertInputLayer {
    name: &'static str,
    expected: Value,
    seen: Arc<AtomicUsize>,
}

#[async_trait]
impl PermissionLayer for AssertInputLayer {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn evaluate(&self, _tool: &str, input: &Value) -> LayerDecision {
        assert_eq!(input, &self.expected, "layer {} saw wrong input", self.name);
        self.seen.fetch_add(1, Ordering::SeqCst);
        LayerDecision::Defer
    }
}

fn fake(
    name: &'static str,
    decision: LayerDecision,
    log: &Arc<CallLog>,
) -> Arc<dyn PermissionLayer> {
    Arc::new(FakeLayer {
        name,
        decision,
        log: Arc::clone(log),
    })
}

#[tokio::test]
async fn layer_order_schema_prehook_rule_interactive() {
    let log = Arc::new(CallLog::default());
    let cascade = PermissionCascade::new(vec![
        fake("schema", LayerDecision::Defer, &log),
        fake("prehook", LayerDecision::Defer, &log),
        fake("rule", LayerDecision::Defer, &log),
        fake("interactive", LayerDecision::Allow, &log),
    ]);

    let outcome = cascade.evaluate("read", json!({"path": "/tmp/x"})).await;

    assert!(matches!(outcome, CascadeOutcome::Allowed { .. }));
    assert_eq!(
        log.snapshot(),
        vec!["schema", "prehook", "rule", "interactive"]
    );
}

#[tokio::test]
async fn first_deny_short_circuits_downstream_layers() {
    let log = Arc::new(CallLog::default());
    let cascade = PermissionCascade::new(vec![
        fake("schema", LayerDecision::Defer, &log),
        fake(
            "prehook",
            LayerDecision::Deny("blocked-by-hook".into()),
            &log,
        ),
        fake("rule", LayerDecision::Allow, &log),
        fake("interactive", LayerDecision::Allow, &log),
    ]);

    let outcome = cascade.evaluate("bash", json!({"cmd": "rm -rf"})).await;

    match outcome {
        CascadeOutcome::Denied { layer, reason } => {
            assert_eq!(layer, "prehook");
            assert_eq!(reason, "blocked-by-hook");
        }
        other => panic!("expected Denied, got {other:?}"),
    }
    assert_eq!(log.snapshot(), vec!["schema", "prehook"]);
}

#[tokio::test]
async fn replace_input_propagates_to_downstream_layers() {
    let log = Arc::new(CallLog::default());
    let seen = Arc::new(AtomicUsize::new(0));
    let replaced = json!({"path": "/safe/sandboxed"});

    let cascade = PermissionCascade::new(vec![
        fake("schema", LayerDecision::Defer, &log),
        fake(
            "prehook",
            LayerDecision::ReplaceInput(replaced.clone()),
            &log,
        ),
        Arc::new(AssertInputLayer {
            name: "rule",
            expected: replaced.clone(),
            seen: Arc::clone(&seen),
        }),
        fake("interactive", LayerDecision::Allow, &log),
    ]);

    let outcome = cascade
        .evaluate("read", json!({"path": "/etc/shadow"}))
        .await;

    assert!(matches!(outcome, CascadeOutcome::Allowed { .. }));
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn all_defer_denies_closed_without_an_authority() {
    let log = Arc::new(CallLog::default());
    let cascade = PermissionCascade::new(vec![
        fake("schema", LayerDecision::Defer, &log),
        fake("prehook", LayerDecision::Defer, &log),
        fake("rule", LayerDecision::Defer, &log),
        fake("interactive", LayerDecision::Defer, &log),
    ]);
    let outcome = cascade
        .evaluate("read", json!({"path": "/etc/hosts"}))
        .await;

    match outcome {
        CascadeOutcome::Denied { layer, reason } => {
            assert_eq!(layer, "cascade");
            assert!(reason.contains("explicitly allowed"));
        }
        other => panic!("expected fail-closed Denied, got {other:?}"),
    }
}

#[tokio::test]
async fn schema_deny_short_circuits_entire_cascade() {
    let log = Arc::new(CallLog::default());
    let cascade = PermissionCascade::new(vec![
        fake("schema", LayerDecision::Deny("invalid-input".into()), &log),
        fake("prehook", LayerDecision::Allow, &log),
        fake("rule", LayerDecision::Allow, &log),
        fake("interactive", LayerDecision::Allow, &log),
    ]);

    let outcome = cascade.evaluate("read", json!({})).await;

    match outcome {
        CascadeOutcome::Denied { layer, reason } => {
            assert_eq!(layer, "schema");
            assert_eq!(reason, "invalid-input");
        }
        other => panic!("expected Denied, got {other:?}"),
    }
    assert_eq!(log.snapshot(), vec!["schema"]);
}

/// V-AC-15 (PRD § 9.2): integration test for default-deny on unknown MCP tool.
///
/// Assembles a realistic cascade — Layer 1 omitted (`Schema` validates against
/// the dispatcher's registered tools; MCP tools live outside the built-in
/// dispatcher); Layer 2 substituted with a `Defer` fake (hook bridge is
/// wiring-only here); Layer 3 [`RuleLayer::empty`] (no operator-authored
/// rules); Layer 4 [`AutoFromEnv`] with the `Ask` directive (non-TTY → Deny
/// fallback). The contract: an `mcp:*` tool without explicit allow MUST
/// resolve to `Denied { layer: "rule", reason: contains "no explicit allow
/// for MCP" }`.
#[tokio::test]
async fn v_ac_15_default_deny_unknown_mcp_tool() {
    use arcana_core::permission::{AutoFromEnv, InteractiveDirective, RuleLayer};

    let log = Arc::new(CallLog::default());
    let cascade = PermissionCascade::new(vec![
        fake("prehook", LayerDecision::Defer, &log),
        Arc::new(RuleLayer::empty()),
        Arc::new(AutoFromEnv::with_directive(InteractiveDirective::Ask)),
    ]);

    let outcome = cascade.evaluate("mcp:unknown/foo", json!({"x": 1})).await;

    match outcome {
        CascadeOutcome::Denied { layer, reason } => {
            assert_eq!(layer, "rule");
            assert!(
                reason.contains("no explicit allow for MCP"),
                "expected MCP-default-deny reason, got: {reason}"
            );
        }
        other => panic!("expected Denied at rule layer, got {other:?}"),
    }
}

/// Complementary case (tiered posture D-3): built-in tools without explicit
/// rule entries fall through to the Interactive layer. With `Allow`
/// directive the cascade resolves to `Allowed`, documenting that built-in
/// tools default-allow unless the operator restricts them.
#[tokio::test]
async fn builtin_tool_without_rules_falls_through_to_interactive_allow() {
    use arcana_core::permission::{AutoFromEnv, InteractiveDirective, RuleLayer};

    let log = Arc::new(CallLog::default());
    let cascade = PermissionCascade::new(vec![
        fake("prehook", LayerDecision::Defer, &log),
        Arc::new(RuleLayer::empty()),
        Arc::new(AutoFromEnv::with_directive(InteractiveDirective::Allow)),
    ]);

    let outcome = cascade.evaluate("read", json!({"path": "/tmp/x"})).await;

    match outcome {
        CascadeOutcome::Allowed { .. } => {}
        other => panic!("expected Allowed via auto-allow, got {other:?}"),
    }
}

/// First-Deny short-circuit invariant — exhaustive sweep over layer
/// arrangements. For each ordering of `total` layers with exactly one forced
/// `Deny` at position `deny_at`, downstream layers MUST NOT run. This is the
/// in-test property-style coverage for the invariant declared in `RuleLayer`
/// + cascade docs; full `proptest` integration is deferred (R-3 mitigation).
#[tokio::test]
async fn first_deny_short_circuit_sweep() {
    for total in 2..=6_usize {
        for deny_at in 0..total {
            let log = Arc::new(CallLog::default());
            let names: [&'static str; 6] = ["L0", "L1", "L2", "L3", "L4", "L5"];
            let layers: Vec<Arc<dyn PermissionLayer>> = (0..total)
                .map(|i| {
                    let decision = if i == deny_at {
                        LayerDecision::Deny(format!("denied-at-{i}"))
                    } else {
                        LayerDecision::Defer
                    };
                    fake(names[i], decision, &log)
                })
                .collect();
            let cascade = PermissionCascade::new(layers);
            let outcome = cascade.evaluate("read", json!({})).await;
            match outcome {
                CascadeOutcome::Denied { reason, .. } => {
                    assert_eq!(reason, format!("denied-at-{deny_at}"));
                }
                other => panic!("expected Denied, got {other:?}"),
            }
            let snapshot = log.snapshot();
            assert_eq!(
                snapshot.len(),
                deny_at + 1,
                "downstream layers ran after deny at position {deny_at}: {snapshot:?}"
            );
        }
    }
}
