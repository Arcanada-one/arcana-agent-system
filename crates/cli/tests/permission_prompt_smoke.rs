//! Smoke test: [`ReadlinePrompt`] wired into a real [`PermissionCascade`] tail.
//!
//! Mirrors what `crates/cli` bootstrap will do — push schema/hook/rule
//! layers first, terminate the chain with the interactive prompt — and
//! confirms the cascade short-circuits exactly as specified by the
//! permission cascade invariants.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::match_wildcard_for_single_variants
)]

use std::sync::Arc;

use arcana_cli::permission_prompt::{MockSource, ReadlinePrompt};
use arcana_core::permission::{CascadeOutcome, LayerDecision, PermissionCascade, PermissionLayer};
use async_trait::async_trait;
use serde_json::{json, Value};

struct ConstLayer(LayerDecision);

#[async_trait]
impl PermissionLayer for ConstLayer {
    fn name(&self) -> &'static str {
        "const-test"
    }

    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        self.0.clone()
    }
}

#[tokio::test]
async fn readline_prompt_terminates_deferring_cascade_with_allow() {
    let cascade = PermissionCascade::new(vec![
        Arc::new(ConstLayer(LayerDecision::Defer)),
        Arc::new(ConstLayer(LayerDecision::Defer)),
        Arc::new(ConstLayer(LayerDecision::Defer)),
        Arc::new(ReadlinePrompt::new(MockSource::new(["y"]))),
    ]);

    let outcome = cascade
        .evaluate("read_file", json!({"path": "/tmp/x"}))
        .await;
    assert!(
        matches!(outcome, CascadeOutcome::Allowed { .. }),
        "expected Allowed on scripted `y`, got {outcome:?}"
    );
}

#[tokio::test]
async fn readline_prompt_terminates_deferring_cascade_with_deny_on_eof() {
    let cascade = PermissionCascade::new(vec![
        Arc::new(ConstLayer(LayerDecision::Defer)),
        Arc::new(ReadlinePrompt::new(MockSource::new(Vec::<String>::new()))),
    ]);

    let outcome = cascade.evaluate("bash", json!({"cmd": "ls"})).await;
    match outcome {
        CascadeOutcome::Denied { layer, reason } => {
            assert_eq!(layer, "interactive_readline");
            assert!(reason.contains("closed (EOF)"));
        }
        other => panic!("expected Denied on empty input queue, got {other:?}"),
    }
}

#[tokio::test]
async fn earlier_deny_short_circuits_before_prompt_fires() {
    // Drained MockSource — would panic-ish (Deny EOF) if the cascade ever
    // hit Layer 4. The Layer-2 Deny must prevent it.
    let cascade = PermissionCascade::new(vec![
        Arc::new(ConstLayer(LayerDecision::Defer)),
        Arc::new(ConstLayer(LayerDecision::Deny("policy-block".into()))),
        Arc::new(ConstLayer(LayerDecision::Allow)),
        Arc::new(ReadlinePrompt::new(MockSource::new(Vec::<String>::new()))),
    ]);

    let outcome = cascade.evaluate("write_file", json!({})).await;
    match outcome {
        CascadeOutcome::Denied { reason, .. } => {
            assert_eq!(reason, "policy-block");
        }
        other => panic!("expected first-Deny short-circuit, got {other:?}"),
    }
}
