//! Pure library consumer integration; no model, HTTP, storage or grant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arcana_cli::effect::{Effect, EffectExpectation};
use arcana_cli::run::RunSummary;
use arcana_cli::usage::bound_private_run_usage;
use arcana_core::agent_loop::{RunOutput, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::usage_export::RunUsageBinding;
use serde_json::Value;

fn binding(request: &str) -> RunUsageBinding {
    RunUsageBinding::new(
        "run".into(),
        "generation".into(),
        request.repeat(64),
        "b".repeat(40),
        "c".repeat(64),
        None,
    )
    .unwrap()
}

#[test]
fn cli_consumer_binds_observation_before_export_and_retains_unknown_allocation() {
    let tracker = CostTracker::new();
    tracker.record_llm_call("local-test-model", 12, 4, 0.001);
    let summary = RunSummary {
        out: RunOutput {
            reason: TerminalReason::ConnectorFatal,
            final_text: None,
            turns: 1,
            tool_calls: 0,
            tool_calls_attempted: 0,
            tool_calls_denied: 0,
            executed_tools: vec![],
            cost: tracker.snapshot(),
            selected_models: vec![],
            first_dispatch_observation: None,
            compactions: 0,
            terminal_detail: None,
        },
        effect: Effect {
            expectation: "read-only",
            tree_digest_before: None,
            tree_digest_after: None,
            tree_changed: None,
            changed_paths: vec![],
            changed_count: 0,
            writes: vec![],
            executed_tools: Default::default(),
            claimed_paths: vec![],
            claimed_but_absent: vec![],
            claimed_but_unchanged: vec![],
        },
        expectation: EffectExpectation::ReadOnly,
    };
    assert!(bound_private_run_usage(&summary, binding("a"), &binding("d")).is_err());
    let result = bound_private_run_usage(&summary, binding("a"), &binding("a")).unwrap();
    assert!(!result.paid_execution_allowed());
    let wire = serde_json::to_value(result).unwrap();
    assert_eq!(wire["schema"], "ArasPrivateRunUsage/v1");
    assert_eq!(wire["localCounters"]["inputTokens"], "12");
    assert_eq!(wire["localCounters"]["scope"], "RUN_CUMULATIVE");
    assert_eq!(wire["outcome"], "OUTCOME_UNKNOWN");
    assert_eq!(wire["billedCost"]["amount"], Value::Null);
    assert_eq!(wire["capabilities"]["attemptUsageExport"], false);
    assert_eq!(wire["acceptedArtifactCount"], Value::Null);
}
