//! Source-only controls: no provider, worker, ledger or effect activation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arcana_core::agent_loop::{RunOutput, TerminalReason};
use arcana_core::cost::{CostSnapshot, CostTracker};
use arcana_core::usage_export::{PrivateRunUsage, RunUsageBinding};
use serde_json::Value;

fn new_binding(
    run_id: String,
    generation: String,
    request: String,
    receipt: Option<String>,
) -> Result<RunUsageBinding, arcana_core::usage_export::InvalidUsageBinding> {
    RunUsageBinding::new(
        run_id,
        generation,
        request,
        "b".repeat(40),
        "c".repeat(64),
        receipt,
    )
}

fn binding() -> RunUsageBinding {
    new_binding(
        "owned-run".into(),
        "source-generation".into(),
        "a".repeat(64),
        Some("private:executor-correlation".into()),
    )
    .unwrap()
}

fn run(reason: TerminalReason, cost: CostSnapshot) -> RunOutput {
    RunOutput {
        reason,
        final_text: Some("PRIVATE_PROVIDER_TEXT_MUST_NOT_ESCAPE".into()),
        turns: 2,
        tool_calls: 0,
        tool_calls_attempted: 0,
        tool_calls_denied: 0,
        executed_tools: vec![],
        cost,
        selected_models: vec!["PRIVATE_MODEL_ID_MUST_NOT_ESCAPE".into()],
        first_dispatch_observation: None,
        compactions: 0,
        terminal_detail: Some("PRIVATE_ERROR_DETAIL_MUST_NOT_ESCAPE".into()),
    }
}

fn json(reason: TerminalReason, cost: CostSnapshot) -> Value {
    serde_json::to_value(PrivateRunUsage::from_run(binding(), &run(reason, cost))).unwrap()
}

fn empty() -> CostSnapshot {
    CostTracker::new().snapshot()
}

#[test]
fn actual_tracker_export_retains_counters_but_never_promotes_a_charge_or_grant() {
    let tracker = CostTracker::new();
    tracker.record_llm_call("model", 100, 12, 0.001_234);
    let doc = json(TerminalReason::Completed, tracker.snapshot());
    assert_eq!(doc["localCounters"]["inputTokens"], "100");
    assert_eq!(doc["localCounters"]["outputTokens"], "12");
    assert_eq!(doc["localCounters"]["costUsdMicros"], "1234");
    assert_eq!(doc["localCounters"]["calls"], "1");
    assert_eq!(doc["localCounters"]["scope"], "RUN_CUMULATIVE");
    assert_eq!(doc["bindingStatus"], "CALLER_SUPPLIED_UNVERIFIED");
    for field in ["estimate", "reservation", "observedCost", "billedCost"] {
        assert_eq!(doc[field]["state"], "UNKNOWN");
        assert!(doc[field]["amount"].is_null());
    }
    assert!(doc["acceptedArtifactCount"].is_null());
    assert!(doc["acceptanceReceiptRef"].is_null());
    assert!(doc["costPerAccepted"].is_null());
    assert_eq!(doc["outcome"], "LOCAL_RUN_FINISHED_UNADMITTED");
}

#[test]
fn failed_zero_counter_run_is_unknown_consumed_not_free_or_retry_permission() {
    let doc = json(TerminalReason::ConnectorFatal, empty());
    assert_eq!(doc["runTermination"], "ConnectorFatal");
    assert_eq!(doc["outcome"], "OUTCOME_UNKNOWN");
    assert_eq!(doc["consumedCostState"], "UNKNOWN");
    assert_eq!(doc["localCounters"]["costUsdMicros"], "0");
    assert!(doc["billedCost"]["amount"].is_null());
    assert_eq!(doc["capabilities"]["paidExecution"], "DENIED");
}

#[test]
fn omitted_legacy_cap_and_even_large_local_cost_cannot_enable_paid_execution() {
    let tracker = CostTracker::new();
    tracker.record_llm_call("model", 1, 1, 1_000.0);
    assert!(tracker.check_budget(None).is_ok());
    let export = PrivateRunUsage::from_run(
        binding(),
        &run(TerminalReason::Completed, tracker.snapshot()),
    );
    assert!(!export.paid_execution_allowed());
    let doc = serde_json::to_value(export).unwrap();
    assert_eq!(doc["capabilities"]["atomicReservation"], false);
    assert_eq!(doc["capabilities"]["paidExecution"], "DENIED");
    assert!(doc["capabilities"]["authenticatedBudgetCap"].is_null());
    assert!(doc["capabilities"]["physicalHardCaps"].is_null());
}

#[test]
fn unknown_resources_and_private_provider_material_never_become_public_measurements() {
    let doc = json(TerminalReason::Completed, empty());
    for field in [
        "cachedInputTokens",
        "inputCost",
        "cpuUser",
        "cpuSystem",
        "peakResidentMemory",
        "elapsedWall",
        "queueDelay",
        "networkSent",
        "networkReceived",
        "providerModelReceiptRef",
    ] {
        assert!(doc[field].is_null(), "{field} must remain unavailable");
    }
    assert_eq!(doc["disclosure"], "PRIVATE_ONLY");
    assert!(!doc.to_string().contains("MUST_NOT_ESCAPE"));
    assert_ne!(doc["schema"], "AtlasAttemptUsage/v1");
}

#[test]
fn decimal_encoding_preserves_full_integer_domain_without_binary_float_conversion() {
    let doc = json(
        TerminalReason::Completed,
        CostSnapshot {
            total_tokens_in: u64::MAX,
            total_tokens_out: 9_007_199_254_740_993,
            total_cost_usd_micros: u64::MAX,
            total_calls: u64::MAX,
        },
    );
    assert_eq!(doc["localCounters"]["inputTokens"], u64::MAX.to_string());
    assert_eq!(doc["localCounters"]["outputTokens"], "9007199254740993");
    assert_eq!(doc["localCounters"]["costUsdMicros"], u64::MAX.to_string());
}

#[test]
fn malformed_or_log_injecting_bindings_refuse_before_export() {
    for digest in ["", "NaN", &"A".repeat(64), &"g".repeat(64), &"0".repeat(63)] {
        assert!(new_binding("run".into(), "gen".into(), digest.into(), None).is_err());
    }
    for id in ["", "a\nb", " spaced", "\u{0}", &"x".repeat(257)] {
        assert!(new_binding(id.into(), "gen".into(), "a".repeat(64), None).is_err());
        assert!(new_binding("run".into(), id.into(), "a".repeat(64), None).is_err());
    }
    assert!(new_binding(
        "run".into(),
        "gen".into(),
        "a".repeat(64),
        Some("bad\nref".into())
    )
    .is_err());
}

#[test]
fn cancellation_and_refusal_preserve_partial_usage_and_never_refund_or_accept() {
    for reason in [
        TerminalReason::AbortedByOperator,
        TerminalReason::PermissionDenied,
        TerminalReason::MaxCostUsd,
        TerminalReason::AbortedByHook,
    ] {
        let tracker = CostTracker::new();
        tracker.record_llm_call("model", 15, 2, 0.02);
        let doc = json(reason, tracker.snapshot());
        assert_eq!(doc["localCounters"]["costUsdMicros"], "20000");
        assert_eq!(doc["consumedCostState"], "UNKNOWN");
        assert_eq!(doc["outcome"], "OUTCOME_UNKNOWN");
        assert!(doc["acceptanceReceiptRef"].is_null());
    }
}

#[test]
fn source_revision_and_receipt_digest_require_explicit_valid_syntax_but_remain_unverified() {
    assert!(RunUsageBinding::new(
        "run".into(),
        "gen".into(),
        "a".repeat(64),
        "fake".into(),
        "c".repeat(64),
        None
    )
    .is_err());
    assert!(RunUsageBinding::new(
        "run".into(),
        "gen".into(),
        "a".repeat(64),
        "b".repeat(40),
        "bill".into(),
        None
    )
    .is_err());
    let doc = json(TerminalReason::Completed, empty());
    assert_eq!(doc["binding"]["sourceRevision"], "b".repeat(40));
    assert_eq!(doc["binding"]["sourceEvidenceDigest"], "c".repeat(64));
    assert_eq!(doc["bindingStatus"], "CALLER_SUPPLIED_UNVERIFIED");
    assert_eq!(doc["capabilities"]["billedChargeIdentity"], false);
    assert_eq!(doc["capabilities"]["attemptUsageExport"], false);
    assert_eq!(doc["capabilities"]["runtimeMountingState"], "NOT_MEASURED");
}
