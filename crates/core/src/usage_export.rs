//! Private, read-only projection of existing local run accounting.
//!
//! This surface does not register a worker, hook, scheduler or provider call.
//! The current driver records successful connector responses only. Its counters
//! are neither per-attempt provider evidence nor reconciled charges. In particular,
//! an error or timeout can consume money without incrementing these counters.
//! Reservation and physical-cap enforcement are unavailable: paid execution must
//! remain denied until the existing authenticated owners supply those mechanisms.

use serde::Serialize;
use thiserror::Error;

use crate::agent_loop::{RunOutput, TerminalReason};

/// Caller-supplied private correlation, never an authenticated grant.
///
/// Construction validates syntax only. It does not verify the request digest,
/// source generation, receipt, ownership, rights or current authority.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunUsageBinding {
    run_id: String,
    source_generation: String,
    request_digest: String,
    source_revision: String,
    source_evidence_digest: String,
    executor_receipt_ref: Option<String>,
}

/// Invalid correlation metadata; rejected values are not echoed into logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid private run usage binding")]
pub struct InvalidUsageBinding;

impl RunUsageBinding {
    /// Construct bounded correlation metadata with a lowercase SHA-256 digest.
    ///
    /// # Errors
    /// Returns [`InvalidUsageBinding`] for empty, oversized, whitespace/control
    /// containing identifiers or a digest outside the 64-character hex domain.
    pub fn new(
        run_id: String,
        source_generation: String,
        request_digest: String,
        source_revision: String,
        source_evidence_digest: String,
        executor_receipt_ref: Option<String>,
    ) -> Result<Self, InvalidUsageBinding> {
        let label = |value: &str| {
            !value.is_empty()
                && value.len() <= 256
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        };
        let hex = |value: &str, length| {
            value.len() == length
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !label(&run_id)
            || !label(&source_generation)
            || !hex(&request_digest, 64)
            || !hex(&source_revision, 40)
            || !hex(&source_evidence_digest, 64)
            || executor_receipt_ref.as_deref().is_some_and(|v| !label(v))
        {
            return Err(InvalidUsageBinding);
        }
        Ok(Self {
            run_id,
            source_generation,
            request_digest,
            source_revision,
            source_evidence_digest,
            executor_receipt_ref,
        })
    }
}

/// Local cumulative integers, encoded as decimal strings without float conversion.
///
/// These are copied from the supplied `RunOutput`, not inferred from a model
/// message. Zero means this local counter is zero, not that a provider charged
/// nothing. Tracker token inputs may have saturated to u32; legacy cost inputs
/// are f64 rounded to USD micros and invalid values may have clamped to zero.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportedCounters {
    state: &'static str,
    scope: &'static str,
    coverage: &'static str,
    input_tokens: String,
    output_tokens: String,
    calls: String,
    cost_usd_micros: String,
    cost_scale: u8,
}

#[derive(Serialize)]
struct UnknownCharge {
    state: &'static str,
    amount: Option<String>,
    reason: &'static str,
}

impl UnknownCharge {
    const fn new() -> Self {
        Self {
            state: "UNKNOWN",
            amount: None,
            reason: "No authenticated estimate, reservation or reconciled charge receipt",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsupportedCapabilities {
    atomic_reservation: bool,
    billed_charge_identity: bool,
    attempt_usage_export: bool,
    physical_enforcement_state: &'static str,
    runtime_mounting_state: &'static str,
    physical_hard_caps: Option<String>,
    authenticated_budget_cap: Option<String>,
    paid_execution: &'static str,
}

/// Serializable private source export; it intentionally has no Deserialize path.
///
/// This is a run-level correlation projection, not `AtlasAttemptUsage/v1`.
/// Fields cannot be mutated into a financial grant through this API. Do not send
/// the raw record to a public reader. Public aggregate disclosure is a separate
/// owner's operation. Missing measurements serialize as null, never numeric zero.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateRunUsage {
    schema: &'static str,
    disclosure: &'static str,
    binding_status: &'static str,
    binding: RunUsageBinding,
    local_counters: ReportedCounters,
    run_termination: String,
    outcome: &'static str,
    consumed_cost_state: &'static str,
    capabilities: UnsupportedCapabilities,
    estimate: UnknownCharge,
    reservation: UnknownCharge,
    observed_cost: UnknownCharge,
    billed_cost: UnknownCharge,
    cached_input_tokens: Option<String>,
    input_cost: Option<String>,
    cpu_user: Option<String>,
    cpu_system: Option<String>,
    peak_resident_memory: Option<String>,
    elapsed_wall: Option<String>,
    queue_delay: Option<String>,
    network_sent: Option<String>,
    network_received: Option<String>,
    provider_model_receipt_ref: Option<String>,
    acceptance_receipt_ref: Option<String>,
    accepted_artifact_count: Option<String>,
    cost_per_accepted: Option<String>,
}

impl PrivateRunUsage {
    /// Export only after all correlation fields match the expected consumer binding.
    ///
    /// Expected values must come from the consumer's pinned request/source context.
    /// Equality is a local correlation check, not authentication or a cursor/lease
    /// decision. No run counters are allocated across targets or attempts.
    ///
    /// # Errors
    /// Returns [`InvalidUsageBinding`] without private values on any mismatch,
    /// including receipt presence. Matching caller metadata remains unverified.
    pub fn from_bound_run(
        binding: RunUsageBinding,
        expected: &RunUsageBinding,
        run: &RunOutput,
    ) -> Result<Self, InvalidUsageBinding> {
        if &binding != expected {
            return Err(InvalidUsageBinding);
        }
        Ok(Self::from_run(binding, run))
    }

    /// Project actual local accounting without I/O, effects or new authority.
    ///
    /// All caller metadata remains unverified. Termination details, model text,
    /// model identifiers and raw first-dispatch receipts are deliberately excluded.
    /// Completed means local termination only, never draft or corpus acceptance.
    #[must_use]
    pub fn from_run(binding: RunUsageBinding, run: &RunOutput) -> Self {
        Self {
            schema: "ArasPrivateRunUsage/v1",
            disclosure: "PRIVATE_ONLY",
            binding_status: "CALLER_SUPPLIED_UNVERIFIED",
            binding,
            local_counters: ReportedCounters {
                state: "LOCAL_CONNECTOR_RESPONSE_UNVERIFIED",
                scope: "RUN_CUMULATIVE",
                coverage: "SUCCESSFUL_CONNECTOR_RESPONSES_ONLY",
                input_tokens: run.cost.total_tokens_in.to_string(),
                output_tokens: run.cost.total_tokens_out.to_string(),
                calls: run.cost.total_calls.to_string(),
                cost_usd_micros: run.cost.total_cost_usd_micros.to_string(),
                cost_scale: 6,
            },
            run_termination: format!("{:?}", run.reason),
            outcome: if run.reason == TerminalReason::Completed {
                "LOCAL_RUN_FINISHED_UNADMITTED"
            } else {
                "OUTCOME_UNKNOWN"
            },
            consumed_cost_state: "UNKNOWN",
            capabilities: UnsupportedCapabilities {
                atomic_reservation: false,
                billed_charge_identity: false,
                attempt_usage_export: false,
                physical_enforcement_state: "NOT_MEASURED",
                runtime_mounting_state: "NOT_MEASURED",
                physical_hard_caps: None,
                authenticated_budget_cap: None,
                paid_execution: "DENIED",
            },
            estimate: UnknownCharge::new(),
            reservation: UnknownCharge::new(),
            observed_cost: UnknownCharge::new(),
            billed_cost: UnknownCharge::new(),
            cached_input_tokens: None,
            input_cost: None,
            cpu_user: None,
            cpu_system: None,
            peak_resident_memory: None,
            elapsed_wall: None,
            queue_delay: None,
            network_sent: None,
            network_received: None,
            provider_model_receipt_ref: None,
            acceptance_receipt_ref: None,
            accepted_artifact_count: None,
            cost_per_accepted: None,
        }
    }

    /// This export cannot authorize a paid worker, even when local cost is zero.
    #[must_use]
    pub const fn paid_execution_allowed(&self) -> bool {
        false
    }
}
