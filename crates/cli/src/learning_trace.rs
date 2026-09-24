//! `LearningTraceCandidate/v1` — what a run leaves behind for the knowledge
//! store to learn from.
//!
//! The receipt says a run happened and what it cost. It does not say what the
//! run DID in a form anything upstream can generalize from, and KC2's upward
//! half — `LearningTrace` → `PromotionProposal` → `Blueprint` — has had no
//! input at all: every one of the five hand-authored upward records in
//! `talomnia-knowledge` was written by a person, none came out of an executed
//! task. This module is the missing producer.
//!
//! Three properties, each of them a refusal of something easier:
//!
//! * **Derived, never narrated.** Every field comes from the audit log, the
//!   contract binding and the driver's own counters. No model call, no reading
//!   of the model's final text. A trace assembled by asking the model what it
//!   had done would be the model's account of itself, which is exactly the
//!   evidence a promotion may not rest on.
//! * **A negative run writes one too.** A run that was refused, ran out of
//!   budget or executed no tool at all produces a trace marked `negative`. The
//!   store needs the failures: a capability set that succeeds twice and fails
//!   nine times is not a blueprint, and that is only visible if the nine were
//!   kept.
//! * **Verification is `not_measured`, stated.** This runtime runs no
//!   verifier. Writing `"verdicts": []` and leaving it there would let a reader
//!   take an empty list for a clean one, so the field carries the third verdict
//!   by name and the promotion bar downstream refuses to read it as a pass.
//!
//! The grouping key is [`Trace::capability_set`]: the distinct tools the run
//! ACTUALLY executed, sorted. Not the contract's allowlist — that is what the
//! run was permitted, and two runs permitted the same tools while using none of
//! them have nothing in common to promote.

use std::path::{Path, PathBuf};

use arcana_core::agent_loop::RunOutput;
use arcana_core::contract::{digest_of, ContractBinding};
use arcana_core::hooks::audit::OUTCOME_SUCCESS;

use crate::run::RunSummary;

use serde::Serialize;
use serde_json::Value;

/// Schema identifier.
pub const SCHEMA: &str = "LearningTraceCandidate/v1";

/// The audit log's filename inside the run's audit directory. Named here
/// rather than in `run` because the trace is the only reader of the file as a
/// file — the executor writes it through `AuditLog`, which owns the name on
/// its own side.
pub const AUDIT_FILE: &str = "audit.log";

/// The third verdict, spelled the way the ecosystem spells it everywhere else.
pub const NOT_MEASURED: &str = "not_measured";

/// One tool invocation, as the audit log recorded it.
///
/// `input_hash` and `output_hash` rather than the values: the audit log holds
/// hashes by design (raw inputs are never persisted), and a trace that carried
/// the arguments would carry whatever the task was working on into a knowledge
/// store. The hashes still do the one job promotion needs — telling two runs
/// that did the same thing from two that merely used the same tool.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Step {
    /// Position in the run, from 1. The ORDER is the point: a blueprint is a
    /// shape of work, and an unordered bag of tool names is not one.
    pub seq: u32,
    pub invocation_id: u64,
    pub tool: String,
    /// `Allowed` / `Denied` / … as the cascade recorded it.
    pub decision: Option<String>,
    /// Which cascade layer decided.
    pub layer: Option<String>,
    /// `success`, `tool_error`, `decision_only`, … `None` when the run ended
    /// before the result record was written.
    pub outcome: Option<String>,
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
    /// Whether the contract's allowlist admits this tool. A step that ran
    /// outside the allowlist is a finding, not a fact to average away.
    pub admitted_by_contract: bool,
}

/// What the run rested on, from the contract it was bound to.
#[derive(Debug, Clone, Serialize)]
pub struct ContractRest {
    pub digest: String,
    pub source: String,
    pub origin: String,
    pub verified_against_live_endpoint: bool,
    pub kc2_revision: Option<String>,
    pub kc2_snapshot: Option<String>,
    /// The constraints the steps rested on: what the contract admitted.
    pub allowlist: Vec<String>,
    pub allowlist_source: String,
}

/// How the run ended, and whether that counts as evidence FOR anything.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub completed: bool,
    pub reason: String,
    pub detail: Option<String>,
    pub turns: u32,
    pub executed: u32,
    pub attempted: u32,
    pub denied: u32,
    /// `true` when this run may not be counted toward a promotion: it did not
    /// complete, or it completed having executed nothing.
    pub negative: bool,
    /// Why, in one token a grouping tool can switch on.
    pub negative_reason: Option<String>,
}

/// What the run spent.
#[derive(Debug, Clone, Serialize)]
pub struct Cost {
    pub calls: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd_micros: u64,
    pub selected_models: Vec<String>,
}

/// The receipt this trace is the companion of.
#[derive(Debug, Clone, Serialize)]
pub struct ReceiptRef {
    /// Relative to the worktree.
    pub path: String,
    /// `sha256:` of the receipt's bytes as written. The digest link is what
    /// makes the trace checkable: a trace whose receipt no longer hashes to
    /// this is a trace about a run nobody can still inspect.
    pub digest: Option<String>,
}

/// Verifier verdicts for this run. Always `not_measured` from here.
#[derive(Debug, Clone, Serialize)]
pub struct Verification {
    /// `not_measured` — this runtime runs no verifier.
    pub state: &'static str,
    pub verdicts: Vec<Value>,
}

/// Where the steps were read from, so a reader can re-derive them.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRef {
    pub path: String,
    /// Byte offset the run's slice starts at — taken before the run began.
    pub from_byte: u64,
    pub records_read: u32,
    /// `true` when the offset could not be taken and the whole log was read;
    /// the slice may then contain records from earlier runs and must not be
    /// read as this run's alone.
    pub slice_unbounded: bool,
}

/// The driver's own account of which tools ran, kept beside the log-derived
/// one so the two can be compared.
///
/// [`Trace::capability_set`] is read out of the durable audit log; this is the
/// in-process counter the agent loop increments at the one line where a tool
/// executor returned. The two are independent derivations of the same set, and
/// that is the entire point: this module's first live run reported
/// `"capability_set": []` for a run that executed three tools, because the
/// derivation matched a literal the log has never written. Every unit test
/// agreed with the bug, since the fixtures carried the same literal. A second
/// witness cannot be talked into the same mistake by the same author.
///
/// The two may legitimately differ in one direction: when the pre-run offset
/// could not be measured the log slice is unbounded and may carry records from
/// an earlier run, so the log-derived set can be the larger one. That is why a
/// disagreement marks the trace negative rather than being silently repaired —
/// which of the two is wrong is not knowable here.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityWitness {
    /// Distinct tools the driver counted as executed, sorted.
    pub driver_set: Vec<String>,
    /// Whether it equals the log-derived [`Trace::capability_set`].
    pub agrees: bool,
}

/// `LearningTraceCandidate/v1`.
#[derive(Debug, Clone, Serialize)]
pub struct Trace {
    pub schema: &'static str,
    pub recorded_at: String,
    pub produced_by: String,
    pub task_id: String,
    /// `<task_id>@<recorded_at>` — two runs of one work item are two traces,
    /// and a store that overwrote the first would lose the negative one.
    pub trace_id: String,
    pub worktree_sha: Option<String>,
    pub contract: ContractRest,
    /// Distinct tools actually executed, sorted. The grouping key.
    pub capability_set: Vec<String>,
    /// The independent second derivation of that set, and whether it agrees.
    pub capability_witness: CapabilityWitness,
    pub steps: Vec<Step>,
    pub outcome: Outcome,
    pub cost: Cost,
    pub receipt: ReceiptRef,
    pub verification: Verification,
    pub audit: AuditRef,
}

/// Everything the builder needs that is not in the driver's output.
pub struct Sources<'a> {
    pub task_id: &'a str,
    pub binding: &'a ContractBinding,
    pub contract_source: &'a str,
    pub contract_origin: String,
    pub verified_live: bool,
    pub worktree_sha: Option<String>,
    pub receipt_path: &'a Path,
    pub audit_path: PathBuf,
    /// Length of the audit log before the run started, or `None` when it could
    /// not be measured.
    pub audit_offset: Option<u64>,
    pub produced_by: String,
    pub recorded_at: String,
}

/// Build the trace for a finished contract-bound run.
#[must_use]
pub fn build(sources: &Sources, summary: &RunSummary, root: &Path) -> Trace {
    // The effect-aware verdict, not `reason.is_success()`. A run the model
    // declared finished while leaving the working tree byte-for-byte unchanged
    // is `NoEffect` (A2-285), and a trace that recorded it as a completed run
    // would feed the promotion bar the precise class of evidence that card
    // exists to reject.
    let (completed, reason) = crate::run::verdict_of(summary);
    let out = &summary.out;
    let slice_unbounded = sources.audit_offset.is_none();
    let records = read_audit_slice(&sources.audit_path, sources.audit_offset.unwrap_or(0));
    let steps = steps_from(&records, sources.binding);
    let capability_set = capability_set(&steps);
    let capability_witness = witness_of(out, &capability_set);
    let negative_reason = if !completed {
        Some("run_did_not_complete".to_owned())
    } else if !capability_witness.agrees {
        Some("capability_witness_disagreed".to_owned())
    } else {
        // There is deliberately no `capability_set.is_empty()` arm left here.
        // It was written before this branch rebased onto A2-285, and that card
        // made it unreachable: `verdict_of` already refuses a success-reason
        // run with zero executed calls as `NoAction`, so `completed` implies
        // `tool_calls > 0`; `tool_calls` and `executed_tools` are incremented
        // on the one same line of the agent loop, so the driver's set is then
        // non-empty; and a non-empty driver set against an empty derived one
        // is a disagreement, caught one arm above. An arm no input can reach
        // is a verdict that can never be wrong, which is not the same as being
        // right. (Ingesters still handle the reason: a trace may come from an
        // older writer, and `kc2_execution_learning.py` derives its own.)
        None
    };
    Trace {
        schema: SCHEMA,
        recorded_at: sources.recorded_at.clone(),
        produced_by: sources.produced_by.clone(),
        task_id: sources.task_id.to_owned(),
        trace_id: format!("{}@{}", sources.task_id, sources.recorded_at),
        worktree_sha: sources.worktree_sha.clone(),
        contract: ContractRest {
            digest: sources.binding.digest().to_owned(),
            source: sources.contract_source.to_owned(),
            origin: sources.contract_origin.clone(),
            verified_against_live_endpoint: sources.verified_live,
            kc2_revision: sources.binding.kc2_revision().map(ToOwned::to_owned),
            kc2_snapshot: sources.binding.kc2_snapshot().map(ToOwned::to_owned),
            allowlist: sources.binding.allowlist().iter().cloned().collect(),
            allowlist_source: sources.binding.allowlist_source().as_str().to_owned(),
        },
        capability_set,
        capability_witness,
        outcome: Outcome {
            completed,
            reason,
            detail: out.terminal_detail.clone(),
            turns: out.turns,
            executed: out.tool_calls,
            attempted: out.tool_calls_attempted,
            denied: out.tool_calls_denied,
            negative: negative_reason.is_some(),
            negative_reason,
        },
        cost: Cost {
            calls: out.cost.total_calls,
            tokens_in: out.cost.total_tokens_in,
            tokens_out: out.cost.total_tokens_out,
            cost_usd_micros: out.cost.total_cost_usd_micros,
            selected_models: out.selected_models.clone(),
        },
        receipt: ReceiptRef {
            path: sources
                .receipt_path
                .strip_prefix(root)
                .unwrap_or(sources.receipt_path)
                .display()
                .to_string(),
            digest: std::fs::read(sources.receipt_path)
                .ok()
                .map(|bytes| digest_of(&bytes)),
        },
        verification: Verification {
            state: NOT_MEASURED,
            verdicts: Vec::new(),
        },
        audit: AuditRef {
            path: sources.audit_path.display().to_string(),
            from_byte: sources.audit_offset.unwrap_or(0),
            records_read: u32::try_from(records.len()).unwrap_or(u32::MAX),
            slice_unbounded,
        },
        steps,
    }
}

/// Length of `path` in bytes, to be taken BEFORE the run starts.
///
/// `None` when the file does not exist yet (the ordinary first-run case) is
/// indistinguishable from `None` when it cannot be read, and both are honest:
/// offset zero over a log that did not exist is the whole of that run's
/// records anyway. What must not happen is a guessed non-zero offset, which
/// would silently truncate the run's own steps out of its trace.
#[must_use]
pub fn audit_offset(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|meta| meta.len())
}

/// Parse the audit records written after `offset`.
fn read_audit_slice(path: &Path, offset: u64) -> Vec<Value> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(text.len());
    // A byte offset that lands mid-character cannot happen on an append-only
    // log of whole lines, but `get` returning `None` rather than panicking is
    // what keeps that assumption from being load-bearing.
    let tail = text.get(start..).unwrap_or("");
    tail.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Pair the decision and result records by `invocation_id`, in decision order.
fn steps_from(records: &[Value], binding: &ContractBinding) -> Vec<Step> {
    let field = |value: &Value, key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    let mut steps = Vec::new();
    for record in records {
        if record.get("phase").and_then(Value::as_str) != Some("decision") {
            continue;
        }
        let Some(invocation_id) = record.get("invocation_id").and_then(Value::as_u64) else {
            continue;
        };
        let tool = field(record, "tool").unwrap_or_default();
        let result = records.iter().find(|other| {
            other.get("phase").and_then(Value::as_str) == Some("result")
                && other.get("invocation_id").and_then(Value::as_u64) == Some(invocation_id)
        });
        steps.push(Step {
            seq: u32::try_from(steps.len() + 1).unwrap_or(u32::MAX),
            invocation_id,
            admitted_by_contract: binding.admits(&tool),
            decision: field(record, "decision"),
            layer: field(record, "layer"),
            outcome: result.and_then(|value| field(value, "outcome")),
            input_hash: field(record, "input_hash"),
            output_hash: result.and_then(|value| field(value, "output_hash")),
            tool,
        });
    }
    steps
}

/// The distinct tools that were allowed AND produced a result — sorted.
///
/// A denial is in the steps and not in the capability set on purpose: the run
/// did not exercise that capability, it was stopped from exercising it, and a
/// grouping key that counted refusals would group runs by what they tried.
///
/// [`OUTCOME_SUCCESS`] rather than a literal, and that is not style. The first
/// live run of this code matched `"ok"`, which the audit log has never
/// written: three successful tool calls produced an empty capability set and
/// a trace marked negative for having exercised nothing. The unit fixtures
/// said `"ok"` too, so every test agreed with the bug.
fn capability_set(steps: &[Step]) -> Vec<String> {
    let mut names: Vec<String> = steps
        .iter()
        .filter(|step| step.decision.as_deref() == Some("Allowed"))
        .filter(|step| step.outcome.as_deref() == Some(OUTCOME_SUCCESS))
        .map(|step| step.tool.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Derive the driver's witness and compare it with the log-derived set.
fn witness_of(out: &RunOutput, capability_set: &[String]) -> CapabilityWitness {
    let mut driver_set = out.executed_tools.clone();
    driver_set.sort();
    driver_set.dedup();
    CapabilityWitness {
        agrees: driver_set == capability_set,
        driver_set,
    }
}

/// Write `trace` to `<root>/receipts/LearningTrace-<trace_id>.json`.
///
/// The timestamp is in the name because a work item may be run more than once
/// and each run is its own evidence. `d931525f` was run five times on
/// 2026-09-24; under a fixed name the store would hold the last one and the
/// four that failed — the ones a promotion bar most needs — would be gone.
///
/// # Errors
/// The message to print, when the file cannot be written.
pub fn write(root: &Path, trace: &Trace) -> Result<PathBuf, String> {
    let dir = root.join(crate::receipt::RECEIPTS_DIR);
    std::fs::create_dir_all(&dir).map_err(|err| {
        format!(
            "receipts directory {} could not be created: {err}",
            dir.display()
        )
    })?;
    let path = dir.join(format!(
        "LearningTrace-{}.json",
        file_stamp(&trace.trace_id)
    ));
    let text = serde_json::to_string_pretty(trace)
        .map_err(|err| format!("the learning trace could not be serialized: {err}"))?;
    std::fs::write(&path, text + "\n").map_err(|err| {
        format!(
            "the learning trace could not be written to {}: {err}",
            path.display()
        )
    })?;
    Ok(path)
}

/// `trace_id` reduced to characters a filename may carry on every platform.
fn file_stamp(trace_id: &str) -> String {
    trace_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use arcana_core::agent_loop::TerminalReason;
    use arcana_core::contract::{verify, ContractDocument, ContractTools};
    use arcana_core::cost::CostSnapshot;
    use arcana_core::hooks::audit::OUTCOME_TOOL_ERROR;

    use std::collections::BTreeMap;

    use crate::effect::{Effect, EffectExpectation};

    fn binding(allow: &[&str]) -> ContractBinding {
        const BYTES: &str = "the contract under test";
        let digest = digest_of(BYTES.as_bytes());
        let document = ContractDocument {
            digest: digest.clone(),
            canonical_bytes: Some(BYTES.to_owned()),
            tools: Some(ContractTools {
                allow: allow.iter().map(|name| (*name).to_owned()).collect(),
            }),
            ..Default::default()
        };
        verify(&digest, &document).expect("the fixture contract verifies")
    }

    /// A finished run, as the driver reports it.
    ///
    /// `executed` names the tools rather than counting them, because the
    /// witness compares names: a fixture that could only say "one tool ran"
    /// could not disagree with the log, and a check that cannot disagree is
    /// not a check.
    fn out(reason: TerminalReason, executed: &[&str]) -> RunSummary {
        summary(reason, executed, tree_changed())
    }

    /// The effect of a run that did change the working tree. The neutral
    /// fixture: these tests are about what the trace derives, not about
    /// A2-285's effect judgement, which has its own test below.
    fn tree_changed() -> Effect {
        Effect {
            expectation: EffectExpectation::Artefact.as_str(),
            tree_digest_before: Some("a".repeat(64)),
            tree_digest_after: Some("b".repeat(64)),
            tree_changed: Some(true),
            changed_paths: vec!["out.md".to_owned()],
            changed_count: 1,
            writes: vec!["write".to_owned()],
            executed_tools: BTreeMap::new(),
            claimed_paths: Vec::new(),
            claimed_but_absent: Vec::new(),
            claimed_but_unchanged: Vec::new(),
        }
    }

    fn summary(reason: TerminalReason, executed: &[&str], effect: Effect) -> RunSummary {
        let executed_tools: Vec<String> = executed.iter().map(|name| (*name).to_owned()).collect();
        let calls = u32::try_from(executed_tools.len()).unwrap();
        RunSummary {
            out: RunOutput {
                reason,
                final_text: None,
                turns: 3,
                tool_calls: calls,
                tool_calls_attempted: calls,
                tool_calls_denied: 0,
                executed_tools,
                cost: CostSnapshot {
                    total_tokens_in: 10,
                    total_tokens_out: 2,
                    total_cost_usd_micros: 9045,
                    total_calls: 3,
                },
                selected_models: vec!["m".to_owned()],
                first_dispatch_observation: None,
                compactions: 0,
                terminal_detail: None,
            },
            effect,
            expectation: EffectExpectation::Artefact,
        }
    }

    fn audit(dir: &Path, lines: &[&str]) -> PathBuf {
        let path = dir.join("audit.log");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    const READ_OK: &str = r#"{"phase":"decision","invocation_id":1,"tool":"read","decision":"Allowed","layer":"cascade","input_hash":"aa"}"#;
    const READ_RESULT: &str = r#"{"phase":"result","invocation_id":1,"tool":"read","outcome":"success","output_hash":"bb"}"#;
    const WRITE_OK: &str = r#"{"phase":"decision","invocation_id":2,"tool":"write","decision":"Allowed","layer":"cascade","input_hash":"cc"}"#;
    const WRITE_RESULT: &str = r#"{"phase":"result","invocation_id":2,"tool":"write","outcome":"success","output_hash":"dd"}"#;
    const READ_ERROR: &str = r#"{"phase":"result","invocation_id":1,"tool":"read","outcome":"tool_error","output_hash":null}"#;
    const BASH_DENIED: &str = r#"{"phase":"decision","invocation_id":3,"tool":"bash","decision":"Denied","layer":"contract-allowlist","input_hash":"ee"}"#;
    const DISPATCH: &str = r#"{"phase":"run","kind":"dispatch","fields":{"turn":1}}"#;

    fn sources<'a>(
        dir: &Path,
        binding: &'a ContractBinding,
        audit_path: PathBuf,
        offset: Option<u64>,
        task_id: &'a str,
        receipt: &'a Path,
    ) -> Sources<'a> {
        let _ = dir;
        Sources {
            task_id,
            binding,
            contract_source: "argana",
            contract_origin: "http://127.0.0.1:18380/".to_owned(),
            verified_live: true,
            worktree_sha: Some("0".repeat(40)),
            receipt_path: receipt,
            audit_path,
            audit_offset: offset,
            produced_by: "arcana test".to_owned(),
            recorded_at: "2026-09-24T21:00:00Z".to_owned(),
        }
    }

    #[test]
    fn steps_are_ordered_and_paired_with_their_results() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(
            dir.path(),
            &[DISPATCH, READ_OK, READ_RESULT, WRITE_OK, WRITE_RESULT],
        );
        let bind = binding(&["read", "write"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);
        let trace = build(
            &src,
            &out(TerminalReason::Completed, &["read", "write"]),
            dir.path(),
        );

        assert_eq!(trace.steps.len(), 2);
        assert_eq!(trace.steps[0].seq, 1);
        assert_eq!(trace.steps[0].tool, "read");
        assert_eq!(trace.steps[0].outcome.as_deref(), Some(OUTCOME_SUCCESS));
        assert_eq!(trace.steps[0].output_hash.as_deref(), Some("bb"));
        assert_eq!(trace.steps[1].seq, 2);
        assert_eq!(trace.steps[1].tool, "write");
        assert_eq!(trace.capability_set, vec!["read", "write"]);
        assert!(!trace.outcome.negative);
    }

    #[test]
    fn a_denied_call_is_a_step_but_not_a_capability() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), &[READ_OK, READ_RESULT, BASH_DENIED]);
        let bind = binding(&["read", "write"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);
        let trace = build(&src, &out(TerminalReason::Completed, &["read"]), dir.path());

        assert_eq!(trace.steps.len(), 2);
        assert_eq!(trace.steps[1].tool, "bash");
        assert_eq!(trace.steps[1].decision.as_deref(), Some("Denied"));
        assert!(!trace.steps[1].admitted_by_contract);
        assert_eq!(trace.capability_set, vec!["read"]);
    }

    #[test]
    fn a_failed_run_still_writes_a_trace_marked_negative() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), &[DISPATCH]);
        let bind = binding(&["read"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);
        let trace = build(&src, &out(TerminalReason::MaxCostUsd, &[]), dir.path());

        assert!(trace.outcome.negative);
        assert_eq!(
            trace.outcome.negative_reason.as_deref(),
            Some("run_did_not_complete")
        );
        assert!(trace.capability_set.is_empty());
        let path = write(dir.path(), &trace).unwrap();
        assert!(path.exists());
    }

    /// The case the first live runs of `d931525f` actually produced: the model
    /// called `read` and every call came back `tool_error`. The run reached its
    /// end with tool calls to its name and nothing exercised, and a capability
    /// set derived from ATTEMPTS rather than results would have called that a
    /// `read` capability twice over.
    #[test]
    fn a_run_whose_every_call_errored_carries_no_capability() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), &[DISPATCH, READ_OK, READ_ERROR]);
        let bind = binding(&["read"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);
        // Empty, and not as a convenience: `OUTCOME_TOOL_ERROR` is written on
        // the arm that returns `CapabilityError::Tool`, which leaves the agent
        // loop before the line that pushes to `executed_tools`. Both witnesses
        // say "nothing ran" for their own reasons.
        let trace = build(&src, &out(TerminalReason::Completed, &[]), dir.path());

        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.steps[0].outcome.as_deref(), Some(OUTCOME_TOOL_ERROR));
        // The point of the test: the step is in the trace, and it is not a
        // capability. A set derived from attempts would hold `read` here.
        assert_eq!(trace.steps[0].tool, "read");
        assert!(trace.capability_set.is_empty());
        assert!(trace.capability_witness.agrees);
        assert!(trace.outcome.negative);
        assert_eq!(
            trace.outcome.negative_reason.as_deref(),
            Some("run_did_not_complete")
        );
        // Because nothing executed, A2-285's rule reaches it first.
        assert_eq!(trace.outcome.reason, "NoAction");
    }

    #[test]
    fn the_offset_keeps_an_earlier_runs_steps_out_of_this_trace() {
        let dir = tempfile::tempdir().unwrap();
        let earlier = format!("{READ_OK}\n{READ_RESULT}\n");
        let path = dir.path().join("audit.log");
        std::fs::write(&path, &earlier).unwrap();
        let offset = audit_offset(&path).unwrap();
        assert_eq!(offset, earlier.len() as u64);
        std::fs::write(&path, earlier + WRITE_OK + "\n" + WRITE_RESULT + "\n").unwrap();

        let bind = binding(&["read", "write"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, path, Some(offset), "task-1", &receipt);
        let trace = build(
            &src,
            &out(TerminalReason::Completed, &["write"]),
            dir.path(),
        );

        assert_eq!(trace.capability_set, vec!["write"]);
        assert_eq!(trace.audit.from_byte, offset);
        assert!(!trace.audit.slice_unbounded);
    }

    #[test]
    fn an_unmeasured_offset_says_so_rather_than_guessing() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), &[READ_OK, READ_RESULT]);
        let bind = binding(&["read"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, None, "task-1", &receipt);
        let trace = build(&src, &out(TerminalReason::Completed, &["read"]), dir.path());

        assert!(trace.audit.slice_unbounded);
        assert_eq!(trace.audit.from_byte, 0);
    }

    #[test]
    fn verification_is_the_third_verdict_and_never_an_empty_pass() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), &[READ_OK, READ_RESULT]);
        let bind = binding(&["read"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);
        let trace = build(&src, &out(TerminalReason::Completed, &["read"]), dir.path());

        assert_eq!(trace.verification.state, NOT_MEASURED);
        assert!(trace.verification.verdicts.is_empty());
    }

    #[test]
    fn the_receipt_is_linked_by_digest() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), &[READ_OK, READ_RESULT]);
        let bind = binding(&["read"]);
        let receipts = dir.path().join("receipts");
        std::fs::create_dir_all(&receipts).unwrap();
        let receipt = receipts.join("ReadinessReceipt-task-1.json");
        std::fs::write(&receipt, b"{\"schema\":\"ReadinessReceipt/v1\"}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);
        let trace = build(&src, &out(TerminalReason::Completed, &["read"]), dir.path());

        assert_eq!(trace.receipt.path, "receipts/ReadinessReceipt-task-1.json");
        assert_eq!(
            trace.receipt.digest,
            Some(digest_of(b"{\"schema\":\"ReadinessReceipt/v1\"}"))
        );
    }

    /// The executor writes the log; this module reads it. Half of the
    /// `"ok"` defect, closed.
    ///
    /// What this proves is that the two SIDES agree: a real
    /// `CapabilityExecutor` writes a real audit log and the capability set is
    /// derived from that, with no fixture in between. What it cannot prove is
    /// the token itself — both sides now read [`OUTCOME_SUCCESS`], so changing
    /// that constant moves them together and this test stays green (measured:
    /// under that mutation it passes and three of the literal-fixture tests
    /// go red). The pair is the guard. Neither test alone is.
    #[tokio::test]
    async fn the_capability_set_is_derived_from_a_log_the_real_executor_wrote() {
        use arcana_core::execution::CapabilityExecutor;
        use arcana_core::hooks::{audit::AuditLog, HookChain, HookContext};
        use arcana_core::permission::{LayerDecision, PermissionCascade, PermissionLayer};
        use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
        use serde_json::json;
        use std::sync::Arc;

        struct ReadTool;

        #[async_trait::async_trait]
        impl Tool for ReadTool {
            fn name(&self) -> &'static str {
                "read"
            }
            fn description(&self) -> &'static str {
                "a tool that succeeds"
            }
            fn input_schema(&self) -> Value {
                json!({ "type": "object" })
            }
            async fn execute(&self, _invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
                Ok(ToolOutput {
                    content: "content".to_owned(),
                    metadata: None,
                })
            }
        }

        struct AllowLayer;

        #[async_trait::async_trait]
        impl PermissionLayer for AllowLayer {
            fn name(&self) -> &'static str {
                "cascade"
            }
            async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
                LayerDecision::Allow
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let mut dispatcher = ToolDispatcher::new();
        dispatcher.register(Arc::new(ReadTool)).unwrap();
        let executor = CapabilityExecutor::new(
            dispatcher,
            PermissionCascade::new(vec![Arc::new(AllowLayer)]),
            HookChain::new(),
            AuditLog::new(dir.path()).unwrap(),
        );
        let ctx = HookContext::new(
            tokio_util::sync::CancellationToken::new(),
            Arc::new(arcana_core::cost::CostTracker::new()),
        );
        executor
            .execute(&ctx, "read", json!({ "path": "x" }))
            .await
            .unwrap();

        let log = dir.path().join(AUDIT_FILE);
        let bind = binding(&["read"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);
        let trace = build(&src, &out(TerminalReason::Completed, &["read"]), dir.path());

        assert_eq!(trace.capability_set, vec!["read"]);
        assert_eq!(trace.steps[0].outcome.as_deref(), Some(OUTCOME_SUCCESS));
        assert!(!trace.outcome.negative);
    }

    /// A2-285's verdict, not the driver's. The model ended the run happily,
    /// `read` executed, and the working tree is byte-for-byte what it was.
    /// Judging this trace by `reason.is_success()` would file a `NoEffect` run
    /// as a completed one and offer it to the promotion bar as evidence — the
    /// one class of run that card exists to refuse.
    #[test]
    fn a_run_that_changed_nothing_is_negative_however_it_ended() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), &[DISPATCH, READ_OK, READ_RESULT]);
        let bind = binding(&["read"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);

        let mut effect = tree_changed();
        effect.tree_digest_after = effect.tree_digest_before.clone();
        effect.tree_changed = Some(false);
        effect.changed_paths = Vec::new();
        effect.changed_count = 0;
        let run = summary(TerminalReason::Completed, &["read"], effect);

        let trace = build(&src, &run, dir.path());

        // The capability genuinely executed, so the set is not the thing that
        // makes this negative — the verdict is.
        assert_eq!(trace.capability_set, vec!["read"]);
        assert!(trace.outcome.negative);
        assert_eq!(trace.outcome.reason, "NoEffect");
        assert_eq!(
            trace.outcome.negative_reason.as_deref(),
            Some("run_did_not_complete")
        );
    }

    /// The defect this module shipped with, made detectable.
    ///
    /// The first live run executed three tools and the trace said
    /// `"capability_set": []`, because the derivation compared against a token
    /// the audit log has never written. Every unit test passed: the fixtures
    /// carried the same wrong token. What was missing was not a better test of
    /// the derivation but a SECOND derivation — here the driver's own counter,
    /// which reached its value without parsing anything.
    ///
    /// Note what the trace does NOT do: pick a winner. It cannot know which
    /// witness is wrong, so it records both and refuses to be promotable.
    #[test]
    fn two_witnesses_that_disagree_make_the_trace_negative() {
        let dir = tempfile::tempdir().unwrap();
        // A log the derivation reads as empty — the shape it took when the
        // outcome literal did not match.
        let log = audit(dir.path(), &[DISPATCH]);
        let bind = binding(&["read", "grep"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);

        let trace = build(
            &src,
            &out(TerminalReason::Completed, &["read", "grep", "read"]),
            dir.path(),
        );

        assert!(trace.capability_set.is_empty());
        assert_eq!(trace.capability_witness.driver_set, vec!["grep", "read"]);
        assert!(!trace.capability_witness.agrees);
        assert!(trace.outcome.negative);
        // Named for what it is. `no_capability_executed` would be the reading
        // the bug gave, and it is a plausible sentence about a broken run.
        assert_eq!(
            trace.outcome.negative_reason.as_deref(),
            Some("capability_witness_disagreed")
        );
    }

    /// The agreeing case, so the check above is not trivially always-red.
    #[test]
    fn the_two_witnesses_agree_on_a_healthy_run() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(
            dir.path(),
            &[DISPATCH, READ_OK, READ_RESULT, WRITE_OK, WRITE_RESULT],
        );
        let bind = binding(&["read", "write"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let src = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);

        let trace = build(
            &src,
            &out(TerminalReason::Completed, &["write", "read"]),
            dir.path(),
        );

        assert!(trace.capability_witness.agrees);
        assert_eq!(trace.capability_witness.driver_set, vec!["read", "write"]);
        assert!(!trace.outcome.negative);
    }

    #[test]
    fn two_runs_of_one_work_item_are_two_files() {
        let dir = tempfile::tempdir().unwrap();
        let log = audit(dir.path(), &[READ_OK, READ_RESULT]);
        let bind = binding(&["read"]);
        let receipt = dir.path().join("r.json");
        std::fs::write(&receipt, b"{}").unwrap();
        let mut first = sources(dir.path(), &bind, log.clone(), Some(0), "task-1", &receipt);
        first.recorded_at = "2026-09-24T21:00:00Z".to_owned();
        let mut second = sources(dir.path(), &bind, log, Some(0), "task-1", &receipt);
        second.recorded_at = "2026-09-24T22:00:00Z".to_owned();

        let a = write(
            dir.path(),
            &build(
                &first,
                &out(TerminalReason::Completed, &["read"]),
                dir.path(),
            ),
        )
        .unwrap();
        let b = write(
            dir.path(),
            &build(&second, &out(TerminalReason::MaxCostUsd, &[]), dir.path()),
        )
        .unwrap();

        assert_ne!(a, b);
        assert!(a.exists() && b.exists());
    }
}
