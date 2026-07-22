//! Phase-C **capstone** (ARAS-0032): the whole vertical prototype in one run.
//!
//! This test is the DoD integration seam for epic ARAS-0029 Phase C. It wires
//! the pieces built on the stacked branches into ONE attempt → check →
//! conclusion loop, on a small real task, fully offline/deterministic:
//!
//! - the REAL [`Driver`] (ARAS-0030) drives the loop to terminal;
//! - the REAL multi-model [`ModelPolicy`] (ARAS-0031) routes two turns to two
//!   DISTINCT model ids (a `Code` step, then a `Summarize` step);
//! - a REAL [`EchoTool`] dispatch happens through the [`ToolDispatcher`];
//! - the executor-owned [`AuditLog`] is the single audit surface (audit is a
//!   field of the fused `CapabilityExecutor`, single audit by construction);
//! - the driver's exhaustive `reduce` reaches
//!   [`TerminalReason::Completed`].
//!
//! It composes existing collaborators only — no new capability code — and reuses
//! the `tests/common/mod.rs` doubles (`ScriptedConnector` mocks the network
//! edge; `EchoTool` is a *real* trivial tool). No network, no DEVS, no
//! `ARCANA_MC_TOKEN`.
//!
//! Covers: V-AC-1 (DoD: Completed after ≥1 tool turn), V-AC-2 (≥2 distinct
//! models in one run), V-AC-6 (single-source audit — one pre/post line per
//! executed capability, through the one cascade path).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use common::{response, tool_call_result, EchoTool, ScriptedConnector};

#[tokio::test]
async fn capstone_vertical_prototype_attempt_check_conclusion() {
    // Isolated temp audit path — no global-state leak across parallel test
    // binaries; this run is the ONLY writer to `audit.log`.
    let dir = TempDir::new().expect("tempdir creation failed");

    // ATTEMPT — a small real task with a code signal ("implement"/"rust") so
    // turn-0 classifies as `Code` (→ expensive model); turn-1, after the tool
    // result, classifies as `Summarize` (→ cheap model). Two distinct ids.
    //
    // Turn 0: the model asks for the echo tool (a Code step emitting a tool
    // call). Turn 1: it produces the final answer (a Summarize step).
    let connector = ScriptedConnector::new(vec![
        response(&tool_call_result("echo", json!({ "text": "world" })), 0.001),
        response("greeting complete: hello world", 0.001),
    ]);

    // A REAL tool dispatch — EchoTool is not a mock.
    let mut dispatcher = ToolDispatcher::new();
    dispatcher
        .register(Arc::new(EchoTool))
        .expect("register echo tool");

    // Allowing cascade + an executor-OWNED AuditLog: the single audit surface
    // the fused executor writes (mirrors driver_audit_inherited). An empty
    // cascade would fail-closed (all-defer → Denied) under C4, so the run uses
    // an explicit allow layer to reach the tool.
    let cascade = common::allow_cascade();
    let audit = AuditLog::new(dir.path()).expect("audit log construction");
    let hooks = HookChain::new();
    let cost = Arc::new(CostTracker::new());

    // The executor fuses authorize→audit→execute and owns the dispatcher,
    // cascade, post-cascade hooks, and the AuditLog.
    let executor = CapabilityExecutor::new(dispatcher, cascade, hooks, audit);

    // Default ModelPolicy already maps Code→"arcana-code-strong" and
    // Summarize→"arcana-cheap-fast" (distinct ids) — reused verbatim, no
    // dispatch.rs change. `DriverConfig::new` carries `ModelPolicy::new()`.
    let out = {
        let driver = Driver::new(
            &connector,
            &executor,
            cost,
            CancellationToken::new(),
            DriverConfig::new("scripted"),
        );
        driver
            .run("implement a greeting in rust: echo the world back")
            .await
    };

    // --- CHECK: terminal verdict + ≥1 real tool turn (V-AC-1) ---------------
    assert_eq!(
        out.reason,
        TerminalReason::Completed,
        "the loop must reach Terminal(Completed)"
    );
    assert!(
        out.turns >= 1,
        "≥1 real tool turn happened, got {}",
        out.turns
    );
    assert_eq!(
        out.final_text.as_deref(),
        Some("greeting complete: hello world"),
        "the final answer is surfaced on RunOutput"
    );

    // --- CHECK: ≥2 distinct models in the one run (V-AC-2 / epic V-AC-5) -----
    let distinct: HashSet<&String> = out.selected_models.iter().collect();
    assert!(
        distinct.len() >= 2,
        "≥2 distinct model ids selected in one run, got {:?}",
        out.selected_models
    );

    // The real EchoTool actually ran: its output is folded back into the 2nd
    // connector request prompt (attempt → tool → check feedback loop).
    let requests = connector.requests();
    assert!(
        requests.len() >= 2,
        "expected ≥2 connector calls, got {}",
        requests.len()
    );
    assert!(
        requests[1].prompt.contains("echo:"),
        "2nd prompt must carry the real tool output, got: {}",
        requests[1].prompt
    );

    // --- CONCLUSION: single-source audit (V-AC-6) ---------------------------
    // The executor-owned AuditLog appends synchronously and flushes per record,
    // so the file is already complete and readable here.
    let contents =
        std::fs::read_to_string(dir.path().join("audit.log")).expect("audit.log read failed");
    let lines: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is not JSON"))
        .collect();

    // The fused executor writes the correlated pair with the C4 audit schema:
    // one `decision` record (carrying `input_hash`) and one terminal `result`
    // record (carrying `output_hash`), both for the same executed capability.
    let decision: Vec<&Value> = lines
        .iter()
        .filter(|l| l["phase"].as_str() == Some("decision"))
        .collect();
    let result: Vec<&Value> = lines
        .iter()
        .filter(|l| l["phase"].as_str() == Some("result"))
        .collect();

    // Exactly one decision + one result line for the ONE executed `echo`
    // capability — no bypass, no double audit (single executor-owned path).
    assert_eq!(
        decision.len(),
        1,
        "exactly one decision audit line for echo"
    );
    assert_eq!(result.len(), 1, "exactly one result audit line for echo");
    assert_eq!(decision[0]["tool"].as_str(), Some("echo"));
    assert_eq!(result[0]["tool"].as_str(), Some("echo"));

    // The decision record carries a Blake3 input hash; the result record a
    // Blake3 output hash — both 16 hex chars.
    for (record, field) in [(decision[0], "input_hash"), (result[0], "output_hash")] {
        let hash = record[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is a string"));
        assert_eq!(hash.len(), 16, "Blake3 {field} is 16 hex chars: {hash}");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "{field} must be hex: {hash}"
        );
    }
}
