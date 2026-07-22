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
//! - the ONE [`AuditHook`] on the [`HookChain`] is the single audit surface;
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
use arcana_core::hooks::audit::AuditHook;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
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

    // Empty (always-allow) cascade + the ONE AuditHook on the HookChain: the
    // single audit surface the driver walks (mirrors driver_audit_inherited).
    let cascade = PermissionCascade::new(vec![]);
    let audit = Arc::new(AuditHook::new(dir.path()).expect("audit hook construction"));
    let mut hooks = HookChain::new();
    hooks.push(audit.clone());
    let cost = Arc::new(CostTracker::new());

    // Default ModelPolicy already maps Code→"arcana-code-strong" and
    // Summarize→"arcana-cheap-fast" (distinct ids) — reused verbatim, no
    // dispatch.rs change. `DriverConfig::new` carries `ModelPolicy::new()`.
    let out = {
        let driver = Driver::new(
            &connector,
            &dispatcher,
            &cascade,
            &hooks,
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
    // Drop every AuditHook owner so the non-blocking WorkerGuard flushes.
    drop(hooks);
    drop(audit);

    let contents =
        std::fs::read_to_string(dir.path().join("audit.log")).expect("audit.log read failed");
    let lines: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is not JSON"))
        .collect();

    let pre: Vec<&Value> = lines
        .iter()
        .filter(|l| l["phase"].as_str() == Some("pre"))
        .collect();
    let post: Vec<&Value> = lines
        .iter()
        .filter(|l| l["phase"].as_str() == Some("post"))
        .collect();

    // Exactly one pre + one post line for the ONE executed `echo` capability —
    // no bypass, no double audit (single cascade/hook path).
    assert_eq!(pre.len(), 1, "exactly one pre-tool audit line for echo");
    assert_eq!(post.len(), 1, "exactly one post-tool audit line for echo");
    for record in [pre[0], post[0]] {
        assert_eq!(record["tool"].as_str(), Some("echo"));
        let hash = record["input_hash"]
            .as_str()
            .expect("input_hash is a string");
        assert_eq!(hash.len(), 16, "Blake3 input hash is 16 hex chars: {hash}");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "input_hash must be hex: {hash}"
        );
    }
}
