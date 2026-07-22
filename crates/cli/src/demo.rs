//! `arcana demo` — the Phase-C vertical-prototype composition root (ARAS-0032).
//!
//! Assembles the SAME real capability core the `DoD` integration test uses —
//! the [`Driver`](arcana_core::agent_loop::Driver) (ARAS-0030), the multi-model
//! [`ModelPolicy`](arcana_core::dispatch::ModelPolicy) (ARAS-0031), and the
//! fused [`CapabilityExecutor`](arcana_core::execution::CapabilityExecutor)
//! (ARAS-0033) that owns the `ToolDispatcher`, the `PermissionCascade`, an empty
//! post-cascade `HookChain`, and the `AuditLog` (audit is a field of the fused
//! authorize→audit→execute transaction — single audit by construction) — and
//! drives one attempt → check → conclusion loop, printing three labelled phases.
//!
//! ## Demo-only scaffolding (NOT capability core)
//!
//! Two pieces in THIS module are deliberately demo-only composition-root
//! fixtures, explicitly permitted by ARAS-0032 V-AC-5 (which forbids *new*
//! `Tool`/`ModelConnector` impls only in `arcana-core` / `arcana-connectors`
//! `src`):
//!
//! - [`DemoConnector`] — a canned, offline [`ModelConnector`] that replays two
//!   fixed turns so the default demo path is deterministic and needs no network
//!   or `ARCANA_MC_TOKEN`. It is NOT a capability-core connector and does not
//!   reimplement `arcana-connectors`.
//! - [`DemoEchoTool`] — a minimal real [`Tool`] (the core `EchoTool` lives in
//!   `crates/core/tests/` and is unreachable from `src`), so a genuine tool
//!   dispatch occurs through the real `ToolDispatcher` in the demo.
//!
//! The optional `--live` path swaps [`DemoConnector`] for the real
//! [`ModelConnectorClient`](arcana_connectors::ModelConnectorClient) when
//! `ARCANA_MC_TOKEN` is present, and falls back to the offline path otherwise.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
use arcana_core::connector::{
    ConnectorError, ConnectorResponse, ExecuteRequest, ModelConnector, Usage,
};
use arcana_core::cost::CostTracker;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::HookChain;
use arcana_core::permission::PermissionCascade;
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

/// Default small real task when the operator does not pass one. Carries a code
/// signal ("implement"/"rust") so turn-0 classifies as `Code` (expensive model)
/// and the post-tool turn as `Summarize` (cheap model) — two distinct ids.
const DEFAULT_TASK: &str = "implement a greeting in rust: echo the world back";

/// Entry point for the `arcana demo` subcommand. Assembles the full vertical
/// loop, prints the three labelled phases, and returns a process exit code
/// (`0` on `Completed`, non-zero otherwise — honest exit code).
#[must_use]
pub fn run_demo(task: Option<String>, live: bool) -> i32 {
    let task = task.unwrap_or_else(|| DEFAULT_TASK.to_owned());
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("arcana demo: failed to start async runtime: {err}");
            return 1;
        }
    };
    runtime.block_on(run_demo_async(&task, live))
}

/// Async body: build the components, run the driver, print the phases.
async fn run_demo_async(task: &str, live: bool) -> i32 {
    // Isolated audit sink under the system temp dir; `AuditHook::new` creates it.
    let audit_dir: PathBuf = std::env::temp_dir().join("arcana-demo");

    // Connector selection: offline canned by default; real Model Connector on
    // `--live` when `ARCANA_MC_TOKEN` is present, else fall back to offline.
    let live_active = live && std::env::var("ARCANA_MC_TOKEN").is_ok();
    let connector: Box<dyn ModelConnector> = if live_active {
        match arcana_connectors::ModelConnectorClient::try_from_env() {
            Ok(client) => {
                println!("(live path: routing through the real Model Connector)");
                Box::new(client)
            }
            Err(err) => {
                println!("(live requested but unavailable: {err}; using offline demo)");
                Box::new(DemoConnector::new())
            }
        }
    } else {
        if live {
            println!("(live requested but ARCANA_MC_TOKEN unset; using offline demo)");
        }
        Box::new(DemoConnector::new())
    };

    let mut dispatcher = ToolDispatcher::new();
    if let Err(err) = dispatcher.register(Arc::new(DemoEchoTool)) {
        eprintln!("arcana demo: tool registration failed: {err}");
        return 1;
    }

    // Empty (always-allow) cascade + an executor-OWNED AuditLog: in the C4
    // CapabilityExecutor the audit is a field of the fused
    // authorize→audit→execute transaction (single audit by construction), not a
    // composable ToolHook.
    let cascade = PermissionCascade::new(vec![]);
    let audit = match AuditLog::new(&audit_dir) {
        Ok(log) => log,
        Err(err) => {
            eprintln!("arcana demo: audit log setup failed: {err}");
            return 1;
        }
    };
    let cost = Arc::new(CostTracker::new());

    // Fuse the capability core: the executor takes ownership of the dispatcher,
    // the cascade, an empty post-cascade HookChain, and the AuditLog. The driver
    // dispatches every tool THROUGH this executor.
    let executor = CapabilityExecutor::new(dispatcher, cascade, HookChain::new(), audit);

    // Default ModelPolicy maps Code→"arcana-code-strong" and
    // Summarize→"arcana-cheap-fast" (distinct ids) — reused verbatim.
    let out = {
        let driver = Driver::new(
            connector.as_ref(),
            &executor,
            cost,
            CancellationToken::new(),
            DriverConfig::new("arcana-demo"),
        );
        driver.run(task).await
    };

    // --- attempt → check → conclusion --------------------------------------
    let models = if out.selected_models.is_empty() {
        "<none>".to_owned()
    } else {
        out.selected_models.join(", ")
    };
    println!("=== ATTEMPT ===");
    println!("task: {task}");
    println!("models selected (in order): {models}");
    println!();
    println!("=== CHECK ===");
    println!("tool turns: {}", out.turns);
    println!("terminal verdict: {:?}", out.reason);
    println!();
    println!("=== CONCLUSION ===");
    println!(
        "final: {}",
        out.final_text.as_deref().unwrap_or("<no final text>")
    );
    println!("audit log: {}", audit_dir.join("audit.log").display());

    // `AuditLog` appends synchronously and flushes per record; the executor owns
    // it and drops at function scope end, so no explicit flush is required.

    i32::from(out.reason != TerminalReason::Completed)
}

// ---------------------------------------------------------------------------
// Demo scaffolding — offline canned connector (NOT a capability-core connector)
// ---------------------------------------------------------------------------

/// Demo-only, offline [`ModelConnector`]: replays a fixed two-turn script — a
/// tool-call turn (Code step) then a final answer (Summarize step) — so the
/// default demo path is deterministic with no network and no `ARCANA_MC_TOKEN`.
///
/// This is composition-root scaffolding permitted by ARAS-0032 V-AC-5; it is
/// NOT part of the capability core and does not reimplement `arcana-connectors`.
struct DemoConnector {
    turns: Vec<ConnectorResponse>,
    idx: AtomicUsize,
}

impl DemoConnector {
    fn new() -> Self {
        Self {
            turns: vec![
                canned_response(&tool_call_fence("echo", &json!({ "text": "world" })), 0.001),
                canned_response("greeting complete: hello world", 0.001),
            ],
            idx: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ModelConnector for DemoConnector {
    async fn execute(&self, _req: ExecuteRequest) -> Result<ConnectorResponse, ConnectorError> {
        let i = self.idx.fetch_add(1, Ordering::Relaxed);
        // Bounded to the last turn so any extra loop iteration re-emits the
        // final answer (never out-of-range, never a panic).
        let last = self.turns.len().saturating_sub(1);
        match self.turns.get(i.min(last)) {
            Some(resp) => Ok(resp.clone()),
            None => Err(ConnectorError::Transport(
                "demo connector has no scripted turns".to_owned(),
            )),
        }
    }
}

/// Build a canned success [`ConnectorResponse`] carrying `result` and `cost`.
fn canned_response(result: &str, cost_usd: f64) -> ConnectorResponse {
    ConnectorResponse {
        id: "demo-id".to_owned(),
        connector: "arcana-demo".to_owned(),
        model: "demo-model".to_owned(),
        result: result.to_owned(),
        usage: Usage {
            input_tokens: 3,
            output_tokens: 5,
            total_tokens: 8,
            cost_usd,
        },
        latency_ms: 1,
        status: "success".to_owned(),
        error: None,
    }
}

/// Render the driver-recognised `tool_call` fenced block for the demo script.
fn tool_call_fence(name: &str, input: &Value) -> String {
    let payload = json!({ "name": name, "input": input });
    format!("```tool_call\n{payload}\n```")
}

// ---------------------------------------------------------------------------
// Demo scaffolding — a minimal real tool (core EchoTool is not reachable here)
// ---------------------------------------------------------------------------

/// Demo-only minimal real [`Tool`]: echoes its input back as content, so a
/// genuine dispatch occurs through the real `ToolDispatcher`. The core
/// `EchoTool` lives in `crates/core/tests/` and is unreachable from `src`, so
/// this equivalent demo fixture is defined in the CLI composition root
/// (permitted by ARAS-0032 V-AC-5). It is NOT a capability-core tool.
struct DemoEchoTool;

#[async_trait]
impl Tool for DemoEchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "demo fixture: echoes its input back as content"
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object" })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        Ok(ToolOutput {
            content: format!("echo:{input}"),
            metadata: None,
        })
    }
}
