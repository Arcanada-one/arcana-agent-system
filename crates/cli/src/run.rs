//! `arcana run` — one task, one working directory, no human at the prompt.
//!
//! The interactive session and `demo` both assume someone is watching: the
//! cascade's tail asks a terminal, and the tool set is a single echo fixture
//! that proves dispatch works without doing anything. A card runner needs the
//! opposite of both — real tools, a policy instead of a prompt, and an exit
//! code plus a done-marker it can read without parsing prose.
//!
//! ## What it composes
//!
//! * The SAME [`Session`](crate::demo::Session) the REPL and `demo` use — the
//!   real [`Driver`], the fused [`CapabilityExecutor`], one append-only audit
//!   log. No second agent-loop driver exists in this binary and none is added
//!   here.
//! * The real built-in tools (`read`, `write`, `edit`, `grep`, `bash`), each
//!   rooted at the working directory rather than at the ambient process
//!   working directory.
//! * The workspace policy in [`crate::workspace`] in place of the interactive
//!   prompt.
//! * A system prompt that states the driver-owned tool-call wire format. This
//!   is not decoration: [`arcana_core::agent_loop::interpret`] recognises
//!   exactly one encoding, a fenced ```` ```tool_call ```` block, and a model
//!   that has not been told so answers with a ```` ```bash ```` block that
//!   reads like an action and is in fact only text. That was the whole of the
//!   "tools do not execute" defect — the dispatcher, the cascade and the
//!   tools were all present and correct, and nothing ever asked them.
//!
//! ## Live only
//!
//! `run` has no offline mode. The offline connector replays two canned turns;
//! replaying them against a real working directory would produce a receipt
//! for work that never happened, which is worse than no run at all.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arcana_core::agent_loop::{DriverConfig, RunOutput, TerminalReason};
use arcana_core::connector::ModelConnector;
use arcana_core::cost::CostTracker;
use arcana_core::dispatch::ModelPolicy;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::HookChain;
use arcana_core::permission::rule::ToolRuleSet;
use arcana_core::permission::{
    AutoFromEnv, InteractiveDirective, PermissionCascade, PermissionLayer, RuleLayer, SchemaLayer,
};
use arcana_core::tool::{Tool, ToolDispatcher};
use arcana_tools::{
    bash::BashTool, edit::EditTool, grep::GrepTool, read::ReadTool, write::WriteTool,
};

use crate::demo::Session;
use crate::workspace::{
    DestructiveCommandFloor, WorkspaceAutoAllow, WorkspaceBoundary, WorkspacePolicy,
};

/// Connector the headless run dispatches through. A CONNECTOR id, not a route
/// label — it goes straight onto the wire.
const RUN_CONNECTOR_ID: &str = "orq";

/// Audit sink for `arcana run`, under the per-user XDG state home.
const RUN_AUDIT_DIR: &str = "run";

/// Fallback when the XDG state home cannot be resolved.
const FALLBACK_STATE_DIR: &str = ".arcana-state";

/// Project-local rule file, resolved inside the working directory.
const PROJECT_RULES_RELATIVE: &str = ".arcana/permissions.toml";

/// Machine-readable last line of every run, success or failure.
///
/// A runner should not have to tell "the run completed" apart from a model
/// sentence that happens to contain those words, so the marker is a fixed
/// prefix followed by one JSON object, and it is always the last line.
pub const DONE_MARKER: &str = "ARCANA_RUN_DONE";

/// Where a tool result too large to carry in the transcript is kept in full,
/// relative to the workspace root. A runner artefact, not the task's output:
/// it is untracked, so `git diff` and a patch built from it are unaffected.
pub const TOOL_OUTPUT_DIR: &str = ".arcana/tool-output";

/// Everything a headless run needs.
#[derive(Debug, Clone)]
pub struct RunRequest {
    /// Directory the run is confined to. Every tool is rooted here.
    pub cwd: PathBuf,
    /// The task, in plain language.
    pub prompt: String,
    /// Connector-attempt cap.
    pub max_turns: u32,
    /// Spend cap in USD, enforced by the driver's cost tracker.
    pub max_cost_usd: Option<f64>,
    /// Pin a model id instead of using the operator's saved choice.
    pub model: Option<String>,
    /// Per-attempt model budget. `None` leaves the client on its own default
    /// (or on `ARCANA_MC_TIMEOUT_SECS`, when that is set).
    pub request_timeout: Option<Duration>,
}

/// Entry point for `arcana run`. Returns a process exit code.
///
/// `0` when the run reached [`TerminalReason::Completed`], `130` when the
/// operator interrupted it, `1` otherwise — including every way the run could
/// not START, so `arcana run ... && next-step` cannot advance on a run that
/// never happened.
#[must_use]
pub fn run(request: &RunRequest) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("arcana run: failed to start async runtime: {err}");
            return exit_failed(&format!("runtime unavailable: {err}"), &request.cwd);
        }
    };
    runtime.block_on(run_async(request))
}

async fn run_async(request: &RunRequest) -> i32 {
    let root = match request.cwd.canonicalize() {
        Ok(root) if root.is_dir() => root,
        Ok(root) => {
            return exit_failed(
                &format!("--cwd `{}` is not a directory", root.display()),
                &request.cwd,
            );
        }
        Err(err) => {
            return exit_failed(
                &format!(
                    "--cwd `{}` cannot be resolved: {err}",
                    request.cwd.display()
                ),
                &request.cwd,
            );
        }
    };
    if request.prompt.trim().is_empty() {
        return exit_failed("the task is empty", &root);
    }

    let policy = match WorkspacePolicy::new(&root) {
        Ok(policy) => Arc::new(policy),
        Err(err) => return exit_failed(&format!("workspace policy: {err}"), &root),
    };

    // `try_from_env` is the production constructor: it pins the Model
    // Connector origin and refuses an override. A headless run that cannot go
    // live must say so and stop — never quietly become an offline replay.
    let connector: Box<dyn ModelConnector> =
        match arcana_connectors::ModelConnectorClient::try_from_env_with_timeout(
            request.request_timeout,
        ) {
            Ok(client) => {
                println!(
                    "model budget: {}s per attempt, waiting up to {}s for a reply, \
{}s to connect",
                    client.request_timeout().as_secs(),
                    client.http_wait().as_secs(),
                    client.connect_timeout().as_secs(),
                );
                Box::new(client)
            }
            Err(err) => {
                return exit_failed(&format!("the Model Connector is unavailable: {err}"), &root);
            }
        };

    let workspace = match assemble(&root, &policy, connector, audit_dir()) {
        Ok(workspace) => workspace,
        Err(err) => return exit_failed(&err, &root),
    };
    let WorkspaceSession { session, tools } = workspace;
    println!("arcana run: workspace {}", root.display());
    println!("audit log: {}", session.audit_log_path().display());

    let interrupt = crate::interrupt::Interrupt::install();
    let (cancel, turn_guard) = crate::interrupt::arm(interrupt.as_ref());
    let out = session
        .run_task(
            &request.prompt,
            driver_config(request, &tools, &root),
            cancel,
        )
        .await;
    drop(turn_guard);

    report(&out, &root)
}

/// Build the driver config for one headless run.
#[must_use]
pub fn driver_config(request: &RunRequest, tools: &[Arc<dyn Tool>], root: &Path) -> DriverConfig {
    let mut config = DriverConfig::new(RUN_CONNECTOR_ID);
    config.max_turns = request.max_turns;
    config.max_cost_usd = request.max_cost_usd;
    if let Some(model) = request.model.clone().or_else(crate::models::explicit_model) {
        config.policy = ModelPolicy::single_model(&model);
        config.model = Some(model);
    }
    config.system_prompt = Some(system_prompt(tools, root));
    // Where a tool result too large to carry is kept in full. Inside the
    // workspace on purpose: the workspace boundary is what decides which paths
    // the model may read, and a spill file it is not allowed to open would be
    // a marker that promises something it cannot deliver.
    config.tool_output_spill_dir = Some(root.join(TOOL_OUTPUT_DIR));
    // Nobody reads the prose of a headless run, so prose alone cannot end it.
    config.require_action = true;
    config
}

/// The built-in tools a headless run may use, each rooted at `root`.
///
/// `webfetch`, `arcana_search` and `model_call` are deliberately absent: each
/// reaches outside the working directory by definition, and nothing in this
/// policy could confine them.
fn workspace_tools(root: &Path) -> Vec<Arc<dyn Tool>> {
    // The path rule set stays permissive: confinement is the workspace
    // layer's job, and duplicating it here as regexes over path strings would
    // put a SECOND, weaker copy of the boundary in the codebase — weaker
    // because `RuleLayer` matches the raw argument while the workspace layer
    // matches the canonicalized path.
    let rules = Arc::new(ToolRuleSet::default());
    vec![
        Arc::new(ReadTool::with_root(Arc::clone(&rules), root)),
        Arc::new(WriteTool::with_root(Arc::clone(&rules), root)),
        Arc::new(EditTool::with_root(Arc::clone(&rules), root)),
        Arc::new(GrepTool::with_root(root)),
        Arc::new(BashTool::new().in_directory(root)),
    ]
}

/// A composed headless run: the session and the tools it was told about.
///
/// The tool list is returned rather than rebuilt by the caller so the system
/// prompt describes the tools that are actually registered — a second list
/// would be free to disagree with the first.
pub struct WorkspaceSession {
    /// The capability core: connector, fused executor, one audit log.
    pub session: Session,
    /// The registered tools, in registration order.
    pub tools: Vec<Arc<dyn Tool>>,
}

/// Compose a headless run over `connector`, confined to `policy`'s root.
///
/// This is the single composition both the command and its tests go through;
/// a test that built its own would be testing a wiring nobody ships.
///
/// # Errors
///
/// Returns an operator-facing message when a tool cannot be registered, the
/// operator's `permissions.toml` cannot be read, or the audit log cannot be
/// opened.
pub fn assemble(
    root: &Path,
    policy: &Arc<WorkspacePolicy>,
    connector: Box<dyn ModelConnector>,
    audit_dir: PathBuf,
) -> Result<WorkspaceSession, String> {
    let tools = workspace_tools(root);
    let executor = assemble_executor(&tools, policy, root, &audit_dir)?;
    Ok(WorkspaceSession {
        session: Session::from_parts(connector, executor, Arc::new(CostTracker::new()), audit_dir),
        tools,
    })
}

/// Fuse dispatcher + cascade + audit into the capability core.
fn assemble_executor(
    tools: &[Arc<dyn Tool>],
    policy: &Arc<WorkspacePolicy>,
    root: &Path,
    audit_dir: &Path,
) -> Result<CapabilityExecutor, String> {
    let dispatch = build_dispatcher(tools)?;
    // The schema layer needs its own dispatcher because the executor takes
    // ownership of the one it dispatches through.
    let schema_dispatcher = Arc::new(build_dispatcher(tools)?);

    let rule_layer = match RuleLayer::load(
        RuleLayer::xdg_user_path().as_deref(),
        Some(&root.join(PROJECT_RULES_RELATIVE)),
    ) {
        Ok(rules) => rules,
        Err(err) => {
            // Unlike the interactive session, an unreadable rule file is fatal
            // here. There is nobody to read the warning, and degrading to "no
            // operator rules" would silently run a task under a policy the
            // operator did not write.
            return Err(format!("permission rules could not be loaded: {err}"));
        }
    };

    let mut layers: Vec<Arc<dyn PermissionLayer>> = vec![
        Arc::new(SchemaLayer::new(schema_dispatcher)),
        // The floor precedes the boundary: both are deny-or-defer, so the
        // order cannot widen the gate-set, and a call that trips both is then
        // reported under the refusal the agent loop treats as terminal.
        Arc::new(DestructiveCommandFloor::new(Arc::clone(policy))),
        Arc::new(WorkspaceBoundary::new(Arc::clone(policy))),
    ];
    // An explicit `ARCANA_PERMISSION_AUTO=deny` means the operator wants
    // nothing to run. Honour it ahead of the auto-allow half, or the flag
    // would be inert on exactly the command that acts without supervision.
    if matches!(auto_directive(), InteractiveDirective::Deny) {
        layers.push(Arc::new(AutoFromEnv::with_directive(
            InteractiveDirective::Deny,
        )));
    }
    layers.push(Arc::new(rule_layer));
    layers.push(Arc::new(WorkspaceAutoAllow::new(Arc::clone(policy))));
    // Fail-closed tail: anything the workspace policy did not recognise ends
    // here, and off a terminal this denies.
    layers.push(Arc::new(AutoFromEnv::from_env()));

    let audit = AuditLog::new(audit_dir).map_err(|err| format!("audit log setup failed: {err}"))?;
    Ok(CapabilityExecutor::new(
        dispatch,
        PermissionCascade::new(layers),
        HookChain::new(),
        audit,
    ))
}

fn auto_directive() -> InteractiveDirective {
    std::env::var(arcana_core::permission::interactive::ENV_AUTO_DIRECTIVE)
        .map_or(InteractiveDirective::Ask, |raw| {
            InteractiveDirective::parse(&raw)
        })
}

fn build_dispatcher(tools: &[Arc<dyn Tool>]) -> Result<ToolDispatcher, String> {
    let mut dispatcher = ToolDispatcher::new();
    for tool in tools {
        dispatcher
            .register(Arc::clone(tool))
            .map_err(|err| format!("tool registration failed: {err}"))?;
    }
    Ok(dispatcher)
}

/// Resolve the audit directory for `arcana run`.
fn audit_dir() -> PathBuf {
    xdg::BaseDirectories::with_prefix("arcana")
        .get_state_home()
        .unwrap_or_else(|| PathBuf::from(FALLBACK_STATE_DIR))
        .join(RUN_AUDIT_DIR)
}

/// The system prompt: the wire format, the catalogue, and the boundary.
///
/// Built from the registered tools rather than hard-coded, so a tool that is
/// added to or removed from `workspace_tools` cannot drift out of the
/// description the model is working from.
#[must_use]
pub fn system_prompt(tools: &[Arc<dyn Tool>], root: &Path) -> String {
    use std::fmt::Write as _;

    let mut catalogue = String::new();
    for tool in tools {
        // A formatting failure into a String cannot happen; ignoring it keeps
        // the catalogue total rather than making the prompt fallible.
        let _ = writeln!(
            catalogue,
            "- `{}` — {}\n  input schema: {}",
            tool.name(),
            tool.description(),
            tool.input_schema()
        );
    }
    format!(
        "You are an autonomous agent working on ONE task in the directory `{root}`. \
Nobody is watching this session, so nothing you print is an action; only a tool call is.\n\
\n\
TOOL CALL FORMAT. To use a tool, reply with a single fenced block tagged `tool_call` \
and nothing else:\n\
```tool_call\n\
{{\"name\": \"<tool name>\", \"input\": {{ ... }}}}\n\
```\n\
The block must be the only fenced block in the reply and its body must be one JSON object \
with exactly the keys `name` and `input`. A ```bash block, a shell transcript, or a \
description of what you would run executes NOTHING and is read as your final answer.\n\
\n\
AVAILABLE TOOLS:\n\
{catalogue}\
\n\
You will receive the tool's output as a `[tool_result]` line and may then call another \
tool or answer.\n\
\n\
WORKSPACE BOUNDARY. Every path you touch must be inside `{root}`; prefer relative paths. \
Shell commands run in `{root}`. Calls naming a path outside it, and destructive commands \
(privilege escalation, package or service management, recursive force deletion, history \
rewriting), are refused by policy and end the run — do not retry a refused call, say what \
was refused instead.\n\
\n\
When the task is done, reply with a plain-text summary of what you changed and no fenced \
block.",
        root = root.display(),
    )
}

/// The marker's verdict for a run that reached the driver.
///
/// The driver already refuses to call a no-action run `Completed` — `run` sets
/// [`DriverConfig::require_action`]. This says it a second time at the one line
/// a runner reads, because that is where the damage happens: `"completed":true`
/// beside `"tool_calls":0` is a receipt for work with no evidence that anything
/// did it, and the marker must be unable to print that pair whatever the layer
/// above decided.
fn verdict(out: &RunOutput) -> (bool, String) {
    if out.reason.is_success() && out.tool_calls == 0 {
        return (false, format!("{:?}", TerminalReason::NoAction));
    }
    (out.reason.is_success(), format!("{:?}", out.reason))
}

/// Print the outcome, the done-marker, and return the exit code.
fn report(out: &RunOutput, root: &Path) -> i32 {
    match out.final_text.as_deref() {
        Some(text) => println!("{text}"),
        None => println!("(no final text — {})", out.reason),
    }
    let spend = crate::usage::TurnSpend::between(&crate::usage::zero_snapshot(), &out.cost);
    println!(
        "{}",
        crate::usage::turn_line(&spend, out.cost.total_cost_usd_micros)
    );
    let (completed, reason) = verdict(out);
    if !completed {
        eprintln!("arcana run: {} ({reason})", out.reason);
    }
    println!(
        "{DONE_MARKER} {}",
        done_marker_body(&DoneMarker {
            completed,
            reason: &reason,
            turns: out.turns,
            tool_calls: out.tool_calls,
            cost_usd_micros: out.cost.total_cost_usd_micros,
            compactions: out.compactions,
            root,
            error: None,
        })
    );
    let code = crate::interrupt::exit_code(out.reason);
    // `exit_code` maps the driver's reason; a marker that says the run did not
    // complete must never be paired with a `0` a wrapper script reads as go.
    if code == 0 && !completed {
        1
    } else {
        code
    }
}

/// Report a run that never reached the driver, and return exit code `1`.
///
/// The done-marker is printed here too: a runner that only looks for the
/// marker must not hang or, worse, read its absence as success.
fn exit_failed(error: &str, root: &Path) -> i32 {
    eprintln!("arcana run: {error}");
    println!(
        "{DONE_MARKER} {}",
        done_marker_body(&DoneMarker {
            completed: false,
            reason: "NotStarted",
            turns: 0,
            tool_calls: 0,
            cost_usd_micros: 0,
            compactions: 0,
            root,
            error: Some(error),
        })
    );
    1
}

/// The JSON body of the done-marker line.
struct DoneMarker<'a> {
    completed: bool,
    reason: &'a str,
    turns: u32,
    tool_calls: u32,
    cost_usd_micros: u64,
    compactions: u32,
    root: &'a Path,
    error: Option<&'a str>,
}

fn done_marker_body(marker: &DoneMarker<'_>) -> String {
    let DoneMarker {
        completed,
        reason,
        turns,
        tool_calls,
        cost_usd_micros,
        compactions,
        root,
        error,
    } = *marker;
    let body = serde_json::json!({
        "completed": completed,
        "reason": reason,
        "turns": turns,
        "tool_calls": tool_calls,
        "cost_usd_micros": cost_usd_micros,
        // Non-zero means the model answered from a summary of part of its own
        // history. A reader comparing two runs of the same card needs that
        // fact; it is not visible anywhere else after the process exits.
        "compactions": compactions,
        "workspace": root.display().to_string(),
        "error": error,
    });
    body.to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_system_prompt_states_the_wire_format_and_every_registered_tool() {
        let root = Path::new("/tmp");
        let tools = workspace_tools(root);
        let prompt = system_prompt(&tools, root);
        assert!(prompt.contains("```tool_call"), "{prompt}");
        for name in ["read", "write", "edit", "grep", "bash"] {
            assert!(prompt.contains(&format!("`{name}`")), "missing {name}");
        }
        // The exact failure the defect produced, named in the prompt.
        assert!(prompt.contains("```bash block"), "{prompt}");
    }

    #[test]
    fn the_done_marker_is_one_json_object_after_a_fixed_prefix() {
        let body = done_marker_body(&DoneMarker {
            completed: true,
            reason: "Completed",
            turns: 2,
            tool_calls: 1,
            cost_usd_micros: 59,
            compactions: 3,
            root: Path::new("/tmp"),
            error: None,
        });
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["completed"], true);
        assert_eq!(parsed["reason"], "Completed");
        assert_eq!(parsed["turns"], 2);
        assert_eq!(parsed["tool_calls"], 1);
        assert_eq!(parsed["cost_usd_micros"], 59);
        assert_eq!(parsed["compactions"], 3);
    }

    #[test]
    fn a_run_that_never_started_is_not_reported_as_completed() {
        let body = done_marker_body(&DoneMarker {
            completed: false,
            reason: "NotStarted",
            turns: 0,
            tool_calls: 0,
            cost_usd_micros: 0,
            compactions: 0,
            root: Path::new("/tmp"),
            error: Some("boom"),
        });
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["completed"], false);
        assert_eq!(parsed["error"], "boom");
    }

    /// One `RunOutput` for the verdict tests; only the two fields it reads.
    fn outcome(reason: TerminalReason, tool_calls: u32) -> RunOutput {
        RunOutput {
            reason,
            final_text: Some("The file has been created successfully.".to_owned()),
            turns: 1,
            tool_calls,
            cost: arcana_core::cost::CostTracker::new().snapshot(),
            selected_models: Vec::new(),
            first_dispatch_observation: None,
            compactions: 0,
        }
    }

    #[test]
    fn a_completed_run_that_executed_nothing_is_not_reported_as_completed() {
        // The live failure verbatim: one turn, zero tool calls, a confident
        // sentence. Even if the layer below said `Completed`, the marker does
        // not.
        let (completed, reason) = verdict(&outcome(TerminalReason::Completed, 0));
        assert!(!completed);
        assert_eq!(reason, "NoAction");
    }

    #[test]
    fn a_completed_run_with_an_executed_tool_call_is_reported_as_completed() {
        // The green half: the same check must be able to say yes, or it is
        // just a constant.
        let (completed, reason) = verdict(&outcome(TerminalReason::Completed, 1));
        assert!(completed);
        assert_eq!(reason, "Completed");
    }

    #[test]
    fn a_failure_keeps_its_own_reason_rather_than_becoming_no_action() {
        let (completed, reason) = verdict(&outcome(TerminalReason::PermissionDenied, 0));
        assert!(!completed);
        assert_eq!(reason, "PermissionDenied");
    }
}
