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
use arcana_core::contract::ContractBinding;
use arcana_core::cost::CostTracker;
use arcana_core::dispatch::ModelPolicy;
use arcana_core::execution::CapabilityExecutor;
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::HookChain;
use arcana_core::permission::rule::ToolRuleSet;
use arcana_core::permission::{
    AutoFromEnv, ContractAllowlistLayer, InteractiveDirective, PermissionCascade, PermissionLayer,
    RuleLayer, SchemaLayer,
};
use arcana_core::prompt_budget::{
    DEFAULT_CONTEXT_BUDGET_UTF16_UNITS, MC_FIELD_MAX_UTF16_UNITS, MIN_ELISION_BUDGET,
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

/// Parent of the per-run sandbox `HOME`, under the same state directory the
/// audit log lives in. See [`sandbox_home`].
const SANDBOX_HOME_DIR: &str = "home";

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

/// Where a reply the runner refused to act on is kept verbatim, relative to
/// the workspace root. Beside the spilled tool output and untracked for the
/// same reason: it is the runner's evidence about the run, not the task's
/// output, so it must not turn up in a patch the task hands back.
pub const REJECTED_DIR: &str = ".arcana/rejected";

/// Where a tool call the permission cascade refused is kept, with the reason,
/// relative to the workspace root. Beside the rejected replies and untracked
/// for the same reason. It exists because a denial used to leave only
/// `decision`/`layer`/`input_hash` in the audit log: pilot A2-240b spent 21
/// of its 100 paid turns on refused calls — the run's largest single sink —
/// and not one of them could be read afterwards (A2-249).
pub const DENIED_DIR: &str = ".arcana/denied";

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
    /// Serialized-transcript ceiling in UTF-16 code units. `None` keeps
    /// [`arcana_core::prompt_budget::DEFAULT_CONTEXT_BUDGET_UTF16_UNITS`].
    ///
    /// Two reasons it is reachable from the command line at all. A model whose
    /// context window is smaller than Model Connector's field limit needs the
    /// lower number, and until this flag existed there was no way to give it
    /// one. And the compaction path could not be exercised live: nothing a
    /// task does makes a transcript cross 90 000 units cheaply, so the only
    /// evidence that folding works in a real run was an offline test
    /// (A2-216 report, § "what is NOT measured").
    pub context_budget: Option<usize>,
    /// Ceiling on one tool result's contribution to the transcript, in UTF-16
    /// code units. `None` keeps
    /// [`arcana_core::prompt_budget::DEFAULT_TOOL_RESULT_BUDGET_UTF16_UNITS`].
    ///
    /// Reachable from the command line for the same reason `--context-budget`
    /// is: nothing an ordinary task does makes a single tool result cross
    /// 8 000 units cheaply, so the elision-and-spill path could be shown to
    /// work offline and nowhere else (A2-218 report, defect 4).
    pub tool_result_budget: Option<usize>,
    /// Append every dispatch's exact request to this file. `None` — the
    /// default — writes no transcript at all.
    pub save_transcript: Option<PathBuf>,
    /// The KC2 contract this run is bound to, when it was started from a work
    /// item. `Some` inserts [`ContractAllowlistLayer`] into the cascade, so a
    /// tool the contract never admitted is refused with the contract named.
    ///
    /// `None` is the ordinary `--prompt` run: no work item, no contract, and
    /// nothing for the layer to enforce. It is NOT a permissive mode — the
    /// whole cascade below it is unchanged either way.
    pub contract: Option<ContractBinding>,
}

/// Reject a `--context-budget` that cannot be honoured, before anything is
/// spent.
///
/// Above [`MC_FIELD_MAX_UTF16_UNITS`] the number is a promise the server will
/// not keep: the transcript would be compacted to a ceiling that still fails
/// validation, so the run would die on an `HTTP 400` having paid for every
/// turn up to it. Zero is refused here rather than left to the driver so the
/// operator reads a sentence instead of a terminal reason.
///
/// # Errors
/// The message to print, when the value cannot be used.
pub fn check_context_budget(units: Option<usize>) -> Result<(), String> {
    let Some(units) = units else { return Ok(()) };
    if units == 0 {
        return Err("--context-budget must be at least 1".to_owned());
    }
    if units > MC_FIELD_MAX_UTF16_UNITS {
        return Err(format!(
            "--context-budget {units} is above the {MC_FIELD_MAX_UTF16_UNITS}-unit limit Model \
             Connector enforces on the request; a transcript compacted to it would still be \
             refused"
        ));
    }
    Ok(())
}

/// Reject a `--tool-result-budget` that cannot be honoured, before anything is
/// spent.
///
/// Two ways the number is unusable, and neither shows up as an error later —
/// which is the point of checking here. Below
/// [`MIN_ELISION_BUDGET`] every oversized result is replaced by the elision
/// marker ALONE, so the run keeps working and quietly tells the model nothing;
/// above the transcript ceiling the setting cannot bind, because one result
/// would be allowed to fill the whole request and the context guard would then
/// have to fold away the task that explains it.
///
/// `context` is the ceiling this run will actually use, so the two flags are
/// judged against each other rather than against the default.
///
/// # Errors
/// The message to print, when the value cannot be used.
pub fn check_tool_result_budget(units: Option<usize>, context: usize) -> Result<(), String> {
    let Some(units) = units else { return Ok(()) };
    if units < MIN_ELISION_BUDGET {
        return Err(format!(
            "--tool-result-budget {units} is below {MIN_ELISION_BUDGET} units, which is less \
             than the marker that says what was elided and where the whole of it is kept; \
             every oversized result would be replaced by that marker and nothing else"
        ));
    }
    if units > context {
        return Err(format!(
            "--tool-result-budget {units} is above this run's {context}-unit transcript \
             ceiling; a single tool result allowed to fill the whole request would leave the \
             guard nothing to keep but the result"
        ));
    }
    Ok(())
}

/// Open (creating) the operator's transcript file, so a run cannot get to turn
/// thirty before discovering it has nowhere to write.
///
/// # Errors
/// The message to print, when the path cannot be appended to.
pub fn check_transcript_path(path: Option<&Path>) -> Result<(), String> {
    let Some(path) = path else { return Ok(()) };
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(|_| ())
        .map_err(|err| {
            format!(
                "--save-transcript `{}` cannot be written: {err}",
                path.display()
            )
        })
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
    // Canonicalize for the marker only. `execute` canonicalizes again and
    // owns the error message; falling back to the raw path here keeps the
    // done-marker printable for a `--cwd` that does not resolve at all.
    let root = request
        .cwd
        .canonicalize()
        .unwrap_or_else(|_| request.cwd.clone());
    match execute(request).await {
        Ok(out) => report_run(&out, &root),
        Err(err) => exit_failed(&err, &root),
    }
}

/// Run one headless task and hand back what the driver measured.
///
/// Separate from [`run_async`] because a contract-bound run needs the
/// [`RunOutput`] itself — the receipt is built from it — and must not have to
/// reconstruct it from an exit code and the marker line.
///
/// # Errors
/// An operator-facing message for every way the run could not START. A run
/// that started and failed returns `Ok` with the terminal reason inside.
pub async fn execute(request: &RunRequest) -> Result<RunOutput, String> {
    let root = match request.cwd.canonicalize() {
        Ok(root) if root.is_dir() => root,
        Ok(root) => {
            return Err(format!("--cwd `{}` is not a directory", root.display()));
        }
        Err(err) => {
            return Err(format!(
                "--cwd `{}` cannot be resolved: {err}",
                request.cwd.display()
            ));
        }
    };
    if request.prompt.trim().is_empty() {
        return Err("the task is empty".to_owned());
    }
    check_context_budget(request.context_budget)?;
    let context = request
        .context_budget
        .unwrap_or(DEFAULT_CONTEXT_BUDGET_UTF16_UNITS);
    check_tool_result_budget(request.tool_result_budget, context)?;
    check_transcript_path(request.save_transcript.as_deref())?;

    let policy = match WorkspacePolicy::new(&root) {
        Ok(policy) => Arc::new(policy),
        Err(err) => return Err(format!("workspace policy: {err}")),
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
                return Err(format!("the Model Connector is unavailable: {err}"));
            }
        };

    let workspace = match assemble(
        &root,
        &policy,
        connector,
        audit_dir(),
        request.contract.clone(),
    ) {
        Ok(workspace) => workspace,
        Err(err) => return Err(err),
    };
    let WorkspaceSession {
        session,
        tools,
        sandbox_home,
    } = workspace;
    println!("arcana run: workspace {}", root.display());
    println!("audit log: {}", session.audit_log_path().display());

    let config = driver_config(request, &tools, &root);
    // Stated, not assumed: the number the transcript is held under decides
    // when the run starts folding its own history, and a live run that
    // compacts should not leave the reader guessing which ceiling it hit.
    println!(
        "context budget: {} characters (UTF-16 units){}",
        config.context_budget_units,
        if request.context_budget.is_some() {
            ""
        } else {
            " (default)"
        }
    );
    println!(
        "tool result budget: {} characters (UTF-16 units){}",
        config.tool_result_budget_units,
        if request.tool_result_budget.is_some() {
            ""
        } else {
            " (default)"
        }
    );
    if let Some(path) = request.save_transcript.as_ref() {
        println!("transcript: appending every request to {}", path.display());
    }

    let interrupt = crate::interrupt::Interrupt::install();
    let (cancel, turn_guard) = crate::interrupt::arm(interrupt.as_ref());
    let out = session.run_task(&request.prompt, config, cancel).await;
    drop(turn_guard);
    release_sandbox_home(&sandbox_home);

    Ok(out)
}

/// Give the per-run sandbox `HOME` back, if the run left it empty.
///
/// Non-recursive on purpose, and that is the whole of the design: an empty
/// directory is the ordinary case and disappears, while a run that DID write
/// to `~` keeps every byte of it. A recursive delete here would tidy away the
/// only evidence of the one behaviour worth looking at afterwards, and an
/// agent runner that deletes its own evidence is the failure mode this
/// codebase is built against.
///
/// Failure is ignored deliberately: this runs after the task is finished, and
/// a leftover directory is untidy, never wrong.
fn release_sandbox_home(home: &Path) {
    drop(std::fs::remove_dir(home));
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
    if let Some(units) = request.context_budget {
        config.context_budget_units = units;
    }
    if let Some(units) = request.tool_result_budget {
        config.tool_result_budget_units = units;
    }
    config.transcript_path.clone_from(&request.save_transcript);
    // Where a tool result too large to carry is kept in full. Inside the
    // workspace on purpose: the workspace boundary is what decides which paths
    // the model may read, and a spill file it is not allowed to open would be
    // a marker that promises something it cannot deliver.
    config.tool_output_spill_dir = Some(root.join(TOOL_OUTPUT_DIR));
    // Beside it, and inside the workspace for the same reason: a reply the
    // runner threw away is evidence about this run, and the operator reading
    // the log line that names the file should find it where the run happened.
    config.rejected_reply_dir = Some(root.join(REJECTED_DIR));
    // And beside that: the call the cascade refused, with the sentence it was
    // refused with. The audit log keeps the hash of that sentence and not the
    // sentence, because a refusal quotes the argument or the path that caused
    // it — so this is the only place the reason is written down.
    config.denied_call_dir = Some(root.join(DENIED_DIR));
    // Nobody reads the prose of a headless run, so prose alone cannot end it.
    config.require_action = true;
    config
}

/// The built-in tools a headless run may use, each rooted at `root`.
///
/// `webfetch`, `arcana_search` and `model_call` are deliberately absent: each
/// reaches outside the working directory by definition, and nothing in this
/// policy could confine them.
fn workspace_tools(root: &Path, sandbox_home: &Path) -> Vec<Arc<dyn Tool>> {
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
        Arc::new(BashTool::new().in_directory(root).with_home(sandbox_home)),
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
    /// The per-run sandbox `HOME` handed to `bash`. Owned by the caller after
    /// this point: it exists, it is empty, and [`run`] removes it when the run
    /// ends IF the run left it empty.
    pub sandbox_home: PathBuf,
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
    contract: Option<ContractBinding>,
) -> Result<WorkspaceSession, String> {
    let sandbox_home = sandbox_home(&audit_dir)?;
    let tools = workspace_tools(root, &sandbox_home);
    let executor = assemble_executor(&tools, policy, root, &audit_dir, contract)?;
    Ok(WorkspaceSession {
        session: Session::from_parts(connector, executor, Arc::new(CostTracker::new()), audit_dir),
        tools,
        sandbox_home,
    })
}

/// Create the sandbox `HOME` this run's `bash` tool will use, and return its
/// absolute path.
///
/// One directory per run, under the run's own state directory beside the audit
/// log. `BashTool`'s own default is `/tmp/arcana-runtime/bash` — one fixed
/// path, in a world-writable directory, shared by every run on the host; see
/// [`arcana_tools::bash::BashTool::with_home`] for what was measured about it.
///
/// Fail-closed, like every other piece of run setup here: a run whose `HOME`
/// could not be created must not silently fall back to the shared one, because
/// the fallback is exactly the state this exists to stop sharing.
///
/// Canonicalized before it is handed on, because `audit_dir` may be relative
/// (`FALLBACK_STATE_DIR`) and `CleanEnv` refuses a `HOME` that is not
/// absolute — a relative one would surface as a tool execution failure on the
/// first command instead of as a setup error here.
fn sandbox_home(audit_dir: &Path) -> Result<PathBuf, String> {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let home = audit_dir
        .join(SANDBOX_HOME_DIR)
        .join(format!("{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&home).map_err(|err| {
        format!(
            "sandbox HOME could not be created at {}: {err}",
            home.display()
        )
    })?;
    // Owner-only: the state directory is the operator's, and a `HOME` other
    // local users can read is the /tmp problem again under a longer path.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("sandbox HOME permissions could not be set: {err}"))?;
    }
    home.canonicalize().map_err(|err| {
        format!(
            "sandbox HOME {} could not be resolved: {err}",
            home.display()
        )
    })
}

/// Fuse dispatcher + cascade + audit into the capability core.
fn assemble_executor(
    tools: &[Arc<dyn Tool>],
    policy: &Arc<WorkspacePolicy>,
    root: &Path,
    audit_dir: &Path,
    contract: Option<ContractBinding>,
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

    let mut layers: Vec<Arc<dyn PermissionLayer>> =
        vec![Arc::new(SchemaLayer::new(schema_dispatcher))];
    // After the schema layer and before everything else. After, because a
    // malformed call is a correction the model can act on and not a contract
    // violation — reporting it as one would send the model looking for a tool
    // it already has. Before, because a tool the contract never admitted must
    // be refused for THAT reason rather than for whichever of the floor or the
    // boundary it happened to trip on the way past.
    if let Some(binding) = contract {
        layers.push(Arc::new(ContractAllowlistLayer::new(binding)));
    }
    layers.extend::<Vec<Arc<dyn PermissionLayer>>>(vec![
        // The floor precedes the boundary: both are deny-or-defer, so the
        // order cannot widen the gate-set, and a call that trips both is then
        // reported under the refusal the agent loop treats as terminal.
        Arc::new(DestructiveCommandFloor::new(Arc::clone(policy))),
        Arc::new(WorkspaceBoundary::new(Arc::clone(policy))),
    ]);
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

/// The system prompt: the wire format, the catalogue, the boundary, and the
/// destructive-command floor.
///
/// Built from the registered tools rather than hard-coded, so a tool that is
/// added to or removed from `workspace_tools` cannot drift out of the
/// description the model is working from. The floor section is generated the
/// same way and for the same reason, from the floor's own constants — see
/// [`crate::workspace::destructive_floor_disclosure`] for what it costs to
/// leave a model guessing at it (pilot A2-231: 78 turns lost to one flag).
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
Shell commands run in `{root}`. The single exception is `{null_sink}`, which is permitted as a \
redirect target or argument because it discards what is written to it and yields nothing when \
read; every other path outside `{root}` is refused, `/dev/` included.\n\
\n\
A `cd` earlier in the same command does NOT move this boundary: {relative_path_remedy} `{root}`. \
So `cd sub && cp file ../other/` is refused even though `../other` would land inside the \
workspace — write it as `cp sub/file other/` instead.\n\
\n\
NO CREDENTIALS ON THIS LANE. `bash` runs with a constructed, credential-free environment: \
`HOME` is an empty directory created for this run — no git config, no credential helper, no \
SSH key, no token — and your own `env_vars` are refused. A PRIVATE repository therefore cannot \
be cloned, fetched or read, and will fail with `could not read Username for \
https://github.com`. That is by design, not a fault to diagnose: do not spend turns \
looking for credentials, and do not treat their absence as evidence that a repository does not \
exist.\n\
\n\
{floor}\n\
\n\
REFUSED CALLS. A call whose arguments do not match the tool's schema, or that names a path \
outside `{root}`, is refused WITHOUT running and handed back to you as a `[tool_result]` \
line that names the field and what was expected. That is a correction, not a verdict: fix \
the call and send it again. Sending the SAME refused call a second time, unchanged, ends \
the run.\n\
\n\
When the task is done, reply with a plain-text summary of what you changed and no fenced \
block.",
        root = root.display(),
        null_sink = crate::workspace::NULL_SINK,
        relative_path_remedy = crate::workspace::RELATIVE_PATH_REMEDY,
        floor = crate::workspace::destructive_floor_disclosure(),
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
#[must_use]
pub fn verdict_of(out: &RunOutput) -> (bool, String) {
    if out.reason.is_success() && out.tool_calls == 0 {
        return (false, format!("{:?}", TerminalReason::NoAction));
    }
    (out.reason.is_success(), format!("{:?}", out.reason))
}

/// Print the outcome, the done-marker, and return the exit code.
///
/// Public because a contract-bound run reports through the same line: the
/// done-marker a runner reads must be the same shape whether the task came
/// from `--prompt` or from a work item.
#[must_use]
pub fn report_run(out: &RunOutput, root: &Path) -> i32 {
    match out.final_text.as_deref() {
        Some(text) => println!("{text}"),
        None => println!("(no final text — {})", out.reason),
    }
    let spend = crate::usage::TurnSpend::between(&crate::usage::zero_snapshot(), &out.cost);
    println!(
        "{}",
        crate::usage::turn_line(&spend, out.cost.total_cost_usd_micros)
    );
    let (completed, reason) = verdict_of(out);
    // Whatever the driver could say about the cause, said here and carried in
    // the marker. Pilot A2-204c4 ended `PermissionDenied` with `"error": null`
    // and the single stderr line `the permission cascade refused the tool
    // call`, which named neither the layer, nor the tool, nor the validation
    // error — three schema refusals of one `read` call were indistinguishable
    // from a policy refusal in every artefact the run left behind.
    let detail = out.terminal_detail.as_deref();
    if !completed {
        eprintln!("{}", outcome_line(out.reason, &reason, detail));
    }
    println!(
        "{DONE_MARKER} {}",
        done_marker_body(&DoneMarker {
            completed,
            reason: &reason,
            turns: out.turns,
            tool_calls: out.tool_calls,
            tool_calls_attempted: out.tool_calls_attempted,
            tool_calls_denied: out.tool_calls_denied,
            cost_usd_micros: out.cost.total_cost_usd_micros,
            compactions: out.compactions,
            root,
            error: detail,
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
            tool_calls_attempted: 0,
            tool_calls_denied: 0,
            cost_usd_micros: 0,
            compactions: 0,
            root,
            error: Some(error),
        })
    );
    1
}

/// The one stderr line a run that did not complete leaves behind.
///
/// Pure so the shape can be pinned without capturing stdio. Pilot A2-204c4
/// printed `arcana run: the permission cascade refused the tool call
/// (PermissionDenied)` — true, and useless: the same sentence covers a
/// misspelt argument and an operator-written policy rule, and the run's
/// done-marker said `"error": null` beside it.
fn outcome_line(reason: TerminalReason, verdict: &str, detail: Option<&str>) -> String {
    match detail {
        Some(detail) => format!("arcana run: {reason} ({verdict}): {detail}"),
        None => format!("arcana run: {reason} ({verdict})"),
    }
}

/// The JSON body of the done-marker line.
struct DoneMarker<'a> {
    completed: bool,
    reason: &'a str,
    turns: u32,
    tool_calls: u32,
    tool_calls_attempted: u32,
    tool_calls_denied: u32,
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
        tool_calls_attempted,
        tool_calls_denied,
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
        // `tool_calls` counts executions and always has. On its own it cannot
        // tell a model that hardly used its tools from one that used them
        // constantly and got the arguments wrong — pilot A2-240b reported 72
        // for 98 attempts, 21 of them refused, and an automatic post-mortem
        // read the 72 as the whole story (A2-249).
        "tool_calls_attempted": tool_calls_attempted,
        "tool_calls_denied": tool_calls_denied,
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
        let tools = workspace_tools(root, Path::new("/tmp/arcana-test-home"));
        let prompt = system_prompt(&tools, root);
        assert!(prompt.contains("```tool_call"), "{prompt}");
        for name in ["read", "write", "edit", "grep", "bash"] {
            assert!(prompt.contains(&format!("`{name}`")), "missing {name}");
        }
        // The exact failure the defect produced, named in the prompt.
        assert!(prompt.contains("```bash block"), "{prompt}");
    }

    #[test]
    fn the_system_prompt_states_the_sink_exception_and_the_credential_free_lane() {
        // A2-253. Both lines exist because the pilot spent turns on what they
        // say: `2>/dev/null` was refused as a boundary escape, and the model
        // then spent many turns hunting for git credentials that this lane
        // does not have and cannot have.
        let root = Path::new("/tmp");
        let tools = workspace_tools(root, Path::new("/tmp/arcana-test-home"));
        let prompt = system_prompt(&tools, root);
        assert!(
            prompt.contains(crate::workspace::NULL_SINK),
            "the one permitted path outside the workspace is named: {prompt}"
        );
        assert!(
            prompt.contains("every other path outside"),
            "and it is stated as the single exception: {prompt}"
        );
        assert!(prompt.contains("NO CREDENTIALS ON THIS LANE"), "{prompt}");
        assert!(
            prompt.contains("could not read Username"),
            "the model is told the exact error it will get, so it stops \
             diagnosing it: {prompt}"
        );
    }

    #[test]
    fn the_sandbox_home_is_per_run_absolute_and_empty() {
        let state = tempfile::TempDir::new().unwrap();
        let first = sandbox_home(state.path()).expect("a sandbox home");
        let second = sandbox_home(state.path()).expect("a second sandbox home");
        assert!(first.is_absolute(), "{first:?}");
        assert!(
            first.is_dir(),
            "the directory exists before any command runs"
        );
        assert_eq!(
            std::fs::read_dir(&first).unwrap().count(),
            0,
            "and it starts empty"
        );
        assert_ne!(first, second, "two runs on one host must not share a HOME");
        assert!(
            first.starts_with(state.path().canonicalize().unwrap()),
            "it lives in the run's own state directory, not in /tmp: {first:?}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&first).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "owner-only: {mode:o}");
        }
    }

    #[test]
    fn an_empty_sandbox_home_is_released_and_a_used_one_is_kept() {
        let state = tempfile::TempDir::new().unwrap();
        let empty = sandbox_home(state.path()).expect("a sandbox home");
        release_sandbox_home(&empty);
        assert!(!empty.exists(), "an empty HOME is given back: {empty:?}");

        let used = sandbox_home(state.path()).expect("a sandbox home");
        std::fs::write(used.join(".gitconfig"), "[user]\n").unwrap();
        release_sandbox_home(&used);
        assert!(
            used.join(".gitconfig").exists(),
            "what the run wrote to `~` survives the cleanup: {used:?}"
        );
    }

    #[test]
    fn a_run_that_was_refused_says_what_refused_it_in_both_places() {
        // A2-225. The detail travels to the two artefacts anything downstream
        // reads: the stderr line an operator sees, and the `error` field a
        // wrapper script parses. The pilot had neither.
        let detail = "schema layer refused `read`: at `/path`: \"\" is shorter than 1 character";
        let line = outcome_line(
            TerminalReason::PermissionDenied,
            "PermissionDenied",
            Some(detail),
        );
        assert!(line.contains("schema layer refused `read`"), "{line}");
        assert!(line.contains("/path"), "{line}");

        let body = done_marker_body(&DoneMarker {
            completed: false,
            reason: "PermissionDenied",
            turns: 31,
            tool_calls: 20,
            tool_calls_attempted: 23,
            tool_calls_denied: 3,
            cost_usd_micros: 73_150,
            compactions: 2,
            root: Path::new("/tmp"),
            error: Some(detail),
        });
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["error"], detail, "the marker must not report null");

        // And a run that ended without a detail still prints one clean line.
        let bare = outcome_line(TerminalReason::MaxTurns, "MaxTurns", None);
        assert!(!bare.ends_with(": "), "{bare}");
    }

    #[test]
    fn the_done_marker_is_one_json_object_after_a_fixed_prefix() {
        let body = done_marker_body(&DoneMarker {
            completed: true,
            reason: "Completed",
            turns: 2,
            tool_calls: 1,
            tool_calls_attempted: 4,
            tool_calls_denied: 2,
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
        // A2-249: what the model TRIED, beside what worked. A marker carrying
        // `tool_calls` alone cannot tell a model that hardly called tools from
        // one that called them four times and landed one.
        assert_eq!(parsed["tool_calls_attempted"], 4);
        assert_eq!(parsed["tool_calls_denied"], 2);
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
            tool_calls_attempted: 0,
            tool_calls_denied: 0,
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
            tool_calls_attempted: tool_calls,
            tool_calls_denied: 0,
            cost: arcana_core::cost::CostTracker::new().snapshot(),
            selected_models: Vec::new(),
            first_dispatch_observation: None,
            compactions: 0,
            terminal_detail: None,
        }
    }

    #[test]
    fn a_completed_run_that_executed_nothing_is_not_reported_as_completed() {
        // The live failure verbatim: one turn, zero tool calls, a confident
        // sentence. Even if the layer below said `Completed`, the marker does
        // not.
        let (completed, reason) = verdict_of(&outcome(TerminalReason::Completed, 0));
        assert!(!completed);
        assert_eq!(reason, "NoAction");
    }

    #[test]
    fn a_completed_run_with_an_executed_tool_call_is_reported_as_completed() {
        // The green half: the same check must be able to say yes, or it is
        // just a constant.
        let (completed, reason) = verdict_of(&outcome(TerminalReason::Completed, 1));
        assert!(completed);
        assert_eq!(reason, "Completed");
    }

    #[test]
    fn a_failure_keeps_its_own_reason_rather_than_becoming_no_action() {
        let (completed, reason) = verdict_of(&outcome(TerminalReason::PermissionDenied, 0));
        assert!(!completed);
        assert_eq!(reason, "PermissionDenied");
    }
}
