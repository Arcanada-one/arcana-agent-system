use clap::{Parser, Subcommand};
use std::io::Read;
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const LICENSE: &str = env!("CARGO_PKG_LICENSE");
const GIT_SHA: &str = env!("ARCANA_GIT_SHA");
/// Whether this binary was built from a tree with uncommitted changes.
///
/// A suffix on the sha is easy to skim past, and this is the one line a release
/// verification actually rests on, so the dirty case gets its own sentence.
const GIT_DIRTY: bool = matches!(env!("ARCANA_GIT_DIRTY").as_bytes(), b"true");

/// Shown under `--help`. These are required by most commands and appeared
/// nowhere in the help text: a first-run user met `ARCANA_MC_TOKEN` in an error
/// message or not at all.
const ENVIRONMENT_HELP: &str = "\
Environment:
  ARCANA_MC_TOKEN               Model Connector API key. Required by `models`,
                                `kb-read`, and by `--live`.
  ARCANA_STATS_TOKEN            Read token for spend reporting, used by `usage`.
                                Purpose-scoped: an ARCANA_MC_TOKEN is refused.
  ARCANA_KB_CLIENT_SECRET_FILE  Path to the knowledge-base client secret,
                                required by `kb-read`.
  ARCANA_MC_BASE_URL            Override the Model Connector endpoint.
  ARCANA_MODEL                  Model id for this process, overriding the saved
                                `models use` choice. `tier` asks for the tiered
                                dispatch policy on purpose. `--model` wins over
                                it.";

#[derive(Parser)]
#[command(
    name = "arcana",
    version,
    about = "Arcanada Agent System CLI",
    // `Usage: arcana [OPTIONS] [COMMAND]` says the command is optional and never
    // says what happens without one — which is the product's main mode. The only
    // mention used to be inside the `--live` flag text, referring to "the
    // no-subcommand REPL" as though the reader already knew what that was.
    long_about = "Arcanada Agent System CLI.\n\nRun with no command to start an interactive session.",
    after_help = ENVIRONMENT_HELP,
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
    /// Run the interactive session against the real Model Connector, which
    /// costs money. Requires `ARCANA_MC_TOKEN`. `demo` has its own `--live`.
    #[arg(long)]
    live: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the version, the exact commit it was built from, and the licence.
    Version,
    /// Sign in. Prints a short code to enter in your browser.
    ///
    /// Uses the OIDC device-authorization grant (RFC 8628); the resulting
    /// credentials are stored for your user only, mode 0600.
    Login,
    /// Send a one-shot `ping` through the Model Connector and print the
    /// response. Reads the API key from `ARCANA_MC_TOKEN`. Hidden debug surface;
    /// the agent loop wires the connector properly in a later release.
    #[command(hide = true)]
    McPing,
    /// Show who you are signed in as, and where the audit log is written.
    Whoami,
    /// Run a short built-in task end to end, and show what the agent did.
    ///
    /// Offline and repeatable by default. `--live` runs it through the real
    /// Model Connector when `ARCANA_MC_TOKEN` is set, and costs money.
    Demo {
        /// The small task to drive (defaults to a built-in code-signal task).
        task: Option<String>,
        /// Route through the real Model Connector when `ARCANA_MC_TOKEN` is set.
        #[arg(long)]
        live: bool,
        /// Closed identifier-only metadata for an explicitly opted-in paired
        /// first-dispatch measurement. The JSON must not contain prompt text,
        /// credentials, token counts, or authorization claims.
        #[arg(long, requires = "live")]
        first_dispatch_measurement_json: Option<String>,
        /// Registered Model Connector id used for the measured dispatch.
        #[arg(long, requires = "first_dispatch_measurement_json")]
        first_dispatch_connector: Option<String>,
        /// Provider model id pinned for the measured dispatch.
        #[arg(long, requires = "first_dispatch_measurement_json")]
        first_dispatch_model: Option<String>,
        /// Read the exact measured first-dispatch prompt from stdin. Prompt
        /// content is never accepted in argv or included in emitted evidence.
        #[arg(long, requires = "first_dispatch_measurement_json")]
        first_dispatch_prompt_stdin: bool,
    },
    /// List the models available through the Model Connector, or choose one.
    ///
    /// The list is read from the LIVE catalogue, never a hard-coded table, and
    /// shows the price per 1M tokens beside each model.
    Models {
        #[command(subcommand)]
        command: Option<ModelsCmd>,
    },
    /// Show what you have spent, as recorded by the Model Connector.
    Usage {
        /// First day of the report, YYYY-MM-DD at UTC. Defaults to 29 days before `--until`.
        #[arg(long)]
        since: Option<String>,
        /// Last day of the report, YYYY-MM-DD at UTC. Defaults to today.
        #[arg(long)]
        until: Option<String>,
    },
    /// Answer one question using only the knowledge base, citing its sources.
    ///
    /// Refuses to answer rather than guess: if the search finds nothing, it
    /// says so.
    KbRead {
        /// Literal search query. Multiple shell words are canonicalized into one query.
        #[arg(required = true, num_args = 1..)]
        query: Vec<String>,
    },
    /// Run ONE task to completion in a working directory, unattended.
    ///
    /// The agent really calls its tools (read / write / edit / grep / shell),
    /// confined to `--cwd` by policy instead of by an interactive prompt.
    /// Always live: it needs `ARCANA_MC_TOKEN` and it costs money. The last
    /// line of stdout is always `ARCANA_RUN_DONE <json>`.
    Run {
        /// Working directory. Every tool is rooted here and paths outside it
        /// are refused. Intended for a disposable checkout or git worktree.
        #[arg(long)]
        cwd: PathBuf,
        /// The task, given literally.
        #[arg(long, conflicts_with_all = ["prompt_stdin", "work_item"])]
        prompt: Option<String>,
        /// Execute the Muneral work item with this id, under the KC2 contract
        /// its `contractDigest` names.
        ///
        /// The task text comes from the work item and the contract, not from
        /// `--prompt`. A work item with no `contractDigest` is refused with
        /// `CONTRACT_MISSING` before the first model call, and a contract
        /// whose bytes do not hash to that digest with
        /// `CONTRACT_DIGEST_MISMATCH`. The run writes
        /// `receipts/ReadinessReceipt-<id>.json` and never changes the work
        /// item's status.
        ///
        /// Reads the agent key from the file named by
        /// `ARCANA_MUNERAL_KEY_FILE`.
        #[arg(long, value_name = "ID", conflicts_with = "prompt_stdin")]
        work_item: Option<String>,
        /// Read the contract document from this file instead of from Argana.
        ///
        /// For the window in which Argana's `GET /v1/contract/{digest}` is not
        /// deployed. The file is re-hashed exactly like the service's answer,
        /// so it cannot be used to run under a digest it does not hash to —
        /// and the receipt records `contract.source: "file"`, which is NOT the
        /// same verdict as a binding checked against the live endpoint.
        #[arg(long, value_name = "PATH", requires = "work_item")]
        contract_file: Option<PathBuf>,
        /// Read the task from stdin. Preferred for anything with quotes,
        /// newlines, or shell metacharacters in it.
        #[arg(long)]
        prompt_stdin: bool,
        /// Connector-attempt cap for the run.
        #[arg(long, default_value_t = 24)]
        max_turns: u32,
        /// Spend cap in USD for the run.
        #[arg(long)]
        max_cost_usd: Option<f64>,
        /// Pin a model id for this run.
        ///
        /// Highest authority in the order flag > `ARCANA_MODEL` > the saved
        /// `arcana models use` choice > tiered policy. The run prints which of
        /// them answered before it spends anything, and a contract-bound run
        /// records it in the receipt as `mc_usage.model_source`. The value
        /// `tier` selects the tiered dispatch policy on purpose.
        #[arg(long)]
        model: Option<String>,
        /// Seconds one model turn may take upstream (5..=600).
        ///
        /// Sent to the Model Connector as the dispatch's own budget, and used
        /// to size how long `arcana` waits: queue time and the server's
        /// second attempt are added on top, so the client never gives up on a
        /// turn the server is still working on. Default 120; the environment
        /// variable `ARCANA_MC_TIMEOUT_SECS` sets the same number. Note that
        /// `connector.arcanada.ai` is fronted by an edge proxy that cuts any
        /// single request at ~125 s (measured 2026-09-23), so values above 120
        /// only help against a deployment reached without it.
        #[arg(long, value_name = "SECONDS")]
        request_timeout: Option<u64>,
        /// Transcript ceiling in UTF-16 code units (1..=100000).
        ///
        /// When the serialized history passes it, the loop elides tool
        /// results and folds older turns into a summary, and says so.
        /// Default 90000 — ten percent under the 100000-unit limit Model
        /// Connector enforces on the request field. Lower it for a model
        /// whose own context window is smaller than that, or to exercise
        /// compaction deliberately.
        #[arg(long, value_name = "UNITS")]
        context_budget: Option<usize>,
        /// Ceiling on ONE tool result inside the transcript, in UTF-16 code
        /// units (240..=`--context-budget`).
        ///
        /// Output past it is elided head-and-tail, the whole of it is written
        /// to `.arcana/tool-output/`, and the marker left in its place names
        /// that file. Default 8000. Lower it to exercise the elision and
        /// spill path in a real run: no ordinary command produces 8000 units
        /// cheaply, so until this flag existed that path had only offline
        /// evidence.
        #[arg(long, value_name = "UNITS")]
        tool_result_budget: Option<usize>,
        /// Append the exact request of every dispatch to this file.
        ///
        /// Off unless asked for. The file is the conversation in clear text —
        /// the task, every reply, every tool result carried in the
        /// transcript — so point it somewhere you are willing to keep that,
        /// not into a checkout you are about to commit. Appended per
        /// dispatch, because a run that compacts does not carry its early
        /// turns into the last request.
        #[arg(long, value_name = "PATH")]
        save_transcript: Option<PathBuf>,
    },
    /// Serve this agent's tools to an MCP client over local loopback.
    Mcp {
        #[command(subcommand)]
        command: McpCmd,
    },
}

#[derive(Subcommand)]
enum ModelsCmd {
    /// Persist the model this agent should use by default.
    ///
    /// Written to the XDG config home, because a model choice is operator
    /// configuration: a runner that isolates `XDG_STATE_HOME` — which is what
    /// every unattended lane does — must still see it.
    Use {
        /// Model id, e.g. `deepseek-v4-flash`. Any id is accepted, including
        /// one the curated list does not show. `tier` stores "use the tiered
        /// dispatch policy" rather than a model.
        model: String,
    },
}

#[derive(Subcommand)]
enum McpCmd {
    /// Serve the capability core over MCP. Defaults to stdio; `--bind`
    /// starts a loopback-only HTTP listener (non-loopback addresses are
    /// rejected before any socket is created).
    Serve {
        /// Optional loopback bind address (e.g. `127.0.0.1:7300`). Omit for
        /// stdio transport.
        #[arg(long)]
        bind: Option<String>,
    },
}

/// The version line, and the warning that voids it.
///
/// Its own function only because `main`'s match has a line budget; the text is
/// unchanged.
fn print_version() {
    println!("arcana {VERSION} ({GIT_SHA}) — {LICENSE}");
    if GIT_DIRTY {
        println!(
            "WARNING: built from a working tree with uncommitted changes. \
             This binary does not correspond to {GIT_SHA} or to any commit, \
             and its provenance cannot be verified."
        );
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Cmd::Version) => print_version(),
        Some(Cmd::Login) => {
            std::process::exit(arcana_cli::login::run_login());
        }
        Some(Cmd::McPing) => {
            std::process::exit(run_mc_ping());
        }
        Some(Cmd::Whoami) => {
            std::process::exit(run_whoami());
        }
        Some(Cmd::Demo {
            task,
            live,
            first_dispatch_measurement_json,
            first_dispatch_connector,
            first_dispatch_model,
            first_dispatch_prompt_stdin,
        }) => {
            let first_dispatch_prompt = if first_dispatch_prompt_stdin {
                if let Ok(prompt) = read_first_dispatch_prompt_stdin() {
                    Some(prompt)
                } else {
                    eprintln!("arcana demo: invalid first-dispatch prompt on stdin");
                    std::process::exit(1);
                }
            } else {
                None
            };
            std::process::exit(arcana_cli::demo::run_demo(
                task,
                live,
                first_dispatch_measurement_json.as_deref(),
                first_dispatch_connector.as_deref(),
                first_dispatch_model.as_deref(),
                first_dispatch_prompt,
            ));
        }
        Some(Cmd::Models { command }) => match command {
            None => std::process::exit(arcana_cli::models::run_list()),
            Some(ModelsCmd::Use { model }) => {
                std::process::exit(arcana_cli::models::run_use(&model));
            }
        },
        Some(Cmd::Usage { since, until }) => {
            std::process::exit(arcana_cli::usage::run_usage(
                since.as_deref(),
                until.as_deref(),
            ));
        }
        Some(Cmd::KbRead { query }) => {
            std::process::exit(arcana_cli::kb_read::run_kb_read(query.join(" ")));
        }
        Some(Cmd::Run {
            cwd,
            prompt,
            work_item,
            contract_file,
            prompt_stdin,
            max_turns,
            max_cost_usd,
            model,
            request_timeout,
            context_budget,
            tool_result_budget,
            save_transcript,
        }) => {
            std::process::exit(run_headless(
                cwd,
                prompt,
                work_item,
                contract_file,
                prompt_stdin,
                max_turns,
                max_cost_usd,
                model,
                request_timeout,
                context_budget,
                tool_result_budget,
                save_transcript,
            ));
        }
        Some(Cmd::Mcp {
            command: McpCmd::Serve { bind },
        }) => {
            std::process::exit(arcana_mcp::run_mcp_serve(bind.as_deref()));
        }
        None => {
            std::process::exit(arcana_cli::repl::run_repl(cli.live));
        }
    }
}

/// Resolve the task text and hand the run to `arcana_cli::run`.
#[allow(clippy::too_many_arguments)]
fn run_headless(
    cwd: PathBuf,
    prompt: Option<String>,
    work_item: Option<String>,
    contract_file: Option<PathBuf>,
    prompt_stdin: bool,
    max_turns: u32,
    max_cost_usd: Option<f64>,
    model: Option<String>,
    request_timeout: Option<u64>,
    context_budget: Option<usize>,
    tool_result_budget: Option<usize>,
    save_transcript: Option<PathBuf>,
) -> i32 {
    // A contract-bound run takes its task from the work item and the contract,
    // so the prompt is resolved LAST and from neither flag. Building the
    // request first would mean a `--work-item` invocation had to carry a
    // placeholder prompt, and a placeholder is one refactor away from being
    // sent to a model.
    if let Some(id) = work_item {
        return arcana_cli::work_item::run(arcana_cli::work_item::WorkItemRequest {
            id,
            contract_file,
            run: arcana_cli::run::RunRequest {
                cwd,
                prompt: String::new(),
                max_turns,
                max_cost_usd,
                model,
                request_timeout: request_timeout.map(std::time::Duration::from_secs),
                context_budget,
                tool_result_budget,
                save_transcript,
                contract: None,
            },
        });
    }
    let prompt = match (prompt, prompt_stdin) {
        (Some(prompt), false) => prompt,
        (None, true) => match read_prompt_stdin() {
            Ok(prompt) => prompt,
            Err(err) => {
                eprintln!("arcana run: could not read the task from stdin: {err}");
                return 1;
            }
        },
        _ => {
            eprintln!(
                "arcana run: pass exactly one of --prompt, --prompt-stdin or --work-item <id>"
            );
            return 1;
        }
    };
    arcana_cli::run::run(&arcana_cli::run::RunRequest {
        cwd,
        prompt,
        max_turns,
        max_cost_usd,
        model,
        request_timeout: request_timeout.map(std::time::Duration::from_secs),
        context_budget,
        tool_result_budget,
        save_transcript,
        contract: None,
    })
}

/// Read a headless task from stdin.
///
/// Capped at the driver's prompt ceiling so a runaway pipe cannot be read
/// into memory unbounded before the driver rejects it anyway.
fn read_prompt_stdin() -> Result<String, String> {
    let limit = arcana_core::agent_loop::MAX_FIRST_DISPATCH_PROMPT_BYTES + 1;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(u64::try_from(limit).map_err(|err| err.to_string())?)
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;
    if bytes.len() >= limit {
        return Err(format!("the task exceeds {limit} bytes"));
    }
    let prompt = String::from_utf8(bytes).map_err(|_| "the task is not valid UTF-8".to_owned())?;
    if prompt.trim().is_empty() {
        return Err("stdin was empty".to_owned());
    }
    Ok(prompt)
}

fn read_first_dispatch_prompt_stdin() -> Result<String, ()> {
    let limit = arcana_core::agent_loop::MAX_FIRST_DISPATCH_PROMPT_BYTES + 1;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(u64::try_from(limit).map_err(|_| ())?)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty() || bytes.len() >= limit {
        return Err(());
    }
    String::from_utf8(bytes).map_err(|_| ())
}

/// Build a Model Connector client from the environment, send a one-shot `ping`,
/// and report the outcome. Returns a process exit code (0 = success).
fn run_mc_ping() -> i32 {
    use arcana_connectors::ModelConnectorClient;
    use arcana_core::connector::{ExecuteRequest, ModelConnector};

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("arcana mc-ping: failed to start async runtime: {err}");
            return 1;
        }
    };

    runtime.block_on(async {
        let client = match ModelConnectorClient::try_from_probe_env() {
            Ok(client) => client,
            Err(err) => {
                eprintln!("arcana mc-ping: {err}");
                return 1;
            }
        };
        let request = ExecuteRequest::new("claude-code", "ping");
        match client.execute(request).await {
            Ok(response) => {
                // A `201 {"status":"success","result":""}` is control-plane
                // green but data-plane dead — the model returned nothing. Treat
                // a degenerate/empty result as a capability-assertion failure
                // (exit 2), distinct from a transport/operational error (exit
                // 1). `status == "error"` never reaches here (it maps to
                // `ConnectorError::Logical` upstream), so an empty `result` is
                // the degenerate case to guard.
                if response.result.trim().is_empty() {
                    eprintln!(
                        "arcana mc-ping: degenerate success envelope — status={} model={} empty result (capability dead)",
                        response.status, response.model
                    );
                    return 2;
                }
                println!(
                    "mc-ping ok: status={} model={} result={:?} tokens={} cost_usd={}",
                    response.status,
                    response.model,
                    response.result,
                    response.usage.total_tokens,
                    response.usage.cost_usd
                );
                0
            }
            Err(err) => {
                eprintln!("arcana mc-ping: {err}");
                1
            }
        }
    })
}

/// Assemble the default permission cascade (bootstrap), walk it
/// once for the built-in `whoami` probe tool, and report the outcome plus
/// the audit log location. Returns a process exit code (0 = success).
fn run_whoami() -> i32 {
    use arcana_cli::bootstrap;
    use arcana_core::permission::CascadeOutcome;

    let bootstrap = match bootstrap::assemble() {
        Ok(bootstrap) => bootstrap,
        Err(err) => {
            eprintln!("arcana whoami: bootstrap failed: {err}");
            return 1;
        }
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("arcana whoami: failed to start async runtime: {err}");
            return 1;
        }
    };

    // Route through `Bootstrap::evaluate` (not the raw `cascade`): the
    // bootstrap-owned `AuditLog` (C4 / ARAS-0033) writes the correlated
    // `decision`/`result` records synchronously and returns `Err` if that
    // durable write fails — so a successful `Ok` guarantees the audit trail
    // we advertise below is on disk.
    let outcome = match runtime.block_on(bootstrap.evaluate("whoami", serde_json::json!({}))) {
        Ok(outcome) => outcome,
        Err(err) => {
            eprintln!("arcana whoami: audit failed: {err}");
            return 1;
        }
    };

    let denied = match &outcome {
        CascadeOutcome::Allowed { .. } => {
            println!("arcana whoami: {}", bootstrap::local_identity());
            false
        }
        CascadeOutcome::Denied { layer, reason } => {
            println!(
                "arcana whoami: cascade denied at layer `{layer}` ({reason}) — local identity would be `{}`",
                bootstrap::local_identity()
            );
            true
        }
    };

    // Stat the audit path we advertise — closes the creative's "prints an
    // `audit log:` it never stats" false-green hole (Supreme-Directive Law-5
    // audit trail). C4's `AuditLog` is a synchronous append+flush sink owned by
    // `Bootstrap`, so the record is already durable once `evaluate` returned
    // `Ok` — no writer-guard drop is needed to force a flush.
    let audit_log_path = &bootstrap.audit_log_path;
    println!("audit log: {}", audit_log_path.display());

    match std::fs::metadata(audit_log_path) {
        // Audit trail exists and is non-empty. A denied capability is a
        // capability-assertion failure (exit 2); an allow is success (0).
        Ok(meta) if meta.len() > 0 => {
            if denied {
                2
            } else {
                0
            }
        }
        // The audit path we advertised is missing or empty → operational
        // failure (exit 1), independent of the cascade verdict.
        _ => {
            eprintln!(
                "arcana whoami: audit log missing or empty at {}",
                audit_log_path.display()
            );
            1
        }
    }
}
