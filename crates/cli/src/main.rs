use arcana_cli::cli::{Cli, Cmd, McpCmd, ModelsCmd};
use clap::Parser;
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
            read_only,
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
                read_only,
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
    read_only: bool,
) -> i32 {
    let expect_effect = if read_only {
        arcana_cli::effect::EffectExpectation::ReadOnly
    } else {
        arcana_cli::effect::EffectExpectation::Artefact
    };
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
                expect_effect,
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
        expect_effect,
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
