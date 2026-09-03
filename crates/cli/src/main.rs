use clap::{Parser, Subcommand};

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
  ARCANA_MC_BASE_URL            Override the Model Connector endpoint.";

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
    /// Serve this agent's tools to an MCP client over local loopback.
    Mcp {
        #[command(subcommand)]
        command: McpCmd,
    },
}

#[derive(Subcommand)]
enum ModelsCmd {
    /// Persist the model this agent should use by default.
    Use {
        /// Model id, e.g. `deepseek-v4-flash`. Any id is accepted, including
        /// one the curated list does not show.
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Cmd::Version) => {
            println!("arcana {VERSION} ({GIT_SHA}) — {LICENSE}");
            if GIT_DIRTY {
                println!(
                    "WARNING: built from a working tree with uncommitted changes. \
                     This binary does not correspond to {GIT_SHA} or to any commit, \
                     and its provenance cannot be verified."
                );
            }
        }
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
        }) => {
            std::process::exit(arcana_cli::demo::run_demo(
                task,
                live,
                first_dispatch_measurement_json.as_deref(),
                first_dispatch_connector.as_deref(),
                first_dispatch_model.as_deref(),
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
