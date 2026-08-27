use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const LICENSE: &str = env!("CARGO_PKG_LICENSE");
const GIT_SHA: &str = env!("ARCANA_GIT_SHA");

#[derive(Parser)]
#[command(
    name = "arcana",
    version,
    about = "Arcanada Agent System CLI",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print version, git SHA, and license metadata.
    Version,
    /// Authenticate against the Auth Arcana identity provider (stub).
    Login,
    /// Send a one-shot `ping` through the Model Connector and print the
    /// response. Reads the API key from `ARCANA_MC_TOKEN`. Hidden debug surface;
    /// the agent loop wires the connector properly in a later release.
    #[command(hide = true)]
    McPing,
    /// Bootstrap smoke check: assemble the default permission cascade,
    /// walk it once, and report where the audit log landed.
    Whoami,
    /// Phase-C vertical prototype: assemble the full driver + multi-model
    /// dispatch + tool dispatch + permission cascade + audit loop, run a small
    /// task, and print the three phases (attempt / check / conclusion). Offline
    /// and deterministic by default; `--live` routes through the real Model
    /// Connector when `ARCANA_MC_TOKEN` is set, else falls back to offline.
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
    /// Run one fail-closed agent loop grounded by the authenticated wiki KB.
    KbRead {
        /// Literal search query. Multiple shell words are canonicalized into one query.
        #[arg(required = true, num_args = 1..)]
        query: Vec<String>,
    },
    /// Expose the capability core as an MCP server (Tier-1 loopback).
    Mcp {
        #[command(subcommand)]
        command: McpCmd,
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
        }
        Some(Cmd::Login) => {
            println!(
                "arcana login: Auth Arcana OIDC device-code flow is not yet implemented in this build."
            );
            println!(
                "Track the upstream OIDC RP rollout at https://github.com/Arcanada-one/arcana-agent-system"
            );
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
        Some(Cmd::KbRead { query }) => {
            std::process::exit(arcana_cli::kb_read::run_kb_read(query.join(" ")));
        }
        Some(Cmd::Mcp {
            command: McpCmd::Serve { bind },
        }) => {
            std::process::exit(arcana_mcp::run_mcp_serve(bind.as_deref()));
        }
        None => {
            println!("arcana {VERSION} (REPL stub — interactive mode coming soon)");
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

/// Assemble the default permission cascade (ARAS-0024 bootstrap), walk it
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
