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
        let client = match ModelConnectorClient::try_from_env() {
            Ok(client) => client,
            Err(err) => {
                eprintln!("arcana mc-ping: {err}");
                return 1;
            }
        };
        let request = ExecuteRequest::new("claude-code", "ping");
        match client.execute(request).await {
            Ok(response) => {
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

    let outcome = runtime.block_on(bootstrap.cascade.evaluate("whoami", serde_json::json!({})));

    match outcome {
        CascadeOutcome::Allowed { .. } => {
            println!("arcana whoami: {}", bootstrap::local_identity());
        }
        CascadeOutcome::Denied { layer, reason } => {
            println!(
                "arcana whoami: cascade denied at layer `{layer}` ({reason}) — local identity would be `{}`",
                bootstrap::local_identity()
            );
        }
    }
    println!("audit log: {}", bootstrap.audit_log_path.display());
    0
}
