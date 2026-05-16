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
        None => {
            println!("arcana {VERSION} (REPL stub — interactive mode coming soon)");
        }
    }
}
