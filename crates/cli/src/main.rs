use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "arcana", version, about = "Arcanada Agent System CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print version and exit.
    Version,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Cmd::Version) => {
            println!("arcana {VERSION}");
        }
        None => {
            println!("arcana {VERSION} (REPL stub — interactive mode coming soon)");
        }
    }
}
