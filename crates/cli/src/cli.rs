//! The command-line surface itself: the clap definition `arcana` parses with.
//!
//! It lives in the library rather than in `main.rs` so that a test can parse a
//! command line with the REAL definition instead of a copy of it. A copy is
//! what let PR #214's how-to page describe a binary named `aras` taking
//! `--contract` and `--item` — three names this CLI has never had — and pass
//! every check we ran (A2-292). `tests/docs_truth.rs` now parses every
//! invocation printed in `docs/` through `Cli::try_parse_from`, which is only
//! a truthful check while the definition it uses is this one.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Shown under `--help`. These are required by most commands and appeared
/// nowhere in the help text: a first-run user met `ARCANA_MC_TOKEN` in an error
/// message or not at all.
pub const ENVIRONMENT_HELP: &str = "\
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
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Cmd>,
    /// Run the interactive session against the real Model Connector, which
    /// costs money. Requires `ARCANA_MC_TOKEN`. `demo` has its own `--live`.
    #[arg(long)]
    pub live: bool,
}

#[derive(Subcommand)]
pub enum Cmd {
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
        /// Quote this file into the work item's brief as ground truth about
        /// this repository. Repeatable; the order is the order given.
        ///
        /// For a task whose answer names commands, flags or environment
        /// variables. The A2-285 live run wrote the page it was asked for and
        /// got every command in it wrong, because the brief described the
        /// deliverable and never showed the command it was about. Pass
        /// `arcana run --help`, or the section of a how-to that already states
        /// the behaviour — a file from the repository, not an answer written
        /// for the model to copy: quoting our own prose back would measure the
        /// operator instead of the run.
        ///
        /// A file that cannot be read, or that is empty, refuses the run
        /// before the first model call. The receipt records each path with the
        /// sha256 of the bytes that reached the prompt.
        #[arg(long, value_name = "PATH", requires = "work_item")]
        ground_truth: Vec<PathBuf>,
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
        /// Declare that this task is not expected to change any file.
        ///
        /// Without it a run that ends with the working tree byte-for-byte as
        /// it found it is reported `NoEffect` and exits non-zero, however
        /// confidently the model's closing sentence describes the file it
        /// wrote. Pilot A2-278 saw that sentence twice, about a page that does
        /// not exist, from runs whose every tool call was a `read` or a
        /// `grep`.
        ///
        /// It is a DECLARATION, made before the run by whoever dispatched it,
        /// for a task whose output is the answer on stdout — an audit, a
        /// review, a question. Nothing the model does or says during the run
        /// can set it.
        #[arg(long)]
        read_only: bool,
    },
    /// Serve this agent's tools to an MCP client over local loopback.
    Mcp {
        #[command(subcommand)]
        command: McpCmd,
    },
}

#[derive(Subcommand)]
pub enum ModelsCmd {
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
pub enum McpCmd {
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
