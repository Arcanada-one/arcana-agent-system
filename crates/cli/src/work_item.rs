//! `arcana run --work-item <id>` — one Muneral work item, executed under the
//! KC2 contract it is bound to, and a receipt that says so.
//!
//! The order of the first four steps is the whole design, and it is an order of
//! REFUSALS:
//!
//! 1. Read the work item from Muneral.
//! 2. No `contractDigest` → stop. `CONTRACT_MISSING`, before the Model
//!    Connector client is built and therefore before a single token is paid
//!    for. An unbound run that has already spent money is a cost no contract
//!    can justify afterwards, which is why this check cannot live inside the
//!    driver.
//! 3. Fetch the contract under that digest and RE-HASH it. A source that
//!    answers with some other contract, or with bytes that were edited after
//!    they were stamped, gets `CONTRACT_DIGEST_MISMATCH` — also before the
//!    first model call.
//! 4. Only then run, with the contract's allowlist in the permission cascade,
//!    and write `receipts/ReadinessReceipt-<id>.json`.
//!
//! What this command never does is write to Muneral. The work item's status is
//! the control plane's to move, and an executor that closed its own work item
//! would be the only witness to its own success.

use std::path::{Path, PathBuf};

use arcana_connectors::contract_source::{
    ArganaContractClient, ContractSource, FileContractSource,
};
use arcana_connectors::muneral::{MuneralClient, WorkItem};
use arcana_core::contract::{verify, ContractBinding, ContractRefusal};

use crate::receipt;
use crate::run::{RunRequest, DONE_MARKER};

/// Everything `--work-item` adds to a headless run.
pub struct WorkItemRequest {
    /// The Muneral work item id.
    pub id: String,
    /// Read the contract from this file instead of from Argana. The receipt
    /// records which was used, and only Argana counts as verified live.
    pub contract_file: Option<PathBuf>,
    /// The run itself. `prompt` is overwritten from the work item and the
    /// contract; `contract` is filled in once the binding is verified.
    pub run: RunRequest,
}

/// Entry point. Returns a process exit code.
#[must_use]
pub fn run(request: WorkItemRequest) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            return refuse(
                "RUNTIME_UNAVAILABLE",
                &format!("failed to start async runtime: {err}"),
            )
        }
    };
    runtime.block_on(run_async(request))
}

async fn run_async(mut request: WorkItemRequest) -> i32 {
    let client = match MuneralClient::try_from_env() {
        Ok(client) => client,
        Err(err) => return refuse("MUNERAL_UNAVAILABLE", &err.to_string()),
    };
    let item = match client.work_item(&request.id).await {
        Ok(item) => item,
        Err(err) => return refuse("WORK_ITEM_UNREADABLE", &err.to_string()),
    };
    println!("work item {}: {}", item.id, item.title);

    // Step 2. The refusal that has to happen here and nowhere later.
    let Some(digest) = item.contract_digest.clone() else {
        return refuse(
            ContractRefusal::Missing.code(),
            &ContractRefusal::Missing.to_string(),
        );
    };

    let source: Box<dyn ContractSource> = match resolve_source(request.contract_file.as_deref()) {
        Ok(source) => source,
        Err(refusal) => return refuse(refusal.code(), &refusal.to_string()),
    };
    println!(
        "contract {digest} from {} ({})",
        source.origin(),
        source.label()
    );

    // Step 3.
    let binding = match fetch_and_verify(source.as_ref(), &digest).await {
        Ok(binding) => binding,
        Err(refusal) => return refuse(refusal.code(), &refusal.to_string()),
    };
    println!(
        "contract verified: {} re-hashed over its {}; tools {:?} (from {})",
        binding.digest(),
        binding.preimage().as_str(),
        binding.allowlist(),
        binding.allowlist_source().as_str(),
    );

    // Step 4.
    request.run.prompt = task_prompt(&item, &binding);
    request.run.contract = Some(binding.clone());

    let summary = match crate::run::execute(&request.run).await {
        Ok(summary) => summary,
        Err(err) => return refuse("RUN_NOT_STARTED", &err),
    };

    let root = request
        .run
        .cwd
        .canonicalize()
        .unwrap_or_else(|_| request.run.cwd.clone());
    let built = receipt::build(
        &item.id,
        &binding,
        source.as_ref(),
        &root,
        &summary,
        // Resolved again rather than carried from the run: the rule is a pure
        // function of the flag, the environment and two files, so asking it
        // twice in one process cannot disagree with itself — and threading a
        // value through `execute` for the receipt alone would put the model
        // choice into the run's signature, which is where it does not belong.
        &crate::models::resolve(request.run.model.as_deref()),
        produced_by(),
        measured_at(),
    );
    let receipt_path = match receipt::write(&root, &built) {
        Ok(path) => path,
        Err(err) => {
            // A run whose receipt could not be written is a run with no
            // evidence, and the plan's acceptance is the receipt. Report it as
            // a failure even when the work itself completed.
            eprintln!("arcana run: {err}");
            return refuse("RECEIPT_UNWRITABLE", &err);
        }
    };
    println!("receipt: {}", receipt_path.display());
    crate::run::report_run(&summary, &root)
}

/// The prompt a contract-bound run is given.
///
/// The contract's projection goes in verbatim and FIRST, because it is the
/// authority on what the work is; the work item's own text follows as the
/// instance. The allowlist is stated in words as well as enforced in the
/// cascade — pilot A2-231 spent 78 turns on a restriction nobody had told the
/// model about, and an enforced-but-undisclosed allowlist is that failure with
/// a different noun.
fn task_prompt(item: &WorkItem, binding: &ContractBinding) -> String {
    let admitted = binding
        .allowlist()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "You are executing Muneral work item {id} under the KC2 contract {digest}.\n\
\n\
THE CONTRACT (authoritative — it defines the work and its limits):\n\
{projection}\n\
\n\
THE WORK ITEM:\n\
{title}\n\
{description}\n\
\n\
CONTRACT TOOL ALLOWLIST. This contract admits exactly these tools: {admitted}. A call to any \
other tool is refused by the permission cascade and recorded; it is not a call to re-send in \
another shape, and it cannot be argued into the contract.\n\
\n\
HOW THIS RUN IS JUDGED. Not by your closing message. The working directory is digested before \
your first turn and again after your last one, and the two digests are compared. If they are \
equal the run is recorded `NoEffect` and fails, however the work is described. If your closing \
message names a file that is not on disk, the run is recorded `ClaimedButAbsent` and fails — a \
path you name is a claim you are held to. Writing a probe or placeholder file to check that \
writing works does not count and does not help.\n\
\n\
So: produce the deliverable with a `write` call, in one piece, before you say anything about \
it. Write the whole file in a single call rather than describing its sections — a description \
of a file is not a file. Then, and only then, say in plain text which path you wrote.\n",
        id = item.id,
        digest = binding.digest(),
        projection = binding.projection(),
        title = item.title,
        description = item.description.as_deref().unwrap_or(""),
    )
}

/// Pick the contract source: the operator's file, or Argana.
fn resolve_source(file: Option<&Path>) -> Result<Box<dyn ContractSource>, ContractRefusal> {
    if let Some(path) = file {
        return Ok(Box::new(FileContractSource::new(path)));
    }
    match ArganaContractClient::try_from_env()? {
        Some(client) => Ok(Box::new(client)),
        // Fail closed and say what would fix it. Inventing a default Argana
        // url would point the run at a host that is not serving contracts and
        // report the result as a transport failure.
        None => Err(ContractRefusal::Unavailable {
            detail: format!(
                "no contract source is configured: set {} to Argana's root, or pass \
                 --contract-file with the contract document",
                arcana_connectors::contract_source::ENV_ARGANA_URL
            ),
        }),
    }
}

async fn fetch_and_verify(
    source: &dyn ContractSource,
    digest: &str,
) -> Result<ContractBinding, ContractRefusal> {
    let document = source.fetch(digest).await?;
    verify(digest, &document)
}

/// `arcana <version> (<git sha>)` — what produced the receipt.
fn produced_by() -> String {
    format!(
        "arcana {} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("ARCANA_GIT_SHA")
    )
}

/// RFC 3339, UTC. `None` from the clock is impossible on a working host, and
/// an empty string would be a receipt that claims no measurement time — so the
/// fallback says exactly that instead.
fn measured_at() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "not_measured".to_owned())
}

/// Print a typed refusal, its done-marker, and return exit code `1`.
///
/// The code is the first token on stderr and is repeated in the marker, so a
/// runner can branch on `CONTRACT_MISSING` without parsing a sentence.
fn refuse(code: &str, detail: &str) -> i32 {
    eprintln!("arcana run: {code}: {detail}");
    println!(
        "{DONE_MARKER} {}",
        serde_json::json!({
            "completed": false,
            "reason": code,
            "code": code,
            "error": detail,
        })
    );
    1
}
