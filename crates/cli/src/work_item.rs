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
//! 5. Attach THAT receipt to the work item — sha256 of its bytes on disk,
//!    `application/json`, a locator — and say whether it landed, on stdout or
//!    loudly on stderr, in the done-marker's `evidence` and in
//!    `receipts/ReadinessReceipt-<id>.evidence.json`. See [`crate::evidence`].
//!
//! What this command never does is move the work item's status. Attaching
//! evidence is a claim about bytes, not a transition: the status is the
//! control plane's to move, and an executor that closed its own work item
//! would be the only witness to its own success.

use std::path::{Path, PathBuf};

use arcana_connectors::contract_source::{
    ArganaContractClient, ContractSource, FileContractSource,
};
use arcana_connectors::muneral::{MuneralClient, WorkItem};
use arcana_core::contract::{verify, ContractBinding, ContractRefusal};

use crate::ground_truth::{self, GroundTruth};
use crate::learning_trace;
use crate::receipt;
use crate::run::{RunRequest, DONE_MARKER};

/// Everything `--work-item` adds to a headless run.
pub struct WorkItemRequest {
    /// The Muneral work item id.
    pub id: String,
    /// Read the contract from this file instead of from Argana. The receipt
    /// records which was used, and only Argana counts as verified live.
    pub contract_file: Option<PathBuf>,
    /// Files quoted into the brief as ground truth about this repository, in
    /// the order the dispatcher named them. See [`crate::ground_truth`].
    pub ground_truth: Vec<PathBuf>,
    /// Locator to attach the receipt under; `None` is `file://<receipt>`.
    pub evidence_uri: Option<String>,
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

    // Step 3.
    let (source, binding) = match bind_contract(request.contract_file.as_deref(), &digest).await {
        Ok(bound) => bound,
        Err(code) => return code,
    };

    // Before step 4, and therefore before the first billable call.
    let grounding = match grounding_or_refuse(&request.ground_truth) {
        Ok(grounding) => grounding,
        Err(code) => return code,
    };

    // Step 4.
    request.run.prompt = task_prompt(&item, &binding, &grounding);
    request.run.contract = Some(binding.clone());

    // Taken BEFORE the run, because it is the only thing that can say which
    // records in a shared append-only log belong to it. Measured, never
    // assumed: `None` here becomes `slice_unbounded` in the trace rather than
    // a zero that would read as "this run wrote everything in the log".
    let audit_path = crate::run::audit_dir().join(learning_trace::AUDIT_FILE);
    let audit_offset = learning_trace::audit_offset(&audit_path);

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
        &grounding,
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

    // The trace is written AFTER the receipt and links to it by digest, so a
    // trace can never claim a receipt that does not exist. A failure to write
    // it is reported and does not change the run's verdict: the receipt is the
    // acceptance, and losing the candidate loses an input to learning, not the
    // evidence that the work happened.
    let trace = learning_trace::build(
        &learning_trace::Sources {
            task_id: &item.id,
            binding: &binding,
            contract_source: source.label(),
            contract_origin: source.origin(),
            verified_live: source.label() == "argana",
            worktree_sha: built.worktree.sha.clone(),
            receipt_path: &receipt_path,
            audit_path,
            audit_offset,
            produced_by: produced_by(),
            recorded_at: built.measured_at.clone(),
        },
        &summary,
        &root,
    );
    match learning_trace::write(&root, &trace) {
        Ok(path) => println!(
            "learning trace: {} ({}, capabilities {:?})",
            path.display(),
            if trace.outcome.negative {
                "negative"
            } else {
                "positive"
            },
            trace.capability_set,
        ),
        Err(err) => eprintln!("arcana run: the learning trace was not written: {err}"),
    }

    conclude_with_evidence(
        &client,
        &item.id,
        &receipt_path,
        request.evidence_uri.as_deref(),
        &summary,
        &root,
    )
    .await
}

/// Step 5, and the end of the run: attach the receipt just written, say
/// whether it landed, print the done-marker carrying that, and return the exit
/// code with the attach folded in.
///
/// After the receipt and the trace, before the marker, so the marker — the
/// last line, the one a runner reads — can say whether the evidence landed.
/// Attempted for a failed run too: a receipt of a failure is evidence of the
/// failure, and the control plane is the one that decides what it means.
///
/// Public so that it can be driven with a real run summary against a mock
/// Muneral: the run above it needs the live Model Connector, whose origin is
/// pinned, so no offline test reaches this point through [`run`].
pub async fn conclude_with_evidence(
    client: &MuneralClient,
    task_id: &str,
    receipt_path: &Path,
    evidence_uri: Option<&str>,
    summary: &crate::run::RunSummary,
    root: &Path,
) -> i32 {
    let evidence =
        crate::evidence::attach(client, task_id, receipt_path, evidence_uri, measured_at()).await;
    crate::evidence::report(&evidence, "arcana run");
    let sidecar = crate::evidence::sidecar_path(receipt_path);
    match crate::evidence::write(&sidecar, &evidence) {
        Ok(()) => println!("evidence outcome: {}", sidecar.display()),
        Err(err) => eprintln!("arcana run: {err}"),
    }
    let marker_evidence = serde_json::to_value(&evidence).ok();
    let code = crate::run::report_run_with_evidence(summary, root, marker_evidence.as_ref());
    exit_code_with_evidence(code, evidence.attached)
}

/// Fold the attach outcome into the run's exit code.
///
/// A run that succeeded and whose receipt is not on its work item exits
/// [`crate::evidence::EXIT_NOT_ATTACHED`], never `0`: that `0` is exactly what
/// let A2-297c's second receipt go missing without anyone noticing. A run that
/// already failed keeps its own code — the marker's `evidence` still says the
/// attach failed.
#[must_use]
pub fn exit_code_with_evidence(run_code: i32, attached: bool) -> i32 {
    if run_code == 0 && !attached {
        crate::evidence::EXIT_NOT_ATTACHED
    } else {
        run_code
    }
}

/// Steps 2b and 3: pick the contract source, fetch the document under `digest`,
/// and re-hash it.
///
/// Returns the process exit code of the refusal, because every failure here is a
/// refusal before the first model call and they all print the same way.
async fn bind_contract(
    contract_file: Option<&Path>,
    digest: &str,
) -> Result<(Box<dyn ContractSource>, ContractBinding), i32> {
    let source: Box<dyn ContractSource> = resolve_source(contract_file)
        .map_err(|refusal| refuse(refusal.code(), &refusal.to_string()))?;
    println!(
        "contract {digest} from {} ({})",
        source.origin(),
        source.label()
    );
    let binding = fetch_and_verify(source.as_ref(), digest)
        .await
        .map_err(|refusal| refuse(refusal.code(), &refusal.to_string()))?;
    println!(
        "contract verified: {} re-hashed over its {}; tools {:?} (from {})",
        binding.digest(),
        binding.preimage().as_str(),
        binding.allowlist(),
        binding.allowlist_source().as_str(),
    );
    Ok((source, binding))
}

/// Read the declared grounding, and say on stdout what was quoted.
///
/// Grounding that cannot be read must not become a run that silently had none,
/// so the refusal is returned as the process exit code — before the contract is
/// used and before the first billable call.
fn grounding_or_refuse(paths: &[PathBuf]) -> Result<Vec<GroundTruth>, i32> {
    let grounding = ground_truth::load(paths)
        .map_err(|refusal| refuse(refusal.code(), &refusal.to_string()))?;
    for item in &grounding {
        println!(
            "ground truth: {} ({}, {} bytes)",
            item.path, item.sha256, item.bytes
        );
    }
    Ok(grounding)
}

/// The prompt a contract-bound run is given.
///
/// The contract's projection goes in verbatim and FIRST, because it is the
/// authority on what the work is; the work item's own text follows as the
/// instance. The allowlist is stated in words as well as enforced in the
/// cascade — pilot A2-231 spent 78 turns on a restriction nobody had told the
/// model about, and an enforced-but-undisclosed allowlist is that failure with
/// a different noun.
fn task_prompt(item: &WorkItem, binding: &ContractBinding, grounding: &[GroundTruth]) -> String {
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
{grounding}\n\
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
        grounding = ground_truth::render(grounding),
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

/// The stderr line a typed refusal prints: `arcana run: <CODE>: <detail>`.
///
/// The code is printed ONCE. `ContractRefusal`'s own `Display` already opens
/// with the code (`CONTRACT_MISSING: the work item carries no contractDigest,
/// …`), and every contract call site passes that string as the detail, so
/// until this stripped it an operator read
/// `arcana run: CONTRACT_MISSING: CONTRACT_MISSING: …`. Measured while
/// building `crates/cli/tests/printed_output.rs`: writing down the one shape
/// this program prints is what made the doubled one visible.
///
/// Public because it is the ONE definition of that shape. A documentation page
/// that quotes a refusal is checked against this function
/// (`crates/cli/tests/printed_output.rs`), not against a second spelling of the
/// format in a test — A2-292's first live page printed
/// `Error: CONTRACT_MISSING: …`, which no build of this program has ever
/// produced, and every check in CI was green on it.
#[must_use]
pub fn refusal_line(code: &str, detail: &str) -> String {
    format!("arcana run: {code}: {}", undoubled(code, detail))
}

/// `detail` with a leading `<CODE>: ` removed, when it is the same code.
fn undoubled<'a>(code: &str, detail: &'a str) -> &'a str {
    detail
        .strip_prefix(code)
        .and_then(|rest| rest.strip_prefix(": "))
        .unwrap_or(detail)
}

/// The done-marker line a typed refusal prints, marker included.
///
/// `reason` and `code` carry the same code on purpose: a runner that branches
/// on either reads the same thing.
#[must_use]
pub fn refusal_marker(code: &str, detail: &str) -> String {
    format!(
        "{DONE_MARKER} {}",
        serde_json::json!({
            "completed": false,
            "reason": code,
            "code": code,
            "error": undoubled(code, detail),
        })
    )
}

/// Print a typed refusal, its done-marker, and return exit code `1`.
///
/// The code is the first token on stderr and is repeated in the marker, so a
/// runner can branch on `CONTRACT_MISSING` without parsing a sentence.
fn refuse(code: &str, detail: &str) -> i32 {
    eprintln!("{}", refusal_line(code, detail));
    println!("{}", refusal_marker(code, detail));
    1
}
