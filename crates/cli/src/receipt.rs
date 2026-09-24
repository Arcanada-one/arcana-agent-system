//! `ReadinessReceipt/v1` for a contract-bound run.
//!
//! The receipt is what a contract-bound run is FOR. Not a log — a log says what
//! happened in the words of whatever was running; a receipt says what was
//! measured, with the identifiers a third party can re-check against the
//! systems that issued them. Three of its fields are joins, not decoration:
//! `task_id` joins it to Muneral, `contractDigest` joins it to the KC2 contract
//! (and MUST equal the digest Muneral holds — that is the acceptance), and
//! `worktree.sha` joins it to the tree the work was done in.
//!
//! Tri-valued throughout. `contract.verified_against_live_endpoint` is `false`
//! when the contract came out of a file rather than out of Argana, and a reader
//! who takes that for a pass is reading a fixture as a deployment.

use std::path::{Path, PathBuf};

use arcana_connectors::contract_source::ContractSource;
use arcana_core::agent_loop::RunOutput;
use arcana_core::contract::ContractBinding;

use crate::models::ResolvedModel;
use serde::Serialize;
use serde_json::Value;

/// Schema identifier, as the ecosystem's other receipts spell it.
pub const SCHEMA: &str = "ReadinessReceipt/v1";

/// Where a contract-bound run writes its receipt, relative to the worktree.
pub const RECEIPTS_DIR: &str = "receipts";

/// One refused tool call, as the receipt reports it.
///
/// The refused call's own `input` is deliberately NOT copied here: it is in the
/// `.arcana/denied/` file this entry names, it can be arbitrarily large, and a
/// receipt that grew with the model's mistakes would stop being readable.
#[derive(Debug, Clone, Serialize)]
pub struct Denial {
    pub turn: Option<u64>,
    pub tool: Option<String>,
    pub layer: Option<String>,
    pub reason: Option<String>,
    /// The file under `.arcana/denied/`, relative to the worktree.
    pub record: String,
}

/// Model Connector spend and traffic for the run.
///
/// `configured_model` and `model_source` are the intent; `selected_models` is
/// what was dispatched. Keeping both is the point: pilot A2-272's receipt
/// listed `grok-3-latest` followed by five `deepseek-v4-flash` and there was
/// nothing in it to say whether that was the lane's choice or the tier policy
/// filling a gap the isolated state directory had left.
#[derive(Debug, Clone, Serialize)]
pub struct McUsage {
    pub calls: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_usd_micros: u64,
    /// The model this run was configured to use, or `null` when the tiered
    /// dispatch policy chose per turn. `null` is an answer, not a gap — read
    /// it with `model_source`.
    pub configured_model: Option<String>,
    /// `flag`, `env`, `config`, `legacy-state` or `tier-policy`.
    pub model_source: String,
    pub selected_models: Vec<String>,
}

/// Tool-call counts. Three numbers, because one of them alone misleads:
/// `executed` is evidence, `attempted` is intent, and the gap is where the
/// model spent turns getting nothing done.
#[derive(Debug, Clone, Serialize)]
pub struct ToolCalls {
    pub executed: u32,
    pub attempted: u32,
    pub denied: u32,
}

/// What the run was bound to, and how well that binding was checked.
#[derive(Debug, Clone, Serialize)]
pub struct ContractSection {
    /// `argana` or `file`.
    pub source: String,
    /// The exact url or path the document came from.
    pub origin: String,
    /// Which bytes were re-hashed: `canonical_bytes` or `projection`.
    pub digest_preimage: String,
    /// `true` ONLY when the document came from the live Argana endpoint.
    pub verified_against_live_endpoint: bool,
    pub kc2_revision: Option<String>,
    pub kc2_snapshot: Option<String>,
    pub allowlist: Vec<String>,
    /// `contract` or `default-no-shell`.
    pub allowlist_source: String,
}

/// The tree the work happened in.
#[derive(Debug, Clone, Serialize)]
pub struct Worktree {
    pub path: String,
    /// `git rev-parse HEAD`, or `null` when the directory is not a git
    /// checkout — absent, not faked, and a reader must treat it as the third
    /// verdict rather than as "clean".
    pub sha: Option<String>,
}

/// How the run ended.
#[derive(Debug, Clone, Serialize)]
pub struct RunSection {
    pub completed: bool,
    pub reason: String,
    pub turns: u32,
    pub compactions: u32,
    pub detail: Option<String>,
}

/// `ReadinessReceipt/v1`.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessReceipt {
    pub schema: &'static str,
    pub measured_at: String,
    pub produced_by: String,
    pub task_id: String,
    /// Muneral's spelling, kept verbatim so the equality the acceptance checks
    /// (`jq .contractDigest` here == `jq .contractDigest` there) is a string
    /// comparison and not a mapping exercise.
    #[serde(rename = "contractDigest")]
    pub contract_digest: String,
    pub contract: ContractSection,
    pub worktree: Worktree,
    pub mc_usage: McUsage,
    pub tool_calls: ToolCalls,
    pub denials: Vec<Denial>,
    pub run: RunSection,
}

/// Build the receipt for a finished contract-bound run.
#[must_use]
// Eight joins, each naming a different system the receipt has to be checkable
// against — Muneral, the contract, its source, the tree, the run, the model
// decision, the producer, the clock. Folding them into a parameter struct
// would hide, not reduce, the number of authorities involved.
#[allow(clippy::too_many_arguments)]
pub fn build(
    task_id: &str,
    binding: &ContractBinding,
    source: &dyn ContractSource,
    root: &Path,
    out: &RunOutput,
    model: &ResolvedModel,
    produced_by: String,
    measured_at: String,
) -> ReadinessReceipt {
    let (completed, reason) = crate::run::verdict_of(out);
    ReadinessReceipt {
        schema: SCHEMA,
        measured_at,
        produced_by,
        task_id: task_id.to_owned(),
        contract_digest: binding.digest().to_owned(),
        contract: ContractSection {
            source: source.label().to_owned(),
            origin: source.origin(),
            digest_preimage: binding.preimage().as_str().to_owned(),
            verified_against_live_endpoint: source.label() == "argana",
            kc2_revision: binding.kc2_revision().map(ToOwned::to_owned),
            kc2_snapshot: binding.kc2_snapshot().map(ToOwned::to_owned),
            allowlist: binding.allowlist().iter().cloned().collect(),
            allowlist_source: binding.allowlist_source().as_str().to_owned(),
        },
        worktree: Worktree {
            path: root.display().to_string(),
            sha: head_sha(root),
        },
        mc_usage: McUsage {
            calls: out.cost.total_calls,
            tokens_in: out.cost.total_tokens_in,
            tokens_out: out.cost.total_tokens_out,
            cost_usd_micros: out.cost.total_cost_usd_micros,
            configured_model: model.model.clone(),
            model_source: model.source.as_str().to_owned(),
            selected_models: out.selected_models.clone(),
        },
        tool_calls: ToolCalls {
            executed: out.tool_calls,
            attempted: out.tool_calls_attempted,
            denied: out.tool_calls_denied,
        },
        denials: denials(root),
        run: RunSection {
            completed,
            reason,
            turns: out.turns,
            compactions: out.compactions,
            detail: out.terminal_detail.clone(),
        },
    }
}

/// The commit `root` is checked out at, read off the repository's own files.
///
/// Deliberately NOT `git rev-parse`: every raw process spawn in the shipped
/// runtime is inventoried by `crates/execution-boundary/tests/spawn_gate.rs`,
/// and that inventory may only shrink. A receipt field is not a reason to grow
/// it — and the answer is three file reads away.
///
/// `None` rather than a placeholder string: a receipt that said `"unknown"`
/// would be a receipt that answers the question, and the honest answer when
/// the directory is not a checkout is that nothing was measured.
fn head_sha(root: &Path) -> Option<String> {
    let gitdir = resolve_gitdir(root)?;
    let head = std::fs::read_to_string(gitdir.join("HEAD")).ok()?;
    let head = head.trim();
    // Detached HEAD: the file IS the answer.
    if is_sha(head) {
        return Some(head.to_owned());
    }
    let reference = head.strip_prefix("ref:")?.trim();
    // A linked worktree keeps its own HEAD and shares everything else, so a
    // loose ref may live in either directory.
    let commondir = common_gitdir(&gitdir);
    for dir in [&gitdir, &commondir] {
        if let Ok(loose) = std::fs::read_to_string(dir.join(reference)) {
            let loose = loose.trim();
            if is_sha(loose) {
                return Some(loose.to_owned());
            }
        }
    }
    packed_ref(&commondir, reference)
}

/// The `.git` directory for `root`: the directory itself, or the one a
/// worktree's `.git` FILE points at.
fn resolve_gitdir(root: &Path) -> Option<PathBuf> {
    let dot_git = root.join(".git");
    let meta = std::fs::metadata(&dot_git).ok()?;
    if meta.is_dir() {
        return Some(dot_git);
    }
    let pointer = std::fs::read_to_string(&dot_git).ok()?;
    let target = pointer.trim().strip_prefix("gitdir:")?.trim();
    let target = PathBuf::from(target);
    Some(if target.is_absolute() {
        target
    } else {
        root.join(target)
    })
}

/// The shared `.git` directory, for a linked worktree; `gitdir` itself
/// otherwise.
fn common_gitdir(gitdir: &Path) -> PathBuf {
    let Ok(raw) = std::fs::read_to_string(gitdir.join("commondir")) else {
        return gitdir.to_path_buf();
    };
    let target = PathBuf::from(raw.trim());
    if target.is_absolute() {
        target
    } else {
        gitdir.join(target)
    }
}

/// Look `reference` up in `packed-refs`.
fn packed_ref(commondir: &Path, reference: &str) -> Option<String> {
    let packed = std::fs::read_to_string(commondir.join("packed-refs")).ok()?;
    packed.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('^') {
            return None;
        }
        let (sha, name) = line.split_once(' ')?;
        (name == reference && is_sha(sha)).then(|| sha.to_owned())
    })
}

/// A 40-character lowercase hex object name.
fn is_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Every refused call the run left under `.arcana/denied/`.
///
/// Read off the disk rather than carried out of the driver, because the files
/// are what an operator will actually look at: if a denial is in the receipt
/// and not on disk, or the other way round, the receipt is wrong and this is
/// the arrangement in which that shows up.
fn denials(root: &Path) -> Vec<Denial> {
    let dir = root.join(crate::run::DENIED_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    names.sort();
    names
        .iter()
        .map(|path| {
            let record = std::fs::read_to_string(path)
                .ok()
                .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
            let field = |key: &str| {
                record
                    .as_ref()
                    .and_then(|value| value.get(key))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            };
            Denial {
                turn: record
                    .as_ref()
                    .and_then(|value| value.get("turn"))
                    .and_then(Value::as_u64),
                tool: field("tool"),
                layer: field("layer"),
                reason: field("reason"),
                record: path
                    .strip_prefix(root)
                    .unwrap_or(path)
                    .display()
                    .to_string(),
            }
        })
        .collect()
}

/// Write `receipt` to `<root>/receipts/ReadinessReceipt-<task_id>.json`.
///
/// # Errors
/// The message to print, when the file cannot be written.
pub fn write(root: &Path, receipt: &ReadinessReceipt) -> Result<std::path::PathBuf, String> {
    let dir = root.join(RECEIPTS_DIR);
    std::fs::create_dir_all(&dir).map_err(|err| {
        format!(
            "receipts directory {} could not be created: {err}",
            dir.display()
        )
    })?;
    let path = dir.join(format!("ReadinessReceipt-{}.json", receipt.task_id));
    let text = serde_json::to_string_pretty(receipt)
        .map_err(|err| format!("the receipt could not be serialized: {err}"))?;
    std::fs::write(&path, text + "\n").map_err(|err| {
        format!(
            "the receipt could not be written to {}: {err}",
            path.display()
        )
    })?;
    Ok(path)
}
