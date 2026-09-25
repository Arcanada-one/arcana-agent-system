//! A contract-bound run attaches its OWN receipt to its Muneral work item.
//!
//! Why this exists. Until A2-336 `arcana run --work-item` wrote
//! `receipts/ReadinessReceipt-<id>.json` and stopped there; getting the receipt
//! onto the work item was a hand-made `POST /tasks/<id>/evidence` by whoever
//! dispatched the run. A2-297c's second run was never attached, the work item
//! was moved to `done` without it, and the index counted "2 of 3" for a day
//! (NR-0016, found by A2-332). The run is the only party that holds the exact
//! bytes at the moment it ends, so the run is what attaches them.
//!
//! What it attaches, and why these values:
//!
//! * `sha256` — of the receipt file AS READ BACK FROM DISK after it was
//!   written, not of the in-memory value that was serialized. The digest is the
//!   attachment's identity in Muneral (`UNIQUE (task_id, sha256)`), and the
//!   bytes a later reader can check are the bytes on disk.
//! * `contentType` — `application/json`.
//! * `uri` — by default `file://<absolute path of the receipt>`. It is the one
//!   locator that is TRUE at the moment of attaching: the receipt has not been
//!   published anywhere else yet, and a web url for a commit that does not
//!   exist would be an invented locator. It resolves only on the host that
//!   wrote it, which is stated rather than hidden — the digest, not the path,
//!   is what binds the claim. When the operator already knows where the bytes
//!   will be readable (a pinned blob url, an object store key), `--evidence-uri`
//!   names it instead. Muneral keeps the FIRST locator for a digest: the same
//!   bytes attached again under another uri are refused with `409
//!   EVIDENCE_DIGEST_CONFLICT`, so choose before the first attach.
//!
//! What it never does: move the work item's status. Attaching is a claim about
//! bytes, recorded under the agent that made it; judging that claim, and
//! transitioning the item on it, stay with the control plane.
//!
//! A failed attach is loud and non-zero (`EVIDENCE_NOT_ATTACHED`, exit `3` when
//! the run itself succeeded), the receipt file is KEPT, and the retry is
//! `arcana attach-receipt`, which sends the same `(sha256, uri, contentType)`
//! and is answered `200 idempotent: true` if the first attempt did land.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use arcana_connectors::muneral::{MuneralClient, WorkItemEvidenceAttachment};
use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

/// The media type of a `ReadinessReceipt/v1` file.
pub const CONTENT_TYPE: &str = "application/json";

/// Schema of the outcome record — the sidecar file and the marker's `evidence`.
pub const OUTCOME_SCHEMA: &str = "EvidenceAttachOutcome/v1";

/// The refusal code of an attach that did not land.
pub const NOT_ATTACHED: &str = "EVIDENCE_NOT_ATTACHED";

/// Exit code of a run that succeeded but whose receipt is not on its work
/// item, and of an `attach-receipt` that did not attach. Distinct from `1` so a
/// wrapper can tell "the work failed" from "the work is done and its evidence
/// is not where the control plane will look for it".
pub const EXIT_NOT_ATTACHED: i32 = 3;

/// What happened when the receipt was offered to Muneral.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub schema: &'static str,
    pub task_id: String,
    /// The receipt file, as the run wrote it.
    pub receipt: String,
    /// sha256 of the receipt's bytes on disk; `None` when they could not be
    /// read, in which case nothing was sent.
    pub sha256: Option<String>,
    pub uri: Option<String>,
    pub content_type: &'static str,
    pub attempted_at: String,
    /// `true` only when Muneral answered with a record naming this task and
    /// this digest.
    pub attached: bool,
    /// `false` on the `201` that created the record, `true` on the `200` that
    /// found it already there. `None` when nothing was attached.
    pub idempotent: Option<bool>,
    pub evidence_id: Option<String>,
    /// [`NOT_ATTACHED`] when `attached` is `false`.
    pub code: Option<&'static str>,
    /// Why not, in the server's words where there were any. Never the key:
    /// every `MuneralError` is built from the response.
    pub error: Option<String>,
    /// The server's `WorkItemEvidenceAttachment/v1`, verbatim.
    pub record: Option<WorkItemEvidenceAttachment>,
}

/// Lowercase hex sha256, as Muneral's `sha256` field requires (no prefix).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

/// `file://` url of `path`, made absolute first. Percent-encoded, so a path
/// with a space is still the absolute, whitespace-free locator Muneral accepts.
///
/// # Errors
/// When the path cannot be made absolute.
pub fn file_uri(path: &Path) -> Result<String, String> {
    let absolute = path
        .canonicalize()
        .map_err(|err| format!("{} cannot be resolved: {err}", path.display()))?;
    Url::from_file_path(&absolute)
        .map(String::from)
        .map_err(|()| format!("{} is not an absolute path", absolute.display()))
}

/// The sidecar that records the outcome next to the receipt:
/// `ReadinessReceipt-<id>.json` → `ReadinessReceipt-<id>.evidence.json`.
///
/// A sidecar and not a field of the receipt: the receipt's digest is what was
/// attached, so it cannot contain the answer to attaching it.
#[must_use]
pub fn sidecar_path(receipt: &Path) -> PathBuf {
    let stem = receipt
        .file_stem()
        .map_or_else(|| "receipt".into(), |s| s.to_string_lossy().into_owned());
    receipt.with_file_name(format!("{stem}.evidence.json"))
}

/// Read the receipt back, hash it, and attach it to `task_id`.
///
/// Never fails as a function: every way this can go wrong is an [`Outcome`]
/// with `attached: false`, so the caller cannot forget to report one.
pub async fn attach(
    client: &MuneralClient,
    task_id: &str,
    receipt: &Path,
    uri_override: Option<&str>,
    attempted_at: String,
) -> Outcome {
    let mut outcome = Outcome {
        schema: OUTCOME_SCHEMA,
        task_id: task_id.to_owned(),
        receipt: receipt.display().to_string(),
        sha256: None,
        uri: None,
        content_type: CONTENT_TYPE,
        attempted_at,
        attached: false,
        idempotent: None,
        evidence_id: None,
        code: Some(NOT_ATTACHED),
        error: None,
        record: None,
    };
    let bytes = match std::fs::read(receipt) {
        Ok(bytes) => bytes,
        Err(err) => {
            outcome.error = Some(format!(
                "the receipt {} could not be read back: {err}",
                receipt.display()
            ));
            return outcome;
        }
    };
    let sha256 = sha256_hex(&bytes);
    outcome.sha256 = Some(sha256.clone());
    let uri = match uri_override {
        Some(uri) => uri.to_owned(),
        None => match file_uri(receipt) {
            Ok(uri) => uri,
            Err(err) => {
                outcome.error = Some(err);
                return outcome;
            }
        },
    };
    outcome.uri = Some(uri.clone());
    match client
        .attach_evidence(task_id, &uri, &sha256, CONTENT_TYPE)
        .await
    {
        Ok(record) => {
            outcome.attached = true;
            outcome.code = None;
            outcome.idempotent = record.idempotent;
            outcome.evidence_id = Some(record.evidence_id.clone());
            outcome.record = Some(record);
        }
        Err(err) => outcome.error = Some(err.to_string()),
    }
    outcome
}

/// Say what happened: one stdout line on success, one loud stderr line and the
/// retry command on failure. `who` is the program prefix (`arcana run`).
pub fn report(outcome: &Outcome, who: &str) {
    let sha = outcome.sha256.as_deref().unwrap_or("not_measured");
    if outcome.attached {
        println!(
            "evidence: {} attached to work item {} as {} (sha256 {sha}, {})",
            outcome.receipt,
            outcome.task_id,
            outcome.evidence_id.as_deref().unwrap_or("?"),
            if outcome.idempotent == Some(true) {
                "already attached — idempotent repeat"
            } else {
                "new record"
            },
        );
        return;
    }
    eprintln!(
        "{who}: {NOT_ATTACHED}: {}; the receipt is kept at {} (sha256 {sha}) and is NOT on work \
         item {} — retry with: arcana attach-receipt --work-item {} --receipt {}{}",
        outcome.error.as_deref().unwrap_or("unknown failure"),
        outcome.receipt,
        outcome.task_id,
        outcome.task_id,
        outcome.receipt,
        outcome
            .uri
            .as_deref()
            .map(|uri| format!(" --evidence-uri {uri}"))
            .unwrap_or_default(),
    );
}

/// Write the outcome as pretty JSON.
///
/// # Errors
/// When the file cannot be written.
pub fn write(path: &Path, outcome: &Outcome) -> Result<(), String> {
    let text = serde_json::to_string_pretty(outcome)
        .map_err(|err| format!("the evidence outcome could not be serialized: {err}"))?;
    std::fs::write(path, text + "\n").map_err(|err| {
        format!(
            "the evidence outcome could not be written to {}: {err}",
            path.display()
        )
    })
}

/// `arcana attach-receipt` — attach (or re-attach) an existing receipt file.
///
/// The retry path for a run that printed `EVIDENCE_NOT_ATTACHED`: re-running
/// the work item would cost money and write a DIFFERENT receipt, while this
/// sends the same bytes, and Muneral answers a repeat of a claim that did land
/// with `200 idempotent: true`. Returns a process exit code: `0` attached (new
/// or repeat), [`EXIT_NOT_ATTACHED`] otherwise, `1` when it could not start.
#[must_use]
pub fn run_attach_receipt(
    task_id: &str,
    receipt: &Path,
    uri: Option<&str>,
    record: Option<&Path>,
) -> i32 {
    const WHO: &str = "arcana attach-receipt";
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("{WHO}: failed to start async runtime: {err}");
            return 1;
        }
    };
    let client = match MuneralClient::try_from_env() {
        Ok(client) => client,
        Err(err) => {
            eprintln!("{WHO}: MUNERAL_UNAVAILABLE: {err}");
            return 1;
        }
    };
    let outcome = runtime.block_on(attach(&client, task_id, receipt, uri, now_utc()));
    report(&outcome, WHO);
    if let Some(path) = record {
        if let Err(err) = write(path, &outcome) {
            eprintln!("{WHO}: {err}");
        }
    }
    println!(
        "{}",
        serde_json::to_string(&outcome).unwrap_or_else(|_| "{}".to_owned())
    );
    if outcome.attached {
        0
    } else {
        EXIT_NOT_ATTACHED
    }
}

/// RFC 3339, UTC; `not_measured` if the clock cannot be formatted.
#[must_use]
pub fn now_utc() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "not_measured".to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_sidecar_sits_next_to_the_receipt() {
        assert_eq!(
            sidecar_path(Path::new("/w/receipts/ReadinessReceipt-abc.json")),
            PathBuf::from("/w/receipts/ReadinessReceipt-abc.evidence.json")
        );
    }

    #[test]
    fn sha256_hex_is_lowercase_and_64_characters() {
        // The empty-input digest, from FIPS 180-2.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_path_with_a_space_becomes_a_whitespace_free_file_uri() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("a receipt.json");
        std::fs::write(&path, "{}").unwrap();
        let uri = file_uri(&path).unwrap();
        assert!(uri.starts_with("file:///"), "{uri}");
        assert!(!uri.contains(' '), "{uri}");
    }
}
