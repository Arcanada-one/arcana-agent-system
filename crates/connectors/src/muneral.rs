//! `MuneralClient` — the work-item half of a contract-bound run.
//!
//! Muneral is the authority on work: what a task is, what it is bound to, and
//! who may execute it. This client reads the work item and it attaches
//! evidence to it; it never moves the work item's status. A run that closed its
//! own work item would be the executor grading its own homework, and the
//! transition is the control plane's to make.
//!
//! ## Evidence is not a transition
//!
//! [`MuneralClient::attach_evidence`] is the one write, and it is a different
//! kind of write: `POST /tasks/{id}/evidence` records a CLAIM — "these bytes
//! (by sha256), of this media type, are at this uri" — under the agent that
//! made it. It changes no status, no assignee and no field of the task, and
//! the server never fetches the uri. The executor is the only party that holds
//! its receipt at the moment the run ends; before this call existed a human
//! had to carry it across by hand, and one was lost (NR-0016, A2-332). Judging
//! the evidence, and moving the status on it, remain the control plane's.
//!
//! ## The key
//!
//! The agent's key is a `mun_sk_` secret and is read from a FILE, never from a
//! command line and never from an inherited plain environment variable holding
//! the value itself. It is wrapped in [`SecretString`] from the moment it is
//! read, so no `Debug`, log line or error message can carry it: every error
//! this module returns is built from the response, not from the request.

use std::path::Path;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use url::Url;

/// The production API root. A base url is accepted from the environment for a
/// local mock only — see [`MuneralClient::try_from_env`].
pub const DEFAULT_BASE_URL: &str = "https://api.muneral.com/api/v1";

/// Override for the API root (test doubles, a mesh-local deployment).
pub const ENV_BASE_URL: &str = "ARCANA_MUNERAL_URL";

/// Path to the file holding the agent's `mun_sk_` key, mode 0600.
pub const ENV_KEY_FILE: &str = "ARCANA_MUNERAL_KEY_FILE";

/// The `User-Agent` the orchestration lane is identified by.
const USER_AGENT: &str = "aup-orchestrator/1.0";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// One work item, in the fields a contract-bound run needs.
///
/// `#[serde(default)]` on everything optional: Muneral's task DTO is larger
/// than this and grows, and a run must not fail because a field it never reads
/// appeared.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkItem {
    pub id: String,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub revision: Option<i64>,
    /// The KC2 contract this item is bound to. `None` is the refusal the plan
    /// names `CONTRACT_MISSING` — see `arcana_core::contract`.
    #[serde(default)]
    pub contract_digest: Option<String>,
}

/// Everything that can go wrong reading a work item.
///
/// Each variant is the SERVER's answer, classified. None of them can carry the
/// key, because none of them is built from the request.
#[derive(Debug, thiserror::Error)]
pub enum MuneralError {
    #[error("the Muneral API root is unusable: {0}")]
    BaseUrl(String),
    #[error("the agent key could not be read from the file named by {ENV_KEY_FILE}: {0}")]
    Key(String),
    #[error("Muneral could not be reached: {0}")]
    Transport(String),
    #[error("Muneral refused the key (HTTP 401): the agent is not authenticated")]
    Unauthorized,
    #[error("Muneral refused the request (HTTP 403): {0}")]
    Forbidden(String),
    #[error("Muneral holds no work item {0} this agent can see (HTTP 404)")]
    NotFound(String),
    #[error("Muneral answered HTTP {status}: {body}")]
    Status { status: u16, body: String },
    /// `409`: the same digest is already attached to this task under a
    /// different uri or media type. The server's whole body is kept — it names
    /// the stored and the attempted values, which is what an operator needs to
    /// decide which claim is wrong.
    #[error("Muneral refused the request (HTTP 409): {0}")]
    Conflict(String),
    #[error("Muneral's answer could not be read as a work item: {0}")]
    Decode(String),
    /// A 2xx whose record is not the attachment that was asked for — another
    /// task, or other bytes. Reported rather than trusted: a success that does
    /// not name our digest is not evidence that our digest was recorded.
    #[error("Muneral answered with an evidence record that is not the one attached: {0}")]
    EvidenceMismatch(String),
}

/// `WorkItemEvidenceAttachment/v1`, as `POST /tasks/{id}/evidence` answers it.
///
/// `snake_case`, as Muneral spells it. `idempotent` is `false` on the `201` that
/// created the record and `true` on the `200` that found it already stored.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WorkItemEvidenceAttachment {
    pub schema: String,
    pub evidence_id: String,
    pub task_id: String,
    pub uri: String,
    pub sha256: String,
    pub content_type: String,
    #[serde(default)]
    pub created_by_agent_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    /// `None` only if the server stopped sending it; the HTTP status is then
    /// the fallback (see [`MuneralClient::attach_evidence`]).
    #[serde(default)]
    pub idempotent: Option<bool>,
}

/// The request body of `POST /tasks/{id}/evidence` — camelCase, as
/// `AttachEvidenceDto` declares it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachEvidenceBody<'a> {
    uri: &'a str,
    sha256: &'a str,
    content_type: &'a str,
}

/// Client for the Muneral work-item API: reads work items, attaches evidence,
/// never transitions status.
#[derive(Debug, Clone)]
pub struct MuneralClient {
    http: reqwest::Client,
    base_url: Url,
    key: SecretString,
}

impl MuneralClient {
    /// Build from the environment: `ARCANA_MUNERAL_KEY_FILE` for the key,
    /// `ARCANA_MUNERAL_URL` (optional) for the API root.
    ///
    /// # Errors
    /// When the key file is unset or unreadable, or the url does not parse.
    pub fn try_from_env() -> Result<Self, MuneralError> {
        let raw = std::env::var(ENV_BASE_URL).unwrap_or_default();
        let raw = if raw.trim().is_empty() {
            DEFAULT_BASE_URL.to_owned()
        } else {
            raw
        };
        let base_url = Url::parse(&raw).map_err(|err| MuneralError::BaseUrl(err.to_string()))?;
        let key_file = std::env::var(ENV_KEY_FILE)
            .map_err(|_| MuneralError::Key(format!("{ENV_KEY_FILE} is not set")))?;
        let key = read_key_file(Path::new(&key_file))?;
        Self::new(base_url, key)
    }

    /// Build over an explicit root and key. Used by the contract tests, which
    /// point it at a mock server.
    ///
    /// # Errors
    /// When the HTTP client cannot be constructed.
    pub fn new(base_url: Url, key: SecretString) -> Result<Self, MuneralError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|err| MuneralError::Transport(err.to_string()))?;
        Ok(Self {
            http,
            base_url,
            key,
        })
    }

    /// `GET /tasks/{id}`.
    ///
    /// # Errors
    /// [`MuneralError`] — each variant is the server's answer, classified.
    pub async fn work_item(&self, id: &str) -> Result<WorkItem, MuneralError> {
        let url = self.endpoint(&["tasks", id])?;
        let response = self
            .http
            .get(url)
            .bearer_auth(self.key.expose_secret())
            .send()
            .await
            .map_err(|err| MuneralError::Transport(err.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| MuneralError::Transport(err.to_string()))?;
        if !status.is_success() {
            return Err(classify(status.as_u16(), id, &body));
        }
        serde_json::from_str(&body).map_err(|err| MuneralError::Decode(err.to_string()))
    }

    /// `POST /tasks/{task_id}/evidence` — attach one artefact, by digest.
    ///
    /// `sha256` is 64 lowercase hex characters with no algorithm prefix, and
    /// `content_type` a lowercase media type; Muneral refuses anything else
    /// with a `400` carrying a machine `code`, which is returned here as
    /// [`MuneralError::Status`] with that body.
    ///
    /// Idempotent by the server's design: repeating the same
    /// `(task, sha256, uri, content_type)` answers `200` with the stored record
    /// and `idempotent: true`, so a caller that lost the first answer may
    /// simply call again. The same digest under a different uri or media type
    /// is [`MuneralError::Conflict`].
    ///
    /// # Errors
    /// [`MuneralError`] — each variant is the server's answer, classified, plus
    /// [`MuneralError::EvidenceMismatch`] when a 2xx names other bytes or
    /// another task than the ones sent.
    pub async fn attach_evidence(
        &self,
        task_id: &str,
        uri: &str,
        sha256: &str,
        content_type: &str,
    ) -> Result<WorkItemEvidenceAttachment, MuneralError> {
        let url = self.endpoint(&["tasks", task_id, "evidence"])?;
        let response = self
            .http
            .post(url)
            .bearer_auth(self.key.expose_secret())
            .json(&AttachEvidenceBody {
                uri,
                sha256,
                content_type,
            })
            .send()
            .await
            .map_err(|err| MuneralError::Transport(err.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| MuneralError::Transport(err.to_string()))?;
        if !status.is_success() {
            return Err(classify(status.as_u16(), task_id, &body));
        }
        let mut record: WorkItemEvidenceAttachment = serde_json::from_str(&body)
            .map_err(|err| MuneralError::Decode(format!("evidence record: {err}")))?;
        if record.task_id != task_id || record.sha256 != sha256 {
            return Err(MuneralError::EvidenceMismatch(format!(
                "sent task {task_id} sha256 {sha256}, answered task {} sha256 {}",
                record.task_id, record.sha256
            )));
        }
        // The route documents 201 = new, 200 = repeat. If the flag is ever
        // absent, the status still says which one it was.
        if record.idempotent.is_none() {
            record.idempotent = Some(status.as_u16() == 200);
        }
        Ok(record)
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, MuneralError> {
        let mut url = self.base_url.clone();
        {
            let mut path = url.path_segments_mut().map_err(|()| {
                MuneralError::BaseUrl("the API root cannot carry a path".to_owned())
            })?;
            // A trailing slash on the root would otherwise produce an empty
            // segment and a `//tasks/<id>` path that no router matches.
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url)
    }
}

/// Classify a non-2xx answer.
///
/// `403` keeps the server's body: Muneral answers a foreign task with a
/// machine reason, and dropping it would turn "this agent is not assigned to
/// that item" into "forbidden", which is exactly the sentence an operator
/// cannot act on. `409` keeps it too, and uncut up to [`CONFLICT_BODY_MAX`]:
/// the body names the stored and the attempted uri, each up to 2048
/// characters, and the 400-character excerpt would cut off the one that
/// differs.
fn classify(status: u16, id: &str, body: &str) -> MuneralError {
    match status {
        401 => MuneralError::Unauthorized,
        403 => MuneralError::Forbidden(excerpt(body)),
        404 => MuneralError::NotFound(id.to_owned()),
        409 => MuneralError::Conflict(bounded(body, CONFLICT_BODY_MAX)),
        other => MuneralError::Status {
            status: other,
            body: excerpt(body),
        },
    }
}

/// At most 400 characters of a response body, so an HTML error page cannot
/// become the whole of an operator's error line.
fn excerpt(body: &str) -> String {
    bounded(body, 400)
}

/// Longest `409` body kept: two 2048-character uris, the message and the keys.
const CONFLICT_BODY_MAX: usize = 8192;

fn bounded(body: &str, max: usize) -> String {
    let trimmed = body.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_owned();
    }
    trimmed.chars().take(max).collect::<String>() + "…"
}

/// Read a `mun_sk_` key out of a file, trimming the trailing newline an editor
/// leaves behind.
///
/// # Errors
/// When the file cannot be read or holds nothing.
pub fn read_key_file(path: &Path) -> Result<SecretString, MuneralError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| MuneralError::Key(format!("{}: {err}", path.display())))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(MuneralError::Key(format!("{} is empty", path.display())));
    }
    Ok(SecretString::from(trimmed.to_owned()))
}
