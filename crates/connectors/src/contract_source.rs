//! Where a contract comes from: Argana over HTTP, or a file on disk.
//!
//! Argana's `GET /v1/contract/{digest}` is the production source. It listens on
//! the arcana-prd loopback, so a run on another host reaches it through an
//! explicit override and not by accident — and until it is deployed, the only
//! honest alternative is a FILE the operator points at, recorded in the receipt
//! as such. The two are the same trait so the run path cannot tell them apart
//! and the receipt always can: `contract_source` names which answered, and only
//! `argana` means the binding was checked against the live endpoint.
//!
//! Neither source is trusted with the verdict. Both hand back a
//! [`ContractDocument`]; `arcana_core::contract::verify` re-hashes it. A file
//! the operator wrote and a service on the mesh are equally unable to make a
//! document pass under a digest that is not its own.

use std::path::{Path, PathBuf};
use std::time::Duration;

use arcana_core::contract::{ContractDocument, ContractRefusal};
use async_trait::async_trait;
use url::Url;

/// Override for Argana's root. Unset means no HTTP source is configured.
pub const ENV_ARGANA_URL: &str = "ARCANA_ARGANA_URL";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A source of contracts, addressed by digest.
#[async_trait]
pub trait ContractSource: Send + Sync {
    /// The label that goes into the receipt's `contract_source` field.
    fn label(&self) -> &'static str;

    /// The exact origin, for the receipt: a url, or a path.
    fn origin(&self) -> String;

    /// Fetch the contract stored under `digest`.
    ///
    /// # Errors
    /// [`ContractRefusal`] — `NotFound` for an unknown digest, `Unavailable`
    /// for everything else. Verification is NOT done here.
    async fn fetch(&self, digest: &str) -> Result<ContractDocument, ContractRefusal>;
}

/// Argana `GET /v1/contract/{digest}`.
#[derive(Debug, Clone)]
pub struct ArganaContractClient {
    http: reqwest::Client,
    base_url: Url,
}

impl ArganaContractClient {
    /// Build over an explicit root.
    ///
    /// # Errors
    /// When the HTTP client cannot be constructed.
    pub fn new(base_url: Url) -> Result<Self, ContractRefusal> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("arcana/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| ContractRefusal::Unavailable {
                detail: err.to_string(),
            })?;
        Ok(Self { http, base_url })
    }

    /// Build from `ARCANA_ARGANA_URL`, or `None` when it is unset.
    ///
    /// # Errors
    /// When the variable is set to something that is not a url.
    pub fn try_from_env() -> Result<Option<Self>, ContractRefusal> {
        let raw = std::env::var(ENV_ARGANA_URL).unwrap_or_default();
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let base_url = Url::parse(raw.trim()).map_err(|err| ContractRefusal::Unavailable {
            detail: format!("{ENV_ARGANA_URL} is not a url: {err}"),
        })?;
        Self::new(base_url).map(Some)
    }
}

#[async_trait]
impl ContractSource for ArganaContractClient {
    fn label(&self) -> &'static str {
        "argana"
    }

    fn origin(&self) -> String {
        self.base_url.to_string()
    }

    async fn fetch(&self, digest: &str) -> Result<ContractDocument, ContractRefusal> {
        let mut url = self.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| ContractRefusal::Unavailable {
                    detail: "the Argana root cannot carry a path".to_owned(),
                })?;
            path.pop_if_empty();
            path.push("v1");
            path.push("contract");
            path.push(digest);
        }
        let response =
            self.http
                .get(url)
                .send()
                .await
                .map_err(|err| ContractRefusal::Unavailable {
                    detail: err.to_string(),
                })?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| ContractRefusal::Unavailable {
                detail: err.to_string(),
            })?;
        if status.as_u16() == 404 {
            return Err(ContractRefusal::NotFound {
                digest: digest.to_owned(),
            });
        }
        if !status.is_success() {
            return Err(ContractRefusal::Unavailable {
                detail: format!("HTTP {}: {}", status.as_u16(), excerpt(&body)),
            });
        }
        serde_json::from_str(&body).map_err(|err| ContractRefusal::Unavailable {
            detail: format!("the answer is not a contract document: {err}"),
        })
    }
}

/// A contract read from a file the operator named.
///
/// This exists because the live endpoint is not deployed yet, and a run that
/// silently invented a contract would be worse than a run that says where it
/// got one. The file is subject to the same re-hash as the service's answer, so
/// it cannot be used to run under a digest it does not hash to.
#[derive(Debug, Clone)]
pub struct FileContractSource {
    path: PathBuf,
}

impl FileContractSource {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl ContractSource for FileContractSource {
    fn label(&self) -> &'static str {
        "file"
    }

    fn origin(&self) -> String {
        self.path.display().to_string()
    }

    async fn fetch(&self, digest: &str) -> Result<ContractDocument, ContractRefusal> {
        let raw = read_to_string(&self.path).map_err(|err| ContractRefusal::Unavailable {
            detail: format!("{}: {err}", self.path.display()),
        })?;
        let document: ContractDocument =
            serde_json::from_str(&raw).map_err(|err| ContractRefusal::Unavailable {
                detail: format!("{} is not a contract document: {err}", self.path.display()),
            })?;
        // A file holding some OTHER contract is a `NotFound`, not a mismatch:
        // the operator pointed at the wrong file, and saying "the bytes do not
        // hash" would send them looking for corruption instead.
        if document.digest != digest {
            return Err(ContractRefusal::NotFound {
                digest: digest.to_owned(),
            });
        }
        Ok(document)
    }
}

fn read_to_string(path: &Path) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

fn excerpt(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.chars().count() <= 400 {
        return trimmed.to_owned();
    }
    trimmed.chars().take(400).collect::<String>() + "…"
}
