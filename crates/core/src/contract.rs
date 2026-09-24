//! The KC2 contract a work item is bound to, and the rule that binds it.
//!
//! A work item in Muneral carries a `contractDigest`. That digest is the whole
//! of the binding: it names one immutable KC2 contract, and everything the run
//! is allowed to do is read out of the document that digest addresses. Two
//! failures this module exists to make impossible:
//!
//! * **A work item with no digest.** Nothing says what the run may do, so
//!   there is nothing to run under. The refusal is [`ContractRefusal::Missing`]
//!   (`CONTRACT_MISSING`) and it happens before the first model call — an
//!   unbound run that has already paid for a turn is a run whose cost cannot
//!   be justified by any contract.
//! * **A contract that is not the one the work item names.** The source is
//!   asked for a digest and answers with a document; if the document's bytes
//!   do not hash to that digest, the answer is about something else. That is
//!   [`ContractRefusal::DigestMismatch`] (`CONTRACT_DIGEST_MISMATCH`).
//!
//! ## What is re-hashed, and why it is the bytes
//!
//! Argana stamps a contract with `H(canonical(body) ‖ canonical(manifest))`,
//! computed by the KC2 pin's own canonicaliser. Re-deriving that rule here, in
//! Rust, would put a second implementation of it in the ecosystem, and two
//! implementations of one rule disagree eventually. So this module never
//! canonicalises anything: it hashes the **bytes the source itself declares as
//! the digest's preimage** and compares. One rule, implemented once, checked
//! byte for byte.
//!
//! Argana's answer carries `canonical.bytes_b64` — base64 of
//! `canonical(body) ‖ canonical(closure_manifest)`, the exact preimage — so the
//! client's whole check is one decode and one hash. That is the preferred
//! route. Two fallbacks exist for a source that is not Argana (a file fixture,
//! a future service): a plain-text `canonical_bytes`, and a `projection` that
//! is itself a string. Which route was taken is recorded on the binding and in
//! the receipt, because "the digest checked out" means something different for
//! each.

use std::collections::BTreeSet;
use std::fmt;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The algorithm prefix every digest in this ecosystem carries.
pub const DIGEST_ALGO_PREFIX: &str = "sha256:";

/// Length of the hex half of a well-formed digest.
pub const DIGEST_HEX_LEN: usize = 64;

/// What a contract-bound run may call when the contract names no tools.
///
/// Not a silent default: it is narrower than the run's tool set, it is recorded
/// on the binding as [`AllowlistSource::DefaultNoShell`], and it appears in the
/// receipt. `bash` is absent deliberately — a shell is the one capability a
/// contract has to grant in words, because it is the only tool whose blast
/// radius is not bounded by its own arguments.
pub const DEFAULT_ALLOWLIST: [&str; 4] = ["read", "grep", "write", "edit"];

/// True when `value` is `sha256:` followed by 64 lowercase hex digits.
///
/// Lowercase on purpose: a digest that differs only in case would compare
/// unequal to the one Muneral stores, and silently normalising it here would
/// hide a producer that is not writing the agreed form.
#[must_use]
pub fn is_wellformed_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(DIGEST_ALGO_PREFIX) else {
        return false;
    };
    hex.len() == DIGEST_HEX_LEN
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `sha256:<hex>` of `bytes`.
#[must_use]
pub fn digest_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut hex = String::with_capacity(DIGEST_ALGO_PREFIX.len() + DIGEST_HEX_LEN);
    hex.push_str(DIGEST_ALGO_PREFIX);
    for byte in out {
        use fmt::Write as _;
        // Writing into a String is infallible; the result is ignored so the
        // helper stays total.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The tools half of a contract document.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ContractTools {
    /// Tool names this contract admits. An empty vector is a contract that
    /// admits no tools, which is different from a contract that says nothing.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// The digested bytes, as Argana sends them.
///
/// `bytes_b64` is `canonical(body) ‖ canonical(closure_manifest)` verbatim —
/// the producer handing over its own preimage rather than leaving the client to
/// reconstruct it. `rule` and `length` are carried for the receipt and the
/// error message; neither is trusted, because the hash is computed over the
/// decoded bytes and nothing else.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CanonicalBlock {
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub bytes_b64: Option<String>,
    #[serde(default)]
    pub length: Option<u64>,
}

/// What the source says about the KC2 pin the contract was admitted at.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Kc2Block {
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub snapshot: Option<String>,
    /// `current`, `moved`, `not_measured` — carried through to the receipt so a
    /// reader can see that a contract admitted at an older pin was executed
    /// knowingly rather than by accident.
    #[serde(default)]
    pub pin_status: Option<String>,
}

/// One contract, as a contract source returns it.
///
/// Mirrors Argana's `ContractResponse` (`GET /v1/contract/{digest}`): `digest`,
/// `projection` as `{body, closure_manifest}`, `canonical` as the bytes, `kc2`
/// as the pin. Everything but `digest` is optional and additive, so a source
/// that grows a field does not break this client and one that has not grown a
/// field yet still parses.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ContractDocument {
    /// The digest the source says this document has. NOT the authority — see
    /// [`verify`].
    pub digest: String,
    /// The digested object, `{body, closure_manifest}`. A source that renders
    /// its projection as text instead may send a string, and then the string is
    /// also a candidate preimage.
    #[serde(default)]
    pub projection: Value,
    /// The digested bytes.
    #[serde(default)]
    pub canonical: Option<CanonicalBlock>,
    /// A plain-text preimage, for a source that sends one instead of base64.
    #[serde(default)]
    pub canonical_bytes: Option<String>,
    /// The KC2 pin, Argana's spelling.
    #[serde(default)]
    pub kc2: Option<Kc2Block>,
    /// The KC2 revision, flat spelling — for a fixture written by hand.
    #[serde(default)]
    pub kc2_revision: Option<String>,
    /// The KC2 snapshot, flat spelling.
    #[serde(default)]
    pub kc2_snapshot: Option<String>,
    /// Tools the contract admits.
    #[serde(default)]
    pub tools: Option<ContractTools>,
}

impl ContractDocument {
    /// The contract in words, for the model's prompt.
    ///
    /// Text, whatever the projection's JSON type: an object is pretty-printed.
    /// This is what the model READS; it is never what is hashed, and the two
    /// must not be confused — see [`DigestPreimage`].
    #[must_use]
    pub fn projection_text(&self) -> String {
        match &self.projection {
            Value::Null => String::new(),
            Value::String(text) => text.clone(),
            other => serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()),
        }
    }

    /// The KC2 revision, from either spelling.
    #[must_use]
    pub fn revision(&self) -> Option<String> {
        self.kc2
            .as_ref()
            .and_then(|kc2| kc2.revision.clone())
            .or_else(|| self.kc2_revision.clone())
    }

    /// The KC2 snapshot, from either spelling.
    #[must_use]
    pub fn snapshot(&self) -> Option<String> {
        self.kc2
            .as_ref()
            .and_then(|kc2| kc2.snapshot.clone())
            .or_else(|| self.kc2_snapshot.clone())
    }
}

/// Where the binding's allowlist came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AllowlistSource {
    /// The contract named its tools.
    Contract,
    /// The contract named none, so [`DEFAULT_ALLOWLIST`] applies.
    DefaultNoShell,
}

impl AllowlistSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::DefaultNoShell => "default-no-shell",
        }
    }
}

/// Which bytes the digest was re-hashed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestPreimage {
    /// `canonical.bytes_b64`, base64-decoded — Argana's route, and the only one
    /// that needs nothing from this client but a decode and a hash.
    CanonicalBytesB64,
    /// A plain-text `canonical_bytes` field.
    CanonicalBytes,
    /// A projection that was itself a string.
    Projection,
}

impl DigestPreimage {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalBytesB64 => "canonical.bytes_b64",
            Self::CanonicalBytes => "canonical_bytes",
            Self::Projection => "projection",
        }
    }
}

/// A verified binding: this digest, these tools, this preimage.
///
/// Only [`verify`] constructs one, so holding a `ContractBinding` is itself the
/// evidence that the digest was re-hashed and matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractBinding {
    digest: String,
    kc2_revision: Option<String>,
    kc2_snapshot: Option<String>,
    allowlist: BTreeSet<String>,
    allowlist_source: AllowlistSource,
    preimage: DigestPreimage,
    projection: String,
}

impl ContractBinding {
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
    #[must_use]
    pub fn kc2_revision(&self) -> Option<&str> {
        self.kc2_revision.as_deref()
    }
    #[must_use]
    pub fn kc2_snapshot(&self) -> Option<&str> {
        self.kc2_snapshot.as_deref()
    }
    #[must_use]
    pub fn allowlist(&self) -> &BTreeSet<String> {
        &self.allowlist
    }
    #[must_use]
    pub fn allowlist_source(&self) -> AllowlistSource {
        self.allowlist_source
    }
    #[must_use]
    pub fn preimage(&self) -> DigestPreimage {
        self.preimage
    }
    #[must_use]
    pub fn projection(&self) -> &str {
        &self.projection
    }
    /// True when the contract admits `tool`.
    #[must_use]
    pub fn admits(&self, tool: &str) -> bool {
        self.allowlist.contains(tool)
    }
}

/// Every way a contract-bound run refuses to start, with the code it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractRefusal {
    /// The work item carries no `contractDigest`.
    Missing,
    /// A digest that is not `sha256:<64 lowercase hex>`.
    MalformedDigest { value: String },
    /// The source has no contract under that digest.
    NotFound { digest: String },
    /// The document's bytes do not hash to the digest it was fetched under.
    DigestMismatch {
        expected: String,
        computed: String,
        preimage: DigestPreimage,
    },
    /// The source returned a document with nothing to hash, or bytes that do
    /// not decode.
    Unverifiable { digest: String, detail: String },
    /// The source could not be reached or answered unusably.
    Unavailable { detail: String },
}

impl ContractRefusal {
    /// The machine-readable code, as the plan names it.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing => "CONTRACT_MISSING",
            Self::MalformedDigest { .. } => "CONTRACT_DIGEST_MALFORMED",
            Self::NotFound { .. } => "CONTRACT_NOT_FOUND",
            Self::DigestMismatch { .. } => "CONTRACT_DIGEST_MISMATCH",
            Self::Unverifiable { .. } => "CONTRACT_UNVERIFIABLE",
            Self::Unavailable { .. } => "CONTRACT_SOURCE_UNAVAILABLE",
        }
    }
}

impl fmt::Display for ContractRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Missing => write!(
                f,
                "{code}: the work item carries no contractDigest, so nothing says what this run \
                 may do; refused before the first model call"
            ),
            Self::MalformedDigest { value } => write!(
                f,
                "{code}: `{value}` is not a sha256:<64 lowercase hex> digest"
            ),
            Self::NotFound { digest } => write!(
                f,
                "{code}: the contract source holds no contract under {digest}"
            ),
            Self::DigestMismatch {
                expected,
                computed,
                preimage,
            } => write!(
                f,
                "{code}: the document returned for {expected} hashes to {computed} over its \
                 {} — the contract is not the one the work item names",
                preimage.as_str()
            ),
            Self::Unverifiable { digest, detail } => write!(
                f,
                "{code}: the document returned for {digest} cannot be re-hashed ({detail}), so the \
                 binding cannot be trusted"
            ),
            Self::Unavailable { detail } => {
                write!(f, "{code}: the contract source is unavailable: {detail}")
            }
        }
    }
}

/// Bind a run to `document`, having re-hashed it against `expected`.
///
/// `expected` is the digest the WORK ITEM carries — never the one the document
/// carries. A check that trusted the document's own `digest` field would pass
/// for any document that is internally consistent, including one about a
/// different contract entirely.
///
/// # Errors
/// Every way the binding cannot be made, as [`ContractRefusal`].
pub fn verify(
    expected: &str,
    document: &ContractDocument,
) -> Result<ContractBinding, ContractRefusal> {
    if !is_wellformed_digest(expected) {
        return Err(ContractRefusal::MalformedDigest {
            value: expected.to_owned(),
        });
    }

    let (preimage, bytes) = preimage_of(expected, document)?;

    let computed = digest_of(&bytes);
    if computed != expected {
        return Err(ContractRefusal::DigestMismatch {
            expected: expected.to_owned(),
            computed,
            preimage,
        });
    }

    let (allowlist, allowlist_source) = match document.tools.as_ref() {
        Some(tools) if !tools.allow.is_empty() => (
            tools.allow.iter().cloned().collect::<BTreeSet<_>>(),
            AllowlistSource::Contract,
        ),
        _ => (
            DEFAULT_ALLOWLIST
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<BTreeSet<_>>(),
            AllowlistSource::DefaultNoShell,
        ),
    };

    Ok(ContractBinding {
        digest: expected.to_owned(),
        kc2_revision: document.revision(),
        kc2_snapshot: document.snapshot(),
        allowlist,
        allowlist_source,
        preimage,
        projection: document.projection_text(),
    })
}

/// The bytes the digest is checked against, and which route produced them.
///
/// Ordered by how little the client has to assume: the producer's own base64
/// preimage first, a plain-text one second, and a projection that happens to be
/// a string last. A projection that is an OBJECT is never a candidate — hashing
/// a re-serialisation of it would be this client guessing at a canonicalisation
/// rule, which is the one thing this module refuses to do.
fn preimage_of(
    expected: &str,
    document: &ContractDocument,
) -> Result<(DigestPreimage, Vec<u8>), ContractRefusal> {
    if let Some(b64) = document
        .canonical
        .as_ref()
        .and_then(|block| block.bytes_b64.as_deref())
        .filter(|raw| !raw.is_empty())
    {
        let bytes = BASE64
            .decode(b64)
            .map_err(|err| ContractRefusal::Unverifiable {
                digest: expected.to_owned(),
                detail: format!("canonical.bytes_b64 is not base64: {err}"),
            })?;
        return Ok((DigestPreimage::CanonicalBytesB64, bytes));
    }
    if let Some(raw) = document
        .canonical_bytes
        .as_deref()
        .filter(|raw| !raw.is_empty())
    {
        return Ok((DigestPreimage::CanonicalBytes, raw.as_bytes().to_vec()));
    }
    if let Value::String(text) = &document.projection {
        if !text.is_empty() {
            return Ok((DigestPreimage::Projection, text.as_bytes().to_vec()));
        }
    }
    Err(ContractRefusal::Unverifiable {
        digest: expected.to_owned(),
        detail: "the document carries no canonical.bytes_b64, no canonical_bytes, and no \
                 string projection"
            .to_owned(),
    })
}
