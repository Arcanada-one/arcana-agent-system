//! The KC2 contract a work item is bound to, and the rule that binds it.
//!
//! A work item in Muneral carries a `contractDigest`. That digest is the byte
//! integrity part of the binding: it names one immutable KC2 contract, and the tools the run
//! is allowed to do is read out of the document that digest addresses. Two
//! failures this module exists to make impossible:
//!
//! Task-run admission additionally requires [`crate::contract_authority`].
//! Hash verification alone authenticates no task, subject, issuer or generation.
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

mod pin;
mod strict;

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

/// The execution profile the strict reader enforces (KC-Brain decision, PR1886).
pub const STRICT_PROFILE: &str = "arcanada-kc2-tools/v1";

/// The closed tool vocabulary of [`STRICT_PROFILE`], ASCII-ascending.
pub const TOOL_VOCABULARY: [&str; 4] = ["edit", "grep", "read", "write"];

/// The existing canonicalisation rule the digested bytes must round-trip under.
pub const CANONICAL_RULE: &str = "json-c14n-pilot/v1";

/// Which profiles this build of the reader can enforce, as a signal admission
/// can check BEFORE a profiled contract is run.
///
/// An older reader that merely ignores `body.tools.profile` is not capable and
/// cannot be relied upon to refuse; it never produces this signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderCapability {
    /// Strict profiles this reader enforces.
    pub strict_profiles: &'static [&'static str],
    /// The canonical-form rule its round-trip check implements.
    pub canonical_rule: &'static str,
}

/// This build's capability.
pub const READER_CAPABILITY: ReaderCapability = ReaderCapability {
    strict_profiles: &[STRICT_PROFILE],
    canonical_rule: CANONICAL_RULE,
};

impl ReaderCapability {
    /// True when this reader enforces `profile`.
    #[must_use]
    pub fn supports(&self, profile: &str) -> bool {
        self.strict_profiles.contains(&profile)
    }

    /// One recordable line, e.g. `strict:arcanada-kc2-tools/v1;canonical:json-c14n-pilot/v1`.
    #[must_use]
    pub fn signal(&self) -> String {
        let profiles: Vec<String> = self
            .strict_profiles
            .iter()
            .map(|profile| format!("strict:{profile}"))
            .collect();
        format!("{};canonical:{}", profiles.join(","), self.canonical_rule)
    }
}

pub use pin::{
    git_blob_id, verify_pin, PinnedSchema, SchemaPin, PROFILE_SCHEMA, PROFILE_SCHEMA_FILES,
    TALOMNIA_SCHEMA_PIN,
};

/// Whether this reader enforces the normative schema it is pinned to, and in what state that pin is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaParity {
    /// No normative schema is pinned, so parity cannot be claimed.
    NotReady,
    /// A schema is pinned but the compiled-in bytes do not match the pinned blobs. The strict
    /// reader refuses (`CONTRACT_READER_UNSUPPORTED`).
    PinMismatch,
    /// The compiled-in schema bytes match the pin, which points at an UNMERGED commit: a
    /// squash-merge or amendment of the owner's PR requires a re-pin before this can merge.
    PinnedVerifiedUnmerged,
    /// As above, with the pinned commit on the owner's default branch.
    PinnedVerified,
}

impl SchemaParity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotReady => "NOT_READY",
            Self::PinMismatch => "PIN_MISMATCH",
            Self::PinnedVerifiedUnmerged => "PINNED_VERIFIED_UNMERGED",
            Self::PinnedVerified => "PINNED_VERIFIED",
        }
    }
}

/// Parity state of `pin`.
#[must_use]
pub fn schema_parity_of(pin: Option<&SchemaPin>) -> SchemaParity {
    match pin {
        None => SchemaParity::NotReady,
        Some(pin) if verify_pin(pin).is_err() => SchemaParity::PinMismatch,
        Some(pin) if pin.merged => SchemaParity::PinnedVerified,
        Some(_) => SchemaParity::PinnedVerifiedUnmerged,
    }
}

/// Parity state of this build.
#[must_use]
pub fn schema_parity() -> SchemaParity {
    schema_parity_of(TALOMNIA_SCHEMA_PIN.as_ref())
}

/// How a contract is read. The mode is explicit and is recorded on the binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderMode<'a> {
    /// The pre-profile compatibility route (what [`verify`] does). It can never
    /// satisfy the strict profile; the binding says so.
    Legacy,
    /// Enforce the closed profile `profile` over the verified bytes.
    Strict { profile: &'a str },
}

/// Which route produced a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReaderRoute {
    /// The recorded legacy compatibility route.
    Legacy,
    /// The strict profile validator.
    Strict,
}

impl ReaderRoute {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Strict => "strict",
        }
    }
}

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
    /// Top-level `kind` dispatch hint of a profile object. Outside the digest;
    /// in strict mode it must agree with the digested bytes.
    #[serde(default)]
    pub kind: Option<String>,
    /// Top-level `schema_version` dispatch hint. Outside the digest; in strict
    /// mode it must equal the digested `body.tools.profile`.
    #[serde(default)]
    pub schema_version: Option<String>,
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

/// How the effective policy (projection text, tool allowlist) was tied to the
/// digested bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyBinding {
    /// The preimage parsed as `canonical(body) ‖ canonical(closure_manifest)`;
    /// the projection shown to the model and the allowlist were DERIVED from
    /// those bytes, and any envelope copy had to equal the derived value.
    DerivedFromCanonicalBytes,
    /// The preimage is opaque text (no body/manifest structure). The model is
    /// shown that text itself, and the envelope may carry no `tools`: an
    /// allowlist outside the digested bytes has no authenticated binding.
    OpaquePreimageText,
}

impl PolicyBinding {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DerivedFromCanonicalBytes => "derived-from-canonical-bytes",
            Self::OpaquePreimageText => "opaque-preimage-text",
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
    policy_binding: PolicyBinding,
    projection: String,
    reader_route: ReaderRoute,
    profile: Option<String>,
    /// Parity of the pin the strict reader ACTUALLY enforced for this binding. `None` on the
    /// legacy route: no schema was enforced there, whatever the build pins.
    enforced_parity: Option<SchemaParity>,
}

impl ContractBinding {
    /// The route that produced this binding. Only [`ReaderRoute::Strict`]
    /// satisfies the strict profile.
    #[must_use]
    pub fn reader_route(&self) -> ReaderRoute {
        self.reader_route
    }
    /// The profile the strict reader recognised and enforced; `None` on the
    /// legacy route, which recognises none.
    #[must_use]
    pub fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }
    /// The capability signal of the reader that built this binding.
    #[must_use]
    pub fn reader_capability(&self) -> String {
        READER_CAPABILITY.signal()
    }
    /// Parity of the reader's rules with the normative schema (see
    /// [`TALOMNIA_SCHEMA_PIN`]).
    #[must_use]
    pub fn schema_parity(&self) -> SchemaParity {
        self.enforced_parity.unwrap_or_else(schema_parity)
    }
    /// The execution-profile gate: true only for a binding the strict reader produced for
    /// `profile` over a VERIFIED pin, by a reader whose capability names that profile. A label is
    /// not enforcement: a binding with no verified pin behind it, a legacy binding, or a profile
    /// this build cannot enforce never satisfies it.
    #[must_use]
    pub fn satisfies_profile(&self, profile: &str) -> bool {
        self.reader_route == ReaderRoute::Strict
            && self.profile.as_deref() == Some(profile)
            && READER_CAPABILITY.supports(profile)
            && matches!(
                self.enforced_parity,
                Some(SchemaParity::PinnedVerified | SchemaParity::PinnedVerifiedUnmerged)
            )
    }

    /// How the effective policy was tied to the digested bytes.
    #[must_use]
    pub fn policy_binding(&self) -> PolicyBinding {
        self.policy_binding
    }
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
    /// The digest verified, but an envelope field that sets the effective policy
    /// (`projection`, `tools`) is not what the verified bytes say, or cannot be
    /// tied to them at all. The envelope is not covered by the digest.
    PolicyUnbound { digest: String, detail: String },
    /// Strict profile: a required profile member (`body.tools`, `profile` or
    /// `allow`) is absent. Never read as a default or as deny-all.
    ProfileRequired { digest: String, detail: String },
    /// Strict profile: the profile members are present but invalid — unknown or
    /// wrong-typed fields, vocabulary, ordering, duplicates, shape.
    ProfileInvalid { digest: String, detail: String },
    /// Strict profile: the digested bytes are not the exact canonical form —
    /// duplicate keys, non-canonical bytes under a matching hash, or a
    /// preimage that is not `canonical(body) ‖ canonical(closure_manifest)`.
    CanonicalInvalid { digest: String, detail: String },
    /// Strict profile: the policy source behind a non-empty allow is missing,
    /// inadmissible, conflicting or unsupported.
    PolicySourceUnresolved { digest: String, detail: String },
    /// This reader cannot enforce the requested profile. Raised before any
    /// contract bytes are examined.
    ReaderUnsupported { requested: String, detail: String },
    /// The digested bytes (or the envelope marker) name a tools profile, but the legacy route was
    /// asked to read them. The legacy route recognises no profile and enforces none, so omitting
    /// `--contract-profile` must not turn profile-marked bytes into a legacy contract.
    ProfileRouteRequired { digest: String, detail: String },
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
            Self::PolicyUnbound { .. } => "CONTRACT_POLICY_UNBOUND",
            Self::ProfileRequired { .. } => "CONTRACT_PROFILE_REQUIRED",
            Self::ProfileInvalid { .. } => "CONTRACT_PROFILE_INVALID",
            Self::CanonicalInvalid { .. } => "CONTRACT_CANONICAL_INVALID",
            Self::PolicySourceUnresolved { .. } => "CONTRACT_POLICY_SOURCE_UNRESOLVED",
            Self::ReaderUnsupported { .. } => "CONTRACT_READER_UNSUPPORTED",
            Self::ProfileRouteRequired { .. } => "CONTRACT_PROFILE_ROUTE_REQUIRED",
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
            Self::PolicyUnbound { digest, detail } => write!(
                f,
                "{code}: the envelope returned for {digest} sets policy that the digested bytes do \
                 not carry ({detail}); refused before the first model call"
            ),
            Self::ProfileRequired { digest, detail } => write!(
                f,
                "{code}: the contract {digest} omits a member the strict profile requires \
                 ({detail}); refused before the first model call"
            ),
            Self::ProfileInvalid { digest, detail } => write!(
                f,
                "{code}: the contract {digest} does not conform to the strict profile \
                 ({detail}); refused before the first model call"
            ),
            Self::CanonicalInvalid { digest, detail } => write!(
                f,
                "{code}: the digested bytes of {digest} are not the exact canonical form \
                 ({detail}); a matching hash is not profile conformance"
            ),
            Self::PolicySourceUnresolved { digest, detail } => write!(
                f,
                "{code}: the policy source behind the tools of {digest} is unresolved ({detail}); \
                 refused before the first model call"
            ),
            Self::ProfileRouteRequired { digest, detail } => write!(
                f,
                "{code}: the contract {digest} is marked with a tools profile ({detail}) and the \
                 legacy route enforces none; run it with --contract-profile, never as a legacy \
                 contract; refused before the first model call"
            ),
            Self::ReaderUnsupported { requested, detail } => write!(
                f,
                "{code}: this reader cannot enforce the profile `{requested}` ({detail}); \
                 capability: {}",
                READER_CAPABILITY.signal()
            ),
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
    verify_with(expected, document, ReaderMode::Legacy)
}

/// [`verify`] with an explicit [`ReaderMode`].
///
/// `Legacy` is the shipped route, recorded as such on the binding. `Strict`
/// runs the profile validator over the bytes that were just re-hashed — the same
/// digest check, the same envelope-vs-bytes binding, one more validator — and
/// never takes the default allowlist, an opaque preimage, a serde-default
/// `allow`, set normalisation or a non-Argana preimage route.
///
/// # Errors
/// Every way the binding cannot be made, as [`ContractRefusal`].
pub fn verify_with(
    expected: &str,
    document: &ContractDocument,
    mode: ReaderMode<'_>,
) -> Result<ContractBinding, ContractRefusal> {
    verify_with_pin(expected, document, mode, TALOMNIA_SCHEMA_PIN.as_ref())
}

/// The capability and pin checks a strict read needs BEFORE any contract byte is examined: the
/// profile must be one this build enforces, and the schema pin must exist and match the compiled-in
/// bytes. Returns the verified pin.
fn strict_gate<'p>(
    profile: &str,
    pin: Option<&'p SchemaPin>,
) -> Result<&'p SchemaPin, ContractRefusal> {
    if !READER_CAPABILITY.supports(profile) {
        return Err(ContractRefusal::ReaderUnsupported {
            requested: profile.to_owned(),
            detail: "no strict reader for that profile is built into this binary".to_owned(),
        });
    }
    let Some(pin) = pin else {
        return Err(ContractRefusal::ReaderUnsupported {
            requested: profile.to_owned(),
            detail: "no talomnia schema is pinned, so the profile cannot be enforced".to_owned(),
        });
    };
    verify_pin(pin).map_err(|detail| ContractRefusal::ReaderUnsupported {
        requested: profile.to_owned(),
        detail: format!("the pinned talomnia schema does not match: {detail}"),
    })?;
    Ok(pin)
}

/// [`verify_with`] against an explicit schema pin. Production code uses [`verify_with`]
/// ([`TALOMNIA_SCHEMA_PIN`]); this exists so a missing or mismatching pin can be exercised.
///
/// In `Strict` mode the pin is checked BEFORE any contract byte is examined: no pin, or compiled-in
/// schema bytes that differ from the pinned blobs, is `CONTRACT_READER_UNSUPPORTED`.
///
/// # Errors
/// Every way the binding cannot be made, as [`ContractRefusal`].
pub fn verify_with_pin(
    expected: &str,
    document: &ContractDocument,
    mode: ReaderMode<'_>,
    pin: Option<&SchemaPin>,
) -> Result<ContractBinding, ContractRefusal> {
    let strict_pin = match mode {
        ReaderMode::Strict { profile } => Some(strict_gate(profile, pin)?),
        ReaderMode::Legacy => None,
    };
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

    if let ReaderMode::Strict { profile } = mode {
        if preimage != DigestPreimage::CanonicalBytesB64 {
            return Err(ContractRefusal::CanonicalInvalid {
                digest: expected.to_owned(),
                detail: format!(
                    "the preimage came from `{}`; the strict profile accepts only \
                     canonical.bytes_b64",
                    preimage.as_str()
                ),
            });
        }
        let Some(pin) = strict_pin else {
            return Err(ContractRefusal::ReaderUnsupported {
                requested: profile.to_owned(),
                detail: "no verified talomnia schema pin for the strict reader".to_owned(),
            });
        };
        let policy = strict::derive(expected, profile, &bytes, document, pin)?;
        return Ok(ContractBinding {
            digest: expected.to_owned(),
            kc2_revision: document.revision(),
            kc2_snapshot: document.snapshot(),
            allowlist: policy.allow.iter().cloned().collect(),
            allowlist_source: AllowlistSource::Contract,
            preimage,
            policy_binding: PolicyBinding::DerivedFromCanonicalBytes,
            projection: serde_json::to_string_pretty(&policy.projection)
                .unwrap_or_else(|_| policy.projection.to_string()),
            reader_route: ReaderRoute::Strict,
            profile: Some(profile.to_owned()),
            enforced_parity: Some(schema_parity_of(Some(pin))),
        });
    }

    // R2: the legacy route enforces no profile, so it must never take a profile-marked contract.
    // Without this, omitting the flag turned bytes that a strict reader refuses (or that need its
    // checks) into a legacy binding with the contract's own `allow`.
    if let Some(why) = strict::profile_mark(&bytes, document) {
        return Err(ContractRefusal::ProfileRouteRequired {
            digest: expected.to_owned(),
            detail: why,
        });
    }

    let policy = derive_policy(expected, &bytes, document)?;

    let (allowlist, allowlist_source) = match policy.tools.as_ref() {
        Some(tools) => (
            tools.allow.iter().cloned().collect::<BTreeSet<_>>(),
            AllowlistSource::Contract,
        ),
        None => (
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
        policy_binding: policy.binding,
        projection: policy.projection,
        reader_route: ReaderRoute::Legacy,
        profile: None,
        enforced_parity: None,
    })
}

/// The effective policy, read out of the verified bytes.
struct DerivedPolicy {
    binding: PolicyBinding,
    projection: String,
    tools: Option<ContractTools>,
}

/// Tie the envelope's `projection` and `tools` to the bytes that were hashed.
///
/// The digest covers `canonical(body) ‖ canonical(closure_manifest)` and nothing
/// else. `projection` (what the model reads) and `tools` (what it may call) sit
/// OUTSIDE it, so a transport that keeps the bytes and swaps either would
/// otherwise change the effective policy under an intact digest. The rule here:
/// the effective values come from the verified bytes; an envelope copy is only
/// ever compared, never adopted, and a copy that differs refuses.
///
/// No canonicalisation is performed. The two halves are parsed as the JSON
/// values they are and the envelope is compared as values, so a re-ordering that
/// the canonicaliser would have fixed cannot make a different policy equal.
/// The accepted Argana schema has no tool field, so a body without `tools` yields
/// the no-shell default and an envelope `tools` is refused rather than believed.
fn derive_policy(
    digest: &str,
    bytes: &[u8],
    document: &ContractDocument,
) -> Result<DerivedPolicy, ContractRefusal> {
    let unbound = |detail: String| ContractRefusal::PolicyUnbound {
        digest: digest.to_owned(),
        detail,
    };
    let text = std::str::from_utf8(bytes).map_err(|err| ContractRefusal::Unverifiable {
        digest: digest.to_owned(),
        detail: format!("the digested bytes are not UTF-8: {err}"),
    })?;

    let Some((body, manifest)) = split_halves(text) else {
        // Opaque preimage: the only thing tied to the digest is the text itself.
        if document.tools.is_some() {
            return Err(unbound(
                "the preimage has no body/closure_manifest structure to carry a tool \
                 allowlist, and an envelope allowlist is not covered by the digest"
                    .to_owned(),
            ));
        }
        match &document.projection {
            Value::Null => {}
            Value::String(shown) if shown == text => {}
            _ => {
                return Err(unbound(
                    "the envelope projection is not the opaque preimage text".to_owned(),
                ))
            }
        }
        return Ok(DerivedPolicy {
            binding: PolicyBinding::OpaquePreimageText,
            projection: text.to_owned(),
            tools: None,
        });
    };

    let derived_projection = serde_json::json!({ "body": body, "closure_manifest": manifest });
    match &document.projection {
        Value::Null => {}
        shown if *shown == derived_projection => {}
        _ => {
            return Err(unbound(
                "the envelope projection differs from the body/closure_manifest in the digested \
                 bytes"
                    .to_owned(),
            ))
        }
    }

    let derived_tools = match body.get("tools") {
        None => None,
        Some(value) => Some(
            serde_json::from_value::<ContractTools>(value.clone())
                .map_err(|err| unbound(format!("body.tools is not a tool allowlist: {err}")))?,
        ),
    };
    if let Some(shown) = document.tools.as_ref() {
        if derived_tools.as_ref() != Some(shown) {
            return Err(unbound(
                "the envelope tools differ from the tools in the digested bytes".to_owned(),
            ));
        }
    }
    Ok(DerivedPolicy {
        binding: PolicyBinding::DerivedFromCanonicalBytes,
        projection: serde_json::to_string_pretty(&derived_projection)
            .unwrap_or_else(|_| derived_projection.to_string()),
        tools: derived_tools,
    })
}

/// `text` as exactly two concatenated JSON objects, or `None`.
fn split_halves(text: &str) -> Option<(Value, Value)> {
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<Value>();
    let body = stream.next()?.ok()?;
    let manifest = stream.next()?.ok()?;
    if stream.next().is_some() || stream.byte_offset() != text.len() {
        return None;
    }
    (body.is_object() && manifest.is_object()).then_some((body, manifest))
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
