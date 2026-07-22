//! The skill-storage seam — a pluggable byte-acquisition backend behind the
//! interpreter.
//!
//! A [`SkillStore`] turns a config-authored [`SkillPin`] into a validated
//! [`SkillPlan`]. Two backends exist this cycle:
//!
//! * [`FileStore`] — the trusted local path (today's `fs::read` + parse,
//!   byte-identical). The local file *is* the trust root, so it performs no
//!   blake3 verification.
//! * [`ScrutatorStore`] — the untrusted KB path. Bytes fetched over the network
//!   are rejected **before parse** unless their locally-recomputed full blake3
//!   equals the config-pinned hash (the trust keystone). A blake3-content-
//!   addressed [`BlakeCache`] short-circuits the network; a store failure with
//!   no verified cache entry fails closed to [`SkillError::StoreUnavailable`] —
//!   it never falls back to a different or stale skill.
//!
//! **Two-phase firewall.** A [`SkillCandidate`] (a fuzzy search proposal) can
//! only *propose*; it carries no `blake3` and no authorization to run. A
//! [`SkillPin`] (the authorization to run) is config-authored. There is
//! deliberately no `SkillCandidate` → `SkillPin` conversion: search proposes,
//! config authorizes.

use std::collections::BTreeSet;

use crate::interpreter::SkillError;
use crate::plan::{Maturity, SkillPlan};

/// A config-authored, pinned reference to a skill's exact bytes.
///
/// `blake3` and `source_id` are supplied from **trusted config** at
/// pin-authoring time — never derived from a fuzzy [`SkillCandidate`]. This is
/// the load-bearing half of the two-phase firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillPin {
    /// Human-readable skill name (informational).
    pub name: String,
    /// Pinned content version (informational).
    pub version: u32,
    /// Full blake3 hex of the exact content bytes — the sole run-path trust
    /// anchor. Empty for a [`FileStore`] pin (the local file is trusted).
    pub blake3: String,
    /// Opaque KB `source_id` (or, for [`FileStore`], the local file path).
    pub source_id: String,
}

impl SkillPin {
    /// Construct a network pin from trusted config values.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: u32,
        blake3: impl Into<String>,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version,
            blake3: blake3.into(),
            source_id: source_id.into(),
        }
    }

    /// Construct a pin for a trusted local file: no network hash anchor is
    /// required because the local filesystem is the trust root.
    #[must_use]
    pub fn local(path: impl Into<String>) -> Self {
        Self {
            name: String::new(),
            version: 0,
            blake3: String::new(),
            source_id: path.into(),
        }
    }
}

/// A fuzzy search proposal for a skill. Deliberately carries **no** `blake3`
/// and **no** run authorization.
///
/// `content_hash` is the KB's SHA-256 ingest-bound digest — a cache/staleness
/// signal only, of a different algorithm and role from the run-path blake3
/// trust anchor. There is intentionally no path from a `SkillCandidate` to a
/// [`SkillPin`]: a candidate can only *propose* a skill to a human/config
/// author, who then pins it.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillCandidate {
    /// Proposed skill name.
    pub name: String,
    /// Proposed skill version.
    pub version: u32,
    /// SHA-256 ingest digest — a staleness signal, **never** a trust anchor.
    pub content_hash: String,
    /// Proposed maturity (advisory; the run-path floor is re-checked on load).
    pub maturity: Maturity,
    /// Relevance score from the search backend.
    pub score: f64,
}

/// A pluggable byte-acquisition backend for skill plans.
#[async_trait::async_trait]
pub trait SkillStore: Send + Sync {
    /// Resolve `pin` to a validated [`SkillPlan`].
    ///
    /// # Errors
    ///
    /// Returns [`SkillError`] on read/fetch failure, a blake3 mismatch (before
    /// parse), a parse failure, or intrinsic-validation failure.
    async fn load(&self, pin: &SkillPin) -> Result<SkillPlan, SkillError>;
}

/// The trusted local-filesystem store: reads and parses the plan file at
/// `pin.source_id`, byte-identical to the legacy `fs::read` + `from_slice`.
///
/// Performs **no** blake3 verification — the local file is the trust root
/// (GAP-2: the blake3 keystone anchors the *untrusted* network path only).
#[derive(Debug, Default, Clone, Copy)]
pub struct FileStore;

#[async_trait::async_trait]
impl SkillStore for FileStore {
    async fn load(&self, pin: &SkillPin) -> Result<SkillPlan, SkillError> {
        let bytes = std::fs::read(&pin.source_id).map_err(|source| SkillError::Read {
            path: pin.source_id.clone(),
            source,
        })?;
        let plan: SkillPlan = serde_json::from_slice(&bytes).map_err(SkillError::Parse)?;
        plan.validate()?;
        Ok(plan)
    }
}

/// The per-agent **enforced** tool ceiling. A plan stage may only declare tools
/// within this set — it can narrow the authority, never widen it (V-AC-4). When
/// no ceiling is configured on the interpreter the declared `tools` remain
/// advisory (the Phase-1 minimal-vertical behaviour), preserving back-compat.
#[derive(Debug, Clone, Default)]
pub struct ToolCeiling {
    allowed: BTreeSet<String>,
}

impl ToolCeiling {
    /// Build a ceiling from an iterator of allowed tool names.
    pub fn new<I, S>(tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: tools.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether `tool` is within the ceiling.
    #[must_use]
    pub fn permits(&self, tool: &str) -> bool {
        self.allowed.contains(tool)
    }
}

/// The per-agent model-endpoint allowlist (V-AC-5). A stage's *resolved* model
/// id must be a member. When unconfigured, model routing is unrestricted (the
/// Phase-1 minimal-vertical behaviour).
#[derive(Debug, Clone, Default)]
pub struct ModelAllowlist {
    allowed: BTreeSet<String>,
}

impl ModelAllowlist {
    /// Build an allowlist from an iterator of allowed model ids/endpoints.
    pub fn new<I, S>(models: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: models.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether `model` is on the allowlist.
    #[must_use]
    pub fn permits(&self, model: &str) -> bool {
        self.allowed.contains(model)
    }
}
