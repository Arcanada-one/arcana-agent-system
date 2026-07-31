//! Metadata-only causal audit (D-REQ-06 / V-AC-5).
//!
//! The secret-safety property here is **structural, not procedural**. An audit
//! record has no free-form payload field, so there is nowhere for a credential
//! value, response body or transcript excerpt to be placed — not by a careless
//! caller, not by a future edit that "just needs to log the response". Every
//! field is an identifier, a timestamp, a status, a count or a hash.

use crate::protocol::{Denial, Generation, Operation};
use std::fmt;

/// The causal identifiers a record carries. Any of these may be absent for a
/// given event, but none of them can hold content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CausalIds {
    /// Incident this event belongs to.
    pub incident: Option<String>,
    /// Execution (agent turn / job) identifier.
    pub execution: Option<String>,
    /// Host boot identifier, so pre- and post-restart events are separable.
    pub host_boot: Option<String>,
    /// Process-tree identifier.
    pub process_tree: Option<String>,
    /// Pane or session identifier.
    pub pane_session: Option<String>,
    /// Credential identifier and version — never the credential.
    pub credential_id: Option<String>,
    /// Credential version.
    pub credential_version: Option<u32>,
    /// Broker lease identifier.
    pub lease: Option<String>,
    /// Broker generation.
    pub generation: Option<Generation>,
    /// Output-scan identifier.
    pub output_scan: Option<String>,
    /// Transcript artifact identifier.
    pub transcript_artifact: Option<String>,
    /// Provider request identifier.
    pub provider_request: Option<String>,
    /// Provider revocation identifier.
    pub provider_revocation: Option<String>,
    /// Vault accessor identifier (accessor, never token material).
    pub vault_accessor: Option<String>,
    /// Deployment identifier.
    pub deployment: Option<String>,
    /// Canary identifier.
    pub canary: Option<String>,
}

/// What happened. A closed set — an event kind cannot be invented at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    PolicyAllow,
    PolicyDeny,
    QuotaCharge,
    ReplayServed,
    OutputScanBlock,
    OutputScanPass,
    BrokerStart,
    BrokerStop,
    GenerationRejected,
}

impl EventKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAllow => "policy_allow",
            Self::PolicyDeny => "policy_deny",
            Self::QuotaCharge => "quota_charge",
            Self::ReplayServed => "replay_served",
            Self::OutputScanBlock => "output_scan_block",
            Self::OutputScanPass => "output_scan_pass",
            Self::BrokerStart => "broker_start",
            Self::BrokerStop => "broker_stop",
            Self::GenerationRejected => "generation_rejected",
        }
    }
}

/// A single metadata-only audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Unix seconds.
    pub at: u64,
    /// What happened.
    pub kind: EventKind,
    /// Causal identifiers.
    pub ids: CausalIds,
    /// Provider name (a policy key, not a secret).
    pub provider: Option<String>,
    /// Model name (a policy key, not a secret).
    pub model: Option<String>,
    /// Operation, if applicable.
    pub operation: Option<Operation>,
    /// Denial reason, if this is a denial.
    pub denial: Option<Denial>,
    /// Quota units charged by this event.
    pub charged: Option<u32>,
    /// A count, e.g. bytes scanned or copies found.
    pub count: Option<u64>,
    /// A hex digest of an artifact — never the artifact.
    pub artifact_sha256: Option<String>,
}

impl AuditRecord {
    /// A record of the given kind at the given time.
    #[must_use]
    pub fn new(at: u64, kind: EventKind) -> Self {
        Self {
            at,
            kind,
            ids: CausalIds::default(),
            provider: None,
            model: None,
            operation: None,
            denial: None,
            charged: None,
            count: None,
            artifact_sha256: None,
        }
    }
}

/// Render as a stable, greppable key=value line.
///
/// Only typed fields are rendered; there is no path by which arbitrary bytes
/// reach this output.
impl fmt::Display for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at={} event={}", self.at, self.kind.as_str())?;
        let i = &self.ids;
        for (k, v) in [
            ("incident", &i.incident),
            ("execution", &i.execution),
            ("host_boot", &i.host_boot),
            ("process_tree", &i.process_tree),
            ("pane_session", &i.pane_session),
            ("credential_id", &i.credential_id),
            ("lease", &i.lease),
            ("output_scan", &i.output_scan),
            ("transcript_artifact", &i.transcript_artifact),
            ("provider_request", &i.provider_request),
            ("provider_revocation", &i.provider_revocation),
            ("vault_accessor", &i.vault_accessor),
            ("deployment", &i.deployment),
            ("canary", &i.canary),
        ] {
            if let Some(val) = v {
                write!(f, " {k}={val}")?;
            }
        }
        if let Some(v) = i.credential_version {
            write!(f, " credential_version={v}")?;
        }
        if let Some(Generation(g)) = i.generation {
            write!(f, " generation={g}")?;
        }
        if let Some(v) = &self.provider {
            write!(f, " provider={v}")?;
        }
        if let Some(v) = &self.model {
            write!(f, " model={v}")?;
        }
        if let Some(v) = self.operation {
            write!(f, " operation={}", v.as_str())?;
        }
        if let Some(v) = &self.denial {
            write!(f, " denial={v}")?;
        }
        if let Some(v) = self.charged {
            write!(f, " charged={v}")?;
        }
        if let Some(v) = self.count {
            write!(f, " count={v}")?;
        }
        if let Some(v) = &self.artifact_sha256 {
            write!(f, " artifact_sha256={v}")?;
        }
        Ok(())
    }
}
