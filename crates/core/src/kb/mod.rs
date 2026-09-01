//! `kb` — the agent-side KB interaction cascade (ratified design,
//! thin measurable v1).
//!
//! Scrutator is a stateless retrieve-resolve-provenance service that ships
//! *signals*; the **agent owns policy**. This module is where a `SearchHit`
//! becomes model-ready evidence, through the ratified 7-step cascade:
//! `retrieve → decide → escalate → size-guard → provenance → cache → grounding
//! hand-off`.
//!
//! ## Controls in force (v1)
//! * Cheapest-sufficient escalation on EXPLICIT triggers only ([`cascade`]).
//! * Content-addressed session cache keyed on `(source_id, content_hash)`
//!   ([`cache`]).
//! * Non-deferrable untrusted-content boundary: nonce-fenced datamarked
//!   envelope, provenance out-of-band, behaviour gate outside the injectable
//!   payload ([`envelope`]).
//! * Size-guard as a fraction of the model context window, with
//!   parent-section windowing + rerank-to-edge ([`size_guard`]).
//! * `trust_class` dispatch with NO cross-promotion ([`trust`]).
//!
//! ## Boundary / hand-off constraint
//! Grounding **cite-or-abstain + NLI-faithfulness stays in Argana**
//!. This module delivers sanitize + cascade only;
//! [`cascade::Admission`] is the clean hand-off seam. The abstention /
//! tool-action hard-gate ([`cascade::BehaviorGate`]) is carried OUT-of-band —
//! it MUST NOT be enforced by a prompt inside the injectable payload.
//!
//! ## Deferred to a measured v2 (NOT built here)
//! Contextual Retrieval (Feeder ingest rework), server-side expansion,
//! sentence-window / auto-merge empirical tuning, empirical size-cap tuning,
//! a RAGAS eval harness. The provenance schema is versioned behind
//! `index_snapshot_id` so a re-embed is a snapshot bump, not a breaking change.

pub mod cache;
pub mod cascade;
pub mod envelope;
pub mod eval;
pub mod metrics;
pub mod size_guard;
pub mod trust;

pub use cache::{CachedEvidence, SessionCache};
pub use cascade::{
    Admission, BehaviorGate, CascadeError, EscalationLevel, EscalationOutcome,
    EscalationThresholds, EvidenceFetch, FetchRange, FetchUnavailable, FetchedEvidence, KbCascade,
    RetrievedChunk,
};
pub use envelope::{datamark, Provenance, UntrustedEnvelope};
pub use eval::{
    evaluate, fixture_corpus, score_item, EvalReport, ItemScores, Judge, LexicalJudge, QaItem,
};
pub use metrics::{CascadeMetrics, MetricsSnapshot};
pub use size_guard::{EvidenceBody, GuardedContent, SizeGuard};
pub use trust::{
    admit_evidence, route, Dispatch, TrustClass, TrustError, EVIDENCE_TRUST_CLASS,
    SKILL_TRUST_CLASS,
};
