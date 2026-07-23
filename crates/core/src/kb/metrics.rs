//! Cascade instrumentation — the two decisive rates ARAS-0049 deferred to a
//! measured v2 (backlog ARAS-0054):
//!
//! * **`source_fetch_trigger_rate`** — fraction of retrievals that escalated
//!   past the chunk to a `POST /v1/fetch` (parent-section or full-source)
//!   instead of serving the chunk directly. High → the chunk-first default is
//!   rarely sufficient (a Contextual-Retrieval / ingest signal).
//! * **`over_fetch_rate`** — fraction of *fetches* whose returned body exceeded
//!   the size-guard budget and had to be windowed/truncated, i.e. we paid for
//!   bytes we could not admit. High → the escalation over-reached (a
//!   server-side-expansion / cap-tuning signal).
//!
//! The counters are **purely additive observability** — they never change the
//! cascade's decisions. Each `admit` records one observation from signals the
//! cascade already produced (`EscalationOutcome`, `from_cache`, `size_guarded`),
//! so instrumentation adds no new I/O and no new branches on the hot path. A
//! structured [`MetricsSnapshot`] is emitted per admit through the crate's
//! existing `tracing` idiom (`target: "kb.cascade"`); the live counters are also
//! readable in-process for tests and for a future metrics-exporter sink.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use super::cascade::EscalationOutcome;

/// Running cascade counters. All fields are monotonic atomic counters, so
/// `record` needs only `&self` (the cascade admits behind a shared reference)
/// and is safe to share across the agent's concurrent retrievals.
#[derive(Debug, Default)]
pub struct CascadeMetrics {
    total: AtomicU64,
    escalated: AtomicU64,
    chunk_served: AtomicU64,
    fetches: AtomicU64,
    over_fetches: AtomicU64,
}

impl CascadeMetrics {
    /// A fresh zeroed counter set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one completed admission from the signals the cascade already
    /// produced. Additive only — callers pass what `admit` computed:
    /// the [`EscalationOutcome`], whether the body came from the session cache
    /// (`from_cache`), and whether the size-guard windowed it (`size_guarded`).
    ///
    /// * every admission bumps `total`;
    /// * a chunk-served admission bumps `chunk_served`; an escalated one bumps
    ///   `escalated` (the fetch *trigger* — counted whether or not the body was
    ///   then served from cache, because the decision escalated past the chunk);
    /// * a `POST /v1/fetch` that actually hit the network (escalated **and not**
    ///   from cache) bumps `fetches`; if that fetched body then exceeded the
    ///   size-guard budget it also bumps `over_fetches`.
    pub fn record(&self, outcome: &EscalationOutcome, from_cache: bool, size_guarded: bool) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match outcome {
            EscalationOutcome::ChunkOnly => {
                self.chunk_served.fetch_add(1, Ordering::Relaxed);
            }
            EscalationOutcome::Escalated(_) => {
                self.escalated.fetch_add(1, Ordering::Relaxed);
                // A cache hit escalated the *decision* but issued no network
                // fetch, so it is a trigger but not a fetch / over-fetch.
                if !from_cache {
                    self.fetches.fetch_add(1, Ordering::Relaxed);
                    if size_guarded {
                        self.over_fetches.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Total admissions observed.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Admissions that escalated past the chunk (fetch triggers).
    #[must_use]
    pub fn escalated(&self) -> u64 {
        self.escalated.load(Ordering::Relaxed)
    }

    /// Admissions served directly from the chunk (no escalation).
    #[must_use]
    pub fn chunk_served(&self) -> u64 {
        self.chunk_served.load(Ordering::Relaxed)
    }

    /// Escalations that actually issued a `POST /v1/fetch` (cache misses).
    #[must_use]
    pub fn fetches(&self) -> u64 {
        self.fetches.load(Ordering::Relaxed)
    }

    /// Fetches whose body exceeded the size-guard budget (over-fetched bytes).
    #[must_use]
    pub fn over_fetches(&self) -> u64 {
        self.over_fetches.load(Ordering::Relaxed)
    }

    /// Fraction of retrievals that escalated to a fetch vs served the chunk.
    /// `0.0` when nothing has been observed yet.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn source_fetch_trigger_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        self.escalated() as f64 / total as f64
    }

    /// Fraction of *fetches* whose body exceeded the size-guard budget. `0.0`
    /// when no fetch has been issued (divide-by-zero guard — the denominator is
    /// fetches, not total retrievals).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn over_fetch_rate(&self) -> f64 {
        let fetches = self.fetches();
        if fetches == 0 {
            return 0.0;
        }
        self.over_fetches() as f64 / fetches as f64
    }

    /// An immutable, serializable point-in-time view — the structured record
    /// emitted to `tracing` and consumable by a future metrics exporter.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total: self.total(),
            escalated: self.escalated(),
            chunk_served: self.chunk_served(),
            fetches: self.fetches(),
            over_fetches: self.over_fetches(),
            source_fetch_trigger_rate: self.source_fetch_trigger_rate(),
            over_fetch_rate: self.over_fetch_rate(),
        }
    }
}

/// A serializable snapshot of [`CascadeMetrics`] — the structured observability
/// record emitted per admit and exportable to a metrics sink.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct MetricsSnapshot {
    /// Total admissions observed.
    pub total: u64,
    /// Admissions that escalated past the chunk.
    pub escalated: u64,
    /// Admissions served from the chunk directly.
    pub chunk_served: u64,
    /// Escalations that issued a network fetch.
    pub fetches: u64,
    /// Fetches that exceeded the size-guard budget.
    pub over_fetches: u64,
    /// `escalated / total`.
    pub source_fetch_trigger_rate: f64,
    /// `over_fetches / fetches`.
    pub over_fetch_rate: f64,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use std::sync::Arc;

    use super::super::cascade::{EscalationLevel, KbCascade, RetrievedChunk};
    use super::super::size_guard::SizeGuard;
    use super::super::{
        EscalationOutcome, EvidenceFetch, FetchRange, FetchUnavailable, FetchedEvidence,
    };
    use super::*;

    // ---- unit: the counter arithmetic -----------------------------------

    #[test]
    fn empty_metrics_report_zero_rates_without_dividing_by_zero() {
        let m = CascadeMetrics::new();
        assert_eq!(m.total(), 0);
        assert_eq!(m.source_fetch_trigger_rate(), 0.0);
        assert_eq!(m.over_fetch_rate(), 0.0);
    }

    #[test]
    fn chunk_served_moves_only_chunk_counter() {
        let m = CascadeMetrics::new();
        m.record(&EscalationOutcome::ChunkOnly, false, false);
        assert_eq!(m.total(), 1);
        assert_eq!(m.chunk_served(), 1);
        assert_eq!(m.escalated(), 0);
        assert_eq!(m.fetches(), 0);
        assert_eq!(m.source_fetch_trigger_rate(), 0.0);
    }

    #[test]
    fn escalated_network_fetch_counts_as_trigger_and_fetch() {
        let m = CascadeMetrics::new();
        m.record(
            &EscalationOutcome::Escalated(EscalationLevel::FullSource),
            false,
            false,
        );
        assert_eq!(m.escalated(), 1);
        assert_eq!(m.fetches(), 1);
        assert_eq!(m.over_fetches(), 0);
        assert_eq!(m.source_fetch_trigger_rate(), 1.0);
        assert_eq!(m.over_fetch_rate(), 0.0);
    }

    #[test]
    fn cache_hit_escalation_is_a_trigger_but_not_a_fetch() {
        let m = CascadeMetrics::new();
        // from_cache = true → decision escalated, but no network fetch issued.
        m.record(
            &EscalationOutcome::Escalated(EscalationLevel::ParentSection),
            true,
            true,
        );
        assert_eq!(m.escalated(), 1, "escalation is still a fetch trigger");
        assert_eq!(m.fetches(), 0, "a cache hit issues no network fetch");
        assert_eq!(m.over_fetches(), 0, "no fetch → no over-fetch");
    }

    #[test]
    fn over_cap_fetch_moves_over_fetch_counter() {
        let m = CascadeMetrics::new();
        m.record(
            &EscalationOutcome::Escalated(EscalationLevel::FullSource),
            false,
            true, // size_guarded → the fetched doc exceeded the budget
        );
        assert_eq!(m.fetches(), 1);
        assert_eq!(m.over_fetches(), 1);
        assert_eq!(m.over_fetch_rate(), 1.0);
    }

    #[test]
    fn mixed_workload_computes_expected_rates() {
        let m = CascadeMetrics::new();
        // 2 chunk-served, 1 fetch (fine), 1 fetch (over-cap), 1 cache-hit escalation.
        m.record(&EscalationOutcome::ChunkOnly, false, false);
        m.record(&EscalationOutcome::ChunkOnly, false, false);
        m.record(
            &EscalationOutcome::Escalated(EscalationLevel::ParentSection),
            false,
            false,
        );
        m.record(
            &EscalationOutcome::Escalated(EscalationLevel::FullSource),
            false,
            true,
        );
        m.record(
            &EscalationOutcome::Escalated(EscalationLevel::ParentSection),
            true,
            false,
        );
        assert_eq!(m.total(), 5);
        assert_eq!(m.escalated(), 3);
        assert_eq!(m.fetches(), 2);
        assert_eq!(m.over_fetches(), 1);
        // 3 of 5 retrievals escalated.
        assert_eq!(m.source_fetch_trigger_rate(), 3.0 / 5.0);
        // 1 of 2 network fetches over-fetched.
        assert_eq!(m.over_fetch_rate(), 0.5);
        let snap = m.snapshot();
        assert_eq!(snap.total, 5);
        assert_eq!(snap.over_fetch_rate, 0.5);
    }

    // ---- integration: counters move when the real cascade runs ----------

    /// A fixture connector returning a fixed body; records fetch count.
    struct FixtureFetch {
        content: String,
    }

    #[async_trait::async_trait]
    impl EvidenceFetch for FixtureFetch {
        async fn fetch(
            &self,
            source_id: &str,
            _range: FetchRange,
        ) -> Result<FetchedEvidence, FetchUnavailable> {
            Ok(FetchedEvidence {
                source_id: source_id.to_owned(),
                path: "p".into(),
                content: self.content.clone(),
                content_hash: "h-fetched".into(),
                index_snapshot_id: "snap".into(),
                namespace: "evidence".into(),
                trust_class: "evidence".into(),
                answer_offset: 0,
            })
        }
    }

    fn chunk() -> RetrievedChunk {
        RetrievedChunk {
            source_id: "src-1".into(),
            chunk_id: "c-1".into(),
            content: "chunk body".into(),
            content_hash: "h1".into(),
            index_snapshot_id: "snap".into(),
            path: "p".into(),
            trust_class: "evidence".into(),
            namespace: "evidence".into(),
            score: 0.9,
            score_margin: 0.2,
            sibling_coverage: 0,
            boundary_aligned: true,
            offset_start: 0,
            offset_end: 10,
        }
    }

    #[tokio::test]
    async fn cascade_instrumentation_tracks_chunk_escalation_and_overfetch() {
        // A large body so the tiny size-guard windows it → over-fetch signal.
        let big = (0..500)
            .map(|n| format!("w{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        let conn = Arc::new(FixtureFetch { content: big });
        // Tiny window: 40 tokens * 0.25 = cap 10 → a full fetch over-fetches.
        let cascade = KbCascade::new(Arc::clone(&conn), SizeGuard::new(40, 0.25));

        // 1) chunk-sufficient → chunk-served, no fetch.
        cascade.admit(&chunk()).await.unwrap();
        assert_eq!(cascade.metrics().chunk_served(), 1);
        assert_eq!(cascade.metrics().fetches(), 0);

        // 2) escalate (boundary misaligned) → over-cap fetch → over-fetch.
        let mut esc = chunk();
        esc.boundary_aligned = false;
        let out = cascade.admit(&esc).await.unwrap();
        assert_eq!(
            out.outcome,
            EscalationOutcome::Escalated(EscalationLevel::ParentSection)
        );
        assert!(out.size_guarded);
        assert_eq!(cascade.metrics().escalated(), 1);
        assert_eq!(cascade.metrics().fetches(), 1);
        assert_eq!(cascade.metrics().over_fetches(), 1);

        // 3) same escalation again → cache hit → trigger, but NOT a new fetch.
        cascade.admit(&esc).await.unwrap();
        assert_eq!(cascade.metrics().escalated(), 2, "still a trigger");
        assert_eq!(cascade.metrics().fetches(), 1, "cache hit issues no fetch");

        // Aggregate rates over the 3 retrievals.
        let m = cascade.metrics();
        assert_eq!(m.total(), 3);
        assert_eq!(m.source_fetch_trigger_rate(), 2.0 / 3.0);
        assert_eq!(m.over_fetch_rate(), 1.0); // 1 of 1 network fetches over-fetched
    }
}
