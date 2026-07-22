//! Content-addressed **session** cache, keyed on
//! `(source_id, content_hash, range_key)`.
//!
//! The cache short-circuits a re-fetch of the same source at the same ingest
//! version within one agent session. The key pairs the opaque `source_id` with
//! the KB's ingest-bound `content_hash`, which the `SearchHit` now carries — so
//! a staleness change (the live file re-ingested under a new hash) is a natural
//! cache MISS: a different `content_hash` never collides with the old entry, and
//! the cascade re-fetches rather than serving stale bytes. The `content_hash` is
//! used here purely as a cache/staleness discriminator, never as a trust anchor.
//!
//! The key also carries a `range_key` (the escalation [`FetchRange`] discriminant)
//! so a later different-range escalation for the same source+hash does not get
//! served the first range's body/answer-offset.

use std::collections::HashMap;
use std::sync::Mutex;

use super::envelope::Provenance;
use super::size_guard::EvidenceBody;

/// A cached, already-trust-fenced evidence body plus its provenance.
#[derive(Debug, Clone)]
pub struct CachedEvidence {
    /// The fetched evidence body (pre-size-guard, post-trust-fence).
    pub body: EvidenceBody,
    /// The out-of-band provenance captured at fetch time.
    pub provenance: Provenance,
}

/// A per-session content-addressed cache.
///
/// Interior-mutable behind a `Mutex` — the map is a composite (key → value)
/// invariant, so this is the project's sanctioned `Mutex` case, not an
/// atomic-counter case.
#[derive(Debug, Default)]
pub struct SessionCache {
    inner: Mutex<HashMap<(String, String, String), CachedEvidence>>,
}

impl SessionCache {
    /// A fresh, empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Look up the entry for `(source_id, content_hash, range_key)`. A different
    /// `content_hash` (staleness) or `range_key` (different escalation range) for
    /// the same `source_id` is a MISS → refetch.
    #[must_use]
    pub fn get(
        &self,
        source_id: &str,
        content_hash: &str,
        range_key: &str,
    ) -> Option<CachedEvidence> {
        let key = (
            source_id.to_owned(),
            content_hash.to_owned(),
            range_key.to_owned(),
        );
        self.inner
            .lock()
            .ok()
            .and_then(|map| map.get(&key).cloned())
    }

    /// Insert (or replace) the entry for `(source_id, content_hash, range_key)`.
    pub fn put(&self, source_id: &str, content_hash: &str, range_key: &str, value: CachedEvidence) {
        let key = (
            source_id.to_owned(),
            content_hash.to_owned(),
            range_key.to_owned(),
        );
        if let Ok(mut map) = self.inner.lock() {
            map.insert(key, value);
        }
    }

    /// Number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |map| map.len())
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn entry(text: &str, hash: &str) -> CachedEvidence {
        CachedEvidence {
            body: EvidenceBody::whole(text),
            provenance: Provenance {
                source_id: "src-1".into(),
                content_hash: hash.into(),
                ..Provenance::default()
            },
        }
    }

    #[test]
    fn put_then_get_same_key_hits() {
        let cache = SessionCache::new();
        cache.put("src-1", "h1", "full", entry("doc body", "h1"));
        let got = cache.get("src-1", "h1", "full").expect("hit");
        assert_eq!(got.body.text, "doc body");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn changed_content_hash_is_a_miss_staleness() {
        let cache = SessionCache::new();
        cache.put("src-1", "h1", "full", entry("stale body", "h1"));
        // Same source_id, new ingest hash → MISS (do not serve stale bytes).
        assert!(cache.get("src-1", "h2", "full").is_none());
    }

    #[test]
    fn different_source_id_is_a_miss() {
        let cache = SessionCache::new();
        cache.put("src-1", "h1", "full", entry("body", "h1"));
        assert!(cache.get("src-2", "h1", "full").is_none());
    }

    #[test]
    fn different_range_key_is_a_miss() {
        let cache = SessionCache::new();
        // First escalation cached the parent-section range.
        cache.put("src-1", "h1", "parent:chunk-7", entry("parent body", "h1"));
        // A later full-source escalation for the same source+hash must NOT be
        // served the parent range's body/answer-offset — it is a MISS.
        assert!(cache.get("src-1", "h1", "full").is_none());
        // …but the original range still hits.
        assert!(cache.get("src-1", "h1", "parent:chunk-7").is_some());
    }
}
