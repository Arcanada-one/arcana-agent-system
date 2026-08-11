//! Quota and idempotency ledger (D-REQ-03 / V-AC-3).
//!
//! The property that matters: **an accepted retry must not repeat a committed
//! provider side effect, and must not charge quota twice.** A duplicate request
//! replays the original outcome rather than performing a second operation.

use crate::protocol::{
    CapabilityRequest, Denial, Generation, IdempotencyKey, Lease, Operation, RequestFingerprint,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A committed outcome, retained so a retry can replay rather than repeat it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct Committed {
    outcome_id: String,
    provider: String,
    model: String,
    charged: u32,
    operation: Operation,
    fingerprint: RequestFingerprint,
}

/// Per-generation quota and idempotency state.
#[derive(Debug, Deserialize, Serialize)]
pub struct Ledger {
    generation: Generation,
    quota_limit: u32,
    quota_spent: u32,
    committed: BTreeMap<IdempotencyKey, Committed>,
    next_outcome: u64,
    max_entries: usize,
}

impl Ledger {
    /// A fresh ledger for a generation.
    #[must_use]
    pub fn new(generation: Generation, quota_limit: u32) -> Self {
        Self {
            generation,
            quota_limit,
            quota_spent: 0,
            committed: BTreeMap::new(),
            next_outcome: 1,
            max_entries: 4096,
        }
    }

    /// Quota units consumed so far.
    #[must_use]
    pub fn quota_spent(&self) -> u32 {
        self.quota_spent
    }

    /// Number of distinct committed operations.
    #[must_use]
    pub fn committed_count(&self) -> usize {
        self.committed.len()
    }

    /// Whether durable state belongs to the exact running policy generation.
    #[must_use]
    pub fn matches_policy(&self, generation: Generation, quota_limit: u32) -> bool {
        self.generation == generation && self.quota_limit == quota_limit
    }

    /// Validate invariants that untrusted durable bytes cannot be allowed to
    /// violate after deserialization.
    #[must_use]
    pub fn durable_invariants_hold(&self) -> bool {
        if self.max_entries != 4096
            || self.committed.len() > self.max_entries
            || self.quota_spent > self.quota_limit
            || self.next_outcome != self.committed.len() as u64 + 1
        {
            return false;
        }
        let mut charged = 0u32;
        let mut outcomes = std::collections::BTreeSet::new();
        for committed in self.committed.values() {
            let Some(sequence) = committed
                .outcome_id
                .strip_prefix("outcome-")
                .and_then(|value| value.parse::<u64>().ok())
            else {
                return false;
            };
            if sequence == 0
                || sequence >= self.next_outcome
                || !outcomes.insert(sequence)
                || committed.provider.is_empty()
                || committed.model.is_empty()
                || committed.fingerprint.0.is_empty()
                || committed.charged == 0
            {
                return false;
            }
            let Some(total) = charged.checked_add(committed.charged) else {
                return false;
            };
            charged = total;
        }
        charged == self.quota_spent && outcomes.len() == self.committed.len()
    }

    /// Outcome identity associated with a committed idempotency key.
    #[must_use]
    pub fn outcome_id_for(&self, key: &IdempotencyKey) -> Option<&str> {
        self.committed
            .get(key)
            .map(|entry| entry.outcome_id.as_str())
    }

    /// Commit a policy-approved request, or replay an already-committed one.
    ///
    /// `check` on the policy MUST have succeeded before this is called.
    ///
    /// # Errors
    /// [`Denial::QuotaExceeded`] when the request would exceed the generation's
    /// quota. A replay never fails on quota: it is not a new charge.
    pub fn commit(&mut self, req: &CapabilityRequest) -> Result<Lease, Denial> {
        // Replay path. A retry carrying a known key returns the original
        // outcome verbatim: same outcome id, no second side effect, no second
        // charge. The provider is never called again.
        if let Some(prior) = self.committed.get(&req.idempotency) {
            if prior.fingerprint != req.fingerprint {
                return Err(Denial::IdempotencyConflict);
            }
            return Ok(Lease {
                generation: self.generation,
                provider: prior.provider.clone(),
                model: prior.model.clone(),
                operation: prior.operation,
                charged: 0,
                outcome_id: prior.outcome_id.clone(),
                replayed: true,
            });
        }

        if self.committed.len() >= self.max_entries {
            return Err(Denial::IdempotencyCapacity);
        }

        let would_spend = self.quota_spent.saturating_add(req.quota_units);
        if would_spend > self.quota_limit {
            return Err(Denial::QuotaExceeded);
        }

        let outcome_id = format!("outcome-{:08}", self.next_outcome);
        self.next_outcome += 1;
        self.quota_spent = would_spend;
        self.committed.insert(
            req.idempotency.clone(),
            Committed {
                outcome_id: outcome_id.clone(),
                provider: req.provider.clone(),
                model: req.model.clone(),
                charged: req.quota_units,
                operation: req.operation,
                fingerprint: req.fingerprint.clone(),
            },
        );

        Ok(Lease {
            generation: self.generation,
            provider: req.provider.clone(),
            model: req.model.clone(),
            operation: req.operation,
            charged: req.quota_units,
            outcome_id,
            replayed: false,
        })
    }
}
