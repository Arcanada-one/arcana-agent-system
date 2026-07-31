//! Quota and idempotency ledger (D-REQ-03 / V-AC-3).
//!
//! The property that matters: **an accepted retry must not repeat a committed
//! provider side effect, and must not charge quota twice.** A duplicate request
//! replays the original outcome rather than performing a second operation.

use crate::protocol::{CapabilityRequest, Denial, Generation, IdempotencyKey, Lease};
use std::collections::BTreeMap;

/// A committed outcome, retained so a retry can replay rather than repeat it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Committed {
    outcome_id: String,
    provider: String,
    model: String,
    charged: u32,
}

/// Per-generation quota and idempotency state.
#[derive(Debug)]
pub struct Ledger {
    generation: Generation,
    quota_limit: u32,
    quota_spent: u32,
    committed: BTreeMap<IdempotencyKey, Committed>,
    next_outcome: u64,
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
            return Ok(Lease {
                generation: self.generation,
                provider: prior.provider.clone(),
                model: prior.model.clone(),
                operation: req.operation,
                charged: 0,
                outcome_id: prior.outcome_id.clone(),
                replayed: true,
            });
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
