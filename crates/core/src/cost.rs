//! Atomic cost tracking with budget circuit breaker.
//!
//! Hot counters live in [`AtomicU64`] for lock-free updates from the agent
//! loop; the public type is [`Send`] + [`Sync`] so it can be wrapped in
//! `Arc` and shared across the dispatcher and worker threads. Costs are
//! stored as integer micro-USD (`USD * 1e6`) to avoid floating-point drift
//! across thousands of incremental updates.

// Costs are clamped to the non-negative finite domain before cast. The
// f64 → u64 conversion would only truncate for amounts above ~1.8e13 USD,
// well outside any realistic agent budget; the inverse direction stays
// inside the 2^53 mantissa range for the same reason.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]

use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

const MICROS_PER_USD: f64 = 1_000_000.0;

/// Aggregator for tokens, calls, and cost across a single agent run.
#[derive(Debug, Default)]
pub struct CostTracker {
    tokens_in: AtomicU64,
    tokens_out: AtomicU64,
    cost_usd_micros: AtomicU64,
    calls: AtomicU64,
}

impl CostTracker {
    /// Construct a fresh tracker with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one upstream LLM call's accounting fields.
    ///
    /// Negative or non-finite `usd` values clamp to zero so a misbehaving
    /// connector cannot drive the running total backwards.
    pub fn record_llm_call(&self, _model: &str, tokens_in: u32, tokens_out: u32, usd: f64) {
        let micros = if usd.is_finite() && usd > 0.0 {
            (usd * MICROS_PER_USD).round() as u64
        } else {
            0
        };
        self.tokens_in
            .fetch_add(u64::from(tokens_in), Ordering::Relaxed);
        self.tokens_out
            .fetch_add(u64::from(tokens_out), Ordering::Relaxed);
        self.cost_usd_micros.fetch_add(micros, Ordering::Relaxed);
        self.calls.fetch_add(1, Ordering::Relaxed);
    }

    /// Compare the running cost against an optional cap (USD).
    ///
    /// Returns [`Err`] when the cap is set and the accumulated cost has
    /// strictly exceeded it. A `None` cap is treated as «no limit».
    ///
    /// # Errors
    ///
    /// Returns [`BudgetExceeded`] when the observed cost is greater than
    /// the supplied cap.
    pub fn check_budget(&self, cap_usd: Option<f64>) -> Result<(), BudgetExceeded> {
        let Some(cap) = cap_usd else { return Ok(()) };
        if !cap.is_finite() || cap < 0.0 {
            return Ok(());
        }
        let observed_micros = self.cost_usd_micros.load(Ordering::Relaxed);
        let cap_micros = (cap * MICROS_PER_USD).round() as u64;
        if observed_micros > cap_micros {
            return Err(BudgetExceeded {
                observed_usd: observed_micros as f64 / MICROS_PER_USD,
                cap_usd: cap,
            });
        }
        Ok(())
    }

    /// Point-in-time copy of the aggregate counters.
    #[must_use]
    pub fn snapshot(&self) -> CostSnapshot {
        CostSnapshot {
            total_tokens_in: self.tokens_in.load(Ordering::Relaxed),
            total_tokens_out: self.tokens_out.load(Ordering::Relaxed),
            total_cost_usd_micros: self.cost_usd_micros.load(Ordering::Relaxed),
            total_calls: self.calls.load(Ordering::Relaxed),
        }
    }
}

/// Immutable copy of the tracker counters at a single instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostSnapshot {
    pub total_tokens_in: u64,
    pub total_tokens_out: u64,
    pub total_cost_usd_micros: u64,
    pub total_calls: u64,
}

/// Signalled when the running cost has crossed the configured cap.
#[derive(Debug, Clone, Copy, Error)]
#[error("cost budget exceeded: observed ${observed_usd:.6}, cap ${cap_usd:.6}")]
pub struct BudgetExceeded {
    pub observed_usd: f64,
    pub cap_usd: f64,
}
