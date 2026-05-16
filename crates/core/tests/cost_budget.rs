//! CostTracker budget enforcement contract.
//!
//! After `record_llm_call($0.02)`, a call to `check_budget(Some(0.01))`
//! MUST return `Err(BudgetExceeded)`. Atomics are exercised under
//! `Arc`-shared concurrent access.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use std::sync::Arc;
use std::thread;

use arcana_core::cost::{BudgetExceeded, CostTracker};

#[test]
fn check_budget_returns_err_when_cap_exceeded() {
    let tracker = CostTracker::new();
    tracker.record_llm_call("haiku", 100, 50, 0.02);

    let result = tracker.check_budget(Some(0.01));

    assert!(matches!(result, Err(BudgetExceeded { .. })));
}

#[test]
fn check_budget_returns_ok_when_below_cap() {
    let tracker = CostTracker::new();
    tracker.record_llm_call("haiku", 100, 50, 0.005);

    let result = tracker.check_budget(Some(0.01));

    assert!(result.is_ok());
}

#[test]
fn check_budget_none_cap_is_always_ok() {
    let tracker = CostTracker::new();
    tracker.record_llm_call("opus", 10_000, 10_000, 99.99);

    let result = tracker.check_budget(None);

    assert!(result.is_ok());
}

#[test]
fn snapshot_aggregates_total_tokens_and_cost() {
    let tracker = CostTracker::new();
    tracker.record_llm_call("haiku", 100, 50, 0.01);
    tracker.record_llm_call("sonnet", 200, 75, 0.03);

    let snap = tracker.snapshot();

    assert_eq!(snap.total_tokens_in, 300);
    assert_eq!(snap.total_tokens_out, 125);
    assert_eq!(snap.total_cost_usd_micros, 40_000);
    assert_eq!(snap.total_calls, 2);
}

#[test]
fn concurrent_record_calls_are_atomic() {
    let tracker = Arc::new(CostTracker::new());
    let threads: Vec<_> = (0..10)
        .map(|_| {
            let t = Arc::clone(&tracker);
            thread::spawn(move || {
                for _ in 0..100 {
                    t.record_llm_call("haiku", 1, 1, 0.0001);
                }
            })
        })
        .collect();

    for handle in threads {
        handle.join().unwrap();
    }

    let snap = tracker.snapshot();
    assert_eq!(snap.total_calls, 1000);
    assert_eq!(snap.total_tokens_in, 1000);
    assert_eq!(snap.total_tokens_out, 1000);
    assert_eq!(snap.total_cost_usd_micros, 100_000);
}

#[test]
fn budget_exceeded_carries_observed_and_cap() {
    let tracker = CostTracker::new();
    tracker.record_llm_call("haiku", 0, 0, 0.05);

    let err = tracker.check_budget(Some(0.01)).unwrap_err();

    assert!((err.observed_usd - 0.05).abs() < 1e-9);
    assert!((err.cap_usd - 0.01).abs() < 1e-9);
}
