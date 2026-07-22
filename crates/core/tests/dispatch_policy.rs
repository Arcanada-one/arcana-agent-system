//! V-AC-2 / V-AC-3 / V-AC-5 (D-REQ-01/02/04): the pure dispatch seam.
//!
//! `ModelPolicy::select` is deterministic + table-driven (task-type → model id +
//! cost tier); `classify` is deterministic + fail-closed; the two exercised
//! task-types resolve to two distinct `CostTier` values. All offline, pure.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_core::agent_loop::HistoryEntry;
use arcana_core::cost::CostTracker;
use arcana_core::dispatch::{classify, CostTier, ModelPolicy, SelectionContext, TaskType};

/// V-AC-2: each configured task-type maps to its declared model id + cost tier,
/// and the same input always yields the same `ModelChoice` (determinism).
#[test]
fn policy_select_by_task_type() {
    let policy = ModelPolicy::new();

    let code = policy.select(TaskType::Code);
    let summarize = policy.select(TaskType::Summarize);
    let default = policy.select(TaskType::Default);

    // Table-driven tiering: code is Expensive, summarize is Cheap.
    assert_eq!(code.tier, CostTier::Expensive, "code step → expensive tier");
    assert_eq!(
        summarize.tier,
        CostTier::Cheap,
        "summarize step → cheap tier"
    );

    // Distinct model ids for the two exercised task-types (multi-model keying).
    assert_ne!(
        code.model_id, summarize.model_id,
        "code and summarize must name distinct model ids"
    );
    assert!(!default.model_id.is_empty(), "default arm has a model id");

    // Determinism: same task-type twice → identical choice.
    assert_eq!(policy.select(TaskType::Code), code);
    assert_eq!(policy.select(TaskType::Summarize), summarize);
    assert_eq!(policy.select(TaskType::Default), default);
}

#[test]
fn single_model_policy_pins_every_task_class_to_one_model() {
    let policy = ModelPolicy::single_model("deepseek-v4-flash");
    for task in [TaskType::Code, TaskType::Summarize, TaskType::Default] {
        assert_eq!(policy.select(task).model_id, "deepseek-v4-flash");
    }
}

/// V-AC-3: `classify` is deterministic and fails closed — a code-signal task →
/// `Code`, a trailing tool-result → `Summarize`, anything unrecognised (incl.
/// empty history) → `Default`; repeated calls on the same context are identical.
#[test]
fn dispatch_classify_task_type() {
    // Code-signal in the task framing → Code.
    let code_hist = vec![HistoryEntry::Task(
        "please implement this rust function".to_owned(),
    )];
    let code_ctx = SelectionContext {
        history: &code_hist,
        turn: 0,
    };
    assert_eq!(classify(&code_ctx), TaskType::Code);

    // A trailing tool-result — the next turn interprets tool output → Summarize.
    let summarize_hist = vec![
        HistoryEntry::Task("greet the world".to_owned()),
        HistoryEntry::Assistant("...".to_owned()),
        HistoryEntry::ToolResult {
            name: "echo".to_owned(),
            content: "echo:{}".to_owned(),
        },
    ];
    let summarize_ctx = SelectionContext {
        history: &summarize_hist,
        turn: 1,
    };
    assert_eq!(classify(&summarize_ctx), TaskType::Summarize);

    // No code-signal, no trailing tool-result → fail closed to Default.
    let default_hist = vec![HistoryEntry::Assistant("hello there".to_owned())];
    let default_ctx = SelectionContext {
        history: &default_hist,
        turn: 0,
    };
    assert_eq!(classify(&default_ctx), TaskType::Default);

    // Empty history → Default (fail closed, no panic).
    let empty: Vec<HistoryEntry> = Vec::new();
    let empty_ctx = SelectionContext {
        history: &empty,
        turn: 0,
    };
    assert_eq!(classify(&empty_ctx), TaskType::Default);

    // A non-code Task must NOT be classified as Code.
    let plain_hist = vec![HistoryEntry::Task("say hello to everyone".to_owned())];
    let plain_ctx = SelectionContext {
        history: &plain_hist,
        turn: 0,
    };
    assert_eq!(classify(&plain_ctx), TaskType::Default);

    // Determinism.
    assert_eq!(classify(&code_ctx), classify(&code_ctx));
    assert_eq!(classify(&summarize_ctx), classify(&summarize_ctx));
}

/// V-AC-5: cost keying is real — the two exercised task-types resolve to two
/// distinct `CostTier` values, and aggregate cost accrues across a multi-model
/// run in the existing `CostTracker` snapshot (§ inline-resolved gap: aggregate
/// accrual, not a per-model breakdown — `cost.rs` is unchanged).
#[test]
fn dispatch_cost_tier_distinct() {
    let policy = ModelPolicy::new();

    // Two distinct tiers for the two exercised task-types.
    assert_ne!(
        policy.select(TaskType::Code).tier,
        policy.select(TaskType::Summarize).tier,
        "code and summarize must resolve to distinct cost tiers"
    );

    // Aggregate accrual across the two-model run: two calls, non-zero cost.
    let tracker = CostTracker::new();
    let code = policy.select(TaskType::Code);
    let summarize = policy.select(TaskType::Summarize);
    tracker.record_llm_call(&code.model_id, 10, 20, 0.010);
    tracker.record_llm_call(&summarize.model_id, 5, 8, 0.002);
    let snap = tracker.snapshot();
    assert!(snap.total_calls >= 2, "both calls accrue in the snapshot");
    assert!(
        snap.total_cost_usd_micros > 0,
        "aggregate cost grows over the multi-model run"
    );
}
