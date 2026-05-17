//! AC-2 + AC-3: HookChain ordering invariants — first `StopExecution`
//! short-circuits the chain, and `ReplaceInput` propagates to subsequent
//! hooks and out to the dispatcher.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::match_wildcard_for_single_variants
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arcana_core::cost::CostTracker;
use arcana_core::hooks::{HookChain, HookContext, HookError, HookResult, PreToolOutcome, ToolHook};
use arcana_core::tool::ToolOutput;
use async_trait::async_trait;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

struct CountingHook {
    label: &'static str,
    calls: Arc<AtomicUsize>,
    seen_input: Mutex<Option<Value>>,
    decision: HookResult,
}

#[async_trait]
impl ToolHook for CountingHook {
    async fn pre_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        input: &Value,
    ) -> Result<HookResult, HookError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut slot) = self.seen_input.lock() {
            *slot = Some(input.clone());
        }
        let _ = self.label;
        Ok(self.decision.clone())
    }

    async fn post_tool(
        &self,
        _ctx: &HookContext,
        _tool: &str,
        _output: &ToolOutput,
    ) -> Result<HookResult, HookError> {
        Ok(HookResult::Continue)
    }
}

fn ctx() -> HookContext {
    HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()))
}

#[tokio::test]
async fn first_stop_short_circuits() {
    let counts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let middle_counts = Arc::clone(&counts);
    let trailing_counts = Arc::clone(&counts);

    let head = Arc::new(CountingHook {
        label: "head",
        calls: Arc::clone(&counts),
        seen_input: Mutex::new(None),
        decision: HookResult::Continue,
    });
    let stopper = Arc::new(CountingHook {
        label: "stopper",
        calls: middle_counts,
        seen_input: Mutex::new(None),
        decision: HookResult::StopExecution("stop_marker".to_string()),
    });
    let tail = Arc::new(CountingHook {
        label: "tail",
        calls: trailing_counts,
        seen_input: Mutex::new(None),
        decision: HookResult::Continue,
    });
    let tail_calls = Arc::clone(&tail.calls);

    let mut chain = HookChain::new();
    chain.push(head);
    chain.push(stopper);
    chain.push(tail.clone());

    let outcome = chain
        .pre_tool(&ctx(), "read", &serde_json::json!({"k": 1}))
        .await
        .expect("pre_tool returned an error");

    match outcome {
        PreToolOutcome::Stop { reason } => assert_eq!(reason, "stop_marker"),
        PreToolOutcome::Proceed { .. } => panic!("expected Stop, got Proceed"),
    }
    // 3 hooks share the same counter; head + stopper = 2 calls.
    // tail must NOT have been invoked.
    assert_eq!(counts.load(Ordering::SeqCst), 2);
    drop(tail_calls);
}

#[tokio::test]
async fn replace_input_propagates_through_chain() {
    let counts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

    let mutator = Arc::new(CountingHook {
        label: "mutator",
        calls: Arc::clone(&counts),
        seen_input: Mutex::new(None),
        decision: HookResult::ReplaceInput(serde_json::json!({"x": 2})),
    });
    let observer = Arc::new(CountingHook {
        label: "observer",
        calls: Arc::clone(&counts),
        seen_input: Mutex::new(None),
        decision: HookResult::Continue,
    });
    let observer_seen = Arc::clone(&observer);

    let mut chain = HookChain::new();
    chain.push(mutator);
    chain.push(observer);

    let outcome = chain
        .pre_tool(&ctx(), "read", &serde_json::json!({"x": 1}))
        .await
        .expect("pre_tool returned an error");

    match outcome {
        PreToolOutcome::Proceed { input } => {
            assert_eq!(input, serde_json::json!({"x": 2}));
        }
        PreToolOutcome::Stop { reason } => panic!("expected Proceed, got Stop({reason})"),
    }

    let seen = observer_seen
        .seen_input
        .lock()
        .expect("observer mutex poisoned");
    assert_eq!(seen.as_ref(), Some(&serde_json::json!({"x": 2})));
}

#[tokio::test]
async fn inject_context_in_pre_phase_is_rejected() {
    let illegal = Arc::new(CountingHook {
        label: "illegal",
        calls: Arc::new(AtomicUsize::new(0)),
        seen_input: Mutex::new(None),
        decision: HookResult::InjectContext("nope".to_string()),
    });
    let mut chain = HookChain::new();
    chain.push(illegal);

    let err = chain
        .pre_tool(&ctx(), "read", &serde_json::json!({}))
        .await
        .expect_err("expected HookError, got Ok");
    let msg = format!("{err}");
    assert!(msg.contains("InjectContext"), "unexpected message: {msg}");
}
