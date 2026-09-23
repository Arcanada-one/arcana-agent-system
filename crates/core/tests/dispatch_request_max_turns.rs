//! ARAS A2-202: the run-level turn cap is NOT the per-request `maxTurns` field
//! of the Model Connector contract.
//!
//! `DriverConfig::max_turns` bounds how many connector attempts *this* loop
//! makes. The wire field `maxTurns` is a per-request passthrough that Model
//! Connector forwards to CLI connectors (`claude-code --max-turns`) and
//! validates as `z.number().int().min(1).max(100)`
//! (model-connector `src/connectors/dto/execute.dto.ts:57`). Conflating them
//! made every run with `--max-turns 120` die on its FIRST dispatch with an
//! HTTP 400 — a run-level budget rejected as a per-request one.
//!
//! This test pins the wire shape, not the internal field: whatever the driver
//! sends must be a request Model Connector's schema accepts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use arcana_core::agent_loop::{Driver, DriverConfig, TerminalReason};
use arcana_core::cost::CostTracker;
use arcana_core::hooks::HookChain;
use arcana_core::tool::ToolDispatcher;
use tokio_util::sync::CancellationToken;

use common::{response, ScriptedConnector};

/// Upper bound of `maxTurns` in the Model Connector request schema.
const MC_MAX_TURNS_CEILING: u64 = 100;

#[tokio::test]
async fn a_run_level_turn_cap_above_the_mc_ceiling_still_builds_an_acceptable_request() {
    let connector = ScriptedConnector::new(vec![response("done", 0.0)]);
    let cascade = common::allow_cascade();
    let cost = Arc::new(CostTracker::new());
    let (executor, _audit_dir) =
        common::test_executor(ToolDispatcher::new(), cascade, HookChain::new());

    // The reproducer: `arcana run --max-turns 120`.
    let mut config = DriverConfig::new("scripted");
    config.max_turns = 120;

    let driver = Driver::new(
        &connector,
        &executor,
        cost,
        CancellationToken::new(),
        config,
    );
    let out = driver.run("say hello").await;
    assert_eq!(out.reason, TerminalReason::Completed);

    let requests = connector.requests();
    let first = requests.first().expect("one dispatch was made");
    let wire = serde_json::to_value(first).expect("request serialises");

    // Absent is fine — MC's field is optional. Present must be inside the
    // contract, or MC answers 400 before the model is ever reached.
    if let Some(value) = wire.get("maxTurns") {
        let sent = value.as_u64().expect("maxTurns is a non-negative integer");
        assert!(
            (1..=MC_MAX_TURNS_CEILING).contains(&sent),
            "maxTurns={sent} is outside the Model Connector contract 1..=100; \
             the run-level cap must not be forwarded as the per-request field"
        );
    }
}
