//! arcana-connectors — HTTP bridges to Arcanada ecosystem services.
//!
//! Phase 1 ships the Model Connector and Scrutator clients. The Model
//! Connector's contract (trait, DTOs, error type) lives in
//! `arcana_core::connector`; this crate provides the concrete
//! `reqwest`-backed implementation. `scrutator` is a standalone thin wrapper
//! (no core-level trait indirection — Scrutator is consumed directly by the
//! `arcana_search` tool in `arcana-tools`). `coworker` is a standalone
//! subprocess wrapper (no HTTP involved) around the operator's local
//! `coworker` CLI. `ops_bot` is the Phase 2 Ops Bot events emitter
//! (fail-soft, see module docs); wiring it into the agent loop's
//! composition root is a separate follow-up (`ARAS-0024`).

pub mod auth_arcana;
pub mod coworker;
pub mod model_connector;
pub mod ops_bot;
pub mod scrutator;

pub use coworker::CoworkerClient;
pub use model_connector::{ApiKey, ModelConnectorClient};
pub use ops_bot::OpsBotClient;
pub use scrutator::{skill_store_from_env, ScrutatorClient, SkillStoreInitError};
