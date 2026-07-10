//! arcana-connectors — HTTP bridges to Arcanada ecosystem services.
//!
//! Phase 1 ships the Model Connector and Scrutator clients. The Model
//! Connector's contract (trait, DTOs, error type) lives in
//! `arcana_core::connector`; this crate provides the concrete
//! `reqwest`-backed implementation. `scrutator` is a standalone thin wrapper
//! (no core-level trait indirection — Scrutator is consumed directly by the
//! `arcana_search` tool in `arcana-tools`). `coworker` is a standalone
//! subprocess wrapper (no HTTP involved) around the operator's local
//! `coworker` CLI.

pub mod coworker;
pub mod model_connector;
pub mod scrutator;

pub use coworker::CoworkerClient;
pub use model_connector::ModelConnectorClient;
pub use scrutator::ScrutatorClient;
