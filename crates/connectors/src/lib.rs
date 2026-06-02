//! arcana-connectors — HTTP bridges to Arcanada ecosystem services.
//!
//! Phase 1 ships the Model Connector client only. The public contract (trait,
//! DTOs, error type) lives in `arcana_core::connector`; this crate provides the
//! concrete `reqwest`-backed implementation.

pub mod model_connector;

pub use model_connector::ModelConnectorClient;
