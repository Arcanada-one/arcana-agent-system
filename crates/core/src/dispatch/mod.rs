//! Multi-model dispatch policy and R1 intent-routed selection.
//!
//! Legacy history heuristics live in [`legacy_policy`]. Trusted step-intent
//! routing (KCLIVE-11 / DRA025–032 R1) lives in [`intent_route`]. The driver
//! calls [`route_step`] when [`crate::agent_loop::DriverConfig::trusted_step`]
//! is set; otherwise it keeps [`classify`] + [`ModelPolicy::select`] for
//! unmigrated conversational paths.

mod intent_route;
mod legacy_policy;

pub use intent_route::{
    capabilities_for_intent, execute_deterministic_transform, fixture_admitted_catalogue,
    route_step, AdmittedProfile, CatalogueAvailability, DeterministicTransform, FilterGate,
    RoutingConflict, RoutingDecision, RoutingFilters, RoutingRequest, StepCapability, StepIntent,
    TrustedStepIntent, UntrustedObservation,
};
pub use legacy_policy::{classify, CostTier, ModelChoice, ModelPolicy, SelectionContext, TaskType};
