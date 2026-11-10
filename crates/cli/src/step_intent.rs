//! Trusted step-intent parsing for plan / task-run inputs (R1).
//!
//! Callers that already have a typed label (CLI flag, skill stage, Muneral
//! plan step) parse it here and set
//! [`arcana_core::agent_loop::DriverConfig::trusted_step`] so the driver
//! routes via [`arcana_core::dispatch::route_step`]. Without that field the
//! driver keeps the legacy history heuristic for unmigrated conversational
//! paths.

use arcana_core::dispatch::{
    fixture_admitted_catalogue, route_step, CatalogueAvailability, RoutingConflict, RoutingFilters,
    RoutingRequest, StepIntent, TrustedStepIntent, UntrustedObservation,
};

/// Parse a trusted step-intent label. Rejects unknown labels rather than
/// guessing from prose.
///
/// # Errors
///
/// Returns a stable error string when the label is not one of the R1 intents.
pub fn parse_step_intent(label: &str) -> Result<StepIntent, String> {
    match label.trim().to_ascii_lowercase().as_str() {
        "planning" => Ok(StepIntent::Planning),
        "implementation" => Ok(StepIntent::Implementation),
        "interpretation" => Ok(StepIntent::Interpretation),
        "verification" => Ok(StepIntent::Verification),
        "deterministic_transform" | "deterministic-transform" => {
            Ok(StepIntent::DeterministicTransform)
        }
        "bounded_summary" | "bounded-summary" | "summary" => Ok(StepIntent::BoundedSummary),
        other => Err(format!(
            "unknown step intent `{other}`; expected planning|implementation|interpretation|\
             verification|deterministic_transform|bounded_summary"
        )),
    }
}

/// When both a trusted intent and an admitted catalogue are available, an
/// explicit pin that fails eligibility is an explicit conflict — never a silent
/// substitution onto another model.
///
/// When no catalogue is available, returns `Ok(())` and leaves legacy
/// `single_model` semantics unchanged (unresolved eligibility is reported only
/// for the R1 `route_step` path that requires a catalogue).
///
/// # Errors
///
/// Returns a conflict description for an ineligible pin under the fixture
/// catalogue (the only admitted record set this crate currently owns offline).
pub fn precheck_pin_with_fixture_catalogue(intent: StepIntent, pin: &str) -> Result<(), String> {
    let request = RoutingRequest {
        trusted: TrustedStepIntent::new(intent),
        filters: RoutingFilters::permissive(),
        catalogue: CatalogueAvailability::Provided,
        profiles: fixture_admitted_catalogue(),
        pin: Some(pin.to_owned()),
        deterministic: None,
        untrusted: UntrustedObservation::default(),
    };
    match route_step(&request) {
        Ok(_) => Ok(()),
        Err(RoutingConflict::IneligiblePin { pin, reason }) => {
            Err(format!("ineligible model pin `{pin}`: {reason}"))
        }
        Err(other) => Err(format!("pin eligibility conflict: {other:?}")),
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_labels() {
        assert_eq!(parse_step_intent("Planning"), Ok(StepIntent::Planning));
        assert_eq!(
            parse_step_intent("bounded-summary"),
            Ok(StepIntent::BoundedSummary)
        );
    }

    #[test]
    fn rejects_unknown_label() {
        assert!(parse_step_intent("cheap").is_err());
    }

    #[test]
    fn eligible_pin_ok_ineligible_conflicts() {
        assert!(precheck_pin_with_fixture_catalogue(StepIntent::Planning, "grok-3-latest").is_ok());
        let Err(err) =
            precheck_pin_with_fixture_catalogue(StepIntent::Planning, "deepseek-v4-flash")
        else {
            panic!("ineligible pin must conflict");
        };
        assert!(err.contains("ineligible"), "{err}");
    }
}
