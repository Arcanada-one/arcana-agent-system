//! Trusted step-intent parsing for plan / task-run inputs (R1).
//!
//! Callers that already have a typed label (CLI flag, skill stage, Muneral
//! plan step) parse it here and set
//! [`arcana_core::agent_loop::DriverConfig::trusted_step`] so the driver
//! routes via [`arcana_core::dispatch::route_step`]. Without that field the
//! driver keeps the legacy history heuristic for unmigrated conversational
//! paths.

use arcana_core::dispatch::{
    fixture_admitted_catalogue, route_step, CatalogueAvailability, DeterministicTransform,
    RoutingConflict, RoutingFilters, RoutingRequest, StepIntent, TrustedStepIntent,
    UntrustedObservation,
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

/// Check an explicit pin against the offline fixture catalogue.
///
/// A deterministic precheck supplies a fixed empty identity transform solely
/// to reach the same pin/profile eligibility checks as `route_step`. It does
/// not inspect or execute the caller's task payload. Actual execution still
/// requires its own declared transform and the full routing checks.
///
/// This helper always uses fixture records and permissive fixture filters.
/// Success is pin eligibility only: it supplies neither an installed catalogue
/// nor task, private-read or effect authority. No production caller is enabled.
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
        deterministic: (intent == StepIntent::DeterministicTransform).then(|| {
            DeterministicTransform {
                transform_id: "exact_identity".to_owned(),
                input: String::new(),
            }
        }),
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
    use arcana_core::dispatch::RoutingDecision;

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

    #[test]
    fn deterministic_eligible_fixture_pin_is_accepted() {
        assert!(
            precheck_pin_with_fixture_catalogue(StepIntent::DeterministicTransform, "none").is_ok()
        );
    }

    #[test]
    fn deterministic_nonmatching_fixture_pins_are_conflicts() {
        for pin in ["grok-3-latest", "not_registered", "none ", ""] {
            let Err(err) =
                precheck_pin_with_fixture_catalogue(StepIntent::DeterministicTransform, pin)
            else {
                panic!("ineligible deterministic pin must conflict: {pin:?}");
            };
            assert!(
                err.starts_with("ineligible model pin "),
                "expected pin conflict for {pin:?}, got {err}"
            );
        }
    }

    #[test]
    fn deterministic_precheck_does_not_relax_execution_payload_checks() {
        assert!(
            precheck_pin_with_fixture_catalogue(StepIntent::DeterministicTransform, "none").is_ok()
        );
        let mut request = RoutingRequest {
            trusted: TrustedStepIntent::new(StepIntent::DeterministicTransform),
            filters: RoutingFilters::permissive(),
            catalogue: CatalogueAvailability::Provided,
            profiles: fixture_admitted_catalogue(),
            pin: Some("none".to_owned()),
            deterministic: None,
            untrusted: UntrustedObservation::default(),
        };
        assert_eq!(
            route_step(&request),
            Err(RoutingConflict::DeterministicContractMissing)
        );

        request.deterministic = Some(DeterministicTransform {
            transform_id: "not_registered".to_owned(),
            input: "AbC".to_owned(),
        });
        assert_eq!(
            route_step(&request),
            Err(RoutingConflict::DeterministicContractMissing)
        );

        request.deterministic = Some(DeterministicTransform {
            transform_id: "exact_ascii_uppercase".to_owned(),
            input: "AbC".to_owned(),
        });
        assert_eq!(
            route_step(&request),
            Ok(RoutingDecision::ZeroLlm {
                transform_id: "exact_ascii_uppercase".to_owned(),
                output: "ABC".to_owned(),
            })
        );
    }
}
