//! R1 trusted step-intent routing (DRA025–032).
//!
//! Authority order (filters → eligibility → cost):
//! 1. Hard filters (privacy / tools / modality / format / context / risk / budget).
//! 2. Required capabilities must be admitted on a profile record — never inferred
//!    from [`crate::dispatch::CostTier`] or from a model's price.
//! 3. Among remaining eligible profiles, pick the lowest `cost_rank`.
//!
//! Model output and tool-result prose are [`UntrustedObservation`] data only.
//! They never reset [`TrustedStepIntent`] and never override hard filters.
//!
//! Catalogue notes: [`fixture_admitted_catalogue`] is a **test/fixture** record
//! set, not an installed Model Connector / production catalogue API. When no
//! admitted catalogue is supplied, routing reports
//! [`RoutingConflict::UnresolvedEligibility`] rather than pretending a check ran.

use std::collections::BTreeSet;

use super::{CostTier, ModelChoice};

/// Trusted current-plan step intent. Sourced from a plan/stage/CLI declaration —
/// never from model or tool prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepIntent {
    /// Plan / design the next work.
    Planning,
    /// Implement a change.
    Implementation,
    /// Interpret evidence (including ambiguous tool results).
    Interpretation,
    /// Verify outcomes against criteria.
    Verification,
    /// Exact deterministic transform with a zero-LLM contract.
    DeterministicTransform,
    /// Explicitly bounded summary step.
    BoundedSummary,
}

/// Capability a profile must admit before it is eligible for a step.
///
/// Distinct from [`CostTier`]: cheap/expensive labels and prices are not
/// capability evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepCapability {
    /// May perform planning.
    Planning,
    /// May perform implementation.
    Implementation,
    /// May interpret ambiguous evidence.
    Interpretation,
    /// May verify outcomes.
    Verification,
    /// May run a declared deterministic transform without an LLM.
    DeterministicTransform,
    /// May produce an explicitly bounded summary.
    BoundedSummary,
}

/// Stable handle for a trusted step (intent + required capabilities).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedStepIntent {
    /// Declared step kind for this plan step.
    pub intent: StepIntent,
    /// Capabilities the step requires. Empty only when the caller intentionally
    /// defers to [`capabilities_for_intent`].
    pub required: BTreeSet<StepCapability>,
}

impl TrustedStepIntent {
    /// Build a trusted intent and fill required capabilities from the intent
    /// when the caller did not list them explicitly.
    #[must_use]
    pub fn new(intent: StepIntent) -> Self {
        Self {
            intent,
            required: capabilities_for_intent(intent),
        }
    }

    /// Override the required set (must still be non-empty for LLM routes).
    #[must_use]
    pub fn with_required(mut self, required: BTreeSet<StepCapability>) -> Self {
        self.required = required;
        self
    }
}

/// Default required capabilities for a trusted intent.
#[must_use]
pub fn capabilities_for_intent(intent: StepIntent) -> BTreeSet<StepCapability> {
    let one = |cap: StepCapability| {
        let mut set = BTreeSet::new();
        set.insert(cap);
        set
    };
    match intent {
        StepIntent::Planning => one(StepCapability::Planning),
        StepIntent::Implementation => one(StepCapability::Implementation),
        StepIntent::Interpretation => one(StepCapability::Interpretation),
        StepIntent::Verification => one(StepCapability::Verification),
        StepIntent::DeterministicTransform => one(StepCapability::DeterministicTransform),
        StepIntent::BoundedSummary => one(StepCapability::BoundedSummary),
    }
}

/// Untrusted observation channel (model text, tool results, prompt injection).
/// Carried so tests can prove it does not affect routing authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UntrustedObservation {
    /// Optional tool-result body (data only).
    pub tool_result: Option<String>,
    /// Optional model/assistant prose (data only).
    pub model_prose: Option<String>,
    /// Optional injected prompt fragment (data only).
    pub prompt_injection: Option<String>,
}

/// Two-state hard filter gate (avoids a bool cluster on [`RoutingFilters`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterGate {
    /// Filter allows the step to continue.
    Allow,
    /// Filter denies the step before cost optimisation.
    Deny,
}

impl FilterGate {
    fn is_deny(self) -> bool {
        matches!(self, Self::Deny)
    }
}

/// Hard filters applied before cost optimisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingFilters {
    /// Privacy gate.
    pub privacy: FilterGate,
    /// Tool-policy gate.
    pub tools: FilterGate,
    /// Modality gate.
    pub modality: FilterGate,
    /// Format gate.
    pub format: FilterGate,
    /// Risk gate.
    pub risk: FilterGate,
    /// Budget gate.
    pub budget: FilterGate,
    /// Current complete-context size (UTF-16 units, same family as prompt budget).
    pub context_units: u64,
    /// Maximum admitted complete-context size.
    pub context_limit_units: u64,
}

impl RoutingFilters {
    /// All hard filters open; context under a generous limit.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            privacy: FilterGate::Allow,
            tools: FilterGate::Allow,
            modality: FilterGate::Allow,
            format: FilterGate::Allow,
            risk: FilterGate::Allow,
            budget: FilterGate::Allow,
            context_units: 0,
            context_limit_units: 90_000,
        }
    }

    fn first_denial(&self) -> Option<&'static str> {
        if self.privacy.is_deny() {
            return Some("privacy");
        }
        if self.tools.is_deny() {
            return Some("tools");
        }
        if self.modality.is_deny() {
            return Some("modality");
        }
        if self.format.is_deny() {
            return Some("format");
        }
        if self.risk.is_deny() {
            return Some("risk");
        }
        if self.budget.is_deny() {
            return Some("budget");
        }
        None
    }

    fn context_oversized(&self) -> bool {
        self.context_units > self.context_limit_units
    }
}

/// How the admitted profile catalogue was obtained for this decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogueAvailability {
    /// Explicit admitted records were supplied by the caller (fixture or future
    /// installed API). Eligibility may be evaluated.
    Provided,
    /// No admitted catalogue is available in this runtime. Must not invent
    /// eligibility from price or [`CostTier`].
    Unavailable,
}

/// An admitted routing profile. Capability claims come only from this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedProfile {
    /// Stable profile id (not a price tier name).
    pub profile_id: String,
    /// Abstract model id written onto an execute request when this profile wins.
    pub model_id: String,
    /// Capabilities this profile is admitted to perform.
    pub admitted: BTreeSet<StepCapability>,
    /// Cost rank used only after filters + eligibility (lower is cheaper).
    pub cost_rank: u32,
    /// Bill tier label after eligibility — never used as capability proof.
    pub bill_tier: CostTier,
    /// When true, the profile may satisfy a deterministic-transform step with
    /// zero LLM dispatch.
    pub zero_llm: bool,
}

/// Declared deterministic transform contract for a zero-LLM positive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicTransform {
    /// Stable transform id.
    pub transform_id: String,
    /// Exact input bytes.
    pub input: String,
}

/// Full routing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRequest {
    /// Trusted current-plan step intent.
    pub trusted: TrustedStepIntent,
    /// Hard filters (evaluated before cost).
    pub filters: RoutingFilters,
    /// Whether an admitted catalogue was actually provided.
    pub catalogue: CatalogueAvailability,
    /// Admitted profiles (ignored when catalogue is [`CatalogueAvailability::Unavailable`]).
    pub profiles: Vec<AdmittedProfile>,
    /// Optional operator/model pin. Eligible pins stay pinned; ineligible pins
    /// are explicit conflicts (never silent substitution).
    pub pin: Option<String>,
    /// Optional deterministic transform payload (required for zero-LLM path).
    pub deterministic: Option<DeterministicTransform>,
    /// Untrusted prose/tool data — must not affect the decision.
    pub untrusted: UntrustedObservation,
}

/// Successful routing outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Dispatch an LLM with the chosen model id / bill tier.
    Model(ModelChoice),
    /// Execute a declared deterministic transform without an LLM.
    ZeroLlm {
        /// Transform id that was admitted.
        transform_id: String,
        /// Exact output of the transform.
        output: String,
    },
}

/// Explicit eligibility / filter conflict — never a silent cheap fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingConflict {
    /// A hard filter denied the step before cost optimisation.
    FilterDenied {
        /// Which filter failed.
        filter: &'static str,
    },
    /// Complete context exceeds the admitted limit.
    ContextOversized {
        /// Observed context size.
        context_units: u64,
        /// Admitted limit.
        context_limit_units: u64,
    },
    /// No admitted catalogue was available to evaluate eligibility.
    UnresolvedEligibility {
        /// Human-readable detail.
        detail: String,
    },
    /// A required capability is not admitted on any remaining profile.
    MissingCapability {
        /// Missing capability.
        capability: StepCapability,
    },
    /// Explicit pin is not among the eligible profiles.
    IneligiblePin {
        /// Requested pin.
        pin: String,
        /// Why it was rejected.
        reason: String,
    },
    /// Filters passed but no profile remained.
    NoEligibleProfile,
    /// Deterministic transform was required but no contract / zero-LLM profile.
    DeterministicContractMissing,
}

/// Route from trusted intent + admitted capabilities.
///
/// `untrusted` is accepted and intentionally unused for authority: injection,
/// tool results, and multilingual prose cannot change the trusted phase.
///
/// # Errors
///
/// Returns [`RoutingConflict`] when a hard filter denies the step, the complete
/// context is oversized, no admitted catalogue is available, a required
/// capability is missing, an explicit pin is ineligible, no eligible profile
/// remains, or a deterministic-transform contract is missing.
pub fn route_step(request: &RoutingRequest) -> Result<RoutingDecision, RoutingConflict> {
    // Absorb untrusted observations so callers can pass tool/model prose without
    // granting them routing authority (black_box prevents dead-code elision).
    core::hint::black_box(&request.untrusted);

    if let Some(filter) = request.filters.first_denial() {
        return Err(RoutingConflict::FilterDenied { filter });
    }
    if request.filters.context_oversized() {
        return Err(RoutingConflict::ContextOversized {
            context_units: request.filters.context_units,
            context_limit_units: request.filters.context_limit_units,
        });
    }

    match request.catalogue {
        CatalogueAvailability::Unavailable => {
            return Err(RoutingConflict::UnresolvedEligibility {
                detail: "no admitted capability catalogue is installed for this runtime; \
                         eligibility cannot be inferred from CostTier or price"
                    .to_owned(),
            });
        }
        CatalogueAvailability::Provided => {}
    }

    let required = if request.trusted.required.is_empty() {
        capabilities_for_intent(request.trusted.intent)
    } else {
        request.trusted.required.clone()
    };

    if request.trusted.intent == StepIntent::DeterministicTransform {
        return route_deterministic(request, &required);
    }

    let mut eligible: Vec<&AdmittedProfile> = request
        .profiles
        .iter()
        .filter(|profile| required.iter().all(|cap| profile.admitted.contains(cap)))
        .collect();

    for cap in &required {
        if !request
            .profiles
            .iter()
            .any(|profile| profile.admitted.contains(cap))
        {
            return Err(RoutingConflict::MissingCapability { capability: *cap });
        }
    }

    if eligible.is_empty() {
        return Err(RoutingConflict::NoEligibleProfile);
    }

    if let Some(pin) = request.pin.as_deref() {
        match eligible.iter().copied().find(|p| p.model_id == pin) {
            Some(profile) => {
                return Ok(RoutingDecision::Model(ModelChoice {
                    model_id: profile.model_id.clone(),
                    tier: profile.bill_tier,
                }));
            }
            None => {
                return Err(RoutingConflict::IneligiblePin {
                    pin: pin.to_owned(),
                    reason:
                        "pinned model is not among profiles that admit the required capabilities"
                            .to_owned(),
                });
            }
        }
    }

    eligible.sort_by_key(|p| (p.cost_rank, p.profile_id.as_str()));
    let winner = eligible[0];
    Ok(RoutingDecision::Model(ModelChoice {
        model_id: winner.model_id.clone(),
        tier: winner.bill_tier,
    }))
}

fn route_deterministic(
    request: &RoutingRequest,
    required: &BTreeSet<StepCapability>,
) -> Result<RoutingDecision, RoutingConflict> {
    let Some(transform) = request.deterministic.as_ref() else {
        return Err(RoutingConflict::DeterministicContractMissing);
    };

    let has_zero_llm = request.profiles.iter().any(|profile| {
        profile.zero_llm && required.iter().all(|cap| profile.admitted.contains(cap))
    });
    if !has_zero_llm {
        // Missing capability vs missing contract: if no profile admits the
        // capability at all, surface MissingCapability; otherwise contract gap.
        for cap in required {
            if !request
                .profiles
                .iter()
                .any(|profile| profile.admitted.contains(cap))
            {
                return Err(RoutingConflict::MissingCapability { capability: *cap });
            }
        }
        return Err(RoutingConflict::DeterministicContractMissing);
    }

    let output = execute_deterministic_transform(transform);
    Ok(RoutingDecision::ZeroLlm {
        transform_id: transform.transform_id.clone(),
        output,
    })
}

/// Exact deterministic transforms admitted by fixture contracts.
///
/// Currently: identity and ASCII uppercase. Unknown transform ids return the
/// input unchanged only when the caller already admitted the profile; the
/// router requires a known id for a useful positive.
#[must_use]
pub fn execute_deterministic_transform(transform: &DeterministicTransform) -> String {
    match transform.transform_id.as_str() {
        "exact_identity" => transform.input.clone(),
        "exact_ascii_uppercase" => transform.input.to_ascii_uppercase(),
        other => format!("unsupported_transform:{other}"),
    }
}

/// Fixture admitted catalogue for offline R1 controls.
///
/// **Not** an installed Model Connector catalogue. Tests and harnesses may use
/// it; production callers without a real admitted API must pass
/// [`CatalogueAvailability::Unavailable`].
#[must_use]
pub fn fixture_admitted_catalogue() -> Vec<AdmittedProfile> {
    vec![
        AdmittedProfile {
            profile_id: "economical_summary".to_owned(),
            model_id: "deepseek-v4-flash".to_owned(),
            admitted: BTreeSet::from([StepCapability::BoundedSummary]),
            cost_rank: 10,
            bill_tier: CostTier::Cheap,
            zero_llm: false,
        },
        AdmittedProfile {
            profile_id: "general_reasoning".to_owned(),
            model_id: "grok-3-latest".to_owned(),
            admitted: BTreeSet::from([
                StepCapability::Planning,
                StepCapability::Implementation,
                StepCapability::Interpretation,
                StepCapability::Verification,
            ]),
            cost_rank: 80,
            bill_tier: CostTier::Expensive,
            zero_llm: false,
        },
        AdmittedProfile {
            profile_id: "deterministic_exact".to_owned(),
            model_id: "none".to_owned(),
            admitted: BTreeSet::from([StepCapability::DeterministicTransform]),
            cost_rank: 0,
            bill_tier: CostTier::Cheap,
            zero_llm: true,
        },
    ]
}
