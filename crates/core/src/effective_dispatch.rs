//! G05: final effective-dispatch guard at the model-request and tool-effect
//! boundary.
//!
//! Before each consequential effect the driver must establish four separately
//! evidenced decisions:
//!
//! 1. [`CoverageComplete`] — every mandatory obligation is present in the final
//!    request, enforced by a current typed guard, or verified-rehydrated.
//! 2. [`PreconditionsDischarged`] — every mandatory member has a current
//!    authenticated `pass` or justified `not_applicable` (necessity /
//!    coverage is not discharge; `Says(source,P)` is not `P`).
//! 3. Current authority — not revoked, not expired, not unavailable.
//! 4. Durable effect identity / reservation through the existing
//!    [`crate::operation_intent`] store (no second ledger).
//!
//! Relevant bindings are re-checked after every await and immediately before
//! the effect. A read-only clarification is not free permission for a
//! model/network call: when the call still hits the connector, it uses the
//! same gate.
//!
//! ## Native field mapping
//!
//! ARAS has no Driver-native mandatory-obligation set, no effect-time
//! discharge witnesses, and no effect-time authority fence on this path
//! (`contract_authority` is point-in-time admission only). Those predicates
//! are supplied by the composition root via [`EffectiveDispatchConfig`]. A
//! missing native source refuses with a typed code; values are never invented.
//! Durable identity reuses [`crate::operation_intent::OperationSession`].

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// How one mandatory obligation is covered in the final effective request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageState {
    /// Exact mandatory bytes / identity present in the final request.
    PresentExact,
    /// A correctly attached current typed guard enforces this obligation.
    EnforcedByCurrentGuard,
    /// Exact retained bytes rehydrated with digest and current authorization.
    VerifiedRehydrated,
    /// Not covered. `CoverageComplete` fails for this member — see
    /// [`evaluate`].
    Missing,
}

/// Separate assessment that the obligation's predicate is true.
///
/// Coverage answers availability; this answers truth. An attributed claim is
/// not a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DischargeAssessment {
    /// Current scope-bound authenticated pass with a witness id.
    Pass {
        witness_id: String,
        evaluated_at_epoch_s: u64,
    },
    /// Justified not-applicable with its own applicability witness.
    NotApplicable {
        witness_id: String,
        applicability_witness_id: String,
        evaluated_at_epoch_s: u64,
    },
    /// Explicitly unknown — not discharged.
    Unknown,
    /// Explicit fail — not discharged.
    Fail,
    /// `Says(source, P)` only — attributed, not proven.
    AttributedOnly,
    /// No witness at all.
    Missing,
    /// Witness exists but is stale for the current epoch/scope.
    Stale,
}

/// One mandatory member of the trusted action-specific obligation set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandatoryMember {
    pub id: String,
    pub coverage: CoverageState,
    pub discharge: DischargeAssessment,
}

/// Current authority for the exact effect. Never invented from task text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentAuthority {
    /// Explicit synthetic or composition-root authority for this effect.
    Current {
        /// Authority generation / epoch the grant was issued under.
        epoch: u64,
        /// Exclusive expiry in Unix seconds; `None` means no wall expiry.
        expires_at_epoch_s: Option<u64>,
        /// Hard revocation flag.
        revoked: bool,
    },
    /// Native ARAS has no effect-time authority field on this path.
    Unavailable,
}

/// Which consequential boundary is about to fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectKind {
    /// A Model Connector / provider request (including clarification that
    /// still makes a network/model call).
    ModelRequest,
    /// A local tool/capability side effect.
    ToolEffect,
}

/// Mutable snapshot the composition root (or a test) owns.
#[derive(Debug, Clone)]
pub struct EffectiveDispatchState {
    pub members: Vec<MandatoryMember>,
    pub authority: CurrentAuthority,
    /// Clock used for expiry checks (Unix seconds). Tests advance it.
    pub now_epoch_s: u64,
}

impl EffectiveDispatchState {
    /// Empty mandatory set is not automatic permission.
    #[must_use]
    pub fn empty_at(now_epoch_s: u64) -> Self {
        Self {
            members: Vec::new(),
            authority: CurrentAuthority::Unavailable,
            now_epoch_s,
        }
    }
}

/// Composition-root route protection for G05/KC-protected execution.
///
/// Trusted and not request-selectable: only [`crate::agent_loop::DriverConfig`]
/// carries this flag. An untrusted request field cannot switch protection off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteProtection {
    /// Outside the G05/KC protected-execution guarantee. Missing
    /// [`EffectiveDispatchConfig`] keeps pre-G05 behaviour.
    #[default]
    LegacyOutsideGuarantee,
    /// Requires the effective-dispatch gate and durable intent. A missing gate
    /// or required trusted input is a typed unavailable refusal before any
    /// model/tool effect — never a silent legacy fallback.
    Protected,
}

/// Opt-in G05 gate. `None` on [`crate::agent_loop::DriverConfig`] keeps the
/// pre-G05 path (existing tests unchanged) for
/// [`RouteProtection::LegacyOutsideGuarantee`] routes.
#[derive(Clone)]
pub struct EffectiveDispatchConfig {
    pub state: Arc<Mutex<EffectiveDispatchState>>,
    /// Invoked between the first check and the immediate-before-effect
    /// recheck (after an await). Production leaves this `None` (a single
    /// `yield_now`). Tests use it to revoke/expire across the await.
    pub between_checks: Option<BetweenChecksHook>,
}

impl std::fmt::Debug for EffectiveDispatchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectiveDispatchConfig")
            .field("state", &self.state)
            .field(
                "between_checks",
                &self.between_checks.as_ref().map(|_| "Some(<hook>)"),
            )
            .finish()
    }
}

/// Async hook run after the first admit and before the final recheck.
pub type BetweenChecksHook =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

impl EffectiveDispatchConfig {
    #[must_use]
    pub fn new(state: EffectiveDispatchState) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
            between_checks: None,
        }
    }

    /// Read the current snapshot (tests / diagnostics).
    ///
    /// A poisoned mutex is recovered: the last consistent state is kept so a
    /// panicked test helper cannot invent a passing authority.
    #[must_use]
    pub fn snapshot(&self) -> EffectiveDispatchState {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Mutate the live snapshot (tests revoke/expire across an await).
    ///
    /// A poisoned mutex is recovered (see [`Self::snapshot`]).
    pub fn with_state_mut<R>(&self, f: impl FnOnce(&mut EffectiveDispatchState) -> R) -> R {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }
}

/// Typed refusal. Nothing was dispatched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EffectGuardError {
    #[error("EFFECT_COVERAGE_INCOMPLETE: mandatory member `{member_id}` is not covered in the final effective request")]
    CoverageIncomplete { member_id: String },
    #[error(
        "EFFECT_OBLIGATION_SET_EMPTY: trusted action-specific obligation set is empty; \
         empty is not automatic permission"
    )]
    ObligationSetEmpty,
    #[error("EFFECT_PRECONDITION_UNDISCHARGED: mandatory member `{member_id}` is not discharged ({reason})")]
    PreconditionUndischarged { member_id: String, reason: String },
    #[error(
        "EFFECT_AUTHORITY_UNAVAILABLE: no native effect-time authority field on the Driver path; \
         composition root must supply CurrentAuthority::Current"
    )]
    AuthorityUnavailable,
    #[error("EFFECT_AUTHORITY_REVOKED: current authority epoch {epoch} is revoked")]
    AuthorityRevoked { epoch: u64 },
    #[error(
        "EFFECT_AUTHORITY_EXPIRED: current authority expired at {expires_at_epoch_s}; now={now_epoch_s}"
    )]
    AuthorityExpired {
        expires_at_epoch_s: u64,
        now_epoch_s: u64,
    },
    #[error(
        "EFFECT_IDENTITY_UNRESERVED: durable effect identity requires the existing \
         operation_intent store reservation; nothing was reserved"
    )]
    IdentityUnreserved,
}

impl EffectGuardError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::CoverageIncomplete { .. } => "EFFECT_COVERAGE_INCOMPLETE",
            Self::ObligationSetEmpty => "EFFECT_OBLIGATION_SET_EMPTY",
            Self::PreconditionUndischarged { .. } => "EFFECT_PRECONDITION_UNDISCHARGED",
            Self::AuthorityUnavailable => "EFFECT_AUTHORITY_UNAVAILABLE",
            Self::AuthorityRevoked { .. } => "EFFECT_AUTHORITY_REVOKED",
            Self::AuthorityExpired { .. } => "EFFECT_AUTHORITY_EXPIRED",
            Self::IdentityUnreserved => "EFFECT_IDENTITY_UNRESERVED",
        }
    }
}

fn coverage_ok(state: CoverageState) -> bool {
    matches!(
        state,
        CoverageState::PresentExact
            | CoverageState::EnforcedByCurrentGuard
            | CoverageState::VerifiedRehydrated
    )
}

fn discharge_reason(d: &DischargeAssessment) -> Option<&'static str> {
    match d {
        DischargeAssessment::Pass { .. } | DischargeAssessment::NotApplicable { .. } => None,
        DischargeAssessment::Unknown => Some("unknown"),
        DischargeAssessment::Fail => Some("fail"),
        DischargeAssessment::AttributedOnly => Some("attributed_only"),
        DischargeAssessment::Missing => Some("missing"),
        DischargeAssessment::Stale => Some("stale"),
    }
}

/// Pure evaluation of one snapshot. No I/O.
///
/// # Errors
/// Typed refusal when any of the four decisions fails.
pub fn evaluate(
    state: &EffectiveDispatchState,
    intent_reserved: bool,
    _kind: EffectKind,
) -> Result<(), EffectGuardError> {
    if !intent_reserved {
        return Err(EffectGuardError::IdentityUnreserved);
    }
    if state.members.is_empty() {
        return Err(EffectGuardError::ObligationSetEmpty);
    }
    for member in &state.members {
        if !coverage_ok(member.coverage) {
            return Err(EffectGuardError::CoverageIncomplete {
                member_id: member.id.clone(),
            });
        }
    }
    for member in &state.members {
        if let Some(reason) = discharge_reason(&member.discharge) {
            return Err(EffectGuardError::PreconditionUndischarged {
                member_id: member.id.clone(),
                reason: reason.to_owned(),
            });
        }
    }
    match &state.authority {
        CurrentAuthority::Unavailable => Err(EffectGuardError::AuthorityUnavailable),
        CurrentAuthority::Current {
            epoch,
            expires_at_epoch_s,
            revoked,
        } => {
            if *revoked {
                return Err(EffectGuardError::AuthorityRevoked { epoch: *epoch });
            }
            if let Some(exp) = *expires_at_epoch_s {
                if state.now_epoch_s >= exp {
                    return Err(EffectGuardError::AuthorityExpired {
                        expires_at_epoch_s: exp,
                        now_epoch_s: state.now_epoch_s,
                    });
                }
            }
            Ok(())
        }
    }
}

impl EffectiveDispatchConfig {
    /// Admit an effect: check → await/refresh → recheck immediately before
    /// the caller may perform the effect.
    ///
    /// # Errors
    /// Typed [`EffectGuardError`]; nothing may be dispatched on `Err`.
    pub async fn admit(
        &self,
        intent_reserved: bool,
        kind: EffectKind,
    ) -> Result<(), EffectGuardError> {
        {
            let snap = self.snapshot();
            evaluate(&snap, intent_reserved, kind)?;
        }
        if let Some(hook) = self.between_checks.as_ref() {
            hook().await;
        } else {
            // Cooperative one-shot yield without requiring tokio's `rt` feature
            // (publish --dry-run verifies the crate with default features only).
            YieldOnce::default().await;
        }
        let snap = self.snapshot();
        evaluate(&snap, intent_reserved, kind)
    }
}

/// Polls `Pending` once, then `Ready`. Lets AC4-style revoke/expiry land across
/// the await without depending on `tokio::task::yield_now` (`rt` feature).
#[derive(Default)]
struct YieldOnce {
    yielded: bool,
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn member(
        id: &str,
        coverage: CoverageState,
        discharge: DischargeAssessment,
    ) -> MandatoryMember {
        MandatoryMember {
            id: id.to_owned(),
            coverage,
            discharge,
        }
    }

    fn pass(id: &str) -> DischargeAssessment {
        DischargeAssessment::Pass {
            witness_id: format!("w-{id}"),
            evaluated_at_epoch_s: 1,
        }
    }

    #[test]
    fn a_proven_b_unknown_refuses_with_b_specific_code() {
        let state = EffectiveDispatchState {
            members: vec![
                member("A", CoverageState::PresentExact, pass("A")),
                member(
                    "B",
                    CoverageState::PresentExact,
                    DischargeAssessment::Unknown,
                ),
            ],
            authority: CurrentAuthority::Current {
                epoch: 1,
                expires_at_epoch_s: None,
                revoked: false,
            },
            now_epoch_s: 10,
        };
        let err = evaluate(&state, true, EffectKind::ModelRequest).unwrap_err();
        assert_eq!(err.code(), "EFFECT_PRECONDITION_UNDISCHARGED");
        assert!(matches!(
            err,
            EffectGuardError::PreconditionUndischarged {
                member_id,
                reason
            } if member_id == "B" && reason == "unknown"
        ));
    }

    #[test]
    fn covered_but_attributed_only_is_not_discharge() {
        let state = EffectiveDispatchState {
            members: vec![member(
                "A",
                CoverageState::PresentExact,
                DischargeAssessment::AttributedOnly,
            )],
            authority: CurrentAuthority::Current {
                epoch: 1,
                expires_at_epoch_s: None,
                revoked: false,
            },
            now_epoch_s: 10,
        };
        let err = evaluate(&state, true, EffectKind::ToolEffect).unwrap_err();
        assert_eq!(err.code(), "EFFECT_PRECONDITION_UNDISCHARGED");
    }

    #[test]
    fn all_predicates_pass() {
        let state = EffectiveDispatchState {
            members: vec![
                member("A", CoverageState::PresentExact, pass("A")),
                member(
                    "B",
                    CoverageState::EnforcedByCurrentGuard,
                    DischargeAssessment::NotApplicable {
                        witness_id: "w-B".into(),
                        applicability_witness_id: "app-B".into(),
                        evaluated_at_epoch_s: 1,
                    },
                ),
            ],
            authority: CurrentAuthority::Current {
                epoch: 7,
                expires_at_epoch_s: Some(100),
                revoked: false,
            },
            now_epoch_s: 50,
        };
        evaluate(&state, true, EffectKind::ModelRequest).unwrap();
    }

    #[test]
    fn empty_set_is_not_permission() {
        let state = EffectiveDispatchState::empty_at(1);
        let err = evaluate(&state, true, EffectKind::ModelRequest).unwrap_err();
        assert_eq!(err.code(), "EFFECT_OBLIGATION_SET_EMPTY");
    }

    #[test]
    fn missing_reservation_refuses() {
        let state = EffectiveDispatchState {
            members: vec![member("A", CoverageState::PresentExact, pass("A"))],
            authority: CurrentAuthority::Current {
                epoch: 1,
                expires_at_epoch_s: None,
                revoked: false,
            },
            now_epoch_s: 1,
        };
        let err = evaluate(&state, false, EffectKind::ModelRequest).unwrap_err();
        assert_eq!(err.code(), "EFFECT_IDENTITY_UNRESERVED");
    }
}
