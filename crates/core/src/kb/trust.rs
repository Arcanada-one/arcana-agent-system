//! `trust_class` dispatch — the sharpest cross-track control shared with the
//! skills path.
//!
//! The KB is a shared supply chain for **behaviour** (`skill`-class documents,
//! executable) AND **evidence** (`evidence`-class documents, inert). Both flow
//! through the same `POST /v1/fetch` primitive, so the two trust models must NOT
//! collapse. Arcana dispatches on the server-derived `trust_class`:
//!
//! * `skill`    → the signature-verified execution path (`arcana-skills`'
//!   blake3-pin + maturity + allowlist-ceiling gates).
//! * `evidence` → the fenced / datamarked inert-data path (this crate's KB
//!   cascade).
//!
//! **No cross-promotion.** Evidence is never interpretable as / promoted to a
//! skill, and a skill payload is never silently demoted to free-text evidence.
//! The KB evidence cascade calls [`admit_evidence`], which admits ONLY an
//! `evidence`-class document; a `skill`-class (or unknown) document is refused
//! before any fetch, parse, or fence. The `trust_class` is always the
//! server-side response-envelope field, never the document body (a body
//! containing `"trust_class":"skill"` cannot forge it).

/// The `trust_class` value a runnable skill document carries.
pub const SKILL_TRUST_CLASS: &str = "skill";
/// The `trust_class` value an inert evidence document carries.
pub const EVIDENCE_TRUST_CLASS: &str = "evidence";

/// A parsed KB trust classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustClass {
    /// Executable behaviour — routes to the signed-exec skills path.
    Skill,
    /// Inert evidence — routes to the fenced-inert cascade.
    Evidence,
    /// Anything else: fail closed, never guessed into a known class.
    Unknown(String),
}

impl TrustClass {
    /// Parse the server-side `trust_class` string.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw {
            SKILL_TRUST_CLASS => Self::Skill,
            EVIDENCE_TRUST_CLASS => Self::Evidence,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// Which arcana-side handling path a document dispatches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// The signature-verified execution path (skills).
    SignedExec,
    /// The fenced / datamarked inert-data path (this cascade).
    FencedInert,
}

/// A `trust_class` dispatch failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// A document of the wrong class was offered to a class-specific path — the
    /// no-cross-promotion boundary. Carries what was seen for the audit spine.
    #[error("cross-promotion refused: {trust_class:?} document offered to the {expected} path")]
    CrossPromotion {
        /// The rejected server-side `trust_class`.
        trust_class: String,
        /// The path that refused it (e.g. `"evidence/fenced-inert"`).
        expected: &'static str,
    },
    /// The `trust_class` matched no known class — fail closed.
    #[error("unknown trust_class: {0:?}")]
    Unknown(String),
}

/// Route a server-side `trust_class` to its handling path.
///
/// # Errors
/// Returns [`TrustError::Unknown`] for any class that is neither `skill` nor
/// `evidence` (fail closed — a class is never guessed).
pub fn route(server_trust_class: &str) -> Result<Dispatch, TrustError> {
    match TrustClass::parse(server_trust_class) {
        TrustClass::Skill => Ok(Dispatch::SignedExec),
        TrustClass::Evidence => Ok(Dispatch::FencedInert),
        TrustClass::Unknown(class) => Err(TrustError::Unknown(class)),
    }
}

/// Admit a document into the **evidence** (fenced-inert) cascade.
///
/// Admits ONLY an `evidence`-class document. A `skill`-class document is
/// refused with [`TrustError::CrossPromotion`] (no silent free-text demotion);
/// an unknown class is refused with [`TrustError::Unknown`]. The argument is
/// always the server-side envelope field.
///
/// # Errors
/// [`TrustError::CrossPromotion`] for a `skill`-class document;
/// [`TrustError::Unknown`] for any unrecognised class.
pub fn admit_evidence(server_trust_class: &str) -> Result<(), TrustError> {
    match route(server_trust_class)? {
        Dispatch::FencedInert => Ok(()),
        Dispatch::SignedExec => Err(TrustError::CrossPromotion {
            trust_class: server_trust_class.to_owned(),
            expected: "evidence/fenced-inert",
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn evidence_routes_to_fenced_inert() {
        assert_eq!(route("evidence").unwrap(), Dispatch::FencedInert);
    }

    #[test]
    fn skill_routes_to_signed_exec() {
        assert_eq!(route("skill").unwrap(), Dispatch::SignedExec);
    }

    #[test]
    fn unknown_class_fails_closed() {
        assert!(matches!(route("gibberish"), Err(TrustError::Unknown(_))));
    }

    #[test]
    fn admit_evidence_accepts_evidence() {
        assert!(admit_evidence("evidence").is_ok());
    }

    #[test]
    fn admit_evidence_refuses_skill_no_cross_promotion() {
        // A skill-class doc entering the evidence cascade is REFUSED, never
        // silently demoted to free-text evidence.
        assert!(matches!(
            admit_evidence("skill"),
            Err(TrustError::CrossPromotion { .. })
        ));
    }

    #[test]
    fn admit_evidence_refuses_unknown() {
        assert!(matches!(admit_evidence(""), Err(TrustError::Unknown(_))));
    }
}
