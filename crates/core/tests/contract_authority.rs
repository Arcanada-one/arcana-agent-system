//! Synthetic provider predicates only: no issuer keys, grants or live effects.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_core::contract::{digest_of, verify, ContractBinding, ContractDocument};
use arcana_core::contract_authority::{
    admit_then, AuthenticatedContractAuthority as Proof, AuthorityRefusal as Refusal,
    AuthorityTrust, ContractAuthorityProvider, UnavailableContractAuthority, WorkItemScope,
};
use async_trait::async_trait;
use serde_json::json;

fn binding() -> ContractBinding {
    // The allowlist lives inside the digested bytes: an envelope-only `tools`
    // is refused (CONTRACT_POLICY_UNBOUND), so a fixture states it in the body.
    let text = r#"{"role":"synthetic","tools":{"allow":["read"]}}{"revisions":[]}"#;
    let digest = digest_of(text.as_bytes());
    let doc: ContractDocument = serde_json::from_value(json!({
        "digest": digest, "canonical_bytes": text,
    }))
    .unwrap();
    verify(&digest, &doc).unwrap()
}

fn scope() -> WorkItemScope {
    WorkItemScope {
        task_id: "fixture-task".into(),
        project_id: Some("fixture-project".into()),
        subject_id: Some("fixture-executor".into()),
    }
}

fn trust() -> AuthorityTrust {
    AuthorityTrust {
        issuer: "fixture-trusted-issuer".into(),
        audience: "fixture-task-run-audience".into(),
        verifier_pin: "fixture-verifier-source-pin".into(),
    }
}

fn proof() -> Proof {
    Proof {
        contract_digest: binding().digest().into(),
        task_id: "fixture-task".into(),
        project_id: "fixture-project".into(),
        subject_id: "fixture-executor".into(),
        issuer: trust().issuer,
        audience: trust().audience,
        verifier_pin: trust().verifier_pin,
        issuer_principal: "fixture-independent-principal".into(),
        issuer_incarnation: "fixture-independent-incarnation".into(),
        proposer_lineage: vec![
            "fixture-proposer".into(),
            "fixture-proposer-incarnation".into(),
        ],
        executor_lineage: vec![
            "fixture-executor".into(),
            "fixture-executor-incarnation".into(),
        ],
        signature_verified: true,
        standing_verified: true,
        issued_generation: 5,
        current_generation: Some(5),
        revoked: false,
    }
}

struct FixtureProvider(fn(&mut Proof));
#[async_trait]
impl ContractAuthorityProvider for FixtureProvider {
    async fn authenticate(&self, _: &ContractBinding, _: &WorkItemScope) -> Result<Proof, Refusal> {
        let mut value = proof();
        (self.0)(&mut value);
        Ok(value)
    }
}

/// Each single-field negative has a fresh same-fixture positive. Refusals use
/// a continuation that panics at the point where a model client would be built.
async fn paired(mutate: fn(&mut Proof), expected: Refusal) {
    let positive = admit_then(
        binding(),
        &scope(),
        &FixtureProvider(|_| {}),
        Some(&trust()),
        |permit| async move {
            assert!(permit.binding().admits("read"));
            assert!(!permit.binding().admits("write"));
            "fixture continuation only"
        },
    )
    .await;
    assert_eq!(positive.unwrap(), "fixture continuation only");
    let result = admit_then(
        binding(),
        &scope(),
        &FixtureProvider(mutate),
        Some(&trust()),
        |permit| async move {
            assert!(
                permit.binding().digest().is_empty(),
                "Model Connector construction must be unreachable on refusal"
            );
        },
    )
    .await;
    assert_eq!(result.err(), Some(expected));
}

#[tokio::test]
async fn task_project_and_subject_are_individually_bound() {
    paired(
        |p| p.task_id = "other-task".into(),
        Refusal::SubjectMismatch,
    )
    .await;
    paired(
        |p| p.project_id = "other-project".into(),
        Refusal::SubjectMismatch,
    )
    .await;
    paired(
        |p| p.subject_id = "other-subject".into(),
        Refusal::SubjectMismatch,
    )
    .await;
}

#[tokio::test]
async fn signature_standing_and_trust_are_individually_required() {
    paired(|p| p.signature_verified = false, Refusal::IssuerUnverified).await;
    paired(|p| p.standing_verified = false, Refusal::IssuerUnverified).await;
    paired(
        |p| p.issuer = "untrusted-key-issuer".into(),
        Refusal::IssuerUnverified,
    )
    .await;
    paired(
        |p| p.audience = "promotion-is-not-task-run".into(),
        Refusal::IssuerUnverified,
    )
    .await;
    paired(
        |p| p.verifier_pin = "different-verifier".into(),
        Refusal::IssuerUnverified,
    )
    .await;
    paired(
        |p| p.contract_digest = digest_of(b"other-bytes"),
        Refusal::IssuerUnverified,
    )
    .await;
}

#[tokio::test]
async fn issuer_principal_and_incarnation_must_be_independent_of_both_roles() {
    paired(
        |p| p.issuer_principal = p.proposer_lineage[0].clone(),
        Refusal::IssuerNotIndependent,
    )
    .await;
    paired(
        |p| p.issuer_principal = p.executor_lineage[0].clone(),
        Refusal::IssuerNotIndependent,
    )
    .await;
    paired(
        |p| p.issuer_incarnation = p.proposer_lineage[1].clone(),
        Refusal::IssuerNotIndependent,
    )
    .await;
    paired(
        |p| p.issuer_incarnation = p.executor_lineage[1].clone(),
        Refusal::IssuerNotIndependent,
    )
    .await;
}

#[tokio::test]
async fn revocation_and_current_generation_refuse_old_bytes_including_aba() {
    paired(|p| p.revoked = true, Refusal::Revoked).await;
    // Same digest after clear/rebind is insufficient: the epoch must be current.
    paired(|p| p.current_generation = Some(6), Refusal::Revoked).await;
    paired(|p| p.current_generation = Some(4), Refusal::Revoked).await;
    paired(|p| p.current_generation = None, Refusal::Unavailable).await;
}

#[tokio::test]
async fn missing_independence_custody_is_not_an_empty_safe_lineage() {
    paired(
        |p| p.proposer_lineage = vec![String::new()],
        Refusal::Unavailable,
    )
    .await;
    paired(
        |p| p.executor_lineage = vec![String::new()],
        Refusal::Unavailable,
    )
    .await;
    paired(|p| p.proposer_lineage.clear(), Refusal::Unavailable).await;
    paired(|p| p.executor_lineage.clear(), Refusal::Unavailable).await;
    paired(|p| p.issuer_principal.clear(), Refusal::IssuerUnverified).await;
    paired(|p| p.issuer_incarnation.clear(), Refusal::IssuerUnverified).await;
}

#[tokio::test]
async fn unavailable_provider_never_constructs_a_model_client() {
    let result = admit_then(
        binding(),
        &scope(),
        &UnavailableContractAuthority,
        Some(&trust()),
        |permit| async move {
            assert!(
                permit.binding().digest().is_empty(),
                "Model Connector constructor"
            );
        },
    )
    .await;
    assert_eq!(result.err(), Some(Refusal::Unavailable));
}

#[tokio::test]
async fn missing_authenticated_caller_project_or_trust_never_uses_defaults() {
    for field in ["subject", "project", "trust"] {
        let mut expected = scope();
        if field == "subject" {
            expected.subject_id = None;
        }
        if field == "project" {
            expected.project_id = None;
        }
        let trusted = trust();
        let configuration = if field == "trust" {
            None
        } else {
            Some(&trusted)
        };
        let result = admit_then(
            binding(),
            &expected,
            &FixtureProvider(|_| {}),
            configuration,
            |permit| async move {
                assert!(
                    permit.binding().digest().is_empty(),
                    "Model Connector constructor"
                );
            },
        )
        .await;
        assert_eq!(result.err(), Some(Refusal::Unavailable));
    }
}

#[test]
fn refusal_codes_are_specific_and_stable() {
    assert_eq!(Refusal::SubjectMismatch.code(), "CONTRACT_SUBJECT_MISMATCH");
    assert_eq!(
        Refusal::IssuerUnverified.code(),
        "CONTRACT_ISSUER_UNVERIFIED"
    );
    assert_eq!(
        Refusal::IssuerNotIndependent.code(),
        "CONTRACT_ISSUER_NOT_INDEPENDENT"
    );
    assert_eq!(Refusal::Revoked.code(), "CONTRACT_REVOKED");
    assert_eq!(
        Refusal::Unavailable.code(),
        "CONTRACT_AUTHORITY_UNAVAILABLE"
    );
}

#[tokio::test]
async fn acting_subject_cannot_issue_even_if_adapter_omits_it_from_lineage() {
    paired(
        |p| {
            p.executor_lineage = vec!["fixture-other-executor".into()];
            p.issuer_principal.clone_from(&p.subject_id);
        },
        Refusal::IssuerNotIndependent,
    )
    .await;
}

#[tokio::test]
async fn acting_subject_cannot_be_issuer_incarnation_with_incomplete_lineage() {
    paired(
        |p| {
            p.executor_lineage = vec!["fixture-other-executor".into()];
            p.issuer_incarnation.clone_from(&p.subject_id);
        },
        Refusal::IssuerNotIndependent,
    )
    .await;
}

#[tokio::test]
async fn executor_lineage_must_anchor_the_actual_acting_subject() {
    paired(
        |p| p.executor_lineage = vec!["fixture-other-executor".into()],
        Refusal::SubjectMismatch,
    )
    .await;
}

/// SM-08 boundary, stated by test: admission is point-in-time. A provider that
/// starts answering "revoked" AFTER admission changes nothing for the running
/// continuation — the provider is asked exactly once and nothing re-asks it
/// before an effect. A revocation before admission is refused (see
/// `revocation_and_current_generation_refuse_old_bytes_including_aba`). This
/// test records the limit; it does not claim an effect-time fence exists.
#[tokio::test]
async fn admission_is_not_a_lease_a_later_revocation_does_not_reach_the_continuation() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Flip {
        asked: AtomicUsize,
        revoked: Arc<AtomicBool>,
    }
    #[async_trait]
    impl ContractAuthorityProvider for Flip {
        async fn authenticate(
            &self,
            _binding: &ContractBinding,
            _scope: &WorkItemScope,
        ) -> Result<Proof, Refusal> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            let mut p = proof();
            p.revoked = self.revoked.load(Ordering::SeqCst);
            Ok(p)
        }
    }
    let revoked = Arc::new(AtomicBool::new(false));
    let provider = Flip {
        asked: AtomicUsize::new(0),
        revoked: Arc::clone(&revoked),
    };
    let ran = admit_then(
        binding(),
        &scope(),
        &provider,
        Some(&trust()),
        |_admitted| {
            let revoked = Arc::clone(&revoked);
            async move {
                // Authority is revoked while the continuation is "mid-effect".
                revoked.store(true, Ordering::SeqCst);
                "effect-after-revocation-still-ran"
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(ran, "effect-after-revocation-still-ran");
    assert_eq!(
        provider.asked.load(Ordering::SeqCst),
        1,
        "no re-check exists"
    );

    // A fresh admission after the revocation IS refused.
    let again = admit_then(binding(), &scope(), &provider, Some(&trust()), |_a| async {
        panic!("revoked authority must not reach the continuation")
    })
    .await;
    assert_eq!(again.err(), Some(Refusal::Revoked));
}
