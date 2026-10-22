//! Synthetic provider predicates only: no issuer keys, grants or live effects.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arcana_core::contract::{digest_of, verify, ContractBinding, ContractDocument};
use arcana_core::contract_authority::{
    admit_then, AuthenticatedContractAuthority as Proof, AuthorityRefusal as Refusal,
    AuthorityTrust, ContractAuthorityProvider, EffectAcceptanceProvider, EffectDispatchOutcome,
    EffectDispatchRequest, EffectRefusal, UnavailableContractAuthority, UnavailableEffectProvider,
    WorkItemScope,
};
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashSet;
use std::sync::Mutex;

fn binding() -> ContractBinding {
    let text = "synthetic read-only contract";
    let digest = digest_of(text.as_bytes());
    let doc: ContractDocument = serde_json::from_value(json!({
        "digest": digest, "projection": text, "tools": {"allow": ["read"]},
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

fn effect_request() -> EffectDispatchRequest {
    EffectDispatchRequest {
        contract_digest: "fixture-contract-digest".into(),
        task_id: "fixture-task".into(),
        project_id: "fixture-project".into(),
        subject_id: "fixture-executor".into(),
        participant_id: "fixture-effect-participant".into(),
        request_id: "fixture-single-use-request".into(),
        issued_generation: 7,
        effect_digest: "fixture-effect-digest".into(),
    }
}

/// Predicate fixture only. This models a provider boundary for deterministic
/// source controls; it is not an authority-domain participant and cannot clear
/// T51/KC or establish a live revocation/effect fence.
struct PredicateOnlyEffectProvider {
    expected: EffectDispatchRequest,
    current_generation: u64,
    revoked: bool,
    consumed: Mutex<HashSet<String>>,
    acceptance_count: Mutex<usize>,
}

impl PredicateOnlyEffectProvider {
    fn new(expected: EffectDispatchRequest, current_generation: u64, revoked: bool) -> Self {
        Self {
            expected,
            current_generation,
            revoked,
            consumed: Mutex::new(HashSet::new()),
            acceptance_count: Mutex::new(0),
        }
    }

    fn acceptance_count(&self) -> usize {
        *self.acceptance_count.lock().unwrap()
    }
}

#[async_trait]
impl EffectAcceptanceProvider for PredicateOnlyEffectProvider {
    async fn accept_and_dispatch(
        &self,
        request: &EffectDispatchRequest,
    ) -> Result<EffectDispatchOutcome, EffectRefusal> {
        if request.participant_id != self.expected.participant_id {
            return Err(EffectRefusal::UnknownParticipant);
        }
        if self.revoked {
            return Err(EffectRefusal::Revoked);
        }
        if request.issued_generation != self.current_generation {
            return Err(EffectRefusal::StaleRequest);
        }
        if request != &self.expected {
            return Err(EffectRefusal::RequestMismatch);
        }

        let mut consumed = self.consumed.lock().unwrap();
        if !consumed.insert(request.request_id.clone()) {
            return Err(EffectRefusal::DuplicateRequest);
        }
        *self.acceptance_count.lock().unwrap() += 1;
        Ok(EffectDispatchOutcome {
            request_id: request.request_id.clone(),
            effect_digest: request.effect_digest.clone(),
        })
    }
}

#[tokio::test]
async fn unavailable_effect_provider_refuses_with_stable_code() {
    let result = UnavailableEffectProvider
        .accept_and_dispatch(&effect_request())
        .await;

    assert_eq!(result, Err(EffectRefusal::ProviderUnavailable));
    assert_eq!(
        EffectRefusal::ProviderUnavailable.code(),
        "EFFECT_PROVIDER_UNAVAILABLE"
    );
}

#[tokio::test]
async fn predicate_only_provider_positive_binds_one_exact_request() {
    let request = effect_request();
    let provider = PredicateOnlyEffectProvider::new(request.clone(), 7, false);

    let result = provider.accept_and_dispatch(&request).await;

    assert_eq!(
        result,
        Ok(EffectDispatchOutcome {
            request_id: request.request_id,
            effect_digest: request.effect_digest,
        })
    );
    assert_eq!(provider.acceptance_count(), 1);
}

#[tokio::test]
async fn unknown_participant_stale_altered_and_revoked_requests_refuse_before_acceptance() {
    let request = effect_request();

    let unknown = PredicateOnlyEffectProvider::new(request.clone(), 7, false);
    let mut unknown_request = request.clone();
    unknown_request.participant_id = "unqualified-participant".into();
    assert_eq!(
        unknown.accept_and_dispatch(&unknown_request).await,
        Err(EffectRefusal::UnknownParticipant)
    );
    assert_eq!(unknown.acceptance_count(), 0);

    let stale = PredicateOnlyEffectProvider::new(request.clone(), 7, false);
    let mut stale_request = request.clone();
    stale_request.issued_generation = 6;
    assert_eq!(
        stale.accept_and_dispatch(&stale_request).await,
        Err(EffectRefusal::StaleRequest)
    );
    assert_eq!(stale.acceptance_count(), 0);

    let altered = PredicateOnlyEffectProvider::new(request.clone(), 7, false);
    let mut altered_request = request.clone();
    altered_request.effect_digest = "different-effect-digest".into();
    assert_eq!(
        altered.accept_and_dispatch(&altered_request).await,
        Err(EffectRefusal::RequestMismatch)
    );
    assert_eq!(altered.acceptance_count(), 0);

    let revoked = PredicateOnlyEffectProvider::new(request.clone(), 7, true);
    assert_eq!(
        revoked.accept_and_dispatch(&request).await,
        Err(EffectRefusal::Revoked)
    );
    assert_eq!(revoked.acceptance_count(), 0);
}

#[tokio::test]
async fn duplicate_request_refuses_without_a_second_acceptance() {
    let request = effect_request();
    let provider = PredicateOnlyEffectProvider::new(request.clone(), 7, false);

    assert!(provider.accept_and_dispatch(&request).await.is_ok());
    assert_eq!(provider.acceptance_count(), 1);
    assert_eq!(
        provider.accept_and_dispatch(&request).await,
        Err(EffectRefusal::DuplicateRequest)
    );
    assert_eq!(provider.acceptance_count(), 1);
}
