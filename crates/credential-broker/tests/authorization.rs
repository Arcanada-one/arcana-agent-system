//! Broker authorization falsifiers (V-AC-3).
//!
//! One scoped request succeeds. Every wrong or missing axis fails **before** any
//! side effect, and duplicate/replay proves exactly one committed operation and
//! one quota charge.
//!
//! No real credential appears here: the broker deals in permissions, and these
//! tests never touch a secret source at all.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_credential_broker::policy::ProviderRule;
use arcana_credential_broker::protocol::{ExactSet, SessionId};
use arcana_credential_broker::{
    authorize, CapabilityPolicy, CapabilityRequest, Denial, ExecutorProfile, Generation,
    IdempotencyKey, Ledger, Operation, PeerIdentity, RequestFingerprint,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const NOW: u64 = 1_000_000;
const EXECUTOR_UID: u32 = 1000;
const EXE: &str = "/opt/arcana/bin/arcana";
const SESSION: &str = "session-abc";
const UPSTREAM: &str = "https://api.example-provider.test/v1";

fn policy() -> CapabilityPolicy {
    let mut models: ExactSet = ExactSet::new();
    models.insert("model-small".to_owned());

    let mut operations = BTreeSet::new();
    operations.insert(Operation::Completion);

    let mut providers = BTreeMap::new();
    providers.insert(
        "mockprovider".to_owned(),
        ProviderRule {
            models,
            operations,
            quota_costs: BTreeMap::from([(Operation::Completion, 1)]),
            upstream: UPSTREAM.to_owned(),
        },
    );

    let mut executables = BTreeSet::new();
    executables.insert(PathBuf::from(EXE));
    let mut profiles = BTreeSet::new();
    profiles.insert(ExecutorProfile("supervised-executor".to_owned()));
    let mut sessions = BTreeSet::new();
    sessions.insert(SESSION.to_owned());

    CapabilityPolicy {
        generation: Generation(7),
        executor_uid: EXECUTOR_UID,
        executables,
        profiles,
        sessions,
        providers,
        quota_limit: 10,
    }
}

fn request() -> CapabilityRequest {
    CapabilityRequest {
        peer: PeerIdentity {
            uid: EXECUTOR_UID,
            pid: 4242,
            executable: PathBuf::from(EXE),
            session: SessionId(SESSION.to_owned()),
        },
        profile: ExecutorProfile("supervised-executor".to_owned()),
        generation: Generation(7),
        provider: "mockprovider".to_owned(),
        model: "model-small".to_owned(),
        operation: Operation::Completion,
        upstream: UPSTREAM.to_owned(),
        quota_units: 1,
        expires_at: NOW + 60,
        idempotency: IdempotencyKey("idem-001".to_owned()),
        fingerprint: RequestFingerprint("fingerprint-001".to_owned()),
    }
}

fn ledger() -> Ledger {
    Ledger::new(Generation(7), 10)
}

// --- positive control ------------------------------------------------------

#[test]
fn scoped_request_succeeds() {
    policy().validate().expect("policy validates");
    let lease = authorize(&policy(), &mut ledger(), &request(), NOW).expect("scoped request");
    assert_eq!(lease.provider, "mockprovider");
    assert_eq!(lease.charged, 1);
    assert!(!lease.replayed);
}

#[test]
fn policy_refuses_missing_or_zero_trusted_quota_cost() {
    let mut missing = policy();
    missing
        .providers
        .get_mut("mockprovider")
        .expect("provider")
        .quota_costs
        .clear();
    assert!(missing.validate().is_err());

    let mut zero = policy();
    zero.providers
        .get_mut("mockprovider")
        .expect("provider")
        .quota_costs
        .insert(Operation::Completion, 0);
    assert!(zero.validate().is_err());
}

// --- one falsifier per axis ------------------------------------------------

/// Each case mutates exactly one axis and asserts the exact denial.
fn assert_denied(mutate: impl FnOnce(&mut CapabilityRequest), expected: Denial, axis: &str) {
    let mut req = request();
    mutate(&mut req);
    let mut led = ledger();
    let got = authorize(&policy(), &mut led, &req, NOW);
    assert_eq!(
        got.err(),
        Some(expected),
        "axis `{axis}` did not fail closed as expected"
    );
    // Nothing may be charged or committed by a denied request.
    assert_eq!(
        led.quota_spent(),
        0,
        "axis `{axis}` charged quota on denial"
    );
    assert_eq!(
        led.committed_count(),
        0,
        "axis `{axis}` committed an outcome on denial"
    );
}

#[test]
fn wrong_peer_uid_fails_closed() {
    assert_denied(|r| r.peer.uid = 0, Denial::PeerUid, "peer uid");
}

#[test]
fn wrong_executable_fails_closed() {
    assert_denied(
        |r| r.peer.executable = PathBuf::from("/bin/sh"),
        Denial::PeerExecutable,
        "executable",
    );
}

#[test]
fn wrong_profile_fails_closed() {
    assert_denied(
        |r| r.profile = ExecutorProfile("unsupervised".to_owned()),
        Denial::Profile,
        "profile",
    );
}

#[test]
fn wrong_session_fails_closed() {
    assert_denied(
        |r| r.peer.session = SessionId("session-other".to_owned()),
        Denial::Session,
        "session",
    );
}

#[test]
fn stale_generation_fails_closed() {
    assert_denied(
        |r| r.generation = Generation(6),
        Denial::StaleGeneration,
        "stale generation",
    );
}

/// A caller claiming a *future* generation is as wrong as one claiming a past.
#[test]
fn future_generation_fails_closed() {
    assert_denied(
        |r| r.generation = Generation(8),
        Denial::StaleGeneration,
        "future generation",
    );
}

#[test]
fn wrong_provider_fails_closed() {
    assert_denied(
        |r| r.provider = "otherprovider".to_owned(),
        Denial::Provider,
        "provider",
    );
}

#[test]
fn wrong_model_fails_closed() {
    assert_denied(
        |r| r.model = "model-huge".to_owned(),
        Denial::Model,
        "model",
    );
}

#[test]
fn disallowed_operation_fails_closed() {
    assert_denied(
        |r| r.operation = Operation::ListModels,
        Denial::OperationNotAllowed,
        "operation",
    );
}

#[test]
fn wrong_upstream_fails_closed() {
    assert_denied(
        |r| r.upstream = "https://attacker.test/v1".to_owned(),
        Denial::Upstream,
        "upstream",
    );
}

#[test]
fn expired_request_fails_closed() {
    assert_denied(|r| r.expires_at = NOW, Denial::Expired, "expiry");
}

#[test]
fn missing_idempotency_key_fails_closed() {
    assert_denied(
        |r| r.idempotency = IdempotencyKey("   ".to_owned()),
        Denial::MissingIdempotencyKey,
        "idempotency",
    );
}

#[test]
fn malformed_or_oversized_idempotency_key_fails_closed() {
    for key in ["contains space", "slash/not-allowed"] {
        assert_denied(
            |r| r.idempotency = IdempotencyKey(key.to_owned()),
            Denial::InvalidIdempotencyKey,
            "idempotency format",
        );
    }
    assert_denied(
        |r| r.idempotency = IdempotencyKey("x".repeat(129)),
        Denial::InvalidIdempotencyKey,
        "idempotency length",
    );
}

/// A wildcard is not a broad grant — it is a malformed request.
#[test]
fn wildcard_fields_fail_closed() {
    type Mutate = fn(&mut CapabilityRequest);
    let cases: [(&str, Mutate); 3] = [
        ("provider", |r| r.provider = "*".to_owned()),
        ("model", |r| r.model = "ALL".to_owned()),
        ("upstream", |r| r.upstream = "any".to_owned()),
    ];
    for (label, mutate) in cases {
        assert_denied(mutate, Denial::WildcardOrEmpty, label);
    }
}

#[test]
fn empty_fields_fail_closed() {
    assert_denied(
        |r| r.model = String::new(),
        Denial::WildcardOrEmpty,
        "empty model",
    );
}

// --- quota, duplicate, replay ---------------------------------------------

#[test]
fn over_quota_fails_closed() {
    let mut led = Ledger::new(Generation(7), 0);
    let req = request();
    assert_eq!(
        authorize(&policy(), &mut led, &req, NOW).err(),
        Some(Denial::QuotaExceeded)
    );
    assert_eq!(led.quota_spent(), 0);
}

#[test]
fn quota_accumulates_and_then_refuses() {
    let pol = policy();
    let mut led = ledger();
    for i in 0..10 {
        let mut req = request();
        req.idempotency = IdempotencyKey(format!("idem-{i:03}"));
        authorize(&pol, &mut led, &req, NOW).expect("within quota");
    }
    assert_eq!(led.quota_spent(), 10);

    let mut over = request();
    over.idempotency = IdempotencyKey("idem-final".to_owned());
    assert_eq!(
        authorize(&pol, &mut led, &over, NOW).err(),
        Some(Denial::QuotaExceeded)
    );
    assert_eq!(led.quota_spent(), 10, "a refused request must not charge");
}

/// The core retry property: one committed operation, one quota charge.
#[test]
fn duplicate_request_replays_without_repeating_side_effect() {
    let pol = policy();
    let mut led = ledger();
    let req = request();

    let first = authorize(&pol, &mut led, &req, NOW).expect("first");
    assert!(!first.replayed);
    assert_eq!(first.charged, 1);

    let retry = authorize(&pol, &mut led, &req, NOW).expect("retry");
    assert!(retry.replayed, "retry must be served as a replay");
    assert_eq!(retry.charged, 0, "retry must not charge quota again");
    assert_eq!(
        retry.outcome_id, first.outcome_id,
        "retry must replay the original outcome, not create a new one"
    );

    assert_eq!(led.quota_spent(), 1, "exactly one quota charge");
    assert_eq!(led.committed_count(), 1, "exactly one committed operation");
}

#[test]
fn reused_key_with_different_fingerprint_fails_closed() {
    let pol = policy();
    let mut led = ledger();
    let req = request();
    authorize(&pol, &mut led, &req, NOW).expect("first");

    let mut changed = req;
    changed.fingerprint = RequestFingerprint("fingerprint-other".to_owned());
    assert_eq!(
        authorize(&pol, &mut led, &changed, NOW).err(),
        Some(Denial::IdempotencyConflict)
    );
    assert_eq!(led.quota_spent(), 1);
    assert_eq!(led.committed_count(), 1);
}

/// A replay of a still-valid key survives quota exhaustion: it is not a charge.
#[test]
fn replay_succeeds_even_when_quota_is_exhausted() {
    let pol = policy();
    let mut led = ledger();
    let req = request();
    let first = authorize(&pol, &mut led, &req, NOW).expect("first");

    for i in 1..10 {
        let mut filler = request();
        filler.idempotency = IdempotencyKey(format!("filler-{i:03}"));
        authorize(&pol, &mut led, &filler, NOW).expect("filler");
    }
    assert_eq!(led.quota_spent(), 10);

    let retry = authorize(&pol, &mut led, &req, NOW).expect("replay under exhausted quota");
    assert!(retry.replayed);
    assert_eq!(retry.outcome_id, first.outcome_id);
    assert_eq!(led.quota_spent(), 10);
}

/// Policy is evaluated before the ledger, so a denied replay-key request cannot
/// resurrect a committed outcome under a different scope.
#[test]
fn denied_request_never_reaches_the_ledger() {
    let pol = policy();
    let mut led = ledger();
    let mut req = request();
    req.provider = "otherprovider".to_owned();
    assert!(authorize(&pol, &mut led, &req, NOW).is_err());
    assert_eq!(led.committed_count(), 0);
}

#[test]
fn deserialized_ledger_rejects_inconsistent_quota_and_outcome_state() {
    let pol = policy();
    let mut valid = ledger();
    authorize(&pol, &mut valid, &request(), NOW).expect("commit");
    assert!(valid.durable_invariants_hold());

    for (field, value) in [
        ("quota_spent", serde_json::json!(0)),
        ("next_outcome", serde_json::json!(99)),
        ("max_entries", serde_json::json!(0)),
    ] {
        let mut encoded = serde_json::to_value(&valid).expect("serialize");
        encoded[field] = value;
        let corrupted: Ledger = serde_json::from_value(encoded).expect("deserialize");
        assert!(
            !corrupted.durable_invariants_hold(),
            "corruption of {field} must fail closed"
        );
    }
}
