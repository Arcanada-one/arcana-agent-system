//! R2 (KCLIVE-11): profile-marked bytes must not enter the legacy route, so omitting
//! `--contract-profile` can never downgrade a profile contract; and the execution-profile gate
//! (`satisfies_profile`) is satisfied only by a strict binding over a verified pin (R1).
//!
//! The route is chosen exactly as `arcana run --work-item` chooses it: the flag present selects
//! `ReaderMode::Strict`, absent selects `ReaderMode::Legacy`. Admission uses a SYNTHETIC authority
//! provider (no issuer, key, grant or live effect) and a continuation counter: on every refusal the
//! counter must stay 0 - the point where a model client would be built is never reached.
//! Positives are producer-generated (`fixtures/kc2_tools_producer`, regenerate with `emit.py`);
//! legacy cases are actual pre-profile bytes. Nothing here is live and nothing is a grant.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::sync::atomic::{AtomicUsize, Ordering};

use arcana_core::contract::{
    digest_of, verify, verify_with, verify_with_pin, AllowlistSource, CanonicalBlock,
    ContractBinding, ContractDocument, ReaderMode, ReaderRoute, SchemaPin, STRICT_PROFILE,
    TALOMNIA_SCHEMA_PIN,
};
use arcana_core::contract_authority::{
    admit_then, AuthenticatedContractAuthority as Proof, AuthorityRefusal, AuthorityTrust,
    ContractAuthorityProvider, WorkItemScope,
};
use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{json, Value};

const PRODUCER: &str = include_str!("fixtures/kc2_tools_producer/producer_positives.json");

fn fixtures() -> Value {
    serde_json::from_str(PRODUCER).unwrap()
}

fn doc_of(body: &str, manifest: &str) -> (String, ContractDocument) {
    let bytes = format!("{body}{manifest}");
    let digest = digest_of(bytes.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes.as_bytes());
    (
        digest.clone(),
        ContractDocument {
            digest,
            canonical: Some(CanonicalBlock {
                bytes_b64: Some(b64),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
}

fn producer_doc(name: &str) -> (String, ContractDocument) {
    let case = &fixtures()["cases"][name];
    doc_of(
        case["body_text"].as_str().unwrap(),
        case["manifest_text"].as_str().unwrap(),
    )
}

fn legacy_doc() -> (String, ContractDocument) {
    let legacy = &fixtures()["legacy_v2"];
    let (d, doc) = doc_of(
        legacy["body_text"].as_str().unwrap(),
        legacy["manifest_text"].as_str().unwrap(),
    );
    assert_eq!(d, legacy["digest"].as_str().unwrap());
    (d, doc)
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

/// A synthetic provider that authenticates exactly the binding it is asked about.
struct Provider;

#[async_trait]
impl ContractAuthorityProvider for Provider {
    async fn authenticate(
        &self,
        binding: &ContractBinding,
        _: &WorkItemScope,
    ) -> Result<Proof, AuthorityRefusal> {
        Ok(Proof {
            contract_digest: binding.digest().into(),
            task_id: "fixture-task".into(),
            project_id: "fixture-project".into(),
            subject_id: "fixture-executor".into(),
            issuer: trust().issuer,
            audience: trust().audience,
            verifier_pin: trust().verifier_pin,
            issuer_principal: "fixture-independent-principal".into(),
            issuer_incarnation: "fixture-independent-incarnation".into(),
            proposer_lineage: vec!["fixture-proposer".into(), "fixture-proposer-inc".into()],
            executor_lineage: vec!["fixture-executor".into(), "fixture-executor-inc".into()],
            signature_verified: true,
            standing_verified: true,
            issued_generation: 5,
            current_generation: Some(5),
            revoked: false,
        })
    }
}

/// What `work_item::run` does after the fetch: the flag chooses the mode, the digest is re-hashed
/// and bound, and only then does admission (and the continuation) run. Returns the refusal code,
/// or the binding the continuation saw.
async fn run(
    flag: Option<&str>,
    digest: &str,
    doc: &ContractDocument,
    continuations: &AtomicUsize,
) -> Result<ContractBinding, String> {
    let mode = flag.map_or(ReaderMode::Legacy, |profile| ReaderMode::Strict { profile });
    let binding = verify_with(digest, doc, mode).map_err(|refusal| refusal.code().to_owned())?;
    admit_then(
        binding,
        &scope(),
        &Provider,
        Some(&trust()),
        |admitted| async move {
            continuations.fetch_add(1, Ordering::SeqCst);
            admitted.binding().clone()
        },
    )
    .await
    .map_err(|refusal| refusal.code().to_owned())
}

const ROUTE_REQUIRED: &str = "CONTRACT_PROFILE_ROUTE_REQUIRED";

#[tokio::test]
async fn strict_flag_binds_a_producer_contract_and_reaches_the_continuation_once() {
    for name in ["rw", "deny_all", "all_four", "deny_all_no_pins"] {
        let (d, doc) = producer_doc(name);
        let counter = AtomicUsize::new(0);
        let binding = run(Some(STRICT_PROFILE), &d, &doc, &counter).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1, "{name}");
        assert_eq!(binding.reader_route(), ReaderRoute::Strict);
        assert!(binding.satisfies_profile(STRICT_PROFILE));
        let want: Vec<String> = fixtures()["cases"][name]["allow"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            binding.allowlist().iter().cloned().collect::<Vec<_>>(),
            want
        );
    }
}

#[tokio::test]
async fn omitting_the_flag_never_downgrades_a_profile_contract_to_the_legacy_route() {
    // Every producer-generated profile contract, flag omitted: refused BEFORE authority, and the
    // continuation counter proves nothing ran. (On a0d5d85 each of these bound as Legacy with the
    // contract's own `allow` and reached the continuation.)
    for name in [
        "rw",
        "deny_all",
        "all_four",
        "deny_all_no_pins",
        "rw_no_pins",
        "u64_max",
        "u64_max_plus_1",
        "uni_non_bmp",
        "uni_controls",
        "uni_lone_surrogate",
    ] {
        let (d, doc) = producer_doc(name);
        let counter = AtomicUsize::new(0);
        assert_eq!(
            run(None, &d, &doc, &counter).await.unwrap_err(),
            ROUTE_REQUIRED,
            "{name}"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "{name}: continuation ran"
        );
        // the same refusal from the plain legacy entry point
        assert_eq!(
            verify(&d, &doc).unwrap_err().code(),
            ROUTE_REQUIRED,
            "{name}"
        );
    }
}

#[tokio::test]
async fn actual_legacy_bytes_and_digests_stay_accepted_when_the_flag_is_omitted() {
    let (d, doc) = legacy_doc();
    let counter = AtomicUsize::new(0);
    let binding = run(None, &d, &doc, &counter).await.unwrap();
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(binding.digest(), d);
    assert_eq!(binding.reader_route(), ReaderRoute::Legacy);
    assert_eq!(binding.allowlist_source(), AllowlistSource::DefaultNoShell);
    assert!(!binding.satisfies_profile(STRICT_PROFILE));
    // explicit legacy mode is the same binding
    assert_eq!(verify_with(&d, &doc, ReaderMode::Legacy).unwrap(), binding);

    // pre-profile `tools: {allow}` contracts, including a legacy deny-all, are unchanged
    for (allow, want) in [
        (json!(["read"]), vec!["read"]),
        (json!([]), Vec::<&str>::new()),
    ] {
        let body = format!(r#"{{"role":"r","tools":{{"allow":{allow}}}}}"#);
        let (d, doc) = doc_of(&body, r#"{"revisions":[],"snapshot_digest":"x"}"#);
        let counter = AtomicUsize::new(0);
        let binding = run(None, &d, &doc, &counter).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(binding.allowlist_source(), AllowlistSource::Contract);
        assert_eq!(
            binding
                .allowlist()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            want
        );
    }
    // free-text and string-projection preimages are legacy bytes too
    let text = "plain contract text";
    let digest = digest_of(text.as_bytes());
    let doc = ContractDocument {
        digest: digest.clone(),
        projection: json!(text),
        ..Default::default()
    };
    assert!(verify(&digest, &doc).is_ok());
    // legacy prose that merely MENTIONS the profile is not marked
    let body =
        r#"{"note":"see arcanada-kc2-tools/v1 for the new form","tools":{"allow":["read"]}}"#;
    let (d, doc) = doc_of(body, r#"{"revisions":[],"snapshot_digest":"x"}"#);
    assert!(verify(&d, &doc).is_ok());
}

#[tokio::test]
async fn the_strict_flag_never_rescues_legacy_bytes() {
    let (d, doc) = legacy_doc();
    let counter = AtomicUsize::new(0);
    assert_eq!(
        run(Some(STRICT_PROFILE), &d, &doc, &counter)
            .await
            .unwrap_err(),
        "CONTRACT_PROFILE_REQUIRED"
    );
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_profile_mark_cannot_hide_from_the_legacy_route() {
    let manifest = r#"{"revisions":[],"snapshot_digest":"x"}"#;
    let cases: Vec<(&str, String, Option<&str>)> = vec![
        (
            "bogus profile value",
            r#"{"tools":{"allow":["read"],"profile":"bogus"}}"#.to_owned(),
            None,
        ),
        (
            "null profile value",
            r#"{"tools":{"allow":["read"],"profile":null}}"#.to_owned(),
            None,
        ),
        (
            "profile without allow",
            r#"{"tools":{"profile":"arcanada-kc2-tools/v1"}}"#.to_owned(),
            None,
        ),
        (
            "a duplicate tools key whose last value carries no mark",
            r#"{"tools":{"allow":["bash"],"profile":"arcanada-kc2-tools/v1"},"tools":{"allow":["read"]}}"#
                .to_owned(),
            None,
        ),
        (
            "a duplicate tools key whose first value carries no mark",
            r#"{"tools":{"allow":["read"]},"tools":{"allow":["bash"],"profile":"arcanada-kc2-tools/v1"}}"#
                .to_owned(),
            None,
        ),
        (
            "a duplicate profile key inside tools",
            r#"{"tools":{"allow":["read"],"profile":"x","profile":"y"}}"#.to_owned(),
            None,
        ),
        (
            "an unparseable body that names the profile (would reach the opaque route)",
            r#"{"tools":{"allow":["read"],"profile":"arcanada-kc2-tools/v1"},"x":"\ud800"}"#
                .to_owned(),
            None,
        ),
        (
            "the envelope hint alone",
            r#"{"tools":{"allow":["read"]}}"#.to_owned(),
            Some("arcanada-kc2-tools/v1"),
        ),
        (
            "an envelope hint of another version of the family",
            r#"{"role":"r"}"#.to_owned(),
            Some("arcanada-kc2-tools/v2"),
        ),
    ];
    for (what, body, hint) in cases {
        let (d, mut doc) = doc_of(&body, manifest);
        doc.schema_version = hint.map(str::to_owned);
        let counter = AtomicUsize::new(0);
        assert_eq!(
            run(None, &d, &doc, &counter).await.unwrap_err(),
            ROUTE_REQUIRED,
            "{what}"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0, "{what}");
    }
    // a hint of the legacy line or an unrelated value does not mark the bytes
    for hint in ["talomnia-ontology/v2", "other/v1"] {
        let (d, mut doc) = doc_of(r#"{"tools":{"allow":["read"]}}"#, manifest);
        doc.schema_version = Some(hint.to_owned());
        assert!(verify(&d, &doc).is_ok(), "{hint}");
    }
}

// ---------- R1: an unpinned or incapable reader does not satisfy the gate ----------

#[test]
fn an_unpinned_or_changed_pin_yields_no_binding_at_all() {
    let (d, doc) = producer_doc("rw");
    let strict = ReaderMode::Strict {
        profile: STRICT_PROFILE,
    };
    // no pin
    let err = verify_with_pin(&d, &doc, strict, None).unwrap_err();
    assert_eq!(err.code(), "CONTRACT_READER_UNSUPPORTED");
    // a pin whose blob is changed
    let real = TALOMNIA_SCHEMA_PIN.unwrap();
    let schemas: Vec<_> = real
        .schemas
        .iter()
        .map(|s| {
            let mut s = *s;
            if s.name == "kc2-v2-body.schema.json" {
                s.blob = "0000000000000000000000000000000000000000";
            }
            s
        })
        .collect();
    let bad = SchemaPin {
        schemas: Box::leak(schemas.into_boxed_slice()),
        ..real
    };
    let err = verify_with_pin(&d, &doc, strict, Some(&bad)).unwrap_err();
    assert_eq!(err.code(), "CONTRACT_READER_UNSUPPORTED");
    // a profile this build cannot enforce, even with a verified pin
    for requested in ["arcanada-kc2-tools/v2", "", "talomnia-ontology/v2"] {
        let err = verify_with_pin(
            &d,
            &doc,
            ReaderMode::Strict { profile: requested },
            Some(&real),
        )
        .unwrap_err();
        assert_eq!(err.code(), "CONTRACT_READER_UNSUPPORTED", "{requested:?}");
    }
}

#[test]
fn the_execution_profile_gate_is_satisfied_only_by_a_strict_binding_over_a_verified_pin() {
    let (d, doc) = producer_doc("rw");
    let real = TALOMNIA_SCHEMA_PIN.unwrap();
    let strict = verify_with_pin(
        &d,
        &doc,
        ReaderMode::Strict {
            profile: STRICT_PROFILE,
        },
        Some(&real),
    )
    .unwrap();
    assert!(strict.satisfies_profile(STRICT_PROFILE));
    assert!(!strict.satisfies_profile("arcanada-kc2-tools/v2"));
    assert!(!strict.satisfies_profile(""));
    assert_eq!(strict.schema_parity().as_str(), "PINNED_VERIFIED_UNMERGED");
    // the legacy route, whatever the build pins, never satisfies it and records no enforced parity
    let (ld, ldoc) = legacy_doc();
    let legacy = verify(&ld, &ldoc).unwrap();
    assert!(!legacy.satisfies_profile(STRICT_PROFILE));
    assert!(!legacy.satisfies_profile(""));
}
