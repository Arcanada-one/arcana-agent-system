//! The two contract sources, against the shape agreed for Argana
//! `GET /v1/contract/{digest}` (A2-271): `200 {digest, projection, …}`,
//! `404 {"code": "CONTRACT_NOT_FOUND"}`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_connectors::contract_source::{ArganaContractClient, ContractSource, FileContractSource};
use arcana_core::contract::{digest_of, verify, ContractRefusal};
use serde_json::json;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PROJECTION: &str = "Role: reviewer. Deliverable: one review note on decision gates.";

#[tokio::test]
async fn argana_returns_a_document_that_re_hashes_to_the_digest_it_was_asked_for() {
    let digest = digest_of(PROJECTION.as_bytes());
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/contract/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "digest": digest,
            "projection": PROJECTION,
            "kc2_revision": "kc2-role-reviewer@r7",
        })))
        .mount(&server)
        .await;

    let client = ArganaContractClient::new(Url::parse(&server.uri()).unwrap()).unwrap();
    assert_eq!(client.label(), "argana");

    let doc = client.fetch(&digest).await.expect("200");
    let binding = verify(&digest, &doc).expect("the live shape verifies");
    assert_eq!(binding.digest(), digest);
}

#[tokio::test]
async fn an_unknown_digest_is_not_found_rather_than_unavailable() {
    let digest = digest_of(b"a contract nobody stored");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/contract/{digest}")))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "code": "CONTRACT_NOT_FOUND"
        })))
        .mount(&server)
        .await;

    let client = ArganaContractClient::new(Url::parse(&server.uri()).unwrap()).unwrap();
    match client.fetch(&digest).await {
        Err(ContractRefusal::NotFound { digest: named }) => assert_eq!(named, digest),
        other => panic!("404 is a NotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn a_server_error_is_unavailable_and_carries_the_status() {
    let digest = digest_of(b"x");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/contract/{digest}")))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
        .mount(&server)
        .await;

    let client = ArganaContractClient::new(Url::parse(&server.uri()).unwrap()).unwrap();
    match client.fetch(&digest).await {
        Err(ContractRefusal::Unavailable { detail }) => {
            assert!(detail.contains("503"), "{detail}");
        }
        other => panic!("5xx is Unavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn a_file_source_is_held_to_the_same_re_hash_as_the_service() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("contract.json");
    let digest = digest_of(PROJECTION.as_bytes());
    // The file claims the right digest and holds the wrong bytes: the exact
    // thing a hand-written fixture gets wrong, and the exact thing the re-hash
    // exists to catch. The source hands it over; `verify` refuses it.
    std::fs::write(
        &path,
        json!({"digest": digest, "projection": "Role: deployer."}).to_string(),
    )
    .unwrap();

    let source = FileContractSource::new(&path);
    assert_eq!(source.label(), "file");
    let doc = source.fetch(&digest).await.expect("the file is read");
    let refusal = verify(&digest, &doc).expect_err("the bytes are not the contract's");
    assert_eq!(refusal.code(), "CONTRACT_DIGEST_MISMATCH");
}

#[tokio::test]
async fn a_file_holding_another_contract_is_a_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("contract.json");
    let other = digest_of(b"some other contract");
    std::fs::write(
        &path,
        json!({"digest": other, "projection": "Role: deployer."}).to_string(),
    )
    .unwrap();

    let source = FileContractSource::new(&path);
    match source.fetch(&digest_of(PROJECTION.as_bytes())).await {
        Err(ContractRefusal::NotFound { .. }) => {}
        other => panic!("the wrong file is a NotFound, got {other:?}"),
    }
}
