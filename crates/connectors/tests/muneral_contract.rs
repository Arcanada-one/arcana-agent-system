//! What `MuneralClient` does with each answer the work-item API can give.
//!
//! The shapes are the ones measured against `https://api.muneral.com/api/v1`
//! on 2026-09-24 (A2-272): a task carries `contractDigest` at the top level, an
//! unauthenticated read is `401 {"message":"Unauthorized","statusCode":401}`,
//! and a task this agent is not assigned to is `403` with a machine reason.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_connectors::muneral::{MuneralClient, MuneralError};
use secrecy::SecretString;
use serde_json::json;
use url::Url;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TASK: &str = "b1227e82-da2b-4fee-aff6-b4ba8c6b01e3";
const DIGEST: &str = "sha256:769cc084de15d0a02c002ad3178df0b752a720bdd28504b756e9b4dc46d4c1b6";

fn client(server: &MockServer) -> MuneralClient {
    MuneralClient::new(
        Url::parse(&format!("{}/api/v1", server.uri())).unwrap(),
        SecretString::from("mun_sk_test".to_owned()),
    )
    .unwrap()
}

#[tokio::test]
async fn a_task_is_read_with_its_contract_digest_and_the_orchestrator_user_agent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .and(header("authorization", "Bearer mun_sk_test"))
        .and(header("user-agent", "aup-orchestrator/1.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": TASK,
            "projectId": "e72dcee5-de8b-4b89-8a86-e57382a05ba8",
            "title": "A2 P2 end-to-end probe",
            "description": "contract_digest: sha256:…\n\nreview a short design note",
            "status": "todo",
            "revision": 0,
            "contractDigest": DIGEST,
            "someFieldThisClientHasNeverHeardOf": {"nested": true},
        })))
        .mount(&server)
        .await;

    let item = client(&server).work_item(TASK).await.expect("200");

    assert_eq!(item.id, TASK);
    assert_eq!(item.contract_digest.as_deref(), Some(DIGEST));
    assert_eq!(item.status.as_deref(), Some("todo"));
}

#[tokio::test]
async fn a_task_without_a_contract_digest_reads_as_none_rather_than_failing() {
    // The refusal belongs to the run, not to the transport: `CONTRACT_MISSING`
    // is a decision about what may be executed, and a decode error here would
    // report it as "Muneral is broken".
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": TASK,
            "title": "an unbound work item",
        })))
        .mount(&server)
        .await;

    let item = client(&server).work_item(TASK).await.expect("200");
    assert!(item.contract_digest.is_none());
}

#[tokio::test]
async fn an_unauthenticated_read_is_reported_as_unauthenticated() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "Unauthorized", "statusCode": 401
        })))
        .mount(&server)
        .await;

    match client(&server).work_item(TASK).await {
        Err(MuneralError::Unauthorized) => {}
        other => panic!("401 must be its own verdict, got {other:?}"),
    }
}

#[tokio::test]
async fn a_foreign_task_keeps_the_servers_machine_reason() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "agent is not assigned to this task",
            "statusCode": 403
        })))
        .mount(&server)
        .await;

    match client(&server).work_item(TASK).await {
        Err(MuneralError::Forbidden(reason)) => {
            assert!(
                reason.contains("not assigned"),
                "the reason must survive: {reason}"
            );
        }
        other => panic!("403 must carry the reason, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unknown_task_names_the_id_it_could_not_find() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    match client(&server).work_item(TASK).await {
        Err(MuneralError::NotFound(id)) => assert_eq!(id, TASK),
        other => panic!("404 must name the id, got {other:?}"),
    }
}

#[tokio::test]
async fn no_error_this_client_produces_can_carry_the_key() {
    // The one property worth a test of its own: every error is built from the
    // response. A `Debug` that leaked the bearer would put a `mun_sk_` into
    // every run log that reported a refusal.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}")))
        .respond_with(ResponseTemplate::new(403).set_body_string("nope"))
        .mount(&server)
        .await;

    let err = client(&server).work_item(TASK).await.unwrap_err();
    let rendered = format!("{err:?} {err}");
    assert!(!rendered.contains("mun_sk_test"), "leaked: {rendered}");
}
