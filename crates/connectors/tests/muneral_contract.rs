//! What `MuneralClient` does with each answer the work-item API can give.
//!
//! The shapes are the ones measured against `https://api.muneral.com/api/v1`
//! on 2026-09-24 (A2-272): a task carries `contractDigest` at the top level, an
//! unauthenticated read is `401 {"message":"Unauthorized","statusCode":401}`,
//! and a task this agent is not assigned to is `403` with a machine reason.
//! The evidence half (`POST /tasks/{id}/evidence`) is at the bottom.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_connectors::muneral::{MuneralClient, MuneralError};
use secrecy::SecretString;
use serde_json::json;
use url::Url;
use wiremock::matchers::{body_json, header, method, path};
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

// --- POST /tasks/{id}/evidence ---------------------------------------------
//
// The 201 body below is not written for this test: it is the answer Muneral
// production gave on 2026-09-25T12:53:19Z to the attachment A2-332 made by
// hand (`runs/A2-332/ev/attach-post.txt`), kept byte for byte.

const REAL_201: &str = include_str!("fixtures/muneral-evidence-attach-201.json");
const EV_TASK: &str = "d931525f-c134-4c6b-85e1-9cdf94e8ab8b";
const EV_SHA: &str = "347c0e6920f9d34310f09308fd2d039afee8f89deeaac10e561a55392a0db94d";
const EV_URI: &str = "https://github.com/Arcanada-one/arcanada-universal-program/blob/78643c691092fa9624b8bd637a330b6a1e7e3fbe/science/experiments/EXP-A2-S16-contract-executor/evidence/ReadinessReceipt-a2-297c-run2-347c0e69.json";

fn evidence_path() -> String {
    format!("/api/v1/tasks/{EV_TASK}/evidence")
}

#[tokio::test]
async fn a_first_attachment_sends_the_dto_body_and_reads_the_real_201() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(evidence_path()))
        .and(header("authorization", "Bearer mun_sk_test"))
        .and(header("user-agent", "aup-orchestrator/1.0"))
        .and(body_json(json!({
            "uri": EV_URI, "sha256": EV_SHA, "contentType": "application/json"
        })))
        .respond_with(
            ResponseTemplate::new(201).set_body_raw(REAL_201.trim_end(), "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let record = client(&server)
        .attach_evidence(EV_TASK, EV_URI, EV_SHA, "application/json")
        .await
        .expect("201");

    assert_eq!(record.schema, "WorkItemEvidenceAttachment/v1");
    assert_eq!(record.evidence_id, "3632d426-78c9-4800-829b-010f3b0f5e77");
    assert_eq!(record.sha256, EV_SHA);
    assert_eq!(record.content_type, "application/json");
    assert_eq!(record.idempotent, Some(false));
}

/// Production's answer to the SAME claim repeated, measured by A2-336 on
/// 2026-09-25T13:23:37Z (`runs/A2-336/ev/live-attach-raw-post.txt`, http=200),
/// byte for byte: the stored record, the same `evidence_id`, `idempotent: true`.
const REAL_200_IDEMPOTENT: &str =
    include_str!("fixtures/muneral-evidence-attach-200-idempotent.json");

#[tokio::test]
async fn a_repeated_attachment_is_a_200_marked_idempotent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(evidence_path()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(REAL_200_IDEMPOTENT.trim_end(), "application/json"),
        )
        .mount(&server)
        .await;

    let record = client(&server)
        .attach_evidence(EV_TASK, EV_URI, EV_SHA, "application/json")
        .await
        .expect("200");
    assert_eq!(record.idempotent, Some(true));
    assert_eq!(record.evidence_id, "3632d426-78c9-4800-829b-010f3b0f5e77");
}

#[tokio::test]
async fn a_200_without_the_flag_is_still_read_as_a_repeat() {
    let mut repeat: serde_json::Value = serde_json::from_str(REAL_201).unwrap();
    repeat.as_object_mut().unwrap().remove("idempotent");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(evidence_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(repeat))
        .mount(&server)
        .await;

    let record = client(&server)
        .attach_evidence(EV_TASK, EV_URI, EV_SHA, "application/json")
        .await
        .expect("200");
    assert_eq!(record.idempotent, Some(true));
}

#[tokio::test]
async fn a_digest_conflict_keeps_the_whole_body_including_both_uris() {
    // Shape from `task-evidence.errors.ts::digestConflict` (Muneral main): the
    // stored and the attempted values, each of which may be 2048 characters.
    let long_uri = format!("file:///{}", "x".repeat(1500));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(evidence_path()))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "code": "EVIDENCE_DIGEST_CONFLICT",
            "message": "Task already carries evidence with sha256, attached with a different uri or contentType.",
            "taskId": EV_TASK,
            "sha256": EV_SHA,
            "stored_uri": EV_URI,
            "stored_content_type": "application/json",
            "attempted_uri": long_uri,
            "attempted_content_type": "application/json",
            "statusCode": 409
        })))
        .mount(&server)
        .await;

    match client(&server)
        .attach_evidence(EV_TASK, &long_uri, EV_SHA, "application/json")
        .await
    {
        Err(MuneralError::Conflict(body)) => {
            assert!(body.contains("EVIDENCE_DIGEST_CONFLICT"), "{body}");
            assert!(body.contains(EV_URI), "stored uri kept");
            assert!(body.contains(&long_uri), "attempted uri kept uncut");
        }
        other => panic!("409 must be a conflict with its body, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unauthenticated_attachment_is_unauthenticated_and_carries_no_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(evidence_path()))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "Unauthorized", "statusCode": 401
        })))
        .mount(&server)
        .await;

    let err = client(&server)
        .attach_evidence(EV_TASK, EV_URI, EV_SHA, "application/json")
        .await
        .unwrap_err();
    assert!(matches!(err, MuneralError::Unauthorized), "{err:?}");
    let rendered = format!("{err:?} {err}");
    assert!(!rendered.contains("mun_sk_test"), "leaked: {rendered}");
}

#[tokio::test]
async fn an_unreachable_muneral_is_a_transport_error_that_carries_no_key() {
    // Port 1 on loopback, as `crates/cli/tests/usage_smoke.rs` uses: nothing
    // listens there. (A started-and-dropped `MockServer` is NOT dead —
    // wiremock pools its servers and hands the same port to the next test.)
    let client = MuneralClient::new(
        Url::parse("http://127.0.0.1:1/api/v1").unwrap(),
        SecretString::from("mun_sk_test".to_owned()),
    )
    .unwrap();

    let err = client
        .attach_evidence(EV_TASK, EV_URI, EV_SHA, "application/json")
        .await
        .unwrap_err();
    assert!(matches!(err, MuneralError::Transport(_)), "{err:?}");
    let rendered = format!("{err:?} {err}");
    assert!(!rendered.contains("mun_sk_test"), "leaked: {rendered}");
}

#[tokio::test]
async fn a_success_that_names_other_bytes_is_not_taken_as_our_attachment() {
    let mut other: serde_json::Value = serde_json::from_str(REAL_201).unwrap();
    other["sha256"] = json!("0".repeat(64));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(evidence_path()))
        .respond_with(ResponseTemplate::new(201).set_body_json(other))
        .mount(&server)
        .await;

    let err = client(&server)
        .attach_evidence(EV_TASK, EV_URI, EV_SHA, "application/json")
        .await
        .unwrap_err();
    assert!(matches!(err, MuneralError::EvidenceMismatch(_)), "{err:?}");
}
