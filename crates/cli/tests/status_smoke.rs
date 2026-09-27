//! Exercise the actual command against authorized and failing API responses.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TASK: &str = "b1227e82-da2b-4fee-aff6-b4ba8c6b01e3";

fn command(server: &MockServer, poison: &MockServer, dir: &TempDir) -> Command {
    let key = dir.path().join("key");
    std::fs::write(&key, "mun_sk_test\n").unwrap();
    let mut cmd = Command::cargo_bin("arcana").unwrap();
    cmd.env_clear()
        .env("ARCANA_MUNERAL_KEY_FILE", key)
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MC_BASE_URL", poison.uri())
        .env("ARCANA_MC_TOKEN", "poison-not-a-real-token")
        .args(["status", "--work-item", TASK]);
    cmd
}

async fn serve(server: &MockServer, suffix: &str, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}{suffix}")))
        .and(header("authorization", "Bearer mun_sk_test"))
        .and(header("user-agent", "aup-orchestrator/1.0"))
        .respond_with(response)
        .expect(1)
        .mount(server)
        .await;
}

fn row() -> Value {
    json!({"id": TASK, "status": "todo", "revision": 7,
        "updatedAt": "2001-01-01T00:00:00Z",
        "title": "PRIVATE_TITLE", "description": "PRIVATE_DESCRIPTION"})
}

async fn run_fixture(
    task: ResponseTemplate,
    readiness: Option<ResponseTemplate>,
) -> (i32, String, String) {
    let server = MockServer::start().await;
    let poison = MockServer::start().await;
    let dir = TempDir::new().unwrap();
    serve(&server, "", task).await;
    let expected = if let Some(response) = readiness {
        serve(&server, "/readiness", response).await;
        2
    } else {
        1
    };
    let output = command(&server, &poison, &dir).output().unwrap();
    server.verify().await;
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), expected);
    assert!(requests.iter().all(|r| r.method.as_str() == "GET"));
    assert!(poison.received_requests().await.unwrap().is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    for secret in [
        "PRIVATE_TITLE",
        "PRIVATE_DESCRIPTION",
        "UPSTREAM_PRIVATE",
        "mun_sk_test",
    ] {
        assert!(!stdout.contains(secret));
        assert!(!stderr.contains(secret));
    }
    (output.status.code().unwrap(), stdout, stderr)
}

#[tokio::test]
async fn status_is_not_readiness_and_old_row_time_is_not_runtime_freshness() {
    for (ready, count, blockers) in [
        (false, 2, vec![json!({"otherTaskTitle": "PRIVATE_TITLE"})]),
        (true, 2, vec![]),
        (true, 0, vec![]),
    ] {
        let (code, stdout, stderr) = run_fixture(
            ResponseTemplate::new(200).set_body_json(row()),
            Some(ResponseTemplate::new(200).set_body_json(json!({
                "taskId": TASK, "dependencyCount": count, "ready": ready, "blockedBy": blockers
            }))),
        )
        .await;
        assert_eq!(code, 0, "{stderr}");
        let v: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(v["work_item_id"], TASK);
        assert_eq!(v["task_status"], "todo");
        assert_eq!(v["task_revision"], 7);
        assert_eq!(v["task_updated_at"], "2001-01-01T00:00:00Z");
        assert_eq!(v["dependency_readiness"]["ready"], ready);
        assert_eq!(v["dependency_readiness"]["dependency_count"], count);
        assert_eq!(v["runtime_freshness"], "unknown");
        assert_eq!(v["runtime_progress"], "not_measured");
        assert_eq!(v["consistency"], "separate_reads");
        assert!(v["task_observed_at"].as_str().unwrap().ends_with('Z'));
    }
}

#[tokio::test]
async fn denied_and_missing_items_have_identical_output_and_no_readiness_probe() {
    let mut outputs = vec![];
    for status in [401, 403, 404] {
        let result = run_fixture(
            ResponseTemplate::new(status).set_body_string("UPSTREAM_PRIVATE"),
            None,
        )
        .await;
        assert_eq!(result.0, 1);
        assert!(result.1.is_empty());
        assert_eq!(result.2, "arcana status: STATUS_NOT_ACCESSIBLE\n");
        outputs.push(result);
    }
    assert!(outputs.windows(2).all(|v| v[0] == v[1]));
}

#[tokio::test]
async fn access_revoked_between_reads_suppresses_the_earlier_row() {
    for status in [401, 403, 404] {
        let result = run_fixture(
            ResponseTemplate::new(200).set_body_json(row()),
            Some(ResponseTemplate::new(status).set_body_string("UPSTREAM_PRIVATE")),
        )
        .await;
        assert_eq!(
            result,
            (
                1,
                String::new(),
                "arcana status: STATUS_NOT_ACCESSIBLE\n".into()
            )
        );
    }
}

#[tokio::test]
async fn missing_malformed_wrong_item_and_inconsistent_readiness_stay_unknown() {
    let bodies = [
        json!({}),
        json!({"taskId": TASK, "ready": true}),
        json!({"taskId":"other", "ready":true,"dependencyCount":0,"blockedBy":[]}),
        json!({"taskId":TASK, "ready":true,"dependencyCount":1,"blockedBy":[{}]}),
        json!({"taskId":TASK, "ready":false,"dependencyCount":0,"blockedBy":[{}]}),
    ];
    for body in bodies {
        let (code, stdout, _) = run_fixture(
            ResponseTemplate::new(200).set_body_json(row()),
            Some(ResponseTemplate::new(200).set_body_json(body)),
        )
        .await;
        assert_eq!(code, 3);
        let v: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            v["dependency_readiness"],
            json!({"state":"unknown", "ready":null})
        );
    }
}

#[tokio::test]
async fn readiness_outage_is_not_an_empty_dependency_set() {
    let (code, stdout, _) = run_fixture(
        ResponseTemplate::new(200).set_body_json(row()),
        Some(ResponseTemplate::new(503).set_body_string("UPSTREAM_PRIVATE")),
    )
    .await;
    assert_eq!(code, 3);
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["dependency_readiness"]["state"], "unknown");
    assert_eq!(v["dependency_readiness"]["ready"], Value::Null);
}

#[tokio::test]
async fn malformed_task_identity_or_status_is_not_displayed() {
    for body in [
        json!({"id":"other", "status":"todo"}),
        json!({"id":TASK}),
        json!({"id":TASK, "status":"UPSTREAM_PRIVATE"}),
    ] {
        let (code, stdout, stderr) =
            run_fixture(ResponseTemplate::new(200).set_body_json(body), None).await;
        assert_eq!(code, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "arcana status: STATUS_INVALID_RESPONSE\n");
    }
}
