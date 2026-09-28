//! Actual-binary controls for terminal outcomes, lost evidence and bounded waits.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{json, Value};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const TASK: &str = "b1227e82-da2b-4fee-aff6-b4ba8c6b01e3";

fn task(status: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({"id": TASK, "status": status,
        "revision": 8, "updatedAt": "2001-01-01T00:00:00Z",
        "title": "PRIVATE_TASK", "description": "PRIVATE_DESCRIPTION"}))
}

fn readiness(ready: bool) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({"taskId": TASK,
        "dependencyCount": 1, "ready": ready,
        "blockedBy": if ready { vec![] } else { vec![json!({"title": "PRIVATE_DEPENDENCY"})] }}))
}

async fn sequence(server: &MockServer, suffix: &str, responses: Vec<ResponseTemplate>) {
    let index = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/tasks/{TASK}{suffix}")))
        .and(header("authorization", "Bearer mun_sk_test"))
        .and(header("user-agent", "aup-orchestrator/1.0"))
        .respond_with(move |_: &Request| {
            let i = index.fetch_add(1, Ordering::SeqCst);
            responses[i.min(responses.len() - 1)].clone()
        })
        .mount(server)
        .await;
}

fn command(server: &MockServer, poison: &MockServer, dir: &TempDir) -> Command {
    let key = dir.path().join("key");
    std::fs::write(&key, "mun_sk_test\n").unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_arcana"));
    cmd.env_clear()
        .env("ARCANA_MUNERAL_KEY_FILE", key)
        .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
        .env("ARCANA_MC_BASE_URL", poison.uri())
        .env("ARCANA_MC_TOKEN", "poison")
        .args(["status", "--work-item", TASK]);
    cmd
}

#[allow(clippy::panic)] // A hung child must fail the test after being reaped.
fn run_with_open_stdin(mut cmd: Command) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep the write end open without sending a byte: a prompt/read would hang.
    let _open_stdin = child.stdin.take().unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("watch failed its finite noninteractive bound: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

async fn fixture(
    tasks: Vec<ResponseTemplate>,
    readiness_rows: Vec<ResponseTemplate>,
    seconds: &str,
    interval: &str,
) -> (i32, Vec<Value>, usize, Duration) {
    let server = MockServer::start().await;
    let poison = MockServer::start().await;
    let dir = TempDir::new().unwrap();
    sequence(&server, "", tasks).await;
    sequence(&server, "/readiness", readiness_rows).await;
    let mut cmd = command(&server, &poison, &dir);
    cmd.args([
        "--watch",
        "--timeout-secs",
        seconds,
        "--interval-secs",
        interval,
    ]);
    let start = Instant::now();
    let output = run_with_open_stdin(cmd);
    let elapsed = start.elapsed();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.is_empty(), "{stderr}");
    for secret in [
        "PRIVATE_TASK",
        "PRIVATE_DESCRIPTION",
        "PRIVATE_DEPENDENCY",
        "PRIVATE_ERROR",
        "mun_sk_test",
    ] {
        assert!(!stdout.contains(secret));
    }
    let rows: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let result = rows.last().unwrap();
    assert_eq!(result["schema"], "WorkItemWatchResult/v1");
    assert_eq!(result["predicate"], "stored_task_completion");
    assert_eq!(result["independent_acceptance"], "not_measured");
    for row in &rows[..rows.len() - 1] {
        assert_eq!(row["schema"], "WorkItemStatusObservation/v1");
        assert_eq!(row["runtime_freshness"], "unknown");
        assert_eq!(row["runtime_progress"], "not_measured");
    }
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().all(|r| r.method.as_str() == "GET"));
    assert!(poison.received_requests().await.unwrap().is_empty());
    (output.status.code().unwrap(), rows, requests.len(), elapsed)
}

#[tokio::test]
async fn observes_transition_instead_of_treating_dependency_ready_as_done() {
    let (code, rows, calls, _) = fixture(
        vec![task("todo"), task("done")],
        vec![readiness(true)],
        "5",
        "1",
    )
    .await;
    assert_eq!(code, 0);
    assert_eq!(calls, 4);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["task_status"], "todo");
    assert_eq!(rows[1]["task_status"], "done");
    assert_ne!(rows[0]["task_observed_at"], rows[1]["task_observed_at"]);
    assert_eq!(rows[2]["outcome"], "ready");
    assert_eq!(rows[2]["reason"], "TASK_DONE");
}

#[tokio::test]
async fn three_terminal_outcomes_have_distinct_codes_and_text() {
    let mut messages = std::collections::HashSet::new();
    for (status, expected_code, state, reason) in [
        ("done", 0, "ready", "TASK_DONE"),
        ("cancelled", 1, "not_ready", "TASK_CANCELLED"),
        (
            "archived",
            3,
            "indeterminate",
            "ARCHIVED_COMPLETION_UNKNOWN",
        ),
    ] {
        let (code, rows, calls, _) =
            fixture(vec![task(status)], vec![readiness(false)], "2", "1").await;
        assert_eq!(code, expected_code);
        assert_eq!(calls, 2);
        assert_eq!(rows[1]["outcome"], state);
        assert_eq!(rows[1]["reason"], reason);
        messages.insert(rows[1]["message"].as_str().unwrap().to_owned());
    }
    assert_eq!(messages.len(), 3);
}

#[tokio::test]
async fn deadline_never_turns_last_readiness_into_a_final_verdict() {
    for ready in [false, true] {
        let (code, rows, calls, elapsed) =
            fixture(vec![task("blocked")], vec![readiness(ready)], "1", "60").await;
        assert_eq!(code, 3);
        assert_eq!(calls, 2);
        assert_eq!(rows[0]["dependency_readiness"]["ready"], ready);
        assert_eq!(rows[1]["outcome"], "indeterminate");
        assert_eq!(rows[1]["reason"], "WATCH_DEADLINE_EXPIRED");
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    }
}

#[tokio::test]
async fn deadline_includes_first_request_and_readiness_wait() {
    for delay_task in [false, true] {
        let (t, r) = if delay_task {
            (
                task("done").set_delay(Duration::from_secs(4)),
                readiness(true),
            )
        } else {
            (
                task("done"),
                readiness(true).set_delay(Duration::from_secs(4)),
            )
        };
        let (code, rows, calls, elapsed) = fixture(vec![t], vec![r], "1", "1").await;
        assert_eq!(code, 3);
        assert_eq!(calls, if delay_task { 1 } else { 2 });
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["reason"], "WATCH_DEADLINE_EXPIRED");
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    }
}

#[tokio::test]
async fn unknown_task_shape_is_indeterminate_without_readiness_or_prompts() {
    for body in [
        json!({"id": TASK}),
        json!({"id": TASK, "status": "future"}),
        json!({"id": "wrong", "status": "done"}),
    ] {
        let (code, rows, calls, _) = fixture(
            vec![ResponseTemplate::new(200).set_body_json(body)],
            vec![readiness(true)],
            "2",
            "1",
        )
        .await;
        assert_eq!(code, 3);
        assert_eq!(calls, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["outcome"], "indeterminate");
        assert_eq!(rows[0]["reason"], "STATUS_INVALID_RESPONSE");
    }
}

#[tokio::test]
async fn malformed_or_unavailable_readiness_cannot_complete_a_done_row() {
    for response in [
        ResponseTemplate::new(200).set_body_json(json!({"taskId": TASK, "newShape": true})),
        ResponseTemplate::new(200).set_body_json(
            json!({"taskId": TASK, "ready": true, "dependencyCount": 1, "blockedBy": [{}]}),
        ),
        ResponseTemplate::new(503).set_body_string("PRIVATE_ERROR"),
    ] {
        let (code, rows, calls, _) = fixture(vec![task("done")], vec![response], "2", "1").await;
        assert_eq!(code, 3);
        assert_eq!(calls, 2);
        assert_eq!(rows[1]["outcome"], "indeterminate");
        assert_eq!(rows[1]["reason"], "DEPENDENCY_READINESS_UNDETERMINED");
    }
}

#[tokio::test]
async fn revoked_access_stops_on_either_read_and_suppresses_that_poll() {
    for http in [401, 403, 404] {
        for second_read in [false, true] {
            let denial = ResponseTemplate::new(http).set_body_string("PRIVATE_ERROR");
            let (tasks, rs) = if second_read {
                (
                    vec![task("todo"), task("done")],
                    vec![readiness(true), denial],
                )
            } else {
                (vec![task("todo"), denial], vec![readiness(true)])
            };
            let (code, rows, calls, _) = fixture(tasks, rs, "5", "1").await;
            assert_eq!(code, 3);
            assert_eq!(calls, if second_read { 4 } else { 3 });
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0]["task_status"], "todo");
            assert_eq!(rows[1]["outcome"], "indeterminate");
            assert_eq!(rows[1]["reason"], "STATUS_NOT_ACCESSIBLE");
        }
    }
}

#[tokio::test]
async fn watch_requires_bounded_arguments_before_network_access() {
    let server = MockServer::start().await;
    let poison = MockServer::start().await;
    let dir = TempDir::new().unwrap();
    for args in [
        vec!["--watch"],
        vec!["--timeout-secs", "1"],
        vec!["--interval-secs", "1"],
        vec!["--watch", "--timeout-secs", "0"],
        vec!["--watch", "--timeout-secs", "3601"],
        vec!["--watch", "--timeout-secs", "1", "--interval-secs", "0"],
        vec!["--watch", "--timeout-secs", "1", "--interval-secs", "61"],
    ] {
        let mut cmd = command(&server, &poison, &dir);
        cmd.args(args);
        assert_eq!(run_with_open_stdin(cmd).status.code(), Some(2));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(poison.received_requests().await.unwrap().is_empty());
}
