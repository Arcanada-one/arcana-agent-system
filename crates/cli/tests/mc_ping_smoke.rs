//! ARAS-0040 items 2 + 2b: `arcana mc-ping` must return a non-zero,
//! capability-assertion exit code (2) on a **degenerate** success envelope
//! (HTTP 201 `{"status":"success","result":""}`) instead of the historical
//! blanket exit 0 for any `Ok(response)`; and `try_from_env` must honour the
//! optional `ARCANA_MC_BASE_URL` override so the harness can point the probe at
//! a loopback replay fixture. Both are proven end-to-end here against a
//! minimal 127.0.0.1 responder — no live mesh, no `ARCANA_MC_TOKEN` secret.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use assert_cmd::Command;

/// Spawn a one-shot loopback HTTP/1.1 responder that replies to the first
/// connection with `201 Created` carrying `body`, then closes. Returns the
/// bound `http://127.0.0.1:PORT` base URL for `ARCANA_MC_BASE_URL`.
fn spawn_201_responder(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Drain what the client sends (headers + small JSON body) so the
            // write side does not block; we do not need to parse it.
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

const DEGENERATE_BODY: &str = r#"{"id":"t","connector":"claude-code","model":"claude-code","result":"","usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2,"costUsd":0.0},"latencyMs":5,"status":"success"}"#;

const HEALTHY_BODY: &str = r#"{"id":"t","connector":"claude-code","model":"claude-code","result":"ARCANA-live-ok","usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2,"costUsd":0.0},"latencyMs":5,"status":"success"}"#;

#[test]
fn mc_ping_exits_2_on_empty_result_via_base_url_override() {
    let base = spawn_201_responder(DEGENERATE_BODY);

    Command::cargo_bin("arcana")
        .unwrap()
        .arg("mc-ping")
        .env("ARCANA_MC_BASE_URL", &base)
        .env("ARCANA_MC_TOKEN", "staging")
        .assert()
        .code(2);
}

#[test]
fn mc_ping_exits_0_on_healthy_result_via_base_url_override() {
    let base = spawn_201_responder(HEALTHY_BODY);

    Command::cargo_bin("arcana")
        .unwrap()
        .arg("mc-ping")
        .env("ARCANA_MC_BASE_URL", &base)
        .env("ARCANA_MC_TOKEN", "staging")
        .assert()
        .success()
        .stdout(predicates::str::contains("ARCANA-live-ok"));
}
