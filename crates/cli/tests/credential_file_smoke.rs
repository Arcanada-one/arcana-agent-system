//! The real CLI names file-policy failures before any external request.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use wiremock::MockServer;

const TASK: &str = "b1227e82-da2b-4fee-aff6-b4ba8c6b01e3";

async fn refused(kind: &str, code: &str, message: &str) {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("key");
    fs::write(&key, "synthetic-private-value").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    match kind {
        "mode" => fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap(),
        "symlink" => {
            let target = dir.path().join("target");
            fs::rename(&key, &target).unwrap();
            symlink(target, &key).unwrap();
        }
        "directory" => {
            fs::remove_file(&key).unwrap();
            fs::create_dir(&key).unwrap();
        }
        "fifo" => {
            fs::remove_file(&key).unwrap();
            assert!(Command::new("mkfifo")
                .arg("-m")
                .arg("600")
                .arg(&key)
                .status()
                .unwrap()
                .success());
        }
        "empty" => fs::write(&key, "").unwrap(),
        "oversized" => fs::write(&key, vec![b'x'; 4097]).unwrap(),
        "missing" => fs::remove_file(&key).unwrap(),
        _ => panic!("unknown fixture"),
    }
    let server = MockServer::start().await;
    for mode in ["status", "watch", "run"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_arcana"));
        command
            .env_clear()
            .env("ARCANA_MUNERAL_KEY_FILE", &key)
            .env("ARCANA_MUNERAL_URL", format!("{}/api/v1", server.uri()))
            .env("ARCANA_MC_BASE_URL", server.uri())
            .env("ARCANA_MC_TOKEN", "synthetic-poison")
            .env("HOME", dir.path())
            .env("XDG_STATE_HOME", dir.path())
            .args([
                if mode == "run" { "run" } else { "status" },
                "--work-item",
                TASK,
            ]);
        if mode == "watch" {
            command.args(["--watch", "--timeout-secs", "1"]);
        }
        if mode == "run" {
            command.arg("--cwd").arg(dir.path());
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _open_stdin = child.stdin.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{kind}/{mode}: file loading hung before refusal");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(if mode == "watch" { 3 } else { 1 }),
            "{kind}/{mode}: {out:?}"
        );
        let stdout = String::from_utf8(out.stdout).unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        let all = format!("{stdout}{stderr}");
        assert!(
            all.contains(message),
            "{kind}/{mode}: missing condition in {all}"
        );
        if mode != "run" {
            assert!(all.contains(code), "{kind}/{mode}: {all}");
        }
        assert!(!all.contains("synthetic-private-value"));
        assert!(!all.contains(&key.display().to_string()));
        if mode == "watch" {
            let value: Value = serde_json::from_str(stdout.trim()).unwrap();
            assert_eq!(value["outcome"], "indeterminate");
            assert_eq!(value["reason"], code);
            assert!(value["message"].as_str().unwrap().contains(message));
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn missing_names_absence() {
    refused("missing", "CREDENTIAL_FILE_MISSING", "file is missing").await;
}
#[tokio::test]
async fn broad_mode_names_permissions() {
    refused(
        "mode",
        "CREDENTIAL_FILE_UNSAFE_PERMISSIONS",
        "insecure permissions",
    )
    .await;
}
#[tokio::test]
async fn symlink_names_type() {
    refused(
        "symlink",
        "CREDENTIAL_FILE_UNSAFE_TYPE",
        "regular non-symlink file",
    )
    .await;
}
#[tokio::test]
async fn directory_names_type() {
    refused(
        "directory",
        "CREDENTIAL_FILE_UNSAFE_TYPE",
        "regular non-symlink file",
    )
    .await;
}
#[tokio::test]
async fn fifo_refuses_without_writer() {
    refused(
        "fifo",
        "CREDENTIAL_FILE_UNSAFE_TYPE",
        "regular non-symlink file",
    )
    .await;
}
#[tokio::test]
async fn empty_names_size() {
    refused(
        "empty",
        "CREDENTIAL_FILE_UNSAFE_SIZE",
        "empty or exceeds the size limit",
    )
    .await;
}
#[tokio::test]
async fn oversized_names_size() {
    refused(
        "oversized",
        "CREDENTIAL_FILE_UNSAFE_SIZE",
        "empty or exceeds the size limit",
    )
    .await;
}
