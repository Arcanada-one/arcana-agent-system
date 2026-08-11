//! Real PTY and resize lifecycle test (V-AC-6).

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::Path;

use arcana_execution_boundary::{
    spawn_pty, BoundaryError, CleanEnv, OutputPolicy, ProcessSpec, TerminalSize, SAFE_SYSTEM_PATH,
};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn child_has_a_real_tty_and_observes_resize() {
    let dir = TempDir::new().expect("tempdir");
    let env =
        CleanEnv::build_with_term(&dir.path().join("home"), SAFE_SYSTEM_PATH, "xterm-256color")
            .expect("clean env");
    let spec = ProcessSpec::new(Path::new("/bin/sh"), env).args([
        "-c",
        "test -t 0 && test -t 1 && stty size; read ready; stty size",
    ]);
    let mut child = spawn_pty(&spec, TerminalSize::new(24, 80)).expect("spawn pty");
    let output = child.take_output().expect("pty output");
    let mut lines = BufReader::new(output).lines();
    assert_eq!(
        lines.next_line().await.expect("read"),
        Some("24 80".to_owned())
    );
    child.resize(TerminalSize::new(41, 111)).expect("resize");
    child.write_input(b"go\n").expect("input");
    assert_eq!(
        lines.next_line().await.expect("read"),
        Some("go".to_owned()),
        "canonical PTYs echo input"
    );
    assert_eq!(
        lines.next_line().await.expect("read"),
        Some("41 111".to_owned())
    );
    assert!(child.wait().await.expect("wait").success());
}

#[test]
fn pty_refuses_output_policy_it_cannot_enforce() {
    let dir = TempDir::new().expect("tempdir");
    let env = CleanEnv::build(&dir.path().join("home"), SAFE_SYSTEM_PATH).expect("env");
    let spec =
        ProcessSpec::new(Path::new("/bin/echo"), env).output_policy(OutputPolicy::Quarantine {
            sentinels: vec![b"sentinel".to_vec()],
        });
    assert!(matches!(
        spawn_pty(&spec, TerminalSize::new(24, 80)),
        Err(BoundaryError::PtyOutputPolicyUnsupported)
    ));
}
