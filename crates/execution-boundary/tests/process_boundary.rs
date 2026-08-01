//! Runtime execution-boundary acceptance tests (V-AC-1/2/6).

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;

use arcana_execution_boundary::{
    BoundaryError, CleanEnv, OutputPolicy, ProcessSpec, Termination, SAFE_SYSTEM_PATH,
};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

fn clean_env(dir: &TempDir) -> CleanEnv {
    CleanEnv::build(&dir.path().join("home"), SAFE_SYSTEM_PATH).expect("clean env")
}

#[tokio::test]
async fn child_receives_only_the_constructed_environment() {
    let dir = TempDir::new().expect("tempdir");
    let spec = ProcessSpec::new(Path::new("/usr/bin/env"), clean_env(&dir))
        .timeout(Duration::from_secs(2));
    let output = spec.run(CancellationToken::new()).await.expect("run");
    assert!(
        output.success,
        "env failed: termination={:?} stderr={}",
        output.termination,
        String::from_utf8_lossy(&output.stderr)
    );
    let mut names: Vec<&str> = std::str::from_utf8(&output.stdout)
        .expect("utf8")
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["HOME", "LANG", "LC_ALL", "PATH", "TERM", "TZ"]);
}

#[tokio::test]
async fn child_cannot_inherit_a_descriptor_even_when_cloexec_was_cleared() {
    let dir = TempDir::new().expect("tempdir");
    let descriptor_path = dir.path().join("descriptor-sentinel");
    std::fs::write(&descriptor_path, b"descriptor sentinel").expect("write sentinel file");
    let inherited = std::fs::File::open(&descriptor_path).expect("open descriptor");
    rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty()).expect("clear cloexec");
    let fd = inherited.as_raw_fd();
    let probe = format!(
        "actual=$(readlink /proc/self/fd/{fd} 2>/dev/null || readlink /dev/fd/{fd} 2>/dev/null || true); [ \"$actual\" != \"$1\" ]"
    );
    let output = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
        .args([
            "-c",
            probe.as_str(),
            "descriptor-probe",
            descriptor_path.to_str().expect("utf8 path"),
        ])
        .run(CancellationToken::new())
        .await
        .expect("run");
    assert!(output.success, "descriptor {fd} escaped into the child");
}

#[tokio::test]
async fn relative_programs_and_sentinel_bearing_argv_fail_closed() {
    let dir = TempDir::new().expect("tempdir");
    let relative = ProcessSpec::new(Path::new("sh"), clean_env(&dir));
    assert!(matches!(
        relative.run(CancellationToken::new()).await,
        Err(BoundaryError::ProgramNotAbsolute)
    ));

    let sentinel = b"credential-material-that-must-not-enter-argv".to_vec();
    let spec = ProcessSpec::new(Path::new("/bin/echo"), clean_env(&dir))
        .arg(String::from_utf8(sentinel.clone()).expect("utf8"))
        .output_policy(OutputPolicy::Quarantine {
            sentinels: vec![sentinel],
        });
    assert!(matches!(
        spec.run(CancellationToken::new()).await,
        Err(BoundaryError::CredentialInArgument { .. })
    ));
}

#[tokio::test]
async fn timeout_terminates_the_whole_process_group() {
    let dir = TempDir::new().expect("tempdir");
    let spec = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
        .args(["-c", "sleep 30 & child=$!; echo $child; wait"])
        .timeout(Duration::from_millis(100))
        .termination_grace(Duration::from_millis(50));
    let output = spec.run(CancellationToken::new()).await.expect("run");
    assert_eq!(output.termination, Termination::TimedOut);
    let grandchild: i32 = std::str::from_utf8(&output.stdout)
        .expect("utf8")
        .trim()
        .parse()
        .expect("pid");
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(grandchild), None).is_err(),
        "the timeout must not leave the grandchild alive"
    );
}

#[tokio::test]
async fn cancellation_and_signal_exit_are_reported_without_ambiguity() {
    let dir = TempDir::new().expect("tempdir");
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });
    let cancelled = ProcessSpec::new(Path::new("/bin/sleep"), clean_env(&dir))
        .arg("30")
        .run(cancel)
        .await
        .expect("cancelled run");
    assert_eq!(cancelled.termination, Termination::Cancelled);

    let signalled = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
        .args(["-c", "kill -TERM $$"])
        .run(CancellationToken::new())
        .await
        .expect("signal run");
    assert_eq!(signalled.termination, Termination::Signal(15));
}

#[tokio::test]
async fn quarantine_blocks_a_sentinel_before_output_release() {
    let dir = TempDir::new().expect("tempdir");
    let sentinel = b"quarantine-sentinel-value".to_vec();
    let spec = ProcessSpec::new(Path::new("/bin/echo"), clean_env(&dir))
        .arg("quarantine-sentinel-value")
        .output_policy(OutputPolicy::Quarantine {
            sentinels: vec![sentinel.clone()],
        });
    // The argv guard fires first. A child cannot receive the credential merely
    // so the output scanner can prove it would catch it.
    assert!(matches!(
        spec.run(CancellationToken::new()).await,
        Err(BoundaryError::CredentialInArgument { .. })
    ));

    let encoded = "cXVhcmFudGluZS1zZW50aW5lbC12YWx1ZQ==";
    let spec = ProcessSpec::new(Path::new("/bin/echo"), clean_env(&dir))
        .arg(encoded)
        .output_policy(OutputPolicy::Quarantine {
            sentinels: vec![sentinel],
        });
    assert!(matches!(
        spec.run(CancellationToken::new()).await,
        Err(BoundaryError::OutputQuarantined(_))
    ));
}
