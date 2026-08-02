//! Runtime execution-boundary acceptance tests (V-AC-1/2/6).

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;

use arcana_execution_boundary::{
    spawn_piped, BoundaryError, CleanEnv, OutputPolicy, ProcessSpec, Termination, TranscriptPolicy,
    TranscriptWriter, SAFE_SYSTEM_PATH,
};
use nix::errno::Errno;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_exit_observer_handles_bounded_mass_concurrency() {
    let mut tasks = tokio::task::JoinSet::new();
    for iteration in 0..64 {
        let dir = TempDir::new().expect("tempdir");
        let spec = ProcessSpec::new(Path::new("/usr/bin/true"), clean_env(&dir));
        tasks.spawn(async move {
            let _dir = dir;
            spec.run(CancellationToken::new())
                .await
                .unwrap_or_else(|error| panic!("iteration {iteration} failed: {error}"))
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert!(result.expect("observer task").success);
    }
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
async fn target_and_group_anchor_close_every_ambient_descriptor() {
    let dir = TempDir::new().expect("tempdir");
    let (read_end, write_end) = nix::unistd::pipe().expect("pipe");
    rustix::io::fcntl_setfd(&write_end, rustix::io::FdFlags::empty())
        .expect("clear writer cloexec");
    rustix::fs::fcntl_setfl(&read_end, rustix::fs::OFlags::NONBLOCK)
        .expect("make reader nonblocking");
    let mut child = spawn_piped(&ProcessSpec::new(
        Path::new("/usr/bin/true"),
        clean_env(&dir),
    ))
    .expect("spawn boundary child");
    drop(write_end);

    let mut observed_eof = false;
    for _ in 0..100 {
        match rustix::io::read(&read_end, &mut [0u8; 1]) {
            Ok(0) => {
                observed_eof = true;
                break;
            }
            Err(rustix::io::Errno::AGAIN) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(count) => panic!("ambient descriptor pipe produced {count} unexpected bytes"),
            Err(error) => panic!("ambient descriptor pipe failed: {error}"),
        }
    }
    child.wait_for_exit().await.expect("observe target exit");
    child
        .finalize_after_exit()
        .await
        .expect("finalize target and anchor");
    assert!(
        observed_eof,
        "target or long-lived group anchor retained the ambient writer"
    );
}

#[tokio::test]
async fn completed_cleanup_refuses_repeated_numeric_group_signals() {
    let dir = TempDir::new().expect("tempdir");
    let mut child = spawn_piped(&ProcessSpec::new(
        Path::new("/usr/bin/true"),
        clean_env(&dir),
    ))
    .expect("spawn boundary child");
    child.wait_for_exit().await.expect("observe target exit");
    child
        .finalize_after_exit()
        .await
        .expect("finalize target and anchor");

    assert!(matches!(
        child.terminate(Duration::from_millis(1)).await,
        Err(BoundaryError::Io {
            phase: "terminate process group",
            ..
        })
    ));
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
    let iterations = if cfg!(target_os = "macos") { 20 } else { 3 };
    for iteration in 0..iterations {
        let dir = TempDir::new().expect("tempdir");
        let spec = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
            .args(["-c", "sleep 30 & child=$!; echo $child; wait"])
            .timeout(Duration::from_millis(100))
            .termination_grace(Duration::from_millis(50));
        let output = spec
            .run(CancellationToken::new())
            .await
            .unwrap_or_else(|error| panic!("iteration {iteration} failed: {error}"));
        assert_eq!(output.termination, Termination::TimedOut);
        let grandchild: i32 = std::str::from_utf8(&output.stdout)
            .expect("utf8")
            .trim()
            .parse()
            .expect("pid");
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(grandchild), None),
            Err(Errno::ESRCH),
            "iteration {iteration} left the grandchild present"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_stopped_child_does_not_block_the_timeout_watchdog() {
    let iterations = if cfg!(target_os = "macos") { 20 } else { 1 };
    for iteration in 0..iterations {
        let dir = TempDir::new().expect("tempdir");
        let started = std::time::Instant::now();
        let output = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
            .args(["-c", "kill -STOP $$"])
            .timeout(Duration::from_millis(100))
            .termination_grace(Duration::from_millis(50))
            .run(CancellationToken::new())
            .await
            .unwrap_or_else(|error| panic!("iteration {iteration} failed: {error}"));
        assert_eq!(
            output.termination,
            Termination::TimedOut,
            "iteration {iteration} misclassified a stop as an exit"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "iteration {iteration} occupied the async watchdog worker"
        );
    }
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

#[tokio::test]
async fn quarantine_preserves_observation_order_across_streams() {
    let dir = TempDir::new().expect("tempdir");
    let sentinel = b"cross-stream-secret".to_vec();
    let spec = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
        .args(["-c", "printf cross-stream-; sleep 0.05; printf secret >&2"])
        .output_policy(OutputPolicy::Quarantine {
            sentinels: vec![sentinel],
        });
    assert!(matches!(
        spec.run(CancellationToken::new()).await,
        Err(BoundaryError::OutputQuarantined(_))
    ));
}

#[tokio::test]
async fn quarantine_is_independent_of_cross_stream_scheduler_order() {
    let dir = TempDir::new().expect("tempdir");
    let sentinel = b"cross-stream-secret".to_vec();
    let spec = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
        .args(["-c", "printf secret >&2; printf cross-stream-"])
        .output_policy(OutputPolicy::Quarantine {
            sentinels: vec![sentinel],
        });
    assert!(matches!(
        spec.run(CancellationToken::new()).await,
        Err(BoundaryError::OutputQuarantined(_))
    ));
}

#[tokio::test]
async fn process_boundary_persists_only_through_restrictive_transcript_writer() {
    let dir = TempDir::new().expect("tempdir");
    let canonical_root = std::fs::canonicalize(dir.path()).expect("canonical temporary root");
    let writer = TranscriptWriter::new(TranscriptPolicy {
        directory: canonical_root.join("transcripts"),
        sentinels: vec![b"never-present-sentinel".to_vec()],
        max_files: 2,
        max_age: Duration::from_secs(60),
        max_bytes: 1024,
    })
    .expect("writer");
    let reader = writer.clone();
    let output = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
        .args(["-c", "printf output; printf warning >&2"])
        .transcript(writer, "execution-1")
        .run(CancellationToken::new())
        .await
        .expect("run");
    let artifact = output
        .transcript_artifact
        .expect("transcript artifact identifier");
    let body = reader.read_artifact(&artifact).expect("read transcript");
    assert!(body.starts_with(b"ARCANA-TRANSCRIPT-V1\0"));
    assert!(body.windows(6).any(|bytes| bytes == b"output"));
    assert!(body.windows(7).any(|bytes| bytes == b"warning"));
}

#[tokio::test]
async fn dropping_execution_future_kills_the_owned_process_group() {
    let dir = TempDir::new().expect("tempdir");
    let pid_file = dir.path().join("grandchild.pid");
    let command = format!(
        "sleep 30 & child=$!; printf %s \"$child\" > {}; wait",
        pid_file.display()
    );
    let spec =
        ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir)).args(["-c".to_owned(), command]);
    let task = tokio::spawn(async move { spec.run(CancellationToken::new()).await });
    for _ in 0..100 {
        if pid_file.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let grandchild: i32 = std::fs::read_to_string(&pid_file)
        .expect("pid file")
        .parse()
        .expect("pid");
    task.abort();
    let _ = task.await;
    for _ in 0..100 {
        if nix::sys::signal::kill(nix::unistd::Pid::from_raw(grandchild), None) == Err(Errno::ESRCH)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("dropping the execution future stranded the process group");
}

#[test]
fn runtime_shutdown_still_signals_the_owned_process_group() {
    let dir = TempDir::new().expect("tempdir");
    let pid_file = dir.path().join("runtime-shutdown-grandchild.pid");
    let command = format!(
        "sleep 30 & child=$!; printf %s \"$child\" > {}; wait",
        pid_file.display()
    );
    let spec =
        ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir)).args(["-c".to_owned(), command]);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.spawn(async move { spec.run(CancellationToken::new()).await });
    runtime.block_on(async {
        for _ in 0..100 {
            if pid_file.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("child did not start before runtime shutdown");
    });
    let grandchild: i32 = std::fs::read_to_string(&pid_file)
        .expect("pid file")
        .parse()
        .expect("pid");

    runtime.shutdown_timeout(Duration::from_secs(1));
    for _ in 0..100 {
        if nix::sys::signal::kill(nix::unistd::Pid::from_raw(grandchild), None) == Err(Errno::ESRCH)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("runtime shutdown stranded the owned process group");
}

#[tokio::test]
async fn cancelling_natural_exit_finalization_cannot_strand_a_descendant() {
    let dir = TempDir::new().expect("tempdir");
    let pid_file = dir.path().join("natural-exit-grandchild.pid");
    let command = format!(
        "sleep 30 & child=$!; printf %s \"$child\" > {}; exit 0",
        pid_file.display()
    );
    let mut child = spawn_piped(
        &ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir)).args(["-c".to_owned(), command]),
    )
    .expect("spawn boundary child");
    for _ in 0..100 {
        if pid_file.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let grandchild: i32 = std::fs::read_to_string(&pid_file)
        .expect("pid file")
        .parse()
        .expect("pid");
    child.wait_for_exit().await.expect("observe leader exit");

    let finalizer = tokio::spawn(async move { child.finalize_after_exit().await });
    tokio::task::yield_now().await;
    finalizer.abort();
    let _ = finalizer.await;

    for _ in 0..100 {
        if nix::sys::signal::kill(nix::unistd::Pid::from_raw(grandchild), None) == Err(Errno::ESRCH)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("cancelling natural-exit finalization stranded a descendant");
}

#[tokio::test]
async fn exited_leader_cannot_hold_the_boundary_open_via_background_pipe() {
    let dir = TempDir::new().expect("tempdir");
    let spec = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
        .args(["-c", "sleep 30 &"])
        .timeout(Duration::from_millis(100))
        .termination_grace(Duration::from_millis(25));
    let started = std::time::Instant::now();
    let result = spec.run(CancellationToken::new()).await;
    assert!(result.is_ok(), "leader exit should close its owned group");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "open descendant pipes must remain bounded"
    );
}

#[tokio::test]
async fn successful_leader_exit_kills_a_pipe_closing_background_descendant() {
    let dir = TempDir::new().expect("tempdir");
    let pid_file = dir.path().join("detached.pid");
    let command = format!(
        "sleep 30 </dev/null >/dev/null 2>&1 & child=$!; printf %s \"$child\" > {}",
        pid_file.display()
    );
    let output = ProcessSpec::new(Path::new("/bin/sh"), clean_env(&dir))
        .args(["-c".to_owned(), command])
        .run(CancellationToken::new())
        .await
        .expect("run");
    assert!(output.success);
    let descendant: i32 = std::fs::read_to_string(&pid_file)
        .expect("pid file")
        .parse()
        .expect("pid");
    for _ in 0..100 {
        if nix::sys::signal::kill(nix::unistd::Pid::from_raw(descendant), None) == Err(Errno::ESRCH)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("successful leader exit stranded a pipe-closing descendant");
}
