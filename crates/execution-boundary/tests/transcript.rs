//! Restrictive transcript-writer acceptance tests (V-AC-5).

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::time::Duration;

use arcana_execution_boundary::{
    Stream, TranscriptChunk, TranscriptError, TranscriptPolicy, TranscriptWriter,
};
use tempfile::TempDir;

const SENTINEL: &[u8] = b"transcript-credential-sentinel";

fn writer(root: &std::path::Path, max_files: usize) -> TranscriptWriter {
    TranscriptWriter::new(TranscriptPolicy {
        directory: root.to_path_buf(),
        sentinels: vec![SENTINEL.to_vec()],
        max_files,
        max_age: Duration::from_secs(24 * 60 * 60),
        max_bytes: 1024 * 1024,
    })
    .expect("writer")
}

#[test]
fn writes_only_after_quarantine_with_restrictive_owner_only_modes() {
    let dir = TempDir::new().expect("tempdir");
    let writer = writer(&dir.path().join("transcripts"), 4);
    let artifact = writer
        .write(
            "task-1",
            &[
                TranscriptChunk::new(Stream::Stdout, b"hello\n"),
                TranscriptChunk::new(Stream::Stderr, b"warning\n"),
            ],
        )
        .expect("write");
    let path = writer.directory().join(format!("{artifact}.log"));

    let root_meta = std::fs::metadata(writer.directory()).expect("root metadata");
    let file_meta = std::fs::metadata(&path).expect("file metadata");
    assert_eq!(root_meta.permissions().mode() & 0o777, 0o700);
    assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(root_meta.uid(), nix::unistd::geteuid().as_raw());
    assert_eq!(file_meta.uid(), nix::unistd::geteuid().as_raw());
    assert!(writer.directory().join(".metadata_never_index").is_file());
    assert!(writer.directory().join(".nosync").is_file());
    assert!(writer.directory().join(".stignore").is_file());

    let body = writer.read_artifact(&artifact).expect("read artifact");
    assert!(body.starts_with(b"ARCANA-TRANSCRIPT-V1\0"));
    assert!(body
        .windows(b"hello\n".len())
        .any(|bytes| bytes == b"hello\n"));
    assert!(body
        .windows(b"warning\n".len())
        .any(|bytes| bytes == b"warning\n"));
}

#[test]
fn sentinel_or_encoded_sentinel_creates_no_transcript() {
    let dir = TempDir::new().expect("tempdir");
    let writer = writer(&dir.path().join("transcripts"), 4);
    let error = writer
        .write(
            "blocked",
            &[TranscriptChunk::new(
                Stream::Stdout,
                b"dHJhbnNjcmlwdC1jcmVkZW50aWFsLXNlbnRpbmVs",
            )],
        )
        .expect_err("must quarantine");
    assert!(matches!(error, TranscriptError::Quarantined(_)));
    assert!(!writer.directory().join("blocked.log").exists());
}

#[test]
fn root_and_destination_symlinks_are_rejected() {
    let dir = TempDir::new().expect("tempdir");
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("mkdir");
    let linked = dir.path().join("linked");
    symlink(&real, &linked).expect("symlink");
    assert!(matches!(
        TranscriptWriter::new(TranscriptPolicy {
            directory: linked,
            sentinels: vec![SENTINEL.to_vec()],
            max_files: 2,
            max_age: Duration::from_secs(60),
            max_bytes: 1024,
        }),
        Err(TranscriptError::SymlinkRejected { .. })
    ));

    let writer = writer(&dir.path().join("transcripts"), 2);
    symlink(&real, writer.directory().join("collision.log")).expect("file symlink");
    assert!(matches!(
        writer.write(
            "collision",
            &[TranscriptChunk::new(Stream::Stdout, b"safe")]
        ),
        Err(TranscriptError::SymlinkRejected { .. })
    ));
}

#[test]
fn preexisting_no_sync_markers_require_regular_files_and_exact_content() {
    let dir = TempDir::new().expect("tempdir");
    let root = dir.path().join("wrong-content");
    std::fs::create_dir(&root).expect("mkdir");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("root mode");
    let marker = root.join(".stignore");
    std::fs::write(&marker, b"").expect("marker");
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).expect("marker mode");
    assert!(matches!(
        TranscriptWriter::new(TranscriptPolicy {
            directory: root,
            sentinels: vec![SENTINEL.to_vec()],
            max_files: 2,
            max_age: Duration::from_secs(60),
            max_bytes: 1024,
        }),
        Err(TranscriptError::MarkerMismatch { .. })
    ));

    let root = dir.path().join("wrong-type");
    std::fs::create_dir(&root).expect("mkdir");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("root mode");
    std::fs::create_dir(root.join(".nosync")).expect("marker directory");
    assert!(matches!(
        TranscriptWriter::new(TranscriptPolicy {
            directory: root,
            sentinels: vec![SENTINEL.to_vec()],
            max_files: 2,
            max_age: Duration::from_secs(60),
            max_bytes: 1024,
        }),
        Err(TranscriptError::UnsafeFileType { .. })
    ));
}

#[test]
fn ancestor_replacement_cannot_redirect_creation_or_pruning() {
    let dir = TempDir::new().expect("tempdir");
    let original = dir.path().join("transcripts");
    let writer = writer(&original, 1);
    let artifact = writer
        .write("one", &[TranscriptChunk::new(Stream::Stdout, b"one")])
        .expect("first write");

    let held = dir.path().join("held");
    std::fs::rename(&original, &held).expect("rename held directory");
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).expect("outside directory");
    std::fs::write(outside.join("outside.log"), b"must survive").expect("outside file");
    symlink(&outside, &original).expect("replace pathname with symlink");

    assert!(matches!(
        writer.write("two", &[TranscriptChunk::new(Stream::Stdout, b"two")]),
        Err(TranscriptError::NamespaceChanged)
    ));
    assert!(!held.join("two.log").exists());
    assert!(held.join("one.log").is_file());
    assert_eq!(
        std::fs::read(outside.join("outside.log")).expect("outside survives"),
        b"must survive"
    );
    assert!(!outside.join("two.log").exists());
    let body = writer
        .read_artifact(&artifact)
        .expect("held descriptor retrieves original artifact");
    assert!(body.windows(3).any(|bytes| bytes == b"one"));
}

#[test]
fn distributed_cross_stream_sentinel_creates_no_transcript() {
    let dir = TempDir::new().expect("tempdir");
    let writer = writer(&dir.path().join("transcripts"), 4);
    let error = writer
        .write(
            "distributed",
            &[
                TranscriptChunk::new(Stream::Stderr, b"credential-sentinel"),
                TranscriptChunk::new(Stream::Stdout, b"transcript-"),
            ],
        )
        .expect_err("must reject scheduler-independent reconstruction");
    assert!(matches!(error, TranscriptError::Quarantined(_)));
    assert!(!writer.directory().join("distributed.log").exists());
}

#[test]
fn retention_keeps_only_the_newest_bounded_set() {
    let dir = TempDir::new().expect("tempdir");
    let writer = writer(&dir.path().join("transcripts"), 2);
    for id in ["one", "two", "three"] {
        writer
            .write(id, &[TranscriptChunk::new(Stream::Stdout, id.as_bytes())])
            .expect("write");
        std::thread::sleep(Duration::from_millis(5));
    }
    let logs: Vec<_> = std::fs::read_dir(writer.directory())
        .expect("read dir")
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "log"))
        .collect();
    assert_eq!(logs.len(), 2);
    assert!(!writer.directory().join("one.log").exists());
}

#[test]
fn invalid_identifier_and_zero_retention_fail_closed() {
    let dir = TempDir::new().expect("tempdir");
    assert!(matches!(
        TranscriptWriter::new(TranscriptPolicy {
            directory: dir.path().join("zero"),
            sentinels: vec![SENTINEL.to_vec()],
            max_files: 0,
            max_age: Duration::from_secs(60),
            max_bytes: 1024,
        }),
        Err(TranscriptError::InvalidRetention)
    ));
    let writer = writer(&dir.path().join("transcripts"), 2);
    assert!(matches!(
        writer.write(
            "../escape",
            &[TranscriptChunk::new(Stream::Stdout, b"safe")]
        ),
        Err(TranscriptError::InvalidIdentifier)
    ));
}

#[test]
fn byte_limit_is_checked_before_destination_creation() {
    let dir = TempDir::new().expect("tempdir");
    let writer = TranscriptWriter::new(TranscriptPolicy {
        directory: dir.path().join("bounded"),
        sentinels: vec![SENTINEL.to_vec()],
        max_files: 2,
        max_age: Duration::from_secs(60),
        max_bytes: 4,
    })
    .expect("writer");
    assert!(matches!(
        writer.write(
            "oversized",
            &[TranscriptChunk::new(Stream::Stdout, b"12345")]
        ),
        Err(TranscriptError::SizeLimitExceeded)
    ));
    assert!(!writer.directory().join("oversized.log").exists());
}
