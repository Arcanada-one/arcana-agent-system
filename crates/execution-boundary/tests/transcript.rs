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
    })
    .expect("writer")
}

#[test]
fn writes_only_after_quarantine_with_restrictive_owner_only_modes() {
    let dir = TempDir::new().expect("tempdir");
    let writer = writer(&dir.path().join("transcripts"), 4);
    let path = writer
        .write(
            "task-1",
            &[
                TranscriptChunk::new(Stream::Stdout, b"hello\n"),
                TranscriptChunk::new(Stream::Stderr, b"warning\n"),
            ],
        )
        .expect("write");

    let root_meta = std::fs::metadata(writer.directory()).expect("root metadata");
    let file_meta = std::fs::metadata(&path).expect("file metadata");
    assert_eq!(root_meta.permissions().mode() & 0o777, 0o700);
    assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(root_meta.uid(), nix::unistd::geteuid().as_raw());
    assert_eq!(file_meta.uid(), nix::unistd::geteuid().as_raw());
    assert!(writer.directory().join(".metadata_never_index").is_file());
    assert!(writer.directory().join(".nosync").is_file());
    assert!(writer.directory().join(".stignore").is_file());

    let body = std::fs::read_to_string(path).expect("read");
    assert!(body.contains("[stdout]\nhello"));
    assert!(body.contains("[stderr]\nwarning"));
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
