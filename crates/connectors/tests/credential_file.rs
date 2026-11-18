//! Independent negative controls for the public Muneral file-loading boundary.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arcana_connectors::muneral::read_key_file;
use secrecy::ExposeSecret;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn fixture(bytes: &[u8]) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credential");
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    (dir, path)
}

fn refused(path: &Path, reason: &str) {
    let error = read_key_file(path).unwrap_err().to_string();
    assert!(error.contains(reason), "wrong refusal: {error}");
    assert!(!error.contains("synthetic-credential-value"));
    assert!(!error.contains(&path.display().to_string()));
}

#[test]
fn valid_regular_file_is_read_and_trimmed() {
    let (_dir, path) = fixture(b" synthetic-credential-value\n");
    assert_eq!(
        read_key_file(&path).unwrap().expose_secret(),
        "synthetic-credential-value"
    );
}

#[test]
fn broad_mode_is_unsafe() {
    let (_dir, path) = fixture(b"synthetic-credential-value");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    refused(&path, "insecure permissions");
}

#[test]
fn final_symlink_is_unsafe() {
    let (dir, target) = fixture(b"synthetic-credential-value");
    let link = dir.path().join("link");
    symlink(target, &link).unwrap();
    refused(&link, "regular non-symlink file");
}

#[test]
fn non_regular_directory_is_unsafe() {
    let dir = TempDir::new().unwrap();
    refused(dir.path(), "regular non-symlink file");
}

#[test]
fn zero_bytes_is_unsafe() {
    let (_dir, path) = fixture(b"");
    refused(&path, "empty or exceeds the size limit");
}

#[test]
fn above_limit_is_unsafe() {
    let (_dir, path) = fixture(&vec![b'x'; 4097]);
    refused(&path, "empty or exceeds the size limit");
}

#[test]
fn missing_is_distinct_from_unsafe() {
    let dir = TempDir::new().unwrap();
    refused(&dir.path().join("absent"), "file is missing");
}

#[test]
fn exact_limit_is_read() {
    let (_dir, path) = fixture(&vec![b'x'; 4096]);
    assert_eq!(read_key_file(&path).unwrap().expose_secret().len(), 4096);
}

#[test]
fn whitespace_only_is_unsafe() {
    let (_dir, path) = fixture(b" \n\t");
    refused(&path, "empty or exceeds the size limit");
}

#[test]
fn invalid_utf8_is_not_read() {
    let (_dir, path) = fixture(&[255]);
    refused(&path, "unavailable");
}
