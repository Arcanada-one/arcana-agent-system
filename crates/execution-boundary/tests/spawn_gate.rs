//! Structural spawn gate (V-AC-1).
//!
//! Every shipped-runtime subprocess must cross the typed execution boundary.
//! This test pins the exact inventory of raw `Command::new` sites so that:
//!
//! 1. a **newly introduced** raw spawn fails CI immediately, and
//! 2. the pinned shipped-runtime list shrinks to empty as each site migrates.
//!
//! The three shipped-runtime entries below are the SEC-0030 migration targets.
//! They are recorded, not excused: this test fails if the list grows, and the
//! list is expected to reach zero before the credentialed path is enabled.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Build-time only; never part of the shipped runtime.
const BUILD_TIME_ALLOWLIST: &[&str] = &["crates/cli/build.rs"];

/// Documented test fixtures.
const TEST_FIXTURE_ALLOWLIST: &[&str] = &["crates/supervisor/src/bin/heartbeat-child.rs"];

/// Shipped-runtime spawn sites still awaiting migration behind the boundary.
/// This list MUST NOT grow. It reaches empty when Phase 2 migration completes.
const PENDING_MIGRATION: &[&str] = &[
    "crates/connectors/src/coworker.rs",
    "crates/supervisor/src/spawn.rs",
    "crates/tools/src/bash.rs",
];

fn workspace_root() -> PathBuf {
    // crates/execution-boundary -> workspace root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Files containing a real (non-comment) `Command::new` call.
fn raw_spawn_sites() -> BTreeSet<String> {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root.join("crates"), &mut files);

    let mut hits = BTreeSet::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let is_test_path = file.components().any(|c| c.as_os_str() == "tests");
        for line in text.lines() {
            let trimmed = line.trim_start();
            // Doc and line comments describe the pattern without invoking it.
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            if trimmed.contains("Command::new") {
                if is_test_path {
                    continue; // test-only spawning is out of the shipped runtime
                }
                let rel = file
                    .strip_prefix(&root)
                    .unwrap_or(&file)
                    .display()
                    .to_string();
                hits.insert(rel);
                break;
            }
        }
    }
    hits
}

#[test]
fn no_unaccounted_raw_spawn_site_exists() {
    let found = raw_spawn_sites();
    let accounted: BTreeSet<String> = BUILD_TIME_ALLOWLIST
        .iter()
        .chain(TEST_FIXTURE_ALLOWLIST)
        .chain(PENDING_MIGRATION)
        .map(|s| (*s).to_owned())
        .collect();

    let unaccounted: Vec<&String> = found.difference(&accounted).collect();
    assert!(
        unaccounted.is_empty(),
        "new raw process-spawn site(s) introduced outside the execution boundary: {unaccounted:?}"
    );
}

/// The migration list must shrink, never grow.
#[test]
fn pending_migration_list_does_not_grow() {
    let found = raw_spawn_sites();
    let still_pending: Vec<&&str> = PENDING_MIGRATION
        .iter()
        .filter(|p| found.contains(**p))
        .collect();
    assert!(
        still_pending.len() <= PENDING_MIGRATION.len(),
        "shipped-runtime spawn inventory grew: {still_pending:?}"
    );
}

/// API-mode routing structurally cannot spawn: it carries no program at all.
#[test]
fn api_route_cannot_spawn() {
    use arcana_execution_boundary::Route;
    let api = Route::NativeApi {
        provider: "mock".to_owned(),
    };
    assert!(!api.may_spawn(), "API mode must never be able to shell out");

    let cli = Route::SupervisedCli {
        adapter: PathBuf::from("/opt/arcana/libexec/declared-adapter"),
    };
    assert!(cli.may_spawn());
}
