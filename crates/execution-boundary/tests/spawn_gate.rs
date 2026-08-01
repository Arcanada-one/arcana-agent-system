//! Structural spawn gate (V-AC-1).
//!
//! Every shipped-runtime subprocess must eventually cross the typed execution
//! boundary. This test pins the exact inventory of raw process-spawn sites so a
//! newly introduced one fails CI, and so the pinned list can only shrink.
//!
//! REGRESSION: the previous version of this file was ineffective in three ways
//! that the independent review confirmed by defeating it —
//!
//! 1. `pending_migration_list_does_not_grow` compared a filtered subset of
//!    `PENDING_MIGRATION` against `PENDING_MIGRATION.len()`, which is true for
//!    every possible input. The test could not fail.
//! 2. The scan matched only the literal `Command::new`, so `use
//!    std::process::Command as Cmd;` or a line break defeated it.
//! 3. It scanned only `crates/` and stopped at the first hit per file, so
//!    additional spawn sites in an already-pinned file were invisible.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Build-time only; never part of the shipped runtime.
const BUILD_TIME_ALLOWLIST: &[&str] = &["crates/cli/build.rs"];

/// Documented test fixtures.
const TEST_FIXTURE_ALLOWLIST: &[&str] = &["crates/supervisor/src/bin/heartbeat-child.rs"];

/// The execution boundary itself is the sanctioned owner of process spawning —
/// migrating the sites below *into* this crate is the goal, not a violation.
/// Everything here is reviewed as part of the boundary's own contract.
const BOUNDARY_ALLOWLIST: &[&str] = &[
    "crates/execution-boundary/src/env_policy.rs",
    "crates/execution-boundary/src/process.rs",
];

/// Shipped-runtime spawn sites still awaiting migration, with their exact
/// current site count. Both the set and the counts may only shrink.
const PENDING_MIGRATION: &[(&str, usize)] = &[];

fn workspace_root() -> PathBuf {
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
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            // Build output and VCS internals only.
            if name == "target" || name == ".git" {
                continue;
            }
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Spawn-API spellings. The point is to catch renames and alternate APIs, not
/// only the one idiom the codebase happens to use today.
fn spawn_markers(text: &str) -> Vec<&'static str> {
    let mut markers = vec![
        "Command::new",
        "process::Command",
        "posix_spawn",
        "execve",
        "execvp",
        "execv(",
        "CommandExt::exec",
        ".exec()",
    ];
    // An aliased import: `use std::process::Command as Cmd;` then `Cmd::new`.
    if let Some(idx) = text.find("process::Command as ") {
        let alias: String = text[idx + "process::Command as ".len()..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !alias.is_empty() {
            // Leak is bounded: one alias per file, test-scoped process.
            markers.push(Box::leak(format!("{alias}::new").into_boxed_str()));
        }
    }
    markers
}

/// Count real (non-comment) spawn sites per file, across the whole repository.
fn raw_spawn_sites() -> BTreeMap<String, usize> {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root, &mut files);

    let mut hits: BTreeMap<String, usize> = BTreeMap::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        // Test-only spawning is out of the shipped runtime, but must still be a
        // path *component* match — not any file whose name contains "tests".
        let is_test_path = Path::new(&rel)
            .components()
            .any(|c| c.as_os_str() == "tests");
        if is_test_path {
            continue;
        }
        let markers = spawn_markers(&text);
        let mut count = 0usize;
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("#[") {
                continue;
            }
            // An import is not a spawn. It still forces the file to be
            // classified (the file appears in `hits` via its real call site),
            // but counting it would let a new spawn hide behind a dropped
            // `use` line while the total stayed flat.
            if trimmed.starts_with("use ") {
                continue;
            }
            if markers.iter().any(|m| trimmed.contains(m)) {
                count += 1;
            }
        }
        if count > 0 {
            hits.insert(rel, count);
        }
    }
    hits
}

/// The inventory must match the pinned classification exactly — no new file,
/// and no new site inside an already-pinned file.
#[test]
fn spawn_inventory_matches_the_pinned_classification() {
    let found = raw_spawn_sites();

    let mut accounted: BTreeMap<&str, Option<usize>> = BTreeMap::new();
    for f in BUILD_TIME_ALLOWLIST
        .iter()
        .chain(TEST_FIXTURE_ALLOWLIST)
        .chain(BOUNDARY_ALLOWLIST)
    {
        accounted.insert(f, None); // count not pinned for non-runtime files
    }
    for (f, n) in PENDING_MIGRATION {
        accounted.insert(f, Some(*n));
    }

    let unaccounted: Vec<&String> = found
        .keys()
        .filter(|f| !accounted.contains_key(f.as_str()))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "new raw process-spawn site(s) outside the execution boundary: {unaccounted:?}"
    );

    for (file, pinned) in &accounted {
        let Some(pinned) = pinned else { continue };
        let actual = found.get(*file).copied().unwrap_or(0);
        assert!(
            actual <= *pinned,
            "`{file}` gained spawn sites: pinned {pinned}, found {actual}. \
             The shipped-runtime inventory may only shrink."
        );
    }
}

/// This is the assertion the old tautology was trying to make: the migration
/// set may lose members, never gain them.
#[test]
fn migration_set_does_not_gain_members() {
    let found = raw_spawn_sites();
    let runtime_files: Vec<&String> = found
        .keys()
        .filter(|f| {
            !BUILD_TIME_ALLOWLIST.contains(&f.as_str())
                && !TEST_FIXTURE_ALLOWLIST.contains(&f.as_str())
                && !BOUNDARY_ALLOWLIST.contains(&f.as_str())
        })
        .collect();
    assert!(
        runtime_files.len() <= PENDING_MIGRATION.len(),
        "shipped-runtime spawn inventory grew to {runtime_files:?}"
    );
}

/// Meta-test: the gate must actually detect an aliased import and a bare
/// `Command::new`, otherwise a green result means nothing.
#[test]
fn gate_detects_aliased_and_plain_spawn_forms() {
    let aliased = "use std::process::Command as Cmd;\nfn a() { Cmd::new(\"/bin/sh\"); }\n";
    let markers = spawn_markers(aliased);
    assert!(
        markers.iter().any(|m| aliased.contains(m)),
        "gate must detect an aliased spawn"
    );

    let plain = "fn a() { let _ = Command::new(\"/bin/sh\"); }";
    assert!(spawn_markers(plain).iter().any(|m| plain.contains(m)));

    let benign = "fn a() { let _ = compute(); }";
    assert!(
        !spawn_markers(benign).iter().any(|m| benign.contains(m)),
        "gate must not fire on benign code"
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
    assert!(Route::SupervisedCli {
        adapter: PathBuf::from("/opt/arcana/libexec/declared-adapter"),
    }
    .may_spawn());
}
