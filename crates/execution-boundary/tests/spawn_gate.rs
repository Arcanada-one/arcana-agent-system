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
use syn::visit::Visit;

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

#[derive(Default)]
struct SpawnVisitor {
    command_names: std::collections::BTreeSet<String>,
    process_modules: std::collections::BTreeSet<String>,
    sites: usize,
}

impl SpawnVisitor {
    fn collect_use(&mut self, prefix: Vec<String>, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(path) => {
                let mut next = prefix;
                next.push(path.ident.to_string());
                self.collect_use(next, &path.tree);
            }
            syn::UseTree::Name(name) => {
                let mut full = prefix;
                full.push(name.ident.to_string());
                self.record_import(&full, name.ident.to_string());
            }
            syn::UseTree::Rename(rename) => {
                let mut full = prefix;
                full.push(rename.ident.to_string());
                self.record_import(&full, rename.rename.to_string());
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_use(prefix.clone(), item);
                }
            }
            syn::UseTree::Glob(_) => {
                // A process-module glob can make `Command` visible.
                if is_process_module(&prefix) {
                    self.command_names.insert("Command".to_owned());
                }
            }
        }
    }

    fn record_import(&mut self, full: &[String], local: String) {
        if is_command_path(full) {
            self.command_names.insert(local);
        } else if is_process_module(full) {
            self.process_modules.insert(local);
        }
    }

    fn path_is_spawn(&self, path: &syn::Path) -> bool {
        let parts: Vec<String> = path
            .segments
            .iter()
            .map(|part| part.ident.to_string())
            .collect();
        if parts.last().is_some_and(|last| {
            matches!(last.as_str(), "posix_spawn" | "execve" | "execvp" | "execv")
        }) {
            return true;
        }
        if parts.last().is_none_or(|last| last != "new") || parts.len() < 2 {
            return false;
        }
        let constructor = &parts[parts.len() - 2];
        self.command_names.contains(constructor)
            || constructor == "Command"
                && (parts.len() == 2
                    || parts[..parts.len() - 2].windows(2).any(|window| {
                        window == ["std", "process"] || window == ["tokio", "process"]
                    }))
            || parts.len() >= 3
                && self.process_modules.contains(&parts[parts.len() - 3])
                && constructor == "Command"
    }
}

impl<'ast> Visit<'ast> for SpawnVisitor {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.collect_use(Vec::new(), &item.tree);
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if let syn::Type::Path(path) = item.ty.as_ref() {
            let parts: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|part| part.ident.to_string())
                .collect();
            if is_command_path(&parts) {
                self.command_names.insert(item.ident.to_string());
            }
        }
        syn::visit::visit_item_type(self, item);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        if self.path_is_spawn(&expression.path) {
            self.sites += 1;
        }
        syn::visit::visit_expr_path(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if expression.method == "exec" {
            self.sites += 1;
        }
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn is_process_module(parts: &[String]) -> bool {
    parts.ends_with(&["std".to_owned(), "process".to_owned()])
        || parts.ends_with(&["tokio".to_owned(), "process".to_owned()])
}

fn is_command_path(parts: &[String]) -> bool {
    parts.last().is_some_and(|last| last == "Command")
        && is_process_module(&parts[..parts.len().saturating_sub(1)])
}

fn spawn_site_count(text: &str) -> Result<usize, syn::Error> {
    let syntax = syn::parse_file(text)?;
    let mut visitor = SpawnVisitor::default();
    visitor.visit_file(&syntax);
    Ok(visitor.sites)
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
        let count = spawn_site_count(&text)
            .unwrap_or_else(|error| panic!("parse {rel} for spawn inventory: {error}"));
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
fn gate_detects_aliases_multiline_and_comments_without_false_hits() {
    for source in [
        "use std::process::Command as Cmd;\nfn a() { Cmd::new(\"/bin/sh\"); }\n",
        "use tokio::process as p;\nfn a() { p::Command\n::new(\"/bin/sh\"); }",
        "type Runner = std::process::Command;\nfn a() { Runner::new(\"/bin/sh\"); }",
        "fn a() { std::process::Command::new(\"/bin/sh\"); }",
    ] {
        assert_eq!(spawn_site_count(source).expect("parse"), 1, "{source}");
    }
    let benign = r#"
        // Command::new("/bin/sh");
        const DOC: &str = "std::process::Command::new";
        fn a() { let _ = compute(); }
    "#;
    assert_eq!(spawn_site_count(benign).expect("parse"), 0);
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
