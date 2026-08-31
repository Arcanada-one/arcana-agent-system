use std::path::PathBuf;
use std::process::Command;

/// Ask git for a path that is correct inside a linked worktree.
///
/// `.git` is a FILE there, not a directory, so a hand-built `../../.git/HEAD`
/// resolves to nothing and the `rerun-if-changed` it feeds is silently inert —
/// which lets a cached stamp outlive the commit it names.
fn git_path(relative: &str) -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-path", relative])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    path.exists().then_some(path)
}

/// Whether the working tree carries changes the commit does not contain.
///
/// Fails toward `true`. If git cannot be consulted at all, the honest answer is
/// "this build cannot prove it matches any commit", not "clean" — a provenance
/// stamp that defaults to reassuring is the defect being fixed.
fn is_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        // `is_none_or`: None means git could not be consulted, which must read
        // as dirty. Never as clean.
        .is_none_or(|output| !output.stdout.is_empty())
}

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|s| s.len() == 7 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| "0000000".to_owned());

    let dirty = is_dirty();
    let stamp = if dirty { format!("{sha}-dirty") } else { sha };

    if dirty {
        // Surfaced at build time as well as at run time: whoever produced the
        // artefact should see it, not only whoever later runs it.
        println!(
            "cargo:warning=building from a working tree with uncommitted changes; \
             this binary will NOT correspond to any commit"
        );
    }

    println!("cargo:rustc-env=ARCANA_GIT_SHA={stamp}");
    println!("cargo:rustc-env=ARCANA_GIT_DIRTY={dirty}");
    println!("cargo:rerun-if-changed=build.rs");
    // Resolved through git so these fire in a worktree, where the old literal
    // `../../.git/...` paths do not exist.
    for relative in ["HEAD", "index", "refs/heads"] {
        if let Some(path) = git_path(relative) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    println!("cargo:rerun-if-env-changed=ARCANA_GIT_SHA");
}
