//! Did the run change anything? — measured, not asked.
//!
//! `arcana run` used to decide "completed" from two facts the model itself
//! supplies: the terminal reason, and the number of tool calls that executed.
//! Both were satisfied by a run that did nothing. Pilot A2-278 ran the same
//! Muneral work item twice (runs 2 and 4, `deepseek-v4-flash`); between them
//! nine and three tool calls executed, every one of them a `read` or a `grep`,
//! nothing was written, and both runs printed `"completed":true` with rc `0`
//! while the model's closing sentence described a file — `docs/how-to/
//! run-work-item.md` — that does not exist, with invented commands inside it.
//! The guard written up in `docs/how-to/run-one-task-unattended.md`
//! ("`completed` is never `true` with `tool_calls` at `0`") counted the reads
//! and let it through.
//!
//! So completion is tied here to an effect an outsider can check:
//!
//! * [`snapshot`] digests the working tree before the first model call and
//!   again after the last one. Equal digests mean the run left the tree
//!   exactly as it found it, whatever it said.
//! * The tools that executed are listed, and the ones that can change a file
//!   ([`MUTATING_TOOLS`]) are named separately — corroboration, never the
//!   verdict. `bash` can write too, and the digest is what catches it.
//! * The paths the final message claims are looked up on disk
//!   ([`Effect::claimed_but_absent`], [`Effect::claimed_but_unchanged`]). A
//!   string comparison and two `stat`s; it costs no model call.
//!
//! ## Declaring a read-only task
//!
//! Not every task should change a file: "audit X and report" is finished when
//! the report is on stdout. That is declared with
//! [`EffectExpectation::ReadOnly`] — `--read-only` on the command line —
//! **by the caller, before the run**. It is never inferred from what the model
//! did, and never read out of the model's own text: a run that could declare
//! itself read-only after the fact would be back where it started.
//!
//! ## The third verdict
//!
//! A tree too large to walk, or one the process cannot read, yields
//! [`TreeSnapshot::complete`] `false`, and then [`Effect::tree_changed`] is
//! `None` — not `false`. `NoEffect` is a refusal, and a refusal has to be
//! provable; an unmeasured tree is not evidence that nothing happened.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// The runner's own scratch directory, excluded from the digest.
///
/// Spilled tool output, rejected replies and refused calls all land here. They
/// are evidence ABOUT the run, not the task's output — a run that only filled
/// `.arcana/` produced nothing, and counting it as an effect would re-open the
/// hole this module exists to close.
pub const RUNNER_DIR: &str = ".arcana";

/// Repository internals, excluded from the digest.
///
/// The working tree is what a patch would carry; `.git` is the machinery
/// underneath it, and it churns (index, logs, objects) for reasons that have
/// nothing to do with the task.
pub const GIT_DIR: &str = ".git";

/// Tools whose successful execution can change a file, by name.
///
/// Reporting only. `bash` is deliberately absent even though it can write:
/// naming it here would make the list look like the verdict, and the verdict
/// is the tree digest. A run whose only write went through `bash` shows an
/// empty `writes` list beside `tree_changed: true`, which is the truth.
pub const MUTATING_TOOLS: [&str; 2] = ["write", "edit"];

/// Upper bound on files walked, over which the snapshot reports itself
/// incomplete rather than spending the run's wall clock on a digest.
const MAX_FILES: usize = 200_000;

/// How many changed paths the receipt names before it stops listing them.
const MAX_CHANGED_LISTED: usize = 32;

/// How many claimed paths are checked. A final message that names more than
/// this is not making a claim a reader can follow anyway.
const MAX_CLAIMS: usize = 32;

/// What the caller declared the task must leave behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EffectExpectation {
    /// The task is expected to change the working tree. The default: a run is
    /// dispatched to do something, and "it read a lot of files" is not it.
    #[default]
    Artefact,
    /// The task was declared read-only before it started, so an unchanged tree
    /// is the expected outcome and not a refusal.
    ReadOnly,
}

impl EffectExpectation {
    /// The word the marker and the receipt print.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Artefact => "artefact",
            Self::ReadOnly => "read-only",
        }
    }

    /// Whether an unchanged tree refuses the run.
    #[must_use]
    pub fn requires_effect(self) -> bool {
        matches!(self, Self::Artefact)
    }
}

/// A digest of the working tree, and the per-file digests it was built from.
#[derive(Debug, Clone)]
pub struct TreeSnapshot {
    /// `sha256:<hex>` over every file's path and content, in path order.
    pub digest: String,
    /// Relative path → `sha256` of that file's bytes (or of its link target).
    files: BTreeMap<String, String>,
    /// `false` when the walk hit [`MAX_FILES`] or could not read a directory.
    /// Then the digest covers part of the tree and must not be compared.
    pub complete: bool,
}

impl TreeSnapshot {
    /// How many files the digest covers.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// The digest string, or `null` for an incomplete walk — a partial digest
    /// compared against another partial digest proves nothing.
    #[must_use]
    pub fn reported_digest(&self) -> Option<&str> {
        self.complete.then_some(self.digest.as_str())
    }
}

/// Digest the working tree under `root`.
///
/// Skips [`GIT_DIR`], [`RUNNER_DIR`] and everything the repository's
/// `.gitignore` files exclude — the same set `git status` would call the
/// working tree, tracked and untracked alike. Ignoring the ignored is not
/// tidiness: a `cargo build` rewrites hundreds of megabytes under `target/`,
/// and a digest that moved because of it would call a run that only compiled
/// the project "a run that produced an artefact".
///
/// Symbolic links are hashed by their target string and never followed, so a
/// link into a directory tree cannot make the walk loop or wander outside
/// `root`.
#[must_use]
pub fn snapshot(root: &Path) -> TreeSnapshot {
    let mut files = BTreeMap::new();
    let mut complete = true;
    let mut walker = Walk {
        files: &mut files,
        complete: &mut complete,
    };
    walker.descend(root, Path::new(""), &Ignore::root(root));
    let mut hasher = Sha256::new();
    for (path, digest) in &files {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(digest.as_bytes());
        hasher.update(*b"\n");
    }
    TreeSnapshot {
        digest: format!("sha256:{}", hex(&hasher.finalize())),
        files,
        complete,
    }
}

/// What the run left behind, as the marker and the receipt report it.
#[derive(Debug, Clone, Serialize)]
pub struct Effect {
    /// `artefact` or `read-only`, as declared before the run.
    pub expectation: &'static str,
    /// Tree digest before the first model call; `null` if not measurable.
    pub tree_digest_before: Option<String>,
    /// Tree digest after the last one; `null` if not measurable.
    pub tree_digest_after: Option<String>,
    /// `true`/`false` when both digests were measured, `null` when either
    /// walk was incomplete. `null` is the third verdict and must not be read
    /// as either of the other two.
    pub tree_changed: Option<bool>,
    /// Files added, removed or rewritten, in path order, at most
    /// [`MAX_CHANGED_LISTED`] of them.
    pub changed_paths: Vec<String>,
    /// How many files changed in total, listed or not.
    pub changed_count: usize,
    /// Executed calls to a tool in [`MUTATING_TOOLS`], in call order.
    pub writes: Vec<String>,
    /// Every tool that executed, with how often. Evidence that the run's
    /// calls were all reads is the point of this card.
    pub executed_tools: BTreeMap<String, usize>,
    /// Paths the final message named.
    pub claimed_paths: Vec<String>,
    /// …of those, the ones that are not on disk.
    pub claimed_but_absent: Vec<String>,
    /// …and the ones that are on disk but identical to before the run.
    pub claimed_but_unchanged: Vec<String>,
}

impl Effect {
    /// Whether the run must be refused for having produced nothing.
    ///
    /// Only a MEASURED unchanged tree refuses. `None` — an incomplete walk —
    /// does not, because the refusal would then rest on a guess.
    #[must_use]
    pub fn refuses_completion(&self, expectation: EffectExpectation) -> bool {
        expectation.requires_effect() && self.tree_changed == Some(false)
    }
}

/// Compare two snapshots and read the final text for claims.
#[must_use]
pub fn measure(
    expectation: EffectExpectation,
    before: &TreeSnapshot,
    after: &TreeSnapshot,
    executed_tools: &[String],
    final_text: Option<&str>,
) -> Effect {
    let measurable = before.complete && after.complete;
    let mut changed: Vec<String> = Vec::new();
    if measurable {
        for (path, digest) in &after.files {
            if before.files.get(path) != Some(digest) {
                changed.push(path.clone());
            }
        }
        for path in before.files.keys() {
            if !after.files.contains_key(path) {
                changed.push(path.clone());
            }
        }
        changed.sort();
        changed.dedup();
    }
    let mut tools: BTreeMap<String, usize> = BTreeMap::new();
    for name in executed_tools {
        *tools.entry(name.clone()).or_insert(0) += 1;
    }
    let writes = executed_tools
        .iter()
        .filter(|name| MUTATING_TOOLS.contains(&name.as_str()))
        .cloned()
        .collect();

    let claimed = final_text.map(claimed_paths).unwrap_or_default();
    let mut absent = Vec::new();
    let mut unchanged = Vec::new();
    for path in &claimed {
        match (before.files.get(path), after.files.get(path)) {
            (_, None) => absent.push(path.clone()),
            (Some(was), Some(now)) if was == now => unchanged.push(path.clone()),
            _ => {}
        }
    }

    Effect {
        expectation: expectation.as_str(),
        tree_digest_before: before.reported_digest().map(ToOwned::to_owned),
        tree_digest_after: after.reported_digest().map(ToOwned::to_owned),
        tree_changed: measurable.then_some(!changed.is_empty()),
        changed_count: changed.len(),
        changed_paths: changed.into_iter().take(MAX_CHANGED_LISTED).collect(),
        writes,
        executed_tools: tools,
        claimed_paths: claimed,
        claimed_but_absent: absent,
        claimed_but_unchanged: unchanged,
    }
}

/// Every workspace-relative path the text names.
///
/// Deliberately conservative and deliberately cheap: a candidate has to
/// contain a `/`, end in a segment with a dot in it, and be spelled out of
/// path characters. That admits `docs/how-to/run-work-item.md` — the exact
/// sentence pilot A2-278's run 2 ended on — and rejects the prose around it
/// ("read/write", "and/or"). It is a claim-detector, not a parser: a path it
/// misses is a claim nobody checks, which is where we already were.
#[must_use]
pub fn claimed_paths(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    // `:` is NOT a separator: keeping `https://example.com/x.html` in one
    // piece is what lets `is_path_like` throw the whole url away. Split on it
    // and the tail arrives looking exactly like a relative path.
    for raw in text.split(|ch: char| ch.is_whitespace() || "`'\"(){}[]<>,;|".contains(ch)) {
        let candidate = raw
            .trim_matches(|ch| ch == '*' || ch == '_')
            .trim_end_matches('.');
        // `./docs/a.md` and `docs/a.md` are the same claim.
        let candidate = candidate.strip_prefix("./").unwrap_or(candidate);
        if !is_path_like(candidate) {
            continue;
        }
        let candidate = candidate.to_owned();
        if !found.contains(&candidate) {
            found.push(candidate);
        }
        if found.len() == MAX_CLAIMS {
            break;
        }
    }
    found
}

fn is_path_like(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.len() > 200 || !candidate.contains('/') {
        return false;
    }
    if !candidate
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "._-/".contains(ch))
    {
        return false;
    }
    // Absolute, home-relative, or `..` — all three name somewhere the run's
    // workspace-relative digest cannot speak about, so none is a claim this
    // run can be held to.
    if candidate.starts_with('/') || candidate.starts_with('~') {
        return false;
    }
    if candidate.split('/').any(|segment| segment == "..") {
        return false;
    }
    let Some(last) = candidate.rsplit('/').next() else {
        return false;
    };
    last.contains('.') && !last.starts_with('.')
}

/// The recursive tree walk, carrying the two accumulators it fills.
struct Walk<'a> {
    files: &'a mut BTreeMap<String, String>,
    complete: &'a mut bool,
}

impl Walk<'_> {
    fn descend(&mut self, dir: &Path, relative: &Path, ignore: &Ignore) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            // A directory the process cannot read leaves a hole in the digest,
            // and a digest with a hole may not be compared.
            *self.complete = false;
            return;
        };
        let mut names: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten() {
            names.push(entry.path());
        }
        names.sort();
        for path in names {
            if self.files.len() >= MAX_FILES {
                *self.complete = false;
                return;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                // A name that is not UTF-8 cannot be put in the digest as a
                // key, so the walk says so rather than skipping it silently.
                *self.complete = false;
                continue;
            };
            if name == GIT_DIR || name == RUNNER_DIR {
                continue;
            }
            let rel = relative.join(name);
            let Some(rel_str) = rel.to_str() else {
                *self.complete = false;
                continue;
            };
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                *self.complete = false;
                continue;
            };
            if meta.is_dir() {
                if ignore.excludes(rel_str, true) {
                    continue;
                }
                let nested = ignore.extend(&path, rel_str);
                self.descend(&path, &rel, &nested);
            } else {
                if ignore.excludes(rel_str, false) {
                    continue;
                }
                self.files
                    .insert(rel_str.to_owned(), file_digest(&path, &meta));
            }
        }
    }
}

/// Hash one file's bytes, or a symlink's target.
///
/// A file that cannot be read is hashed as the fact that it could not be read,
/// rather than skipped: a file whose permissions changed mid-run is a change,
/// and dropping it would make the tree look unchanged.
fn file_digest(path: &Path, meta: &std::fs::Metadata) -> String {
    if meta.is_symlink() {
        let target = std::fs::read_link(path).map_or_else(
            |err| format!("unreadable-link:{err}"),
            |target| target.display().to_string(),
        );
        return hex(&Sha256::digest(format!("symlink:{target}").as_bytes()));
    }
    match std::fs::read(path) {
        Ok(bytes) => hex(&Sha256::digest(&bytes)),
        Err(err) => hex(&Sha256::digest(format!("unreadable:{err}").as_bytes())),
    }
}

/// Lowercase hex, the way `demo.rs` already spells a digest in this crate.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The `.gitignore` rules in force for one directory.
///
/// Accumulated as the walk descends, the way git does it: a nested
/// `.gitignore` adds to its parent's rules and its patterns are anchored at
/// its own directory.
///
/// ## What this understands, and what it does not
///
/// Comments, blank lines, negation (`!`), directory-only patterns (trailing
/// `/`), anchoring (a leading or embedded `/`), and `*`, `?` and `**` as
/// wildcards. It does NOT read `.git/info/exclude`, the user's global
/// `core.excludesFile`, or character classes (`[a-z]`) — a pattern using one
/// is treated as a literal and its files stay IN the digest. Erring that way
/// is deliberate: an over-eager ignore hides a file the run wrote, which is
/// the failure this module is built against.
struct Ignore {
    rules: Vec<Rule>,
}

struct Rule {
    /// Pattern segments; `**` matches any run of segments.
    segments: Vec<String>,
    /// Matches only directories.
    dir_only: bool,
    /// `!` — re-includes a path an earlier rule excluded.
    negated: bool,
}

impl Ignore {
    /// Rules from the working tree root's own `.gitignore`.
    fn root(root: &Path) -> Self {
        let mut ignore = Self { rules: Vec::new() };
        ignore.load(root, "");
        ignore
    }

    /// This directory's rules plus the ones it inherits.
    fn extend(&self, dir: &Path, relative: &str) -> Self {
        let mut next = Self {
            rules: self
                .rules
                .iter()
                .map(|rule| Rule {
                    segments: rule.segments.clone(),
                    dir_only: rule.dir_only,
                    negated: rule.negated,
                })
                .collect(),
        };
        next.load(dir, relative);
        next
    }

    fn load(&mut self, dir: &Path, base: &str) {
        let Ok(text) = std::fs::read_to_string(dir.join(".gitignore")) else {
            return;
        };
        for line in text.lines() {
            if let Some(rule) = Rule::parse(line, base) {
                self.rules.push(rule);
            }
        }
    }

    /// Whether `relative` is excluded. Last matching rule wins, as in git.
    fn excludes(&self, relative: &str, is_dir: bool) -> bool {
        let path: Vec<&str> = relative.split('/').collect();
        let mut excluded = false;
        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                continue;
            }
            if rule.matches(&path) {
                excluded = !rule.negated;
            }
        }
        excluded
    }
}

impl Rule {
    fn parse(line: &str, base: &str) -> Option<Self> {
        let line = line.trim_end();
        if line.trim().is_empty() || line.starts_with('#') {
            return None;
        }
        let (negated, body) = match line.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, line),
        };
        let dir_only = body.ends_with('/');
        let body = body.trim_end_matches('/');
        if body.is_empty() {
            return None;
        }
        // Anchored when the pattern has a slash anywhere but at its end; a
        // bare name matches at any depth, which is a leading `**`.
        let anchored = body.trim_start_matches('/').contains('/') || body.starts_with('/');
        let body = body.trim_start_matches('/');
        let mut segments: Vec<String> = Vec::new();
        if !anchored {
            segments.push("**".to_owned());
        } else if !base.is_empty() {
            segments.extend(base.split('/').map(ToOwned::to_owned));
        }
        segments.extend(body.split('/').map(ToOwned::to_owned));
        Some(Self {
            segments,
            dir_only,
            negated,
        })
    }

    /// Whether the pattern matches `path`, or any directory on the way to it.
    ///
    /// The second half is what makes `/target/` exclude everything under it
    /// without a `**` in the pattern, exactly as git does.
    fn matches(&self, path: &[&str]) -> bool {
        (1..=path.len()).any(|len| glob(&self.segments, &path[..len]))
    }
}

/// Segment-wise glob, with `**` matching any run of segments.
fn glob(pattern: &[String], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((head, rest)) if head == "**" => {
            (0..=path.len()).any(|skip| glob(rest, &path[skip..]))
        }
        Some((head, rest)) => match path.split_first() {
            Some((segment, tail)) if glob_segment(head, segment) => glob(rest, tail),
            _ => false,
        },
    }
}

/// `*` and `?` inside one path segment. `*` does not cross a `/` — it cannot,
/// because it is only ever handed one segment.
fn glob_segment(pattern: &str, segment: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let segment: Vec<char> = segment.chars().collect();
    let (mut p, mut s) = (0usize, 0usize);
    let (mut star, mut resume) = (None, 0usize);
    while s < segment.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some(p);
                resume = s;
                p += 1;
            }
            Some('?') => {
                p += 1;
                s += 1;
            }
            Some(ch) if *ch == segment[s] => {
                p += 1;
                s += 1;
            }
            _ => match star {
                Some(at) => {
                    p = at + 1;
                    resume += 1;
                    s = resume;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|ch| *ch == '*')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn write(root: &Path, relative: &str, body: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn a_tree_that_did_not_change_digests_the_same_twice() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "docs/a.md", "one");
        let first = snapshot(dir.path());
        let second = snapshot(dir.path());
        assert!(first.complete);
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.file_count(), 1);
    }

    #[test]
    fn a_new_file_moves_the_digest() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "docs/a.md", "one");
        let before = snapshot(dir.path());
        write(dir.path(), "docs/how-to/b.md", "two");
        let after = snapshot(dir.path());
        assert_ne!(before.digest, after.digest);
        let effect = measure(
            EffectExpectation::Artefact,
            &before,
            &after,
            &["write".to_owned()],
            None,
        );
        assert_eq!(effect.tree_changed, Some(true));
        assert_eq!(effect.changed_paths, vec!["docs/how-to/b.md".to_owned()]);
        assert!(!effect.refuses_completion(EffectExpectation::Artefact));
    }

    #[test]
    fn rewriting_a_file_with_the_same_bytes_is_not_a_change() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.md", "one");
        let before = snapshot(dir.path());
        write(dir.path(), "a.md", "one");
        let after = snapshot(dir.path());
        assert_eq!(before.digest, after.digest);
    }

    #[test]
    fn deleting_a_file_is_a_change() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.md", "one");
        let before = snapshot(dir.path());
        std::fs::remove_file(dir.path().join("a.md")).unwrap();
        let after = snapshot(dir.path());
        let effect = measure(EffectExpectation::Artefact, &before, &after, &[], None);
        assert_eq!(effect.tree_changed, Some(true));
        assert_eq!(effect.changed_paths, vec!["a.md".to_owned()]);
    }

    #[test]
    fn the_runners_own_scratch_directory_is_not_an_effect() {
        // The failure this whole module exists for, in miniature: a run that
        // spilled tool output and rejected a reply filled `.arcana/` and
        // nothing else. It produced nothing.
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.md", "one");
        let before = snapshot(dir.path());
        write(dir.path(), ".arcana/tool-output/0001.txt", "spill");
        write(dir.path(), ".arcana/rejected/0001-turn5.txt", "reply");
        let after = snapshot(dir.path());
        assert_eq!(before.digest, after.digest);
        let effect = measure(EffectExpectation::Artefact, &before, &after, &[], None);
        assert!(effect.refuses_completion(EffectExpectation::Artefact));
    }

    #[test]
    fn git_internals_are_not_an_effect() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.md", "one");
        let before = snapshot(dir.path());
        write(dir.path(), ".git/index", "churn");
        assert_eq!(before.digest, snapshot(dir.path()).digest);
    }

    #[test]
    fn a_gitignored_build_directory_is_not_an_effect() {
        // `cargo build` is not an artefact. Without this the cheapest way for
        // a model to make a run look productive would be to compile.
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), ".gitignore", "/target/\n*.log\n__pycache__/\n");
        write(dir.path(), "a.md", "one");
        let before = snapshot(dir.path());
        write(dir.path(), "target/debug/arcana", "binary");
        write(dir.path(), "run.log", "noise");
        write(dir.path(), "tools/__pycache__/x.pyc", "bytecode");
        let after = snapshot(dir.path());
        assert_eq!(
            before.digest, after.digest,
            "ignored churn moved the digest"
        );
    }

    #[test]
    fn a_negated_ignore_pattern_is_still_measured() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), ".gitignore", ".env\n.env.*\n!.env.example\n");
        let before = snapshot(dir.path());
        write(dir.path(), ".env.local", "SECRET=1");
        assert_eq!(before.digest, snapshot(dir.path()).digest);
        write(dir.path(), ".env.example", "SECRET=");
        assert_ne!(before.digest, snapshot(dir.path()).digest);
    }

    #[test]
    fn a_nested_gitignore_is_anchored_at_its_own_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "crate/.gitignore", "/out/\n");
        let before = snapshot(dir.path());
        write(dir.path(), "crate/out/x", "ignored here");
        assert_eq!(before.digest, snapshot(dir.path()).digest);
        write(dir.path(), "out/x", "not ignored at the root");
        assert_ne!(before.digest, snapshot(dir.path()).digest);
    }

    #[test]
    fn a_run_that_only_read_refuses_completion() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.md", "one");
        let before = snapshot(dir.path());
        let after = snapshot(dir.path());
        let effect = measure(
            EffectExpectation::Artefact,
            &before,
            &after,
            &[
                "read".to_owned(),
                "grep".to_owned(),
                "grep".to_owned(),
                "read".to_owned(),
            ],
            Some("The documentation page `docs/how-to/run-work-item.md` has been created."),
        );
        assert_eq!(effect.tree_changed, Some(false));
        assert!(effect.writes.is_empty());
        assert_eq!(effect.executed_tools["read"], 2);
        assert_eq!(effect.executed_tools["grep"], 2);
        assert_eq!(
            effect.claimed_but_absent,
            vec!["docs/how-to/run-work-item.md".to_owned()]
        );
        assert!(effect.refuses_completion(EffectExpectation::Artefact));
    }

    #[test]
    fn a_declared_read_only_task_may_finish_without_changing_anything() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "a.md", "one");
        let before = snapshot(dir.path());
        let after = snapshot(dir.path());
        let effect = measure(
            EffectExpectation::ReadOnly,
            &before,
            &after,
            &["read".to_owned()],
            None,
        );
        assert_eq!(effect.tree_changed, Some(false));
        assert!(!effect.refuses_completion(EffectExpectation::ReadOnly));
        assert_eq!(effect.expectation, "read-only");
    }

    #[test]
    fn a_claim_about_a_file_that_did_not_move_is_reported_as_unchanged() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "docs/how-to/x.md", "as it was");
        let before = snapshot(dir.path());
        write(dir.path(), "other.md", "something else");
        let after = snapshot(dir.path());
        let effect = measure(
            EffectExpectation::Artefact,
            &before,
            &after,
            &["write".to_owned()],
            Some("I updated docs/how-to/x.md with the new section."),
        );
        assert!(effect.claimed_but_absent.is_empty());
        assert_eq!(
            effect.claimed_but_unchanged,
            vec!["docs/how-to/x.md".to_owned()]
        );
    }

    #[test]
    fn an_incomplete_walk_is_the_third_verdict_and_refuses_nothing() {
        let before = TreeSnapshot {
            digest: "sha256:aa".to_owned(),
            files: BTreeMap::new(),
            complete: false,
        };
        let after = before.clone();
        let effect = measure(EffectExpectation::Artefact, &before, &after, &[], None);
        assert_eq!(effect.tree_changed, None);
        assert_eq!(effect.tree_digest_before, None);
        assert!(!effect.refuses_completion(EffectExpectation::Artefact));
    }

    #[test]
    fn prose_that_is_not_a_path_is_not_a_claim() {
        let claims = claimed_paths(
            "I checked read/write access and/or the cascade; see https://example.com/x.html \
             and ../outside/y.md and docs/plan.md.",
        );
        assert_eq!(claims, vec!["docs/plan.md".to_owned()]);
    }

    #[test]
    fn a_path_in_backticks_or_quotes_is_a_claim() {
        assert_eq!(
            claimed_paths("created `docs/a.md`, \"docs/b.md\" and (docs/c.md)"),
            vec![
                "docs/a.md".to_owned(),
                "docs/b.md".to_owned(),
                "docs/c.md".to_owned()
            ]
        );
    }

    #[test]
    fn glob_segments_match_the_way_git_does() {
        assert!(glob_segment("*.log", "run.log"));
        assert!(!glob_segment("*.log", "run.log.txt"));
        assert!(glob_segment("a?c", "abc"));
        assert!(glob_segment("*", "anything"));
        assert!(glob_segment("x*y*z", "xAyBz"));
        assert!(!glob_segment("x*y*z", "xAyB"));
    }
}
