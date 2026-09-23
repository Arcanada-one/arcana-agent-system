//! Workspace-scoped permission policy for an unattended run.
//!
//! `arcana run` hands a model real tools — `write`, `edit`, `bash` — with no
//! human at the prompt to approve each call. The cascade's interactive tail is
//! therefore useless there: off a terminal it denies everything, and
//! `ARCANA_PERMISSION_AUTO=allow` waives every check at once, which is not a
//! policy but the absence of one. This module is the policy that stands in
//! between: **auto-allow inside the working directory, refuse outside it, and
//! refuse a closed list of destructive commands.**
//!
//! ## Gate-set in force
//!
//! The policy ships as THREE layers so a rule file cannot widen it:
//!
//! 1. [`DestructiveCommandFloor`] — evaluated FIRST, answers `Deny` or
//!    `Defer` only, and owns the closed refused-command list.
//! 2. [`WorkspaceBoundary`] — evaluated BEFORE [`RuleLayer`], answers `Deny`
//!    or `Defer` only, and owns workspace confinement. A boundary refusal
//!    cannot be overridden downstream, because the cascade short-circuits on
//!    the first concrete answer.
//! 3. [`RuleLayer`] — the operator's own `permissions.toml`, unchanged.
//! 4. [`WorkspaceAutoAllow`] — evaluated AFTER the rules, answers `Allow` or
//!    `Defer`. A tool this policy does not recognise defers to the cascade
//!    tail, which is fail-closed.
//!
//! A single combined layer was the obvious shape and is wrong: `RuleLayer`
//! can answer `Allow` (an `allow_commands` entry), and the cascade stops at
//! the first concrete answer, so a permissive rule file placed before a
//! combined layer would silently buy passage out of the workspace.
//!
//! Splitting the deny-only half in two is not a second policy: both halves
//! read the same [`WorkspacePolicy::assess`], and a call refused by either is
//! refused. They are separate layers because the agent loop decides whether
//! to hand a refusal back to the model by the layer's NAME, and these two
//! refusals must be answered differently — see
//! `arcana_core::agent_loop::RECOVERABLE_DENIAL_LAYERS`.
//!
//! ## What this is NOT
//!
//! Path tools are checked exactly: the path is canonicalized (symlinks,
//! `..`, the lot) and matched against the canonical workspace root, so
//! `write` cannot leave the directory.
//!
//! `bash` is checked by reading the command STRING. That is a heuristic, not
//! a sandbox: there is no namespace, no seccomp filter and no chroot under
//! it, so an obfuscated payload (`python3 -c` with an assembled path, a
//! base64 blob, a path passed through a variable) can still reach outside the
//! workspace. It is stated here rather than implied because the difference
//! decides what a caller may run in: a disposable git worktree, not a host
//! whose integrity depends on this check.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arcana_core::permission::{LayerDecision, PermissionLayer};
use arcana_core::tool::ToolError;
use arcana_tools::path_guard;
use async_trait::async_trait;
use serde_json::Value;

/// Tools whose `path` argument this policy confines to the workspace.
const PATH_TOOLS: [&str; 4] = ["read", "write", "edit", "grep"];

/// Command words refused outright, with the reason shown to the operator.
///
/// Matched against the first word of every pipeline / list segment, so
/// `foo && sudo bar` is refused on `sudo` and a file merely NAMED `sudo.txt`
/// is not. The list is deliberately closed: a word that is not on it and
/// touches nothing outside the workspace is allowed to run.
const REFUSED_COMMANDS: [(&str, &str); 42] = [
    ("sudo", "privilege escalation"),
    ("doas", "privilege escalation"),
    ("su", "privilege escalation"),
    ("visudo", "privilege escalation"),
    ("passwd", "credential surface"),
    ("useradd", "account management"),
    ("usermod", "account management"),
    ("userdel", "account management"),
    ("shutdown", "host lifecycle"),
    ("reboot", "host lifecycle"),
    ("halt", "host lifecycle"),
    ("poweroff", "host lifecycle"),
    ("init", "host lifecycle"),
    ("systemctl", "host service control"),
    ("service", "host service control"),
    ("journalctl", "host log access"),
    ("dd", "raw device write"),
    ("mkfs", "filesystem creation"),
    ("mkswap", "filesystem creation"),
    ("fdisk", "partition table"),
    ("parted", "partition table"),
    ("losetup", "block device"),
    ("mount", "mount table"),
    ("umount", "mount table"),
    ("chown", "ownership change"),
    ("chmod", "permission change"),
    ("chgrp", "ownership change"),
    ("apt", "package management"),
    ("apt-get", "package management"),
    ("dpkg", "package management"),
    ("yum", "package management"),
    ("dnf", "package management"),
    ("pacman", "package management"),
    ("snap", "package management"),
    ("kill", "signals processes outside this run"),
    ("pkill", "signals processes outside this run"),
    ("killall", "signals processes outside this run"),
    ("crontab", "schedules work outside this run"),
    ("ssh", "network egress is not covered by this policy"),
    ("scp", "network egress is not covered by this policy"),
    ("sftp", "network egress is not covered by this policy"),
    ("rsync", "network egress is not covered by this policy"),
];

/// Refused command phrases that need more than the leading word.
///
/// Each entry is a sequence of words that must appear consecutively in one
/// segment. `git push --force` is refused; `git push` is not, because branch
/// and pull request are how work leaves this repository.
const REFUSED_PHRASES: [(&[&str], &str); 8] = [
    (&["git", "push", "--force"], "rewrites a shared branch"),
    (&["git", "push", "-f"], "rewrites a shared branch"),
    (&["git", "reset", "--hard"], "discards work irrecoverably"),
    (&["git", "clean"], "discards untracked work irrecoverably"),
    (&["git", "filter-branch"], "rewrites history"),
    (
        &["git", "stash"],
        "the stash stack is shared with other worktrees",
    ),
    (
        &["git", "worktree", "remove"],
        "removes another session's worktree",
    ),
    (&["history", "-c"], "erases the audit trail of this session"),
];

/// Upper bound on the command length this policy will reason about.
///
/// A refusal must be a decision, not a timeout: past this size the policy
/// stops claiming it understood the command and refuses.
const MAX_COMMAND_BYTES: usize = 16 * 1024;

/// What the policy concluded about one tool call.
///
/// The two refusal variants exist because the agent loop treats them
/// differently, and the difference is not severity but **what the reason
/// discloses**. `OutsideWorkspace` names a directory the model was already
/// given as its cwd, and the recovery — work inside it — is the behaviour we
/// want, so that reason is handed back to the model. `Destructive` names a
/// word on a closed refusal list, and handing that back to a model that wants
/// the effect invites a hunt for a synonym the list does not carry. See
/// `arcana_core::agent_loop::RECOVERABLE_DENIAL_LAYERS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assessment {
    /// Every effect this call can have lands inside the workspace.
    InsideWorkspace,
    /// Refused because an effect lands outside the workspace, with an
    /// operator-facing reason naming the path and the root.
    OutsideWorkspace(String),
    /// Refused by the closed destructive-command floor, with an
    /// operator-facing reason naming the refused command and why.
    Destructive(String),
    /// A tool this policy makes no statement about. The cascade tail decides,
    /// and the tail is fail-closed.
    Unrecognised,
}

impl Assessment {
    /// The operator-facing reason, for either refusal kind.
    #[must_use]
    pub fn refusal_reason(&self) -> Option<&str> {
        match self {
            Self::OutsideWorkspace(reason) | Self::Destructive(reason) => Some(reason),
            Self::InsideWorkspace | Self::Unrecognised => None,
        }
    }

    /// True for either refusal kind.
    #[must_use]
    pub const fn is_refused(&self) -> bool {
        matches!(self, Self::OutsideWorkspace(_) | Self::Destructive(_))
    }
}

/// Workspace confinement policy, rooted at one canonical directory.
#[derive(Debug)]
pub struct WorkspacePolicy {
    root: PathBuf,
}

impl WorkspacePolicy {
    /// Root the policy at `root`, canonicalizing it first.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when `root` cannot be canonicalized —
    /// a policy rooted at a path the kernel will not resolve would compare
    /// canonical tool paths against a non-canonical prefix and refuse
    /// everything for the wrong reason.
    pub fn new(root: &Path) -> std::io::Result<Self> {
        Ok(Self {
            root: root.canonicalize()?,
        })
    }

    /// The canonical directory this policy confines calls to.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Classify one tool call.
    #[must_use]
    pub fn assess(&self, tool: &str, input: &Value) -> Assessment {
        if PATH_TOOLS.contains(&tool) {
            // `grep` defaults its path to `.`; the others require one, and a
            // missing path is a schema problem the schema layer owns, not a
            // reason for this layer to invent a verdict.
            let Some(path) = input.get("path").and_then(Value::as_str) else {
                return if tool == "grep" {
                    Assessment::InsideWorkspace
                } else {
                    Assessment::Unrecognised
                };
            };
            return self.assess_path(tool, path);
        }
        if tool == "bash" {
            let Some(command) = input.get("command").and_then(Value::as_str) else {
                return Assessment::Unrecognised;
            };
            return self.assess_command(command);
        }
        Assessment::Unrecognised
    }

    /// Confine a single path argument to the workspace.
    fn assess_path(&self, tool: &str, path: &str) -> Assessment {
        match path_guard::resolve(path, &self.root) {
            Ok(resolved) if resolved.starts_with(&self.root) => Assessment::InsideWorkspace,
            Ok(resolved) => Assessment::OutsideWorkspace(format!(
                "`{tool}` path `{}` resolves to `{}`, outside the workspace `{}`",
                path,
                resolved.display(),
                self.root.display()
            )),
            Err(ToolError::PermissionDenied(reason)) => {
                Assessment::OutsideWorkspace(format!("`{tool}` path `{path}` refused: {reason}"))
            }
            Err(err) => {
                Assessment::OutsideWorkspace(format!("`{tool}` path `{path}` refused: {err}"))
            }
        }
    }

    /// Confine one shell command. See the module header for what this check
    /// is and is not.
    fn assess_command(&self, command: &str) -> Assessment {
        if command.len() > MAX_COMMAND_BYTES {
            return Assessment::Destructive(format!(
                "command is {} bytes, over the {MAX_COMMAND_BYTES}-byte limit this policy will reason about",
                command.len()
            ));
        }
        if command.contains(":(){") {
            return Assessment::Destructive("refused: fork bomb".to_owned());
        }
        let segments = segments(command);
        // The floor is swept across EVERY segment before any path check, so a
        // command that trips both is classified by the floor. Judging the two
        // in one pass per segment would let `cat /etc/shadow && sudo x` be
        // reported as a path problem, and a path problem is the kind this
        // policy hands back to the model.
        for segment in &segments {
            if let Some(reason) = refused_segment(segment) {
                return Assessment::Destructive(reason);
            }
        }
        for segment in &segments {
            for word in segment {
                if let Some(reason) = self.refused_word(word) {
                    return Assessment::OutsideWorkspace(reason);
                }
            }
        }
        Assessment::InsideWorkspace
    }

    /// Refuse a single word that names a path outside the workspace.
    ///
    /// An environment assignment is checked on its VALUE (`OUT=/etc/shadow`
    /// is the path `/etc/shadow`), which is the only reason `=` survives
    /// word splitting.
    fn refused_word(&self, word: &str) -> Option<String> {
        let word = word.split_once('=').map_or(word, |(_, value)| value);
        let bare = word.trim_matches(|c| matches!(c, '"' | '\''));
        if bare.starts_with('~') {
            return Some(format!(
                "refused: `{bare}` names a home directory outside the workspace `{}`",
                self.root.display()
            ));
        }
        if bare == ".." || bare.contains("../") {
            return Some(format!(
                "refused: `{bare}` walks out of the workspace `{}` with `..`",
                self.root.display()
            ));
        }
        if !bare.starts_with('/') {
            return None;
        }
        match path_guard::resolve(bare, &self.root) {
            Ok(resolved) if resolved.starts_with(&self.root) => None,
            Ok(resolved) => Some(format!(
                "refused: `{bare}` resolves to `{}`, outside the workspace `{}`",
                resolved.display(),
                self.root.display()
            )),
            Err(err) => Some(format!("refused: `{bare}` could not be resolved: {err}")),
        }
    }
}

/// Split a command into segments at shell list / pipe / subshell separators,
/// and each segment into words.
///
/// Redirections break words without starting a segment, so the target of
/// `echo x > /etc/passwd` survives as its own word for the path check, while
/// `a && sudo b` becomes two segments and is judged on `sudo` as a command
/// word rather than as an argument. `=` is deliberately NOT a separator:
/// keeping `FOO=/etc/shadow` whole is what lets the head-of-segment rule
/// recognise it as an environment assignment rather than as the command.
fn segments(command: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut segment: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut new_segment = false;
    for ch in command.chars() {
        match ch {
            ';' | '|' | '&' | '\n' | '`' | '(' | ')' | '{' | '}' => new_segment = true,
            ' ' | '\t' | '<' | '>' | ',' => {}
            _ => {
                word.push(ch);
                continue;
            }
        }
        if !word.is_empty() {
            segment.push(std::mem::take(&mut word));
        }
        if new_segment {
            new_segment = false;
            if !segment.is_empty() {
                out.push(std::mem::take(&mut segment));
            }
        }
    }
    if !word.is_empty() {
        segment.push(word);
    }
    if !segment.is_empty() {
        out.push(segment);
    }
    out
}

/// The command word of a segment: the first word that is neither a flag nor
/// an environment assignment, with any directory prefix stripped.
///
/// The assignment rule is what stops `SUDO_ASKPASS=x sudo rm` from being read
/// as a command called `SUDO_ASKPASS=x`, and the flag rule keeps `-i` in
/// `env -i sudo` from taking the command word's place.
fn command_word(segment: &[String]) -> Option<&str> {
    let word = segment
        .iter()
        .find(|word| !word.starts_with('-') && !word.contains('='))?;
    let bare = word.trim_matches(|c| matches!(c, '"' | '\''));
    Some(bare.rsplit('/').next().unwrap_or(bare))
}

/// Refuse a segment on its command word or on a refused phrase.
fn refused_segment(segment: &[String]) -> Option<String> {
    let head = command_word(segment)?;
    if let Some((_, reason)) = REFUSED_COMMANDS
        .iter()
        .find(|(name, _)| *name == head || head.starts_with(&format!("{name}.")))
    {
        return Some(format!("refused: `{head}` — {reason}"));
    }
    if is_recursive_force_rm(segment) {
        return Some(
            "refused: `rm` with recursive and force flags — deletes trees irrecoverably".to_owned(),
        );
    }
    for (phrase, reason) in REFUSED_PHRASES {
        if contains_phrase(segment, phrase) {
            return Some(format!("refused: `{}` — {reason}", phrase.join(" ")));
        }
    }
    None
}

/// `rm` carrying both a recursive and a force flag, in any spelling.
fn is_recursive_force_rm(segment: &[String]) -> bool {
    if command_word(segment) != Some("rm") {
        return false;
    }
    let flags: String = segment
        .iter()
        .filter(|word| word.starts_with('-'))
        .flat_map(|word| word.chars())
        .collect();
    let long: Vec<&str> = segment.iter().map(String::as_str).collect();
    let recursive = flags.contains('r') || flags.contains('R') || long.contains(&"--recursive");
    let force = flags.contains('f') || long.contains(&"--force");
    recursive && force
}

/// Whether `segment` contains `phrase` as consecutive words.
fn contains_phrase(segment: &[String], phrase: &[&str]) -> bool {
    if phrase.len() > segment.len() {
        return false;
    }
    segment
        .windows(phrase.len())
        .any(|window| window.iter().zip(phrase).all(|(word, want)| word == want))
}

/// Deny-only floor for the closed destructive-command list, placed BEFORE
/// [`WorkspaceBoundary`] and before the operator's rule layer.
///
/// It is a separate layer from the boundary for one reason: the agent loop
/// keys its fold-back decision off the layer NAME, and these two refusals must
/// be answered differently. A boundary refusal goes back to the model so it
/// can work inside the workspace; a floor refusal ends the run, because the
/// only thing a model can do with "`sudo` is refused" that it could not do
/// before is look for a word the list does not carry.
///
/// Both halves are deny-or-defer, so putting the floor first cannot widen
/// anything — it only decides which refusal a call that trips both is
/// reported under, and the safe answer is the floor.
pub struct DestructiveCommandFloor {
    policy: Arc<WorkspacePolicy>,
}

impl DestructiveCommandFloor {
    #[must_use]
    pub const fn new(policy: Arc<WorkspacePolicy>) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl PermissionLayer for DestructiveCommandFloor {
    fn name(&self) -> &'static str {
        "destructive_command_floor"
    }

    async fn evaluate(&self, tool: &str, input: &Value) -> LayerDecision {
        match self.policy.assess(tool, input) {
            Assessment::Destructive(reason) => LayerDecision::Deny(reason),
            Assessment::OutsideWorkspace(_)
            | Assessment::InsideWorkspace
            | Assessment::Unrecognised => LayerDecision::Defer,
        }
    }
}

/// Deny-only half of the policy, placed BEFORE the operator's rule layer.
///
/// Answers only the workspace-confinement half; the destructive-command floor
/// is [`DestructiveCommandFloor`], which runs ahead of it.
pub struct WorkspaceBoundary {
    policy: Arc<WorkspacePolicy>,
}

impl WorkspaceBoundary {
    #[must_use]
    pub const fn new(policy: Arc<WorkspacePolicy>) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl PermissionLayer for WorkspaceBoundary {
    fn name(&self) -> &'static str {
        "workspace_boundary"
    }

    async fn evaluate(&self, tool: &str, input: &Value) -> LayerDecision {
        match self.policy.assess(tool, input) {
            Assessment::OutsideWorkspace(reason) => LayerDecision::Deny(reason),
            // Already denied by the floor layer ahead of this one. Repeating
            // the verdict here would be harmless but would also hide a wiring
            // mistake, so this half states only what it is for.
            Assessment::Destructive(_) | Assessment::InsideWorkspace | Assessment::Unrecognised => {
                LayerDecision::Defer
            }
        }
    }
}

/// Allow-only half of the policy, placed AFTER the operator's rule layer.
pub struct WorkspaceAutoAllow {
    policy: Arc<WorkspacePolicy>,
}

impl WorkspaceAutoAllow {
    #[must_use]
    pub const fn new(policy: Arc<WorkspacePolicy>) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl PermissionLayer for WorkspaceAutoAllow {
    fn name(&self) -> &'static str {
        "workspace_auto_allow"
    }

    async fn evaluate(&self, tool: &str, input: &Value) -> LayerDecision {
        match self.policy.assess(tool, input) {
            Assessment::InsideWorkspace => LayerDecision::Allow,
            // Already denied by the boundary/floor layers; repeating the
            // verdict here would be harmless but would also hide a wiring
            // mistake, so this half states only what it is for.
            Assessment::OutsideWorkspace(_)
            | Assessment::Destructive(_)
            | Assessment::Unrecognised => LayerDecision::Defer,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn policy(root: &TempDir) -> WorkspacePolicy {
        WorkspacePolicy::new(root.path()).expect("policy")
    }

    fn refusal(assessment: &Assessment) -> &str {
        match assessment.refusal_reason() {
            Some(reason) => reason,
            None => panic!("expected a refusal, got {assessment:?}"),
        }
    }

    #[test]
    fn a_path_inside_the_workspace_is_allowed() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for path in ["notes.txt", "./a/b.txt", "deep/dir/file"] {
            assert_eq!(
                policy.assess("write", &json!({ "path": path, "content": "" })),
                Assessment::InsideWorkspace,
                "{path}"
            );
        }
    }

    #[test]
    fn a_path_outside_the_workspace_is_refused_however_it_is_spelled() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for path in ["/etc/passwd", "../escaped.txt", "a/../../escaped.txt"] {
            let assessment = policy.assess("write", &json!({ "path": path, "content": "" }));
            assert!(
                refusal(&assessment).contains("outside the workspace"),
                "{path}: {assessment:?}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_out_of_the_workspace_is_refused_by_its_target() {
        // The check is on the canonical path, which is the only reason this
        // case is caught: the string `link/passwd` is entirely innocent.
        let root = TempDir::new().unwrap();
        std::os::unix::fs::symlink("/etc", root.path().join("link")).unwrap();
        let policy = policy(&root);
        let assessment = policy.assess("read", &json!({ "path": "link/passwd" }));
        assert!(refusal(&assessment).contains("outside the workspace"));
    }

    #[test]
    fn an_ordinary_command_inside_the_workspace_is_allowed() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for command in [
            "echo HELLO > proof.txt",
            "cargo test --workspace",
            "git status --short && git add -A",
            "grep -rn TODO src",
            "rm stale.txt",
        ] {
            assert_eq!(
                policy.assess("bash", &json!({ "command": command })),
                Assessment::InsideWorkspace,
                "{command}"
            );
        }
    }

    #[test]
    fn a_command_naming_a_path_outside_the_workspace_is_refused() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for command in [
            "echo ESCAPED > /tmp/outside-proof",
            "cat /etc/passwd",
            "cp secret.txt ~/stash",
            "cd ../.. && ls",
            "OUT=/etc/shadow cat $OUT",
        ] {
            let assessment = policy.assess("bash", &json!({ "command": command }));
            // The KIND is asserted, not merely the refusal: this is the half
            // the agent loop hands back to the model, and a misclassified
            // destructive command would leak the refused-word list into a
            // model's context under the guise of a path problem.
            assert!(
                matches!(assessment, Assessment::OutsideWorkspace(_)),
                "{command}: {assessment:?}"
            );
        }
    }

    #[test]
    fn a_path_inside_the_workspace_is_allowed_even_when_written_absolutely() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        let inside = root.path().join("proof.txt");
        let command = format!("echo HELLO > {}", inside.display());
        assert_eq!(
            policy.assess("bash", &json!({ "command": command })),
            Assessment::InsideWorkspace
        );
    }

    #[test]
    fn destructive_commands_are_refused_wherever_they_sit_in_the_line() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for command in [
            "sudo systemctl restart nginx",
            "true && sudo rm x",
            "echo hi; reboot",
            "rm -rf build",
            "rm -fr .",
            "rm --recursive --force target",
            "git push --force origin main",
            "git reset --hard HEAD~3",
            "git stash push -u",
            "dd if=/dev/zero of=disk.img",
            "apt-get install -y curl",
            "pkill -f cargo",
            "$(sudo id)",
            ":(){ :|:& };:",
        ] {
            let assessment = policy.assess("bash", &json!({ "command": command }));
            // Must be `Destructive`, never `OutsideWorkspace`: the agent loop
            // ends the run on the former and hands the latter back to the
            // model, so this assertion is what keeps the refused-command list
            // out of a model's context.
            assert!(
                matches!(assessment, Assessment::Destructive(_)),
                "{command}: {assessment:?}"
            );
        }
    }

    #[test]
    fn a_refused_word_is_not_refused_as_an_argument() {
        // Over-refusal has a cost too: a policy that refuses `git commit -m
        // "drop sudo"` is one an operator routes around.
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for command in [
            "git commit -m \"remove the sudo call\"",
            "echo mount",
            "cargo build --features service",
        ] {
            assert_eq!(
                policy.assess("bash", &json!({ "command": command })),
                Assessment::InsideWorkspace,
                "{command}"
            );
        }
    }

    #[test]
    fn a_tool_the_policy_does_not_know_is_left_to_the_fail_closed_tail() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        assert_eq!(
            policy.assess("webfetch", &json!({ "url": "https://example.com" })),
            Assessment::Unrecognised
        );
    }

    #[test]
    fn an_oversized_command_is_refused_rather_than_analysed() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        let command = "echo ".repeat(MAX_COMMAND_BYTES);
        let assessment = policy.assess("bash", &json!({ "command": command }));
        assert!(refusal(&assessment).contains("limit this policy will reason about"));
    }

    #[tokio::test]
    async fn the_boundary_half_denies_and_never_allows() {
        let root = TempDir::new().unwrap();
        let policy = Arc::new(policy(&root));
        let layer = WorkspaceBoundary::new(Arc::clone(&policy));
        assert!(matches!(
            layer
                .evaluate("write", &json!({ "path": "/etc/passwd" }))
                .await,
            LayerDecision::Deny(_)
        ));
        // Inside the workspace it DEFERS: allowing here would put the allow
        // ahead of the operator's own rule file.
        assert!(matches!(
            layer.evaluate("write", &json!({ "path": "ok.txt" })).await,
            LayerDecision::Defer
        ));
    }

    #[tokio::test]
    async fn the_auto_allow_half_allows_and_never_denies() {
        let root = TempDir::new().unwrap();
        let policy = Arc::new(policy(&root));
        let layer = WorkspaceAutoAllow::new(Arc::clone(&policy));
        assert!(matches!(
            layer.evaluate("write", &json!({ "path": "ok.txt" })).await,
            LayerDecision::Allow
        ));
        assert!(matches!(
            layer
                .evaluate("write", &json!({ "path": "/etc/passwd" }))
                .await,
            LayerDecision::Defer
        ));
    }
}
