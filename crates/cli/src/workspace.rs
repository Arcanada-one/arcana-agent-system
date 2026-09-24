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
    (GIT_STASH, GIT_STASH_REASON),
    (
        &["git", "worktree", "remove"],
        "removes another session's worktree",
    ),
    (&["history", "-c"], "erases the audit trail of this session"),
];

/// The `git stash` phrase, named so the special case below and the entry in
/// [`REFUSED_PHRASES`] cannot drift apart.
const GIT_STASH: &[&str] = &["git", "stash"];

/// Why the mutating `git stash` forms are refused.
const GIT_STASH_REASON: &str = "the stash stack is shared with other worktrees";

/// `git stash` subcommands that only READ the stash stack, and are therefore
/// NOT refused.
///
/// ## Why the exception exists (A2-259)
///
/// Pilot A2-240d had finished its task — commit `6302742`, published as
/// `arcanada-support#114` — and died on turn 62
/// (`/home/dev/aup/arc2/wt/A2-240d/.arcana/denied/0006-turn62.json`) on
///
/// ```text
/// git format-patch … && git apply --stat … && git stash list && git log --oneline -1
/// ```
///
/// A floor refusal is terminal by design, so a **listing** ended a completed
/// run. That is not the floor doing its job badly; it is the floor's list
/// naming a git command rather than a git EFFECT. `git stash` guards one
/// thing, the stack shared with every other worktree, and `list` and `show`
/// cannot touch it.
///
/// ## Why these two and nothing else
///
/// Each was measured against `git` 2.43.0 rather than read off the manual
/// (`/home/dev/aup/arc2/runs/A2-259/report.md`):
///
/// * `git stash list` prints the stack and leaves it byte-identical; a
///   trailing word is not a subcommand but a revision, so `git stash list
///   drop` exits 1 with `fatal: bad revision 'drop'` and drops nothing.
/// * `git stash show` diffs one entry and leaves the stack byte-identical.
/// * There is no option that turns either into a mutation: `git stash list
///   --exec='touch pwned'` is rejected outright with `fatal: unrecognized
///   argument`, and `list` forwards only `git log` options.
///
/// Everything else — bare `git stash` (which IS `push`), `push`, `pop`,
/// `apply`, `drop`, `clear`, `branch`, `store`, `create` — changes the stack.
/// The rule is therefore an allow-list, not a deny-list: a `git stash` whose
/// next word this array does not carry is refused, including a spelling git
/// itself does not know.
const GIT_STASH_READ_ONLY: [&str; 2] = ["list", "show"];

/// `git stash` subcommands the prompt names as refused.
///
/// Illustrative rather than exhaustive — the rule is "anything that is not
/// [`GIT_STASH_READ_ONLY`]" — but every entry here is checked against
/// [`WorkspacePolicy::assess`] by
/// `crates/cli/tests/run_destructive_floor_prompt.rs`, so the prompt cannot
/// name a form the floor does not actually refuse.
const GIT_STASH_MUTATING: [&str; 8] = [
    "push", "pop", "apply", "drop", "clear", "branch", "store", "create",
];

/// `git`'s global options that swallow the FOLLOWING word.
///
/// Needed to find where the subcommand starts, which is how
/// `git --no-pager stash drop` and `git -C sub stash drop` are refused: both
/// were ALLOWED before A2-259, because the floor matched `git` and `stash` as
/// adjacent words and a global option sits between them
/// (`/home/dev/aup/arc2/runs/A2-259/receipt-before-floor.txt`). The `=`
/// spellings (`--git-dir=x`) need no entry: they are one word.
const GIT_GLOBAL_OPTIONS_WITH_VALUE: [&str; 6] = [
    "-c",
    "-C",
    "--exec-path",
    "--git-dir",
    "--work-tree",
    "--namespace",
];

/// The only path outside the workspace a `bash` command may name.
///
/// ## Why an exception exists at all (A2-253)
///
/// Turn 6 of pilot A2-240c was refused on `2>/dev/null`
/// (`/home/dev/aup/arc2/wt/A2-240c/.arcana/denied/0003-turn6.json`) — one of
/// that run's five boundary refusals, and the only one where the model had
/// not tried to leave the workspace at all. `cmd 2>/dev/null` is how a shell
/// says "discard this", and refusing it teaches nothing: the correction the
/// model can act on is to write the same command without the idiom, which is
/// not a boundary anybody wanted to defend.
///
/// ## Why it is safe, stated as a property rather than a habit
///
/// `/dev/null` is a character device with no storage: a write is discarded, a
/// read returns EOF immediately. It can therefore neither carry workspace
/// contents out (nothing written to it can be read back, by this run or by
/// anyone) nor bring anything in (it has nothing to give). That is the whole
/// of the argument, and it is what makes this exception one path and not a
/// directory: `/dev/zero` and `/dev/urandom` are sources, `/dev/stdout` and
/// `/dev/fd/*` are aliases for descriptors this policy does not own, and
/// `/dev/sda` is a disk. None of them are allowed, and `/dev/` is never
/// matched as a prefix.
///
/// The comparison is on the **canonicalized** path, so a symlink named
/// `null` inside the workspace is judged by where it points, and a spelling
/// like `/dev/null/../../etc/passwd` resolves elsewhere and is refused
/// normally.
pub const NULL_SINK: &str = "/dev/null";

/// What to do instead, appended to every `..` refusal.
///
/// ## Why the refusal needed a remedy (A2-259)
///
/// The check resolves `..` against the workspace ROOT, not against a `cd`
/// earlier in the same command, so `cd sub && tar -x -C ../snap` is refused
/// even though `../snap` would land inside the workspace. Tracking the `cd`
/// is not on the table: a shell string has no single reading of it —
/// subshells, `cd -`, `cd "$VAR"`, and `;` vs `&&` vs `||` all decide where
/// the next word resolves, and a boundary that guesses is not a boundary.
///
/// The refusal stays. What was missing is the correction, and its absence was
/// measured: pilot A2-240d spent three of its six denied calls on this one
/// shape — turns 15, 16 and 54
/// (`/home/dev/aup/arc2/wt/A2-240d/.arcana/denied/`), the second immediately
/// after the first and the third thirty-eight turns later. The reason it was
/// handed named the problem (`..`) and no way to be right, so the model could
/// only try the same shape again. A boundary refusal IS handed back to the
/// model (`arcana_core::agent_loop::RECOVERABLE_DENIAL_LAYERS`), which is
/// exactly why it must carry one.
pub const RELATIVE_PATH_REMEDY: &str =
    "`..` is resolved against the workspace root, not against a \
`cd` earlier in the same command; name the path from the workspace root (`sub/dir/file`) or \
absolutely under";

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
                "refused: `{bare}` walks out of the workspace `{root}` with `..` — {RELATIVE_PATH_REMEDY} `{root}`",
                root = self.root.display()
            ));
        }
        if !bare.starts_with('/') {
            return None;
        }
        match path_guard::resolve(bare, &self.root) {
            Ok(resolved) if resolved.starts_with(&self.root) => None,
            // The one path outside the workspace that carries nothing out of
            // it and nothing into it. See [`NULL_SINK`].
            Ok(resolved) if resolved == Path::new(NULL_SINK) => None,
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

/// A word with its surrounding quotes removed.
///
/// `segments` does not interpret quoting, so `git "stash" drop` arrives with
/// the marks attached and walked past both halves of the stash rule until
/// A2-259.
fn unquoted(word: &str) -> &str {
    word.trim_matches(|c| matches!(c, '"' | '\''))
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
    if let Some(reason) = refused_git_stash(segment) {
        return Some(reason);
    }
    for (phrase, reason) in REFUSED_PHRASES {
        // The stash entry is decided by the subcommand, one line above; a
        // second, adjacency-only verdict here would refuse `git stash list`
        // again and make the allow-list dead code.
        if phrase == GIT_STASH {
            continue;
        }
        if contains_phrase(segment, phrase) {
            return Some(format!("refused: `{}` — {reason}", phrase.join(" ")));
        }
    }
    None
}

/// Refuse a segment that invokes a `git stash` form which CHANGES the stack.
///
/// The read-only forms are [`GIT_STASH_READ_ONLY`]; everything else, including
/// a bare `git stash` and a subcommand git does not know, is refused. Two
/// spellings are recognised, and the union is deliberate — dropping either
/// re-opens a hole measured on this floor:
///
/// * `git` and `stash` as adjacent words, wherever the pair sits in the
///   segment. This is what keeps `xargs git stash pop` refused.
/// * `stash` reached as git's subcommand past its global options, which is how
///   `git --no-pager stash drop` and `git -C sub stash drop` are written.
///   Both were allowed before A2-259.
///
/// Neither half subsumes the other. The subcommand half sees through a global
/// option, which adjacency cannot; adjacency sees an invocation the subcommand
/// half walks past, because that half reads the FIRST word named `git` in the
/// segment and `find . -name git -exec git stash pop \;` runs the second one.
/// Both were put to a mutant: deleting either turns
/// `a_git_stash_that_changes_the_stack_is_refused_however_it_is_spelled` red
/// (`/home/dev/aup/arc2/runs/A2-259/receipt-mutation.txt`).
///
/// Not recognised, and stated rather than implied: an alias defined on the
/// same line, `git -c alias.l='stash drop' l`, still drops (measured on git
/// 2.43.0). Reading it would mean evaluating git's config, and the module
/// header already says this check is a string heuristic and not a sandbox.
fn refused_git_stash(segment: &[String]) -> Option<String> {
    let mut invocations: Vec<Option<&str>> = Vec::new();
    for (index, window) in segment.windows(2).enumerate() {
        if unquoted(&window[0]) == "git" && unquoted(&window[1]) == "stash" {
            invocations.push(segment.get(index + 2).map(|word| unquoted(word)));
        }
    }
    if let Some(index) = git_subcommand_index(segment) {
        if unquoted(&segment[index]) == "stash" {
            invocations.push(segment.get(index + 1).map(|word| unquoted(word)));
        }
    }
    invocations
        .into_iter()
        .find_map(|subcommand| match subcommand {
            // A bare `git stash` IS `git stash push`, so the absence of a
            // subcommand is the mutating case, not the undecided one.
            None => Some(format!("refused: `git stash` — {GIT_STASH_REASON}")),
            Some(named) if GIT_STASH_READ_ONLY.contains(&named) => None,
            Some(named) => Some(format!("refused: `git stash {named}` — {GIT_STASH_REASON}")),
        })
}

/// Index of the word `git` would read as its subcommand, if the segment runs
/// `git` at all.
///
/// Implements git's own grammar for the part before the subcommand — global
/// options, some of which swallow the next word
/// ([`GIT_GLOBAL_OPTIONS_WITH_VALUE`]) — and nothing more. It is a single
/// reading precisely because it is git's, not a guess about what a word means.
fn git_subcommand_index(segment: &[String]) -> Option<usize> {
    let start = segment.iter().position(|word| {
        let bare = unquoted(word);
        bare.rsplit('/').next().unwrap_or(bare) == "git"
    })?;
    let mut index = start + 1;
    while index < segment.len() {
        let word = segment[index].as_str();
        if !word.starts_with('-') {
            return Some(index);
        }
        if GIT_GLOBAL_OPTIONS_WITH_VALUE.contains(&word) {
            index += 1;
        }
        index += 1;
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

/// The floor's refused-command list, rendered for the model's system prompt.
///
/// ## Why the list is disclosed at all
///
/// The module's own rule is that a floor refusal is NOT handed back to the
/// model (`arcana_core::agent_loop::RECOVERABLE_DENIAL_LAYERS`), because
/// naming the refused word to a model that has just asked for the effect
/// invites a hunt for a synonym the list does not carry. That rule is about
/// what happens AFTER a probe, and it stands.
///
/// Telling the model the rule BEFORE it acts is a different act, and the
/// measured cost of not doing it is the argument for it: pilot A2-231
/// (`/home/dev/aup/arc2/runs/A2-231/log`, 2026-09-23) ran 78 turns and 62
/// tool calls, then asked for `rm -rf` on its own scratch directory, and the
/// floor correctly refused and ended the run — 0.27 USD and every turn of
/// work thrown away over a flag. The model was not evading the floor; it did
/// not know the floor existed, and the prompt's one vague clause ("recursive
/// force deletion … refused by policy") gave it no way to be right. `rm -r`
/// without `-f`, which is permitted, would have done exactly what it wanted.
///
/// This disclosure is also not a security downgrade, because the floor is not
/// a security boundary: the module header says outright that the `bash` check
/// is a string heuristic with no namespace, seccomp or chroot under it, and
/// that a caller must therefore run in a disposable worktree. What the floor
/// protects against is an unwitting command, and an unwitting model that is
/// never told the rule cannot follow it.
///
/// ## Why it is generated rather than written
///
/// Every word comes from the same constants the floor evaluates, so a command
/// added to [`REFUSED_COMMANDS`] or [`REFUSED_PHRASES`] cannot be refused
/// silently: it appears in the next prompt without anybody remembering to
/// edit prose. `crates/cli/tests/run_destructive_floor_prompt.rs` pins both
/// halves — that the prompt names every entry, and that what it STATES about
/// a command equals what [`WorkspacePolicy::assess`] actually does to it.
#[must_use]
pub fn destructive_floor_disclosure() -> String {
    let mut names: Vec<&str> = REFUSED_COMMANDS.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    let phrases = REFUSED_PHRASES
        .iter()
        .map(|(phrase, _)| format!("`{}`", phrase.join(" ")))
        .collect::<Vec<_>>()
        .join(", ");
    let stash_refused = GIT_STASH_MUTATING
        .iter()
        .map(|sub| format!("`git stash {sub}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let stash_permitted = GIT_STASH_READ_ONLY
        .iter()
        .map(|sub| format!("`git stash {sub}`"))
        .collect::<Vec<_>>()
        .join(" and ");
    format!(
        "DESTRUCTIVE COMMANDS. The `bash` commands below are refused BEFORE they run, and a \
refusal here ENDS THE RUN immediately: it is not handed back to you as a correction, so there is \
no second attempt and everything done so far is lost. Check each command against this list \
before you send it.\n\
\n\
Refused by name, as the command word of any pipeline stage or `;`/`&&` list element: {names}.\n\
\n\
Refused as a phrase: {phrases}.\n\
\n\
Refused for `git stash`, every form that CHANGES the shared stack: a bare `git stash`, and \
{stash_refused}. A `git` global option in front of the subcommand changes nothing — \
`git --no-pager stash drop` is refused too.\n\
\n\
Refused by shape: `rm` carrying a recursive flag (`-r`, `-R`, `--recursive`) AND a force flag \
(`-f`, `--force`) at the same time — `rm -rf`, `rm -fr`, `rm -Rf` and `rm -r --force` are all \
refused; a fork bomb; any command longer than {max_bytes} bytes.\n\
\n\
Use these instead. `rm -r <dir>` removes a directory and everything in it and is PERMITTED — \
recursion alone is fine, it is only the combination with a force flag that is refused. `rm \
<file>` and `rm -f <file>` are permitted. {stash_permitted} only READ the stash stack and are \
PERMITTED — a listing is not a mutation, and you may use them freely. For a clean working area, \
`mkdir` a fresh sub-directory and work in that. Ordinary tools — `mkdir`, `mv`, `cp`, `touch`, \
`find`, `sed`, `cargo`, `python3`, `git add`, `git commit`, `git push` — are not on any list \
above and run normally.",
        names = names.join(", "),
        phrases = phrases,
        max_bytes = MAX_COMMAND_BYTES,
    )
}

/// The refused command words, for a test that asserts the prompt names them
/// all. Exposed rather than duplicated: a copy in the test would drift.
#[must_use]
pub fn refused_command_words() -> Vec<&'static str> {
    REFUSED_COMMANDS.iter().map(|(name, _)| *name).collect()
}

/// The refused phrases, joined as they are written on a command line.
#[must_use]
pub fn refused_command_phrases() -> Vec<String> {
    REFUSED_PHRASES
        .iter()
        .map(|(phrase, _)| phrase.join(" "))
        .collect()
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
///
/// ## Should a floor refusal be recoverable when the command mutates nothing?
///
/// Asked by A2-259, because pilot A2-240d lost a FINISHED run to `git stash
/// list`. The answer is no, and the answer does not depend on how bad that
/// was.
///
/// Recoverability would have to be decided by a predicate over the command —
/// "this one contains no mutating operation, so hand it back". That predicate
/// is the floor's own classifier, and the floor has already stated what it is:
/// a check on the command STRING, with no namespace, no seccomp and no chroot
/// under it (see the module header). It cannot read a variable, a `$( )`, an
/// alias, or a script it is about to run — this module's own tests pin `git -c
/// alias.l='stash drop' l` walking straight past it. Making terminality
/// conditional on that classifier means the run continues exactly when the
/// classifier is fooled, which is the one case where continuing is wrong.
///
/// The second half of the argument is about what the model is told. Terminality
/// is what keeps a refusal from becoming an oracle: "`sudo` is refused" handed
/// back to a model that wants root is a hint to look for a word the list does
/// not carry, and a conditional rule would hand back exactly the refusals the
/// classifier judged harmless — the probes. A model probing the list is
/// indistinguishable, at this layer, from a model that meant well.
///
/// So the loss A2-240d took is real and is fixed at the other end: a command
/// that mutates nothing must not REACH the floor. That is a defect in the
/// list, and the list is where [`GIT_STASH_READ_ONLY`] fixes it — narrowing a
/// rule that named a git command rather than a git effect. The prompt
/// ([`destructive_floor_disclosure`]) is the other half: the model is told the
/// rule before it acts, which prevents the loss without ever answering a
/// probe.
///
/// Changing terminality would need a DEC-level decision with an evidence gate,
/// and nothing measured here argues for one.
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
    fn the_null_sink_is_permitted_wherever_a_command_names_it() {
        // Turn 6 of pilot A2-240c died on `2>/dev/null`
        // (`.arcana/denied/0003-turn6.json`). A sink carries nothing out of
        // the workspace and has nothing to bring in, so it is the one path
        // outside the root a command may name.
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for command in [
            "ls -la sup 2>/dev/null",
            "echo noise > /dev/null",
            "cat /dev/null",
            "curl -sS -o /dev/null -w '%{http_code}' https://example.com",
            "cd runs 2>/dev/null && ls",
        ] {
            assert_eq!(
                policy.assess("bash", &json!({ "command": command })),
                Assessment::InsideWorkspace,
                "{command}"
            );
        }
    }

    #[test]
    fn the_exception_is_one_path_and_not_the_device_directory() {
        // The paired negative. `/dev/` is not a prefix rule: a source, an
        // alias for somebody else's descriptor and a raw disk are all still
        // outside the workspace, and so is anything that merely starts with
        // the sink's name.
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for command in [
            "cat /dev/zero > noise.bin",
            "head -c 16 /dev/urandom",
            "cat /dev/sda",
            "echo x > /dev/stdout",
            "cat /dev/nullify",
            "cat /dev/null/../../etc/passwd",
            "cat /etc/hosts",
            "ls -la /home/dev/arcanada/Projects",
        ] {
            let assessment = policy.assess("bash", &json!({ "command": command }));
            assert!(
                assessment.is_refused(),
                "{command} must stay refused: {assessment:?}"
            );
        }
    }

    #[test]
    fn the_sink_exception_does_not_reach_the_path_tools() {
        // `write`/`read`/`edit`/`grep` have no use for a sink, and every
        // allowance is a hole somebody has to justify later. The exception is
        // the shell-command half only.
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        let assessment = policy.assess("write", &json!({ "path": "/dev/null", "content": "" }));
        assert!(
            refusal(&assessment).contains("outside the workspace"),
            "{assessment:?}"
        );
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

    /// A2-259, the refusing direction: every `git stash` form that can change
    /// the shared stack, in the spellings the floor has to see through.
    #[test]
    fn a_git_stash_that_changes_the_stack_is_refused_however_it_is_spelled() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for command in [
            // A bare `git stash` IS `git stash push`.
            "git stash",
            "git stash -u",
            "git stash push -m wip",
            "git stash pop",
            "git stash apply",
            "git stash drop",
            "git stash clear",
            "git stash branch topic",
            "git stash store $SHA",
            "git stash create",
            // A subcommand git itself does not know is refused, because the
            // rule is an allow-list of the two read-only forms.
            "git stash unlist",
            // A read-only form does not launder a mutating one beside it.
            "git stash list; git stash drop",
            "git stash list && git stash drop",
            "git apply --stat p.patch && git stash pop",
            // Global options in front of the subcommand: ALLOWED before
            // A2-259, see `runs/A2-259/receipt-before-floor.txt`.
            "git --no-pager stash drop",
            "git -C sub stash pop",
            "git --git-dir=.git stash clear",
            // Not the command word, still a `git stash`. The second is the
            // case adjacency alone catches: the subcommand half reads the
            // FIRST word named `git`, and that one is a `-name` argument.
            "xargs git stash pop",
            "find . -name git -exec git stash pop \\;",
            // `segments` does not interpret quoting.
            "git \"stash\" drop",
            "\"git\" stash drop",
        ] {
            let assessment = policy.assess("bash", &json!({ "command": command }));
            assert!(
                matches!(assessment, Assessment::Destructive(_)),
                "{command}: {assessment:?}"
            );
        }
    }

    /// A2-259, the permitting direction. `git stash list` and `git stash show`
    /// only READ the stack (measured on git 2.43.0, see
    /// [`GIT_STASH_READ_ONLY`]), and a floor refusal is terminal — pilot
    /// A2-240d's finished run died on the last line here.
    #[test]
    fn a_git_stash_that_only_reads_the_stack_is_allowed() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        for command in [
            "git stash list",
            "git stash show",
            "git stash show stash@{0}",
            "git stash list --stat",
            "git --no-pager stash list",
            "git -C sub stash show",
            // Pilot A2-240d, turn 62, verbatim but for the patch path.
            "git apply --stat p.patch && git stash list && git log --oneline -1",
        ] {
            let assessment = policy.assess("bash", &json!({ "command": command }));
            assert_eq!(
                assessment,
                Assessment::InsideWorkspace,
                "{command}: {assessment:?}"
            );
        }
    }

    /// The refusal names the form that was refused, not just the word `git
    /// stash` — the operator reading the run's last line needs to know which
    /// of the nine it was.
    #[test]
    fn the_stash_refusal_names_the_subcommand_it_refused() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        assert_eq!(
            refusal(&policy.assess("bash", &json!({ "command": "git stash pop" }))),
            "refused: `git stash pop` — the stash stack is shared with other worktrees"
        );
        assert_eq!(
            refusal(&policy.assess("bash", &json!({ "command": "git stash" }))),
            "refused: `git stash` — the stash stack is shared with other worktrees"
        );
    }

    /// Stated as a test rather than as a hope: an alias defined on the same
    /// line defeats the floor, measured on git 2.43.0 (`git -c
    /// alias.l='stash drop' l` printed `Dropped refs/stash@{0}`). It was open
    /// before A2-259 and is open after; reading it would mean evaluating
    /// git's config, and the module header says outright that this check is a
    /// string heuristic and not a sandbox. Pinned so the gap is a recorded
    /// fact instead of a surprise.
    #[test]
    fn a_git_alias_still_walks_past_the_stash_rule() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        assert_eq!(
            policy.assess(
                "bash",
                &json!({ "command": "git -c alias.l='stash drop' l" })
            ),
            Assessment::InsideWorkspace,
            "the alias hole closed — update this test and the module docs"
        );
    }

    /// A2-259: the `..` refusal stands, and now says how to write the path
    /// instead. Pilot A2-240d spent three of its six denied calls on this one
    /// shape because the old reason named only the problem.
    #[test]
    fn a_relative_path_out_of_the_workspace_is_refused_with_the_way_to_write_it() {
        let root = TempDir::new().unwrap();
        let policy = policy(&root);
        // Pilot A2-240d, turn 54: after `cd sup`, `../snap` IS inside the
        // workspace — and is refused anyway, because the check resolves it
        // against the root.
        let assessment = policy.assess(
            "bash",
            &json!({ "command": "cd sup && git archive HEAD | tar -x -C ../snap" }),
        );
        assert!(matches!(assessment, Assessment::OutsideWorkspace(_)));
        let reason = refusal(&assessment);
        assert!(
            reason.contains("not against a `cd` earlier in the same command"),
            "the refusal does not say why the `cd` did not help: {reason}"
        );
        assert!(
            reason.contains("name the path from the workspace root")
                && reason.contains(&root.path().canonicalize().unwrap().display().to_string()),
            "the refusal does not say what to write instead: {reason}"
        );
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
