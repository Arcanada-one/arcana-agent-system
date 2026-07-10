//! `CoworkerClient` — thin subprocess wrapper around the operator's local
//! `coworker` CLI (`~/.local/bin/coworker ask|write|stats`), which offloads
//! bulk I/O (reads, boilerplate generation) to an external LLM provider.
//!
//! # Shell-free by construction (`feedback_coworker_spec_no_heredoc`)
//!
//! Every argument this module sends to the `coworker` binary is passed as a
//! distinct [`tokio::process::Command::arg`] element — the OS `exec` family
//! receives each one as a separate argv entry and **no shell is ever
//! invoked**. This is deliberate: free-text fields such as `--spec` may
//! legitimately contain heredoc-looking sequences (`<<EOP ... EOP`) supplied
//! by an upstream caller, and those bytes must never pass through anything
//! that could interpret them as shell syntax. Do **not** "simplify" this by
//! routing through `Command::new("sh").arg("-c").arg(format!(...))` or any
//! other string-concatenation-then-shell-interpret path — that is exactly
//! the construction that would let a `--spec` value smuggle a heredoc.
//!
//! Argv construction is split into pure, unit-testable `build_*_args`
//! functions (no process spawn, no I/O) so the "no heredoc survival"
//! invariant can be asserted structurally: the spec text must appear as a
//! single, byte-for-byte-unchanged `Vec<String>` element.
//!
//! # Caller responsibility (`feedback_coworker_draft_fabrication`)
//!
//! This client only captures stdout/stderr/exit code — it does not inspect
//! or validate the content `coworker write` produces. Callers MUST grep the
//! generated output for phantom/fabricated artefacts (invented file paths,
//! invented API endpoints, invented config keys) before trusting or
//! committing it. This module intentionally does not attempt fabrication
//! detection; that judgment belongs to the caller with task context.

use std::path::{Path, PathBuf};

use tokio::process::Command;

/// Env var that overrides the resolved `coworker` binary path. Takes
/// precedence over the `~/.local/bin/coworker` default.
const ENV_BIN_OVERRIDE: &str = "ARCANA_COWORKER_BIN";

/// Relative fallback used only when `$HOME` cannot be resolved at all (should
/// not happen on any supported deployment target, but avoids a panic).
const DEFAULT_BIN_RELATIVE: &str = ".local/bin/coworker";

/// Captured result of one `coworker` subprocess invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoworkerOutput {
    /// Whether the process exited with status 0.
    pub success: bool,
    /// Raw exit code, when the process terminated normally (`None` if killed
    /// by a signal).
    pub exit_code: Option<i32>,
    /// Captured stdout, lossily decoded as UTF-8.
    pub stdout: String,
    /// Captured stderr, lossily decoded as UTF-8.
    pub stderr: String,
}

/// Every way spawning the `coworker` subprocess can fail. Non-zero exit is
/// **not** an error here — it is surfaced via [`CoworkerOutput::success`] /
/// [`CoworkerOutput::exit_code`] so callers can inspect stderr for context.
#[derive(Debug, thiserror::Error)]
pub enum CoworkerError {
    /// The OS failed to spawn the process at all (binary missing, not
    /// executable, permission denied, …).
    #[error("failed to spawn coworker binary at {bin}: {reason}")]
    Spawn { bin: String, reason: String },
}

/// Build the argv for `coworker ask --provider <p> --profile <pr> --paths
/// <f1> <f2> ... --question "<q>"`.
///
/// Pure and side-effect-free: no process is spawned. `question` is appended
/// as a single trailing element, unmodified.
#[must_use]
pub fn build_ask_args(
    provider: Option<&str>,
    profile: Option<&str>,
    paths: &[String],
    question: &str,
) -> Vec<String> {
    let mut args = vec!["ask".to_owned()];
    push_option_flag(&mut args, "--provider", provider);
    push_option_flag(&mut args, "--profile", profile);
    if !paths.is_empty() {
        args.push("--paths".to_owned());
        args.extend(paths.iter().cloned());
    }
    args.push("--question".to_owned());
    args.push(question.to_owned());
    args
}

/// Build the argv for `coworker write --provider <p> --profile <pr> --spec
/// "<what>" --context <ref1> ... --target <out>`.
///
/// Pure and side-effect-free: no process is spawned, no shell is involved.
/// `spec` is appended as a single trailing-flag element exactly as given —
/// this is the literal `DoD` surface for `feedback_coworker_spec_no_heredoc`:
/// a `spec` containing `<<EOP ... EOP` survives as one unchanged
/// `Vec<String>` element, never split or shell-interpreted, because there is
/// no shell anywhere in this function or in the caller
/// ([`CoworkerClient::write`]) that consumes its output.
#[must_use]
pub fn build_write_args(
    spec: &str,
    provider: Option<&str>,
    profile: Option<&str>,
    context: &[String],
    target: &str,
) -> Vec<String> {
    let mut args = vec!["write".to_owned()];
    push_option_flag(&mut args, "--provider", provider);
    push_option_flag(&mut args, "--profile", profile);
    args.push("--spec".to_owned());
    args.push(spec.to_owned());
    if !context.is_empty() {
        args.push("--context".to_owned());
        args.extend(context.iter().cloned());
    }
    args.push("--target".to_owned());
    args.push(target.to_owned());
    args
}

/// Build the argv for `coworker stats --since <window> --by <dimension>`.
///
/// Pure and side-effect-free: no process is spawned.
#[must_use]
pub fn build_stats_args(since: Option<&str>, by: Option<&str>) -> Vec<String> {
    let mut args = vec!["stats".to_owned()];
    push_option_flag(&mut args, "--since", since);
    push_option_flag(&mut args, "--by", by);
    args
}

/// Append `flag value` as two argv elements when `value` is `Some`; no-op
/// otherwise. Shared by all three `build_*_args` functions.
fn push_option_flag(args: &mut Vec<String>, flag: &str, value: Option<&str>) {
    if let Some(v) = value {
        args.push(flag.to_owned());
        args.push(v.to_owned());
    }
}

/// Resolve the `coworker` binary path from an explicit override and `$HOME`
/// value. Pure function (no env access) so the resolution logic is
/// unit-testable without mutating process-global env state.
///
/// Precedence: non-blank `override_bin` wins; otherwise `$HOME/.local/bin/coworker`;
/// otherwise the bare relative fallback `.local/bin/coworker`.
#[must_use]
fn resolve_bin_path(override_bin: Option<&str>, home: Option<&str>) -> PathBuf {
    if let Some(over) = override_bin.map(str::trim).filter(|s| !s.is_empty()) {
        return PathBuf::from(over);
    }
    match home.map(str::trim).filter(|s| !s.is_empty()) {
        Some(home) => PathBuf::from(home)
            .join(".local")
            .join("bin")
            .join("coworker"),
        None => PathBuf::from(DEFAULT_BIN_RELATIVE),
    }
}

/// Thin subprocess client for the operator's local `coworker` CLI.
#[derive(Debug, Clone)]
pub struct CoworkerClient {
    bin_path: PathBuf,
}

impl CoworkerClient {
    /// Build a client resolving the binary path from `$ARCANA_COWORKER_BIN`
    /// (override) or `$HOME/.local/bin/coworker` (default). Never fails —
    /// path resolution has a fallback even when `$HOME` is unset; a missing
    /// or non-executable binary surfaces as [`CoworkerError::Spawn`] on the
    /// first call.
    #[must_use]
    pub fn from_env() -> Self {
        let override_bin = std::env::var(ENV_BIN_OVERRIDE).ok();
        let home = std::env::var("HOME").ok();
        Self {
            bin_path: resolve_bin_path(override_bin.as_deref(), home.as_deref()),
        }
    }

    /// Build a client with an explicit binary path (used by tests and any
    /// non-default deployment, e.g. pointing at a harmless no-op binary like
    /// `/bin/echo` to exercise the spawn path without invoking the real
    /// `coworker`).
    #[must_use]
    pub fn with_bin_path(bin_path: impl Into<PathBuf>) -> Self {
        Self {
            bin_path: bin_path.into(),
        }
    }

    /// The resolved binary path this client will spawn.
    #[must_use]
    pub fn bin_path(&self) -> &Path {
        &self.bin_path
    }

    /// Run `coworker ask --provider <p> --profile <pr> --paths <f1> <f2> ...
    /// --question "<q>"`.
    ///
    /// # Errors
    /// Returns [`CoworkerError::Spawn`] if the OS fails to launch the
    /// process. A non-zero exit from `coworker` itself is **not** an error —
    /// inspect [`CoworkerOutput::success`].
    pub async fn ask(
        &self,
        provider: Option<&str>,
        profile: Option<&str>,
        paths: &[String],
        question: &str,
    ) -> Result<CoworkerOutput, CoworkerError> {
        self.run(&build_ask_args(provider, profile, paths, question))
            .await
    }

    /// Run `coworker write --provider <p> --profile <pr> --spec "<what>"
    /// --context <ref1> ... --target <out>`.
    ///
    /// `spec` is passed through [`tokio::process::Command::arg`] as a single
    /// literal `OsString` argv element — never interpolated into a shell
    /// string. This is the load-bearing invariant behind
    /// `feedback_coworker_spec_no_heredoc`: a `spec` value containing
    /// `<<EOP ... EOP` cannot be misread as a shell heredoc because no shell
    /// is ever spawned on this path. Do not refactor this method to build a
    /// shell command string.
    ///
    /// # Errors
    /// Returns [`CoworkerError::Spawn`] if the OS fails to launch the
    /// process. A non-zero exit from `coworker` itself is **not** an error —
    /// inspect [`CoworkerOutput::success`].
    ///
    /// # Caller responsibility
    /// Per `feedback_coworker_draft_fabrication`: the caller MUST grep the
    /// returned output (and/or the `target` file it wrote) for
    /// phantom/fabricated artefacts before trusting or committing it. This
    /// method does not perform that check.
    pub async fn write(
        &self,
        spec: &str,
        provider: Option<&str>,
        profile: Option<&str>,
        context: &[String],
        target: &str,
    ) -> Result<CoworkerOutput, CoworkerError> {
        self.run(&build_write_args(spec, provider, profile, context, target))
            .await
    }

    /// Run `coworker stats --since <window> --by <dimension>`.
    ///
    /// # Errors
    /// Returns [`CoworkerError::Spawn`] if the OS fails to launch the
    /// process.
    pub async fn stats(
        &self,
        since: Option<&str>,
        by: Option<&str>,
    ) -> Result<CoworkerOutput, CoworkerError> {
        self.run(&build_stats_args(since, by)).await
    }

    /// Spawn `self.bin_path` with `args` and capture stdout/stderr/exit
    /// code. No shell is ever involved: `args` are passed via
    /// [`tokio::process::Command::args`], each element becoming one argv
    /// entry.
    async fn run(&self, args: &[String]) -> Result<CoworkerOutput, CoworkerError> {
        let output = Command::new(&self.bin_path)
            .args(args)
            .output()
            .await
            .map_err(|err| CoworkerError::Spawn {
                bin: self.bin_path.display().to_string(),
                reason: err.to_string(),
            })?;
        Ok(CoworkerOutput {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const HEREDOC_SPEC: &str = "summarize this <<EOP\nmalicious injected content\nEOP";

    #[test]
    fn build_write_args_preserves_heredoc_spec_as_single_unchanged_element() {
        let args = build_write_args(HEREDOC_SPEC, None, None, &[], "out.md");
        let spec_idx = args
            .iter()
            .position(|a| a == "--spec")
            .expect("--spec flag present");
        let spec_value = &args[spec_idx + 1];
        assert_eq!(spec_value, HEREDOC_SPEC);
        // Structural proof: the heredoc text is exactly one argv element,
        // never split across several (which is what would happen if it had
        // been tokenized by a shell).
        assert_eq!(args.iter().filter(|a| a.contains("EOP")).count(), 1);
    }

    #[test]
    fn build_write_args_orders_flags_and_includes_context_and_target() {
        let context = vec!["ref1.md".to_owned(), "ref2.md".to_owned()];
        let args = build_write_args(
            "plain spec",
            Some("deepseek"),
            Some("datarim"),
            &context,
            "out.md",
        );
        assert_eq!(
            args,
            vec![
                "write",
                "--provider",
                "deepseek",
                "--profile",
                "datarim",
                "--spec",
                "plain spec",
                "--context",
                "ref1.md",
                "ref2.md",
                "--target",
                "out.md",
            ]
        );
    }

    #[test]
    fn build_write_args_omits_absent_optionals() {
        let args = build_write_args("spec text", None, None, &[], "out.md");
        assert_eq!(
            args,
            vec!["write", "--spec", "spec text", "--target", "out.md"]
        );
    }

    #[test]
    fn build_ask_args_preserves_heredoc_question_as_single_unchanged_element() {
        let paths = vec!["a.md".to_owned(), "b.md".to_owned()];
        let question = "explain <<EOP\ninjected\nEOP please";
        let args = build_ask_args(Some("moonshot"), Some("code"), &paths, question);
        assert_eq!(
            args,
            vec![
                "ask",
                "--provider",
                "moonshot",
                "--profile",
                "code",
                "--paths",
                "a.md",
                "b.md",
                "--question",
                question,
            ]
        );
        let question_idx = args.iter().position(|a| a == "--question").unwrap();
        assert_eq!(args[question_idx + 1], question);
    }

    #[test]
    fn build_ask_args_omits_paths_flag_when_empty() {
        let args = build_ask_args(None, None, &[], "question text");
        assert_eq!(args, vec!["ask", "--question", "question text"]);
    }

    #[test]
    fn build_stats_args_structural() {
        assert_eq!(
            build_stats_args(Some("7d"), Some("profile")),
            vec!["stats", "--since", "7d", "--by", "profile"]
        );
        assert_eq!(build_stats_args(None, None), vec!["stats"]);
    }

    #[test]
    fn resolve_bin_path_prefers_override() {
        let resolved = resolve_bin_path(Some("/opt/coworker"), Some("/home/dev"));
        assert_eq!(resolved, PathBuf::from("/opt/coworker"));
    }

    #[test]
    fn resolve_bin_path_blank_override_falls_back_to_home() {
        let resolved = resolve_bin_path(Some("   "), Some("/home/dev"));
        assert_eq!(resolved, PathBuf::from("/home/dev/.local/bin/coworker"));
    }

    #[test]
    fn resolve_bin_path_falls_back_to_home_default() {
        let resolved = resolve_bin_path(None, Some("/home/dev"));
        assert_eq!(resolved, PathBuf::from("/home/dev/.local/bin/coworker"));
    }

    #[test]
    fn resolve_bin_path_falls_back_to_relative_when_home_missing() {
        let resolved = resolve_bin_path(None, None);
        assert_eq!(resolved, PathBuf::from(DEFAULT_BIN_RELATIVE));
    }

    #[test]
    fn with_bin_path_sets_bin_path_verbatim() {
        let client = CoworkerClient::with_bin_path("/bin/echo");
        assert_eq!(client.bin_path(), Path::new("/bin/echo"));
    }
}
