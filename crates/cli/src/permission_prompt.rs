//! Layer 4 interactive prompt for the permission cascade.
//!
//! `ReadlinePrompt` implements [`PermissionLayer`] + [`InteractiveLayer`] and
//! reads a yes/no verdict from a [`PromptSource`]. The default
//! [`RustylineSource`] wraps `rustyline::DefaultEditor` for a real terminal;
//! tests inject [`MockSource`] with a scripted line queue.
//!
//! The cascade enters Layer 4 only when Layers 1-3 returned
//! [`LayerDecision::Defer`]. A non-affirmative answer (`n`, empty line,
//! EOF, IO error, no answer at all) maps to [`LayerDecision::Deny`] —
//! fail-closed by design, matching the `AutoFromEnv` posture when no terminal
//! is available.
//!
//! ## Why the read is bounded
//!
//! Fail-closed on EOF is not enough on its own, because an idle terminal
//! never reaches EOF. A pty that is attached but never sends a byte — every
//! `ssh -t host arcana ...`, every CI job that allocates one, every unattended
//! tmux or cron pane — left `rustyline::readline` parked forever, holding the
//! terminal, with the prompt line as the last thing the process ever printed.
//! Measured before this bound existed: `script -qec 'arcana whoami' /dev/null
//! < /dev/null` was still alive at 60 s and had to be killed with `SIGKILL`, while the
//! same binary with no pty at all denied correctly in milliseconds.
//!
//! So the wait has a clock. See [`prompt_timeout`].

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcana_core::permission::{InteractiveLayer, LayerDecision, PermissionLayer};
use async_trait::async_trait;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use serde_json::Value;
use thiserror::Error;

/// Abstraction over a line-oriented input source.
///
/// `ReadlinePrompt` calls [`PromptSource::read_line`] with a rendered prompt
/// string and expects either a user line or [`PromptError`]. Production
/// wiring uses [`RustylineSource`]; tests use [`MockSource`].
pub trait PromptSource: Send + Sync {
    /// Render `prompt` and read a single line from the source.
    ///
    /// # Errors
    /// Returns [`PromptError::Eof`] when the source is exhausted,
    /// [`PromptError::Interrupted`] on Ctrl-C, and [`PromptError::Io`] /
    /// [`PromptError::Readline`] for terminal-level failures.
    fn read_line(&self, prompt: &str) -> Result<String, PromptError>;
}

/// Error surface for [`PromptSource::read_line`].
#[derive(Debug, Error)]
pub enum PromptError {
    /// End of input — stdin closed or scripted queue exhausted.
    #[error("end of input")]
    Eof,
    /// User pressed Ctrl-C or otherwise interrupted the prompt.
    #[error("interrupted")]
    Interrupted,
    /// Underlying IO failure.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// Other readline failure (terminal misbehaviour, encoding errors, …).
    #[error("readline error: {0}")]
    Readline(String),
    /// The bound elapsed with no answer — see the module docs.
    #[error("no answer after {seconds}s")]
    TimedOut { seconds: u64 },
}

/// Environment override for the interactive-prompt bound, in whole seconds.
///
/// `0` disables the bound, restoring the old unbounded wait for an operator
/// who genuinely wants to leave a prompt open indefinitely.
pub const ENV_PROMPT_TIMEOUT: &str = "ARCANA_PROMPT_TIMEOUT_SECS";

/// How long to wait for an answer before denying.
///
/// Two minutes is long enough that a human reading the prompt is never cut
/// off mid-thought, and short enough that an unattended invocation fails in a
/// time a CI job or a supervisor will tolerate.
pub const DEFAULT_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Resolve the prompt bound from the environment.
///
/// An unset, empty, or unparseable value yields [`DEFAULT_PROMPT_TIMEOUT`]:
/// a typo in the override must not silently restore the unbounded wait this
/// exists to prevent. `0` is the one value that disables it, and it has to be
/// spelled exactly.
#[must_use]
pub fn prompt_timeout() -> Option<Duration> {
    let Ok(raw) = std::env::var(ENV_PROMPT_TIMEOUT) else {
        return Some(DEFAULT_PROMPT_TIMEOUT);
    };
    match raw.trim().parse::<u64>() {
        Ok(0) => None,
        Ok(seconds) => Some(Duration::from_secs(seconds)),
        Err(_) => Some(DEFAULT_PROMPT_TIMEOUT),
    }
}

impl From<ReadlineError> for PromptError {
    fn from(err: ReadlineError) -> Self {
        match err {
            ReadlineError::Eof => Self::Eof,
            ReadlineError::Interrupted => Self::Interrupted,
            ReadlineError::Io(io) => Self::Io(io),
            other => Self::Readline(other.to_string()),
        }
    }
}

/// Production prompt source backed by `rustyline::DefaultEditor`.
///
/// The editor lives behind a [`Mutex`] because `read_line` takes `&self`
/// (the trait shape is shared across cascade layers) but the rustyline
/// editor's `readline` needs `&mut`. Contention is irrelevant in practice:
/// the cascade processes one tool call at a time per operator session.
pub struct RustylineSource {
    editor: Mutex<DefaultEditor>,
}

impl RustylineSource {
    /// Construct a [`RustylineSource`] wrapping a fresh editor.
    ///
    /// # Errors
    /// Returns the underlying rustyline error if editor initialisation
    /// fails (no terminal, locale problems, …). Callers SHOULD fall back
    /// to `AutoFromEnv` in that case.
    pub fn new() -> Result<Self, PromptError> {
        let editor = DefaultEditor::new()?;
        Ok(Self {
            editor: Mutex::new(editor),
        })
    }
}

impl PromptSource for RustylineSource {
    fn read_line(&self, prompt: &str) -> Result<String, PromptError> {
        let mut editor = self
            .editor
            .lock()
            .map_err(|err| PromptError::Readline(format!("editor mutex poisoned: {err}")))?;
        Ok(editor.readline(prompt)?)
    }
}

/// Scripted prompt source for tests.
///
/// Each call to `read_line` pops the next queued response. The queue is
/// stored under a [`Mutex`] for the same `&self` reason as [`RustylineSource`].
pub struct MockSource {
    answers: Mutex<std::collections::VecDeque<String>>,
}

impl MockSource {
    /// Build a mock source from a list of scripted answers.
    #[must_use]
    pub fn new<I, S>(answers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let queue = answers.into_iter().map(Into::into).collect();
        Self {
            answers: Mutex::new(queue),
        }
    }
}

impl PromptSource for MockSource {
    fn read_line(&self, _prompt: &str) -> Result<String, PromptError> {
        let mut queue = self
            .answers
            .lock()
            .map_err(|err| PromptError::Readline(format!("mock queue poisoned: {err}")))?;
        queue.pop_front().ok_or(PromptError::Eof)
    }
}

/// Layer 4 interactive prompt — asks the operator for a yes/no verdict.
pub struct ReadlinePrompt<S: PromptSource> {
    source: Arc<S>,
    timeout: Option<Duration>,
}

impl<S: PromptSource> ReadlinePrompt<S> {
    /// Wrap a [`PromptSource`] as a cascade layer, bounded by
    /// [`prompt_timeout`].
    pub fn new(source: S) -> Self {
        Self {
            source: Arc::new(source),
            timeout: prompt_timeout(),
        }
    }

    /// Wrap a [`PromptSource`] with an explicit bound (`None` = unbounded).
    ///
    /// Used by the tests, which must pin the bound rather than inherit
    /// whatever the ambient environment says.
    pub fn with_timeout(source: S, timeout: Option<Duration>) -> Self {
        Self {
            source: Arc::new(source),
            timeout,
        }
    }
}

impl ReadlinePrompt<RustylineSource> {
    /// Convenience constructor for the production wiring path.
    ///
    /// # Errors
    /// Surfaces [`PromptError`] from the underlying [`RustylineSource::new`].
    pub fn with_terminal() -> Result<Self, PromptError> {
        Ok(Self::new(RustylineSource::new()?))
    }
}

/// Render the prompt string the operator sees.
///
/// Pulled out as a free function so it can be unit-tested without touching
/// any prompt source. Keeping the formatting local also avoids the
/// 50-line guideline pressure on [`PermissionLayer::evaluate`].
#[must_use]
pub fn render_prompt(tool: &str) -> String {
    format!("[arcana permission] allow tool `{tool}`? (y/N): ")
}

/// Classify the operator's raw answer into a [`LayerDecision`].
///
/// Allow on `y`/`yes` (case-insensitive, trimmed). Everything else — empty
/// lines, `n`, `no`, garbage, multi-word answers — maps to `Deny`.
/// Fail-closed by construction.
#[must_use]
pub fn classify_answer(raw: &str) -> LayerDecision {
    match raw.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => LayerDecision::Allow,
        other => LayerDecision::Deny(format!(
            "operator declined at interactive prompt (`{other}`)"
        )),
    }
}

impl<S: PromptSource + 'static> ReadlinePrompt<S> {
    /// Read one line, giving up after `budget`.
    ///
    /// The read happens on a DETACHED `std::thread`, deliberately not on
    /// tokio's blocking pool: the runtime joins that pool at shutdown, so a
    /// pool task parked on a read that will never return would reproduce the
    /// original hang at process exit instead of at the prompt. A detached
    /// thread is abandoned when the process exits, which is exactly the
    /// semantics wanted for a terminal nobody is sitting at.
    async fn read_line_bounded(
        &self,
        prompt: &str,
        budget: Duration,
    ) -> Result<String, PromptError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let source = Arc::clone(&self.source);
        let owned = prompt.to_owned();
        std::thread::spawn(move || {
            // The receiver is gone on timeout; dropping the answer is correct.
            drop(tx.send(source.read_line(&owned)));
        });
        match tokio::time::timeout(budget, rx).await {
            Ok(Ok(result)) => result,
            // The reader thread vanished without answering. Fail closed.
            Ok(Err(_)) => Err(PromptError::Eof),
            Err(_) => Err(PromptError::TimedOut {
                seconds: budget.as_secs(),
            }),
        }
    }
}

#[async_trait]
impl<S: PromptSource + 'static> PermissionLayer for ReadlinePrompt<S> {
    fn name(&self) -> &'static str {
        "interactive_readline"
    }

    async fn evaluate(&self, tool: &str, _input: &Value) -> LayerDecision {
        let prompt = render_prompt(tool);
        let answer = match self.timeout {
            Some(budget) => self.read_line_bounded(&prompt, budget).await,
            None => self.source.read_line(&prompt),
        };
        match answer {
            Ok(line) => classify_answer(&line),
            Err(PromptError::Eof) => {
                LayerDecision::Deny("interactive prompt closed (EOF)".to_string())
            }
            Err(PromptError::Interrupted) => {
                LayerDecision::Deny("interactive prompt interrupted (Ctrl-C)".to_string())
            }
            Err(PromptError::TimedOut { seconds }) => LayerDecision::Deny(format!(
                "no answer at the interactive prompt after {seconds}s — nobody appears to be at \
                 the terminal. Answer the prompt, or set a permission rule so this tool does not \
                 need one; {ENV_PROMPT_TIMEOUT}=0 restores an unbounded wait."
            )),
            Err(err) => LayerDecision::Deny(format!("interactive prompt failed: {err}")),
        }
    }
}

impl<S: PromptSource + 'static> InteractiveLayer for ReadlinePrompt<S> {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Serialises the tests that mutate `ARCANA_PROMPT_TIMEOUT_SECS`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn render_prompt_includes_tool_name() {
        let rendered = render_prompt("read_file");
        assert!(rendered.contains("read_file"));
        assert!(rendered.contains("(y/N)"));
    }

    #[test]
    fn classify_answer_yes_variants_allow() {
        for raw in ["y", "Y", "yes", "YES", "  yes  ", "Yes\n"] {
            assert!(
                matches!(classify_answer(raw), LayerDecision::Allow),
                "expected Allow for {raw:?}"
            );
        }
    }

    #[test]
    fn classify_answer_non_affirmative_denies() {
        for raw in ["", "n", "no", "maybe", "skip", " ", "once"] {
            match classify_answer(raw) {
                LayerDecision::Deny(reason) => {
                    assert!(reason.contains("operator declined"), "raw={raw:?}");
                }
                other => panic!("expected Deny for {raw:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn readline_prompt_allows_when_mock_returns_yes() {
        let layer = ReadlinePrompt::new(MockSource::new(["y"]));
        let decision = layer
            .evaluate("read_file", &json!({"path": "/tmp/foo"}))
            .await;
        assert!(matches!(decision, LayerDecision::Allow));
        assert_eq!(layer.name(), "interactive_readline");
    }

    #[tokio::test]
    async fn readline_prompt_denies_on_empty_line() {
        let layer = ReadlinePrompt::new(MockSource::new([""]));
        let decision = layer.evaluate("write_file", &json!({})).await;
        match decision {
            LayerDecision::Deny(reason) => {
                assert!(reason.contains("operator declined"));
            }
            other => panic!("expected Deny on empty line, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn readline_prompt_denies_on_eof_when_queue_drained() {
        let layer = ReadlinePrompt::new(MockSource::new(Vec::<String>::new()));
        let decision = layer.evaluate("bash", &json!({"cmd": "ls"})).await;
        match decision {
            LayerDecision::Deny(reason) => {
                assert!(reason.contains("closed (EOF)"));
            }
            other => panic!("expected Deny on EOF, got {other:?}"),
        }
    }

    // --- the bound (#103) --------------------------------------------------

    /// A source that never answers, standing in for a pty that is attached and
    /// idle. Blocking forever is the whole point.
    struct NeverAnswers;

    impl PromptSource for NeverAnswers {
        fn read_line(&self, _prompt: &str) -> Result<String, PromptError> {
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_terminal_denies_instead_of_hanging() {
        // Before the bound this test would never return. `start_paused` means
        // the 120s budget is auto-advanced, so the assertion is about the
        // decision, not about waiting two minutes.
        let layer = ReadlinePrompt::with_timeout(NeverAnswers, Some(DEFAULT_PROMPT_TIMEOUT));
        match layer.evaluate("whoami", &json!({})).await {
            LayerDecision::Deny(reason) => {
                assert!(reason.contains("no answer"), "reason={reason}");
                assert!(reason.contains("120s"), "reason={reason}");
                assert!(reason.contains(ENV_PROMPT_TIMEOUT), "reason={reason}");
            }
            other => panic!("an idle terminal must deny, got {other:?}"),
        }
    }

    /// A source that thinks for a moment and then answers, standing in for an
    /// operator who reads the prompt before typing.
    struct SlowYes;

    impl PromptSource for SlowYes {
        fn read_line(&self, _prompt: &str) -> Result<String, PromptError> {
            std::thread::sleep(Duration::from_millis(150));
            Ok("y".to_owned())
        }
    }

    #[tokio::test]
    async fn the_bound_does_not_cut_off_an_answer_that_arrives() {
        // The converse, so the test above cannot pass on a layer that denies
        // everything: an answer that takes a moment is still heard.
        //
        // Deliberately NOT `start_paused`. With the clock auto-advancing, the
        // budget elapses before the reader thread is even scheduled, and this
        // asserts nothing — it failed exactly that way when first written.
        let layer = ReadlinePrompt::with_timeout(SlowYes, Some(Duration::from_secs(30)));
        assert!(matches!(
            layer.evaluate("whoami", &json!({})).await,
            LayerDecision::Allow
        ));
    }

    #[tokio::test]
    async fn a_zero_budget_is_the_documented_unbounded_escape_hatch() {
        // `None` is what `prompt_timeout()` returns for `...=0`. A source that
        // answers immediately proves the unbounded path still reads.
        let layer = ReadlinePrompt::with_timeout(MockSource::new(["yes"]), None);
        assert!(matches!(
            layer.evaluate("whoami", &json!({})).await,
            LayerDecision::Allow
        ));
    }

    #[test]
    fn prompt_timeout_reads_the_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_PROMPT_TIMEOUT, "5");
        let five = prompt_timeout();
        std::env::set_var(ENV_PROMPT_TIMEOUT, "0");
        let disabled = prompt_timeout();
        std::env::remove_var(ENV_PROMPT_TIMEOUT);
        let default = prompt_timeout();
        assert_eq!(five, Some(Duration::from_secs(5)));
        assert_eq!(disabled, None, "0 must disable the bound");
        assert_eq!(default, Some(DEFAULT_PROMPT_TIMEOUT));
    }

    #[test]
    fn a_typo_in_the_override_keeps_the_bound_rather_than_removing_it() {
        // Falling back to "unbounded" on an unparseable value would restore the
        // hang through a typo — the failure mode this whole change exists to
        // remove.
        let _guard = ENV_LOCK.lock().unwrap();
        for raw in ["", "  ", "abc", "-1", "12s", "1.5"] {
            std::env::set_var(ENV_PROMPT_TIMEOUT, raw);
            let resolved = prompt_timeout();
            assert_eq!(
                resolved,
                Some(DEFAULT_PROMPT_TIMEOUT),
                "{raw:?} must fall back to the default bound, not to unbounded"
            );
        }
        std::env::remove_var(ENV_PROMPT_TIMEOUT);
    }

    #[tokio::test]
    async fn readline_prompt_denies_on_no_then_allows_on_yes() {
        let layer = ReadlinePrompt::new(MockSource::new(["n", "yes"]));

        let first = layer.evaluate("read_file", &json!({})).await;
        assert!(matches!(first, LayerDecision::Deny(_)));

        let second = layer.evaluate("read_file", &json!({})).await;
        assert!(matches!(second, LayerDecision::Allow));
    }
}
