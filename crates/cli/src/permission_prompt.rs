//! Layer 4 interactive prompt for the permission cascade.
//!
//! `ReadlinePrompt` implements [`PermissionLayer`] + [`InteractiveLayer`] and
//! reads a yes/no verdict from a [`PromptSource`]. The default
//! [`RustylineSource`] wraps `rustyline::DefaultEditor` for a real terminal;
//! tests inject [`MockSource`] with a scripted line queue.
//!
//! The cascade enters Layer 4 only when Layers 1-3 returned
//! [`LayerDecision::Defer`]. A non-affirmative answer (`n`, empty line,
//! EOF, IO error) maps to [`LayerDecision::Deny`] — fail-closed by design,
//! matching the `AutoFromEnv` posture when no terminal is available.

use std::io;
use std::sync::Mutex;

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
    source: S,
}

impl<S: PromptSource> ReadlinePrompt<S> {
    /// Wrap a [`PromptSource`] as a cascade layer.
    pub const fn new(source: S) -> Self {
        Self { source }
    }
}

impl ReadlinePrompt<RustylineSource> {
    /// Convenience constructor for the production wiring path.
    ///
    /// # Errors
    /// Surfaces [`PromptError`] from the underlying [`RustylineSource::new`].
    pub fn with_terminal() -> Result<Self, PromptError> {
        Ok(Self {
            source: RustylineSource::new()?,
        })
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

#[async_trait]
impl<S: PromptSource> PermissionLayer for ReadlinePrompt<S> {
    fn name(&self) -> &'static str {
        "interactive_readline"
    }

    async fn evaluate(&self, tool: &str, _input: &Value) -> LayerDecision {
        let prompt = render_prompt(tool);
        match self.source.read_line(&prompt) {
            Ok(line) => classify_answer(&line),
            Err(PromptError::Eof) => {
                LayerDecision::Deny("interactive prompt closed (EOF)".to_string())
            }
            Err(PromptError::Interrupted) => {
                LayerDecision::Deny("interactive prompt interrupted (Ctrl-C)".to_string())
            }
            Err(err) => LayerDecision::Deny(format!("interactive prompt failed: {err}")),
        }
    }
}

impl<S: PromptSource> InteractiveLayer for ReadlinePrompt<S> {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

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

    #[tokio::test]
    async fn readline_prompt_denies_on_no_then_allows_on_yes() {
        let layer = ReadlinePrompt::new(MockSource::new(["n", "yes"]));

        let first = layer.evaluate("read_file", &json!({})).await;
        assert!(matches!(first, LayerDecision::Deny(_)));

        let second = layer.evaluate("read_file", &json!({})).await;
        assert!(matches!(second, LayerDecision::Allow));
    }
}
