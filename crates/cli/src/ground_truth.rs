//! `--ground-truth <PATH>`: a file the dispatcher quotes into a work item's
//! brief as the authority on this repository.
//!
//! Why this exists. The A2-285 live run produced the page it was asked for, and
//! the page was wrong in every command it printed: a binary named `aras`, flags
//! `--contract` and `--item`, and two KC2-flavoured environment variables that
//! exist nowhere in this repository (they are spelled out only in
//! `crates/cli/tests/docs_truth.rs`, which asserts that they occur NOWHERE in
//! the source — naming them here would make that assertion false, and the
//! assertion caught this comment doing exactly that). None of it came from the
//! contract or the work item; it came
//! from what a model expects a CLI like this one to look like. The brief asked
//! for a how-to page about a command and told it nothing about that command.
//!
//! So grounding is DECLARED, in the same shape as `--read-only`: by whoever
//! dispatches the run, before it starts, naming files in the repository. Not
//! answers written by hand — quoting the page we would have written would make
//! the run a measurement of the operator (A2-285 refused to hand-edit the
//! model's page for exactly this reason). `arcana run --help` piped to a file
//! and a section of an existing how-to are ground truth; a paragraph we drafted
//! for the model to copy is not.
//!
//! Fail closed. A named file that cannot be read, or is empty, refuses the run
//! before the first model call: a grounded run that quietly became an ungrounded
//! one would be indistinguishable in the receipt from a grounded one that went
//! wrong.

use std::path::{Path, PathBuf};

use arcana_core::contract::digest_of;

/// A file quoted into the brief, with the digest that says which bytes.
#[derive(Debug, Clone)]
pub struct GroundTruth {
    /// The path as the dispatcher named it.
    pub path: String,
    /// `sha256:<hex>` over the bytes that went into the prompt.
    pub sha256: String,
    pub bytes: usize,
    pub text: String,
}

/// Why a run with grounding refused to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroundTruthRefusal {
    Unreadable { path: String, detail: String },
    Empty { path: String },
}

impl GroundTruthRefusal {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreadable { .. } => "GROUND_TRUTH_UNREADABLE",
            Self::Empty { .. } => "GROUND_TRUTH_EMPTY",
        }
    }
}

impl std::fmt::Display for GroundTruthRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, detail } => {
                write!(f, "cannot read the ground-truth file {path}: {detail}")
            }
            Self::Empty { path } => write!(
                f,
                "the ground-truth file {path} is empty; an empty authority is \
                 not an authority, and a run that dropped it silently would \
                 look exactly like a grounded one"
            ),
        }
    }
}

/// Read every declared file, in the order the dispatcher named them.
///
/// # Errors
///
/// [`GroundTruthRefusal::Unreadable`] for a path that cannot be read as UTF-8,
/// [`GroundTruthRefusal::Empty`] for a file with nothing but whitespace in it.
/// Both refuse the run before the first model call.
pub fn load(paths: &[PathBuf]) -> Result<Vec<GroundTruth>, GroundTruthRefusal> {
    paths.iter().map(|path| load_one(path)).collect()
}

fn load_one(path: &Path) -> Result<GroundTruth, GroundTruthRefusal> {
    let shown = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|err| GroundTruthRefusal::Unreadable {
        path: shown.clone(),
        detail: err.to_string(),
    })?;
    if text.trim().is_empty() {
        return Err(GroundTruthRefusal::Empty { path: shown });
    }
    // The same helper the contract binding hashes with: one spelling of
    // `sha256:<hex>` in the process, so a receipt's two digests are comparable.
    Ok(GroundTruth {
        path: shown,
        sha256: digest_of(text.as_bytes()),
        bytes: text.len(),
        text,
    })
}

/// The section appended to the brief.
///
/// It says what the quoted text IS and what it outranks. The model's own
/// expectation of how a CLI is spelled is the thing being corrected, so it is
/// named: "a name you remember from another tool is not evidence".
#[must_use]
pub fn render(items: &[GroundTruth]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "\nGROUND TRUTH. What follows are files from the repository you are working in, quoted \
verbatim by whoever dispatched this run. They are the authority on the names of binaries, \
subcommands, flags and environment variables. If your deliverable prints a command, every part of \
that command must appear below. A flag you remember from a tool like this one is not evidence, and \
neither is a plausible reading of the task: a command line nobody can run is a wrong answer, even \
when the prose around it is right.\n",
    );
    for item in items {
        use std::fmt::Write as _;
        // Writing into a String is infallible.
        let _ = write!(
            out,
            "\n--- ground truth: {} ({}, {} bytes) ---\n{}\n--- end of {} ---\n",
            item.path,
            item.sha256,
            item.bytes,
            item.text.trim_end(),
            item.path
        );
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn file(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(content.as_bytes()).expect("write");
        file.flush().expect("flush");
        file
    }

    #[test]
    fn a_missing_file_refuses_the_run() {
        let refusal = load(&[PathBuf::from("/nonexistent/help.txt")])
            .expect_err("a named file that is not there must refuse");
        assert_eq!(refusal.code(), "GROUND_TRUTH_UNREADABLE");
    }

    #[test]
    fn an_empty_file_refuses_the_run() {
        let empty = file("   \n");
        let refusal =
            load(&[empty.path().to_path_buf()]).expect_err("an empty authority must refuse");
        assert_eq!(refusal.code(), "GROUND_TRUTH_EMPTY");
    }

    #[test]
    fn the_digest_is_over_the_bytes_that_reach_the_prompt() {
        let help = file("Usage: arcana run --cwd <CWD>\n");
        let loaded = load(&[help.path().to_path_buf()]).expect("loaded");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].bytes, 30);
        assert_eq!(
            loaded[0].sha256,
            digest_of(b"Usage: arcana run --cwd <CWD>\n"),
        );
        let rendered = render(&loaded);
        assert!(
            rendered.contains("Usage: arcana run --cwd <CWD>"),
            "{rendered}"
        );
        assert!(rendered.contains(&loaded[0].sha256), "{rendered}");
    }

    #[test]
    fn no_grounding_adds_nothing_to_the_brief() {
        assert!(render(&[]).is_empty());
    }
}
