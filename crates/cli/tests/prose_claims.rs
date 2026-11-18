//! Prose claims: a factual statement in an agent-written page is supported by a
//! span of this repository's source, or it is a finding.
//!
//! Why this exists. `tests/docs_truth.rs` settled the class of claim a parser
//! can settle — a command line we print is a command line the binary accepts —
//! and said in its own module doc that it judges neither prose nor printed
//! output. Measured on PR #217 (A2-297), the page that check passed still told
//! an operator that the Muneral agent key is "a PEM-encoded Ed25519 private
//! key" (`crates/connectors/src/muneral.rs` reads a `mun_sk_` secret out of a
//! file, mode 0600) and to `export ARCANA_MODEL="anthropic.claude-sonnet-4-…"`,
//! a model id that occurs nowhere in this repository and names a vendor we do
//! not dispatch to. Both sentences parse. Both are false. Green docs-truth and
//! a true page are, again, different measurements.
//!
//! What a claim is here. The page is split into paragraphs (with the heading
//! chain above them) and fenced lines, and five kinds of claim are extracted
//! and settled against the source:
//!
//! 1. **Literals** — an identifier, a repository-relative path, a flag or an
//!    assigned value we tell an operator to type must OCCUR in the program.
//!    The finding reports the supporting `file:line` when there is one, and
//!    `every_supported_literal_really_occurs_at_the_span_reported` re-reads
//!    that span: a checker that cites a span it has not re-read is the
//!    reviewer failure mode in deterministic clothing.
//! 2. **Format and algorithm terms** — a paragraph that asserts the encoding
//!    or algorithm of a credential or file (`FORMAT_TERMS`) must have that term
//!    in a file that DECLARES the entity the paragraph is about. Corpus-wide
//!    search is not enough: `PEM` occurs in this repository, in a deny-path
//!    test (`crates/core/tests/rule_layer.rs`), which supports nothing about
//!    the Muneral key.
//! 3. **Numbers** — a default, bound or range a page attributes to a flag must
//!    occur in that flag's own definition in `crates/cli/src/cli.rs` (its doc
//!    comment, which IS the `--help` text, or its `#[arg]` attribute).
//! 4. **Flag relations** — "requires", "conflicts with" are not compared to
//!    text at all: the claim is replayed through `Cli::try_parse_from` and the
//!    real clap definition answers.
//! 5. **Broken words** — a one-letter word is a typo ("i mmediately" shipped
//!    on the #217 page past three reviewers).
//!
//! What it is NOT. This is the deterministic half of the check. It cannot judge
//! a sentence whose defect is meaning rather than a token — for that, a blind
//! reviewer model reads the page beside the source excerpts and must quote its
//! support or answer UNSUPPORTED (`dev-tools/prose-review/`, run live, not in
//! CI). `FORMAT_TERMS` is a dated list, not a theory of language: it grows when
//! a page invents a term that is not on it.
//!
//! Scope. Applied to `AGENT_WRITTEN_PAGES` — pages produced by `arcana run`,
//! which no hand wrote and no hand reviewed line by line. A page a person wrote
//! is not exempt because it is truer; it is out of scope because this check's
//! false positives are the author's time, and the author of these is a model.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use arcana_cli::cli::Cli;
use clap::{CommandFactory, Parser};

/// This file, as a path suffix — excluded from the source corpus.
///
/// Measured in A2-292 and true again here: with the checker in the corpus,
/// every term in `FORMAT_TERMS` and every counter-example in a test body
/// "occurs in the source", and the check confirms whatever it is asked about.
const SELF_PATH: &str = "crates/cli/tests/prose_claims.rs";

/// A page written by `arcana run`, with the work item it was dispatched for.
struct AgentPage {
    path: &'static str,
    work_item: &'static str,
    written: &'static str,
}

/// Every page in this repository that a model wrote end to end.
///
/// A page enters this list when the dispatcher commits a run's output. The
/// entry is the honest label: "no hand wrote this", which is exactly the
/// condition under which the checks below are worth their false positives.
const AGENT_WRITTEN_PAGES: &[AgentPage] = &[AgentPage {
    path: "docs/how-to/run-work-item-under-kc2-contract.md",
    work_item: "d931525f-c134-4c6b-85e1-9cdf94e8ab8b",
    written: "2026-09-25",
}];

/// Terms that assert the FORMAT or ALGORITHM of a file or credential.
///
/// Dated 2026-09-25, opened by the `PEM`/`Ed25519` sentence on the #217 page.
/// A term here is a claim about bytes: it is either in the source that declares
/// the thing, or nobody has checked it.
const FORMAT_TERMS: &[&str] = &[
    "PEM",
    "DER",
    "PKCS8",
    "PKCS#8",
    "X.509",
    "ASN.1",
    "Ed25519",
    "X25519",
    "Curve25519",
    "secp256k1",
    "RSA",
    "ECDSA",
    "JWT",
    "JWS",
    "JWK",
    "JWE",
    "HMAC",
    "MD5",
    "SHA-1",
    "PGP",
    "GPG",
    "OpenSSH",
    "base64",
    "base32",
    "AES",
    "ChaCha20",
    "bcrypt",
    "scrypt",
    "argon2",
    "PBKDF2",
    "mTLS",
];

/// Words after which a bare number is a claim about a bound, not narration.
const NUMBER_CUES: &[&str] = &[
    "default", "defaults", "max", "maximum", "min", "minimum", "range", "ceiling", "cap", "limit",
    "up to", "at most", "at least",
];

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    where_: String,
    what: String,
}

/// A paragraph of prose with the heading chain standing above it.
struct Paragraph {
    lines: Vec<(usize, String)>,
    /// Headings in force, joined — the entity a section is ABOUT is usually
    /// named in its heading and not repeated in every sentence under it.
    headings: String,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root is two levels above this crate")
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

// ---------------------------------------------------------------- page layout

/// Split a page into prose paragraphs and the lines inside fenced blocks.
fn split_page(text: &str) -> (Vec<Paragraph>, Vec<(usize, String)>) {
    let mut paragraphs = Vec::new();
    let mut fenced = Vec::new();
    let mut headings: Vec<(usize, String)> = Vec::new();
    let mut current: Vec<(usize, String)> = Vec::new();
    let mut fence: Option<(char, usize)> = None;

    let heading_chain = |headings: &[(usize, String)]| {
        headings
            .iter()
            .map(|(_, text)| text.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    };

    for (number, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        let trimmed = line.trim_start();
        let fence_char = trimmed.chars().next().filter(|c| *c == '`' || *c == '~');
        let run = fence_char.map_or(0, |c| trimmed.chars().take_while(|ch| *ch == c).count());
        let info = if run >= 3 { trimmed[run..].trim() } else { "" };
        match fence {
            Some((open_char, open_run)) => {
                if run >= open_run && fence_char == Some(open_char) && info.is_empty() {
                    fence = None;
                } else {
                    fenced.push((number, line.to_owned()));
                }
                continue;
            }
            None => {
                if run >= 3 {
                    if !current.is_empty() {
                        paragraphs.push(Paragraph {
                            lines: std::mem::take(&mut current),
                            headings: heading_chain(&headings),
                        });
                    }
                    fence = Some((fence_char.expect("a run implies its character"), run));
                    continue;
                }
            }
        }
        if let Some(rest) = trimmed.strip_prefix('#') {
            let level = 1 + rest.chars().take_while(|c| *c == '#').count();
            if !current.is_empty() {
                paragraphs.push(Paragraph {
                    lines: std::mem::take(&mut current),
                    headings: heading_chain(&headings),
                });
            }
            headings.retain(|(existing, _)| *existing < level);
            headings.push((level, trimmed.trim_start_matches('#').trim().to_owned()));
            continue;
        }
        if trimmed.is_empty() {
            if !current.is_empty() {
                paragraphs.push(Paragraph {
                    lines: std::mem::take(&mut current),
                    headings: heading_chain(&headings),
                });
            }
        } else {
            current.push((number, line.to_owned()));
        }
    }
    if !current.is_empty() {
        paragraphs.push(Paragraph {
            lines: current,
            headings: heading_chain(&headings),
        });
    }
    (paragraphs, fenced)
}

/// The contents of every `` `backtick` `` span on a line.
fn inline_codes(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '`' {
            index += 1;
            continue;
        }
        let open = chars[index..].iter().take_while(|c| **c == '`').count();
        let start = index + open;
        let mut end = start;
        while end < chars.len() {
            if chars[end] == '`' {
                let run = chars[end..].iter().take_while(|c| **c == '`').count();
                if run == open {
                    break;
                }
                end += run;
            } else {
                end += 1;
            }
        }
        if end >= chars.len() {
            break;
        }
        out.push(chars[start..end].iter().collect());
        index = end + open;
    }
    out
}

/// `NAME=value` on a line, with the value as written (quotes stripped).
fn assignments(line: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let boundary = index == 0
            || matches!(
                chars[index - 1],
                ' ' | '\t' | '\'' | '"' | '(' | '{' | ';' | '|' | '&'
            );
        if boundary && (chars[index].is_ascii_uppercase() || chars[index] == '_') {
            let mut end = index;
            while end < chars.len()
                && (chars[end].is_ascii_uppercase()
                    || chars[end].is_ascii_digit()
                    || chars[end] == '_')
            {
                end += 1;
            }
            if end < chars.len() && chars[end] == '=' && end - index >= 3 {
                let name: String = chars[index..end].iter().collect();
                let mut value = String::new();
                let mut cursor = end + 1;
                let quote = chars
                    .get(cursor)
                    .copied()
                    .filter(|c| *c == '\'' || *c == '"');
                if quote.is_some() {
                    cursor += 1;
                }
                while cursor < chars.len() {
                    let c = chars[cursor];
                    match quote {
                        Some(q) if c == q => break,
                        None if c.is_whitespace() => break,
                        _ => value.push(c),
                    }
                    cursor += 1;
                }
                out.push((name, value));
                index = cursor + 1;
                continue;
            }
            index = end.max(index + 1);
            continue;
        }
        index += 1;
    }
    out
}

// --------------------------------------------------------------- the program

/// The program, as text: everything outside the documentation.
fn source_corpus(root: &Path) -> &'static Vec<(String, String)> {
    static CORPUS: OnceLock<Vec<(String, String)>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut files = Vec::new();
        let extensions = [
            "rs", "sh", "bash", "bats", "toml", "yml", "yaml", "json", "plist", "service",
        ];
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if path.is_dir() {
                    if matches!(name.as_str(), ".git" | "target" | "docs" | "node_modules") {
                        continue;
                    }
                    stack.push(path);
                } else if !path.ends_with(SELF_PATH)
                    && path
                        .extension()
                        .is_some_and(|ext| extensions.iter().any(|e| ext == *e))
                {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        files.push((relative(root, &path), content));
                    }
                }
            }
        }
        files.sort();
        let bytes: usize = files.iter().map(|(_, text)| text.len()).sum();
        assert!(
            bytes > 100_000,
            "the source corpus is {bytes} bytes — too small to be this \
             repository, so 'the token is nowhere in the source' would be \
             vacuously true"
        );
        files
    })
}

/// The first `file:line` whose text contains `needle`, at a token boundary.
///
/// This is the deterministic half's "quoted span": the finding either names
/// where the support is, or there is none.
fn supporting_span(root: &Path, needle: &str, scope: Option<&BTreeSet<String>>) -> Option<String> {
    let boundary = |text: &str, at: usize| {
        let before = text[..at].chars().next_back();
        let after = text[at + needle.len()..].chars().next();
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        !ident(before) && !ident(after)
    };
    for (path, text) in source_corpus(root) {
        if scope.is_some_and(|files| !files.contains(path)) {
            continue;
        }
        for (offset, line) in text.lines().enumerate() {
            if let Some(at) = line.find(needle) {
                if boundary(line, at) {
                    return Some(format!("{path}:{}", offset + 1));
                }
            }
        }
    }
    None
}

/// Case-insensitive variant, for terms an English sentence may recase.
fn supporting_span_ci(
    root: &Path,
    needle: &str,
    scope: Option<&BTreeSet<String>>,
) -> Option<String> {
    let lowered = needle.to_ascii_lowercase();
    for (path, text) in source_corpus(root) {
        if scope.is_some_and(|files| !files.contains(path)) {
            continue;
        }
        for (offset, line) in text.lines().enumerate() {
            if line.to_ascii_lowercase().contains(&lowered) {
                return Some(format!("{path}:{}", offset + 1));
            }
        }
    }
    None
}

/// Every `ARCANA_*` name that occurs as a literal in the source, and the files
/// it occurs in — the files a claim about that variable must be supported by.
fn env_declarations(root: &Path) -> &'static BTreeMap<String, BTreeSet<String>> {
    static INDEX: OnceLock<BTreeMap<String, BTreeSet<String>>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (path, text) in source_corpus(root) {
            let chars: Vec<char> = text.chars().collect();
            let mut index_at = 0;
            while index_at < chars.len() {
                if chars[index_at..].starts_with(&['A', 'R', 'C', 'A', 'N', 'A', '_']) {
                    let before = index_at.checked_sub(1).map(|i| chars[i]);
                    if !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                        let mut end = index_at;
                        while end < chars.len()
                            && (chars[end].is_ascii_uppercase()
                                || chars[end].is_ascii_digit()
                                || chars[end] == '_')
                        {
                            end += 1;
                        }
                        let name: String = chars[index_at..end].iter().collect();
                        index.entry(name).or_default().insert(path.clone());
                        index_at = end;
                        continue;
                    }
                }
                index_at += 1;
            }
        }
        index
    })
}

/// Every long flag the real clap definition accepts, anywhere in the tree.
fn real_long_flags() -> &'static BTreeSet<String> {
    static FLAGS: OnceLock<BTreeSet<String>> = OnceLock::new();
    FLAGS.get_or_init(|| {
        let mut out = BTreeSet::new();
        let mut stack = vec![Cli::command()];
        while let Some(command) = stack.pop() {
            for arg in command.get_arguments() {
                if let Some(long) = arg.get_long() {
                    out.insert(format!("--{long}"));
                }
            }
            for sub in command.get_subcommands() {
                stack.push(sub.clone());
            }
        }
        out
    })
}

/// Long flags of `arcana run`, and whether each one takes a value.
fn run_flags() -> &'static BTreeMap<String, bool> {
    static FLAGS: OnceLock<BTreeMap<String, bool>> = OnceLock::new();
    FLAGS.get_or_init(|| {
        let command = Cli::command();
        let run = command
            .get_subcommands()
            .find(|sub| sub.get_name() == "run")
            .expect("`arcana run` exists")
            .clone();
        run.get_arguments()
            .filter_map(|arg| {
                arg.get_long().map(|long| {
                    let takes_value = !matches!(
                        arg.get_action(),
                        clap::ArgAction::SetTrue
                            | clap::ArgAction::SetFalse
                            | clap::ArgAction::Count
                    );
                    (format!("--{long}"), takes_value)
                })
            })
            .collect()
    })
}

/// Each `arcana run` flag's own definition in `cli.rs`: the doc comment that
/// becomes its help text, plus its `#[arg]` attribute.
fn flag_definitions(root: &Path) -> &'static BTreeMap<String, String> {
    static BLOCKS: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    BLOCKS.get_or_init(|| {
        let text = std::fs::read_to_string(root.join("crates/cli/src/cli.rs"))
            .expect("the clap definition is readable");
        let mut blocks = BTreeMap::new();
        let mut pending = String::new();
        let mut has_arg = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(doc) = trimmed.strip_prefix("///") {
                pending.push_str(doc.trim());
                pending.push('\n');
            } else if trimmed.starts_with("#[arg") || trimmed.starts_with("#[command") {
                pending.push_str(trimmed);
                pending.push('\n');
                has_arg = true;
            } else if has_arg {
                if let Some((name, _)) = trimmed.split_once(':') {
                    let name = name.trim();
                    if !name.is_empty()
                        && name
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                    {
                        blocks.insert(
                            format!("--{}", name.replace('_', "-")),
                            std::mem::take(&mut pending),
                        );
                    }
                }
                pending.clear();
                has_arg = false;
            } else {
                pending.clear();
            }
        }
        blocks
    })
}

// ------------------------------------------------------------------- findings

/// Is this literal one a machine can settle at all?
enum Literal {
    /// A long flag: settled against the real clap surface.
    Flag(String),
    /// A repository-relative path: its stable prefix must occur in the source.
    Path(String),
    /// An identifier with a separator in it: must occur in the source.
    Identifier(String),
    /// Narration, a placeholder, an operator's own path — not a claim.
    NotAClaim,
}

fn classify(raw: &str) -> Literal {
    let token = raw.trim();
    if token.is_empty()
        || token.contains(char::is_whitespace)
        || token.contains('$')
        || token.contains('"')
        || token.contains('\'')
        || token.starts_with('<')
        || token.starts_with('~')
        || token.starts_with('/')
        || token.starts_with('.')
    {
        return Literal::NotAClaim;
    }
    let token = token.trim_end_matches(['.', ',', ';', ':', ')']);
    if let Some(flag) = token.strip_prefix("--") {
        if !flag.is_empty() && flag.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            return Literal::Flag(token.to_owned());
        }
        return Literal::NotAClaim;
    }
    if token.starts_with('-') {
        return Literal::NotAClaim;
    }
    if token.contains('/') {
        // A placeholder segment is a wildcard; the prefix before it is not.
        let stable = token.split(['<', '*']).next().unwrap_or(token);
        if stable.len() >= 6 && stable.contains('/') {
            return Literal::Path(stable.to_owned());
        }
        return Literal::NotAClaim;
    }
    let separated = token.contains('_') || token.contains('-') || token.contains('.');
    let shaped = token.len() >= 4
        && separated
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && token.chars().any(|c| c.is_ascii_alphabetic());
    if shaped {
        // A hyphenated English phrase is prose, not an identifier.
        let english = token
            .split(['-', '.'])
            .all(|part| part.chars().all(|c| c.is_ascii_lowercase()) && part.len() > 2)
            && !token.contains('_')
            && token.split(['-', '.']).count() == 2;
        if english {
            return Literal::NotAClaim;
        }
        return Literal::Identifier(token.to_owned());
    }
    Literal::NotAClaim
}

fn literal_findings(root: &Path, path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (paragraphs, fenced) = split_page(text);
    let mut candidates: Vec<(usize, String, &'static str)> = Vec::new();
    for paragraph in &paragraphs {
        for (number, line) in &paragraph.lines {
            for code in inline_codes(line) {
                candidates.push((*number, code, "named in the prose"));
            }
        }
    }
    for (number, line) in &fenced {
        for (name, value) in assignments(line) {
            if env_declarations(root).contains_key(&name) {
                candidates.push((*number, value, "assigned to a variable the program reads"));
            }
        }
    }
    for (number, token, how) in candidates {
        let at = format!("{path}:{number}");
        match classify(&token) {
            Literal::Flag(flag) => {
                if !real_long_flags().contains(&flag) {
                    findings.push(Finding {
                        where_: at,
                        what: format!("`{flag}` is not a flag this CLI defines ({how})"),
                    });
                }
            }
            Literal::Path(stable) => {
                if supporting_span(root, &stable, None).is_none() {
                    findings.push(Finding {
                        where_: at,
                        what: format!("the path `{stable}` occurs nowhere in the program ({how})"),
                    });
                }
            }
            Literal::Identifier(identifier) => {
                if supporting_span(root, &identifier, None).is_none() {
                    findings.push(Finding {
                        where_: at,
                        what: format!("`{identifier}` occurs nowhere in the program ({how})"),
                    });
                }
            }
            Literal::NotAClaim => {}
        }
    }
    findings
}

fn format_term_findings(root: &Path, path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (paragraphs, _) = split_page(text);
    for paragraph in &paragraphs {
        let body: String = paragraph
            .lines
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let context = format!("{} {body}", paragraph.headings);
        // The entities this paragraph is about, and the files that declare them.
        let mut scope: BTreeSet<String> = BTreeSet::new();
        let mut entities: Vec<String> = Vec::new();
        for (name, files) in env_declarations(root) {
            if context.contains(name.as_str()) {
                entities.push(name.clone());
                scope.extend(files.iter().cloned());
            }
        }
        for term in FORMAT_TERMS {
            let Some((offset, _)) = paragraph
                .lines
                .iter()
                .find(|(_, line)| contains_word(line, term))
            else {
                continue;
            };
            let scoped = if entities.is_empty() {
                None
            } else {
                Some(&scope)
            };
            if supporting_span_ci(root, term, scoped).is_some() {
                continue;
            }
            let about = if entities.is_empty() {
                "and nowhere in the program".to_owned()
            } else {
                format!(
                    "about {}, and occurs in no file that declares {}",
                    entities.join(", "),
                    if entities.len() == 1 { "it" } else { "them" }
                )
            };
            findings.push(Finding {
                where_: format!("{path}:{offset}"),
                what: format!("the page asserts `{term}` {about}"),
            });
        }
    }
    findings
}

fn contains_word(line: &str, needle: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    lowered.match_indices(&needle_lower).any(|(at, _)| {
        let before = lowered[..at].chars().next_back();
        let after = lowered[at + needle_lower.len()..].chars().next();
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        !ident(before) && !ident(after)
    })
}

/// Every flag named on a line, in order.
fn flags_on(line: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let bytes: Vec<char> = line.chars().collect();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == '-' && bytes[index + 1] == '-' && bytes[index + 2].is_ascii_lowercase() {
            let mut end = index + 2;
            while end < bytes.len() && (bytes[end].is_ascii_lowercase() || bytes[end] == '-') {
                end += 1;
            }
            out.push((index, bytes[index..end].iter().collect::<String>()));
            index = end;
            continue;
        }
        index += 1;
    }
    out
}

/// Numbers a line attributes to a flag: after a cue word, or either side of a
/// range dash.
fn claimed_numbers(line: &str) -> Vec<String> {
    let lowered = line.to_ascii_lowercase();
    let mut out = Vec::new();
    let chars: Vec<char> = lowered.chars().collect();
    let number_at = |start: usize| -> Option<(String, usize)> {
        let mut end = start;
        while end < chars.len() && chars[end].is_ascii_digit() {
            end += 1;
        }
        if end == start {
            return None;
        }
        Some((chars[start..end].iter().collect(), end))
    };
    for cue in NUMBER_CUES {
        for (at, _) in lowered.match_indices(cue) {
            let mut cursor = lowered[..at].chars().count() + cue.chars().count();
            // Skip the small words between the cue and its number.
            while cursor < chars.len()
                && !chars[cursor].is_ascii_digit()
                && (chars[cursor].is_whitespace()
                    || chars[cursor].is_ascii_lowercase()
                    || matches!(chars[cursor], ':' | '=' | '(' | '`' | ',' | '*' | '_'))
            {
                cursor += 1;
            }
            if let Some((number, _)) = number_at(cursor) {
                out.push(number);
            }
        }
    }
    // `5-600`, `5–600`, `5..600`: a range claim needs no cue word.
    let mut index = 0;
    while index < chars.len() {
        if let Some((low, after)) = number_at(index) {
            let mut cursor = after;
            let mut dashed = false;
            while cursor < chars.len() && matches!(chars[cursor], '-' | '–' | '—' | '.' | '=') {
                dashed = true;
                cursor += 1;
            }
            if dashed {
                if let Some((high, end)) = number_at(cursor) {
                    out.push(low);
                    out.push(high);
                    index = end;
                    continue;
                }
            }
            index = after;
            continue;
        }
        index += 1;
    }
    out.sort();
    out.dedup();
    out
}

fn number_findings(root: &Path, path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (paragraphs, _) = split_page(text);
    let definitions = flag_definitions(root);
    for paragraph in &paragraphs {
        for (number, line) in &paragraph.lines {
            let flags: Vec<String> = flags_on(line)
                .into_iter()
                .map(|(_, flag)| flag)
                .filter(|flag| definitions.contains_key(flag))
                .collect();
            let Some(flag) = flags.first() else {
                continue;
            };
            if flags.len() > 1 {
                // Two flags on one line: which one the number belongs to is a
                // guess, and a guess is not a check.
                continue;
            }
            let definition = definitions[flag].replace('_', "");
            for claimed in claimed_numbers(line) {
                if !contains_word(&definition, &claimed) {
                    findings.push(Finding {
                        where_: format!("{path}:{number}"),
                        what: format!(
                            "the page attributes `{claimed}` to `{flag}`; that number is not in \
                             its definition in crates/cli/src/cli.rs"
                        ),
                    });
                }
            }
        }
    }
    findings
}

/// Replay one relation claim through the real clap definition.
fn relation_holds(subject: &str, relation: &str, object: &str) -> Result<(), String> {
    let flags = run_flags();
    let (Some(subject_value), Some(object_value)) = (flags.get(subject), flags.get(object)) else {
        return Ok(());
    };
    let argv = |pairs: &[(&str, bool)]| -> Vec<String> {
        let mut argv = vec!["arcana".to_owned(), "run".to_owned()];
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for (flag, takes_value) in pairs {
            if !seen.insert(flag) {
                continue;
            }
            argv.push((*flag).to_owned());
            if *takes_value {
                argv.push("1".to_owned());
            }
        }
        if seen.insert("--cwd") {
            argv.push("--cwd".to_owned());
            argv.push("1".to_owned());
        }
        argv
    };
    let together = Cli::try_parse_from(argv(&[(subject, *subject_value), (object, *object_value)]));
    match relation {
        "conflicts" => {
            if together.is_ok() {
                return Err(format!(
                    "clap accepts `{subject}` together with `{object}`, so they do not conflict"
                ));
            }
        }
        "requires" => {
            let alone = Cli::try_parse_from(argv(&[(subject, *subject_value)]));
            if alone.is_ok() {
                return Err(format!(
                    "clap accepts `{subject}` without `{object}`, so it does not require it"
                ));
            }
            if together.is_err() {
                return Err(format!(
                    "clap refuses `{subject}` even WITH `{object}`: {}",
                    together
                        .err()
                        .map_or_else(String::new, |err| err.kind().to_string())
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn relation_findings(path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (paragraphs, _) = split_page(text);
    for paragraph in &paragraphs {
        let heading_subject = flags_on(&paragraph.headings)
            .into_iter()
            .next_back()
            .map(|(_, flag)| flag);
        for (number, line) in &paragraph.lines {
            let flags = flags_on(line);
            let lowered = line.to_ascii_lowercase();
            for (relation, phrase) in [
                ("requires", "requires"),
                ("requires", "required by"),
                ("conflicts", "conflicts with"),
                ("conflicts", "conflict with"),
                ("conflicts", "cannot be used with"),
                ("conflicts", "never with"),
            ] {
                for (at, _) in lowered.match_indices(phrase) {
                    let at = lowered[..at].chars().count();
                    let subject = flags
                        .iter()
                        .rfind(|(offset, _)| *offset < at)
                        .map(|(_, flag)| flag.clone())
                        .or_else(|| heading_subject.clone());
                    let Some(subject) = subject else {
                        continue;
                    };
                    for (offset, object) in &flags {
                        if *offset <= at || *object == subject {
                            continue;
                        }
                        if let Err(why) = relation_holds(&subject, relation, object) {
                            findings.push(Finding {
                                where_: format!("{path}:{number}"),
                                what: format!(
                                    "the page says `{subject}` {phrase} `{object}`, but {why}"
                                ),
                            });
                        }
                    }
                }
            }
        }
    }
    findings.sort();
    findings.dedup();
    findings
}

fn broken_word_findings(path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (paragraphs, _) = split_page(text);
    for paragraph in &paragraphs {
        for (number, line) in &paragraph.lines {
            // Inline code is not English.
            let mut prose = line.clone();
            for code in inline_codes(line) {
                prose = prose.replace(&format!("`{code}`"), " ");
            }
            let mut previous = String::new();
            for word in prose.split_whitespace() {
                let word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
                // `120 s` is a unit, not a split word.
                let unit = !previous.is_empty() && previous.chars().all(|c| c.is_ascii_digit());
                let was = std::mem::replace(&mut previous, word.to_owned());
                let _ = was;
                if word.len() == 1
                    && word.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                    && !matches!(word, "a" | "A" | "I")
                    && !unit
                {
                    findings.push(Finding {
                        where_: format!("{path}:{number}"),
                        what: format!("`{word}` is a one-letter word — a split word or a typo"),
                    });
                }
            }
        }
    }
    findings
}

// ------------------------------------------------------- shell-command origins

/// First tokens that make a line an instruction to run something other than
/// this program.
///
/// Dated 2026-09-25, opened by the `cargo install arcana` cell on PR #222's
/// page: crates.io's `arcana` is a stranger's 2021 placeholder, this repository
/// does not publish the name, and the page told an operator to install it. A
/// tool enters this list when a page tells someone to run it. Shell builtins
/// and file operations are deliberately absent: what this check is about is a
/// command that FETCHES or BUILDS code from somewhere.
const COMMAND_HEADS: &[&str] = &[
    "apt",
    "apt-get",
    "bash",
    "brew",
    "cargo",
    "cosign",
    "curl",
    "dnf",
    "docker",
    "gh",
    "git",
    "gpg",
    "make",
    "node",
    "npm",
    "npx",
    "pip",
    "pip3",
    "pipx",
    "pnpm",
    "podman",
    "python",
    "python3",
    "rustup",
    "scp",
    "sh",
    "sha256sum",
    "shasum",
    "ssh",
    "tar",
    "unzip",
    "wget",
    "yarn",
    "yum",
    "zsh",
];

/// Fence info strings whose contents are commands and not output.
const SHELL_FENCES: &[&str] = &[
    "bash",
    "sh",
    "shell",
    "zsh",
    "console",
    "terminal",
    "shell-session",
    "sh-session",
];

/// A command line as a page or a document writes it.
struct Command {
    at: String,
    raw: String,
    tokens: Vec<String>,
    /// From a `` `backtick` `` span in prose, rather than a shell-fenced block.
    inline: bool,
}

/// Does an inline span TELL someone to run something, or name a command?
///
/// Measured on the second live rerun of d931525f: "a `git worktree` is the
/// intended target" is a noun phrase about a concept, and reading it as an
/// instruction made this check red on a page that instructed nobody to run
/// anything. A span carries an instruction when it carries an operand — a third
/// token, a flag, a URL or a path. PR #222's cell, `cargo install arcana`, is
/// three tokens; `cargo install` alone, as `docs/how-to/install.md` writes it in
/// prose, is not. A fenced shell block is judged whatever its length: a block is
/// already an instruction to type what is in it.
fn carries_an_operand(tokens: &[String]) -> bool {
    tokens.len() >= 3
        || tokens
            .iter()
            .skip(1)
            .any(|token| token.starts_with('-') || token.contains("://") || token.contains('/'))
}

/// Cut a command line into tokens: continuations joined, a trailing shell
/// comment dropped, whitespace collapsed.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for token in line.split_whitespace() {
        if token == "\\" {
            continue;
        }
        if token.starts_with('#') && !tokens.is_empty() {
            break;
        }
        tokens.push(token.trim_end_matches('\\').to_owned());
    }
    tokens.retain(|token| !token.is_empty());
    // `sudo` and `env` say who runs the command, not which one it is.
    while tokens
        .first()
        .is_some_and(|first| first == "sudo" || first == "env")
    {
        tokens.remove(0);
    }
    tokens
}

fn is_command(tokens: &[String]) -> bool {
    tokens
        .first()
        .is_some_and(|head| COMMAND_HEADS.contains(&head.as_str()))
}

/// Strip a shell prompt a document may have typed in front of a command.
fn without_prompt(line: &str) -> &str {
    let trimmed = line.trim();
    for prompt in ["$ ", "% ", "> ", "- run: ", "run: ", "RUN "] {
        if let Some(rest) = trimmed.strip_prefix(prompt) {
            return rest.trim_start();
        }
    }
    trimmed
}

/// Every command a markdown document tells an operator to run: the lines of its
/// shell-fenced blocks, and the inline spans that name a tool.
fn commands_in_markdown(path: &str, text: &str) -> Vec<Command> {
    let mut out = Vec::new();
    let mut fence: Option<(String, bool)> = None;
    let mut pending: Option<(usize, String)> = None;
    for (number, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        let trimmed = line.trim_start();
        let run = trimmed
            .chars()
            .take_while(|c| *c == '`' || *c == '~')
            .count();
        if run >= 3 {
            let info = trimmed[run..].trim().to_lowercase();
            match &fence {
                Some((open, _)) if info.is_empty() || info == *open => fence = None,
                Some(_) => {}
                None => {
                    let shell = SHELL_FENCES.contains(&info.as_str());
                    fence = Some((info, shell));
                }
            }
            pending = None;
            continue;
        }
        if let Some((_, shell)) = &fence {
            if !*shell {
                continue;
            }
            let body = without_prompt(line);
            if body.starts_with('#') || body.is_empty() {
                continue;
            }
            let (start, joined) = match pending.take() {
                Some((start, prefix)) => (start, format!("{prefix} {body}")),
                None => (number, body.to_owned()),
            };
            if joined.trim_end().ends_with('\\') {
                pending = Some((start, joined.trim_end().trim_end_matches('\\').to_owned()));
                continue;
            }
            let tokens = tokenize(&joined);
            out.push(Command {
                at: format!("{path}:{start}"),
                raw: joined.split_whitespace().collect::<Vec<_>>().join(" "),
                tokens,
                inline: false,
            });
            continue;
        }
        for span in inline_codes(line) {
            let tokens = tokenize(&span);
            if is_command(&tokens) {
                out.push(Command {
                    at: format!("{path}:{number}"),
                    raw: span.split_whitespace().collect::<Vec<_>>().join(" "),
                    tokens,
                    inline: true,
                });
            }
        }
    }
    out
}

/// Every command line in a script this repository ships.
fn commands_in_script(path: &str, text: &str) -> Vec<Command> {
    let mut out = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (number, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        let body = without_prompt(line);
        if body.starts_with('#') || body.is_empty() {
            pending = None;
            continue;
        }
        let (start, joined) = match pending.take() {
            Some((start, prefix)) => (start, format!("{prefix} {body}")),
            None => (number, body.to_owned()),
        };
        if joined.trim_end().ends_with('\\') {
            pending = Some((start, joined.trim_end().trim_end_matches('\\').to_owned()));
            continue;
        }
        // A script line may chain: `cd x && cargo build`.
        for piece in joined.split("&&").flat_map(|p| p.split(';')) {
            let tokens = tokenize(piece);
            if is_command(&tokens) {
                out.push(Command {
                    at: format!("{path}:{start}"),
                    raw: piece.split_whitespace().collect::<Vec<_>>().join(" "),
                    tokens,
                    inline: false,
                });
            }
        }
    }
    out
}

/// Every command this repository documents or runs itself.
///
/// The corpus is the repository's own instructions — its how-to and reference
/// pages, its README, its scripts and its workflows — MINUS the agent-written
/// pages. A page may not be its own authority: two model-written pages agreeing
/// with each other is the fixture-by-the-same-hand failure (A2-287), in prose.
fn documented_commands(root: &Path) -> &'static Vec<Command> {
    static CORPUS: OnceLock<Vec<Command>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        let agent_pages: BTreeSet<&str> = AGENT_WRITTEN_PAGES.iter().map(|p| p.path).collect();
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if path.is_dir() {
                    if matches!(
                        name.as_str(),
                        ".git" | "target" | "node_modules" | "origin" | "receipts"
                    ) {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                let relative_path = relative(root, &path);
                if agent_pages.contains(relative_path.as_str())
                    || relative_path.starts_with("docs/origin/")
                {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let extension = path
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if extension == "md" {
                    out.extend(commands_in_markdown(&relative_path, &text));
                } else if matches!(extension.as_str(), "sh" | "bash" | "yml" | "yaml" | "toml")
                    || matches!(name.as_str(), "Makefile" | "Dockerfile")
                {
                    out.extend(commands_in_script(&relative_path, &text));
                }
            }
        }
        assert!(
            out.len() >= 20,
            "only {} documented command(s) were found — that measures the \
             scanner, not the repository",
            out.len()
        );
        out
    })
}

/// A token a page wrote stands for one a document wrote.
///
/// Equal, or a placeholder: `<work-item-id>`, `/path/to/checkout`,
/// `$HOME/…`. A placeholder is where a page is ALLOWED to differ, because the
/// value is the reader's; a word is not.
fn token_stands_for(page: &str, documented: &str) -> bool {
    let placeholder = |token: &str| {
        token.contains('<')
            || token.contains('>')
            || token.contains("/path/to")
            || token.contains("...")
            || token.starts_with('$')
    };
    page == documented || placeholder(page) || placeholder(documented)
}

fn same_command(page: &[String], documented: &[String]) -> bool {
    page.len() == documented.len()
        && page
            .iter()
            .zip(documented)
            .all(|(one, other)| token_stands_for(one, other))
}

/// `cargo install` that does not build THIS checkout.
///
/// `--path` into this repository, or `--git` at its URL, or the command
/// installs whatever crates.io serves under that name. Measured on 2026-09-25:
/// crates.io `arcana` is version 0.0.0, published 2021-05-04 by someone else,
/// with the description "placeholder" — and `docs/how-to/install.md` says in so
/// many words that this workspace publishes nothing there.
fn cargo_install_finding(root: &Path, at: &str, raw: &str, tokens: &[String]) -> Option<Finding> {
    if tokens.first().map(String::as_str) != Some("cargo")
        || tokens.get(1).map(String::as_str) != Some("install")
    {
        return None;
    }
    let value_after = |flag: &str| {
        tokens
            .iter()
            .position(|token| token == flag)
            .and_then(|index| tokens.get(index + 1))
            .map(String::as_str)
    };
    if let Some(path) = value_after("--path") {
        if root.join(path).exists() {
            return None;
        }
        return Some(Finding {
            where_: at.to_owned(),
            what: format!(
                "`{raw}` installs from `{path}`, which is not a directory of \
                 this repository"
            ),
        });
    }
    if let Some(url) = value_after("--git") {
        if url.contains("Arcanada-one/arcana-agent-system") {
            return None;
        }
        return Some(Finding {
            where_: at.to_owned(),
            what: format!("`{raw}` installs from `{url}`, which is not this repository"),
        });
    }
    Some(Finding {
        where_: at.to_owned(),
        what: format!(
            "`{raw}` installs a crates.io package: this workspace publishes \
             none (`docs/how-to/install.md`), so the name resolves to whatever \
             a stranger registered. A page tells an operator to build this \
             checkout — `cargo install --locked --path crates/cli` — or nothing"
        ),
    })
}

/// Every non-`arcana` command a page prints is a command this repository
/// documents or runs itself.
fn shell_command_findings(root: &Path, path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for command in commands_in_markdown(path, text) {
        if !is_command(&command.tokens) || (command.inline && !carries_an_operand(&command.tokens))
        {
            continue;
        }
        if let Some(finding) =
            cargo_install_finding(root, &command.at, &command.raw, &command.tokens)
        {
            findings.push(finding);
            continue;
        }
        let supported = documented_commands(root)
            .iter()
            .find(|documented| same_command(&command.tokens, &documented.tokens));
        if supported.is_none() {
            findings.push(Finding {
                where_: command.at.clone(),
                what: format!(
                    "`{}` is not a command this repository documents or runs: \
                     it occurs in no how-to, no reference page, no script and \
                     no workflow of this checkout",
                    command.raw
                ),
            });
        }
    }
    findings
}

// ------------------------------------------------------------------- findings

fn all_findings(root: &Path, path: &str, text: &str) -> Vec<Finding> {
    let mut findings = literal_findings(root, path, text);
    findings.extend(format_term_findings(root, path, text));
    findings.extend(number_findings(root, path, text));
    findings.extend(relation_findings(path, text));
    findings.extend(broken_word_findings(path, text));
    findings.extend(shell_command_findings(root, path, text));
    findings.sort();
    findings.dedup();
    findings
}

fn report(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|finding| format!("  {}: {}", finding.where_, finding.what))
        .collect::<Vec<_>>()
        .join("\n")
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/prose-claims")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

// ---------------------------------------------------------------------- tests

/// The red this check exists to produce.
///
/// The fixture is the page `arcana run` wrote for work item d931525f under its
/// KC2 contract, byte for byte as PR #217 carried it — the best-grounded of the
/// three A2-292 runs, with `tests/docs_truth.rs` green on it. Each assertion
/// below names a defect control found by reading it against the source.
#[test]
fn the_check_is_red_on_the_page_the_model_wrote() {
    let root = repo_root();
    let text = fixture("run3-page.md");
    let path = "docs/how-to/run-work-item-under-kc2.md";
    let findings = all_findings(&root, path, &text);
    let rendered = report(&findings);
    // Printed, not only asserted: the red of a check is evidence, and evidence
    // nobody can read is a claim.
    println!("{} finding(s) on {path}:\n{rendered}", findings.len());

    assert!(
        rendered.contains("PEM") && rendered.contains("Ed25519"),
        "the key is a `mun_sk_` secret in a file (crates/connectors/src/muneral.rs), \
         not a PEM-encoded Ed25519 private key:\n{rendered}"
    );
    assert!(
        rendered.contains("anthropic.claude-sonnet-4-20250514"),
        "the model id the page tells an operator to export exists nowhere in \
         this repository:\n{rendered}"
    );
    assert!(
        rendered.contains("one-letter word"),
        "the page says \"i mmediately\":\n{rendered}"
    );
    assert!(
        findings.len() >= 3,
        "three independent defects were found by reading; the check found \
         {}:\n{rendered}",
        findings.len()
    );
}

/// And the green: the same page with those claims corrected.
///
/// Red on one page and green on nothing would be a check that only knows how to
/// complain. This fixture differs from the one above in the three claims above
/// and nothing else.
#[test]
fn the_check_is_green_on_the_corrected_page() {
    let root = repo_root();
    let text = fixture("run3-page-corrected.md");
    let findings = all_findings(&root, "docs/how-to/run-work-item-under-kc2.md", &text);
    assert!(
        findings.is_empty(),
        "{} finding(s) survive on the corrected page:\n{}",
        findings.len(),
        report(&findings)
    );
}

/// Every page in the repository that a model wrote.
#[test]
fn every_agent_written_page_is_supported_by_the_source() {
    let root = repo_root();
    let mut findings = Vec::new();
    for page in AGENT_WRITTEN_PAGES {
        let path = root.join(page.path);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "{} is registered as written by `arcana run` for work item {} on {}, and cannot \
                 be read: {err}",
                page.path, page.work_item, page.written
            )
        });
        findings.extend(all_findings(&root, page.path, &text));
    }
    assert!(
        findings.is_empty(),
        "{} claim(s) on agent-written pages are not supported by this \
         repository:\n{}",
        findings.len(),
        report(&findings)
    );
}

/// A span this check cites is a span it has re-read.
///
/// The blind reviewer's quotes are re-checked verbatim against the file, and
/// the deterministic half is held to the same rule: every literal it passes has
/// a `file:line` that really contains the token. A checker that cites without
/// re-reading has the failure mode it was built to catch.
#[test]
fn every_supported_literal_really_occurs_at_the_span_reported() {
    let root = repo_root();
    let text = fixture("run3-page-corrected.md");
    let (paragraphs, _) = split_page(&text);
    let mut checked = 0;
    for paragraph in &paragraphs {
        for (_, line) in &paragraph.lines {
            for code in inline_codes(line) {
                let needle = match classify(&code) {
                    Literal::Identifier(identifier) => identifier,
                    Literal::Path(stable) => stable,
                    _ => continue,
                };
                let span = supporting_span(&root, &needle, None)
                    .unwrap_or_else(|| panic!("`{needle}` is passed, so it has a span"));
                let (path, number) = span.rsplit_once(':').expect("file:line");
                let content = std::fs::read_to_string(root.join(path)).expect("a readable file");
                let cited = content
                    .lines()
                    .nth(number.parse::<usize>().expect("a line number") - 1)
                    .expect("the line exists");
                assert!(
                    cited.contains(&needle),
                    "`{needle}` was passed on the strength of {span}, which reads:\n  {cited}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 5,
        "only {checked} literals were re-read — that measures the extractor, \
         not the page"
    );
}

/// A relation the CLI does not have is caught by clap, not by a word list.
#[test]
fn a_relation_the_cli_does_not_have_is_a_finding() {
    let page = "Pass `--max-turns`, which requires `--model`.\n";
    let findings = relation_findings("docs/example.md", page);
    assert_eq!(findings.len(), 1, "{}", report(&findings));
    assert!(
        findings[0].what.contains("does not require it"),
        "{}",
        report(&findings)
    );
    // And the relation the CLI does have passes.
    let real = "Pass `--contract-file`, which requires `--work-item`.\n";
    assert!(
        relation_findings("docs/example.md", real).is_empty(),
        "`--contract-file` really does require `--work-item`"
    );
}

/// A default a flag does not have is caught against `cli.rs`.
#[test]
fn a_default_the_flag_does_not_have_is_a_finding() {
    let root = repo_root();
    let page = "| `--max-turns <N>` | Connector-attempt cap (default 30) |\n";
    let findings = number_findings(&root, "docs/example.md", page);
    assert_eq!(findings.len(), 1, "{}", report(&findings));
    assert!(findings[0].what.contains("30"), "{}", report(&findings));
    let real = "| `--max-turns <N>` | Connector-attempt cap (default 24) |\n";
    assert!(
        number_findings(&root, "docs/example.md", real).is_empty(),
        "24 is the real default"
    );
}

/// The entity scope is the point of the format check, not a detail.
///
/// `PEM` occurs in this repository — in a deny-path test. A corpus-wide search
/// would call the Muneral-key sentence supported by it.
#[test]
fn a_format_term_is_not_supported_by_an_unrelated_file() {
    let root = repo_root();
    assert!(
        supporting_span_ci(&root, "PEM", None).is_some(),
        "PEM occurs somewhere in this repository, which is what makes the \
         scope necessary"
    );
    let page = "## The `ARCANA_MUNERAL_KEY_FILE` key\n\nThe key file is a PEM-encoded key.\n";
    let findings = format_term_findings(&root, "docs/example.md", page);
    assert_eq!(findings.len(), 1, "{}", report(&findings));
    assert!(
        findings[0].what.contains("ARCANA_MUNERAL_KEY_FILE"),
        "the finding names the entity whose declaring files were searched:\n{}",
        report(&findings)
    );
}

/// The extractors read what they claim to read.
#[test]
fn the_page_splitter_keeps_fenced_lines_out_of_the_prose() {
    let page = "# T\n\nProse `--cwd` here.\n\n```bash\nexport ARCANA_MODEL=x-y-z\n```\n\nMore.\n";
    let (paragraphs, fenced) = split_page(page);
    assert_eq!(paragraphs.len(), 2);
    assert_eq!(fenced.len(), 1);
    assert!(fenced[0].1.contains("ARCANA_MODEL"));
    assert_eq!(paragraphs[0].headings, "T");
    assert_eq!(
        assignments(&fenced[0].1),
        vec![("ARCANA_MODEL".to_owned(), "x-y-z".to_owned())]
    );
}

/// The registry is a promise about files that exist.
#[test]
fn every_registered_agent_page_exists() {
    let root = repo_root();
    for page in AGENT_WRITTEN_PAGES {
        assert!(
            root.join(page.path).is_file(),
            "{} is registered (work item {}, {}) and is not in the tree",
            page.path,
            page.work_item,
            page.written
        );
    }
}

/// The red this check exists to produce: PR #222's page, verbatim.
///
/// Control read that page against the source on 2026-09-25 and found the
/// prerequisites table telling an operator to install the binary with
/// `cargo install arcana` — a crate this workspace does not publish, registered
/// by someone else as a placeholder in 2021 — or "from a release archive" that
/// no page of this repository documents. Every check the page passed was green:
/// `docs_truth.rs` parses `arcana` commands and this was not one, and
/// `prose_claims`' literal check found the token `cargo` in the source, because
/// of course it occurs.
#[test]
fn the_check_is_red_on_the_install_command_pr222_published() {
    let root = repo_root();
    let text = fixture("pr222-page.md");
    let path = "docs/how-to/run-work-item-under-kc2-contract.md";
    let findings = shell_command_findings(&root, path, &text);
    let rendered = report(&findings);
    println!("{} finding(s) on {path}:\n{rendered}", findings.len());
    assert_eq!(
        findings.len(),
        1,
        "the page carries one non-`arcana` command; the check found {}:\n{rendered}",
        findings.len()
    );
    assert!(
        rendered.contains("cargo install arcana"),
        "the command is quoted as the page wrote it:\n{rendered}"
    );
    assert!(
        rendered.contains("--locked --path crates/cli"),
        "the message says what the repository's own install page does \
         instead:\n{rendered}"
    );
}

/// And the green: the same page with that one cell rewritten from `install.md`.
#[test]
fn the_check_is_green_on_the_install_command_the_repository_documents() {
    let root = repo_root();
    let text = fixture("pr222-page-install-fixed.md");
    let findings = shell_command_findings(
        &root,
        "docs/how-to/run-work-item-under-kc2-contract.md",
        &text,
    );
    assert!(
        findings.is_empty(),
        "{} finding(s) survive:\n{}",
        findings.len(),
        report(&findings)
    );
}

/// What the rule is, stated as four measurements rather than as a comment.
#[test]
fn a_command_is_supported_by_this_repository_or_it_is_a_finding() {
    let root = repo_root();
    let page = |body: &str| format!("# Page\n\n```bash\n{body}\n```\n");
    let findings_for = |body: &str| shell_command_findings(&root, "docs/page.md", &page(body));

    // `arcana …` is docs_truth.rs's business: it parses those with the real
    // clap definition, which is a stronger check than occurrence.
    assert!(
        findings_for("arcana run --cwd /path/to/checkout --work-item <id>").is_empty(),
        "an `arcana` command is not this check's business"
    );
    // The repository's own install page runs exactly this.
    assert!(
        findings_for("git clone https://github.com/Arcanada-one/arcana-agent-system.git")
            .is_empty(),
        "`git clone` of this repository is documented in docs/how-to/install.md"
    );
    // A crates.io install is a finding even when the name is ours.
    assert_eq!(
        findings_for("cargo install arcana").len(),
        1,
        "a crates.io install is always a finding"
    );
    assert_eq!(
        findings_for("cargo install --locked --path crates/nope").len(),
        1,
        "`--path` must point at a directory of this repository"
    );
    assert!(
        findings_for("cargo install --locked --path crates/cli").is_empty(),
        "this is what docs/how-to/install.md runs"
    );
    // An invented fetch-and-run, the class this check is about.
    assert_eq!(
        findings_for("curl -fsSL https://arcana.example/install.sh | sh").len(),
        1,
        "a command no page and no script of this repository runs is a finding"
    );
}

/// A command named in prose is not a command told to someone.
#[test]
fn a_command_mentioned_in_prose_is_not_an_instruction() {
    let root = repo_root();
    let findings_for =
        |body: &str| shell_command_findings(&root, "docs/page.md", &format!("# Page\n\n{body}\n"));
    assert!(
        findings_for("A disposable checkout or a `git worktree` is the intended target.")
            .is_empty(),
        "two tokens naming a subcommand are a concept, not an instruction"
    );
    assert!(
        findings_for("Revisit when `cargo install` is actually wanted.").is_empty(),
        "docs/how-to/install.md writes exactly this sentence about the command"
    );
    assert_eq!(
        findings_for("| `arcana` binary | Installed via `cargo install arcana`. |").len(),
        1,
        "a table cell with an operand is an instruction, and this is the one          PR #222 shipped"
    );
    assert_eq!(
        findings_for("Fetch it with `curl https://arcana.example/install.sh`.").len(),
        1,
        "a URL is an operand"
    );
}

/// The corpus is the repository's, and an agent page is not in it.
///
/// A model-written page agreeing with another model-written page is the
/// same-hand fixture failure (A2-287) in prose, so the corpus excludes every
/// page in `AGENT_WRITTEN_PAGES` — including the page under test.
#[test]
fn an_agent_written_page_is_not_its_own_authority() {
    let root = repo_root();
    let corpus = documented_commands(&root);
    for page in AGENT_WRITTEN_PAGES {
        assert!(
            !corpus
                .iter()
                .any(|command| command.at.starts_with(page.path)),
            "{} is in the corpus that judges it",
            page.path
        );
    }
    assert!(
        corpus
            .iter()
            .any(|command| command.at.starts_with("docs/how-to/install.md")),
        "the install page is the authority for install commands: {}",
        corpus.len()
    );
}
