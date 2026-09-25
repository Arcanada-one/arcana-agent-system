//! Docs truth: an `arcana` command line printed in our documentation is parsed
//! by the CLI's REAL clap definition, and an environment variable named in a
//! fenced block exists somewhere outside the docs.
//!
//! Why this exists. PR #214 shipped `docs/how-to/run-work-item-under-kc2-contract.md`,
//! written end to end by the agent under its KC2 contract. It was reviewed as
//! an artefact — the page exists, on the path the model named — and every check
//! in CI was green. Read against `crates/cli/src/cli.rs` it names a binary
//! `aras` (it is `arcana`), a flag `--contract` (it is `--contract-file`, and it
//! requires `--work-item`), a flag `--item` (it is `--work-item`), and two
//! environment variables, `KC2_CONTRACT` and `KC2_SNAPSHOT`, that exist nowhere
//! in this repository. "The page was written" and "the page is true" are
//! different measurements, and we had only the first (A2-292).
//!
//! What it is NOT. Nothing here judges prose, and nothing here judges printed
//! OUTPUT: a fenced block showing an invented success line is invisible to a
//! parser. It judges the one class of claim a machine can settle — that a
//! command line we tell an operator to type is a command line this binary
//! accepts, and that a variable we tell them to set is a name that occurs in
//! the program.
//!
//! The check is only as truthful as the definition it parses with, which is why
//! `Cli` was moved out of `main.rs` into the library: a second copy of the
//! surface in a test would drift, and a drifting copy would have accepted
//! `--contract` too.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use arcana_cli::cli::Cli;
use clap::Parser;

/// Markdown that is documentation for an operator, and therefore held to this.
///
/// `docs/` is the Diataxis tree; `README.md` is the front door and carries a
/// dozen invocations of its own. `CHANGELOG.md` and `docs/origin/` narrative
/// are excluded: the first records what past versions did (an old flag spelled
/// correctly for its release is not a defect today), the second is a record of
/// conversations, not instructions.
const SCANNED_ROOTS: &[&str] = &["docs", "README.md"];

/// Paths under `SCANNED_ROOTS` that are not instructions to an operator.
const SCAN_EXCLUDED: &[&str] = &["docs/origin"];

/// Names this tool is called in prose but has never had as a binary.
///
/// `aras` is the repository's abbreviation and the name #214's page used in
/// every one of its eleven command lines. Without this list the parse check
/// would pass that page in silence: it looks for `arcana` invocations, and
/// there were none — the page never mentioned the binary at all.
const WRONG_BINARY_NAMES: &[&str] = &[
    "aras",
    "arcana-agent",
    "arcana-agent-system",
    "arcana-cli",
    "arcanada",
];

/// The binary this CLI actually installs as.
const BINARY: &str = "arcana";

/// This file, as a path suffix. Excluded from the source corpus below.
const SELF_PATH: &str = "crates/cli/tests/docs_truth.rs";

/// A variable named in a fenced block that is deliberately not required to
/// occur in the program.
///
/// Every entry is a shell variable the doc's own script assigns and uses inside
/// the same block — a local of an example, not configuration of `arcana`. They
/// are listed one by one, dated, and asserted to still be reachable
/// (`every_environment_allowance_is_still_used`), because an allowance nobody
/// can see is the same thing as a check nobody runs.
const ENV_ALLOWANCES: &[Allowance] = &[
    Allowance {
        file: "docs/how-to/credential-incident-recovery.md",
        var: "VAULT_IP",
        since: "2026-09-24",
        reason: "key of the broker's private config file, parsed by the script in the same block",
    },
    Allowance {
        file: "docs/how-to/credential-incident-recovery.md",
        var: "VAULT_NODE_KEY",
        since: "2026-09-24",
        reason: "key of the broker's private config file, parsed by the script in the same block",
    },
    Allowance {
        file: "docs/how-to/credential-incident-recovery.md",
        var: "VAULT_DNS",
        since: "2026-09-24",
        reason: "key of the broker's private config file, parsed by the script in the same block",
    },
    Allowance {
        file: "docs/how-to/credential-incident-recovery.md",
        var: "VAULT_VERSION",
        since: "2026-09-24",
        reason: "key of the broker's private config file, parsed by the script in the same block",
    },
    Allowance {
        file: "docs/how-to/credential-incident-recovery.md",
        var: "VAULT_MOUNT",
        since: "2026-09-24",
        reason: "key of the broker's private config file, parsed by the script in the same block",
    },
    Allowance {
        file: "docs/how-to/credential-incident-recovery.md",
        var: "VAULT_SECRET_PATH",
        since: "2026-09-24",
        reason: "key of the broker's private config file, parsed by the script in the same block",
    },
    Allowance {
        file: "docs/how-to/deployment.md",
        var: "BROKER",
        since: "2026-09-24",
        reason: "shell local holding the staged lifecycle script path in the same block",
    },
    Allowance {
        file: "docs/how-to/install.md",
        var: "TAG",
        since: "2026-09-24",
        reason: "shell local of the download example in the same block",
    },
    Allowance {
        file: "README.md",
        var: "TAG",
        since: "2026-09-24",
        reason: "shell local of the download example in the same block",
    },
];

struct Allowance {
    file: &'static str,
    var: &'static str,
    since: &'static str,
    reason: &'static str,
}

/// One fenced block, with the line numbers its content had in the file.
///
/// The info string (` ```bash `) is deliberately NOT kept: the two lines in
/// `docs/reference/mcp-server.md` that invoke this CLI sit in a block with no
/// language at all, and half the shell in this repository's documentation is in
/// an unlabelled fence. Filtering on the label would have made this check blind
/// to exactly the pages that need it.
struct Block {
    lines: Vec<(usize, String)>,
}

/// A command line found in a fenced block.
struct Invocation {
    /// The command word as written — `arcana`, or one of the wrong names.
    name: String,
    /// Arguments, already unquoted, up to the first pipe / redirect / comment.
    args: Vec<String>,
    /// `NAME=value` prefixes that precede the command word.
    env_prefix: Vec<String>,
    line: usize,
    raw: String,
}

/// A defect, as the test reports it.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    where_: String,
    what: String,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root is two levels above this crate")
}

/// Every markdown file in scope, in a stable order.
fn scanned_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in SCANNED_ROOTS {
        let path = root.join(entry);
        if path.is_file() {
            out.push(path);
        } else if path.is_dir() {
            collect_markdown(root, &path, &mut out);
        } else {
            panic!("scanned root {} does not exist", path.display());
        }
    }
    out.sort();
    assert!(
        out.len() > 5,
        "the scan found almost nothing ({} files) — a check that reads no \
         input is green for the wrong reason",
        out.len()
    );
    out
}

fn collect_markdown(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let excluded = |path: &Path| {
        let relative = relative(root, path);
        SCAN_EXCLUDED
            .iter()
            .any(|prefix| relative == *prefix || relative.starts_with(&format!("{prefix}/")))
    };
    if excluded(dir) {
        return;
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", dir.display()))
        .map(|entry| entry.expect("a readable directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_markdown(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "md") && !excluded(&path) {
            out.push(path);
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// An open fence: its character, its length, and the content so far.
type OpenFence = (char, usize, Vec<(usize, String)>);

/// Split markdown into fenced blocks.
///
/// A fence is three or more backticks or tildes; the closing fence is the same
/// character, at least as long, and carries no info string. Anything else that
/// looks like a fence inside a block (a nested example) stays content.
fn fenced_blocks(text: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut open: Option<OpenFence> = None;
    for (number, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        let trimmed = line.trim_start();
        let fence_char = trimmed.chars().next().filter(|c| *c == '`' || *c == '~');
        let run = fence_char.map_or(0, |c| trimmed.chars().take_while(|ch| *ch == c).count());
        let info = if run >= 3 { trimmed[run..].trim() } else { "" };
        match open.as_mut() {
            None => {
                if run >= 3 {
                    open = Some((
                        fence_char.expect("a run implies its character"),
                        run,
                        Vec::new(),
                    ));
                }
            }
            Some((open_char, open_run, content)) => {
                let closes = run >= *open_run && fence_char == Some(*open_char) && info.is_empty();
                if closes {
                    blocks.push(Block {
                        lines: std::mem::take(content),
                    });
                    open = None;
                } else {
                    content.push((number, line.to_owned()));
                }
            }
        }
    }
    // An unterminated fence is a malformed document, not a silent pass: what it
    // opened is still scanned.
    if let Some((_, _, content)) = open {
        blocks.push(Block { lines: content });
    }
    blocks
}

/// Join trailing-backslash continuations into logical lines, keeping the line
/// number the logical line STARTS on.
fn logical_lines(block: &Block) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (number, raw) in &block.lines {
        let trimmed = raw.trim();
        let (text, continues) = match trimmed.strip_suffix('\\') {
            Some(head) => (head.trim_end(), true),
            None => (trimmed, false),
        };
        match pending.take() {
            Some((start, mut acc)) => {
                acc.push(' ');
                acc.push_str(text);
                if continues {
                    pending = Some((start, acc));
                } else {
                    out.push((start, acc));
                }
            }
            None => {
                if continues {
                    pending = Some((*number, text.to_owned()));
                } else {
                    out.push((*number, text.to_owned()));
                }
            }
        }
    }
    if let Some((start, acc)) = pending {
        out.push((start, acc));
    }
    out
}

/// Tokenize one logical line the way a reader would type it.
///
/// Stops at the first unquoted pipe, semicolon, ampersand, redirect or comment:
/// what follows is another command, not an argument of this one. `<WORD>` and
/// `[WORD]` are documentation placeholders, not redirects and not arguments —
/// the angle brackets are kept in the token, the square brackets are dropped,
/// so `arcana demo [TASK]` is checked as `arcana demo TASK` and
/// `arcana mcp serve [--bind ADDR]` still checks `--bind`.
fn tokenize(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut index = 0;
    let push = |tokens: &mut Vec<String>, current: &mut String| {
        if !current.is_empty() {
            tokens.push(std::mem::take(current));
        }
    };
    while index < chars.len() {
        let c = chars[index];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                current.push(c);
            }
            index += 1;
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            ' ' | '\t' => push(&mut tokens, &mut current),
            '#' if current.is_empty() => break,
            // Another command, or a redirect: what follows is not an argument
            // of this one.
            '|' | ';' | '&' | '>' => break,
            '<' => {
                // `<<` is a heredoc; `<WORD>` is a placeholder; a lone `<` is a
                // redirect.
                let rest: String = chars[index..].iter().collect();
                if rest.starts_with("<<") {
                    break;
                }
                let placeholder = rest
                    .strip_prefix('<')
                    .and_then(|r| r.find('>').map(|end| &r[..end]))
                    .is_some_and(|inner| {
                        !inner.is_empty()
                            && inner
                                .chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
                    });
                if placeholder {
                    current.push(c);
                } else {
                    break;
                }
            }
            '[' if current.is_empty() => {}
            ']' => {}
            _ => current.push(c),
        }
        index += 1;
    }
    push(&mut tokens, &mut current);
    tokens
}

/// Read one command line out of a logical line, or decide it is not one.
fn parse_command(number: usize, line: &str) -> Option<Invocation> {
    let mut text = line.trim();
    for prompt in ["$ ", "% ", "# "] {
        if let Some(rest) = text.strip_prefix(prompt) {
            text = rest.trim_start();
        }
    }
    let mut tokens = tokenize(text);
    if tokens.is_empty() {
        return None;
    }
    // `env FOO=1 arcana …`
    if tokens.first().is_some_and(|t| t == "env") {
        tokens.remove(0);
    }
    let mut env_prefix = Vec::new();
    while let Some(first) = tokens.first() {
        let Some((name, _)) = first.split_once('=') else {
            break;
        };
        if name.is_empty()
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || name.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            break;
        }
        env_prefix.push(name.to_owned());
        tokens.remove(0);
    }
    let name = tokens.first()?.clone();
    if name != BINARY && !WRONG_BINARY_NAMES.contains(&name.as_str()) {
        return None;
    }
    // Our own diagnostics are printed as `arcana run: <message>`, and a doc
    // that shows one is quoting OUTPUT. A parser cannot judge output, and
    // treating it as an invocation would make every error-message example a
    // finding. Recognized narrowly: the colon must be attached to the command
    // word or the word right after it.
    if tokens.iter().take(2).any(|token| token.ends_with(':')) {
        return None;
    }
    Some(Invocation {
        name,
        args: tokens[1..].to_vec(),
        env_prefix,
        line: number,
        raw: text.to_owned(),
    })
}

/// Every invocation candidate in one document.
fn invocations(text: &str) -> Vec<Invocation> {
    let mut out = Vec::new();
    for block in fenced_blocks(text) {
        for (number, line) in logical_lines(&block) {
            if let Some(invocation) = parse_command(number, &line) {
                out.push(invocation);
            }
        }
    }
    out
}

/// Every `NAME=` occurrence inside fenced blocks, with the line it sits on and
/// whether it prefixes a command (rather than standing alone as a shell local).
fn env_assignments(text: &str) -> Vec<(usize, String, bool)> {
    let mut out = Vec::new();
    for block in fenced_blocks(text) {
        for (number, line) in logical_lines(&block) {
            let prefixes: BTreeSet<String> = parse_command(number, &line)
                .map(|invocation| invocation.env_prefix.into_iter().collect())
                .unwrap_or_default();
            for name in assignment_names(&line) {
                let prefixes_command = prefixes.contains(&name);
                out.push((number, name, prefixes_command));
            }
        }
    }
    out
}

/// `NAME=` where NAME is an upper-case identifier at a token boundary.
///
/// Upper-case only, and at least three characters: a lower-case `path=…` in an
/// example is a field, not an environment variable, and `x=1` is arithmetic.
fn assignment_names(line: &str) -> Vec<String> {
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
                out.push(name);
                index = end + 1;
                continue;
            }
            index = end.max(index + 1);
            continue;
        }
        index += 1;
    }
    out
}

/// The program, as text: everything outside the documentation.
///
/// "Appears in the source" is deliberately generous — a variable read by a
/// shell helper, a workflow or a manifest counts, not just Rust. What it
/// refuses is a name that occurs NOWHERE but the page telling an operator to
/// set it.
fn source_corpus(root: &Path) -> &'static str {
    static CORPUS: OnceLock<String> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut text = String::new();
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
                // `SELF_PATH` is skipped: measured, not foreseen — with this
                // file in the corpus, `KC2_CONTRACT` "occurred in the source",
                // in the assertion complaining that it does not, and every
                // allowance below was reported stale for the same reason. A
                // checker that reads its own text as evidence confirms whatever
                // it is asked about.
                } else if !path.ends_with(SELF_PATH)
                    && path
                        .extension()
                        .is_some_and(|ext| extensions.iter().any(|e| ext == *e))
                {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        text.push_str(&content);
                        text.push('\n');
                    }
                }
            }
        }
        assert!(
            text.len() > 100_000,
            "the source corpus is {} bytes — too small to be this repository, \
             so 'the name is nowhere in the source' would be vacuously true",
            text.len()
        );
        text
    })
}

fn mentioned_in_source(root: &Path, name: &str) -> bool {
    let corpus = source_corpus(root);
    corpus.match_indices(name).any(|(at, _)| {
        let before = corpus[..at].chars().next_back();
        let after = corpus[at + name.len()..].chars().next();
        let identifier = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        !identifier(before) && !identifier(after)
    })
}

/// Parse every invocation in one document and report what fails.
fn parse_findings(path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for invocation in invocations(text) {
        let at = format!("{path}:{}", invocation.line);
        if invocation.name != BINARY {
            findings.push(Finding {
                where_: at.clone(),
                what: format!(
                    "the binary is `{BINARY}`, not `{}` — `{}`",
                    invocation.name, invocation.raw
                ),
            });
            // Still parse the arguments: a page with the wrong name usually has
            // more than one thing wrong with it, and reporting them together is
            // the difference between one fix and three rounds.
        }
        let argv = std::iter::once(BINARY.to_owned()).chain(invocation.args.iter().cloned());
        if let Err(err) = Cli::try_parse_from(argv) {
            // The whole message, folded onto one line. Clap puts "the following
            // required arguments were not provided:" on the first line and the
            // NAME of the missing argument on the next one, so a first-line-only
            // message would report the `--contract-file` / `--work-item`
            // relation without ever naming `--work-item`.
            let message = err
                .to_string()
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with("For more information"))
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_owned();
            findings.push(Finding {
                where_: at,
                what: format!("`{}` — {message}", invocation.raw),
            });
        }
    }
    findings
}

fn env_findings(root: &Path, path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (line, name, prefixes_command) in env_assignments(text) {
        if mentioned_in_source(root, &name) {
            continue;
        }
        let allowed = ENV_ALLOWANCES
            .iter()
            .any(|allowance| allowance.file == path && allowance.var == name);
        if allowed && !prefixes_command {
            continue;
        }
        let note = if prefixes_command {
            " (it is set for an `arcana` invocation, so no allowance applies)"
        } else {
            ""
        };
        findings.push(Finding {
            where_: format!("{path}:{line}"),
            what: format!("`{name}=` occurs nowhere in the source{note}"),
        });
    }
    findings
}

fn report(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|finding| format!("  {}: {}", finding.where_, finding.what))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_cli_invocation_in_the_docs_parses_with_the_real_definition() {
    let root = repo_root();
    let mut findings = Vec::new();
    let mut checked = 0;
    for path in scanned_files(&root) {
        let text = std::fs::read_to_string(&path).expect("a readable document");
        let relative = relative(&root, &path);
        checked += invocations(&text).len();
        findings.extend(parse_findings(&relative, &text));
    }
    assert!(
        checked >= 10,
        "only {checked} invocations were found in the documentation — the \
         extractor, not the documentation, is what that measures"
    );
    assert!(
        findings.is_empty(),
        "{} command line(s) in the documentation are not command lines this \
         binary accepts:\n{}",
        findings.len(),
        report(&findings)
    );
}

#[test]
fn every_environment_variable_in_the_docs_exists_in_the_source() {
    let root = repo_root();
    let mut findings = Vec::new();
    for path in scanned_files(&root) {
        let text = std::fs::read_to_string(&path).expect("a readable document");
        let relative = relative(&root, &path);
        findings.extend(env_findings(&root, &relative, &text));
    }
    assert!(
        findings.is_empty(),
        "{} environment variable(s) are named in a fenced block and occur \
         nowhere in the program:\n{}\nFix the page, or add a dated entry to \
         ENV_ALLOWANCES saying why the name is a local of the example.",
        findings.len(),
        report(&findings)
    );
}

/// The check, run against the page that motivated it, unedited.
///
/// This is the red this test exists to produce. The fixture is PR #214's
/// `docs/how-to/run-work-item-under-kc2-contract.md` byte for byte, and the
/// assertions below name each defect a human reviewer found by reading it
/// against `cli.rs`. A checker that cannot be shown failing is a checker
/// nobody has measured.
#[test]
fn the_check_is_red_on_the_page_that_motivated_it() {
    let root = repo_root();
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/docs-truth/pr-214-page.md");
    let text = std::fs::read_to_string(&fixture).expect("the #214 page fixture");
    let path = "docs/how-to/run-work-item-under-kc2-contract.md";

    let parse = parse_findings(path, &text);
    let rendered = report(&parse);
    assert!(
        parse.len() >= 8,
        "the page carries eleven command lines, all of them wrong; the check \
         found {}:\n{rendered}",
        parse.len()
    );
    assert!(
        rendered.contains("the binary is `arcana`, not `aras`"),
        "the wrong binary name is the first thing a reader would hit:\n{rendered}"
    );
    assert!(
        rendered.contains("--contract"),
        "`--contract` is not a flag of this CLI:\n{rendered}"
    );
    assert!(
        rendered.contains("--item"),
        "`--item` is not a flag of this CLI:\n{rendered}"
    );

    let env = env_findings(&root, path, &text);
    let rendered_env = report(&env);
    for name in ["KC2_CONTRACT", "KC2_SNAPSHOT"] {
        assert!(
            rendered_env.contains(name),
            "{name} exists nowhere in this repository:\n{rendered_env}"
        );
        assert!(
            !mentioned_in_source(&root, name),
            "{name} now occurs in the source, so this fixture no longer \
             demonstrates the defect it was recorded for"
        );
    }
    assert!(
        rendered_env.contains("no allowance applies"),
        "both names are set as the prefix of an invocation, which no allowance \
         can excuse:\n{rendered_env}"
    );
}

/// A correct page passes.
///
/// Red on the real page and green on nothing would be a check that only knows
/// how to complain. This is the same scanner over a page written against
/// `cli.rs`: the flags are the real ones, in the real spellings, including the
/// `--contract-file` that requires `--work-item`.
#[test]
fn the_check_is_green_on_a_page_whose_commands_are_real() {
    let root = repo_root();
    let page = "\
# Example

```bash
arcana run --cwd /tmp/wt --work-item d931525f --contract-file ./contract.json
```

```bash
ARCANA_MUNERAL_KEY_FILE=/run/secrets/key \\
  ARCANA_MODEL=deepseek-v4-flash \\
  arcana run --cwd /tmp/wt --work-item d931525f --max-cost-usd 0.50
```

```
arcana run: CONTRACT_MISSING: the work item names no contract
```
";
    let parse = parse_findings("docs/example.md", page);
    assert!(parse.is_empty(), "{}", report(&parse));
    let env = env_findings(&root, "docs/example.md", page);
    assert!(env.is_empty(), "{}", report(&env));
}

/// `--contract-file` without `--work-item` must be caught.
///
/// The one defect on #214's page that is not a spelling: clap's `requires`
/// relation. A check that only compared flag names to a list would pass it.
#[test]
fn a_real_flag_used_without_the_flag_it_requires_is_a_finding() {
    let page = "```bash\narcana run --cwd /tmp/wt --contract-file ./contract.json\n```\n";
    let findings = parse_findings("docs/example.md", page);
    assert_eq!(
        findings.len(),
        1,
        "exactly one finding expected:\n{}",
        report(&findings)
    );
    assert!(
        findings[0].what.contains("--work-item"),
        "the message names the flag that is missing:\n{}",
        report(&findings)
    );
}

/// An allowance that no longer excuses anything is deleted, not kept.
#[test]
fn every_environment_allowance_is_still_used() {
    let root = repo_root();
    let mut stale = Vec::new();
    for allowance in ENV_ALLOWANCES {
        let path = root.join(allowance.file);
        let used = std::fs::read_to_string(&path).is_ok_and(|text| {
            env_assignments(&text)
                .iter()
                .any(|(_, name, _)| name == allowance.var)
        }) && !mentioned_in_source(&root, allowance.var);
        if !used {
            stale.push(format!(
                "  {} / {} (since {}: {})",
                allowance.file, allowance.var, allowance.since, allowance.reason
            ));
        }
    }
    assert!(
        stale.is_empty(),
        "{} allowance(s) excuse nothing any more — delete them:\n{}",
        stale.len(),
        stale.join("\n")
    );
}
