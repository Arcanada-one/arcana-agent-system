//! Printed output: a line our documentation shows this program printing is a
//! line this program can print.
//!
//! Why this exists. `docs_truth.rs` parses every COMMAND in the docs with the
//! real clap definition and says, in its own module doc, that printed OUTPUT is
//! out of its scope. A2-292 measured what that hole costs: the first live run
//! of work item d931525f wrote a page whose refusal example read
//!
//! ```text
//! Error: CONTRACT_MISSING: the work item names no contract
//! ```
//!
//! while every build of this program prints `arcana run: CONTRACT_MISSING: …`
//! and, on the next line, the done-marker. The page's commands were real, so
//! `docs_truth.rs` was green; nothing looked at the two lines an operator would
//! actually grep for. The page was withheld by hand, which is a review, not a
//! check.
//!
//! How it judges. Not by a second spelling of the format: by calling the
//! functions that print it. [`refusal_line`] and [`refusal_marker`] are the
//! ones `refuse()` calls, and [`done_marker_body`] is the one every run's last
//! line comes from — a documented line is reconstructed from its own code and
//! detail and compared to what they return. A copy of the format in this file
//! would drift from the program, and a drifted copy passes exactly the kind of
//! line this test exists to catch.
//!
//! What it is NOT. It does not judge prose (`prose_claims.rs`), and it does not
//! invent a vocabulary of refusal codes: the codes come out of the source, from
//! the `refuse("…")` call sites and the `code()` functions that name them.
//! A line carrying a SCREAMING_SNAKE token that is not one of those is only a
//! finding when the page prints it as this program's own diagnostic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use arcana_cli::run::{done_marker_body, DoneMarker, DONE_MARKER};
use arcana_cli::work_item::{refusal_line, refusal_marker};
use arcana_core::contract::{ContractRefusal, DigestPreimage};

/// Markdown held to this — the same scope `docs_truth.rs` parses commands in.
const SCANNED_ROOTS: &[&str] = &["docs", "README.md"];

/// Narrative, not instructions: a record of conversations.
const SCAN_EXCLUDED: &[&str] = &["docs/origin"];

/// This file, as a path suffix. Excluded from the source scan below, so that
/// the invented code in a negative control does not become vocabulary and
/// excuse itself (the failure A2-292 hit twice with `mentioned_in_source`).
const SELF_PATH: &str = "crates/cli/tests/printed_output.rs";

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

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

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
        "the scan found {} files — a check that reads no input is green for \
         the wrong reason",
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

/// Every line inside a fenced block, with its line number.
///
/// A fence is three or more backticks or tildes; the block ends at the first
/// fence of the same character that is at least as long and carries no info
/// string. Only fenced content is judged: a refusal quoted in a sentence is
/// prose, and prose is `prose_claims.rs`'s business.
fn fenced_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut open: Option<(char, usize)> = None;
    for (number, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        let trimmed = line.trim_start();
        let fence_char = trimmed.chars().next().filter(|c| *c == '`' || *c == '~');
        let run = fence_char.map_or(0, |c| trimmed.chars().take_while(|ch| *ch == c).count());
        let info = if run >= 3 { trimmed[run..].trim() } else { "" };
        match open {
            None => {
                if run >= 3 {
                    open = Some((fence_char.expect("a run implies its character"), run));
                }
            }
            Some((open_char, open_run)) => {
                if run >= open_run && fence_char == Some(open_char) && info.is_empty() {
                    open = None;
                } else {
                    out.push((number, line.to_owned()));
                }
            }
        }
    }
    out
}

/// The refusal codes this program has, read out of the program.
///
/// Two shapes, both of them where a code is BORN: the literal argument of a
/// `refuse(…)` call, and the string a `code()` function returns for one of its
/// variants. A code that exists nowhere in either is a code no build prints.
fn refusal_codes(root: &Path) -> &'static BTreeSet<String> {
    static CODES: OnceLock<BTreeSet<String>> = OnceLock::new();
    CODES.get_or_init(|| {
        let mut codes = BTreeSet::new();
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
                } else if path.extension().is_some_and(|ext| ext == "rs")
                    && !path.ends_with(SELF_PATH)
                {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        collect_codes(&text, &mut codes);
                    }
                }
            }
        }
        assert!(
            codes.len() >= 6,
            "only {} refusal code(s) were found in the source — that measures \
             the scanner, not the program: {codes:?}",
            codes.len()
        );
        codes
    })
}

/// `refuse("CODE"` and `=> "CODE"` inside a `fn code(` body.
fn collect_codes(text: &str, out: &mut BTreeSet<String>) {
    for (index, _) in text.match_indices("refuse(") {
        if let Some(code) = quoted_after(&text[index + "refuse(".len()..]) {
            out.insert(code);
        }
    }
    let mut in_code_fn = false;
    let mut depth: i32 = 0;
    for line in text.lines() {
        if !in_code_fn {
            if line.contains("fn code(") {
                in_code_fn = true;
                depth = 0;
            } else {
                continue;
            }
        }
        depth += i32::try_from(line.matches('{').count()).unwrap_or(0);
        depth -= i32::try_from(line.matches('}').count()).unwrap_or(0);
        if let Some(rest) = line.split_once("=> ").map(|(_, rest)| rest) {
            if let Some(code) = quoted_after(rest) {
                out.insert(code);
            }
        }
        if depth <= 0 && line.contains('}') {
            in_code_fn = false;
        }
    }
}

/// The first `"…"` literal in `text`, when it is SCREAMING_SNAKE.
fn quoted_after(text: &str) -> Option<String> {
    let start = text.find('"')?;
    if text[..start].chars().any(|c| !c.is_whitespace()) {
        return None;
    }
    let rest = &text[start + 1..];
    let end = rest.find('"')?;
    let literal = &rest[..end];
    is_code(literal).then(|| literal.to_owned())
}

/// A SCREAMING_SNAKE token of at least five characters: `CONTRACT_MISSING`,
/// not `OK` and not `Contract`.
fn is_code(token: &str) -> bool {
    token.len() >= 5
        && token.contains('_')
        && token
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The keys every done-marker line really carries, taken from the writers.
fn done_marker_keys() -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let run = DoneMarker {
        completed: true,
        reason: "Completed",
        turns: 1,
        tool_calls: 1,
        tool_calls_attempted: 1,
        tool_calls_denied: 0,
        cost_usd_micros: 1,
        compactions: 0,
        root: Path::new("/tmp/arcana-printed-output"),
        error: None,
        effect: None,
    };
    for source in [
        done_marker_body(&run),
        marker_json(&refusal_marker("X_Y", "d")),
    ] {
        let value: serde_json::Value =
            serde_json::from_str(&source).expect("the writer emits one JSON object");
        keys.extend(
            value
                .as_object()
                .expect("an object")
                .keys()
                .map(ToOwned::to_owned),
        );
    }
    keys
}

/// The JSON of a done-marker line, marker prefix removed.
fn marker_json(line: &str) -> String {
    line.strip_prefix(DONE_MARKER)
        .unwrap_or(line)
        .trim()
        .to_owned()
}

/// Strip a shell prompt a page may have typed in front of the output.
fn without_prompt(line: &str) -> &str {
    let trimmed = line.trim();
    for prompt in ["$ ", "% "] {
        if let Some(rest) = trimmed.strip_prefix(prompt) {
            return rest.trim_start();
        }
    }
    trimmed
}

/// Split `head: CODE: detail`, or `CODE: detail` with no head.
fn split_diagnostic(line: &str) -> Option<(Option<&str>, &str, &str)> {
    let (first, rest) = line.split_once(": ")?;
    if is_code(first) {
        return Some((None, first, rest));
    }
    let (code, detail) = rest.split_once(": ")?;
    is_code(code).then_some((Some(first), code, detail))
}

fn findings(root: &Path, path: &str, text: &str) -> Vec<Finding> {
    let codes = refusal_codes(root);
    let keys = done_marker_keys();
    let mut findings = Vec::new();
    for (number, raw) in fenced_lines(text) {
        let at = || format!("{path}:{number}");
        let line = without_prompt(&raw);
        // A shell comment inside a block is prose that happens to be indented:
        // measured on `README.md`, whose synopsis explains the done-marker in a
        // trailing `#   ARCANA_RUN_DONE <json>, which reports tool_calls`. That
        // sentence is not a line the program prints, and reading it as one made
        // the check red on the repository's front page.
        if line.starts_with('#') {
            continue;
        }
        if line.contains(DONE_MARKER) {
            findings.extend(done_marker_findings(&at(), line, &keys));
            continue;
        }
        let Some((head, code, detail)) = split_diagnostic(line) else {
            continue;
        };
        let known = codes.contains(code);
        if known {
            let expected = refusal_line(code, detail);
            if line != expected {
                findings.push(Finding {
                    where_: at(),
                    what: format!(
                        "`{line}` is not how this program prints a refusal — \
                         `refuse()` prints `{expected}`"
                    ),
                });
            }
        } else if head == Some("arcana run") {
            findings.push(Finding {
                where_: at(),
                what: format!(
                    "`{code}` is not a refusal code this program has; the codes \
                     it prints are named in the source at their `refuse(…)` \
                     call sites"
                ),
            });
        }
    }
    findings
}

fn done_marker_findings(at: &str, line: &str, keys: &BTreeSet<String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !line.starts_with(DONE_MARKER) {
        findings.push(Finding {
            where_: at.to_owned(),
            what: format!(
                "`{DONE_MARKER}` is the first token of the line the program \
                 prints, and here it is not: `{line}`"
            ),
        });
        return findings;
    }
    let body = marker_json(line);
    // `ARCANA_RUN_DONE <json>` is how `cli.rs`'s own help text writes the
    // shape of the line rather than an instance of it. A placeholder in angle
    // brackets is that, and nothing else is: a page may say the line carries
    // JSON without inventing one.
    if body.starts_with('<') && body.ends_with('>') && !body[1..].contains('<') {
        return findings;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
        findings.push(Finding {
            where_: at.to_owned(),
            what: format!(
                "the done-marker is followed by text that is not one JSON object: `{body}`"
            ),
        });
        return findings;
    };
    let Some(object) = value.as_object() else {
        findings.push(Finding {
            where_: at.to_owned(),
            what: format!("the done-marker carries a JSON value that is not an object: `{body}`"),
        });
        return findings;
    };
    for key in object.keys() {
        if !keys.contains(key.as_str()) {
            findings.push(Finding {
                where_: at.to_owned(),
                what: format!("`{key}` is not a field of the done-marker this program writes"),
            });
        }
    }
    for required in ["completed", "reason"] {
        if !object.contains_key(required) {
            findings.push(Finding {
                where_: at.to_owned(),
                what: format!("the done-marker always carries `{required}`, and this one does not"),
            });
        }
    }
    // A refusal marker is fully determined by its code and detail: rebuild it
    // and compare. This is the half a key check cannot do — `"reason"` and
    // `"code"` disagreeing is a marker no `refuse()` ever wrote.
    if let Some(code) = object.get("code").and_then(serde_json::Value::as_str) {
        let detail = object
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let expected: serde_json::Value =
            serde_json::from_str(&marker_json(&refusal_marker(code, detail)))
                .expect("the writer emits JSON");
        if value != expected {
            findings.push(Finding {
                where_: at.to_owned(),
                what: format!(
                    "the done-marker of a `{code}` refusal is `{}`, not `{body}`",
                    marker_json(&refusal_marker(code, detail))
                ),
            });
        }
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

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/printed-output")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

#[test]
fn every_printed_line_in_the_docs_is_a_line_this_program_prints() {
    let root = repo_root();
    let mut findings = Vec::new();
    for path in scanned_files(&root) {
        let text = std::fs::read_to_string(&path).expect("a readable document");
        findings.extend(findings_for(&root, &relative(&root, &path), &text));
    }
    assert!(
        findings.is_empty(),
        "{} line(s) of printed output in the documentation are not lines this \
         program prints:\n{}",
        findings.len(),
        report(&findings)
    );
}

fn findings_for(root: &Path, path: &str, text: &str) -> Vec<Finding> {
    findings(root, path, text)
}

/// The red this check exists to produce: A2-292's first live page, verbatim.
///
/// Two lines, both invented, both green under every check that existed when the
/// page was written: a refusal printed with an `Error:` prefix this program has
/// never used, and a done-marker introduced by a word that is not the marker.
#[test]
fn the_check_is_red_on_the_output_the_first_live_run_invented() {
    let root = repo_root();
    let text = fixture("a2-292-run1-output.md");
    let findings = findings(&root, "docs/how-to/invented.md", &text);
    let rendered = report(&findings);
    assert!(
        findings.len() >= 3,
        "the fixture carries three invented lines; the check found {}:\n{rendered}",
        findings.len()
    );
    assert!(
        rendered
            .contains("arcana run: CONTRACT_MISSING: the work item has no contractDigest field"),
        "the message says what the program prints instead:\n{rendered}"
    );
    assert!(
        rendered.contains("is not a refusal code this program has"),
        "an invented code is named as such:\n{rendered}"
    );
    assert!(
        rendered.contains("is not a field of the done-marker"),
        "an invented done-marker field is named as such:\n{rendered}"
    );
}

/// Green on the real format — produced by the writers themselves.
#[test]
fn the_check_is_green_on_the_lines_the_writers_produce() {
    let root = repo_root();
    let refusal = refusal_line("CONTRACT_MISSING", "the work item names no contract");
    let marker = refusal_marker("CONTRACT_MISSING", "the work item names no contract");
    let run_marker = done_marker_body(&DoneMarker {
        completed: true,
        reason: "Completed",
        turns: 6,
        tool_calls: 5,
        tool_calls_attempted: 9,
        tool_calls_denied: 0,
        cost_usd_micros: 28133,
        compactions: 0,
        root: Path::new("/tmp/arcana-printed-output"),
        error: None,
        effect: None,
    });
    let page = format!("# Page\n\n```text\n{refusal}\n{marker}\n{DONE_MARKER} {run_marker}\n```\n");
    let findings = findings(&root, "docs/how-to/real.md", &page);
    assert!(findings.is_empty(), "{}", report(&findings));
}

/// A refusal quoted with the wrong prefix is a finding even when its code and
/// its detail are real.
#[test]
fn a_refusal_printed_with_a_prefix_this_program_never_uses_is_a_finding() {
    let root = repo_root();
    let page = "```text\nError: CONTRACT_DIGEST_MISMATCH: the bytes hash to something else\n```\n";
    let findings = findings(&root, "docs/example.md", page);
    assert_eq!(findings.len(), 1, "{}", report(&findings));
    assert!(
        findings[0]
            .what
            .contains("arcana run: CONTRACT_DIGEST_MISMATCH"),
        "{}",
        report(&findings)
    );
}

/// `reason` and `code` are the same code in every marker `refuse()` writes.
#[test]
fn a_done_marker_whose_reason_and_code_disagree_is_a_finding() {
    let root = repo_root();
    let page = format!(
        "```text\n{DONE_MARKER} {{\"completed\":false,\"reason\":\"Failed\",\
         \"code\":\"CONTRACT_MISSING\",\"error\":\"no digest\"}}\n```\n"
    );
    let findings = findings(&root, "docs/example.md", &page);
    assert_eq!(findings.len(), 1, "{}", report(&findings));
    assert!(
        findings[0].what.contains("refusal is"),
        "{}",
        report(&findings)
    );
}

/// The vocabulary is read out of the program, and it is the program's.
#[test]
fn the_refusal_codes_come_from_the_source_that_prints_them() {
    let root = repo_root();
    let codes = refusal_codes(&root);
    for expected in [
        "CONTRACT_MISSING",
        "CONTRACT_DIGEST_MISMATCH",
        "GROUND_TRUTH_EMPTY",
        "GROUND_TRUTH_UNREADABLE",
        "MUNERAL_UNAVAILABLE",
        "WORK_ITEM_UNREADABLE",
    ] {
        assert!(
            codes.contains(expected),
            "{expected} is refused by this program and the scan did not find \
             it: {codes:?}"
        );
    }
    assert!(
        !codes.contains("CONTRACT_EXPIRED"),
        "no such code exists, and a vocabulary that contains it would excuse \
         a page that invents it: {codes:?}"
    );
}

/// The done-marker keys are the writer's, not a list in this file.
#[test]
fn the_done_marker_keys_come_from_the_writer() {
    let keys = done_marker_keys();
    for expected in [
        "completed",
        "reason",
        "turns",
        "tool_calls",
        "tool_calls_attempted",
        "tool_calls_denied",
        "cost_usd_micros",
        "compactions",
        "workspace",
        "error",
        "effect",
        "code",
    ] {
        assert!(keys.contains(expected), "{expected} missing from {keys:?}");
    }
    assert!(
        !keys.contains("exit_code"),
        "a key the writer does not emit must not be accepted: {keys:?}"
    );
}

/// Output quoted OUTSIDE a fenced block is not this check's business, and it
/// says so by measurement rather than by comment.
#[test]
fn prose_is_left_to_the_prose_check() {
    let root = repo_root();
    let page = "The command prints Error: CONTRACT_MISSING: no digest, and stops.\n";
    assert!(findings(&root, "docs/example.md", page).is_empty());
}

/// A refusal prints its code once, and the run through the real refusal types
/// is what says so.
///
/// `ContractRefusal`'s `Display` opens with the code, and every contract call
/// site passes it to `refuse()` as the detail. Before `refusal_line` stripped
/// the duplicate, an operator asking why a run stopped read
/// `arcana run: CONTRACT_MISSING: CONTRACT_MISSING: the work item carries no
/// contractDigest, …`. Nothing was measuring the line — the page A2-292
/// withheld showed it once, and so did the page this check was written for.
#[test]
fn a_refusal_prints_its_code_once() {
    let refusals = [
        ContractRefusal::Missing,
        ContractRefusal::MalformedDigest {
            value: "sha256:zz".to_owned(),
        },
        ContractRefusal::NotFound {
            digest: "sha256:aa".to_owned(),
        },
        ContractRefusal::DigestMismatch {
            expected: "sha256:aa".to_owned(),
            computed: "sha256:bb".to_owned(),
            preimage: DigestPreimage::CanonicalBytes,
        },
        ContractRefusal::Unverifiable {
            digest: "sha256:aa".to_owned(),
            detail: "no bytes".to_owned(),
        },
        ContractRefusal::Unavailable {
            detail: "connection refused".to_owned(),
        },
    ];
    for refusal in refusals {
        let code = refusal.code();
        let line = refusal_line(code, &refusal.to_string());
        let doubled = format!("arcana run: {code}: {code}:");
        assert!(
            !line.starts_with(&doubled),
            "the code is printed twice: {line}"
        );
        assert!(
            line.starts_with(&format!("arcana run: {code}: ")),
            "the code is the first token after the program name: {line}"
        );
        let marker = refusal_marker(code, &refusal.to_string());
        assert!(
            !marker.contains(&format!("\"error\":\"{code}: ")),
            "the marker's error repeats the code it already carries: {marker}"
        );
    }
}

/// The detail of an unrelated code is left alone.
///
/// Stripping `<CODE>: ` only when it is THIS code: a detail that quotes some
/// other program's code is the detail, not a duplicate.
#[test]
fn a_detail_that_opens_with_a_different_code_is_untouched() {
    let line = refusal_line("CONTRACT_MISSING", "MUNERAL_UNAVAILABLE: the API refused");
    assert_eq!(
        line,
        "arcana run: CONTRACT_MISSING: MUNERAL_UNAVAILABLE: the API refused"
    );
}
