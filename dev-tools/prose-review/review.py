#!/usr/bin/env python3
"""Blind reviewer for an agent-written page: every claim must be quoted out of
the source, or it is UNSUPPORTED.

The deterministic half of this check is `crates/cli/tests/prose_claims.rs`,
which settles the claims a machine can settle (literals, paths, flag relations,
numbers). This is the other half, for the claims whose defect is meaning: the
Muneral agent key is "a PEM-encoded Ed25519 private key" is a grammatical,
plausible, false sentence, and no token in it is misspelled.

Blind means blind. The reviewer model is given the page's claims and the source
excerpts and nothing else: not our verdicts, not the defect list, not the name
of the run that wrote the page. It must answer, per claim, either

    SUPPORTED <file> | <verbatim quote from that file>

or

    UNSUPPORTED

and the quote is then re-read from the file on disk. A quote that is not in the
file is itself a finding (`QUOTE_NOT_IN_FILE`) — a reviewer that invents its
evidence is the failure mode we are checking the page for, one level up.

Two passes, and the second one is the classifier. Pass 1 is blind and narrow:
it reads the excerpts it was given, and an UNSUPPORTED there means "not in this
excerpt", which is not the same as "false". Measured on A2-297b: 15 UNSUPPORTED
items, 11 of them true and simply outside the excerpt — and they were sorted
into true/false by the EXECUTOR, the party that wanted the page green. That is
not a check. So pass 2 re-reads every UNSUPPORTED claim against the FULL text of
the relevant files and must answer with a quote:

    SUPPORTED <file> | <quote>      the full file states it after all
    CONTRADICTED <file> | <quote>   the full file says otherwise — a defect
    ABSENT                          nothing in these files bears on it

Every quote is re-read from disk exactly as in pass 1. The classification in the
JSON is pass 2's own answer: nothing downstream of this script may relabel a
claim, and both passes' raw output is recorded so the relabelling would be
visible if it happened.

Never in CI: it costs money and it is not deterministic. Run it before
committing a page a model wrote, and keep the JSON beside the run.

Usage:
  review.py --page docs/how-to/x.md --source crates/cli/src/cli.rs \
            [--source crates/connectors/src/muneral.rs:1..60] \
            [--full-source crates/cli/src/run.rs] \
            [--model deepseek-v4-flash] [--out findings.json]

`--full-source` names the files pass 2 reads whole (default: every `--source`
path, span stripped). Pass 2 is skipped only with `--no-classify`, and the JSON
says so where a verdict would be.

Environment: ARCANA_MC_TOKEN (required), ARCANA_MC_BASE_URL (optional).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict

DEFAULT_BASE_URL = "https://connector.arcanada.ai"
# One normalization, and it is named: source and markdown both wrap lines, so a
# quote is compared with runs of whitespace collapsed. Nothing else is relaxed.
WS = re.compile(r"\s+")
# A2-297b measured nine QUOTE_NOT_IN_FILE verdicts that were the checker's
# fault: the model quotes a wrapped doc comment and drops the interior `/// `,
# so the quote is not in the file once whitespace alone is collapsed. Comment
# markers are removed from BOTH sides before comparing, and nothing else is.
# Measured twice on 2026-09-25: a model quoting a wrapped doc comment carries
# the interior `//!` into the MIDDLE of its one-line quote, and a `write!`
# string wrapped with a trailing `\` keeps that backslash in the file and not
# in the quote. Both are removed from BOTH sides; nothing else is relaxed, and
# because the same normalization runs over the file, a quote cannot be made to
# match by inventing a marker.
COMMENT_MARKER = re.compile(r"(?m)///|//!|//|^[ \t]*(\*(?!/)|\*/|/\*)[ \t]?|\\\n")
# The Model Connector refuses a prompt over 100 000 characters (HTTP 400). A
# budget measured before the call is cheaper than a traceback after it.
MAX_PROMPT_CHARS = 100_000


# A model answering on ONE line escapes the newlines inside its quote: the third
# normalization measured on 2026-09-25, on a quote that was in the file at
# `crates/cli/src/work_item.rs:8` and read as invented.
ESCAPED_WS = re.compile(r"\\[nt]")


def collapse(text: str) -> str:
    return WS.sub(" ", ESCAPED_WS.sub(" ", COMMENT_MARKER.sub("", text))).strip()


@dataclass
class Claim:
    index: int
    line: int
    text: str


@dataclass
class Finding:
    claim: int
    line: int
    text: str
    code: str
    detail: str


def read_source(spec: str) -> tuple[str, str]:
    """`path` or `path:start..end` -> (path, text with line numbers)."""
    if ":" in spec and ".." in spec.rsplit(":", 1)[-1]:
        path, span = spec.rsplit(":", 1)
        start, end = (int(part) for part in span.split(".."))
    else:
        path, start, end = spec, 1, None
    lines = open(path, encoding="utf-8").read().splitlines()
    end = len(lines) if end is None else min(end, len(lines))
    numbered = [f"{n:>5}  {lines[n - 1]}" for n in range(start, end + 1)]
    return path, "\n".join(numbered)


def claims_of(page: str) -> list[Claim]:
    """Split a page into factual claims.

    Prose is split into sentences; a fenced line that assigns a variable or
    invokes a command is one claim of its own — `export ARCANA_MODEL="…"` is a
    claim about a model id, and it is not a sentence.
    """
    out: list[Claim] = []
    fence = None
    buffer: list[tuple[int, str]] = []

    def flush() -> None:
        if not buffer:
            return
        start = buffer[0][0]
        text = " ".join(line for _, line in buffer).strip()
        offset = 0
        for piece in re.split(r"(?<=[.:!?])\s+(?=[A-Z`*\-])", text):
            piece = piece.strip()
            if len(piece) > 12:
                line = start + text[:offset].count("  ")
                out.append(Claim(len(out) + 1, line, piece))
            offset += len(piece) + 1
        buffer.clear()

    for number, raw in enumerate(page.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            flush()
            marker = stripped[:3]
            fence = None if fence == marker else marker
            continue
        if fence:
            if stripped and not stripped.startswith("#"):
                out.append(Claim(len(out) + 1, number, stripped))
            continue
        if not stripped:
            flush()
            continue
        if stripped.startswith("#"):
            flush()
            out.append(Claim(len(out) + 1, number, stripped.lstrip("# ").strip()))
            continue
        buffer.append((number, raw.strip()))
    flush()
    return out


PROMPT = """\
You are checking a documentation page against the source code of the program it
documents. You have the source excerpts below and nothing else. You do not know
who wrote the page and you must not assume any claim is true.

For EACH numbered claim, answer on ONE line, in this exact format:

  <n>: SUPPORTED <file> | <quote>
  <n>: UNSUPPORTED
  <n>: NOT_A_CLAIM

<quote> must be copied CHARACTER FOR CHARACTER out of the excerpt of <file>
below (without the line-number prefix). Do not paraphrase, do not shorten with
"...", do not quote a claim back to itself. If the excerpts do not state the
claim, the answer is UNSUPPORTED even if you believe the claim is true —
believing is not support. NOT_A_CLAIM is for a heading or a sentence that
states nothing checkable (an instruction to create a directory, a transition).

Answer every claim, in order, with no other text.

=== SOURCE EXCERPTS ===
{sources}

=== CLAIMS ===
{claims}
"""


CLASSIFY_PROMPT = """\
You are reading whole source files of a program and deciding, for each numbered
statement below, whether those files STATE it, CONTRADICT it, or say nothing
about it. You do not know who wrote the statements and you must not assume any
of them is true.

For EACH numbered statement, answer on ONE line, in this exact format:

  <n>: SUPPORTED <file> | <quote>
  <n>: CONTRADICTED <file> | <quote>
  <n>: ABSENT

<quote> must be copied CHARACTER FOR CHARACTER out of the file you name, as it
appears below (without the line-number prefix). Do not paraphrase and do not
shorten with "...". SUPPORTED means the quote states the statement.
CONTRADICTED means the quote says something the statement cannot be true
beside — a different value, a different name, a different behaviour; quote the
line that conflicts. ABSENT means these files do not settle it either way, and
takes no quote.

Answer every statement, in order, with no other text.

=== SOURCE FILES (complete) ===
{sources}

=== STATEMENTS ===
{claims}
"""


def verdict_lines(output: str) -> dict[int, str]:
    """`3: SUPPORTED file | quote` -> {3: "SUPPORTED file | quote"}."""
    verdicts: dict[int, str] = {}
    for line in output.splitlines():
        match = re.match(r"\s*\**\s*(\d+)\s*[:.)]\s*(.*)", line)
        if match:
            verdicts[int(match.group(1))] = match.group(2).strip()
    return verdicts


def quote_in_file(paths: list[str], named: str, quote: str) -> tuple[str | None, bool]:
    """Re-read a cited quote from disk: (the file it was found in, whether it is)."""
    named = named.strip("`*").strip()
    candidates = [path for path in paths if path.endswith(named) or named.endswith(path)]
    if not candidates:
        return None, False
    body = collapse(open(candidates[0], encoding="utf-8").read())
    return candidates[0], collapse(quote.strip("`\"' ")) in body


def numbered(path: str) -> str:
    lines = open(path, encoding="utf-8").read().splitlines()
    return "\n".join(f"{n:>5}  {line}" for n, line in enumerate(lines, start=1))


def file_groups(paths: list[str], overhead: int) -> list[list[str]]:
    """Split full files into groups whose prompt fits the connector's limit."""
    budget = MAX_PROMPT_CHARS - overhead
    groups: list[list[str]] = []
    current: list[str] = []
    size = 0
    for path in paths:
        cost = len(numbered(path)) + len(path) + 16
        if cost > budget:
            raise SystemExit(
                f"{path} alone renders {cost} characters and the budget for a "
                f"classification prompt is {budget}: pass a narrower file"
            )
        if current and size + cost > budget:
            groups.append(current)
            current, size = [], 0
        current.append(path)
        size += cost
    if current:
        groups.append(current)
    return groups


def classify(
    base: str,
    token: str,
    connector: str,
    model: str,
    timeout_ms: int,
    claims: list[Claim],
    paths: list[str],
) -> tuple[dict[int, dict], list[dict]]:
    """Second reviewer run: an UNSUPPORTED claim against the FULL files.

    The verdict this returns IS the classification. Nothing downstream may
    relabel it — that is the whole point of the pass: on A2-297b the executor
    sorted pass 1's UNSUPPORTED list into "true, outside the excerpt" and
    "unverifiable" by hand, and one of the items it called unverifiable was the
    page telling an operator to install a stranger's crate.
    """
    rendered_claims = "\n".join(f"{claim.index}: {claim.text}" for claim in claims)
    overhead = len(CLASSIFY_PROMPT) + len(rendered_claims)
    runs: list[dict] = []
    merged: dict[int, dict] = {}
    for group in file_groups(paths, overhead):
        sources = "\n".join(f"--- {path} (complete) ---\n{numbered(path)}" for path in group)
        prompt = CLASSIFY_PROMPT.format(sources=sources, claims=rendered_claims)
        answer = dispatch(base, token, connector, model, prompt, timeout_ms)
        output = answer.get("output") or answer.get("result") or answer.get("text") or ""
        if not isinstance(output, str):
            output = json.dumps(output)
        runs.append(
            {
                "files": group,
                "prompt_chars": len(prompt),
                "usage": answer.get("usage"),
                "raw_output": output,
            }
        )
        verdicts = verdict_lines(output)
        for claim in claims:
            raw = verdicts.get(claim.index)
            if raw is None:
                merged.setdefault(
                    claim.index,
                    {"verdict": "NO_VERDICT", "detail": "the classifier returned no line"},
                )
                continue
            upper = raw.upper()
            if upper.startswith("ABSENT"):
                merged.setdefault(claim.index, {"verdict": "ABSENT", "detail": raw[:200]})
                continue
            label = "CONTRADICTED" if upper.startswith("CONTRADICTED") else "SUPPORTED"
            rest = raw[len(label):].strip() if upper.startswith(label) else raw
            if "|" not in rest:
                merged.setdefault(
                    claim.index,
                    {"verdict": "MALFORMED", "detail": f"no quote in the verdict: {raw[:160]}"},
                )
                continue
            named, quote = (part.strip() for part in rest.split("|", 1))
            found, ok = quote_in_file(group, named, quote)
            record = {
                "verdict": label if ok else "QUOTE_NOT_IN_FILE",
                "file": found or named,
                "quote": quote[:400],
                "quote_verified": ok,
                "detail": raw[:200] if ok else f"{found or named} does not contain the quote",
            }
            # A quote-backed verdict outranks an ABSENT from another group: the
            # group that held the answer is the one that could answer.
            previous = merged.get(claim.index)
            if previous is None or previous["verdict"] in {"ABSENT", "NO_VERDICT"} or (
                previous["verdict"] == "SUPPORTED" and record["verdict"] == "CONTRADICTED"
            ):
                merged[claim.index] = record
    return merged, runs


def dispatch(base: str, token: str, connector: str, model: str, prompt: str, timeout_ms: int) -> dict:
    body = json.dumps(
        {"connector": connector, "prompt": prompt, "model": model, "timeout": timeout_ms}
    ).encode()
    request = urllib.request.Request(
        base.rstrip("/") + "/execute",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "aup-orchestrator/1.0",
        },
        method="POST",
    )
    if len(prompt) > MAX_PROMPT_CHARS:
        raise SystemExit(
            f"prompt is {len(prompt)} characters and the Model Connector accepts "
            f"{MAX_PROMPT_CHARS}: narrow the excerpts or pass fewer files"
        )
    try:
        with urllib.request.urlopen(request, timeout=timeout_ms / 1000 + 60) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        # The body says WHY; a traceback out of urllib says only that something
        # was rejected, and A2-297b spent a card's time on that.
        detail = error.read().decode("utf-8", "replace")[:2000]
        raise SystemExit(f"Model Connector returned {error.code}: {detail}") from error


def connector_for(base: str, token: str, model: str) -> str:
    """Read the connector out of the LIVE catalogue, never a table here."""
    request = urllib.request.Request(
        base.rstrip("/") + "/connectors/catalog",
        headers={"Authorization": f"Bearer {token}", "User-Agent": "aup-orchestrator/1.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        catalog = json.loads(response.read())
    for entry in catalog.get("models", []):
        if entry.get("model") == model:
            return entry["connector"]
    raise SystemExit(f"{model} is not in the live catalogue")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--page", required=True)
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument(
        "--full-source",
        action="append",
        default=[],
        help="file pass 2 reads whole (default: every --source path, span stripped)",
    )
    parser.add_argument(
        "--no-classify",
        action="store_true",
        help="skip pass 2 — then an UNSUPPORTED claim stays unclassified, and says so",
    )
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--connector")
    parser.add_argument("--out")
    parser.add_argument("--timeout-ms", type=int, default=300_000)
    args = parser.parse_args()

    token = os.environ.get("ARCANA_MC_TOKEN")
    if not token:
        raise SystemExit("ARCANA_MC_TOKEN is not set")
    base = os.environ.get("ARCANA_MC_BASE_URL", DEFAULT_BASE_URL)

    page = open(args.page, encoding="utf-8").read()
    claims = claims_of(page)
    sources: dict[str, str] = {}
    for spec in args.source:
        path, text = read_source(spec)
        sources.setdefault(path, "")
        sources[path] += text + "\n"
    rendered_sources = "\n".join(
        f"--- {path} ---\n{text}" for path, text in sources.items()
    )
    rendered_claims = "\n".join(f"{claim.index}: {claim.text}" for claim in claims)
    prompt = PROMPT.format(sources=rendered_sources, claims=rendered_claims)

    connector = args.connector or connector_for(base, token, args.model)
    answer = dispatch(base, token, connector, args.model, prompt, args.timeout_ms)
    output = answer.get("output") or answer.get("result") or answer.get("text") or ""
    if not isinstance(output, str):
        output = json.dumps(output)

    verdicts = verdict_lines(output)

    findings: list[Finding] = []
    # Every claim pass 1 did not settle WITH A VERIFIED QUOTE: UNSUPPORTED, and
    # also the ones whose support could not be re-read (an unverifiable quote
    # leaves the claim unjudged exactly as an absent one does). None of them is
    # the executor's to sort.
    unsettled: list[Claim] = []
    supported = unsupported = not_a_claim = 0
    for claim in claims:
        verdict = verdicts.get(claim.index)
        if verdict is None:
            unsettled.append(claim)
            findings.append(
                Finding(claim.index, claim.line, claim.text, "NO_VERDICT",
                        "the reviewer returned no line for this claim")
            )
            continue
        if verdict.upper().startswith("UNSUPPORTED"):
            unsupported += 1
            # Not a finding yet, and not the executor's to sort: pass 2 below
            # says what it is.
            unsettled.append(claim)
            continue
        if verdict.upper().startswith("NOT_A_CLAIM"):
            not_a_claim += 1
            continue
        rest = verdict[len("SUPPORTED"):].strip() if verdict.upper().startswith("SUPPORTED") else verdict
        if "|" not in rest:
            unsettled.append(claim)
            findings.append(
                Finding(claim.index, claim.line, claim.text, "MALFORMED",
                        f"no quote in the verdict: {verdict[:120]}")
            )
            continue
        named, quote = (part.strip() for part in rest.split("|", 1))
        named = named.strip("`*").strip()
        candidates = [path for path in sources if path.endswith(named) or named.endswith(path)]
        if not candidates:
            unsettled.append(claim)
            findings.append(
                Finding(claim.index, claim.line, claim.text, "QUOTE_FILE_UNKNOWN",
                        f"the reviewer cited `{named}`, which is not an excerpt it was given")
            )
            continue
        body = collapse(open(candidates[0], encoding="utf-8").read())
        if collapse(quote.strip("`\"' ")) not in body:
            unsettled.append(claim)
            findings.append(
                Finding(claim.index, claim.line, claim.text, "QUOTE_NOT_IN_FILE",
                        f"{candidates[0]} does not contain the quote: {quote[:160]}")
            )
            continue
        supported += 1

    full_paths = args.full_source or sorted(sources)
    classification: dict[str, dict] = {}
    pass2_runs: list[dict] = []
    if unsettled and not args.no_classify:
        verdict_by_claim, pass2_runs = classify(
            base, token, connector, args.model, args.timeout_ms, unsettled, full_paths
        )
        for claim in unsettled:
            record = verdict_by_claim.get(
                claim.index, {"verdict": "NO_VERDICT", "detail": "the classifier answered nothing"}
            )
            classification[str(claim.index)] = {
                "line": claim.line,
                "text": claim.text,
                **record,
            }
            if record["verdict"] == "CONTRADICTED":
                findings.append(
                    Finding(claim.index, claim.line, claim.text, "FALSE_CLAIM",
                            f"the classifier quotes {record.get('file')}: {record.get('quote', '')[:200]}")
                )
            elif record["verdict"] in {"QUOTE_NOT_IN_FILE", "MALFORMED", "NO_VERDICT"}:
                findings.append(
                    Finding(claim.index, claim.line, claim.text, f"CLASSIFIER_{record['verdict']}",
                            record.get("detail", ""))
                )
    elif unsettled:
        for claim in unsettled:
            findings.append(
                Finding(claim.index, claim.line, claim.text, "UNSETTLED_UNCLASSIFIED",
                        "pass 1 did not settle this claim with a verified quote and pass 2 "
                        "was not run (--no-classify)")
            )

    result = {
        "page": args.page,
        "model": args.model,
        "connector": connector,
        "claims": len(claims),
        "supported": supported,
        "unsupported": unsupported,
        "not_a_claim": not_a_claim,
        # Whose verdict this is, written into the artefact: an UNSUPPORTED claim
        # is classified by the second reviewer run, and the executor quotes that
        # answer rather than replacing it.
        "classification_authority": "reviewer-pass-2" if pass2_runs else "none (pass 2 not run)",
        "classification": classification,
        "classified_counts": {
            verdict: sum(1 for item in classification.values() if item["verdict"] == verdict)
            for verdict in sorted({item["verdict"] for item in classification.values()})
        },
        "usage": answer.get("usage"),
        "findings": [asdict(finding) for finding in findings],
        "passes": [
            {"pass": 1, "kind": "blind-excerpts", "prompt_chars": len(prompt),
             "usage": answer.get("usage"), "raw_output": output},
            *[{"pass": 2, "kind": "classify-full-files", **run} for run in pass2_runs],
        ],
        "raw_output": output,
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(rendered + "\n")
    print(rendered)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
