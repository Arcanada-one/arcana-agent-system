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

Never in CI: it costs money and it is not deterministic. Run it before
committing a page a model wrote, and keep the JSON beside the run.

Usage:
  review.py --page docs/how-to/x.md --source crates/cli/src/cli.rs \
            [--source crates/connectors/src/muneral.rs:1..60] \
            [--model deepseek-v4-flash] [--out findings.json]

Environment: ARCANA_MC_TOKEN (required), ARCANA_MC_BASE_URL (optional).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from dataclasses import dataclass, asdict

DEFAULT_BASE_URL = "https://connector.arcanada.ai"
# One normalization, and it is named: source and markdown both wrap lines, so a
# quote is compared with runs of whitespace collapsed. Nothing else is relaxed.
WS = re.compile(r"\s+")


def collapse(text: str) -> str:
    return WS.sub(" ", text).strip()


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
    with urllib.request.urlopen(request, timeout=timeout_ms / 1000 + 60) as response:
        return json.loads(response.read())


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

    verdicts: dict[int, str] = {}
    for line in output.splitlines():
        match = re.match(r"\s*\**\s*(\d+)\s*[:.)]\s*(.*)", line)
        if match:
            verdicts[int(match.group(1))] = match.group(2).strip()

    findings: list[Finding] = []
    supported = unsupported = not_a_claim = 0
    for claim in claims:
        verdict = verdicts.get(claim.index)
        if verdict is None:
            findings.append(
                Finding(claim.index, claim.line, claim.text, "NO_VERDICT",
                        "the reviewer returned no line for this claim")
            )
            continue
        if verdict.upper().startswith("UNSUPPORTED"):
            unsupported += 1
            findings.append(
                Finding(claim.index, claim.line, claim.text, "UNSUPPORTED",
                        "the reviewer could not quote support for this claim")
            )
            continue
        if verdict.upper().startswith("NOT_A_CLAIM"):
            not_a_claim += 1
            continue
        rest = verdict[len("SUPPORTED"):].strip() if verdict.upper().startswith("SUPPORTED") else verdict
        if "|" not in rest:
            findings.append(
                Finding(claim.index, claim.line, claim.text, "MALFORMED",
                        f"no quote in the verdict: {verdict[:120]}")
            )
            continue
        named, quote = (part.strip() for part in rest.split("|", 1))
        named = named.strip("`*").strip()
        candidates = [path for path in sources if path.endswith(named) or named.endswith(path)]
        if not candidates:
            findings.append(
                Finding(claim.index, claim.line, claim.text, "QUOTE_FILE_UNKNOWN",
                        f"the reviewer cited `{named}`, which is not an excerpt it was given")
            )
            continue
        body = collapse(open(candidates[0], encoding="utf-8").read())
        if collapse(quote.strip("`\"' ")) not in body:
            findings.append(
                Finding(claim.index, claim.line, claim.text, "QUOTE_NOT_IN_FILE",
                        f"{candidates[0]} does not contain the quote: {quote[:160]}")
            )
            continue
        supported += 1

    result = {
        "page": args.page,
        "model": args.model,
        "connector": connector,
        "claims": len(claims),
        "supported": supported,
        "unsupported": unsupported,
        "not_a_claim": not_a_claim,
        "usage": answer.get("usage"),
        "findings": [asdict(finding) for finding in findings],
        "raw_output": output,
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(rendered + "\n")
    print(rendered)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
