#!/usr/bin/env bash
# A2-238. A pull request that is based on another branch must be checked like any other.
#
# Measured 2026-09-23 on this repository: `ci.yml` and `graph-admission-call.yml` both triggered on
# `pull_request: branches: [main]`, so PR #196 — stacked on the unmerged branch of PR #195, which is
# our ordinary way of working — showed an EMPTY check list. Not a red check somebody argues with: the
# absence of one. `graph-admission` never ran, and the reviewer saw a pull request that looked
# checked because nothing said otherwise.
#
# The three rules below are the shape that cannot fail that way again. Each one refers to a way a
# check disappears while the workflow file still looks correct:
#
#   R1  `pull_request` carries no branch filter. A filter names the bases we thought of; a stacked
#       PR is by definition based on a branch nobody named in advance.
#   R2  `push` stays pinned to the default branch. R1 must not be read as "triggers are noise" —
#       push-to-main is what makes `release-pending` and the scheduled checks meaningful, and
#       widening it would run the whole battery on every branch push.
#   R3  no job is gated on `github.event_name == '<one event>'`. An equality silently SKIPS the job
#       for every other event the workflow declares, and a skipped job is reported as a success.
#       That is how `changelog` was skipped in the manual-dispatch workaround A2-234 had to use.
#       Negations (`!=`) are fine: they widen, they do not narrow to a single event.
#
# An unrecognised file shape is a FAILURE, never a pass: the parser below understands exactly the
# YAML this repository writes, and a file it cannot read is a file it cannot vouch for.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="${1:-$root/.github/workflows}"

python3 - "$dir" <<'PY'
import pathlib
import re
import sys

WORKFLOWS = pathlib.Path(sys.argv[1])
DEFAULT_BRANCH = "main"

failures: list[str] = []


def fail(path: pathlib.Path, line: int, text: str) -> None:
    failures.append(f"{path.name}:{line}: {text}")


def top_level_block(lines: list[str], key: str) -> list[tuple[int, str]]:
    """The lines of one top-level mapping, with their 1-based numbers.

    Only the narrow YAML this repository writes: a top-level key at column 0, its body indented,
    comments and blank lines ignored. `on:` written as a flow mapping or a list is not understood,
    and the caller turns that into a failure rather than a silent pass."""
    out: list[tuple[int, str]] = []
    inside = False
    for n, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            if inside:
                break
            inside = re.fullmatch(rf"{re.escape(key)}:\s*", line) is not None
            if inside:
                continue
            # `on: [push]` / `on: {push: ...}` — a shape this parser does not read.
            if re.match(rf"{re.escape(key)}:\s*\S", line):
                raise SystemExit(f"{key}: written inline; this checker reads only the block form")
            continue
        if inside:
            out.append((n, line))
    return out


def sub_block(block: list[tuple[int, str]], key: str) -> tuple[int, list[tuple[int, str]]] | None:
    """One second-level key of a top-level block, e.g. `pull_request:` inside `on:`."""
    head, body, depth = None, [], None
    for n, line in block:
        indent = len(line) - len(line.lstrip())
        if head is None:
            if re.fullmatch(rf"\s*{re.escape(key)}:\s*", line):
                head, depth = n, indent
            continue
        if indent <= depth:
            break
        body.append((n, line))
    return None if head is None else (head, body)


for path in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        on_block = top_level_block(lines, "on")
    except SystemExit as exc:
        fail(path, 1, str(exc))
        continue
    if not on_block:
        fail(path, 1, "no `on:` block — a workflow whose triggers cannot be read is not vouched for")
        continue

    # R1 — pull_request carries no branch filter.
    pr = sub_block(on_block, "pull_request")
    if pr is not None:
        for n, line in pr[1]:
            if re.match(r"\s*branches(-ignore)?:", line):
                fail(path, n,
                     "`pull_request` carries a branch filter, so a pull request based on any other "
                     "branch gets NO checks at all (A2-238). Remove the filter.")

    # R2 — push stays pinned to the default branch.
    push = sub_block(on_block, "push")
    if push is not None:
        branches = [(n, line) for n, line in push[1] if re.match(r"\s*branches:", line)]
        tags = [(n, line) for n, line in push[1] if re.match(r"\s*tags:", line)]
        if not branches and not tags:
            fail(path, push[0], "`push` is unrestricted — pin it to "
                                f"`branches: [{DEFAULT_BRANCH}]` or to tags")
        for n, line in branches:
            if DEFAULT_BRANCH not in line:
                fail(path, n, f"`push` no longer covers {DEFAULT_BRANCH}: {line.strip()}")

    # R3 — no job narrowed to a single event by equality.
    for n, raw in enumerate(lines, 1):
        m = re.search(r"github\.event_name\s*==\s*'([a-z_]+)'", raw)
        if m and "||" not in raw and "!=" not in raw:
            fail(path, n,
                 f"a job runs only when the event is {m.group(1)!r}; it is SKIPPED (and reported as "
                 "a success) for every other event this workflow declares. Widen the condition.")

if failures:
    print("workflow trigger contract violated:", file=sys.stderr)
    for f in failures:
        print("  " + f, file=sys.stderr)
    sys.exit(1)

print(f"workflow trigger contract holds for {len(list(WORKFLOWS.glob('*.y*ml')))} workflow file(s)")
PY
