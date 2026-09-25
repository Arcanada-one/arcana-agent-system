#!/usr/bin/env python3
"""AUP-GRAPH-006 gate0 — the admission gate: «нет receipt — нет мержа».

Subcommands
  gate           refuse / pause / admit a change range in a program-owned repository, from the
                 ChangeAdmissionReceipt/v1 documents that are bound to it (contract
                 contracts/graph-verified-change/admission-gate.v1.json).
  attach         build a WorkItemEvidenceAttachment/v1 for a receipt and append it to the program-side
                 evidence ledger; with --post, deliver it to Muneral when a work-item evidence route
                 exists (probe recorded, never a status write).
  charter-scan   scan the live charter surfaces of a host for TDD / test-first and classify every hit
                 (mandate_default | opt_in_reference | neutral_mention | historical).
  pr-coverage    measure which merges of a pilot repository carry a receipt (AM1 baseline / window).
  --selftest     fixtures + negative controls + mutation battery on a scratch git repository.

Python 3.12 stdlib only; deterministic; never writes to the repository it gates.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# KB-039 / A2-243 defect 4, the same reason as in ci_gate.py: importing a sibling writes
# tools/graph/__pycache__/*.pyc, and under a VENDORED bundle that is an unlisted file beside a
# hashed one — and a PEP 552 `unchecked_hash` .pyc is imported in preference to the .py the
# manifest hashes, without validating it. Before the first sibling import.
sys.dont_write_bytecode = True
import schema_check  # noqa: E402  (sibling tool, reused as a library)
import impact_pair  # noqa: E402
import canary_evidence  # noqa: E402  (DEC-AUP-0037: the gate reads the canary document, not the claim)

TOOL = "tools/graph/admit_change.py"
VERSION = "1.0.0"
MODEL = "claude-opus-5"
PROGRAM_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = PROGRAM_ROOT / "contracts/graph-verified-change/admission-gate.v1.json"
FIXTURE_DIR = PROGRAM_ROOT / "contracts/graph-verified-change/fixtures/admission"
LEDGER_DIR = PROGRAM_ROOT / "receipts/graph/work-item-evidence"

# The BLOCKING checks: the mutation battery disables each one and demands that at least one blocked
# fixture then gets through — a check that cannot be killed that way is a check that never blocked.
CHECK_IDS = ["C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C09", "C10", "C11", "C12", "C13",
             # AUP-GRAPH-006:gate4b — C16 REFUSES a structural exemption whose evidence the gate
             # re-measures and does not confirm, so it blocks and belongs in the disable battery.
             "C16", "C18",
             # DEC-AUP-0039 — C19 REFUSES a `verified` claim its own probe evidence contradicts, and it
             # is what LOWERS that entity's verdict to what was observed, so disabling it must (and does)
             # let a blocked fixture through: it belongs in the disable battery.
             "C19"]
# AUP-GRAPH-006:gate2a. C14/C15 are INFORMATIONAL: they name why the gate did or did not author a
# receipt on the automated-author path, and they never raise the verdict (their policy verdict is
# `admit`, rank 0). Disabling one therefore cannot let anything through, so the disabled-check battery
# would report a permanent survivor for a check that does not block by design. They are held to the
# property instead — asserted in the selftest — and their behaviour is measured by the dedicated
# gate2a mutation battery in ci_gate.py, where the four mutants of the card each flip the verdict.
INFORMATIONAL_CHECK_IDS = ["C14", "C15", "C17", "C20"]
# How many C18 coverage problems the one-line human rendering shows before it says how many it is
# not showing. The JSON check entry always carries every one of them (A2-274).
C18_PROBLEMS_SHOWN = 20
VERDICT_RANK = {"admit": 0, "paused_safe": 1, "refuse": 2}
EXIT_OF = {"admit": 0, "paused_safe": 3, "refuse": 5}


# ------------------------------------------------------------------ helpers
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    return sha256_bytes(p.read_bytes())


def parse_iso(s):
    return schema_check.parse_iso(s)


def git(repo: Path, *args: str, check=True) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:300]}")
    return r.stdout


def git_ok(repo: Path, *args: str) -> bool:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True).returncode == 0


def git_text_or_none(repo: Path, *args: str) -> str | None:
    """git output decoded as UTF-8, or None when the bytes are not UTF-8 at all.

    A2-243 defect 3: `git(..., text=True)` raises UnicodeDecodeError on a non-UTF-8 blob, and
    `pin_only_edit` reads EVERY changed path outside the bundle-managed set as text. A committed
    `__pycache__/*.pyc` — or any image, any binary fixture — made the gate raise instead of return.
    A gate that crashes is not a gate that refuses: the job goes red with a traceback and no reason
    code, which is indistinguishable from the CI runner having a bad day, and the reflex it teaches
    is to re-run rather than to read. The verdict belongs in the return value."""
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if r.returncode != 0:
        return ""
    try:
        return r.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def load_policy(path: Path | None) -> dict:
    return json.loads((path or POLICY_PATH).read_text(encoding="utf-8"))


def write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ range + receipt discovery
def range_files(repo: Path, base: str, head: str) -> list[dict]:
    # -z: git C-quotes a non-ASCII or special path in line output, and a quoted name matches no receipt path
    fields = git(repo, "diff", "--name-status", "-M", "-z", f"{base}..{head}").split("\0")
    files, i = [], 0
    while i < len(fields) and fields[i]:
        status = fields[i][0]
        n = 2 if status in "RC" else 1
        path = fields[i + n]
        files.append({"path": path, "status": status})
        i += n + 1
    return sorted(files, key=lambda f: f["path"])


def range_commits(repo: Path, base: str, head: str) -> list[str]:
    return [c for c in git(repo, "rev-list", f"{base}..{head}").split() if c]


def discover_receipts(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    for p in paths:
        if p.is_file():
            found.append(p)
            continue
        if not p.is_dir():
            continue
        for f in sorted(p.rglob("*.json")):
            try:
                # the schema key is sorted late in a canonically written receipt — scan the whole file, never a prefix
                if f.stat().st_size <= 32 * 1024 * 1024 and b"ChangeAdmissionReceipt" in f.read_bytes():
                    found.append(f)
            except OSError:
                continue
    return found


def read_receipt(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as e:
        return None, str(e)[:200]


def receipt_binds(repo: Path, doc: dict, base: str, head: str, commits: set[str]) -> tuple[bool, str]:
    """Is this receipt bound to exactly this change range?  (check C05)"""
    cs = doc.get("change_set") or {}
    tree = doc.get("tree") or {}
    mode = cs.get("mode")
    if mode == "diff":
        r_base, r_head = cs.get("base"), cs.get("head")
        if not (isinstance(r_base, str) and isinstance(r_head, str)):
            return False, "diff receipt without base/head"
        if r_head not in commits and r_head != head:
            return False, f"receipt head {r_head[:12]} is not a commit of {base[:12]}..{head[:12]}"
        if not git_ok(repo, "merge-base", "--is-ancestor", r_base, head):
            return False, f"receipt base {r_base[:12]} is not an ancestor of {head[:12]}"
        return True, f"diff {r_base[:12]}..{r_head[:12]}"
    if mode == "worktree":
        tc = tree.get("commit")
        if isinstance(tc, str) and (tc in commits or tc == head):
            return True, f"worktree at {tc[:12]}"
        return False, f"worktree receipt at {str(tc)[:12]} outside the range"
    return False, f"unknown change_set.mode {mode!r}"


# ------------------------------------------------------------------ the gate
# ------------------------------------------------------------------ AUP-GRAPH-006:gate2a
# The typed automated-author path: a dependency bot cannot author a ChangeAdmissionReceipt/v1, so
# making the gate a required check made every dependabot pull request need a human. The rule is not
# relaxed — the RECEIPT AUTHOR is typed. For a pull request whose author matches a registered
# automated author IN THE EVENT PAYLOAD, and whose diff touches only that author's path allowlist,
# the gate computes the impact set the same way as for anyone else and authors the receipt itself,
# with the typed exemption AUTOMATED_DEPENDENCY_UPDATE over ONE entity: the missing agent-authored
# receipt. Verification is never exempted: a lockfile/manifest change triggers the global fallback
# (impact = whole repository) and the repository's OWN test job is the verifier for it.

CONCLUSION_TO_VERDICT = {"success": "verified", "failure": "failed", "cancelled": "failed",
                         "timed_out": "failed", "action_required": "failed"}


def event_author(event: dict) -> dict:
    """The author fields the decision may look at — all from the payload GitHub delivered."""
    pr = event.get("pull_request") if isinstance(event.get("pull_request"), dict) else {}
    user = pr.get("user") if isinstance(pr.get("user"), dict) else {}
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    return {"login": user.get("login"), "id": user.get("id"), "type": user.get("type"),
            "author_association": pr.get("author_association"),
            # recorded, never consulted: the head branch name is chosen by whoever opens the PR
            "claimed_head_ref": head.get("ref"), "is_pull_request": bool(pr)}


def match_automated_author(policy: dict, event: dict | None) -> tuple[dict | None, dict]:
    """→ (author spec or None, evidence). Identity comes from the event payload, never the branch."""
    spec = policy.get("automated_authors") or {}
    authors = spec.get("authors") or []
    if not isinstance(event, dict) or not event:
        return None, {"matched": False, "reason": "no pull_request event payload was supplied to the gate"}
    who = event_author(event)
    if not who["is_pull_request"]:
        return None, {"matched": False, "reason": "the event payload carries no `pull_request` object", "author": who}
    for au in authors:
        if who["login"] == au.get("login") and who["id"] == au.get("user_id") and who["type"] == au.get("user_type"):
            return au, {"matched": True, "author_id": au.get("id"), "author": who,
                        "matched_on": ["pull_request.user.login", "pull_request.user.id", "pull_request.user.type"],
                        "branch_name_used": False}
    return None, {"matched": False, "author": who,
                  "reason": (f"login/id/type {who['login']!r}/{who['id']!r}/{who['type']!r} matches no registered "
                             f"automated author ({', '.join(str(a.get('login')) for a in authors) or 'none'}); "
                             f"the head branch name {who['claimed_head_ref']!r} is not evidence of authorship"),
                  "branch_name_used": False}


def allowlist_split(paths: list[str], globs: list[str]) -> tuple[list[str], list[str]]:
    inside = [p for p in paths if any(fnmatch.fnmatch(p, g) for g in globs)]
    return inside, [p for p in paths if p not in set(inside)]


def build_graph_at(repo: Path, rev: str, out: Path) -> dict | None:
    """Build the caller repository's graph at `rev` with the bundled builder (stdlib, deterministic)."""
    script = Path(__file__).resolve().parent / "build_graph.py"
    r = subprocess.run([sys.executable, str(script), str(repo), "--rev", rev, "--out", str(out)],
                       capture_output=True, text=True,
                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if r.returncode != 0 or not out.exists():
        return None
    try:
        return json.loads(out.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def synthesize_automated_receipt(repo: Path, base: str, head: str, files: list[dict], author: dict,
                                 policy: dict, *, repo_name: str, verifier_job: str | None,
                                 verifier_conclusion: str | None, verifier_output_ref: str | None,
                                 workdir: Path, event_evidence: dict) -> tuple[dict | None, str]:
    """The gate authors the receipt. → (receipt, note). None means the impact set could not be computed."""
    import impact as impact_mod  # sibling tool, reused as a library (bundled)

    gp = workdir / f"graph-{base[:12]}.json"
    graph = build_graph_at(repo, base, gp)
    if graph is None:
        return None, f"the graph could not be built at {base[:12]} — nothing to compute an impact set from"
    man = graph["manifest"]

    cs_files, fallback_files = [], []
    for f in files:
        kind = impact_mod.classify_file(f["path"], None)
        cs_files.append({"path": f["path"], "status": f["status"], "kind": kind, "node_id": None})
        if kind in impact_mod.FALLBACK_KINDS:
            fallback_files.append(f["path"])
    if not fallback_files:
        return None, ("no changed path classifies as a lockfile or a global config, so the whole-repository "
                      "fallback does not apply and this path has no impact set to stand on")

    total_nodes = len(graph.get("nodes") or [])
    captured = datetime.now(timezone.utc)
    ttl = int(author.get("exemption_ttl_days") or 30)
    expires = (captured + timedelta(days=ttl)).strftime("%Y-%m-%dT%H:%M:%SZ")
    repo_entity = f"repository:{repo_name}"
    authorship_entity = f"receipt_authorship:{repo_name}@{head[:12]}"

    concl = (verifier_conclusion or "").strip().lower()
    repo_verdict = CONCLUSION_TO_VERDICT.get(concl, "not_measured")
    exit_code = 0 if repo_verdict == "verified" else (1 if repo_verdict == "failed" else None)
    verifier = {
        "id": "repo-own-test-job",
        "kind": "other",
        "command": (f"GitHub Actions job {verifier_job!r} on {head[:12]} — the repository's OWN suite"
                    if verifier_job else "the repository's own test job — NOT NAMED by the caller"),
        "entities": [repo_entity],
        "exit_code": exit_code if exit_code is not None else 125,
        "output_ref": verifier_output_ref or f"github-actions:{repo_name}@{head[:12]}:{verifier_job or 'unnamed'}",
        "conclusion": concl or None,
        "note": ("verifier-matrix.v1.json defines `targeted_test` as tests covering the affected node, «never the "
                 "whole suite» — this is the whole suite, so it is recorded as kind `other`, which is what it is. "
                 "It is the verifier DEC-AUP-0008 prescribes for a global fallback (the Bazel/Nx rule): the "
                 "blast radius is the repository, so the repository's own suite is what must be green."),
    }
    verdicts = [
        {"entity": repo_entity, "verdict": repo_verdict,
         **({"verifier_ids": ["repo-own-test-job"]} if repo_verdict == "verified" else {}),
         "reason": (f"the repository's own test job {verifier_job!r} concluded {concl!r}"
                    if concl else
                    "the caller named no required verifier job, or its conclusion was not reported to the gate — "
                    "an unreported job is not a green one (DEC-AUP-0008 I4)")},
        {"entity": authorship_entity, "verdict": "not_measured",
         "reason": ("no agent-authored ChangeAdmissionReceipt/v1 exists for this change: it was opened by a "
                    f"registered automated author ({author.get('login')}), which cannot run the graph tooling. "
                    "This entity is the MISSING AUTHOR, not a missing measurement of the code.")},
    ]
    exemptions = [{
        "entity": authorship_entity,
        "code": author.get("exemption_code") or "AUTOMATED_DEPENDENCY_UPDATE",
        "owner": (policy.get("automated_authors") or {}).get("authors", [{}])[0].get("exemption_owner")
                 or author.get("exemption_owner") or "",
        "expires_at_utc": expires,
        "reason": ((policy.get("automated_authors") or {}).get("what_the_exemption_is_about") or "")
                  or "the receipt author is typed; verification is not exempted",
        "scope": ("receipt AUTHORSHIP only. It does not carry, and must never be extended to carry, "
                  f"{repo_entity} — if the repository's own test job is not green that entity is failed or "
                  "not_measured on its own and the change is refused or paused."),
        "evidence": event_evidence,
    }]
    adm = "admitted_with_exemptions" if repo_verdict == "verified" else (
        "refused" if repo_verdict == "failed" else "paused_safe")
    receipt = {
        "schema": "ChangeAdmissionReceipt/v1",
        "receipt_id": f"car-automated-{head[:12]}-{captured.strftime('%Y%m%dT%H%M%SZ')}",
        "captured_at_utc": captured.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": {"tool": TOOL, "version": VERSION, "path": "automated_author"},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "decision_ref": "DEC-AUP-0008",
        "portion_id": "AUP-GRAPH-006:gate2a",
        "work_item": None,
        "authored_by": {
            "path": "automated_author",
            "rule": (policy.get("automated_authors") or {}).get("identity_rule", ""),
            **event_evidence,
        },
        "repo": {"name": repo_name, "path": str(repo)},
        "graph": {"source_commit": base, "graph_digest": man["graph_digest"],
                  "builder_version": man.get("builder_version") or man.get("version") or "unknown",
                  "built_at_utc": man.get("built_at_utc") or captured.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "nodes": total_nodes, "edges": len(graph.get("edges") or [])},
        "tree": {"commit": head, "dirty": False},
        "staleness": {"method": "the graph is built here, from git objects, at change_set.base",
                      "verdict": "fresh", "mismatched_nodes": []},
        "change_set": {"mode": "diff", "base": base, "head": head, "files": cs_files},
        "impact_set": {
            "method": ("global fallback: a lockfile / global-config change makes every node of the graph affected "
                       "(DEC-AUP-0008, the Bazel/Nx rule). The entities are NOT enumerated here: the verifier for "
                       "this impact is the repository's own test job, which makes one statement about the whole "
                       "repository, not one statement per node — enumerating would dress a single measurement up "
                       f"as {total_nodes} of them."),
            "scope": "whole_repository",
            "enumerated": False,
            "deterministic_core": [],
            "inferred_tail": [],
            "global_fallback": {"triggered": True, "files": fallback_files, "scope": "whole_repository",
                                "total_nodes": total_nodes,
                                "reason": (f"{', '.join(fallback_files)} changed ⇒ every node affected "
                                           f"(lockfile / global config: safe fallback, Bazel/Nx practice); "
                                           f"{total_nodes} nodes in the graph at {base[:12]}")},
            "total": total_nodes,
        },
        "verifiers": [verifier],
        "verdicts": verdicts,
        "exemptions": exemptions,
        "admission": {
            "verdict": adm,
            "rule": ("admitted_with_exemptions requires every non-verified entity to carry a valid exemption "
                     "(owner + expiry). Here exactly one entity is exempted — the missing agent-authored receipt. "
                     "The repository entity is never exempted: it is verified by the repository's own test job, "
                     "or it is failed / not_measured and this receipt refuses or pauses the change itself."),
        },
    }
    return receipt, (f"authored for {author.get('login')}: {len(cs_files)} allowlisted path(s), "
                     f"global fallback over {total_nodes} nodes, repository entity {repo_verdict}")


# ------------------------------------------------------------------ AUP-GRAPH-006:gate4b
# Structural exemptions — the typed verdict for a change whose impact the gate structurally CANNOT
# compute. Decided in contracts/graph-verified-change/impact-uncomputable.v1.md; the parameters and
# the non-coverage of each battery live in admission-gate.v1.json → structural_exemptions.
#
# Two cases, ONE mechanism: synthesize the non-code entity that names the missing thing, give it the
# verdict it actually has (`not_measured`), and cover it with an exemption BOUND TO THE DIFF whose
# evidence the gate re-measures itself (C16) — the receipt is never believed about its own exemption.
# The tri-valued entity vocabulary is deliberately NOT widened: a fourth value would be read as
# «not one of the three» — i.e. silently not-a-problem — by every consumer not taught it.
STRUCTURAL_CODES = ("NO_IMPACT_BY_CONSTRUCTION", "GATE_SELF_UPDATE")
CODE_OF_CASE = {"no_impact_by_construction": "NO_IMPACT_BY_CONSTRUCTION",
                "gate_self_update": "GATE_SELF_UPDATE"}
ENTITY_PREFIX_OF_CASE = {"no_impact_by_construction": "impact_computability",
                         "gate_self_update": "gate_self_update"}
DEFAULT_BUNDLE_DIR = ".github/graph-admission"
BUNDLE_MANIFEST_NAME = "BUNDLE.json"
BUNDLE_SIG_NAME = "BUNDLE.json.sig"
BUNDLE_PUBKEY_NAME = "SIGNING-KEY.pub"
BUNDLE_SIGNING_NAMESPACE = "graph-admission-bundle"
STRUCTURAL_EXEMPTION_TTL_HOURS = 24
STRUCTURAL_EXEMPTION_OWNER = "AUP-E29/AUP-GRAPH-006 — issued by tools/graph/admit_change.py exempt, re-measured by the gate (C16)"


def diff_digest(repo: Path, base: str, head: str) -> str:
    """sha256 over the sorted `status \\t path \\t blob_sha` triples of base..head.

    This is the expiry of a structural exemption. A calendar TTL (gate2a's 30 days) survives an
    amend, an added file and a force-push; this digest survives none of them, which is the honest
    lifetime of an assertion about ONE diff."""
    rows = []
    for line in git(repo, "diff", "--raw", "-M", base, head).splitlines():
        if not line.startswith(":"):
            continue
        meta, _, rest = line.partition("\t")
        parts = meta.split()
        if len(parts) < 5 or not rest:
            continue
        status, dst_sha = parts[4], parts[3]
        path = rest.split("\t")[-1]
        rows.append(f"{status}\t{path}\t{dst_sha}")
    return sha256_bytes("\n".join(sorted(rows)).encode())


def bundle_paths_at(repo: Path, ref: str, bundle_rel: str) -> tuple[set[str], dict | None]:
    """The caller-repository paths the bundle manifest at `ref` MANAGES → (paths, manifest).

    Read from git, never from the working tree: the classification of a diff must not depend on
    what happens to be checked out. An entry with `verified_by_the_job is False` (the vendored
    workflow) lives at the repository root, everything else under the bundle directory."""
    rel = bundle_rel.strip("/")
    raw = git(repo, "show", f"{ref}:{rel}/{BUNDLE_MANIFEST_NAME}", check=False)
    if not raw.strip():
        return set(), None
    try:
        man = json.loads(raw)
    except json.JSONDecodeError:
        return set(), None
    paths = {f"{rel}/{BUNDLE_MANIFEST_NAME}", f"{rel}/{BUNDLE_SIG_NAME}", f"{rel}/{BUNDLE_PUBKEY_NAME}"}
    for f in man.get("files") or []:
        p = f.get("path") if isinstance(f, dict) else None
        if isinstance(p, str) and p:
            paths.add(p if f.get("verified_by_the_job") is False else f"{rel}/{p}")
    return paths, man


# AUP-GRAPH-006:gate4b-pin — measured on the REAL subject (muneral), not predicted: a caller pins the
# program SHA in its OWN workflow (`program_ref: '<40hex>'` in .github/workflows/ci.yml), OUTSIDE the
# bundle, precisely so that the bundle cannot vouch for its own pin. A refresh must therefore move a
# file B1 would otherwise call «not bundle-managed», and the shape rule as first written could never
# admit the very change it exists for. The allowance is the narrowest one that is still checkable: the
# ONLY edit tolerated outside the bundle is a `program_ref` line, and its new value must EQUAL the head
# bundle's own program_ref. That is strictly stronger than silence — nothing checked the pin against
# the manifest before the run; now the admission does.
# AUP-GRAPH-006:gate5b — DECLARED DERIVED ARTEFACTS (B6). The argument, the rejected remedy and the
# residuals: contracts/graph-verified-change/derived-artefacts.v1.md. In one line: B1's model — «a bundle
# refresh changes nothing but the bundle» — is false in any caller whose own evidence is bound to its tree,
# and this is the SECOND instance of that error (the first was the program_ref pin, above). The declaration
# lives OUTSIDE the bundle directory on purpose: a file under the bundle path that the manifest does not
# manage is refused by B1 / BUNDLE_MODIFIED_BY_PR, so a declaration kept there could never be read on the
# very change it exists for. `.arcana/` is where a caller already keeps verify.json and fitness-baseline.json.
DEFAULT_DECLARATION_REL = ".arcana/derived-artefacts.v1.json"
DECLARATION_SCHEMA = "GraphAdmissionDerivedArtefacts/v1"
GLOB_CHARS = "*?["
DERIVED_SETUP_TIMEOUT_S = 900
DERIVED_VERIFY_TIMEOUT_S = 600


def read_declaration(repo: Path, ref: str, rel: str = DEFAULT_DECLARATION_REL) -> tuple[dict | None, str]:
    """The declaration IN FORCE is the one at BASE — never at head. A refresh cannot widen its own licence."""
    raw = git(repo, "show", f"{ref}:{rel}", check=False)
    if not raw.strip():
        return None, f"no {rel} at {ref[:12]}: this repository declares no derived artefacts"
    try:
        d = json.loads(raw)
    except json.JSONDecodeError as e:
        return None, f"{rel} at {ref[:12]} is not JSON ({e})"
    if d.get("schema") != DECLARATION_SCHEMA:
        return None, f"{rel} at {ref[:12]} carries schema {d.get('schema')!r}, not {DECLARATION_SCHEMA!r}"
    return d, "read"


def declaration_in_force(repo: Path, base: str, head: str, changed: dict,
                         rel: str = DEFAULT_DECLARATION_REL) -> tuple[dict | None, str, bool]:
    """→ (declaration, why, is_bootstrap). Normally the declaration IN FORCE is the one at BASE: a change
    may not widen its own licence. The single exception is the BOOTSTRAP — the diff ADDS the file and base
    has none — because otherwise a repository whose required suite is red until an artefact is rewritten,
    and whose gate refuses the rewrite until a declaration exists, can never land the declaration at all.
    That is measured, not hypothetical: it is muneral. Reading it at head is only half the rule; B6.1 also
    requires the case to be a bundle refresh, where B1 has proved the VERIFIER is base's."""
    d, why = read_declaration(repo, base, rel)
    if d is not None or changed.get(rel) != "A":
        return d, why, False
    dh, why_h = read_declaration(repo, head, rel)
    if dh is None:
        return None, f"{why}; and the added file at head is unusable: {why_h}", False
    return dh, f"BOOTSTRAP: no declaration at base {base[:12]}; the one at head {head[:12]} is read instead", True


def declared_artefacts(decl: dict | None) -> tuple[dict, list[str]]:
    """→ ({exact path: entry}, [rejected entries]). A glob is a licence whose extent is decided later, by
    whatever files happen to match; an exact path list is one decided when it is merged, in a readable diff."""
    ok, bad = {}, []
    for a in ((decl or {}).get("artefacts") or []):
        pth = a.get("path") if isinstance(a, dict) else None
        if not isinstance(pth, str) or not pth:
            bad.append(f"{a!r}: no path")
        elif any(c in pth for c in GLOB_CHARS):
            bad.append(f"{pth}: a glob, not an exact path")
        elif not isinstance((a.get("verify") or {}).get("argv"), list) or not a["verify"]["argv"]:
            bad.append(f"{pth}: no verify.argv")
        else:
            ok[pth] = a
    return ok, bad


def corrupt_one_byte(data: bytes) -> tuple[bytes, int, str]:
    """Flip ONE byte, in class (digit→digit, letter→letter), so the corruption is SEMANTIC and the verifier
    is made to refuse a wrong VALUE rather than a broken syntax. Deterministic: the first eligible byte at
    or after the midpoint. → (bytes, offset, what)."""
    for i in range(len(data) // 2, len(data)):
        c = data[i:i + 1]
        if c.isdigit():
            return data[:i] + (b"0" if c != b"0" else b"1") + data[i + 1:], i, f"{c.decode()}→{'0' if c != b'0' else '1'}"
        if c.isalpha():
            lo = c.lower()
            r = b"a" if lo != b"a" else b"b"
            r = r.upper() if c.isupper() else r
            return data[:i] + r + data[i + 1:], i, f"{c.decode()}→{r.decode()}"
    return data + b"\n", len(data), "appended a newline (no alphanumeric byte to flip)"


PROGRAM_REF_PIN_RE = re.compile(r"^\s*program_ref:\s*['\"]?([0-9a-f]{40})['\"]?\s*(?:#.*)?$")


def pin_only_edit(repo: Path, base: str, head: str, path: str, expect_ref: str | None) -> tuple[bool, str]:
    """→ (is a program_ref pin update and nothing else, why). Blobs are read from git, never the tree."""
    import difflib
    old = git_text_or_none(repo, "show", f"{base}:{path}")
    new = git_text_or_none(repo, "show", f"{head}:{path}")
    if old is None or new is None:
        side = "base" if old is None else "head"
        return False, (f"the file is not UTF-8 text at {side}, so it cannot be a `program_ref:` pin line "
                       f"— a binary path outside the bundle makes this an ordinary change, which is a "
                       f"verdict, not a traceback (A2-243 defect 3)")
    if not old or not new:
        return False, "the file is added or removed by this change, which is not an in-place pin update"
    diff = [l for l in difflib.unified_diff(old.splitlines(), new.splitlines(), n=0, lineterm="")
            if l[:1] in "+-" and not l.startswith(("---", "+++"))]
    if not diff:
        return True, "no textual change"
    for l in diff:
        m = PROGRAM_REF_PIN_RE.match(l[1:])
        if not m:
            return False, f"a changed line is not a program_ref pin: {l[:90]!r}"
        if l[0] == "+" and expect_ref and m.group(1) != expect_ref:
            return False, (f"the new pin {m.group(1)[:12]} is not the head bundle's program_ref "
                           f"{str(expect_ref)[:12]} — a caller that pins one SHA and vendors another")
    return True, (f"{len(diff)} changed line(s), every one a program_ref pin, every new value equal to the "
                  f"head bundle's program_ref {str(expect_ref)[:12]}")


# ============================================================================================
# DEC-AUP-0038 — the self-update's OWN receipt, as a file.
#
# B1's model is «a bundle refresh changes nothing but the bundle». A ChangeAdmissionReceipt/v1 is
# not part of the bundle, so committing one turned the refresh into an ordinary change — and the
# only carrier left was the pull-request body, which GitHub caps at 65 536 characters. Measured on
# the four refreshes of bundle 21d0f8fb8e60 (A2-244, re-read from the GitHub API on 2026-09-24):
# auth-arcana #150 body 33 879, arcana-agent-system #201 body 37 355, scrutator #98 body 33 786 —
# and muneral #158 body 65 092, i.e. 444 characters of headroom, and only because the receipt was
# minified (74 385 bytes pretty-printed, 63 093 compact). DEC-AUP-0008 says «no receipt, no merge»;
# B1 said the receipt may not be a file; GitHub said the body has a ceiling. The next arm added to
# the B-battery removes the 444, and there is then no way to deliver the receipt at all.
#
# This is the THIRD instance of B1's model being false about a caller (the program_ref pin was the
# first, the declared derived artefact the second), and it is admitted the same way: one exactly
# identified path, every condition re-derived from Git, and nothing about the document's CONTENT
# taken on trust — setting the path aside only decides WHICH CASE the diff belongs to. The receipt
# is then bound, schema-checked, re-measured by impact_pair and coverage-checked exactly as a
# receipt handed in from the body is.
RECEIPT_ISSUE_RE = re.compile(r"^receipts/graph/[^/]+\.json$")


def _self_update_receipt_ok(repo: Path, base: str, head: str, path: str, changed: dict) -> tuple[bool, str]:
    """DEC-AUP-0038 R2, condition by condition. → (is this refresh's own receipt, why)."""
    if changed.get(path) != "A" or git_ok(repo, "cat-file", "-e", f"{base}:{path}"):
        return False, (f"{path} is not ADDED by this range (git status {changed.get(path)!r}); the licence covers "
                       f"the record this refresh FILES, never an edit to a receipt that already stood there")
    raw = git(repo, "show", f"{head}:{path}", check=False)
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        return False, f"{path} is not JSON at head ({e})"
    if not isinstance(doc, dict) or not str(doc.get("schema", "")).startswith("ChangeAdmissionReceipt"):
        return False, f"{path} carries schema {(doc or {}).get('schema')!r}, not ChangeAdmissionReceipt/v1"
    wid = work_item_id(doc.get("work_item"))
    if not wid:
        return False, (f"{path} declares no work item — a record nobody owns is not this change's receipt "
                       f"(re-issue with --work-item <ID>)")
    cs = doc.get("change_set") or {}
    if cs.get("mode") != "diff":
        return False, f"{path} was taken in {cs.get('mode')!r} mode, not over a diff, so it names no range"
    if cs.get("base") != base:
        return False, (f"{path} is about {str(cs.get('base'))[:12]}..{str(cs.get('head'))[:12]}, and this "
                       f"admission is about {base[:12]}..{head[:12]}")
    rhead = cs.get("head")
    if not isinstance(rhead, str) or rhead not in set(range_commits(repo, base, head)):
        return False, (f"{path} names head {str(rhead)[:12]}, which is not a commit of {base[:12]}..{head[:12]}")
    return True, (f"{path} is this refresh's own ChangeAdmissionReceipt/v1 for work item {wid} over "
                  f"{base[:12]}..{rhead[:12]} — added by this range, and judged on its merits by every "
                  f"check below (DEC-AUP-0038)")


def split_self_update_receipt(repo: Path, base: str, head: str, outside: list[str],
                              changed: dict) -> tuple[list[str], list[str], dict]:
    """→ (0 or 1 receipt path, the rest of `outside`, evidence). DEC-AUP-0038 R1/R2/R4."""
    candidates = [p for p in outside if RECEIPT_ISSUE_RE.match(p)]
    ev: dict = {"rule": "DEC-AUP-0038", "candidates": candidates, "admitted": None}
    if not candidates:
        ev["why"] = "no receipts/graph/*.json among the changed paths outside the bundle"
        return [], list(outside), ev
    if len(candidates) > 1:
        ev["why"] = (f"{len(candidates)} receipts under receipts/graph/ ({', '.join(candidates[:4])}) — a refresh "
                     f"files exactly one record of itself, and «at most one» is what makes the licence checkable")
        return [], list(outside), ev
    path = candidates[0]
    ok, why = _self_update_receipt_ok(repo, base, head, path, changed)
    ev["why"] = why
    if not ok:
        return [], list(outside), ev
    ev["admitted"] = path
    ev["work_item"] = work_item_id((json.loads(git(repo, "show", f"{head}:{path}")) or {}).get("work_item"))
    return [path], [p for p in outside if p != path], ev


# ============================================================================================
# A2-261 / DEC-AUP-0041 — the record commit of a caller whose evidence binds its WHOLE tree.
#
# DEC-AUP-0038 R6 admits one alternative binding, `base..H` (H = the receipt's own head), and only
# when the single path between H and this head is the receipt. That condition is unsatisfiable in the
# one caller the decision was written for. muneral declares `apps/api/test/assembly/mutation-results.json`,
# whose content pins `trackedTreeWithoutEvidence` — a hash of the whole tracked tree, the receipt file
# included — so the commit that FILES the receipt necessarily regenerates the artefact, two paths move,
# and the tolerance does not apply. All four commit orderings were tried on the real repository and none
# is a fixed point (A2-256 §4.1, 2026-09-24, branch arc2/a2-256-receipt-file-attempt @143c84b):
#
#   STRUCTURAL_EXEMPTION_UNSOUND — GATE_SELF_UPDATE: change_binding sha256:7d966430… /
#   5954cff8a922..992e8527423f does not bind this diff (sha256:2c4212bb… / 5954cff8a922..143c84beff6a)
#
# The remedy is a DEDUPLICATION, not a new licence. GATEORDER-0 (`trailing-record-commits.v1.md`, check
# C06) already decided — in writing, before the code — which paths a commit AFTER a receipt's head may
# carry: (a) the bound receipt itself, and (b) a derived artefact declared at BASE whose own verifier is
# run at head and run again with one byte corrupted, which it must refuse. R6 asks the identical question
# about the binding digest and answers it with (a) alone, because the refresh it was written against
# (scrutator) moved no artefact. One gate held two definitions of "record path", and muneral is the
# witness: the identical commit satisfies C06 and fails C16.
#
# So the predicate below is shared by both call sites. What it is NOT is a pass: a path it admits is
# still measured by B6.4/B6.5 at head, and `recheck_structural` refuses the change unless those runs
# prove that path by themselves. Three guards come from the consilium of 2026-09-24 and are new to BOTH
# rules (governance/consilium/2026-09-24-record-commit-derived-artefact/):
#   - a path that is NOT a regular file at head is refused. `_verify_declared_artefacts` and B6.5 write
#     the corrupted bytes to `worktree/path` and restore them afterwards; if that path is a symlink the
#     runner writes THROUGH it, outside the worktree. Nothing in this file looked at a blob's mode.
#   - a path named by a declared `argv`/`cwd` is refused: an artefact that IS its own verifier would
#     vouch for its own replacement.
#   - the artefact must already exist at base for the R6 window (`require_at_base`), because a file
#     added after the receipt's head is a new fact, not a refreshed one — the same thing B6.2 says.
INTERPRETERS = ("node", "python", "python3", "sh", "bash", "zsh", "ruby", "perl", "deno", "bun", "pnpm",
                "npm", "npx", "yarn", "uv", "pwsh")


def declared_command_paths(entries: dict) -> set[str]:
    """The repository paths a declaration's setup/verify commands EXECUTE — never the ones they read.

    The distinction is the whole point and it is positional: argv[0] is the program, and argv[1] is too
    when argv[0] is an interpreter. Everything after that is data. Measured on the real subject before
    this narrowing existed: muneral's verify argv is
    `node apps/api/test/assembly/mutation-harness.js --verify-structure apps/api/test/assembly/mutation-results.json`,
    so a rule that treated every argv token as executed code refused muneral's OWN artefact for appearing
    as its own verifier's argument — a guard that fires on the case it was written to permit."""
    out: set[str] = set()
    for e in (entries or {}).values():
        for stage in ("verify", "setup"):
            s = (e or {}).get(stage) if isinstance(e, dict) else None
            if not isinstance(s, dict):
                continue
            cwd = str(s.get("cwd") or ".").strip("/")
            argv = [str(t).strip() for t in (s.get("argv") or [])]
            heads = argv[:1]
            if argv and Path(argv[0]).name in INTERPRETERS:
                heads += [t for t in argv[1:2] if not t.startswith("-")]
            for t in heads:
                t = t.lstrip("/")
                t = t[2:] if t.startswith("./") else t
                if not t:
                    continue
                out.add(t)
                if cwd and cwd != ".":
                    out.add(f"{cwd}/{t}")
    return out


def blob_mode(repo: Path, ref: str, path: str) -> str | None:
    """The git file mode of one path at one ref, or None when the path is not there."""
    out = git(repo, "ls-tree", ref, "--", path, check=False).strip()
    return out.split(" ", 1)[0] if out else None


REGULAR_MODES = ("100644", "100755")


def record_path_refusal(repo: Path, base: str, head: str, path: str, entries: dict,
                        *, require_at_base: bool = False) -> str | None:
    """→ the reason `path` may NOT be a record path of a commit after a receipt's head, or None.

    ONE definition, two callers: C06's clause (b) and the DEC-AUP-0038 R6 binding window. Everything is
    read from git at base and head; the declaration is the one at BASE, never at head, and the B6.1
    BOOTSTRAP is deliberately not honoured — a change may not license its own record commit."""
    if not isinstance(entries.get(path), dict):
        return (f"{path} is not an exact entry of {DEFAULT_DECLARATION_REL} read at base {base[:12]} — the "
                f"declaration in force is base's, and a glob is not an exact path")
    mode_h = blob_mode(repo, head, path)
    if mode_h is None:
        return f"{path} does not exist at head {head[:12]}: there are no bytes for its verifier to judge"
    if mode_h not in REGULAR_MODES:
        return (f"{path} is mode {mode_h} at head {head[:12]}, not a regular file — the mutation test writes "
                f"to it and a symlink or a gitlink is written THROUGH, off the worktree")
    if require_at_base:
        mode_b = blob_mode(repo, base, path)
        if mode_b is None:
            return (f"{path} is ADDED after the receipt's head, not refreshed — a new file is a new fact, and "
                    f"the exemption was issued before it existed")
        if mode_b not in REGULAR_MODES:
            return f"{path} is mode {mode_b} at base {base[:12]}, not a regular file"
    if path in declared_command_paths(entries):
        return (f"{path} is itself named by a declared setup/verify argv — an artefact that IS the verifier "
                f"would vouch for its own replacement")
    return None


def admissible_ranges_invariant(admissible: set, head: str, record_head: str | None) -> str | None:
    """DEC-AUP-0038 reverse_if R-4, as a predicate rather than as prose → the refusal, or None.

    A2-261b extracted it from `recheck_structural`. Inline it was a TRIPWIRE over a condition no input
    can reach — `admissible` is built there as one literal plus at most one `add`, so `> 2` is dead by
    construction and no mutation of the call site can be made red. A tripwire is still worth keeping
    (it is what notices the day someone adds a third `add`), but "cannot go red" is not "verified", so
    the predicate is tested DIRECTLY on a synthetic three-member set instead of being left unmeasured.
    """
    if len(admissible) > 2 or {h for _d, _b, h in admissible} - {head, record_head or head}:
        return (f"the gate built {len(admissible)} admissible binding range(s) for this change — DEC-AUP-0038 R6 "
                f"and DEC-AUP-0041 allow exactly `base..head` and `base..<the bound receipt's own head>`, and a "
                f"third range is the observation that withdraws the whole tolerance (DEC-AUP-0038 reverse_if R-4)")
    return None


# ============================================================================================
# A2-298 / DEC-AUP-0051 — «Update branch» is not a second change.
#
# Measured by control on arcana-agent-system#218, 2026-09-25. A bundle refresh was open, `main` moved,
# the branch was updated from `main` through GitHub's button, and the refresh stopped being admissible:
# `graph-admission` refused BUNDLE_MODIFIED_BY_PR, the receipt found 0 receipts at head, `reissue` gave
# PAUSED_SAFE, and `exempt` said NOT ELIGIBLE with «2 changed paths are outside the bundle». The pull
# request was rebuilt from scratch on `main` as #221. Nothing was wrong with it; the SHAPE RULE could
# not see the difference between a file this pull request wrote and a file the base branch wrote and
# the merge carried in.
#
# B1's model is «a bundle refresh changes nothing but the bundle», and `git diff base..head` after an
# update-branch merge contains every path the base branch moved since `base` — none of which the
# refresh authored. This is the FOURTH time B1's model has been false about a caller (the program_ref
# pin, the declared derived artefact, the refresh's own receipt), and it is admitted the same way:
# one exactly identified set of paths, every condition re-derived from Git, nothing taken on trust.
#
# WHAT THE SHAPE PROVES, and it is proved rather than assumed. For each path the split admits, the git
# BLOB OID at head is byte-identical to the blob OID at `A` — the merge-base of the base branch and
# head, i.e. the base branch commit this branch was brought up to. Identical OIDs are identical bytes:
# the pull request contributes NOTHING at that path, it merely contains the base branch. Two further
# conditions make that reading safe:
#   * every non-first parent merged into this range must be an ancestor of the base branch, so a
#     feature branch merged in sideways (which also descends from `base`) is NOT admitted here; and
#   * no merge commit in the range may touch a bundle-managed path relative to its first parent —
#     a merge that rewrites gate bytes is a change to the gate, whoever resolved it.
#
# WHAT IT DOES NOT PROVE, written here rather than left for someone to discover: that the bytes at A
# were themselves admitted. The shape proves they are the BASE BRANCH's bytes, unmodified; that the
# base branch only accepts admitted bytes is a property of that branch's protection rule and of
# nothing in this file — the same residual `evaluate_workflow_integrity` names for the vendored
# workflow. If `main` can take an unadmitted commit, this licence carries it; so can any merge.
#
# The base branch is never GUESSED by name. Either the caller names it (`--base-branch`), or the
# repository itself says which branch it clones (`refs/remotes/origin/HEAD`). When neither resolves,
# the paths are NOT admitted and the arm is not_measured — today's refusal, unchanged.
def resolve_base_branch(repo: Path, base_branch: str | None) -> tuple[str | None, str]:
    """→ (a ref that resolves in this clone, why). Never invents a branch name."""
    if base_branch:
        if git_ok(repo, "rev-parse", "--verify", f"{base_branch}^{{commit}}"):
            return base_branch, f"named by --base-branch ({base_branch})"
        return None, (f"--base-branch {base_branch!r} does not resolve to a commit in this clone, so the "
                      f"base branch is unknown — a ref that is not there is not a base branch")
    tgt = git(repo, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD", check=False).strip()
    if tgt and git_ok(repo, "rev-parse", "--verify", f"{tgt}^{{commit}}"):
        return tgt, (f"read from the repository itself: refs/remotes/origin/HEAD → {tgt}; no --base-branch "
                     f"was given and no branch name was assumed")
    return None, ("no base branch: --base-branch was not given and this clone has no "
                  "refs/remotes/origin/HEAD to read one from (a bare fetch of one pull-request ref has none)")


def _range_merges(repo: Path, base: str, head: str) -> list[dict]:
    """Every merge commit on the FIRST-PARENT line of base..head, with its parents. The first-parent
    line is the branch's own history: a merge reachable only through someone else's second parent was
    not performed on this branch and is not this branch's update."""
    out = []
    for line in git(repo, "rev-list", "--merges", "--first-parent", "--parents",
                    f"{base}..{head}", check=False).splitlines():
        ids = line.split()
        if len(ids) >= 3:
            out.append({"commit": ids[0], "first_parent": ids[1], "merged_in": ids[2:]})
    return out


def split_base_branch_merge(repo: Path, base: str, head: str, outside: list[str], changed: dict,
                            managed: set[str], base_branch: str | None = None,
                            ) -> tuple[list[str], list[str], dict]:
    """→ (paths the BASE BRANCH brought in, the rest of `outside`, evidence). DEC-AUP-0051."""
    ev: dict = {"rule": "DEC-AUP-0051", "merges": [], "admitted": [], "refused": {}, "base_branch": None}
    merges = _range_merges(repo, base, head)
    ev["merges"] = [m["commit"][:12] for m in merges]
    if not merges:
        ev["verdict"] = "vacuous"
        ev["why"] = "no merge commit on the first-parent line of this range — nothing was merged in"
        return [], list(outside), ev
    ref, why = resolve_base_branch(repo, base_branch)
    ev["base_branch"], ev["base_branch_why"] = ref, why
    if not ref:
        ev["verdict"] = "not_measured"
        ev["why"] = why
        return [], list(outside), ev
    anchor = git(repo, "merge-base", ref, head, check=False).strip()
    ev["anchor"] = anchor or None
    if not anchor:
        ev["verdict"] = "not_measured"
        ev["why"] = f"{ref} and {head[:12]} have no merge base in this clone"
        return [], list(outside), ev
    sideways = [m["commit"][:12] for m in merges
                for p in m["merged_in"] if not git_ok(repo, "merge-base", "--is-ancestor", p, ref)]
    if sideways:
        ev["verdict"] = "failed"
        ev["why"] = (f"merge commit(s) {', '.join(sorted(set(sideways)))} bring in a parent that is NOT an "
                     f"ancestor of {ref} — something other than the base branch was merged into this "
                     f"refresh, and a sideways merge descends from the base too, so descent proves nothing")
        return [], list(outside), ev
    if not git_ok(repo, "merge-base", "--is-ancestor", base, anchor) or anchor == base:
        ev["verdict"] = "failed" if anchor != base else "vacuous"
        ev["why"] = (f"the base branch anchor {anchor[:12]} is {base[:12]} itself — the base branch has not "
                     f"moved, so no path in this diff can have come from it"
                     if anchor == base else
                     f"the base branch anchor {anchor[:12]} is not a descendant of the range's base "
                     f"{base[:12]}: this is not a branch brought UP TO its base branch")
        return [], list(outside), ev
    touched_bundle = {}
    for m in merges:
        moved = {x for x in git(repo, "diff", "--name-only", "--no-renames", m["first_parent"], m["commit"],
                                check=False).split("\n") if x}
        ev.setdefault("merge_brought_in", {})[m["commit"][:12]] = sorted(moved)[:24]
        bad = sorted(moved & managed)
        if bad:
            touched_bundle[m["commit"][:12]] = bad
    if touched_bundle:
        ev["verdict"] = "failed"
        ev["merge_touched_bundle"] = touched_bundle
        ev["why"] = (f"merge commit(s) {', '.join(touched_bundle)} modify bundle-managed path(s) "
                     f"({'; '.join(sorted({p for v in touched_bundle.values() for p in v})[:4])}) relative to "
                     f"their first parent — gate bytes written by a merge resolution are a change to the gate")
        return [], list(outside), ev
    admitted, rest = [], []
    for p in outside:
        at_head = git(repo, "rev-parse", f"{head}:{p}", check=False).strip() or None
        at_anchor = git(repo, "rev-parse", f"{anchor}:{p}", check=False).strip() or None
        if at_head is not None and at_head == at_anchor:
            admitted.append(p)
            ev.setdefault("blob_identity", {})[p] = at_head[:12]
        elif at_head is None and at_anchor is None:
            admitted.append(p)
            ev.setdefault("blob_identity", {})[p] = "absent at head and at the base branch anchor"
        else:
            rest.append(p)
            ev["refused"][p] = (f"head {str(at_head)[:12] if at_head else 'absent'} is not the base branch's "
                                f"{str(at_anchor)[:12] if at_anchor else 'absent'} — this pull request wrote it")
    ev["admitted"] = admitted
    ev["verdict"] = "verified" if admitted else "vacuous"
    ev["why"] = (f"{len(admitted)} changed path(s) carry, at head, the very git blob the base branch carries at "
                 f"{anchor[:12]} ({ref}), brought in by merge commit(s) {', '.join(ev['merges'])} that touch no "
                 f"bundle-managed path: this change contributes nothing at those paths"
                 if admitted else
                 f"this range merges the base branch ({anchor[:12]}), but no changed path outside the bundle "
                 f"carries the base branch's bytes at head")
    return admitted, rest, ev


def split_outside(repo: Path, base: str, head: str, outside: list[str],
                  expect_ref: str | None,
                  declared: frozenset = frozenset()) -> tuple[list[str], list[str], list[str]]:
    """→ (pin-only edits, declared derived artefacts, everything else). Everything else makes the change an
    ordinary one. `declared` is read at BASE by the caller of this function; being in it is not yet a pass —
    B6 has six more arms to survive."""
    pin, derived, rest = [], [], []
    for p in outside:
        if p in declared:
            derived.append(p)
            continue
        ok, why = pin_only_edit(repo, base, head, p, expect_ref)
        (pin if ok else rest).append(p if ok else f"{p}: {why}")
    return pin, derived, rest


# ============================================================================================
# AUP-DEBT-002 Card 1 (B7) — DEC-AUP-0020. Amending `.arcana/derived-artefacts.v1.json` ITSELF.
#
# B6 (above) verifies that a DECLARED artefact really is derived. It never verifies the
# DECLARATION's own edit: a diff that touches ONLY the declaration file is routed by
# `structural_case()` to the ORDINARY rule (B6.1's own comment already says so: "widening it is an
# ordinary change, under the ordinary rule") — and the ordinary rule's impact set for a file no
# extractor models is empty, every time, by construction, so DEC-AUP-0008's own correct default
# (empty impact + no exemption => paused_safe) then refuses it forever. The guard cannot see itself,
# so it cannot move. Full grounding: governance/decisions/DEC-AUP-0020.json,
# governance/consilium/2026-09-07-derived-artefacts-self-amend/ (SYNTHESIS.md).
#
# B7 is a NEW, NARROW arm, scoped ONLY to this one file's own schema — never a general fix to the
# graph-impact path (DEC-AUP-0020 rule 2). It fires ONLY when a diff's changed paths are EXACTLY
# {declaration_rel}, status M. Binding rules, all from DEC-AUP-0020:
#   - a CLOSED diff grammar: one add-path, one remove-path, one add-glob, or one narrow-an-existing-
#     glob per change (rule 3). Anything else is not a "declaration edit"; it never reaches B7.
#   - no bare wildcard, and no glob that can match anything a graph source root already covers
#     (rule 3's own abuse case, `src/**`).
#   - a mandatory dry-run replay of B6.2-B6.6 against the diff that motivated the request, before
#     admission (rule 4) — except a REMOVAL, exempt by rule 5 (it can only narrow the exemption).
#   - a second, independent authority distinct from the one that computed the primary verdict
#     (rule 7 — this program's consilium idiom, per Role 5's reasoning that DEC-AUP-0010 already
#     forbids inventing a human sign-off gate).
#   - grant-and-spend in the same commit/PR is an ABSOLUTE refusal (rule 6). Enforced STRUCTURALLY
#     here, not by a promise: the case fires only for a SOLO edit to the declaration file, so a diff
#     that also uses the new entry never reaches B7 at all — it falls to the ordinary rule, where
#     B6.1 already refuses "the declaration is itself changed by this diff" for anything reaching B6.
# ============================================================================================
DECLARATION_AMEND_CASE = "declaration_amend"
SPENT_RECEIPT_ARCHIVE_CASE = "spent_receipt_archive"
CODE_OF_CASE["spent_receipt_archive"] = "SPENT_RECEIPT_ARCHIVE"
ENTITY_PREFIX_OF_CASE["spent_receipt_archive"] = "spent_receipt_archive"
RECEIPT_ARCHIVE_PREFIX = "receipts/archive/"
CODE_OF_CASE["declaration_amend"] = "GATE_DECLARATION_AMEND"
ENTITY_PREFIX_OF_CASE["declaration_amend"] = "gate_declaration_amend"
STRUCTURAL_CODES = STRUCTURAL_CODES + ("GATE_DECLARATION_AMEND",)
STRUCTURAL_CODES = STRUCTURAL_CODES + ("SPENT_RECEIPT_ARCHIVE",)
SOURCE_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs", ".java", ".rb", ".mjs", ".cjs"}


def _b7_glob_runs(pattern: str) -> list[tuple[int, int]]:
    """[(start, end)) of each MAXIMAL run of characters in GLOB_CHARS."""
    runs, i, n = [], 0, len(pattern)
    while i < n:
        if pattern[i] in GLOB_CHARS:
            j = i + 1
            while j < n and pattern[j] in GLOB_CHARS:
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    return runs


def b7_glob_narrows(old: str, new: str) -> tuple[bool, str]:
    """→ (is `new` a SOUND narrowing of `old`, why). Pattern-subset for arbitrary globs is not
    decidable by inspection in general, and DEC-AUP-0020's grammar is "refused, not approximated" —
    so this recognises exactly ONE syntactic shape, chosen because it is provably sound (never a
    false positive): `old` has EXACTLY ONE contiguous run of glob characters (its one wildcard
    token — `*`, `**`, or `?`); `new` has the identical literal prefix and suffix around that same
    position, and its middle is that SAME wildcard token with purely literal characters added around
    it, and nothing else in `new` is a glob character. `*`/`**` matches strictly more than
    `<literal>*` or `*<literal>` — located this way, prefix/suffix identity cannot be fooled by a
    literal substring downstream of the wildcard that happens to coincide character-for-character."""
    if not old or not new or old == new:
        return False, "identical, or one side empty — not a narrowing"
    old_runs = _b7_glob_runs(old)
    if len(old_runs) != 1:
        return False, (f"the OLD pattern has {len(old_runs)} run(s) of glob characters, not exactly one — this "
                       f"function recognises narrowing only a pattern with a SINGLE wildcard token, refused "
                       f"rather than approximated for any other shape")
    s, e = old_runs[0]
    old_mid = old[s:e]
    if old_mid not in ("*", "**", "?"):
        return False, f"the OLD pattern's one wildcard token is {old_mid!r}, not `*`, `**`, or `?`"
    prefix, suffix = old[:s], old[e:]
    if not new.startswith(prefix) or not new.endswith(suffix) or len(new) < len(prefix) + len(suffix):
        return False, (f"the NEW pattern does not share the OLD pattern's literal prefix {prefix!r} and suffix "
                       f"{suffix!r} around its wildcard — not a narrowing of THIS token")
    new_mid = new[len(prefix):len(new) - len(suffix)] if suffix else new[len(prefix):]
    if not new_mid or old_mid not in new_mid:
        return False, f"the NEW pattern's middle {new_mid!r} does not contain the OLD wildcard token {old_mid!r}"
    added = new_mid.replace(old_mid, "", 1)
    if any(c in GLOB_CHARS for c in added):
        return False, (f"the NEW pattern adds {added!r} around the wildcard, and that addition itself contains a "
                       f"glob character — that can WIDEN, not narrow, and is refused")
    if not added:
        return False, "the NEW pattern's middle is identical to the OLD wildcard token — not a narrowing, no change"
    return True, f"{old!r} -> {new!r}: the sole wildcard token {old_mid!r} gained the literal constraint {added!r}"


def b7_classify_grammar(old_artefacts, new_artefacts) -> dict:
    """The closed diff grammar (DEC-AUP-0020 rule 3) over the declaration's `artefacts` list, keyed
    by `path`. → dict with `op` in {"add", "remove", "narrow_glob", "invalid"}, `detail`, and (for
    add/narrow_glob) `entry` — the entry as it reads at head."""
    def by_path(lst):
        out = {}
        for a in (lst or []):
            if isinstance(a, dict) and isinstance(a.get("path"), str) and a["path"]:
                out[a["path"]] = a
        return out
    old_m, new_m = by_path(old_artefacts), by_path(new_artefacts)
    added = [p for p in new_m if p not in old_m]
    removed = [p for p in old_m if p not in new_m]
    same_path_changed = [p for p in (set(old_m) & set(new_m))
                         if json.dumps(old_m[p], sort_keys=True) != json.dumps(new_m[p], sort_keys=True)]

    if len(added) == 1 and not removed and not same_path_changed:
        p, entry = added[0], new_m[added[0]]
        if not isinstance((entry.get("verify") or {}).get("argv"), list) or not entry["verify"]["argv"]:
            return {"op": "invalid", "detail": f"the added entry {p!r} has no verify.argv — an entry B6.1 would "
                                               f"refuse as unusable anyway; B7 does not admit a licence that "
                                               f"cannot be checked"}
        return {"op": "add", "path": p, "entry": entry,
                "detail": f"exactly one path/glob added ({p!r}), nothing else in the declaration changed"}

    if len(removed) == 1 and not added and not same_path_changed:
        p = removed[0]
        return {"op": "remove", "path": p, "entry": old_m[p],
                "detail": f"exactly one declared path/glob removed ({p!r}), nothing else changed — DEC-AUP-0020 "
                          f"rule 5: this can only NARROW the exemption surface"}

    if len(added) == 1 and len(removed) == 1 and not same_path_changed:
        # a glob narrowing shows up as one add + one remove: the pattern string IS the dict key.
        old_p, new_p = removed[0], added[0]
        old_e, new_e = old_m[old_p], new_m[new_p]
        rest_old = {k: v for k, v in old_e.items() if k != "path"}
        rest_new = {k: v for k, v in new_e.items() if k != "path"}
        if json.dumps(rest_old, sort_keys=True) != json.dumps(rest_new, sort_keys=True):
            return {"op": "invalid", "detail": f"{old_p!r} -> {new_p!r} changes verify/setup as well as the "
                                               f"path/glob — DEC-AUP-0020 rule 3 forbids bundling a change to an "
                                               f"existing entry's verify/setup with anything else"}
        ok, why = b7_glob_narrows(old_p, new_p)
        if not ok:
            return {"op": "invalid", "detail": f"{old_p!r} -> {new_p!r} is not a provable narrowing: {why}"}
        return {"op": "narrow_glob", "path": new_p, "old_path": old_p, "entry": new_e, "detail": why}

    return {"op": "invalid",
            "detail": f"{len(added)} added, {len(removed)} removed, {len(same_path_changed)} entry(ies) with the "
                      f"same path but different content — not expressible as the closed grammar (exactly one add, "
                      f"one remove, or one narrow-glob per change); DEC-AUP-0020 rule 3: refused, not approximated"}


def b7_source_roots(repo: Path, ref: str) -> set[str]:
    """Top-level directories at `ref` that hold at least one file of a recognised source extension —
    an OVER-approximation of "a graph source root", on purpose: asking "does build_graph.py actually
    extract from this file" exactly would mean building the whole graph for a syntactic pre-check,
    and over-approximating can only make B7 refuse MORE, never admit a glob it should not."""
    out = git(repo, "ls-tree", "-r", "--name-only", ref, check=False)
    roots = set()
    for line in out.splitlines():
        if "." in line.rsplit("/", 1)[-1] and ("." + line.rsplit(".", 1)[-1]) in SOURCE_EXTENSIONS:
            roots.add(line.split("/", 1)[0])
    return roots


def b7_covers_source_root(repo: Path, ref: str, pattern: str) -> tuple[bool, str]:
    """DEC-AUP-0020 rule 3's own abuse case: no glob that can match anything a graph source root
    already covers (`src/**` or equivalent). A bare wildcard (every path segment is glob-only) is
    refused outright; otherwise refuse if the pattern's fixed prefix names, or sits inside, a
    discovered source root, or the pattern matches a synthetic deep probe path under one."""
    segments = pattern.split("/")
    if all(seg == "" or all(c in GLOB_CHARS for c in seg) for seg in segments):
        return True, f"{pattern!r} has no literal path segment at all — a bare wildcard, refused outright"
    roots = b7_source_roots(repo, ref)
    first_glob = next((k for k, c in enumerate(pattern) if c in GLOB_CHARS), len(pattern))
    prefix = pattern[:first_glob].rstrip("/")
    for root in sorted(roots):
        probe = f"{root}/__b7_probe__/__b7_probe__.ts"
        matches = fnmatch.fnmatch(probe, pattern) or fnmatch.fnmatch(f"{root}/x", pattern)
        if matches or prefix in (root, ""):
            return True, (f"{pattern!r} matches under, or sits at, the source root {root!r} "
                          f"(probe {probe!r} matches: {matches}; fixed prefix {prefix!r})")
    return False, (f"{pattern!r} matches no probe path under any of {len(roots)} discovered source root(s) "
                   f"({sorted(roots)[:6]}), and its fixed prefix {prefix!r} does not coincide with one")


def b7_match_candidate(pattern: str, changed_paths: list[str]) -> list[str]:
    """The concrete paths in a CANDIDATE diff that `pattern` would license, TODAY. A glob's ultimate
    extent is still "decided later, by whatever files happen to match" (declared_artefacts' own
    docstring) — this proves the arms hold for what matches now, not for all time."""
    if any(c in GLOB_CHARS for c in pattern):
        return sorted(p for p in changed_paths if fnmatch.fnmatch(p, pattern))
    return [pattern] if pattern in changed_paths else []


def b7_dry_run(repo: Path, entry: dict, candidate_base: str, candidate_head: str, workdir: Path, *,
              verifier_job: str | None = None, verifier_conclusion: str | None = None) -> dict:
    """DEC-AUP-0020 rule 4 — replay B6.2-B6.6 as if `entry` were already declared, against the diff
    that actually motivated the request. B6.1 is deliberately NOT replayed: it asks whether the entry
    is declared at BASE, which is exactly the question B7 exists to answer for the FIRST time. A
    synthetic exact-path declaration — one entry per file the pattern actually matches in the
    candidate diff — makes B6.1 trivially true so B6.2-B6.6 run for real, on the real gate code."""
    cfiles = range_files(repo, candidate_base, candidate_head)
    changed_paths = [f["path"] for f in cfiles]
    matched = b7_match_candidate(entry["path"], changed_paths)
    ev: dict = {"case": "declaration_amend_dry_run", "checks": [],
                "candidate_range": f"{candidate_base}..{candidate_head}", "matched": matched}
    if not matched:
        _chk(ev, "B7.DRYRUN", "DRY_RUN", None,
             f"{entry['path']!r} matches no path changed in the candidate diff {candidate_base[:12]}.."
             f"{candidate_head[:12]} — nothing to replay against. 'nothing matched' is not a real verdict: "
             f"not_measured, not a pass")
        return ev
    synth_decl = {"schema": DECLARATION_SCHEMA,
                  "artefacts": [{**{k: v for k, v in entry.items() if k != "path"}, "path": p} for p in matched]}
    inner_ev: dict = {"checks": []}
    evaluate_derived(repo, candidate_base, candidate_head, matched, synth_decl,
                     "dry-run synthetic declaration (B7)", [], cfiles, workdir, inner_ev,
                     declaration_rel=DEFAULT_DECLARATION_REL, case="",
                     verifier_job=verifier_job, verifier_conclusion=verifier_conclusion)
    # evaluate_derived's own per-arm detail lives in `derived_arms` (B6.1-B6.6); `checks` carries only
    # its ONE rolled-up "B6" summary line. B6.1 is included there too (trivially true against our
    # synthetic exact-path declaration) — dropped here since rule 4 asks for B6.2-B6.6 specifically.
    ev["checks"] = [c for c in (inner_ev.get("derived_arms") or []) if c["id"] != "B6.1"]
    ev["derived_arms"] = inner_ev.get("derived_arms")
    ev["derived_runs"] = inner_ev.get("derived_runs")
    return ev


def evaluate_declaration_amend(repo: Path, base: str, head: str, files: list[dict], workdir: Path, *,
                               declaration_rel: str = DEFAULT_DECLARATION_REL,
                               candidate_range: str | None = None,
                               authority_id: str | None = None,
                               second_opinion: dict | None = None,
                               verifier_job: str | None = None,
                               verifier_conclusion: str | None = None) -> dict:
    """B7 — DEC-AUP-0020. Admits an amendment to the declaration file ITSELF. Reachable only when
    `structural_case()` finds this diff's changed paths are EXACTLY {declaration_rel} — every other
    path stays on the ordinary rule, unmodified, per the decision's own rule 2."""
    ev: dict = {"case": "declaration_amend", "checks": [], "eligible": False}
    changed = {f["path"]: str(f["status"])[0] for f in files}
    if not _chk(ev, "B7.1", "NOT_SAME_CHANGE", set(changed) == {declaration_rel} and changed.get(declaration_rel) == "M",
                f"DEC-AUP-0020 rule 6 (grant-and-spend), enforced structurally: B7 admits ONLY a diff whose "
                f"changed paths are exactly {{{declaration_rel!r}}}; this diff changes {sorted(changed)} — "
                f"anything else falls to the ordinary rule, which B6.1 already refuses if it also touches the "
                f"declaration"):
        return ev
    old_raw = git(repo, "show", f"{base}:{declaration_rel}", check=False)
    new_raw = git(repo, "show", f"{head}:{declaration_rel}", check=False)
    try:
        old_doc = json.loads(old_raw) if old_raw.strip() else {"schema": DECLARATION_SCHEMA, "artefacts": []}
        new_doc = json.loads(new_raw)
    except json.JSONDecodeError as e:
        _chk(ev, "B7.2", "GRAMMAR", False, f"the declaration is not valid JSON on one side of this diff: {e}")
        return ev
    if not _chk(ev, "B7.2", "GRAMMAR",
                new_doc.get("schema") == DECLARATION_SCHEMA and
                b7_classify_grammar(old_doc.get("artefacts"), new_doc.get("artefacts"))["op"] != "invalid",
                "closed diff grammar (DEC-AUP-0020 rule 3): " +
                (f"head declares schema {new_doc.get('schema')!r}, want {DECLARATION_SCHEMA!r}"
                 if new_doc.get("schema") != DECLARATION_SCHEMA else
                 b7_classify_grammar(old_doc.get("artefacts"), new_doc.get("artefacts"))["detail"])):
        return ev
    grammar = b7_classify_grammar(old_doc.get("artefacts"), new_doc.get("artefacts"))
    ev["grammar"], ev["op"] = grammar, grammar["op"]
    op, pattern = grammar["op"], grammar.get("path")

    if op in ("add", "narrow_glob"):
        covers, why = b7_covers_source_root(repo, head, pattern)
        if not _chk(ev, "B7.3", "SCOPE", not covers,
                    f"no bare wildcard, no glob matching a graph source root (DEC-AUP-0020 rule 3's abuse case, "
                    f"`src/**`): {why}"):
            return ev
    else:
        _chk(ev, "B7.3", "SCOPE", True, "a removal can only narrow the exemption surface — DEC-AUP-0020 rule 5")

    if op == "remove":
        _chk(ev, "B7.4", "DRY_RUN", True,
             "removal is exempt from the dry-run requirement (DEC-AUP-0020 rule 5): it can only narrow the "
             "exemption surface, never widen it")
    elif not candidate_range or ".." not in (candidate_range or ""):
        _chk(ev, "B7.4", "DRY_RUN", None,
             "DEC-AUP-0020 rule 4 requires a dry-run replay against the diff that motivated the request; no "
             "--b7-candidate-range was given, so the arm cannot be measured. not_measured is not a pass: the "
             "amendment pauses")
    else:
        cb, chd = candidate_range.split("..", 1)
        try:
            cb_sha, ch_sha = git(repo, "rev-parse", cb).strip(), git(repo, "rev-parse", chd).strip()
        except RuntimeError as e:
            _chk(ev, "B7.4", "DRY_RUN", None, f"the candidate range {candidate_range!r} does not resolve: {e}")
            cb_sha = ch_sha = None
        if cb_sha and ch_sha:
            dr = b7_dry_run(repo, grammar["entry"], cb_sha, ch_sha, workdir,
                            verifier_job=verifier_job, verifier_conclusion=verifier_conclusion)
            ev["dry_run"] = dr
            sub = [c["verdict"] for c in dr["checks"]]
            any_failed = any(v == "failed" for v in sub)
            all_verified = bool(sub) and all(v == "verified" for v in sub)
            _chk(ev, "B7.4", "DRY_RUN", (False if any_failed else (True if all_verified else None)),
                f"B6.2-B6.6 replayed against {candidate_range} as if {pattern!r} were already declared: "
                + "; ".join(f"{c['id']} {c['verdict']}" for c in dr["checks"]))

    my_digest = diff_digest(repo, base, head)
    ev["change_digest"] = my_digest
    if not second_opinion:
        _chk(ev, "B7.5", "SECOND_AUTHORITY", None,
             "DEC-AUP-0020 rule 7: the entity that authors this diff must not be the sole authority whose "
             "verdict admits it. No --b7-second-opinion evidence was given, so this cannot be measured. "
             "not_measured is not a pass: the amendment pauses")
    else:
        so = second_opinion
        problems = []
        if not authority_id or not so.get("authority_id") or authority_id == so.get("authority_id"):
            problems.append(f"authority_id {authority_id!r} is not distinct from the second opinion's "
                            f"{so.get('authority_id')!r} — reverse_if #2: two invocations of the SAME "
                            f"session/agent is a degraded single-body amendment, not independent review")
        if so.get("change_digest") != my_digest or so.get("base") != base or so.get("head") != head:
            problems.append(f"the second opinion is bound to {str(so.get('base'))[:12]}.."
                            f"{str(so.get('head'))[:12]} / {str(so.get('change_digest'))[:16]}…, not this diff "
                            f"{base[:12]}..{head[:12]} / {my_digest[:16]}… — it does not vouch for THIS change")
        if candidate_range and so.get("candidate_range") != candidate_range:
            problems.append(f"the second opinion replayed candidate range {so.get('candidate_range')!r}, this "
                            f"evaluation {candidate_range!r} — both authorities must dry-run the SAME diff")
        if so.get("verdict") != "verified":
            problems.append(f"the second opinion's own verdict is {so.get('verdict')!r}, not 'verified'")
        if (so.get("grammar") or {}).get("op") != op:
            problems.append(f"the second opinion classified this diff as {(so.get('grammar') or {}).get('op')!r}, "
                            f"this evaluation as {op!r} — both authorities must independently agree on WHAT is "
                            f"being admitted")
        _chk(ev, "B7.5", "SECOND_AUTHORITY", (False if problems else True),
            "; ".join(problems) if problems else
            f"a second, isolated authority ({so.get('authority_id')!r}) independently re-derived the same "
            f"verdict on this exact diff ({my_digest[:16]}…) — DEC-AUP-0020 rule 7's substitute for a human "
            f"second-signer, this program's own consilium idiom")

    ev["eligible"] = all(c["verdict"] == "verified" for c in ev["checks"])
    return ev


def structural_case(repo: Path, base: str, head: str, files: list[dict],
                    bundle_rel: str = DEFAULT_BUNDLE_DIR,
                    base_branch: str | None = None) -> tuple[str | None, dict]:
    """Classify the diff from GIT STATUSES ALONE (cheap, no graph, no subprocess beyond git).

    → ('gate_self_update' | 'no_impact_by_construction' | None, evidence). The order matters: a
    bundle refresh EDITS managed files, so it is tested first; a bundle INSTALLATION adds only new
    files and is therefore an all-new-files change, which is why the two holes are one hole."""
    changed = {f["path"]: str(f["status"])[0] for f in files}
    ev = {"changed": len(changed), "bundle_dir": bundle_rel}
    if not changed:
        return None, {**ev, "reason": "empty diff — no case"}
    # AUP-DEBT-002:B7 (DEC-AUP-0020). A diff whose ONLY changed path is the declaration file itself,
    # in place (M), is classified here — before the bundle/self-update logic, and before the
    # ordinary-rule fallthrough below, which is exactly where this diff used to get stuck forever
    # (empty measured impact, no exemption, paused_safe by construction). Deliberately independent of
    # `bundle_rel`: this is not a bundle-refresh concept.
    if changed == {DEFAULT_DECLARATION_REL: "M"}:
        return "declaration_amend", ev
    # Moving a SPENT receipt into receipts/archive/ is the same shape of hole this file already
    # names above: empty measured impact, no exemption, paused_safe by construction. Receipt nodes
    # carry `mandatory: []` in the matrix, so a receipt that appears in ANY diff is not_measured by
    # declaration; and archiving one is how a repository stops a spent receipt from pulling every
    # later change into its impact set (the `verifies` edges are built from string literals, so a
    # receipt naming ci.yml 131 times becomes a dependency of every change to ci.yml). Without this
    # case the cleanup can never be merged: leave the receipt where it is and it stays a dependency;
    # move it and the move itself is an "edit", which falls to the ordinary rule. Measured on
    # muneral@fb390e7e: a diff containing ONLY that rename has impact core 0 and still paused.
    #
    # The rename never travels alone in the repository this case was written for. muneral's mutation
    # evidence pins `trackedTreeWithoutEvidence` — a hash of the WHOLE tracked tree — so moving one
    # receipt rewrites apps/api/test/assembly/mutation-results.json in the same commit, and the shape
    # check below («at most two paths») then reads a three-path diff and refuses. Measured on
    # muneral@98bab50a: «1 path(s) are edited ... this is an ordinary change», with the rename itself
    # already recognised — the case was correct and unreachable. That is the exact conflict
    # .arcana/derived-artefacts.v1.json exists to resolve, and gate5b already resolves it for an
    # ordinary edit; the declared set is subtracted HERE for the same reason and by the same rule:
    # the declaration is read at BASE (a change may not widen its own licence), and every declared
    # path is still re-measured by the six B6 arms afterwards. Subtracting it is not a pass — it only
    # decides which case the diff belongs to.
    decl_sr, _why_sr, _boot_sr = declaration_in_force(repo, base, head, changed)
    declared_sr, _bad_sr = declared_artefacts(decl_sr)
    receipt_move = {p: s for p, s in changed.items() if p not in set(declared_sr)}
    if receipt_move != changed:
        ev["declared_derived_artefacts_set_aside"] = sorted(set(changed) - set(receipt_move))
    if receipt_move and _is_spent_receipt_archive(repo, base, head, receipt_move):
        return "spent_receipt_archive", ev
    managed_base, man_b = bundle_paths_at(repo, base, bundle_rel)
    managed_head, man_h = bundle_paths_at(repo, head, bundle_rel)
    managed = managed_base | managed_head
    edited = {p: s for p, s in changed.items() if s != "A"}
    outside = sorted(set(changed) - managed)
    decl, _decl_why, _boot = declaration_in_force(repo, base, head, changed)
    declared, _bad = declared_artefacts(decl)
    if _boot:
        outside = [x for x in outside if x != DEFAULT_DECLARATION_REL]
    # DEC-AUP-0038. Set aside BEFORE the pin/derived split, and only when there is a bundle to
    # refresh at all: the receipt of a self-update is admissible because the diff IS a self-update,
    # never the other way round.
    self_receipt, outside, receipt_ev = (split_self_update_receipt(repo, base, head, outside, changed)
                                         if managed else ([], outside, {"rule": "DEC-AUP-0038",
                                                                        "candidates": [], "admitted": None,
                                                                        "why": "no bundle at base or head"}))
    # DEC-AUP-0051. Set aside what the BASE BRANCH wrote and an update-branch merge carried in, before the
    # pin/derived split: a path whose head bytes are the base branch's bytes is not a pin candidate and not
    # a derived artefact — it is not this change's path at all.
    merged_in, outside, merge_ev = (split_base_branch_merge(repo, base, head, outside, changed, managed,
                                                           base_branch)
                                    if outside and managed else
                                    ([], outside, {"rule": "DEC-AUP-0051", "merges": [], "admitted": [],
                                                   "why": "no path outside the bundle, or no bundle"}))
    pin_only, derived, outside_real = (
        split_outside(repo, base, head, outside, (man_h or {}).get("program_ref"), frozenset(declared))
        if outside and managed else ([], [], outside))
    ev.update({"edited": sorted(edited), "outside_the_bundle": outside_real[:12],
               "program_ref_pin_updates": pin_only, "declared_derived_artefacts": derived,
               "self_update_receipt": receipt_ev, "base_branch_merge": merge_ev,
               "base_branch_merge_paths": merged_in,
               "managed_at_base": len(managed_base), "managed_at_head": len(managed_head)})
    edited = {p: st for p, st in edited.items() if p not in set(merged_in)}
    if managed and not outside_real and any(p in managed_base for p in edited):
        ev["self_update_receipt_admitted"] = self_receipt
        ev["program_ref"] = {"base": (man_b or {}).get("program_ref"), "head": (man_h or {}).get("program_ref")}
        return "gate_self_update", ev
    # AUP-GRAPH-006:gate5b. The declared-derived-artefact exception is NOT specific to a bundle refresh, and
    # muneral is the proof: its mutation evidence binds the whole tracked tree, so EVERY change to that
    # repository drags the regenerated artefact — an all-new-files change included. A1 refusing «added files
    # PLUS an edit» is right about an ordinary edit and wrong about a file whose bytes are a function of the
    # rest of the tree. The tolerance is the same set, measured by the same six arms (B6), and outside a
    # bundle refresh the declaration is read at base exactly as it is inside one.
    derived_edits = [p for p in edited if p in set(declared)]
    real_edits = {p: st for p, st in edited.items() if p not in set(derived_edits)}
    ev["declared_derived_artefacts"] = sorted(set(ev.get("declared_derived_artefacts") or []) | set(derived_edits))
    if not real_edits:
        return "no_impact_by_construction", ev
    ev["reason"] = (f"{len(real_edits)} path(s) are edited or removed and the change is not a bundle refresh "
                    f"({len(outside)} changed path(s) are outside the bundle) — this is an ordinary change and "
                    f"the ordinary rule applies"
                    + (f"; {len(derived_edits)} edited path(s) ARE declared derived artefacts and were not "
                       f"counted against it" if derived_edits else ""))
    return None, ev



def _is_spent_receipt_archive(repo: Path, base: str, head: str, changed: dict) -> bool:
    """True only for a diff that does NOTHING but move receipt bytes into receipts/archive/.

    Three conditions, all structural and all cheap to check: the diff touches exactly two paths (or
    one, when git reports a rename), the destination is under receipts/archive/, and the bytes are
    identical on both sides. Identical bytes is what makes this safe: the receipt is not rewritten,
    only relocated, so no assertion it carries can change while it is being exempted. A receipt whose
    CONTENT changes, or a move bundled with any other edit, falls through to the ordinary rule."""
    paths = sorted(changed)
    if not paths or len(paths) > 2:
        return False
    dests = [p for p in paths if p.startswith(RECEIPT_ARCHIVE_PREFIX)]
    if len(dests) != 1:
        return False
    dest = dests[0]
    srcs = [p for p in paths if p != dest]
    if len(srcs) > 1:
        return False
    if not all(p.startswith("receipts/") and p.endswith(".json") for p in paths):
        return False
    new_raw = git(repo, "show", f"{head}:{dest}", check=False)
    if not new_raw.strip():
        return False
    if srcs:
        old_raw = git(repo, "show", f"{base}:{srcs[0]}", check=False)
        if not old_raw.strip() or old_raw != new_raw:
            return False   # relocated AND rewritten is an ordinary change
    # A COPY changes only the destination path, so `srcs` is empty and the checks above never fire.
    # The question is therefore asked of the head TREE, not of the diff: after the move, no receipt
    # outside receipts/archive/ may still carry these bytes. Otherwise a diff that duplicates a
    # receipt would be exempted as a cleanup while the original keeps dragging its edges.
    if _same_receipt_outside_archive(repo, head, dest, new_raw):
        return False
    return True


def _same_receipt_outside_archive(repo: Path, head: str, dest: str, raw: str) -> bool:
    """True when the head tree still holds these exact receipt bytes somewhere outside the archive."""
    listing = git(repo, "ls-tree", "-r", "--name-only", head, "receipts/", check=False)
    for p in listing.splitlines():
        p = p.strip()
        if not p or p == dest or p.startswith(RECEIPT_ARCHIVE_PREFIX) or not p.endswith(".json"):
            continue
        if git(repo, "show", f"{head}:{p}", check=False) == raw:
            return True
    return False

def _chk(ev: dict, cid: str, code: str, ok: bool | None, detail: str) -> bool:
    ev["checks"].append({"id": cid, "code": code,
                         "verdict": "not_measured" if ok is None else ("verified" if ok else "failed"),
                         "detail": detail})
    return bool(ok)


def evaluate_no_impact(repo: Path, base: str, head: str, files: list[dict], workdir: Path, *,
                       declaration_rel: str = DEFAULT_DECLARATION_REL,
                       verifier_job: str | None = None, verifier_conclusion: str | None = None) -> dict:
    """A1-A4. The graph is rebuilt at HEAD: at base the added files do not exist and the question
    «does anything reference them?» cannot be asked at all."""
    import impact as impact_mod  # sibling tool, reused as a library (bundled)
    ev: dict = {"case": "no_impact_by_construction", "checks": [], "eligible": False, "coverage_gap": []}
    changed_no = {f["path"]: str(f["status"])[0] for f in files}
    decl, decl_why, _boot = declaration_in_force(repo, base, head, changed_no, declaration_rel)
    declared_all, bad_entries = declared_artefacts(decl)
    added = sorted(f["path"] for f in files if str(f["status"])[0] == "A")
    derived = sorted(f["path"] for f in files
                     if str(f["status"])[0] != "A" and f["path"] in declared_all)
    ev["declared_derived_artefacts"] = derived
    others = sorted(f"{str(f['status'])[0]}:{f['path']}" for f in files
                    if str(f["status"])[0] != "A" and f["path"] not in declared_all)
    a1 = _chk(ev, "A1", "ALL_PATHS_ADDED", not others,
              f"{len(added)} added path(s), {len(others)} edited/removed/renamed" +
              (f" ({', '.join(others[:4])}) — a rename is an edit of the old path, and an edit beside new files "
               f"is an ordinary change: no exemption" if others else " — every path in this diff is a new file")
              + (f"; {len(derived)} edited path(s) are DECLARED DERIVED ARTEFACTS ({', '.join(derived[:3])}) and "
                 f"are not counted as ordinary edits — B6 has still to measure them, and appearing in the "
                 f"declaration is not yet a pass" if derived else ""))
    b6 = evaluate_derived(repo, base, head, derived, decl, decl_why, bad_entries, files, Path(workdir), ev,
                          declaration_rel=declaration_rel, case="no_impact_by_construction",
                          verifier_job=verifier_job, verifier_conclusion=verifier_conclusion)
    fb = [p for p in added if impact_mod.classify_file(p, None) in impact_mod.FALLBACK_KINDS]
    a3 = _chk(ev, "A3", "NO_GLOBAL_FALLBACK", not fb,
              (f"{', '.join(fb)} is a lockfile / global config: the impact is the WHOLE repository "
               f"(the Bazel/Nx rule of DEC-AUP-0008), never nothing" if fb else
               "no added path is a lockfile or a global config, so the global fallback does not apply"))
    gp = Path(workdir) / f"graph-head-{head[:12]}.json"
    graph = build_graph_at(repo, head, gp)
    if graph is None:
        a2 = _chk(ev, "A2", "NO_INBOUND_EDGE_AT_HEAD", None,
                  f"the graph could not be built at head {head[:12]} — the claim cannot be measured, and "
                  f"not_measured is not a pass (DEC-AUP-0008 I4)")
    else:
        node_path = {n["id"]: n.get("path") for n in graph.get("nodes") or []}
        addset = set(added)
        new_ids = {nid for nid, p in node_path.items() if p in addset}
        viol = [f"{e['from']} -[{e['type']}/{e['provenance']}]-> {e['to']}"
                for e in (graph.get("edges") or [])
                if e.get("to") in new_ids and e.get("from") not in new_ids]
        a2 = _chk(ev, "A2", "NO_INBOUND_EDGE_AT_HEAD", not viol,
                  (f"{len(viol)} pre-existing node(s) reference an added path at head "
                   f"({'; '.join(sorted(viol)[:3])}) — the files were picked up by convention or glob, so this "
                   f"change DOES reach existing behaviour with no textual edit anywhere" if viol else
                   f"{len(new_ids)} node(s) of the {len(added)} added path(s); every incoming edge of each of them "
                   f"originates from another added path — the blast radius is empty by construction, measured at "
                   f"head over {len(graph.get('edges') or [])} edge(s)"))
        have = {p for p in node_path.values() if p}
        ev["coverage_gap"] = [p for p in added if p not in have]
        ev["language_coverage"] = (graph.get("manifest") or {}).get("language_coverage")
        ev["graph_at_head"] = {"source_commit": (graph.get("manifest") or {}).get("source_commit"),
                               "graph_digest": (graph.get("manifest") or {}).get("graph_digest"),
                               "nodes": len(graph.get("nodes") or []), "edges": len(graph.get("edges") or [])}
        _chk(ev, "A4", "BUILDER_COVERAGE_NAMED", None if ev["coverage_gap"] else True,
             (f"{len(ev['coverage_gap'])}/{len(added)} added path(s) yield NO node at head "
              f"({', '.join(ev['coverage_gap'][:4])}); language_coverage={ev['language_coverage']} — A2 can only "
              f"see edges the builder can build, so for these files «the graph sees nothing» is not «there is "
              f"nothing to see»" if ev["coverage_gap"] else
              f"every added path yields at least one node at head; language_coverage={ev['language_coverage']}"))
    ev["eligible"] = bool(a1 and a2 and a3 and b6)
    ev["added"] = added
    return ev



def evaluate_spent_receipt_archive(repo: Path, base: str, head: str, files: list[dict],
                                   workdir: Path, *, verifier_job: str | None = None,
                                   verifier_conclusion: str | None = None) -> dict:
    """S1-S3. Admits a diff that does NOTHING but relocate a spent receipt into receipts/archive/.

    A receipt node carries `mandatory: []` in the verifier matrix, so ANY diff containing one is
    not_measured by declaration — and not_measured pauses. Archiving is how a repository stops a
    spent receipt from dragging every later change into its impact set, but the archiving move is
    itself an edit of the old path, so it falls to the ordinary rule and pauses too. That is a
    cleanup which can never be merged, the same shape of hole DEC-AUP-0020 rule 2 already named for
    the declaration file. The three arms below are what keeps it narrow: the bytes must be identical
    (the receipt is relocated, never rewritten, so no assertion it carries can change while it is
    being exempted), the destination must be under receipts/archive/, and nothing else may change."""
    ev: dict = {"case": "spent_receipt_archive", "checks": [], "eligible": False}
    changed = {f_["path"]: str(f_["status"])[0] for f_ in files}
    # A declared derived artefact is set aside before S1 measures the shape, for the reason
    # structural_case() records: in the repository this case was written for, EVERY change rewrites
    # the mutation evidence, so the rename can never arrive alone and S1 would refuse a diff whose
    # receipt half is exactly what it admits. The declaration is read at BASE — a change may not
    # widen its own licence — and setting a path aside here decides SHAPE only: S5 below re-measures
    # every path set aside, running the declared verifier on the honest tree and then on the same
    # tree with one byte of the artefact corrupted.
    decl, _why, _boot = declaration_in_force(repo, base, head, changed)
    declared, _bad = declared_artefacts(decl)
    set_aside = sorted(set(changed) & set(declared))
    if set_aside:
        changed = {p: s for p, s in changed.items() if p not in set(declared)}
        ev["declared_derived_artefacts_set_aside"] = set_aside
    paths = sorted(changed)
    ev["changed_paths"] = paths
    dests = [p for p in paths if p.startswith(RECEIPT_ARCHIVE_PREFIX)]
    srcs = [p for p in paths if p not in dests]
    s1 = _chk(ev, "S1", "NOT_A_PURE_ARCHIVE_MOVE",
              len(paths) <= 2 and len(dests) == 1 and len(srcs) <= 1
              and all(p.startswith("receipts/") and p.endswith(".json") for p in paths),
              (f"this diff changes {paths} — S1 admits ONLY a move of one receipt json into "
               f"{RECEIPT_ARCHIVE_PREFIX}; anything else falls to the ordinary rule")
              if not (len(paths) <= 2 and len(dests) == 1 and len(srcs) <= 1
                      and all(p.startswith("receipts/") and p.endswith(".json") for p in paths))
              else f"exactly one receipt json moves into {RECEIPT_ARCHIVE_PREFIX} and nothing else changes")
    if not s1:
        return ev
    dest = dests[0]
    new_raw = git(repo, "show", f"{head}:{dest}", check=False)
    old_raw = git(repo, "show", f"{base}:{srcs[0]}", check=False) if srcs else ""
    identical = bool(new_raw.strip()) and (not srcs or old_raw == new_raw)
    s2 = _chk(ev, "S2", "RECEIPT_REWRITTEN_WHILE_ARCHIVED", identical,
              "the receipt bytes are identical on both sides: relocated, never rewritten"
              if identical else
              "the receipt is rewritten as well as moved — a changed assertion may not ride an archive move")
    still = _same_receipt_outside_archive(repo, head, dest, new_raw)
    s3 = _chk(ev, "S3", "COPY_NOT_MOVE", not still,
              "no receipt outside receipts/archive/ carries these bytes at head: this is a move"
              if not still else "these receipt bytes still exist outside the archive at head — a copy duplicates "
                               "the receipt, it does not spend it, and the original keeps its edges")
    try:
        doc = json.loads(new_raw) if new_raw.strip() else {}
    except json.JSONDecodeError:
        doc = {}
    adm = (doc.get("admission") or {})
    ev["receipt"] = {"path": dest, "schema": doc.get("schema"),
                     "admission": adm.get("verdict") if isinstance(adm, dict) else adm}
    _chk(ev, "S4", "RECEIPT_ADMISSION_RECORDED", None,
         f"the archived receipt records admission={ev['receipt']['admission']!r}; whether its range is merged "
         f"is NOT checked here — a squash merge rewrites the commit a receipt names, so that question has no "
         f"answer in this repository (measured: 6 of 8 receipt ranges name commits main does not contain)")
    # A path set aside for SHAPE must still be MEASURED, or setting it aside is a bypass wearing the
    # word "declared". S5 runs the declaration's own verifier against the honest head tree and then
    # corrupts one byte and requires that same verifier to refuse it — the B6.4/B6.5 pair, which the
    # self-update case already applies to exactly this file. Without the second half, a declaration
    # naming a verifier that accepts anything would launder any edit through this case.
    if set_aside:
        s5_ok, s5_why = _verify_declared_artefacts(repo, head, declared, set_aside, workdir)
        s5 = _chk(ev, "S5", "DECLARED_ARTEFACT_UNVERIFIED", s5_ok, s5_why)
    else:
        s5 = True
    ev["eligible"] = bool(s1 and s2 and s3 and s5)
    return ev

def _verify_declared_artefacts(repo: Path, head: str, entries: dict, paths: list[str],
                               workdir) -> tuple[bool | None, str]:
    """Run a declared artefact's own verifier twice: on the honest head tree, then on the same tree
    with ONE byte of the artefact corrupted. → (verdict, why), where None is not_measured.

    This is the B6.4/B6.5 pair applied outside the self-update case. It is deliberately the same
    measurement rather than a cheaper one: accepting a declared path on the strength of the
    declaration alone would turn `declared` into a licence, and the second run is what proves the
    named verifier actually binds these bytes. A scratch WORKTREE, because a caller's verifier may
    need git plumbing of its own."""
    wt = Path(workdir) / f"declared-wt-{head[:12]}"
    made = subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", "--force", str(wt), head],
                          capture_output=True, text=True)
    if made.returncode != 0:
        return None, (f"a scratch worktree at head could not be created ({made.stderr.strip()[:160]}) — the "
                      f"declared verifier cannot be run, and not_measured is not a pass")
    try:
        for pth in paths:
            e = entries.get(pth) or {}
            setup, ver = e.get("setup") or {}, e.get("verify") or {}
            if not (ver.get("argv")):
                return False, f"{pth}: the declaration names no verify.argv — nothing to measure"
            vcwd = wt / str(ver.get("cwd") or ".")
            if setup.get("argv"):
                rc_s, tail_s = _run_declared(setup["argv"], wt / str(setup.get("cwd") or "."),
                                             DERIVED_SETUP_TIMEOUT_S)
                if rc_s != 0:
                    return None, f"{pth}: the declared setup exited {rc_s}: {tail_s}"
            rc_c, tail_c = _run_declared(ver["argv"], vcwd, DERIVED_VERIFY_TIMEOUT_S)
            if rc_c != 0:
                return False, f"{pth}: the declared verifier exits {rc_c} on the honest head tree: {tail_c}"
            target = wt / pth
            original = target.read_bytes()
            mutated, off, what = corrupt_one_byte(original)
            target.write_bytes(mutated)
            try:
                rc_m, tail_m = _run_declared(ver["argv"], vcwd, DERIVED_VERIFY_TIMEOUT_S)
            finally:
                target.write_bytes(original)
            if rc_m in (0, None):
                return False, (f"{pth}: the declared verifier ACCEPTS a corrupted artefact (exit {rc_m}, byte "
                               f"{off} {what}): it does not bind these bytes, so the declaration is not "
                               f"evidence. {tail_m}")
        return True, (f"{len(paths)} declared artefact(s) measured, not assumed: the declared verifier accepts "
                      f"the honest head tree and REFUSES it with one byte corrupted, so the declaration binds "
                      f"these bytes")
    finally:
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)],
                       capture_output=True, text=True)
        subprocess.run(["git", "-C", str(repo), "worktree", "prune"], capture_output=True, text=True)


def _materialize_bundle(repo: Path, ref: str, rel: str, dest: Path) -> Path | None:
    """Extract the bundle directory as it exists at `ref` — the head bundle is what is being
    installed, the BASE bundle is the gate that judges it."""
    r = subprocess.run(["git", "-C", str(repo), "archive", ref, rel.strip("/")], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        return None
    dest.mkdir(parents=True, exist_ok=True)
    t = subprocess.run(["tar", "-x", "-C", str(dest)], input=r.stdout, capture_output=True)
    if t.returncode != 0:
        return None
    out = dest / rel.strip("/")
    return out if out.exists() else None


_SIG_DRIVER = """import json, sys
sys.path.insert(0, sys.argv[1])
import sshsig
ok, reason, det = sshsig.verify_detached(open(sys.argv[2], 'rb').read(), open(sys.argv[3]).read(),
                                         open(sys.argv[4]).read(), sys.argv[5])
print(json.dumps({"ok": bool(ok), "reason": reason, "detail": det}))
"""


def _bundle_selftest(bundle_root: Path) -> tuple[int | None, int | None, str]:
    """→ (exit code, arm count, tail). `ci_gate.py --selftest` is the battery that runs from inside a
    vendored bundle; `admit_change.py --selftest` does NOT (its fixture set is not bundled — measured,
    `fixture-drift`), which is recorded as non-coverage rather than silently skipped."""
    script = bundle_root / "tools/graph/ci_gate.py"
    if not script.exists():
        return None, None, "no tools/graph/ci_gate.py in this bundle"
    # HOST SAFETY (retrofit4's incident, recorded in REPORT-GRAPH-RETROFIT4 §"Honest accounting"): this is
    # the call that recursed without bound before the AUP_GATE4B_NESTED marker existed, and the harness
    # killing the parent did NOT stop the children — they were reparented to init and kept spawning. The
    # marker is the primary guard; this timeout is the second one, so an unguarded future battery cannot
    # spawn for longer than a bounded time under one parent.
    try:
        r = subprocess.run([sys.executable, str(script), "--selftest"], capture_output=True, text=True,
                           timeout=1800,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "AUP_GATE4B_NESTED": "1"})
    except subprocess.TimeoutExpired:
        return None, None, "the bundle's ci_gate.py --selftest did not finish within 1800 s"
    m = re.search(r"TOTAL PASS: (\d+)/(\d+)", r.stdout)
    arms = int(m.group(2)) if m else None
    return r.returncode, arms, ((r.stdout or "") + (r.stderr or ""))[-400:]


def _bundle_policy_check_ids(bundle_root: Path) -> list[str] | None:
    p = bundle_root / "contracts/graph-verified-change/admission-gate.v1.json"
    try:
        return sorted(c["id"] for c in json.loads(p.read_text())["checks"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None


TOOLCHAIN_MISMATCH_CODE = "ARTEFACT_VERIFIER_TOOLCHAIN_MISMATCH"
TOOLCHAIN_MISMATCH_RE = re.compile(r"TOOLCHAIN_MISMATCH|toolchain mismatch|unsupported engine|"
                                   r"wrong node version|engine \"?node", re.I)


def _interpreter_identity(argv: list) -> str:
    """WHICH binary the gate ran, resolved from PATH, and what it calls itself.

    A2-275 measured the cost of leaving this out: muneral's artefact verifier pins node major.minor,
    arcana-devs had 24.20.0 while the evidence was recorded on 24.21.0, and the gate reported
    CHANGE_SET_INCOMPLETE — "your change set is incomplete" — for a fact about PATH. The versions were
    in the verifier's own output; the one thing missing was which binary the gate had picked.
    """
    exe = str(argv[0]) if argv else ""
    resolved = shutil.which(exe) or (exe if exe and os.path.exists(exe) else None)
    if not resolved:
        return f"{exe!r} — not found on PATH={os.environ.get('PATH', '')[:200]}"
    try:
        ver = subprocess.run([resolved, "--version"], capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        ver = ""
    return f"{exe} → {resolved} ({ver.splitlines()[0][:40] if ver else 'no --version'})"


def _run_declared(argv: list[str], cwd: Path, timeout: int) -> tuple[int | None, str]:
    """Run a caller-declared command. Bounded, captured, and never shell-interpreted: argv is a list."""
    try:
        r = subprocess.run([str(x) for x in argv], cwd=str(cwd), capture_output=True, text=True,
                           timeout=timeout, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except OSError as e:
        return None, f"could not be run: {e}"
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()[-300:]


def evaluate_derived(repo: Path, base: str, head: str, derived: list[str], decl: dict | None,
                     decl_why: str, bad_entries: list[str], files: list[dict], workdir: Path, ev: dict,
                     *, declaration_rel: str = DEFAULT_DECLARATION_REL, case: str = "",
                     verifier_job: str | None = None, verifier_conclusion: str | None = None) -> bool:
    """B6 — a caller-DECLARED allowlist is a caller-CONTROLLED hole unless the gate re-measures every clause
    of it, so the gate measures all six arms itself (and C16 re-measures them on every evaluation, exactly
    as for A1-A4 and B1-B5). Reachable ONLY after B1, and ONLY on the self-update path: it is B1 that has
    already proved that the toolchain, the lockfile, the declaration and the verifier's own implementation
    are all BASE's, byte-for-byte, in a tree this pull request did not write. That is B2's anchor extended
    one step — a declared artefact is judged by the verifier the caller already had."""
    import impact as impact_mod
    if not derived:
        _chk(ev, "B6", "SELF_UPDATE_DERIVED_ARTEFACT", True,
             "no changed path outside the bundle claims to be a derived artefact — the arm is vacuous here, "
             "and vacuous is not the same as measured: nothing was licensed")
        return True
    changed = {f["path"]: str(f["status"])[0] for f in files}
    sub: list[dict] = []
    ok_all = True

    def arm(cid: str, ok: bool | None, detail: str) -> bool:
        nonlocal ok_all
        sub.append({"id": cid, "verdict": "not_measured" if ok is None else ("verified" if ok else "failed"),
                    "detail": detail})
        ok_all = ok_all and bool(ok)
        return bool(ok)

    # ---- B6.1 DECLARED: the licence in force is the one at BASE, and this change may not touch it.
    # THE ONE EXCEPTION, and it is a bootstrap, not a convenience. Measured on the real subject: muneral's
    # ruleset requires `lint-and-test`, which is red until the evidence is rewritten, AND `graph-admission`,
    # which refuses the rewrite until a declaration exists at base — so NO first change can be green on both,
    # and the declaration could never land at all. The exception is admissible only where B1 has already
    # proved that every other path is bundle-managed or the program_ref pin: on a bundle refresh the verify
    # command and its whole implementation are BASE's, byte-for-byte, so the change may introduce the
    # caller's DECLARATION but can never introduce the VERIFIER. On the ordinary path A1 permits arbitrary
    # ADDED files, so a change could ship its own verifier — and there the declaration must be at base.
    # RESIDUAL, stated: a refresh may name a dependent-less file that some existing base command binds, and
    # B6.6 checks the verifier job's name and conclusion, never that the job runs that command.
    bootstrap = (changed.get(declaration_rel) == "A" and case == "gate_self_update")
    missing = [p for p in derived if p not in (decl and declared_artefacts(decl)[0] or {})]
    if decl is None:
        arm("B6.1", False, f"{len(derived)} path(s) outside the bundle and no usable declaration: {decl_why}")
    elif declaration_rel in changed and not bootstrap:
        arm("B6.1", False, f"{declaration_rel} is itself changed by this diff ({changed[declaration_rel]}) — a "
                           f"change may not widen its own licence. Widening it is an ORDINARY change, under "
                           f"the ordinary rule, with an ordinary receipt and a readable line in history"
                           + ("" if case == "gate_self_update" else
                              ". The bootstrap exception exists only for a bundle refresh, where B1 has "
                              "already proved the verifier is base's"))
    elif bad_entries:
        arm("B6.1", False, f"the declaration at base {base[:12]} carries {len(bad_entries)} unusable entry(ies) "
                           f"({'; '.join(bad_entries[:3])}) — a glob is a licence whose extent is decided later, "
                           f"by whatever files happen to match")
    elif missing:
        arm("B6.1", False, f"{', '.join(missing[:4])} is not in {declaration_rel} at base {base[:12]}")
    elif bootstrap:
        arm("B6.1", True, f"BOOTSTRAP: {declaration_rel} does not exist at base {base[:12]} and is ADDED by this "
                          f"diff, so the declaration in force is the one at HEAD {head[:12]}. Admissible ONLY "
                          f"because this is a bundle refresh, where B1 has already proved every other changed "
                          f"path is bundle-managed or the program_ref pin: this change may introduce the "
                          f"caller's DECLARATION, never its VERIFIER — whose implementation is base's, "
                          f"byte-for-byte. All {len(derived)} path(s) are declared there by exact path")
    else:
        arm("B6.1", True, f"all {len(derived)} path(s) are declared by exact path in {declaration_rel} at BASE "
                          f"{base[:12]}, and that file is not touched by this diff")
    entries = (declared_artefacts(decl)[0] if decl else {})

    # ---- B6.2 REFRESHED: a derived artefact is refreshed; a new file is a new fact.
    wrong = [f"{p}({changed.get(p, '?')})" for p in derived
             if changed.get(p) != "M" or not git_ok(repo, "cat-file", "-e", f"{base}:{p}")]
    arm("B6.2", not wrong,
        (f"{', '.join(wrong[:4])} is not an in-place refresh of a file that already existed at base — added, "
         f"deleted and renamed paths are refused whatever the declaration says (A1's rule, one level in), "
         f"which is what kills «declare a path, then create it as a backdoor»" if wrong else
         f"every declared path exists at base {base[:12]} and its status is M — a refresh, not a new fact"))

    # ---- B6.3 BOUNDED: the graph bounds the exemption, not the declaration.
    fb = [p for p in derived if impact_mod.classify_file(p, None) in impact_mod.FALLBACK_KINDS]
    if fb:
        arm("B6.3", False, f"{', '.join(fb)} is a lockfile / global config: its blast radius is the WHOLE "
                           f"repository (A3's rule), which no declaration can shrink")
    else:
        gp = Path(workdir) / f"graph-derived-head-{head[:12]}.json"
        graph = build_graph_at(repo, head, gp)
        if graph is None:
            arm("B6.3", None, f"the graph could not be built at head {head[:12]} — the impact of the declared "
                              f"artefacts cannot be measured, and not_measured is not a pass")
        else:
            node_path = {n["id"]: n.get("path") for n in graph.get("nodes") or []}
            dset = set(derived)
            ids = {nid for nid, pp in node_path.items() if pp in dset}
            dependents = [f"{e['from']} -[{e['type']}]-> {e['to']}" for e in (graph.get("edges") or [])
                          if e.get("to") in ids and e.get("from") not in ids]
            gap = [pp for pp in derived if pp not in {v for v in node_path.values() if v}]
            ev.setdefault("coverage_gap", []).extend(gap)
            arm("B6.3", not dependents,
                (f"{len(dependents)} entity(ies) depend on a declared artefact at head "
                 f"({'; '.join(sorted(dependents)[:3])}) — a self-update receipt carries no verdicts for them, "
                 f"so this is an ordinary change. THIS is the arm that refuses a declaration covering src/**"
                 if dependents else
                 f"no entity depends on any declared artefact, measured on a graph rebuilt AT HEAD over "
                 f"{len(graph.get('edges') or [])} edge(s)"
                 + (f". COVERAGE GAP, stated: {len(gap)}/{len(derived)} declared path(s) yield no node at all "
                    f"({', '.join(gap[:3])}), so for those this bound holds VACUOUSLY — A4's gap inherited by "
                    f"the declaration, reported and never read as a pass" if gap else "")))

    # ---- B6.4 / B6.5: the only measurement that is not a declaration. A scratch WORKTREE, because a
    # caller's verifier may need git plumbing (muneral's gitSupplement writes a temporary index).
    wt = Path(workdir) / f"derived-wt-{head[:12]}"
    made = subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", "--force", str(wt), head],
                          capture_output=True, text=True)
    if made.returncode != 0:
        arm("B6.4", None, f"a scratch worktree at head could not be created ({made.stderr.strip()[:160]}) — the "
                          f"verifier cannot be run, and not_measured is not a pass")
        arm("B6.5", None, "not run: no scratch worktree")
    else:
        try:
            runs = []
            for pth in derived:
                e = entries.get(pth) or {}
                setup, ver = e.get("setup") or {}, e.get("verify") or {}
                vcwd = wt / str(ver.get("cwd") or ".")
                if setup.get("argv"):
                    rc_s, tail_s = _run_declared(setup["argv"], wt / str(setup.get("cwd") or "."),
                                                 DERIVED_SETUP_TIMEOUT_S)
                    runs.append({"path": pth, "stage": "setup", "argv": setup["argv"], "rc": rc_s})
                    if rc_s != 0:
                        arm("B6.4", None, f"{pth}: the declared setup exited {rc_s}: {tail_s}")
                        arm("B6.5", None, "not run: setup failed")
                        break
                rc_c, tail_c = _run_declared(ver["argv"], vcwd, DERIVED_VERIFY_TIMEOUT_S)
                runs.append({"path": pth, "stage": "clean", "argv": ver["argv"], "rc": rc_c})
                if rc_c != 0 and TOOLCHAIN_MISMATCH_RE.search(tail_c or ""):
                    ev["toolchain_mismatch"] = {"code": TOOLCHAIN_MISMATCH_CODE, "path": pth,
                                               "interpreter": _interpreter_identity(ver["argv"]),
                                               "tail": tail_c}
                    tail_c = (f"{TOOLCHAIN_MISMATCH_CODE}: {tail_c} — the gate ran "
                              f"{ev['toolchain_mismatch']['interpreter']}. This is a fact about PATH on the "
                              f"host running the gate, NOT about the change set: put the pinned interpreter "
                              f"first on PATH (the repository's .nvmrc / engines) and re-run")
                if not arm("B6.4", rc_c == 0,
                           (f"{pth}: the declared verifier {' '.join(map(str, ver['argv']))[:90]} accepts the head "
                            f"tree (exit 0). A stale artefact, or one hand-edited to a value the verifier does not "
                            f"recompute, exits non-zero here"
                            if rc_c == 0 else
                            f"{pth}: the declared verifier exits {rc_c} on the head tree: {tail_c}")):
                    arm("B6.5", None, "not run: the verifier does not accept the honest head tree")
                    break
                target = wt / pth
                original = target.read_bytes()
                mutated, off, what = corrupt_one_byte(original)
                target.write_bytes(mutated)
                try:
                    rc_m, tail_m = _run_declared(ver["argv"], vcwd, DERIVED_VERIFY_TIMEOUT_S)
                finally:
                    target.write_bytes(original)
                runs.append({"path": pth, "stage": "corrupted", "offset": off, "byte": what, "rc": rc_m})
                if not arm("B6.5", rc_m not in (0, None),
                           (f"{pth}: one byte corrupted at offset {off} ({what}) and the declared verifier REFUSES "
                            f"it (exit {rc_m}) — a declaration claims «job {e.get('verified_by_job')!r} verifies "
                            f"this file», and this is a mutation test of that claim, run by the gate, on this "
                            f"change. A verifier that does not bind these bytes survives it and is refused"
                            if rc_m not in (0, None) else
                            f"{pth}: the declared verifier ACCEPTS a corrupted artefact (exit {rc_m}, byte {off} "
                            f"{what}): it does not bind these bytes, so the declaration is not evidence. "
                            f"{tail_m}")):
                    break
            ev["derived_runs"] = runs
        finally:
            subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)],
                           capture_output=True, text=True)
            subprocess.run(["git", "-C", str(repo), "worktree", "prune"], capture_output=True, text=True)

    # ---- B6.6 REQUIRED_AND_UPSTREAM: gate2a's existing workflow inputs, so this costs nothing.
    want = sorted({str((entries.get(p) or {}).get("verified_by_job") or "") for p in derived})
    concl = (verifier_conclusion or "").strip().lower()
    if not verifier_job or not concl:
        arm("B6.6", None, f"the caller passed no verifier_job / verifier_conclusion (gate2a's workflow inputs), "
                          f"so «the artefact's verifier is a real job that is green on this head» cannot be "
                          f"measured. not_measured is not a pass: no exemption, the change pauses")
    elif [w for w in want if w != verifier_job.strip()]:
        arm("B6.6", False, f"the declaration names verifier job(s) {want} but the caller's workflow passes "
                           f"verifier_job={verifier_job.strip()!r} — an artefact vouched for by a job that is "
                           f"not the one that ran")
    else:
        arm("B6.6", concl == "success",
            (f"the caller's own {verifier_job.strip()!r} — the job the declaration names, and the job the "
             f"admission workflow depends on — concluded {concl!r} on this head"
             if concl == "success" else
             f"the declared verifier job {verifier_job.strip()!r} concluded {concl!r}, not 'success'"))

    ev["derived_arms"] = sub
    worst = "verified" if ok_all else ("failed" if any(x["verdict"] == "failed" for x in sub) else "not_measured")
    return _chk(ev, "B6", "SELF_UPDATE_DERIVED_ARTEFACT", ok_all if worst != "not_measured" else None,
                f"{len(derived)} declared derived artefact(s): "
                + "; ".join(f"{x['id']} {x['verdict']}" for x in sub)
                + ". " + "; ".join(x["detail"] for x in sub if x["verdict"] != "verified")[:600]
                if not ok_all else
                f"{len(derived)} declared derived artefact(s) ({', '.join(derived[:3])}) survive all six arms: "
                + "; ".join(f"{x['id']} {x['detail'][:110]}" for x in sub))


def evaluate_workflow_integrity(repo: Path, head: str, man_h: dict | None, ev: dict) -> bool:
    """B8 SELF_UPDATE_WORKFLOW_INTEGRITY — KB-039, measured live in four repositories on 2026-09-24.

    BUNDLE.json's first entry is not a tool: it is the vendored, EXECUTING workflow, carrying
    `verified_by_the_job: false`. `ci_gate.verify_bundle` skipped its hash on the strength of that
    flag; `bundle_paths_at` counted it as bundle-managed anyway. Each half was defensible and together
    they said: this file is inside the bundle's authority and nothing checks it. A caller pull request
    editing ONLY that file — no key, BUNDLE.json and its signature untouched and still valid —
    classified as `gate_self_update` and passed B1/B2/B3/B4/B6, and for a `pull_request` event GitHub
    runs the workflow as of the pull-request HEAD, so the file the change rewrites is the job that
    judges it.

    The arm: the workflow's bytes AT HEAD, read from git, must hash to the sha256 the head manifest
    records for it. A legitimate refresh moves the file and its entry together and re-signs, so it
    passes; the bypass moves the file alone, so it fails. Deletion fails too — absent bytes are not
    bytes that match, and a vacuous pass here is how the arm would have been written to look like
    coverage while being none.

    WHICH SIDE VERIFIES IT, since the job cannot trust itself. This arm runs in `admit_change.py`, and
    that is sound for the reason B2 is sound, not despite it. Two invocations matter and they differ:

      * The LOCAL run — `tools/graph/admit_change.py gate|exempt`, which DEC-AUP-0007 makes the
        authoritative admission — executes the PROGRAM repository's own copy of this file. The caller's
        pull request did not write it. There the arm is base-side in the strongest sense available.
      * The CI run executes the caller's VENDORED copy, whose bytes `verify_bundle` has already checked
        against a manifest that B2 verified with the BASE tree's `sshsig.py` against the BASE tree's
        key. So the code running this arm is attested by the key, in the same chain every other arm
        hangs from. The vendored workflow was the ONE file the manifest named and the chain did not
        reach; this puts it inside.

    WHAT NEITHER BUYS, written here rather than left for someone to discover: a head workflow rewritten
    so that it never invokes the gate at all reports whatever it likes under the same job name, and no
    arm of any battery runs to contradict it. That residual is closed by branch protection requiring
    the check and by nothing in this file — DEC-AUP-0036 card C3, which measured `graph-admission` as
    required in ONE of four callers."""
    entries = [f for f in ((man_h or {}).get("files") or [])
               if isinstance(f, dict) and f.get("verified_by_the_job") is False and f.get("path")]
    if man_h is None:
        return _chk(ev, "B8", "SELF_UPDATE_WORKFLOW_INTEGRITY", None,
                    "there is no readable bundle manifest at head, so the vendored workflow cannot be "
                    "compared against one. not_measured is not a pass: no exemption, the change pauses")
    if not entries:
        return _chk(ev, "B8", "SELF_UPDATE_WORKFLOW_INTEGRITY", True,
                    "this bundle vendors no executing workflow (no manifest entry carries "
                    "verified_by_the_job: false), so there is no such file for a pull request to rewrite. "
                    "Vacuous, and recorded as vacuous")
    results, bad = [], []
    for f in entries:
        path = f["path"]
        rc = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", f"{head}:{path}"],
                            capture_output=True)
        if rc.returncode != 0:
            results.append({"path": path, "verdict": "failed", "reason": "absent at head"})
            bad.append(f"{path}: the manifest lists it but it does not exist at head {head[:12]} — "
                       f"deleting the executing workflow is not a bundle refresh either")
            continue
        got = sha256_bytes(rc.stdout)
        oid = git(repo, "rev-parse", f"{head}:{path}", check=False).strip() or None
        want_oid = f.get("blob_oid")
        entry = {"path": path, "sha256_at_head": got, "sha256_in_manifest": f.get("sha256"),
                 "blob_oid_at_head": oid, "blob_oid_in_manifest": want_oid}
        if got != f.get("sha256"):
            entry["verdict"] = "failed"
            bad.append(f"{path}: {got[:23]}… at head {head[:12]} is not the {str(f.get('sha256'))[:23]}… "
                       f"the SIGNED manifest records — the job that judges this change was rewritten by it, "
                       f"and the key that attests the gate has attested no such workflow")
        elif want_oid and oid and want_oid != oid:
            # DEC-AUP-0036 R2 used as a verdict rather than a note: same bytes cannot have two OIDs, so
            # this is a manifest that contradicts itself, not a workflow that moved.
            entry["verdict"] = "failed"
            bad.append(f"{path}: the bytes hash to the manifest's sha256 but its recorded blob_oid "
                       f"{str(want_oid)[:12]} is not the git object id of those bytes ({str(oid)[:12]})")
        else:
            entry["verdict"] = "verified"
        results.append(entry)
    ev["vendored_workflow"] = results
    return _chk(ev, "B8", "SELF_UPDATE_WORKFLOW_INTEGRITY", not bad,
                ("; ".join(bad) if bad else
                 f"all {len(results)} vendored executing workflow(s) hash at head {head[:12]} to the sha256 "
                 f"the signed head manifest records"
                 + (" and to its recorded git blob OID" if any(r.get("blob_oid_in_manifest") for r in results)
                    else " (this manifest predates DEC-AUP-0036 R2 and records no blob OID to cross-check)")
                 + " — a workflow change is admissible, a workflow change the manifest does not attest is not"))


def evaluate_self_update(repo: Path, base: str, head: str, files: list[dict], workdir: Path,
                         bundle_rel: str = DEFAULT_BUNDLE_DIR, *,
                         declaration_rel: str = DEFAULT_DECLARATION_REL,
                         verifier_job: str | None = None,
                         verifier_conclusion: str | None = None,
                         base_branch: str | None = None) -> dict:
    """B1-B5. The anchor is B2 and only B2: on a bundle-refresh pull request every byte of the head
    checkout is written by the pull request, so evidence collected by the head bundle is evidence the
    artefact under review collected about itself. B2 verifies the head manifest with the BASE tree's
    sshsig.py against the BASE tree's public key — a self-update is judged by the gate it replaces."""
    ev: dict = {"case": "gate_self_update", "checks": [], "eligible": False, "coverage_gap": []}
    b1m = True
    rel = bundle_rel.strip("/")
    wd = Path(workdir)
    managed_base, man_b = bundle_paths_at(repo, base, bundle_rel)
    managed_head, man_h = bundle_paths_at(repo, head, bundle_rel)
    ev["managed_paths_at_head"] = sorted(managed_head)
    changed = {f["path"]: str(f["status"])[0] for f in files}
    outside = sorted(set(changed) - (managed_base | managed_head))
    decl, decl_why, boot = declaration_in_force(repo, base, head, changed, declaration_rel)
    declared, bad_entries = declared_artefacts(decl)
    if boot:
        outside = [x for x in outside if x != declaration_rel]
        ev["declaration_bootstrap"] = declaration_rel
    self_receipt, outside, receipt_ev = split_self_update_receipt(repo, base, head, outside, changed)
    merged_in, outside, merge_ev = (split_base_branch_merge(repo, base, head, outside, changed,
                                                           managed_base | managed_head, base_branch)
                                    if outside else ([], outside, {"rule": "DEC-AUP-0051", "merges": [],
                                                                   "admitted": [],
                                                                   "why": "no path outside the bundle"}))
    ev["base_branch_merge"] = merge_ev
    pin_only, derived, outside_real = (
        split_outside(repo, base, head, outside, (man_h or {}).get("program_ref"), frozenset(declared))
        if outside else ([], [], []))
    ev["program_ref_pin_updates"] = pin_only
    ev["declared_derived_artefacts"] = derived
    ev["self_update_receipt"] = receipt_ev
    b1 = _chk(ev, "B1", "SELF_UPDATE_SHAPE", not outside_real,
              (f"{len(outside_real)} changed path(s) are neither bundle-managed, nor a bare program_ref pin "
               f"update, nor a declared derived artefact ({'; '.join(outside_real[:3])}) — this is an ordinary "
               f"change wearing a bundle refresh's clothes"
               if outside_real else
               f"all {len(changed)} changed path(s) are bundle-managed at base or head"
               + (f", except {len(pin_only)} caller workflow file(s) whose ONLY change is the program_ref pin, "
                  f"updated to the head bundle's own program_ref "
                  f"({str((man_h or {}).get('program_ref'))[:12]}) — the pin lives outside the bundle by "
                  f"design, so that the bundle cannot vouch for it" if pin_only else "")
               + (f", and {len(derived)} declared derived artefact(s) ({', '.join(derived[:3])}), which B6 "
                  f"has still to measure — appearing in the declaration is not yet a pass" if derived else "")
               + (f", and {declaration_rel}, which this refresh ADDS: the BOOTSTRAP clause of B6.1, "
                  f"admissible only here because B1 has proved every other path is bundle-managed or the "
                  f"pin, so this change may introduce the caller's DECLARATION but never its VERIFIER"
                  if boot else "")
               + (f", and {self_receipt[0]}, this refresh's OWN ChangeAdmissionReceipt/v1 for work item "
                  f"{receipt_ev.get('work_item')} over this very range (DEC-AUP-0038: at most one, ADDED by "
                  f"the range, re-derived from Git — set aside as a CASE, then judged by every check below "
                  f"exactly as a receipt handed in from the pull-request body)" if self_receipt else "")))
    # DEC-AUP-0051 — B1M. Its own arm rather than a clause of B1, so that «the base branch was merged
    # in and could not be read» is a not_measured that PAUSES the change, never a silent widening of B1.
    b1m = _chk(ev, "B1M", "SELF_UPDATE_BASE_BRANCH_MERGE",
               {"verified": True, "vacuous": True, "not_measured": None, "failed": False,
                None: True}.get(merge_ev.get("verdict"), False),
               (f"{len(merged_in)} changed path(s) are the BASE BRANCH's own, carried in by "
                f"{len(merge_ev.get('merges') or [])} merge commit(s) and proved by git blob identity with "
                f"{str(merge_ev.get('anchor'))[:12]} on {merge_ev.get('base_branch')}: "
                f"{', '.join(merged_in[:4])}{' …' if len(merged_in) > 4 else ''}. Their ADMISSION is the base "
                f"branch's protection rule, not this arm — what is proved here is that this change did not "
                f"write them"
                if merged_in else str(merge_ev.get("why") or "no merge commit in this range")))
    b6 = evaluate_derived(repo, base, head, derived, decl, decl_why, bad_entries, files, wd, ev,
                          declaration_rel=declaration_rel, case="gate_self_update",
                          verifier_job=verifier_job, verifier_conclusion=verifier_conclusion)

    base_bundle = _materialize_bundle(repo, base, rel, wd / "base")
    head_bundle = _materialize_bundle(repo, head, rel, wd / "head")
    base_sshsig = (base_bundle / "tools/graph/sshsig.py") if base_bundle else None
    if not base_bundle or not base_sshsig or not base_sshsig.exists():
        b2 = _chk(ev, "B2", "SELF_UPDATE_KEY_CONTINUITY", None,
                  f"the bundle at base {base[:12]} carries no tools/graph/sshsig.py — a pin older than gate2b "
                  f"has no signature code, so the only non-circular anchor cannot be evaluated. not_measured is "
                  f"not a pass: no exemption, the change pauses")
    else:
        base_pub = base_bundle / BUNDLE_PUBKEY_NAME
        man_p, sig_p = head_bundle and (head_bundle / BUNDLE_MANIFEST_NAME), head_bundle and (head_bundle / BUNDLE_SIG_NAME)
        if not base_pub.exists() or not head_bundle or not man_p.exists() or not sig_p.exists():
            b2 = _chk(ev, "B2", "SELF_UPDATE_KEY_CONTINUITY", None,
                      f"missing " + ", ".join(n for n, e in ((f"{base}:{rel}/{BUNDLE_PUBKEY_NAME}", base_pub.exists()),
                                                             (f"{head}:{rel}/{BUNDLE_MANIFEST_NAME}", bool(head_bundle) and man_p.exists()),
                                                             (f"{head}:{rel}/{BUNDLE_SIG_NAME}", bool(head_bundle) and sig_p.exists())) if not e))
        else:
            drv = wd / "verify_with_base_sshsig.py"
            drv.write_text(_SIG_DRIVER)
            r = subprocess.run([sys.executable, str(drv), str(base_bundle / "tools/graph"), str(man_p),
                                str(sig_p), str(base_pub), BUNDLE_SIGNING_NAMESPACE],
                               capture_output=True, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            try:
                res = json.loads(r.stdout)
            except json.JSONDecodeError:
                res = {"ok": False, "reason": f"the base tree's sshsig.py could not be run: "
                                              f"{(r.stderr or r.stdout).strip()[:200]}", "detail": {}}
            ev["signature"] = {"verified": bool(res.get("ok")), "reason": res.get("reason"),
                               "verifier_from": f"{base[:12]}:{rel}/tools/graph/sshsig.py",
                               "key_from": f"{base[:12]}:{rel}/{BUNDLE_PUBKEY_NAME}",
                               "key_fingerprint": (res.get("detail") or {}).get("public_key_fingerprint")}
            b2 = _chk(ev, "B2", "SELF_UPDATE_KEY_CONTINUITY", bool(res.get("ok")),
                      (f"the head bundle's {BUNDLE_MANIFEST_NAME} verifies with the sshsig.py of base {base[:12]} "
                       f"against the {BUNDLE_PUBKEY_NAME} of base {base[:12]} "
                       f"({(res.get('detail') or {}).get('public_key_fingerprint')}) — the key the repository "
                       f"already trusted, in a tree this pull request did not write"
                       if res.get("ok") else
                       f"the head bundle does NOT verify against the key of base {base[:12]}: {res.get('reason')}"))

    if not head_bundle:
        b3 = _chk(ev, "B3", "SELF_UPDATE_SELFTEST", None, f"no bundle directory at head {head[:12]}")
        b4 = _chk(ev, "B4", "SELF_UPDATE_MONOTONIC", None, "no head bundle to compare against")
    else:
        rc_h, arms_h, tail_h = _bundle_selftest(head_bundle)
        ev["selftest"] = {"head": {"exit_code": rc_h, "arms": arms_h}}
        b3 = _chk(ev, "B3", "SELF_UPDATE_SELFTEST", rc_h == 0,
                  (f"the head bundle's ci_gate.py --selftest passes, {arms_h} arm(s). Self-consistency, made "
                   f"meaningful only by B2 — admit_change.py --selftest is NOT runnable from a vendored bundle "
                   f"(its fixture set is not bundled: `fixture-drift`), which is non-coverage, not a pass"
                   if rc_h == 0 else
                   f"the head bundle's ci_gate.py --selftest exits {rc_h}: {tail_h.strip()[-200:]}"))
        ids_h = _bundle_policy_check_ids(head_bundle)
        ids_b = _bundle_policy_check_ids(base_bundle) if base_bundle else None
        rc_b, arms_b, _ = _bundle_selftest(base_bundle) if base_bundle else (None, None, "")
        ev["selftest"]["base"] = {"exit_code": rc_b, "arms": arms_b}
        ev["policy_check_ids"] = {"base": ids_b, "head": ids_h}
        if ids_b is None or ids_h is None:
            b4 = _chk(ev, "B4", "SELF_UPDATE_MONOTONIC", None,
                      "one of the two bundles carries no readable admission-gate.v1.json — monotonicity cannot be measured")
        else:
            dropped = sorted(set(ids_b) - set(ids_h))
            shrank = (arms_b is not None and arms_h is not None and arms_h < arms_b)
            b4 = _chk(ev, "B4", "SELF_UPDATE_MONOTONIC", not dropped and not shrank,
                      (f"the update DROPS check(s) {', '.join(dropped)}" if dropped else "") +
                      ("; " if dropped and shrank else "") +
                      (f"the battery SHRINKS from {arms_b} to {arms_h} arm(s)" if shrank else "") or
                      (f"no policy check id is dropped ({len(ids_b)} → {len(ids_h)}) and the battery does not "
                       f"shrink ({arms_b} → {arms_h} arm(s)) — a proxy for «the update does not weaken the gate», "
                       f"never a comparison of semantics"))
    _chk(ev, "B5", "SELF_UPDATE_PROVENANCE", None,
         f"program_ref {str((man_b or {}).get('program_ref'))[:12]} → {str((man_h or {}).get('program_ref'))[:12]}; "
         f"a caller's CI cannot read the private program repository, so this is the pointer an auditor follows, "
         f"never an enforced check")
    b8 = evaluate_workflow_integrity(repo, head, man_h, ev)
    ev["program_ref"] = {"base": (man_b or {}).get("program_ref"), "head": (man_h or {}).get("program_ref")}
    ev["eligible"] = bool(b1 and b1m and b2 and b3 and b4 and b6 and b8)
    return ev


def evaluate_structural(repo: Path, base: str, head: str, files: list[dict], case: str,
                        workdir: Path, bundle_rel: str = DEFAULT_BUNDLE_DIR, *,
                        declaration_rel: str = DEFAULT_DECLARATION_REL,
                        verifier_job: str | None = None, verifier_conclusion: str | None = None,
                        candidate_range: str | None = None, authority_id: str | None = None,
                        second_opinion: dict | None = None, base_branch: str | None = None) -> dict:
    Path(workdir).mkdir(parents=True, exist_ok=True)
    if case == "no_impact_by_construction":
        return evaluate_no_impact(repo, base, head, files, Path(workdir),
                                  declaration_rel=declaration_rel, verifier_job=verifier_job,
                                  verifier_conclusion=verifier_conclusion)
    if case == "spent_receipt_archive":
        return evaluate_spent_receipt_archive(repo, base, head, files, Path(workdir),
                                              verifier_job=verifier_job, verifier_conclusion=verifier_conclusion)
    if case == "declaration_amend":
        return evaluate_declaration_amend(repo, base, head, files, Path(workdir),
                                          declaration_rel=declaration_rel, candidate_range=candidate_range,
                                          authority_id=authority_id, second_opinion=second_opinion,
                                          verifier_job=verifier_job, verifier_conclusion=verifier_conclusion)
    return evaluate_self_update(repo, base, head, files, Path(workdir), bundle_rel,
                                declaration_rel=declaration_rel, verifier_job=verifier_job,
                                verifier_conclusion=verifier_conclusion, base_branch=base_branch)


MATRIX_REL = "contracts/graph-verified-change/verifier-matrix.v1.json"


def matrix_declared_unverifiable(repo: Path, ref: str, bundle_rel: str) -> frozenset[str]:
    """Node types the verifier matrix gives no mandatory verifier — not_measured BY DECLARATION.

    Read at BASE, never at head, for the same reason read_declaration is: a change must not widen
    its own licence by shipping a matrix that declares its own affected types unverifiable. An
    unreadable or malformed matrix yields the empty set, so every not_measured entity keeps owing
    an exemption — failing closed costs a PAUSED_SAFE, failing open would admit unverified work."""
    for rel in (f"{bundle_rel}/{MATRIX_REL}", MATRIX_REL):
        raw = git(repo, "show", f"{ref}:{rel}", check=False)
        if not raw.strip():
            continue
        try:
            types = (json.loads(raw).get("node_types") or {})
        except json.JSONDecodeError:
            return frozenset()
        return frozenset(t for t, spec in types.items()
                         if isinstance(spec, dict) and not (spec.get("mandatory") or []))
    return frozenset()


def structural_covered_entities(case: str, synthesized: str, verdict_entities, managed: set[str],
                                declared_unverifiable: frozenset[str] = frozenset()) -> set[str]:
    """Which entities an exemption of this code may name — never more.

    `NO_IMPACT_BY_CONSTRUCTION`: exactly the synthesized entity (there are no others; the receipt has
    zero verdicts by construction). `GATE_SELF_UPDATE`: the synthesized entity plus the nodes whose
    PATH is bundle-managed — the vendored foreign code itself, whose verification happened in the
    program repository, which is the same principle gate3b already landed for vendored config keys.
    An exemption that grows past this set is how a typed exception becomes a bypass.

    On a self-update the set also admits entities whose NODE TYPE the verifier matrix at BASE gives
    no mandatory verifier — `receipt` and `work_item` today. Those are not_measured BY DECLARATION:
    verify.py reads the matrix's own `not_measured_reason` for them, so without this the gate would
    demand an exemption for a limit it declared itself and no receipt could ever leave paused_safe.
    The loop is not hypothetical — it re-arms on every change to gate code, because a `verifies`
    edge points from each past receipt to the code it verified, pulling all of them into the impact
    set. The narrowing is deliberately two-sided: the type must carry NO mandatory verifier at base
    (a change cannot widen its own licence by shipping a matrix), and the case must be a self-update,
    so an ordinary change still owes an exemption for every not_measured entity it produces."""
    allowed = {synthesized}
    if case == "gate_self_update":
        for eid in verdict_entities:
            node_type, _, path = str(eid).partition(":")
            if path and path in managed:
                allowed.add(eid)
            elif node_type in declared_unverifiable:
                allowed.add(eid)
    elif case == "spent_receipt_archive":
        # The receipt being archived is itself a `receipt` node, and `receipt` carries `mandatory: []`
        # in the matrix — not_measured BY DECLARATION, for the reason the matrix states: a historical
        # receipt is asserted, never re-verified. So the one entity this case exists to move is the one
        # entity it could not cover, and the cleanup stayed paused_safe with its own subject uncovered.
        # Measured on muneral@7e3470e6: `*** UNCOVERED *** receipt:receipts/graph/change-admission-
        # sec-floors-round2-…json` while every S arm was verified.
        #
        # The narrowing is the same two-sided one the self-update branch already uses, and no wider:
        # the type must carry NO mandatory verifier AT BASE (a change cannot widen its own licence by
        # shipping a matrix), and only a node of such a type is admitted — a code_unit or a route
        # appearing in this diff is still owed an ordinary exemption, which is what keeps S1's «nothing
        # else changes» from being decorative.
        for eid in verdict_entities:
            node_type, _, _p = str(eid).partition(":")
            if node_type in declared_unverifiable:
                allowed.add(eid)
    return allowed


def structural_exemption(repo: Path, base: str, head: str, files: list[dict], policy: dict, *,
                         repo_name: str, workdir: Path, bundle_rel: str = DEFAULT_BUNDLE_DIR,
                         verdict_entities=(), owner: str | None = None,
                         program_receipt: str | None = None,
                         declaration_rel: str = DEFAULT_DECLARATION_REL,
                         verifier_job: str | None = None,
                         verifier_conclusion: str | None = None,
                         candidate_range: str | None = None, authority_id: str | None = None,
                         second_opinion: dict | None = None,
                         base_branch: str | None = None) -> tuple[list[dict], dict]:
    """The gate issues the exemption(s). → (exemptions, evidence). [] means: not eligible, stay paused."""
    case, cev = structural_case(repo, base, head, files, bundle_rel, base_branch)
    if case is None:
        return [], {"case": None, "eligible": False, **cev}
    ev = evaluate_structural(repo, base, head, files, case, workdir, bundle_rel,
                             declaration_rel=declaration_rel, verifier_job=verifier_job,
                             verifier_conclusion=verifier_conclusion, candidate_range=candidate_range,
                             authority_id=authority_id, second_opinion=second_opinion,
                             base_branch=base_branch)
    ev.update({k: v for k, v in cev.items() if k not in ev})
    if not ev["eligible"]:
        return [], ev
    captured = datetime.now(timezone.utc)
    spec = ((policy.get("structural_exemptions") or {}).get("codes") or {}).get(CODE_OF_CASE[case]) or {}
    synth = f"{ENTITY_PREFIX_OF_CASE[case]}:{repo_name}@{head[:12]}"
    managed, _ = bundle_paths_at(repo, head, bundle_rel)
    managed |= bundle_paths_at(repo, base, bundle_rel)[0]
    covered = structural_covered_entities(case, synth, verdict_entities, managed,
                                          matrix_declared_unverifiable(repo, base, bundle_rel))
    binding = {"base": base, "head": head, "digest": diff_digest(repo, base, head)}
    ev["change_binding"] = binding
    ev["synthesized_entity"] = synth
    out = []
    for entity in sorted(covered):
        out.append({
            "entity": entity,
            "code": CODE_OF_CASE[case],
            "owner": owner or STRUCTURAL_EXEMPTION_OWNER,
            "expires_at_utc": (captured + timedelta(hours=STRUCTURAL_EXEMPTION_TTL_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reason": spec.get("covers") or CODE_OF_CASE[case],
            "scope": ("; ".join(spec.get("does_not_cover") or []) or "see impact-uncomputable.v1.md"),
            "change_binding": binding,
            "expiry_rule": ("the DIGEST is the expiry, not the clock: this exemption is void for any other diff. "
                            f"expires_at_utc is a {STRUCTURAL_EXEMPTION_TTL_HOURS} h backstop because C10 requires "
                            "an expiry, and removing that requirement would weaken a check"),
            "evidence": {"checks": ev["checks"], "case": case,
                         **({"language_coverage": ev["language_coverage"]} if "language_coverage" in ev else {}),
                         **({"coverage_gap": ev["coverage_gap"]} if ev.get("coverage_gap") else {}),
                         **({"signature": ev["signature"]} if "signature" in ev else {}),
                         **({"selftest": ev["selftest"]} if "selftest" in ev else {}),
                         **({"derived_arms": ev["derived_arms"]} if ev.get("derived_arms") else {}),
                         **({"derived_runs": ev["derived_runs"]} if ev.get("derived_runs") else {}),
                         **({"program_side_receipt": program_receipt} if program_receipt else {}),
                         # AUP-DEBT-002:B7 — the inputs C16 needs to RE-DERIVE this verdict on every future
                         # evaluation, not trust it. Never a claim of the verdict itself: recheck_structural
                         # re-runs evaluate_declaration_amend from these, exactly as B6.6 re-measures
                         # verifier_job/verifier_conclusion rather than trusting the receipt about them.
                         **({"b7": {"op": ev.get("op"), "grammar": ev.get("grammar"),
                                    "candidate_range": candidate_range, "authority_id": authority_id,
                                    "second_opinion": second_opinion}} if case == "declaration_amend" else {})},
        })
    # The battery is measured ONCE for the whole change, and `evidence` and `scope` are that one
    # measurement — byte-identical in every exemption the loop above emits. Storing a copy per
    # entity is pure duplication, and it is not free: on muneral #84 nineteen copies made
    # `exemptions` 83 % of a 177 KB receipt, past the 65 536-byte pull-request body limit that is
    # the only channel a bundle refresh has (a receipt FILE would be a third path outside the
    # bundle, which B1 refuses). Deduplicated: 52 778 bytes, and the receipt fits.
    #
    # Nothing is lost. The gate already reads the battery from the FIRST exemption only
    # (`exemptions[0].get("evidence")`), and C16 re-measures every arm from the repository on each
    # evaluation rather than trusting what the receipt says — so the copies were never the
    # evidence, only a transcript of it. Each later exemption keeps a pointer naming where its
    # battery lives, so a reader is never left guessing whether one was withheld.
    if len(out) > 1:
        for x in out[1:]:
            if x.get("evidence") == out[0].get("evidence"):
                x["evidence_ref"] = "exemptions[0].evidence — one battery per change, measured once"
                del x["evidence"]
            if x.get("scope") == out[0].get("scope"):
                x["scope_ref"] = "exemptions[0].scope"
                del x["scope"]
    return out, ev


def recheck_structural(repo: Path, base: str, head: str, files: list[dict], policy: dict,
                       exemptions: list[dict], *, repo_name: str, verdict_entities,
                       workdir: Path, bundle_rel: str = DEFAULT_BUNDLE_DIR,
                       declaration_rel: str = DEFAULT_DECLARATION_REL,
                       verifier_job: str | None = None,
                       verifier_conclusion: str | None = None,
                       receipt_head: str | None = None,
                       base_branch: str | None = None) -> tuple[list[str], dict]:
    """C16 — the gate RE-MEASURES the battery of every structural exemption it is shown.

    The cheap discriminators run first (the git-status classification, then the binding digest), so
    a receipt presenting a stale or forged exemption is refused without ever building a graph.

    DEC-AUP-0038 R6 is why the classification now runs FIRST: a receipt cannot bind a range that
    contains the commit that files the receipt, so committing it moved the head and the binding
    failed. Measured on the scrutator refresh replayed on this host (2026-09-24, base 21d6ce968f41):
    `STRUCTURAL_EXEMPTION_UNSOUND … sha256:e576eb4e… / 21d6ce96..46a4a922 does not bind this diff
    (sha256:7cfe2790… / 21d6ce96..8870dcea)`. B1 admitting the receipt file was therefore necessary
    and not sufficient. The tolerance is exactly one alternative binding and no other: the range up
    to the receipt's OWN head, admitted only when the single path separating that head from this one
    is the very receipt file DEC-AUP-0038 R2 has already proved to be this refresh's own record."""
    problems: list[str] = []
    ev: dict = {}
    codes = {x.get("code") for x in exemptions}
    if len(codes) > 1:
        return [f"a receipt may carry at most one structural exemption code; it carries {sorted(codes)}"], ev
    case, cev = structural_case(repo, base, head, files, bundle_rel, base_branch)
    digest = diff_digest(repo, base, head)
    admissible = {(digest, base, head)}
    filed = (cev.get("self_update_receipt") or {}).get("admitted") if case == "gate_self_update" else None
    record_note, record_head, record_extra = "", None, []
    # A2-261b. The refusal REASON is evidence, not just prose inside one problem string. It used to live
    # only in `record_note`, which is appended to the binding problem — and only when a `bad` exemption is
    # returned at all, so a test could assert "some binding problem exists" and pass with the guard deleted.
    # `record_commit` is now written on the refusal path too, path by path, with the reason each path was
    # not a record path (mode, absence at base, being its own verifier), and it survives the early return.
    record_refusal: dict | None = None
    if filed and receipt_head and receipt_head != head and receipt_head in set(range_commits(repo, base, head)):
        moved = _names(repo, "diff", "--name-only", "--no-renames", receipt_head, head)
        entries, _bad_entries = declared_artefacts(read_declaration(repo, base)[0])
        extra = sorted(moved - {filed})
        not_record = {p: r for p in extra
                      for r in [record_path_refusal(repo, base, head, p, entries, require_at_base=True)] if r}
        refusals = list(not_record.values())
        why = ("" if filed in moved else
               f"{filed} is not among the paths {receipt_head[:12]}..{head[:12]} moves") or "; ".join(refusals[:3])
        if why:
            record_note = (f" (the range up to the receipt's own head {receipt_head[:12]} was NOT admitted: {why} "
                           f"— DEC-AUP-0041 R1)")
            record_refusal = {"rule": "DEC-AUP-0041", "receipt": filed, "receipt_head": receipt_head,
                              "verdict": "refused", "carried": extra, "not_record_paths": not_record,
                              "why": why}
            ev["record_commit"] = record_refusal
        else:
            admissible.add((diff_digest(repo, base, receipt_head), base, receipt_head))
            record_head, record_extra = receipt_head, extra
            record_note = (f" (the range up to the receipt's own head {receipt_head[:12]} is admissible too, "
                           f"and ONLY it: the paths between that head and {head[:12]} are {filed}, this "
                           f"refresh's own receipt under DEC-AUP-0038"
                           + (f", and {len(extra)} derived artefact(s) declared at base ({', '.join(extra[:3])}), "
                              f"each of which B6.4/B6.5 must still prove at head — DEC-AUP-0041" if extra else "")
                           + ")")
    # DEC-AUP-0041 carries DEC-AUP-0038's reverse_if R-4 forward verbatim, so the invariant it watches is
    # asserted here rather than argued in prose: this tolerance widens the CONDITION on the second range and
    # never the SET of ranges. Two members, and their heads are this head and the bound receipt's own.
    if (broken := admissible_ranges_invariant(admissible, head, record_head)):
        return [broken], ev
    bad = [x for x in exemptions
           if ((x.get("change_binding") or {}).get("digest"),
               (x.get("change_binding") or {}).get("base"),
               (x.get("change_binding") or {}).get("head")) not in admissible]
    if bad:
        cb = bad[0].get("change_binding") or {}
        return [f"{bad[0].get('code')}: change_binding {str(cb.get('digest'))[:23]}… / "
                f"{str(cb.get('base'))[:12]}..{str(cb.get('head'))[:12]} does not bind this diff "
                f"({digest[:23]}… / {base[:12]}..{head[:12]}) — a structural exemption expires WITH the change, "
                f"never on a calendar" + record_note], ev
    ev["binding"] = {"admissible": sorted(f"{b[:12]}..{h[:12]}" for _d, b, h in admissible),
                     "self_update_receipt": filed, "record_commit_derived": record_extra}
    binding_ev = ev["binding"]
    want = CODE_OF_CASE.get(case or "")
    code = sorted(codes)[0]
    if want != code:
        return [f"{code}: the gate's own classification of this diff is "
                f"{want or 'an ordinary change'} — {cev.get('reason') or 'the exemption does not apply here'}"], ev
    synth = f"{ENTITY_PREFIX_OF_CASE[case]}:{repo_name}@{head[:12]}"
    # DEC-AUP-0038 R6, second half. The synthesized entity names the head, so the record commit that
    # files the receipt renames it out from under the exemption for exactly the reason the binding
    # failed above — and under exactly the same proof. Measured on the same scrutator replay:
    # `the synthesized entity gate_self_update:…@8870dcea3979 carries no exemption`, on a receipt
    # whose exemption named …@46a4a922322f, one commit earlier, that commit being the receipt itself.
    synths = {synth} | ({f"{ENTITY_PREFIX_OF_CASE[case]}:{repo_name}@{record_head[:12]}"} if record_head else set())
    managed, _ = bundle_paths_at(repo, head, bundle_rel)
    managed |= bundle_paths_at(repo, base, bundle_rel)[0]
    allowed = structural_covered_entities(case, synth, verdict_entities, managed,
                                          matrix_declared_unverifiable(repo, base, bundle_rel)) | synths
    named = {x.get("entity") for x in exemptions}
    extra = sorted(named - allowed)
    if extra:
        problems.append(f"{code}: exempts {len(extra)} entity(ies) outside what this code may cover "
                        f"({', '.join(map(str, extra[:4]))}); it may name {sorted(allowed)[:1]}"
                        + (" plus the bundle-managed nodes" if case == "gate_self_update" else " and nothing else"))
    if not (named & synths):
        problems.append(f"{code}: the synthesized entity {synth} carries no exemption — the code exists to cover "
                        f"exactly that entity" + record_note)
    b7meta = (exemptions[0].get("evidence") or {}).get("b7") or {} if case == "declaration_amend" else {}
    ev = evaluate_structural(repo, base, head, files, case, Path(workdir), bundle_rel,
                             declaration_rel=declaration_rel, verifier_job=verifier_job,
                             verifier_conclusion=verifier_conclusion,
                             candidate_range=b7meta.get("candidate_range"), authority_id=b7meta.get("authority_id"),
                             second_opinion=b7meta.get("second_opinion"))
    # The binding evidence was computed above and then overwritten by the battery's own dictionary, so no
    # receipt ever carried it. It is the one place a reader can see WHICH range the exemption bound.
    ev["binding"] = binding_ev
    if record_refusal:
        ev["record_commit"] = record_refusal
    # DEC-AUP-0041 R2. Admitting the second range on the cheap, git-only test above is not the proof: the
    # proof is that the very battery this call just ran accepted each carried artefact at head and REFUSED
    # it with one byte corrupted. The verifier is not run a second time here — it was already run, on those
    # paths, at that head, and `derived_runs` is what it wrote down. A path the battery did not reach is
    # not_measured, and not_measured is not a pass.
    if record_head:
        unproved = [f"{p} — {why}" for p, (ok, why) in ((p, _derived_run_verdict(ev, p)) for p in record_extra)
                    if not ok]
        ev["record_commit"] = {
            "rule": "DEC-AUP-0041", "receipt": filed, "receipt_head": record_head, "derived": record_extra,
            "bound_by_the_exemption": any((x.get("change_binding") or {}).get("head") == record_head
                                          for x in exemptions),
            "verdict": "failed" if unproved else "verified",
            "why": "; ".join(unproved) if unproved else
                   (f"{len(record_extra)} artefact(s) carried by the record commit, each accepted by its own "
                    f"declared verifier at head and REFUSED by it with one byte corrupted" if record_extra else
                    "the record commit moved the receipt and nothing else — DEC-AUP-0038 R6 unchanged")}
        if unproved and ev["record_commit"]["bound_by_the_exemption"]:
            problems.append(f"{code}: a path the record commit carried {RECORD_UNPROVED} — "
                            + "; ".join(unproved[:3])
                            + ". The second binding range is admitted on the promise that every path between "
                              "the receipt's head and this one is a record path; that promise is measured by "
                              "B6.4/B6.5, not granted by the declaration")
    if not ev.get("eligible"):
        failed = [c for c in ev["checks"] if c["verdict"] != "verified"]
        # A2-275 defect 1: the battery can fail for a reason that belongs to the HOST, and reporting
        # that under the change-set code sends the reader to rebuild a change set that is fine. The
        # mismatch keeps its own code, in its own check, and the blocking verdict still stands.
        head_code = TOOLCHAIN_MISMATCH_CODE + " — " if ev.get("toolchain_mismatch") else ""
        problems.append(f"{code}: {head_code}the gate re-measured the evidence battery and it does not pass — "
                        + "; ".join(f"{c['id']} {c['code']} {c['verdict']}: {c['detail'][:240]}" for c in failed[:3]))
    return problems, ev


RECORD_UNPROVED = "is not proved by its own declared verifier at head"


def _derived_run_verdict(ev: dict, path: str) -> tuple[bool, str]:
    """Did THIS evaluation's B6.4/B6.5 prove `path` at head? → (ok, why). Read from what the battery
    wrote down (`derived_runs`), never from the declaration that asked for it."""
    if path not in set(ev.get("declared_derived_artefacts") or []):
        return False, "B6 did not measure it as a declared derived artefact of this change"
    runs = [r for r in (ev.get("derived_runs") or []) if r.get("path") == path]
    clean = [r for r in runs if r.get("stage") == "clean"]
    corrupted = [r for r in runs if r.get("stage") == "corrupted"]
    if not clean:
        return False, "its declared verifier was never run on the honest head tree (not_measured is not a pass)"
    if any(r.get("rc") != 0 for r in clean):
        return False, f"its declared verifier exits {clean[0].get('rc')} on the honest head tree"
    if not corrupted:
        return False, "the one-byte mutation test was not run (not_measured is not a pass)"
    if any(r.get("rc") in (0, None) for r in corrupted):
        return False, ("its declared verifier ACCEPTS the artefact with one byte corrupted, so it does not "
                       "bind these bytes and the declaration is not evidence")
    return True, "accepted at head and refused with one byte corrupted"


def _receipt_head(doc: dict) -> str | None:
    cs = doc.get("change_set") or {}
    h = cs.get("head") if cs.get("mode") == "diff" else (doc.get("tree") or {}).get("commit")
    return h if isinstance(h, str) and h else None


def _names(repo: Path, *args: str) -> set[str]:
    """NUL-separated path names: never git's C-quoted form, which a filesystem path would not match."""
    return {p for p in git(repo, *args, "-z", check=False).split("\0") if p}


def trailing_record_commits(repo: Path, base: str, head: str, bound: list[dict], changed: set[str],
                            workdir: Path) -> dict:
    """GATEORDER-0 — the commits after every bound receipt's head, and which of their paths are record paths.

    The rule and its residuals: contracts/graph-verified-change/trailing-record-commits.v1.md. Everything here
    is read from git at base/head; the receipt contributes only its head and its own bound bytes. The result
    never widens what a receipt verifies — it only says which paths a trailing commit may carry."""
    heads = sorted({h for h in (_receipt_head(r["_doc"]) for r in bound)
                    if h and git_ok(repo, "cat-file", "-e", f"{h}^{{commit}}")})
    out = {"rule": "contracts/graph-verified-change/trailing-record-commits.v1.md", "receipt_heads": heads,
           "trailing_commits": [], "admitted_paths": {"receipts": [], "derived": []},
           "edited_after_receipt_head": [], "derived_verification": {"verdict": None, "why": "no declared path"}}
    if not heads:
        return out
    trailing = [c for c in git(repo, "rev-list", head, f"^{base}", *[f"^{h}" for h in heads]).split() if c]
    out["trailing_commits"] = trailing
    if not trailing:
        return out
    # Each trailing commit's OWN paths, with renames split into their delete and add sides: a rename
    # pairing would otherwise hide the deletion of its source behind an admissible destination. A merge
    # contributes only the paths it changes against EVERY parent (-c) — what the merge itself wrote —
    # so joining two receipted branches is not an edit, while a conflict resolution is.
    touched: set[str] = set()
    for c in trailing:
        parents = git(repo, "rev-list", "--parents", "-n", "1", c).split()[1:]
        if len(parents) > 1:
            touched |= _names(repo, "diff-tree", "-r", "-c", "--no-commit-id", "--name-only", c)
        elif parents:
            touched |= _names(repo, "diff", "--name-only", "--no-renames", parents[0], c)
    # A path a trailing commit touches and a later one restores has no net change over the range.
    range_paths = _names(repo, "diff", "--name-only", "--no-renames", base, head)
    trailing_paths = sorted(touched & range_paths)
    in_receipt_ranges = set()
    for h in heads:
        in_receipt_ranges |= _names(repo, "diff", "--name-only", "--no-renames", base, h)

    # (a) the receipt itself — the bytes at head:path are the bytes the gate bound
    receipt_paths = set()
    root = repo.resolve()
    for r in bound:
        try:
            rel = Path(r["path"]).resolve().relative_to(root).as_posix()
        except ValueError:
            continue  # a receipt from the pull-request body or a workdir is not a file of this change
        blob = subprocess.run(["git", "-C", str(repo), "show", f"{head}:{rel}"], capture_output=True)
        if blob.returncode == 0 and r.get("digest") == sha256_bytes(blob.stdout):
            receipt_paths.add(rel)

    # (b) a derived artefact declared AT BASE (no bootstrap), measured by its own verifier at head.
    # The membership test is `record_path_refusal`, the SAME predicate the DEC-AUP-0038 R6 binding window
    # uses (DEC-AUP-0041): a deleted artefact has no bytes to verify, a non-regular blob is written THROUGH
    # by the mutation test, and a path that is itself a declared verifier would vouch for its replacement.
    decl, why_decl = read_declaration(repo, base)
    declared, _bad = declared_artefacts(decl)
    refused = {p: r for p in trailing_paths if p not in receipt_paths
               for r in [record_path_refusal(repo, base, head, p, declared)] if r}
    derived = [p for p in trailing_paths if p not in receipt_paths and p not in refused]
    out["not_record_paths"] = refused
    derived_ok: set[str] = set()
    if derived:
        workdir.mkdir(parents=True, exist_ok=True)
        ok, why = _verify_declared_artefacts(repo, head, declared, derived, workdir)
        out["derived_verification"] = {"verdict": ok, "why": why, "paths": derived, "declaration": why_decl}
        if ok is True:
            derived_ok = set(derived)
    elif decl is None:
        out["derived_verification"]["why"] = why_decl

    record = receipt_paths | derived_ok
    out["edited_after_receipt_head"] = [p for p in trailing_paths if p not in record]
    out["admitted_paths"] = {"receipts": sorted(p for p in trailing_paths if p in receipt_paths
                                                and p not in in_receipt_ranges),
                             "derived": sorted(p for p in trailing_paths if p in derived_ok
                                               and p not in in_receipt_ranges)}
    return out


def cashed_canary_ids(doc: dict, boundary_inferred: set[str]) -> set[str]:
    """Which canary verifier ids a receipt actually SPENDS (DEC-AUP-0037's `cashed` condition).

    The same condition `schema_check.classify` applies to the same rule, in one place both halves
    can be asked: a claim is cashed when a `verified` verdict cites the row, or when the row's
    claimed entities are what would keep INFERRED_BOUNDARY_WITHOUT_CANARY quiet for a boundary
    entity reached over an inferred or observed edge.

    A2-242b. Without this, the gate refused this decision's OWN receipt — two `not_measured`
    verdicts, nothing resting on the row — for citing a `verify.py` canary output that is not a
    CanaryResult, while the validator called the same bytes conformant. A rule that punishes the
    receipt which refused to overstate itself teaches authors to cite nothing instead.

    A2-270. `boundary_inferred` is the set of boundary entities that still OWE a canary — the
    caller subtracts the validly exempted ones, because an exemption, not the row, is what keeps
    C12 quiet for those. The second half is «what the listing suppresses», never «what the listing
    says»: `verify.py`'s `v-canary` row names every boundary entity it ran over even when it
    consumed zero canary documents, and reading that list as a claim refused every caller receipt
    of a code change under the 5fde907 bundle (measured on muneral#163). DEC-AUP-0037 R2 already
    decides this side: coverage is what the DOCUMENT lists, and `covered` below is read from the
    document either way — narrowing `cashed` changes which problems are REPORTED, never which
    entities are covered."""
    vds = doc.get("verdicts") if isinstance(doc.get("verdicts"), list) else []
    cited = {vid for rec in vds if isinstance(rec, dict) and rec.get("verdict") == "verified"
             for vid in (rec.get("verifier_ids") or []) if isinstance(vid, str)}
    out = set()
    for v in doc.get("verifiers") or []:
        if not isinstance(v, dict) or v.get("kind") != "canary":
            continue
        vid = v.get("id")
        if vid in cited or (set(v.get("entities") or []) & boundary_inferred):
            out.add(vid)
    return out


def canary_coverage(repo: Path, rows: list[dict], cashed: set[str] | None = None, *,
                    head: str | None = None) -> tuple[set[str], list[str]]:
    """Which entities a receipt's canary rows ACTUALLY cover (DEC-AUP-0037 R1/R2).

    The coverage is read out of the evidence document, never out of the row that cites it. A row is
    a claim; the document is the measurement. `#112` (A2-233) merged with a row naming two entities
    verified from a canary whose plan, result and source evidence were never committed and whose
    output_ref pointed at one worker's disk — and nothing here opened it, so nothing noticed.

    Refusals are total, never partial: a path outside the repository is not opened at all (an
    absolute output_ref is exactly how the evidence left the tree), an absent or unreadable document
    covers nothing, and a document that is not a CanaryResult covers nothing. Every refusal is
    named, because an entity silently losing its coverage looks identical to one that never had any.

    `cashed` — when given, the ids of the rows something actually RESTS on
    (`cashed_canary_ids`). Coverage is still read from every row, because a row nobody cashes can
    still be the reason a boundary entity is covered; but a problem is only REPORTED for a row whose
    claim is being spent. With `cashed=None` every problem is reported, which is what a caller that
    holds no verdicts (a test, a direct call) should get.

    `head` — the commit being admitted. A2-263 §5.3: this function used to open `output_ref` out of
    the WORKING TREE. `.gitignore:15` ignores `receipts/graph/verifier-out/**/graph-*.json` and
    `impact.Repo.dirty()` is `git status --porcelain`, which does not list ignored files, so a
    CanaryResult present in NO COMMIT credited a boundary entity with full coverage and zero
    problems while the worktree reported clean — and the LOCAL gate, authoritative under
    DEC-AUP-0007, is the one that cashed it. Every read now goes through git objects at `head`.
    Without a head nothing is opened at all: a caller that cannot say which commit it is admitting
    cannot be told what a canary covers.

    A2-263 §5.4: the binding is RE-DERIVED here (`canary_evidence.consume`), not taken from the
    row. The graph-architect's prediction in A2-257 §5.4 — that this turns the first cashed canary
    row into a C12 refusal — is measured in `test_canary_evidence_from_git_objects.py`, not
    assumed: coverage is the document's `entity_verdicts` only while the document's subject binds
    to `head` under DEC-AUP-0040, and is empty, by name, when it does not.
    """
    covered: set[str] = set()
    problems: list[str] = []
    root = repo.resolve()

    def report(vid, text: str) -> None:
        if cashed is None or vid in cashed:
            problems.append(f"{vid}: {text}")

    for v in rows:
        if not isinstance(v, dict) or v.get("kind") != "canary":
            continue
        vid, ref = v.get("id"), v.get("output_ref")
        if not isinstance(ref, str) or not schema_check.repo_relative(ref):
            report(vid, f"output_ref {ref!r} is not a path inside the repository — "
                        f"evidence the gate cannot open is testimony, not measurement")
            continue
        path = (root / ref).resolve()
        if not str(path).startswith(str(root) + os.sep):
            report(vid, f"output_ref {ref!r} resolves outside the repository")
            continue
        if not head:
            report(vid, f"canary evidence {ref} was not opened: no admitted head was given, and "
                        f"{canary_evidence.EVIDENCE_AT_HEAD_REQUIRED}")
            continue
        try:
            doc = json.loads(canary_evidence.read_at_commit(root, head, ref))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            report(vid, f"canary evidence {ref} cannot be read from {str(head)[:12]} "
                        f"({type(exc).__name__}) — {canary_evidence.EVIDENCE_AT_HEAD_REQUIRED}")
            continue
        if not isinstance(doc, dict) or not str(doc.get("schema", "")).startswith("CanaryResult/"):
            report(vid, f"{ref} is not a CanaryResult document (schema="
                        f"{doc.get('schema') if isinstance(doc, dict) else type(doc).__name__!r})")
            continue
        rows_ok, binding, _doc = canary_evidence.consume(path, root, head, at_head=ref)
        if binding:
            report(vid, f"{ref} does not bind {str(head)[:12]}: " + "; ".join(binding[:3]))
            continue
        listed = set(rows_ok)
        surplus = sorted(set(v.get("entities") or []) - listed)
        if surplus:
            report(vid, f"the row names {len(surplus)} entity(ies) the document does not "
                        f"list, which are therefore not covered: " + ", ".join(surplus[:6]))
        covered |= listed
    return covered, problems


def probe_effective_verdicts(doc: dict, verdict_of: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """What an entity's verdict is worth once the PROBES it rests on are counted (DEC-AUP-0039).

    An endpoint probe observes a running contour. Its evidence cannot be re-derived from the tree at
    head the way a type-check's can, so the receipt carries the measurement itself in `observed`, one
    row per probe, each naming the `endpoint_probe` verifier row it belongs to. A2-251 measured what
    that section was worth before this function existed: a receipt all of whose fifteen observations
    were `failed` came back `conformant` from the validator and `admit` from the gate, because nothing
    read the key. Tolerated is not read.

    This is the gate's half, and it is deliberately the SAME arithmetic every other verifier gets: an
    entity claimed `verified` on a probe that was observed to fail is counted `failed`, on a probe that
    could not be measured `not_measured` — and from there C08/C09 and the ordinary exemption rules
    apply, unchanged. The receipt's own claim is not believed over the receipt's own evidence.

    Returns (downgrades, problems). `problems` names only rows something RESTS on — DEC-AUP-0037's
    cashed condition: a probe row nobody cites claims nothing, and an honest `not_measured` verdict
    must stay clean or the rule would punish the receipt that refused to overstate itself.
    """
    rows = doc.get("observed") if isinstance(doc.get("observed"), list) else []
    probes = {v.get("id") for v in (doc.get("verifiers") or [])
              if isinstance(v, dict) and v.get("kind") == "endpoint_probe"}
    seen: dict[str, list[str]] = {vid: [] for vid in probes if isinstance(vid, str)}
    for o in rows:
        if isinstance(o, dict) and o.get("verifier_id") in seen and isinstance(o.get("verdict"), str):
            seen[o["verifier_id"]].append(o["verdict"])
    RANK = {"verified": 0, "not_measured": 1, "failed": 2}
    downgrades: dict[str, str] = {}
    problems: list[str] = []
    for rec in (doc.get("verdicts") or []):
        if not isinstance(rec, dict) or rec.get("verdict") != "verified":
            continue
        ent = rec.get("entity")
        for vid in (rec.get("verifier_ids") or []):
            if vid not in seen:
                continue
            if not seen[vid]:
                problems.append(f"{ent} is verified on endpoint probe {vid}, which records no observation "
                                f"at all — a claim of measurement is not a measurement")
                worst = "not_measured"
            else:
                worst = max(seen[vid], key=lambda v: RANK.get(v, 2))
                if worst == "verified":
                    continue
                bad = sorted({v for v in seen[vid] if v != "verified"})
                problems.append(f"{ent} is verified on endpoint probe {vid}, whose {len(seen[vid])} "
                                f"observation(s) include {', '.join(bad)}")
            if RANK.get(worst, 2) > RANK.get(downgrades.get(ent, "verified"), 0):
                downgrades[ent] = worst
    return {e: v for e, v in downgrades.items() if verdict_of.get(e) == "verified"}, problems


def gate(repo: Path, base: str, head: str, receipt_paths: list[Path], policy: dict, *,
         description: str = "", bypass_flag: bool = False, disabled: frozenset[str] = frozenset(),
         work_item_enforcement: str | None = None, ledger_dir: Path = LEDGER_DIR,
         repo_name: str | None = None, explicit_receipts: bool = True,
         event: dict | None = None, verifier_job: str | None = None,
         verifier_conclusion: str | None = None, verifier_output_ref: str | None = None,
         automated_workdir: Path | None = None,
         bundle_rel: str = DEFAULT_BUNDLE_DIR,
         structural_workdir: Path | None = None,
         base_branch: str | None = None) -> dict:
    checks: list[dict] = []
    # A2-238. The policy's own words: `off` means "the attachment is not required (never used in a
    # PROGRAM-OWNED repository)", and `.github/workflows/graph-admission.yml` therefore defaults its
    # caller-facing input to `off` — "the evidence ledger lives in the program repository". The
    # library default did not know that, so an agent running the gate the ordinary way against a
    # caller repository got `paused_safe / C13 WORK_ITEM_EVIDENCE_MISSING` for a ledger that could
    # not exist there, i.e. a pause about where the tool was run rather than about the change
    # (measured by A2-234 on ARAS #196, and by A2-233 on its own branch). CI never saw it, because
    # CI passes the flag; the local gate — the AUTHORITATIVE one under DEC-AUP-0007 — did.
    #
    # The flag still wins over the detection, in both directions, and whichever of the three
    # decided it is recorded in the receipt: a default that cannot be read back is a default nobody
    # can argue with.
    if work_item_enforcement:
        enforcement, enforcement_source = work_item_enforcement, "--enforcement"
    elif is_program_repo(repo, repo_name):
        enforcement, enforcement_source = policy["work_item_evidence"]["enforcement"], "policy default (program repository)"
    else:
        enforcement, enforcement_source = "off", ("caller repository: the evidence ledger lives in the program "
                                                  "repository (admission-gate.v1.json → work_item_evidence."
                                                  "enforcement_values.off). Pass --enforcement explicitly to override.")
    pol_checks = {c["id"]: c for c in policy["checks"]}

    def add(cid: str, detail: str, entities=None, verdict=None, **extra):
        if cid in disabled:
            return
        spec = pol_checks[cid]
        checks.append({"id": cid, "code": spec["code"], "verdict": verdict or spec["verdict"],
                       "detail": detail, **({"entities": entities[:40]} if entities else {}), **extra})

    desc_l = (description or "").lower()

    # C01 — bypass refused before any lookup
    env_bypass = [k for k in ("AUP_SKIP_RECEIPT", "AUP_ADMIT_BYPASS") if os.environ.get(k)]
    phrases = [p for p in pol_checks["C01"]["bypass_phrases"] if p in desc_l]
    if bypass_flag or env_bypass or phrases:
        src = (["--skip-receipt"] if bypass_flag else []) + [f"env:{k}" for k in env_bypass] + [f"phrase:{p}" for p in phrases]
        add("C01", "bypass attempt: " + ", ".join(src))

    commits = range_commits(repo, base, head)
    files = range_files(repo, base, head)
    changed = {f["path"] for f in files}

    # --- AUP-GRAPH-006:gate2a — the typed automated-author path -------------------------------
    # It runs BEFORE the receipt binding, and its only effect is to ADD a receipt to the list that
    # every downstream check then examines. Nothing downstream knows or cares who wrote a receipt.
    automated = {"eligible": False, "receipt_path": None}
    au_spec, au_evidence = match_automated_author(policy, event)
    automated["author_match"] = au_evidence
    if au_spec is not None:
        allowed = au_spec.get("path_allowlist") or []
        inside, outside = allowlist_split(sorted(changed), allowed)
        # A declared derived artefact is not "outside the manifest allowlist" — it is the tree's own
        # function of what the allowlist admits. MEASURED on muneral #32: the dependency bump is
        # inside the list, but this repository's mutation evidence pins a hash of the whole tracked
        # tree, so the bump is only green once apps/api/test/assembly/mutation-results.json is
        # rewritten in the same head. The bot cannot do that, so a workflow does it — and that
        # commit then put the pull request OUTSIDE the allowlist and refused it. `lint-and-test`
        # green plus `graph-admission` refused, on a change whose every path is either a manifest or
        # a declared artefact: the same mutually-exclusive-greens shape gate5a fixed for the
        # self-update path, reappearing on the automated-author path one contract over.
        #
        # The licence is NOT taken on trust, exactly as B6 does not take it on trust: the entries
        # come from the declaration READ AT BASE (a change may not widen its own licence), and each
        # such path is put through the artefact's OWN verifier twice — once on the honest head tree,
        # once with a single byte corrupted, which must be refused. An artefact whose verifier
        # cannot be run, or does not catch the corruption, stays outside and the ordinary rule
        # applies. not_measured is not a pass here either.
        if outside:
            decl_au, why_au, _boot_au = declaration_in_force(repo, base, head, {f["path"]: f["status"] for f in files})
            declared_au, _bad_au = declared_artefacts(decl_au)
            candidates = [p for p in outside if p in declared_au]
            if candidates:
                wd_au = Path(automated_workdir) if automated_workdir else Path(tempfile.mkdtemp(prefix="gate2a-decl-"))
                wd_au.mkdir(parents=True, exist_ok=True)
                ok_au, why_v = _verify_declared_artefacts(repo, head, declared_au, candidates, wd_au)
                automated["declared_artefacts"] = {"paths": candidates, "verdict": ok_au,
                                                   "why": why_v, "declaration": why_au}
                if ok_au is True:
                    outside = [p for p in outside if p not in set(candidates)]
                    inside = sorted(set(inside) | set(candidates))
        automated["path_allowlist"] = {"inside": inside, "outside": outside}
        if outside:
            add("C15", f"{au_spec.get('login')} authored this pull request, but {len(outside)} changed path(s) are "
                       f"outside the dependency-manifest allowlist ({', '.join(outside[:4])}"
                       f"{' …' if len(outside) > 4 else ''}) — no exemption is issued and the ordinary rule applies")
        else:
            wd = Path(automated_workdir) if automated_workdir else Path(tempfile.mkdtemp(prefix="gate2a-"))
            wd.mkdir(parents=True, exist_ok=True)
            rec_doc, note = synthesize_automated_receipt(
                repo, base, head, files, au_spec, policy,
                repo_name=repo_name or repo_remote_name(repo), verifier_job=verifier_job,
                verifier_conclusion=verifier_conclusion, verifier_output_ref=verifier_output_ref,
                workdir=wd, event_evidence=au_evidence)
            automated["note"] = note
            if rec_doc is None:
                add("C15", f"{au_spec.get('login')}: the gate could not author a receipt — {note}")
            else:
                rp = wd / "automated-author-receipt.json"
                write_json(rp, rec_doc)
                receipt_paths = list(receipt_paths) + [rp]
                automated.update({"eligible": True, "receipt_path": str(rp),
                                  "receipt_id": rec_doc["receipt_id"],
                                  "admission": rec_doc["admission"]["verdict"],
                                  "exemption_code": rec_doc["exemptions"][0]["code"]})
                add("C14", f"{au_spec.get('login')} is a registered automated author (matched on "
                           f"pull_request.user.login+id+type, NOT on the branch name "
                           f"{au_evidence.get('author', {}).get('claimed_head_ref')!r}); {note}. The receipt the "
                           f"gate authored is checked exactly like any other receipt below.")
    elif event is not None and au_evidence.get("reason"):
        add("C15", au_evidence["reason"])

    # bind receipts
    bound, unbound = [], []
    for p in receipt_paths:
        doc, err = read_receipt(p)
        rec = {"path": str(p), "digest": sha256_file(p) if p.exists() else None}
        if doc is None:
            rec.update({"bound": False, "reason": f"unreadable: {err}"})
            unbound.append(rec)
            continue
        if not str(doc.get("schema", "")).startswith("ChangeAdmissionReceipt"):
            continue  # a document that merely mentions the schema (a dossier, a readiness receipt) is not a receipt
        rec["receipt_id"] = doc.get("receipt_id")
        ok, why = receipt_binds(repo, doc, base, head, set(commits))
        rec.update({"bound": ok, "reason": why})
        (bound if ok else unbound).append(rec | {"_doc": doc})

    # C05 — a receipt was named for this change but belongs to another range
    if explicit_receipts:
        for rec in unbound:
            add("C05", f"{Path(rec['path']).name}: {rec['reason']}")

    # C02 / C03 — no receipt at all
    if not bound:
        claim = [m for m in pol_checks["C02"]["claim_markers"] if m in desc_l]
        if claim:
            add("C02", "the change description claims verification without a receipt: " + ", ".join(claim))
        add("C03", f"no ChangeAdmissionReceipt/v1 bound to {base[:12]}..{head[:12]} "
                   f"({len(unbound)} candidate receipt(s) examined)")

    covered: set[str] = set()
    all_codes: list[str] = []
    for rec in bound:
        doc = rec["_doc"]
        cls = schema_check.classify(doc)
        rec["schema_verdict"] = cls["verdict"]
        rec["schema_codes"] = cls.get("codes", [])
        all_codes += rec["schema_codes"]
        if cls["verdict"] != "conformant":
            add("C04", f"{Path(rec['path']).name}: " + ", ".join(cls["codes"][:8]))

        cs = doc.get("change_set") or {}
        for f in cs.get("files") or []:
            if isinstance(f, dict) and isinstance(f.get("path"), str):
                covered.add(f["path"])

        stale = (doc.get("staleness") or {}).get("verdict")
        if stale != "fresh":
            add("C07", f"{Path(rec['path']).name}: staleness.verdict={stale!r}")

        # Revision selections are remeasured from Git, not trusted from receipt node_ids.
        try:
            coverage_problems = impact_pair.receipt_problems(repo, doc)
        except Exception as exc:
            # The class name alone ("Refusal") hides the whole diagnosis: the reason a coverage
            # measurement refused (STALE_GRAPH, a dirty tree, a missing graph) is carried in the
            # message, and C18 is the only place an operator ever sees it. Keep the text.
            detail = str(exc).strip() or type(exc).__name__
            coverage_problems = ["dual graph coverage could not be measured: "
                                 + type(exc).__name__ + ": " + detail]
        if coverage_problems:
            # A2-274 measured what truncation costs: ten real coverage problems, four printed, so
            # an author fixed the four and got the same red check back with the next four — two
            # extra receipt-rebuild cycles for a list the gate already held in memory. The whole
            # list now travels in the check entry, and the human line names the remainder instead
            # of hiding it: a gate that knows ten problems must never report "4".
            shown = coverage_problems[:C18_PROBLEMS_SHOWN]
            more = len(coverage_problems) - len(shown)
            add("C18", f"{Path(rec['path']).name}: " + "; ".join(shown)
                       + (f" …and {more} more of {len(coverage_problems)} (the full list is in this check's "
                          f"`coverage_problems` — re-run the gate with --json)" if more else ""),
                coverage_problems=list(coverage_problems))

        # verdict aggregation with admissible exemptions
        captured = parse_iso(doc.get("captured_at_utc")) or datetime.now(timezone.utc)
        verdict_of = {v["entity"]: v.get("verdict") for v in (doc.get("verdicts") or [])
                      if isinstance(v, dict) and "entity" in v}
        valid_exempt, bad_exempt = set(), []
        for x in doc.get("exemptions") or []:
            if not isinstance(x, dict):
                bad_exempt.append("exemption is not an object")
                continue
            exp = parse_iso(x.get("expires_at_utc"))
            if not x.get("owner"):
                bad_exempt.append(f"{x.get('entity')}: no owner")
            elif exp is None:
                bad_exempt.append(f"{x.get('entity')}: no expiry")
            elif exp <= captured:
                bad_exempt.append(f"{x.get('entity')}: expired {x.get('expires_at_utc')}")
            elif x.get("entity") not in verdict_of:
                bad_exempt.append(f"{x.get('entity')}: exempts an entity that has no verdict")
            else:
                valid_exempt.add(x["entity"])
        if bad_exempt:
            add("C10", f"{Path(rec['path']).name}: " + "; ".join(bad_exempt[:6]))

        # --- AUP-GRAPH-006:gate4b — C16/C17: the receipt is never believed about its own structural
        # exemption. The gate re-measures A1-A4 / B1-B5 here, from git and from a graph rebuilt at
        # head, every time it evaluates this range.
        struct = [x for x in (doc.get("exemptions") or [])
                  if isinstance(x, dict) and x.get("code") in STRUCTURAL_CODES]
        if struct:
            swd = Path(structural_workdir) if structural_workdir else Path(tempfile.mkdtemp(prefix="gate4b-"))
            problems, sev = recheck_structural(repo, base, head, files, policy, struct,
                                               repo_name=repo_name or repo_remote_name(repo),
                                               verdict_entities=list(verdict_of), workdir=swd,
                                               bundle_rel=bundle_rel, verifier_job=verifier_job,
                                               verifier_conclusion=verifier_conclusion,
                                               receipt_head=_receipt_head(doc), base_branch=base_branch)
            rec["structural_exemption"] = {"code": sorted({x.get("code") for x in struct})[0],
                                           "entities": sorted(str(x.get("entity")) for x in struct),
                                           "re_measured": [c for c in (sev.get("checks") or [])],
                                           "problems": problems}
            if sev.get("toolchain_mismatch"):
                tm = sev["toolchain_mismatch"]
                add("C20", f"{Path(rec['path']).name}: {tm['path']}: the declared artefact verifier refused the "
                           f"head tree over its toolchain, not over these bytes. The gate ran "
                           f"{tm['interpreter']}. {tm['tail'][:200]}")
            if problems:
                add("C16", f"{Path(rec['path']).name}: " + "; ".join(problems[:3]))
                valid_exempt -= {x.get("entity") for x in struct}
            elif sev.get("coverage_gap"):
                add("C17", f"{Path(rec['path']).name}: {len(sev['coverage_gap'])} added path(s) yield no node at "
                           f"head ({', '.join(sev['coverage_gap'][:4])}); language_coverage="
                           f"{sev.get('language_coverage')} — the exemption is admitted on a WEAKER measurement "
                           f"here than where the builder covers the files")

        # C19 — the probes an entity rests on are counted before the verdicts are. A `verified` claim
        # resting on an endpoint probe that was observed to fail becomes `failed` here, and C08/C09
        # then treat it exactly as they treat a failed tsc: this is what «probe verdicts count like
        # any other verifier's» means. The claim/evidence contradiction is ALSO reported in its own
        # right, because a receipt that overstates its own measurement is a different defect from an
        # entity that honestly failed.
        if "C19" not in disabled:
            probe_downgrades, probe_problems = probe_effective_verdicts(doc, verdict_of)
            for probe_problem in probe_problems:
                add("C19", f"{Path(rec['path']).name}: {probe_problem}")
            verdict_of.update(probe_downgrades)
            if probe_downgrades:
                rec["probe_downgrades"] = dict(sorted(probe_downgrades.items()))

        failed = sorted(e for e, v in verdict_of.items() if v == "failed" and e not in valid_exempt)
        notm = sorted(e for e, v in verdict_of.items() if v == "not_measured" and e not in valid_exempt)
        rec["entity_counts"] = {
            "verified": sum(1 for v in verdict_of.values() if v == "verified"),
            "failed": sum(1 for v in verdict_of.values() if v == "failed"),
            "not_measured": sum(1 for v in verdict_of.values() if v == "not_measured"),
            "exempted": len(valid_exempt),
        }
        if failed:
            add("C08", f"{Path(rec['path']).name}: {len(failed)} entity(ies) failed without an exemption", failed)
        if notm:
            add("C09", f"{Path(rec['path']).name}: {len(notm)} entity(ies) not_measured without an exemption", notm)

        av = (doc.get("admission") or {}).get("verdict")
        rec["admission"] = av
        if av == "paused_safe":
            add("C11", f"{Path(rec['path']).name}: the receipt itself pauses the change", verdict="paused_safe")
        elif av not in ("admitted", "admitted_with_exemptions"):
            add("C11", f"{Path(rec['path']).name}: admission.verdict={av!r}")

        # C12 — inferred/observed hop onto a service boundary without a canary.
        # DEC-AUP-0037 R2: the entities a canary covers are the ones its committed document lists.
        # This used to read `verifiers[kind=canary].entities` — the receipt's own claim about its own
        # coverage, twelve lines from impact_pair.py's docstring saying a receipt may not do that.
        #
        # A2-242b. The boundary set is computed FIRST, because it is half of the `cashed` condition:
        # a row is being spent when a `verified` verdict cites it, or when its claim is what would
        # keep this very check quiet for a boundary entity. Reporting a row's problems without that
        # condition refused this decision's own receipt, whose canary row carries two `not_measured`
        # verdicts and discharges nothing — while `schema_check`, which does apply it, called the
        # same bytes conformant.
        imp = doc.get("impact_set") or {}
        boundary_inferred = []
        for section in ("deterministic_core", "inferred_tail"):
            for e in imp.get(section) or []:
                if not isinstance(e, dict) or e.get("boundary") not in ("service", "repo"):
                    continue
                hops = e.get("path") if isinstance(e.get("path"), list) else []
                if any(isinstance(h, dict) and h.get("provenance") in ("inferred", "observed") for h in hops):
                    boundary_inferred.append(e["entity"])
        # A2-270: a validly exempted boundary entity is kept quiet by its EXEMPTION (the
        # `e not in valid_exempt` term below), so a canary row that merely lists it is spending
        # nothing. Passing the full set made `verify.py`'s scope list a claim and turned every
        # caller receipt into a C12 refusal.
        canary_entities, canary_problems = canary_coverage(
            repo, doc.get("verifiers") or [],
            cashed=cashed_canary_ids(doc, set(boundary_inferred) - set(valid_exempt)), head=head)
        for problem in canary_problems:
            add("C12", f"{Path(rec['path']).name}: {problem}")
        boundary = [e for e in boundary_inferred
                    if e not in canary_entities and e not in valid_exempt]
        if boundary:
            add("C12", f"{Path(rec['path']).name}: {len(boundary)} boundary entity(ies) reached over an "
                       f"inferred/observed edge with no canary", sorted(set(boundary)))

    # C06 — the receipts must cover every changed file, and nothing but a record commit may follow a
    # receipt's head (GATEORDER-0: contracts/graph-verified-change/trailing-record-commits.v1.md)
    record = None
    if bound:
        wd_rc = Path(automated_workdir) if automated_workdir else Path(tempfile.mkdtemp(prefix="gateorder0-"))
        record = trailing_record_commits(repo, base, head, bound, changed, wd_rc)
        uncovered = sorted(changed - covered - set(record["admitted_paths"]["receipts"])
                           - set(record["admitted_paths"]["derived"]))
        after = record["edited_after_receipt_head"]
        if uncovered or after:
            parts = []
            if uncovered:
                parts.append(f"{len(uncovered)}/{len(changed)} changed file(s) are absent from the receipt change_set")
            if after:
                parts.append(f"{len(after)} path(s) changed AFTER the receipt head by a commit no receipt has seen "
                             f"({', '.join(after[:4])}) — only the receipt file itself and a declared derived "
                             f"artefact that its own verifier accepts are record commits; re-issue the receipt on "
                             f"the full range")
            if record["derived_verification"].get("verdict") not in (None, True):
                parts.append("declared derived artefact(s) not admitted: " + str(record["derived_verification"]["why"]))
            add("C06", "; ".join(parts), sorted(set(uncovered) | set(after)))

    # C13 — work-item evidence attachment
    evidence = {"enforcement": enforcement, "enforcement_source": enforcement_source,
                "entries": [], "status": "not_measured"}
    if bound and enforcement != "off":
        missing = []
        for rec in bound:
            doc = rec["_doc"]
            wi = doc.get("work_item")
            digest = rec["digest"]
            entry = ledger_lookup(ledger_dir, wi, digest)
            evidence["entries"].append({"receipt": Path(rec["path"]).name, "work_item": wi,
                                        "ledger": bool(entry),
                                        "delivery": (entry or {}).get("delivery", {}).get("status")})
            if not wi:
                missing.append(f"{Path(rec['path']).name}: receipt.work_item is null")
            elif not entry:
                missing.append(f"{Path(rec['path']).name}: no ledger entry with digest {str(digest)[:19]}…")
            elif enforcement == "muneral" and (entry.get("delivery") or {}).get("status") != "posted":
                missing.append(f"{Path(rec['path']).name}: Muneral delivery "
                               f"{(entry.get('delivery') or {}).get('status')!r}")
        evidence["status"] = "verified" if not missing else "not_measured"
        if missing:
            # The detail names the lever, because the two ways out are different actions and the
            # code alone points at neither: in the program repository the answer is to WRITE the
            # ledger entry; anywhere else the answer is that this enforcement level does not apply.
            add("C13", "; ".join(missing[:6]) + f" [enforcement={enforcement!r} from {enforcement_source}] — "
                       "attach the evidence with `admit_change.py attach --receipt <path> --work-item <id>`, "
                       "or pass `--enforcement off` if this repository does not own the ledger")

    verdict = "admit"
    for c in checks:
        if VERDICT_RANK[c["verdict"]] > VERDICT_RANK[verdict]:
            verdict = c["verdict"]

    doc = {
        "schema": "AdmissionGateReceipt/v1",
        "gate_receipt_id": f"gate-{stamp()}",
        "captured_at_utc": now_iso(),
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "decision_ref": "DEC-AUP-0008",
        "policy": {"path": str(POLICY_PATH.relative_to(PROGRAM_ROOT)), "id": policy["id"],
                   "digest": sha256_bytes(canonical(policy).encode())},
        "repo": {"name": repo_name or repo_remote_name(repo), "path": str(repo)},
        "range": {"base": base, "head": head, "commits": len(commits), "files": files},
        "receipts": [{k: v for k, v in r.items() if not k.startswith("_")} for r in bound + unbound],
        "checks": checks,
        "work_item_evidence": evidence,
        "automated_author": automated,
        "record_commits": record,
        "verdict": verdict,
        "reason_codes": sorted({c["code"] for c in checks}),
        "exit_code": EXIT_OF[verdict],
        "rule": policy["purpose"],
        "disabled_checks": sorted(disabled),
    }
    return doc


# The two files that only the program repository has at its root: the policy this gate reads and the
# tool that reads it. A caller repository carries the gate as a VENDORED bundle under
# `.github/graph-admission/`, so neither path exists at its root — which is the whole point of the
# distinction, because the work-item evidence LEDGER lives beside them and nowhere else.
PROGRAM_MARKERS = ("contracts/graph-verified-change/admission-gate.v1.json", "tools/graph/admit_change.py")


def is_program_repo(repo: Path, repo_name: str | None = None) -> bool:
    """Is the repository being gated the one that owns the evidence ledger?

    Asked of the tree, not of a remote URL: the answer decides a DEFAULT, and a default that
    depends on network-visible configuration would differ between a clone and its mirror. The
    remote name is consulted only as a second opinion, and only when it is already in hand."""
    if all((repo / m).exists() for m in PROGRAM_MARKERS):
        return True
    name = (repo_name or "").lower()
    return name.endswith("/arcanada-universal-program")


def repo_remote_name(repo: Path) -> str:
    try:
        url = git(repo, "remote", "get-url", "origin").strip()
    except RuntimeError:
        return repo.name
    m = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?$", url)
    return m.group(1) if m else repo.name


# ------------------------------------------------------------------ work-item evidence ledger
def ledger_path(ledger_dir: Path, work_item) -> Path | None:
    wid = work_item_id(work_item)
    return (ledger_dir / f"{wid}.json") if wid else None


def work_item_id(work_item) -> str | None:
    if isinstance(work_item, str):
        return work_item
    if isinstance(work_item, dict):
        for k in ("id", "task_id", "key", "card"):
            if work_item.get(k):
                return str(work_item[k])
    return None


def ledger_lookup(ledger_dir: Path, work_item, digest: str | None) -> dict | None:
    p = ledger_path(ledger_dir, work_item)
    if not p or not p.exists() or not digest:
        return None
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    for a in doc.get("attachments", []):
        if (a.get("evidence_ref") or {}).get("digest") == digest:
            return a
    return None


def build_attachment(receipt_path: Path, doc: dict, work_item: str, label: str, uri: str | None,
                     muneral_task_id: str | None = None) -> dict:
    digest = sha256_file(receipt_path)
    try:
        rel = str(receipt_path.resolve().relative_to(PROGRAM_ROOT))
    except ValueError:
        rel = str(receipt_path)
    return {
        "schema": "WorkItemEvidenceAttachment/v1",
        "attachment_kind": "evidence",
        "work_item": {"system": "muneral", "task_id": work_item, "muneral_task_id": muneral_task_id,
                      "epic": doc.get("work_item", {}).get("epic") if isinstance(doc.get("work_item"), dict) else None},
        "evidence_ref": {
            "uri": f"{uri or 'aup://arcanada-universal-program/'}{rel}"[:512],
            "digest": digest,
            "contentType": "application/json",
            "label": label[:128],
        },
        "receipt_path": rel,
        "receipt_id": doc.get("receipt_id"),
        "attached_at_utc": now_iso(),
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "delivery": {"target": "muneral", "status": "not_measured",
                     "reason_code": "MUNERAL_NO_WORK_ITEM_EVIDENCE_ROUTE",
                     "checked_at_utc": now_iso(), "probe": []},
    }


MUNERAL_CANDIDATE_ROUTES = [
    ("POST", "/tasks/{id}/evidence"),
    ("POST", "/tasks/{id}/attachments"),
    ("POST", "/tasks/{id}/receipts"),
    ("POST", "/work-items/{id}/evidence"),
]


def muneral_probe(task_id: str, key: str, base_url: str, ua: str) -> list[dict]:
    """Read-only discovery: does a work-item evidence route exist for an agent key?

    A 404 says the route does not exist; 401/403 says it exists but rejects an agent key.
    Probes are GETs — this function never writes to Muneral and never touches a status route.
    """
    out = []
    for _method, tmpl in MUNERAL_CANDIDATE_ROUTES:
        path = tmpl.format(id=task_id)
        req = urllib.request.Request(base_url + path, method="GET",
                                     headers={"Authorization": f"Bearer {key}", "User-Agent": ua})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        except OSError as e:
            code = f"error:{type(e).__name__}"
        out.append({"probe": f"GET {path}", "status": code})
    return out


def cmd_attach(a) -> int:
    policy = load_policy(a.policy)
    receipt_path = Path(a.receipt).resolve()
    doc, err = read_receipt(receipt_path)
    if doc is None:
        print(f"unreadable receipt: {err}", file=sys.stderr)
        return 2
    wi = a.work_item or work_item_id(doc.get("work_item"))
    if not wi:
        print("no work item: pass --work-item or set receipt.work_item", file=sys.stderr)
        return 2
    att = build_attachment(receipt_path, doc, wi, a.label or f"ChangeAdmissionReceipt/v1 {doc.get('receipt_id')}",
                           a.uri, a.muneral_task_id)

    if a.post:
        key = os.environ.get("MUNERAL_API_KEY")
        m = policy["work_item_evidence"]["muneral"]
        if not key:
            att["delivery"]["reason_code"] = "NO_MUNERAL_API_KEY"
        else:
            att["delivery"]["probe"] = muneral_probe(a.muneral_task_id or wi, key, m["base_url"], m["user_agent"])
            live = [p for p in att["delivery"]["probe"] if p["status"] not in (404,)]
            att["delivery"]["checked_at_utc"] = now_iso()
            if not live:
                att["delivery"]["reason_code"] = "MUNERAL_NO_WORK_ITEM_EVIDENCE_ROUTE"
            else:
                att["delivery"]["reason_code"] = "MUNERAL_EVIDENCE_ROUTE_PRESENT_NOT_POSTED"
                att["delivery"]["note"] = ("a candidate route answered; posting is enabled only after the route "
                                           "is declared in admission-gate.v1.json work_item_evidence.muneral.evidence_route")

    ledger_dir = Path(a.ledger_dir) if a.ledger_dir else LEDGER_DIR
    p = ledger_path(ledger_dir, wi)
    ledger = {"schema": "WorkItemEvidenceLedger/v1", "work_item": wi, "system": "muneral", "attachments": []}
    if p.exists():
        try:
            ledger = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    existing = {(x.get("evidence_ref") or {}).get("digest") for x in ledger.get("attachments", [])}
    if att["evidence_ref"]["digest"] in existing:
        for i, x in enumerate(ledger["attachments"]):
            if (x.get("evidence_ref") or {}).get("digest") == att["evidence_ref"]["digest"]:
                ledger["attachments"][i] = att | {"attached_at_utc": x.get("attached_at_utc", att["attached_at_utc"])}
    else:
        ledger["attachments"].append(att)
    ledger["updated_at_utc"] = now_iso()
    write_json(p, ledger)
    print(json.dumps({"ledger": str(p), "work_item": wi, "digest": att["evidence_ref"]["digest"],
                      "delivery": att["delivery"]["status"], "reason_code": att["delivery"].get("reason_code")},
                     ensure_ascii=False))
    return 0


# ------------------------------------------------------------------ charter scan
def classify_line(path: str, line: str, policy: dict) -> str:
    tp = policy["tdd_policy"]
    low = line.lower()
    if any(m in path for m in tp["historical_path_markers"]):
        return "historical"
    # a line that describes the scanner itself (or a grep marker) prescribes nothing; the markers are enumerated in
    # the policy so that every line treated this way stays visible in the receipt under its own class
    if any(m in low for m in tp["meta_markers"]):
        return "meta_classifier_reference"
    if any(m in low for m in tp["opt_in_patterns"]):
        return "opt_in_reference"
    if any(m in low for m in tp["mandate_patterns"]):
        return "mandate_default"
    return "neutral_mention"


HIT_RE = re.compile(r"\bTDD\b|test-first|test first|Iron Law|tdd-required|tdd-discipline", re.IGNORECASE)


def git_surface_files(repo: Path, ref: str, path: str, glob: str | None) -> list[tuple[str, str]]:
    """(display path, content) for a charter surface read from a git ref — the authoritative document is the one on
    main, not the state a shared checkout happens to be parked at (program CLAUDE.md § Authority)."""
    listing = git(repo, "ls-tree", "-r", "--name-only", ref, "--", path).splitlines()
    out = []
    for f in listing:
        rel = f[len(path):].lstrip("/") if f != path else f
        if glob and f != path and not fnmatch.fnmatch(rel, glob):
            continue
        out.append((f, git(repo, "show", f"{ref}:{f}")))
    return out


def scan_surface(spec: dict, policy: dict) -> dict:
    if spec.get("repo"):
        repo, ref = Path(spec["repo"]), spec.get("ref", "origin/main")
        res = {"host": spec["host"], "path": f"{spec['repo']}@{ref}:{spec['path']}", "kind": spec["kind"],
               "hits": [], "status": "verified", "files_scanned": 0, "in_charter": spec.get("in_charter", True),
               "source": {"repo": spec["repo"], "ref": ref, "commit": git(repo, "rev-parse", ref).strip(),
                          "note": "authoritative content read from the git ref, not from the working tree"}}
        if spec.get("note"):
            res["note"] = spec["note"]
        files = git_surface_files(repo, ref, spec["path"], spec.get("glob"))
        res["files_scanned"] = len(files)
        for name, text in files:
            for i, line in enumerate(text.splitlines(), 1):
                if HIT_RE.search(line):
                    res["hits"].append({"file": name, "line": i, "class": classify_line(name, line, policy),
                                        "text": line.strip()[:200]})
        res["violations"] = [h for h in res["hits"] if h["class"] == "mandate_default"]
        if res["violations"]:
            res["status"] = "failed" if res["in_charter"] else "recorded_out_of_charter"
        return res
    p = Path(os.path.expanduser(spec["path"]))
    res = {"host": spec["host"], "path": spec["path"], "kind": spec["kind"], "hits": [],
           "status": "verified", "files_scanned": 0, "in_charter": spec.get("in_charter", True)}
    if spec.get("note"):
        res["note"] = spec["note"]
    if spec.get("writable") is False:
        res["writable"] = False
    if spec.get("reachable") is False:
        res["status"] = "not_measured"
        res["reason"] = spec.get("reason", "surface not reachable from this host")
        return res
    files: list[Path] = []
    if p.is_file():
        files = [p]
    elif p.is_dir():
        pattern = spec.get("glob", "*.md")
        files = sorted(f for f in p.rglob("*") if f.is_file() and fnmatch.fnmatch(str(f.relative_to(p)), pattern))
    elif spec.get("absent_is_clean"):
        res["status"] = "verified"
        res["reason"] = "surface absent: it defines nothing, therefore it mandates nothing"
        return res
    else:
        res["status"] = "not_measured"
        res["reason"] = "path does not exist on this host"
        return res
    res["files_scanned"] = len(files)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            res["hits"].append({"file": str(f), "line": 0, "class": "not_measured", "text": str(e)[:120]})
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if HIT_RE.search(line):
                res["hits"].append({"file": str(f), "line": i,
                                    "class": classify_line(str(f), line, policy),
                                    "text": line.strip()[:200]})
    res["violations"] = [h for h in res["hits"] if h["class"] == "mandate_default"]
    if res["violations"]:
        res["status"] = "failed" if res["in_charter"] else "recorded_out_of_charter"
    return res


def cmd_charter_scan(a) -> int:
    policy = load_policy(a.policy)
    surfaces = policy["tdd_policy"]["charter_surfaces"]
    if a.host:
        surfaces = [s for s in surfaces if s["host"] == a.host]
    results = [scan_surface(s, policy) for s in surfaces]
    counts = {}
    for r in results:
        for h in r["hits"]:
            counts[h["class"]] = counts.get(h["class"], 0) + 1
    in_charter = [r for r in results if r["in_charter"]]
    verdict = ("failed" if any(r["status"] == "failed" for r in in_charter)
               else "not_measured" if any(r["status"] == "not_measured" for r in in_charter)
               else "verified")
    out_of_charter = sum(len(r.get("violations", [])) for r in results if not r["in_charter"])
    doc = {"schema": "CharterScanReceipt/v1", "captured_at_utc": now_iso(),
           "producer": {"tool": TOOL, "version": VERSION}, "model": MODEL,
           "provisional_until_fable_review": True,
           "measure": "AM3 — a search for TDD across the live charters returns only opt-in contexts",
           "pattern": HIT_RE.pattern, "surfaces": results, "class_counts": counts, "verdict": verdict,
           "in_charter_surfaces": len(in_charter),
           "out_of_charter_mandate_hits": out_of_charter,
           "note": "verdict verified requires zero mandate_default hits on every reachable surface; an unreachable "
                   "surface keeps the whole measure not_measured — a charter updated on one host only is a failure "
                   "condition of AUP-GRAPH-006"}
    if a.out:
        write_json(Path(a.out), doc)
    print(json.dumps({"verdict": verdict, "class_counts": counts,
                      "out_of_charter_mandate_hits": out_of_charter,
                      "surfaces": [{"host": r["host"], "path": r["path"], "status": r["status"],
                                    "in_charter": r["in_charter"], "hits": len(r["hits"]),
                                    "violations": len(r.get("violations", []))}
                                   for r in results]}, ensure_ascii=False, indent=1))
    return 0 if verdict == "verified" else (3 if verdict == "not_measured" else 5)


# ------------------------------------------------------------------ PR / merge coverage
def cmd_pr_coverage(a) -> int:
    policy = load_policy(a.policy)
    repo = Path(a.repo).resolve()
    since = a.since or policy["scope"]["enabled_at_utc"]
    receipts = discover_receipts([Path(d) if Path(d).is_absolute() else repo / d
                                  for d in (a.receipt_dir or ["receipts"])])
    heads: dict[str, list[str]] = {}
    for p in receipts:
        doc, _ = read_receipt(p)
        if not isinstance(doc, dict):
            continue
        cs = doc.get("change_set") or {}
        for c in (cs.get("head"), (doc.get("tree") or {}).get("commit")):
            if isinstance(c, str) and len(c) == 40:
                heads.setdefault(c, []).append(str(p.relative_to(repo)) if p.is_relative_to(repo) else str(p))
    log = git(repo, "log", f"--since={since}", "--format=%H%x09%ct%x09%s", a.rev or "HEAD")
    rows = []
    for line in log.splitlines():
        if not line.strip():
            continue
        sha, ts, subject = line.split("\t", 2)
        covered = sha in heads
        rows.append({"commit": sha, "at_utc": datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "subject": subject[:120], "receipt": heads.get(sha, [])[:3], "covered": covered})
    n = len(rows)
    cov = sum(1 for r in rows if r["covered"])
    doc = {"schema": "AdmissionCoverageReceipt/v1", "captured_at_utc": now_iso(),
           "producer": {"tool": TOOL, "version": VERSION}, "model": MODEL,
           "provisional_until_fable_review": True,
           "measure": "AM1 — share of changes in a pilot repository that carry a ChangeAdmissionReceipt/v1",
           "repo": repo_remote_name(repo), "since_utc": since, "rev": a.rev or "HEAD",
           "window": {"enabled_at_utc": policy["scope"]["enabled_at_utc"],
                      "ends_utc": policy["scope"]["coverage_window_ends_utc"],
                      "phase": "baseline" if since <= policy["scope"]["enabled_at_utc"] else "window"},
           "counts": {"commits": n, "with_receipt": cov, "without_receipt": n - cov},
           "coverage": round(cov / n, 4) if n else None,
           "method": "a commit is covered when a ChangeAdmissionReceipt/v1 in the repository names it as "
                     "change_set.head or tree.commit; receipts written before the gate existed are historical (I14) "
                     "and are counted, never re-verified",
           "commits": rows}
    if a.out:
        write_json(Path(a.out), doc)
    print(json.dumps({k: doc[k] for k in ("repo", "since_utc", "counts", "coverage")}, ensure_ascii=False))
    return 0


# ------------------------------------------------------------------ fixtures
def base_receipt(base: str, head: str, *, wi="AUP-GRAPH-006") -> dict:
    return {
        "schema": "ChangeAdmissionReceipt/v1",
        "receipt_id": "car-fixture",
        "captured_at_utc": "2026-09-05T12:00:00Z",
        "producer": {"tool": "tools/graph/verify.py", "version": "1.0.0"},
        "decision_ref": "DEC-AUP-0008",
        "repo": {"name": "Arcanada-one/fixture"},
        "graph": {"source_commit": base, "graph_digest": "sha256:" + "a" * 64,
                  "builder_version": "1.0.0", "built_at_utc": "2026-09-05T11:00:00Z"},
        "tree": {"commit": head, "dirty": False},
        "staleness": {"method": "graph.source_commit == change_set.base; clean tree", "verdict": "fresh",
                      "checked_at_utc": "2026-09-05T12:00:00Z"},
        "change_set": {"mode": "diff", "base": base, "head": head, "files": [
            {"path": "src/a.ts", "status": "M", "kind": "code", "node_id": "code_unit:src/a.ts"},
            {"path": "src/c.ts", "status": "A", "kind": "code", "node_id": "code_unit:src/c.ts"}]},
        "impact_set": {"method": "reverse traversal (GRAPH-003)", "max_depth": 3,
                       "deterministic_core": [{"entity": "code_unit:src/b.ts", "depth": 1, "path": [
                           {"from": "code_unit:src/b.ts", "to": "code_unit:src/a.ts",
                            "edge_type": "imports", "provenance": "deterministic"}]}],
                       "inferred_tail": [], "global_fallback": {"triggered": False}},
        "verifiers": [{"id": "v-tsc", "kind": "type_check", "command": "tsc --noEmit",
                       "entities": ["code_unit:src/a.ts", "code_unit:src/b.ts", "code_unit:src/c.ts"],
                       "exit_code": 0, "output_ref": "verifier-out/tsc.txt"}],
        "verdicts": [{"entity": e, "verdict": "verified", "verifier_ids": ["v-tsc"], "reason": "tsc exit 0"}
                     for e in ("code_unit:src/a.ts", "code_unit:src/b.ts", "code_unit:src/c.ts")],
        "exemptions": [],
        "admission": {"verdict": "admitted", "rule": "admitted requires every verdict = verified"},
        "work_item": {"system": "muneral", "id": wi},
    }


SELFTEST_TOOLCHAIN = {
    "tsc": "TypeScript compiler — compiles the positive admission fixture (src/a.ts, src/b.ts, src/c.ts). "
           "Absent: that one fixture is not_measured; the rest of the battery is unaffected.",
}


def compile_positive_fixture(repo: Path, outputs: Path) -> dict:
    """Compile the positive admission fixture, or say honestly that this host could not.

    A hard raise here made the HOST the verdict. On a machine without `tsc` the gate's own battery
    aborted before it ran, and `tools/ci/self_check.py`'s ratchet then read the absence of a compiler
    as a regression of whatever change was being measured (arcana-devs, A2-229). The tool applies
    `an absent tool yields not_measured, never verified` to every verifier it drives; it now applies
    it to itself, and declares the dependency in SELFTEST_TOOLCHAIN instead of discovering it by
    crashing. A compiler that RUNS and rejects the fixture is still a failure — that is the fixture's
    own claim going false, which is what this check is for."""
    tsc = shutil.which("tsc")
    if not tsc:
        (outputs / "tsc.txt").write_text("tsc not found on PATH; the positive fixture was not compiled\n")
        return {"tool": "tsc", "verdict": "not_measured",
                "reason": "tsc is not on PATH. " + SELFTEST_TOOLCHAIN["tsc"]}
    result = subprocess.run([tsc, "--noEmit", "--target", "ES2022", "--module", "commonjs",
                             "src/a.ts", "src/b.ts", "src/c.ts"], cwd=repo, capture_output=True, text=True, timeout=60)
    (outputs / "tsc.txt").write_text(result.stdout + result.stderr)
    if result.returncode:
        return {"tool": "tsc", "verdict": "failed",
                "reason": f"the positive scratch fixture fails actual TypeScript compilation (tsc exit "
                          f"{result.returncode}): {(result.stdout + result.stderr).strip()[:300]}"}
    return {"tool": "tsc", "verdict": "verified", "reason": "the positive scratch fixture compiles (tsc exit 0)"}


def prepare_gate_fixture_outputs(repo: Path, base: str, head: str, *, compile_types: bool) -> dict | None:
    """Real minimum verifier evidence for the scratch fixture, never product evidence."""
    import verify
    import contract_diff
    tree_base = impact_pair.build_graph.load_tree_git(repo, base, "")
    tree_head = impact_pair.build_graph.load_tree_git(repo, head, "")
    graph = impact_pair.index_at(impact_pair.impact.Repo(repo), head).doc
    fitness = verify.fitness_violations(graph, tree_head, verify.TreeScan(tree_head),
                                       {"fr01", "fr02", "fr03", "fr04", "fr05", "rc01", "rc02", "rc03"})
    contracts = contract_diff.run_diff(tree_base, tree_head, graph=graph, repo_name="fixture")
    if fitness or contracts["summary"]["breaking"] or any(e["verdict"] != "verified" for e in contracts["edges"]):
        raise RuntimeError("the positive scratch fixture does not pass actual contract/fitness checks")
    outputs = repo.parent / "verifier-out"
    outputs.mkdir(exist_ok=True)
    write_json(outputs / "fitness.json", {"violations": fitness})
    write_json(outputs / "contract.json", contracts)
    return compile_positive_fixture(repo, outputs) if compile_types else None


def make_fixtures(base: str, head: str, repo: Path | None = None) -> dict[str, dict]:
    """name -> {receipt|None, expect_verdict, expect_codes, description, kwargs}"""
    F: dict[str, dict] = {}
    if repo is not None:
        prepare_gate_fixture_outputs(repo, base, head, compile_types=False)

    def fresh_receipt():
        r = base_receipt(base, head)
        if repo is not None:
            ir = impact_pair.impact.Repo(repo)
            q = impact_pair.query(impact_pair.index_at(ir, base), impact_pair.index_at(ir, head),
                                 ir.diff_files(base, head), repo=ir, base=base, head=head,
                                 tree_commit=head, tree_dirty=False)
            q["head_graph"]["staleness"]["checked_at_utc"] = impact_pair.build_graph.FIXED_BUILT_AT
            for key in ("graph", "head_graph", "revision_selection", "impact_set"):
                r[key] = q[key]
            r["verify"] = {"required_by_entity": impact_pair.mandatory_by_entity(
                impact_pair.index_at(ir, base), impact_pair.index_at(ir, head), q)}
            for vid, kind, command, output in (
                ("v-fitness", "fitness_rules", "verify.fitness_violations(actual fixture head)", "fitness.json"),
                ("v-contract", "contract_diff", "contract_diff.run_diff(actual fixture base, head)", "contract.json")):
                r["verifiers"].append({"id": vid, "kind": kind, "command": command,
                                       "entities": [v["entity"] for v in r["verdicts"]], "exit_code": 0,
                                       "output_ref": "verifier-out/" + output})
                for verdict in r["verdicts"]:
                    verdict["verifier_ids"].append(vid)
        return r

    def add(name, expect, codes, desc, mutate=None, extra=None, **kw):
        r = fresh_receipt()
        if mutate:
            mutate(r)
        F[name] = {"receipt": r, "expect_verdict": expect, "expect_codes": codes, "description": desc,
                   "extra": extra or [], "kwargs": kw}

    add("conformant-admit", "admit", [], "a conformant receipt bound to the range, every entity verified")

    def omitted_head(r):
        r.pop("head_graph", None)
        r.pop("revision_selection", None)
    add("violation-HEAD_IMPACT_NOT_COVERED", "paused_safe", ["HEAD_IMPACT_NOT_COVERED"],
        "base-only receipt cannot skip binding new head obligations", omitted_head)

    def missing_verify(r):
        r.pop("verify", None)
    add("violation-HEAD_IMPACT_NOT_COVERED-missing-verifier-map", "paused_safe", ["HEAD_IMPACT_NOT_COVERED"],
        "complete entity lists cannot substitute the missing mandatory verifier map", missing_verify)

    def omitted_kind(r):
        for verdict in r["verdicts"]:
            verdict["verifier_ids"] = [v for v in verdict["verifier_ids"] if v != "v-fitness"]
    add("violation-HEAD_IMPACT_NOT_COVERED-missing-fitness-output", "paused_safe", ["HEAD_IMPACT_NOT_COVERED"],
        "actual fitness output exists but must be referenced by each verified entity", omitted_kind)

    def exempt(r):
        r["verdicts"][1] = {"entity": "code_unit:src/b.ts", "verdict": "not_measured",
                            "reason": "no verifier covers a generated file"}
        r["exemptions"] = [{"entity": "code_unit:src/b.ts", "reason": "generated file, covered by the generator's own receipt",
                            "owner": "AUP-E29 executor aup-graph", "expires_at_utc": "2026-12-05T00:00:00Z"}]
        r["admission"] = {"verdict": "admitted_with_exemptions",
                          "rule": "admitted_with_exemptions requires every non-verified entity to carry a valid exemption"}
    add("conformant-admit-with-exemptions", "admit", [],
        "one not_measured entity carried by an exemption with owner and expiry", exempt)

    # AUP-GRAPH-006:gate4b — C16. The gate re-measures every structural exemption it is shown; a
    # receipt that presents one bound to a DIFFERENT diff is refused, not merely ignored. This is
    # the change-bound expiry made testable: the fixture range is an ordinary edit, so the code
    # does not apply to it at all, and the binding digest is not this diff's digest either.
    def stale_structural(r):
        r["exemptions"] = [{"entity": "code_unit:src/b.ts", "code": "NO_IMPACT_BY_CONSTRUCTION",
                            "owner": "AUP-E29", "expires_at_utc": "2027-01-01T00:00:00Z",
                            "reason": "claims the impact set is empty by construction",
                            "change_binding": {"base": "0" * 40, "head": "0" * 40,
                                               "digest": "sha256:" + "0" * 64}}]
    add("violation-STRUCTURAL_EXEMPTION_UNSOUND", "refuse", ["STRUCTURAL_EXEMPTION_UNSOUND"],
        "a structural exemption bound to another diff is refused — the digest, not the clock, is the expiry",
        stale_structural)

    F["violation-RECEIPT_MISSING"] = {"receipt": None, "expect_verdict": "refuse",
                                      "expect_codes": ["RECEIPT_MISSING"], "extra": [],
                                      "description": "negative control: no receipt at all", "kwargs": {}}
    F["violation-RECEIPT_REPLACED_BY_CHECKBOX"] = {
        "receipt": None, "expect_verdict": "refuse",
        "expect_codes": ["RECEIPT_MISSING", "RECEIPT_REPLACED_BY_CHECKBOX"],
        "description": "the pull-request description claims «[x] graph-verified» and carries no receipt",
        "extra": [], "kwargs": {"description": "Refactor tasks module\n\n- [x] graph-verified\n"}}
    F["violation-MANUAL_BYPASS_REFUSED"] = {
        "receipt": None, "expect_verdict": "refuse",
        "expect_codes": ["MANUAL_BYPASS_REFUSED", "RECEIPT_MISSING"],
        "description": "a bypass flag refuses before any receipt lookup", "extra": [], "kwargs": {"bypass_flag": True}}
    F["violation-MANUAL_BYPASS_REFUSED-with-receipt"] = {
        "receipt": fresh_receipt(), "expect_verdict": "refuse",
        "expect_codes": ["MANUAL_BYPASS_REFUSED"],
        "description": "even a conformant receipt does not survive a bypass phrase in the description",
        "extra": [], "kwargs": {"description": "hotfix: skip-graph-verify, ship it"}}

    def stale(r):
        r["staleness"]["verdict"] = "stale"
        r["staleness"]["mismatched_nodes"] = ["code_unit:src/a.ts"]
    add("violation-RECEIPT_ON_STALE_GRAPH", "refuse", ["RECEIPT_MALFORMED", "RECEIPT_ON_STALE_GRAPH"],
        "the receipt was issued on a stale graph", stale)

    def not_checked(r):
        r["staleness"]["verdict"] = "not_checked"
    add("violation-STALENESS_NOT_CHECKED", "refuse", ["RECEIPT_MALFORMED", "RECEIPT_ON_STALE_GRAPH"],
        "freshness was never checked — the graph selected nothing that can be trusted", not_checked)

    def partial(r):
        r["change_set"]["files"] = r["change_set"]["files"][:1]
        r["verdicts"] = [v for v in r["verdicts"] if v["entity"] != "code_unit:src/c.ts"]
        if "revision_selection" in r:
            r["revision_selection"]["head"] = [e for e in r["revision_selection"]["head"] if e != "code_unit:src/c.ts"]
            r["verify"]["required_by_entity"].pop("code_unit:src/c.ts", None)
    add("violation-CHANGE_SET_INCOMPLETE", "refuse", ["CHANGE_SET_INCOMPLETE"],
        "the receipt describes one of the two changed files", partial)

    def other_range(r):
        r["change_set"]["head"] = "b" * 40
        r["change_set"]["base"] = "c" * 40
        r["graph"]["source_commit"] = "c" * 40
        r["tree"]["commit"] = "b" * 40
    add("violation-RECEIPT_NOT_BOUND_TO_RANGE", "refuse", ["RECEIPT_MISSING", "RECEIPT_NOT_BOUND_TO_RANGE"],
        "a receipt for another branch never admits this change: it is reported as not bound AND the change counts "
        "as receipt-less", other_range)

    other = base_receipt("c" * 40, "b" * 40)
    other["receipt_id"] = "car-fixture-other-branch"
    other["tree"]["commit"] = "b" * 40
    add("violation-RECEIPT_NOT_BOUND_TO_RANGE-extra", "refuse", ["RECEIPT_NOT_BOUND_TO_RANGE"],
        "a conformant receipt for this range plus a receipt named for another branch: pointing the gate at the "
        "wrong receipt is refused, never silently ignored", extra=[other])

    def failed(r):
        r["verdicts"][1] = {"entity": "code_unit:src/b.ts", "verdict": "failed",
                            "verifier_ids": ["v-tsc"], "reason": "tsc TS2345"}
        r["admission"] = {"verdict": "refused", "rule": "failed without an exemption ⇒ refused"}
    add("violation-VERDICT_FAILED", "refuse", ["ADMISSION_NOT_ADMITTED", "VERDICT_FAILED"],
        "a failed entity refuses the change", failed)

    def notm(r):
        r["verdicts"][1] = {"entity": "code_unit:src/b.ts", "verdict": "not_measured",
                            "reason": "no verifier covers this entity"}
        r["admission"] = {"verdict": "paused_safe", "rule": "not_measured without an exemption ⇒ paused_safe"}
    add("violation-NOT_MEASURED_WITHOUT_EXEMPTION", "paused_safe",
        ["ADMISSION_NOT_ADMITTED", "NOT_MEASURED_WITHOUT_EXEMPTION"],
        "not_measured is a third verdict: the change pauses, it is never admitted", notm)

    def expired(r):
        exempt(r)
        r["exemptions"][0]["expires_at_utc"] = "2026-08-01T00:00:00Z"
    add("violation-EXEMPTION_INADMISSIBLE-expired", "refuse",
        ["EXEMPTION_INADMISSIBLE", "NOT_MEASURED_WITHOUT_EXEMPTION", "RECEIPT_MALFORMED"],
        "an expired exemption does not carry a not_measured entity", expired)

    def no_owner(r):
        exempt(r)
        r["exemptions"][0]["owner"] = ""
    add("violation-EXEMPTION_INADMISSIBLE-owner", "refuse",
        ["EXEMPTION_INADMISSIBLE", "NOT_MEASURED_WITHOUT_EXEMPTION", "RECEIPT_MALFORMED"],
        "an exemption without an owner is inadmissible", no_owner)

    def two_valued(r):
        r["verdicts"][1] = {"entity": "code_unit:src/b.ts", "verdict": "pass", "verifier_ids": ["v-tsc"]}
    add("violation-RECEIPT_MALFORMED-two-valued", "refuse", ["RECEIPT_MALFORMED"],
        "a two-valued verdict (pass) is not a tri-valued verdict", two_valued)

    def boundary(r):
        r["impact_set"]["inferred_tail"] = [{"entity": "route:GET /api/v1/tasks", "depth": 2, "boundary": "service",
                                             "path": [{"from": "route:GET /api/v1/tasks", "to": "code_unit:src/a.ts",
                                                       "edge_type": "consumes_contract", "provenance": "inferred"}]}]
        r["verdicts"].append({"entity": "route:GET /api/v1/tasks", "verdict": "verified",
                              "verifier_ids": ["v-tsc"], "reason": "provider compiles"})
    add("violation-INFERRED_BOUNDARY_WITHOUT_CANARY", "refuse",
        ["HEAD_IMPACT_NOT_COVERED", "INFERRED_BOUNDARY_WITHOUT_CANARY", "RECEIPT_MALFORMED"],
        "an inferred edge across a service boundary needs a canary, never a bare verified", boundary)

    def empty_impact(r):
        r["impact_set"]["deterministic_core"] = []
        r["verdicts"] = [v for v in r["verdicts"] if v["entity"] != "code_unit:src/b.ts"]
    add("violation-EMPTY_IMPACT_WITHOUT_EXPLANATION", "refuse", ["RECEIPT_MALFORMED", "HEAD_IMPACT_NOT_COVERED"],
        "an empty impact set on a code change is a prediction that must be explained", empty_impact)

    def probe_contradicted(r):
        r["verifiers"].append({"id": "v-probe", "kind": "endpoint_probe",
                               "command": "scripts/probe-endpoints.sh --base-url http://127.0.0.1:3521",
                               "entities": ["code_unit:src/c.ts"], "exit_code": 0,
                               "output_ref": "verifier-out/probe.json"})
        r["observed"] = [
            {"probe": "health.serves", "verifier_id": "v-probe", "expected": "GET /health -> 200",
             "observed": "200 {\"status\":\"ok\"}", "verdict": "verified", "source": "probe run on the fixture contour"},
            {"probe": "tasks.create", "verifier_id": "v-probe",
             "expected": "POST /tasks with an agent key -> 201 with an id",
             "observed": "500 internal server error", "verdict": "failed",
             "detail": "the route answered 500 where 201 with an id was expected",
             "source": "probe run on the fixture contour"},
        ]
        for verdict in r["verdicts"]:
            if verdict["entity"] == "code_unit:src/c.ts":
                verdict["verifier_ids"].append("v-probe")
    add("violation-PROBE_CLAIM_CONTRADICTS_OBSERVATION", "refuse",
        ["PROBE_CLAIM_CONTRADICTS_OBSERVATION", "RECEIPT_MALFORMED", "VERDICT_FAILED"],
        "an entity claimed verified on an endpoint probe that was observed to fail: the gate counts the "
        "probe like any other verifier, so the entity is failed and the overstated claim is named",
        probe_contradicted)

    def no_wi(r):
        r["work_item"] = None
    add("violation-WORK_ITEM_EVIDENCE_MISSING", "paused_safe", ["WORK_ITEM_EVIDENCE_MISSING"],
        "a receipt that is attached to no Work Item pauses the change (evidence attachment, never a status)", no_wi,
        # The enforcement level is stated, not inherited (A2-238). The scratch repository this battery
        # runs against is caller-shaped, and a caller repository now defaults to `off` because the
        # evidence ledger lives in the program repository — so without this the fixture would quietly
        # measure the default instead of the check it exists for, and report `admit` as a pass.
        work_item_enforcement="ledger")

    return F


def cmd_make_fixtures(a) -> int:
    with tempfile.TemporaryDirectory(prefix="admit-fixture-generation-") as tmp:
        repo, base, head = scratch_repo(Path(tmp))
        F = make_fixtures(base, head, repo)
        F = json.loads(json.dumps(F).replace(base, "0" * 40).replace(head, "1" * 40))
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    written = []
    for name, spec in sorted(F.items()):
        doc = {"schema": "AdmissionGateFixture/v1", "name": name, "description": spec["description"],
               "expect": {"verdict": spec["expect_verdict"], "codes": sorted(spec["expect_codes"])},
               "gate_kwargs": spec["kwargs"],
               "extra_receipts": spec.get("extra") or [],
               "placeholders": {"base": "0" * 40, "head": "1" * 40,
                                "note": "the selftest rewrites both placeholders to the commits of a scratch "
                                        "repository so the git binding (C05/C06) is exercised for real"},
               "receipt": spec["receipt"]}
        p = FIXTURE_DIR / f"{name}.json"
        write_json(p, doc)
        written.append(p.name)
    readme = FIXTURE_DIR / "README.md"
    readme.write_text(
        "# Admission-gate fixtures (AUP-GRAPH-006 gate0)\n\n"
        "Each file is an `AdmissionGateFixture/v1`: a `receipt` (a ChangeAdmissionReceipt/v1 with the placeholder\n"
        "commits `000…0` = base and `111…1` = head, or `null` for the no-receipt controls), the `gate_kwargs` that\n"
        "describe how the change is presented to the gate (pull-request description, bypass flag), and the `expect`\n"
        "verdict + reason codes.\n\n"
        "`python3 tools/graph/admit_change.py --selftest` builds a scratch git repository (two commits, `src/a.ts`\n"
        "modified and `src/c.ts` added), rewrites the placeholders to its real commits, runs the gate for every\n"
        "fixture and compares verdict and codes; then it runs the mutation battery (each check disabled in turn —\n"
        "at least one fixture must stop being blocked, otherwise the check is unobservable and the mutant survives).\n\n"
        "Regenerate with `python3 tools/graph/admit_change.py --make-fixtures` (deterministic).\n",
        encoding="utf-8")
    print(json.dumps({"fixtures": len(written), "dir": str(FIXTURE_DIR.relative_to(PROGRAM_ROOT))}))
    return 0


# ------------------------------------------------------------------ selftest
def scratch_repo(root: Path) -> tuple[Path, str, str]:
    repo = root / "repo"
    repo.mkdir(parents=True)
    env = {"GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "f@x", "GIT_COMMITTER_NAME": "fixture",
           "GIT_COMMITTER_EMAIL": "f@x", "GIT_AUTHOR_DATE": "2026-09-05T00:00:00Z",
           "GIT_COMMITTER_DATE": "2026-09-05T00:00:00Z", "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "HOME": str(root)}
    def g(*args):
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env)
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)}: {r.stderr[:200]}")
        return r.stdout
    g("init", "-q", "-b", "main")
    (repo / "src").mkdir()
    (repo / "src/a.ts").write_text("export const a = 1;\n")
    (repo / "src/b.ts").write_text("import { a } from './a';\nexport const b = a + 1;\n")
    (repo / "src/contract.ts").write_text("export type Status = 'ready' | 'done';\n")
    (repo / "README.md").write_text("# fixture\n")
    g("add", "-A"); g("commit", "-q", "-m", "base")
    base = g("rev-parse", "HEAD").strip()
    (repo / "src/a.ts").write_text("export const a = 2;\n")
    (repo / "src/c.ts").write_text("export const c = 3;\n")
    g("add", "-A"); g("commit", "-q", "-m", "change")
    head = g("rev-parse", "HEAD").strip()
    return repo, base, head


def run_fixture(repo: Path, base: str, head: str, spec: dict, policy: dict, workdir: Path,
                disabled=frozenset(), ledger_dir: Path | None = None) -> dict:
    paths = []
    if spec["receipt"] is not None:
        doc = json.loads(json.dumps(spec["receipt"]).replace("0" * 40, base).replace("1" * 40, head))
        p = workdir / "receipt.json"
        write_json(p, doc)
        paths = [p]
    return gate(repo, base, head, paths, policy, disabled=disabled,
                ledger_dir=ledger_dir if ledger_dir is not None else (workdir / "ledger"),
                repo_name="Arcanada-one/fixture", **spec["kwargs"])


def selftest(receipt_out: Path | None, keep: bool = False) -> int:
    policy = load_policy(None)
    root = Path(tempfile.mkdtemp(prefix="admit-selftest-"))
    results, battery = [], []
    passed = failed = 0
    try:
        repo, base, head = scratch_repo(root)
        toolchain = prepare_gate_fixture_outputs(repo, base, head, compile_types=True)
        # The declared toolchain is a battery row of its own: a host without `tsc` is not_measured, and
        # not_measured is not a pass — but it is not a failure of the change either (A2-233).
        results.append({"case": "positive-fixture-compiles", "ok": None if toolchain["verdict"] == "not_measured"
                        else toolchain["verdict"] == "verified", "detail": [toolchain["reason"]]})
        if toolchain["verdict"] == "failed":
            failed += 1
        elif toolchain["verdict"] == "verified":
            passed += 1
        F = make_fixtures(base, head, repo)
        # fixtures on disk must match the generated ones (drift control)
        drift = []
        for name in F:
            p = FIXTURE_DIR / f"{name}.json"
            if not p.exists():
                drift.append(f"{name}: missing on disk")
                continue
            on_disk = json.loads(p.read_text(encoding="utf-8"))
            gen = json.loads(json.dumps(F[name]["receipt"]).replace(base, "0" * 40).replace(head, "1" * 40)) \
                if F[name]["receipt"] is not None else None
            gen_extra = json.loads(json.dumps(F[name].get("extra") or []).replace(base, "0" * 40).replace(head, "1" * 40))
            if canonical(on_disk.get("extra_receipts") or []) != canonical(gen_extra) or \
                    canonical(on_disk.get("receipt")) != canonical(gen) or \
                    on_disk["expect"]["verdict"] != F[name]["expect_verdict"] or \
                    on_disk["expect"]["codes"] != sorted(F[name]["expect_codes"]):
                drift.append(f"{name}: fixture on disk differs from the generator")
        results.append({"case": "fixture-drift", "ok": not drift, "detail": drift[:5]})
        passed, failed = (passed + 1, failed) if not drift else (passed, failed + 1)

        ledger_dir = root / "ledger"

        # 1. every fixture reaches its expected verdict and codes
        for name, spec in sorted(F.items()):
            wd = root / "wd" / name
            wd.mkdir(parents=True)
            # each fixture's receipt is re-written into wd; the ledger holds the attachment for the same bytes
            paths = []
            for i, ex in enumerate(spec.get("extra") or []):
                ep = wd / f"extra{i}.json"
                write_json(ep, json.loads(json.dumps(ex).replace("0" * 40, base).replace("1" * 40, head)))
                paths.append(ep)
            if spec["receipt"] is not None:
                doc = json.loads(json.dumps(spec["receipt"]).replace("0" * 40, base).replace("1" * 40, head))
                p = wd / "receipt.json"
                write_json(p, doc)
                paths = [p] + paths
                wi = work_item_id(doc.get("work_item"))
                if wi:
                    att = build_attachment(p, doc, wi, f"fixture {name}", None)
                    lp = ledger_path(ledger_dir, wi)
                    led = json.loads(lp.read_text(encoding="utf-8")) if lp.exists() else \
                        {"schema": "WorkItemEvidenceLedger/v1", "work_item": wi, "system": "muneral", "attachments": []}
                    led["attachments"].append(att)
                    write_json(lp, led)
            g = gate(repo, base, head, paths, policy, ledger_dir=ledger_dir,
                     repo_name="Arcanada-one/fixture", **spec["kwargs"])
            ok = g["verdict"] == spec["expect_verdict"] and g["reason_codes"] == sorted(spec["expect_codes"])
            results.append({"case": f"fixture:{name}", "ok": ok, "expect": spec["expect_verdict"],
                            "got": g["verdict"], "expect_codes": sorted(spec["expect_codes"]),
                            "got_codes": g["reason_codes"], "exit": g["exit_code"]})
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 2. determinism — the same input twice yields the same decision (timestamps excluded)
        def strip(d):
            return canonical({k: v for k, v in d.items() if k not in ("captured_at_utc", "gate_receipt_id")})
        wd = root / "wd" / "conformant-admit"
        g1 = gate(repo, base, head, [wd / "receipt.json"], policy, ledger_dir=ledger_dir, repo_name="Arcanada-one/fixture")
        g2 = gate(repo, base, head, [wd / "receipt.json"], policy, ledger_dir=ledger_dir, repo_name="Arcanada-one/fixture")
        ok = strip(g1) == strip(g2)
        results.append({"case": "determinism", "ok": ok})
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 3. environment bypass is refused too
        os.environ["AUP_SKIP_RECEIPT"] = "1"
        try:
            g3 = gate(repo, base, head, [wd / "receipt.json"], policy, ledger_dir=ledger_dir,
                      repo_name="Arcanada-one/fixture")
        finally:
            del os.environ["AUP_SKIP_RECEIPT"]
        ok = g3["verdict"] == "refuse" and "MANUAL_BYPASS_REFUSED" in g3["reason_codes"]
        results.append({"case": "env-bypass-refused", "ok": ok, "got": g3["verdict"], "codes": g3["reason_codes"]})
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 4. mutation battery — disabling a check must let at least one blocked fixture through
        battery = []
        for cid in CHECK_IDS:
            relaxed, silenced = [], []
            for name, spec in sorted(F.items()):
                if spec["expect_verdict"] == "admit":
                    continue
                wd2 = root / "wd" / name
                paths = [wd2 / "receipt.json"] + [wd2 / f"extra{i}.json" for i in range(len(spec.get("extra") or []))] \
                    if spec["receipt"] is not None else [wd2 / f"extra{i}.json" for i in range(len(spec.get("extra") or []))]
                gm = gate(repo, base, head, paths, policy, disabled=frozenset({cid}), ledger_dir=ledger_dir,
                          repo_name="Arcanada-one/fixture", **spec["kwargs"])
                if gm["reason_codes"] != sorted(spec["expect_codes"]):
                    silenced.append(name)
                if VERDICT_RANK[gm["verdict"]] < VERDICT_RANK[spec["expect_verdict"]]:
                    relaxed.append(name)
            killed = bool(silenced)
            battery.append({"check": cid, "code": {c["id"]: c["code"] for c in policy["checks"]}[cid],
                            "mutant_killed": killed, "fixtures_silenced": silenced[:6],
                            "fixtures_relaxed_to_a_weaker_verdict": relaxed[:6]})
            results.append({"case": f"mutant:{cid}", "ok": killed, "silenced": silenced[:6], "relaxed": relaxed[:6]})
            passed, failed = (passed + 1, failed) if killed else (passed, failed + 1)

        # 4b. the informational checks must in fact be informational (AUP-GRAPH-006:gate2a).
        # This is the property that exempts them from the disable battery, so it is asserted, not assumed.
        by_id = {c["id"]: c for c in policy["checks"]}
        for cid in INFORMATIONAL_CHECK_IDS:
            spec = by_id.get(cid)
            ok = bool(spec) and spec["verdict"] == "admit" and VERDICT_RANK[spec["verdict"]] == 0
            results.append({"case": f"informational:{cid}", "ok": ok,
                            "verdict": (spec or {}).get("verdict"), "code": (spec or {}).get("code"),
                            "rule": "an informational check never raises the gate verdict"})
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
        # and no check id may be in both lists
        overlap = sorted(set(CHECK_IDS) & set(INFORMATIONAL_CHECK_IDS))
        results.append({"case": "informational:disjoint", "ok": not overlap, "overlap": overlap})
        passed, failed = (passed + 1, failed) if not overlap else (passed, failed + 1)
        # every check in the policy is classified as one or the other
        unclassified = sorted({c["id"] for c in policy["checks"]} - set(CHECK_IDS) - set(INFORMATIONAL_CHECK_IDS))
        results.append({"case": "informational:policy-fully-classified", "ok": not unclassified,
                        "unclassified": unclassified})
        passed, failed = (passed + 1, failed) if not unclassified else (passed, failed + 1)

        # 5. charter-scan classification unit checks
        cls_cases = [
            ("/home/x/.claude/agents/developer.md", "- Write tests (TDD).", "mandate_default"),
            ("/home/x/.claude/agents/developer.md", "TDD is opt-in for client spaces", "opt_in_reference"),
            ("/home/x/ws/spaces/arcanada/space.yml", 'vendor_canary_marker: "tdd-discipline"', "meta_classifier_reference"),
            ("/home/x/ws/documentation/mandates/m.md", "TDD is mandatory for every change", "mandate_default"),
            ("/home/x/ws/datarim/reflection/x.md", "Iron Law: no production code without a failing test", "historical"),
            ("/home/x/ws/documentation/mandates/m.md", "verification_policy: tdd-required in space.yml", "opt_in_reference"),
        ]
        for path, line, want in cls_cases:
            got = classify_line(path, line, policy)
            ok = got == want
            results.append({"case": f"classify:{want}", "ok": ok, "got": got, "line": line[:60]})
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 6. the attachment is evidence-shaped and never a status
        p = wd / "receipt.json"
        doc = json.loads(p.read_text(encoding="utf-8"))
        att = build_attachment(p, doc, "AUP-GRAPH-006", "selftest", None)
        ok = (att["attachment_kind"] == "evidence" and att["evidence_ref"]["contentType"] == "application/json"
              and re.match(r"^sha256:[0-9a-f]{64}$", att["evidence_ref"]["digest"])
              and len(att["evidence_ref"]["uri"]) <= 512 and len(att["evidence_ref"]["label"]) <= 128
              and att["delivery"]["status"] == "not_measured"
              and "status" not in att and "transition" not in canonical(att).lower())
        results.append({"case": "attachment-shape", "ok": ok})
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 7. no status/transition route is reachable from this tool
        src = Path(__file__).read_text(encoding="utf-8")
        needles = ["/trans" + "itions", "/sta" + "tus", "method=" + "\"POST\""]
        ok = not any(n in src for n in needles)
        results.append({"case": "no-status-write-path", "ok": ok})
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)

    # A row whose `ok` is None was NOT MEASURED — a declared tool this host does not have. It is not a
    # failure (the exit code stays 0, so a missing compiler cannot read as a regression of the change)
    # and it is not a pass either, so it gets its own name in the verdict rather than disappearing
    # into PASS. DEC-AUP-0008: not_measured is the third verdict.
    not_measured = [r["case"] for r in results if r["ok"] is None]
    verdict = "FAIL" if failed else ("PASS_WITH_NOT_MEASURED" if not_measured else "PASS")
    doc = {
        "schema": "ReadinessReceipt/v1",
        "portion_id": "AUP-GRAPH-006:gate0",
        "captured_at_utc": now_iso(),
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "decision_ref": ["DEC-AUP-0008", "DEC-AUP-0015"],
        "checks": {"passed": passed, "failed": failed, "not_measured": len(not_measured),
                   "total": passed + failed + len(not_measured)},
        "toolchain": SELFTEST_TOOLCHAIN,
        "results": results,
        "battery": battery,
        "verdict": verdict,
    }
    if receipt_out:
        write_json(receipt_out, doc)
    print(json.dumps({"verdict": verdict, "passed": passed, "failed": failed,
                      "not_measured": len(not_measured)}, ensure_ascii=False))
    for r in results:
        if r["ok"] is None:
            print("  NOT_MEASURED " + canonical(r)[:300], file=sys.stderr)
        elif not r["ok"]:
            print("  FAIL " + canonical(r)[:300], file=sys.stderr)
    return 0 if failed == 0 else 1


# ------------------------------------------------------------------ cli
class UsageError(Exception):
    """Arguments the tool cannot work from, NAMED.

    Raised rather than reported on the spot because these commands are also used as a library
    (`ci_gate.py` calls `cmd_exempt` with a hand-built `Namespace` that has no parser on it): a
    helper that reached for the parser would trade one AttributeError for another. `main` turns it
    into argparse's own usage error — the subcommand's usage plus the message, exit code 2.
    """


def resolve_range(a) -> tuple[str, str]:
    """`--range <base>..<head>` or `--base` + `--head`, by ONE rule for every subcommand that takes one.

    A missing range is a usage error the caller must answer, never a range the tool picks for them:
    the gate binds a receipt to an EXACT range, so an inferred merge-base would admit a change
    against a base nobody named, and the receipt would say so in a field the caller never read.
    `verify.py` already keeps that contract for `--repo` + one of `--diff / --worktree / --files`;
    the two tools of DEC-AUP-0008 now answer a missing range the same way, with exit code 2.

    The revisions are resolved here too, so a ref that does not exist is named rather than thrown:
    every one of these was a traceback, and a traceback out of the admission gate is read by the
    caller as "no receipt" — the tool looks skipped when it in fact never got a chance to run.
    """
    if a.range:
        if ".." not in a.range:
            raise UsageError(f"--range must be <base>..<head>, got {a.range!r}")
        base, head = a.range.split("..", 1)
    else:
        base, head = a.base, a.head
    missing = [flag for flag, v in (("--base", base), ("--head", head)) if not v]
    if missing:
        raise UsageError(f"{' and '.join(missing)} missing — pass --range <base>..<head>, or --base and --head")
    try:
        return git(repo_of(a), "rev-parse", base).strip(), git(repo_of(a), "rev-parse", head).strip()
    except RuntimeError as e:
        raise UsageError(f"the range {base}..{head} does not resolve in {a.repo}: {e}") from e


def repo_of(a) -> Path:
    return Path(a.repo).resolve()


def cmd_gate(a) -> int:
    policy = load_policy(a.policy)
    repo = Path(a.repo).resolve()
    base, head = resolve_range(a)
    desc = a.description or ""
    if a.description_file:
        desc += "\n" + Path(a.description_file).read_text(encoding="utf-8")
    search = [Path(p) if Path(p).is_absolute() else repo / p for p in (a.receipt_dir or ["receipts"])]
    paths = [Path(p) for p in (a.receipt or [])] or discover_receipts(search)
    event = None
    if a.event_file:
        ep = Path(a.event_file)
        if ep.exists():
            try:
                event = json.loads(ep.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError as e:
                event = {"_unparsable": str(e)}
    doc = gate(repo, base, head, paths, policy, description=desc, bypass_flag=a.skip_receipt,
               work_item_enforcement=a.enforcement, explicit_receipts=bool(a.receipt),
               ledger_dir=Path(a.ledger_dir) if a.ledger_dir else LEDGER_DIR,
               repo_name=a.repo_name, event=event, verifier_job=a.verifier_job,
               verifier_conclusion=a.verifier_conclusion, verifier_output_ref=a.verifier_output_ref,
               automated_workdir=Path(a.workdir) if a.workdir else None,
               bundle_rel=getattr(a, "bundle_dir", None) or DEFAULT_BUNDLE_DIR,
               structural_workdir=(Path(a.workdir) / "gate4b") if a.workdir else None,
               base_branch=getattr(a, "base_branch", None))
    if a.out:
        write_json(Path(a.out), doc)
    if a.json:
        print(json.dumps(doc, ensure_ascii=False, indent=1))
    else:
        print(f"{doc['verdict'].upper()}  {doc['repo']['name']}  {base[:12]}..{head[:12]}  "
              f"files={len(doc['range']['files'])}  receipts={sum(1 for r in doc['receipts'] if r.get('bound'))}"
              f"  codes={','.join(doc['reason_codes']) or '-'}")
        for c in doc["checks"]:
            print(f"  [{c['verdict']}] {c['code']}: {c['detail']}")
    return doc["exit_code"]


def previous_self_receipts(repo: Path, rev: str, work_item: str) -> list[str]:
    """Every ChangeAdmissionReceipt/v1 under `receipts/graph/` at `rev` that declares `work_item`.

    Read out of the GIT OBJECT at `rev`, not off the working tree: a reissue is run with the new
    draft already written by a previous attempt, and the tree copy would then be the document the
    caller is about to replace rather than the one that is committed.
    """
    out = git_text_or_none(repo, "ls-tree", "-r", "--name-only", rev) or ""
    found = []
    for rel in out.splitlines():
        if not RECEIPT_ISSUE_RE.match(rel.strip()):
            continue
        rel = rel.strip()
        raw = git_text_or_none(repo, "show", f"{rev}:{rel}") or ""
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(doc, dict):
            continue
        if str(doc.get("schema", "")).startswith("ChangeAdmissionReceipt") and doc.get("work_item") == work_item:
            found.append(rel)
    return sorted(found)


def cmd_reissue(a) -> int:
    """A2-289 — re-issue a ChangeAdmissionReceipt AT THE PATH IT ALREADY OCCUPIES, in one commit.

    THE DANCE THIS REMOVES, measured on ARAS #212 (A2-278, commits c2126aa…466a4a9). The receipt is
    filed, then something forces another commit — a red `changelog` check, a rebase, a review fix —
    and the range the receipt names no longer describes the branch, so it must be re-issued. The
    agent re-ran verify.py, which timestamps its output path, and the new receipt landed BESIDE the
    old one. DEC-AUP-0035 supersedes the previous draft only AT THE SAME PATH (condition: «the
    document at the path this run writes to declares this run's work item»), so the old receipt was
    an ordinary receipt entity the matrix gives no verifier — an I14 `not_measured` — and the change
    became PAUSED_SAFE. The fix was two commits: one deleting the stale receipt, then the re-issue
    over the range that deletion created (87bf2a6, 466a4a9). Both measured in test_reissue.py.

    WHY NOT THE OTHER OPTION. A2-278 offered an alternative — document «changelog before receipt» in
    docs/graph-admission.md. That removes ONE TRIGGER, not the mechanism: the same pause is
    reproduced with no changelog anywhere in the fixture, by any second commit at all
    (`TheDanceItself.test_a_second_commit_alone_reproduces_it`). Ordering advice cannot be measured
    by anything, and a rebase does not read it. So the ordering note is worth writing and is NOT the
    answer to this defect.

    WHAT THIS COMMAND WILL NOT DO. It never picks between two candidate receipts and it never
    deletes one. Several receipts for one work item under `receipts/graph/` is the debt A2-278 left
    behind, and «the tool quietly chose the newest» is how a record of a different range gets
    overwritten. It names them and exits 2; `--supersede <path>` is the caller saying which.
    """
    repo = Path(a.repo).resolve()
    base, head = resolve_range(a)
    if a.supersede:
        dest = a.supersede
        why = "named by --supersede"
        if not git_ok(repo, "cat-file", "-e", f"{head}:{dest}"):
            raise UsageError(f"--supersede {dest} is not a file at {head[:12]} — a re-issue replaces a receipt "
                             f"that is COMMITTED; a path only in the working tree is a first issuance, and "
                             f"DEC-AUP-0035 has nothing at that path to supersede.")
    else:
        found = previous_self_receipts(repo, head, a.work_item)
        if not found:
            raise UsageError(
                f"no ChangeAdmissionReceipt/v1 under receipts/graph/ at {head[:12]} declares work item "
                f"{a.work_item}. Nothing to re-issue: this is a FIRST issuance — run verify.py --out "
                f"receipts/graph/<name>.json --work-item {a.work_item}. (A receipt filed without "
                f"--work-item cannot be found here, and cannot be superseded at its path either — "
                f"verify.py warns about that when it writes one.)")
        if len(found) > 1:
            raise UsageError(
                f"{len(found)} receipts under receipts/graph/ declare work item {a.work_item}: "
                f"{', '.join(found)}. A re-issue supersedes exactly ONE path and this command will not "
                f"guess which — the other copies are records of ranges that are no longer this branch's. "
                f"Name it with --supersede <path>, and delete the stale copies in that same commit.")
        dest = found[0]
        why = f"the only receipt at {head[:12]} declaring work item {a.work_item}"

    print(f"re-issuing at {dest}  ({why})", file=sys.stderr)
    if a.print_path:
        print(dest)
        return 0

    verify = Path(a.verify) if a.verify else (Path(__file__).resolve().parent / "verify.py")
    if not verify.exists():
        raise UsageError(f"no verify.py at {verify} — pass --verify <path>")
    argv = [sys.executable, str(verify), "--repo", str(repo), "--diff", f"{base}..{head}",
            "--graph", "auto", "--work-item", a.work_item, "--out", str(repo / dest), *(a.verify_args or [])]
    print("+ " + " ".join(argv), file=sys.stderr)
    return subprocess.run(argv).returncode


def cmd_exempt(a) -> int:
    """AUP-GRAPH-006:gate4b — the GATE issues a structural exemption into a receipt.

    Never hand-written: the codes are re-measured by the gate on every evaluation (C16), so an
    exemption written by hand that the battery does not confirm is refused, not merely ignored."""
    policy = load_policy(a.policy)
    repo = Path(a.repo).resolve()
    base, head = resolve_range(a)
    files = range_files(repo, base, head)
    rp = Path(a.receipt)
    doc = json.loads(rp.read_text(encoding="utf-8"))
    verdict_of = {v["entity"]: v.get("verdict") for v in (doc.get("verdicts") or [])
                  if isinstance(v, dict) and "entity" in v}
    wd = Path(a.workdir) if a.workdir else Path(tempfile.mkdtemp(prefix="gate4b-exempt-"))
    repo_name = a.repo_name or (doc.get("repo") or {}).get("name") or repo_remote_name(repo)
    second_opinion = None
    if getattr(a, "b7_second_opinion", None):
        second_opinion = json.loads(Path(a.b7_second_opinion).read_text(encoding="utf-8"))
    exemptions, ev = structural_exemption(repo, base, head, files, policy, repo_name=repo_name,
                                          base_branch=getattr(a, "base_branch", None),
                                          verifier_job=getattr(a, "verifier_job", None),
                                          verifier_conclusion=getattr(a, "verifier_conclusion", None),
                                          workdir=wd, bundle_rel=a.bundle_dir,
                                          verdict_entities=list(verdict_of), owner=a.owner,
                                          program_receipt=a.program_receipt,
                                          candidate_range=getattr(a, "b7_candidate_range", None),
                                          authority_id=getattr(a, "b7_authority_id", None),
                                          second_opinion=second_opinion)
    report = {"schema": "StructuralExemptionEvidence/v1", "producer": {"tool": TOOL, "version": VERSION},
              "model": MODEL, "provisional_until_fable_review": True,
              "decision_ref": "DEC-AUP-0008", "portion_id": "AUP-GRAPH-006:gate4b",
              "contract": "contracts/graph-verified-change/impact-uncomputable.v1.md",
              "repo": repo_name, "range": {"base": base, "head": head},
              "case": ev.get("case"), "eligible": bool(exemptions), "evidence": ev,
              "exemptions": exemptions}
    if a.evidence_out:
        write_json(Path(a.evidence_out), report)
    for c in ev.get("checks") or []:
        print(f"  [{c['verdict']}] {c['id']} {c['code']}: {c['detail']}")
    if not exemptions:
        print(f"NOT ELIGIBLE ({ev.get('case') or 'no structural case'}): the change stays paused_safe. "
              f"{ev.get('reason') or 'the evidence battery does not pass; make it pass or split the pull request'}")
        return 3
    synth = ev["synthesized_entity"]
    if synth not in verdict_of:
        doc.setdefault("verdicts", []).append({
            "entity": synth, "verdict": "not_measured",
            "reason": ("the impact of this change is not computable by the graph: "
                       + ("every path is a new file, so no node exists at change_set.base to seed the traversal "
                          "with, and the impact set is dependents (seeds excluded)"
                          if ev["case"] == "no_impact_by_construction" else
                          "this change is the vendored admission-gate bundle itself, whose tools are the code that "
                          "would do the measuring")
                       + f". Covered by the typed exemption {CODE_OF_CASE[ev['case']]}, whose evidence the gate "
                         f"re-measures on every evaluation (C16).")})
    keep = [x for x in (doc.get("exemptions") or [])
            if not (isinstance(x, dict) and x.get("code") in STRUCTURAL_CODES)]
    doc["exemptions"] = keep + exemptions
    verdict_of[synth] = "not_measured"
    exempted = {x["entity"] for x in doc["exemptions"]}
    left = sorted(e for e, v in verdict_of.items() if v != "verified" and e not in exempted)
    adm = ("refused" if any(verdict_of[e] == "failed" for e in left) else
           ("paused_safe" if left else "admitted_with_exemptions"))
    doc["admission"] = {"verdict": adm,
                        "rule": ("admitted_with_exemptions requires every non-verified entity to carry a valid "
                                 "exemption (owner + expiry). The structural exemption issued here covers only the "
                                 "entities its code may cover; anything else that is not verified still pauses or "
                                 "refuses this change on its own.")}
    doc.setdefault("notes", []).append(
        f"AUP-GRAPH-006:gate4b — {CODE_OF_CASE[ev['case']]} issued by `{TOOL} exempt` over "
        f"{len(exemptions)} entity(ies), bound to {ev['change_binding']['digest'][:23]}… "
        f"({base[:12]}..{head[:12]}); the digest, not the clock, is the expiry.")
    out = Path(a.out) if a.out else rp
    write_json(out, doc)
    print(f"{adm.upper()}  {CODE_OF_CASE[ev['case']]}  {len(exemptions)} exemption(s)  "
          f"binding {ev['change_binding']['digest'][:23]}…  → {out}")
    return 0 if adm == "admitted_with_exemptions" else 3


def cmd_b7_opine(a) -> int:
    """DEC-AUP-0020 rule 7 — the second, independent authority's OWN recomputation, never a copy of
    the primary's claim. Runs the full B7.1-B7.4 arm set itself, from git and from a scratch worktree
    it builds itself, and writes a `B7SecondOpinion/v1` that the primary's `exempt --b7-second-opinion`
    cross-checks (authority_id differs, digests bind the SAME diff, both classify the SAME op) rather
    than trusts. Never given its own second opinion here — that would recurse without bound; its own
    B7.5 SECOND_AUTHORITY arm is deliberately excluded from this command's verdict."""
    repo = Path(a.repo).resolve()
    base, head = resolve_range(a)
    files = range_files(repo, base, head)
    case, cev = structural_case(repo, base, head, files, a.bundle_dir)
    wd = Path(a.workdir) if a.workdir else Path(tempfile.mkdtemp(prefix="b7-opine-"))
    if case != "declaration_amend":
        doc = {"schema": "B7SecondOpinion/v1", "authority_id": a.authority_id, "base": base, "head": head,
               "verdict": "failed",
               "reason": f"the gate's own classification of this diff is {case or 'an ordinary change'}, not a "
                        f"declaration amendment — {cev.get('reason', '')}"}
        write_json(Path(a.out), doc)
        print(f"FAILED: not a declaration_amend diff ({case})")
        return 3
    ev = evaluate_declaration_amend(repo, base, head, files, wd, candidate_range=a.b7_candidate_range,
                                    authority_id=a.authority_id, second_opinion=None,
                                    verifier_job=a.verifier_job, verifier_conclusion=a.verifier_conclusion)
    relevant = [c for c in ev["checks"] if c["code"] != "SECOND_AUTHORITY"]
    verdict = ("verified" if relevant and all(c["verdict"] == "verified" for c in relevant) else
              ("failed" if any(c["verdict"] == "failed" for c in relevant) else "not_measured"))
    doc = {"schema": "B7SecondOpinion/v1", "authority_id": a.authority_id, "base": base, "head": head,
          "change_digest": ev.get("change_digest") or diff_digest(repo, base, head),
          "candidate_range": a.b7_candidate_range, "op": ev.get("op"), "grammar": ev.get("grammar"),
          "verdict": verdict, "checks": relevant}
    write_json(Path(a.out), doc)
    for c in relevant:
        print(f"  [{c['verdict']}] {c['id']} {c['code']}: {c['detail'][:200]}")
    print(f"{verdict.upper()} — second opinion by {a.authority_id!r} written to {a.out}")
    return 0 if verdict == "verified" else 3


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--make-fixtures", action="store_true")
    ap.add_argument("--receipt-out", type=Path, help="with --selftest: ReadinessReceipt/v1 path")
    ap.add_argument("--keep", action="store_true", help="with --selftest: keep the scratch repository")
    sub = ap.add_subparsers(dest="cmd")

    g = sub.add_parser("gate", help="admit / pause / refuse a change range")
    g.add_argument("--repo", required=True)
    g.add_argument("--range", help="<base>..<head>")
    g.add_argument("--base"), g.add_argument("--head")
    g.add_argument("--receipt", action="append", help="explicit ChangeAdmissionReceipt/v1 (repeatable)")
    g.add_argument("--receipt-dir", action="append", help="search directory (default receipts/)")
    g.add_argument("--description", default="", help="pull-request / commit description text")
    g.add_argument("--description-file")
    g.add_argument("--skip-receipt", action="store_true", help="bypass attempt — always refused (negative control)")
    g.add_argument("--enforcement", choices=["off", "ledger", "muneral"])
    g.add_argument("--ledger-dir")
    g.add_argument("--policy", type=Path)
    g.add_argument("--out")
    g.add_argument("--json", action="store_true")
    g.add_argument("--repo-name")
    g.add_argument("--event-file", help="the GitHub `pull_request` event payload (GITHUB_EVENT_PATH). The ONLY "
                                        "source of author identity for the automated-author path — never the branch name.")
    g.add_argument("--verifier-job", help="name of the repository's own test job, the verifier of a whole-repository "
                                          "(global fallback) impact")
    g.add_argument("--verifier-conclusion", help="that job's conclusion (success|failure|cancelled|timed_out|skipped); "
                                                 "anything else, or absent, is not_measured — never an assumed pass")
    g.add_argument("--verifier-output-ref", help="a URL or id the verdict can be traced to (the workflow run)")
    g.add_argument("--workdir", help="scratch directory for the graph build and an authored receipt")
    g.add_argument("--bundle-dir", default=DEFAULT_BUNDLE_DIR, help="the vendored gate bundle directory, for the gate4b self-update classification")
    g.add_argument("--base-branch", help="DEC-AUP-0051: the ref of the branch this change targets (origin/main). A bundle refresh whose branch was UPDATED from its base branch carries the base "
                                         "branch's own commits in its range; paths whose head blob is byte-identical to that branch's are not this change's paths. Default: refs/remotes/origin/HEAD, "
                                         "read from the clone — never a guessed branch name; unresolvable means not_measured, which pauses, never admits")

    g.set_defaults(fn=cmd_gate)

    ri = sub.add_parser("reissue", help="re-issue a ChangeAdmissionReceipt at the path it already occupies "
                                        "(DEC-AUP-0035 supersedes the previous draft only at the SAME path)")
    ri.add_argument("--repo", required=True)
    ri.add_argument("--range", help="<base>..<head>")
    ri.add_argument("--base"), ri.add_argument("--head")
    ri.add_argument("--work-item", required=True, help="the work item BOTH drafts declare — condition 3 of "
                                                       "DEC-AUP-0035 compares it, and a receipt filed without "
                                                       "one can never be superseded at its path")
    ri.add_argument("--supersede", help="the receipt path to replace, when more than one declares this work item")
    ri.add_argument("--print-path", action="store_true", help="resolve the destination and print it; run nothing")
    ri.add_argument("--verify", help="path to verify.py (default: beside this file)")
    ri.add_argument("verify_args", nargs="*", help="further arguments passed through to verify.py "
                                                    "(--tsc, --select, --canary, …); put them after `--`")
    ri.set_defaults(fn=cmd_reissue)

    ex = sub.add_parser("exempt", help="issue a structural exemption into a receipt (gate4b) — the gate, "
                                       "never the change author by hand")
    ex.add_argument("--repo", required=True)
    ex.add_argument("--range", help="<base>..<head>")
    ex.add_argument("--base"), ex.add_argument("--head")
    ex.add_argument("--receipt", required=True, help="the ChangeAdmissionReceipt/v1 to issue into")
    ex.add_argument("--out", help="write the amended receipt here (default: in place)")
    ex.add_argument("--evidence-out", help="write the StructuralExemptionEvidence/v1 report here")
    ex.add_argument("--bundle-dir", default=DEFAULT_BUNDLE_DIR)
    ex.add_argument("--base-branch", help="DEC-AUP-0051: the ref of the branch this change targets (origin/main). A bundle refresh whose branch was UPDATED from its base branch carries the base "
                                         "branch's own commits in its range; paths whose head blob is byte-identical to that branch's are not this change's paths. Default: refs/remotes/origin/HEAD, "
                                         "read from the clone — never a guessed branch name; unresolvable means not_measured, which pauses, never admits")

    ex.add_argument("--owner", help="the exemption owner (default: the gate itself)")
    ex.add_argument("--program-receipt", help="digest or path of the program-side ChangeAdmissionReceipt the "
                                              "bundle's program_ref was admitted with (B5, recorded not enforced)")
    ex.add_argument("--policy", type=Path)
    ex.add_argument("--repo-name")
    ex.add_argument("--workdir")
    # B6.6. The agent STATES what the caller's workflow will pass; CI RE-MEASURES it against the real
    # `needs.<job>.result` (C16 → recheck_structural), so a wrong claim here is caught where it matters.
    ex.add_argument("--verifier-job", help="B6.6: the caller job the declaration names (gate2a's workflow input)")
    ex.add_argument("--verifier-conclusion", help="B6.6: that job's conclusion on this head")
    # AUP-DEBT-002:B7 (DEC-AUP-0020) — a declaration_amend case reads these; every other case ignores them.
    ex.add_argument("--b7-candidate-range", help="B7 rule 4: <base>..<head> of the diff that MOTIVATES the "
                                                 "amendment, dry-run replayed — never merged with it")
    ex.add_argument("--b7-authority-id", help="B7 rule 7: this invocation's own authority identity")
    ex.add_argument("--b7-second-opinion", help="B7 rule 7: a B7SecondOpinion/v1 file from `b7-opine`, produced "
                                                "by a DIFFERENT authority-id")
    ex.set_defaults(fn=cmd_exempt)

    bo = sub.add_parser("b7-opine", help="DEC-AUP-0020 rule 7 — an independent authority's own recomputed "
                                         "verdict on a declaration amendment, for --b7-second-opinion")
    bo.add_argument("--repo", required=True)
    bo.add_argument("--range", help="<base>..<head> of the AMENDMENT (the declaration-only diff)")
    bo.add_argument("--base"), bo.add_argument("--head")
    bo.add_argument("--b7-candidate-range", help="same candidate range the primary authority will use")
    bo.add_argument("--authority-id", required=True)
    bo.add_argument("--verifier-job"), bo.add_argument("--verifier-conclusion")
    bo.add_argument("--bundle-dir", default=DEFAULT_BUNDLE_DIR)
    bo.add_argument("--workdir")
    bo.add_argument("--out", required=True)
    bo.set_defaults(fn=cmd_b7_opine)

    at = sub.add_parser("attach", help="attach a receipt to a Work Item as evidence (never a status)")
    at.add_argument("--receipt", required=True)
    at.add_argument("--work-item")
    at.add_argument("--muneral-task-id", help="the Muneral task uuid the evidence belongs to (receipts/muneral/*task-map*)")
    at.add_argument("--label")
    at.add_argument("--uri")
    at.add_argument("--ledger-dir")
    at.add_argument("--policy", type=Path)
    at.add_argument("--post", action="store_true", help="probe Muneral for a work-item evidence route and record it")
    at.set_defaults(fn=cmd_attach)

    cs = sub.add_parser("charter-scan", help="classify TDD / test-first hits across the live charter surfaces")
    cs.add_argument("--host")
    cs.add_argument("--policy", type=Path)
    cs.add_argument("--out")
    cs.set_defaults(fn=cmd_charter_scan)

    pc = sub.add_parser("pr-coverage", help="measure receipt coverage of the merges of a pilot repository")
    pc.add_argument("--repo", required=True)
    pc.add_argument("--since")
    pc.add_argument("--rev")
    pc.add_argument("--receipt-dir", action="append")
    pc.add_argument("--policy", type=Path)
    pc.add_argument("--out")
    pc.set_defaults(fn=cmd_pr_coverage)

    # Each subcommand carries its OWN parser, so a usage error prints that subcommand's usage and
    # exits 2 (argparse's own contract) instead of the caller reading a traceback as "no receipt".
    for sp in sub.choices.values():
        sp.set_defaults(parser=sp)

    a = ap.parse_args(argv)
    if a.selftest:
        return selftest(a.receipt_out, a.keep)
    if a.make_fixtures:
        return cmd_make_fixtures(a)
    if not a.cmd:
        ap.print_help()
        return 2
    try:
        return a.fn(a)
    except UsageError as e:
        (getattr(a, "parser", None) or ap).error(str(e))   # usage + message on stderr, exit 2


if __name__ == "__main__":
    sys.exit(main())
