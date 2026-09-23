#!/usr/bin/env python3
"""AUP-GRAPH-006 `gate1` — the admission gate as a CI check (`.github/workflows/graph-admission.yml`).

DEC-AUP-0007 makes CI a POST-HOC gate: the authoritative admission is the local
`tools/graph/admit_change.py gate` run by the agent that makes the change. This driver is what the
reusable workflow executes on a pull request:

  1. `bundle`  — vendor the gate tools of a pinned program-repo SHA into a caller repository
                 (`.github/graph-admission/`) with a `BUNDLE.json` manifest of per-file sha256.
                 The program repository is private: a caller's `GITHUB_TOKEN` cannot check it out,
                 and no shared PAT exists. Vendoring keeps the promise that matters — the gate runs
                 the code of ONE pinned program SHA, never `main` — without inventing a credential.
  2. `run`     — verify the bundle, classify the change, collect the receipts, run the gate, and
                 write the check text.

Verdict mapping (the job's own status IS the `graph-admission` check):
    admit                    → green
    doc-only change          → green, verdict `not_measured`, stated in the check text
    paused_safe / refuse     → red, with the typed reason codes of the gate receipt
    no receipt               → red (`RECEIPT_MISSING`)
    bundle tampered/mismatch → red (`BUNDLE_*`)

Receipt sources (both supported, both reported):
    a) files in the pull-request head tree matching `--receipt-glob` (default the caller's
       `receipts/graph/**` and `receipts/**/change-admission-*.json`);
    b) a fenced ```json block in the PR body whose `schema` starts with `ChangeAdmissionReceipt`.
    The PR body is read from a FILE (the workflow passes it through an environment variable and a
    file, never through a shell interpolation) — a PR body is attacker-controlled text.

stdlib only (Python 3.12), deterministic, no network.
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
from pathlib import Path

TOOL = "tools/graph/ci_gate.py"
VERSION = "1.0.0"
MODEL = "claude-opus-5"
PROGRAM_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_FILES = [
    "tools/graph/admit_change.py",
    "tools/graph/schema_check.py",
    "tools/graph/build_graph.py",
    # build_graph.py imports this at module scope to classify .github/workflows/* paths, so a bundle
    # without it is not merely reduced — the vendored builder raises ModuleNotFoundError on import
    # and the caller's gate cannot build a graph at all. Measured: the pre-1.0.1 builder carried no
    # such import, so the omission only became fatal when the import was added.
    "tools/graph/workflow_config.py",
    # AUP-GRAPH-006:gate2a — the automated-author path classifies changed paths and decides the global
    # fallback with the SAME code the local gate uses, so the classifier travels with the bundle.
    "tools/graph/impact.py",
    # The rest of admit_change.py's local imports. `impact_pair` is imported at module scope by
    # admit_change.py (and inside impact.py), so a bundle without it raises ModuleNotFoundError the
    # moment ci_gate imports admit_change — measured in muneral CI, where the gate died before
    # producing any verdict at all. `verify` and `contract_diff` are imported inside admit_change's
    # verification path: absent, they do not fail at import time, they fail when the gate reaches
    # the work they do, which is worse — a bundle that starts and then cannot finish.
    "tools/graph/impact_pair.py",
    "tools/graph/verify.py",
    "tools/graph/contract_diff.py",
    # verify.py's own chain: canary_evidence at module scope, process_observation from there.
    # Found by importing every bundled module from a directory that contains nothing else — a
    # static import scan missed it, and so did testing one entry point by hand.
    "tools/graph/canary_evidence.py",
    "tools/graph/process_observation.py",
    # AUP-GRAPH-006:gate2b — the SSHSIG/Ed25519 verifier. It must travel with the bundle: the gate
    # verifies the bundle's signature before trusting anything in it, and a verifier the caller does
    # not have is a verification that silently does not happen.
    "tools/graph/sshsig.py",
    "tools/graph/ci_gate.py",
    "contracts/graph-verified-change/admission-gate.v1.json",
    "contracts/graph-verified-change/relationship-graph.v1.json",
    "contracts/graph-verified-change/change-admission-receipt.v1.json",
    "contracts/graph-verified-change/verifier-matrix.v1.json",
]
DEFAULT_RECEIPT_GLOBS = ["receipts/graph/**/*.json", "receipts/**/change-admission-*.json"]

# AUP-GRAPH-006:gate2b — the bundle's cryptographic half.
SIGNATURE_NAME = "BUNDLE.json.sig"
PUBKEY_NAME = "SIGNING-KEY.pub"
SIGNING_NAMESPACE = "graph-admission-bundle"
PROGRAM_PUBKEY_PATH = "contracts/graph-verified-change/bundle-signing-key.pub"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sshsig  # noqa: E402  (sibling tool, stdlib-only, reused as a library)


def sha256_file(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout


# --------------------------------------------------------------------------------------- bundle
def cmd_bundle(a) -> int:
    out = Path(a.out).resolve()
    ref = a.program_ref or git(PROGRAM_ROOT, "rev-parse", "HEAD").strip()
    files = []
    if getattr(a, "workflow_out", None):
        # The reusable workflow itself, vendored next to the tools. A caller CAN call it across
        # repositories (`uses: Arcanada-one/arcanada-universal-program/.github/workflows/…@<sha>`)
        # when GitHub resolves that reference; a caller whose runs fail to start on the cross-repo
        # reference calls the vendored copy locally (`uses: ./.github/workflows/graph-admission.yml`)
        # — the same file, its sha256 recorded here against the same pinned program SHA.
        wf = Path(a.workflow_out)
        wf.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROGRAM_ROOT / ".github/workflows/graph-admission.yml", wf)
        files.append({"path": ".github/workflows/graph-admission.yml", "sha256": sha256_file(wf),
                      "vendored_to": str(wf.name), "verified_by_the_job": False,
                      "note": "the workflow file itself; it is already running by the time the job checks the bundle"})
    for rel in BUNDLE_FILES:
        src = PROGRAM_ROOT / rel
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        files.append({"path": rel, "sha256": sha256_file(src)})
    manifest = {
        "schema": "GraphAdmissionBundle/v1",
        "program_repo": "Arcanada-one/arcanada-universal-program",
        "program_ref": ref,
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "files": files,
        "rule": ("The workflow refuses unless every file's sha256 matches this manifest AND the caller's "
                 "`program_ref` input matches `program_ref` here. The bundle is a VENDORED copy of one pinned "
                 "program-repo SHA (the program repository is private and no shared credential exists to check it "
                 "out from a caller's CI). A pull request that changes anything under the bundle directory is "
                 "refused by the gate job — a bundle refresh is its own pull request."),
    }
    manifest["bundle_digest"] = "sha256:" + hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    mp = out / "BUNDLE.json"
    mp.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")

    # AUP-GRAPH-006:gate2b — sign BUNDLE.json. It carries every file's sha256, so a detached signature
    # over it binds the whole vendored set. The PRIVATE key never enters a repository (it lives outside
    # git on the signing host); the PUBLIC key travels with the bundle AND is committed in the program
    # repository, so the two copies can be compared by anyone who can read both.
    signed = None
    if getattr(a, "sign_key", None):
        key = Path(a.sign_key)
        sig = out / SIGNATURE_NAME
        produced = mp.with_suffix(mp.suffix + ".sig")
        # AUP-GRAPH-006:gate3a — `ssh-keygen -Y sign` PROMPTS «Overwrite (y/n)?» when its output file already
        # exists and, with no tty to answer it, exits **0** while leaving the OLD signature on disk. Refreshing a
        # bundle in place would therefore have shipped a stale signature over new bytes under a success exit code.
        # Measured on this host (OpenSSH 9.6p1), not inferred. Removing the target first is the fix; the post-sign
        # verification below is what caught it and stays.
        for stale in {produced, sig}:
            stale.unlink(missing_ok=True)
        r = subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", SIGNING_NAMESPACE,
                            "-O", "hashalg=sha512", str(mp)], capture_output=True, text=True)
        if r.returncode != 0 or not produced.exists():
            print(f"SIGNING FAILED: ssh-keygen exited {r.returncode}: {(r.stderr or r.stdout).strip()[:300]}",
                  file=sys.stderr)
            return 4
        if produced != sig:
            shutil.move(str(produced), str(sig))
        pub = key.with_suffix(".pub") if key.suffix != ".pub" else key
        shutil.copyfile(pub, out / PUBKEY_NAME)
        # the same public key is committed in the program repository, so a caller's copy is comparable
        (PROGRAM_ROOT / PROGRAM_PUBKEY_PATH).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pub, PROGRAM_ROOT / PROGRAM_PUBKEY_PATH)
        kt, aa = sshsig.parse_public_key((out / PUBKEY_NAME).read_text())
        fp = sshsig.fingerprint(kt, aa)
        ok, reason, _ = sshsig.verify_detached(mp.read_bytes(), sig.read_text(),
                                               (out / PUBKEY_NAME).read_text(), SIGNING_NAMESPACE)
        if not ok:
            print(f"SIGNING PRODUCED AN UNVERIFIABLE SIGNATURE: {reason}", file=sys.stderr)
            return 4
        signed = fp
    print(f"{out}: {len(files)} files, program_ref {ref[:12]}, bundle_digest {manifest['bundle_digest'][:23]}…"
          + (f", signed by {signed}" if signed else ", UNSIGNED"))
    return 0


def verify_bundle(tools: Path, program_ref: str | None,
                  key_fingerprint: str | None = None) -> tuple[dict | None, list[str], dict]:
    """→ (manifest, problems, signature record). A problem is a typed one-line reason for the check text.

    AUP-GRAPH-006:gate2b. The SIGNATURE is checked BEFORE anything in BUNDLE.json is believed: the
    per-file sha256 map is only as trustworthy as the file that carries it, and a pull request that
    rewrites a tool AND its manifest entry keeps that map perfectly consistent (mutant (j) of gate1 —
    caught there by a diff-shape rule, `BUNDLE_MODIFIED_BY_PR`, never by verification). Here the
    manifest must additionally verify against an Ed25519 key the program repository holds.
    """
    sigrec = {"required": True, "namespace": SIGNING_NAMESPACE, "verified": False,
              "key_fingerprint": None, "pinned_fingerprint": key_fingerprint or None,
              "fingerprint_pinned": bool(key_fingerprint), "reason": None}
    mp = tools / "BUNDLE.json"
    if not mp.exists():
        return None, [f"BUNDLE_MISSING: no {mp.name} under {tools}"], sigrec
    sp, kp = tools / SIGNATURE_NAME, tools / PUBKEY_NAME
    if not sp.exists() or not kp.exists():
        missing = ", ".join(n for n, e in ((SIGNATURE_NAME, sp.exists()), (PUBKEY_NAME, kp.exists())) if not e)
        sigrec["reason"] = f"missing {missing}"
        return None, [f"BUNDLE_SIGNATURE_MISSING: {missing} is absent under {tools} — an unsigned bundle is "
                      f"refused, never trusted on its own hashes (a manifest signs nothing for itself)"], sigrec
    ok, reason, det = sshsig.verify_detached(mp.read_bytes(), sp.read_text(), kp.read_text(), SIGNING_NAMESPACE)
    sigrec.update({"verified": ok, "reason": reason, "key_fingerprint": det.get("public_key_fingerprint"),
                   "hash_algorithm": det.get("hash_algorithm"), "key_type": det.get("key_type")})
    if not ok:
        return None, [f"BUNDLE_SIGNATURE_INVALID: {reason}"], sigrec
    if key_fingerprint:
        if det.get("public_key_fingerprint") != key_fingerprint:
            return None, [f"BUNDLE_SIGNATURE_UNTRUSTED_KEY: the bundle is signed by "
                          f"{det.get('public_key_fingerprint')} but the caller pins {key_fingerprint} — a "
                          f"valid signature by an unpinned key is not a trusted signature"], sigrec
    try:
        man = json.loads(mp.read_text())
    except json.JSONDecodeError as e:
        return None, [f"BUNDLE_MALFORMED: {e}"], sigrec
    problems = []
    for f in man.get("files", []):
        if f.get("verified_by_the_job") is False:
            continue
        p = tools / f["path"]
        if not p.exists():
            problems.append(f"BUNDLE_FILE_MISSING: {f['path']}")
        elif sha256_file(p) != f["sha256"]:
            problems.append(f"BUNDLE_DIGEST_MISMATCH: {f['path']} is not the file of program_ref "
                            f"{str(man.get('program_ref'))[:12]}")
    if program_ref and man.get("program_ref") != program_ref:
        problems.append(f"BUNDLE_REF_MISMATCH: caller pinned program_ref {program_ref[:12]}, "
                        f"bundle carries {str(man.get('program_ref'))[:12]}")
    return man, problems, sigrec


# --------------------------------------------------------------------------------------- run
def changed_files(repo: Path, base: str, head: str) -> list[str]:
    out = git(repo, "diff", "--name-only", f"{base}..{head}")
    return [l for l in out.splitlines() if l]


def is_doc_only(paths: list[str], globs: list[str]) -> bool:
    return bool(paths) and all(any(fnmatch.fnmatch(p, g) for g in globs) for p in paths)


def receipts_from_body(body: str, workdir: Path) -> list[Path]:
    out = []
    for i, m in enumerate(re.finditer(r"```(?:json)?\s*\n(.*?)```", body, re.S)):
        try:
            doc = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict) and str(doc.get("schema", "")).startswith("ChangeAdmissionReceipt"):
            p = workdir / f"pr-body-receipt-{i}.json"
            p.write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
            out.append(p)
    return out


def receipts_from_tree(repo: Path, globs: list[str], changed: set[str] | None = None,
                       base: str | None = None) -> list[Path]:
    """Receipts this CHANGE carries, not every receipt the repository has ever accumulated.

    A receipt that already existed at `base` and is untouched by `base..head` was merged by an
    EARLIER change. Its range can never be a subrange of this one, so judging it can only ever
    produce RECEIPT_NOT_BOUND_TO_RANGE — a permanent refusal of every later pull request in the
    repository. Observed in muneral: one merged node-pin receipt held #79, #81 and #83 red at once
    while each carried a correct receipt of its own.

    The exclusion is deliberately narrow: a receipt is dropped only when git can PROVE it is a
    merged artefact — present at base AND absent from the diff. Anything else is judged, including
    a receipt sitting in the working tree that was never committed. That matters beyond the
    fixtures: `--receipt-glob` output and locally staged receipts must still reach the gate.

    This narrows DISCOVERY only; it does not soften the check. A receipt the change adds or modifies
    is still judged, so "pointing the gate at the wrong receipt is refused, never silently ignored"
    (mutation arm violation-RECEIPT_NOT_BOUND_TO_RANGE-extra) still holds — that arm hands the gate
    its extra receipt as an explicit --receipt path and never reaches this function.
    """
    at_base: set[str] = set()
    if base is not None and changed is not None:
        try:
            listing = git(repo, "ls-tree", "-r", "--name-only", base)
            at_base = {ln for ln in listing.splitlines() if ln}
        except Exception:
            # cannot prove anything is merged → judge everything, the pre-existing behaviour
            at_base = set()
    out, seen = [], set()
    for g in globs:
        for p in sorted(repo.glob(g)):
            if not p.is_file():
                continue
            rel = str(p.relative_to(repo))
            # the default globs overlap, so the same receipt was collected — and reported — twice
            if rel in seen:
                continue
            if changed is not None and rel in at_base and rel not in changed:
                continue  # merged by an earlier change, and this one does not touch it
            try:
                doc = json.loads(p.read_text())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(doc, dict) and str(doc.get("schema", "")).startswith("ChangeAdmissionReceipt"):
                seen.add(rel)
                out.append(p)
    return out

def cmd_run(a) -> int:
    repo = Path(a.repo).resolve()
    tools = Path(a.tools).resolve()
    work = Path(a.workdir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    base = git(repo, "rev-parse", a.base).strip()
    head = git(repo, "rev-parse", a.head).strip()
    result = {
        "schema": "GraphAdmissionCiResult/v1",
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "decision_refs": ["DEC-AUP-0008", "DEC-AUP-0007"],
        "repo": a.repo_name or repo.name,
        "range": {"base": base, "head": head},
        "receipt_sources": {"tree": [], "pr_body": []},
        "checks": [],
        "verdict": None,
        "conclusion": None,
        "reason_codes": [],
    }

    def fail(code: str, detail: str) -> int:
        result["verdict"] = "refused"
        result["conclusion"] = "failure"
        result["reason_codes"] = sorted(set(result["reason_codes"] + [code]))
        result["checks"].append({"code": code, "detail": detail, "verdict": "refuse"})
        return finish(1)

    def finish(rc: int) -> int:
        Path(a.out).write_text(json.dumps(result, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
        lines = [f"### graph-admission — {result['verdict']} ({result['conclusion']})",
                 "",
                 f"- repository `{result['repo']}`, range `{base[:12]}..{head[:12]}`, "
                 f"{len(result['range'].get('files', []))} changed file(s)",
                 f"- receipts: {len(result['receipt_sources']['tree'])} from the head tree, "
                 f"{len(result['receipt_sources']['pr_body'])} from the pull-request body",
                 f"- reason codes: {', '.join(result['reason_codes']) or '—'}",
                 ""]
        for c in result["checks"]:
            lines.append(f"- **{c['verdict']}** `{c['code']}` — {c['detail']}")
        lines += ["", "Rule (DEC-AUP-0008, AUP-GRAPH-006): «нет receipt — нет мержа». `not_measured` is a third "
                      "verdict, never read as pass. CI is a POST-HOC gate (DEC-AUP-0007): the authoritative "
                      "admission is the local `tools/graph/admit_change.py gate` run of the agent that made the change."]
        text = "\n".join(lines) + "\n"
        if a.summary:
            Path(a.summary).write_text(text)
        print(text)
        return rc

    man, problems, sigrec = verify_bundle(tools, a.program_ref, getattr(a, "signing_key_fingerprint", None))
    result["bundle"] = {"path": str(tools.relative_to(repo)) if tools.is_relative_to(repo) else str(tools),
                        "program_ref": (man or {}).get("program_ref"),
                        "bundle_digest": (man or {}).get("bundle_digest"), "problems": problems,
                        "signature": sigrec}
    if problems:
        return fail(problems[0].split(":")[0], "; ".join(problems))
    if sigrec.get("fingerprint_pinned"):
        result["checks"].append({"code": "BUNDLE_SIGNATURE_VERIFIED", "verdict": "verified",
                                 "detail": (f"BUNDLE.json carries a valid Ed25519 SSHSIG detached signature in "
                                            f"namespace {SIGNING_NAMESPACE!r} by {sigrec['key_fingerprint']}, "
                                            f"which is the key this caller pins. Every per-file sha256 below is "
                                            f"therefore signed, not merely self-consistent.")})
    else:
        result["checks"].append({"code": "BUNDLE_SIGNATURE_UNPINNED", "verdict": "not_measured",
                                 "detail": (f"the signature is valid for the key SHIPPED IN THE BUNDLE "
                                            f"({sigrec['key_fingerprint']}), but this caller pins no expected "
                                            f"fingerprint, so what is proven is self-consistency, not provenance: "
                                            f"anyone who can replace both the signature and {PUBKEY_NAME} in the "
                                            f"same change satisfies it. Pass `signing_key_fingerprint` from the "
                                            f"caller's own workflow file to turn this into a provenance claim. "
                                            f"`not_measured` is not a pass (DEC-AUP-0008 I4).")})

    files = changed_files(repo, base, head)
    result["range"]["files"] = files
    bundle_rel = str(tools.relative_to(repo)) if tools.is_relative_to(repo) else None
    if bundle_rel:
        prefix = bundle_rel.rstrip("/") + "/"
        status = {}
        for line in git(repo, "diff", "--name-status", f"{base}..{head}").splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                status[parts[-1]] = parts[0][0]
        touched = {f: status.get(f, "?") for f in files if f.startswith(prefix)}
        edited = {f: st for f, st in touched.items() if st != "A"}
        if edited:
            # An EDIT or a DELETE of a vendored tool is the tamper path — refused. A pure ADDITION is
            # the installing pull request itself (the bundle cannot pre-exist its own installation);
            # it is recorded, and the sha256 check above still binds every added file to BUNDLE.json.
            #
            # AUP-GRAPH-006:gate4b — with ONE typed exception: a bundle REFRESH, whose changed set is
            # exactly the bundle-managed paths and nothing else. That is the gate updating itself, and
            # it was the only change in this repository that «нет receipt — нет мержа» could not admit
            # (measured: muneral #69 and #70, both merged with an admin override of the required check).
            # It is not waved through here — it is handed to the gate, which must find a receipt
            # carrying a GATE_SELF_UPDATE exemption whose B1-B5 battery the gate itself re-measures.
            import admit_change as admit_mod  # sibling tool, reused as a library (bundled)
            files_status = [{"path": f, "status": status.get(f, "M")} for f in files]
            su_case, su_ev = admit_mod.structural_case(repo, base, head, files_status, bundle_rel)
            if su_case != "gate_self_update":
                return fail("BUNDLE_MODIFIED_BY_PR",
                            f"this pull request edits or removes {len(edited)} file(s) under the vendored gate bundle "
                            f"({', '.join(sorted(edited)[:3])}) — a bundle refresh is its own pull request, gated on its own"
                            + (f"; and it is not one: {su_ev.get('reason') or 'the changed set is not exactly the '
                               'bundle-managed paths'}" if su_ev.get("outside_the_bundle") or su_ev.get("reason") else ""))
            result["self_update"] = su_ev
            result["checks"].append({"code": "SELF_UPDATE_CANDIDATE", "verdict": "not_measured",
                                     "detail": (f"this pull request refreshes the vendored gate bundle itself "
                                                f"(program_ref {str((su_ev.get('program_ref') or {}).get('base'))[:12]} → "
                                                f"{str((su_ev.get('program_ref') or {}).get('head'))[:12]}) and changes "
                                                f"NOTHING else. BUNDLE_MODIFIED_BY_PR is therefore not the answer, and "
                                                f"neither is a pass: the gate below must find a receipt carrying a "
                                                f"GATE_SELF_UPDATE exemption, and it re-measures that exemption's whole "
                                                f"battery — signature continuity against the key of the BASE tree, the "
                                                f"head bundle's own selftest, and check-id/arm monotonicity. "
                                                f"`not_measured` is not a pass (DEC-AUP-0008 I4).")})
        if touched and not result.get("self_update"):
            # …and NOT on the self-update path: there the bundle is REFRESHED, not installed, and
            # saying «ADDS the vendored gate bundle» about a diff of six modified files is a check text
            # that misdescribes what it measured. Caught by replaying the real muneral refresh locally.
            result["checks"].append({"code": "BUNDLE_INSTALLED_BY_PR", "verdict": "not_measured",
                                     "detail": f"this pull request ADDS the vendored gate bundle "
                                               f"({len(touched)} new file(s)); every added file matches BUNDLE.json and "
                                               f"the pinned program_ref, but a bundle installed by the very change it "
                                               f"gates is a tripwire, not a proof — CI is post-hoc (DEC-AUP-0007)."})

    policy = json.loads((tools / "contracts/graph-verified-change/admission-gate.v1.json").read_text())
    doc_globs = ((policy.get("ci_gate") or {}).get("doc_only_globs")) or []
    result["doc_only_globs"] = doc_globs
    if is_doc_only(files, doc_globs):
        result["verdict"] = "not_measured"
        result["conclusion"] = "success"
        result["reason_codes"] = ["DOC_ONLY_NOT_MEASURED"]
        result["checks"].append({"code": "DOC_ONLY_NOT_MEASURED", "verdict": "not_measured",
                                 "detail": f"every one of the {len(files)} changed path(s) matches the policy's "
                                           f"doc_only_globs — the gate measured NOTHING about code here. "
                                           f"`not_measured` is not a pass: it says no code entity was affected, so "
                                           f"no verifier was selected (DEC-AUP-0008 I4)."})
        return finish(0)

    body = ""
    if a.pr_body_file and Path(a.pr_body_file).exists():
        body = Path(a.pr_body_file).read_text(errors="replace")
    body_receipts = receipts_from_body(body, work)
    tree_receipts = receipts_from_tree(repo, a.receipt_glob or DEFAULT_RECEIPT_GLOBS, changed=set(files), base=base)
    result["receipt_sources"]["tree"] = [str(p.relative_to(repo)) for p in tree_receipts]
    result["receipt_sources"]["pr_body"] = [p.name for p in body_receipts]
    receipts = tree_receipts + body_receipts
    cmd = [sys.executable, str(tools / "tools/graph/admit_change.py"), "gate", "--repo", str(repo),
           "--range", f"{base}..{head}", "--json", "--out", str(work / "gate.json"),
           "--enforcement", a.enforcement, "--workdir", str(work / "gate2a"),
           "--repo-name", result["repo"]]
    if bundle_rel:
        cmd += ["--bundle-dir", bundle_rel]
    # AUP-GRAPH-006:gate2a — the automated-author path. The event payload is the ONLY source of author
    # identity; the head branch name is attacker-controllable and is never consulted.
    if getattr(a, "event_file", None) and Path(a.event_file).exists():
        cmd += ["--event-file", a.event_file]
        result["automated_author_inputs"] = {
            "event_file": a.event_file,
            "verifier_job": getattr(a, "verifier_job", None) or None,
            "verifier_conclusion": getattr(a, "verifier_conclusion", None) or None,
        }
    for flag, val in (("--verifier-job", getattr(a, "verifier_job", None)),
                      ("--verifier-conclusion", getattr(a, "verifier_conclusion", None)),
                      ("--verifier-output-ref", getattr(a, "verifier_output_ref", None))):
        if val:
            cmd += [flag, val]
    if receipts:
        for p in receipts:
            cmd += ["--receipt", str(p)]
    else:
        # no receipt was found in either source — the GATE still runs, so that it, and not this driver,
        # types the reason (C03 RECEIPT_MISSING, or C02 RECEIPT_REPLACED_BY_CHECKBOX when the description
        # claims verification instead). Its search directory is an empty one: nothing unrelated is picked up.
        empty = work / "no-receipts"
        empty.mkdir(exist_ok=True)
        cmd += ["--receipt-dir", str(empty)]
        # NOTE: `refuse` here is the DRIVER's finding about the two human-facing sources. The gate may
        # still author a receipt itself on the automated-author path (AUP-GRAPH-006:gate2a); when it does,
        # this entry is downgraded below, after the gate has spoken, so a driver-level note can never
        # outvote the gate's own verdict.
        result["checks"].append({"code": "RECEIPT_SOURCES_EMPTY", "verdict": "refuse",
                                 "detail": "no ChangeAdmissionReceipt/v1 in the head tree "
                                           f"({', '.join(a.receipt_glob or DEFAULT_RECEIPT_GLOBS)}) and none as a "
                                           "```json block in the pull-request body. «Нет receipt — нет мержа»."})
    if a.pr_body_file and Path(a.pr_body_file).exists():
        cmd += ["--description-file", a.pr_body_file]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    try:
        gate_doc = json.loads((work / "gate.json").read_text())
    except (OSError, json.JSONDecodeError):
        return fail("GATE_TOOL_FAILED", f"admit_change.py gate exited {proc.returncode}: "
                                        f"{(proc.stderr or proc.stdout).strip()[:400]}")
    result["gate"] = {"gate_receipt_id": gate_doc.get("gate_receipt_id"), "verdict": gate_doc.get("verdict"),
                      "exit_code": gate_doc.get("exit_code"), "reason_codes": gate_doc.get("reason_codes"),
                      "receipts": gate_doc.get("receipts"), "policy": gate_doc.get("policy")}
    result["automated_author"] = gate_doc.get("automated_author")
    result["checks"] += [{"code": c["code"], "verdict": c["verdict"], "detail": c["detail"]} for c in gate_doc["checks"]]
    result["reason_codes"] = sorted(set(result["reason_codes"] + list(gate_doc.get("reason_codes") or [])))

    # the caller repository's own graph, built here from the pinned bundle, cross-checked against the receipt
    if a.build_graph:
        bound = [r for r in gate_doc.get("receipts", []) if r.get("bound")]
        # …including a receipt the gate AUTHORED itself on the automated-author path: it is not one of
        # the driver's two sources, but it is a receipt like any other and is rebuilt against like one.
        pool = list(map(str, receipts))
        au_path = (gate_doc.get("automated_author") or {}).get("receipt_path")
        if au_path:
            pool.append(au_path)
        for rec in bound:
            src = next((json.loads(Path(p).read_text()) for p in pool
                        if Path(p).exists() and Path(p).name == Path(rec["path"]).name), None)
            g = (src or {}).get("graph") or {}
            if not g.get("source_commit") or not g.get("graph_digest"):
                result["checks"].append({"code": "GRAPH_NOT_REBUILT", "verdict": "not_measured",
                                         "detail": f"{Path(rec['path']).name}: the receipt names no graph "
                                                   "source_commit/digest to rebuild against"})
                continue
            gp = work / f"graph-{g['source_commit'][:12]}.json"
            b = subprocess.run([sys.executable, str(tools / "tools/graph/build_graph.py"), str(repo),
                                "--rev", g["source_commit"], "--out", str(gp)], capture_output=True, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            if b.returncode != 0:
                result["checks"].append({"code": "GRAPH_BUILD_FAILED", "verdict": "not_measured",
                                         "detail": (b.stderr or b.stdout).strip()[:300]})
                continue
            built = json.loads(gp.read_text())["manifest"]["graph_digest"]
            same = built == g["graph_digest"]
            result["checks"].append({"code": "GRAPH_REBUILT_MATCHES" if same else "GRAPH_DIGEST_MISMATCH",
                                     "verdict": "verified" if same else "refuse",
                                     "detail": (f"{Path(rec['path']).name}: graph rebuilt here at "
                                                f"{g['source_commit'][:12]} → {built[:23]}… "
                                                + ("equals the digest the receipt was produced against"
                                                   if same else f"but the receipt claims {g['graph_digest'][:23]}…"))})
            if not same:
                result["reason_codes"] = sorted(set(result["reason_codes"] + ["GRAPH_DIGEST_MISMATCH"]))

    if (gate_doc.get("automated_author") or {}).get("eligible"):
        for c in result["checks"]:
            if c["code"] == "RECEIPT_SOURCES_EMPTY":
                c["verdict"] = "not_measured"
                c["detail"] += (" — the gate then AUTHORED one itself on the automated-author path "
                                f"({(gate_doc['automated_author'].get('author_match') or {}).get('author', {}).get('login')}), "
                                "and that receipt was checked exactly like any other.")
    hard = [c for c in result["checks"] if c["verdict"] == "refuse"]
    gv = gate_doc.get("verdict")
    result["verdict"] = {"admit": "admitted", "paused_safe": "paused", "refuse": "refused"}.get(gv, gv)
    if hard and result["verdict"] == "admitted":
        result["verdict"] = "refused"
    # The gate's receipt rows carry `entity_counts.exempted` and `admission`, never an `exemptions` key:
    # keying on `r["exemptions"]` (gate1) made `admitted_with_exemptions` unreachable in CI. Read the
    # fields the gate actually emits.
    exempt = any((r.get("entity_counts") or {}).get("exempted") or r.get("admission") == "admitted_with_exemptions"
                 for r in gate_doc.get("receipts", []) if r.get("bound"))
    if result["verdict"] == "admitted" and exempt:
        result["verdict"] = "admitted_with_exemptions"
    result["conclusion"] = "success" if result["verdict"].startswith("admitted") else "failure"
    return finish(0 if result["conclusion"] == "success" else 1)


# --------------------------------------------------------------------------------------- selftest
def selftest() -> int:
    """The mutation battery of the CI job: every mutant must FLIP the verdict of the conformant control.

    Reuses the admission fixtures of `tools/graph/admit_change.py` (scratch git repository + the
    ChangeAdmissionReceipt/v1 fixture set), so the battery exercises the real gate, not a mock."""
    import tempfile
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import admit_change  # noqa: E402

    root = Path(tempfile.mkdtemp(prefix="ci-gate-selftest-"))
    checks, red = [], 0

    def check(name, ok, **kw):
        nonlocal red
        checks.append({"name": name, "ok": bool(ok), **kw})
        if not ok:
            red += 1
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + json.dumps(kw, ensure_ascii=False)[:300]))

    repo, base, head = admit_change.scratch_repo(root)
    # Without `repo`, make_fixtures cannot bind head_graph/revision_selection, and every receipt
    # it builds is a base-only receipt — which the paired coverage check refuses by design
    # (HEAD_IMPACT_NOT_COVERED). The conformant CONTROL was therefore unpassable, and each mutant
    # that could not flip an already-red control was scored a failure too.
    F = admit_change.make_fixtures(base, head, repo)
    bundle = root / "bundle"
    cmd_bundle(argparse.Namespace(out=str(bundle), program_ref="0" * 40, workflow_out=None, sign_key=None))
    sign_bundle(bundle)  # gate2b: an unsigned bundle is refused, so every fixture bundle is signed
    (repo / ".github").mkdir(exist_ok=True)
    shutil.copytree(bundle, repo / ".github/graph-admission")
    rdir = repo / "receipts/graph"
    rdir.mkdir(parents=True, exist_ok=True)
    # The bundle and the receipt directory are dropped into the WORKING TREE, which leaves it dirty.
    # The dual-graph coverage measurement refuses a dirty tree outright (STALE_GRAPH, --diff mode),
    # and that refusal surfaced only as a bare "Refusal", so every arm depending on the conformant
    # control read as a failure of the CONTROL rather than of the fixture that set it up.
    # Excluding them locally keeps the tree clean without touching base..head — committing them
    # would move `head` and unbind the fixtures already built for that exact range.
    (repo / ".git/info").mkdir(parents=True, exist_ok=True)
    (repo / ".git/info/exclude").write_text(".github/graph-admission/\nreceipts/graph/\n")

    def run(receipt: dict | None, *, body: str = "", extra_files: list[str] | None = None,
            tamper: str | None = None, program_ref: str = "0" * 40, doc_only: bool = False) -> dict:
        for p in rdir.glob("*.json"):
            p.unlink()
        if receipt is not None:
            (rdir / "car.json").write_text(json.dumps(receipt, indent=1, sort_keys=True) + "\n")
        bp = root / "body.txt"
        bp.write_text(body)
        saved = None
        tp = repo / ".github/graph-admission/tools/graph/admit_change.py"
        if tamper:
            saved = tp.read_text()
            tp.write_text(saved + f"\n# {tamper}\n")
        b, h = base, head
        if doc_only:
            (repo / "README.md").write_text("# fixture\n\nchanged\n")
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.email=f@x", "-c", "user.name=f",
                            "commit", "-q", "-m", "docs"], check=True)
            b, h = head, admit_change.git(repo, "rev-parse", "HEAD").strip()
        out = root / "result.json"
        rc = cmd_run(argparse.Namespace(
            repo=str(repo), repo_name="Arcanada-one/fixture", tools=str(repo / ".github/graph-admission"),
            program_ref=program_ref, base=b, head=h, pr_body_file=str(bp), receipt_glob=["receipts/graph/*.json"],
            enforcement="off", build_graph=False, workdir=str(root / "work"), out=str(out), summary=None))
        if saved is not None:
            tp.write_text(saved)
        doc = json.loads(out.read_text())
        doc["_rc"] = rc
        return doc

    control = run(F["conformant-admit"]["receipt"])
    check("(d) conformant receipt in the head tree → green, verdict admitted",
          control["_rc"] == 0 and control["verdict"].startswith("admitted") and control["conclusion"] == "success",
          verdict=control["verdict"], rc=control["_rc"], codes=control["reason_codes"])

    body_only = run(None, body="Change description.\n\n```json\n"
                    + json.dumps(F["conformant-admit"]["receipt"], indent=1) + "\n```\n")
    check("(d') the same receipt delivered ONLY as a ```json block in the pull-request body → green",
          body_only["_rc"] == 0 and body_only["verdict"].startswith("admitted")
          and len(body_only["receipt_sources"]["pr_body"]) == 1 and not body_only["receipt_sources"]["tree"],
          verdict=body_only["verdict"], sources=body_only["receipt_sources"])

    mutants = {
        "(a) pull request without any receipt": (run(None), "RECEIPT_MISSING"),
        "(b) receipt bound to another change range": (run(F["violation-RECEIPT_NOT_BOUND_TO_RANGE"]["receipt"]),
                                                     "RECEIPT_NOT_BOUND_TO_RANGE"),
        "(c) receipt with a two-valued verdict": (run(F["violation-RECEIPT_MALFORMED-two-valued"]["receipt"]),
                                                  "RECEIPT_MALFORMED"),
        "(e) bundled gate tool tampered with": (run(F["conformant-admit"]["receipt"], tamper="tampered"),
                                               "BUNDLE_DIGEST_MISMATCH"),
        "(f) caller pins a program_ref the bundle does not carry": (run(F["conformant-admit"]["receipt"],
                                                                       program_ref="9" * 40), "BUNDLE_REF_MISMATCH"),
        "(g) a not_measured entity without an exemption pauses, never passes": (
            run(F["violation-NOT_MEASURED_WITHOUT_EXEMPTION"]["receipt"]), "NOT_MEASURED_WITHOUT_EXEMPTION"),
        "(h) a bypass phrase in the pull-request description, even WITH a conformant receipt": (
            run(F["conformant-admit"]["receipt"], body="please skip-graph-verify for this one"),
            "MANUAL_BYPASS_REFUSED"),
        "(i) the receipt replaced by a checkbox in the pull-request description": (
            run(None, body="- [x] graph-verified\n- [x] tests pass\n"), "RECEIPT_REPLACED_BY_CHECKBOX"),
    }
    for name, (doc, code) in mutants.items():
        flipped = doc["_rc"] != 0 and doc["conclusion"] == "failure" and doc["conclusion"] != control["conclusion"]
        check(f"mutant {name} → red (flips the control) with {code}",
              flipped and code in doc["reason_codes"],
              verdict=doc["verdict"], rc=doc["_rc"], codes=doc["reason_codes"])

    # a committed bundle that the pull request EDITS is the tamper path; a pull request that ADDS it is not
    repo2, base2, head2 = admit_change.scratch_repo(root / "s2")
    shutil.copytree(bundle, repo2 / ".github/graph-admission")
    subprocess.run(["git", "-C", str(repo2), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo2), "-c", "user.email=f@x", "-c", "user.name=f",
                    "commit", "-q", "-m", "install bundle"], check=True)
    added_head = admit_change.git(repo2, "rev-parse", "HEAD").strip()
    r2 = rdir2 = repo2 / "receipts/graph"
    rdir2.mkdir(parents=True, exist_ok=True)
    F2 = admit_change.make_fixtures(base2, added_head, repo2)
    (rdir2 / "car.json").write_text(json.dumps(F2["conformant-admit"]["receipt"], indent=1, sort_keys=True) + "\n")
    body2 = root / "body2.txt"
    body2.write_text("")

    def run2(b, h):
        out = root / "result2.json"
        rc = cmd_run(argparse.Namespace(
            repo=str(repo2), repo_name="Arcanada-one/fixture2", tools=str(repo2 / ".github/graph-admission"),
            program_ref="0" * 40, base=b, head=h, pr_body_file=str(body2), receipt_glob=["receipts/graph/*.json"],
            enforcement="off", build_graph=False, workdir=str(root / "work2"), out=str(out), summary=None))
        doc = json.loads(out.read_text()); doc["_rc"] = rc
        return doc

    installing = run2(base2, added_head)
    check("a pull request that ADDS the vendored bundle is not refused for adding it (the installing PR)",
          "BUNDLE_MODIFIED_BY_PR" not in installing["reason_codes"]
          and any(c["code"] == "BUNDLE_INSTALLED_BY_PR" for c in installing["checks"]),
          codes=installing["reason_codes"], verdict=installing["verdict"])
    # the realistic tamper: the tool AND the manifest rewritten consistently, so the sha256 check passes
    tp2 = repo2 / ".github/graph-admission/tools/graph/admit_change.py"
    tp2.write_text(tp2.read_text() + "\n# edited in the pull request\n")
    mp2 = repo2 / ".github/graph-admission/BUNDLE.json"
    man2 = json.loads(mp2.read_text())
    for f in man2["files"]:
        if f["path"].endswith("admit_change.py"):
            f["sha256"] = sha256_file(tp2)
    mp2.write_text(json.dumps(man2, indent=1, sort_keys=True) + "\n")
    subprocess.run(["git", "-C", str(repo2), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo2), "-c", "user.email=f@x", "-c", "user.name=f",
                    "commit", "-q", "-m", "edit a vendored tool"], check=True)
    edited_head = admit_change.git(repo2, "rev-parse", "HEAD").strip()
    edit_mut = run2(added_head, edited_head)
    # gate2b changed what catches this. The tamper keeps the sha256 map consistent but CANNOT keep the
    # signature valid — BUNDLE.json's bytes changed and the attacker has no key — so the cryptographic
    # layer now fires FIRST. The mutant must still flip; the code it flips with is stronger than gate1's.
    check("mutant (j) the pull request rewrites a vendored gate tool AND its BUNDLE.json entry (the sha256 "
          "check passes) → still red, now with BUNDLE_SIGNATURE_INVALID (gate2b) rather than only the "
          "diff-shape rule",
          edit_mut["_rc"] != 0 and "BUNDLE_SIGNATURE_INVALID" in edit_mut["reason_codes"],
          codes=edit_mut["reason_codes"], verdict=edit_mut["verdict"])

    # …and the diff-shape layer must still work on its own, for the one attacker the signature cannot
    # stop: someone who HOLDS the signing key. Re-sign the tampered bundle correctly and the signature
    # is valid; BUNDLE_MODIFIED_BY_PR is then the only thing standing, and it must still stand.
    sign_bundle(repo2 / ".github/graph-admission")
    subprocess.run(["git", "-C", str(repo2), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo2), "-c", "user.email=f@x", "-c", "user.name=f",
                    "commit", "-q", "-m", "re-sign the tampered bundle with the trusted key"], check=True)
    resigned_head = admit_change.git(repo2, "rev-parse", "HEAD").strip()
    resign_mut = run2(added_head, resigned_head)
    check("mutant (j2) the same tamper, correctly RE-SIGNED with the trusted key (the key-holder case, "
          "which no signature can catch) → still red, with BUNDLE_MODIFIED_BY_PR — the two layers are "
          "independent",
          resign_mut["_rc"] != 0 and "BUNDLE_MODIFIED_BY_PR" in resign_mut["reason_codes"]
          and "BUNDLE_SIGNATURE_INVALID" not in resign_mut["reason_codes"],
          codes=resign_mut["reason_codes"], verdict=resign_mut["verdict"])

    doc_only = run(None, doc_only=True)
    check("doc-only change (README.md) → green with verdict not_measured, no receipt required",
          doc_only["_rc"] == 0 and doc_only["verdict"] == "not_measured"
          and doc_only["reason_codes"] == ["DOC_ONLY_NOT_MEASURED"],
          verdict=doc_only["verdict"], codes=doc_only["reason_codes"])
    check("doc-only green is stated as not_measured in the check text, never as a pass",
          any("never as a pass" in c["detail"] or "not a pass" in c["detail"] for c in doc_only["checks"]))

    print(f"\nSELFTEST {'PASS' if not red else 'FAIL'}: {len(checks) - red}/{len(checks)} checks, "
          f"{len(mutants) + 2}/{len(mutants) + 2} mutants" if not red else
          f"\nSELFTEST FAIL: {len(checks) - red}/{len(checks)} checks")
    shutil.rmtree(root, ignore_errors=True)

    print("\n--- AUP-GRAPH-006:gate2a — the automated-author battery ---")
    g2a_checks, g2a_red = selftest_gate2a()
    red += g2a_red
    checks += g2a_checks
    print("\n--- AUP-GRAPH-006:gate2b — the bundle-signature battery ---")
    g2b_checks, g2b_red = selftest_gate2b()
    red += g2b_red
    checks += g2b_checks
    print("\n--- AUP-GRAPH-006:gate4b — the structural-exemption battery ---")
    g4b_checks, g4b_red = selftest_gate4b()
    red += g4b_red
    checks += g4b_checks
    print("\n--- AUP-GRAPH-006:gate5b — the declared-derived-artefact battery ---")
    g5b_checks, g5b_red = selftest_gate5b()
    red += g5b_red
    checks += g5b_checks
    print("\n--- AUP-DEBT-002:B7 — the declaration-amendment battery (DEC-AUP-0020) ---")
    b7_checks, b7_red = selftest_b7()
    red += b7_red
    checks += b7_checks
    measured = [c for c in checks if c.get("ok") is not None]
    print(f"\nTOTAL {'PASS' if not red else 'FAIL'}: {len(measured) - red}/{len(measured)} checks across "
          f"six batteries ({len(checks) - len(measured)} not_measured)")
    return 0 if not red else 1


def selftest_gate2a() -> tuple[list[dict], int]:
    """AUP-GRAPH-006:gate2a — the automated-author mutation battery.

    Control: a dependabot pull request touching ONLY a lockfile is green with the typed exemption.
    Every mutant must FLIP it. A survivor is a hole, reported as one.
    """
    import tempfile
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import admit_change  # noqa: E402

    root = Path(tempfile.mkdtemp(prefix="gate2a-selftest-"))
    checks, red = [], 0

    def check(name, ok, **kw):
        nonlocal red
        checks.append({"name": name, "ok": bool(ok), **kw})
        if not ok:
            red += 1
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + json.dumps(kw, ensure_ascii=False)[:400]))

    # a repository with a lockfile, a manifest and source — the shape a dependency bump lands in
    repo = root / "repo"
    repo.mkdir(parents=True)
    env = {"GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "f@x", "GIT_COMMITTER_NAME": "fixture",
           "GIT_COMMITTER_EMAIL": "f@x", "GIT_AUTHOR_DATE": "2026-09-05T00:00:00Z",
           "GIT_COMMITTER_DATE": "2026-09-05T00:00:00Z", "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "HOME": str(root)}

    def g(*args):
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env)
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)}: {r.stderr[:300]}")
        return r.stdout

    g("init", "-q", "-b", "main")
    (repo / "src").mkdir()
    (repo / "src/a.ts").write_text("export const a = 1;\n")
    (repo / "src/b.ts").write_text("import { a } from './a';\nexport const b = a + 1;\n")
    (repo / "package.json").write_text('{\n "name": "fixture",\n "dependencies": {"left-pad": "1.0.0"}\n}\n')
    (repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\npackages:\n  left-pad@1.0.0: {}\n")
    g("add", "-A"); g("commit", "-q", "-m", "base")
    base = g("rev-parse", "HEAD").strip()

    bundle = root / "bundle"
    cmd_bundle(argparse.Namespace(out=str(bundle), program_ref="0" * 40, workflow_out=None, sign_key=None))
    sign_bundle(bundle)
    shutil.copytree(bundle, repo / ".github/graph-admission")
    g("add", "-A"); g("commit", "-q", "-m", "install the gate bundle")
    base = g("rev-parse", "HEAD").strip()

    def commit(files: dict[str, str], msg: str, branch: str) -> str:
        """One branch per mutant, each a single commit on `base`: a mutant must differ from the control
        in exactly the one thing it mutates, and sequential commits would carry the previous one's files
        into the diff (observed: mutant (d) inherited mutant (b)'s src/a.ts and refused for the wrong reason)."""
        g("checkout", "-q", "-B", branch, base)
        for rel, body in files.items():
            fp = repo / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(body)
        g("add", "-A"); g("commit", "-q", "-m", msg)
        return g("rev-parse", "HEAD").strip()

    DEPENDABOT = {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"}
    HUMAN = {"login": "mallory", "id": 12345, "type": "User"}

    def event(user: dict, head_ref: str) -> str:
        p = root / f"event-{user['login']}-{abs(hash(head_ref)) % 10 ** 6}.json"
        p.write_text(json.dumps({"action": "opened", "pull_request": {
            "number": 1, "user": user, "author_association": "NONE",
            "head": {"ref": head_ref}, "base": {"ref": "main"}}}, indent=1))
        return str(p)

    def run(head: str, *, event_file: str | None, conclusion: str | None, job: str = "lint-and-test",
            body: str = "") -> dict:
        bp = root / "body.txt"
        bp.write_text(body)
        out = root / "result.json"
        rc = cmd_run(argparse.Namespace(
            repo=str(repo), repo_name="Arcanada-one/fixture", tools=str(repo / ".github/graph-admission"),
            program_ref="0" * 40, base=base, head=head, pr_body_file=str(bp),
            receipt_glob=["receipts/graph/*.json"], enforcement="off", build_graph=True,
            workdir=str(root / f"work-{head[:8]}"), out=str(out), summary=None,
            event_file=event_file, verifier_job=job, verifier_conclusion=conclusion,
            verifier_output_ref="https://example.invalid/run/1"))
        doc = json.loads(out.read_text())
        doc["_rc"] = rc
        return doc

    # ---------------------------------------------------------------- control (a)
    lock_head = commit({"pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  left-pad@1.1.0: {}\n",
                        "package.json": '{\n "name": "fixture",\n "dependencies": {"left-pad": "1.1.0"}\n}\n'},
                       "build(deps): bump left-pad from 1.0.0 to 1.1.0", "mut-a")
    control = run(lock_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.1.0"),
                  conclusion="success")
    au = control.get("automated_author") or {}
    check("(a) dependabot pull request touching only dependency manifests → green with the typed exemption",
          control["_rc"] == 0 and control["verdict"] == "admitted_with_exemptions"
          and au.get("eligible") is True and au.get("exemption_code") == "AUTOMATED_DEPENDENCY_UPDATE"
          and "AUTOMATED_AUTHOR_RECEIPT_ISSUED" in control["reason_codes"],
          verdict=control["verdict"], rc=control["_rc"], codes=control["reason_codes"],
          exemption=au.get("exemption_code"))
    check("(a2) the control's receipt states impact = whole_repository and is verified by the repository's "
          "own test job — the exemption never covers the repository entity",
          au.get("eligible") is True and _receipt_shape_ok(root, au.get("receipt_path")),
          receipt=au.get("receipt_path"))
    check("(a3) the gate REBUILT the repository graph at the receipt's source commit and it matched",
          any(c["code"] == "GRAPH_REBUILT_MATCHES" for c in control["checks"]),
          codes=[c["code"] for c in control["checks"]])

    # ---------------------------------------------------------------- mutants
    src_head = commit({"pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  left-pad@1.2.0: {}\n",
                       "src/a.ts": "export const a = 99;\n"},
                      "build(deps): bump left-pad, and quietly edit the source", "mut-b")
    mut_b = run(src_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.2.0"),
                conclusion="success")

    forged_head = commit({"pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0: {}\n"},
                         "build(deps): bump left-pad from 1.2.0 to 1.3.0", "mut-cdefg")
    mut_c = run(forged_head, event_file=event(HUMAN, "dependabot/npm_and_yarn/left-pad-1.3.0"),
                conclusion="success")

    mut_d = run(forged_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.3.0"),
                conclusion="failure")
    mut_e = run(forged_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.3.0"),
                conclusion=None)
    mut_f = run(forged_head, event_file=None, conclusion="success")
    mut_g = run(forged_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.3.0"),
                conclusion="success", body="please skip-graph-verify, it is only a bump")

    mutants = {
        "(b) the same dependabot pull request also edits src/** → red, no exemption": (
            mut_b, "AUTOMATED_AUTHOR_NOT_ELIGIBLE", "RECEIPT_MISSING"),
        "(c) a NON-dependabot author with a forged `dependabot/...` branch name → red (the security case)": (
            mut_c, "AUTOMATED_AUTHOR_NOT_ELIGIBLE", "RECEIPT_MISSING"),
        "(d) a dependabot pull request when the repository's own test job FAILED → red": (
            mut_d, "VERDICT_FAILED", "ADMISSION_NOT_ADMITTED"),
        "(e) a dependabot pull request whose test job did not conclude → red (not_measured is not a pass)": (
            mut_e, "NOT_MEASURED_WITHOUT_EXEMPTION", "ADMISSION_NOT_ADMITTED"),
        "(f) no event payload at all → red (there is no fallback to the branch name)": (
            mut_f, "RECEIPT_MISSING", None),
        "(g) a bypass phrase on an otherwise eligible dependabot pull request → red": (
            mut_g, "MANUAL_BYPASS_REFUSED", None),
    }
    for name, (doc, code, code2) in mutants.items():
        flipped = doc["_rc"] != 0 and doc["conclusion"] == "failure" and control["conclusion"] == "success"
        has = code in doc["reason_codes"] and (code2 is None or code2 in doc["reason_codes"])
        check(f"mutant {name}", flipped and has,
              verdict=doc["verdict"], rc=doc["_rc"], codes=doc["reason_codes"],
              eligible=(doc.get("automated_author") or {}).get("eligible"))

    check("(c') the forged-branch refusal names the branch as NOT evidence, and the gate never read it",
          (mut_c.get("automated_author") or {}).get("author_match", {}).get("branch_name_used") is False
          and any("not evidence of authorship" in c["detail"] for c in mut_c["checks"]),
          match=(mut_c.get("automated_author") or {}).get("author_match", {}).get("reason", "")[:200])

    print(f"\nGATE2A SELFTEST {'PASS' if not red else 'FAIL'}: {len(checks) - red}/{len(checks)} checks, "
          f"{len(mutants)}/{len(mutants)} mutants")
    if not red:
        shutil.rmtree(root, ignore_errors=True)
    else:
        print(f"scratch kept at {root}")
    return checks, red


def _receipt_shape_ok(root: Path, receipt_path: str | None) -> bool:
    """The control's authored receipt must make exactly the claims the policy says it makes."""
    if not receipt_path or not Path(receipt_path).exists():
        return False
    r = json.loads(Path(receipt_path).read_text())
    gf = r["impact_set"]["global_fallback"]
    verdict_of = {v["entity"]: v["verdict"] for v in r["verdicts"]}
    exempt = {x["entity"] for x in r["exemptions"]}
    repo_ent = next((e for e in verdict_of if e.startswith("repository:")), None)
    auth_ent = next((e for e in verdict_of if e.startswith("receipt_authorship:")), None)
    return bool(
        gf.get("triggered") is True and gf.get("scope") == "whole_repository" and gf.get("total_nodes")
        and r["impact_set"]["scope"] == "whole_repository"
        and repo_ent and verdict_of[repo_ent] == "verified" and repo_ent not in exempt
        and auth_ent and verdict_of[auth_ent] == "not_measured" and auth_ent in exempt
        and r["exemptions"][0]["owner"] and r["exemptions"][0]["expires_at_utc"]
        and r["verifiers"][0]["kind"] == "other"
        and r["admission"]["verdict"] == "admitted_with_exemptions"
        and r["authored_by"]["path"] == "automated_author"
    )


SELFTEST_SEED = bytes(range(32))          # a throwaway fixture key, never a production key
SELFTEST_OTHER_SEED = bytes(range(32, 64))  # "the attacker's own key"


def sign_bundle(bundle: Path, seed: bytes = SELFTEST_SEED, namespace: str = SIGNING_NAMESPACE,
                hash_algorithm: str = "sha512") -> str:
    """Sign a bundle the way `--sign-key` does, but in pure Python.

    The batteries must not depend on an OpenSSH binary: a battery that silently skips when a tool is
    absent reports a pass it never measured. `selftest_gate2b` cross-checks this against the real
    `ssh-keygen` where that binary exists, and records `not_measured` where it does not."""
    mp = bundle / "BUNDLE.json"
    pub = sshsig.ed25519_keypair(seed)[1]
    (bundle / PUBKEY_NAME).write_text(sshsig.public_key_line(pub, "selftest"))
    (bundle / SIGNATURE_NAME).write_text(
        sshsig.make_detached(seed, mp.read_bytes(), namespace, hash_algorithm))
    return sshsig.fingerprint(sshsig.SUPPORTED_KEY_TYPE, pub)


def reseal_bundle(bundle: Path, seed: bytes = SELFTEST_SEED, program_ref: str | None = None) -> str:
    """Recompute BUNDLE.json over the bundle's current bytes and sign it. A mutant that rewrites a
    tool AND its manifest entry AND the signature is exactly the attacker gate2b was built for, so
    the batteries below must be able to build one."""
    mp = bundle / "BUNDLE.json"
    man = json.loads(mp.read_text())
    if program_ref:
        man["program_ref"] = program_ref
    for f in man.get("files", []):
        if f.get("verified_by_the_job") is False:
            continue
        p = bundle / f["path"]
        if p.exists():
            f["sha256"] = sha256_file(p)
    man["bundle_digest"] = "sha256:" + hashlib.sha256(
        json.dumps(man["files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    mp.write_text(json.dumps(man, indent=1, sort_keys=True) + "\n")
    return sign_bundle(bundle, seed)


def selftest_gate4b() -> tuple[list[dict], int]:
    """AUP-GRAPH-006:gate4b — the structural-exemption battery.

    The gap: `admitted` requires every affected entity to carry `verified`, and two classes of real
    change cannot produce that STRUCTURALLY — an all-new-files change (the impact set is dependents,
    seeds excluded, and a file added by the change has no node at base) and the gate's own bundle
    refresh. Both landed as `paused_safe` and were being worked around by hand; muneral #69 and #70
    were BOTH merged with an admin override of the required check.

    Every arm here is a mutant of the control that must FLIP it. A survivor is a hole, reported as
    one — never accommodated by weakening the mutant."""
    # B3 runs the bundle's OWN `ci_gate.py --selftest`, and this battery is part of that selftest — so a
    # nested run would recurse without bound. The nested invocation is marked and skips this battery; it
    # is reported as `not_measured`, never as a pass, and the base/head arm counts B4 compares are both
    # taken with the same marker, so the monotonicity comparison stays like-for-like. NON-COVERAGE, stated:
    # a self-update's B3 therefore exercises three batteries of the new bundle, not four.
    if os.environ.get("AUP_GATE4B_NESTED"):
        name = ("gate4b battery not run inside a nested bundle selftest (AUP_GATE4B_NESTED): B3 runs the "
                "bundle's own selftest, so running it here would recurse without bound")
        print("n/m  " + name)
        return [{"name": name, "ok": None}], 0
    import tempfile
    root = Path(tempfile.mkdtemp(prefix="gate4b-selftest-"))
    checks, red = [], 0

    def check(name, ok, **kw):
        nonlocal red
        checks.append({"name": name, "ok": bool(ok), **kw})
        if not ok:
            red += 1
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + json.dumps(kw, ensure_ascii=False, default=str)[:500]))

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import admit_change  # noqa: E402

    GIT_ENV = {"GIT_AUTHOR_NAME": "f", "GIT_AUTHOR_EMAIL": "f@x", "GIT_COMMITTER_NAME": "f",
               "GIT_COMMITTER_EMAIL": "f@x", "GIT_AUTHOR_DATE": "2026-09-06T00:00:00Z",
               "GIT_COMMITTER_DATE": "2026-09-06T00:00:00Z",
               "PATH": os.environ.get("PATH", "/usr/bin:/bin")}

    pristine = root / "pristine-bundle"
    cmd_bundle(argparse.Namespace(out=str(pristine), program_ref="0" * 40, workflow_out=None, sign_key=None))
    BASE_FP = sign_bundle(pristine)

    def new_repo(name: str, with_bundle: bool = True, extra_under_bundle: bool = False):
        repo = root / name / "repo"
        repo.mkdir(parents=True)
        env = {**GIT_ENV, "HOME": str(root / name)}

        def g(*a):
            r = subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, env=env)
            if r.returncode != 0:
                raise RuntimeError(f"git {' '.join(a)}: {r.stderr[:300]}")
            return r.stdout
        g("init", "-q", "-b", "main")
        (repo / "src").mkdir()
        (repo / "src/a.ts").write_text("export const a = 1;\n")
        (repo / "src/b.ts").write_text("import { a } from './a';\nexport const b = a + 1;\n")
        if with_bundle:
            (repo / ".github").mkdir(exist_ok=True)
            shutil.copytree(pristine, repo / ".github/graph-admission")
            # the caller pins the program SHA in its OWN workflow, OUTSIDE the bundle — measured on
            # muneral, where .github/workflows/ci.yml carries `program_ref: '<40hex>'` for exactly the
            # reason the comment there gives: a pin inside the bundle would be replaced by the very
            # change it is meant to constrain.
            (repo / ".github/workflows").mkdir(parents=True, exist_ok=True)
            (repo / ".github/workflows/ci.yml").write_text(
                "jobs:\n  graph-admission:\n    uses: ./.github/workflows/graph-admission.yml\n"
                "    with:\n      program_ref: '" + "0" * 40 + "'\n"
                "      signing_key_fingerprint: 'SHA256:fixture'\n")
            if extra_under_bundle:
                (repo / ".github/graph-admission/NOTES.md").write_text("a note that is not bundle-managed\n")
        g("add", "-A")
        g("commit", "-q", "-m", "base")
        return repo, g, g("rev-parse", "HEAD").strip()

    def draft_receipt(repo_name: str, base: str, head: str, files: list[dict], verdicts: list[dict],
                      empty_impact: bool, impact_core: list[dict] | None = None) -> dict:
        r = {
            "schema": "ChangeAdmissionReceipt/v1", "receipt_id": f"car-gate4b-{head[:8]}",
            "captured_at_utc": "2026-09-06T12:00:00Z",
            "producer": {"tool": "tools/graph/verify.py", "version": "1.0.0"},
            "decision_ref": "DEC-AUP-0008", "repo": {"name": repo_name},
            "graph": {"source_commit": base, "graph_digest": "sha256:" + "a" * 64,
                      "builder_version": "1.0.0", "built_at_utc": "2026-09-06T11:00:00Z"},
            "tree": {"commit": head, "dirty": False},
            "staleness": {"method": "graph.source_commit == change_set.base; clean tree", "verdict": "fresh",
                          "checked_at_utc": "2026-09-06T12:00:00Z"},
            "change_set": {"mode": "diff", "base": base, "head": head, "files": files},
            "impact_set": {"method": "reverse traversal (dependents; seeds excluded)", "max_depth": 3,
                           "deterministic_core": impact_core or [], "inferred_tail": [],
                           "global_fallback": {"triggered": False}},
            "verifiers": [], "verdicts": verdicts, "exemptions": [],
            "admission": {"verdict": "paused_safe",
                          "rule": "admitted requires every verdict = verified; zero verdicts ⇒ paused_safe"},
            "work_item": {"system": "muneral", "id": "AUP-GRAPH-006"},
        }
        if empty_impact:
            r["empty_impact_explanation"] = {
                "reason": "every changed path is a new file (status A): the graph in --diff mode is built at "
                          "change_set.base, where none of these files exists, so no seed and no dependent can exist",
                "graph_metadata": {"extractors": ["imports"], "language_coverage": ["typescript"],
                                   "changed_node_known_to_graph": False, "reverse_edges_of_changed_nodes": 0}}
        return r

    def issue(repo: Path, base: str, head: str, receipt: dict, repo_name="Arcanada-one/fixture") -> tuple[int, dict]:
        d = root / f"issue-{head[:8]}-{abs(hash(json.dumps(receipt, sort_keys=True))) % 10**6}"
        d.mkdir(parents=True, exist_ok=True)
        rp, out = d / "draft.json", d / "exempted.json"
        rp.write_text(json.dumps(receipt, indent=1, sort_keys=True) + "\n")
        rc = admit_change.cmd_exempt(argparse.Namespace(
            repo=str(repo), range=f"{base}..{head}", base=None, head=None, receipt=str(rp), out=str(out),
            evidence_out=str(d / "evidence.json"), bundle_dir=admit_change.DEFAULT_BUNDLE_DIR, owner=None,
            program_receipt=None, policy=None, repo_name=repo_name, workdir=str(d / "wd")))
        return rc, (json.loads(out.read_text()) if out.exists() else receipt)

    def run_ci(repo: Path, base: str, head: str, receipt: dict | None, *, pin: str | None = BASE_FP,
               program_ref: str = "0" * 40, tag: str = "run") -> dict:
        d = root / f"ci-{tag}-{head[:8]}"
        d.mkdir(parents=True, exist_ok=True)
        body = "" if receipt is None else "```json\n" + json.dumps(receipt, indent=1, sort_keys=True) + "\n```\n"
        (d / "body.txt").write_text(body)
        out = d / "result.json"
        rc = cmd_run(argparse.Namespace(
            repo=str(repo), repo_name="Arcanada-one/fixture", tools=str(repo / ".github/graph-admission"),
            program_ref=program_ref, base=base, head=head, pr_body_file=str(d / "body.txt"),
            receipt_glob=["receipts/graph/*.json"], enforcement="off", build_graph=False,
            workdir=str(d / "work"), out=str(out), summary=None, signing_key_fingerprint=pin))
        doc = json.loads(out.read_text())
        doc["_rc"] = rc
        return doc

    # ============================================================ case A — the all-new-files change
    repo, g, base = new_repo("A-control")
    (repo / "src/new1.ts").write_text("export const n1 = 1;\n")
    (repo / "src/new2.ts").write_text("import { n1 } from './new1';\nexport const n2 = n1 + 1;\n")
    g("add", "-A"); g("commit", "-q", "-m", "two new files, nothing else")
    head_a = g("rev-parse", "HEAD").strip()
    # node_id is None for an added path, which is what verify.py emits: in --diff mode the graph is
    # built at base, where the file does not exist, so it has no node to name.
    files_a = [{"path": p, "status": "A", "kind": "code", "node_id": None}
               for p in ("src/new1.ts", "src/new2.ts")]
    rc_ex, exempted = issue(repo, base, head_a, draft_receipt("Arcanada-one/fixture", base, head_a, files_a, [], True))
    check("(a) CONTROL: an all-new-files change is issued NO_IMPACT_BY_CONSTRUCTION by the gate "
          "(A1 all-added, A2 no pre-existing node references them at head, A3 no global fallback)",
          rc_ex == 0 and exempted["admission"]["verdict"] == "admitted_with_exemptions"
          and any(x["code"] == "NO_IMPACT_BY_CONSTRUCTION" for x in exempted["exemptions"]),
          rc=rc_ex, admission=exempted["admission"]["verdict"],
          codes=[x.get("code") for x in exempted.get("exemptions", [])])
    ci_a = run_ci(repo, base, head_a, exempted, tag="a")
    check("(a) …and the CI gate admits it — the permanent red of the seven dark-launch proposals is "
          "structural, not a policy",
          ci_a["_rc"] == 0 and ci_a["verdict"] == "admitted_with_exemptions",
          rc=ci_a["_rc"], verdict=ci_a["verdict"], codes=ci_a["reason_codes"])

    # ---- mutant (b): the abuse case — new files PLUS an edit to an existing file
    repo_b, gb, base_b = new_repo("B-abuse")
    (repo_b / "src/new1.ts").write_text("export const n1 = 1;\n")
    (repo_b / "src/a.ts").write_text("export const a = 99;  // a real edit smuggled in beside the new file\n")
    gb("add", "-A"); gb("commit", "-q", "-m", "a new file AND an edit")
    head_b = gb("rev-parse", "HEAD").strip()
    files_b = [{"path": "src/new1.ts", "status": "A", "kind": "code", "node_id": None},
               {"path": "src/a.ts", "status": "M", "kind": "code", "node_id": None}]
    rc_b, not_exempted = issue(repo_b, base_b, head_b, draft_receipt("Arcanada-one/fixture", base_b, head_b, files_b, [], True))
    check("(b) MUTANT: adding files AND editing an existing one is NOT exempted — the gate refuses to issue",
          rc_b != 0 and not any(x.get("code") in admit_change.STRUCTURAL_CODES
                                for x in (not_exempted.get("exemptions") or [])),
          rc=rc_b, exemptions=[x.get("code") for x in (not_exempted.get("exemptions") or [])])
    # …and the same abuse, FORGED by hand with a correct change binding: the gate re-measures A1 and refuses
    forged = draft_receipt("Arcanada-one/fixture", base_b, head_b, files_b, [], True)
    synth_b = f"impact_computability:Arcanada-one/fixture@{head_b[:12]}"
    forged["verdicts"] = [{"entity": synth_b, "verdict": "not_measured", "reason": "forged"}]
    forged["exemptions"] = [{"entity": synth_b, "code": "NO_IMPACT_BY_CONSTRUCTION", "owner": "an attacker",
                             "expires_at_utc": "2027-01-01T00:00:00Z", "reason": "claims an empty impact set",
                             "change_binding": {"base": base_b, "head": head_b,
                                                "digest": admit_change.diff_digest(repo_b, base_b, head_b)}}]
    forged["admission"] = {"verdict": "admitted_with_exemptions", "rule": "claimed"}
    ci_b = run_ci(repo_b, base_b, head_b, forged, tag="b")
    check("(b) MUTANT: the same abuse with a HAND-WRITTEN exemption whose change binding is CORRECT → the gate "
          "re-measures A1 itself and refuses (C16). The receipt is never believed about its own exemption",
          ci_b["_rc"] != 0 and "STRUCTURAL_EXEMPTION_UNSOUND" in ci_b["reason_codes"],
          rc=ci_b["_rc"], verdict=ci_b["verdict"], codes=ci_b["reason_codes"])

    # ---- mutant (b2): a new file that a PRE-EXISTING node references at head (A2)
    repo_b2, gb2, base_b2 = new_repo("B2-inbound")
    (repo_b2 / "src/b.ts").write_text("import { a } from './a';\nimport { n } from './new1';\nexport const b = a + n;\n")
    gb2("add", "-A"); gb2("commit", "-q", "-m", "base where b.ts already imports a file that does not exist yet")
    base_b2 = gb2("rev-parse", "HEAD").strip()
    (repo_b2 / "src/new1.ts").write_text("export const n = 1;\n")
    gb2("add", "-A"); gb2("commit", "-q", "-m", "add the file the existing module already imports")
    head_b2 = gb2("rev-parse", "HEAD").strip()
    rc_b2, _ = issue(repo_b2, base_b2, head_b2, draft_receipt(
        "Arcanada-one/fixture", base_b2, head_b2,
        [{"path": "src/new1.ts", "status": "A", "kind": "code", "node_id": None}], [], True))
    check("(b2) MUTANT: an all-new-files change whose file a PRE-EXISTING node references at head is refused "
          "(A2) — a file picked up by convention or an existing import changes behaviour with no textual edit",
          rc_b2 != 0, rc=rc_b2)

    # ============================================================ case B — the gate updating itself
    def refresh(name: str, mutate=None, seed: bytes = SELFTEST_SEED, pin: str | None = None,
                wf_extra: str = ""):
        """A repository whose base already carries the bundle, and a pull request that refreshes it
        and changes NOTHING else — the shape that was merged twice with an admin override."""
        repo_r, gr, base_r = new_repo(name)
        newb = root / f"{name}-newbundle"
        shutil.copytree(pristine, newb)
        (newb / "tools/graph/build_graph.py").write_text(
            (newb / "tools/graph/build_graph.py").read_text() + "\n# refreshed at a newer program ref\n")
        if mutate:
            mutate(newb)
        reseal_bundle(newb, seed, program_ref="1" * 40)
        shutil.rmtree(repo_r / ".github/graph-admission")
        shutil.copytree(newb, repo_r / ".github/graph-admission")
        wf = repo_r / ".github/workflows/ci.yml"
        wf.write_text(wf.read_text().replace("0" * 40, pin if pin is not None else "1" * 40))
        if wf_extra:
            wf.write_text(wf.read_text() + wf_extra)
        gr("add", "-A"); gr("commit", "-q", "-m", "refresh the vendored gate bundle")
        return repo_r, gr, base_r, gr("rev-parse", "HEAD").strip()

    def self_update_receipt(repo_r: Path, base_r: str, head_r: str) -> dict:
        changed = [l.split("\t") for l in admit_change.git(repo_r, "diff", "--name-status", base_r, head_r).splitlines() if l]
        files = [{"path": c[-1], "status": c[0][0], "kind": "config", "node_id": None} for c in changed]
        tools_changed = [f["path"] for f in files if f["path"].endswith(".py")][:3]
        verdicts = [{"entity": f"code_unit:{p}", "verdict": "not_measured",
                     "reason": "vendored foreign code: this file is a byte-copy of the program repository at "
                               "the bundle's program_ref, and it is the code that would do the measuring"}
                    for p in tools_changed]
        core = [{"entity": v["entity"], "depth": 1,
                 "path": [{"from": v["entity"], "to": f"code_unit:{tools_changed[0]}",
                           "edge_type": "imports", "provenance": "deterministic"}]}
                for v in verdicts]
        return draft_receipt("Arcanada-one/fixture", base_r, head_r, files, verdicts, False, core)

    repo_c, gc, base_c, head_c = refresh("C-control")
    rc_su, su_receipt = issue(repo_c, base_c, head_c, self_update_receipt(repo_c, base_c, head_c))
    check("(control) CONTROL: a legitimate bundle refresh is issued GATE_SELF_UPDATE — signature continuity "
          "against the key of the BASE tree, the head bundle's own selftest, and check-id/arm monotonicity",
          rc_su == 0 and su_receipt["admission"]["verdict"] == "admitted_with_exemptions"
          and all(x["code"] == "GATE_SELF_UPDATE" for x in su_receipt["exemptions"]),
          rc=rc_su, admission=su_receipt["admission"]["verdict"], n=len(su_receipt.get("exemptions") or []))
    ci_c = run_ci(repo_c, base_c, head_c, su_receipt, program_ref="1" * 40, tag="c")
    check("(control) …and the CI gate admits it WITHOUT an admin override, with BUNDLE_MODIFIED_BY_PR replaced "
          "by SELF_UPDATE_CANDIDATE — «нет receipt — нет мержа» now holds for changes to the rule too",
          ci_c["_rc"] == 0 and ci_c["verdict"] == "admitted_with_exemptions"
          and "BUNDLE_MODIFIED_BY_PR" not in ci_c["reason_codes"]
          and any(c["code"] == "SELF_UPDATE_CANDIDATE" for c in ci_c["checks"]),
          rc=ci_c["_rc"], verdict=ci_c["verdict"], codes=ci_c["reason_codes"])

    # ---- mutant (c): the refreshed bundle's own selftest FAILS
    def break_selftest(b: Path):
        f = b / "tools/graph/ci_gate.py"
        t = f.read_text()
        assert "def selftest() -> int:" in t
        f.write_text(t.replace("def selftest() -> int:", "def selftest() -> int:\n    return 7", 1))
    repo_d, gd, base_d, head_d = refresh("D-selftest", break_selftest)
    rc_d, rec_d = issue(repo_d, base_d, head_d, self_update_receipt(repo_d, base_d, head_d))
    check("(c) MUTANT: a self-update whose own selftest FAILS is refused (B3) — a bundle that cannot pass its "
          "own battery is not admitted by being the gate",
          rc_d != 0 and not (rec_d.get("exemptions") or []),
          rc=rc_d, exemptions=[x.get("code") for x in (rec_d.get("exemptions") or [])])

    # ---- mutant (d): the refreshed bundle is signed by a DIFFERENT key (no continuity with base)
    repo_e, ge, base_e, head_e = refresh("E-key", seed=SELFTEST_OTHER_SEED)
    rc_e, rec_e = issue(repo_e, base_e, head_e, self_update_receipt(repo_e, base_e, head_e))
    check("(d) MUTANT: a self-update whose bundle is signed by another key is refused (B2) — the anchor is the "
          "SIGNING-KEY.pub and the sshsig.py of the BASE tree, which the pull request did not write, so the "
          "refusal holds even though the head bundle is perfectly self-consistent",
          rc_e != 0 and not (rec_e.get("exemptions") or []), rc=rc_e)
    ci_e = run_ci(repo_e, base_e, head_e, None, pin=None, program_ref="1" * 40, tag="e")
    check("(d) …and with NO fingerprint pinned in the caller's workflow — where verify_bundle can only say "
          "BUNDLE_SIGNATURE_UNPINNED (not_measured) — the change is still red, never admitted",
          ci_e["_rc"] != 0 and ci_e["verdict"] != "admitted"
          and any(c["code"] == "BUNDLE_SIGNATURE_UNPINNED" for c in ci_e["checks"]),
          rc=ci_e["_rc"], verdict=ci_e["verdict"], codes=ci_e["reason_codes"])

    # ---- mutant (e): a change that merely TOUCHES a file under the bundle path is not a self-update
    repo_f, gf, base_f = new_repo("F-underpath", extra_under_bundle=True)
    (repo_f / ".github/graph-admission/NOTES.md").write_text("edited, and this file is not bundle-managed\n")
    gf("add", "-A"); gf("commit", "-q", "-m", "touch a non-managed file under the bundle directory")
    head_f = gf("rev-parse", "HEAD").strip()
    case_f, ev_f = admit_change.structural_case(
        repo_f, base_f, head_f,
        [{"path": ".github/graph-admission/NOTES.md", "status": "M"}])
    ci_f = run_ci(repo_f, base_f, head_f, None, tag="f")
    check("(e) MUTANT: a non-bundle change that merely touches a file under the bundle path is NOT a "
          "self-update — BUNDLE_MODIFIED_BY_PR still stands and no exemption is on offer",
          case_f is None and ci_f["_rc"] != 0 and "BUNDLE_MODIFIED_BY_PR" in ci_f["reason_codes"]
          and not any(c["code"] == "SELF_UPDATE_CANDIDATE" for c in ci_f["checks"]),
          case=case_f, rc=ci_f["_rc"], codes=ci_f["reason_codes"])

    # ---- mutant (g): the refresh DROPS a policy check id
    def drop_a_check(b: Path):
        p = b / "contracts/graph-verified-change/admission-gate.v1.json"
        d = json.loads(p.read_text())
        d["checks"] = [c for c in d["checks"] if c["id"] != "C17"]
        p.write_text(json.dumps(d, indent=1, ensure_ascii=False) + "\n")
    repo_g, gg, base_g, head_g = refresh("G-monotonic", drop_a_check)
    rc_g, rec_g = issue(repo_g, base_g, head_g, self_update_receipt(repo_g, base_g, head_g))
    check("(g) MUTANT: a self-update that REMOVES a policy check id is refused (B4) — «the rule holds for every "
          "change except changes to the rule» is exactly the shape this proxy exists to catch",
          rc_g != 0 and not (rec_g.get("exemptions") or []), rc=rc_g)

    # ---- mutant (h): the caller workflow edit carries MORE than the pin
    repo_i, gi, base_i, head_i = refresh("I-wfextra", wf_extra="      extra_input: 'smuggled in beside the pin'\n")
    rc_i, rec_i = issue(repo_i, base_i, head_i, self_update_receipt(repo_i, base_i, head_i))
    check("(h) MUTANT: a refresh whose caller-workflow edit carries anything BESIDES the program_ref pin is "
          "refused (B1) — the allowance for the pin is the narrowest one that is still checkable, never a "
          "licence to edit the workflow that decides which code runs",
          rc_i != 0 and not (rec_i.get("exemptions") or []), rc=rc_i)

    # ---- mutant (i): the pin is updated to a DIFFERENT SHA than the bundle carries
    repo_j, gj, base_j, head_j = refresh("J-wrongpin", pin="2" * 40)
    rc_j, rec_j = issue(repo_j, base_j, head_j, self_update_receipt(repo_j, base_j, head_j))
    check("(i) MUTANT: a refresh whose caller pins a DIFFERENT SHA than the bundle it vendors is refused (B1) "
          "— the pin lives outside the bundle so the bundle cannot vouch for it, and nothing checked it "
          "against the manifest before the run until now",
          rc_j != 0 and not (rec_j.get("exemptions") or []), rc=rc_j)

    # ---- mutant (f): an exemption presented against a DIFFERENT diff
    repo_h, gh, base_h = new_repo("H-binding")
    (repo_h / "src/new1.ts").write_text("export const n1 = 1;\n")
    gh("add", "-A"); gh("commit", "-q", "-m", "one new file")
    head_h1 = gh("rev-parse", "HEAD").strip()
    files_h = [{"path": "src/new1.ts", "status": "A", "kind": "code", "node_id": None}]
    rc_h, exempted_h = issue(repo_h, base_h, head_h1, draft_receipt("Arcanada-one/fixture", base_h, head_h1, files_h, [], True))
    (repo_h / "src/new2.ts").write_text("export const n2 = 2;\n")
    gh("add", "-A"); gh("commit", "-q", "-m", "one more new file — the same KIND of change, a different change")
    head_h2 = gh("rev-parse", "HEAD").strip()
    reused = json.loads(json.dumps(exempted_h))
    reused["change_set"]["head"] = head_h2
    reused["tree"]["commit"] = head_h2
    reused["change_set"]["files"] = files_h + [{"path": "src/new2.ts", "status": "A", "kind": "code",
                                                "node_id": None}]
    ci_h = run_ci(repo_h, base_h, head_h2, reused, tag="h")
    check("(f) MUTANT: the SAME exemption re-presented against a different diff is refused (C16) — the digest, "
          "not the clock, is the expiry; gate2a's 30-day calendar exemption would still be inside its window",
          rc_h == 0 and ci_h["_rc"] != 0 and "STRUCTURAL_EXEMPTION_UNSOUND" in ci_h["reason_codes"],
          issued=rc_h, rc=ci_h["_rc"], codes=ci_h["reason_codes"])

    print(f"\nGATE4B SELFTEST {'PASS' if not red else 'FAIL'}: {len(checks) - red}/{len(checks)} checks, "
          f"{red} failing")
    shutil.rmtree(root, ignore_errors=True)
    return checks, red


# --------------------------------------------------------------------------------------------------
# AUP-GRAPH-006:gate5b — the declared-derived-artefact battery (B6)
# --------------------------------------------------------------------------------------------------
VERIFY_DERIVED_SRC = """import hashlib, pathlib, subprocess, sys
ART = "data/derived.txt"
root = pathlib.Path(__file__).resolve().parent.parent
files = subprocess.run(["git", "-C", str(root), "ls-files"], capture_output=True, text=True).stdout.split()
h = hashlib.sha256()
for f in sorted(files):
    if f == ART:
        continue
    h.update(f.encode() + b"\\0")
    p = root / f
    h.update((p.read_bytes() if p.exists() else b"") + b"\\0")
want = h.hexdigest()
got = (root / ART).read_text().strip()
if got != want:
    print("derived artefact is stale or tampered: %s != %s" % (got[:12], want[:12]), file=sys.stderr)
    raise SystemExit(1)
print("derived artefact matches the tracked tree")
"""


def _tracked_tree_digest(repo: Path, exclude: str) -> str:
    """The fixture's own copy of the rule muneral's gitSupplement implements: a hash of the whole tracked
    tree except the evidence file itself. Deliberately the SAME shape as the real subject."""
    import hashlib
    files = subprocess.run(["git", "-C", str(repo), "ls-files"], capture_output=True, text=True).stdout.split()
    h = hashlib.sha256()
    for f in sorted(files):
        if f == exclude:
            continue
        h.update(f.encode() + b"\0")
        p = repo / f
        h.update((p.read_bytes() if p.exists() else b"") + b"\0")
    return h.hexdigest()


def selftest_gate5b() -> tuple[list[dict], int]:
    """AUP-GRAPH-006:gate5b — B6, declared derived artefacts.

    The gap this closes was MEASURED on muneral #71, not predicted: `graph-admission` and `lint-and-test`
    were green only in mutually exclusive states, because muneral's mutation evidence pins a hash of the
    whole tracked tree and B1 refuses to carry the regenerated file. B1's model — «a bundle refresh
    changes nothing but the bundle» — is false in any caller whose evidence is bound to its tree.

    A caller-declared allowlist is a caller-CONTROLLED hole, so every arm below is a mutant of a
    declaration that must be REFUSED. A survivor is a hole, reported as one — never accommodated by
    weakening the mutant. The fixture's artefact is a hash of the whole tracked tree excluding itself:
    the same shape as the real subject, so the battery exercises the real coupling."""
    # Reuses gate4b's marker deliberately: it means «we are inside a nested bundle selftest», and B3 runs
    # the head bundle's own ci_gate.py --selftest, which contains THIS battery. A new env key would have to
    # be declared in .env.example, whose change triggers the global fallback (hole #4) — reuse is both
    # semantically right and cheaper. NON-COVERAGE, stated: a refresh that breaks only the gate5b arms
    # passes B3, exactly as gate4b already records for its own arms.
    if os.environ.get("AUP_GATE4B_NESTED"):
        name = ("gate5b battery not run inside a nested bundle selftest (AUP_GATE4B_NESTED): B3 runs the "
                "bundle's own selftest, so running it here would recurse without bound")
        print("n/m  " + name)
        return [{"name": name, "ok": None}], 0
    import tempfile
    root = Path(tempfile.mkdtemp(prefix="gate5b-selftest-"))
    checks, red = [], 0

    def check(name, ok, **kw):
        nonlocal red
        checks.append({"name": name, "ok": bool(ok), **kw})
        if not ok:
            red += 1
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + json.dumps(kw, ensure_ascii=False, default=str)[:600]))

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import admit_change  # noqa: E402

    GIT_ENV = {"GIT_AUTHOR_NAME": "f", "GIT_AUTHOR_EMAIL": "f@x", "GIT_COMMITTER_NAME": "f",
               "GIT_COMMITTER_EMAIL": "f@x", "GIT_AUTHOR_DATE": "2026-09-06T00:00:00Z",
               "GIT_COMMITTER_DATE": "2026-09-06T00:00:00Z",
               "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    DECL_REL = admit_change.DEFAULT_DECLARATION_REL
    ART = "data/derived.txt"

    pristine = root / "pristine-bundle"
    cmd_bundle(argparse.Namespace(out=str(pristine), program_ref="0" * 40, workflow_out=None, sign_key=None))
    BASE_FP = sign_bundle(pristine)

    def declaration(paths=(ART,), job="lint-and-test", argv=None, glob=False) -> dict:
        return {"schema": admit_change.DECLARATION_SCHEMA,
                "artefacts": [{"path": ("data/*.txt" if glob else p), "verified_by_job": job,
                               "verify": {"argv": argv or ["python3", "tools/verify_derived.py"], "cwd": "."},
                               "why": "a hash of the whole tracked tree except itself — the shape muneral's "
                                      "mutation evidence has, and the reason a bundle refresh cannot avoid it"}
                              for p in paths]}

    def new_repo(name: str, decl: dict | None = None):
        repo = root / name / "repo"
        repo.mkdir(parents=True)
        env = {**GIT_ENV, "HOME": str(root / name)}

        def g(*a):
            r = subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, env=env)
            if r.returncode != 0:
                raise RuntimeError(f"git {' '.join(a)}: {r.stderr[:300]}")
            return r.stdout
        g("init", "-q", "-b", "main")
        (repo / "src").mkdir()
        (repo / "src/a.ts").write_text("export const a = 1;\n")
        (repo / "src/b.ts").write_text("import { a } from './a';\nexport const b = a + 1;\n")
        (repo / "tools").mkdir()
        (repo / "tools/verify_derived.py").write_text(VERIFY_DERIVED_SRC)
        (repo / ".github").mkdir(exist_ok=True)
        shutil.copytree(pristine, repo / ".github/graph-admission")
        (repo / ".github/workflows").mkdir(parents=True, exist_ok=True)
        (repo / ".github/workflows/ci.yml").write_text(
            "jobs:\n  graph-admission:\n    needs: lint-and-test\n"
            "    uses: ./.github/workflows/graph-admission.yml\n"
            "    with:\n      program_ref: '" + "0" * 40 + "'\n"
            "      verifier_job: 'lint-and-test'\n"
            "      signing_key_fingerprint: 'SHA256:fixture'\n")
        if decl is not None:
            (repo / DECL_REL).parent.mkdir(parents=True, exist_ok=True)
            (repo / DECL_REL).write_text(json.dumps(decl, indent=1, sort_keys=True) + "\n")
        (repo / "data").mkdir()
        (repo / ART).write_text("placeholder\n")
        g("add", "-A")
        (repo / ART).write_text(_tracked_tree_digest(repo, ART) + "\n")
        g("add", "-A")
        g("commit", "-q", "-m", "base")
        return repo, g, g("rev-parse", "HEAD").strip()

    def refresh(name: str, decl: dict | None = None, *, extra=None, regenerate: bool = True,
                pin: str = "1" * 40):
        """Base already carries the bundle and a fresh artefact; the pull request refreshes the bundle,
        moves the pin, and regenerates the artefact — the shape muneral #71 cannot express today."""
        repo, g, base = new_repo(name, decl)
        newb = root / f"{name}-newbundle"
        shutil.copytree(pristine, newb)
        (newb / "tools/graph/build_graph.py").write_text(
            (newb / "tools/graph/build_graph.py").read_text() + "\n# refreshed at a newer program ref\n")
        reseal_bundle(newb, SELFTEST_SEED, program_ref=pin)
        shutil.rmtree(repo / ".github/graph-admission")
        shutil.copytree(newb, repo / ".github/graph-admission")
        wf = repo / ".github/workflows/ci.yml"
        wf.write_text(wf.read_text().replace("0" * 40, pin))
        if extra:
            extra(repo)
        g("add", "-A")
        if regenerate:
            (repo / ART).write_text(_tracked_tree_digest(repo, ART) + "\n")
            g("add", "-A")
        g("commit", "-q", "-m", "refresh the vendored gate bundle")
        return repo, g, base, g("rev-parse", "HEAD").strip()

    def receipt_for(repo: Path, base: str, head: str) -> dict:
        changed = [l.split("\t") for l in admit_change.git(repo, "diff", "--name-status", base, head).splitlines() if l]
        files = [{"path": c[-1], "status": c[0][0], "kind": "config", "node_id": None} for c in changed]
        tools_changed = [f["path"] for f in files if f["path"].endswith(".py")][:2]
        verdicts = [{"entity": f"code_unit:{p}", "verdict": "not_measured", "reason": "vendored foreign code"}
                    for p in tools_changed]
        # A receipt whose impact set is empty must EXPLAIN it (schema_check EMPTY_IMPACT_WITHOUT_EXPLANATION)
        # — the rule that «an empty impact set is a prediction, never an approval». The fixture obeys it the
        # same way a real receipt does, rather than being handed a core it did not measure.
        core = [{"entity": v["entity"], "depth": 1,
                 "path": [{"from": v["entity"], "to": f"code_unit:{tools_changed[0]}",
                           "edge_type": "imports", "provenance": "deterministic"}]}
                for v in verdicts]
        empty_expl = {} if core else {"empty_impact_explanation": {
            "reason": "every changed path is either a new file or a declared derived artefact whose bytes are a "
                      "function of the rest of the tree; the graph in --diff mode is built at base, where the "
                      "new files do not exist, so no seed and no dependent can exist",
            "graph_metadata": {"extractors": ["imports"], "language_coverage": ["typescript"],
                               "changed_node_known_to_graph": False, "reverse_edges_of_changed_nodes": 0}}}
        return {**empty_expl, "schema": "ChangeAdmissionReceipt/v1", "receipt_id": f"car-gate5b-{head[:8]}",
                "captured_at_utc": "2026-09-06T12:00:00Z",
                "producer": {"tool": "tools/graph/verify.py", "version": "1.0.0"},
                "decision_ref": "DEC-AUP-0008", "repo": {"name": "Arcanada-one/fixture"},
                "graph": {"source_commit": base, "graph_digest": "sha256:" + "a" * 64,
                          "builder_version": "1.0.0", "built_at_utc": "2026-09-06T11:00:00Z"},
                "tree": {"commit": head, "dirty": False},
                "staleness": {"method": "graph.source_commit == change_set.base; clean tree",
                              "verdict": "fresh", "checked_at_utc": "2026-09-06T12:00:00Z"},
                "change_set": {"mode": "diff", "base": base, "head": head, "files": files},
                "impact_set": {"method": "reverse traversal (dependents; seeds excluded)", "max_depth": 3,
                               "deterministic_core": core, "inferred_tail": [],
                               "global_fallback": {"triggered": False}},
                "verifiers": [], "verdicts": verdicts, "exemptions": [],
                "admission": {"verdict": "paused_safe", "rule": "admitted requires every verdict = verified"},
                "work_item": {"system": "muneral", "id": "AUP-GRAPH-006"}}

    def issue(repo: Path, base: str, head: str, *, job="lint-and-test", concl="success") -> tuple[int, dict]:
        d = root / f"issue-{repo.parent.name}-{head[:8]}"
        d.mkdir(parents=True, exist_ok=True)
        rp, out = d / "draft.json", d / "exempted.json"
        rp.write_text(json.dumps(receipt_for(repo, base, head), indent=1, sort_keys=True) + "\n")
        rc = admit_change.cmd_exempt(argparse.Namespace(
            repo=str(repo), range=f"{base}..{head}", base=None, head=None, receipt=str(rp), out=str(out),
            evidence_out=str(d / "evidence.json"), bundle_dir=admit_change.DEFAULT_BUNDLE_DIR, owner=None,
            program_receipt=None, policy=None, repo_name="Arcanada-one/fixture", workdir=str(d / "wd"),
            verifier_job=job, verifier_conclusion=concl))
        return rc, (json.loads(out.read_text()) if out.exists() else json.loads(rp.read_text()))

    def arms_of(repo: Path, base: str, head: str, *, job="lint-and-test", concl="success") -> dict:
        """The B6 sub-arms as the gate measured them — so a mutant can be pinned to the arm that caught it."""
        d = root / f"arms-{repo.parent.name}-{head[:8]}"
        d.mkdir(parents=True, exist_ok=True)
        ev = admit_change.evaluate_structural(repo, base, head, receipt_for(repo, base, head)["change_set"]["files"],
                                              "gate_self_update", d, admit_change.DEFAULT_BUNDLE_DIR,
                                              verifier_job=job, verifier_conclusion=concl)
        return {x["id"]: x["verdict"] for x in (ev.get("derived_arms") or [])} | {
            c["id"]: c["verdict"] for c in ev["checks"]}

    def arms_of2(repo: Path, base: str, head: str, *, job="lint-and-test", concl="success") -> dict:
        d = root / f"arms2-{repo.parent.name}-{head[:8]}"
        d.mkdir(parents=True, exist_ok=True)
        ev = admit_change.evaluate_structural(repo, base, head,
                                              receipt_for(repo, base, head)["change_set"]["files"],
                                              "no_impact_by_construction", d,
                                              admit_change.DEFAULT_BUNDLE_DIR,
                                              verifier_job=job, verifier_conclusion=concl)
        return {x["id"]: x["verdict"] for x in (ev.get("derived_arms") or [])} | {
            c["id"]: c["verdict"] for c in ev["checks"]}

    def admitted(rc: int, rec: dict) -> bool:
        return rc == 0 and rec["admission"]["verdict"] == "admitted_with_exemptions" and any(
            x.get("code") == "GATE_SELF_UPDATE" for x in (rec.get("exemptions") or []))

    # ---------------------------------------------------------------- CONTROL: the honest case
    repo, g, base, head = refresh("A-control", declaration())
    rc, rec = issue(repo, base, head)
    a = arms_of(repo, base, head)
    check("(control) CONTROL: a bundle refresh that also carries the caller's DECLARED derived artefact, "
          "regenerated, is admitted — the state muneral #71 could not express: graph-admission and "
          "lint-and-test green on the SAME head",
          admitted(rc, rec) and all(a.get(k) == "verified" for k in ("B6.1", "B6.2", "B6.3", "B6.4", "B6.5", "B6.6")),
          rc=rc, admission=rec["admission"]["verdict"], arms=a)

    d0 = root / "ci-control"
    d0.mkdir(parents=True, exist_ok=True)
    (d0 / "body.txt").write_text("```json\n" + json.dumps(rec, indent=1, sort_keys=True) + "\n```\n")
    out0 = d0 / "result.json"
    rc0 = cmd_run(argparse.Namespace(
        repo=str(repo), repo_name="Arcanada-one/fixture", tools=str(repo / ".github/graph-admission"),
        program_ref="1" * 40, base=base, head=head, pr_body_file=str(d0 / "body.txt"),
        receipt_glob=["receipts/graph/*.json"], enforcement="off", build_graph=False,
        workdir=str(d0 / "work"), out=str(out0), summary=None, signing_key_fingerprint=BASE_FP,
        verifier_job="lint-and-test", verifier_conclusion="success"))
    doc0 = json.loads(out0.read_text())
    check("(control) …and the CI gate ADMITS it, re-measuring B6 itself (C16) — the check that was green only "
          "while the caller's own suite was red is now green beside it",
          rc0 == 0 and doc0["verdict"] == "admitted_with_exemptions"
          and "STRUCTURAL_EXEMPTION_UNSOUND" not in doc0["reason_codes"]
          and "BUNDLE_MODIFIED_BY_PR" not in doc0["reason_codes"],
          rc=rc0, verdict=doc0["verdict"], codes=doc0["reason_codes"])

    # ---- MUTANT 1 (the brief's «a declared artefact the verifier does NOT regenerate»): a verifier that
    # exits 0 whatever the artefact says. B6.4 passes; B6.5 is what must catch it.
    repo1, _, base1, head1 = refresh("B-blind-verifier",
                                     declaration(argv=["python3", "-c", "raise SystemExit(0)"]))
    rc1, rec1 = issue(repo1, base1, head1)
    a1 = arms_of(repo1, base1, head1)
    check("(1) MUTANT: a declared artefact whose verifier does NOT bind it (a command that exits 0 whatever "
          "the bytes say) is REFUSED — B6.4 alone would have passed it; B6.5 corrupts one byte and the "
          "verifier must refuse. A declaration is a claim; this is a mutant of the claim",
          not admitted(rc1, rec1) and a1.get("B6.5") == "failed" and a1.get("B6.4") == "verified",
          rc=rc1, admission=rec1["admission"]["verdict"], arms=a1)

    # ---- MUTANT 2 (the brief's «a declaration that covers source files»)
    def edit_source(repo: Path):
        (repo / "src/a.ts").write_text("export const a = 99;  // smuggled through a bundle refresh\n")
    repo2, _, base2, head2 = refresh("C-source", declaration(paths=(ART, "src/a.ts")), extra=edit_source)
    rc2, rec2 = issue(repo2, base2, head2)
    a2 = arms_of(repo2, base2, head2)
    check("(2) MUTANT: a declaration that covers SOURCE is REFUSED — B6.3 measures the impact of the declared "
          "paths on a graph rebuilt AT HEAD and src/a.ts has dependents, for which a self-update receipt "
          "carries no verdicts. The declaration cannot shrink a blast radius",
          not admitted(rc2, rec2) and a2.get("B6.3") == "failed",
          rc=rc2, admission=rec2["admission"]["verdict"], arms=a2)

    # ---- MUTANT 3 (the brief's «a hand-edited "regenerated" artefact»)
    def hand_edit(repo: Path):
        (repo / ART).write_text("0" * 64 + "\n")
    repo3, _, base3, head3 = refresh("D-handedited", declaration(), extra=hand_edit, regenerate=False)
    rc3, rec3 = issue(repo3, base3, head3)
    a3 = arms_of(repo3, base3, head3)
    check("(3) MUTANT: an artefact hand-edited to a value the verifier does not recompute is REFUSED (B6.4) — "
          "and note the framing this disposes of: a hand edit producing the CORRECT value simply IS the "
          "regeneration, so what is proved is that the bytes carry no free information",
          not admitted(rc3, rec3) and a3.get("B6.4") == "failed",
          rc=rc3, admission=rec3["admission"]["verdict"], arms=a3)

    # ---- MUTANT 4: the refresh edits the declaration itself — a licence written by the change it licenses
    def widen(repo: Path):
        (repo / DECL_REL).write_text(json.dumps(declaration(paths=(ART, "src/a.ts")), indent=1, sort_keys=True) + "\n")
    repo4, _, base4, head4 = refresh("E-selfwiden", declaration(), extra=widen)
    rc4, rec4 = issue(repo4, base4, head4)
    a4 = arms_of(repo4, base4, head4)
    check("(4) MUTANT: a refresh that EDITS the declaration is REFUSED (B6.1) — the licence in force is the "
          "one at BASE, and widening it is an ordinary change with an ordinary receipt",
          not admitted(rc4, rec4) and a4.get("B6.1") == "failed",
          rc=rc4, admission=rec4["admission"]["verdict"], arms=a4)

    # ---- MUTANT 5: the BOOTSTRAP clause must not widen B1 beyond the declaration file itself.
    # HISTORY, kept rather than quietly rewritten: this arm used to assert «a declaration that exists only
    # at HEAD licenses nothing, full stop». gate5b's bootstrap clause deliberately narrows that claim — a
    # BUNDLE REFRESH may add the declaration, because B1 has already proved every other path is
    # bundle-managed or the pin, so such a change may introduce the caller's DECLARATION but never its
    # VERIFIER. The old claim is not dropped, it is SPLIT: (control-3) is the case now admitted, (14) is the
    # ordinary-path case still refused, and this arm now guards the clause's edge — the refresh may add the
    # declaration and NOTHING ELSE besides the artefacts it declares. This is exactly the «check retained by
    # id but weakened in body» residual B4 cannot see, so it is written down here instead of being silent.
    def boot_and_smuggle(r: Path):
        (r / DECL_REL).parent.mkdir(parents=True, exist_ok=True)
        (r / DECL_REL).write_text(json.dumps(declaration(), indent=1, sort_keys=True) + "\n")
        (r / "src/b.ts").write_text("import { a } from './a';\nexport const b = a + 7;  // smuggled\n")
    repo5, g5, base5, head5 = refresh("F-bootstrap-smuggle", None, extra=boot_and_smuggle)
    rc5, rec5 = issue(repo5, base5, head5)
    a5 = arms_of(repo5, base5, head5)
    check("(5) MUTANT: the bootstrap clause does NOT widen B1 — a refresh that adds the declaration and also "
          "carries an undeclared path is still refused. The clause tolerates the declaration file itself and "
          "the artefacts it declares, and nothing else",
          not admitted(rc5, rec5) and a5.get("B1") == "failed",
          rc=rc5, admission=rec5["admission"]["verdict"], arms=a5)

    # ---- MUTANT 6: a declared path the refresh ADDS rather than refreshes
    def add_new(repo: Path):
        (repo / "data/extra.txt").write_text("a brand new file under a declared name\n")
    repo6, _, base6, head6 = refresh("G-added", declaration(paths=(ART, "data/extra.txt")), extra=add_new)
    rc6, rec6 = issue(repo6, base6, head6)
    a6 = arms_of(repo6, base6, head6)
    check("(6) MUTANT: a declared path the refresh ADDS is REFUSED (B6.2) — a derived artefact is refreshed, "
          "a new file is a new fact; this is what kills «declare a path, then create it as a backdoor»",
          not admitted(rc6, rec6) and a6.get("B6.2") == "failed",
          rc=rc6, admission=rec6["admission"]["verdict"], arms=a6)

    # ---- MUTANT 7: the declaration uses a glob
    repo7, _, base7, head7 = refresh("H-glob", declaration(glob=True))
    rc7, rec7 = issue(repo7, base7, head7)
    a7 = arms_of(repo7, base7, head7)
    check("(7) MUTANT: a GLOB in the declaration licenses nothing (B1 refuses the path, B6.1 refuses the "
          "declaration) — a glob is a licence whose extent is decided later, by whatever files happen to match",
          not admitted(rc7, rec7) and (a7.get("B1") == "failed" or a7.get("B6.1") == "failed"),
          rc=rc7, admission=rec7["admission"]["verdict"], arms=a7)

    # ---- MUTANT 8: the caller's own verifier job did not pass
    rc8, rec8 = issue(repo, base, head, concl="failure")
    a8 = arms_of(repo, base, head, concl="failure")
    check("(8) MUTANT: the same honest refresh with the caller's verifier job RED is refused (B6.6) — the "
          "artefact's freshness is the verifier's claim, and a failed verifier makes no claim",
          not admitted(rc8, rec8) and a8.get("B6.6") == "failed",
          rc=rc8, admission=rec8["admission"]["verdict"], arms=a8)

    # ---- MUTANT 9: the declaration names a different job than the one that ran
    rc9, rec9 = issue(repo, base, head, job="some-other-job")
    a9 = arms_of(repo, base, head, job="some-other-job")
    check("(9) MUTANT: an artefact vouched for by a job that is NOT the one the workflow ran is refused (B6.6)",
          not admitted(rc9, rec9) and a9.get("B6.6") == "failed",
          rc=rc9, admission=rec9["admission"]["verdict"], arms=a9)

    # ---- MUTANT 10: B6 must not have widened B1 — an undeclared file carried alongside still refuses
    def smuggle(repo: Path):
        (repo / "src/b.ts").write_text("import { a } from './a';\nexport const b = a + 2;\n")
    repo10, _, base10, head10 = refresh("I-undeclared", declaration(), extra=smuggle)
    rc10, rec10 = issue(repo10, base10, head10)
    a10 = arms_of(repo10, base10, head10)
    check("(10) MUTANT: an UNDECLARED file carried beside the bundle is still refused (B1) — B6 widened the "
          "shape rule by exactly the declared set and by nothing else",
          not admitted(rc10, rec10) and a10.get("B1") == "failed",
          rc=rc10, admission=rec10["admission"]["verdict"], arms=a10)

    # ---- MUTANT 11: a hand-written exemption over the same abuse, with a CORRECT change binding — C16
    forged = receipt_for(repo2, base2, head2)
    synth = f"gate_self_update:Arcanada-one/fixture@{head2[:12]}"
    forged["verdicts"] = [{"entity": synth, "verdict": "not_measured", "reason": "forged"}]
    forged["exemptions"] = [{"entity": synth, "code": "GATE_SELF_UPDATE", "owner": "an attacker",
                             "expires_at_utc": "2027-01-01T00:00:00Z",
                             "reason": "claims a declared derived artefact",
                             "change_binding": {"base": base2, "head": head2,
                                                "digest": admit_change.diff_digest(repo2, base2, head2)}}]
    forged["admission"] = {"verdict": "admitted_with_exemptions", "rule": "claimed"}
    d11 = root / "ci-forged"
    d11.mkdir(parents=True, exist_ok=True)
    (d11 / "body.txt").write_text("```json\n" + json.dumps(forged, indent=1, sort_keys=True) + "\n```\n")
    out11 = d11 / "result.json"
    rc11 = cmd_run(argparse.Namespace(
        repo=str(repo2), repo_name="Arcanada-one/fixture", tools=str(repo2 / ".github/graph-admission"),
        program_ref="1" * 40, base=base2, head=head2, pr_body_file=str(d11 / "body.txt"),
        receipt_glob=["receipts/graph/*.json"], enforcement="off", build_graph=False,
        workdir=str(d11 / "work"), out=str(out11), summary=None, signing_key_fingerprint=BASE_FP,
        verifier_job="lint-and-test", verifier_conclusion="success"))
    doc11 = json.loads(out11.read_text())
    check("(11) MUTANT: the source-covering abuse with a HAND-WRITTEN exemption whose change binding is "
          "CORRECT is refused by C16 — the gate re-measures B6 itself and does not accept the receipt's word",
          rc11 != 0 and "STRUCTURAL_EXEMPTION_UNSOUND" in doc11["reason_codes"],
          rc=rc11, verdict=doc11["verdict"], codes=doc11["reason_codes"])

    # ---------------------------------------------------------------- the ORDINARY path (no bundle refresh)
    # muneral is the proof this is needed: its evidence binds the whole tracked tree, so EVERY change drags
    # the regenerated artefact — an all-new-files change included. The tolerance is the same set and the same
    # six arms; only the case around it differs.
    def ordinary(name: str, decl: dict | None, *, edit=None, regenerate: bool = True):
        repo_o, g_o, base_o = new_repo(name, decl)
        if edit:
            edit(repo_o)
        (repo_o / "src/new1.ts").write_text("export const n1 = 1;\n")
        g_o("add", "-A")
        if regenerate:
            (repo_o / ART).write_text(_tracked_tree_digest(repo_o, ART) + "\n")
            g_o("add", "-A")
        g_o("commit", "-q", "-m", "an ordinary change that drags the derived artefact")
        return repo_o, g_o, base_o, g_o("rev-parse", "HEAD").strip()

    repo12, _, base12, head12 = ordinary("J-ordinary", declaration())
    rc12, rec12 = issue(repo12, base12, head12)
    a12 = arms_of2(repo12, base12, head12)
    check("(control-2) CONTROL: an ORDINARY all-new-files change that also carries the declared derived "
          "artefact is admitted under NO_IMPACT_BY_CONSTRUCTION — without this every change to a repository "
          "whose evidence binds its whole tree is permanently paused_safe, which is muneral exactly",
          rc12 == 0 and rec12["admission"]["verdict"] == "admitted_with_exemptions"
          and all(a12.get(k) == "verified" for k in ("A1", "B6.1", "B6.4", "B6.5")),
          rc=rc12, admission=rec12["admission"]["verdict"], arms=a12)

    repo13, _, base13, head13 = ordinary("K-ordinary-blind",
                                         declaration(argv=["python3", "-c", "raise SystemExit(0)"]))
    rc13, rec13 = issue(repo13, base13, head13)
    a13 = arms_of2(repo13, base13, head13)
    check("(12) MUTANT: the same ordinary change with a verifier that does NOT bind the artefact is refused "
          "(B6.5) — the tolerance travels with its measurement, not without it",
          rc13 != 0 and a13.get("B6.5") == "failed",
          rc=rc13, admission=rec13["admission"]["verdict"], arms=a13)

    def smuggle_o(repo: Path):
        (repo / "src/a.ts").write_text("export const a = 42;  // an ordinary edit beside the new file\n")
    repo14, _, base14, head14 = ordinary("L-ordinary-smuggle", declaration(), edit=smuggle_o)
    rc14, rec14 = issue(repo14, base14, head14)
    a14 = arms_of2(repo14, base14, head14)
    check("(13) MUTANT: an UNDECLARED edit beside the new files is still refused (A1) — the tolerance widened "
          "A1 by exactly the declared set and by nothing else",
          rc14 != 0 and a14.get("A1") == "failed",
          rc=rc14, admission=rec14["admission"]["verdict"], arms=a14)

    # ------------------------------------------------ the BOOTSTRAP: how the declaration ever lands at all
    # Measured on muneral, not predicted: its ruleset requires BOTH `lint-and-test` (red until the evidence
    # is rewritten) AND `graph-admission` (which refuses the rewrite until a declaration exists at base), so
    # without this clause the declaration can never land and the mutual exclusion is permanent. The clause
    # is admissible ONLY on a bundle refresh, where B1 has already proved every other path is bundle-managed
    # or the pin: such a change may introduce the caller's DECLARATION, never its VERIFIER.
    repo15, _, base15, head15 = refresh("M-bootstrap", None, extra=lambda r: (
        (r / DECL_REL).parent.mkdir(parents=True, exist_ok=True),
        (r / DECL_REL).write_text(json.dumps(declaration(), indent=1, sort_keys=True) + "\n")))
    rc15, rec15 = issue(repo15, base15, head15)
    a15 = arms_of(repo15, base15, head15)
    check("(control-3) BOOTSTRAP: a bundle refresh that ADDS the declaration and carries the artefact it "
          "declares is admitted — the only way the first declaration can ever land in a repository whose "
          "required suite is red until the artefact is rewritten",
          admitted(rc15, rec15) and all(a15.get(k) == "verified"
                                        for k in ("B1", "B6.1", "B6.2", "B6.3", "B6.4", "B6.5", "B6.6")),
          rc=rc15, admission=rec15["admission"]["verdict"], arms=a15)

    repo16, _, base16, head16 = ordinary("N-ordinary-bootstrap", None, edit=lambda r: (
        (r / DECL_REL).parent.mkdir(parents=True, exist_ok=True),
        (r / DECL_REL).write_text(json.dumps(declaration(), indent=1, sort_keys=True) + "\n")))
    rc16, rec16 = issue(repo16, base16, head16)
    a16 = arms_of2(repo16, base16, head16)
    check("(14) MUTANT: an ORDINARY change that adds the declaration and uses it in the same breath is "
          "REFUSED — there A1 permits arbitrary ADDED files, so the change could ship its own verifier, and "
          "the bootstrap clause deliberately does not reach that case",
          rc16 != 0 and a16.get("B6.1") == "failed",
          rc=rc16, admission=rec16["admission"]["verdict"], arms=a16)

    print(f"\nGATE5B SELFTEST {'PASS' if not red else 'FAIL'}: {len(checks) - red}/{len(checks)} checks, "
          f"{len(checks) - 3} mutants")
    shutil.rmtree(root, ignore_errors=True)
    return checks, red


def selftest_b7() -> tuple[list[dict], int]:
    """AUP-DEBT-002 Card 1 — B7, DEC-AUP-0020. Sixth battery. Amending
    `.arcana/derived-artefacts.v1.json` ITSELF, on its own narrow admission arm — never a general fix
    to the graph-impact path. Reuses the real gate code (admit_change.py's `b7_*` helpers and
    `evaluate_declaration_amend`), not a mock, on a scratch git repository built for this battery.

    Every mutant below is a diff, or an authority pairing, that DEC-AUP-0020 says MUST be refused —
    at least one per binding property (closed diff grammar; mandatory dry-run replay; a second,
    independent authority; absolute refusal of grant-and-spend in one commit/PR) — plus two positive
    controls (a legitimate ADD, and a legitimate REMOVE) that must be admitted. A survivor here is a
    HOLE, reported as one, never accommodated by weakening the mutant."""
    import tempfile
    root = Path(tempfile.mkdtemp(prefix="b7-selftest-"))
    checks, red = [], 0

    def check(name, ok, **kw):
        nonlocal red
        checks.append({"name": name, "ok": bool(ok), **kw})
        if not ok:
            red += 1
        print(("ok   " if ok else "FAIL ") + name
              + ("" if ok else "  " + json.dumps(kw, ensure_ascii=False, default=str)[:600]))

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import admit_change as ac  # noqa: E402

    ENV = {"GIT_AUTHOR_NAME": "f", "GIT_AUTHOR_EMAIL": "f@x", "GIT_COMMITTER_NAME": "f",
           "GIT_COMMITTER_EMAIL": "f@x", "GIT_AUTHOR_DATE": "2026-09-07T00:00:00Z",
           "GIT_COMMITTER_DATE": "2026-09-07T00:00:00Z", "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    DECL_REL = ac.DEFAULT_DECLARATION_REL
    VERIFY_SRC = ("import pathlib, sys\n"
                  "d = pathlib.Path('data/derived2.txt').read_bytes()\n"
                  "s = pathlib.Path('data/source2.txt').read_bytes()\n"
                  "sys.exit(0 if d == s else 1)\n")
    NOOP_VERIFY_SRC = "import sys\nsys.exit(0)\n"  # the ["true"] shape — never binds anything

    repo = root / "repo"
    repo.mkdir(parents=True)
    env = {**ENV, "HOME": str(repo)}

    def g(*a):
        r = subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, env=env)
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(a)}: {r.stderr[:300]}")
        return r.stdout

    g("init", "-q", "-b", "main")
    (repo / "src").mkdir()
    (repo / "src/a.ts").write_text("export const a = 1;\n")
    (repo / "data").mkdir()
    for stem, content in (("", "hello\n"), ("2", "world\n"), ("3", "x\n")):
        (repo / f"data/source{stem}.txt").write_text(content)
        (repo / f"data/derived{stem}.txt").write_text(content)
    (repo / "tools").mkdir()
    (repo / "tools/verify_derived.py").write_text(VERIFY_SRC)
    (repo / "tools/verify_noop.py").write_text(NOOP_VERIFY_SRC)
    base_artefacts = [{"path": "data/derived.txt", "verified_by_job": "lint-and-test",
                       "verify": {"argv": ["python3", "tools/verify_derived.py"]}}]
    (repo / DECL_REL).parent.mkdir(parents=True, exist_ok=True)
    (repo / DECL_REL).write_text(json.dumps({"schema": ac.DECLARATION_SCHEMA, "artefacts": base_artefacts},
                                            indent=1, sort_keys=True) + "\n")
    g("add", "-A")
    g("commit", "-q", "-m", "base")
    base = g("rev-parse", "HEAD").strip()

    def amend_from(parent: str, artefacts: list, msg: str) -> str:
        g("checkout", "-q", parent)
        (repo / DECL_REL).write_text(json.dumps({"schema": ac.DECLARATION_SCHEMA, "artefacts": artefacts},
                                                indent=1, sort_keys=True) + "\n")
        g("add", "-A")
        g("commit", "-q", "-m", msg)
        h = g("rev-parse", "HEAD").strip()
        g("checkout", "-q", "main")
        return h

    def candidate_from(parent: str, edits, msg: str) -> str:
        g("checkout", "-q", parent)
        edits(repo)
        g("add", "-A")
        g("commit", "-q", "-m", msg)
        h = g("rev-parse", "HEAD").strip()
        g("checkout", "-q", "main")
        return h

    def opine(b, h, *, authority_id: str, candidate_range: str | None) -> dict:
        files = ac.range_files(repo, b, h)
        ev = ac.evaluate_declaration_amend(repo, b, h, files, root / f"wd-opine-{authority_id}",
                                           candidate_range=candidate_range, authority_id=authority_id,
                                           second_opinion=None, verifier_job="lint-and-test",
                                           verifier_conclusion="success")
        relevant = [c for c in ev["checks"] if c["code"] != "SECOND_AUTHORITY"]
        verdict = ("verified" if relevant and all(c["verdict"] == "verified" for c in relevant) else
                  ("failed" if any(c["verdict"] == "failed" for c in relevant) else "not_measured"))
        return {"schema": "B7SecondOpinion/v1", "authority_id": authority_id, "base": b, "head": h,
               "change_digest": ev.get("change_digest"), "candidate_range": candidate_range,
               "op": ev.get("op"), "grammar": ev.get("grammar"), "verdict": verdict, "checks": relevant}

    # ==== positive control 1 — a legitimate ADD, dry-run replayed, two distinct authorities ====
    cand_head = candidate_from(base, lambda r: (
        (r / "data/source2.txt").write_text("world v2\n"), (r / "data/derived2.txt").write_text("world v2\n")),
        "candidate: regenerate derived2 from source2")
    add_entry = {"path": "data/derived2.txt", "verified_by_job": "lint-and-test",
                "verify": {"argv": ["python3", "tools/verify_derived.py"]}}
    add_head = amend_from(base, base_artefacts + [add_entry], "declare data/derived2.txt")
    second = opine(base, add_head, authority_id="reviewer-2", candidate_range=f"{base}..{cand_head}")
    add_files = ac.range_files(repo, base, add_head)
    add_case, _ = ac.structural_case(repo, base, add_head, add_files)
    primary = ac.evaluate_declaration_amend(repo, base, add_head, add_files, root / "wd-control",
                                            candidate_range=f"{base}..{cand_head}", authority_id="primary-1",
                                            second_opinion=second, verifier_job="lint-and-test",
                                            verifier_conclusion="success")
    check("(control-1) a legitimate ADD, dry-run replayed against the real candidate diff it motivates, with a "
         "second, distinct authority's independent re-derivation -> ELIGIBLE (admitted)",
         add_case == "declaration_amend" and primary["eligible"],
         case=add_case, checks=primary["checks"])

    # ==== positive control 2 — a legitimate REMOVE, exempt from the dry-run requirement (rule 5) ====
    rm_head = amend_from(base, [], "remove data/derived.txt from the declaration")
    rm_files = ac.range_files(repo, base, rm_head)
    rm_case, _ = ac.structural_case(repo, base, rm_head, rm_files)
    rm_second = opine(base, rm_head, authority_id="reviewer-2", candidate_range=None)
    rm_primary = ac.evaluate_declaration_amend(repo, base, rm_head, rm_files, root / "wd-control-rm",
                                               candidate_range=None, authority_id="primary-1",
                                               second_opinion=rm_second)
    check("(control-2) a legitimate REMOVE is exempt from the dry-run requirement (DEC-AUP-0020 rule 5) and is "
         "admitted on the closed-grammar + second-authority checks alone",
         rm_case == "declaration_amend" and rm_primary["eligible"],
         case=rm_case, checks=rm_primary["checks"])

    # ==== property 1: closed diff grammar (rule 3) ====
    glob_entry = {"path": "data/generated/*.txt", "verified_by_job": "lint-and-test",
                 "verify": {"argv": ["python3", "tools/verify_noop.py"]}}
    with_glob_head = amend_from(base, base_artefacts + [glob_entry], "declare data/generated/*.txt (fixture)")
    widen_head = amend_from(with_glob_head, base_artefacts + [{**glob_entry, "path": "data/**"}],
                            "WIDEN data/generated/*.txt -> data/**")
    widen_files = ac.range_files(repo, with_glob_head, widen_head)
    widen_ev = ac.evaluate_declaration_amend(repo, with_glob_head, widen_head, widen_files, root / "wd-widen")
    check("mutant (grammar-widen) widening `data/generated/*.txt` -> `data/**` is refused, not approximated "
         "(DEC-AUP-0020 rule 3: widening a glob is not narrowing)",
         not widen_ev["eligible"] and any(c["code"] == "GRAMMAR" and c["verdict"] == "failed"
                                          for c in widen_ev["checks"]),
         checks=widen_ev["checks"])

    bundle_head = amend_from(base, [{**base_artefacts[0], "verify": {"argv": ["python3", "tools/verify_noop.py"]}},
                                    add_entry], "add data/derived2.txt AND edit derived.txt's verify, together")
    bundle_files = ac.range_files(repo, base, bundle_head)
    bundle_ev = ac.evaluate_declaration_amend(repo, base, bundle_head, bundle_files, root / "wd-bundle")
    check("mutant (grammar-bundled) adding a new entry AND editing an existing entry's verify/setup in the SAME "
         "diff is refused (DEC-AUP-0020 rule 3 forbids bundling)",
         not bundle_ev["eligible"] and any(c["code"] == "GRAMMAR" and c["verdict"] == "failed"
                                           for c in bundle_ev["checks"]),
         checks=bundle_ev["checks"])

    # ==== property 1b: no bare wildcard / no glob covering a graph source root (rule 3's abuse case) ====
    srcglob_entry = {"path": "src/**", "verified_by_job": "lint-and-test",
                     "verify": {"argv": ["python3", "tools/verify_noop.py"]}}
    srcglob_head = amend_from(base, base_artefacts + [srcglob_entry], "declare src/** (the contract's own abuse case)")
    srcglob_files = ac.range_files(repo, base, srcglob_head)
    srcglob_ev = ac.evaluate_declaration_amend(repo, base, srcglob_head, srcglob_files, root / "wd-srcglob")
    check("mutant (scope) declaring `src/**` — a graph source root — is refused outright (DEC-AUP-0020 rule 3's "
         "own abuse case)",
         not srcglob_ev["eligible"] and any(c["code"] == "SCOPE" and c["verdict"] == "failed"
                                            for c in srcglob_ev["checks"]),
         checks=srcglob_ev["checks"])

    # ==== property 2: mandatory dry-run replay (rule 4) ====
    no_cand_ev = ac.evaluate_declaration_amend(repo, base, add_head, add_files, root / "wd-nocand",
                                               candidate_range=None, authority_id="primary-1",
                                               second_opinion=second, verifier_job="lint-and-test",
                                               verifier_conclusion="success")
    check("mutant (dry-run missing) no --b7-candidate-range given for an ADD -> not eligible (not_measured is "
         "not a pass)",
         not no_cand_ev["eligible"],
         checks=no_cand_ev["checks"])

    weak_cand_head = candidate_from(base, lambda r: (r / "data/derived3.txt").write_text("tampered\n"),
                                    "candidate: touch derived3 under a verifier that binds nothing")
    weak_entry = {"path": "data/derived3.txt", "verified_by_job": "lint-and-test",
                 "verify": {"argv": ["python3", "tools/verify_noop.py"]}}
    weak_amend_head = amend_from(base, base_artefacts + [weak_entry], "declare data/derived3.txt (weak verifier)")
    weak_files = ac.range_files(repo, base, weak_amend_head)
    weak_ev = ac.evaluate_declaration_amend(repo, base, weak_amend_head, weak_files, root / "wd-weak",
                                            candidate_range=f"{base}..{weak_cand_head}", authority_id="primary-1",
                                            second_opinion=None, verifier_job="lint-and-test",
                                            verifier_conclusion="success")
    check("mutant (dry-run weak-verifier) a verifier that never refuses a corrupted artefact (the `[\"true\"]` "
         "shape) is caught by B6.5 INSIDE the replay -> DRY_RUN fails, not eligible",
         not weak_ev["eligible"] and any(c["code"] == "DRY_RUN" and c["verdict"] == "failed"
                                         for c in weak_ev["checks"]),
         checks=weak_ev["checks"])

    # ==== property 3: a second, independent authority (rule 7 / reverse_if #2) ====
    no_second_ev = ac.evaluate_declaration_amend(repo, base, add_head, add_files, root / "wd-nos2",
                                                 candidate_range=f"{base}..{cand_head}", authority_id="primary-1",
                                                 second_opinion=None, verifier_job="lint-and-test",
                                                 verifier_conclusion="success")
    check("mutant (second-authority missing) no --b7-second-opinion given -> not eligible",
         not no_second_ev["eligible"], checks=no_second_ev["checks"])

    same_id_ev = ac.evaluate_declaration_amend(repo, base, add_head, add_files, root / "wd-sameid",
                                               candidate_range=f"{base}..{cand_head}", authority_id="primary-1",
                                               second_opinion={**second, "authority_id": "primary-1"},
                                               verifier_job="lint-and-test", verifier_conclusion="success")
    check("mutant (second-authority same-id) primary and 'second' opinion share ONE authority_id -> refused "
         "(reverse_if #2: a degraded single-body amendment is the exact failure DEC-AUP-0020 names as grounds "
         "to reopen the decision)",
         not same_id_ev["eligible"] and any(c["code"] == "SECOND_AUTHORITY" and c["verdict"] == "failed"
                                            for c in same_id_ev["checks"]),
         checks=same_id_ev["checks"])

    stale_ev = ac.evaluate_declaration_amend(repo, base, add_head, add_files, root / "wd-stale",
                                             candidate_range=f"{base}..{cand_head}", authority_id="primary-1",
                                             second_opinion={**second, "change_digest": "0" * 64},
                                             verifier_job="lint-and-test", verifier_conclusion="success")
    check("mutant (second-authority stale) the second opinion is bound to a DIFFERENT diff digest — a stale or "
         "forged vouch — -> refused",
         not stale_ev["eligible"] and any(c["code"] == "SECOND_AUTHORITY" and c["verdict"] == "failed"
                                          for c in stale_ev["checks"]),
         checks=stale_ev["checks"])

    # ==== property 4: absolute refusal of grant-and-spend in one commit/PR (rule 6) ====
    gs_head = candidate_from(base, lambda r: (
        (r / DECL_REL).write_text(json.dumps({"schema": ac.DECLARATION_SCHEMA,
                                              "artefacts": base_artefacts + [add_entry]},
                                             indent=1, sort_keys=True) + "\n"),
        (r / "data/source2.txt").write_text("grant-and-spend\n"),
        (r / "data/derived2.txt").write_text("grant-and-spend\n")),
        "grant AND spend the exemption in one commit")
    gs_files = ac.range_files(repo, base, gs_head)
    gs_case, gs_cev = ac.structural_case(repo, base, gs_head, gs_files)
    check("mutant (grant-and-spend) a diff that BOTH adds a declaration entry AND uses it in the SAME commit is "
         "NEVER classified declaration_amend — it falls to the ordinary rule, where B6.1 refuses a declaration "
         "changed in the same diff it is relied on (DEC-AUP-0020 rule 6, structurally enforced)",
         gs_case is None,
         case=gs_case, reason=gs_cev.get("reason"))

    print(f"\nB7 SELFTEST {'PASS' if not red else 'FAIL'}: {len(checks) - red}/{len(checks)} checks, "
          f"{len(checks) - 2} mutants, 2 positive controls")
    shutil.rmtree(root, ignore_errors=True)
    return checks, red


def selftest_gate2b() -> tuple[list[dict], int]:
    """AUP-GRAPH-006:gate2b — the bundle stops being a tripwire and becomes a signature.

    gate1's mutant (j) — rewrite a vendored tool AND its BUNDLE.json entry so the sha256 map stays
    consistent — was caught by `BUNDLE_MODIFIED_BY_PR`, a rule about the SHAPE OF THE DIFF, never by
    verification. That rule cannot see a tamper that is already in the base tree. These fixtures put
    the tamper in the BASE commit, where the diff rule is blind by construction, and measure what the
    signature does about it.
    """
    import tempfile
    root = Path(tempfile.mkdtemp(prefix="gate2b-selftest-"))
    checks, red = [], 0

    def check(name, ok, **kw):
        nonlocal red
        checks.append({"name": name, "ok": bool(ok), **kw})
        if not ok:
            red += 1
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + json.dumps(kw, ensure_ascii=False)[:400]))

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import admit_change  # noqa: E402

    pristine = root / "pristine-bundle"
    cmd_bundle(argparse.Namespace(out=str(pristine), program_ref="0" * 40, workflow_out=None, sign_key=None))
    FP = sign_bundle(pristine)
    OTHER_FP = sshsig.fingerprint(sshsig.SUPPORTED_KEY_TYPE, sshsig.ed25519_keypair(SELFTEST_OTHER_SEED)[1])

    def scenario(name: str, mutate=None, pin: str | None = FP) -> dict:
        """A repository whose BASE COMMIT already carries the bundle (mutated or not), and a pull
        request that touches only src/ — so BUNDLE_MODIFIED_BY_PR can never fire."""
        d = root / name
        repo = d / "repo"
        repo.mkdir(parents=True)
        env = {"GIT_AUTHOR_NAME": "f", "GIT_AUTHOR_EMAIL": "f@x", "GIT_COMMITTER_NAME": "f",
               "GIT_COMMITTER_EMAIL": "f@x", "GIT_AUTHOR_DATE": "2026-09-05T00:00:00Z",
               "GIT_COMMITTER_DATE": "2026-09-05T00:00:00Z",
               "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(d)}

        def g(*a):
            r = subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, env=env)
            if r.returncode != 0:
                raise RuntimeError(f"git {' '.join(a)}: {r.stderr[:200]}")
            return r.stdout

        g("init", "-q", "-b", "main")
        (repo / "src").mkdir()
        (repo / "src/a.ts").write_text("export const a = 1;\n")
        (repo / ".github").mkdir()
        tools = repo / ".github/graph-admission"
        shutil.copytree(pristine, tools)
        if mutate:
            mutate(tools)
        g("add", "-A"); g("commit", "-q", "-m", "base, bundle already installed")
        base = g("rev-parse", "HEAD").strip()
        (repo / "src/a.ts").write_text("export const a = 2;\n")
        g("add", "-A"); g("commit", "-q", "-m", "an ordinary change that does not touch the bundle")
        head = g("rev-parse", "HEAD").strip()
        (d / "body.txt").write_text("")
        out = d / "result.json"
        rc = cmd_run(argparse.Namespace(
            repo=str(repo), repo_name="Arcanada-one/fixture", tools=str(tools), program_ref="0" * 40,
            base=base, head=head, pr_body_file=str(d / "body.txt"), receipt_glob=["receipts/graph/*.json"],
            enforcement="off", build_graph=False, workdir=str(d / "work"), out=str(out), summary=None,
            signing_key_fingerprint=pin))
        doc = json.loads(out.read_text())
        doc["_rc"] = rc
        doc["_touched_bundle"] = "BUNDLE_MODIFIED_BY_PR" in doc["reason_codes"]
        return doc

    # ---------------------------------------------------------------- fixture 1: valid signature
    valid = scenario("valid")
    check("valid signature + pinned key: the bundle is trusted (no BUNDLE_* refusal)",
          not any(c["code"].startswith("BUNDLE_") and c["verdict"] == "refuse" for c in valid["checks"])
          and (valid["bundle"]["signature"] or {}).get("verified") is True
          and any(c["code"] == "BUNDLE_SIGNATURE_VERIFIED" for c in valid["checks"]),
          codes=valid["reason_codes"], sig=valid["bundle"]["signature"])
    check("the pull request does NOT touch the bundle, so the gate1 diff-shape rule cannot fire here "
          "— whatever the signature catches below, it catches on its own",
          not valid["_touched_bundle"])

    # ---------------------------------------------------------------- fixture 2: the consistent tamper
    def tamper_consistently(tools: Path):
        tp = tools / "tools/graph/admit_change.py"
        tp.write_text(tp.read_text() + "\n# an attacker's line\n")
        mp = tools / "BUNDLE.json"
        man = json.loads(mp.read_text())
        for f in man["files"]:
            if f["path"].endswith("admit_change.py"):
                f["sha256"] = sha256_file(tp)
        man["bundle_digest"] = "sha256:" + hashlib.sha256(
            json.dumps(man["files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        mp.write_text(json.dumps(man, indent=1, sort_keys=True) + "\n")

    tampered = scenario("tampered", tamper_consistently)
    check("a tampered tool WITH a consistent BUNDLE.json, already in the base tree → refused by the "
          "SIGNATURE (gate1 could only catch this when the pull request itself touched the bundle)",
          tampered["_rc"] != 0 and "BUNDLE_SIGNATURE_INVALID" in tampered["reason_codes"]
          and not tampered["_touched_bundle"],
          codes=tampered["reason_codes"], touched=tampered["_touched_bundle"])

    # ---------------------------------------------------------------- fixture 3: no signature
    def remove_signature(tools: Path):
        (tools / SIGNATURE_NAME).unlink()

    unsigned = scenario("unsigned", remove_signature)
    check("a bundle with no signature → refused (an unsigned bundle is never trusted on its own hashes)",
          unsigned["_rc"] != 0 and "BUNDLE_SIGNATURE_MISSING" in unsigned["reason_codes"],
          codes=unsigned["reason_codes"])

    def remove_pubkey(tools: Path):
        (tools / PUBKEY_NAME).unlink()

    nokey = scenario("nokey", remove_pubkey)
    check("a bundle with no public key → refused, not skipped",
          nokey["_rc"] != 0 and "BUNDLE_SIGNATURE_MISSING" in nokey["reason_codes"],
          codes=nokey["reason_codes"])

    # ---------------------------------------------------------------- fixture 4: the attacker re-signs
    def resign_with_own_key(tools: Path):
        tamper_consistently(tools)
        sign_bundle(tools, SELFTEST_OTHER_SEED)

    resigned = scenario("resigned", resign_with_own_key)
    check("a tamper re-signed with the ATTACKER's own key, public key swapped too → refused, because "
          "the caller pins a fingerprint OUTSIDE the bundle",
          resigned["_rc"] != 0 and "BUNDLE_SIGNATURE_UNTRUSTED_KEY" in resigned["reason_codes"],
          codes=resigned["reason_codes"])

    # …and the residual, measured rather than asserted: with NO pinned fingerprint it gets through.
    unpinned = scenario("resigned-unpinned", resign_with_own_key, pin=None)
    check("THE RESIDUAL, measured not claimed: the same attack with NO pinned fingerprint is NOT "
          "refused — and the check text says so as `not_measured`, never as a pass",
          not any(c["code"].startswith("BUNDLE_") and c["verdict"] == "refuse" for c in unpinned["checks"])
          and any(c["code"] == "BUNDLE_SIGNATURE_UNPINNED" and c["verdict"] == "not_measured"
                  for c in unpinned["checks"]),
          codes=unpinned["reason_codes"])

    # ---------------------------------------------------------------- fixture 5: wrong namespace
    def sign_other_namespace(tools: Path):
        sign_bundle(tools, SELFTEST_SEED, namespace="git")

    wrongns = scenario("wrong-namespace", sign_other_namespace)
    check("a signature by the RIGHT key over the right bytes but in another namespace (e.g. a `git` "
          "commit signature reused) → refused",
          wrongns["_rc"] != 0 and "BUNDLE_SIGNATURE_INVALID" in wrongns["reason_codes"],
          codes=wrongns["reason_codes"])

    # ---------------------------------------------------------------- the verifier vs the real ssh-keygen
    kg = shutil.which("ssh-keygen")
    if not kg:
        checks.append({"name": "cross-check against ssh-keygen", "ok": None,
                       "verdict": "not_measured", "reason": "no ssh-keygen on this host"})
        print("not_measured  cross-check against ssh-keygen: the binary is absent on this host")
    else:
        d = root / "xcheck"
        d.mkdir()
        pub = sshsig.ed25519_keypair(SELFTEST_SEED)[1]
        msg = b"cross-check message\n"
        (d / "m").write_bytes(msg)
        (d / "allowed").write_text("signer@fixture " + sshsig.public_key_line(pub, "x"))
        agree = []
        for alg in ("sha512", "sha256"):
            (d / "s.sig").write_text(sshsig.make_detached(SELFTEST_SEED, msg, SIGNING_NAMESPACE, alg))
            r = subprocess.run([kg, "-Y", "verify", "-f", str(d / "allowed"), "-I", "signer@fixture",
                                "-n", SIGNING_NAMESPACE, "-s", str(d / "s.sig")],
                               input=msg, capture_output=True)
            agree.append(r.returncode == 0)
        check("signatures this implementation PRODUCES are accepted by the real `ssh-keygen -Y verify` "
              "(sha512 and sha256)", all(agree), results=agree)
        # …and the other direction: ssh-keygen signs, this implementation verifies
        r = subprocess.run([kg, "-q", "-t", "ed25519", "-N", "", "-C", "x", "-f", str(d / "k")],
                           capture_output=True)
        both = []
        if r.returncode == 0:
            for alg in ("sha512", "sha256"):
                subprocess.run([kg, "-Y", "sign", "-q", "-f", str(d / "k"), "-n", SIGNING_NAMESPACE,
                                "-O", f"hashalg={alg}", str(d / "m")], capture_output=True)
                ok, _, _ = sshsig.verify_detached(msg, (d / "m.sig").read_text(),
                                                  (d / "k.pub").read_text(), SIGNING_NAMESPACE)
                both.append(ok)
                (d / "m.sig").unlink()
            # a one-byte change to the message must break a REAL ssh-keygen signature under this verifier
            subprocess.run([kg, "-Y", "sign", "-q", "-f", str(d / "k"), "-n", SIGNING_NAMESPACE, str(d / "m")],
                           capture_output=True)
            bad, _, _ = sshsig.verify_detached(msg + b"!", (d / "m.sig").read_text(),
                                               (d / "k.pub").read_text(), SIGNING_NAMESPACE)
            check("signatures the real `ssh-keygen -Y sign` produces are accepted by this implementation, "
                  "and a one-byte change to the message breaks them", all(both) and not bad,
                  accepted=both, tampered_rejected=not bad)
        else:
            print("not_measured  ssh-keygen could not generate a key here")

    # AUP-GRAPH-006:gate3a — RE-SIGNING IN PLACE. `ssh-keygen -Y sign` prompts «Overwrite (y/n)?» when its output
    # file exists and, with no tty, exits 0 leaving the OLD signature. A bundle refresh would then ship a stale
    # signature over new bytes under a success exit code. Found by refreshing muneral's real bundle, not by reading.
    kg = shutil.which("ssh-keygen")
    if kg:
        d = root / "resign"
        d.mkdir(parents=True, exist_ok=True)
        subprocess.run([kg, "-q", "-t", "ed25519", "-N", "", "-C", "x", "-f", str(d / "k")], capture_output=True)
        msg1, msg2 = d / "m", d / "m"
        msg1.write_bytes(b"first bundle bytes\n")
        subprocess.run([kg, "-Y", "sign", "-q", "-f", str(d / "k"), "-n", SIGNING_NAMESPACE,
                        "-O", "hashalg=sha512", str(msg1)], capture_output=True)
        stale = (d / "m.sig").read_text()
        msg2.write_bytes(b"second bundle bytes\n")
        # (a) the pre-gate3a behaviour, reproduced: sign again WITHOUT removing the target
        r_noclean = subprocess.run([kg, "-Y", "sign", "-q", "-f", str(d / "k"), "-n", SIGNING_NAMESPACE,
                                    "-O", "hashalg=sha512", str(msg2)], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        kept_stale = (d / "m.sig").read_text() == stale
        ok_stale, _, _ = sshsig.verify_detached(msg2.read_bytes(), (d / "m.sig").read_text(),
                                                (d / "k.pub").read_text(), SIGNING_NAMESPACE)
        check("RE-SIGN TRAP: `ssh-keygen -Y sign` over an existing .sig exits 0 and keeps the STALE signature, "
              "which then does NOT verify over the new bytes — the defect gate3a fixes", 
              r_noclean.returncode == 0 and kept_stale and not ok_stale,
              exit_code=r_noclean.returncode, kept_stale=kept_stale, stale_verifies=ok_stale)
        # (b) the fix: remove the target first, exactly as cmd_bundle now does
        (d / "m.sig").unlink(missing_ok=True)
        subprocess.run([kg, "-Y", "sign", "-q", "-f", str(d / "k"), "-n", SIGNING_NAMESPACE,
                        "-O", "hashalg=sha512", str(msg2)], capture_output=True, stdin=subprocess.DEVNULL)
        ok_fresh, _, _ = sshsig.verify_detached(msg2.read_bytes(), (d / "m.sig").read_text(),
                                                (d / "k.pub").read_text(), SIGNING_NAMESPACE)
        check("re-signing after removing the target produces a signature that verifies over the NEW bytes "
              "(cmd_bundle unlinks it before signing, and still verifies what it produced)", ok_fresh)

    print(f"\nGATE2B SELFTEST {'PASS' if not red else 'FAIL'}: "
          f"{sum(1 for c in checks if c.get('ok')) }/{len([c for c in checks if c.get('ok') is not None])} "
          f"checks, {'0' if not red else red} failing")
    if not red:
        shutil.rmtree(root, ignore_errors=True)
    else:
        print(f"scratch kept at {root}")
    return checks, red


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=False)

    b = sub.add_parser("bundle", help="vendor the gate tools of a pinned program SHA into a caller repository")
    b.add_argument("--out", required=True)
    b.add_argument("--program-ref")
    b.add_argument("--workflow-out", help="also vendor .github/workflows/graph-admission.yml here (local `uses: ./…` calls)")
    b.add_argument("--sign-key", help="AUP-GRAPH-006:gate2b — Ed25519 private key (ssh-keygen format) to sign "
                                      "BUNDLE.json with. The key must live OUTSIDE any repository; its public "
                                      "half is written into the bundle and into the program repository.")
    b.set_defaults(fn=cmd_bundle)

    r = sub.add_parser("run", help="the pull-request check")
    r.add_argument("--repo", required=True)
    r.add_argument("--repo-name")
    r.add_argument("--tools", required=True, help="the vendored bundle directory")
    r.add_argument("--program-ref")
    r.add_argument("--base", required=True)
    r.add_argument("--head", required=True)
    r.add_argument("--pr-body-file")
    r.add_argument("--receipt-glob", action="append")
    r.add_argument("--enforcement", default="off", choices=["off", "ledger", "muneral"])
    r.add_argument("--build-graph", action="store_true")
    r.add_argument("--workdir", default=os.environ.get("RUNNER_TEMP", "/tmp") + "/graph-admission")
    r.add_argument("--out", default="graph-admission-result.json")
    r.add_argument("--summary")
    r.add_argument("--event-file", help="GITHUB_EVENT_PATH — the pull_request event payload; the automated-author "
                                        "path reads the author from it and from nothing else")
    r.add_argument("--verifier-job", help="the repository's own test job, verifier of a whole-repository impact")
    r.add_argument("--verifier-conclusion", help="that job's conclusion; absent/unknown is not_measured, never a pass")
    r.add_argument("--verifier-output-ref", help="URL the verdict can be traced to")
    r.add_argument("--signing-key-fingerprint", help="AUP-GRAPH-006:gate2b — the SHA256:… fingerprint the caller "
                                                     "trusts, set in the caller's OWN workflow file, outside the "
                                                     "bundle. Without it the signature proves self-consistency "
                                                     "only, and the check says so as not_measured.")
    r.set_defaults(fn=cmd_run)
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not getattr(a, "fn", None):
        ap.error("a subcommand or --selftest is required")
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
