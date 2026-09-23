"""Fail-closed source and probe validation shared by native canary consumers.

Integrity checks do not authenticate the measurement harness. Its source claim
is trusted evidence, explicitly scoped to the committed Git subject checked here.
"""
from __future__ import annotations
import os
import stat
import hashlib
import json
import re
import subprocess
from pathlib import Path
from datetime import datetime

RANK = {"verified": 0, "not_measured": 1, "failed": 2}
SOURCE_FIELDS = {
    "ReadinessReceipt/v1": "source_head",
    "ControlledAuthOidcFlagProof/v1": "source",
    "ControlledEmailVerificationProof/v1": "source",
    "MeasuredGitSource/v1": "commit",
}


MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 10


def read_regular(path):
    """Bounded descriptor read; reject FIFO/device/symlink before reading bytes."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_EVIDENCE_BYTES:
            raise ValueError("evidence is not a bounded regular file")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, MAX_EVIDENCE_BYTES + 1 - total))
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > MAX_EVIDENCE_BYTES:
                raise ValueError("evidence exceeded size limit during read")
            chunks.append(chunk)
    finally:
        os.close(fd)


def structure_errors(doc):
    errors = []
    if not isinstance(doc, dict) or doc.get("schema") not in ("CanaryResult/v1", "CanaryResult/v2"):
        return ["not a CanaryResult/v1 object"]
    if not isinstance(doc.get("environment"), str) or not doc["environment"]:
        errors.append("missing environment")
    if doc.get("phase") not in ("pre", "post"):
        errors.append("invalid phase")
    if not isinstance(doc.get("plan"), dict) or not isinstance(doc["plan"].get("id"), str) or not doc["plan"]["id"]:
        errors.append("missing plan id")
    if not isinstance(doc.get("read_only"), bool):
        errors.append("missing read_only")
    elif not doc["read_only"] and not doc.get("mutating_owner"):
        errors.append("missing mutating owner")
    timestamp = doc.get("captured_at_utc")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) if isinstance(timestamp, str) else None
        if parsed is None or parsed.tzinfo is None:
            errors.append("missing timezone-aware capture timestamp")
    except ValueError:
        errors.append("invalid capture timestamp")
    if "resident_version" not in doc or "model" not in doc:
        errors.append("missing required result metadata")
    probes = doc.get("probes")
    rows = doc.get("entity_verdicts")
    if not isinstance(probes, list) or not isinstance(rows, list):
        return errors + ["probes and entity_verdicts must be arrays"]
    by_id = {}
    for p in probes:
        if not isinstance(p, dict) or not isinstance(p.get("id"), str) or not p["id"]:
            errors.append("malformed probe")
            continue
        if p["id"] in by_id:
            errors.append("duplicate probe id")
        by_id[p["id"]] = p
        if not isinstance(p.get("outcome"), str) or p["outcome"] not in RANK:
            errors.append("invalid probe outcome")
        if doc.get("schema") == "CanaryResult/v2":
            if p.get("kind") == "process":
                import process_observation
                errors.extend(process_observation.result_errors(p))
                continue
            if p.get("kind") != "process":
                errors.append("v2 currently supports process observations only")
                continue
        elif p.get("kind") not in (None, "http"):
            errors.append("v1 supports HTTP observations only")
        status = p.get("status")
        if p.get("outcome") in ("verified", "failed") and (type(status) is not int or not 100 <= status <= 599):
            errors.append("measured probe lacks actual HTTP status")
        if p.get("outcome") == "verified" and (p.get("executed") is False or p.get("offline") is True):
            errors.append("unrun probe reported verified")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("entity"), str) or not row["entity"]:
            errors.append("malformed entity verdict")
            continue
        if row["entity"] in seen:
            errors.append("duplicate entity id")
        seen.add(row["entity"])
        if not isinstance(row.get("verdict"), str) or row["verdict"] not in RANK:
            errors.append("invalid entity verdict")
        if not isinstance(row.get("reason"), str):
            errors.append("entity reason must be a string")
        ids = row.get("probe_ids")
        if not isinstance(ids, list) or not ids or any(not isinstance(i, str) or i not in by_id for i in ids):
            errors.append("entity has missing probe references")
            continue
        if len(ids) != len(set(ids)):
            errors.append("duplicate entity probe references")
        outcomes = [by_id[i].get("outcome") for i in ids]
        if all(isinstance(o, str) and o in RANK for o in outcomes) and (row.get("verdict") == "verified" and any(o != "verified" for o in outcomes) or row.get("verdict") == "failed" and "failed" not in outcomes or row.get("verdict") == "not_measured" and "failed" in outcomes):
            errors.append("entity verdict contradicts cited probes")
    return errors


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, stderr=subprocess.DEVNULL, timeout=GIT_TIMEOUT_SECONDS).strip()


def source_errors(doc, path, repo, commit, *, dirty=False):
    if dirty:
        return ["dirty worktree has no supported immutable measured subject"]
    subject = doc.get("subject")
    if not isinstance(subject, dict) or subject.get("schema") != "GitCanarySubject/v1":
        return ["missing supported immutable source subject"]
    try:
        actual_commit = git(repo, "rev-parse", "--verify", commit + "^{commit}")
        actual_tree = git(repo, "rev-parse", "--verify", actual_commit + "^{tree}")
        if subject.get("commit") != actual_commit or subject.get("tree") != actual_tree:
            return ["measured subject differs from candidate commit/tree"]
        ref = subject.get("evidence")
        if not isinstance(ref, dict) or not isinstance(ref.get("path"), str) or not re.fullmatch(r"[0-9a-f]{64}", str(ref.get("sha256", ""))):
            return ["missing measured source evidence reference"]
        evidence_path = Path(ref["path"])
        if not evidence_path.is_absolute():
            evidence_path = Path(path).parent / evidence_path
        raw = read_regular(evidence_path)
        if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
            return ["measured source evidence digest mismatch"]
        evidence = json.loads(raw)
        if not isinstance(evidence, dict) or evidence.get("schema") not in SOURCE_FIELDS:
            return ["unsupported measured source evidence schema"]
        field = SOURCE_FIELDS[evidence["schema"]]
        if ref.get("source_field") != field or evidence.get(field) != actual_commit:
            return ["original measured source claim differs from candidate"]
        if evidence.get("schema") == "MeasuredGitSource/v1" and (evidence.get("tree") != actual_tree or evidence.get("dirty") is not False or not evidence.get("producer") or not evidence.get("captured_at_utc")):
            return ["incomplete measured Git source claim"]
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return ["measured source evidence cannot be verified"]
    return []


def consume(path, repo, commit, *, dirty=False):
    """Return normalized rows and errors; invalid evidence never yields PASS."""
    try:
        doc = json.loads(read_regular(path))
    except (OSError, ValueError):
        return {}, ["canary document cannot be read"], {}
    errors = structure_errors(doc)
    if not errors:
        source_path = doc.get("plan", {}).get("path", path) if doc.get("schema") == "CanaryResult/v2" else path
        if not isinstance(source_path, (str, os.PathLike)):
            errors = ["invalid original plan reference"]
        else:
            if doc.get("schema") == "CanaryResult/v2":
                source_path = Path(path).parent / source_path
            errors = source_errors(doc, source_path, repo, commit, dirty=dirty)
    if not errors and doc.get("schema") == "CanaryResult/v2":
        import process_observation
        errors = process_observation.bound_errors(doc, path, read_regular)
    if errors:
        return {}, errors, doc if isinstance(doc, dict) else {}
    return {r["entity"]: dict(r) for r in doc["entity_verdicts"]}, [], doc
