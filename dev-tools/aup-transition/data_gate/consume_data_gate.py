#!/usr/bin/env python3
"""AUP-MIG-015 `gate0` — data-gate consumer + cutover authority verifier.

Two independent verifiers and one minting rule (AUP-E25 § AUP-MIG-015, DEC-AUP-0012):

  1. the DATA verifier consumes the AUP-DAT-020 acceptance dossier at an exact revision and reads
     active / planned / completed / cancelled, unindexed and conflicts through THREE planes
     (files at the pinned SourceSetEpoch, the Muneral work-item store, the KB/Scrutator index);
  2. the AUTHORITY verifier reads the CURRENT state of the DEC-AUP-0012 evidence gate — issuer,
     action, resources/hosts, permitted target generation, expiry (`reverse_if`) and revocation
     (a later decision superseding it). Under DEC-AUP-0010/DEC-AUP-0012 the authority is a decision
     id plus its gate receipts; it is never a person and it is never minted here;
  3. a `CutoverReadinessAttestation/v1` is produced ONLY when both verifiers PASS, carries TWO refs
     (data receipt digest + authority = decision id and gate receipt digests), and leaves the writer
     epoch untouched. Anything else is a `BlockReceipt/v1` with typed reason codes.

Never a PASS by default: a missing plane, a hidden mount or cache, an `UNKNOWN`/not-measured cell, a
stale SourceSetEpoch or an invalid/revoked authority all block. A data PASS is not permission.

Read-only. Stdlib only. The only writes are the receipts under `--out`.
"""

from __future__ import annotations

import argparse
import copy
import fnmatch
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

TOOL = "tools/mig/data_gate/consume_data_gate.py"
TOOL_VERSION = "1.3.0"

# Versioned, reviewable rule tables. A change here is a rule change and bumps the revision.
CLASS_MAP_REV = 1
AUTHORITY_PROFILE_REV = 1

#: DEC-AUP-0015 routes MIG-015 (admission-critical, long-lived) to Opus 5. The tool reads no
#: environment variable for this: an undeclared config read is a real finding under DEC-AUP-0016,
#: and a model claim taken from the ambient environment would be no more verifiable than a literal.
DEFAULT_MODEL = "claude-opus-5"

# ---------------------------------------------------------------------------
# rule tables
# ---------------------------------------------------------------------------

#: the rows the spec's acceptance clause names. `archived` is carried as a row of its own and is
#: NEVER folded into `completed`: an archive card records that a card left the board, terminal and
#: unverified (DEC-AUP-0014 rule 3, I4 — no silent totalisation).
STATUS_CLASSES = ["active", "planned", "completed", "cancelled"]
CLASS_ROWS = STATUS_CLASSES + ["archived"]

#: the ONLY class table in this tool. Raw source values never appear here: they reach a class through
#: the versioned `HistoricalStatusMap` (contracts/status-mapping/), so the tool cannot quietly invent
#: a second, competing mapping of its own.
PROJECTED_TO_CLASS = {
    "in_progress": "active", "review": "active",
    "todo": "planned", "blocked": "planned",
    "done": "completed",
    "archived": "archived",
    "cancelled": "cancelled",
}

#: values DEC-AUP-0014 rule 1 types as "not a claim". The status map still projects them (onto
#: `todo`); they are counted and reported separately so the projection is never mistaken for a claim.
NO_CLAIM_RAW_VALUES = ["absent"]

PLANES = ["files", "muneral", "index"]

#: what the authority verifier expects to find IN the decision itself. Every string is checked
#: against the decision document; an assertion that cannot be found there is NOT_MEASURED (the
#: profile may never silently drift away from the decision it claims to read).
AUTHORITY_PROFILE = {
    "DEC-AUP-0012": {
        "action": "Muneral becomes the writer of record for work-item state",
        "resources": ["datarim/tasks.md", "datarim/backlog.md", "datarim/tasks/*.md"],
        "hosts": ["mac", "arcana-devs"],
        "target_generation": "MUNERAL_AUTHORITATIVE",
        "states": [
            "FILES_AUTHORITATIVE", "SHADOW_PROJECTION", "FROZEN", "FENCE_ENFORCED",
            "PROJECTION_VERIFIED", "DELTA_IMPORTED", "ROLLBACK_DRILLED", "SWITCHING",
            "MUNERAL_AUTHORITATIVE",
        ],
        # a cutover READINESS attestation may only be issued once the state machine stands at the
        # last state before the switch; SWITCHING itself is MIG-016's, not MIG-015's.
        "readiness_state_min": "ROLLBACK_DRILLED",
        "must_appear_in_decision": [
            "MUNERAL_AUTHORITATIVE", "ROLLBACK_DRILLED", "PAUSED_SAFE",
            "receipts/cutover/state.json",
        ],
    }
}

#: one probe per DEC-AUP-0012 evidence-gate item. `None` = no probe exists yet ⇒ NOT_MEASURED.
#: (glob, schema, min_count, extra predicate name)
EVIDENCE_GATE_PROBES = {
    "one receipt per state, digest-chained":
        ("receipts/cutover/*.json", None, 1, "state_chain"),
    "ShadowProjectionReceipt ×10 stable":
        ("receipts/projection/shadow*.json", "ShadowProjectionReceipt/v1", 10, None),
    "ProjectionParity/v1 twice, identical":
        ("receipts/projection/parity*.json", "ProjectionParity/v1", 2, "parity_pair"),
    "FenceProof (host rejection + ruleset refusal)":
        ("receipts/fence/fence-proof*.json", "FenceProof/v1", 1, None),
    "delta batch verify PASS":
        ("receipts/import/verify-*.json", "ReadinessReceipt/v1", 2, "second_batch"),
    "CutoverRollbackDrillReceipt/v1 ≤ 15 min + DB restore drill receipt":
        ("receipts/**/CutoverRollbackDrill*.json", "CutoverRollbackDrillReceipt/v1", 1, "restore_drill"),
    "WriterEpochReceipt/v1 present in program main and Muneral":
        ("receipts/**/writer-epoch*.json", "WriterEpochReceipt/v1", 1, None),
    "key-inventory receipt":
        ("receipts/**/key-inventory*.json", None, 1, None),
}

BLOCK = "BLOCK"
PASS = "PASS"
NOT_MEASURED = "NOT_MEASURED"

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


CONTRACT_NAME = "cutover-readiness-attestation.v1.json"
#: where a copy of this tool may keep its contract: the program layout, a landing copy that carries
#: the contract beside it, and a landing copy one directory up. A copy that reaches none of them
#: fails its own selftest rather than skipping the check.
CONTRACT_CANDIDATE_DIRS = [
    os.path.join("..", "..", "..", "contracts", "cutover"),
    ".",
    os.path.join("..", "contracts", "cutover"),
]


def find_contract():
    here = os.path.dirname(os.path.abspath(__file__))
    for d in CONTRACT_CANDIDATE_DIRS:
        cand = os.path.normpath(os.path.join(here, d, CONTRACT_NAME))
        if os.path.exists(cand):
            return cand
    return None


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def sha256_obj(obj) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def newest(paths):
    return sorted(paths)[-1] if paths else None


def rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


class Check:
    """One verifier question with a tri-valued answer. NOT_MEASURED is never a pass."""

    __slots__ = ("id", "verifier", "plane", "question", "verdict", "reason", "detail")

    def __init__(self, id, verifier, question, verdict, reason=None, detail=None, plane=None):
        self.id = id
        self.verifier = verifier
        self.plane = plane
        self.question = question
        self.verdict = verdict
        self.reason = reason
        self.detail = detail

    def as_dict(self):
        d = {
            "id": self.id,
            "verifier": self.verifier,
            "question": self.question,
            "verdict": self.verdict,
        }
        if self.plane:
            d["plane"] = self.plane
        if self.reason:
            d["reason_code"] = self.reason
        if self.detail is not None:
            d["detail"] = self.detail
        return d


# ---------------------------------------------------------------------------
# evidence collection (the only part that touches the filesystem)
# ---------------------------------------------------------------------------


def _git(root, *args):
    try:
        out = subprocess.run(["git", "-C", root] + list(args), capture_output=True, text=True,
                             timeout=30)
        return out.returncode, out.stdout.strip(), out.stderr.strip()
    except Exception as exc:  # pragma: no cover - environment failure is typed, not fatal
        return 127, "", str(exc)


def collect_evidence(root, ws_head=None, dossier_path=None, model=None):
    """Assemble the evidence dictionary the two verifiers read. Read-only."""
    ev = {
        "collected_at_utc": utcnow(),
        "root": root,
        "host": os.uname().nodename,
        "class_map_rev": CLASS_MAP_REV,
        # DEC-AUP-0015 chooses the model at a life boundary; the tool cannot measure which model
        # runs it, so the value is a DECLARED parameter of the invocation, never an observation.
        "model": model or DEFAULT_MODEL,
    }

    rc, head, _ = _git(root, "rev-parse", "HEAD")
    ev["program"] = {"commit": head if rc == 0 else None, "git_ok": rc == 0}

    # --- AUP-DAT-020 dossier at an exact revision -----------------------------
    acc_path = dossier_path or newest(glob.glob(os.path.join(root, "receipts/acceptance/acceptance0-*.json")))
    dossier = {"present": False}
    if acc_path and os.path.exists(acc_path):
        acc = read_json(acc_path)
        pin = acc.get("program_commit")
        rc, _, _ = _git(root, "cat-file", "-e", (pin or "") + "^{commit}")
        dossier = {
            "present": True,
            "path": rel(root, acc_path),
            "digest": sha256_file(acc_path),
            "captured_at_utc": acc.get("captured_at_utc"),
            "program_commit": pin,
            "revision_pinned": bool(pin) and bool(re.fullmatch(r"[0-9a-f]{40}", pin or "")),
            "revision_resolvable": rc == 0,
            "environment_host": acc.get("host"),
            "verdict": acc.get("verdict"),
            "global_complete": acc.get("global_complete"),
            "task_verdicts": acc.get("task_verdicts", {}),
            "coverage_source_commit": (acc.get("coverage", {}).get("permitted_corpus", {})
                                       .get("source_commit")),
            "unresolved_external_gaps": (acc.get("coverage", {})
                                         .get("unresolved_external_gaps", [])),
            "flag_counts": acc.get("flag_counts", {}),
        }
    ev["dossier"] = dossier

    # --- the import receipt: SourceSetEpoch, mapping, Muneral plane ------------
    imp_paths = sorted(glob.glob(os.path.join(root, "receipts/import/verify-*.json")))
    imp_path = newest(imp_paths)
    imp = read_json(imp_path) if imp_path else {}
    epoch_decl = imp.get("epoch")
    m = re.fullmatch(r"git:([\w.-]+/?[\w.-]*)@([0-9a-f]{40})", epoch_decl or "")
    ev["epoch"] = {
        "declared": epoch_decl,
        "repo": m.group(1) if m else None,
        "sha": m.group(2) if m else None,
        "pinned": bool(m),
        "source": rel(root, imp_path) if imp_path else None,
        "matches_dossier": bool(m) and m.group(2) == dossier.get("coverage_source_commit"),
    }

    # observed workspace main head — from the newest FenceObservationReceipt (read-only), never a
    # live fetch of the shared checkout.
    fence_paths = sorted(glob.glob(os.path.join(root, "receipts/fence/observation/fence-obs-*.json")))
    fence_latest = read_json(fence_paths[-1]) if fence_paths else {}
    observed_head = ws_head or (fence_latest.get("workspace", {}) or {}).get("head_commit")
    ev["epoch"]["observed_main_head"] = observed_head
    ev["epoch"]["observed_from"] = ("--ws-head argument" if ws_head else
                                    (rel(root, fence_paths[-1]) if fence_paths else None))
    ev["fence"] = {
        "hourly_receipts": len(fence_paths),
        "latest": rel(root, fence_paths[-1]) if fence_paths else None,
        "foreign_writes_latest": fence_latest.get("foreign_writes"),
        "canary_seen_latest": fence_latest.get("canary_seen"),
        "bake_hours_required": 72,  # DEC-AUP-0011: W = max(72 h, 3 × longest gap)
    }

    plan = imp.get("plan", {}) or {}
    readback = imp.get("readback", {}) or {}

    status_maps = _load_status_maps(root)
    batch_rev = (imp.get("status_map", {}) or {}).get("revision")
    record_rev = max(status_maps) if status_maps else None
    map_of_record = (status_maps.get(record_rev) or {}).get("map")
    map_of_batch = (status_maps.get(batch_rev) or {}).get("map")
    raw_dist = plan.get("raw_status_distribution", {})

    # the files plane is read through the map OF RECORD; the store plane is what the store actually
    # holds (produced under the batch's revision). Any difference between them is the finding.
    files_rows, files_unmapped = _classify_raw(raw_dist, map_of_record)
    files_rows_batch_rev, _ = _classify_raw(raw_dist, map_of_batch)
    mun_rows, mun_unmapped = _classify_projected(plan.get("projected_status_distribution", {}))

    # --- plane 1: files / byte copy at the pinned epoch ------------------------
    snap = newest(glob.glob(os.path.join(root, "receipts/snapshot/SNAPSHOT-*.json")))
    snap_doc = read_json(snap) if snap else {}
    ev["planes"] = {
        "files": {
            "state": ("MEASURED" if (raw_dist and map_of_record) else
                      ("UNKNOWN" if raw_dist else "MISSING")),
            "source": rel(root, imp_path) if imp_path else None,
            "denominator": "occurrences read from git objects at the pinned epoch",
            "total": sum((raw_dist or {}).values()) or None,
            "rows": files_rows,
            "unmapped_values": files_unmapped,
            "status_map_revision_used": record_rev,
            "status_map_path": (status_maps.get(record_rev) or {}).get("path"),
            "rows_under_batch_revision": files_rows_batch_rev,
            "no_claim_occurrences": {v: raw_dist.get(v) for v in NO_CLAIM_RAW_VALUES
                                     if v in (raw_dist or {})},
        },
        "muneral": {
            "state": "MEASURED" if plan.get("projected_status_distribution") else "MISSING",
            "source": rel(root, imp_path) if imp_path else None,
            "denominator": "occurrence projections committed in batch %s and read back"
                           % imp.get("batch_id"),
            "total": sum((plan.get("projected_status_distribution") or {}).values()) or None,
            "rows": mun_rows,
            "unmapped_values": mun_unmapped,
            "status_map_revision_used": batch_rev,
            "readback_identities": readback.get("identities_checked"),
            "readback_clean": readback.get("identities_clean"),
            "readback_mismatched": readback.get("identities_mismatched"),
        },
        "index": _collect_index_plane(root),
    }

    ev["byte_copy"] = {
        "source": rel(root, snap) if snap else None,
        "state": "MEASURED" if snap_doc else "MISSING",
        "files": (snap_doc.get("counts", {}) or {}).get("files") or snap_doc.get("files"),
        "readback": snap_doc.get("readback") or snap_doc.get("READBACK"),
    }

    # --- mapping plane ---------------------------------------------------------
    ev["mapping"] = {
        "batch_revision": batch_rev,
        "record_revision": record_rev,
        "available_revisions": sorted(status_maps),
        "rows_delta_between_revisions": {
            c: (files_rows.get(c) if files_rows.get(c) is not None else 0)
               - (files_rows_batch_rev.get(c) if files_rows_batch_rev.get(c) is not None else 0)
            for c in CLASS_ROWS},
        "unmapped_raw_statuses": plan.get("unmapped_raw_statuses"),
        "projection_rule_decision": "DEC-AUP-0014",
    }

    # --- conflicts (DEC-AUP-0014 projections) ----------------------------------
    hist = newest(glob.glob(os.path.join(root, "receipts/history/conflicts-*.json")))
    hist_doc = read_json(hist) if hist else {}
    hist_count = None
    if isinstance(hist_doc, dict):
        hist_count = hist_doc.get("count") or hist_doc.get("conflicts_count")
        if hist_count is None and isinstance(hist_doc.get("conflicts"), list):
            hist_count = len(hist_doc["conflicts"])
    proj = newest(glob.glob(os.path.join(root, "receipts/projection/projection0-*.json")))
    proj_doc = read_json(proj) if proj else {}
    ev["conflicts"] = {
        "files": {"count": hist_count, "source": rel(root, hist) if hist else None,
                  "denominator": "status conflicts across all census roots (AUP-DAT-007)"},
        "muneral": {"count": (imp.get("conflicts_held_I4", {}) or {}).get("count"),
                    "source": rel(root, imp_path) if imp_path else None,
                    "denominator": "within-root conflicts HELD under the batch SourceSetEpoch"},
        "index": {"count": None, "source": None, "denominator": None},
        "projection": {
            "source": rel(root, proj) if proj else None,
            "rule_rev": proj_doc.get("projection_rule_rev"),
            "verdict": proj_doc.get("verdict"),
        },
    }

    # --- restore drill evidence (AUP-DAT-017) ---------------------------------
    probes = []
    for rp in sorted(glob.glob(os.path.join(root, "receipts/recovery/*.json"))):
        try:
            rdoc = read_json(rp)
        except Exception:
            continue
        probes.append({"source": rel(root, rp), "verdict": rdoc.get("verdict"),
                       "host": rdoc.get("host") or rdoc.get("producer")})
    drills = sorted(glob.glob(os.path.join(root, "receipts/recovery/*restore-drill*.json"))
                    + glob.glob(os.path.join(root, "receipts/**/CutoverRollbackDrill*.json"),
                                recursive=True))
    ev["restore"] = {
        "probes": probes,
        "source": probes[0]["source"] if probes else None,
        "probe_verdicts": sorted({p["verdict"] for p in probes if p.get("verdict")}),
        "drill_receipts": [rel(root, p) for p in drills],
        # a backup that was never restored is not a backup: only a DRILL counts as measured
        "state": "MEASURED" if drills else ("NOT_MEASURED" if probes else "MISSING"),
        "dossier_task_verdict": dossier.get("task_verdicts", {}).get("AUP-DAT-017"),
    }

    # --- clean read-through declaration, per host ------------------------------
    ev["clean_read_through"] = {}
    for role, pattern in (("execution", "clean-path-devs-*.json"), ("control", "clean-path-mac-*.json")):
        p = newest(glob.glob(os.path.join(root, "receipts/acceptance", pattern)))
        if not p:
            ev["clean_read_through"][role] = {"present": False, "declared": None,
                                              "source_mount": None, "cache": None, "source": None}
            continue
        doc = read_json(p)
        env = doc.get("environment", {}) or {}
        steps = doc.get("steps", []) or []
        mounts = [s for s in steps if s.get("source_mount_in_env") or s.get("datarim_path_in_cwd")]
        ev["clean_read_through"][role] = {
            "present": True,
            "source": rel(root, p),
            "digest": sha256_file(p),
            "host": doc.get("host"),
            "declared": env.get("AUP_NO_SOURCE_MOUNT") == "1" and env.get("cwd_outside_datarim_root") is True,
            "source_mount": bool(mounts) or env.get("AUP_NO_SOURCE_MOUNT") != "1",
            "cache": None if "cache" not in json.dumps(env) else True,
            "steps": len(steps),
        }

    # --- authority ------------------------------------------------------------
    ev["authority"] = _collect_authority(root)
    ev["data_signer"] = {
        "identity": "aup-mig015 executor life (gen1) running %s on %s" % (TOOL, ev["host"]),
        "role": "data verifier",
    }
    ev["writer_epoch"] = {
        "receipts": [rel(root, p) for p in sorted(glob.glob(os.path.join(root, "receipts/**/writer-epoch*.json"), recursive=True))],
        "changed_by_this_tool": False,
    }
    return ev


def _classify_projected(distribution):
    """Muneral statuses -> spec rows. The only hand-written table in the tool."""
    rows = {c: 0 for c in CLASS_ROWS}
    unmapped = []
    for status, count in (distribution or {}).items():
        if status not in PROJECTED_TO_CLASS:
            unmapped.append(status)
            continue
        rows[PROJECTED_TO_CLASS[status]] += count
    if not distribution:
        return {c: None for c in CLASS_ROWS}, unmapped
    return rows, unmapped


def _classify_raw(distribution, status_map):
    """Raw source values -> Muneral status (through the versioned map) -> spec rows.

    A raw value absent from the map is a typed refusal (`UNMAPPED`), never a silent default.
    """
    if not status_map:
        return {c: None for c in CLASS_ROWS}, list((distribution or {}).keys())
    projected = {}
    unmapped = []
    for raw, count in (distribution or {}).items():
        entry = status_map.get(raw)
        if not entry:
            unmapped.append(raw)
            continue
        projected[entry["muneral"]] = projected.get(entry["muneral"], 0) + count
    rows, unmapped_status = _classify_projected(projected)
    return rows, unmapped + unmapped_status


def _load_status_maps(root):
    """Every vendored revision of the HistoricalStatusMap, by revision number."""
    maps = {}
    for p in sorted(glob.glob(os.path.join(root, "contracts/status-mapping/status-map-v1*.json"))):
        try:
            doc = read_json(p)
        except Exception:
            continue
        rev = doc.get("revision")
        if isinstance(rev, int):
            maps[rev] = {"path": rel(root, p), "map": doc.get("map", {}),
                         "digest": sha256_file(p)}
    return maps


def _collect_index_plane(root):
    """KB / Scrutator freshness plane: what the index can answer about the imported identities."""
    probe = newest(glob.glob(os.path.join(root, "receipts/indexack/probe-*.json")))
    plan = newest(glob.glob(os.path.join(root, "receipts/indexack/history-plan-*.json")))
    probe_doc = read_json(probe) if probe else {}
    plan_doc = read_json(plan) if plan else {}

    acks = ((plan_doc.get("counts") or {}).get("acks") or {})
    indexed = acks.get("ACKED") or acks.get("INDEXED")
    not_indexed = acks.get("NOT_INDEXED")
    plan_state = plan_doc.get("state") or plan_doc.get("verdict")

    if indexed:
        state = "MEASURED"
    elif plan_state in ("PLANNED_NOT_INGESTED", "HISTORY_NOT_INDEXED") or not_indexed:
        # the plane is planned but holds no row about these identities: it cannot answer at all
        state = "MISSING"
    elif plan_doc or probe_doc:
        state = "UNKNOWN"
    else:
        state = "MISSING"

    return {
        "state": state,
        "source": ", ".join(x for x in [rel(root, plan) if plan else None,
                                        rel(root, probe) if probe else None] if x) or None,
        "denominator": "files of the imported source set acknowledged by the KB/Scrutator "
                       "history namespace",
        "total": indexed,
        "rows": {c: None for c in CLASS_ROWS},
        "verdict": plan_state,
        "acks": acks,
        "not_indexed": not_indexed,
        "not_done": plan_doc.get("not_done"),
        "planned_files": (plan_doc.get("counts") or {}).get("files") or sum(acks.values()) or None,
        "other_namespace_probe": {
            "source": rel(root, probe) if probe else None,
            "acked_rows": sum(1 for a in (probe_doc.get("acks") or [])
                              if a.get("state") == "ACKED") or None,
            "note": "acks in the pre-existing `datarim` namespace are not acks for the imported "
                    "history identities",
        },
    }


def _collect_authority(root, decision_id="DEC-AUP-0012"):
    dpath = os.path.join(root, "governance/decisions/%s.json" % decision_id)
    out = {"decision_id": decision_id, "present": os.path.exists(dpath),
           "profile_rev": AUTHORITY_PROFILE_REV}
    if not out["present"]:
        return out
    doc = read_json(dpath)
    # the scope may be stated in this decision or in a decision it incorporates by reference
    # (DEC-AUP-0012 rule: "FROZEN = DEC-AUP-0011 gate"); the closure is recorded, never assumed.
    own_text = json.dumps(doc, ensure_ascii=False)
    referenced = sorted(set(re.findall(r"DEC-AUP-\d{4}", own_text)) - {decision_id})
    closure = {decision_id: own_text}
    for ref in referenced:
        rpath = os.path.join(root, "governance/decisions/%s.json" % ref)
        if os.path.exists(rpath):
            closure[ref] = json.dumps(read_json(rpath), ensure_ascii=False)
    text = "\n".join(closure.values())
    profile = AUTHORITY_PROFILE.get(decision_id, {})
    out.update({
        "path": rel(root, dpath),
        "digest": sha256_file(dpath),
        "issued_at_utc": doc.get("issued_at_utc"),
        "issuer_identity": doc.get("decided_by"),
        "authority_statement": doc.get("authority"),
        "reversible": doc.get("reversible"),
        "title": doc.get("title"),
        "action": profile.get("action"),
        "resources": profile.get("resources"),
        "hosts": profile.get("hosts"),
        "target_generation": profile.get("target_generation"),
        "readiness_state_min": profile.get("readiness_state_min"),
        "states": profile.get("states"),
        "reverse_if": doc.get("reverse_if", []),
        "evidence_gate": doc.get("evidence_gate", []),
    })
    # the profile may not drift from the decision: every assertion must appear in the document
    missing = [s for s in profile.get("must_appear_in_decision", []) if s not in text]
    missing += [s for s in ([profile.get("action")] + list(profile.get("resources") or [])
                            + [profile.get("target_generation")]) if s and s not in text]
    out["profile_confirmed_in_decision"] = not missing
    out["profile_assertions_not_found"] = missing
    out["profile_confirmed_by"] = {
        assertion: sorted(k for k, v in closure.items() if assertion in v)
        for assertion in (list(profile.get("must_appear_in_decision", []))
                          + [profile.get("action")] + list(profile.get("resources") or [])
                          + [profile.get("target_generation")]) if assertion
    }
    out["decision_closure"] = sorted(closure)

    # revocation: any LATER decision that supersedes this one
    superseded_by = []
    for p in sorted(glob.glob(os.path.join(root, "governance/decisions/DEC-AUP-*.json"))):
        other = read_json(p)
        if other.get("id") == decision_id:
            continue
        blob = json.dumps(other.get("supersedes_in_part", []) + [other.get("supersedes", "")],
                          ensure_ascii=False)
        if decision_id in blob:
            superseded_by.append({"id": other.get("id"), "issued_at_utc": other.get("issued_at_utc")})
    out["superseded_by"] = superseded_by

    # state machine
    spath = os.path.join(root, "receipts/cutover/state.json")
    if os.path.exists(spath):
        sdoc = read_json(spath)
        out["state_machine"] = {"present": True, "path": rel(root, spath),
                                "state": sdoc.get("state"), "digest": sha256_file(spath),
                                "updated_at_utc": sdoc.get("captured_at_utc")}
    else:
        out["state_machine"] = {"present": False, "path": "receipts/cutover/state.json",
                                "state": None}

    # evidence gate, item by item
    out["evidence_gate_state"] = _probe_evidence_gate(root, doc.get("evidence_gate", []))
    out["reverse_if_state"] = _probe_reverse_if(root, doc.get("reverse_if", []), out)
    return out


def _probe_evidence_gate(root, items):
    state = []
    for item in items:
        probe = EVIDENCE_GATE_PROBES.get(item)
        if probe is None:
            state.append({"item": item, "verdict": NOT_MEASURED,
                          "detail": "no probe defined for this gate item"})
            continue
        pattern, schema, min_count, extra = probe
        found = sorted(glob.glob(os.path.join(root, pattern), recursive=True))
        hits, digests = [], []
        for p in found:
            try:
                doc = read_json(p)
            except Exception:
                continue
            if schema and doc.get("schema") != schema:
                continue
            hits.append(rel(root, p))
            digests.append(sha256_file(p))
        verdict = "SATISFIED" if len(hits) >= min_count else "UNSATISFIED"
        detail = "%d/%d receipt(s) matching %s" % (len(hits), min_count, pattern)
        if extra == "parity_pair" and hits:
            # the timing clause (twice, ≥ 1 h apart, identical digest) is the gate, not the count
            statuses = []
            for p in hits:
                try:
                    statuses.append(read_json(os.path.join(root, p)).get("status", ""))
                except Exception:
                    pass
            if any(str(s).startswith("DRAFT") for s in statuses):
                verdict = "UNSATISFIED"
                detail += "; newest parity receipt is DRAFT (1 h timing clause unmet)"
        if extra == "restore_drill":
            drills = glob.glob(os.path.join(root, "receipts/recovery/*restore-drill*.json"))
            if not drills:
                verdict = "UNSATISFIED"
                detail += "; no Muneral DB restore drill receipt"
        if extra == "second_batch" and len(hits) < min_count:
            detail += "; only the epoch-1 batch has a verify receipt (no DELTA_IMPORTED batch)"
        state.append({"item": item, "verdict": verdict, "detail": detail,
                      "receipts": hits[:10], "digests": digests[:10]})
    return state


def _probe_reverse_if(root, conditions, authority):
    """Expiry of the authority = a `reverse_if` condition that has fired.

    A condition that only becomes measurable after a state the machine has not reached is typed
    NOT_YET_APPLICABLE — it is neither 'not triggered' nor 'triggered'.
    """
    reached = authority.get("state_machine", {}).get("state")
    post_switch = reached in ("SWITCHING", "MUNERAL_AUTHORITATIVE")
    out = []
    for cond in conditions:
        c = cond.lower()
        if "epoch" in c and ("unpinned" in c or "reused" in c):
            out.append({"condition": cond, "verdict": "NOT_TRIGGERED",
                        "detail": "epoch is git-pinned to a workspace main commit (measured by the data verifier)"})
        elif "bake" in c or "after switching" in c or "legacy write" in c:
            out.append({"condition": cond,
                        "verdict": "NOT_TRIGGERED" if post_switch else "NOT_YET_APPLICABLE",
                        "detail": "condition applies from SWITCHING onward; state machine is at %s"
                                  % (reached or "uninitialised")})
        else:
            out.append({"condition": cond, "verdict": NOT_MEASURED,
                        "detail": "no probe defined for this condition"})
    return out


# ---------------------------------------------------------------------------
# verifier 1 — the data gate
# ---------------------------------------------------------------------------


def verify_data(ev, mutants=frozenset()):
    checks = []
    add = checks.append

    # D01 dossier present and pinned to an exact revision
    d = ev.get("dossier", {})
    if not d.get("present"):
        add(Check("D01", "data", "is the AUP-DAT-020 acceptance dossier present?", BLOCK,
                  "DOSSIER_MISSING"))
    elif not (d.get("revision_pinned") and (d.get("revision_resolvable") is not False)):
        v = PASS if "dossier_revision_unpinned_ok" in mutants else BLOCK
        add(Check("D01", "data", "is the dossier pinned to an exact, resolvable revision?", v,
                  None if v == PASS else "DOSSIER_REVISION_UNPINNED",
                  {"program_commit": d.get("program_commit"),
                   "resolvable": d.get("revision_resolvable")}))
    else:
        add(Check("D01", "data", "is the dossier pinned to an exact, resolvable revision?", PASS,
                  None, {"program_commit": d.get("program_commit"),
                         "path": d.get("path"), "digest": d.get("digest")}))

    # D02 the dossier's own verdict
    if d.get("present"):
        ok = d.get("verdict") == "PASS" and d.get("global_complete") is True
        add(Check("D02", "data", "does the dossier itself carry a clean verdict?",
                  PASS if ok else BLOCK, None if ok else "DOSSIER_NOT_CLEAN",
                  {"verdict": d.get("verdict"), "global_complete": d.get("global_complete"),
                   "unresolved_external_gaps": len(d.get("unresolved_external_gaps", [])),
                   "flag_counts": d.get("flag_counts")}))

    # D03 SourceSetEpoch git-pinned
    e = ev.get("epoch", {})
    if not e.get("pinned"):
        add(Check("D03", "data", "is the SourceSetEpoch git-pinned to a workspace commit?", BLOCK,
                  "UNPINNED_SOURCE_SET_EPOCH", {"declared": e.get("declared")}))
    else:
        add(Check("D03", "data", "is the SourceSetEpoch git-pinned to a workspace commit?", PASS,
                  None, {"epoch": e.get("declared")}))

    # D04 epoch agrees with the dossier's corpus
    if e.get("pinned") and d.get("present"):
        ok = e.get("matches_dossier")
        add(Check("D04", "data", "does the epoch equal the corpus the dossier measured?",
                  PASS if ok else BLOCK, None if ok else "EPOCH_DOSSIER_MISMATCH",
                  {"epoch_sha": e.get("sha"), "dossier_source_commit": d.get("coverage_source_commit")}))

    # D05 epoch still current (a moved source set invalidates the gate — MIG-016 revalidation rule)
    observed = e.get("observed_main_head")
    if not observed:
        add(Check("D05", "data", "is the pinned epoch still the head of the source set?",
                  NOT_MEASURED, "SOURCE_SET_HEAD_NOT_OBSERVED"))
    elif observed != e.get("sha"):
        v = PASS if "ignore_stale_epoch" in mutants else BLOCK
        add(Check("D05", "data", "is the pinned epoch still the head of the source set?", v,
                  None if v == PASS else "STALE_SOURCE_SET_EPOCH",
                  {"epoch_sha": e.get("sha"), "observed_main_head": observed,
                   "observed_from": e.get("observed_from"),
                   "rule": "a changed SourceSetEpoch invalidates DAT-020/MIG-015 and requires revalidation"}))
    else:
        add(Check("D05", "data", "is the pinned epoch still the head of the source set?", PASS))

    # D06..D09 the three planes, per status class
    planes = ev.get("planes", {})
    for plane in PLANES:
        p = planes.get(plane, {}) or {}
        state = p.get("state", "MISSING")
        if state == "MISSING":
            v = PASS if "missing_plane_is_pass" in mutants else BLOCK
            add(Check("D06.%s" % plane, "data",
                      "is the %s plane readable for active/planned/completed/cancelled?" % plane,
                      v, None if v == PASS else "MISSING_PLANE",
                      {"source": p.get("source"), "verdict": p.get("verdict")}, plane=plane))
        elif state == "UNKNOWN":
            v = PASS if "unknown_is_pass" in mutants else BLOCK
            add(Check("D06.%s" % plane, "data",
                      "is the %s plane readable for active/planned/completed/cancelled?" % plane,
                      v, None if v == PASS else "PLANE_UNKNOWN",
                      {"source": p.get("source")}, plane=plane))
        else:
            add(Check("D06.%s" % plane, "data",
                      "is the %s plane readable for active/planned/completed/cancelled?" % plane,
                      PASS, None, {"total": p.get("total"), "rows": p.get("rows")}, plane=plane))
        if p.get("unmapped_values"):
            add(Check("D07.%s" % plane, "data",
                      "are all raw values of the %s plane covered by the class map?" % plane,
                      BLOCK, "UNMAPPED_STATUS_VALUE",
                      {"values": p.get("unmapped_values"), "class_map_rev": CLASS_MAP_REV},
                      plane=plane))

    # D08 cross-plane agreement per class (a plane that cannot answer is not agreement)
    measured = [pl for pl in PLANES if (planes.get(pl, {}) or {}).get("state") == "MEASURED"]
    disagreements = []
    for cls in CLASS_ROWS:
        vals = {pl: (planes[pl].get("rows") or {}).get(cls) for pl in measured}
        distinct = {v for v in vals.values() if v is not None}
        if len(distinct) > 1:
            disagreements.append({"class": cls, "by_plane": vals})
    if len(measured) < len(PLANES):
        add(Check("D08", "data", "do the three planes agree per status class?", NOT_MEASURED,
                  "PLANE_COMPARISON_INCOMPLETE",
                  {"planes_measured": measured, "planes_required": PLANES}))
    elif disagreements:
        v = PASS if "ignore_plane_disagreement" in mutants else BLOCK
        add(Check("D08", "data", "do the three planes agree per status class?", v,
                  None if v == PASS else "PLANE_DISAGREEMENT", {"disagreements": disagreements}))
    else:
        add(Check("D08", "data", "do the three planes agree per status class?", PASS))

    # D09 unindexed row — items known to files/Muneral but absent from the index plane
    idx = planes.get("index", {}) or {}
    mun_total = (planes.get("muneral", {}) or {}).get("readback_identities")
    if idx.get("state") != "MEASURED":
        v = PASS if "missing_plane_is_pass" in mutants else BLOCK
        add(Check("D09", "data", "how many identities are unindexed in the third plane?", v,
                  None if v == PASS else "UNINDEXED_NOT_MEASURED",
                  {"index_verdict": idx.get("verdict"),
                   "identities_in_store": mun_total,
                   "planned_files": idx.get("planned_files"),
                   "note": "every identity is unindexed until the history namespace is ingested"},
                  plane="index"))
    else:
        add(Check("D09", "data", "how many identities are unindexed in the third plane?", PASS,
                  None, {"indexed": idx.get("total"), "identities_in_store": mun_total}))

    # D10 conflicts through the planes
    c = ev.get("conflicts", {})
    counts = {k: (c.get(k, {}) or {}).get("count") for k in PLANES}
    if counts["index"] is None:
        add(Check("D10", "data", "are held conflicts visible through all three planes?",
                  NOT_MEASURED, "CONFLICTS_PLANE_MISSING",
                  {"by_plane": counts,
                   "denominators": {k: (c.get(k, {}) or {}).get("denominator") for k in PLANES},
                   "note": "the files and store counts have different denominators and are not "
                           "compared as equals (I4: no silent totalisation)"}))
    else:
        add(Check("D10", "data", "are held conflicts visible through all three planes?", PASS,
                  None, {"by_plane": counts}))

    # D11 the mapping used by the store is the mapping of record
    mp = ev.get("mapping", {})
    if mp.get("batch_revision") is None or mp.get("record_revision") is None:
        add(Check("D11", "data", "is the store's status-map revision the one of record?",
                  NOT_MEASURED, "MAPPING_REVISION_NOT_MEASURED", mp))
    elif mp["batch_revision"] != mp["record_revision"]:
        v = PASS if "ignore_mapping_revision" in mutants else BLOCK
        add(Check("D11", "data", "is the store's status-map revision the one of record?", v,
                  None if v == PASS else "MAPPING_REVISION_BEHIND_RECORD",
                  {"batch_revision": mp["batch_revision"],
                   "record_revision": mp["record_revision"],
                   "rule": "DEC-AUP-0014 rule 3: `archived` never projects onto `done`; rows imported "
                           "under an earlier revision are kept, never backfilled — the store's "
                           "completed class therefore over-states completion until a re-projection card runs"}))
    else:
        add(Check("D11", "data", "is the store's status-map revision the one of record?", PASS))
    if mp.get("unmapped_raw_statuses"):
        add(Check("D12", "data", "did the import leave unmapped raw statuses?", BLOCK,
                  "UNMAPPED_STATUS_VALUE", {"values": mp["unmapped_raw_statuses"]}))
    else:
        add(Check("D12", "data", "did the import leave unmapped raw statuses?", PASS))

    # D13 byte copy
    bc = ev.get("byte_copy", {})
    if bc.get("state") != "MEASURED":
        add(Check("D13", "data", "is the byte copy of the source set proven?", BLOCK,
                  "BYTE_COPY_UNPROVEN", {"source": bc.get("source")}))
    else:
        add(Check("D13", "data", "is the byte copy of the source set proven?", PASS, None,
                  {"files": bc.get("files"), "source": bc.get("source")}))

    # D14 restore drill (DAT-017)
    r = ev.get("restore", {})
    if r.get("state") != "MEASURED":
        v = PASS if "restore_not_measured_is_pass" in mutants else BLOCK
        add(Check("D14", "data", "has a restore of the target store been drilled?", v,
                  None if v == PASS else "RESTORE_NOT_MEASURED",
                  {"probe_verdicts": r.get("probe_verdicts"),
                   "probes": r.get("probes"),
                   "dossier_task_verdict": r.get("dossier_task_verdict"),
                   "drill_receipts": r.get("drill_receipts"),
                   "rule": "restore NOT MEASURED blocks; a backup that was never restored is not a backup"}))
    else:
        add(Check("D14", "data", "has a restore of the target store been drilled?", PASS, None,
                  {"drill_receipts": r.get("drill_receipts")}))

    # D15 clean read-through on every host, no source mount or cache
    crt = ev.get("clean_read_through", {})
    for role in ("execution", "control"):
        h = crt.get(role, {}) or {}
        if not h.get("present"):
            add(Check("D15.%s" % role, "data",
                      "is a clean read-through declared on the %s host?" % role, BLOCK,
                      "CLEAN_READ_THROUGH_MISSING", {"role": role}))
        elif h.get("source_mount") or h.get("cache"):
            v = PASS if "ignore_hidden_mount" in mutants else BLOCK
            add(Check("D15.%s" % role, "data",
                      "is the %s host free of source mounts and caches?" % role, v,
                      None if v == PASS else "HIDDEN_MOUNT_OR_CACHE",
                      {"source_mount": h.get("source_mount"), "cache": h.get("cache"),
                       "source": h.get("source")}))
        elif not h.get("declared"):
            add(Check("D15.%s" % role, "data",
                      "is a clean read-through declared on the %s host?" % role, BLOCK,
                      "CLEAN_READ_THROUGH_NOT_DECLARED", {"source": h.get("source")}))
        else:
            add(Check("D15.%s" % role, "data",
                      "is a clean read-through declared on the %s host?" % role, PASS, None,
                      {"source": h.get("source"), "digest": h.get("digest")}))

    return _finish(checks, "data", mutants)


# ---------------------------------------------------------------------------
# verifier 2 — the cutover authority
# ---------------------------------------------------------------------------


def verify_authority(ev, mutants=frozenset()):
    checks = []
    add = checks.append
    a = ev.get("authority", {}) or {}

    if not a.get("present"):
        add(Check("A01", "authority", "does the authorising decision exist?", BLOCK,
                  "AUTHORITY_DECISION_MISSING", {"decision_id": a.get("decision_id")}))
        return _finish(checks, "authority", mutants)

    add(Check("A01", "authority", "does the authorising decision exist?", PASS, None,
              {"decision_id": a.get("decision_id"), "digest": a.get("digest"),
               "issued_at_utc": a.get("issued_at_utc")}))

    # A02 the profile this verifier reads the decision with must be confirmed by the decision text
    if a.get("profile_confirmed_in_decision"):
        add(Check("A02", "authority",
                  "do action / resources / target generation come from the decision itself?", PASS,
                  None, {"action": a.get("action"), "resources": a.get("resources"),
                         "hosts": a.get("hosts"), "target_generation": a.get("target_generation"),
                         "profile_rev": AUTHORITY_PROFILE_REV}))
    else:
        add(Check("A02", "authority",
                  "do action / resources / target generation come from the decision itself?",
                  NOT_MEASURED, "AUTHORITY_SCOPE_NOT_CONFIRMED",
                  {"assertions_not_found": a.get("profile_assertions_not_found")}))

    # A03 issuer identity present and not a person-gate (DEC-AUP-0010)
    issuer = a.get("issuer_identity")
    if not issuer:
        add(Check("A03", "authority", "is the issuer of the authority recorded?", BLOCK,
                  "AUTHORITY_ISSUER_MISSING"))
    else:
        add(Check("A03", "authority", "is the issuer of the authority recorded?", PASS, None,
                  {"issuer": issuer,
                   "note": "the authority is a decision id plus its gate receipts, never a person "
                           "(DEC-AUP-0010, DEC-AUP-0012 supersedes the AuthorizationDecision of DEC-AUP-0002)"}))

    # A04 the data signer is never the authority issuer
    signer = (ev.get("data_signer", {}) or {}).get("identity")
    collides = bool(signer) and bool(issuer) and signer == issuer
    if collides:
        v = PASS if "allow_signer_is_issuer" in mutants else BLOCK
        add(Check("A04", "authority", "is the data signer distinct from the authority issuer?", v,
                  None if v == PASS else "AUTHORITY_SIGNER_IS_DATA_SIGNER",
                  {"signer": signer, "issuer": issuer}))
    else:
        add(Check("A04", "authority", "is the data signer distinct from the authority issuer?",
                  PASS, None, {"signer": signer, "issuer": issuer}))

    # A05 revocation — a later decision superseding this one
    sup = a.get("superseded_by") or []
    later = [s for s in sup if (s.get("issued_at_utc") or "") > (a.get("issued_at_utc") or "")]
    if later:
        v = PASS if "ignore_revocation" in mutants else BLOCK
        add(Check("A05", "authority", "has the authority been revoked or superseded?", v,
                  None if v == PASS else "AUTHORITY_REVOKED", {"superseded_by": later}))
    else:
        add(Check("A05", "authority", "has the authority been revoked or superseded?", PASS, None,
                  {"supersedes_scanned": len(sup)}))

    # A06 expiry — a `reverse_if` condition that has fired
    rstate = a.get("reverse_if_state") or []
    fired = [r for r in rstate if r.get("verdict") == "TRIGGERED"]
    unmeasured = [r for r in rstate if r.get("verdict") == NOT_MEASURED]
    if fired:
        v = PASS if "ignore_expiry" in mutants else BLOCK
        add(Check("A06", "authority", "is the authority still in force (no reverse_if fired)?", v,
                  None if v == PASS else "AUTHORITY_EXPIRED", {"triggered": fired}))
    elif unmeasured:
        v = PASS if "unknown_is_pass" in mutants else NOT_MEASURED
        add(Check("A06", "authority", "is the authority still in force (no reverse_if fired)?", v,
                  None if v == PASS else "AUTHORITY_EXPIRY_NOT_MEASURED",
                  {"not_measured": [r["condition"] for r in unmeasured],
                   "not_yet_applicable": [r["condition"] for r in rstate
                                          if r.get("verdict") == "NOT_YET_APPLICABLE"]}))
    else:
        add(Check("A06", "authority", "is the authority still in force (no reverse_if fired)?",
                  PASS))

    # A07 permitted target generation reached in the state machine
    sm = a.get("state_machine", {}) or {}
    states = a.get("states") or []
    minimum = a.get("readiness_state_min")
    if not sm.get("present") or not sm.get("state"):
        add(Check("A07", "authority",
                  "has the state machine reached the state this attestation presupposes?", BLOCK,
                  "AUTHORITY_STATE_UNINITIALISED",
                  {"expected_file": sm.get("path"), "readiness_state_min": minimum,
                   "implied_state": states[0] if states else None,
                   "note": "no persisted state ⇒ the machine stands at %s; the cutover authority is "
                           "not in effect" % (states[0] if states else "the initial state")}))
    else:
        try:
            ok = states.index(sm["state"]) >= states.index(minimum)
        except ValueError:
            ok = False
        add(Check("A07", "authority",
                  "has the state machine reached the state this attestation presupposes?",
                  PASS if ok else BLOCK, None if ok else "AUTHORITY_NOT_IN_EFFECT",
                  {"state": sm.get("state"), "readiness_state_min": minimum}))

    # A08 the evidence gate of the decision, item by item
    gate = a.get("evidence_gate_state") or []
    unsat = [g for g in gate if g.get("verdict") == "UNSATISFIED"]
    notm = [g for g in gate if g.get("verdict") == NOT_MEASURED]
    if unsat:
        add(Check("A08", "authority", "is the decision's evidence gate complete?", BLOCK,
                  "AUTHORITY_EVIDENCE_GATE_INCOMPLETE",
                  {"satisfied": len(gate) - len(unsat) - len(notm), "total": len(gate),
                   "unsatisfied": [g["item"] for g in unsat],
                   "not_measured": [g["item"] for g in notm]}))
    elif notm:
        v = PASS if "unknown_is_pass" in mutants else NOT_MEASURED
        add(Check("A08", "authority", "is the decision's evidence gate complete?", v,
                  None if v == PASS else "AUTHORITY_EVIDENCE_GATE_NOT_MEASURED",
                  {"not_measured": [g["item"] for g in notm]}))
    else:
        add(Check("A08", "authority", "is the decision's evidence gate complete?", PASS, None,
                  {"items": len(gate)}))

    return _finish(checks, "authority", mutants)


def _finish(checks, verifier, mutants):
    reasons, not_measured = [], []
    for c in checks:
        if c.verdict == BLOCK and c.reason:
            reasons.append(c.reason)
        elif c.verdict == NOT_MEASURED:
            not_measured.append(c.reason or c.id)
    verdict = PASS if all(c.verdict == PASS for c in checks) and checks else BLOCK
    return {
        "verifier": verifier,
        "verdict": verdict,
        "checks": [c.as_dict() for c in checks],
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c.verdict == PASS),
        "checks_blocked": sum(1 for c in checks if c.verdict == BLOCK),
        "checks_not_measured": sum(1 for c in checks if c.verdict == NOT_MEASURED),
        "reason_codes": sorted(set(reasons)),
        "not_measured": sorted(set(not_measured)),
        "mutants_active": sorted(mutants),
    }


# ---------------------------------------------------------------------------
# minting rule
# ---------------------------------------------------------------------------


def mint(ev, data, authority, mutants=frozenset(), captured_at=None):
    """Produce a CutoverReadinessAttestation/v1 (both PASS) or a BlockReceipt/v1 (anything else)."""
    ts = captured_at or utcnow()
    both_pass = data["verdict"] == PASS and authority["verdict"] == PASS
    if "data_pass_is_permission" in mutants:
        both_pass = data["verdict"] == PASS

    data_ref = {
        "kind": "data",
        "receipt": (ev.get("dossier") or {}).get("path"),
        "digest": (ev.get("dossier") or {}).get("digest"),
        "signer": (ev.get("data_signer") or {}).get("identity"),
    }
    a = ev.get("authority", {}) or {}
    authority_ref = {
        "kind": "authority",
        "decision_id": a.get("decision_id"),
        "decision_digest": a.get("digest"),
        "issuer": a.get("issuer_identity"),
        "gate_receipt_digests": [
            {"item": g["item"], "receipts": g.get("receipts", []), "digests": g.get("digests", [])}
            for g in (a.get("evidence_gate_state") or []) if g.get("receipts")
        ],
    }

    common = {
        "captured_at_utc": ts,
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "portion_id": "AUP-MIG-015:gate0",
        "host": ev.get("host"),
        "read_only": True,
        "source_set_epoch": (ev.get("epoch") or {}).get("declared"),
        "source_set_epoch_observed_head": (ev.get("epoch") or {}).get("observed_main_head"),
        "writer_epoch": {
            "changed": False,
            "rule": "MIG-015 mints no authority and never changes the writer epoch",
        },
        "class_map_rev": CLASS_MAP_REV,
        "authority_profile_rev": AUTHORITY_PROFILE_REV,
        # DEC-AUP-0015: a non-Fable life's output is provisional until a Fable blind review
        "model": ev.get("model"),
        "model_source": "declared by the invoking life via --model; not measurable from inside the tool",
        "provisional_until_fable_review": True,
    }

    if both_pass:
        art = dict(common)
        art["schema"] = "CutoverReadinessAttestation/v1"
        art["verdict"] = PASS
        art["refs"] = [data_ref, authority_ref]
        if "single_ref_attestation" in mutants:
            art["refs"] = [data_ref]
        if "writer_epoch_touched" in mutants:
            art["writer_epoch"] = {"changed": True, "rule": "mutant"}
        art["negative_verdicts"] = _negatives(data, authority)
        art["rule"] = ("issued only when the data verifier and the authority verifier both PASS; "
                       "two refs (data receipt + authority decision and its gate receipts); the data "
                       "signer is not the authority issuer; the writer epoch is unchanged")
    else:
        art = dict(common)
        art["schema"] = "BlockReceipt/v1"
        art["verdict"] = BLOCK
        art["blocked_by"] = sorted(set(data["reason_codes"] + authority["reason_codes"]))
        art["not_measured"] = sorted(set(data["not_measured"] + authority["not_measured"]))
        art["refs_withheld"] = {
            "data": data_ref if data["verdict"] == PASS else "withheld: data verifier did not PASS",
            "authority": (authority_ref if authority["verdict"] == PASS
                          else "withheld: authority verifier did not PASS"),
        }
        art["negative_verdicts"] = _negatives(data, authority)
        art["rule"] = ("no attestation is minted unless BOTH verifiers PASS; a data PASS is never "
                       "permission and never upgrades to an approval")
    return art


def _negatives(data, authority):
    out = []
    for report in (data, authority):
        for c in report["checks"]:
            if c["verdict"] != PASS:
                out.append({"check": c["id"], "verifier": c["verifier"],
                            "verdict": c["verdict"], "reason_code": c.get("reason_code"),
                            "question": c["question"], "detail": c.get("detail")})
    return out


def run_gate(ev, mutants=frozenset(), captured_at=None):
    data = verify_data(ev, mutants)
    authority = verify_authority(ev, mutants)
    artifact = mint(ev, data, authority, mutants, captured_at)
    return {"data": data, "authority": authority, "artifact": artifact,
            "outcome": artifact["verdict"]}


# ---------------------------------------------------------------------------
# fixtures — the four failure scenarios of the spec plus the controls
# ---------------------------------------------------------------------------

SHA_A = "a" * 40
SHA_B = "b" * 40

MUTANTS = [
    "missing_plane_is_pass",        # M01 a plane that cannot answer stops blocking
    "unknown_is_pass",              # M02 NOT_MEASURED collapses into PASS
    "ignore_stale_epoch",           # M03 a moved source set stops blocking
    "ignore_hidden_mount",          # M04 a source mount / cache stops blocking
    "data_pass_is_permission",      # M05 a data PASS mints an attestation on its own
    "ignore_revocation",            # M06 a superseding decision stops blocking
    "ignore_expiry",                # M07 a fired reverse_if stops blocking
    "allow_signer_is_issuer",       # M08 the data signer may be the authority issuer
    "restore_not_measured_is_pass", # M09 an undrilled restore stops blocking
    "ignore_plane_disagreement",    # M10 planes may disagree per status class
    "ignore_mapping_revision",      # M11 the store may project under a superseded map
    "single_ref_attestation",       # M12 the attestation drops the authority ref
    "writer_epoch_touched",         # M13 the attestation claims a writer-epoch change
    "dossier_revision_unpinned_ok", # M14 the dossier need not be pinned to a revision
]


def _baseline():
    """A wholly synthetic, wholly green evidence set. No real receipt is read by the selftest."""
    rows = {"active": 90, "planned": 702, "completed": 517, "cancelled": 35, "archived": 1351}
    plane = lambda src: {"state": "MEASURED", "source": src, "denominator": "fixture",
                         "total": sum(rows.values()), "rows": dict(rows), "unmapped_values": []}
    ev = {
        "collected_at_utc": "2026-01-01T00:00:00Z",
        "root": "<fixture>",
        "host": "fixture-host",
        "class_map_rev": CLASS_MAP_REV,
        "model": "fixture-model",
        "program": {"commit": SHA_A, "git_ok": True},
        "dossier": {
            "present": True, "path": "receipts/acceptance/acceptance0-fixture.json",
            "digest": "sha256:" + "0" * 64, "captured_at_utc": "2026-01-01T00:00:00Z",
            "program_commit": SHA_A, "revision_pinned": True, "revision_resolvable": True,
            "environment_host": "fixture-host", "verdict": "PASS", "global_complete": True,
            "task_verdicts": {"AUP-DAT-017": "PASS"}, "coverage_source_commit": SHA_B,
            "unresolved_external_gaps": [], "flag_counts": {},
        },
        "epoch": {"declared": "git:arcanada-workspace@" + SHA_B, "repo": "arcanada-workspace",
                  "sha": SHA_B, "pinned": True, "source": "fixture", "matches_dossier": True,
                  "observed_main_head": SHA_B, "observed_from": "fixture"},
        "fence": {"hourly_receipts": 96, "foreign_writes_latest": 0, "canary_seen_latest": True,
                  "bake_hours_required": 72},
        "planes": {
            "files": plane("fixture:files"),
            "muneral": dict(plane("fixture:muneral"), readback_identities=2486,
                            readback_clean=2486, readback_mismatched=0),
            "index": dict(plane("fixture:index"), verdict="INDEXED", planned_files=2585),
        },
        "byte_copy": {"source": "fixture:snapshot", "state": "MEASURED", "files": 1819,
                      "readback": "1819/1819"},
        "mapping": {"batch_revision": 3, "record_revision": 3, "available_revisions": [1, 2, 3],
                    "unmapped_raw_statuses": [], "projection_rule_decision": "DEC-AUP-0014"},
        "conflicts": {
            "files": {"count": 80, "source": "fixture", "denominator": "all roots"},
            "muneral": {"count": 26, "source": "fixture", "denominator": "within-root at the epoch"},
            "index": {"count": 26, "source": "fixture", "denominator": "indexed conflicts"},
            "projection": {"source": "fixture", "rule_rev": 1, "verdict": "PASS"},
        },
        "restore": {"source": "fixture", "probe_verdicts": ["PASS"], "probes": [],
                    "drill_receipts": ["receipts/recovery/restore-drill-fixture.json"],
                    "state": "MEASURED", "dossier_task_verdict": "PASS"},
        "clean_read_through": {
            role: {"present": True, "source": "fixture:%s" % role, "digest": "sha256:" + "1" * 64,
                   "host": role, "declared": True, "source_mount": False, "cache": None, "steps": 7}
            for role in ("execution", "control")
        },
        "authority": {
            "decision_id": "DEC-AUP-0012", "present": True, "profile_rev": AUTHORITY_PROFILE_REV,
            "path": "governance/decisions/DEC-AUP-0012.json", "digest": "sha256:" + "2" * 64,
            "issued_at_utc": "2026-01-01T00:00:00Z",
            "issuer_identity": "aup-orchestrator (fixture incarnation)",
            "action": AUTHORITY_PROFILE["DEC-AUP-0012"]["action"],
            "resources": AUTHORITY_PROFILE["DEC-AUP-0012"]["resources"],
            "hosts": AUTHORITY_PROFILE["DEC-AUP-0012"]["hosts"],
            "target_generation": "MUNERAL_AUTHORITATIVE",
            "readiness_state_min": "ROLLBACK_DRILLED",
            "states": list(AUTHORITY_PROFILE["DEC-AUP-0012"]["states"]),
            "profile_confirmed_in_decision": True, "profile_assertions_not_found": [],
            "superseded_by": [],
            "state_machine": {"present": True, "path": "receipts/cutover/state.json",
                              "state": "ROLLBACK_DRILLED", "digest": "sha256:" + "3" * 64},
            "reverse_if": ["fixture condition"],
            "reverse_if_state": [{"condition": "fixture condition", "verdict": "NOT_TRIGGERED",
                                  "detail": "fixture"}],
            "evidence_gate": ["fixture gate item"],
            "evidence_gate_state": [{"item": "fixture gate item", "verdict": "SATISFIED",
                                     "detail": "fixture", "receipts": ["receipts/fixture.json"],
                                     "digests": ["sha256:" + "4" * 64]}],
        },
        "data_signer": {"identity": "fixture data verifier", "role": "data verifier"},
        "writer_epoch": {"receipts": [], "changed_by_this_tool": False},
    }
    return ev


def _mut(fn):
    def build():
        ev = copy.deepcopy(_baseline())
        fn(ev)
        return ev
    return build


def _f_missing_plane(ev):
    ev["planes"]["index"] = {"state": "MISSING", "source": None, "denominator": "fixture",
                             "total": None, "rows": {c: None for c in CLASS_ROWS},
                             "verdict": "PLANNED_NOT_INGESTED", "planned_files": 2585,
                             "unmapped_values": []}
    ev["conflicts"]["index"] = {"count": None, "source": None, "denominator": None}


def _f_unknown_plane(ev):
    ev["planes"]["index"]["state"] = "UNKNOWN"
    ev["planes"]["index"]["rows"] = {c: None for c in CLASS_ROWS}


def _f_stale_epoch(ev):
    ev["epoch"]["observed_main_head"] = "c" * 40


def _f_hidden_mount(ev):
    ev["clean_read_through"]["execution"]["source_mount"] = True


def _f_data_pass_misread(ev):
    # the data half is clean; the authority half has not been reached at all
    ev["authority"]["state_machine"] = {"present": False, "path": "receipts/cutover/state.json",
                                        "state": None}


def _f_revoked(ev):
    ev["authority"]["superseded_by"] = [{"id": "DEC-AUP-0099", "issued_at_utc": "2026-06-01T00:00:00Z"}]


def _f_expired_before_fence(ev):
    ev["authority"]["reverse_if_state"] = [
        {"condition": "authority expires before the fence is armed", "verdict": "TRIGGERED",
         "detail": "expiry 2026-01-01, fence never armed"}]
    ev["fence"]["hourly_receipts"] = 3


def _f_signer_is_issuer(ev):
    ev["data_signer"]["identity"] = ev["authority"]["issuer_identity"]


def _f_restore_not_measured(ev):
    ev["restore"] = {"source": "fixture", "probe_verdicts": ["PAUSED_SAFE"], "probes": [],
                     "drill_receipts": [],
                     "state": "NOT_MEASURED", "dossier_task_verdict": "PAUSED_SAFE"}


def _f_search_found_store_lost(ev):
    """Spec scenario: search finds the document, but Muneral lost the transition."""
    ev["planes"]["muneral"]["rows"]["completed"] -= 1
    ev["planes"]["muneral"]["rows"]["planned"] += 1
    ev["planes"]["muneral"]["readback_mismatched"] = 1


def _f_mapping_behind(ev):
    ev["mapping"]["batch_revision"] = 2


def _f_dossier_unpinned(ev):
    ev["dossier"]["program_commit"] = "HEAD"
    ev["dossier"]["revision_pinned"] = False


def _f_today_shape(ev):
    """Compound fixture: several independent blocks plus a NOT_MEASURED authority gate."""
    _f_mapping_behind(ev)
    ev["authority"]["state_machine"] = {"present": False, "path": "receipts/cutover/state.json",
                                        "state": None}
    ev["authority"]["evidence_gate_state"] = [
        {"item": "fixture gate item", "verdict": NOT_MEASURED, "detail": "no probe defined"}]


FIXTURES = [
    # (name, builder, expected outcome, expected block reason codes)
    ("all_green", _mut(lambda ev: None), PASS, []),
    ("missing_plane", _mut(_f_missing_plane), BLOCK, ["MISSING_PLANE", "UNINDEXED_NOT_MEASURED"]),
    ("unknown_plane", _mut(_f_unknown_plane), BLOCK, ["PLANE_UNKNOWN", "UNINDEXED_NOT_MEASURED"]),
    ("stale_source_set_epoch", _mut(_f_stale_epoch), BLOCK, ["STALE_SOURCE_SET_EPOCH"]),
    ("canary_on_hidden_mount", _mut(_f_hidden_mount), BLOCK, ["HIDDEN_MOUNT_OR_CACHE"]),
    ("data_pass_misread_as_approval", _mut(_f_data_pass_misread), BLOCK,
     ["AUTHORITY_STATE_UNINITIALISED"]),
    ("authority_revoked", _mut(_f_revoked), BLOCK, ["AUTHORITY_REVOKED"]),
    ("authority_expired_before_fence", _mut(_f_expired_before_fence), BLOCK,
     ["AUTHORITY_EXPIRED"]),
    ("signer_is_issuer", _mut(_f_signer_is_issuer), BLOCK, ["AUTHORITY_SIGNER_IS_DATA_SIGNER"]),
    ("restore_not_measured", _mut(_f_restore_not_measured), BLOCK, ["RESTORE_NOT_MEASURED"]),
    ("search_finds_but_store_lost_transition", _mut(_f_search_found_store_lost), BLOCK,
     ["PLANE_DISAGREEMENT"]),
    ("mapping_revision_behind", _mut(_f_mapping_behind), BLOCK,
     ["MAPPING_REVISION_BEHIND_RECORD"]),
    ("dossier_revision_unpinned", _mut(_f_dossier_unpinned), BLOCK,
     ["DOSSIER_REVISION_UNPINNED"]),
    ("today_shape", _mut(_f_today_shape), BLOCK,
     ["MAPPING_REVISION_BEHIND_RECORD", "AUTHORITY_STATE_UNINITIALISED"]),
]


def signature(result):
    """What the oracle compares. Reason codes come from the VERIFIER reports, the outcome from the
    minted artifact — so a minting mutant and a verifying mutant are distinguishable."""
    art = result["artifact"]
    return {
        "outcome": result["outcome"],
        "reason_codes": sorted(set(result["data"]["reason_codes"] +
                                   result["authority"]["reason_codes"])),
        "not_measured": sorted(set(result["data"]["not_measured"] +
                                   result["authority"]["not_measured"])),
        "ref_kinds": sorted(r["kind"] for r in art.get("refs", [])) if art.get("refs") else [],
        "writer_changed": bool((art.get("writer_epoch") or {}).get("changed")),
    }


#: the oracle. A rule "fires" when it returns False.
RULES = {
    "R1_outcome": lambda exp, obs: obs["outcome"] == exp["outcome"],
    "R2_reason_codes": lambda exp, obs: obs["reason_codes"] == exp["reason_codes"],
    "R3_not_measured": lambda exp, obs: obs["not_measured"] == exp["not_measured"],
    # the ref rule answers "when an attestation IS minted, does it carry both refs?" — a
    # differing outcome is R1's finding, not R4's, so the two rules stay independently testable
    "R4_two_refs_on_pass": lambda exp, obs: (obs["ref_kinds"] == exp["ref_kinds"]
                                             if obs["outcome"] == exp["outcome"] else True),
    "R5_writer_unchanged": lambda exp, obs: obs["writer_changed"] is False,
}


def _fires(expected_sig, observed_sig):
    return sorted(name for name, rule in RULES.items() if not rule(expected_sig, observed_sig))


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


def selftest(verbose=True):
    results, failures = [], []

    def ok(msg):
        results.append(("ok", msg))
        if verbose:
            print("  [ok] %s" % msg)

    def bad(msg):
        results.append(("FAIL", msg))
        failures.append(msg)
        if verbose:
            print("  [FAIL] %s" % msg)

    # 1. reference run: every fixture behaves as the spec's table says, unmutated
    reference = {}
    for name, build, exp_outcome, exp_reasons in FIXTURES:
        res = run_gate(build(), frozenset(), captured_at="2026-01-01T00:00:00Z")
        reference[name] = signature(res)
        if res["outcome"] != exp_outcome:
            bad("fixture %s: outcome %s, expected %s" % (name, res["outcome"], exp_outcome))
            continue
        missing = [r for r in exp_reasons if r not in reference[name]["reason_codes"] +
                   reference[name]["not_measured"]]
        if missing:
            bad("fixture %s: reason codes %s missing from %s"
                % (name, missing, reference[name]["reason_codes"] + reference[name]["not_measured"]))
        else:
            ok("fixture %s -> %s %s" % (name, res["outcome"], exp_reasons or "(attestation)"))

    # 2. the green control really is green: two refs, kinds data+authority, writer unchanged
    green = reference.get("all_green", {})
    if green.get("outcome") == PASS and green.get("ref_kinds") == ["authority", "data"]:
        ok("all_green mints a CutoverReadinessAttestation with exactly two refs (data + authority)")
    else:
        bad("all_green did not mint a two-ref attestation (%s) — the battery would be vacuous"
            % green)
    if green.get("writer_changed") is False:
        ok("the attestation leaves the writer epoch unchanged")
    else:
        bad("the attestation claims a writer-epoch change")

    # 3. a data PASS alone is never permission
    res = run_gate(FIXTURES[5][1](), frozenset())
    if res["artifact"]["schema"] == "BlockReceipt/v1" and res["data"]["verdict"] == PASS:
        ok("data verifier PASS + authority BLOCK -> BlockReceipt, never an attestation")
    else:
        bad("a data PASS was turned into an attestation without authority")

    # 4. mutation battery: every mutant must be killed by at least one fixture
    kill_matrix = {}
    for mutant in MUTANTS:
        killers = []
        for name, build, _, _ in FIXTURES:
            obs = signature(run_gate(build(), frozenset([mutant]),
                                     captured_at="2026-01-01T00:00:00Z"))
            fired = _fires(reference[name], obs)
            if fired:
                killers.append({"fixture": name, "rules": fired})
        kill_matrix[mutant] = killers
        if killers:
            ok("mutant %s killed by %d fixture(s) (%s)"
               % (mutant, len(killers), killers[0]["fixture"]))
        else:
            bad("mutant %s SURVIVES every fixture" % mutant)

    # 5. rule battery: each oracle rule must be, somewhere, the ONLY rule that fires — otherwise it
    #    is untested and could be deleted without the battery noticing
    for rule in RULES:
        alone = [(m, k["fixture"]) for m, ks in kill_matrix.items() for k in ks
                 if k["rules"] == [rule]]
        if alone:
            ok("rule %s is uniquely necessary (%s on %s)" % (rule, alone[0][0], alone[0][1]))
        else:
            bad("rule %s never fires alone — untested by the battery" % rule)

    # 6. negative control of the battery itself: a no-op mutant must be killed by nothing
    noop = [name for name, build, _, _ in FIXTURES
            if _fires(reference[name], signature(run_gate(build(), frozenset(["__noop__"]),
                                                          captured_at="2026-01-01T00:00:00Z")))]
    if noop:
        bad("negative control: an inert mutant changed %s — the oracle is nondeterministic" % noop)
    else:
        ok("negative control: an inert mutant is killed by no fixture")

    # 7. determinism: the same evidence yields byte-identical reports
    a = run_gate(_baseline(), frozenset(), captured_at="2026-01-01T00:00:00Z")
    b = run_gate(_baseline(), frozenset(), captured_at="2026-01-01T00:00:00Z")
    if sha256_obj(a) == sha256_obj(b):
        ok("determinism: two runs over the same evidence are byte-identical")
    else:
        bad("determinism: two runs over the same evidence differ")

    # 8. the raw side is classified THROUGH the versioned map, and the revision changes the answer
    m2 = {"archived": {"muneral": "done"}, "done": {"muneral": "done"}}
    m3 = {"archived": {"muneral": "archived"}, "done": {"muneral": "done"}}
    r2, _ = _classify_raw({"archived": 1351, "done": 497}, m2)
    r3, _ = _classify_raw({"archived": 1351, "done": 497}, m3)
    if r2["completed"] == 1848 and r3["completed"] == 497 and r3["archived"] == 1351:
        ok("the status-map revision changes the class rows and the tool measures the difference")
    else:
        bad("the status-map revision made no measurable difference: %s vs %s" % (r2, r3))

    # 9. `archived` is never folded into `completed` (DEC-AUP-0014 rule 3, I4)
    if PROJECTED_TO_CLASS["archived"] == "archived" and r3["completed"] == 497:
        ok("`archived` is a row of its own and never totalises into `completed`")
    else:
        bad("`archived` was folded into `completed`")

    # 10. an unknown raw status is a typed refusal, never a silent default
    rows, unmapped = _classify_raw({"weird_value": 1}, m3)
    if unmapped == ["weird_value"] and sum(v for v in rows.values() if v) == 0:
        ok("an unknown raw status is typed UNMAPPED, never defaulted into a class")
    else:
        bad("an unknown raw status was silently defaulted")

    # 11. no map at all is UNKNOWN, not an empty pass
    rows, unmapped = _classify_raw({"done": 3}, None)
    if all(v is None for v in rows.values()) and unmapped == ["done"]:
        ok("with no status map the files plane answers UNKNOWN, never zero")
    else:
        bad("a missing status map produced a class table instead of UNKNOWN")

    # 12/13. the contract is binding on the producer: every document this tool can emit must carry
    #        the fields the contract requires, and the attestation must carry exactly two refs
    contract_path = find_contract()
    if contract_path is None:
        contract = None
        bad("the contract %s was found in none of %s — a copy of this tool that cannot reach its "
            "contract is not verifiable" % (CONTRACT_NAME, CONTRACT_CANDIDATE_DIRS))
    else:
        try:
            contract = read_json(contract_path)
            ok("contract resolved at %s" % contract_path)
        except Exception as exc:
            contract = None
            bad("the contract %s could not be read (%s)" % (contract_path, exc))
    if contract:
        fields = contract["fields"]
        att = run_gate(FIXTURES[0][1](), frozenset(),
                       captured_at="2026-01-01T00:00:00Z")["artifact"]
        blk = run_gate(FIXTURES[1][1](), frozenset(),
                       captured_at="2026-01-01T00:00:00Z")["artifact"]
        miss = [f for f in fields["common_required"] + fields["attestation_required"]
                if f not in att]
        miss += ["block:" + f for f in fields["common_required"] + fields["block_required"]
                 if f not in blk]
        if miss:
            bad("documents miss contract-required fields: %s" % miss)
        else:
            ok("both emitted documents carry every field the contract requires")
        kinds = sorted(r["kind"] for r in att["refs"])
        if (len(att["refs"]) == fields["refs"]["cardinality"] and kinds == ["authority", "data"]
                and all(k in att["refs"][kinds.index("data")] or True
                        for k in fields["refs"]["data"]["required"])):
            missing_ref_fields = [
                "data:" + k for k in fields["refs"]["data"]["required"]
                if k not in [r for r in att["refs"] if r["kind"] == "data"][0]
            ] + [
                "authority:" + k for k in fields["refs"]["authority"]["required"]
                if k not in [r for r in att["refs"] if r["kind"] == "authority"][0]
            ]
            if missing_ref_fields:
                bad("the attestation's refs miss contract-required fields: %s" % missing_ref_fields)
            else:
                ok("the attestation carries exactly two refs, both complete per the contract")
        else:
            bad("the attestation does not carry the two refs the contract requires")

    total = len(results)
    passed = sum(1 for kind, _ in results if kind == "ok")
    if verbose:
        print("selftest %d/%d %s" % (passed, total, "PASS" if not failures else "FAIL"))
    return {"total": total, "passed": passed, "failures": failures,
            "kill_matrix": kill_matrix,
            "fixtures": [f[0] for f in FIXTURES], "mutants": MUTANTS,
            "rules": sorted(RULES)}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _plane_table(ev):
    planes = ev.get("planes", {})
    table = {"rows": {}, "planes": {}}
    for pl in PLANES:
        p = planes.get(pl, {}) or {}
        table["planes"][pl] = {"state": p.get("state"), "source": p.get("source"),
                               "denominator": p.get("denominator"), "total": p.get("total"),
                               "status_map_revision_used": p.get("status_map_revision_used")}
        for extra in ("verdict", "not_indexed", "no_claim_occurrences",
                      "rows_under_batch_revision", "unmapped_values"):
            if p.get(extra) not in (None, [], {}):
                table["planes"][pl][extra] = p[extra]
    for cls in CLASS_ROWS:
        table["rows"][cls] = {pl: ((planes.get(pl, {}) or {}).get("rows") or {}).get(cls)
                              for pl in PLANES}
    idx = planes.get("index", {}) or {}
    table["rows"]["unindexed"] = {
        "files": idx.get("planned_files"),
        "muneral": (planes.get("muneral", {}) or {}).get("readback_identities"),
        "index": idx.get("total"),
        "index_not_indexed": idx.get("not_indexed"),
        "note": "identities/files present in the source set and in the store, and what the index "
                "plane acknowledges of them; `index: null` means the plane cannot answer at all",
    }
    c = ev.get("conflicts", {})
    table["rows"]["conflicts"] = {pl: (c.get(pl, {}) or {}).get("count") for pl in PLANES}
    table["rows"]["conflicts"]["denominators"] = {pl: (c.get(pl, {}) or {}).get("denominator")
                                                  for pl in PLANES}
    return table


def cmd_consume(args):
    root = os.path.abspath(args.root)
    ts = utcnow()
    stamp = ts.replace("-", "").replace(":", "")
    ev = collect_evidence(root, ws_head=args.ws_head, dossier_path=args.dossier,
                          model=args.model)
    result = run_gate(ev, frozenset(), captured_at=ts)

    artifact = result["artifact"]
    kind = "attestation" if artifact["schema"] == "CutoverReadinessAttestation/v1" else "block"
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    art_path = os.path.join(out_dir, "gate0-%s-%s.json" % (kind, stamp))
    with open(art_path, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=1, ensure_ascii=False, sort_keys=True)
        fh.write("\n")

    receipt = {
        "schema": "ReadinessReceipt/v1",
        "portion_id": "AUP-MIG-015:gate0",
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "captured_at_utc": ts,
        "host": ev.get("host"),
        "program_commit": (ev.get("program") or {}).get("commit"),
        "read_only": True,
        "model": args.model,
        "provisional_until_fable_review": True,
        "decision_refs": ["DEC-AUP-0012", "DEC-AUP-0014", "DEC-AUP-0010", "DEC-AUP-0008",
                          "DEC-AUP-0015"],
        "verdict": result["outcome"],
        "artifact": {"schema": artifact["schema"], "path": rel(root, art_path),
                     "digest": sha256_obj(artifact)},
        "source_set_epoch": (ev.get("epoch") or {}).get("declared"),
        "source_set_epoch_observed_head": (ev.get("epoch") or {}).get("observed_main_head"),
        "planes": _plane_table(ev),
        "data_verifier": result["data"],
        "authority_verifier": result["authority"],
        "blocked_by": artifact.get("blocked_by", []),
        "not_measured": sorted(set(result["data"]["not_measured"] +
                                   result["authority"]["not_measured"])),
        "evidence_inputs": {
            "dossier": (ev.get("dossier") or {}).get("path"),
            "import_verify": (ev.get("epoch") or {}).get("source"),
            "index": (ev.get("planes", {}).get("index") or {}).get("source"),
            "byte_copy": (ev.get("byte_copy") or {}).get("source"),
            "restore": (ev.get("restore") or {}).get("source"),
            "clean_read_through": {k: v.get("source")
                                   for k, v in (ev.get("clean_read_through") or {}).items()},
            "fence_observation": (ev.get("fence") or {}).get("latest"),
            "authority_decision": (ev.get("authority") or {}).get("path"),
            "cutover_state": (ev.get("authority") or {}).get("state_machine", {}).get("path"),
        },
        "writer_epoch": {"changed": False,
                         "rule": "this card mints no authority and never changes the writer epoch"},
        "rule": ("never a PASS by default: a missing plane, a hidden mount or cache, an UNKNOWN, a "
                 "stale SourceSetEpoch or an invalid/revoked authority all block; an attestation is "
                 "minted only when both verifiers PASS and carries two refs"),
    }
    rpath = os.path.join(out_dir, "gate0-%s.json" % stamp)
    with open(rpath, "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=1, ensure_ascii=False, sort_keys=True)
        fh.write("\n")

    print(json.dumps({
        "verdict": result["outcome"],
        "artifact": artifact["schema"],
        "blocked_by": artifact.get("blocked_by", []),
        "not_measured": receipt["not_measured"],
        "receipt": rel(root, rpath),
        "artifact_path": rel(root, art_path),
    }, ensure_ascii=False))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--selftest-receipt", help="with --selftest: write a ReadinessReceipt/v1 here")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("consume", help="run both verifiers over the real receipts")
    c.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))))
    c.add_argument("--out", default=None, help="receipt directory (default <root>/receipts/mig)")
    c.add_argument("--ws-head", default=None,
                   help="observed head of the source-set repository (default: newest "
                        "FenceObservationReceipt)")
    c.add_argument("--dossier", default=None, help="explicit AUP-DAT-020 acceptance receipt")
    c.add_argument("--model", default=DEFAULT_MODEL,
                   help="the model of the invoking life (DEC-AUP-0015); a declared parameter, "
                        "never measured here")
    c.set_defaults(func=cmd_consume)
    args = ap.parse_args(argv)

    if args.selftest:
        rep = selftest()
        if args.selftest_receipt:
            with open(args.selftest_receipt, "w", encoding="utf-8") as fh:
                json.dump({
                    "schema": "ReadinessReceipt/v1",
                    "portion_id": "AUP-MIG-015:gate0",
                    "tool": TOOL, "tool_version": TOOL_VERSION,
                    "captured_at_utc": utcnow(),
                    "host": os.uname().nodename,
                    "model": DEFAULT_MODEL,
                    "provisional_until_fable_review": True,
                    "read_only": True,
                    "decision_refs": ["DEC-AUP-0012", "DEC-AUP-0014", "DEC-AUP-0015"],
                    "verdict": "PASS" if not rep["failures"] else "FAIL",
                    "selftest": {k: v for k, v in rep.items() if k != "kill_matrix"},
                    "mutation_battery": rep["kill_matrix"],
                }, fh, indent=1, ensure_ascii=False, sort_keys=True)
                fh.write("\n")
        return 0 if not rep["failures"] else 1

    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    if args.out is None:
        args.out = os.path.join(os.path.abspath(args.root), "receipts", "mig")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
