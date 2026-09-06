"""AUP-MIG-016 `coord0` — the evidence gates of DEC-AUP-0012, one evaluator per ladder transition.

Each transition of the persisted ladder (`FILES_AUTHORITATIVE → … → MUNERAL_AUTHORITATIVE`) has an
evaluator that reads the *named* receipts from the program's `receipts/` tree and answers
tri-valued: `PASS`, `BLOCK` (the evidence exists and says no, or it is missing) and `NOT_MEASURED`
(nobody has measured it — never read as a pass). A gate passes only when every requirement passes;
one `NOT_MEASURED` is enough to keep the ladder where it is.

Every verdict names the receipt class it wanted, the card that has to mint it, the files it found
(with digests) and the files it did not find. That list is the interface to the producing cards:
a requirement whose class does not exist yet fixes the schema name here.

Read-only: nothing under `receipts/` is written by this module.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

PASS, BLOCK, NOT_MEASURED = "PASS", "BLOCK", "NOT_MEASURED"
MAX_PARSE_BYTES = 2_000_000  # bigger receipts are indexed by digest only and reported as skipped

# mutations of the gate layer (see gate_oracle.py: each must be killed by a rule)
GATE_MUTATIONS = {
    "N05_gate_passes_with_missing_receipt": "a requirement whose evidence is missing is reported PASS",
    "N09_not_measured_counts_as_pass": "a NOT_MEASURED requirement is folded into the PASS majority",
    "N10_gate_omits_missing_receipts": "the verdict lists the receipts that exist and hides the missing ones",
    "N12_delta_checklist_list_shape_dropped": "the delta-batch normaliser drops the list-of-items checklist "
                                              "shape, treating a real (list-shaped) checklist as unrecognised",
    "N13_delta_checklist_mismatch_ignored": "an unrecognised delta-batch checklist shape is treated as an "
                                            "empty checklist instead of a typed BLOCK (COORD-FIX0)",
    "N14_derived_marker_ignores_in_place_rewrite": "a DerivedMarkerAudit/v1 reporting >=1 in-place rewrite "
                                                   "still PASSes the derived-marker requirement (SHADOW-MARKER0)",
    "N15_derived_marker_stale_accepted": "the derived-marker requirement PASSes an audit whose tree_digest "
                                         "does not match the stable ShadowProjectionReceipt/v1 run (SHADOW-MARKER0)",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def parse_iso(s: Any) -> Optional[datetime]:
    if not isinstance(s, str):
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None


@dataclass
class Doc:
    path: str
    digest: str
    schema: Optional[str]
    doc: Optional[Dict[str, Any]]
    captured_at: Optional[datetime]

    def ref(self) -> Dict[str, Any]:
        return {"path": self.path, "digest": self.digest,
                "captured_at_utc": self.captured_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.captured_at else None}


class EvidenceIndex:
    """Every JSON receipt of the program, indexed by its `schema`. Files above `MAX_PARSE_BYTES`
    and files that do not parse are recorded as *skipped* — a gate that would have needed one of
    them is NOT_MEASURED, never PASS."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.by_schema: Dict[str, List[Doc]] = {}
        self.skipped: List[Dict[str, Any]] = []
        self.files = 0
        for dirpath, _dirs, files in os.walk(root / "receipts"):
            for name in sorted(files):
                if not name.endswith(".json"):
                    continue
                p = Path(dirpath) / name
                rel = str(p.relative_to(root))
                self.files += 1
                try:
                    size = p.stat().st_size
                except OSError as exc:
                    self.skipped.append({"path": rel, "reason": f"stat_failed:{exc.__class__.__name__}"})
                    continue
                if size > MAX_PARSE_BYTES:
                    self.skipped.append({"path": rel, "reason": "larger_than_parse_limit", "bytes": size})
                    continue
                try:
                    doc = json.loads(p.read_text(encoding="utf-8"))
                except (ValueError, OSError, UnicodeDecodeError) as exc:
                    self.skipped.append({"path": rel, "reason": f"unparsable:{exc.__class__.__name__}"})
                    continue
                if not isinstance(doc, dict):
                    continue
                schema = doc.get("schema")
                if not isinstance(schema, str):
                    continue
                d = Doc(rel, sha256_file(p), schema, doc, parse_iso(doc.get("captured_at_utc") or doc.get("issued_at_utc")))
                self.by_schema.setdefault(schema, []).append(d)
        for docs in self.by_schema.values():
            docs.sort(key=lambda d: (d.captured_at or datetime.min.replace(tzinfo=timezone.utc), d.path))

    def of(self, schema: str, where: Optional[Callable[[Doc], bool]] = None) -> List[Doc]:
        return [d for d in self.by_schema.get(schema, []) if where is None or where(d)]

    def summary(self) -> Dict[str, Any]:
        return {
            "root": str(self.root),
            "json_files_seen": self.files,
            "schemas_indexed": len(self.by_schema),
            "skipped": self.skipped,
            "skipped_count": len(self.skipped),
        }


@dataclass
class Requirement:
    id: str
    question: str
    receipt_class: str
    producer: str            # the card / decision that has to mint the evidence
    check: Callable[[EvidenceIndex], Tuple[str, Optional[str], Dict[str, Any]]]


def _refs(docs: List[Doc], limit: int = 12) -> List[Dict[str, Any]]:
    return [d.ref() for d in docs[:limit]]


# ------------------------------------------------------------------ individual requirements
def _shadow_runs(idx: EvidenceIndex) -> Tuple[List[Doc], List[Tuple[str, int]]]:
    """Shared by `_shadow_stable` and `_derived_marker`: every ShadowProjectionReceipt/v1 carrying an
    `output_digest`, in index order (captured_at_utc, then path), reduced to consecutive-run lengths
    per digest."""
    docs = [d for d in idx.of("ShadowProjectionReceipt/v1") if isinstance(d.doc, dict) and d.doc.get("output_digest")]
    runs: List[Tuple[str, int]] = []
    for d in docs:
        dig = d.doc["output_digest"]
        if runs and runs[-1][0] == dig:
            runs[-1] = (dig, runs[-1][1] + 1)
        else:
            runs.append((dig, 1))
    return docs, runs


def _longest_stable_run(runs: List[Tuple[str, int]]) -> Tuple[Optional[str], int]:
    if not runs:
        return None, 0
    dig, n = max(runs, key=lambda r: r[1])
    return dig, n


def _shadow_stable(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs, runs = _shadow_runs(idx)
    longest_digest, longest = _longest_stable_run(runs)
    detail = {
        "required": "≥ 10 consecutive regenerations byte-stable on the projected fields (DEC-AUP-0012 rule 2)",
        "receipts_found": len(docs),
        "longest_stable_run": longest,
        "longest_stable_run_output_digest": longest_digest,
        "runs": [{"output_digest": dig, "consecutive": n} for dig, n in runs],
        "present": _refs(docs),
        "missing": [] if longest >= 10 else [f"{10 - longest} further consecutive ShadowProjectionReceipt/v1 with the same output_digest"],
    }
    if not docs:
        return NOT_MEASURED, "SHADOW_PROJECTION_NOT_MEASURED", detail
    return (PASS, None, detail) if longest >= 10 else (BLOCK, "SHADOW_NOT_YET_STABLE", detail)


def _parity_pairs(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("ProjectionParity/v1")
    good = [d for d in docs if d.doc.get("identical_digest") is True
            and float(d.doc.get("gap_seconds") or 0) >= 3600.0
            and str(d.doc.get("status", "")).upper() in ("VERIFIED", "PASS")]
    detail = {
        "required": "2 × ProjectionParity/v1, identical digest, the pair ≥ 1 h apart (DEC-AUP-0012 rule 2 / rule 4)",
        "receipts_found": len(docs),
        "qualifying": len(good),
        "present": _refs(docs),
        "rejected": [{"path": d.path, "identical_digest": d.doc.get("identical_digest"),
                      "gap_seconds": d.doc.get("gap_seconds"), "status": d.doc.get("status")}
                     for d in docs if d not in good],
        "missing": [] if len(good) >= 2 else [f"{2 - len(good)} further qualifying ProjectionParity/v1"],
    }
    if not docs:
        return NOT_MEASURED, "PARITY_NOT_MEASURED", detail
    return (PASS, None, detail) if len(good) >= 2 else (BLOCK, "PARITY_INSUFFICIENT", detail)


def _derived_marker(idx: EvidenceIndex, mutations: frozenset = frozenset()) -> Tuple[str, Optional[str], Dict[str, Any]]:
    """AUP-MIG-016 SHADOW-MARKER0: reads `DerivedMarkerAudit/v1` (tools/projection/marker_audit.py),
    the real per-row audit `ShadowProjectionReceipt/v1` never asserted. PASS requires: an audit exists,
    its `tree_digest` matches the digest of the longest byte-stable ShadowProjectionReceipt/v1 run
    (never a stale revision), 0 unmarked derived rows, 0 malformed markers, 0 in-place rewrites, and
    every held identity renders every raw value it has (`held_both_values_count == held_total`)."""
    docs = idx.of("DerivedMarkerAudit/v1")
    _, runs = _shadow_runs(idx)
    stable_digest, stable_len = _longest_stable_run(runs)
    detail: Dict[str, Any] = {
        "required": "every derived row carries `<!-- derived: muneral <batch> rule_rev <n> -->`, 0 raw statuses "
                    "rewritten in place, held identities render every raw value seen, audited over every row, "
                    "no sampling (DEC-AUP-0012 rule 2, I4)",
        "receipts_found": len(docs),
        "present": _refs(docs),
        "stable_run_output_digest": stable_digest,
        "stable_run_length": stable_len,
    }
    if not docs:
        detail["missing"] = ["a DerivedMarkerAudit/v1 receipt (tools/projection/marker_audit.py has not been run "
                             "against a shadow-branch revision yet)"]
        return NOT_MEASURED, "DERIVED_MARKER_NOT_MEASURED", detail

    latest = docs[-1]
    a = latest.doc if isinstance(latest.doc, dict) else {}
    audited_digest = a.get("tree_digest")
    unmarked = a.get("unmarked_derived") or []
    malformed = a.get("malformed_markers") or []
    in_place = a.get("in_place_rewrites") or []
    held_total = a.get("held_total")
    held_both = a.get("held_both_values_count")
    detail.update({
        "latest_audit": latest.ref(),
        "audited_tree_digest": audited_digest,
        "rows_total": a.get("rows_total"),
        "derived_eligible_rows": a.get("derived_eligible_rows"),
        "derived_marked_count": a.get("derived_marked_count"),
        "unmarked_derived_count": len(unmarked),
        "malformed_marker_count": len(malformed),
        "in_place_rewrite_count": len(in_place),
        "held_total": held_total,
        "held_both_values_count": held_both,
    })

    stale = stable_digest is None or audited_digest != stable_digest
    if stale and "N15_derived_marker_stale_accepted" not in mutations:
        detail["missing"] = [f"a DerivedMarkerAudit/v1 whose tree_digest matches the stable "
                             f"ShadowProjectionReceipt/v1 run's output_digest ({stable_digest!r}); the latest "
                             f"audit measured {audited_digest!r}"]
        return BLOCK, "MARKER_AUDIT_STALE", detail

    violations: List[str] = []
    if unmarked:
        violations.append(f"{len(unmarked)} unmarked derived row(s): {[u.get('legacyId') for u in unmarked][:10]}")
    if malformed:
        violations.append(f"{len(malformed)} malformed derived marker(s): {[m.get('legacyId') for m in malformed][:10]}")
    if in_place and "N14_derived_marker_ignores_in_place_rewrite" not in mutations:
        violations.append(f"{len(in_place)} identity(ies) with a raw status rewritten in place: {[i.get('legacyId') for i in in_place][:10]}")
    if held_total is not None and held_both is not None and held_both != held_total:
        violations.append(f"held identities render every raw value on {held_both}/{held_total}, not {held_total}/{held_total}")
    detail["missing"] = violations
    if violations:
        return BLOCK, "DERIVED_MARKER_VIOLATION", detail
    return PASS, None, detail


def _freeze_activation(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("FreezeActivationReceipt/v1")
    detail = {
        "required": "FreezeActivationReceipt/v1 citing every hourly receipt digest, the ruleset id + evaluate "
                    "results (0 violations), the fence selftest, the canary receipts, the rollback drill and the "
                    "latest FleetDrainReceipt (DEC-AUP-0011)",
        "present": _refs(docs),
        "missing": [] if docs else ["FreezeActivationReceipt/v1 (no document of this class exists)"],
    }
    return (PASS, None, detail) if docs else (BLOCK, "FREEZE_NOT_ACTIVATED", detail)


def _fence_observation_window(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("FenceObservationReceipt/v1")
    clean = [d for d in docs if (d.doc.get("foreign_writes") in (0, [], None)) and d.doc.get("canary_seen") is True]
    detail = {
        "required": "W = max(72 h, 3 × the longest gap between foreign writes) consecutive hourly "
                    "FenceObservationReceipt/v1 with foreign_writes = 0 and canary_seen = true (DEC-AUP-0011)",
        "window_hours_minimum": 72,
        "receipts_found": len(docs),
        "receipts_with_canary_and_no_foreign_write": len(clean),
        "present": _refs(docs),
        "missing": [] if len(clean) >= 72 else
                   [f"{max(0, 72 - len(clean))} further hourly FenceObservationReceipt/v1 with canary_seen = true"],
    }
    if not docs:
        return NOT_MEASURED, "FENCE_OBSERVATION_NOT_MEASURED", detail
    if len(clean) >= 72:
        return PASS, None, detail
    return BLOCK, "FENCE_WINDOW_INCOMPLETE", detail


def _fleet_drain(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("FleetDrainReceipt/v1")
    latest = docs[-1] if docs else None
    undetermined = latest.doc.get("undetermined_count") if latest else None
    detail = {
        "required": "the latest FleetDrainReceipt has undetermined_count = 0 (NOT_DRAINED is allowed) (DEC-AUP-0011)",
        "present": _refs(docs),
        "latest": latest.ref() if latest else None,
        "undetermined_count": undetermined,
        "missing": [] if docs else ["FleetDrainReceipt/v1"],
    }
    if latest is None:
        return NOT_MEASURED, "DRAIN_NOT_MEASURED", detail
    return (PASS, None, detail) if undetermined == 0 else (BLOCK, "DRAIN_UNDETERMINED", detail)


def _freeze_rollback_drill(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("FreezeRollbackDrillReceipt/v1")
    ok = [d for d in docs if str(d.doc.get("verdict", "")).upper().startswith("PASS")]
    detail = {
        "required": "FreezeRollbackDrillReceipt/v1 PASS ≤ 5 min (DEC-AUP-0011)",
        "present": _refs(docs),
        "passing": _refs(ok),
        "missing": [] if ok else ["a passing FreezeRollbackDrillReceipt/v1"],
    }
    if not docs:
        return NOT_MEASURED, "FREEZE_ROLLBACK_NOT_MEASURED", detail
    return (PASS, None, detail) if ok else (BLOCK, "FREEZE_ROLLBACK_NOT_PASSED", detail)


def _fence_proof(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("FenceProofReceipt/v1")
    detail = {
        "required": "a staging rejection receipt carrying the real FENCED_WRITE_DENIED log line AND one "
                    "ruleset-refused push (DEC-AUP-0012 rule 3)",
        "present": _refs(docs),
        "missing": [] if docs else ["FenceProofReceipt/v1 (class not minted yet; this evaluator fixes the name "
                                    "for the producing card)"],
    }
    return (PASS, None, detail) if docs else (BLOCK, "FENCE_PROOF_MISSING", detail)


def _projection_100(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("ShadowProjectionReceipt/v1")
    latest = docs[-1] if docs else None
    rows = latest.doc.get("rows_total") if latest else None
    identical = latest.doc.get("rows_identical") if latest else None
    detail = {
        "required": "PROJECTION_VERIFIED on 100 % of the fenced files (1,382 rows, no sampling) (DEC-AUP-0012 rule 4)",
        "expected_rows": 1382,
        "latest": latest.ref() if latest else None,
        "rows_total": rows,
        "rows_identical": identical,
        "findings": latest.doc.get("finding_count") if latest else None,
        "present": _refs(docs[-3:]),
        "missing": [] if (rows == 1382 and identical == rows) else
                   ["a receipt in which every fenced row is verified (rows_identical = rows_total = 1382)"],
    }
    if latest is None:
        return NOT_MEASURED, "PROJECTION_NOT_MEASURED", detail
    if rows == 1382 and identical == rows:
        return PASS, None, detail
    return BLOCK, "PROJECTION_NOT_VERIFIED", detail


#: the eight conditions DEC-AUP-0012 rule 5 puts on a second import batch, by the key the producing
#: card records them under. A condition the producer does not report at all is NOT_MEASURED.
DELTA_CONDITIONS = [
    "sourceSetEpoch_git_pinned",
    "capturedAt_pinned",
    "unmappedCount_0",
    "statusMapRevision_unchanged_or_bumped_by_decision",
    "rerun_converges_to_one_occurrenceDigest",
    "epoch1_occurrenceDigest_unchanged",
    "new_conflicts_projected_under_DEC_AUP_0014",
    "verify_import_passes_under_batch_epoch",
]


#: the list-shape checklist (e.g. receipts/delta/importer-scope0-*.json) names each condition by a
#: free-text `check` label rather than the DELTA_CONDITIONS slug; this is the map from the label as
#: minted by the real producing cards to the canonical slug. A label that matches no condition (after
#: the punctuation-insensitive fallback below) is recorded as an *additional* condition, not dropped.
DELTA_CONDITION_ALIASES: Dict[str, str] = {
    "sourceSetEpoch git-pinned": "sourceSetEpoch_git_pinned",
    "capturedAt pinned": "capturedAt_pinned",
    "unmappedCount = 0": "unmappedCount_0",
    "statusMapRevision unchanged or bumped by decision": "statusMapRevision_unchanged_or_bumped_by_decision",
    "rerun converges to one occurrenceDigest": "rerun_converges_to_one_occurrenceDigest",
    "epoch-1 occurrenceDigest unchanged": "epoch1_occurrenceDigest_unchanged",
    "new conflicts projected under DEC-AUP-0014": "new_conflicts_projected_under_DEC_AUP_0014",
    "verify_import.py PASS under the batch's epoch": "verify_import_passes_under_batch_epoch",
}


def _slug(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


_ALIAS_BY_SLUG = {_slug(k): v for k, v in DELTA_CONDITION_ALIASES.items()}
_CONDITION_BY_SLUG = {_slug(c): c for c in DELTA_CONDITIONS}


def _match_delta_condition(label: str) -> Optional[str]:
    slug = _slug(label)
    return _CONDITION_BY_SLUG.get(slug) or _ALIAS_BY_SLUG.get(slug)


def _normalize_delta_checklist(block: Any, mutations: frozenset = frozenset()
                                ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Turns either known checklist shape into (condition_map, extra_map): `condition_map` keys are
    DELTA_CONDITIONS slugs, `extra_map` holds everything reported beyond the eight. Returns (None,
    None) for any other shape — the caller turns that into a typed BLOCK, never an exception."""
    if isinstance(block, dict):
        condition_map = {c: block[c] for c in DELTA_CONDITIONS if c in block}
        extra_map = {k: v for k, v in block.items() if k not in DELTA_CONDITIONS}
        return condition_map, extra_map
    if isinstance(block, list) and "N12_delta_checklist_list_shape_dropped" not in mutations:
        condition_map, extra_map = {}, {}
        for item in block:
            if not isinstance(item, dict) or not isinstance(item.get("check"), str):
                return None, None
            matched = _match_delta_condition(item["check"])
            (condition_map if matched else extra_map)[matched or item["check"]] = item.get("verdict")
        return condition_map, extra_map
    if "N13_delta_checklist_mismatch_ignored" in mutations:
        return {}, {}
    return None, None


def _delta_batch(idx: EvidenceIndex, mutations: frozenset = frozenset()) -> Tuple[str, Optional[str], Dict[str, Any]]:
    """Reads the delta-import card's own checklist wherever it wrote it (any receipt carrying a
    `delta_imported_checklist*` block), and re-aggregates the eight conditions here — the gate never
    inherits the producer's summary verdict. The block may be a dict keyed by condition or a list of
    `{check, verdict}` items (both shapes seen in real receipts); any other shape is a typed BLOCK,
    never an exception (COORD-FIX0)."""
    docs = [d for d in idx.of("ReadinessReceipt/v1")
            if isinstance(d.doc, dict) and any(k.startswith("delta_imported_checklist") for k in d.doc)]
    imports = [d for d in idx.of("ReadinessReceipt/v1") if d.path.startswith("receipts/import/verify-")]
    detail: Dict[str, Any] = {
        "required": "a second import batch: sourceSetEpoch git-pinned to a workspace main commit, capturedAt "
                    "pinned, unmappedCount = 0, statusMapRevision unchanged or bumped by a decision, the rerun "
                    "converges to one occurrenceDigest, the epoch-1 occurrenceDigest unchanged, new conflicts "
                    "projected under DEC-AUP-0014, verify_import PASS under the batch's epoch (DEC-AUP-0012 rule 5)",
        "checklists_found": _refs(docs),
        "import_verify_receipts": _refs(imports),
        "source_set_deltas": len(idx.of("SourceSetDelta/v1")),
    }
    if not docs:
        detail["missing"] = ["a receipt carrying the DEC-AUP-0012 rule-5 checklist for the second (delta) batch "
                             "— the follow-up batch for ARCA-0211 / MUN-0040 named by the decision"]
        return BLOCK, "DELTA_BATCH_NOT_ADMITTED", detail
    latest = docs[-1]
    block = next((v for k, v in latest.doc.items() if k.startswith("delta_imported_checklist")), {})
    condition_map, extra_map = _normalize_delta_checklist(block, mutations)
    if condition_map is None:
        detail.update({
            "checklist_source": latest.ref(),
            "offending_shape": type(block).__name__,
            "missing": [f"delta_imported_checklist at {latest.path} is neither a dict keyed by condition nor "
                        "a list of {check, verdict} items"],
        })
        return BLOCK, "DELTA_CHECKLIST_SCHEMA_MISMATCH", detail
    conditions: Dict[str, str] = {}
    for cond in DELTA_CONDITIONS:
        raw = condition_map.get(cond)
        verdict = raw.get("verdict") if isinstance(raw, dict) else raw
        conditions[cond] = str(verdict).upper() if verdict is not None else "NOT_REPORTED"
    extra = {k: (v.get("verdict") if isinstance(v, dict) else v) for k, v in extra_map.items()}
    failed = [c for c, v in conditions.items() if v not in ("PASS", "NOT_MEASURED", "NOT_REPORTED")]
    unmeasured = [c for c, v in conditions.items() if v in ("NOT_MEASURED", "NOT_REPORTED")]
    detail.update({
        "checklist_source": latest.ref(),
        "conditions": conditions,
        "additional_conditions_reported_by_the_producer": extra,
        "note": "the producer's own summary verdict is not inherited; the eight conditions are re-aggregated here",
        "missing": [] if not (failed or unmeasured) else
                   [f"condition {c} = {conditions[c]}" for c in failed + unmeasured],
    })
    if failed:
        return BLOCK, "DELTA_CONDITION_FAILED", detail
    if unmeasured:
        return NOT_MEASURED, "DELTA_CONDITION_NOT_MEASURED", detail
    return PASS, None, detail


def _cutover_rollback_drill(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("CutoverRollbackDrillReceipt/v1")
    detail = {
        "required": "CutoverRollbackDrillReceipt/v1 PASS ≤ 15 min (DEC-AUP-0012 rule 6)",
        "present": _refs(docs),
        "missing": [] if docs else ["CutoverRollbackDrillReceipt/v1"],
    }
    return (PASS, None, detail) if docs else (BLOCK, "CUTOVER_ROLLBACK_DRILL_MISSING", detail)


def _db_restore_drill(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("DatabaseRestoreDrillReceipt/v1")
    surveys = [d for d in idx.of("ReadinessReceipt/v1") if d.path.startswith("receipts/recovery/backup-survey")]
    detail = {
        "required": "a scripted restore drill of the Muneral database (arcanada_muneral, from the restic "
                    "snapshot named in the backup survey) with restore time and row counts vs live "
                    "(DEC-AUP-0012 rule 6)",
        "input_present": _refs(surveys),
        "present": _refs(docs),
        "missing": [] if docs else ["DatabaseRestoreDrillReceipt/v1 (class not minted yet; the backup survey is "
                                    "the input it must cite)"],
    }
    return (PASS, None, detail) if docs else (BLOCK, "DB_RESTORE_DRILL_MISSING", detail)


def _writer_epoch(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("WriterEpochReceipt/v1")
    detail = {
        "required": "WriterEpochReceipt/v1 present in program main and naming the Muneral batch, which names "
                    "the commit back (DEC-AUP-0012 rule 8)",
        "present": _refs(docs),
        "missing": [] if docs else ["WriterEpochReceipt/v1"],
    }
    return (PASS, None, detail) if docs else (BLOCK, "WRITER_EPOCH_RECEIPT_MISSING", detail)


def _key_inventory(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("KeyInventoryReceipt/v1")
    detail = {
        "required": "a key-inventory receipt per step: the projection bot is a least-privilege GitHub App "
                    "scoped to arcanada-workspace with contents:write on the datarim task paths only, a "
                    "read-only Muneral key, and no shared key between bot and agents (DEC-AUP-0012 rule 8)",
        "present": _refs(docs),
        "missing": [] if docs else ["KeyInventoryReceipt/v1"],
    }
    return (PASS, None, detail) if docs else (BLOCK, "KEY_INVENTORY_MISSING", detail)


def _readiness_attestation(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("CutoverReadinessAttestation/v1")
    blocks = [d for d in idx.of("BlockReceipt/v1") if d.path.startswith("receipts/mig/gate0-block")]
    detail = {
        "required": "the AUP-MIG-015 CutoverReadinessAttestation with its two refs (data receipt + the "
                    "authorising decision) (AUP-E25 § MIG-015, DEC-AUP-0012)",
        "present": _refs(docs),
        "latest_gate_refusal": blocks[-1].ref() if blocks else None,
        "missing": [] if docs else ["CutoverReadinessAttestation/v1 — AUP-MIG-015:gate0 currently issues a "
                                    "BlockReceipt/v1 instead"],
    }
    return (PASS, None, detail) if docs else (BLOCK, "READINESS_ATTESTATION_MISSING", detail)


def _bake(idx: EvidenceIndex) -> Tuple[str, Optional[str], Dict[str, Any]]:
    docs = idx.of("CutoverBakeObservationReceipt/v1")
    detail = {
        "required": "24 h bake: hourly drift = 0, non-bot writes = 0, Muneral 5xx < 1 % (DEC-AUP-0012 rule 9)",
        "hours_required": 24,
        "present": _refs(docs),
        "missing": [] if len(docs) >= 24 else [f"{24 - len(docs)} hourly CutoverBakeObservationReceipt/v1"],
    }
    if not docs:
        return BLOCK, "BAKE_NOT_STARTED", detail
    return (PASS, None, detail) if len(docs) >= 24 else (BLOCK, "BAKE_INCOMPLETE", detail)


# ------------------------------------------------------------------ the gate table
GATES: List[Dict[str, Any]] = [
    {
        "from": "FILES_AUTHORITATIVE", "to": "SHADOW_PROJECTION",
        "decision_rule": "DEC-AUP-0012 rule 2 (dark launch first)",
        "requirements": [
            Requirement("E1.1", "is the shadow projection byte-stable over ≥ 10 consecutive regenerations?",
                        "ShadowProjectionReceipt/v1", "PROJ-SHADOW1 (hourly job)", _shadow_stable),
            Requirement("E1.2", "are there two identical ProjectionParity/v1 receipts ≥ 1 h apart?",
                        "ProjectionParity/v1", "PROJ-SHADOW1", _parity_pairs),
            Requirement("E1.3", "is the derived-row marker rule audited per row?",
                        "ShadowProjectionReceipt/v1", "PROJ-SHADOW1 / PROJ-RULE0", _derived_marker),
        ],
    },
    {
        "from": "SHADOW_PROJECTION", "to": "FROZEN",
        "decision_rule": "DEC-AUP-0012 rule 3 (FROZEN = the DEC-AUP-0011 gate)",
        "requirements": [
            Requirement("E2.1", "has the freeze been activated?", "FreezeActivationReceipt/v1",
                        "the DEC-AUP-0011 freeze-activation card", _freeze_activation),
            Requirement("E2.2", "is the observation window W complete with a positive control every hour?",
                        "FenceObservationReceipt/v1", "AUP-FENCE-OBS0 (hourly job)", _fence_observation_window),
            Requirement("E2.3", "is the latest fleet drain free of undetermined sessions?", "FleetDrainReceipt/v1",
                        "the drain observer", _fleet_drain),
            Requirement("E2.4", "was the freeze rollback drilled?", "FreezeRollbackDrillReceipt/v1",
                        "AUP-FENCE-OBS0", _freeze_rollback_drill),
        ],
    },
    {
        "from": "FROZEN", "to": "FENCE_ENFORCED",
        "decision_rule": "DEC-AUP-0012 rule 3 (real rejection + ruleset refusal)",
        "requirements": [
            Requirement("E3.1", "is there a real FENCED_WRITE_DENIED rejection and a ruleset-refused push?",
                        "FenceProofReceipt/v1", "the fence-enforcement card (DEC-AUP-0011)", _fence_proof),
        ],
    },
    {
        "from": "FENCE_ENFORCED", "to": "PROJECTION_VERIFIED",
        "decision_rule": "DEC-AUP-0012 rule 4 (100 % of the fenced rows, no sampling)",
        "requirements": [
            Requirement("E4.1", "is every fenced row verified against the projection?",
                        "ShadowProjectionReceipt/v1", "PROJ-SHADOW1", _projection_100),
            Requirement("E4.2", "are there two identical ProjectionParity/v1 receipts ≥ 1 h apart?",
                        "ProjectionParity/v1", "PROJ-SHADOW1", _parity_pairs),
        ],
    },
    {
        "from": "PROJECTION_VERIFIED", "to": "DELTA_IMPORTED",
        "decision_rule": "DEC-AUP-0012 rule 5 (a second batch only under eight conditions)",
        "requirements": [
            Requirement("E5.1", "has a second import batch been admitted under the epoch conditions?",
                        "ReadinessReceipt/v1 (receipts/import/verify-*)", "AUP-MUN-0041 delta-import card", _delta_batch),
        ],
    },
    {
        "from": "DELTA_IMPORTED", "to": "ROLLBACK_DRILLED",
        "decision_rule": "DEC-AUP-0012 rule 6 (rollback ≤ 15 min + a database restore drill)",
        "requirements": [
            Requirement("E6.1", "was the cutover rollback drilled within 15 minutes?",
                        "CutoverRollbackDrillReceipt/v1", "the rollback-drill card", _cutover_rollback_drill),
            Requirement("E6.2", "was the Muneral database restore drilled from the named snapshot?",
                        "DatabaseRestoreDrillReceipt/v1", "the restore-drill card", _db_restore_drill),
        ],
    },
    {
        "from": "ROLLBACK_DRILLED", "to": "SWITCHING",
        "decision_rule": "DEC-AUP-0012 rule 8 (one atomic program commit, least-privilege bot)",
        "requirements": [
            Requirement("E7.1", "does a WriterEpochReceipt/v1 exist in program main?", "WriterEpochReceipt/v1",
                        "the SWITCHING card", _writer_epoch),
            Requirement("E7.2", "is the bot's key inventory receipted?", "KeyInventoryReceipt/v1",
                        "the SWITCHING card", _key_inventory),
            Requirement("E7.3", "is there a readiness attestation with both refs?", "CutoverReadinessAttestation/v1",
                        "AUP-MIG-015:gate0", _readiness_attestation),
        ],
    },
    {
        "from": "SWITCHING", "to": "MUNERAL_AUTHORITATIVE",
        "decision_rule": "DEC-AUP-0012 rule 9 (24 h bake)",
        "requirements": [
            Requirement("E8.1", "has the 24 h bake passed with drift 0 and no non-bot write?",
                        "CutoverBakeObservationReceipt/v1", "the bake observer card", _bake),
        ],
    },
]

GATE_BY_TARGET = {g["to"]: g for g in GATES}


def evaluate_gate(target_state: str, idx: EvidenceIndex, mutations: frozenset = frozenset()) -> Dict[str, Any]:
    """Evaluate the gate that guards the transition *into* `target_state`. Tri-valued, never PASS on
    missing or unmeasured evidence."""
    gate = GATE_BY_TARGET.get(target_state)
    if gate is None:
        return {"target_state": target_state, "verdict": BLOCK, "reason_code": "NO_SUCH_TRANSITION", "checks": []}
    checks: List[Dict[str, Any]] = []
    for req in gate["requirements"]:
        # E5.1 (_delta_batch) is the only check whose own normaliser has switchable mutants
        # (N12/N13); every other requirement takes only the evidence index.
        # E5.1 (_delta_batch) and E1.3 (_derived_marker) are the only checks whose own logic has
        # switchable mutants; every other requirement takes only the evidence index.
        verdict, reason, detail = req.check(idx, mutations) if req.id in ("E5.1", "E1.3") else req.check(idx)
        if "N05_gate_passes_with_missing_receipt" in mutations and verdict == BLOCK:
            verdict, reason = PASS, None
        if "N10_gate_omits_missing_receipts" in mutations:
            detail = {k: v for k, v in detail.items() if k != "missing"}
        checks.append({
            "id": req.id, "question": req.question, "receipt_class": req.receipt_class,
            "producer": req.producer, "verdict": verdict, "reason_code": reason, "detail": detail,
        })
    blocked = [c for c in checks if c["verdict"] == BLOCK]
    unmeasured = [c for c in checks if c["verdict"] == NOT_MEASURED]
    if "N09_not_measured_counts_as_pass" in mutations:
        unmeasured = []
    if blocked:
        verdict, reason = BLOCK, blocked[0]["reason_code"]
    elif unmeasured:
        verdict, reason = NOT_MEASURED, unmeasured[0]["reason_code"]
    else:
        verdict, reason = PASS, None
    return {
        "from_state": gate["from"], "target_state": target_state, "decision_rule": gate["decision_rule"],
        "verdict": verdict, "reason_code": reason,
        "counts": {"pass": sum(1 for c in checks if c["verdict"] == PASS), "block": len(blocked),
                   "not_measured": len(unmeasured)},
        "checks": checks,
        "evidence_index": idx.summary(),
    }


def evaluate_all(idx: EvidenceIndex, mutations: frozenset = frozenset()) -> List[Dict[str, Any]]:
    return [evaluate_gate(g["to"], idx, mutations) for g in GATES]
