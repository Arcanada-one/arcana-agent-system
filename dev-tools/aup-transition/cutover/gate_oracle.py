"""AUP-MIG-016 `coord0` — the independent oracle of the *gate* layer.

The MIG-014 oracle (`tools/mig/fault_drill/oracle.py`, rules O01–O18) judges the crash-safety of the
cutover window and is reused unchanged. It knows nothing about DEC-AUP-0012's evidence ladder, the
transition receipts, the production barrier or the host activation ledger — the properties this card
adds. Those are judged here, by rules over a *trace*, with no import from `coordinator.py`: the state
names, the ordering and the tri-valued verdicts are re-declared.

  G01_RECEIPT_BEFORE_ADVANCE   every durable advance is preceded by its transition receipt
  G02_MISSING_EVIDENCE_NAMED   a gate check that is not PASS names the evidence it did not find
  G03_NO_PASS_ON_MISSING       a gate whose checks name missing evidence never reads PASS
  G04_BARRIER_SCHEMA_DISTINCT  the production barrier validates as ProductionCutoverBarrier/v1 and
                               carries no key of the DAT-018 rehearsal receipt
  G05_ACK_IDEMPOTENT           at most one applied activation ack per (host, writer epoch)
  G06_PHASE_AUTHORISED         no phase effect is issued before the ladder state that authorises it
  G07_LADDER_ONLY_INITIALISED  in a coord0 run the state file is only ever written at FILES_AUTHORITATIVE
  G08_RESUME_FROM_RECORD       a resumed process takes the recorded state, never one inferred from the world
  G09_TRIVALUED                verdicts are PASS / BLOCK / NOT_MEASURED and a gate PASSes only if every
                               check PASSes (NOT_MEASURED is never folded into a pass)
  G10_RECEIPT_DETERMINISTIC    one distinct receipt digest per (keys, state): a resume rewrites the same
                               receipt, never a second one

stdlib only.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

LADDER_ORDER = ["FILES_AUTHORITATIVE", "SHADOW_PROJECTION", "FROZEN", "FENCE_ENFORCED", "PROJECTION_VERIFIED",
                "DELTA_IMPORTED", "ROLLBACK_DRILLED", "SWITCHING", "MUNERAL_AUTHORITATIVE"]
PHASE_ORDER = ["QUIESCING", "FENCED", "FINAL_SYNC", "VALIDATED", "WRITE_COMMITTED", "HOSTS_ACTIVATING",
               "OBSERVING", "COMPLETE"]
REQUIRED_LADDER_FOR_PHASE = {
    "QUIESCING": "FROZEN", "FENCED": "FENCE_ENFORCED", "FINAL_SYNC": "DELTA_IMPORTED",
    "VALIDATED": "ROLLBACK_DRILLED", "WRITE_COMMITTED": "SWITCHING", "HOSTS_ACTIVATING": "SWITCHING",
    "OBSERVING": "SWITCHING", "COMPLETE": "MUNERAL_AUTHORITATIVE",
}
VERDICTS = {"PASS", "BLOCK", "NOT_MEASURED"}
BARRIER_SCHEMA = "ProductionCutoverBarrier/v1"
CANDIDATE_KEYS = {"rehearsal", "candidate_scope", "bounded_paths", "active_generation_pointer_unchanged"}
RULES = ["G01_RECEIPT_BEFORE_ADVANCE", "G02_MISSING_EVIDENCE_NAMED", "G03_NO_PASS_ON_MISSING",
         "G04_BARRIER_SCHEMA_DISTINCT", "G05_ACK_IDEMPOTENT", "G06_PHASE_AUTHORISED",
         "G07_LADDER_ONLY_INITIALISED", "G08_RESUME_FROM_RECORD", "G09_TRIVALUED",
         "G10_RECEIPT_DETERMINISTIC"]


def evaluate(trace: Dict[str, Any], disabled: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """`trace` may carry any of: `window_journal`, `events`, `ladder_journal`, `gate_evaluations`.
    A part that is absent is simply not judged (the caller decides what it measured)."""
    disabled = disabled or set()
    v: List[Dict[str, Any]] = []

    def hit(rule: str, detail: str) -> None:
        if rule not in disabled:
            v.append({"rule": rule, "detail": detail})

    wj: List[Dict[str, Any]] = trace.get("window_journal", [])
    lj: List[Dict[str, Any]] = trace.get("ladder_journal", [])
    events: List[Dict[str, Any]] = trace.get("events", [])
    gates: List[Dict[str, Any]] = trace.get("gate_evaluations", [])

    # ---------------- G01 / G10 over the ladder journal
    receipted: Set[str] = set()
    for rec in lj:
        op = rec.get("op")
        if op in ("receipt_write", "receipt_reused"):
            receipted.add(rec.get("state"))
        if op == "state_write":
            st = rec.get("state")
            if st not in receipted:
                hit("G01_RECEIPT_BEFORE_ADVANCE",
                    f"ladder seq {rec.get('seq')}: state {st} written before its transition receipt")
            if st != "FILES_AUTHORITATIVE" and trace.get("card") == "coord0":
                hit("G07_LADDER_ONLY_INITIALISED",
                    f"ladder seq {rec.get('seq')}: coord0 wrote the state file at {st}")
    digests: Dict[str, Set[str]] = {}
    for rec in lj:
        if rec.get("op") in ("receipt_write", "receipt_reused"):
            digests.setdefault(str(rec.get("state")), set()).add(str(rec.get("digest")))
    for st, ds in digests.items():
        if len(ds) > 1:
            hit("G10_RECEIPT_DETERMINISTIC", f"ladder: {len(ds)} distinct receipt digests for state {st}")

    # ---------------- G01 / G10 over the window journal
    phase_receipts: Dict[str, Set[str]] = {}
    seen_receipt: Set[str] = set()
    for rec in wj:
        if rec.get("kind") == "phase_receipt":
            st = rec.get("state_to")
            seen_receipt.add(st)
            phase_receipts.setdefault(str(st), set()).add(str(rec.get("digest")))
        if rec.get("kind") == "transition":
            to = rec.get("state_to")
            if to in PHASE_ORDER and to not in seen_receipt:
                hit("G01_RECEIPT_BEFORE_ADVANCE",
                    f"window seq {rec.get('seq')}: transition into {to} without a preceding phase receipt")
    for st, ds in phase_receipts.items():
        if len(ds) > 1:
            hit("G10_RECEIPT_DETERMINISTIC", f"window: {len(ds)} distinct receipt digests for phase {st}")

    # ---------------- G06 over the window journal (authorisation precedes the effect)
    authorised: Dict[str, bool] = {}
    for rec in wj:
        if rec.get("kind") == "gate_check":
            phase = rec.get("phase")
            need = REQUIRED_LADDER_FOR_PHASE.get(str(phase))
            ladder_state = rec.get("ladder_state")
            really = (ladder_state in LADDER_ORDER and need in LADDER_ORDER
                      and LADDER_ORDER.index(ladder_state) >= LADDER_ORDER.index(need))
            authorised[str(phase)] = really
            if rec.get("authorised") and not really:
                hit("G06_PHASE_AUTHORISED",
                    f"window seq {rec.get('seq')}: phase {phase} declared authorised at ladder state "
                    f"{ladder_state}, which is below {need}")
        if rec.get("kind") == "intent":
            phase = str(rec.get("state_to"))
            if not authorised.get(phase, False):
                hit("G06_PHASE_AUTHORISED",
                    f"window seq {rec.get('seq')}: effects intended for phase {phase} without a satisfied "
                    f"ladder gate ({REQUIRED_LADDER_FOR_PHASE.get(phase)})")

    # ---------------- G04 the production barrier
    for rec in wj:
        if rec.get("kind") != "barrier":
            continue
        doc = rec.get("document") or {}
        if doc.get("schema") != BARRIER_SCHEMA:
            hit("G04_BARRIER_SCHEMA_DISTINCT",
                f"window seq {rec.get('seq')}: barrier schema {doc.get('schema')} is not {BARRIER_SCHEMA}")
        shared = sorted(CANDIDATE_KEYS & set(doc))
        if shared:
            hit("G04_BARRIER_SCHEMA_DISTINCT",
                f"window seq {rec.get('seq')}: the barrier carries rehearsal-only keys {shared}")
        if doc.get("scope") not in (None, "production-global") or doc.get("scope") is None:
            hit("G04_BARRIER_SCHEMA_DISTINCT",
                f"window seq {rec.get('seq')}: barrier scope {doc.get('scope')} is not production-global")

    # ---------------- G05 the host activation ledger
    applied: Dict[str, int] = {}
    for rec in wj:
        if rec.get("kind") != "ack":
            continue
        if str(rec.get("result")) == "applied":
            k = f"{rec.get('host')}@{rec.get('epoch')}"
            applied[k] = applied.get(k, 0) + 1
    for k, n in applied.items():
        if n > 1:
            hit("G05_ACK_IDEMPOTENT", f"host activation {k} applied {n} times")

    # ---------------- G08 resume takes the recorded state
    for e in events:
        if e.get("kind") != "resume_recovered":
            continue
        if e.get("recovered_state") != e.get("recorded_state"):
            hit("G08_RESUME_FROM_RECORD",
                f"event seq {e.get('seq')}: resumed into {e.get('recovered_state')} while the record said "
                f"{e.get('recorded_state')} (method {e.get('method')})")

    # ---------------- G02 / G03 / G09 over the gate evaluations
    for ev in gates:
        checks = ev.get("checks", [])
        target = ev.get("target_state")
        for c in checks:
            if c.get("verdict") not in VERDICTS:
                hit("G09_TRIVALUED", f"gate {target} check {c.get('id')}: verdict {c.get('verdict')}")
            if c.get("verdict") in ("BLOCK", "NOT_MEASURED"):
                detail = c.get("detail") or {}
                if "missing" not in detail:
                    hit("G02_MISSING_EVIDENCE_NAMED",
                        f"gate {target} check {c.get('id')}: {c.get('verdict')} without naming the missing evidence")
            if c.get("verdict") == "PASS" and (c.get("detail") or {}).get("missing"):
                hit("G03_NO_PASS_ON_MISSING",
                    f"gate {target} check {c.get('id')} PASSes while naming missing evidence "
                    f"{(c.get('detail') or {}).get('missing')}")
        if ev.get("verdict") == "PASS":
            bad = [c.get("id") for c in checks if c.get("verdict") != "PASS"]
            if bad:
                hit("G09_TRIVALUED", f"gate {target} PASSes while checks {bad} do not")
            missing = [c.get("id") for c in checks if (c.get("detail") or {}).get("missing")]
            if missing:
                hit("G03_NO_PASS_ON_MISSING",
                    f"gate {target} PASSes although checks {missing} name evidence that does not exist")
        if ev.get("verdict") not in VERDICTS:
            hit("G09_TRIVALUED", f"gate {target}: aggregate verdict {ev.get('verdict')}")
    return v
