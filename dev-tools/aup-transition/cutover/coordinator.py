#!/usr/bin/env python3
"""AUP-MIG-016 `coord0` — the real crash-safe cutover coordinator.

The AUP-MIG-014 drill rehearsed a *simulated* coordinator. This is the coordinator itself: a
persisted state machine with a receipt per transition, resume from the recorded state and
`PAUSED_SAFE` on unsafe uncertainty. It still touches no host, no writer epoch and no fence — the
fence / lease / barrier / host-activation backends are interfaces with a **simulated**
implementation only (`backends.py`), and the real ones are later cards under DEC-AUP-0011 /
DEC-AUP-0012.

Two state vocabularies, reconciled explicitly (`--reconciliation`)
-----------------------------------------------------------------
* **DEC-AUP-0012** names nine states — the durable *readiness ladder* that lives in
  `receipts/cutover/state.json`, one evidence gate per transition.
* **AUP-E25 § AUP-MIG-016** names eight states — the *execution phases of the cutover window*, the
  crash-safe part the fault drill exercises.

They are not the same machine at the same granularity, so the coordinator runs both: the ladder
decides *whether* a phase may run at all, the window decides *how* it runs and how it recovers.
Every phase names the minimum ladder state that authorises it; **the decision wins on gating** — a
phase whose ladder state has not been reached pauses safe, whatever the spec's order suggests.
Where the two orders genuinely disagree the conflict is recorded (`ORDER_CONFLICTS`), not silently
resolved.

What this card (`AUP-MIG-016:coord0`) may write
-----------------------------------------------
`receipts/cutover/state.json` at `FILES_AUTHORITATIVE` **and nothing else**: `advance()` refuses
every ladder transition unless a later card enables it *and* the gate evaluates to `PASS`. Today
every gate refuses (`--gates`), which is the expected and receipted outcome.

Python 3 stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Optional

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import backends as be  # noqa: E402
import gates as gt  # noqa: E402
from world import HOSTS, LEASE_TTL, PAUSED_SAFE, STEP_TICKS, World  # noqa: E402  (simulated environment)

TOOL = "tools/mig/cutover/coordinator.py"
VERSION = "1.0.0"
MODEL = "claude-opus-5"
PROGRAM_ROOT = _HERE.parents[2]
STATE_PATH = PROGRAM_ROOT / "receipts/cutover/state.json"
CUTOVER_DIR = PROGRAM_ROOT / "receipts/cutover"
MIGRATION_ID = "AUP-MIG-016"

# ---------------------------------------------------------------- the two vocabularies
LADDER = [
    "FILES_AUTHORITATIVE", "SHADOW_PROJECTION", "FROZEN", "FENCE_ENFORCED", "PROJECTION_VERIFIED",
    "DELTA_IMPORTED", "ROLLBACK_DRILLED", "SWITCHING", "MUNERAL_AUTHORITATIVE",
]
PHASES = ["QUIESCING", "FENCED", "FINAL_SYNC", "VALIDATED", "WRITE_COMMITTED", "HOSTS_ACTIVATING", "OBSERVING", "COMPLETE"]
INIT = "INIT"
ABORTED = "ABORTED"

#: the minimum ladder state that authorises each window phase (the decision wins on gating)
AUTHORISING_LADDER_STATE = {
    "QUIESCING": "FROZEN",
    "FENCED": "FENCE_ENFORCED",
    "FINAL_SYNC": "DELTA_IMPORTED",
    "VALIDATED": "ROLLBACK_DRILLED",
    "WRITE_COMMITTED": "SWITCHING",
    "HOSTS_ACTIVATING": "SWITCHING",
    "OBSERVING": "SWITCHING",
    "COMPLETE": "MUNERAL_AUTHORITATIVE",
}

RECONCILIATION = [
    {"ladder_state": "FILES_AUTHORITATIVE", "spec_phase": None,
     "note": "the baseline before any cutover work; AUP-E25 has no state for it"},
    {"ladder_state": "SHADOW_PROJECTION", "spec_phase": None,
     "note": "dark launch, added by DEC-AUP-0012 (cheapest reversible step); no AUP-E25 analogue"},
    {"ladder_state": "FROZEN", "spec_phase": "QUIESCING",
     "note": "the DEC-AUP-0011 freeze is what authorises the drain of migration-owned lanes"},
    {"ladder_state": "FENCE_ENFORCED", "spec_phase": "FENCED",
     "note": "the fence mechanism is proven (real rejection + ruleset refusal) before the coordinator sets "
             "the global legacy-write fence and takes the single writer lease"},
    {"ladder_state": "PROJECTION_VERIFIED", "spec_phase": None,
     "note": "AUP-E25 folds this into VALIDATED; the decision makes it its own gate (100 % of the fenced rows)"},
    {"ladder_state": "DELTA_IMPORTED", "spec_phase": "FINAL_SYNC",
     "note": "re-discovery of roots / worktrees / refs / backups under the fence and the final delta"},
    {"ladder_state": "ROLLBACK_DRILLED", "spec_phase": "VALIDATED",
     "note": "consistency + Scrutator ack are only accepted once the rollback and the database restore are drilled"},
    {"ladder_state": "SWITCHING", "spec_phase": "WRITE_COMMITTED / HOSTS_ACTIVATING / OBSERVING",
     "note": "the decision has one atomic state for the CAS commit, the idempotent per-host acks and the "
             "observation window; AUP-E25 splits it into three phases, which the window keeps"},
    {"ladder_state": "MUNERAL_AUTHORITATIVE", "spec_phase": "COMPLETE",
     "note": "reached only after the 24 h bake; COMPLETE then makes the legacy contour read-only"},
]

ORDER_CONFLICTS = [
    "order: DEC-AUP-0012 verifies the projection (PROJECTION_VERIFIED) *before* importing the delta "
    "(DELTA_IMPORTED); AUP-E25 runs FINAL_SYNC (the final delta) *before* VALIDATED. Held, not resolved by "
    "default: the window's FINAL_SYNC is authorised by DELTA_IMPORTED and VALIDATED by ROLLBACK_DRILLED, so "
    "both ladder gates are satisfied before either phase runs and neither order is violated.",
    "granularity: AUP-E25 gives host activation and the observation window their own states; DEC-AUP-0012 "
    "keeps them inside SWITCHING. The ladder follows the decision; the window keeps the three phases so the "
    "MIG-014 fault matrix stays applicable, and each phase carries the SWITCHING authorisation.",
    "vocabulary: AUP-E25's FENCED is the *operational* fence during the cutover window; DEC-AUP-0012's "
    "FENCE_ENFORCED is the *proof* that the fence rejects a real write. Same word, different obligations; "
    "the proof gates the operation.",
]

# ---------------------------------------------------------------- window protocol constants
NEEDS = {
    "QUIESCING": ["muneral"], "FENCED": ["muneral"], "FINAL_SYNC": ["scrutator"], "VALIDATED": ["kc2"],
    "WRITE_COMMITTED": ["muneral"], "HOSTS_ACTIVATING": ["muneral"], "OBSERVING": [], "COMPLETE": ["muneral"],
}
FENCE_PHASES = {"FINAL_SYNC", "VALIDATED", "WRITE_COMMITTED"}
MAX_ATTEMPTS = 3

#: protective rules of the *real* coordinator that a mutant switches off. M01–M16 are the MIG-014
#: rules (the independent oracle of the drill kills them); N01–N11 are the rules this card adds,
#: killed by `gate_oracle.py`.
MUTATIONS = {
    "M01_reissue_effect_on_resume": "resume re-issues an intent's effect without a readback",
    "M02_abort_after_commit": "controlled abort accepted after WRITE_COMMITTED",
    "M03_stop_foreign_lanes": "QUIESCING stops lanes that are not migration-owned",
    "M04_authority_accepts_stale_epoch": "the authority accepts writes / acks carrying an old writer epoch",
    "M05_rollback_on_corrupt_known_good": "rollback proceeds although the known-good digest does not verify",
    "M06_break_glass_never_expires": "break-glass accepted without an expiry or past it",
    "M07_rollback_restores_legacy_hooks": "rollback re-installs the legacy hooks",
    "M08_resume_revoked_run": "a stale checkpoint resumes a run whose authorization was revoked",
    "M09_repeat_unknown_effect": "an UNKNOWN effect outcome is retried immediately",
    "M10_double_transition_on_resume": "resume re-applies the last checkpointed transition",
    "M11_replay_calls_model": "replay ignores the saved observations",
    "M12_ignore_lease_expiry": "effects under the fence are issued without checking the lease token",
    "M13_ignore_source_set_epoch_change": "the live SourceSetEpoch is not compared with the keyed one",
    "M14_unkeyed_transition": "durable records omit the target writer epoch",
    "M15_drain_unknown_proceeds": "QUIESCING proceeds although a host's lanes could not be classified",
    "M16_pause_without_reason": "PAUSED_SAFE is entered without a durable reason",
    "N01_ignore_ladder_authorisation": "a window phase runs although its DEC-AUP-0012 ladder state is not reached",
    "N02_state_advances_before_receipt": "the durable state advances before its transition receipt is written",
    "N03_barrier_accepts_candidate_schema": "a DAT-018 rehearsal receipt is accepted as the production barrier",
    "N04_host_ack_not_idempotent": "a repeated host ack is appended to the activation ledger a second time",
    "N05_gate_passes_with_missing_receipt": gt.GATE_MUTATIONS["N05_gate_passes_with_missing_receipt"],
    "N06_state_file_written_at_any_state": "the state file is (re)created at a state other than FILES_AUTHORITATIVE",
    "N08_resume_recomputes_state": "resume recomputes the state from the world instead of the recorded one",
    "N09_not_measured_counts_as_pass": gt.GATE_MUTATIONS["N09_not_measured_counts_as_pass"],
    "N10_gate_omits_missing_receipts": gt.GATE_MUTATIONS["N10_gate_omits_missing_receipts"],
    "N11_receipt_regenerated_on_resume": "a transition receipt is regenerated (non-deterministically) on resume",
    "N12_delta_checklist_list_shape_dropped": gt.GATE_MUTATIONS["N12_delta_checklist_list_shape_dropped"],
    "N13_delta_checklist_mismatch_ignored": gt.GATE_MUTATIONS["N13_delta_checklist_mismatch_ignored"],
    "N14_derived_marker_ignores_in_place_rewrite": gt.GATE_MUTATIONS["N14_derived_marker_ignores_in_place_rewrite"],
    "N15_derived_marker_stale_accepted": gt.GATE_MUTATIONS["N15_derived_marker_stale_accepted"],
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def rel(path: Path) -> str:
    """Program-relative where possible (receipts name paths, not machines); absolute for the drill's
    temporary directories."""
    try:
        return str(path.relative_to(PROGRAM_ROOT))
    except ValueError:
        return str(path)


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


# ================================================================== the readiness ladder
class LadderCrash(RuntimeError):
    """Simulated process death inside a ladder transition (drill only). The files written before it
    survive — that is the point: the resume must find them and finish the transition."""


class LadderStore:
    """The durable ladder. `state.json` is written **after** the transition receipt, never before,
    and only ever forward by one state. This card may create it at FILES_AUTHORITATIVE and nothing
    else: `allow_advance` is False unless a later card sets it, and even then the gate must PASS."""

    SCHEMA = "CutoverLadderState/v1"
    RECEIPT_SCHEMA = "CutoverTransitionReceipt/v1"

    def __init__(self, path: Path, receipt_dir: Optional[Path] = None, allow_advance: bool = False,
                 mutations: FrozenSet[str] = frozenset(), crash_after: Optional[str] = None) -> None:
        self.path = path
        self.receipt_dir = receipt_dir or path.parent
        self.allow_advance = allow_advance
        self.mutations = mutations
        self.crash_after = crash_after   # "receipt" | "state" — drill only
        self.journal: List[Dict[str, Any]] = []   # ordered record of what this process did (oracle input)

    # ----- journal
    def _op(self, op: str, **kw: Any) -> Dict[str, Any]:
        rec = {"seq": len(self.journal) + 1, "op": op}
        rec.update(kw)
        self.journal.append(rec)
        return rec

    # ----- io
    def load(self) -> Optional[Dict[str, Any]]:
        if not self.path.exists():
            return None
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write_state(self, doc: Dict[str, Any]) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        d = gt.sha256_file(self.path)
        self._op("state_write", state=doc["state"], path=rel(self.path), digest=d)
        return d

    def _write_receipt(self, from_state: Optional[str], to_state: str, keys: Dict[str, Any],
                       gate: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Deterministic file name per transition. An existing receipt is reused verbatim: a resume
        after a crash must not produce a second, different receipt for the same transition."""
        idx = LADDER.index(to_state)
        name = f"transition-{idx:02d}-{to_state}.json"
        path = self.receipt_dir / name
        if path.exists() and "N11_receipt_regenerated_on_resume" not in self.mutations:
            doc = json.loads(path.read_text(encoding="utf-8"))
            d = gt.sha256_file(path)
            self._op("receipt_reused", state=to_state, path=rel(path), digest=d)
            return {"path": rel(path), "digest": d, "doc": doc, "reused": True}
        doc = {
            "schema": self.RECEIPT_SCHEMA,
            "portion_id": "AUP-MIG-016:coord0",
            "migration_id": keys["migration_id"],
            "keys": keys,
            "from_state": from_state,
            "to_state": to_state,
            "decision_ref": "DEC-AUP-0012",
            "gate": gate,
            "produced_by": {"tool": TOOL, "version": VERSION},
            "captured_at_utc": now_iso(),
            "host": os.uname().nodename,
            "backends": "none (ladder transition; the window's backends are declared in its own receipts)",
            "model": MODEL,
            "provisional_until_fable_review": True,
        }
        if "N11_receipt_regenerated_on_resume" in self.mutations:
            doc["nonce"] = os.urandom(4).hex()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        d = gt.sha256_file(path)
        self._op("receipt_write", state=to_state, path=rel(path), digest=d)
        return {"path": rel(path), "digest": d, "doc": doc, "reused": False}

    # ----- protocol
    def initialise(self, migration_id: str, source_set_epoch: str, target_writer_epoch: Optional[int]) -> Dict[str, Any]:
        """Create the ladder at FILES_AUTHORITATIVE. Idempotent: an existing file is left alone."""
        existing = self.load()
        if existing is not None:
            self._op("init_noop", state=existing.get("state"))
            return {"created": False, "state": existing.get("state"), "path": rel(self.path)}
        keys = {"migration_id": migration_id, "source_set_epoch": source_set_epoch,
                "target_writer_epoch": target_writer_epoch}
        receipt = self._write_receipt(None, "FILES_AUTHORITATIVE", keys, gate=None)
        doc = {
            "schema": self.SCHEMA,
            "portion_id": "AUP-MIG-016:coord0",
            "migration_id": migration_id,
            "keys": keys,
            "state": "FILES_AUTHORITATIVE",
            "ladder": LADDER,
            "created_at_utc": now_iso(),
            "updated_at_utc": now_iso(),
            "history": [{"from": None, "to": "FILES_AUTHORITATIVE", "at_utc": now_iso(),
                         "receipt": receipt["path"], "receipt_digest": receipt["digest"]}],
            "written_by": {"tool": TOOL, "version": VERSION, "card": "AUP-MIG-016:coord0"},
            "rule": "the receipt is written before the state advances; every other transition is refused "
                    "unless its DEC-AUP-0012 gate receipt exists and verifies",
            "model": MODEL,
            "provisional_until_fable_review": True,
        }
        state_digest = self._write_state(doc)
        return {"created": True, "state": "FILES_AUTHORITATIVE", "path": rel(self.path),
                "receipt": receipt["path"], "receipt_digest": receipt["digest"], "state_digest": state_digest}

    def state(self) -> str:
        doc = self.load()
        return doc["state"] if doc else "FILES_AUTHORITATIVE"  # no file ⇒ the machine stands at the baseline

    def advance(self, to_state: str, gate_verdict: Dict[str, Any]) -> Dict[str, Any]:
        """Advance one state. Refused unless: this card is allowed to advance, the target is the next
        state, and the gate PASSes. The receipt is written first, the state after it."""
        doc = self.load()
        current = doc["state"] if doc else "FILES_AUTHORITATIVE"
        if to_state not in LADDER:
            return self._refusal(current, to_state, "NO_SUCH_STATE")
        if LADDER.index(to_state) != LADDER.index(current) + 1:
            return self._refusal(current, to_state, "NOT_THE_NEXT_STATE")
        if not self.allow_advance and "N06_state_file_written_at_any_state" not in self.mutations:
            return self._refusal(current, to_state, "CARD_SCOPE_COORD0",
                                 note="AUP-MIG-016:coord0 may write FILES_AUTHORITATIVE only; the first real "
                                      "transition is the next card (coord1) under DEC-AUP-0012")
        if gate_verdict.get("verdict") != gt.PASS:
            return self._refusal(current, to_state, "GATE_" + str(gate_verdict.get("verdict")),
                                 note=gate_verdict.get("reason_code"))
        if doc is None:
            return self._refusal(current, to_state, "NO_STATE_FILE")
        keys = doc["keys"]
        if "N02_state_advances_before_receipt" in self.mutations:
            doc["state"] = to_state
            doc["updated_at_utc"] = now_iso()
            self._write_state(doc)
            receipt = self._write_receipt(current, to_state, keys, gate_verdict)
        else:
            receipt = self._write_receipt(current, to_state, keys, gate_verdict)
            if self.crash_after == "receipt":
                raise LadderCrash(f"drill: crash after the receipt of {current} -> {to_state}")
            if gt.sha256_file(self.receipt_dir / Path(receipt["path"]).name) != receipt["digest"]:
                return self._refusal(current, to_state, "RECEIPT_DIGEST_MISMATCH")
            doc["state"] = to_state
            doc["updated_at_utc"] = now_iso()
        doc.setdefault("history", []).append({
            "from": current, "to": to_state, "at_utc": now_iso(),
            "receipt": receipt["path"], "receipt_digest": receipt["digest"],
            "gate_digest": digest(gate_verdict),
        })
        self._write_state(doc)
        return {"advanced": True, "from": current, "to": to_state, "receipt": receipt["path"]}

    def _refusal(self, current: str, to_state: str, reason: str, note: Optional[str] = None) -> Dict[str, Any]:
        rec = {"advanced": False, "from": current, "to": to_state, "reason_code": reason, "note": note}
        self._op("advance_refused", **{k: v for k, v in rec.items() if k != "advanced"})
        return rec


class LadderView:
    """What the window is allowed to know about the ladder: the state and where it came from."""

    def __init__(self, state: str, source: str, history: Optional[List[Dict[str, Any]]] = None) -> None:
        self.state = state
        self.source = source
        self.history = history or []

    def authorises(self, phase: str) -> bool:
        need = AUTHORISING_LADDER_STATE[phase]
        return LADDER.index(self.state) >= LADDER.index(need)

    def describe(self) -> Dict[str, Any]:
        return {"state": self.state, "source": self.source}


# ================================================================== the cutover window
class Journal:
    """Durable, append-only, survives the process. In the drill the scenario owns it (that is what
    makes a crash a crash); live it is the ladder's receipt directory."""

    def __init__(self) -> None:
        self.records: List[Dict[str, Any]] = []

    def append(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        rec = dict(rec)
        rec["seq"] = len(self.records) + 1
        self.records.append(rec)
        return rec

    def last(self, kind: str) -> Optional[Dict[str, Any]]:
        for r in reversed(self.records):
            if r["kind"] == kind:
                return r
        return None


class BreakGlass:
    """Break-glass authorization (MIG-004 shape): human issuer, incident id, exact host/action/path,
    expiry, separate config home. Never a way past the ladder — only a way to touch legacy by name."""

    REQUIRED = ("issuer", "issuer_kind", "incident_id", "host", "action", "path", "expires_at", "config_home")

    def __init__(self, **fields: Any) -> None:
        self.fields = fields

    def validate(self, now: int, mutations: FrozenSet[str]) -> Dict[str, Any]:
        f = self.fields
        problems: List[str] = []
        for k in self.REQUIRED:
            if k not in f or f[k] in (None, ""):
                problems.append(f"missing:{k}")
        if f.get("issuer_kind") not in (None, "human"):
            problems.append("issuer_not_human")
        if f.get("expires_at") is not None:
            if f["expires_at"] <= now and "M06_break_glass_never_expires" not in mutations:
                problems.append("expired")
        elif "M06_break_glass_never_expires" in mutations:
            problems = [p for p in problems if p != "missing:expires_at"]
        if f.get("config_home") and f["config_home"] == f.get("default_config_home"):
            problems.append("config_home_not_separate")
        return {"accepted": not problems, "problems": problems, "checked_at": now}


class CutoverWindow:
    """The crash-safe execution machine of AUP-E25 § MIG-016.

    Protocol per phase: durable observation → durable intent → keyed effect(s) → durable **receipt**
    → checkpoint → transition. A crash anywhere is recovered from the journal: an observation is
    reused, a dangling intent is reconciled by readback (never re-issued blind), a receipt already on
    disk is reused verbatim, a checkpointed phase is never re-run. Repeated resume is a no-op.

    Constructor signature is deliberately the one the MIG-014 scenario runner expects, so the fault
    matrix of `fault0` can be re-run against this coordinator without changing the matrix.
    """

    def __init__(self, world: World, journal: Journal, observer: Any, migration_id: str,
                 mutations: FrozenSet[str] = frozenset(), fault_hook: Optional[Callable[[str, str], None]] = None,
                 replay_mode: bool = False, ladder: Optional[LadderView] = None,
                 backends: Optional[be.Backends] = None) -> None:
        self.world = world
        self.journal = journal
        self.observer = observer
        self.migration_id = migration_id
        self.mutations = mutations
        self.fault_hook = fault_hook or (lambda point, phase: None)
        self.replay_mode = replay_mode
        self.ladder = ladder or LadderView("MUNERAL_AUTHORITATIVE", "drill fixture: every gate satisfied")
        self.backends = backends or be.Backends.simulated(world)
        self.keyed_epoch = world.source_set_epoch
        self.state = INIT
        self.paused_reason: Optional[str] = None
        self.paused_at: Optional[str] = None
        self.lease_token: Optional[str] = None
        self.target_writer_epoch: int = self.backends.lease.current_epoch() + 1
        self.findings: List[str] = []
        self.break_glass_log: List[Dict[str, Any]] = []
        self.ack_ledger: List[Dict[str, Any]] = []
        self.barrier: Optional[Dict[str, Any]] = None
        self.resume_count = 0
        self._recover()

    # ----- durable helpers -------------------------------------------------
    def keys(self) -> Dict[str, Any]:
        k = {"migration_id": self.migration_id, "source_set_epoch": self.keyed_epoch,
             "target_writer_epoch": self.target_writer_epoch}
        if "M14_unkeyed_transition" in self.mutations:
            k.pop("target_writer_epoch")
        return k

    def _durable(self, kind: str, **kw: Any) -> Dict[str, Any]:
        rec = {"kind": kind, "at": self.world.clock.now(), "keys": self.keys()}
        rec.update(kw)
        return self.journal.append(rec)

    def _pause(self, reason: str) -> None:
        if self.state == PAUSED_SAFE:
            return
        self._durable("transition", state_from=self.state, state_to=PAUSED_SAFE,
                      reason=None if "M16_pause_without_reason" in self.mutations else reason,
                      paused_at_state=self.state)
        self.paused_reason = reason
        self.paused_at = self.state
        self.state = PAUSED_SAFE
        self.world.event("paused_safe", reason=reason, at_state=self.paused_at)

    def _recover(self) -> None:
        """Process start: rebuild from the recorded state. Never from the world — a coordinator that
        infers 'where it must be' from the environment cannot be crash-safe."""
        recorded = INIT
        for r in self.journal.records:
            if r["kind"] == "transition":
                recorded = r["state_to"]
                if r["state_to"] == PAUSED_SAFE:
                    self.paused_reason = r.get("reason")
                    self.paused_at = r.get("paused_at_state")
                if r["state_to"] == ABORTED:
                    self.paused_reason = r.get("reason")
            if r["kind"] == "lease":
                self.lease_token = r["lease_id"]
                self.target_writer_epoch = r["epoch"]
            if r["kind"] == "meta":
                self.keyed_epoch = r["keys"]["source_set_epoch"]
            if r["kind"] == "barrier":
                self.barrier = r.get("document")
            if r["kind"] == "ack":
                self.ack_ledger.append({k: r[k] for k in ("host", "epoch", "result") if k in r})
        if "N08_resume_recomputes_state" in self.mutations:
            guessed = self._guess_state_from_world()
            self.world.event("resume_recovered", recorded_state=recorded, recovered_state=guessed, method="world_guess")
            self.state = guessed
        else:
            self.world.event("resume_recovered", recorded_state=recorded, recovered_state=recorded, method="journal")
            self.state = recorded
        if not self.journal.records:
            self._durable("meta", note="cutover window opened", ladder=self.ladder.describe(),
                          backends=self.backends.describe())

    def _guess_state_from_world(self) -> str:
        a = self.backends
        if a.lease.current_epoch() >= self.target_writer_epoch:
            return "WRITE_COMMITTED"
        if a.fence.active():
            return "FENCED"
        return INIT

    # ----- public protocol --------------------------------------------------
    def resume(self) -> Dict[str, Any]:
        self.resume_count += 1
        before = self.state
        self.world.event("resume", state=self.state, resume_no=self.resume_count)
        if self.state in (ABORTED, "COMPLETE"):
            return {"state": self.state, "changed": False}
        if not self.world.auth_valid and "M08_resume_revoked_run" not in self.mutations:
            self._pause("AUTH_REVOKED")
            return {"state": self.state, "changed": before != self.state}
        if "M10_double_transition_on_resume" in self.mutations:
            last = self.journal.last("transition")
            if last and last["state_to"] in PHASES and last["state_to"] != "COMPLETE":
                nxt = PHASES[PHASES.index(last["state_to"]) + 1]
                self._durable("transition", state_from=last["state_to"], state_to=nxt, reason="M10 replayed transition")
                self.state = nxt
        last_intent = self.journal.last("intent")
        last_cp = self.journal.last("checkpoint")
        if last_intent and (not last_cp or last_cp["seq"] < last_intent["seq"]):
            self._reconcile(last_intent)
        if self.state == PAUSED_SAFE and self.paused_reason and self._pause_cleared():
            self._durable("transition", state_from=PAUSED_SAFE, state_to=self.paused_at,
                          reason="forward recovery: cause cleared")
            self.world.event("forward_recovery", to_state=self.paused_at, cleared=self.paused_reason)
            self.state = self.paused_at
            self.paused_reason = None
        return {"state": self.state, "changed": before != self.state}

    def _pause_cleared(self) -> bool:
        r = self.paused_reason or ""
        w = self.world
        if r.startswith("SERVICE_UNAVAILABLE:"):
            return w.services.get(r.split(":", 1)[1], False)
        if r in ("UNKNOWN_EFFECT_UNRECONCILED", "DRAIN_UNKNOWN", "HOST_UNREACHABLE", "HOST_LOST_IN_OBSERVATION"):
            return w.network and all(h.alive for h in w.hosts.values())
        return False  # AUTH_REVOKED, LEASE_EXPIRED, KNOWN_GOOD_CORRUPT, REVALIDATION_REQUIRED, GATE_* need a decision

    def _reconcile(self, intent: Dict[str, Any]) -> None:
        for key in intent["effect_keys"]:
            if "M01_reissue_effect_on_resume" in self.mutations:
                self.world.event("reconcile", key=key, method="blind_reissue")
                self.world.apply_effect(key, intent["state_to"], self._effect_fn(intent["state_to"], key),
                                        NEEDS[intent["state_to"]])
                continue
            rb = self.world.readback(key)
            self._durable("reconciliation", state=intent["state_to"], effect_key=key, readback=rb,
                          terminal="applied" if rb == "applied" else ("not_applied" if rb == "not_applied" else "unknown"),
                          reissued=False)
            self.world.event("reconcile", key=key, method="readback", result=rb)
            if rb is None:
                self._pause("UNKNOWN_EFFECT_UNRECONCILED")
                return
            if rb == "not_applied":
                r = self._issue(intent["state_to"], key)
                if r == "unknown":
                    self._durable("reconciliation", state=intent["state_to"], effect_key=key, readback=None,
                                  terminal="unknown", reissued=False)
                    self._pause("UNKNOWN_EFFECT_UNRECONCILED")
                    return
                if r.startswith("rejected"):
                    self._pause(self._reason_for(r, intent["state_to"]))
                    return
        if all(self.world.readback(k) == "applied" for k in intent["effect_keys"]):
            self._phase_receipt(intent["state_to"], intent["effect_keys"], via="reconciliation")
            self._checkpoint(intent["state_to"], intent["effect_keys"], via="reconciliation")

    def step(self) -> str:
        if self.state in (PAUSED_SAFE, ABORTED, "COMPLETE"):
            return self.state
        nxt = PHASES[0] if self.state == INIT else PHASES[PHASES.index(self.state) + 1]
        self.world.clock.advance(STEP_TICKS)
        self.fault_hook("before_observation", nxt)
        if not self.world.known_good_ok():
            self._pause("KNOWN_GOOD_CORRUPT")
            return self.state
        obs_key = f"{self.migration_id}:{nxt}:obs"
        existing = next((r for r in self.journal.records if r["kind"] == "observation" and r["key"] == obs_key), None)
        if existing is None or "M11_replay_calls_model" in self.mutations:
            obs = self.observer.observe(obs_key, nxt, self._context(nxt),
                                        force_model="M11_replay_calls_model" in self.mutations)
            self._durable("observation", key=obs_key, state=nxt, observation=obs)
        else:
            obs = existing["observation"]
            self.world.event("observation_reused", key=obs_key, state=nxt)
        self.fault_hook("after_observation", nxt)
        guard = self._guard(nxt, obs)
        if guard:
            self._pause(guard)
            return self.state
        effect_keys = self._effect_keys(nxt)
        self._durable("intent", state_to=nxt, effect_keys=effect_keys)
        results: Dict[str, str] = {}
        for key in effect_keys:
            r = self._issue(nxt, key)
            if r == "unknown" and "M09_repeat_unknown_effect" in self.mutations:
                r = self._issue(nxt, key)
            results[key] = r
        for key, r in results.items():
            if r == "unknown":
                self._durable("reconciliation", state=nxt, effect_key=key, readback=None, terminal="unknown",
                              reissued=False)
                self._pause("UNKNOWN_EFFECT_UNRECONCILED")
                return self.state
        for key, r in results.items():
            if r.startswith("rejected"):
                self._pause(self._reason_for(r, nxt))
                return self.state
        self.fault_hook("after_effect", nxt)
        self._phase_receipt(nxt, effect_keys, via="step")
        # the durable step the real coordinator adds: the transition receipt is on disk before the
        # state advances, so a crash here must be repaired by *reusing* it, never by writing a second one
        self.fault_hook("after_receipt", nxt)
        self._checkpoint(nxt, effect_keys, via="step")
        self.fault_hook("after_checkpoint", nxt)
        return self.state

    def run(self, max_steps: int = 20) -> str:
        for _ in range(max_steps):
            s = self.step()
            if s in (PAUSED_SAFE, ABORTED, "COMPLETE"):
                return s
        return self.state

    def abort(self, reason: str) -> Dict[str, Any]:
        at = self.paused_at if self.state == PAUSED_SAFE else self.state
        committed = at in PHASES and PHASES.index(at) >= PHASES.index("WRITE_COMMITTED")
        if committed and "M02_abort_after_commit" not in self.mutations:
            self.world.event("abort_refused", at_state=at, reason="past_write_committed")
            return {"accepted": False, "state": self.state,
                    "why": "past WRITE_COMMITTED: only forward recovery or PAUSED_SAFE"}
        if self.state in (ABORTED, "COMPLETE"):
            return {"accepted": False, "state": self.state, "why": "terminal"}
        self.backends.fence.release_fence(f"{self.migration_id}:fence")
        self.backends.lease.release(self.lease_token)
        self._durable("transition", state_from=self.state, state_to=ABORTED, reason=reason, aborted_at_state=at)
        self.world.event("aborted", at_state=at, reason=reason)
        self.state = ABORTED
        return {"accepted": True, "state": self.state}

    def rollback_to_known_good(self) -> Dict[str, Any]:
        ok = self.world.known_good_ok()
        if not ok and "M05_rollback_on_corrupt_known_good" not in self.mutations:
            self._durable("rollback", verdict="refused", reason="KNOWN_GOOD_CORRUPT", pins=None)
            self._pause("KNOWN_GOOD_CORRUPT")
            self.world.event("rollback_refused", reason="KNOWN_GOOD_CORRUPT")
            return {"accepted": False, "reason": "KNOWN_GOOD_CORRUPT", "state": self.state}
        if "M07_rollback_restores_legacy_hooks" in self.mutations:
            self.world.legacy_hooks_restored = True
            self.world.event("legacy_hooks_restored")
        self.world.active_generation = dict(self.world.known_good)
        self._durable("rollback", verdict="applied", pins=dict(self.world.known_good),
                      known_good_digest=self.world.known_good_digest)
        self.world.event("rollback_applied", pins=list(self.world.known_good))
        return {"accepted": True, "state": self.state}

    def reactivate_host(self, host: str, epoch: Optional[int] = None) -> str:
        """A host repeats its activation (a login or an update re-runs the activation script). The
        ledger records a repeat, never a second activation, and the authority rejects an old epoch;
        neither re-enables the legacy contour."""
        e = self.target_writer_epoch if epoch is None else epoch
        if not self.backends.hosts.alive(host):
            self._durable("ack", host=host, epoch=e, result="rejected:host_unreachable", migration_id=self.migration_id)
            return "rejected:host_unreachable"
        res = self.backends.hosts.ack(host, e, self.migration_id,
                                      accept_stale="M04_authority_accepts_stale_epoch" in self.mutations)
        self._record_ack(host, e, res)
        self.world.event("host_reactivation", host=host, epoch=e, result=res,
                         legacy_policy=self.world.legacy_policy)
        return res

    def use_break_glass(self, bg: BreakGlass) -> Dict[str, Any]:
        v = bg.validate(self.world.clock.now(), self.mutations)
        rec = {"fields": {k: bg.fields.get(k) for k in BreakGlass.REQUIRED}, **v}
        self.break_glass_log.append(rec)
        self.world.event("break_glass", accepted=v["accepted"], problems=v["problems"],
                         expires_at=bg.fields.get("expires_at"))
        return rec

    # ----- internals --------------------------------------------------------
    def _context(self, phase: str) -> Dict[str, Any]:
        if phase == "QUIESCING":
            classes: Dict[str, str] = {}
            for l in self.world.lanes:
                classes[l.lane_id] = "unknown-foreign" if not self.world.hosts[l.host].alive else l.owner_class
            return {"lane_classes": classes}
        return {"state": phase, "epoch": self.world.source_set_epoch}

    def _guard(self, nxt: str, obs: Dict[str, Any]) -> Optional[str]:
        w = self.world
        # the decision wins on gating: no phase without its ladder state
        if not self.ladder.authorises(nxt) and "N01_ignore_ladder_authorisation" not in self.mutations:
            need = AUTHORISING_LADDER_STATE[nxt]
            self._durable("gate_check", phase=nxt, required_ladder_state=need, ladder_state=self.ladder.state,
                          authorised=False)
            return f"GATE_NOT_SATISFIED:{need}"
        self._durable("gate_check", phase=nxt, required_ladder_state=AUTHORISING_LADDER_STATE[nxt],
                      ladder_state=self.ladder.state, authorised=True)
        if nxt == "QUIESCING":
            dead_hosts = [h for h, x in w.hosts.items() if not x.alive]
            if dead_hosts and "M15_drain_unknown_proceeds" not in self.mutations:
                return "DRAIN_UNKNOWN"
        if nxt in ("VALIDATED", "WRITE_COMMITTED") and w.source_set_epoch != self.keyed_epoch \
                and "M13_ignore_source_set_epoch_change" not in self.mutations:
            return "REVALIDATION_REQUIRED"
        if nxt in FENCE_PHASES and "M12_ignore_lease_expiry" not in self.mutations:
            chk = self.backends.lease.check(self.lease_token)
            if chk != "valid":
                return "LEASE_EXPIRED" if chk == "expired" else f"LEASE_{chk.upper()}"
        if nxt in ("OBSERVING", "COMPLETE"):
            if [h for h, x in w.hosts.items() if not x.alive]:
                return "HOST_LOST_IN_OBSERVATION"
        if nxt in ("HOSTS_ACTIVATING", "OBSERVING", "COMPLETE") and w.source_set_epoch != self.keyed_epoch:
            f = "post_commit_source_set_epoch_drift: recorded for post-cutover reconciliation, no rollback"
            if f not in self.findings:
                self.findings.append(f)
                w.event("finding", text=f)
        return None

    def _effect_keys(self, phase: str) -> List[str]:
        m, e = self.migration_id, self.target_writer_epoch
        if phase == "HOSTS_ACTIVATING":
            return [f"{m}:{e}:ack:{h}" for h in HOSTS]
        return [f"{m}:{e}:{phase}"]

    def _stoppable_lanes(self) -> List[Any]:
        """By construction: only lanes positively classified as migration-owned on a live host can
        ever be handed to `stop_lane`. Foreign and unknown lanes get a handoff, never a stop."""
        if "M03_stop_foreign_lanes" in self.mutations:
            return [l for l in self.world.lanes if not l.stopped]
        return [l for l in self.world.lanes
                if not l.stopped and l.owner_class == "migration-owned" and self.world.hosts[l.host].alive]

    def _effect_fn(self, phase: str, key: str) -> Callable[[], str]:
        w, m = self.world, self.migration_id
        stale = "M04_authority_accepts_stale_epoch" in self.mutations
        if phase == "QUIESCING":
            def fn() -> str:
                stoppable = {l.lane_id for l in self._stoppable_lanes()}
                for l in w.lanes:
                    if l.stopped:
                        continue
                    if l.lane_id in stoppable:
                        w.stop_lane(l, by="coordinator")
                    else:
                        w.handoff_lane(l)
                return "applied"
            return fn
        if phase == "FENCED":
            def fn() -> str:
                self.backends.fence.set_fence(f"{m}:fence")
                if self.lease_token is None or self.backends.lease.check(self.lease_token) != "valid":
                    lease = self.backends.lease.acquire(holder=m, ttl=LEASE_TTL)
                    self.lease_token = lease["token"]
                    self.target_writer_epoch = lease["epoch"]
                    self._durable("lease", lease_id=lease["token"], epoch=lease["epoch"],
                                  expires_at=lease["expires_at"], ttl=lease["ttl"])
                    self._durable("fence", key=f"{m}:fence", active=True, lease_id=lease["token"])
                return "applied"
            return fn
        if phase == "FINAL_SYNC":
            return lambda: "applied"   # re-discovery of roots/worktrees/refs/backups + final delta + Scrutator ack
        if phase == "VALIDATED":
            return lambda: "applied"   # consistency verdict against the keyed SourceSetEpoch
        if phase == "WRITE_COMMITTED":
            def fn() -> str:
                res = self.backends.lease.cas_commit(self.lease_token, expected_epoch=self.target_writer_epoch - 1,
                                                     new_epoch=self.target_writer_epoch, accept_stale=stale)
                if res == "applied":
                    self._mint_barrier(res)
                return res
            return fn
        if phase == "HOSTS_ACTIVATING":
            host = key.rsplit(":", 1)[1]
            def fn() -> str:
                if not self.backends.hosts.alive(host):
                    return "rejected:host_unreachable"
                res = self.backends.hosts.ack(host, self.target_writer_epoch, m, accept_stale=stale)
                self._record_ack(host, self.target_writer_epoch, res)
                return res
            return fn
        if phase == "OBSERVING":
            return lambda: "applied"   # the observation window opens (the 24 h bake is the ladder's gate)
        if phase == "COMPLETE":
            def fn() -> str:
                w.legacy_policy = "read-only"
                self.backends.fence.release_fence(f"{m}:fence")
                self.backends.lease.release(self.lease_token)
                self._durable("fence", key=f"{m}:fence", active=False, lease_id=self.lease_token)
                return "applied"
            return fn
        raise ValueError(phase)

    def _record_ack(self, host: str, epoch: int, result: str) -> None:
        """Idempotent activation ledger: one entry per (host, epoch, migration). A repeated ack is
        recorded as a repeat, never as a second activation."""
        existing = next((a for a in self.ack_ledger if a["host"] == host and a["epoch"] == epoch), None)
        if existing is not None and "N04_host_ack_not_idempotent" not in self.mutations:
            existing["repeats"] = existing.get("repeats", 0) + 1
            self._durable("ack", host=host, epoch=epoch, result="idempotent", migration_id=self.migration_id)
            return
        self.ack_ledger.append({"host": host, "epoch": epoch, "result": result, "repeats": 0})
        self._durable("ack", host=host, epoch=epoch, result=result, migration_id=self.migration_id)

    def _mint_barrier(self, cas_result: str) -> None:
        doc = be.make_production_barrier(
            migration_id=self.migration_id, source_set_epoch=self.keyed_epoch,
            previous_epoch=self.target_writer_epoch - 1, target_epoch=self.target_writer_epoch,
            fence_key=f"{self.migration_id}:fence", token=self.lease_token, cas_result=cas_result,
            ledger=list(self.ack_ledger),
            evidence={"ladder_state": self.ladder.state, "backends": self.backends.describe()})
        if "N03_barrier_accepts_candidate_schema" in self.mutations:
            doc = {"schema": be.CANDIDATE_SCHEMA, "rehearsal": True, "candidate_scope": "bounded",
                   "bounded_paths": ["datarim/tasks.md"], "active_generation_pointer_unchanged": True}
        v = be.validate_production_barrier(doc, accept_candidate="N03_barrier_accepts_candidate_schema" in self.mutations)
        put = self.backends.barrier.put(doc)
        self.barrier = doc
        self._durable("barrier", document=doc, validation=v, store_result=put,
                      distinct_from_candidate=be.BARRIER_DISJOINT_PROOF)
        self.world.event("barrier_minted", valid=v["valid"], store_result=put, schema=doc.get("schema"))

    def _phase_receipt(self, phase: str, effect_keys: List[str], via: str) -> Dict[str, Any]:
        """The receipt of the transition, written **before** the state advances. Deterministic: the
        same phase of the same keyed migration always yields the same document, so a crash between
        the receipt and the checkpoint is repaired by rewriting the identical receipt."""
        existing = next((r for r in self.journal.records
                         if r["kind"] == "phase_receipt" and r["document"]["phase"] == phase), None)
        if existing is not None and "N11_receipt_regenerated_on_resume" not in self.mutations:
            self.world.event("phase_receipt_reused", phase=phase)
            return existing["document"]
        doc = {
            "schema": "CutoverPhaseReceipt/v1",
            "portion_id": "AUP-MIG-016:coord0",
            "phase": phase,
            "keys": self.keys(),
            "ladder_state": self.ladder.state,
            "authorising_ladder_state": AUTHORISING_LADDER_STATE[phase],
            "effect_keys": sorted(effect_keys),
            "lease_id": self.lease_token,
            "backends": self.backends.describe(),
            "via": via,
        }
        if "N11_receipt_regenerated_on_resume" in self.mutations:
            doc["nonce"] = os.urandom(4).hex()
        doc["document_digest"] = digest({k: v for k, v in doc.items() if k != "document_digest"})
        self._durable("phase_receipt", state_to=phase, document=doc, digest=doc["document_digest"])
        self.world.event("phase_receipt_written", phase=phase, digest=doc["document_digest"])
        return doc

    def _issue(self, phase: str, key: str) -> str:
        last = "rejected:unissued"
        for _attempt in range(MAX_ATTEMPTS):
            last = self.world.apply_effect(key, phase, self._effect_fn(phase, key), NEEDS[phase],
                                           bypass_auth="M08_resume_revoked_run" in self.mutations)
            if last in ("applied", "unknown") or last.startswith(("rejected:auth", "rejected:token", "rejected:epoch",
                                                                  "rejected:stale", "rejected:host")):
                return last
            self.world.clock.advance(1)
        return last

    def _reason_for(self, result: str, phase: str) -> str:
        if result.startswith("rejected:unavailable:"):
            return "SERVICE_UNAVAILABLE:" + result.split(":", 2)[2]
        if result == "rejected:auth_revoked":
            return "AUTH_REVOKED"
        if result.startswith("rejected:token_expired"):
            return "LEASE_EXPIRED"
        if result.startswith("rejected:token"):
            return "LEASE_INVALID"
        if result.startswith("rejected:epoch"):
            return "WRITER_EPOCH_MISMATCH"
        if result.startswith("rejected:host"):
            return "HOST_UNREACHABLE"
        return "EFFECT_REJECTED:" + result

    def _checkpoint(self, nxt: str, effect_keys: List[str], via: str) -> None:
        self._durable("checkpoint", state_to=nxt, effect_keys=effect_keys, via=via)
        self._durable("transition", state_from=self.state if self.state != PAUSED_SAFE else self.paused_at,
                      state_to=nxt, via=via)
        self.world.event("transition", state_from=self.state, state_to=nxt, via=via)
        self.state = nxt
        self.paused_reason = None


# ================================================================== CLI
def cmd_status(args: argparse.Namespace) -> int:
    store = LadderStore(STATE_PATH)
    doc = store.load()
    out = {
        "tool": TOOL, "version": VERSION, "captured_at_utc": now_iso(),
        "state_file": rel(STATE_PATH),
        "exists": doc is not None,
        "state": store.state(),
        "history": (doc or {}).get("history", []),
        "ladder": LADDER,
        "next_state": LADDER[LADDER.index(store.state()) + 1] if store.state() != LADDER[-1] else None,
        "card_scope": "AUP-MIG-016:coord0 writes FILES_AUTHORITATIVE only",
        "backends": {"available": "simulated", "real": "refused (BackendNotAvailable)"},
    }
    print(json.dumps(out, indent=1, ensure_ascii=False))
    return 0


def cmd_reconciliation(args: argparse.Namespace) -> int:
    print(json.dumps({
        "schema": "CutoverStateVocabularyMap/v1",
        "decision_states": LADDER, "spec_states": PHASES,
        "authorising_ladder_state": AUTHORISING_LADDER_STATE,
        "table": RECONCILIATION,
        "conflicts_held": ORDER_CONFLICTS,
        "rule": "DEC-AUP-0012 wins on gating: a spec phase never runs before the ladder state that authorises it",
    }, indent=1, ensure_ascii=False))
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    store = LadderStore(STATE_PATH)
    res = store.initialise(MIGRATION_ID, args.source_set_epoch, args.target_writer_epoch)
    print(json.dumps({"init": res, "journal": store.journal}, indent=1, ensure_ascii=False))
    return 0


def cmd_gates(args: argparse.Namespace) -> int:
    idx = gt.EvidenceIndex(PROGRAM_ROOT)
    store = LadderStore(STATE_PATH)
    current = store.state()
    evals = gt.evaluate_all(idx)
    next_state = LADDER[LADDER.index(current) + 1] if current != LADDER[-1] else None
    attempt = None
    if next_state:
        gate = next(e for e in evals if e["target_state"] == next_state)
        attempt = store.advance(next_state, gate)
    doc = {
        "schema": "CutoverGateEvaluation/v1",
        "portion_id": "AUP-MIG-016:coord0",
        "producer": {"tool": TOOL, "version": VERSION},
        "captured_at_utc": now_iso(),
        "host": os.uname().nodename,
        "decision_ref": "DEC-AUP-0012",
        "ladder_state": current,
        "next_state": next_state,
        "advance_attempt": attempt,
        "gates": evals,
        "summary": {e["target_state"]: {"verdict": e["verdict"], "reason_code": e["reason_code"], **e["counts"]}
                    for e in evals},
        "model": MODEL,
        "provisional_until_fable_review": True,
    }
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"written": str(p), "summary": doc["summary"], "advance_attempt": attempt},
                         indent=1, ensure_ascii=False))
    else:
        print(json.dumps(doc, indent=1, ensure_ascii=False))
    return 0


def cmd_advance(args: argparse.Namespace) -> int:
    idx = gt.EvidenceIndex(PROGRAM_ROOT)
    store = LadderStore(STATE_PATH, allow_advance=args.enable_advance)
    gate = gt.evaluate_gate(args.advance, idx)
    res = store.advance(args.advance, gate)
    print(json.dumps({"attempt": res, "gate": {"verdict": gate["verdict"], "reason_code": gate.get("reason_code")}},
                     indent=1, ensure_ascii=False))
    return 0 if res.get("advanced") else 3


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="AUP-MIG-016 cutover coordinator (coord0)")
    ap.add_argument("--status", action="store_true", help="print the persisted ladder state")
    ap.add_argument("--reconciliation", action="store_true", help="print the two-vocabulary map")
    ap.add_argument("--init", action="store_true", help="create receipts/cutover/state.json at FILES_AUTHORITATIVE")
    ap.add_argument("--gates", action="store_true", help="evaluate every DEC-AUP-0012 gate against the real receipts")
    ap.add_argument("--advance", metavar="STATE", help="attempt one ladder transition (refused by card scope)")
    ap.add_argument("--enable-advance", action="store_true", help="(later cards) allow the ladder to advance")
    ap.add_argument("--drill", action="store_true", help="run the MIG-014 fault matrix against this coordinator")
    ap.add_argument("--selftest", action="store_true", help="reference matrix + mutation battery + rule battery")
    ap.add_argument("--out", help="output file (--gates) or directory (--drill)")
    ap.add_argument("--source-set-epoch", default="538d2e768ab0a98e2f7dafd651c4cd3035ef60b5")
    ap.add_argument("--target-writer-epoch", type=int, default=None)
    args = ap.parse_args(argv)
    if args.drill or args.selftest:
        import drill  # local import: the drill pulls in the MIG-014 modules
        return drill.main_from(args)
    if args.reconciliation:
        return cmd_reconciliation(args)
    if args.init:
        return cmd_init(args)
    if args.gates:
        return cmd_gates(args)
    if args.advance:
        return cmd_advance(args)
    return cmd_status(args)


if __name__ == "__main__":
    raise SystemExit(main())
