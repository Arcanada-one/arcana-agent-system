"""AUP-MIG-016 `coord0` — the MIG-014 fault matrix, re-run against the **real** coordinator.

`fault0` (AUP-MIG-014) built a simulated coordinator, an independent oracle (`oracle.py`, rules
O01–O18) and a fault matrix of 120 scenarios, and declared itself "the executable acceptance oracle
of the MIG-016 coordinator, which does not exist yet". It exists now, so the matrix is pointed at it:
`RealScenario` reuses `scenarios.Scenario` unchanged — the same faults, the same injection points,
the same crash / resume / clear / abort choreography, the same expectation table — and only swaps
the system under test for `coordinator.CutoverWindow`.

On top of the reused matrix this module drills what the real coordinator adds:

* **gate refusal** — the window at every ladder position: a phase whose DEC-AUP-0012 ladder state is
  not reached must pause safe and issue no effect;
* **the ladder itself** — card scope (coord0 may only create `FILES_AUTHORITATIVE`), a crash between
  the transition receipt and the state write, and the resume that finishes it from the receipt;
* **the live gates** — the real evidence of the program, evaluated today;
* the **host reactivation** clause (a login or update re-runs the activation script).

`--selftest` is evidence, not reassurance: the reference must satisfy both oracles *and* the
expectation table; every mutant of `coordinator.MUTATIONS` must be killed; every rule of both oracles
must fire on some mutant; and the selftest's own negative controls must go red.

stdlib only; no host, service, repository or process is touched. The only writes are under `--out`
and in a temporary directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
FAULT_DRILL = HERE.parents[0] / "fault_drill"
# the MIG-014 modules use flat imports and one of them is *also* called `coordinator`, so they are
# resolved first and this card's coordinator is loaded under an explicit name — the drill must run
# the real coordinator, never the simulated one it replaces.
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))
sys.path.insert(0, str(FAULT_DRILL))   # ahead of this directory: `coordinator` must mean the MIG-014 one here

import oracle  # noqa: E402  (MIG-014, unchanged: rules O01–O18)
import scenarios as sc  # noqa: E402  (MIG-014, unchanged: the fault matrix and the expectation table)


def _load(name: str, filename: str):
    import importlib.util
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


co = _load("mig016_coordinator", "coordinator.py")
be = sys.modules["backends"]
gt = sys.modules["gates"]
import gate_oracle as go  # noqa: E402

assert sc.Coordinator is not co.CutoverWindow, "the drill must swap the system under test, not reuse it"

VERSION = "coord0/1.0.0"
FULL_LADDER = "MUNERAL_AUTHORITATIVE"
PASS_GATE = {"verdict": "PASS", "reason_code": None, "target_state": "SHADOW_PROJECTION",
             "note": "drill fixture: a synthetic PASS, never a real gate verdict"}
BLOCK_GATE = {"verdict": "BLOCK", "reason_code": "SHADOW_NOT_YET_STABLE", "target_state": "SHADOW_PROJECTION"}
WINDOW_MUTANTS = [m for m in co.MUTATIONS if m.startswith("M")]
LADDER_MUTANTS = ["N02_state_advances_before_receipt", "N06_state_file_written_at_any_state",
                  "N11_receipt_regenerated_on_resume"]
GATE_MUTANTS = ["N05_gate_passes_with_missing_receipt", "N09_not_measured_counts_as_pass",
                "N10_gate_omits_missing_receipts"]
#: the delta-checklist normaliser's own mutants (COORD-FIX0) — killed by a dedicated fixture
#: comparison (reference verdict vs mutated verdict), not by the generic gate oracle: both mutants
#: still emit a structurally valid tri-valued verdict with `missing` correctly named, so no G0x rule
#: fires on them; only the *wrong* verdict for a known-good fixture proves the bug.
DELTA_CHECKLIST_MUTANTS = ["N12_delta_checklist_list_shape_dropped", "N13_delta_checklist_mismatch_ignored"]
#: the reused matrix knows four injection points; the real coordinator has a fifth durable step
#: (the transition receipt), so the drill adds one crash scenario per phase for it.
RECEIPT_POINT_SCENARIOS = [("crash", _p, "after_receipt") for _p in
                           ["QUIESCING", "FENCED", "FINAL_SYNC", "VALIDATED", "WRITE_COMMITTED",
                            "HOSTS_ACTIVATING", "OBSERVING", "COMPLETE"]]
NEW_WINDOW_MUTANTS = ["N01_ignore_ladder_authorisation", "N03_barrier_accepts_candidate_schema",
                      "N04_host_ack_not_idempotent", "N08_resume_recomputes_state",
                      "N11_receipt_regenerated_on_resume"]


def full_matrix() -> List[Tuple[str, str, Optional[str]]]:
    """The MIG-014 matrix, unchanged, plus the crash scenarios for the receipt step."""
    return sc.matrix() + RECEIPT_POINT_SCENARIOS


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def program_commit() -> Optional[str]:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True, text=True,
                              check=True).stdout.strip()
    except Exception:
        return None


# ------------------------------------------------------------------ the reused matrix
class RealScenario(sc.Scenario):
    """The MIG-014 scenario with the real coordinator as the system under test."""

    def __init__(self, fault: str, state: str, point: Optional[str], mutations: FrozenSet[str] = frozenset(),
                 mode: str = "live", saved_obs: Optional[Dict[str, Any]] = None,
                 ladder_state: str = FULL_LADDER) -> None:
        super().__init__(fault, state, point, mutations=mutations, mode=mode, saved_obs=saved_obs)
        self.ladder_state = ladder_state
        self.reactivations: List[Dict[str, Any]] = []

    def new_coordinator(self) -> co.CutoverWindow:
        return co.CutoverWindow(
            self.world, self.journal, self.observer, self.migration_id,
            mutations=self.mutations, fault_hook=self.hook, replay_mode=(self.mode == "replay"),
            ladder=co.LadderView(self.ladder_state, "drill fixture: simulated gate evidence, the live "
                                                    "receipts/cutover/state.json is never read or written"),
            backends=be.Backends.simulated(self.world))

    def run(self) -> Dict[str, Any]:
        tr = super().run()
        c = self.coordinator
        committed = self.world.authority.current_epoch == c.target_writer_epoch
        for entry in [a for a in list(c.ack_ledger) if a.get("result") == "applied"]:
            host, epoch = entry["host"], entry["epoch"]
            self.reactivations.append({"host": host, "epoch": epoch, "kind": "repeat",
                                       "result": c.reactivate_host(host, epoch)})
            if committed and epoch - 1 > 0:
                self.reactivations.append({"host": host, "epoch": epoch - 1, "kind": "stale",
                                           "result": c.reactivate_host(host, epoch - 1)})
        tr = self.trace()
        tr["ladder_state"] = self.ladder_state
        tr["reactivations"] = self.reactivations
        tr["ack_ledger"] = list(c.ack_ledger)
        tr["barrier"] = c.barrier
        return tr


def run_real_matrix(mutations: FrozenSet[str] = frozenset(), mode: str = "live",
                    saved: Optional[Dict[str, Dict[str, Any]]] = None,
                    only: Optional[List[Tuple[str, str, Optional[str]]]] = None,
                    ladder_state: str = FULL_LADDER) -> List[Dict[str, Any]]:
    traces: List[Dict[str, Any]] = []
    for (f, s, p) in (only or full_matrix()):
        scen = RealScenario(f, s, p, mutations=mutations, mode=mode,
                            saved_obs=(saved or {}).get(sc.scenario_id(f, s, p)), ladder_state=ladder_state)
        try:
            tr = scen.run()
        except KeyError as exc:   # replay without a saved observation
            tr = {"scenario": scen.id, "fault": f, "state": s, "point": p, "mode": mode,
                  "journal": scen.journal.records, "events": scen.world.events,
                  "effect_ledger": scen.world.effect_ledger, "authority_log": scen.world.authority.log,
                  "final": {**scen.world.snapshot(), "state": "REPLAY_FAILED"}, "transitions": [],
                  "transition_digest": None, "paused_reasons": [], "abort_result": None, "rollback_result": None,
                  "stale_writer": None, "resume_results": [], "break_glass": [], "findings": [],
                  "notes": [str(exc)], "saved_observations": {}, "replay_error": str(exc),
                  "ladder_state": ladder_state, "reactivations": [], "ack_ledger": [], "barrier": None}
        traces.append(tr)
    return traces


def gate_trace(tr: Dict[str, Any], card: str = "coord0-drill") -> Dict[str, Any]:
    return {"card": card, "window_journal": tr.get("journal", []), "events": tr.get("events", [])}


def evaluate_traces(traces: List[Dict[str, Any]], disabled_o: Optional[set] = None,
                    disabled_g: Optional[set] = None) -> Dict[str, Any]:
    per: List[Dict[str, Any]] = []
    for tr in traces:
        viol = oracle.evaluate(tr, disabled=disabled_o)
        gviol = go.evaluate(gate_trace(tr), disabled=disabled_g)
        exp = sc.check_expectation(tr) if not tr.get("replay_error") else ["replay failed: " + tr["replay_error"]]
        per.append({
            "scenario": tr["scenario"], "fault": tr["fault"], "state": tr["state"], "point": tr["point"],
            "mode": tr["mode"], "ladder_state": tr.get("ladder_state"), "final": tr["final"]["state"],
            "paused_reasons": tr["paused_reasons"], "transition_digest": tr["transition_digest"],
            "effect_counter_max": max((r["count"] for r in tr["effect_ledger"].values()), default=0),
            "model_calls": tr["final"]["model_calls"], "oracle_violations": viol, "gate_oracle_violations": gviol,
            "expectation_mismatches": exp,
            "verdict": "PASS" if not viol and not gviol and not exp else "FAIL",
        })
    return {"scenarios": per, "n": len(per),
            "oracle_violations": sum(len(p["oracle_violations"]) for p in per),
            "gate_oracle_violations": sum(len(p["gate_oracle_violations"]) for p in per),
            "expectation_mismatches": sum(len(p["expectation_mismatches"]) for p in per),
            "pass": sum(1 for p in per if p["verdict"] == "PASS"),
            "fail": sum(1 for p in per if p["verdict"] == "FAIL")}


# ------------------------------------------------------------------ gate-refusal scenarios
def first_blocked_phase(ladder_state: str) -> Optional[str]:
    for phase in co.PHASES:
        need = co.AUTHORISING_LADDER_STATE[phase]
        if co.LADDER.index(ladder_state) < co.LADDER.index(need):
            return phase
    return None


def run_gate_refusal() -> List[Dict[str, Any]]:
    """The window at every ladder position. `crash@COMPLETE` is a fault that can only fire once the
    whole window ran, so for every position below the top it is a no-op: what stops the machine is
    the gate, not the fault."""
    out: List[Dict[str, Any]] = []
    for ladder_state in co.LADDER:
        scen = RealScenario("crash", "COMPLETE", "after_checkpoint", ladder_state=ladder_state)
        tr = scen.run()
        blocked = first_blocked_phase(ladder_state)
        mismatches: List[str] = []
        if blocked is None:
            if tr["final"]["state"] != "COMPLETE":
                mismatches.append(f"fully authorised ladder ended in {tr['final']['state']}")
        else:
            need = co.AUTHORISING_LADDER_STATE[blocked]
            want = f"GATE_NOT_SATISFIED:{need}"
            if tr["final"]["state"] != "PAUSED_SAFE":
                mismatches.append(f"expected PAUSED_SAFE at {blocked}, got {tr['final']['state']}")
            if tr["final"].get("paused_reason") != want:
                mismatches.append(f"pause reason {tr['final'].get('paused_reason')} != {want}")
            if any(r.get("kind") == "intent" and r.get("state_to") == blocked for r in tr["journal"]):
                mismatches.append(f"effects were intended for the unauthorised phase {blocked}")
            reached = [r.get("state_to") for r in tr["journal"] if r.get("kind") == "transition"]
            if blocked in reached:
                mismatches.append(f"phase {blocked} was entered without its ladder state")
        out.append({
            "ladder_state": ladder_state, "first_blocked_phase": blocked,
            "final": tr["final"]["state"], "paused_reason": tr["final"].get("paused_reason"),
            "gate_checks": [r for r in tr["journal"] if r.get("kind") == "gate_check"],
            "oracle_violations": oracle.evaluate(tr),
            "gate_oracle_violations": go.evaluate(gate_trace(tr)),
            "mismatches": mismatches,
            "verdict": "PASS" if not mismatches else "FAIL",
            "trace": tr,
        })
    return out


# ------------------------------------------------------------------ the ladder drills
def ladder_card_scope(tmp: Path, mutations: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    """A coord0-shaped session: it may create the state file at FILES_AUTHORITATIVE and must refuse
    every advance — even one whose gate says PASS."""
    root = tmp / "card-scope"
    root.mkdir(parents=True, exist_ok=True)
    store = co.LadderStore(root / "state.json", allow_advance=False, mutations=mutations)
    steps = [
        {"step": "initialise", "result": store.initialise("AUP-MIG-016", "sse-drill", 8)},
        {"step": "initialise_again", "result": store.initialise("AUP-MIG-016", "sse-drill", 8)},
        {"step": "advance_with_a_passing_gate", "result": store.advance("SHADOW_PROJECTION", PASS_GATE)},
    ]
    mismatches: List[str] = []
    if not steps[0]["result"].get("created"):
        mismatches.append("the first initialise did not create the state file")
    if steps[1]["result"].get("created"):
        mismatches.append("the second initialise created a second state file (not idempotent)")
    advanced = steps[2]["result"].get("advanced")
    if advanced and "N06_state_file_written_at_any_state" not in mutations:
        mismatches.append("an advance was accepted although coord0 may only write FILES_AUTHORITATIVE")
    if not advanced and steps[2]["result"].get("reason_code") not in ("CARD_SCOPE_COORD0",) \
            and "N06_state_file_written_at_any_state" not in mutations:
        mismatches.append(f"unexpected refusal reason {steps[2]['result'].get('reason_code')}")
    return {"steps": steps, "journal": store.journal, "state_file": json.loads((root / "state.json").read_text()),
            "mismatches": mismatches, "verdict": "PASS" if not mismatches else "FAIL"}


def ladder_crash_safety(tmp: Path, mutations: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    """A later card's ladder (advance enabled): a crash between the transition receipt and the state
    write, then the resume that finishes the transition from the receipt already on disk."""
    root = tmp / "crash-safety"
    root.mkdir(parents=True, exist_ok=True)
    path = root / "state.json"
    journal: List[Dict[str, Any]] = []
    steps: List[Dict[str, Any]] = []

    s0 = co.LadderStore(path, allow_advance=True, mutations=mutations)
    steps.append({"step": "initialise", "result": s0.initialise("AUP-MIG-016", "sse-drill", 8)})
    steps.append({"step": "advance_on_a_blocking_gate", "result": s0.advance("SHADOW_PROJECTION", BLOCK_GATE)})
    journal += s0.journal

    s1 = co.LadderStore(path, allow_advance=True, mutations=mutations, crash_after="receipt")
    crashed = False
    try:
        s1.advance("SHADOW_PROJECTION", PASS_GATE)
    except co.LadderCrash as exc:
        crashed = True
        steps.append({"step": "crash_after_receipt", "result": str(exc)})
    journal += s1.journal
    state_after_crash = json.loads(path.read_text())["state"]

    s2 = co.LadderStore(path, allow_advance=True, mutations=mutations)   # a fresh process
    steps.append({"step": "resume_advance", "result": s2.advance("SHADOW_PROJECTION", PASS_GATE)})
    steps.append({"step": "advance_again", "result": s2.advance("SHADOW_PROJECTION", PASS_GATE)})
    journal += s2.journal
    for i, rec in enumerate(journal, 1):
        rec["seq"] = i

    final = json.loads(path.read_text())
    mismatches: List[str] = []
    if not crashed:
        mismatches.append("the injected crash did not happen")
    if state_after_crash != "FILES_AUTHORITATIVE" and "N02_state_advances_before_receipt" not in mutations:
        mismatches.append(f"the state advanced to {state_after_crash} before the transition receipt was durable")
    if steps[1]["result"].get("advanced"):
        mismatches.append("a blocking gate was accepted")
    if not steps[-2]["result"].get("advanced"):
        mismatches.append(f"the resume did not finish the transition: {steps[-2]['result']}")
    if steps[-1]["result"].get("advanced"):
        mismatches.append("a repeated advance to the same state was accepted twice")
    if final["state"] != "SHADOW_PROJECTION":
        mismatches.append(f"final ladder state {final['state']}")
    if len([h for h in final["history"] if h["to"] == "SHADOW_PROJECTION"]) != 1:
        mismatches.append("the transition appears more than once in the history")
    return {"steps": steps, "journal": journal, "state_file": final, "state_after_crash": state_after_crash,
            "mismatches": mismatches, "verdict": "PASS" if not mismatches else "FAIL"}


# ------------------------------------------------------------------ gate evaluation (live + fixture)
def fixture_index(tmp: Path) -> gt.EvidenceIndex:
    """A synthetic evidence tree in which the shadow-projection gate's *measurable* requirements are
    satisfied. It exists to show the instrument is not stuck on 'no': the gate then reads
    NOT_MEASURED (because the derived-marker audit still has nobody to measure it), never PASS."""
    root = tmp / "fixture"
    proj = root / "receipts" / "projection"
    proj.mkdir(parents=True, exist_ok=True)
    dig = "sha256:" + "a" * 64
    for i in range(10):
        (proj / f"shadow-fixture-{i:02d}.json").write_text(json.dumps({
            "schema": "ShadowProjectionReceipt/v1", "captured_at_utc": f"2026-09-05T{10 + i:02d}:00:00Z",
            "output_digest": dig, "rows_total": 1382, "rows_identical": 1382, "finding_count": 0,
            "fixture": "AUP-MIG-016 coord0 drill — synthetic, never program evidence",
        }, indent=1) + "\n", encoding="utf-8")
    for i in range(2):
        (proj / f"parity-fixture-{i}.json").write_text(json.dumps({
            "schema": "ProjectionParity/v1", "captured_at_utc": f"2026-09-05T{20 + i:02d}:00:00Z",
            "status": "VERIFIED", "identical_digest": True, "gap_seconds": 3600.0,
            "fixture": "AUP-MIG-016 coord0 drill — synthetic, never program evidence",
        }, indent=1) + "\n", encoding="utf-8")
    return gt.EvidenceIndex(root)


def delta_checklist_fixture(tmp: Path, label: str, block: Any) -> gt.EvidenceIndex:
    """One isolated evidence tree carrying exactly one `delta_imported_checklist_<label>` block, so
    `_delta_batch`'s `docs[-1]` picks it unambiguously (COORD-FIX0 fixtures: dict shape, list shape,
    malformed shape)."""
    root = tmp / f"delta-checklist-{label}"
    d = root / "receipts" / "import"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"checklist-{label}-fixture.json").write_text(json.dumps({
        "schema": "ReadinessReceipt/v1", "portion_id": f"drill:delta-checklist-{label}-fixture",
        "captured_at_utc": "2026-01-01T00:00:00Z",
        f"delta_imported_checklist_{label}_fixture": block,
    }), encoding="utf-8")
    return gt.EvidenceIndex(root)


def delta_checklist_fixtures(tmp: Path) -> Dict[str, gt.EvidenceIndex]:
    dict_block = {cond: {"verdict": "PASS", "evidence": "fixture"} for cond in gt.DELTA_CONDITIONS}
    list_block = [{"check": label, "verdict": "PASS", "evidence": "fixture"}
                  for label in gt.DELTA_CONDITION_ALIASES]
    return {
        "dict": delta_checklist_fixture(tmp, "dict", dict_block),
        "list": delta_checklist_fixture(tmp, "list", list_block),
        "malformed": delta_checklist_fixture(tmp, "malformed", "not-a-valid-checklist-block"),
    }


def evaluate_gates(idx: gt.EvidenceIndex, mutations: FrozenSet[str] = frozenset()) -> List[Dict[str, Any]]:
    return gt.evaluate_all(idx, mutations)


# ------------------------------------------------------------------ selftest
def selftest(as_json: bool = True) -> int:
    report: Dict[str, Any] = {
        "schema": "SelftestReport/v1", "tool": co.TOOL, "version": VERSION, "captured_at_utc": utcnow(),
        "host": platform.node(), "program_commit": program_commit(), "model": co.MODEL,
        "provisional_until_fable_review": True,
        "reuses": {"fault_matrix": "tools/mig/fault_drill/scenarios.py (unchanged)",
                   "oracle": "tools/mig/fault_drill/oracle.py (unchanged, O01–O18)",
                   "environment": "tools/mig/fault_drill/world.py (the simulated backend)"},
    }
    ok = True
    checks: Dict[str, bool] = {}

    def req(name: str, cond: Any) -> bool:
        """Record every acceptance clause of the selftest by name, so a FAIL says which one."""
        checks[name] = bool(cond)
        return bool(cond)

    # 1. the reference matrix against the real coordinator
    traces = run_real_matrix()
    ref = evaluate_traces(traces)
    report["reference_matrix"] = {k: v for k, v in ref.items() if k != "scenarios"}
    report["reference_failures"] = [p for p in ref["scenarios"] if p["verdict"] == "FAIL"][:10]
    ok &= req("reference_matrix_clean", ref["fail"] == 0)

    # 2. replay from the saved observations: no model call, identical transition digests
    saved = {tr["scenario"]: tr["saved_observations"] for tr in traces}
    live_digest = {tr["scenario"]: tr["transition_digest"] for tr in traces}
    rtraces = run_real_matrix(mode="replay", saved=saved)
    for tr in rtraces:
        tr["live_transition_digest"] = live_digest.get(tr["scenario"])
    rep = evaluate_traces(rtraces)
    report["replay"] = {"n": rep["n"], "fail": rep["fail"],
                        "model_calls_total": sum(p["model_calls"] for p in rep["scenarios"]),
                        "digest_equal": sum(1 for tr in rtraces
                                            if tr["transition_digest"] == tr.get("live_transition_digest"))}
    ok &= req("replay_no_model_calls_same_digests", rep["fail"] == 0 and report["replay"]["model_calls_total"] == 0 and report["replay"]["digest_equal"] == rep["n"])

    # 3. gate refusal at every ladder position
    refusal = run_gate_refusal()
    report["gate_refusal"] = [{k: v for k, v in r.items() if k != "trace"} for r in refusal]
    ok &= req("gate_refusal_at_every_ladder_position", all(r["verdict"] == "PASS" for r in refusal))

    # 4. the ladder drills
    with tempfile.TemporaryDirectory(prefix="mig016-coord0-") as td:
        tmp = Path(td)
        card_scope = ladder_card_scope(tmp)
        crash = ladder_crash_safety(tmp)
        fidx = fixture_index(tmp)
        fixture_gates = evaluate_gates(fidx)
        fixture_mutant_gates = {m: evaluate_gates(fidx, frozenset([m])) for m in GATE_MUTANTS}
        ladder_mutants = {}
        for m in LADDER_MUTANTS:
            mt = Path(td) / f"mut-{m}"
            mt.mkdir(parents=True, exist_ok=True)
            ladder_mutants[m] = {"card_scope": ladder_card_scope(mt, frozenset([m])),
                                 "crash_safety": ladder_crash_safety(mt, frozenset([m]))}
    report["ladder_card_scope"] = {k: v for k, v in card_scope.items() if k != "journal"}
    report["ladder_crash_safety"] = {k: v for k, v in crash.items() if k != "journal"}
    ok &= req("ladder_card_scope_and_crash_safety", card_scope["verdict"] == "PASS" and crash["verdict"] == "PASS")
    card_scope_trace = {"card": "coord0", "ladder_journal": card_scope["journal"]}
    crash_trace = {"card": "coord0-drill", "ladder_journal": crash["journal"]}
    report["ladder_gate_oracle"] = {"card_scope": go.evaluate(card_scope_trace), "crash_safety": go.evaluate(crash_trace)}
    ok &= req("ladder_gate_oracle_clean", not report["ladder_gate_oracle"]["card_scope"] and not report["ladder_gate_oracle"]["crash_safety"])

    # 5. the live gates over the program's real receipts (they are expected to refuse)
    live_idx = gt.EvidenceIndex(co.PROGRAM_ROOT)
    live_gates = evaluate_gates(live_idx)
    live_gate_viol = go.evaluate({"card": "coord0", "gate_evaluations": live_gates})
    report["live_gates"] = {g["target_state"]: {"verdict": g["verdict"], "reason_code": g["reason_code"], **g["counts"]}
                            for g in live_gates}
    report["live_gate_oracle_violations"] = live_gate_viol
    ok &= req("live_gate_evaluation_clean", not live_gate_viol)
    fixture_viol = go.evaluate({"card": "coord0-drill", "gate_evaluations": fixture_gates})
    report["fixture_gates"] = {g["target_state"]: {"verdict": g["verdict"], "reason_code": g["reason_code"]}
                               for g in fixture_gates}
    report["fixture_gate_oracle_violations"] = fixture_viol
    ok &= req("fixture_gate_evaluation_clean", not fixture_viol)
    ok &= req("fixture_gate_reads_not_measured", fixture_gates[0]["verdict"] == "NOT_MEASURED")   # measurable parts pass, the unmeasured one still holds

    # 6. mutation battery
    mutants: Dict[str, Any] = {}
    kill_o: Dict[str, set] = {}
    kill_g: Dict[str, set] = {}
    mutant_traces: Dict[str, List[Dict[str, Any]]] = {}
    crash_only = [t for t in full_matrix() if t[0] == "crash"]
    for m in WINDOW_MUTANTS:
        mt = run_real_matrix(mutations=frozenset([m])) if m != "M11_replay_calls_model" \
            else run_real_matrix(mutations=frozenset([m]), mode="replay", saved=saved)
        if m == "M11_replay_calls_model":
            for tr in mt:
                tr["live_transition_digest"] = live_digest.get(tr["scenario"])
        mutant_traces[m] = mt
        o_rules, g_rules = set(), set()
        for tr in mt:
            for v in oracle.evaluate(tr):
                o_rules.add(v["rule"])
            for v in go.evaluate(gate_trace(tr)):
                g_rules.add(v["rule"])
        kill_o[m], kill_g[m] = o_rules, g_rules
        mutants[m] = {"harness": "reused fault matrix", "killed": bool(o_rules | g_rules),
                      "killed_by": sorted(o_rules | g_rules), "description": co.MUTATIONS[m]}
        ok &= req(f"mutant_killed:{m}@matrix", o_rules | g_rules)
    for m in NEW_WINDOW_MUTANTS:
        ladder_state = "FILES_AUTHORITATIVE" if m == "N01_ignore_ladder_authorisation" else FULL_LADDER
        mt = run_real_matrix(mutations=frozenset([m]), only=crash_only, ladder_state=ladder_state)
        mutant_traces[m] = mt
        g_rules = set()
        for tr in mt:
            for v in go.evaluate(gate_trace(tr)):
                g_rules.add(v["rule"])
        kill_g[m] = g_rules
        kill_o.setdefault(m, set())
        mutants[m] = {"harness": f"fault matrix (crash scenarios) at ladder {ladder_state}",
                      "killed": bool(g_rules), "killed_by": sorted(g_rules), "description": co.MUTATIONS[m]}
        ok &= req(f"mutant_killed:{m}@matrix-crash", g_rules)
    for m in LADDER_MUTANTS:
        rules = set()
        for kind, tr in (("card_scope", {"card": "coord0", "ladder_journal": ladder_mutants[m]["card_scope"]["journal"]}),
                         ("crash_safety", {"card": "coord0-drill", "ladder_journal": ladder_mutants[m]["crash_safety"]["journal"]})):
            for v in go.evaluate(tr):
                rules.add(v["rule"])
        prev = mutants.get(m, {})
        killed_by = sorted(set(prev.get("killed_by", [])) | rules)
        mutants[m] = {"harness": (prev.get("harness", "") + " + ladder drill").strip(" +"),
                      "killed": bool(killed_by), "killed_by": killed_by, "description": co.MUTATIONS[m]}
        kill_g[m] = set(killed_by) | kill_g.get(m, set())
        ok &= req(f"mutant_killed:{m}@ladder", killed_by)
    for m in GATE_MUTANTS:
        rules = set()
        for idx_name, evals in (("live", evaluate_gates(live_idx, frozenset([m]))),
                                ("fixture", fixture_mutant_gates[m])):
            for v in go.evaluate({"card": "coord0", "gate_evaluations": evals}):
                rules.add(v["rule"])
        mutants[m] = {"harness": "gate evaluation (live receipts + fixture)", "killed": bool(rules),
                      "killed_by": sorted(rules), "description": co.MUTATIONS[m]}
        kill_g[m] = rules
        ok &= req(f"mutant_killed:{m}@gates", rules)
    # 6b. the delta-checklist normaliser (COORD-FIX0): dict shape, list shape, malformed shape
    with tempfile.TemporaryDirectory(prefix="mig016-coord0-delta-checklist-") as td:
        fx = delta_checklist_fixtures(Path(td))
        dict_ref = gt._delta_batch(fx["dict"])
        list_ref = gt._delta_batch(fx["list"])
        malformed_ref = gt._delta_batch(fx["malformed"])
        list_n12 = gt._delta_batch(fx["list"], frozenset(["N12_delta_checklist_list_shape_dropped"]))
        malformed_n13 = gt._delta_batch(fx["malformed"], frozenset(["N13_delta_checklist_mismatch_ignored"]))
    report["delta_checklist_fixtures"] = {
        "dict_shape": {"verdict": dict_ref[0], "reason_code": dict_ref[1]},
        "list_shape": {"verdict": list_ref[0], "reason_code": list_ref[1]},
        "malformed_shape": {"verdict": malformed_ref[0], "reason_code": malformed_ref[1]},
        "list_shape_under_N12": {"verdict": list_n12[0], "reason_code": list_n12[1]},
        "malformed_shape_under_N13": {"verdict": malformed_n13[0], "reason_code": malformed_n13[1]},
    }
    ok &= req("delta_checklist_dict_shape_reads_pass", dict_ref[0] == gt.PASS)
    ok &= req("delta_checklist_list_shape_reads_pass", list_ref[0] == gt.PASS)
    ok &= req("delta_checklist_malformed_shape_blocks_typed",
              malformed_ref[0] == gt.BLOCK and malformed_ref[1] == "DELTA_CHECKLIST_SCHEMA_MISMATCH")
    killed_n12 = list_n12[0] != list_ref[0]
    killed_n13 = malformed_n13[0] != malformed_ref[0]
    mutants["N12_delta_checklist_list_shape_dropped"] = {
        "harness": "delta-checklist normaliser fixture (list shape, reference vs mutant verdict)",
        "killed": killed_n12, "killed_by": ["fixture:list_shape_verdict_changed"] if killed_n12 else [],
        "description": co.MUTATIONS["N12_delta_checklist_list_shape_dropped"],
    }
    mutants["N13_delta_checklist_mismatch_ignored"] = {
        "harness": "delta-checklist normaliser fixture (malformed shape, reference vs mutant verdict)",
        "killed": killed_n13, "killed_by": ["fixture:malformed_shape_verdict_changed"] if killed_n13 else [],
        "description": co.MUTATIONS["N13_delta_checklist_mismatch_ignored"],
    }
    ok &= req("mutant_killed:N12_delta_checklist_list_shape_dropped@delta_checklist_fixture", killed_n12)
    ok &= req("mutant_killed:N13_delta_checklist_mismatch_ignored@delta_checklist_fixture", killed_n13)

    report["mutation_battery"] = {"mutants": mutants, "killed": sum(1 for x in mutants.values() if x["killed"]),
                                  "total": len(mutants)}
    ok &= req("every_declared_mutation_has_a_harness", len(mutants) == len(co.MUTATIONS))

    # 7. rule battery: every rule of both oracles must fire on some mutant
    o_load = {r: {"fires_on": sorted(m for m, ks in kill_o.items() if r in ks)} for r in oracle.RULES}
    for r, v in o_load.items():
        v["load_bearing"] = bool(v["fires_on"])
    g_load = {r: {"fires_on": sorted(m for m, ks in kill_g.items() if r in ks)} for r in go.RULES}
    for r, v in g_load.items():
        v["load_bearing"] = bool(v["fires_on"])
    report["rule_battery"] = {"window_oracle": o_load, "gate_oracle": g_load}
    ok &= req("window_oracle_rules_load_bearing", all(v["load_bearing"] for v in o_load.values()))
    ok &= req("gate_oracle_rules_load_bearing", all(v["load_bearing"] for v in g_load.values()))

    # 8. negative controls of the selftest itself
    wrong = dict(traces[0])
    wrong["final"] = dict(wrong["final"], state="COMPLETE" if wrong["final"]["state"] != "COMPLETE" else "PAUSED_SAFE")
    neg_exp = sc.check_expectation(wrong)
    neg_gate = go.evaluate({"card": "coord0", "gate_evaluations": [
        {"target_state": "SHADOW_PROJECTION", "verdict": "PASS",
         "checks": [{"id": "X", "verdict": "BLOCK", "detail": {"missing": ["everything"]}}]}]})
    report["negative_controls"] = {"wrong_expectation_reported": bool(neg_exp), "detail": neg_exp[:2],
                                   "wrong_gate_reported": bool(neg_gate),
                                   "gate_detail": [v["rule"] for v in neg_gate]}
    ok &= req("negative_controls_go_red", bool(neg_exp) and bool(neg_gate))

    report["checks"] = checks
    report["failed_checks"] = sorted(k for k, v in checks.items() if not v)
    report["verdict"] = "PASS" if ok else "FAIL"
    if as_json:
        print(json.dumps(report, indent=1, ensure_ascii=False))
    else:
        print(f"selftest {report['verdict']}: matrix {ref['pass']}/{ref['n']} pass, "
              f"mutants {report['mutation_battery']['killed']}/{report['mutation_battery']['total']} killed")
    return 0 if ok else 1


# ------------------------------------------------------------------ drill
def compact_documents(schema: str, records: List[Dict[str, Any]], key) -> Dict[str, Any]:
    """The window's receipts and barriers are deterministic: the same keyed transition always yields
    the same document, so 128 scenarios produce one document per phase, not 1024. Store each distinct
    document once, and per scenario only its digest — which is what makes the claim checkable."""
    distinct: Dict[str, Dict[str, Any]] = {}
    index: List[Dict[str, Any]] = []
    for r in records:
        doc = r.get("document") or {}
        d = doc.get("document_digest") or ("sha256:" + hashlib.sha256(
            json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest())
        distinct.setdefault(d, {"key": key(r), "document": doc})
        index.append({"scenario": r.get("scenario"), "key": key(r), "digest": d})
    per_run: Dict[str, set] = {}
    for row in index:
        per_run.setdefault(f"{row['scenario']}|{row['key']}", set()).add(row["digest"])
    worst = max((len(v) for v in per_run.values()), default=0)
    return {"schema": schema, "distinct_documents": distinct, "per_scenario": index,
            "distinct_count": len(distinct), "record_count": len(records),
            "max_distinct_digests_per_run_and_key": worst,
            "determinism": "the property is one digest per (scenario, key): inside a run a receipt is "
                           "reused verbatim, never regenerated (gate-oracle G10). Across runs the "
                           "documents legitimately differ — a different lease id, a different route "
                           "into the phase (step vs reconciliation)"}


def drill(out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    traces = run_real_matrix()
    ev = evaluate_traces(traces)
    saved = {tr["scenario"]: tr["saved_observations"] for tr in traces}
    live_digest = {tr["scenario"]: tr["transition_digest"] for tr in traces}
    rtraces = run_real_matrix(mode="replay", saved=saved)
    for tr in rtraces:
        tr["live_transition_digest"] = live_digest.get(tr["scenario"])
    rev = evaluate_traces(rtraces)
    refusal = run_gate_refusal()
    with tempfile.TemporaryDirectory(prefix="mig016-coord0-") as td:
        tmp = Path(td)
        card_scope = ladder_card_scope(tmp)
        crash = ladder_crash_safety(tmp)
    live_idx = gt.EvidenceIndex(co.PROGRAM_ROOT)
    live_gates = evaluate_gates(live_idx)

    def dump(name: str, obj: Any) -> Dict[str, Any]:
        p = out_dir / name
        p.write_text(json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        return {"file": name, "digest": "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest(),
                "bytes": p.stat().st_size}

    def collect(kind: str) -> List[Dict[str, Any]]:
        return [{"scenario": tr["scenario"], **r} for tr in traces for r in tr["journal"] if r["kind"] == kind]

    files = [
        dump("transitions.json", {"schema": "CutoverDrillTransitions/v1", "records": collect("transition")}),
        dump("fence.json", {"schema": "CutoverDrillFence/v1", "records": collect("fence")}),
        dump("lease.json", {"schema": "CutoverDrillLease/v1", "records": collect("lease")}),
        dump("reconciliation.json", {"schema": "CutoverDrillReconciliation/v1", "records": collect("reconciliation")}),
        dump("rollback.json", {"schema": "CutoverDrillRollback/v1", "records": collect("rollback")}),
        dump("barrier.json", {**compact_documents("CutoverDrillBarrier/v1", collect("barrier"),
                                                  key=lambda r: r["document"]["schema"]),
                              "distinct_from_candidate": be.BARRIER_DISJOINT_PROOF,
                              "production_required_keys": list(be.BARRIER_REQUIRED),
                              "candidate_required_keys": list(be.CANDIDATE_REQUIRED)}),
        dump("activation-ledger.json", {"schema": "CutoverDrillActivationLedger/v1", "records": collect("ack"),
                                        "reactivations": [{"scenario": tr["scenario"], **r}
                                                          for tr in traces for r in tr["reactivations"]]}),
        dump("phase-receipts.json", compact_documents("CutoverDrillPhaseReceipts/v1", collect("phase_receipt"),
                                                       key=lambda r: r["document"]["phase"])),
        dump("gate-checks.json", {"schema": "CutoverDrillGateChecks/v1", "records": collect("gate_check")}),
        dump("gate-refusal.json", {"schema": "CutoverDrillGateRefusal/v1",
                                   "scenarios": [{k: v for k, v in r.items() if k != "trace"} for r in refusal]}),
        dump("ladder.json", {"schema": "CutoverDrillLadder/v1", "card_scope": card_scope, "crash_safety": crash}),
        dump("gates-live.json", {"schema": "CutoverGateEvaluation/v1", "captured_at_utc": utcnow(),
                                 "gates": live_gates}),
        dump("observations.json", {"schema": "CutoverDrillObservations/v1", "saved": saved}),
        dump("scenarios.json", {"schema": "CutoverDrillScenarios/v1", "scenarios": ev["scenarios"]}),
        dump("replay.json", {"schema": "CutoverDrillReplay/v1", "scenarios": rev["scenarios"]}),
    ]
    summary = {
        "schema": "CutoverDrillSummary/v1", "tool": co.TOOL, "version": VERSION, "captured_at_utc": utcnow(),
        "host": platform.node(), "program_commit": program_commit(), "model": co.MODEL,
        "provisional_until_fable_review": True,
        "system_under_test": "tools/mig/cutover/coordinator.py (the real coordinator), simulated backends",
        "reused_unchanged": ["tools/mig/fault_drill/scenarios.py", "tools/mig/fault_drill/oracle.py",
                             "tools/mig/fault_drill/world.py"],
        "matrix": {k: v for k, v in ev.items() if k != "scenarios"},
        "replay": {"n": rev["n"], "fail": rev["fail"],
                   "model_calls_total": sum(p["model_calls"] for p in rev["scenarios"]),
                   "digest_equal": sum(1 for tr in rtraces if tr["transition_digest"] == tr.get("live_transition_digest"))},
        "gate_refusal": {"positions": len(refusal), "pass": sum(1 for r in refusal if r["verdict"] == "PASS")},
        "ladder": {"card_scope": card_scope["verdict"], "crash_safety": crash["verdict"]},
        "live_gates": {g["target_state"]: g["verdict"] for g in live_gates},
        "files": files,
        "not_measured": [
            "real hosts, the real Muneral writer authority, real tmux lanes and the real GitHub ruleset: the "
            "backends are simulated (backends.Backends.real() refuses)",
            "the live ladder: receipts/cutover/state.json is neither read nor advanced by the drill",
        ],
    }
    p = out_dir / "summary.json"
    p.write_text(json.dumps(summary, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(out_dir), "matrix": summary["matrix"], "replay": summary["replay"],
                      "gate_refusal": summary["gate_refusal"], "ladder": summary["ladder"],
                      "live_gates": summary["live_gates"]}, indent=1, ensure_ascii=False))
    return 0 if ev["fail"] == 0 and rev["fail"] == 0 and all(r["verdict"] == "PASS" for r in refusal) else 1


def main_from(args: argparse.Namespace) -> int:
    if args.selftest:
        return selftest(as_json=True)
    if not args.out:
        print("--drill requires --out <dir>", file=sys.stderr)
        return 2
    return drill(Path(args.out))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="AUP-MIG-016 coord0 drill")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--drill", action="store_true")
    ap.add_argument("--out")
    raise SystemExit(main_from(ap.parse_args()))
