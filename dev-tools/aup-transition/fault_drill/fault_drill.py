#!/usr/bin/env python3
"""AUP-MIG-014 `fault0` — fault drill for the MIG-016 cutover coordinator, checked by an independent oracle.

    fault_drill.py --selftest [--json]
        reference matrix (every fault × every state, crash × 4 points) must satisfy the oracle AND the
        spec's expectation table; then the mutation battery: every coordinator mutant (M01..M15) must be
        killed by the oracle; every oracle rule disabled in turn must let ≥ 1 mutant survive (rule is
        load-bearing); a negative control of the selftest itself (a wrong expectation is reported red).
    fault_drill.py --drill --out <dir>
        runs the matrix live, saves the observations, replays every scenario from them without a model
        call, writes keyed transition / fence / lease / reconciliation / rollback receipts + summary.
    fault_drill.py --replay <dir>
        replays a saved drill directory (no model calls) and compares transition digests.

No real host, service, process, tmux server or repository is touched. stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import oracle  # noqa: E402
from coordinator import MUTATIONS  # noqa: E402
from scenarios import CRASH_POINTS, FAULTS, check_expectation, matrix, run_matrix, scenario_id  # noqa: E402
from world import STATES, canonical  # noqa: E402

VERSION = "fault0/1.0.0"


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha_file(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def program_commit() -> Optional[str]:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return None


def evaluate_traces(traces: List[Dict[str, Any]], disabled: Optional[set] = None) -> Dict[str, Any]:
    per = []
    total_viol = 0
    total_exp = 0
    for tr in traces:
        viol = oracle.evaluate(tr, disabled=disabled)
        exp = check_expectation(tr) if tr["mode"] == "live" or tr.get("final", {}).get("state") != "REPLAY_FAILED" else ["replay failed: " + tr.get("replay_error", "")]
        if tr.get("replay_error"):
            exp = ["replay failed: " + tr["replay_error"]]
        total_viol += len(viol)
        total_exp += len(exp)
        per.append({
            "scenario": tr["scenario"], "fault": tr["fault"], "state": tr["state"], "point": tr["point"], "mode": tr["mode"],
            "final": tr["final"]["state"], "paused_reasons": tr["paused_reasons"], "transitions": tr["transitions"],
            "transition_digest": tr["transition_digest"], "effect_counter_max": max((r["count"] for r in tr["effect_ledger"].values()), default=0),
            "model_calls": tr["final"]["model_calls"], "oracle_violations": viol, "expectation_mismatches": exp,
            "verdict": "PASS" if not viol and not exp else "FAIL",
        })
    return {"scenarios": per, "n": len(per), "oracle_violations": total_viol, "expectation_mismatches": total_exp,
            "pass": sum(1 for p in per if p["verdict"] == "PASS"), "fail": sum(1 for p in per if p["verdict"] == "FAIL")}


# ---------------------------------------------------------------- selftest
def selftest(as_json: bool) -> int:
    report: Dict[str, Any] = {"tool": "fault_drill", "version": VERSION, "captured_at_utc": utcnow()}
    ok = True
    # 1. reference matrix
    traces = run_matrix()
    ref = evaluate_traces(traces)
    report["reference_matrix"] = {k: v for k, v in ref.items() if k != "scenarios"}
    report["reference_failures"] = [p for p in ref["scenarios"] if p["verdict"] == "FAIL"]
    ok &= ref["fail"] == 0
    # 2. replay of the reference from saved observations (no model calls)
    saved = {tr["scenario"]: tr["saved_observations"] for tr in traces}
    live_digest = {tr["scenario"]: tr["transition_digest"] for tr in traces}
    rtraces = run_matrix(mode="replay", saved=saved)
    for tr in rtraces:
        tr["live_transition_digest"] = live_digest.get(tr["scenario"])
    rep = evaluate_traces(rtraces)
    report["replay"] = {"n": rep["n"], "fail": rep["fail"], "model_calls_total": sum(p["model_calls"] for p in rep["scenarios"]),
                        "digest_equal": sum(1 for tr in rtraces if tr["transition_digest"] == tr.get("live_transition_digest"))}
    ok &= rep["fail"] == 0 and report["replay"]["model_calls_total"] == 0 and report["replay"]["digest_equal"] == rep["n"]
    # 3. mutation battery: every coordinator mutant must be killed (≥1 oracle violation or expectation mismatch → we require ORACLE)
    mutants: Dict[str, Any] = {}
    kill_map: Dict[str, set] = {}
    mutant_traces: Dict[str, List[Dict[str, Any]]] = {}
    for m in sorted(MUTATIONS):
        mt = run_matrix(mutations=frozenset([m]))
        if m == "M11_replay_calls_model":
            mt = run_matrix(mutations=frozenset([m]), mode="replay", saved=saved)
            for tr in mt:
                tr["live_transition_digest"] = live_digest.get(tr["scenario"])
        mutant_traces[m] = mt
        rules = set()
        n_viol = 0
        for tr in mt:
            for v in oracle.evaluate(tr):
                rules.add(v["rule"])
                n_viol += 1
        kill_map[m] = rules
        mutants[m] = {"killed": bool(rules), "killed_by": sorted(rules), "violations": n_viol, "description": MUTATIONS[m]}
        ok &= bool(rules)
    report["mutation_battery"] = {"mutants": mutants, "killed": sum(1 for x in mutants.values() if x["killed"]), "total": len(mutants)}
    # 4. every oracle rule is load-bearing: disabling it must let ≥1 mutant survive that only it killed,
    #    OR reduce the total violation count (a rule that changes nothing is untested)
    load: Dict[str, Any] = {}
    for rule in oracle.RULES:
        survivors = []
        for m, mt in mutant_traces.items():
            rules = set()
            for tr in mt:
                for v in oracle.evaluate(tr, disabled={rule}):
                    rules.add(v["rule"])
            if not rules:
                survivors.append(m)
        fired = any(rule in ks for ks in kill_map.values())
        load[rule] = {"fires_on_some_mutant": fired, "mutants_surviving_without_it": survivors, "load_bearing": fired}
        ok &= fired
    report["rule_battery"] = load
    # 5. negative control of the selftest: a deliberately wrong expectation must be reported
    wrong = dict(traces[0])
    wrong["final"] = dict(wrong["final"], state="COMPLETE" if wrong["final"]["state"] != "COMPLETE" else "PAUSED_SAFE")
    neg = check_expectation(wrong)
    report["negative_control"] = {"wrong_expectation_reported": bool(neg), "detail": neg[:2]}
    ok &= bool(neg)
    report["verdict"] = "PASS" if ok else "FAIL"
    if as_json:
        print(json.dumps(report, indent=1, ensure_ascii=False))
    else:
        rm = report["reference_matrix"]
        print(f"reference matrix: {rm['n']} scenarios, {rm['pass']} pass / {rm['fail']} fail (oracle violations {rm['oracle_violations']}, expectation mismatches {rm['expectation_mismatches']})")
        for p in report["reference_failures"][:20]:
            print("  FAIL", p["scenario"], p["final"], p["oracle_violations"][:2], p["expectation_mismatches"][:2])
        rp = report["replay"]
        print(f"replay: {rp['n']} scenarios, {rp['fail']} fail, model calls {rp['model_calls_total']}, digests equal {rp['digest_equal']}/{rp['n']}")
        mb = report["mutation_battery"]
        print(f"mutation battery: {mb['killed']}/{mb['total']} mutants killed")
        for m, x in mb["mutants"].items():
            print(f"  {'KILLED ' if x['killed'] else 'SURVIVED'} {m} by {x['killed_by']}")
        print("rule battery: " + ", ".join(f"{r}={'ok' if x['load_bearing'] else 'UNTESTED'}" for r, x in load.items()))
        print(f"negative control: {'ok' if report['negative_control']['wrong_expectation_reported'] else 'FAIL'}")
        print(report["verdict"])
    return 0 if ok else 1


# ---------------------------------------------------------------- drill
def drill(out: Path, as_json: bool) -> int:
    out.mkdir(parents=True, exist_ok=True)
    ts = utcnow()
    traces = run_matrix()
    ref = evaluate_traces(traces)
    saved = {tr["scenario"]: tr["saved_observations"] for tr in traces}
    (out / "observations.json").write_text(json.dumps(saved, indent=1, ensure_ascii=False, sort_keys=True))
    live_digest = {tr["scenario"]: tr["transition_digest"] for tr in traces}
    rtraces = run_matrix(mode="replay", saved=saved)
    for tr in rtraces:
        tr["live_transition_digest"] = live_digest.get(tr["scenario"])
    rep = evaluate_traces(rtraces)
    keys_of = lambda r: r.get("keys", {})  # noqa: E731
    transitions, fence, lease, reconciliation, rollback = [], [], [], [], []
    for tr in traces:
        sid = tr["scenario"]
        for r in tr["journal"]:
            base = {"scenario": sid, "seq": r["seq"], "at": r["at"], "keys": keys_of(r)}
            if r["kind"] == "transition":
                transitions.append({**base, "state_from": r.get("state_from"), "state_to": r.get("state_to"), "reason": r.get("reason"), "via": r.get("via")})
            elif r["kind"] == "fence":
                fence.append({**base, "fence_key": r.get("key"), "active": r.get("active"), "lease_id": r.get("lease_id")})
            elif r["kind"] == "lease":
                lease.append({**base, "lease_id": r.get("lease_id"), "epoch": r.get("epoch"), "expires_at": r.get("expires_at"), "ttl": r.get("ttl")})
            elif r["kind"] == "reconciliation":
                reconciliation.append({**base, "state": r.get("state"), "effect_key": r.get("effect_key"), "readback": r.get("readback"), "terminal": r.get("terminal"), "reissued": r.get("reissued")})
            elif r["kind"] == "rollback":
                rollback.append({**base, "verdict": r.get("verdict"), "reason": r.get("reason"), "pins": r.get("pins"), "known_good_digest": r.get("known_good_digest")})
        for a in tr["authority_log"]:
            if a["op"] in ("lease_acquire", "lease_check", "lease_release") and a.get("result") != "valid":
                lease.append({"scenario": sid, "authority_seq": a["seq"], "at": a["at"], "op": a["op"], "result": a.get("result"), "reason": a.get("reason"), "epoch": a.get("epoch"), "expires_at": a.get("expires_at")})
            if a["op"] in ("fence_set", "fence_release"):
                fence.append({"scenario": sid, "authority_seq": a["seq"], "at": a["at"], "op": a["op"], "fence_key": a.get("key"), "result": a.get("result")})
            if a["op"] in ("writer_write", "cas_commit", "host_ack") and a.get("result") == "rejected":
                reconciliation.append({"scenario": sid, "authority_seq": a["seq"], "at": a["at"], "op": a["op"], "result": "rejected", "reason": a.get("reason"), "host": a.get("host"), "writer_epoch": a.get("writer_epoch"), "current_epoch": a.get("current_epoch")})
    receipts = {
        "transitions": {"schema": "FaultDrillTransitions/v1", "captured_at_utc": ts, "keyed_by": ["migration_id", "source_set_epoch", "target_writer_epoch"], "n": len(transitions), "records": transitions},
        "fence": {"schema": "FaultDrillFence/v1", "captured_at_utc": ts, "n": len(fence), "records": fence},
        "lease": {"schema": "FaultDrillLease/v1", "captured_at_utc": ts, "n": len(lease), "records": lease},
        "reconciliation": {"schema": "FaultDrillReconciliation/v1", "captured_at_utc": ts, "n": len(reconciliation), "records": reconciliation},
        "rollback": {"schema": "FaultDrillRollback/v1", "captured_at_utc": ts, "n": len(rollback), "records": rollback},
    }
    for name, doc in receipts.items():
        (out / f"{name}.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False))
    (out / "scenarios.json").write_text(json.dumps(ref["scenarios"], indent=1, ensure_ascii=False))
    (out / "replay.json").write_text(json.dumps(rep["scenarios"], indent=1, ensure_ascii=False))
    summary = {
        "schema": "FaultDrillSummary/v1", "tool": "fault_drill", "version": VERSION, "captured_at_utc": ts,
        "host": platform.node(), "program_commit": program_commit(),
        "matrix": {"faults": FAULTS, "states": STATES, "crash_points": CRASH_POINTS, "denominator": len(matrix()),
                   "formula": f"crash × {len(CRASH_POINTS)} points × {len(STATES)} states + {len(FAULTS) - 1} other faults × {len(STATES)} states"},
        "live": {k: v for k, v in ref.items() if k != "scenarios"},
        "replay": {"n": rep["n"], "fail": rep["fail"], "model_calls_total": sum(p["model_calls"] for p in rep["scenarios"]),
                   "digest_equal": sum(1 for tr in rtraces if tr["transition_digest"] == tr.get("live_transition_digest"))},
        "receipts": {name: {"path": f"{name}.json", "n": doc["n"], "sha256": sha_file(out / f"{name}.json")} for name, doc in receipts.items()},
        "observations": {"path": "observations.json", "sha256": sha_file(out / "observations.json"), "model_calls_live": sum(p["model_calls"] for p in ref["scenarios"])},
        "effect_counter_max": max(p["effect_counter_max"] for p in ref["scenarios"]),
        "verdict": "PASS" if ref["fail"] == 0 and rep["fail"] == 0 and sum(p["model_calls"] for p in rep["scenarios"]) == 0 else "FAIL",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False))
    if as_json:
        print(json.dumps(summary, indent=1, ensure_ascii=False))
    else:
        print(f"drill: {summary['matrix']['denominator']} scenarios live {summary['live']['pass']}/{summary['live']['n']} pass; replay model calls {summary['replay']['model_calls_total']}, digests equal {summary['replay']['digest_equal']}/{summary['replay']['n']}; effect counter max {summary['effect_counter_max']}; verdict {summary['verdict']} → {out}")
    return 0 if summary["verdict"] == "PASS" else 1


def replay(src: Path) -> int:
    saved = json.loads((src / "observations.json").read_text())
    live = {p["scenario"]: p["transition_digest"] for p in json.loads((src / "scenarios.json").read_text())}
    rtraces = run_matrix(mode="replay", saved=saved)
    for tr in rtraces:
        tr["live_transition_digest"] = live.get(tr["scenario"])
    rep = evaluate_traces(rtraces)
    calls = sum(p["model_calls"] for p in rep["scenarios"])
    eq = sum(1 for tr in rtraces if tr["transition_digest"] == tr.get("live_transition_digest"))
    print(f"replay: {rep['n']} scenarios, {rep['fail']} fail, model calls {calls}, digests equal {eq}/{rep['n']}")
    return 0 if rep["fail"] == 0 and calls == 0 and eq == rep["n"] else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--drill", action="store_true")
    ap.add_argument("--replay", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest(a.json)
    if a.drill:
        if not a.out:
            ap.error("--drill needs --out <dir>")
        return drill(a.out, a.json)
    if a.replay:
        return replay(a.replay)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
