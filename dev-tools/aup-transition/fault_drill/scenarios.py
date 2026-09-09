"""AUP-MIG-014 `fault0` — fault matrix, scenario runner, expectations, replay.

A scenario = (fault, target state, injection point). The runner builds a fresh world + journal,
runs the coordinator with the fault hook armed, catches a simulated Crash, resumes TWICE (the
second resume must change nothing), clears clearable faults (service / network / host return),
resumes again and runs to a terminal state. It then exercises the controlled-abort clause, the
rollback drill, the stale-epoch writer and the break-glass fixture where the scenario asks for
them, freezes the trace and hands it to the independent oracle.

Expectations (`EXPECT`) are the spec's acceptance table for the terminal state; they are checked
in addition to the oracle's invariants and reported separately so a wrong expectation and a wrong
invariant never hide each other.

stdlib only.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from coordinator import BreakGlass, Coordinator, Journal, Observer
from world import ABORTED, HOSTS, LEASE_TTL, PAUSED_SAFE, STATES, World, canonical

CRASH_POINTS = ["before_observation", "after_observation", "after_effect", "after_checkpoint"]
FAULTS = [
    "crash",
    "lease_expiry",
    "auth_revoke",
    "corrupt_config",
    "muneral_unavailable",
    "kc2_unavailable",
    "scrutator_unavailable",
    "network_loss",
    "host_loss_mac",
    "host_loss_devs",
    "source_set_epoch_change",
    "abort_request",
]
CLEARABLE = {"muneral_unavailable", "kc2_unavailable", "scrutator_unavailable", "network_loss", "host_loss_mac", "host_loss_devs"}
NEEDS_SERVICE = {
    "muneral": {"QUIESCING", "FENCED", "WRITE_COMMITTED", "HOSTS_ACTIVATING", "COMPLETE"},
    "kc2": {"VALIDATED"},
    "scrutator": {"FINAL_SYNC"},
}
POST_COMMIT = {"HOSTS_ACTIVATING", "OBSERVING", "COMPLETE"}
COMMIT_IDX = STATES.index("WRITE_COMMITTED")


def expectation(fault: str, state: str) -> Dict[str, Any]:
    """Expected terminal outcome of the reference coordinator for (fault, state)."""
    idx = STATES.index(state)
    pre_commit = idx <= COMMIT_IDX  # the durable state while entering S is its predecessor
    if fault == "crash":
        return {"final": "COMPLETE", "paused_first": False, "effect_max": 1, "model_calls_max_per_key": 1}
    if fault == "lease_expiry":
        if state in ("FINAL_SYNC", "VALIDATED", "WRITE_COMMITTED"):
            return {"final": ABORTED, "reason_first": "LEASE_EXPIRED", "paused_first": True, "abort_allowed": True, "fence_released": True}
        return {"final": "COMPLETE", "paused_first": False}
    if fault == "auth_revoke":
        if pre_commit:
            return {"final": ABORTED, "reason_first": "AUTH_REVOKED", "paused_first": True, "abort_allowed": True, "resume_changes_nothing": True}
        return {"final": PAUSED_SAFE, "reason": "AUTH_REVOKED", "abort_allowed": False, "resume_changes_nothing": True}
    if fault == "corrupt_config":
        return {"final": PAUSED_SAFE, "reason": "KNOWN_GOOD_CORRUPT", "rollback_refused": True}
    if fault.endswith("_unavailable"):
        svc = fault.split("_")[0]
        hits = any(STATES.index(s) >= idx for s in NEEDS_SERVICE[svc])  # the outage persists until the first pause
        return {"final": "COMPLETE", "paused_first": hits, "reason_first": f"SERVICE_UNAVAILABLE:{svc}" if hits else None}
    if fault == "network_loss":
        return {"final": "COMPLETE", "paused_first": True, "reason_first": "UNKNOWN_EFFECT_UNRECONCILED", "effect_max": 1, "reconciled": True}
    if fault.startswith("host_loss"):
        if state == "QUIESCING":
            return {"final": "COMPLETE", "paused_first": True, "reason_first": "DRAIN_UNKNOWN", "stale_writer_rejected": True}
        if idx <= STATES.index("HOSTS_ACTIVATING"):  # the loss persists until activation needs the host
            return {"final": "COMPLETE", "paused_first": True, "reason_first": "HOST_UNREACHABLE", "stale_writer_rejected": True, "partial_ack": True, "effect_max": 1}
        return {"final": "COMPLETE", "paused_first": True, "reason_first": "HOST_LOST_IN_OBSERVATION", "stale_writer_rejected": True}
    if fault == "source_set_epoch_change":
        if idx <= COMMIT_IDX:
            return {"final": ABORTED, "reason_first": "REVALIDATION_REQUIRED", "paused_first": True, "abort_allowed": True}
        return {"final": "COMPLETE", "finding": "post_commit_source_set_epoch_drift"}
    if fault == "abort_request":
        if pre_commit:
            return {"final": ABORTED, "fence_released": True, "paused_first": False}
        return {"final": "COMPLETE", "abort_refused": True, "paused_first": False}
    raise ValueError(fault)


def matrix() -> List[Tuple[str, str, Optional[str]]]:
    out: List[Tuple[str, str, Optional[str]]] = []
    for f in FAULTS:
        for s in STATES:
            if f == "crash":
                for p in CRASH_POINTS:
                    out.append((f, s, p))
            else:
                out.append((f, s, None))
    return out


def scenario_id(fault: str, state: str, point: Optional[str]) -> str:
    return f"{fault}@{state}" + (f"#{point}" if point else "")


class Scenario:
    def __init__(self, fault: str, state: str, point: Optional[str], mutations: FrozenSet[str] = frozenset(),
                 mode: str = "live", saved_obs: Optional[Dict[str, Any]] = None) -> None:
        self.fault, self.state, self.point = fault, state, point
        self.mutations = mutations
        self.mode = mode
        self.id = scenario_id(fault, state, point)
        self.world = World()
        self.journal = Journal()
        self.observer = Observer(self.world, saved=dict(saved_obs) if saved_obs else None, mode=mode)
        self.migration_id = "mig-016-drill"
        self.armed = True
        self.notes: List[str] = []
        self.paused_reasons: List[str] = []
        self.abort_result: Optional[Dict[str, Any]] = None
        self.rollback_result: Optional[Dict[str, Any]] = None
        self.stale_writer: Optional[str] = None
        self.resume_results: List[Dict[str, Any]] = []
        self.break_glass: List[Dict[str, Any]] = []

    # ----- fault injection -----
    def hook(self, point: str, state: str) -> None:
        if not self.armed or state != self.state:
            return
        w = self.world
        if self.fault == "crash":
            if point != self.point:
                return
            self.armed = False
            w.event("fault_injected", fault="crash", at_state=state, point=point)
            raise CrashSignal()
        if point != "before_observation":
            return
        self.armed = False
        w.event("fault_injected", fault=self.fault, at_state=state, point=point)
        if self.fault == "lease_expiry":
            w.clock.advance(LEASE_TTL + 1)
        elif self.fault == "auth_revoke":
            w.auth_valid = False
        elif self.fault == "corrupt_config":
            w.corrupt_known_good()
        elif self.fault.endswith("_unavailable"):
            w.services[self.fault.split("_")[0]] = False
        elif self.fault == "network_loss":
            w.network = False
        elif self.fault.startswith("host_loss"):
            w.hosts[self.fault.split("_")[2]].alive = False
        elif self.fault == "source_set_epoch_change":
            w.source_set_epoch = "sse-NEWROOT"
        elif self.fault == "abort_request":
            raise AbortSignal()

    def clear_fault(self) -> None:
        w = self.world
        if self.fault not in CLEARABLE:
            return
        if self.fault.endswith("_unavailable"):
            w.services[self.fault.split("_")[0]] = True
        elif self.fault == "network_loss":
            w.network = True
        elif self.fault.startswith("host_loss"):
            w.hosts[self.fault.split("_")[2]].alive = True
        w.event("fault_cleared", fault=self.fault)

    # ----- run -----
    def new_coordinator(self) -> Coordinator:
        return Coordinator(self.world, self.journal, self.observer, self.migration_id, mutations=self.mutations,
                           fault_hook=self.hook, replay_mode=(self.mode == "replay"))

    def run(self) -> Dict[str, Any]:
        c = self.new_coordinator()
        try:
            c.run()
        except AbortSignal:
            self.abort_result = c.abort("drill: controlled abort requested")
            c.run()  # refused abort → the run continues forward
        except CrashSignal:
            self.notes.append(f"crashed at {self.point} of {self.state}")
            c = self.new_coordinator()  # process restart: rebuild from the journal
            self.resume_results.append(c.resume())
            self.resume_results.append(c.resume())  # repeated resume must change nothing
            c.run()
        if c.state == PAUSED_SAFE:
            self.paused_reasons.append(c.paused_reason or "")
        # controlled-abort clause on every pause: attempt it, the coordinator decides
        if c.state == PAUSED_SAFE and self.fault in ("lease_expiry", "auth_revoke", "source_set_epoch_change"):
            self.abort_result = c.abort("drill: abort after pause")
        # clearable faults: cause disappears, resume twice, continue
        if c.state == PAUSED_SAFE and self.fault in CLEARABLE:
            self.clear_fault()
            self.resume_results.append(c.resume())
            self.resume_results.append(c.resume())
            c.run()
            if c.state == PAUSED_SAFE:
                self.paused_reasons.append(c.paused_reason or "")
        # host loss during activation: the old writer on the returned host tries a stale write
        if self.fault.startswith("host_loss"):
            host = self.fault.split("_")[2]
            self.stale_writer = self.world.authority.writer_write(writer_epoch=c.target_writer_epoch - 1, host=host,
                                                                  accept_stale="M04_authority_accepts_stale_epoch" in self.mutations)
        # rollback drill on the corrupt fixture (post-commit states) and a positive one at OBSERVING
        if self.fault == "corrupt_config" and c.state == PAUSED_SAFE:
            self.rollback_result = c.rollback_to_known_good()
        if self.fault == "crash" and self.state == "OBSERVING" and self.point == "after_checkpoint":
            self.rollback_result = c.rollback_to_known_good()
        # break-glass fixture rides along on the auth_revoke lane (an operator opening a break-glass)
        if self.fault == "auth_revoke":
            now = self.world.clock.now()
            base = dict(issuer="operator", issuer_kind="human", incident_id="INC-2026-0905-1", host="devs", action="read", path="/home/dev/aup/drill", config_home="/home/dev/aup/bg-home", default_config_home="/home/dev/.claude")
            self.break_glass.append(c.use_break_glass(BreakGlass(**base, expires_at=now + 30)))
            self.break_glass.append(c.use_break_glass(BreakGlass(**base, expires_at=now - 1)))
            self.break_glass.append(c.use_break_glass(BreakGlass(**{k: v for k, v in base.items()})))
            self.break_glass.append(c.use_break_glass(BreakGlass(**{**base, "issuer_kind": "agent"}, expires_at=now + 30)))
            self.break_glass.append(c.use_break_glass(BreakGlass(**{**base, "config_home": "/home/dev/.claude"}, expires_at=now + 30)))
            self.world.clock.advance(31)
            self.break_glass.append(c.use_break_glass(BreakGlass(**base, expires_at=now + 30)))
        # a resume on a terminal run must change nothing either
        self.resume_results.append(c.resume())
        self.coordinator = c
        return self.trace()

    def trace(self) -> Dict[str, Any]:
        c = self.coordinator
        final = self.world.snapshot()
        final["state"] = c.state
        final["paused_reason"] = c.paused_reason
        transitions = [(r.get("state_from"), r.get("state_to")) for r in self.journal.records if r["kind"] == "transition"]
        return {
            "scenario": self.id,
            "fault": self.fault,
            "state": self.state,
            "point": self.point,
            "mode": self.mode,
            "mutations": sorted(self.mutations),
            "journal": self.journal.records,
            "events": self.world.events,
            "effect_ledger": self.world.effect_ledger,
            "authority_log": self.world.authority.log,
            "final": final,
            "transitions": transitions,
            "transition_digest": "sha256:" + hashlib.sha256(canonical(transitions).encode()).hexdigest(),
            "paused_reasons": self.paused_reasons,
            "abort_result": self.abort_result,
            "rollback_result": self.rollback_result,
            "stale_writer": self.stale_writer,
            "resume_results": self.resume_results,
            "break_glass": self.break_glass,
            "findings": c.findings,
            "notes": self.notes,
            "saved_observations": self.observer.saved,
        }


class CrashSignal(Exception):
    pass


class AbortSignal(Exception):
    pass


def check_expectation(tr: Dict[str, Any]) -> List[str]:
    """Compare a trace with the spec's expectation table. Returns mismatches."""
    exp = expectation(tr["fault"], tr["state"])
    m: List[str] = []
    final = tr["final"]["state"]
    if final != exp["final"]:
        m.append(f"final {final} != expected {exp['final']}")
    if "reason" in exp and tr["final"].get("paused_reason") != exp["reason"]:
        m.append(f"pause reason {tr['final'].get('paused_reason')} != {exp['reason']}")
    if exp.get("paused_first") and not tr["paused_reasons"]:
        m.append("expected a first PAUSED_SAFE, none recorded")
    if exp.get("paused_first") is False and tr["paused_reasons"]:
        m.append(f"unexpected pause(s) {tr['paused_reasons']}")
    if exp.get("reason_first") and (not tr["paused_reasons"] or tr["paused_reasons"][0] != exp["reason_first"]):
        m.append(f"first pause reason {tr['paused_reasons'][:1]} != {exp['reason_first']}")
    if "effect_max" in exp:
        worst = max((r["count"] for r in tr["effect_ledger"].values()), default=0)
        if worst > exp["effect_max"]:
            m.append(f"effect counter {worst} > {exp['effect_max']}")
    if exp.get("reconciled"):
        recs = [r for r in tr["journal"] if r["kind"] == "reconciliation" and r.get("terminal") in ("applied", "not_applied")]
        if not recs:
            m.append("no terminal reconciliation record")
    if exp.get("abort_allowed") is True and not (tr["abort_result"] and tr["abort_result"]["accepted"]):
        m.append("controlled abort expected to be accepted")
    if exp.get("abort_allowed") is False and tr["abort_result"] and tr["abort_result"]["accepted"]:
        m.append("controlled abort accepted after WRITE_COMMITTED")
    if exp.get("abort_refused") and not (tr["abort_result"] and not tr["abort_result"]["accepted"]):
        m.append("abort should have been refused")
    if exp.get("fence_released") and tr["final"]["fence_active"]:
        m.append("fence still active after abort")
    if exp.get("rollback_refused") and not (tr["rollback_result"] and not tr["rollback_result"]["accepted"]):
        m.append("rollback on corrupt known-good should be refused")
    if exp.get("stale_writer_rejected") and not (tr["stale_writer"] or "").startswith("rejected"):
        m.append(f"stale writer write not rejected ({tr['stale_writer']})")
    if exp.get("partial_ack"):
        hosts = tr["final"]["hosts"]
        if not all(h["acked_epoch"] == tr["final"]["writer_epoch"] for h in hosts.values()):
            m.append(f"not every host acked the committed epoch at the end: {hosts}")
    if exp.get("finding") and not any(exp["finding"] in f for f in tr["findings"]):
        m.append(f"finding {exp['finding']} not recorded")
    if exp.get("resume_changes_nothing"):
        if any(r["changed"] for r in tr["resume_results"]):
            m.append("a resume changed the state of a revoked run")
    # repeated resume never changes state twice: consecutive resumes with 'changed' both True
    rr = tr["resume_results"]
    for i in range(1, len(rr)):
        if rr[i - 1]["changed"] and rr[i]["changed"]:
            m.append("two consecutive resumes both changed the state")
    if "model_calls_max_per_key" in exp:
        calls: Dict[str, int] = {}
        for e in tr["events"]:
            if e.get("kind") == "observation_model_call":
                calls[e["key"]] = calls.get(e["key"], 0) + 1
        if calls and max(calls.values()) > exp["model_calls_max_per_key"]:
            m.append("an observation key consulted the model more than once")
    if tr["fault"] == "auth_revoke":
        bg = tr["break_glass"]
        want = [True, False, False, False, False, False]
        got = [b["accepted"] for b in bg]
        if got != want:
            m.append(f"break-glass verdicts {got} != {want}")
    return m


def run_matrix(mutations: FrozenSet[str] = frozenset(), mode: str = "live", saved: Optional[Dict[str, Dict[str, Any]]] = None,
               only: Optional[List[Tuple[str, str, Optional[str]]]] = None) -> List[Dict[str, Any]]:
    traces = []
    for (f, s, p) in (only or matrix()):
        sc = Scenario(f, s, p, mutations=mutations, mode=mode, saved_obs=(saved or {}).get(scenario_id(f, s, p)))
        try:
            tr = sc.run()
        except KeyError as e:  # replay without a saved observation
            tr = sc.trace() if hasattr(sc, "coordinator") else {"scenario": sc.id, "fault": f, "state": s, "point": p, "mode": mode,
                                                                 "journal": sc.journal.records, "events": sc.world.events, "effect_ledger": sc.world.effect_ledger,
                                                                 "authority_log": sc.world.authority.log, "final": {**sc.world.snapshot(), "state": "REPLAY_FAILED"},
                                                                 "transitions": [], "transition_digest": None, "paused_reasons": [], "abort_result": None, "rollback_result": None,
                                                                 "stale_writer": None, "resume_results": [], "break_glass": [], "findings": [], "notes": [str(e)], "saved_observations": {}}
            tr["replay_error"] = str(e)
        traces.append(tr)
    return traces
