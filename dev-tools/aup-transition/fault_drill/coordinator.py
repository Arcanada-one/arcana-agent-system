"""AUP-MIG-014 `fault0` — the simulated MIG-016 cutover coordinator (system under test).

A crash-safe state machine over `QUIESCING → FENCED → FINAL_SYNC → VALIDATED → WRITE_COMMITTED →
HOSTS_ACTIVATING → OBSERVING → COMPLETE` with `PAUSED_SAFE` for unsafe uncertainty and a controlled
`ABORTED` that is only reachable before `WRITE_COMMITTED`. Every durable record is keyed by
(migration_id, source_set_epoch, target_writer_epoch).

Each transition runs the same four-phase protocol, and a fault can hit any phase boundary:

    before_observation → [observation: durable]  → after_observation
                       → [intent: durable] → [effect: external, keyed] → after_effect
                       → [checkpoint: durable] → after_checkpoint

Resume rebuilds everything from the journal: an observation already on disk is reused (no model
call), an intent without a checkpoint is reconciled through a readback of the effect ledger (never
re-issued blind), and a checkpointed transition is never re-run. Repeated resume is a no-op.

`mutations` switches OFF one protective rule at a time; they exist only so the independent oracle
can be shown to kill each of them (`fault_drill.py --selftest`). A coordinator with an empty
mutation set is the reference behaviour.

stdlib only; no real host, service or process is touched.
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict, FrozenSet, List, Optional

from world import (ABORTED, HOSTS, INIT, LEASE_TTL, PAUSED_SAFE, STATES, STEP_TICKS, Crash, World, canonical)

MUTATIONS = {
    "M01_reissue_effect_on_resume": "resume re-issues an intent's effect without a readback (effect counter can reach 2)",
    "M02_abort_after_commit": "controlled abort accepted after WRITE_COMMITTED",
    "M03_stop_foreign_lanes": "QUIESCING force-stops foreign / unknown lanes",
    "M04_authority_accepts_stale_epoch": "authority accepts writes and acks carrying an old writer epoch",
    "M05_rollback_on_corrupt_known_good": "rollback proceeds although the known-good generation digest does not verify",
    "M06_break_glass_never_expires": "break-glass accepted after its expiry (and without one)",
    "M07_rollback_restores_legacy_hooks": "rollback re-installs the legacy hooks instead of the last-good generation",
    "M08_resume_revoked_run": "a stale checkpoint resumes a run whose authorization was revoked",
    "M09_repeat_unknown_effect": "an UNKNOWN effect outcome is retried immediately (second application)",
    "M10_double_transition_on_resume": "resume re-applies the last checkpointed transition (state advances twice)",
    "M11_replay_calls_model": "replay ignores the saved observations and calls the model again",
    "M12_ignore_lease_expiry": "effects under the fence are issued without checking the lease token",
    "M13_ignore_source_set_epoch_change": "VALIDATED / WRITE_COMMITTED do not compare the live SourceSetEpoch with the keyed one",
    "M14_unkeyed_transition": "durable transition records omit the target writer epoch",
    "M15_drain_unknown_proceeds": "QUIESCING proceeds to FENCED although a host's lanes could not be classified (drain UNKNOWN)",
    "M16_pause_without_reason": "PAUSED_SAFE is entered without a durable reason",
}

NEEDS = {
    "QUIESCING": ["muneral"],
    "FENCED": ["muneral"],
    "FINAL_SYNC": ["scrutator"],
    "VALIDATED": ["kc2"],
    "WRITE_COMMITTED": ["muneral"],
    "HOSTS_ACTIVATING": ["muneral"],
    "OBSERVING": [],
    "COMPLETE": ["muneral"],
}
FENCE_STATES = {"FINAL_SYNC", "VALIDATED", "WRITE_COMMITTED"}  # lease must be valid for these effects
MAX_ATTEMPTS = 3


class Observer:
    """The 'model' side: produces an observation for a transition. Live mode counts a model call;
    replay mode serves the saved observation and refuses to call the model."""

    def __init__(self, world: World, saved: Optional[Dict[str, Any]] = None, mode: str = "live") -> None:
        self.world = world
        self.saved = saved if saved is not None else {}
        self.mode = mode

    def observe(self, key: str, state: str, context: Dict[str, Any], force_model: bool = False) -> Dict[str, Any]:
        if self.mode == "replay" and not force_model:
            if key not in self.saved:
                raise KeyError(f"replay: no saved observation for {key}")
            self.world.event("observation_replayed", key=key, state=state)
            return self.saved[key]
        self.world.model_calls += 1
        obs = {"key": key, "state": state, "verdict": "ok", "context_digest": hashlib.sha256(canonical(context).encode()).hexdigest()[:16]}
        if state == "QUIESCING":
            obs["lanes"] = context.get("lane_classes", {})
        self.saved[key] = obs
        self.world.event("observation_model_call", key=key, state=state)
        return obs


class Journal:
    """Durable, append-only. Survives a Crash because the scenario owns it, not the coordinator."""

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
    """Break-glass authorization fixture (MIG-004 shape): human issuer, incident id, exact
    host/action/path, expiry, separate config home."""

    REQUIRED = ("issuer", "issuer_kind", "incident_id", "host", "action", "path", "expires_at", "config_home")

    def __init__(self, **fields: Any) -> None:
        self.fields = fields

    def validate(self, now: int, mutations: FrozenSet[str]) -> Dict[str, Any]:
        f = self.fields
        problems = []
        for k in self.REQUIRED:
            if k not in f or f[k] in (None, ""):
                problems.append(f"missing:{k}")
        if f.get("issuer_kind") not in (None, "human"):
            problems.append("issuer_not_human")
        if "expires_at" in f and f.get("expires_at") is not None:
            if f["expires_at"] <= now and "M06_break_glass_never_expires" not in mutations:
                problems.append("expired")
        elif "M06_break_glass_never_expires" in mutations:
            problems = [p for p in problems if p != "missing:expires_at"]
        if f.get("config_home") and f["config_home"] == f.get("default_config_home"):
            problems.append("config_home_not_separate")
        return {"accepted": not problems, "problems": problems, "checked_at": now}


class Coordinator:
    def __init__(self, world: World, journal: Journal, observer: Observer, migration_id: str,
                 mutations: FrozenSet[str] = frozenset(), fault_hook: Optional[Callable[[str, str], None]] = None,
                 replay_mode: bool = False) -> None:
        self.world = world
        self.journal = journal
        self.observer = observer
        self.migration_id = migration_id
        self.mutations = mutations
        self.fault_hook = fault_hook or (lambda point, state: None)
        self.replay_mode = replay_mode
        self.keyed_epoch = world.source_set_epoch
        self.state = INIT
        self.paused_reason: Optional[str] = None
        self.lease_token: Optional[str] = None
        self.target_writer_epoch: int = world.authority.current_epoch + 1
        self.findings: List[str] = []
        self.break_glass_log: List[Dict[str, Any]] = []
        self.resume_count = 0
        self._recover()

    # ----- durable helpers -----
    def keys(self) -> Dict[str, Any]:
        k = {"migration_id": self.migration_id, "source_set_epoch": self.keyed_epoch, "target_writer_epoch": self.target_writer_epoch}
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
        self._durable("transition", state_from=self.state, state_to=PAUSED_SAFE, reason=None if "M16_pause_without_reason" in self.mutations else reason, paused_at_state=self.state)
        self.paused_reason = reason
        self.paused_at = self.state
        self.state = PAUSED_SAFE
        self.world.event("paused_safe", reason=reason, at_state=self.paused_at)

    def _recover(self) -> None:
        """Rebuild in-memory state from the journal (called on construction = process start)."""
        self.paused_at = None
        for r in self.journal.records:
            if r["kind"] == "transition":
                self.state = r["state_to"]
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
        if not self.journal.records:
            self._durable("meta", note="migration opened")

    # ----- public protocol -----
    def resume(self) -> Dict[str, Any]:
        """Process (re)start after a crash or a pause. Idempotent: without new facts it changes
        nothing. Reconciles a dangling intent through a readback, never by blind re-issue."""
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
            if last and last["state_to"] in STATES and last["state_to"] != "COMPLETE":
                nxt = STATES[STATES.index(last["state_to"]) + 1]
                self._durable("transition", state_from=last["state_to"], state_to=nxt, reason="M10 replayed transition")
                self.state = nxt
        # a dangling intent = effect issued, no checkpoint → reconcile
        last_intent = self.journal.last("intent")
        last_cp = self.journal.last("checkpoint")
        if last_intent and (not last_cp or last_cp["seq"] < last_intent["seq"]):
            self._reconcile(last_intent)
        if self.state == PAUSED_SAFE and self.paused_reason and self._pause_cleared():
            self._durable("transition", state_from=PAUSED_SAFE, state_to=self.paused_at, reason="forward recovery: cause cleared")
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
        return False  # AUTH_REVOKED, LEASE_EXPIRED, KNOWN_GOOD_CORRUPT, REVALIDATION_REQUIRED, ... need a decision, not a retry

    def _reconcile(self, intent: Dict[str, Any]) -> None:
        for key in intent["effect_keys"]:
            if "M01_reissue_effect_on_resume" in self.mutations:
                self.world.event("reconcile", key=key, method="blind_reissue")
                fn = self._effect_fn(intent["state_to"], key)
                self.world.apply_effect(key, intent["state_to"], fn, NEEDS[intent["state_to"]])
                continue
            rb = self.world.readback(key)
            self._durable("reconciliation", state=intent["state_to"], effect_key=key, readback=rb,
                          terminal="applied" if rb == "applied" else ("not_applied" if rb == "not_applied" else "unknown"), reissued=False)
            self.world.event("reconcile", key=key, method="readback", result=rb)
            if rb is None:
                self._pause("UNKNOWN_EFFECT_UNRECONCILED")
                return
            if rb == "not_applied":  # never applied server-side: the (first) application happens now
                r = self._issue(intent["state_to"], key)
                if r == "unknown":
                    self._durable("reconciliation", state=intent["state_to"], effect_key=key, readback=None, terminal="unknown", reissued=False)
                    self._pause("UNKNOWN_EFFECT_UNRECONCILED")
                    return
                if r.startswith("rejected"):
                    self._pause(self._reason_for(r, intent["state_to"]))
                    return
        if all(self.world.readback(k) == "applied" for k in intent["effect_keys"]):
            self._checkpoint(intent["state_to"], intent["effect_keys"], via="reconciliation")

    def step(self) -> str:
        """Perform the next transition. Returns the resulting state."""
        if self.state in (PAUSED_SAFE, ABORTED, "COMPLETE"):
            return self.state
        nxt = STATES[0] if self.state == INIT else STATES[STATES.index(self.state) + 1]
        self.world.clock.advance(STEP_TICKS)
        self.fault_hook("before_observation", nxt)
        # integrity of the known-good generation is checked before every transition
        if not self.world.known_good_ok():
            self._pause("KNOWN_GOOD_CORRUPT")
            return self.state
        # observation (durable; reused on resume)
        obs_key = f"{self.migration_id}:{nxt}:obs"
        existing = next((r for r in self.journal.records if r["kind"] == "observation" and r["key"] == obs_key), None)
        if existing is None or "M11_replay_calls_model" in self.mutations:
            ctx = self._context(nxt)
            obs = self.observer.observe(obs_key, nxt, ctx, force_model="M11_replay_calls_model" in self.mutations)
            self._durable("observation", key=obs_key, state=nxt, observation=obs)
        else:
            obs = existing["observation"]
            self.world.event("observation_reused", key=obs_key, state=nxt)
        self.fault_hook("after_observation", nxt)
        # guards that decide PAUSED_SAFE before any effect
        guard = self._guard(nxt, obs)
        if guard:
            self._pause(guard)
            return self.state
        # intent (durable, write-ahead) then effects
        effect_keys = self._effect_keys(nxt)
        self._durable("intent", state_to=nxt, effect_keys=effect_keys)
        results: Dict[str, str] = {}
        for key in effect_keys:  # every key is issued (independent, idempotent effects: partial activation is allowed)
            r = self._issue(nxt, key)
            if r == "unknown" and "M09_repeat_unknown_effect" in self.mutations:
                r = self._issue(nxt, key)
            results[key] = r
        for key, r in results.items():
            if r == "unknown":
                self._durable("reconciliation", state=nxt, effect_key=key, readback=None, terminal="unknown", reissued=False)
                self._pause("UNKNOWN_EFFECT_UNRECONCILED")
                return self.state
        for key, r in results.items():
            if r.startswith("rejected"):
                self._pause(self._reason_for(r, nxt))
                return self.state
        self.fault_hook("after_effect", nxt)
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
        """Controlled abort: release lease + fence, leave legacy exactly as it is (owner-controlled,
        no hook restoration). Refused at or after WRITE_COMMITTED."""
        at = self.paused_at if self.state == PAUSED_SAFE else self.state
        committed = at in STATES and STATES.index(at) >= STATES.index("WRITE_COMMITTED")
        if committed and "M02_abort_after_commit" not in self.mutations:
            self.world.event("abort_refused", at_state=at, reason="past_write_committed")
            return {"accepted": False, "state": self.state, "why": "past WRITE_COMMITTED: only forward recovery or PAUSED_SAFE"}
        if self.state in (ABORTED, "COMPLETE"):
            return {"accepted": False, "state": self.state, "why": "terminal"}
        a = self.world.authority
        a.release_fence(f"{self.migration_id}:fence")
        a.release_lease(self.lease_token)
        self._durable("transition", state_from=self.state, state_to=ABORTED, reason=reason, aborted_at_state=at)
        self.world.event("aborted", at_state=at, reason=reason)
        self.state = ABORTED
        return {"accepted": True, "state": self.state}

    def rollback_to_known_good(self) -> Dict[str, Any]:
        """Post-commit recovery to the last-good generation of the NEW contour (code/config/schema/
        policy pins). Never to legacy hooks. Refused when the known-good digest does not verify."""
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
        self._durable("rollback", verdict="applied", pins=dict(self.world.known_good), known_good_digest=self.world.known_good_digest)
        self.world.event("rollback_applied", pins=list(self.world.known_good))
        return {"accepted": True, "state": self.state}

    def use_break_glass(self, bg: BreakGlass) -> Dict[str, Any]:
        v = bg.validate(self.world.clock.now(), self.mutations)
        rec = {"fields": {k: bg.fields.get(k) for k in BreakGlass.REQUIRED}, **v}
        self.break_glass_log.append(rec)
        self.world.event("break_glass", accepted=v["accepted"], problems=v["problems"], expires_at=bg.fields.get("expires_at"))
        return rec

    # ----- internals -----
    def _context(self, state: str) -> Dict[str, Any]:
        if state == "QUIESCING":
            classes: Dict[str, str] = {}
            for l in self.world.lanes:
                classes[l.lane_id] = "unknown-foreign" if not self.world.hosts[l.host].alive else l.owner_class
            return {"lane_classes": classes}
        return {"state": state, "epoch": self.world.source_set_epoch}

    def _guard(self, nxt: str, obs: Dict[str, Any]) -> Optional[str]:
        w = self.world
        if nxt == "QUIESCING":
            unknown = [k for k, v in obs.get("lanes", {}).items() if v == "unknown-foreign"]
            dead_hosts = [h for h, x in w.hosts.items() if not x.alive]
            if dead_hosts and "M15_drain_unknown_proceeds" not in self.mutations:
                return "DRAIN_UNKNOWN"
        if nxt in ("VALIDATED", "WRITE_COMMITTED") and w.source_set_epoch != self.keyed_epoch and "M13_ignore_source_set_epoch_change" not in self.mutations:
            return "REVALIDATION_REQUIRED"
        if nxt in FENCE_STATES and "M12_ignore_lease_expiry" not in self.mutations:
            chk = w.authority.check_token(self.lease_token)
            if chk != "valid":
                return "LEASE_EXPIRED" if chk == "expired" else f"LEASE_{chk.upper()}"
        if nxt in ("OBSERVING", "COMPLETE"):
            dead = [h for h, x in w.hosts.items() if not x.alive]
            if dead:
                return "HOST_LOST_IN_OBSERVATION"
        # HOSTS_ACTIVATING has no guard: each host ack is its own idempotent effect; a missing host
        # is a rejected effect (partial activation → PAUSED_SAFE with the live hosts already acked)
        if nxt in ("HOSTS_ACTIVATING", "OBSERVING", "COMPLETE") and w.source_set_epoch != self.keyed_epoch:
            f = "post_commit_source_set_epoch_drift: recorded for post-cutover reconciliation, no rollback"
            if f not in self.findings:
                self.findings.append(f)
                w.event("finding", text=f)
        return None

    def _effect_keys(self, state: str) -> List[str]:
        m, e = self.migration_id, self.target_writer_epoch
        if state == "HOSTS_ACTIVATING":
            return [f"{m}:{e}:ack:{h}" for h in HOSTS]
        return [f"{m}:{e}:{state}"]

    def _effect_fn(self, state: str, key: str) -> Callable[[], str]:
        w, a, m = self.world, self.world.authority, self.migration_id
        stale = "M04_authority_accepts_stale_epoch" in self.mutations
        if state == "QUIESCING":
            def fn() -> str:
                for l in w.lanes:
                    if l.stopped:
                        continue
                    if l.owner_class == "migration-owned" and w.hosts[l.host].alive:
                        w.stop_lane(l, by="coordinator")
                    elif "M03_stop_foreign_lanes" in self.mutations:
                        w.stop_lane(l, by="coordinator")
                    else:
                        w.handoff_lane(l)
                return "applied"
            return fn
        if state == "FENCED":
            def fn() -> str:
                a.set_fence(f"{m}:fence")
                if self.lease_token is None or a.check_token(self.lease_token) != "valid":
                    lease = a.acquire_lease(holder=m, ttl=LEASE_TTL)
                    self.lease_token = lease.token
                    self.target_writer_epoch = lease.epoch
                    self._durable("lease", lease_id=lease.token, epoch=lease.epoch, expires_at=lease.expires_at, ttl=LEASE_TTL)
                    self._durable("fence", key=f"{m}:fence", active=True, lease_id=lease.token)
                return "applied"
            return fn
        if state == "FINAL_SYNC":
            return lambda: "applied"  # final delta + Scrutator ack (service availability is checked by the ledger)
        if state == "VALIDATED":
            return lambda: "applied"  # KC2 verdict against the keyed SourceSetEpoch
        if state == "WRITE_COMMITTED":
            return lambda: a.cas_commit(self.lease_token, expected_epoch=self.target_writer_epoch - 1, new_epoch=self.target_writer_epoch, accept_stale=stale)
        if state == "HOSTS_ACTIVATING":
            host = key.rsplit(":", 1)[1]
            def fn() -> str:
                if not w.hosts[host].alive:
                    return "rejected:host_unreachable"
                return a.host_ack(host, self.target_writer_epoch, m, accept_stale=stale)
            return fn
        if state == "OBSERVING":
            return lambda: "applied"  # observation window opened (ledger write)
        if state == "COMPLETE":
            def fn() -> str:
                w.legacy_policy = "read-only"
                a.release_fence(f"{m}:fence")
                a.release_lease(self.lease_token)
                self._durable("fence", key=f"{m}:fence", active=False, lease_id=self.lease_token)
                return "applied"
            return fn
        raise ValueError(state)

    def _issue(self, state: str, key: str) -> str:
        w = self.world
        needs = NEEDS[state]
        last = "rejected:unissued"
        for attempt in range(MAX_ATTEMPTS):
            last = w.apply_effect(key, state, self._effect_fn(state, key), needs, bypass_auth="M08_resume_revoked_run" in self.mutations)
            if last == "applied" or last == "unknown" or last.startswith("rejected:auth") or last.startswith("rejected:token") or last.startswith("rejected:epoch") or last.startswith("rejected:stale") or last.startswith("rejected:host"):
                return last
            w.clock.advance(1)
        return last

    def _reason_for(self, result: str, state: str) -> str:
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
        self._durable("transition", state_from=self.state if self.state != PAUSED_SAFE else self.paused_at, state_to=nxt, via=via)
        self.world.event("transition", state_from=self.state, state_to=nxt, via=via)
        self.state = nxt
        self.paused_reason = None
