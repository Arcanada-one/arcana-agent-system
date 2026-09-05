"""AUP-MIG-014 `fault0` — the simulated environment the cutover coordinator acts on.

Nothing here touches a real host, service, tmux server or file outside the caller's output
directory. The world is deterministic: a tick clock, an append-only event trace, an effect ledger
keyed by idempotency key (the "generic effect counter"), a server-side writer authority that owns
the lease / fencing token / writer epoch and rejects stale epochs, two hosts (mac, devs) with an
idempotent activation ledger, and a lane inventory with owner classes (only migration-owned lanes
may ever be stopped).

stdlib only.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

STATES = [
    "QUIESCING",
    "FENCED",
    "FINAL_SYNC",
    "VALIDATED",
    "WRITE_COMMITTED",
    "HOSTS_ACTIVATING",
    "OBSERVING",
    "COMPLETE",
]
PAUSED_SAFE = "PAUSED_SAFE"
ABORTED = "ABORTED"
INIT = "INIT"
HOSTS = ["mac", "devs"]
SERVICES = ["muneral", "kc2", "scrutator"]
LEASE_TTL = 100
STEP_TICKS = 5


class Crash(Exception):
    """Simulated process death at an injection point. The world (durable side) survives; the
    coordinator object does not."""


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


class Clock:
    def __init__(self) -> None:
        self.t = 0

    def now(self) -> int:
        return self.t

    def advance(self, dt: int) -> None:
        self.t += dt


@dataclass
class Lane:
    lane_id: str
    host: str
    owner_class: str  # migration-owned | foreign-confirmed | unknown-foreign | already-stopped
    legacy_dependent: bool = True
    stopped: bool = False
    handoff_sent: bool = False


@dataclass
class Host:
    name: str
    alive: bool = True
    acked_epoch: Optional[int] = None
    ack_migration: Optional[str] = None


@dataclass
class Lease:
    token: str
    epoch: int
    holder: str
    issued_at: int
    expires_at: int
    released: bool = False


class Authority:
    """Server-side writer authority (the Muneral-side single-writer switch). Owns the writer epoch,
    hands out one lease / fencing token at a time and rejects every write carrying a stale epoch or
    an expired / unknown token. Every decision is logged (this log is oracle input)."""

    def __init__(self, world: "World") -> None:
        self.world = world
        self.current_epoch = 7  # the legacy writer's epoch at the start of the drill
        self.lease: Optional[Lease] = None
        self.fence_active = False
        self.fence_key: Optional[str] = None
        self.log: List[Dict[str, Any]] = []
        self._seq = 0

    def _rec(self, op: str, **kw: Any) -> Dict[str, Any]:
        self._seq += 1
        r = {"seq": self._seq, "at": self.world.clock.now(), "op": op}
        r.update(kw)
        self.log.append(r)
        return r

    def set_fence(self, key: str) -> str:
        if self.fence_active and self.fence_key == key:
            self._rec("fence_set", key=key, result="idempotent")
            return "applied"
        self.fence_active = True
        self.fence_key = key
        self._rec("fence_set", key=key, result="applied")
        return "applied"

    def release_fence(self, key: str) -> str:
        self.fence_active = False
        self._rec("fence_release", key=key, result="applied")
        return "applied"

    def acquire_lease(self, holder: str, ttl: int) -> Lease:
        now = self.world.clock.now()
        if self.lease and not self.lease.released and self.lease.expires_at > now and self.lease.holder != holder:
            self._rec("lease_acquire", holder=holder, result="rejected", reason="held_by_other")
            raise PermissionError("lease held by another holder")
        epoch = self.current_epoch + 1
        token = f"lease-e{epoch}-t{now}"  # simulated fencing token: low-entropy by design (secret scanners flag hex forms in receipts)
        self.lease = Lease(token=token, epoch=epoch, holder=holder, issued_at=now, expires_at=now + ttl)
        self._rec("lease_acquire", holder=holder, result="applied", epoch=epoch, lease_id=token, expires_at=now + ttl)
        return self.lease

    def check_token(self, token: Optional[str]) -> str:
        now = self.world.clock.now()
        if not self.lease or token != self.lease.token:
            self._rec("lease_check", lease_id=token, result="unknown_token")
            return "unknown_token"
        if self.lease.released:
            self._rec("lease_check", lease_id=token, result="released")
            return "released"
        if self.lease.expires_at <= now:
            self._rec("lease_check", lease_id=token, result="expired", expires_at=self.lease.expires_at)
            return "expired"
        self._rec("lease_check", lease_id=token, result="valid")
        return "valid"

    def release_lease(self, token: Optional[str]) -> str:
        if self.lease and self.lease.token == token:
            self.lease.released = True
            self._rec("lease_release", lease_id=token, result="applied")
            return "applied"
        self._rec("lease_release", lease_id=token, result="rejected")
        return "rejected"

    def cas_commit(self, token: Optional[str], expected_epoch: int, new_epoch: int, accept_stale: bool = False) -> str:
        """Compare-and-swap of the writer epoch under the fencing token. `accept_stale` exists only
        so a mutant can model a broken authority; the real rule rejects."""
        chk = self.check_token(token)
        if chk != "valid" and not accept_stale:
            self._rec("cas_commit", result="rejected", reason=f"token_{chk}", expected=expected_epoch, new=new_epoch)
            return "rejected:token_" + chk
        if self.current_epoch != expected_epoch and not accept_stale:
            self._rec("cas_commit", result="rejected", reason="epoch_mismatch", expected=expected_epoch, current=self.current_epoch)
            return "rejected:epoch_mismatch"
        if self.current_epoch == new_epoch:
            self._rec("cas_commit", result="idempotent", epoch=new_epoch)
            return "applied"
        self.current_epoch = new_epoch
        self._rec("cas_commit", result="applied", epoch=new_epoch)
        return "applied"

    def writer_write(self, writer_epoch: int, host: str, accept_stale: bool = False) -> str:
        """A write attempted by some writer (e.g. the old writer on a host that missed the
        activation). The authority must reject any epoch below the committed one."""
        if writer_epoch < self.current_epoch and not accept_stale:
            self._rec("writer_write", host=host, writer_epoch=writer_epoch, current_epoch=self.current_epoch, result="rejected", reason="stale_epoch")
            return "rejected:stale_epoch"
        self._rec("writer_write", host=host, writer_epoch=writer_epoch, current_epoch=self.current_epoch, result="accepted")
        return "accepted"

    def host_ack(self, host: str, epoch: int, migration_id: str, accept_stale: bool = False) -> str:
        h = self.world.hosts[host]
        if epoch < self.current_epoch and not accept_stale:
            self._rec("host_ack", host=host, epoch=epoch, result="rejected", reason="stale_epoch")
            return "rejected:stale_epoch"
        if h.acked_epoch == epoch and h.ack_migration == migration_id:
            self._rec("host_ack", host=host, epoch=epoch, result="idempotent")
            return "applied"
        h.acked_epoch = epoch
        h.ack_migration = migration_id
        self._rec("host_ack", host=host, epoch=epoch, result="applied")
        return "applied"


class World:
    def __init__(self, source_set_epoch: str = "sse-538d2e76") -> None:
        self.clock = Clock()
        self.services: Dict[str, bool] = {s: True for s in SERVICES}
        self.network = True
        self.auth_valid = True
        self.source_set_epoch = source_set_epoch
        self.hosts: Dict[str, Host] = {h: Host(h) for h in HOSTS}
        self.lanes: List[Lane] = [
            Lane("mac:aup-orchestrator", "mac", "migration-owned"),
            Lane("devs:aup-mig014", "devs", "migration-owned"),
            Lane("devs:aup-graph", "devs", "migration-owned"),
            Lane("mac:fleet-ops-1", "mac", "foreign-confirmed"),
            Lane("devs:fleet-anchor", "devs", "foreign-confirmed"),
            Lane("devs:unnamed-3", "devs", "unknown-foreign"),
            Lane("mac:old-session", "mac", "already-stopped", stopped=True),
        ]
        self.known_good: Dict[str, str] = {
            "code": "sha256:c0de" + "0" * 60,
            "config": "sha256:c0f1" + "0" * 60,
            "schema": "sha256:5c4e" + "0" * 60,
            "policy": "sha256:9011" + "0" * 60,
        }
        self.known_good_digest = digest(self.known_good)
        self.active_generation: Dict[str, str] = dict(self.known_good)
        self.legacy_hooks_restored = False
        self.legacy_policy = "owner-controlled-writes"
        self.effect_ledger: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
        self.model_calls = 0
        self.authority = Authority(self)
        self._seq = 0

    # ----- trace -----
    def event(self, kind: str, **kw: Any) -> Dict[str, Any]:
        self._seq += 1
        e = {"seq": self._seq, "at": self.clock.now(), "kind": kind}
        e.update(kw)
        self.events.append(e)
        return e

    # ----- effects (idempotency key + counter) -----
    def apply_effect(self, key: str, kind: str, fn: Callable[[], str], needs: Optional[List[str]] = None, bypass_auth: bool = False) -> str:
        """Issue an external effect. Returns 'applied' | 'rejected:<reason>' | 'unknown'.

        The counter in the ledger counts *issues that reached the server*. A service outage
        rejects before anything is applied (count unchanged). A network loss lets the request
        reach the server (count +1, effect applied) but loses the answer → 'unknown'. Auth
        revocation rejects at the door. The coordinator's job is to never issue a second
        application of the same key."""
        needs = needs or []
        rec = self.effect_ledger.setdefault(key, {"key": key, "kind": kind, "count": 0, "attempts": 0, "results": []})
        rec["attempts"] += 1
        if not self.auth_valid and not bypass_auth:
            rec["results"].append("rejected:auth_revoked")
            self.event("effect", key=key, effect_kind=kind, result="rejected:auth_revoked")
            return "rejected:auth_revoked"
        for s in needs:
            if not self.services.get(s, True):
                rec["results"].append(f"rejected:unavailable:{s}")
                self.event("effect", key=key, effect_kind=kind, result=f"rejected:unavailable:{s}")
                return f"rejected:unavailable:{s}"
        if rec["count"] >= 1 and rec["results"] and rec["results"][-1] in ("applied", "unknown"):
            # a second application of an already-applied key: counted, and visible to the oracle
            pass
        result = fn()
        if result == "applied":
            rec["count"] += 1  # the counter counts server-side applications, not attempts
        if result == "applied" and not self.network:
            rec["results"].append("unknown")
            self.event("effect", key=key, effect_kind=kind, result="unknown", server_side="applied")
            return "unknown"
        rec["results"].append(result)
        self.event("effect", key=key, effect_kind=kind, result=result)
        return result

    def readback(self, key: str) -> Optional[str]:
        """Reconciliation read of the ledger. Needs the network; returns None when unreadable."""
        if not self.network:
            self.event("readback", key=key, result="unreadable")
            return None
        rec = self.effect_ledger.get(key)
        applied = bool(rec and rec["count"] >= 1 and any(r in ("applied", "unknown") for r in rec["results"]))
        self.event("readback", key=key, result="applied" if applied else "not_applied")
        return "applied" if applied else "not_applied"

    # ----- integrity of the known-good generation -----
    def known_good_ok(self) -> bool:
        return digest(self.known_good) == self.known_good_digest

    def corrupt_known_good(self) -> None:
        self.known_good["policy"] = "sha256:dead" + "0" * 60

    # ----- lanes -----
    def stop_lane(self, lane: Lane, by: str) -> str:
        lane.stopped = True
        self.event("lane_stop", lane=lane.lane_id, owner_class=lane.owner_class, by=by)
        return "applied"

    def handoff_lane(self, lane: Lane) -> None:
        lane.handoff_sent = True
        self.event("lane_handoff", lane=lane.lane_id, owner_class=lane.owner_class)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "clock": self.clock.now(),
            "services": dict(self.services),
            "network": self.network,
            "auth_valid": self.auth_valid,
            "source_set_epoch": self.source_set_epoch,
            "hosts": {h: {"alive": x.alive, "acked_epoch": x.acked_epoch} for h, x in self.hosts.items()},
            "lanes": [{"id": l.lane_id, "owner_class": l.owner_class, "stopped": l.stopped, "handoff_sent": l.handoff_sent} for l in self.lanes],
            "known_good_ok": self.known_good_ok(),
            "active_generation": dict(self.active_generation),
            "legacy_hooks_restored": self.legacy_hooks_restored,
            "legacy_policy": self.legacy_policy,
            "writer_epoch": self.authority.current_epoch,
            "fence_active": self.authority.fence_active,
            "model_calls": self.model_calls,
        }
