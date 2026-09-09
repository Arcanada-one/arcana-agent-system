"""AUP-MIG-016 `coord0` — fence / lease / barrier / host-activation backends.

The coordinator never talks to a host, a service or a repository directly: it talks to the four
interfaces declared here. Exactly one implementation of each is available today — the **simulated**
one, which is the deterministic world of the MIG-014 fault drill (`tools/mig/fault_drill/world.py`).
The real backends (a GitHub push ruleset, the Muneral single-writer lease, the production barrier
document in program main, the per-host activation ledger on Mac / Arcana DEVS) are later cards under
the gates of DEC-AUP-0011 / DEC-AUP-0012; asking for one here raises `BackendNotAvailable` with the
decision id that still has to be satisfied, and never a silent fallback to the simulation.

`ProductionCutoverBarrier/v1` is declared here too, with the schema-distinctness check the spec asks
for: the production barrier and the DAT-018 `CandidateBarrierReceipt` rehearsal share no required
key, so a rehearsal receipt can never be presented where the production barrier is required.

stdlib only; nothing outside the caller's output directory is written.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_FAULT_DRILL = Path(__file__).resolve().parents[1] / "fault_drill"
if str(_FAULT_DRILL) not in sys.path:
    sys.path.insert(0, str(_FAULT_DRILL))

from world import LEASE_TTL, World  # noqa: E402  (MIG-014 simulated environment, reused as the sim backend)

SIMULATED = "simulated (tools/mig/fault_drill/world.py — no host, service, repository or process is touched)"


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


class BackendNotAvailable(RuntimeError):
    """A real backend was asked for. It does not exist yet and must not be improvised."""


# ------------------------------------------------------------------ interfaces
class FenceBackend:
    """The global legacy-write fence held from FINAL_SYNC to the CAS commit."""

    kind = "fence"

    def set_fence(self, key: str) -> str:
        raise NotImplementedError

    def release_fence(self, key: str) -> str:
        raise NotImplementedError

    def active(self) -> bool:
        raise NotImplementedError


class LeaseBackend:
    """The single writer lease / fencing token and the CAS swap of the writer epoch."""

    kind = "lease"

    def acquire(self, holder: str, ttl: int) -> Dict[str, Any]:
        raise NotImplementedError

    def check(self, token: Optional[str]) -> str:
        raise NotImplementedError

    def release(self, token: Optional[str]) -> str:
        raise NotImplementedError

    def cas_commit(self, token: Optional[str], expected_epoch: int, new_epoch: int, accept_stale: bool = False) -> str:
        raise NotImplementedError

    def current_epoch(self) -> int:
        raise NotImplementedError


class HostActivationBackend:
    """Per-host idempotent activation acks; the authority rejects an old writer epoch."""

    kind = "host_activation"

    def ack(self, host: str, epoch: int, migration_id: str, accept_stale: bool = False) -> str:
        raise NotImplementedError

    def alive(self, host: str) -> bool:
        raise NotImplementedError

    def hosts(self) -> List[str]:
        raise NotImplementedError


class BarrierStore:
    """Where the ProductionCutoverBarrier document is put once the CAS commit succeeded."""

    kind = "barrier"

    def put(self, doc: Dict[str, Any]) -> str:
        raise NotImplementedError

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


# ------------------------------------------------------------------ the production barrier
BARRIER_SCHEMA = "ProductionCutoverBarrier/v1"
CANDIDATE_SCHEMA = "CandidateBarrierReceipt"

# required keys of the production barrier (system-wide switch)
BARRIER_REQUIRED = (
    "schema",
    "migration_id",
    "source_set_epoch",
    "previous_writer_epoch",
    "target_writer_epoch",
    "scope",
    "global_fence_key",
    "fencing_token_id",
    "cas_result",
    "authorising_decisions",
    "ladder_state",
    "host_activation_ledger",
)
# required keys of the DAT-018 rehearsal receipt (bounded candidate scope), per AUP-E27 § DAT-018
CANDIDATE_REQUIRED = (
    "schema",
    "rehearsal",
    "candidate_scope",
    "bounded_paths",
    "active_generation_pointer_unchanged",
)
# the two documents share no required key except `schema`, whose value differs: a rehearsal receipt
# can never be presented where the production barrier is required, and the reverse is also true.
BARRIER_DISJOINT_PROOF = sorted(set(BARRIER_REQUIRED) & set(CANDIDATE_REQUIRED))


def validate_production_barrier(doc: Dict[str, Any], accept_candidate: bool = False) -> Dict[str, Any]:
    """Tri-valued validation of a barrier document. `accept_candidate` exists only so a mutant can
    model a coordinator that takes the rehearsal receipt for the real thing."""
    problems: List[str] = []
    if not isinstance(doc, dict):
        return {"valid": False, "problems": ["not_an_object"], "schema": None}
    schema = doc.get("schema")
    if schema != BARRIER_SCHEMA and not accept_candidate:
        problems.append(f"schema_is_not_{BARRIER_SCHEMA}:{schema}")
    for k in BARRIER_REQUIRED:
        if k not in doc and not accept_candidate:
            problems.append(f"missing:{k}")
    for k in CANDIDATE_REQUIRED:
        if k in doc and k != "schema" and not accept_candidate:
            problems.append(f"candidate_only_key_present:{k}")
    if doc.get("scope") not in (None, "production-global") and not accept_candidate:
        problems.append(f"scope_is_not_production_global:{doc.get('scope')}")
    return {"valid": not problems, "problems": problems, "schema": schema}


def make_production_barrier(migration_id: str, source_set_epoch: str, previous_epoch: int, target_epoch: int,
                            fence_key: str, token: Optional[str], cas_result: str, ledger: List[Dict[str, Any]],
                            evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic: the same transition always produces the same document (no wall clock inside),
    so a resume after a crash rewrites the byte-identical barrier instead of a second one."""
    doc = {
        "schema": BARRIER_SCHEMA,
        "migration_id": migration_id,
        "source_set_epoch": source_set_epoch,
        "previous_writer_epoch": previous_epoch,
        "target_writer_epoch": target_epoch,
        "scope": "production-global",
        "global_fence_key": fence_key,
        "fencing_token_id": token,
        "cas_result": cas_result,
        "authorising_decisions": ["DEC-AUP-0012", "DEC-AUP-0010"],
        "ladder_state": "SWITCHING",
        "host_activation_ledger": ledger,
        "evidence": evidence,
        "distinct_from": {
            "schema": CANDIDATE_SCHEMA,
            "shared_required_keys": BARRIER_DISJOINT_PROOF,
            "note": "AUP-E25 § MIG-016: the production barrier differs in schema from the candidate receipt",
        },
    }
    doc["document_digest"] = digest({k: v for k, v in doc.items() if k != "document_digest"})
    return doc


# ------------------------------------------------------------------ simulated implementations
class SimulatedFence(FenceBackend):
    backend = SIMULATED

    def __init__(self, world: World) -> None:
        self.world = world

    def set_fence(self, key: str) -> str:
        return self.world.authority.set_fence(key)

    def release_fence(self, key: str) -> str:
        return self.world.authority.release_fence(key)

    def active(self) -> bool:
        return self.world.authority.fence_active


class SimulatedLease(LeaseBackend):
    backend = SIMULATED

    def __init__(self, world: World) -> None:
        self.world = world

    def acquire(self, holder: str, ttl: int = LEASE_TTL) -> Dict[str, Any]:
        lease = self.world.authority.acquire_lease(holder=holder, ttl=ttl)
        return {"token": lease.token, "epoch": lease.epoch, "expires_at": lease.expires_at, "ttl": ttl}

    def check(self, token: Optional[str]) -> str:
        return self.world.authority.check_token(token)

    def release(self, token: Optional[str]) -> str:
        return self.world.authority.release_lease(token)

    def cas_commit(self, token: Optional[str], expected_epoch: int, new_epoch: int, accept_stale: bool = False) -> str:
        return self.world.authority.cas_commit(token, expected_epoch, new_epoch, accept_stale=accept_stale)

    def current_epoch(self) -> int:
        return self.world.authority.current_epoch


class SimulatedHostActivation(HostActivationBackend):
    backend = SIMULATED

    def __init__(self, world: World) -> None:
        self.world = world

    def ack(self, host: str, epoch: int, migration_id: str, accept_stale: bool = False) -> str:
        return self.world.authority.host_ack(host, epoch, migration_id, accept_stale=accept_stale)

    def alive(self, host: str) -> bool:
        return self.world.hosts[host].alive

    def hosts(self) -> List[str]:
        return sorted(self.world.hosts)


class SimulatedBarrierStore(BarrierStore):
    backend = SIMULATED

    def __init__(self) -> None:
        self.docs: Dict[str, Dict[str, Any]] = {}

    def put(self, doc: Dict[str, Any]) -> str:
        key = f"{doc.get('migration_id')}:{doc.get('target_writer_epoch')}"
        existing = self.docs.get(key)
        if existing is not None:
            return "idempotent" if canonical(existing) == canonical(doc) else "conflict"
        self.docs[key] = doc
        return "applied"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return self.docs.get(key)


class Backends:
    """The four backends the coordinator is given. `mode` is carried into every receipt."""

    def __init__(self, fence: FenceBackend, lease: LeaseBackend, hosts: HostActivationBackend,
                 barrier: BarrierStore, mode: str) -> None:
        self.fence, self.lease, self.hosts, self.barrier, self.mode = fence, lease, hosts, barrier, mode

    @classmethod
    def simulated(cls, world: World) -> "Backends":
        return cls(SimulatedFence(world), SimulatedLease(world), SimulatedHostActivation(world),
                   SimulatedBarrierStore(), mode="simulated")

    @classmethod
    def real(cls) -> "Backends":
        raise BackendNotAvailable(
            "the real fence / lease / barrier / host-activation backends do not exist yet: the fence is "
            "armed by the DEC-AUP-0011 freeze activation card and the writer lease by the DEC-AUP-0012 "
            "SWITCHING card. AUP-MIG-016:coord0 ships the interfaces and the simulated backend only.")

    def describe(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "fence": getattr(self.fence, "backend", type(self.fence).__name__),
            "lease": getattr(self.lease, "backend", type(self.lease).__name__),
            "host_activation": getattr(self.hosts, "backend", type(self.hosts).__name__),
            "barrier": getattr(self.barrier, "backend", type(self.barrier).__name__),
            "real_backends": "refused (BackendNotAvailable): later cards under DEC-AUP-0011 / DEC-AUP-0012",
        }
