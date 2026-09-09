"""AUP-MIG-013 rebuild0 -- the rehearsal target and its idempotent effect.

The real target is a task-owned local git repository (never
`datarim-history`, `aup`, or any `datarim/` path -- brief rule 2). It is
created under the caller's control (``RehearsalTarget.ensure_init``), never
touches arcanada-workspace or any shared checkout, and is never pushed
anywhere: the mechanism under test is the idempotent-effect protocol itself
(one effect per idempotency key, target readback through canonical refs),
not workspace content.

The one effect the canary performs is: write one JSON record at
``canary/handoff/<idempotency_key>.json`` and commit it. Idempotency is
enforced by checking the **committed tree at HEAD** (via `git show`, not the
working tree) for that path before writing -- a second call with the same
key is a no-op, proven by reading through git objects rather than trusting
an in-process flag.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class NetworkLossError(RuntimeError):
    pass


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=check
    )


@dataclass
class EffectResult:
    status: str  # APPLIED | ALREADY_APPLIED | UNKNOWN
    idempotency_key: str
    reason: str = ""


class RehearsalTarget:
    def __init__(self, root: Path):
        self.root = Path(root)

    def ensure_init(self) -> None:
        if (self.root / ".git").exists():
            return
        self.root.mkdir(parents=True, exist_ok=True)
        _git(self.root, "init", "-q", "-b", "main")
        _git(self.root, "config", "user.email", "aup-rehearsal@localhost")
        _git(self.root, "config", "user.name", "aup-rehearsal")
        (self.root / "README.md").write_text(
            "task-owned rehearsal target for AUP-MIG-013 rebuild0 -- canary records only, "
            "never datarim/, never pushed anywhere.\n"
        )
        _git(self.root, "add", "README.md")
        _git(self.root, "commit", "-q", "-m", "init rehearsal target")

    def _committed_path(self, rel: str) -> Optional[str]:
        """Read a path through HEAD's committed tree, not the working copy."""
        r = _git(self.root, "show", f"HEAD:{rel}", check=False)
        if r.returncode != 0:
            return None
        return r.stdout

    def readback(self, idempotency_key: str) -> Optional[dict]:
        rel = f"canary/handoff/{idempotency_key}.json"
        raw = self._committed_path(rel)
        if raw is None:
            return None
        return json.loads(raw)

    def apply_effect(self, idempotency_key: str, payload: dict) -> EffectResult:
        self.ensure_init()
        if self.readback(idempotency_key) is not None:
            return EffectResult(status="ALREADY_APPLIED", idempotency_key=idempotency_key)
        rel_dir = self.root / "canary" / "handoff"
        rel_dir.mkdir(parents=True, exist_ok=True)
        path = rel_dir / f"{idempotency_key}.json"
        path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
        _git(self.root, "add", f"canary/handoff/{idempotency_key}.json")
        _git(self.root, "commit", "-q", "-m", f"canary effect {idempotency_key}")
        return EffectResult(status="APPLIED", idempotency_key=idempotency_key)


def handoff_canary(
    target: RehearsalTarget,
    idempotency_key: str,
    payload: dict,
    simulate_network_loss: bool = False,
) -> EffectResult:
    """Execute exactly one idempotent effect against the rehearsal target.

    ``simulate_network_loss`` models the acknowledgement being lost after
    the request was sent: the effect is attempted for real against the
    target (so the target's own idempotency ledger is authoritative), but
    the caller is handed ``UNKNOWN`` because it cannot trust its own view of
    what happened -- exactly the partition the spec's network-loss fixture
    names. The caller must call ``reconcile`` (readback only, no repeat).
    """
    result = target.apply_effect(idempotency_key, payload)
    if simulate_network_loss:
        return EffectResult(
            status="UNKNOWN", idempotency_key=idempotency_key, reason="NETWORK_LOSS_SIMULATED"
        )
    return result


def _force_effect(target: RehearsalTarget, idempotency_key: str, payload: dict) -> EffectResult:
    """Write+commit unconditionally, bypassing the idempotency readback --
    exists only to give the M06 mutant a real second effect to be caught by,
    modelling the bug class 'reconcile re-issues instead of reading back'."""
    target.ensure_init()
    rel_dir = target.root / "canary" / "handoff"
    rel_dir.mkdir(parents=True, exist_ok=True)
    path = rel_dir / f"{idempotency_key}.json"
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
    _git(target.root, "add", f"canary/handoff/{idempotency_key}.json")
    _git(target.root, "commit", "-q", "--allow-empty", "-m", f"forced re-effect {idempotency_key}")
    return EffectResult(status="APPLIED", idempotency_key=idempotency_key, reason="FORCED_REISSUE")


def effect_commit_count(target: RehearsalTarget, idempotency_key: str) -> int:
    """Ground truth for 'at most one effect': count commits in the target's
    own history that touched this idempotency key's canary path."""
    rel = f"canary/handoff/{idempotency_key}.json"
    r = _git(target.root, "log", "--oneline", "--", rel, check=False)
    if r.returncode != 0 or not r.stdout.strip():
        return 0
    return len(r.stdout.strip().splitlines())


def reconcile(target: RehearsalTarget, idempotency_key: str) -> EffectResult:
    """Terminal result via readback alone -- never re-issues the effect."""
    record = target.readback(idempotency_key)
    if record is None:
        return EffectResult(status="NOT_APPLIED", idempotency_key=idempotency_key, reason="RECONCILED_BY_READBACK")
    return EffectResult(status="APPLIED", idempotency_key=idempotency_key, reason="RECONCILED_BY_READBACK")
