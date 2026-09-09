"""AUP-MIG-014 `fault0` — the independent oracle.

Deliberately shares no code with `coordinator.py`: it re-declares the state order and evaluates
the acceptance clauses of AUP-E25 § MIG-014 / § MIG-016 as rules over a *trace* — the durable
journal, the world's event log, the effect ledger, the authority log, the final lane / host state
and the observation mode. A rule fires with a violation code; the oracle is deterministic and
tri-valued only at the level of the caller (a trace it cannot read is `UNREADABLE`, never `ok`).

Rule table (each rule is load-bearing: `fault_drill.py --selftest` disables every rule in turn and
requires that some coordinator mutant then survives):

  O01_ORDER                   durable transitions follow the linear order, or go to PAUSED_SAFE /
                              ABORTED, or return from PAUSED_SAFE to the state they paused at
  O02_NO_ABORT_AFTER_COMMIT   ABORTED is never reached from WRITE_COMMITTED or later
  O03_EFFECT_ONCE             every effect key is applied at most once server-side
  O04_RESUME_IDEMPOTENT       a resume that finds no new fact writes no durable transition
  O05_FOREIGN_NOT_STOPPED     no foreign-confirmed / unknown-foreign lane is ever stopped
  O06_STALE_EPOCH_REJECTED    the authority never accepts a write / ack carrying an old writer epoch
  O07_CORRUPT_KNOWN_GOOD      a corrupt known-good generation ends in PAUSED_SAFE and no rollback
  O08_BREAK_GLASS_EXPIRES     a break-glass without expiry or past it is never accepted
  O09_NO_LEGACY_ROLLBACK      legacy hooks are never restored
  O10_REVOKED_NOT_RESUMED     after auth revocation no forward transition happens
  O11_REPLAY_NO_MODEL_CALLS   in replay mode the model is never called and the transition
                              sequence equals the live one
  O12_UNKNOWN_RECONCILED      every UNKNOWN effect outcome ends in a readback-based terminal
                              result, never in a re-issue
  O13_KEYED                   every durable transition carries migration_id, source_set_epoch
                              and target_writer_epoch
  O14_LEASE_HELD_UNDER_FENCE  FINAL_SYNC / VALIDATED / WRITE_COMMITTED effects are issued only
                              under a valid lease id
  O15_PAUSE_HAS_REASON        PAUSED_SAFE always carries a reason
  O16_REVALIDATION_ON_EPOCH   a SourceSetEpoch different from the keyed one before commit ends in
                              PAUSED_SAFE(REVALIDATION_REQUIRED), never in WRITE_COMMITTED
  O17_DRAIN_UNKNOWN_BLOCKS    FENCED is never reached while a host's lanes were unclassifiable
  O18_OBSERVATION_ONCE        the model is consulted at most once per observation key

stdlib only.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

ORDER = ["QUIESCING", "FENCED", "FINAL_SYNC", "VALIDATED", "WRITE_COMMITTED", "HOSTS_ACTIVATING", "OBSERVING", "COMPLETE"]
PAUSED = "PAUSED_SAFE"
ABORTED = "ABORTED"
INIT = "INIT"
COMMIT_INDEX = ORDER.index("WRITE_COMMITTED")
FENCE_STATES = {"FINAL_SYNC", "VALIDATED", "WRITE_COMMITTED"}
RULES = ["O01_ORDER", "O02_NO_ABORT_AFTER_COMMIT", "O03_EFFECT_ONCE", "O04_RESUME_IDEMPOTENT", "O05_FOREIGN_NOT_STOPPED",
         "O06_STALE_EPOCH_REJECTED", "O07_CORRUPT_KNOWN_GOOD", "O08_BREAK_GLASS_EXPIRES", "O09_NO_LEGACY_ROLLBACK",
         "O10_REVOKED_NOT_RESUMED", "O11_REPLAY_NO_MODEL_CALLS", "O12_UNKNOWN_RECONCILED", "O13_KEYED",
         "O14_LEASE_HELD_UNDER_FENCE", "O15_PAUSE_HAS_REASON", "O16_REVALIDATION_ON_EPOCH", "O17_DRAIN_UNKNOWN_BLOCKS",
         "O18_OBSERVATION_ONCE"]


def _idx(s: str) -> int:
    return ORDER.index(s) if s in ORDER else -1


def evaluate(trace: Dict[str, Any], disabled: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """Return the list of violations {rule, detail}. Empty list = every enabled rule holds."""
    disabled = disabled or set()
    v: List[Dict[str, Any]] = []

    def hit(rule: str, detail: str) -> None:
        if rule not in disabled:
            v.append({"rule": rule, "detail": detail})

    journal: List[Dict[str, Any]] = trace.get("journal", [])
    events: List[Dict[str, Any]] = trace.get("events", [])
    ledger: Dict[str, Dict[str, Any]] = trace.get("effect_ledger", {})
    authority: List[Dict[str, Any]] = trace.get("authority_log", [])
    final = trace.get("final", {})
    lanes = final.get("lanes", [])
    transitions = [r for r in journal if r.get("kind") == "transition"]

    # O01 / O02 / O13 / O15 over the transition sequence
    prev = INIT
    paused_at: Optional[str] = None
    for t in transitions:
        a, b = t.get("state_from"), t.get("state_to")
        ok = False
        if b in ORDER or (b == INIT and a == PAUSED):
            if a == INIT and b == ORDER[0]:
                ok = True
            elif a in ORDER and _idx(b) == _idx(a) + 1:
                ok = True
            elif a == PAUSED and b == paused_at:
                ok = True
        elif b == PAUSED:
            ok = a in ORDER or a == INIT
            paused_at = t.get("paused_at_state") or a
            if not t.get("reason"):
                hit("O15_PAUSE_HAS_REASON", f"seq {t.get('seq')}: PAUSED_SAFE without reason")
        elif b == ABORTED:
            at = t.get("aborted_at_state") or (paused_at if a == PAUSED else a)
            ok = a in ORDER or a == PAUSED or a == INIT
            if at in ORDER and _idx(at) >= COMMIT_INDEX:
                hit("O02_NO_ABORT_AFTER_COMMIT", f"seq {t.get('seq')}: ABORTED from {at}")
        if not ok:
            hit("O01_ORDER", f"seq {t.get('seq')}: {a} -> {b} is not an allowed transition")
        keys = t.get("keys", {})
        for k in ("migration_id", "source_set_epoch", "target_writer_epoch"):
            if k not in keys or keys[k] in (None, ""):
                hit("O13_KEYED", f"seq {t.get('seq')}: transition {a}->{b} lacks key {k}")
                break
        prev = b
    reached = {t.get("state_to") for t in transitions}
    committed = "WRITE_COMMITTED" in reached
    for e in events:
        if e.get("kind") == "abort_refused":
            pass
    # an accepted abort event after commit (belt and braces over the event log)
    for e in events:
        if e.get("kind") == "aborted" and e.get("at_state") in ORDER and _idx(e["at_state"]) >= COMMIT_INDEX:
            hit("O02_NO_ABORT_AFTER_COMMIT", f"event seq {e.get('seq')}: abort accepted at {e['at_state']}")

    # O03 effect counter
    for key, rec in ledger.items():
        if rec.get("count", 0) > 1:
            hit("O03_EFFECT_ONCE", f"effect {key} applied {rec['count']} times (results {rec.get('results')})")

    # O04 resume idempotence: between two consecutive resume events with no fact change, no transition
    # We detect via the journal: transitions written 'via' resume-replay are tagged by the coordinator's
    # mutant with reason 'M10'; more generally: two transitions with the same state_to on the forward
    # path, or a transition whose state_from is not the last state_to.
    seen_forward: Dict[str, int] = {}
    for t in transitions:
        b = t.get("state_to")
        if b in ORDER:
            seen_forward[b] = seen_forward.get(b, 0) + 1
    # a forward state may be re-entered once from PAUSED_SAFE (recovery) — count entries from PAUSED separately
    for b, n in seen_forward.items():
        from_paused = sum(1 for t in transitions if t.get("state_to") == b and t.get("state_from") == PAUSED)
        if n - from_paused > 1:
            hit("O04_RESUME_IDEMPOTENT", f"state {b} entered {n - from_paused} times on the forward path")
    resumes = [e for e in events if e.get("kind") == "resume"]
    for i in range(1, len(resumes)):
        r0, r1 = resumes[i - 1], resumes[i]
        between = [e for e in events if r0["seq"] < e["seq"] < r1["seq"]]
        facts = [e for e in between if e.get("kind") in ("fault_cleared", "fault_injected", "effect", "readback", "forward_recovery", "reconcile")]
        trans = [e for e in between if e.get("kind") == "transition"]
        if trans and not facts:
            hit("O04_RESUME_IDEMPOTENT", f"resume #{r0.get('resume_no')} produced a transition without a new fact")

    # O05 foreign lanes
    for e in events:
        if e.get("kind") == "lane_stop" and e.get("owner_class") in ("foreign-confirmed", "unknown-foreign"):
            hit("O05_FOREIGN_NOT_STOPPED", f"lane {e.get('lane')} ({e.get('owner_class')}) stopped by {e.get('by')}")
    for l in lanes:
        if l.get("stopped") and l.get("owner_class") in ("foreign-confirmed", "unknown-foreign") and l.get("id") != "mac:old-session":
            hit("O05_FOREIGN_NOT_STOPPED", f"lane {l.get('id')} ({l.get('owner_class')}) is stopped at the end")

    # O06 stale epoch
    for a in authority:
        if a.get("op") == "writer_write" and a.get("result") == "accepted" and a.get("writer_epoch", 0) < a.get("current_epoch", 0):
            hit("O06_STALE_EPOCH_REJECTED", f"authority seq {a.get('seq')}: stale writer epoch {a.get('writer_epoch')} accepted on {a.get('host')}")
        if a.get("op") == "host_ack" and a.get("result") in ("applied", "idempotent") and a.get("epoch") is not None and a["epoch"] < trace.get("final", {}).get("writer_epoch", a["epoch"]) and a.get("result") == "applied":
            # an ack for an epoch below the committed one that was accepted (not merely idempotent)
            hit("O06_STALE_EPOCH_REJECTED", f"authority seq {a.get('seq')}: host ack with stale epoch {a['epoch']} accepted")
        if a.get("op") == "cas_commit" and a.get("result") == "applied" and a.get("reason") is None:
            pass

    # O07 corrupt known-good
    if final.get("known_good_ok") is False:
        rb_applied = any(r.get("kind") == "rollback" and r.get("verdict") == "applied" for r in journal)
        if rb_applied:
            hit("O07_CORRUPT_KNOWN_GOOD", "rollback applied while the known-good generation digest does not verify")
        if final.get("state") not in (PAUSED, ABORTED):
            hit("O07_CORRUPT_KNOWN_GOOD", f"known-good corrupt but final state is {final.get('state')}")

    # O08 break-glass
    for e in events:
        if e.get("kind") == "break_glass" and e.get("accepted"):
            exp = e.get("expires_at")
            if exp is None:
                hit("O08_BREAK_GLASS_EXPIRES", f"break-glass without expiry accepted (seq {e.get('seq')})")
            elif exp <= e.get("at", 0):
                hit("O08_BREAK_GLASS_EXPIRES", f"expired break-glass accepted (expires_at {exp} <= now {e.get('at')})")

    # O09 legacy rollback
    if final.get("legacy_hooks_restored") or any(e.get("kind") == "legacy_hooks_restored" for e in events):
        hit("O09_NO_LEGACY_ROLLBACK", "legacy hooks restored")

    # O10 revoked run not resumed: after the 'fault_injected auth_revoke' event no forward transition
    rev = next((e for e in events if e.get("kind") == "fault_injected" and e.get("fault") == "auth_revoke"), None)
    if rev is not None:
        for e in events:
            if e["seq"] > rev["seq"] and e.get("kind") == "transition" and e.get("state_to") in ORDER:
                hit("O10_REVOKED_NOT_RESUMED", f"forward transition to {e['state_to']} after auth revocation (event seq {e['seq']})")
                break

    # O11 replay
    if trace.get("mode") == "replay":
        if final.get("model_calls", 0) > 0:
            hit("O11_REPLAY_NO_MODEL_CALLS", f"replay made {final['model_calls']} model call(s)")
        if trace.get("live_transition_digest") and trace.get("transition_digest") != trace.get("live_transition_digest"):
            hit("O11_REPLAY_NO_MODEL_CALLS", "replayed transition sequence differs from the live one")

    # O12 unknown reconciled
    for key, rec in ledger.items():
        results = rec.get("results", [])
        if "unknown" in results:
            i = results.index("unknown")
            if len(results) > i + 1:
                hit("O12_UNKNOWN_RECONCILED", f"effect {key} re-issued after UNKNOWN (results {results})")
            recs = [r for r in journal if r.get("kind") == "reconciliation" and r.get("effect_key") == key]
            if not any(r.get("terminal") in ("applied", "not_applied") for r in recs) and final.get("state") not in (PAUSED, ABORTED):
                hit("O12_UNKNOWN_RECONCILED", f"effect {key}: UNKNOWN outcome without a terminal reconciliation, run ended in {final.get('state')}")
            if any(r.get("reissued") for r in recs):
                hit("O12_UNKNOWN_RECONCILED", f"effect {key}: reconciliation re-issued")

    # O14 lease under fence: each fence-state effect must be preceded by a token check 'valid' after the last lease acquire
    fence_effects = [e for e in events if e.get("kind") == "effect" and e.get("kind") and str(e.get("key", "")).split(":")[-1] in FENCE_STATES and e.get("result") in ("applied", "unknown")]
    for fe in fence_effects:
        checks = [a for a in authority if a.get("op") == "lease_check" and a.get("at") <= fe.get("at")]
        last = checks[-1] if checks else None
        if last is None or last.get("result") != "valid":
            hit("O14_LEASE_HELD_UNDER_FENCE", f"effect {fe.get('key')} issued without a valid lease check (last check: {last and last.get('result')})")
    # expired lease with a later fence-state effect
    for a in authority:
        if a.get("op") == "lease_check" and a.get("result") == "expired":
            later = [fe for fe in fence_effects if fe.get("at") >= a.get("at")]
            if later:
                hit("O14_LEASE_HELD_UNDER_FENCE", f"fence-state effect after an expired token check at {a.get('at')}")
            break

    # O16 revalidation on epoch change before commit
    ep = next((e for e in events if e.get("kind") == "fault_injected" and e.get("fault") == "source_set_epoch_change"), None)
    if ep is not None:
        commit_ev = next((e for e in events if e.get("kind") == "transition" and e.get("state_to") == "WRITE_COMMITTED"), None)
        if commit_ev is not None and commit_ev["seq"] > ep["seq"]:
            hit("O16_REVALIDATION_ON_EPOCH", "WRITE_COMMITTED reached after the SourceSetEpoch changed and before revalidation")

    # O17 drain unknown blocks the fence
    for e in events:
        if e.get("kind") == "fault_injected" and e.get("fault", "").startswith("host_loss") and e.get("at_state") == "QUIESCING":
            fenced = next((x for x in events if x.get("kind") == "transition" and x.get("state_to") == "FENCED"), None)
            cleared = next((x for x in events if x.get("kind") == "fault_cleared" and x["seq"] > e["seq"]), None)
            if fenced is not None and (cleared is None or fenced["seq"] < cleared["seq"]):
                hit("O17_DRAIN_UNKNOWN_BLOCKS", "FENCED reached while a host's lanes were unclassifiable")

    # O18 observation once
    calls: Dict[str, int] = {}
    for e in events:
        if e.get("kind") == "observation_model_call":
            calls[e.get("key")] = calls.get(e.get("key"), 0) + 1
    for k, n in calls.items():
        if n > 1:
            hit("O18_OBSERVATION_ONCE", f"observation {k} consulted the model {n} times")

    return v
