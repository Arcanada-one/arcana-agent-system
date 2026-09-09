"""AUP-MIG-013 rebuild0 selftest fixtures.

Ten hermetic fixtures (F0 green control + F1..F9, one per named failure
scenario plus the twice-determinism proof and the missing-link diagnostic),
a mutation battery (M01..M07, one per protective check) and a rule battery
over ``oracle.py`` (R01..R07). Every ``RehearsalTarget`` lives under a
``TemporaryDirectory`` -- nothing here touches a real host path.
"""
from __future__ import annotations

import copy
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import core  # noqa: E402
import oracle  # noqa: E402
from backend import RehearsalTarget, effect_commit_count  # noqa: E402
from package import HandoffEnvelope, JobPackageInputs, PortabilityError, build_envelope, build_package  # noqa: E402

AUDIENCE = "devs-rehearsal-15be398a"
EXPIRY = "2026-09-06T20:00:00Z"
CLOCK = "2026-09-05T20:00:00Z"


def base_inputs(**overrides) -> JobPackageInputs:
    fields = dict(
        kc2_revision="kc2@2026.09.0-abc123",
        muneral_work_revision="git:arcanada-workspace@538d2e768ab0",
        policy_pin="policy@rebuild0-r1",
        model_pin="claude-sonnet-5",
        tool_pin="mig-rebuild@0.1.0",
        audience=AUDIENCE,
        clock=CLOCK,
        random_seed=42,
    )
    fields.update(overrides)
    return JobPackageInputs(**fields)


def _key(digest: str) -> str:
    return digest.split(":", 1)[1][:24]


def f0_green_control(active_mutants=frozenset()):
    inputs = base_inputs()
    twice = core.twice_check(inputs, active_mutants=active_mutants)
    pkg = twice["package"]
    envelope = build_envelope(pkg, expiry=EXPIRY)
    manifest = pkg.to_dict()
    with tempfile.TemporaryDirectory() as d:
        target = RehearsalTarget(Path(d) / "target")
        key = _key(pkg.digest)
        eff1 = core.handoff_canary(target, key, {"digest": pkg.digest, "audience": pkg.inputs.audience})
        eff2 = core.handoff_canary(target, key, {"digest": pkg.digest, "audience": pkg.inputs.audience})
        vr = core.verify_handoff(
            manifest, envelope.to_dict(), expected_audience=inputs.audience,
            target=target, idempotency_key=key, trace_claims_applied=True, active_mutants=active_mutants,
        )
        count = effect_commit_count(target, key)
    trace = {**twice["trace"], **vr["trace"], "effect_count": count}
    ok = (
        twice["verdict"] == "PASS" and eff1.status == "APPLIED" and eff2.status == "ALREADY_APPLIED"
        and vr["verdict"] == "PASS" and not vr["not_measured"] and count == 1
    )
    return {"id": "F0_green_control", "expect": "PASS (all-green control)", "verdict": vr["verdict"], "ok": ok, "trace": trace}


def f1_twice_hidden_nondeterminism(active_mutants=frozenset()):
    inputs = base_inputs()
    twice = core.twice_check(inputs, inject_hidden_nondeterminism=True, active_mutants=active_mutants)
    ok = twice["verdict"] == "DIGEST_MISMATCH_BETWEEN_BUILDS"
    return {"id": "F1_twice_hidden_nondeterminism", "expect": "DIGEST_MISMATCH_BETWEEN_BUILDS", "verdict": twice["verdict"], "ok": ok, "trace": twice["trace"]}


def _mutated_field_fixture(fid: str, field: str, new_value, active_mutants=frozenset()):
    inputs = base_inputs()
    pkg = build_package(inputs)
    envelope = build_envelope(pkg, expiry=EXPIRY)
    manifest = copy.deepcopy(pkg.to_dict())
    manifest["inputs"][field] = new_value  # digest field left stale -> recompute mismatch
    with tempfile.TemporaryDirectory() as d:
        target = RehearsalTarget(Path(d) / "target")
        key = _key(pkg.digest)
        core.handoff_canary(target, key, {"digest": pkg.digest})
        vr = core.verify_handoff(
            manifest, envelope.to_dict(), expected_audience=inputs.audience,
            target=target, idempotency_key=key, trace_claims_applied=True, active_mutants=active_mutants,
        )
    ok = vr["verdict"] == "DIGEST_MISMATCH"
    return {"id": fid, "expect": "DIGEST_MISMATCH", "verdict": vr["verdict"], "ok": ok, "trace": vr["trace"]}


def f2_mutated_byte(active_mutants=frozenset()):
    return _mutated_field_fixture("F2_mutated_byte", "tool_pin", "mig-rebuild@0.1.0" + chr(ord("0") ^ 1), active_mutants)


def f3_mutated_audience(active_mutants=frozenset()):
    return _mutated_field_fixture("F3_mutated_audience", "audience", "some-other-audience", active_mutants)


def f4_mutated_source_revision(active_mutants=frozenset()):
    return _mutated_field_fixture("F4_mutated_source_revision", "muneral_work_revision", "git:arcanada-workspace@deadbeef00", active_mutants)


def f5_transport_substituting_authority(active_mutants=frozenset()):
    original = base_inputs(audience=AUDIENCE)
    attacker = base_inputs(audience="attacker-audience")
    pkg_attacker = build_package(attacker)
    envelope_attacker = build_envelope(pkg_attacker, expiry=EXPIRY)
    manifest_attacker = pkg_attacker.to_dict()
    with tempfile.TemporaryDirectory() as d:
        target = RehearsalTarget(Path(d) / "target")
        key = _key(pkg_attacker.digest)
        core.handoff_canary(target, key, {"digest": pkg_attacker.digest})
        # verify against the ORIGINAL rebuild's pinned audience, not whatever arrived
        vr = core.verify_handoff(
            manifest_attacker, envelope_attacker.to_dict(), expected_audience=original.audience,
            target=target, idempotency_key=key, trace_claims_applied=True, active_mutants=active_mutants,
        )
    ok = vr["verdict"] == "REJECTED" and vr["trace"].get("digest_match") is True
    return {"id": "F5_transport_substituting_authority", "expect": "REJECTED (digest self-consistent, authority not)", "verdict": vr["verdict"], "ok": ok, "trace": vr["trace"]}


def f6_trace_without_target_effect(active_mutants=frozenset()):
    inputs = base_inputs()
    pkg = build_package(inputs)
    envelope = build_envelope(pkg, expiry=EXPIRY)
    manifest = pkg.to_dict()
    with tempfile.TemporaryDirectory() as d:
        target = RehearsalTarget(Path(d) / "target")
        target.ensure_init()  # target exists and is reachable; the effect itself never happened
        key = _key(pkg.digest)
        vr = core.verify_handoff(
            manifest, envelope.to_dict(), expected_audience=inputs.audience,
            target=target, idempotency_key=key, trace_claims_applied=True, active_mutants=active_mutants,
        )
    ok = vr["verdict"] == "DETECTED"
    return {"id": "F6_trace_without_target_effect", "expect": "DETECTED", "verdict": vr["verdict"], "ok": ok, "trace": vr["trace"]}


def f7_private_absolute_path(active_mutants=frozenset()):
    inputs = base_inputs(tool_pin="mig-rebuild@0.1.0 /home/dev/.secrets/Muneral.md")
    pkg = build_package(inputs)
    # the build-time guard must independently refuse too
    try:
        build_envelope(pkg, expiry=EXPIRY)
        build_time_refused = False
    except PortabilityError:
        build_time_refused = True
    envelope = HandoffEnvelope(
        digest=pkg.digest, audience=pkg.inputs.audience, expiry=EXPIRY,
        canonical_refs={
            "kc2_revision": pkg.inputs.kc2_revision, "muneral_work_revision": pkg.inputs.muneral_work_revision,
            "policy_pin": pkg.inputs.policy_pin, "model_pin": pkg.inputs.model_pin, "tool_pin": pkg.inputs.tool_pin,
        },
    )
    manifest = pkg.to_dict()
    with tempfile.TemporaryDirectory() as d:
        target = RehearsalTarget(Path(d) / "target")
        key = _key(pkg.digest)
        core.handoff_canary(target, key, {"digest": pkg.digest})
        vr = core.verify_handoff(
            manifest, envelope.to_dict(), expected_audience=inputs.audience,
            target=target, idempotency_key=key, trace_claims_applied=True, active_mutants=active_mutants,
        )
    ok = build_time_refused and vr["verdict"] == "NONPORTABLE"
    return {"id": "F7_private_absolute_path", "expect": "NONPORTABLE (build-time AND verify-time)", "verdict": vr["verdict"], "ok": ok, "trace": vr["trace"]}


def f8_network_loss(active_mutants=frozenset()):
    inputs = base_inputs()
    pkg = build_package(inputs)
    with tempfile.TemporaryDirectory() as d:
        target = RehearsalTarget(Path(d) / "target")
        key = _key(pkg.digest)
        eff1 = core.handoff_canary(target, key, {"digest": pkg.digest}, simulate_network_loss=True)
        rec = core.reconcile(target, key, active_mutants=active_mutants)
        retry = core.handoff_canary(target, key, {"digest": pkg.digest})
        count = effect_commit_count(target, key)
    ok = (
        eff1.status == "UNKNOWN" and rec.status == "APPLIED" and rec.reason == "RECONCILED_BY_READBACK"
        and retry.status == "ALREADY_APPLIED" and count == 1
    )
    trace = {"effect_count": count, "verdict": "PASS" if ok else "EFFECT_COUNT_VIOLATION"}
    return {"id": "F8_network_loss", "expect": "UNKNOWN -> reconcile APPLIED via readback, no repeat, effect_count=1", "verdict": trace["verdict"], "ok": ok, "trace": trace}


def f9_target_unreachable(active_mutants=frozenset()):
    inputs = base_inputs()
    pkg = build_package(inputs)
    envelope = build_envelope(pkg, expiry=EXPIRY)
    manifest = pkg.to_dict()
    vr = core.verify_handoff(
        manifest, envelope.to_dict(), expected_audience=inputs.audience,
        target=None, idempotency_key=_key(pkg.digest), trace_claims_applied=True, active_mutants=active_mutants,
    )
    ok = vr["verdict"] == "NOT_MEASURED" and bool(vr["not_measured"])
    return {"id": "F9_target_unreachable", "expect": "NOT_MEASURED (missing-link diagnostic, never PASS)", "verdict": vr["verdict"], "ok": ok, "trace": vr["trace"]}


FIXTURES = {
    "F0": f0_green_control,
    "F1": f1_twice_hidden_nondeterminism,
    "F2": f2_mutated_byte,
    "F3": f3_mutated_audience,
    "F4": f4_mutated_source_revision,
    "F5": f5_transport_substituting_authority,
    "F6": f6_trace_without_target_effect,
    "F7": f7_private_absolute_path,
    "F8": f8_network_loss,
    "F9": f9_target_unreachable,
}

MUTANT_FIXTURE = {
    "M01_SKIP_TWICE_CHECK": "F1",
    "M02_SKIP_DIGEST_CHECK": "F2",
    "M03_SKIP_AUTHORITY_CHECK": "F5",
    "M04_SKIP_TRACE_PARITY": "F6",
    "M05_SKIP_PORTABILITY": "F7",
    "M06_RECONCILE_REISSUES_EFFECT": "F8",
    "M07_SKIP_MISSING_LINK_TYPING": "F9",
}

MUTANT_RULE = {
    "M01_SKIP_TWICE_CHECK": "R01_TWICE_CHECK_ENFORCED",
    "M02_SKIP_DIGEST_CHECK": "R02_DIGEST_RECOMPUTE_ENFORCED",
    "M03_SKIP_AUTHORITY_CHECK": "R03_AUTHORITY_PIN_ENFORCED",
    "M04_SKIP_TRACE_PARITY": "R04_TRACE_TARGET_PARITY_ENFORCED",
    "M05_SKIP_PORTABILITY": "R05_PORTABILITY_ENFORCED",
    "M06_RECONCILE_REISSUES_EFFECT": "R06_EFFECT_COUNT_AT_MOST_ONE",
    "M07_SKIP_MISSING_LINK_TYPING": "R07_MISSING_LINK_TYPED",
}


def run_selftest() -> dict:
    checks = []

    def record(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    # 1. baseline: every fixture, unmutated, must hit its typed expectation
    baseline_traces = {}
    for fid, fn in FIXTURES.items():
        r = fn()
        baseline_traces[fid] = r["trace"]
        record(f"baseline:{r['id']}", r["ok"], f"expect={r['expect']} got={r['verdict']}")

    # 2. negative control: an inert mutant name changes nothing
    for fid, fn in FIXTURES.items():
        r_inert = fn(active_mutants=frozenset({"M00_INERT"}))
        base = FIXTURES[fid]()
        record(f"negative_control:{fid}", r_inert["verdict"] == base["verdict"], "inert mutant must not change any verdict")

    # 3. mutation battery + 4. rule battery (paired: each mutant killed by its fixture,
    #    and the oracle rule it disables fires uniquely for that pair)
    for mutant, fid in MUTANT_FIXTURE.items():
        rule = MUTANT_RULE[mutant]
        clean = FIXTURES[fid]()
        mutated = FIXTURES[fid](active_mutants=frozenset({mutant}))
        clean_violations = oracle.check(clean["trace"])
        mutated_violations = oracle.check(mutated["trace"])
        killed = (mutated["verdict"] != clean["verdict"]) or (rule in mutated_violations)
        record(f"mutation_battery:{mutant}", killed, f"clean={clean['verdict']} mutated={mutated['verdict']} oracle={mutated_violations}")
        record(f"rule_battery:{rule}", clean_violations == [] and mutated_violations == [rule], f"clean_violations={clean_violations} mutated_violations={mutated_violations}")

    # 5. determinism: the green control's own digest is stable across two independent runs
    d1 = f0_green_control()
    d2 = f0_green_control()
    record("determinism:F0_repeat", d1["trace"].get("twice_match") and d2["trace"].get("twice_match") and d1["ok"] and d2["ok"], "")

    total = len(checks)
    passed = sum(1 for c in checks if c["ok"])
    return {
        "schema": "SelftestReport/v1",
        "tool": "tools/mig/rebuild",
        "total": total,
        "passed": passed,
        "all_pass": passed == total,
        "checks": checks,
    }
