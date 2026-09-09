"""AUP-MIG-013 rebuild0 -- the checks verify-handoff performs, with named
mutant switches (``active_mutants``) so the selftest mutation battery can
disable one protective check at a time and prove the oracle notices.

Verdict precedence (first match wins): NONPORTABLE > NOT_MEASURED (target
unreachable) > DIGEST_MISMATCH > REJECTED (authority) > DETECTED (trace/
target parity) > PASS.
"""
from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from backend import EffectResult, RehearsalTarget, _force_effect, handoff_canary as _handoff_canary, reconcile as _reconcile  # noqa: E402
from package import JobPackageInputs, build_envelope, build_package, portability_findings, recompute_digest_from_manifest  # noqa: E402


def twice_check(inputs: JobPackageInputs, inject_hidden_nondeterminism: bool = False, active_mutants: frozenset = frozenset()) -> dict:
    pkg_a = build_package(inputs)
    inputs_b = replace(inputs, tool_pin=inputs.tool_pin + "+drift") if inject_hidden_nondeterminism else inputs
    pkg_b = build_package(inputs_b)
    match = pkg_a.digest == pkg_b.digest
    if not match and "M01_SKIP_TWICE_CHECK" not in active_mutants:
        verdict = "DIGEST_MISMATCH_BETWEEN_BUILDS"
    else:
        verdict = "PASS"
    return {
        "verdict": verdict,
        "digest_a": pkg_a.digest,
        "digest_b": pkg_b.digest,
        "package": pkg_a,
        "trace": {"twice_attempted": True, "twice_match": match, "verdict": verdict},
    }


def verify_handoff(
    manifest: dict,
    envelope: dict,
    expected_audience: str,
    target: Optional[RehearsalTarget],
    idempotency_key: str,
    trace_claims_applied: Optional[bool] = None,
    active_mutants: frozenset = frozenset(),
) -> dict:
    reasons: list[str] = []
    not_measured: list[str] = []
    trace: dict = {}

    findings = portability_findings(manifest) + portability_findings(envelope)
    trace["portability_findings"] = findings
    if findings and "M05_SKIP_PORTABILITY" not in active_mutants:
        trace["verdict"] = "NONPORTABLE"
        return {"verdict": "NONPORTABLE", "reasons": findings, "not_measured": [], "trace": trace}

    recomputed = recompute_digest_from_manifest(manifest)
    digest_match = recomputed == manifest["digest"] == envelope["digest"]
    trace["digest_checked"] = True
    trace["digest_match"] = digest_match
    if not digest_match and "M02_SKIP_DIGEST_CHECK" not in active_mutants:
        reasons.append(f"DIGEST_MISMATCH: recomputed={recomputed} manifest={manifest['digest']} envelope={envelope['digest']}")
        trace["verdict"] = "DIGEST_MISMATCH"
        return {"verdict": "DIGEST_MISMATCH", "reasons": reasons, "not_measured": not_measured, "trace": trace}

    authority_match = envelope["audience"] == expected_audience
    trace["authority_checked"] = True
    trace["authority_match"] = authority_match
    if not authority_match and "M03_SKIP_AUTHORITY_CHECK" not in active_mutants:
        reasons.append(f"AUTHORITY_SUBSTITUTED: envelope audience={envelope['audience']!r} expected={expected_audience!r}")
        trace["verdict"] = "REJECTED"
        return {"verdict": "REJECTED", "reasons": reasons, "not_measured": not_measured, "trace": trace}

    if target is None:
        not_measured.append("TARGET_UNREACHABLE: no rehearsal target configured")
        trace["target_unreachable"] = True
        if "M07_SKIP_MISSING_LINK_TYPING" in active_mutants:
            trace["verdict"] = "PASS"
            return {"verdict": "PASS", "reasons": reasons, "not_measured": [], "trace": trace}
        trace["verdict"] = "NOT_MEASURED"
        return {"verdict": "NOT_MEASURED", "reasons": reasons, "not_measured": not_measured, "trace": trace}

    try:
        record = target.readback(idempotency_key)
    except Exception as exc:  # unreachable/corrupt target -- typed, never crashes the verifier
        not_measured.append(f"TARGET_UNREACHABLE: {exc!r}")
        trace["target_unreachable"] = True
        if "M07_SKIP_MISSING_LINK_TYPING" in active_mutants:
            trace["verdict"] = "PASS"
            return {"verdict": "PASS", "reasons": reasons, "not_measured": [], "trace": trace}
        trace["verdict"] = "NOT_MEASURED"
        return {"verdict": "NOT_MEASURED", "reasons": reasons, "not_measured": not_measured, "trace": trace}

    target_has_record = record is not None
    trace["target_has_record"] = target_has_record
    if trace_claims_applied is not None:
        trace["trace_claims_applied"] = trace_claims_applied
        if trace_claims_applied and not target_has_record and "M04_SKIP_TRACE_PARITY" not in active_mutants:
            reasons.append("TRACE_WITHOUT_TARGET_EFFECT: local trace claims applied, target readback found nothing")
            trace["verdict"] = "DETECTED"
            return {"verdict": "DETECTED", "reasons": reasons, "not_measured": not_measured, "trace": trace}

    trace["verdict"] = "PASS"
    return {"verdict": "PASS", "reasons": reasons, "not_measured": not_measured, "trace": trace}


def handoff_canary(target: RehearsalTarget, idempotency_key: str, payload: dict, simulate_network_loss: bool = False) -> EffectResult:
    return _handoff_canary(target, idempotency_key, payload, simulate_network_loss=simulate_network_loss)


def reconcile(target: RehearsalTarget, idempotency_key: str, active_mutants: frozenset = frozenset()) -> EffectResult:
    if "M06_RECONCILE_REISSUES_EFFECT" in active_mutants:
        # the bug this mutant models: reconcile "fixes" an UNKNOWN by re-running the
        # effect instead of reading back -- exactly what R06/O12-style rules forbid.
        return _force_effect(target, idempotency_key, {"reissued_by": "buggy_reconcile"})
    return _reconcile(target, idempotency_key)
