"""Independent oracle for AUP-MIG-013 rebuild0 -- shares no code with
rebuild.py/backend.py. Reads a fixture's *trace* (a small dict of observed
facts) and checks program-level invariants, never the fixture's own claimed
verdict. A mutant that disables a protective check in rebuild.py should
still be visible here as a violation.
"""
from __future__ import annotations

RULES = (
    "R01_TWICE_CHECK_ENFORCED",
    "R02_DIGEST_RECOMPUTE_ENFORCED",
    "R03_AUTHORITY_PIN_ENFORCED",
    "R04_TRACE_TARGET_PARITY_ENFORCED",
    "R05_PORTABILITY_ENFORCED",
    "R06_EFFECT_COUNT_AT_MOST_ONE",
    "R07_MISSING_LINK_TYPED",
)


def check(trace: dict) -> list[str]:
    """Return the list of rule violations found in ``trace`` (empty = clean)."""
    v = []

    if trace.get("twice_attempted") and not trace.get("twice_match", True):
        if trace.get("verdict") not in ("DIGEST_MISMATCH_BETWEEN_BUILDS",):
            v.append("R01_TWICE_CHECK_ENFORCED")

    if trace.get("digest_checked") and not trace.get("digest_match", True):
        if trace.get("verdict") == "PASS":
            v.append("R02_DIGEST_RECOMPUTE_ENFORCED")

    if trace.get("authority_checked") and not trace.get("authority_match", True):
        if trace.get("verdict") != "REJECTED":
            v.append("R03_AUTHORITY_PIN_ENFORCED")

    if trace.get("trace_claims_applied") and not trace.get("target_has_record", True):
        if trace.get("verdict") != "DETECTED":
            v.append("R04_TRACE_TARGET_PARITY_ENFORCED")

    if trace.get("portability_findings"):
        if trace.get("verdict") not in ("NONPORTABLE",):
            v.append("R05_PORTABILITY_ENFORCED")

    if "effect_count" in trace and trace["effect_count"] > 1:
        v.append("R06_EFFECT_COUNT_AT_MOST_ONE")

    if trace.get("target_unreachable") and trace.get("verdict") not in ("NOT_MEASURED",):
        v.append("R07_MISSING_LINK_TYPED")

    return v
