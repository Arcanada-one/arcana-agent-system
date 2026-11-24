#!/usr/bin/env python3
"""FI10 guarded_dispatch adapter — explicit mock-only verifier composition.

This module is a synthetic FI10 binding for arcana-agent-system. It is NOT an
installed production verifier and MUST NOT be reported as knowledge-admitted,
runtime-authorized, or effect-authorized.

Floor (always):
  runtime_authorized = false
  knowledge_admitted = false
  effect_authorized = false
  installed_verifier_provenance = not_measured

Mocked guard behaviour is reported separately from installed verifier
provenance. Class D and class E routes remain disabled by configuration.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping, Optional

VERIFIER_KIND = "mock-only"
INSTALLED_VERIFIER_PROVENANCE = "not_measured"
ADAPTER_SCHEMA = "FI10GuardedDispatchAdapter/v1"
LEASE_SCHEMA = "FI10EffectLease/v1"
AUTHORITY_SCHEMA = "VerifiedKnowledgeDispatch/v1"

# Strictest-wins ordinal (higher = stricter). Unknown fails closed as E.
_CLASS_RANK = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5}

# Private-address / official-letter markers used by synthetic fixtures only.
_PRIVATE_ADDRESS_MARKERS = (
    "private_address",
    "home address",
    "residential address",
    "street address",
)
_OFFICIAL_LETTER_MARKERS = (
    "official_letter",
    "official letter",
    "contract",
    "payment_instruction",
    "physical_work",
)


class Refusal(Exception):
    """Fail-closed refusal with a stable machine code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_digest(value: Any) -> str:
    """Stable sha256 over canonical JSON (sorted keys, no NaN)."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return sha256(payload.encode("utf-8")).hexdigest()


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise Refusal(code)


def _as_mapping(value: Any, code: str) -> Mapping[str, Any]:
    _need(isinstance(value, Mapping), code)
    return value


def classify_effect(trusted: Mapping[str, Any], submitter_class: Optional[str] = None) -> str:
    """Derive effective class from trusted evidence. Submitter class is a claim only."""
    trusted = _as_mapping(trusted, "TRUSTED_EVIDENCE_INVALID")
    derived: list[str] = []

    claimed = trusted.get("trusted_effect_class")
    if isinstance(claimed, str) and claimed in _CLASS_RANK:
        derived.append(claimed)

    operation = str(trusted.get("operation") or "")
    channel = str(trusted.get("channel") or "")
    disclosure = str(trusted.get("disclosure") or "")
    payload_text = str(trusted.get("payload_text") or "")
    blob = " ".join([operation, channel, disclosure, payload_text]).lower()

    if any(marker in blob for marker in _PRIVATE_ADDRESS_MARKERS):
        derived.append("E")
    if any(marker in blob for marker in _OFFICIAL_LETTER_MARKERS):
        derived.append("E")
    if trusted.get("discloses_private_address") is True:
        derived.append("E")
    if trusted.get("official_letter") is True:
        derived.append("E")

    # Submitter class never binds; retained only as an explicit non-authority claim.
    _ = submitter_class

    if not derived:
        # Unbound classification fails closed (DEC-AUP-0160 scope).
        return "E"
    return max(derived, key=lambda c: _CLASS_RANK[c])


def load_route_table(path: Path | str) -> dict[str, Any]:
    """Load FI10 route table. Every class D/E route must be disabled."""
    raw = Path(path).read_text(encoding="utf-8")
    table = json.loads(raw)
    _need(isinstance(table, dict), "ROUTE_TABLE_INVALID")
    _need(table.get("schema") == "FI10RouteTable/v1", "ROUTE_TABLE_SCHEMA_MISMATCH")
    _need(table.get("enabled") is False, "ROUTE_TABLE_GLOBALLY_ENABLED")
    routes = table.get("routes")
    _need(isinstance(routes, list) and routes, "ROUTE_TABLE_EMPTY")
    for route in routes:
        _need(isinstance(route, dict), "ROUTE_ENTRY_INVALID")
        effect_class = route.get("effect_class")
        _need(effect_class in _CLASS_RANK, "ROUTE_CLASS_INVALID")
        if effect_class in ("D", "E"):
            _need(route.get("enabled") is False, "FI10_DE_ROUTE_ENABLED")
        else:
            # A/B/C may exist as synthetic local-mock entries but stay disabled by default.
            _need(route.get("enabled") is False, "FI10_ROUTE_ENABLED")
    return table


def assert_no_enabled_routes(table: Mapping[str, Any]) -> None:
    _need(table.get("enabled") is False, "ROUTE_TABLE_GLOBALLY_ENABLED")
    for route in table.get("routes") or []:
        _need(route.get("enabled") is False, "FI10_ROUTE_ENABLED")


def create_lease(
    *,
    request: Mapping[str, Any],
    attempt_id: str,
    executor_id: str,
    payload_digest: str,
    target_set: list[str],
    policy_generation: str,
    source_generation: str,
    issuer_id: str,
    standing: Mapping[str, Any],
    expires_at: int,
    now: int,
) -> dict[str, Any]:
    """Bind the atomic lease fields required by DEC-AUP-0160 before any callback."""
    _need(isinstance(attempt_id, str) and attempt_id, "LEASE_ATTEMPT_INVALID")
    _need(isinstance(executor_id, str) and executor_id, "LEASE_EXECUTOR_INVALID")
    _need(isinstance(payload_digest, str) and len(payload_digest) == 64, "LEASE_PAYLOAD_DIGEST_INVALID")
    _need(isinstance(target_set, list) and all(isinstance(t, str) for t in target_set), "LEASE_TARGET_INVALID")
    _need(isinstance(policy_generation, str) and policy_generation, "LEASE_POLICY_GENERATION_INVALID")
    _need(isinstance(source_generation, str) and source_generation, "LEASE_SOURCE_GENERATION_INVALID")
    _need(isinstance(issuer_id, str) and issuer_id, "LEASE_ISSUER_INVALID")
    _need(isinstance(expires_at, int) and expires_at > now, "LEASE_EXPIRED")
    standing = _as_mapping(standing, "LEASE_STANDING_INVALID")
    _need(standing.get("issuer_verdict") == "mock_verified", "LEASE_ISSUER_FORGED")
    _need(standing.get("revocation_state") == "clear", "LEASE_REVOKED")
    _need(standing.get("withdrawal_state", "clear") == "clear", "LEASE_WITHDRAWN")
    consent = standing.get("consent")
    if consent is not None:
        consent = _as_mapping(consent, "LEASE_CONSENT_INVALID")
        _need(consent.get("state") == "current", "LEASE_CONSENT_STALE")
        _need(isinstance(consent.get("expires_at"), int) and consent["expires_at"] > now, "LEASE_CONSENT_STALE")

    request_digest = canonical_digest(request)
    lease = {
        "schema": LEASE_SCHEMA,
        "verifier_kind": VERIFIER_KIND,
        "request_digest": request_digest,
        "attempt_id": attempt_id,
        "executor_id": executor_id,
        "payload_digest": payload_digest,
        "target_set": list(target_set),
        "policy_generation": policy_generation,
        "source_generation": source_generation,
        "issuer_id": issuer_id,
        "standing_digest": canonical_digest(standing),
        "expires_at": expires_at,
        "withdrawal_state": standing.get("withdrawal_state", "clear"),
        "consumed": False,
        "idempotency_key": f"fi10-lease-{request_digest[:16]}-{attempt_id}",
    }
    lease["lease_digest"] = canonical_digest(lease)
    return lease


def revalidate_lease(
    lease: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    executor_id: str,
    payload_digest: str,
    target_set: list[str],
    policy_generation: str,
    source_generation: str,
    issuer_id: str,
    standing: Mapping[str, Any],
    now: int,
) -> None:
    """Revalidate the same atomic boundary on retry/resume and before callback."""
    _need(lease.get("schema") == LEASE_SCHEMA, "LEASE_SCHEMA_MISMATCH")
    _need(lease.get("consumed") is False, "LEASE_ALREADY_CONSUMED")
    _need(lease.get("request_digest") == canonical_digest(request), "LEASE_REQUEST_MISMATCH")
    _need(lease.get("executor_id") == executor_id, "LEASE_EXECUTOR_MISMATCH")
    _need(lease.get("payload_digest") == payload_digest, "LEASE_PAYLOAD_MISMATCH")
    _need(list(lease.get("target_set") or []) == list(target_set), "LEASE_TARGET_MISMATCH")
    _need(lease.get("policy_generation") == policy_generation, "LEASE_POLICY_MISMATCH")
    _need(lease.get("source_generation") == source_generation, "LEASE_SOURCE_MISMATCH")
    _need(lease.get("issuer_id") == issuer_id, "LEASE_ISSUER_MISMATCH")
    _need(lease.get("standing_digest") == canonical_digest(standing), "LEASE_STANDING_MISMATCH")
    _need(isinstance(lease.get("expires_at"), int) and lease["expires_at"] > now, "LEASE_EXPIRED")
    _need(standing.get("issuer_verdict") == "mock_verified", "LEASE_ISSUER_FORGED")
    _need(standing.get("revocation_state") == "clear", "LEASE_REVOKED")
    _need(standing.get("withdrawal_state", "clear") == "clear", "LEASE_WITHDRAWN")
    consent = standing.get("consent")
    if consent is not None:
        _need(consent.get("state") == "current", "LEASE_CONSENT_STALE")
        _need(isinstance(consent.get("expires_at"), int) and consent["expires_at"] > now, "LEASE_CONSENT_STALE")


def consume_lease(lease: MutableMapping[str, Any]) -> None:
    _need(lease.get("consumed") is False, "LEASE_ALREADY_CONSUMED")
    lease["consumed"] = True


def reconcile_unknown_outcome(
    *,
    idempotency_key: str,
    prior: Optional[Mapping[str, Any]],
    registry: MutableMapping[str, Any],
) -> dict[str, Any]:
    """Reconcile ambiguous outcomes under a stable idempotency key; no second callback."""
    _need(isinstance(idempotency_key, str) and idempotency_key, "IDEMPOTENCY_KEY_INVALID")
    existing = registry.get(idempotency_key)
    if existing is not None:
        return {
            "verdict": "reconciled",
            "code": "RECONCILED_NO_SECOND_CALLBACK",
            "retry": False,
            "external_callbacks": 0,
            "local_callbacks": 0,
            "prior": deepcopy(existing),
        }
    outcome = {
        "state": (prior or {}).get("state", "unknown"),
        "idempotency_key": idempotency_key,
    }
    registry[idempotency_key] = deepcopy(outcome)
    if outcome["state"] in ("accepted_response_lost", "unknown", "ambiguous"):
        return {
            "verdict": "reconciled",
            "code": "RECONCILED_UNKNOWN_NO_RETRY",
            "retry": False,
            "external_callbacks": 0,
            "local_callbacks": 0,
            "prior": outcome,
        }
    return {
        "verdict": "reconciled",
        "code": "RECONCILED_RECORDED",
        "retry": False,
        "external_callbacks": 0,
        "local_callbacks": 0,
        "prior": outcome,
    }


def classify_compensation(effect: Mapping[str, Any]) -> dict[str, Any]:
    """Compensation is a separately classified and authorized effect."""
    effective = classify_effect(effect, submitter_class=effect.get("submitter_class"))
    return {
        "schema": "FI10CompensationClass/v1",
        "effective_class": effective,
        "separately_classified": True,
        "authorized": False,
        "enabled": False,
        "code": "COMPENSATION_HELD",
    }


def _mock_verify_evidence(
    request: Mapping[str, Any],
    local: Mapping[str, Any],
    *,
    standing: Mapping[str, Any],
    now: int,
    reviewer_id: str,
) -> dict[str, Any]:
    """Explicit mock-only verifier. Not installed verifier provenance."""
    _need(standing.get("issuer_verdict") == "mock_verified", "MANDATE_ISSUER_FORGED")
    _need(standing.get("revocation_state") == "clear", "AUTHORITY_REVOKED_OR_UNKNOWN")
    _need(standing.get("withdrawal_state", "clear") == "clear", "AUTHORITY_WITHDRAWN")
    _need(isinstance(standing.get("valid_from"), int) and standing["valid_from"] <= now, "AUTHORITY_NOT_YET_VALID")
    _need(isinstance(standing.get("expires_at"), int) and standing["expires_at"] > now, "AUTHORITY_EXPIRED")
    consent = standing.get("consent")
    if consent is not None:
        _need(consent.get("state") == "current", "CONSENT_STALE")
        _need(isinstance(consent.get("expires_at"), int) and consent["expires_at"] > now, "CONSENT_STALE")

    pin = canonical_digest(request)
    authority = {
        "schema": AUTHORITY_SCHEMA,
        "verdict": "verified",
        "verifier_kind": VERIFIER_KIND,
        "installed_verifier_provenance": INSTALLED_VERIFIER_PROVENANCE,
        "request_digest": pin,
        "selection_digest": local["selection_digest"],
        "contract_digest": local["contract_digest"],
        "store_snapshot_digest": local["store_snapshot_digest"],
        "knowledge_commit": local["knowledge_commit"],
        "executor_id": request["executor_id"],
        "reviewer_id": reviewer_id,
        "valid_from": standing["valid_from"],
        "expires_at": standing["expires_at"],
        "revoked": False,
        "obligations": {
            key: "verified"
            for key in (
                "semantic_fit",
                "kc2_authority",
                "source_main",
                "vectors",
                "graph",
                "file_references",
                "feeder_generation",
            )
        },
        "generations": {
            "vectors": local["generation"],
            "graph": local["generation"],
            "references": local["generation"],
            "feeder": local["generation"],
        },
    }
    return authority


def _verify_authority_shape(
    result: Mapping[str, Any],
    *,
    request_pin: str,
    local: Mapping[str, Any],
    executor_id: str,
    now: int,
) -> None:
    _need(result.get("schema") == AUTHORITY_SCHEMA, "AUTHORITY_RESPONSE_INVALID")
    _need(result.get("verdict") == "verified", "AUTHORITY_NOT_VERIFIED")
    _need(result.get("verifier_kind") == VERIFIER_KIND, "AUTHORITY_NOT_MOCK_ONLY")
    _need(result.get("installed_verifier_provenance") == INSTALLED_VERIFIER_PROVENANCE, "PROVENANCE_CLAIM_INVALID")
    _need(result.get("request_digest") == request_pin, "AUTHORITY_BINDING_MISMATCH")
    _need(result.get("selection_digest") == local["selection_digest"], "AUTHORITY_BINDING_MISMATCH")
    _need(result.get("contract_digest") == local["contract_digest"], "AUTHORITY_BINDING_MISMATCH")
    _need(result.get("store_snapshot_digest") == local["store_snapshot_digest"], "AUTHORITY_BINDING_MISMATCH")
    _need(result.get("knowledge_commit") == local["knowledge_commit"], "AUTHORITY_BINDING_MISMATCH")
    _need(result.get("executor_id") == executor_id, "EXECUTOR_MISMATCH")
    _need(
        isinstance(result.get("reviewer_id"), str)
        and bool(result["reviewer_id"])
        and result["reviewer_id"] != executor_id,
        "SELF_REVIEW_REFUSED",
    )
    _need(isinstance(result.get("expires_at"), int) and result["expires_at"] > now, "AUTHORITY_EXPIRED")
    _need(isinstance(result.get("valid_from"), int) and result["valid_from"] <= now, "AUTHORITY_NOT_YET_VALID")
    _need(result.get("revoked") is False, "AUTHORITY_REVOKED_OR_UNKNOWN")


def mock_only_guarded_dispatch(
    request: Mapping[str, Any],
    *,
    expected_request_digest: str,
    local: Mapping[str, Any],
    verify_evidence: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]],
    launch: Callable[[Mapping[str, Any]], None],
    clock: Callable[[], int],
    gates_enabled: bool = True,
) -> dict[str, Any]:
    """FI10-local composition mirroring the guarded_dispatch seam (mock-only).

    This is labelled mock-only and is not installed verifier provenance. When
    gates_enabled is False (harness gate-removal mutant), refuse before launch.
    """
    invoked = False
    try:
        _need(gates_enabled, "GATE_REMOVED")
        frozen = deepcopy(dict(request))
        _need(set(frozen) == {"selection", "executor_id", "effect"}, "INVALID_DISPATCH_REQUEST")
        _need(isinstance(frozen["executor_id"], str) and frozen["executor_id"], "INVALID_EXECUTOR")
        _need(isinstance(frozen["effect"], dict) and frozen["effect"], "MISSING_EFFECT")
        pin = canonical_digest(frozen)
        _need(pin == expected_request_digest, "REQUEST_PIN_MISMATCH")
        authority = verify_evidence(deepcopy(frozen), deepcopy(local))
        _verify_authority_shape(
            authority,
            request_pin=pin,
            local=local,
            executor_id=frozen["executor_id"],
            now=clock(),
        )
        _need(canonical_digest(request) == pin, "REQUEST_CHANGED_DURING_ADMISSION")
        # Second verification before callback (authority may change).
        authority = verify_evidence(deepcopy(frozen), deepcopy(local))
        _verify_authority_shape(
            authority,
            request_pin=pin,
            local=local,
            executor_id=frozen["executor_id"],
            now=clock(),
        )
        _need(canonical_digest(request) == pin, "REQUEST_CHANGED_DURING_ADMISSION")
        invoked = True
        launch(deepcopy(frozen))
        return {
            "verdict": "pass",
            "code": "LOCAL_MOCK_CALLBACK_RETURNED",
            "runtime_authorized": False,
            "knowledge_admitted": False,
            "effect_authorized": False,
            "executor_invoked": True,
            "verifier_kind": VERIFIER_KIND,
            "installed_verifier_provenance": INSTALLED_VERIFIER_PROVENANCE,
            "external_callbacks": 0,
            "local_callbacks": 1,
        }
    except Refusal as exc:
        return {
            "verdict": "fail",
            "code": exc.code,
            "runtime_authorized": False,
            "knowledge_admitted": False,
            "effect_authorized": False,
            "executor_invoked": invoked,
            "verifier_kind": VERIFIER_KIND,
            "installed_verifier_provenance": INSTALLED_VERIFIER_PROVENANCE,
            "external_callbacks": 0,
            "local_callbacks": 0,
        }
    except Exception:
        return {
            "verdict": "not_measured",
            "code": "DISPATCH_ERROR",
            "runtime_authorized": False,
            "knowledge_admitted": False,
            "effect_authorized": False,
            "executor_invoked": invoked,
            "verifier_kind": VERIFIER_KIND,
            "installed_verifier_provenance": INSTALLED_VERIFIER_PROVENANCE,
            "external_callbacks": 0,
            "local_callbacks": 0,
        }


def fi10_dispatch(
    request: Mapping[str, Any],
    *,
    route_table: Mapping[str, Any],
    trusted_effect: Mapping[str, Any],
    standing: Mapping[str, Any],
    local: Mapping[str, Any],
    attempt_id: str,
    payload_digest: str,
    target_set: list[str],
    policy_generation: str,
    source_generation: str,
    issuer_id: str,
    reviewer_id: str,
    local_callback: Callable[[Mapping[str, Any]], None],
    clock: Callable[[], int],
    outcome_registry: Optional[MutableMapping[str, Any]] = None,
    prior_outcome: Optional[Mapping[str, Any]] = None,
    gates_enabled: bool = True,
    guarded_dispatch_fn: Optional[Callable[..., dict[str, Any]]] = None,
    bypass_detector: Optional[MutableMapping[str, Any]] = None,
) -> dict[str, Any]:
    """Classify, lease-bind, and invoke mock-only guarded_dispatch for FI10.

    External callbacks are never issued. A successful synthetic A/B path yields
    exactly one local callback. Class D/E routes stay disabled.
    """
    assert_no_enabled_routes(route_table)
    submitter_claim = None
    if isinstance(request.get("effect"), Mapping):
        submitter_claim = request["effect"].get("submitter_class")
    effective_class = classify_effect(trusted_effect, submitter_class=submitter_claim)

    if effective_class in ("D", "E"):
        return {
            "verdict": "fail",
            "code": f"CLASS_{effective_class}_DISABLED",
            "effective_class": effective_class,
            "runtime_authorized": False,
            "knowledge_admitted": False,
            "effect_authorized": False,
            "executor_invoked": False,
            "verifier_kind": VERIFIER_KIND,
            "installed_verifier_provenance": INSTALLED_VERIFIER_PROVENANCE,
            "external_callbacks": 0,
            "local_callbacks": 0,
        }

    now = clock()
    try:
        lease = create_lease(
            request=request,
            attempt_id=attempt_id,
            executor_id=str(request["executor_id"]),
            payload_digest=payload_digest,
            target_set=target_set,
            policy_generation=policy_generation,
            source_generation=source_generation,
            issuer_id=issuer_id,
            standing=standing,
            expires_at=int(standing["expires_at"]),
            now=now,
        )
    except Refusal as exc:
        return {
            "verdict": "fail",
            "code": exc.code,
            "effective_class": effective_class,
            "runtime_authorized": False,
            "knowledge_admitted": False,
            "effect_authorized": False,
            "executor_invoked": False,
            "verifier_kind": VERIFIER_KIND,
            "installed_verifier_provenance": INSTALLED_VERIFIER_PROVENANCE,
            "external_callbacks": 0,
            "local_callbacks": 0,
        }

    registry = outcome_registry if outcome_registry is not None else {}
    if prior_outcome is not None or lease["idempotency_key"] in registry:
        reconciled = reconcile_unknown_outcome(
            idempotency_key=lease["idempotency_key"],
            prior=prior_outcome,
            registry=registry,
        )
        reconciled.update(
            {
                "effective_class": effective_class,
                "runtime_authorized": False,
                "knowledge_admitted": False,
                "effect_authorized": False,
                "executor_invoked": False,
                "verifier_kind": VERIFIER_KIND,
                "installed_verifier_provenance": INSTALLED_VERIFIER_PROVENANCE,
            }
        )
        return reconciled

    standing_box: dict[str, Any] = {"current": deepcopy(dict(standing))}

    def verify_evidence(req: Mapping[str, Any], loc: Mapping[str, Any]) -> Mapping[str, Any]:
        return _mock_verify_evidence(
            req,
            loc,
            standing=standing_box["current"],
            now=clock(),
            reviewer_id=reviewer_id,
        )

    local_calls: list[Any] = []

    def launch(req: Mapping[str, Any]) -> None:
        revalidate_lease(
            lease,
            request=req,
            executor_id=str(req["executor_id"]),
            payload_digest=payload_digest,
            target_set=target_set,
            policy_generation=policy_generation,
            source_generation=source_generation,
            issuer_id=issuer_id,
            standing=standing_box["current"],
            now=clock(),
        )
        consume_lease(lease)
        local_callback(req)
        local_calls.append(req)
        if bypass_detector is not None:
            bypass_detector["adapter_mediated_launches"] = (
                int(bypass_detector.get("adapter_mediated_launches", 0)) + 1
            )

    dispatch = guarded_dispatch_fn or mock_only_guarded_dispatch
    result = dispatch(
        request,
        expected_request_digest=canonical_digest(request),
        local=local,
        verify_evidence=verify_evidence,
        launch=launch,
        clock=clock,
        gates_enabled=gates_enabled,
    )
    result = dict(result)
    result["effective_class"] = effective_class
    result["lease_digest"] = lease.get("lease_digest")
    result["idempotency_key"] = lease["idempotency_key"]
    result["adapter_schema"] = ADAPTER_SCHEMA
    if result.get("verdict") == "pass":
        registry[lease["idempotency_key"]] = {
            "state": "local_mock_completed",
            "idempotency_key": lease["idempotency_key"],
        }
        result["local_callbacks"] = len(local_calls)
        result["external_callbacks"] = 0
    else:
        result["local_callbacks"] = 0
        result["external_callbacks"] = 0
    # Floor never inflated by mock path.
    result["runtime_authorized"] = False
    result["knowledge_admitted"] = False
    result["effect_authorized"] = False
    result["verifier_kind"] = VERIFIER_KIND
    result["installed_verifier_provenance"] = INSTALLED_VERIFIER_PROVENANCE
    # Expose standing box for harness authority-change mutants.
    result["_standing_box"] = standing_box
    result["_lease"] = lease
    return result


def detect_direct_executor_bypass(
    *,
    direct_invocations: int,
    adapter_mediated_launches: int,
) -> dict[str, Any]:
    """Harness detector: any direct executor call bypassing the adapter is FAIL."""
    bypassed = direct_invocations > 0 and direct_invocations > adapter_mediated_launches
    return {
        "verdict": "fail" if bypassed else "pass",
        "code": "DIRECT_EXECUTOR_BYPASS_DETECTED" if bypassed else "NO_BYPASS",
        "direct_invocations": direct_invocations,
        "adapter_mediated_launches": adapter_mediated_launches,
        "external_callbacks": 0,
    }


def default_route_table_path() -> Path:
    return Path(__file__).resolve().parents[2] / "config" / "routes" / "fi10.json"
