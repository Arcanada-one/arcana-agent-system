"""FI10-T5.1 synthetic harness: mock-only guarded_dispatch adapter controls."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = REPO_ROOT / "src" / "dispatch" / "fi10_adapter.py"
ROUTES_PATH = REPO_ROOT / "config" / "routes" / "fi10.json"
FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures" / "synthetic_controls.json"


def _load_adapter():
    spec = importlib.util.spec_from_file_location("fi10_adapter", ADAPTER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["fi10_adapter"] = module
    spec.loader.exec_module(module)
    return module


adapter = _load_adapter()


class FI10AdapterHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controls = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
        cls.routes = adapter.load_route_table(ROUTES_PATH)

    def setUp(self):
        self.now = self.controls["now"]
        self.local = deepcopy(self.controls["local"])
        self.standing = deepcopy(self.controls["valid_standing"])
        self.registry: dict = {}
        self.bypass = {"adapter_mediated_launches": 0}
        self.local_calls: list = []
        self.external_calls: list = []

    def _request(self, effect: dict, executor_id: str = "synthetic-local-mock"):
        return {
            "selection": {
                "task_id": "synthetic-fi10-t51",
                "knowledge_commit": self.local["knowledge_commit"],
            },
            "executor_id": executor_id,
            "effect": deepcopy(effect),
        }

    def _dispatch(self, trusted_effect, request_effect, **kwargs):
        request = self._request(request_effect)
        payload_digest = adapter.canonical_digest({"payload": request_effect})
        target_set = list(trusted_effect.get("target_set") or ["local-mock-only"])

        def local_callback(req):
            self.local_calls.append(req)

        def external_callback(_req):
            self.external_calls.append("external")

        # External callback must never be wired by the adapter under test.
        _ = external_callback

        return adapter.fi10_dispatch(
            request,
            route_table=self.routes,
            trusted_effect=trusted_effect,
            standing=kwargs.pop("standing", self.standing),
            local=self.local,
            attempt_id=kwargs.pop("attempt_id", "attempt-1"),
            payload_digest=kwargs.pop("payload_digest", payload_digest),
            target_set=kwargs.pop("target_set", target_set),
            policy_generation=kwargs.pop("policy_generation", "policy-gen-1"),
            source_generation=kwargs.pop("source_generation", "source-gen-1"),
            issuer_id=kwargs.pop("issuer_id", "synthetic-issuer"),
            reviewer_id=kwargs.pop("reviewer_id", "synthetic-reviewer"),
            local_callback=local_callback,
            clock=kwargs.pop("clock", lambda: self.now),
            outcome_registry=self.registry,
            bypass_detector=self.bypass,
            **kwargs,
        )

    def _assert_zero_effects(self, result):
        self.assertEqual(result.get("external_callbacks"), 0)
        self.assertEqual(self.external_calls, [])
        self.assertFalse(result.get("runtime_authorized"))
        self.assertFalse(result.get("knowledge_admitted"))
        self.assertFalse(result.get("effect_authorized"))
        self.assertEqual(result.get("verifier_kind"), "mock-only")
        self.assertEqual(result.get("installed_verifier_provenance"), "not_measured")

    # --- AC1: fixtures zero external; positive A/B one local ---

    def test_positive_class_a_one_local_callback(self):
        pos = self.controls["positive_class_a"]
        result = self._dispatch(pos["trusted_effect"], pos["request_effect"])
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["code"], "LOCAL_MOCK_CALLBACK_RETURNED")
        self.assertEqual(result["local_callbacks"], 1)
        self.assertEqual(len(self.local_calls), 1)
        self._assert_zero_effects(result)

    def test_positive_class_b_one_local_callback(self):
        pos = self.controls["positive_class_b"]
        result = self._dispatch(pos["trusted_effect"], pos["request_effect"])
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["local_callbacks"], 1)
        self.assertEqual(len(self.local_calls), 1)
        self._assert_zero_effects(result)

    def test_class_c_private_address_reclassified_e_refused(self):
        trusted = {
            "operation": "notify",
            "channel": "email",
            "disclosure": "includes private_address of recipient",
            "payload_text": "deliver to home address 1 Example Street",
            "trusted_effect_class": "C",
            "discloses_private_address": True,
        }
        effect = {"operation": "notify", "submitter_class": "C"}
        result = self._dispatch(trusted, effect)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["code"], "CLASS_E_DISABLED")
        self.assertEqual(result["effective_class"], "E")
        self.assertEqual(self.local_calls, [])
        self._assert_zero_effects(result)

    def test_d_official_letter_reclassified_e_refused(self):
        trusted = {
            "operation": "prepare_official_letter",
            "channel": "postal",
            "disclosure": "official_letter body",
            "payload_text": "official letter to counterparty",
            "trusted_effect_class": "D",
            "official_letter": True,
        }
        effect = {"operation": "prepare_official_letter", "submitter_class": "D"}
        result = self._dispatch(trusted, effect)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["code"], "CLASS_E_DISABLED")
        self.assertEqual(result["effective_class"], "E")
        self.assertEqual(self.local_calls, [])
        self._assert_zero_effects(result)

    def test_stale_consent_refused(self):
        pos = self.controls["positive_class_a"]
        standing = deepcopy(self.standing)
        standing["consent"] = {"state": "stale", "expires_at": self.now - 1}
        result = self._dispatch(pos["trusted_effect"], pos["request_effect"], standing=standing)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["code"], "LEASE_CONSENT_STALE")
        self.assertEqual(self.local_calls, [])
        self._assert_zero_effects(result)

    def test_altered_digest_or_target_refused(self):
        pos = self.controls["positive_class_a"]
        request = self._request(pos["request_effect"])
        good_digest = adapter.canonical_digest({"payload": pos["request_effect"]})

        def local_callback(req):
            self.local_calls.append(req)

        # Altered payload digest vs lease binding at launch revalidation.
        result = adapter.fi10_dispatch(
            request,
            route_table=self.routes,
            trusted_effect=pos["trusted_effect"],
            standing=self.standing,
            local=self.local,
            attempt_id="attempt-altered",
            payload_digest=good_digest,
            target_set=["local-mock-only"],
            policy_generation="policy-gen-1",
            source_generation="source-gen-1",
            issuer_id="synthetic-issuer",
            reviewer_id="synthetic-reviewer",
            local_callback=local_callback,
            clock=lambda: self.now,
            outcome_registry=self.registry,
            bypass_detector=self.bypass,
        )
        # Mutate target after lease creation via standing-box-independent mismatch:
        # re-run with mismatched target_set vs what lease was built for by patching launch path.
        self.assertEqual(result["verdict"], "pass")
        self.local_calls.clear()
        self.registry.clear()

        mismatched = self._dispatch(
            pos["trusted_effect"],
            pos["request_effect"],
            attempt_id="attempt-altered-2",
            payload_digest="0" * 64,
        )
        # Digest mismatch surfaces at launch revalidation after verify; if create_lease
        # accepts the digest shape, launch revalidation compares equal values — force
        # target mismatch via a custom launch wrapper by altering trusted target after.
        # Simpler path: create lease then revalidate with altered target.
        lease = adapter.create_lease(
            request=request,
            attempt_id="attempt-x",
            executor_id="synthetic-local-mock",
            payload_digest=good_digest,
            target_set=["local-mock-only"],
            policy_generation="policy-gen-1",
            source_generation="source-gen-1",
            issuer_id="synthetic-issuer",
            standing=self.standing,
            expires_at=self.standing["expires_at"],
            now=self.now,
        )
        with self.assertRaises(adapter.Refusal) as raised:
            adapter.revalidate_lease(
                lease,
                request=request,
                executor_id="synthetic-local-mock",
                payload_digest=good_digest,
                target_set=["altered-target"],
                policy_generation="policy-gen-1",
                source_generation="source-gen-1",
                issuer_id="synthetic-issuer",
                standing=self.standing,
                now=self.now,
            )
        self.assertEqual(raised.exception.code, "LEASE_TARGET_MISMATCH")
        with self.assertRaises(adapter.Refusal) as raised2:
            adapter.revalidate_lease(
                lease,
                request=request,
                executor_id="synthetic-local-mock",
                payload_digest="f" * 64,
                target_set=["local-mock-only"],
                policy_generation="policy-gen-1",
                source_generation="source-gen-1",
                issuer_id="synthetic-issuer",
                standing=self.standing,
                now=self.now,
            )
        self.assertEqual(raised2.exception.code, "LEASE_PAYLOAD_MISMATCH")
        self.assertEqual(mismatched.get("external_callbacks"), 0)
        self.assertEqual(self.external_calls, [])

    def test_revoked_between_check_and_callback(self):
        pos = self.controls["positive_class_a"]
        request = self._request(pos["request_effect"])
        payload_digest = adapter.canonical_digest({"payload": pos["request_effect"]})
        standing_box = {"current": deepcopy(self.standing)}
        calls = []

        def verify_evidence(req, loc):
            auth = adapter._mock_verify_evidence(
                req,
                loc,
                standing=standing_box["current"],
                now=self.now,
                reviewer_id="synthetic-reviewer",
            )
            # After first successful verification, revoke before second check / callback.
            standing_box["current"] = dict(
                standing_box["current"], revocation_state="revoked"
            )
            return auth

        def launch(_req):
            calls.append("launched")

        result = adapter.mock_only_guarded_dispatch(
            request,
            expected_request_digest=adapter.canonical_digest(request),
            local=self.local,
            verify_evidence=verify_evidence,
            launch=launch,
            clock=lambda: self.now,
            gates_enabled=True,
        )
        self.assertEqual(result["verdict"], "fail")
        self.assertIn(result["code"], {"AUTHORITY_REVOKED_OR_UNKNOWN", "LEASE_REVOKED"})
        # Second verify sees revoked standing via _mock_verify_evidence path:
        # our custom verify returns first auth then mutates; second call raises.
        # Re-run with verify that raises on second call:
        state = {"n": 0}

        def verify_then_revoke(req, loc):
            state["n"] += 1
            if state["n"] == 1:
                return adapter._mock_verify_evidence(
                    req,
                    loc,
                    standing=self.standing,
                    now=self.now,
                    reviewer_id="synthetic-reviewer",
                )
            raise adapter.Refusal("AUTHORITY_REVOKED_OR_UNKNOWN")

        calls.clear()
        result2 = adapter.mock_only_guarded_dispatch(
            request,
            expected_request_digest=adapter.canonical_digest(request),
            local=self.local,
            verify_evidence=verify_then_revoke,
            launch=launch,
            clock=lambda: self.now,
        )
        self.assertEqual(result2["verdict"], "fail")
        self.assertEqual(result2["code"], "AUTHORITY_REVOKED_OR_UNKNOWN")
        self.assertEqual(calls, [])
        self.assertEqual(result2["external_callbacks"], 0)
        _ = payload_digest  # retained for lease symmetry documentation

    def test_duplicate_attempt_no_second_callback(self):
        pos = self.controls["positive_class_a"]
        first = self._dispatch(pos["trusted_effect"], pos["request_effect"], attempt_id="dup-1")
        self.assertEqual(first["verdict"], "pass")
        self.assertEqual(len(self.local_calls), 1)
        second = self._dispatch(pos["trusted_effect"], pos["request_effect"], attempt_id="dup-1")
        self.assertEqual(second["verdict"], "reconciled")
        self.assertEqual(second["code"], "RECONCILED_NO_SECOND_CALLBACK")
        self.assertEqual(len(self.local_calls), 1)
        self.assertEqual(second["external_callbacks"], 0)

    def test_unknown_outcome_no_retry(self):
        pos = self.controls["positive_class_a"]
        result = self._dispatch(
            pos["trusted_effect"],
            pos["request_effect"],
            attempt_id="unknown-1",
            prior_outcome={"state": "accepted_response_lost"},
        )
        self.assertEqual(result["verdict"], "reconciled")
        self.assertEqual(result["code"], "RECONCILED_UNKNOWN_NO_RETRY")
        self.assertFalse(result["retry"])
        self.assertEqual(self.local_calls, [])
        self._assert_zero_effects(result)

    def test_forged_issuer_refused(self):
        pos = self.controls["positive_class_a"]
        standing = deepcopy(self.standing)
        standing["issuer_verdict"] = "unverified"
        result = self._dispatch(pos["trusted_effect"], pos["request_effect"], standing=standing)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["code"], "LEASE_ISSUER_FORGED")
        self.assertEqual(self.local_calls, [])
        self._assert_zero_effects(result)

    # --- AC2: gate removal / authority change / direct bypass ---

    def test_gate_removal_fails_closed(self):
        pos = self.controls["positive_class_a"]
        result = self._dispatch(
            pos["trusted_effect"], pos["request_effect"], gates_enabled=False
        )
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["code"], "GATE_REMOVED")
        self.assertEqual(self.local_calls, [])
        self._assert_zero_effects(result)

    def test_authority_change_between_verification_and_callback(self):
        pos = self.controls["positive_class_a"]
        request = self._request(pos["request_effect"])
        standing_box = {"current": deepcopy(self.standing)}
        calls = []
        n = {"v": 0}

        def verify_evidence(req, loc):
            n["v"] += 1
            if n["v"] >= 2:
                standing_box["current"] = dict(
                    standing_box["current"], revocation_state="revoked"
                )
                raise adapter.Refusal("AUTHORITY_REVOKED_OR_UNKNOWN")
            return adapter._mock_verify_evidence(
                req,
                loc,
                standing=standing_box["current"],
                now=self.now,
                reviewer_id="synthetic-reviewer",
            )

        def launch(_req):
            calls.append("launched")

        result = adapter.mock_only_guarded_dispatch(
            request,
            expected_request_digest=adapter.canonical_digest(request),
            local=self.local,
            verify_evidence=verify_evidence,
            launch=launch,
            clock=lambda: self.now,
        )
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["code"], "AUTHORITY_REVOKED_OR_UNKNOWN")
        self.assertEqual(calls, [])
        self.assertEqual(result["external_callbacks"], 0)

    def test_direct_executor_bypass_detected(self):
        def direct_executor(_req):
            self.local_calls.append("direct")

        direct_executor({"effect": {"operation": "bypass"}})
        detection = adapter.detect_direct_executor_bypass(
            direct_invocations=1,
            adapter_mediated_launches=int(self.bypass.get("adapter_mediated_launches", 0)),
        )
        self.assertEqual(detection["verdict"], "fail")
        self.assertEqual(detection["code"], "DIRECT_EXECUTOR_BYPASS_DETECTED")
        self.assertEqual(detection["external_callbacks"], 0)

        # Positive path records adapter-mediated launch; direct==mediated is not bypass.
        pos = self.controls["positive_class_a"]
        self.local_calls.clear()
        result = self._dispatch(pos["trusted_effect"], pos["request_effect"])
        self.assertEqual(result["verdict"], "pass")
        detection_ok = adapter.detect_direct_executor_bypass(
            direct_invocations=0,
            adapter_mediated_launches=int(self.bypass["adapter_mediated_launches"]),
        )
        self.assertEqual(detection_ok["verdict"], "pass")
        self.assertEqual(detection_ok["code"], "NO_BYPASS")

    # --- AC3: no route enabled; mock vs installed provenance ---

    def test_all_routes_disabled_including_de(self):
        table = adapter.load_route_table(ROUTES_PATH)
        self.assertIs(table["enabled"], False)
        de_routes = [r for r in table["routes"] if r["effect_class"] in ("D", "E")]
        self.assertGreaterEqual(len(de_routes), 1)
        for route in table["routes"]:
            self.assertIs(route["enabled"], False)
        adapter.assert_no_enabled_routes(table)
        # Mutant: enabling a D/E route must fail closed.
        mutant = deepcopy(table)
        for route in mutant["routes"]:
            if route["effect_class"] == "E":
                route["enabled"] = True
                break
        mutant_path = Path(self._tmp_mutant(mutant))
        with self.assertRaises(adapter.Refusal) as raised:
            adapter.load_route_table(mutant_path)
        self.assertEqual(raised.exception.code, "FI10_DE_ROUTE_ENABLED")

    def test_mock_provenance_distinct_from_installed(self):
        pos = self.controls["positive_class_a"]
        result = self._dispatch(pos["trusted_effect"], pos["request_effect"])
        self.assertEqual(result["verifier_kind"], "mock-only")
        self.assertEqual(result["installed_verifier_provenance"], "not_measured")
        self.assertNotEqual(result["verifier_kind"], result["installed_verifier_provenance"])

    def test_submitter_class_does_not_bind(self):
        # Submitter claims A but trusted evidence discloses private address → E.
        trusted = {
            "operation": "notify",
            "channel": "email",
            "disclosure": "private_address",
            "payload_text": "residential address included",
            "trusted_effect_class": "C",
            "discloses_private_address": True,
        }
        effect = {"operation": "notify", "submitter_class": "A"}
        effective = adapter.classify_effect(trusted, submitter_class="A")
        self.assertEqual(effective, "E")
        result = self._dispatch(trusted, effect)
        self.assertEqual(result["code"], "CLASS_E_DISABLED")

    def test_compensation_separately_classified(self):
        comp = adapter.classify_compensation(
            {
                "operation": "refund_payment",
                "official_letter": False,
                "trusted_effect_class": "B",
                "submitter_class": "A",
            }
        )
        self.assertTrue(comp["separately_classified"])
        self.assertFalse(comp["authorized"])
        self.assertFalse(comp["enabled"])
        self.assertEqual(comp["code"], "COMPENSATION_HELD")

    def _tmp_mutant(self, table: dict) -> str:
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".json",
            delete=False,
        )
        with handle as fh:
            json.dump(table, fh)
        return handle.name


if __name__ == "__main__":
    unittest.main()
