#!/usr/bin/env python3
"""Emit producer-generated positive fixtures for the strict-reader tests (KCLIVE-11, R1).

Usage: emit.py <talomnia checkout at 336e644071323f5489ee417cc130ed3143185cbf> > producer_positives.json

Every positive is produced by the pinned talomnia opt-in producer
(`kc2_tools_profile_producer.emit_synthetic_profile_contract`), which re-reads its own output with
the strict reader before returning it, so these bytes are valid by the owner's reader, not by this
repository's opinion. The v2 SOURCE contract is synthetic (no native revision, no real content
digest): nothing here is a grant or evidence of source eligibility. Read-only on the checkout.
"""
import base64
import copy
import json
import subprocess
import sys
from pathlib import Path

TAL = Path(sys.argv[1]).resolve()
COMMIT = "336e644071323f5489ee417cc130ed3143185cbf"
head = subprocess.run(["git", "-C", str(TAL), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
if head != COMMIT:
    raise SystemExit(f"REFUSED: {TAL} is at {head}, the pin is {COMMIT}")
sys.dont_write_bytecode = True
for sub in ("kc2/src", "ontology/src"):
    sys.path.insert(0, str(TAL / sub))
import kc2_tools_profile as reader  # noqa: E402
import kc2_tools_profile_producer as producer  # noqa: E402

canon = reader.canonical
D = lambda n: "sha256:" + f"{n:064x}"


def v2_source(pins=2):
    body = {
        "canonicalization": {"name": "json-c14n-pilot", "version": "v1"},
        "conflict_records": [], "embedded": [], "envelope_unverified": [],
        "projection": [{"assertions": [f"synthetic assertion {i}"],
                        "source": {"content_digest": D(i + 1), "revision_id": f"synthetic-pin@r{i + 1}"}}
                       for i in range(pins)],
        "quarantined": [], "reduction": "closure-only", "refusals": [],
        "scope": {"project": "synthetic"}, "task": {"goal": "synthetic goal"},
        "verdict": "T", "verdicts": {},
    }
    manifest = {"revisions": [[f"synthetic-pin@r{i + 1}", D(i + 1)] for i in range(pins)], "snapshot_digest": D(0)}
    c = {"kind": "KnowledgeContract", "schema_version": "talomnia-ontology/v2", "body": body, "closure_manifest": manifest}
    c["contract_digest"] = canon.contract_digest(body, manifest)
    return c


def sealed(fn, pins=2):
    c = v2_source(pins)
    fn(c)
    c["contract_digest"] = canon.contract_digest(c["body"], c["closure_manifest"])
    return c


def entry(source, allow):
    r = producer.emit_synthetic_profile_contract(source, allow)
    assert "refusal" not in r, r
    c = r["contract"]
    body = canon.canonical_bytes(c["body"]).decode()
    man = canon.canonical_bytes(c["closure_manifest"]).decode()
    return {"allow": list(allow), "body_text": body, "manifest_text": man, "digest": c["contract_digest"],
            "whole_b64": base64.b64encode(r["bytes"]).decode()}


def bounds(val):
    return lambda c: c["body"]["task"].__setitem__("bounds", {"limit": val})


def text(val):
    return lambda c: (c["body"]["task"].__setitem__("goal", val), c["body"]["task"].__setitem__("bounds", {val: val}))


cases = {
    "rw": entry(v2_source(2), ["read", "write"]),
    "deny_all": entry(v2_source(2), []),
    "all_four": entry(v2_source(2), ["edit", "grep", "read", "write"]),
    "deny_all_no_pins": entry(v2_source(0), []),
    "rw_no_pins": entry(v2_source(0), ["read", "write"]),
    "u64_max": entry(sealed(bounds(18446744073709551615)), ["read"]),
    "i64_min": entry(sealed(bounds(-9223372036854775808)), ["read"]),
    "i64_max": entry(sealed(bounds(9223372036854775807)), ["read"]),
    "u64_max_plus_1": entry(sealed(bounds(18446744073709551616)), ["read"]),
    "i64_min_minus_1": entry(sealed(bounds(-9223372036854775809)), ["read"]),
    "pow2_200": entry(sealed(bounds(2 ** 200)), ["read"]),
    "uni_bmp": entry(sealed(text("café значение")), ["read"]),
    "uni_non_bmp": entry(sealed(text("\U0001F600 \U0001D11E")), ["read"]),
    "uni_controls": entry(sealed(text("a\u0001\u007f\"\\\n\t\r\b\f z\u0000")), ["read"]),
    "uni_lone_surrogate": entry(sealed(text("x\ud800y")), ["read"]),
}
legacy = v2_source(2)
out = {
    "producer": {"talomnia_commit": COMMIT, "entry": "kc2_tools_profile_producer.emit_synthetic_profile_contract",
                 "source": "synthetic talomnia-ontology/v2 contract (no native revision)"},
    "cases": cases,
    "legacy_v2": {"body_text": canon.canonical_bytes(legacy["body"]).decode(),
                  "manifest_text": canon.canonical_bytes(legacy["closure_manifest"]).decode(),
                  "digest": legacy["contract_digest"]},
}
json.dump(out, sys.stdout, indent=1, sort_keys=True)
print()
