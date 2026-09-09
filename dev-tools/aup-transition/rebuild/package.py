"""AUP-MIG-013 rebuild0 -- canonical job package + handoff envelope.

Every input the package digest depends on is explicit: nothing here reads a
wall clock, a random source or an environment variable. ``rebuild --twice``
in rebuild.py proves determinism by building the package twice from the same
explicit ``JobPackageInputs`` and asserting one digest -- the proof is that
this module never calls ``time.time()``/``os.urandom()``/``random`` itself.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Optional

CANONICAL_ENCODING = "utf-8-nfc-lf"  # explicit input, never platform-default

# A private absolute path looks like a real filesystem path under a home
# directory or /root; canonical refs (git shas, revision strings, dotted
# versions) never look like this. Portability check, not a path allowlist.
_PRIVATE_PATH_RE = re.compile(r"(?:^|[\s\"'=:])(/home/[^/\s\"']+|/root/[^\s\"']*)")
_SECRET_PREFIX_RE = re.compile(r"mun_sk_|ghp_|xox[baprs]-")


@dataclass(frozen=True)
class JobPackageInputs:
    kc2_revision: str
    muneral_work_revision: str  # SourceSetEpoch-style git-pinned ref, DEC-AUP-0012 rule 5
    policy_pin: str
    model_pin: str
    tool_pin: str
    audience: str  # pinned into the digest itself, so a post-build swap is a digest mismatch
    clock: str  # explicit ISO-8601 UTC, never sampled internally
    random_seed: int  # explicit, never sampled internally
    canonical_encoding: str = CANONICAL_ENCODING

    def canonical_dict(self) -> dict:
        return {
            "audience": self.audience,
            "canonical_encoding": self.canonical_encoding,
            "clock": self.clock,
            "kc2_revision": self.kc2_revision,
            "model_pin": self.model_pin,
            "muneral_work_revision": self.muneral_work_revision,
            "policy_pin": self.policy_pin,
            "random_seed": self.random_seed,
            "tool_pin": self.tool_pin,
        }


class PortabilityError(ValueError):
    def __init__(self, findings: list[str]):
        super().__init__("bundle non-portable: " + "; ".join(findings))
        self.findings = findings


def portability_findings(payload: dict) -> list[str]:
    """Scan a canonical payload for private absolute paths or secrets.

    Returns typed findings; an empty list means portable. Never raises --
    callers decide whether a non-empty list is fatal.
    """
    findings = []
    blob = json.dumps(payload, sort_keys=True)
    for m in _PRIVATE_PATH_RE.finditer(blob):
        findings.append(f"PRIVATE_ABSOLUTE_PATH:{m.group(1)}")
    for m in _SECRET_PREFIX_RE.finditer(blob):
        findings.append(f"SECRET_LITERAL:{m.group(0)[:8]}...")
    return sorted(set(findings))


def canonical_bytes(payload: dict) -> bytes:
    # sort_keys + fixed separators + NFC/LF encoding name pinned above make
    # this reproducible across two independent calls in the same process.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def digest_of(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class JobPackage:
    inputs: JobPackageInputs
    digest: str
    portability: list[str] = field(default_factory=list)

    @property
    def portable(self) -> bool:
        return not self.portability

    def to_dict(self) -> dict:
        return {
            "schema": "MigRebuildJobPackage/v1",
            "digest": self.digest,
            "inputs": self.inputs.canonical_dict(),
            "portability": self.portability,
        }


def build_package(inputs: JobPackageInputs) -> JobPackage:
    payload = inputs.canonical_dict()
    findings = portability_findings(payload)
    return JobPackage(inputs=inputs, digest=digest_of(payload), portability=findings)


@dataclass(frozen=True)
class HandoffEnvelope:
    digest: str
    audience: str
    expiry: str  # explicit ISO-8601 UTC, derived from the caller's clock input
    canonical_refs: dict

    def to_dict(self) -> dict:
        return {
            "schema": "MigHandoffEnvelope/v1",
            "digest": self.digest,
            "audience": self.audience,
            "expiry": self.expiry,
            "canonical_refs": self.canonical_refs,
        }

    @staticmethod
    def from_dict(d: dict) -> "HandoffEnvelope":
        return HandoffEnvelope(
            digest=d["digest"],
            audience=d["audience"],
            expiry=d["expiry"],
            canonical_refs=d["canonical_refs"],
        )


def build_envelope(package: JobPackage, expiry: str) -> HandoffEnvelope:
    """Audience travels once, inside ``inputs`` (digest-bearing); the
    envelope's top-level ``audience`` is a copy for cheap transport checks,
    never a second source of truth."""
    refs = {
        "kc2_revision": package.inputs.kc2_revision,
        "muneral_work_revision": package.inputs.muneral_work_revision,
        "policy_pin": package.inputs.policy_pin,
        "model_pin": package.inputs.model_pin,
        "tool_pin": package.inputs.tool_pin,
    }
    envelope = HandoffEnvelope(
        digest=package.digest, audience=package.inputs.audience, expiry=expiry, canonical_refs=refs
    )
    findings = portability_findings(envelope.to_dict())
    if findings:
        raise PortabilityError(findings)
    return envelope


def recompute_digest_from_manifest(manifest: dict) -> str:
    """Recompute the package digest from the full manifest's inputs.

    The manifest (``JobPackage.to_dict()``) is what actually travels for
    offline validation -- the envelope alone (digest/audience/expiry/refs)
    is deliberately too thin to recompute from, since it is the part meant
    to be safe to hand across a transport. Neither carries a secret or a
    private absolute path; the manifest inputs are pins and revisions.
    """
    return digest_of(manifest["inputs"])
