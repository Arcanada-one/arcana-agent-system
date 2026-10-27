"""Typed fixture primitives for gated DEC-AUP-0079 source adoption.

Immutable Git inputs and exact diagnostics are separate from production fitness.
This module does not exempt source, change the graph, or grant admission. Native
consumers must additionally prove containment and trusted-BASE applicability.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping
from urllib.parse import quote


class FixtureError(ValueError):
    def __init__(self, code: str, detail: str):
        self.code, self.detail = code, detail
        super().__init__(f"{code}: {detail}")


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise FixtureError("DUPLICATE_JSON_KEY", str(key))
            result[key] = value
        return result

    def invalid(value):
        raise FixtureError("NONFINITE_JSON", value)

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FixtureError("INVALID_JSON", str(exc)) from exc


def safe_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise FixtureError("PATH_INVALID", repr(value))
    p = PurePosixPath(value)
    if p.is_absolute() or value != p.as_posix() or any(x in ("", ".", "..") for x in value.split("/")):
        raise FixtureError("PATH_ESCAPE", value)
    return value


def exact_keys(obj, keys: set[str], code: str):
    if not isinstance(obj, dict) or set(obj) != keys:
        raise FixtureError(code, f"required exact keys {sorted(keys)}")


@dataclass(frozen=True)
class Blob:
    mode: str
    oid: str
    data: bytes


@dataclass(frozen=True)
class GitSnapshot:
    commit: str
    blobs: Mapping[str, Blob]

    @classmethod
    def read(cls, repo: Path, rev: str):
        def git(*args, input=None):
            return subprocess.run(["git", "--no-replace-objects", "-C", str(repo), *args], input=input,
                                  check=True, capture_output=True).stdout
        commit = git("rev-parse", "--verify", f"{rev}^{{commit}}").decode().strip()
        entries = {}
        for row in git("ls-tree", "-r", "-z", commit).split(b"\0"):
            if not row:
                continue
            metadata, raw_path = row.split(b"\t", 1)
            mode, kind, oid = metadata.decode().split()
            path = raw_path.decode("utf-8")
            safe_path(path)
            if kind != "blob":
                entries[path] = (mode, oid, None)
            else:
                entries[path] = (mode, oid, True)
        # Read object ids, never worktree paths: symlink bytes are not followed.
        regular = [(p, oid) for p, (_, oid, blob) in sorted(entries.items()) if blob]
        output = git("cat-file", "--batch", input="".join(oid + "\n" for _, oid in regular).encode())
        blobs, offset = {}, 0
        for path, oid in regular:
            end = output.index(b"\n", offset)
            got_oid, kind, length = output[offset:end].decode().split()
            if got_oid != oid or kind != "blob":
                raise FixtureError("GIT_OBJECT_MISMATCH", path)
            size = int(length)
            data = output[end + 1:end + 1 + size]
            if len(data) != size or output[end + 1 + size:end + 2 + size] != b"\n":
                raise FixtureError("GIT_OBJECT_TRUNCATED", path)
            blobs[path] = Blob(entries[path][0], oid, data)
            offset = end + 2 + size
        if offset != len(output):
            raise FixtureError("GIT_OBJECT_TRAILING", "unexpected object bytes")
        for path, (mode, oid, blob) in entries.items():
            if not blob:
                blobs[path] = Blob(mode, oid, b"")
        return cls(commit, MappingProxyType(blobs))

    def bound(self, declaration: dict) -> Blob:
        exact_keys(declaration, {"path", "git_blob", "sha256"}, "BINDING_SHAPE")
        path = safe_path(declaration["path"])
        blob = self.blobs.get(path)
        if blob is None:
            raise FixtureError("BINDING_MISSING", path)
        if blob.mode != "100644":
            raise FixtureError("NONREGULAR_INPUT", f"{path}: {blob.mode}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(declaration["sha256"])):
            raise FixtureError("DIGEST_INVALID", path)
        if blob.oid != declaration["git_blob"] or digest(blob.data) != declaration["sha256"]:
            raise FixtureError("DIGEST_MISMATCH", path)
        return blob


def validate_inventory(snapshot: GitSnapshot, manifest: dict) -> dict[str, dict]:
    exact_keys(manifest, {"schema", "cases"}, "MANIFEST_SHAPE")
    if manifest["schema"] != "TypedFixtureManifest/v1":
        raise FixtureError("MANIFEST_VERSION", repr(manifest["schema"]))
    if not isinstance(manifest["cases"], list) or not manifest["cases"]:
        raise FixtureError("EMPTY_CASE_INVENTORY", "at least one explicit case is required")
    ids, roots, members, cases = set(), [], {}, {}
    for case in manifest["cases"]:
        exact_keys(case, {"id", "canonical_roots", "members", "closed_inventory_sha256",
                          "checker", "expectation", "independent_witnesses"}, "CASE_SHAPE")
        cid = case["id"]
        if not isinstance(cid, str) or not cid or cid in ids:
            raise FixtureError("CASE_ID_DUPLICATE", repr(cid))
        ids.add(cid)
        exact_keys(case["canonical_roots"], {"base", "head"}, "ROOT_SHAPE")
        for side, root in case["canonical_roots"].items():
            safe_path(root)
            if any(root == old or root.startswith(old + "/") or old.startswith(root + "/") for old in roots):
                raise FixtureError("ROOT_OVERLAP", root)
            roots.append(root)
        if not isinstance(case["members"], list) or not case["members"]:
            raise FixtureError("EMPTY_MEMBER_INVENTORY", cid)
        actual = {p for p in snapshot.blobs if any(p.startswith(root + "/") for root in case["canonical_roots"].values())}
        declared = set()
        for member in case["members"]:
            exact_keys(member, {"side", "path", "context_relative_path", "mode", "git_blob", "sha256"}, "MEMBER_SHAPE")
            side = member["side"]
            if not isinstance(side, str) or side not in case["canonical_roots"]:
                raise FixtureError("SIDE_INVALID", str(side))
            path, relative = safe_path(member["path"]), safe_path(member["context_relative_path"])
            if path != case["canonical_roots"][side] + "/" + relative:
                raise FixtureError("MEMBER_ROOT_MISMATCH", path)
            if path in members or path in declared:
                raise FixtureError("MEMBER_DUPLICATE", path)
            blob = snapshot.bound({k: member[k] for k in ("path", "git_blob", "sha256")})
            if member["mode"] != "100644" or member["mode"] != blob.mode:
                raise FixtureError("MEMBER_MODE_MISMATCH", path)
            declared.add(path)
            members[path] = {"case": cid, "side": side, "root": case["canonical_roots"][side]}
        if actual != declared:
            raise FixtureError("INVENTORY_INCOMPLETE", f"{cid}: unlisted={sorted(actual-declared)}, absent={sorted(declared-actual)}")
        if digest(canonical(sorted(case["members"], key=lambda m: (m["side"], m["path"])))) != case["closed_inventory_sha256"]:
            raise FixtureError("INVENTORY_DIGEST_MISMATCH", cid)
        for key in ("checker", "expectation"):
            snapshot.bound(case[key])
        witnesses = case["independent_witnesses"]
        if not isinstance(witnesses, list) or not witnesses:
            raise FixtureError("INDEPENDENT_WITNESS_MISSING", cid)
        used = {case["checker"]["path"], case["expectation"]["path"]}
        for witness in witnesses:
            snapshot.bound(witness)
            if witness["path"] in used:
                raise FixtureError("WITNESS_ALIAS", witness["path"])
            used.add(witness["path"])
        if used & actual:
            raise FixtureError("CHECKER_SPECIMEN_MIXED_USE", cid)
        cases[cid] = case
    for cid, case in cases.items():
        roles = [case["checker"], case["expectation"], *case["independent_witnesses"]]
        if any(binding["path"] in members for binding in roles):
            raise FixtureError("CHECKER_SPECIMEN_MIXED_USE", cid)
    return {"cases": cases, "members": members}


def retained_witness_bindings(base: GitSnapshot, base_manifest: dict,
                              head: GitSnapshot, head_manifest: dict) -> dict[str, list[dict]]:
    """Retain BASE witnesses for later independent execution, never admission.

    Both inventories are validated against immutable snapshots. HEAD may add
    witnesses, but cannot delete a BASE case, rename an old witness, or change
    its Git/byte identity and bless that edit in its own manifest. This helper
    does not measure containment or execute the retained witness; native
    consumers still need those independent obligations before classification.
    """
    old = validate_inventory(base, base_manifest)["cases"]
    new = validate_inventory(head, head_manifest)["cases"]
    retained = {}
    for cid, case in old.items():
        if cid not in new:
            raise FixtureError("TRUSTED_CASE_REMOVED", cid)
        bindings = {w["path"]: w for w in new[cid]["independent_witnesses"]}
        for witness in case["independent_witnesses"]:
            path = witness["path"]
            if path not in bindings:
                raise FixtureError("TRUSTED_WITNESS_REMOVED", f"{cid}: {path}")
            if bindings[path] != witness:
                raise FixtureError("TRUSTED_WITNESS_CHANGED", f"{cid}: {path}")
        retained[cid] = copy.deepcopy(case["independent_witnesses"])
    return retained


# Only display/revision transport fields are removed; their Git context is bound
# independently by the immutable inventory. Every diagnostic field is retained.
RAW_FIELDS = {"schema", "tool", "tool_version", "repo", "base", "head", "graph", "edge_source",
              "framework_sources", "contracts", "breaking", "edges", "limitations", "summary"}
TRANSPORT_FIELDS = {"commit", "rev", "tree", "dirty"}


def diagnostic_projection(raw: dict) -> dict:
    if not isinstance(raw, dict) or set(raw) not in (RAW_FIELDS, RAW_FIELDS - {"framework_sources"}):
        raise FixtureError("DIAGNOSTIC_SHAPE", "unknown or missing diagnostic field")
    if raw["schema"] != "ContractDiff/v1":
        raise FixtureError("DIAGNOSTIC_VERSION", str(raw["schema"]))
    for side in ("base", "head"):
        if not isinstance(raw[side], dict) or set(raw[side]) - TRANSPORT_FIELDS:
            raise FixtureError("TRANSPORT_FIELD_UNKNOWN", side)
        if raw[side].get("dirty"):
            raise FixtureError("DIRTY_DIAGNOSTIC", side)
    result = copy.deepcopy({k: v for k, v in raw.items() if k not in ("repo", "base", "head")})
    if not isinstance(result["contracts"], dict) or not isinstance(result["edges"], list) or not isinstance(result["breaking"], list):
        raise FixtureError("DIAGNOSTIC_COLLECTION_SHAPE", "contracts/edges/breaking")
    # Sort complete diagnostic objects, retaining duplicates and all fields.
    for key in ("breaking", "edges"):
        result[key] = sorted(result[key], key=canonical)
    for contract in result["contracts"].values():
        if not isinstance(contract, dict) or not isinstance(contract.get("changes"), list):
            raise FixtureError("CONTRACT_SHAPE", "changes are mandatory")
        contract["changes"] = sorted(contract["changes"], key=canonical)
    return result


def compare_diagnostics(expected: dict, actual: dict, raw_exit: int) -> dict:
    """Exact diagnostic comparison only; not a fixture-case or admission verdict."""
    exact_keys(expected, {"schema", "case_id", "raw_exit_status", "projection", "projection_sha256"}, "EXPECTATION_SHAPE")
    if expected["schema"] != "ExactFixtureDiagnostic/v1":
        raise FixtureError("EXPECTATION_VERSION", str(expected["schema"]))
    if type(raw_exit) is not int or type(expected["raw_exit_status"]) is not int or not 0 <= raw_exit <= 255:
        raise FixtureError("EXIT_INVALID", repr(raw_exit))
    if digest(canonical(expected["projection"])) != expected["projection_sha256"]:
        raise FixtureError("EXPECTATION_DIGEST_MISMATCH", expected["case_id"])
    projection = diagnostic_projection(actual)
    matched = canonical(projection) == canonical(expected["projection"]) and raw_exit == expected["raw_exit_status"]
    return {"diagnostic_verdict": "verified" if matched else "failed", "reason": "exact diagnostics reproduced" if matched else "DIAGNOSTIC_MISMATCH",
            "raw_exit_status": raw_exit, "raw_diagnostic_sha256": digest(canonical(actual)),
            "actual_projection_sha256": digest(canonical(projection)), "raw_diagnostics": copy.deepcopy(actual)}


def sample_namespace(case_id: str, root: str, side: str, raw_id: str) -> str:
    safe_path(root)
    if (side not in ("base", "head") or not isinstance(case_id, str) or not case_id
            or not isinstance(raw_id, str) or not raw_id):
        raise FixtureError("NAMESPACE_CONTEXT_INVALID", repr((case_id, side, raw_id)))
    # Reversible encoding, rather than a truncation/collision-prone hash.
    return "sample:" + ":".join(quote(x, safe="") for x in (case_id, root, side, raw_id))


def mandatory_dependencies(manifest_path: str, inventory: dict) -> dict[str, set[str]]:
    """Dependent case -> physical dependencies; native traversal must use reverse edges."""
    safe_path(manifest_path)
    result = {}
    for cid, case in inventory["cases"].items():
        deps = {manifest_path, case["checker"]["path"], case["expectation"]["path"]}
        deps.update(w["path"] for w in case["independent_witnesses"])
        deps.update(m["path"] for m in case["members"])
        result[cid] = deps
    return result


def dependency_union(base: dict[str, set[str]], head: dict[str, set[str]]) -> dict[str, set[str]]:
    return {cid: base.get(cid, set()) | head.get(cid, set()) for cid in base.keys() | head.keys()}


def paired_manifest_dependencies(base: GitSnapshot, head: GitSnapshot,
                                 manifest_path: str) -> dict[str, set[str]]:
    """Read both committed inventories and retain their complete dependencies.

    The caller must select the canonical path from trusted BASE authority.
    Missing/invalid manifests refuse, rather than erase old obligations. This
    helper neither executes witnesses nor grants native classification.
    """
    path = safe_path(manifest_path)

    def read(snapshot):
        blob = snapshot.blobs.get(path)
        if blob is None:
            raise FixtureError("MANIFEST_MISSING", f"{snapshot.commit}: {path}")
        if blob.mode != "100644":
            raise FixtureError("NONREGULAR_INPUT", f"{path}: {blob.mode}")
        return strict_json(blob.data)

    old, new = read(base), read(head)
    old_inventory = validate_inventory(base, old)
    new_inventory = validate_inventory(head, new)
    retained_witness_bindings(base, old, head, new)
    return dependency_union(mandatory_dependencies(path, old_inventory),
                            mandatory_dependencies(path, new_inventory))


def affected_cases(base: dict[str, set[str]], head: dict[str, set[str]], changed_paths: set[str]) -> set[str]:
    """Mandatory complete dependency union; deletion cannot shrink the old set."""
    return {cid for cid, deps in dependency_union(base, head).items() if deps & changed_paths}
