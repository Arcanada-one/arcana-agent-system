"""Revision-bound impact over both sides of a committed change.

Each traversal uses one real graph. Paths never cross revisions. The union selects
verification obligations; it does not manufacture verification results.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import build_graph
import impact
import schema_check

SOURCE_EXTS = impact.CODE_EXTS | {".prisma", ".py", ".rs", ".go", ".java", ".kt", ".cs", ".c", ".cpp", ".h"}


def index_at(repo: impact.Repo, revision: str) -> impact.GraphIndex:
    doc = build_graph.build(repo.path, rev=revision, built_at=build_graph.FIXED_BUILT_AT)
    errors = schema_check.check_graph(doc, schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH))
    if errors:
        raise impact.Refusal("GRAPH_INVALID", "rebuilt revision graph is invalid", {"violations": errors})
    return impact.GraphIndex(doc)


def selected(q: dict) -> set[str]:
    # A global fallback (lockfile / global config) makes the impact the WHOLE REPOSITORY as ONE
    # entity - the Bazel/Nx rule of DEC-AUP-0008 - and its verifier is the repository's own test
    # job. impact.py still lists every node in deterministic_core so a reader can see the blast
    # radius, but those rows ARE the radius, not N separate measurements: enumerating them here
    # demands N verdicts for one measurement, which no receipt can honestly supply.
    # MEASURED on the real subject: muneral #32/#55/#60, where the gate issued
    # AUTOMATED_AUTHOR_RECEIPT_ISSUED - authoring a receipt carrying exactly two verdicts, the
    # repository entity and the missing author - and then paused that same receipt with
    # HEAD_IMPACT_NOT_COVERED over 464 nodes it had itself collapsed into one. Two halves of one
    # gate disagreeing about how many entities a fallback carries.
    if q["impact_set"].get("global_fallback", {}).get("triggered"):
        return set(q["seeds"])
    return set(q["seeds"]) | {e["entity"] for section in ("deterministic_core", "inferred_tail")
                             for e in q["impact_set"][section]}


def query(base_idx: impact.GraphIndex, head_idx: impact.GraphIndex, files: list[dict], *,
          repo: impact.Repo, base: str, head: str, tree_commit: str, tree_dirty: bool,
          max_depth=impact.DEFAULT_MAX_DEPTH, graph_path=None, head_graph_path=None, edge_types=None) -> dict:
    common = dict(mode="diff", base=base, head=head, tree_commit=tree_commit, tree_dirty=tree_dirty,
                  repo=repo, max_depth=max_depth, edge_types=edge_types)
    before = impact.query(base_idx, copy.deepcopy(files), graph_path=graph_path, **common)
    head_files = [f for f in files if f["status"] not in {"D", "R"}]
    # A deletion-only range still binds and checks the head graph, even with no head seeds.
    head_stale = impact.check_staleness(head_idx, repo, "diff", base, tree_commit, tree_dirty,
                                       set(), set(impact.RULES), head=head, graph_role="head")
    after = impact.query(head_idx, copy.deepcopy(head_files), graph_role="head",
                         graph_path=head_graph_path, **common) if head_files else None
    out = copy.deepcopy(before)
    versions = [("base", before)] + ([("head", after)] if after else [])
    entries = {}
    for role, q in versions:
        for section in ("deterministic_core", "inferred_tail"):
            for entry in q["impact_set"][section]:
                entries.setdefault(entry["entity"], []).append((role, section, entry))
    for section in ("deterministic_core", "inferred_tail"):
        out["impact_set"][section] = []
    for entity, paths in sorted(entries.items()):
        # Keep an actual path as the display path and all revision paths as obligations.
        # A boundary inferred in either revision must retain its canary requirement.
        role, section, chosen = max(paths, key=lambda p: (p[1] == "inferred_tail", p[2].get("boundary") in {"repo", "service"}))
        entry = copy.deepcopy(chosen)
        entry["revision_paths"] = [{"revision": r, "section": s, **copy.deepcopy(e)} for r, s, e in paths]
        out["impact_set"][section].append(entry)
    base_files = {f["path"]: f for f in out["change_set"]["files"]}
    for f in (after or {}).get("change_set", {}).get("files", []):
        dest = base_files[f["path"]]
        ids = sorted(set(dest.get("node_ids", [])) | set(f.get("node_ids", [])))
        if ids:
            dest.update(node_ids=ids, node_id=next((i for i in ids if i.startswith("code_unit:")), ids[0]))
            dest.pop("new", None)
            dest.pop("uncovered", None)
    out["seeds"] = sorted(set(before["seeds"]) | set((after or {}).get("seeds", [])))
    out["impact_set"]["total"] = len(entries)
    out["impact_set"]["method"] = "Union of independently revision-bound base/head traversals; " + before["impact_set"]["method"]
    if after and after["impact_set"]["global_fallback"]["triggered"]:
        out["impact_set"]["global_fallback"] = after["impact_set"]["global_fallback"]
    # Never carry a base-only 'new file has no consumers' explanation into a measured head.
    if entries or out["impact_set"]["global_fallback"]["triggered"]:
        out.pop("empty_impact_explanation", None)
        out["events"] = [e for e in out["events"] if e.get("code") != "EMPTY_IMPACT_REQUIRES_EXPLANATION"]
    out["events"] = [{**e, "revision": "base"} for e in out["events"]]
    if after:
        out["events"].extend({**e, "revision": "head"} for e in after["events"]
                             if not (e.get("code") == "EMPTY_IMPACT_REQUIRES_EXPLANATION"
                                     and (entries or out["impact_set"]["global_fallback"]["triggered"])))
    missing = sorted(f["path"] for f in head_files
                     if Path(f["path"]).suffix.lower() in SOURCE_EXTS
                     and not head_idx.path_nodes(f["path"], set(impact.RULES)))
    if missing:
        out["events"].append({"code": "HEAD_CODE_NOT_MEASURED", "files": missing})
    out["head_graph"] = {k: head_idx.manifest[k] for k in ("source_commit", "graph_digest", "builder_version", "built_at_utc")}
    out["head_graph"].update(path=head_graph_path, staleness=head_stale)
    out["stats"].update(seeds=len(out["seeds"]),
                        deterministic_core=len(out["impact_set"]["deterministic_core"]),
                        inferred_tail=len(out["impact_set"]["inferred_tail"]),
                        graph_nodes=len(set(base_idx.nodes) | set(head_idx.nodes)),
                        new_files=missing)
    out["revision_selection"] = {"schema": "RevisionImpactSelection/v1", "base": sorted(selected(before)),
                                 "head": sorted(selected(after)) if after else [], "unmeasured_head_files": missing}
    return out


def receipt_problems(repo_path: Path, doc: dict) -> list[str]:
    """Rebuild from Git, never from receipt node_ids or declared revision selections.

Legacy receipts stay readable, but cannot omit workflow verifier obligations
or admit head obligations absent at base.
A paired receipt must match both graph digests and the complete dual selection.
"""
    cs = doc.get("change_set") or {}
    if cs.get("mode") != "diff":
        return []
    repo = impact.Repo(repo_path)
    base, head = repo.rev(cs["base"]), repo.rev(cs["head"])
    actual = repo.diff_files(base, head)
    paths = {f.get("path") for f in cs.get("files", [])}
    files = [f for f in actual if f["path"] in paths]
    if not files:
        return []  # ordinary file/range binding checks reject unrelated receipts
    before, after = index_at(repo, base), index_at(repo, head)
    selection_config = doc.get("impact_set") or {}
    depth = selection_config.get("max_depth", impact.DEFAULT_MAX_DEPTH)
    edge_types = selection_config.get("edge_types", "all")
    if depth is not None and (isinstance(depth, bool) or not isinstance(depth, int) or depth < 0):
        return ["invalid bound impact depth"]
    if edge_types != "all" and (not isinstance(edge_types, list) or not all(isinstance(t, str) for t in edge_types)):
        return ["invalid bound impact edge types"]
    q = query(before, after, files, repo=repo, base=base, head=head,
              tree_commit=repo.head(), tree_dirty=repo.dirty(), max_depth=depth,
              edge_types=None if edge_types == "all" else set(edge_types))
    selection = q["revision_selection"]
    paired = "revision_selection" in doc or "head_graph" in doc
    new_required = set(selection["head"]) - set(selection["base"])
    workflow_selected = any(
        idx.nodes.get(entity, {}).get("kind") == "workflow_configuration"
        for role, idx in (("base", before), ("head", after))
        for entity in selection[role]
    )
    enforce_mandatory = paired or workflow_selected
    if not enforce_mandatory and not new_required and not selection["unmeasured_head_files"]:
        return []
    problems = []
    if not paired and (new_required or selection["unmeasured_head_files"]):
        problems.append("head graph binding missing for new head impact obligations")
    if paired:
        for field, idx in (("graph", before), ("head_graph", after)):
            binding = doc.get(field) or {}
            if any(binding.get(k) != idx.manifest[k] for k in ("source_commit", "graph_digest")):
                problems.append(field + " revision/digest does not match the rebuilt Git graph")
        if doc.get("revision_selection") != selection:
            problems.append("revision selection differs from independently rebuilt Git impact")
        for section in ("deterministic_core", "inferred_tail"):
            if selection_config.get(section) != q["impact_set"][section]:
                problems.append("revision impact paths differ from independent traversal: " + section)
    expected = set(selection["base"]) | set(selection["head"])
    verdicts = {v.get("entity") for v in doc.get("verdicts", [])}
    missing = sorted(expected - verdicts)
    if missing:
        problems.append("missing selected entity verdicts: " + ", ".join(missing[:12]))
    admitted = (doc.get("admission") or {}).get("verdict") in {"admitted", "admitted_with_exemptions"}
    verification = doc.get("verify") if isinstance(doc.get("verify"), dict) else {}
    required = verification.get("required_by_entity")
    if enforce_mandatory and admitted and required is None:
        problems.append("admitted receipt has no mandatory verifier mapping")
    if required is not None:
        if not isinstance(required, dict) or expected - set(required):
            problems.append("required_by_entity omits independently selected entities")
        else:
            mandatory = mandatory_by_entity(before, after, q)
            if any(not isinstance(required[e], list) or not set(vs) <= set(required[e]) for e, vs in mandatory.items()):
                problems.append("required_by_entity omits mandatory base/head verifier obligations")
    if enforce_mandatory and admitted:
        mandatory = mandatory_by_entity(before, after, q)
        records = {v.get("entity"): v for v in doc.get("verdicts", []) if isinstance(v, dict)}
        verifiers = {v.get("id"): v for v in doc.get("verifiers", []) if isinstance(v, dict)}
        for entity, minimum in mandatory.items():
            record = records.get(entity, {})
            # Existing admission rules still judge failed/not_measured and explicit exemptions.
            if record.get("verdict") != "verified":
                continue
            referenced = [verifiers.get(i, {}) for i in record.get("verifier_ids", [])]
            covered_kinds = {v.get("kind") for v in referenced
                             if entity in v.get("entities", []) and v.get("exit_code") == 0
                             and isinstance(v.get("output_ref"), str) and v["output_ref"].strip()}
            if set(minimum) - covered_kinds:
                problems.append("verified entity lacks referenced mandatory output scope: " + entity)
    if selection["unmeasured_head_files"]:
        problems.append("head code extraction not measured: " + ", ".join(selection["unmeasured_head_files"]))
    return problems


def mandatory_by_entity(before: impact.GraphIndex, after: impact.GraphIndex, q: dict) -> dict[str, list[str]]:
    """The matrix minimum, independent of a producer's supplied requirement arrays."""
    matrix = json.loads((Path(__file__).resolve().parents[2] / "contracts/graph-verified-change/verifier-matrix.v1.json").read_text())
    affected = selected(q)
    changed = set(q["seeds"])
    hops = {e: set() for e in affected}
    for section in ("deterministic_core", "inferred_tail"):
        for e in q["impact_set"][section]:
            # A global fallback makes selected() return the seeds alone, while impact.py still
            # lists the whole graph in deterministic_core as the readable blast radius. Rows
            # outside the selection have no hops entry and are not entities to be verified -
            # they ARE the radius. Skipping them keeps this function agreeing with selected()
            # instead of raising KeyError on the first one (measured: muneral #108).
            if e["entity"] not in hops:
                continue
            for path in e.get("revision_paths", [e]):
                hops[e["entity"]].update(h["edge_type"] for h in path.get("path", []))
    result = {}
    for eid in affected:
        node = after.nodes.get(eid) or before.nodes[eid]
        kinds = hops[eid]
        for idx in (before, after):
            kinds.update(e["type"] for e in idx.fwd.get(eid, []) if e["to"] in affected or eid in changed)
            kinds.update(e["type"] for e in idx.rev.get(eid, []) if e["from"] in affected)
        required = set(matrix["node_types"].get(node["type"], {}).get("mandatory", []))
        required.update(matrix.get("node_kinds", {}).get(node.get("kind"), {}).get("mandatory", []))
        for kind in kinds:
            required.update(matrix["edge_types"].get(kind, {}).get("mandatory", []))
        required = {v for v in required if node["type"] in matrix["verifiers"][v]["applies_to_nodes"]}
        # AUP-GRAPH-009 polyglot2, second site. This function recomputes the matrix minimum
        # independently of verify.py, so the discharge has to exist in BOTH or the gate refuses a
        # receipt the producer issued correctly: measured on scrutator, verify.py dropped the
        # obligation and this one did not, giving `required_by_entity omits mandatory base/head
        # verifier obligations`. `type_check` applies to code_unit, deployable_unit and route; a node
        # that is not TypeScript can never discharge it, whichever of the three it is.
        if node["type"] in ("code_unit", "route") and Path(node.get("path", "")).suffix not in impact.CODE_EXTS:
            required.discard("type_check")
        if node["type"] == "deployable_unit" and not _deployable_has_ts(node.get("path", ""), before, after):
            required.discard("type_check")
        result[eid] = sorted(required)
    return result


def _deployable_has_ts(dep_path: str, before: impact.GraphIndex, after: impact.GraphIndex) -> bool:
    """Does this deployable contain TypeScript, as the graph sees it?

    verify.py reads the tree; here only the two graph indexes are in hand, so membership is decided
    by the nodes that live under the deployable's path. Vendored copies are excluded for the same
    reason as there — a caller does not type-check somebody else's shipped code, and
    `.github/graph-admission/**` is a vendored copy of this very tool.
    """
    prefix = "" if dep_path.rstrip("/") in ("", ".") else dep_path.rstrip("/") + "/"
    for idx in (before, after):
        for n in idx.nodes.values():
            p = n.get("path") or ""
            if not p.startswith(prefix):
                continue
            rel = p[len(prefix):]
            if rel.startswith(".github/graph-admission/") or "node_modules/" in rel or rel.startswith("vendor/"):
                continue
            if Path(rel).suffix in impact.CODE_EXTS:
                return True
    return False
