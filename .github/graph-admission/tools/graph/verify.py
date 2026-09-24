#!/usr/bin/env python3
"""AUP-GRAPH-005 `verify0` — `arcana verify <change-set>`: impact set (GRAPH-003) → mandatory verifiers per edge / node
type from the normative matrix contracts/graph-verified-change/verifier-matrix.v1.json → ChangeAdmissionReceipt/v1
DRAFT with a tri-valued verdict for every affected entity (DEC-AUP-0008).

    verify.py --repo <repo> (--diff <base>..<head> | --worktree | --files p[:S] ...) [--graph <graph.json> | auto]
              [--select targeted_test,property_check] [--profile <VerifyProfile.json>] [--baseline <FitnessBaseline.json>]
              [--tsc <bin>] [--prisma <bin>] [--workdir <dir>] [--out <CAR-draft.json>] [--verifier-out <dir>] [--json]
              [--disable <verifier,...>]            # mutation battery / diagnostics only: recorded as MANDATORY_VERIFIER_DISABLED
    verify.py --repo <repo> --freeze-baseline <out.json> [--rev <rev>] --owner <role> --expires <iso-utc>
    verify.py --selftest [--receipt <ReadinessReceipt.json>] [--tsc <bin>] [--prisma <bin>]
              [--pilot <repo> --pilot-graph <graph.json> --pilot-out <dir> --pilot-commits N]

Semantics (the graph SELECTS verification, it never replaces it — consilium 2026-09-05, DEC-AUP-0008):
  selection   required(entity) = ⋃ matrix.edge_types[t].mandatory over the edge types t of the hops reaching the entity
              in its best impact path and of every edge binding it to another affected entity ∪ matrix.node_types[type].mandatory; a changed node additionally takes the mandatory
              verifiers of its own outgoing edge types at head (its routes, contracts, config keys, models); selectable
              verifiers (targeted_test, property_check) only with --select; applicability filtered by the verifier's
              applies_to_nodes
  verifiers   type_check (tsc --noEmit per deployable, errors attributed by file), contract_diff (GRAPH-004 tool),
              route_config_consistency (RC-01 prefix, RC-02 controller registered under the root module, RC-03 route still
              served), schema_diff (prisma schema-lite diff + prisma validate), config_schema (keys read ⊆ keys declared),
              fitness_rules (FR-01 transport→persistence, FR-02 import cycles, FR-03 module boundary, FR-04 reuse marker
              resolves, FR-05 deployable boundary; frozen baseline + exemption registry), doc_reference (references into
              the change set still resolve), targeted_test (jest / vitest restricted to the specs whose `verifies` edge
              reaches an affected node), property_check (declared per node in the profile)
  verdicts    per entity: failed if any verifier reports failed; not_measured if a required verifier is missing, disabled
              (MANDATORY_VERIFIER_DISABLED) or could not attribute; verified only when every required verifier reports
              verified; an entity reached through an inferred/observed hop across a service/repo boundary stays
              not_measured until a canary lists it (GRAPH-008); receipt / work_item nodes carry the matrix's reason
  admission   admitted only when every verdict is verified; a failed verdict ⇒ refused; not_measured ⇒ paused_safe;
              exemptions are attached by the admitting agent (GRAPH-006), never invented here — the output is a DRAFT
  head tree   worktree mode runs the tool-chain verifiers in the repository itself (nothing is emitted: --noEmit,
              --incremental false); diff mode with head ≠ HEAD exports the head tree with `git archive` into --workdir,
              links the repository's node_modules into it and builds workspace packages there — the repository is
              never written (the pilot clone stays untouched)
Exit codes: 0 draft admitted · 1 draft paused_safe / refused · 2 refusal (impact refusal, STALE_GRAPH, …) · 3 draft
computed with EMPTY_IMPACT_REQUIRES_EXPLANATION raised by impact0.
stdlib only; Python ≥ 3.10. tsc / prisma / jest / vitest are the repository's own binaries (node_modules/.bin), found
through --tsc/--prisma, the profile, or discovery; an absent tool yields not_measured, never verified.
"""
from __future__ import annotations

import workflow_config
import canary_evidence
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import schema_check  # noqa: E402
import build_graph  # noqa: E402
import impact  # noqa: E402
import impact_pair  # noqa: E402
import contract_diff  # noqa: E402

VERSION = "1.0.1"
TOOL = "tools/graph/verify.py"
MATRIX_PATH = ROOT / "contracts" / "graph-verified-change" / "verifier-matrix.v1.json"
FIXTURE_DIR = ROOT / "contracts" / "graph-verified-change" / "fixtures"
TS_MINI = FIXTURE_DIR / "ts-mini"
VFIX = FIXTURE_DIR / "verify"
BASELINE_DIR = ROOT / "contracts" / "graph-verified-change" / "fitness-baseline"
FRAMEWORK_ENV_RE = re.compile(r"^(NODE_ENV|CI|PORT|HOME|PATH|TZ|DEBUG|NO_PROXY|HTTPS?_PROXY|NEXT_.*|__NEXT.*|VERCEL.*|NEXTAUTH_.*|AUTH_.*|WS_NO_.*)$")
ENV_DECL_FILES = [".env.example", ".env.schema", ".env.template", "env.schema.json", ".env.sample"]
TRANSPORT_RE = re.compile(r"\.(controller|gateway|resolver)\.[cm]?[jt]sx?$")
PERSISTENCE_RE = re.compile(r"(^|/)prisma\.service\.[cm]?[jt]s$|\.repository\.[cm]?[jt]s$")
PERSISTENCE_PKGS = {"@prisma/client", "typeorm"}
BOUNDARY_TARGET_RE = re.compile(r"\.(controller|gateway|processor)\.[cm]?[jt]sx?$")
CODE_EXTS = {".ts", ".tsx", ".mts", ".cts"}
TS_ERR_RE = re.compile(r"^(.+?)\((\d+),(\d+)\): error (TS\d+): (.*)$")
# Diagnostics that say the compiler could not FIND something, not that the code is wrong: TS2307
# "Cannot find module", TS2688 "Cannot find type definition file", TS7016 "implicitly has an 'any'
# type because a declaration file could not be found". In a tree whose dependencies were never
# installed these are the whole output and none of them belong to the change (verify.dependency_install_missing).
UNRESOLVED_MODULE_CODES = {"TS2307", "TS2688", "TS7016"}
SHARED_KINDS = {"library", "shared_package"}
MANDATORY_IDS = ["type_check", "contract_diff", "route_config_consistency", "schema_diff", "config_schema", "fitness_rules", "doc_reference",
                 "canary"]
SELECTABLE_IDS = ["targeted_test", "property_check"]
# internal rules the mutation battery disables one at a time
RULES = ["aggregate_failed_wins", "missing_required_not_measured", "disabled_mandatory_event", "inferred_boundary_hold",
         "baseline_expiry", "admission_rule", "every_entity_verdict", "changed_node_outgoing"]


# ----------------------------------------------------------------------------------------------- helpers
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha_text(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def dump(obj) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")


def git(args: list[str], cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def run_cmd(cmd: list[str], cwd: Path, env: dict | None = None, timeout: int = 900) -> tuple[int, str, float]:
    t0 = time.monotonic()
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)
        out = p.stdout + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
        return p.returncode, out, round(time.monotonic() - t0, 2)
    except subprocess.TimeoutExpired as ex:
        return 124, f"TIMEOUT after {timeout}s: {ex}", round(time.monotonic() - t0, 2)
    except FileNotFoundError as ex:
        return 127, f"NOT FOUND: {ex}", round(time.monotonic() - t0, 2)


def rel_ref(p: Path) -> str:
    try:
        return p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(p.resolve())


def load_matrix(path: Path = MATRIX_PATH) -> dict:
    m = json.loads(path.read_text())
    if m.get("schema") != "VerifierMatrix/v1":
        raise SystemExit(f"{path}: not a VerifierMatrix/v1")
    return m


def parse_iso(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


class Refusal(Exception):
    def __init__(self, code: str, reason: str, details=None):
        super().__init__(f"{code}: {reason}")
        self.code, self.reason, self.details = code, reason, details or {}


# ----------------------------------------------------------------------------------------------- head-tree analysis
class TreeScan:
    """Import resolution + light parsing over one tree (the builder's own resolver, no graph needed)."""

    def __init__(self, tree: build_graph.Tree):
        self.tree = tree
        self.b = build_graph.Builder(tree, set(), build_graph.DEFAULT_WORK_ITEM_PATTERN)
        self.b.base()
        self.b.resolve_all()
        self.ts = self.b.ts
        self._type_only: dict[str, set[str]] = {}

    def type_only_specs(self, path: str) -> set[str]:
        if path not in self._type_only:
            f = self.ts.get(path)
            specs = set()
            if f:
                for m in re.finditer(r"""(?:^|[;\n])\s*import\s+type\s+[^;'"]*?from\s*['"]([^'"]+)['"]""", f.code):
                    specs.add(m.group(1))
                for m in re.finditer(r"""(?:^|[;\n])\s*import\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]""", f.code):
                    parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
                    if parts and all(p.startswith("type ") for p in parts):
                        specs.add(m.group(2))
            self._type_only[path] = specs
        return self._type_only[path]

    def value_imports(self, path: str) -> list[str]:
        f = self.ts.get(path)
        if not f:
            return []
        out = []
        tos = self.type_only_specs(path)
        for imp in f.imports:
            r = f.resolved.get(imp["spec"])
            if r and imp["spec"] not in tos and r != path:
                out.append(r)
        return sorted(set(out))

    def external_specs(self, path: str) -> set[str]:
        f = self.ts.get(path)
        if not f:
            return set()
        return {i["spec"] for i in f.imports if i["spec"] not in f.resolved and not i["spec"].startswith(".")}

    def symbol_file(self, path: str, symbol: str) -> str | None:
        f = self.ts.get(path)
        if not f:
            return None
        for imp in f.imports:
            for local, _imported in imp["symbols"]:
                if local == symbol:
                    return f.resolved.get(imp["spec"])
        return None


def config_keys_read(code: str, lang: str = "ts") -> set[str]:
    if lang == "python":
        return {g for m in build_graph.PY_ENV_RE.finditer(code) for g in m.groups() if g}
    if lang == "rust":
        return set(build_graph.RUST_ENV_RE.findall(code))
    keys = set(re.findall(r"process\.env\.([A-Z_][A-Z0-9_]*)", code))
    keys |= set(re.findall(r"""process\.env\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\]""", code))
    keys |= set(re.findall(r"""configService\.get(?:<[^>]*>)?\(\s*['"]([A-Z_][A-Z0-9_]*)['"]""", code))
    return keys


def declared_config_keys(tree: build_graph.Tree, deployable_dirs: list[str], extra_files: list[str]) -> tuple[set[str], list[str]]:
    keys, sources = set(), []
    candidates = list(ENV_DECL_FILES) + list(extra_files)
    dirs = [""] + [d.rstrip("/") + "/" for d in deployable_dirs]
    for d in dirs:
        for name in candidates:
            p = d + name
            if tree.exists(p):
                sources.append(p)
                txt = tree.text(p)
                if p.endswith(".json"):
                    try:
                        doc = json.loads(txt)
                        props = doc.get("properties", doc) if isinstance(doc, dict) else {}
                        keys |= {k for k in props if re.match(r"^[A-Z_][A-Z0-9_]*$", k)}
                    except json.JSONDecodeError:
                        pass
                else:
                    keys |= set(re.findall(r"^\s*(?:export\s+)?#?\s*([A-Z_][A-Z0-9_]*)\s*=", txt, re.M))
    for p in tree.paths:
        if re.match(r"^(docker-compose[\w.-]*\.ya?ml|compose[\w.-]*\.ya?ml)$", os.path.basename(p)) and p.count("/") <= 1:
            sources.append(p)
            keys |= set(re.findall(r"^\s*-?\s*([A-Z_][A-Z0-9_]*)\s*[:=]", tree.text(p), re.M))
    return keys, sorted(set(sources))


# ---- prisma schema-lite
def prisma_lite(text: str) -> dict:
    code = re.sub(r"//[^\n]*", "", text)
    out = {"models": {}, "enums": {}, "parse_errors": []}
    depth = 0
    for m in re.finditer(r"\b(model|enum)\s+(\w+)\s*\{", code):
        start = m.end()
        i, depth = start, 1
        while i < len(code) and depth:
            depth += {"{": 1, "}": -1}.get(code[i], 0)
            i += 1
        if depth:
            out["parse_errors"].append(f"unbalanced block {m.group(1)} {m.group(2)}")
            break
        body = code[start:i - 1]
        if m.group(1) == "enum":
            out["enums"][m.group(2)] = sorted(w for w in re.findall(r"^\s*(\w+)\s*$", body, re.M))
            continue
        fields = {}
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("@@"):
                continue
            fm = re.match(r"^(\w+)\s+(\w+)(\[\])?(\?)?\s*(.*)$", line)
            if not fm:
                continue
            attrs = fm.group(5)
            fields[fm.group(1)] = {"type": fm.group(2), "list": bool(fm.group(3)), "optional": bool(fm.group(4)),
                                   "default": "@default(" in attrs, "relation": "@relation(" in attrs, "id": "@id" in attrs}
        out["models"][m.group(2)] = fields
    if code.count("{") != code.count("}"):
        out["parse_errors"].append("unbalanced braces in schema")
    return out


def prisma_diff(base: dict, head: dict) -> dict:
    changes: dict[str, list[dict]] = {}

    def add(model, code, sev, detail, field=None):
        changes.setdefault(model, []).append({"code": code, "severity": sev, "detail": detail, "field": field})

    for name in sorted(set(base["models"]) | set(head["models"])):
        b, h = base["models"].get(name), head["models"].get(name)
        if b is None:
            add(name, "MODEL_ADDED", "compatible", "model added")
            continue
        if h is None:
            add(name, "MODEL_REMOVED", "breaking", "model removed")
            continue
        for f in sorted(set(b) | set(h)):
            fb, fh = b.get(f), h.get(f)
            if fb is None:
                if fh["optional"] or fh["default"] or fh["list"]:
                    add(name, "FIELD_ADDED_OPTIONAL", "compatible", f"field {f} added (optional / default / list)", f)
                else:
                    add(name, "NEW_REQUIRED_FIELD_WITHOUT_DEFAULT", "breaking", f"required field {f} added without default", f)
                continue
            if fh is None:
                add(name, "FIELD_REMOVED", "breaking", f"field {f} removed", f)
                continue
            if fb["type"] != fh["type"] or fb["list"] != fh["list"]:
                add(name, "FIELD_TYPE_CHANGED", "breaking", f"field {f}: {fb['type']}{'[]' if fb['list'] else ''} → {fh['type']}{'[]' if fh['list'] else ''}", f)
            if fb["optional"] and not fh["optional"]:
                add(name, "FIELD_MADE_REQUIRED", "breaking", f"field {f} optional → required", f)
            elif not fb["optional"] and fh["optional"]:
                add(name, "FIELD_MADE_OPTIONAL", "compatible", f"field {f} required → optional", f)
            if fb["relation"] != fh["relation"]:
                add(name, "RELATION_CHANGED", "breaking", f"field {f}: relation attribute changed", f)
    for name in sorted(set(base["enums"]) | set(head["enums"])):
        b, h = base["enums"].get(name), head["enums"].get(name)
        if b is None:
            add(name, "ENUM_ADDED", "compatible", "enum added")
        elif h is None:
            add(name, "ENUM_REMOVED", "breaking", "enum removed")
        else:
            rem, addv = sorted(set(b) - set(h)), sorted(set(h) - set(b))
            if rem:
                add(name, "ENUM_VALUE_REMOVED", "breaking", f"values removed: {', '.join(rem)}")
            if addv:
                add(name, "ENUM_VALUE_ADDED", "compatible", f"values added: {', '.join(addv)}")
    return changes


# ---- NestJS module reachability (RC-02)
def module_meta(code: str) -> dict[str, list[str]]:
    """identifiers listed in imports: / controllers: / providers: of every @Module({...}) in the file."""
    out = {"imports": [], "controllers": [], "providers": []}
    for m in re.finditer(r"@Module\s*\(\s*\{", code):
        i, depth = m.end(), 1
        while i < len(code) and depth:
            depth += {"{": 1, "}": -1}.get(code[i], 0)
            i += 1
        body = code[m.end():i - 1]
        for key in out:
            km = re.search(r"\b" + key + r"\s*:\s*\[", body)
            if not km:
                continue
            j, d = km.end(), 1
            while j < len(body) and d:
                d += {"[": 1, "]": -1}.get(body[j], 0)
                j += 1
            inner = body[km.end():j - 1]
            out[key] += re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b(?=\s*(?:,|$|\.|\]|\())", inner)
    return out


def nest_registered_files(scan: TreeScan, root_file: str) -> tuple[set[str], list[str]]:
    """Files whose classes are registered (controllers/providers) in modules reachable from NestFactory.create(X)."""
    f = scan.ts.get(root_file)
    if not f:
        return set(), ["root file not found"]
    m = re.search(r"NestFactory\.create(?:<[^>]*>)?\(\s*([A-Z][A-Za-z0-9_]*)", f.code)
    if not m:
        return set(), ["no NestFactory.create in root file"]
    root_mod = scan.symbol_file(root_file, m.group(1))
    if not root_mod:
        return set(), [f"root module {m.group(1)} not resolved"]
    seen_modules, registered, notes = set(), set(), []
    stack = [root_mod]
    while stack:
        mod = stack.pop()
        if mod in seen_modules:
            continue
        seen_modules.add(mod)
        tf = scan.ts.get(mod)
        if not tf:
            continue
        meta = module_meta(tf.code)
        for ident in meta["imports"]:
            tgt = scan.symbol_file(mod, ident)
            if tgt and tgt not in seen_modules:
                stack.append(tgt)
        for ident in meta["controllers"] + meta["providers"]:
            tgt = scan.symbol_file(mod, ident)
            if tgt:
                registered.add(tgt)
            elif re.search(r"\bclass\s+" + re.escape(ident) + r"\b", tf.code):
                registered.add(mod)
    notes.append(f"{len(seen_modules)} modules reachable from {root_mod}")
    return registered, notes


# ----------------------------------------------------------------------------------------------- fitness rules
def deployable_of(path: str, deployables: dict[str, dict]) -> str | None:
    best = None
    for d in deployables:
        dd = d.rstrip("/")
        rank = 0 if dd in ("", ".") else len(dd)
        best_rank = 0 if best in ("", ".") else len(best or "")
        if (dd in ("", ".") or path.startswith(dd + "/")) and (best is None or rank > best_rank):
            best = dd
    return best


def module_of(path: str, dep: str | None) -> str | None:
    if dep is None:
        return None
    rest = path if dep in ("", ".") else path[len(dep) + 1:]
    m = re.match(r"^src/([^/]+)/", rest)
    return m.group(1) if m else None


def type_project_of(path: str, deployables: dict[str, dict], tree: build_graph.Tree) -> str | None:
    """A root tooling tsconfig can own checks without being a runtime deployable.

    This selects a compiler project, not a graph owner or a verified verdict:
    v_type_check still requires the compiler's actual --listFiles membership.
    """
    dep = deployable_of(path, deployables)
    return "." if dep is None and tree.exists("tsconfig.json") else dep


def tarjan_scc(nodes: list[str], adj: dict[str, list[str]]) -> list[list[str]]:
    index, low, on, stack, out, counter = {}, {}, set(), [], [], [0]

    def strong(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        for w in adj.get(v, []):
            if w not in index:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1:
                out.append(sorted(comp))

    sys.setrecursionlimit(max(10000, sys.getrecursionlimit()))
    for v in nodes:
        if v not in index:
            strong(v)
    return sorted(out)


def fitness_violations(graph: dict, tree: build_graph.Tree, scan: TreeScan, rules_on: set[str]) -> list[dict]:
    nodes = {n["id"]: n for n in graph["nodes"]}
    deployables = {n["path"].rstrip("/"): n for n in graph["nodes"] if n["type"] == "deployable_unit" and n.get("path")}
    pkg_json: dict[str, dict] = {}
    for d in [""] + list(deployables):
        p = (d + "/package.json") if d not in ("", ".") else "package.json"
        if tree.exists(p):
            try:
                pkg_json[d] = json.loads(tree.text(p))
            except json.JSONDecodeError:
                pkg_json[d] = {}
    workspace_pkgs = {n.get("symbol") for n in graph["nodes"] if n["type"] == "deployable_unit"}
    for p in tree.paths:
        if re.match(r"^packages/[^/]+/package\.json$", p):
            try:
                workspace_pkgs.add(json.loads(tree.text(p)).get("name"))
            except json.JSONDecodeError:
                pass
    viol: list[dict] = []

    def add(rule, entity, detail, key):
        viol.append({"verifier": "fitness_rules", "rule": rule, "entity": entity, "detail": detail,
                     "fingerprint": sha_text(f"fitness_rules|{rule}|{entity}|{key}")})

    imports = [e for e in graph["edges"] if e["type"] == "imports" and e["provenance"] == "deterministic"]
    for e in imports:
        fp, tp = nodes[e["from"]].get("path"), nodes[e["to"]].get("path")
        if not fp:
            continue
        if e.get("via") == "reuse-marker":
            if "fr04" in rules_on:
                pkg = nodes[e["to"]].get("symbol") or e["to"].split(":", 1)[1]
                dep = deployable_of(fp, deployables)
                declared = False
                for d in (dep or "", ""):
                    pj = pkg_json.get(d, {})
                    for sec in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                        if pkg in (pj.get(sec) or {}):
                            declared = True
                if pkg in workspace_pkgs:
                    declared = True
                if not declared:
                    add("FR-04", e["from"], f"reuse marker names {pkg}, which is neither a dependency of {dep or 'the root'} nor a workspace package", pkg)
            continue
        if not tp:
            continue
        if "fr01" in rules_on and TRANSPORT_RE.search(fp) and PERSISTENCE_RE.search(tp):
            add("FR-01", e["from"], f"transport unit imports persistence unit {tp}", tp)
        dep_f, dep_t = deployable_of(fp, deployables), deployable_of(tp, deployables)
        if "fr03" in rules_on and dep_f and dep_f == dep_t:
            mf, mt = module_of(fp, dep_f), module_of(tp, dep_t)
            if mf and mt and mf != mt and BOUNDARY_TARGET_RE.search(tp):
                add("FR-03", e["from"], f"module {mf} imports {tp} of module {mt} (controller / gateway / processor are not a module's exported surface)", tp)
        if "fr05" in rules_on and dep_f and dep_t and dep_f != dep_t and deployables[dep_t].get("kind") not in SHARED_KINDS:
            add("FR-05", e["from"], f"deployable {dep_f} imports {tp} of deployable {dep_t} ({deployables[dep_t].get('kind')})", tp)
    if "fr01" in rules_on:
        for path, f in scan.ts.items():
            if TRANSPORT_RE.search(path):
                ext = scan.external_specs(path) & PERSISTENCE_PKGS
                for pkg in sorted(ext):
                    add("FR-01", f"code_unit:{path}", f"transport unit imports persistence package {pkg}", pkg)
    if "fr02" in rules_on:
        by_dep: dict[str, list[str]] = {}
        for path in scan.ts:
            d = deployable_of(path, deployables)
            if d:
                by_dep.setdefault(d, []).append(path)
        for d, paths in sorted(by_dep.items()):
            ps = set(paths)
            adj = {p: [t for t in scan.value_imports(p) if t in ps] for p in sorted(paths)}
            for comp in tarjan_scc(sorted(paths), adj):
                for member in comp:
                    add("FR-02", f"code_unit:{member}", "import cycle: " + " → ".join(comp) + " → " + comp[0], "|".join(comp))
    viol.sort(key=lambda v: (v["rule"], v["entity"], v["detail"]))
    return viol


def vendored_paths(graph: dict) -> dict[str, str]:
    """{path → owning repository} for every node the builder marked as vendored foreign code (gate3b, hole H7).

    A vendored `GraphAdmissionBundle/v1` copy is the PROGRAM's code sitting in a caller's tree. `config_schema`
    asks "are the keys this repository reads declared by this repository?" — a question about the OWNER of the
    file. Asking it of foreign code makes the caller declare the program's environment (`AUP_SKIP_RECEIPT`,
    `MUNERAL_API_KEY`, `RUNNER_TEMP`), which the caller never reads. The nodes and their `reads_config` edges
    are untouched; only the attribution changes, and the skip is REPORTED, never silent.
    """
    out: dict[str, str] = {}
    for n in graph.get("nodes", []):
        a = n.get("attrs") or {}
        if a.get("vendored") and n.get("path"):
            out[n["path"]] = a.get("vendored_from") or "unknown"
    return out


def config_violations(graph: dict, tree: build_graph.Tree, scan: TreeScan, extra_files: list[str]) -> tuple[list[dict], set[str], list[str], dict]:
    deployables = [n["path"] for n in graph["nodes"] if n["type"] == "deployable_unit" and n.get("path")]
    declared, sources = declared_config_keys(tree, deployables, extra_files)
    viol = []
    vendored = vendored_paths(graph)
    skipped: dict[str, dict] = {}

    def note_vendored(path: str, keys: set[str]) -> bool:
        """True when `path` is foreign code. Records what was NOT attributed, so the skip is auditable."""
        if path not in vendored:
            return False
        if keys:
            rec = skipped.setdefault(vendored[path], {"owner": vendored[path], "files": [], "keys": set()})
            rec["files"].append(path)
            rec["keys"] |= keys
        return True

    if not sources:
        return viol, declared, sources, {}
    for path, f in sorted(scan.ts.items()):
        undeclared = {k for k in config_keys_read(f.code) if k not in declared and not FRAMEWORK_ENV_RE.match(k)}
        if note_vendored(path, undeclared):
            continue
        for k in sorted(config_keys_read(f.code)):
            if k in declared or FRAMEWORK_ENV_RE.match(k):
                continue
            viol.append({"verifier": "config_schema", "rule": "UNDECLARED_CONFIG_KEY", "entity": f"code_unit:{path}",
                         "detail": f"reads {k}, declared in none of {', '.join(sources)}", "key": k,
                         "fingerprint": sha_text(f"config_schema|UNDECLARED_CONFIG_KEY|code_unit:{path}|{k}")})
    # AUP-GRAPH-009 polyglot1: config_schema was TS-only (scan.ts, populated only for CODE_EXT) — a Python/Rust
    # config_key read was never checked against the declared set at all, so it fell through to whatever verdict
    # the (empty) violation list implied, not a real check. Scan the tree directly for the two extractors that
    # build_graph.py already gives a reads_config edge to.
    for path in sorted(tree.paths):
        if path.endswith(build_graph.PY_EXT):
            lang, code = "python", build_graph.strip_comments_python(tree.text(path))
        elif path.endswith(build_graph.RUST_EXT):
            lang, code = "rust", build_graph.strip_comments_rust(tree.text(path))
        else:
            continue
        undeclared = {k for k in config_keys_read(code, lang) if k not in declared and not FRAMEWORK_ENV_RE.match(k)}
        if note_vendored(path, undeclared):
            continue
        for k in sorted(config_keys_read(code, lang)):
            if k in declared or FRAMEWORK_ENV_RE.match(k):
                continue
            viol.append({"verifier": "config_schema", "rule": "UNDECLARED_CONFIG_KEY", "entity": f"code_unit:{path}",
                         "detail": f"reads {k}, declared in none of {', '.join(sources)}", "key": k,
                         "fingerprint": sha_text(f"config_schema|UNDECLARED_CONFIG_KEY|code_unit:{path}|{k}")})
    report = {owner: {"owner": r["owner"], "files": sorted(r["files"]), "keys": sorted(r["keys"])}
              for owner, r in sorted(skipped.items())}
    return viol, declared, sources, report


# ----------------------------------------------------------------------------------------------- baseline
def make_baseline(repo_name: str, commit: str, entries: list[dict], owner: str, expires: str, mode: str) -> dict:
    return {"schema": "FitnessBaseline/v1", "repo": repo_name, "frozen_at_commit": commit, "frozen_at_utc": now_iso(),
            "mode": mode, "owner": owner, "expires_at_utc": expires, "decision_ref": "DEC-AUP-0008",
            "rule": "entries are pre-existing findings frozen at frozen_at_commit; they are reported and not counted while the "
                    "baseline is unexpired; a finding not in the baseline is new and fails its entity; exemptions carry owner + expiry",
            "entries": [{k: v for k, v in e.items() if k in ("verifier", "rule", "entity", "detail", "fingerprint")} for e in entries],
            "exemptions": []}


def resolve_baseline(a, repo_top: Path, repo_name: str) -> tuple[dict | None, str]:
    if getattr(a, "baseline", None) == "auto":
        return None, ""    # force the per-run freeze at base (historical replays: the registry is frozen at HEAD, not at their parent)
    if getattr(a, "baseline", None):
        return json.loads(Path(a.baseline).read_text()), str(a.baseline)
    local = repo_top / ".arcana" / "fitness-baseline.json"
    if local.is_file():
        return json.loads(local.read_text()), str(local)
    prog = BASELINE_DIR / (repo_name.replace("/", "__") + ".v1.json")
    if prog.is_file():
        return json.loads(prog.read_text()), rel_ref(prog)
    return None, ""


# ----------------------------------------------------------------------------------------------- profile / toolchain
def load_profile(a, repo_top: Path) -> tuple[dict, str]:
    if getattr(a, "profile", None):
        return json.loads(Path(a.profile).read_text()), str(a.profile)
    local = repo_top / ".arcana" / "verify.json"
    if local.is_file():
        return json.loads(local.read_text()), str(local)
    return {"schema": "VerifyProfile/v1", "deployables": {}, "auto": True}, "(auto-detected)"


def find_bin(name: str, explicit: str | None, exec_root: Path, repo_top: Path, deployable_dirs: list[str]) -> str | None:
    if explicit:
        return explicit if Path(explicit).is_file() else None
    for base in (exec_root, repo_top):
        for d in [""] + deployable_dirs:
            p = base / d / "node_modules" / ".bin" / name
            if p.is_file():
                return str(p)
    return shutil.which(name)


# ----------------------------------------------------------------------------------------------- the runner
class Verify:
    def __init__(self, a, matrix: dict):
        self.a = a
        self.matrix = matrix
        self.disabled = {x.strip() for x in (getattr(a, "disable", "") or "").split(",") if x.strip()}
        self.selected = {x.strip() for x in (getattr(a, "select", "") or "").split(",") if x.strip()}
        self.rules = set(RULES) - {x.strip() for x in (getattr(a, "disable_rule", "") or "").split(",") if x.strip()}
        self.fr_rules = {"fr01", "fr02", "fr03", "fr04", "fr05", "rc01", "rc02", "rc03"} - \
            {x.strip() for x in (getattr(a, "disable_rule", "") or "").split(",") if x.strip()}
        unknown = (self.disabled | self.selected) - set(MANDATORY_IDS) - set(SELECTABLE_IDS)
        if unknown:
            raise SystemExit(f"unknown verifier(s): {sorted(unknown)}")
        self.captured_at = now_iso()
        self.repo = impact.Repo(Path(a.repo))
        self.top = self.repo.top
        self.workdir = Path(a.workdir) if a.workdir else Path(os.environ.get("TMPDIR", "/tmp")) / "arcana-verify"
        self.workdir.mkdir(parents=True, exist_ok=True)
        # Captured verifier output and the two graph dumps go to the WORKDIR, never beside the receipt.
        # The old default was `<out>.d/` — so `--out receipts/graph/car.json` dropped `car.d/` into the
        # repository's own receipts directory: two files of ~155k lines each, which then get committed
        # by mistake (A2-229 had to route them out of the tree by hand). A receipt is a document; its
        # working scratch is not, and the tool must not make the author remember the difference.
        self.out_dir = Path(a.verifier_out) if a.verifier_out else self.workdir / "verifier-out"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.profile, self.profile_ref = load_profile(a, self.top)
        self.events: list[dict] = []
        self.notes: list[str] = []
        self.verifiers: list[dict] = []
        self.ev: dict[str, dict[str, tuple[str, str]]] = {}   # verifier id → entity → (verdict, reason)
        self.canary_paths = list(getattr(a, "canary", None) or [])   # CanaryResult/v1 documents (AUP-GRAPH-008)
        self.canary_verified: set[str] = set()
        self.prep_seconds = 0.0
        # DEC-AUP-0035. WHERE this run's receipt is going, expressed relative to the repository, and
        # for which work item. Both are needed to recognise the one entity a receipt can never
        # verify: the previous version of itself. `--out` outside the tree yields None, and that
        # case records a note rather than quietly behaving like a match.
        self.work_item = getattr(a, "work_item", None) or None
        self.self_receipt_rel: str | None = None
        if getattr(a, "out", None):
            try:
                self.self_receipt_rel = Path(a.out).resolve().relative_to(self.top).as_posix()
            except ValueError:
                self.self_receipt_rel = None

    # ---- change set + impact
    def impact_query(self) -> dict:
        a = self.a
        mode = "diff" if a.diff else "worktree"
        tree_commit, tree_dirty = self.repo.head(), self.repo.dirty()
        base = head = None
        if a.diff:
            b, _, h = a.diff.partition("..")
            base, head = self.repo.rev(b), self.repo.rev(h or "HEAD")
            files = self.repo.diff_files(base, head)
        elif a.files:
            files = impact.parse_file_args(a.files)
        else:
            files = self.repo.worktree_files()
        self.mode, self.base, self.head = mode, base, head
        if a.graph and a.graph != "auto":
            self.graph_path = str(a.graph)
            self.idx = impact.load_graph(Path(a.graph), set(impact.RULES))
        else:
            rev = base if mode == "diff" else tree_commit
            doc = build_graph.build(self.top, rev=rev, built_at=build_graph.FIXED_BUILT_AT)
            gp = self.out_dir / f"graph-{rev[:12]}.json"
            gp.write_bytes(build_graph.dump_graph(doc))
            self.graph_path = rel_ref(gp)
            self.idx = impact.load_graph(gp, set(impact.RULES))
        if mode == "diff":
            self.pair_head_idx = impact_pair.index_at(self.repo, head)
            hp = self.out_dir / f"graph-head-{head[:12]}.json"
            hp.write_bytes(build_graph.dump_graph(self.pair_head_idx.doc))
            return impact_pair.query(self.idx, self.pair_head_idx, files, repo=self.repo, base=base, head=head,
                                     tree_commit=tree_commit, tree_dirty=tree_dirty, graph_path=self.graph_path,
                                     head_graph_path=rel_ref(hp),
                                     max_depth=None if a.max_depth is not None and a.max_depth < 0 else (a.max_depth if a.max_depth is not None else impact.DEFAULT_MAX_DEPTH))
        q = impact.query(self.idx, files, mode=mode, base=base, head=head, tree_commit=tree_commit, tree_dirty=tree_dirty,
                         repo=self.repo, max_depth=None if a.max_depth is not None and a.max_depth < 0 else (a.max_depth if a.max_depth is not None else impact.DEFAULT_MAX_DEPTH),
                         rules=set(impact.RULES), graph_path=self.graph_path)
        return q

    # ---- head tree / exec root
    def prepare_head(self):
        t0 = time.monotonic()
        if self.mode == "worktree":
            self.tree_head = build_graph.load_tree_worktree(self.top)
            self.exec_root = self.top
            self.exported = False
        else:
            self.tree_head = build_graph.load_tree_git(self.top, self.head, "")
            if self.head == self.repo.head() and not self.repo.dirty():
                self.exec_root = self.top
                self.exported = False
            else:
                self.exec_root = self.export_head()
                self.exported = True
        self.tree_base = build_graph.load_tree_git(self.top, self.base, "") if self.mode == "diff" else \
            build_graph.load_tree_git(self.top, self.repo.head(), "")
        self.graph_head = build_graph.build(self.top, worktree=True, built_at=build_graph.FIXED_BUILT_AT) if self.mode == "worktree" \
            else build_graph.build(self.top, rev=self.head, built_at=build_graph.FIXED_BUILT_AT)
        self.scan_head = TreeScan(self.tree_head)
        self.head_nodes = {n["id"]: n for n in self.graph_head["nodes"]}
        self.head_rev: dict[str, list[dict]] = {}
        self.head_fwd: dict[str, list[dict]] = {}
        for e in self.graph_head["edges"]:
            self.head_rev.setdefault(e["to"], []).append(e)
            self.head_fwd.setdefault(e["from"], []).append(e)
        self.deployables = {n["path"].rstrip("/"): n for n in self.graph_head["nodes"] if n["type"] == "deployable_unit" and n.get("path")}
        for n in self.idx.doc["nodes"]:
            if n["type"] == "deployable_unit" and n.get("path"):
                self.deployables.setdefault(n["path"].rstrip("/"), n)
        self.prep_seconds += round(time.monotonic() - t0, 2)

    def export_head(self) -> Path:
        dest = self.workdir / f"export-{self.head[:12]}"
        if not (dest / ".arcana-export-ok").exists():
            if dest.exists():
                shutil.rmtree(dest)
            dest.mkdir(parents=True)
            tar = subprocess.run(["git", "archive", "--format=tar", self.head], cwd=self.top, check=True, capture_output=True).stdout
            subprocess.run(["tar", "-x", "-C", str(dest)], input=tar, check=True)
            linked = []
            for d in [""] + sorted(p for p in (self.tree_head.paths) if p.endswith("/package.json") and p.count("/") <= 2):
                d = d[:-len("/package.json")] if d.endswith("/package.json") else d
                src = self.top / d / "node_modules"
                tgt = dest / d / "node_modules"
                if src.is_dir() and not tgt.exists():
                    tgt.symlink_to(src, target_is_directory=True)
                    linked.append(d or ".")
            built = []
            for d in sorted(self.tree_head.paths):
                if re.match(r"^packages/[^/]+/tsconfig\.json$", d):
                    pdir = dest / os.path.dirname(d)
                    tsc = find_bin("tsc", self.a.tsc, dest, self.top, [os.path.dirname(d)])
                    if tsc:
                        rc, out, secs = run_cmd([tsc, "-p", "tsconfig.json"], pdir)
                        built.append(f"{os.path.dirname(d)} (tsc exit {rc}, {secs}s)")
            (dest / ".arcana-export-ok").write_text(json.dumps({"head": self.head, "node_modules_linked": linked, "packages_built": built}))
        info = json.loads((dest / ".arcana-export-ok").read_text())
        self.notes.append(f"head tree {self.head[:12]} exported with git archive into {dest} (node_modules linked from the repository for "
                          f"{info['node_modules_linked']}; workspace packages built: {info['packages_built'] or 'none'}); the repository was not written")
        return dest

    # ---- entities + selection
    def collect_entities(self, q: dict):
        imp = q["impact_set"]
        self.entities: dict[str, dict] = {}
        # A global fallback (lockfile / global config) makes the impact the WHOLE REPOSITORY as ONE
        # entity - the Bazel/Nx rule of DEC-AUP-0008 - and its verifier is the repository's own test
        # job. impact.py still lists every node in deterministic_core so a reader can see the blast
        # radius, and the receipt keeps that listing; but those rows ARE the radius, not N separate
        # measurements. Enumerating them here creates one entity, and therefore one demanded
        # verdict, per row - which is how the gate came to pause a receipt it had issued itself
        # (measured on muneral #108: selected() 8 entities against 466 verdicts, 151 of them
        # not_measured, PAUSED_SAFE). selected() and mandatory_by_entity() already honour the flag;
        # this is the same disagreement at its source.
        # `q["seeds"]` is exactly what impact_pair.selected() returns under a triggered fallback;
        # read it directly rather than importing that module for one predicate.
        selection = set(q["seeds"]) if imp.get("global_fallback", {}).get("triggered") else None
        for section in ("deterministic_core", "inferred_tail"):
            for e in imp[section]:
                if selection is not None and e["entity"] not in selection:
                    continue
                hops = [h for p in e.get("revision_paths", [e]) for h in (p.get("path") or [])]
                ent = {"id": e["entity"], "section": section, "hop_types": sorted({h["edge_type"] for h in hops}),
                       "inferred_boundary": any(h.get("provenance") in ("inferred", "observed") for h in hops) and e.get("boundary") in ("service", "repo"),
                       "node": self.head_nodes.get(e["entity"]) or self.idx.nodes.get(e["entity"]) or {"id": e["entity"], "type": e.get("node_type") or e["entity"].split(":", 1)[0]}}
                self.entities.setdefault(e["entity"], ent)
        for f in q["change_set"]["files"]:
            for nid in (f.get("node_ids") or ([f["node_id"]] if f.get("node_id") else [])):
                if nid in self.entities:
                    self.entities[nid]["changed"] = True
                    self.entities[nid]["status"] = f["status"]
                    continue
                node = self.head_nodes.get(nid) or self.idx.nodes.get(nid) or {"id": nid, "type": nid.split(":", 1)[0], "path": f["path"]}
                self.entities[nid] = {"id": nid, "section": "changed", "hop_types": [], "inferred_boundary": False, "node": node,
                                      "changed": True, "status": f["status"]}
        # selection widening: the impact path keeps one best hop per entity; every edge that binds an affected entity to
        # another affected / changed entity selects its verifiers too (never fewer verifiers than the graph relates)
        affected = set(self.entities)
        for eid, ent in self.entities.items():
            types = set(ent["hop_types"])
            for e in self.idx.fwd.get(eid, []) + self.head_fwd.get(eid, []):
                if e["to"] in affected:
                    types.add(e["type"])
            for e in self.idx.rev.get(eid, []) + self.head_rev.get(eid, []):
                if e["from"] in affected:
                    types.add(e["type"])
            ent["hop_types"] = sorted(types)
        m = self.matrix
        for ent in self.entities.values():
            ntype = ent["node"]["type"]
            req = set(m["node_types"].get(ntype, {}).get("mandatory", []))
            req |= set(m.get("node_kinds", {}).get(ent["node"].get("kind"), {}).get("mandatory", []))
            for t in ent["hop_types"]:
                req |= set(m["edge_types"].get(t, {}).get("mandatory", []))
            if ent.get("changed") and "changed_node_outgoing" in self.rules:
                for e in self.head_fwd.get(ent["id"], []) + [x for x in self.idx.doc["edges"] if x["from"] == ent["id"]]:
                    req |= set(m["edge_types"].get(e["type"], {}).get("mandatory", []))
            req = {v for v in req if ntype in m["verifiers"][v]["applies_to_nodes"]}
            # AUP-GRAPH-009 polyglot2. `type_check` applies to three node types (code_unit,
            # deployable_unit, route) but the "this file is not TypeScript" discharge existed for ONE
            # of them. The same fact was answered two different ways: a non-TS code_unit had the
            # requirement dropped, while a deployable unit kept it and could only ever record
            # `no tsconfig for deployable`, and a Python route recorded `type_check produced no
            # verdict`. Both are permanent: nothing an author can do in a Python or Rust repository
            # produces a tsc verdict, so the change is pinned at paused_safe for good — which is
            # exactly the pressure that makes someone substitute a `kind: other` verifier, and the
            # gate rightly refuses that. Measured on Arcanada-one/scrutator (1.78MB Python, zero TS):
            # deployable_unit:. not_measured, admission paused_safe, permanently.
            #
            # A MISSING tsconfig is NOT the same fact and keeps its not_measured: such a deployable
            # holds TypeScript the compiler was never pointed at, which is a real coverage gap. So
            # the discriminator is the tree, never the absence of a config file.
            if ntype in ("code_unit", "route") and not self.is_ts(ent["node"].get("path", "")):
                req.discard("type_check")
            if ntype == "deployable_unit" and not self.deployable_has_ts(ent["node"].get("path", "")):
                req.discard("type_check")
            for s in self.selected:
                if ntype in m["verifiers"][s]["applies_to_nodes"]:
                    req.add(s)
            ent["required"] = sorted(req)
        self.disabled_hits = sorted(v for v in self.disabled if any(v in e["required"] for e in self.entities.values()))
        if self.disabled_hits and "disabled_mandatory_event" in self.rules:
            self.events.append({"code": "MANDATORY_VERIFIER_DISABLED", "verifiers": self.disabled_hits,
                                "reason": "a mandatory verifier was disabled on the command line; the entities it covers are not_measured and the draft cannot be admitted"})

    @staticmethod
    def is_ts(path: str) -> bool:
        return os.path.splitext(path)[1] in CODE_EXTS or path.endswith((".js", ".mjs", ".cjs", ".jsx"))

    def deployable_has_ts(self, dep_path: str) -> bool:
        """Does this deployable actually contain TypeScript the compiler could check?

        Read from the HEAD tree, not from the presence of a tsconfig: a config can be absent from a
        TypeScript deployable (a real coverage gap, which must stay not_measured) and a config can
        never appear in a tree that has no TypeScript at all (not applicable). Only the tree tells
        the two apart. node_modules and vendored bundles are excluded — a caller does not type-check
        somebody else's shipped code, and `.github/graph-admission/**` in particular is a vendored
        copy of this very tool.
        """
        prefix = "" if dep_path.rstrip("/") in ("", ".") else dep_path.rstrip("/") + "/"
        for p in self.tree_head.paths:
            if not p.startswith(prefix):
                continue
            rel = p[len(prefix):]
            if rel.startswith(".github/graph-admission/") or "node_modules/" in rel or rel.startswith("vendor/"):
                continue
            if os.path.splitext(rel)[1] in CODE_EXTS:
                return True
        return False

    def needing(self, verifier: str) -> list[str]:
        return sorted(e for e, ent in self.entities.items() if verifier in ent["required"] and verifier not in self.disabled)

    def entity_file(self, eid: str) -> str | None:
        n = self.entities[eid]["node"]
        return n.get("path")

    def record(self, vid: str, kind: str, command: str, entities: list[str], exit_code: int, output: str, started: str,
               secs: float, summary: str, verdicts: dict[str, tuple[str, str]], ext: str = "txt"):
        ref = self.out_dir / f"{vid}.{ext}"
        ref.write_text(output if isinstance(output, str) else json.dumps(output, ensure_ascii=False, indent=1))
        self.verifiers.append({"id": vid, "kind": kind, "command": command, "entities": sorted(entities), "exit_code": int(exit_code),
                               "output_ref": rel_ref(ref), "started_at_utc": started, "duration_s": secs, "summary": summary})
        self.ev.setdefault(vid, {}).update(verdicts)

    # ---- verifiers
    def v_type_check(self):
        ents = self.needing("type_check")
        if not ents:
            return
        groups: dict[tuple[str, str], list[str]] = {}   # (deployable, tsconfig) → entities
        unattributed = {}
        for eid in ents:
            ent = self.entities[eid]
            n = ent["node"]
            path = n.get("path") or ""
            if n["type"] == "deployable_unit":
                dep = path.rstrip("/")
                for cfg in self.tsconfigs_for(dep, None):
                    groups.setdefault((dep, cfg), []).append(eid)
                if not self.tsconfigs_for(dep, None):
                    unattributed[eid] = ("not_measured", f"no tsconfig for deployable {dep}")
                continue
            dep = type_project_of(path, self.deployables, self.tree_head)
            if dep is None:
                unattributed[eid] = ("not_measured", f"{path} lies in no deployable with a TypeScript project and no root tsconfig exists")
                continue
            cfgs = self.tsconfigs_for(dep, path)
            if not cfgs:
                unattributed[eid] = ("not_measured", f"no tsconfig covers {path}")
                continue
            for cfg in cfgs:
                groups.setdefault((dep, cfg), []).append(eid)
        for (dep, cfg), eids in sorted(groups.items()):
            started = now_iso()
            gen = self.generated_tsconfig(dep, cfg)
            tsc = find_bin("tsc", self.a.tsc, self.exec_root, self.top, [dep])
            vid = "v-type-check-" + re.sub(r"[^a-z0-9]+", "-", (dep + "-" + os.path.basename(cfg).replace(".json", "")).lower()).strip("-")
            if not tsc:
                self.record(vid, "type_check", f"tsc -p {gen} (tsc not found)", eids, 127, "tsc binary not found (node_modules/.bin/tsc, --tsc, PATH)",
                            started, 0.0, "not_measured: tsc unavailable", {e: ("not_measured", "tsc unavailable on this host") for e in eids})
                continue
            rc, out, secs = run_cmd([tsc, "-p", str(gen.resolve()), "--noEmit", "--incremental", "false", "--listFiles"], self.exec_root / dep)
            listed, errors_by_file, n_err, global_errors = set(), {}, 0, []
            unresolved = 0
            for line in out.splitlines():
                m = TS_ERR_RE.match(line.strip())
                if m:
                    n_err += 1
                    unresolved += m.group(4) in UNRESOLVED_MODULE_CODES
                    errors_by_file.setdefault(self.norm_tsc_path(m.group(1), dep), []).append(f"{m.group(4)} L{m.group(2)}: {m.group(5)[:160]}")
                elif re.match(r"^error TS\d+:", line.strip()):
                    n_err += 1
                    global_errors.append(line.strip()[:240])
                elif line.startswith("/") and not line.strip().endswith(":"):
                    listed.add(self.norm_tsc_path(line.strip(), dep))
            # The compiler RAN and exited normally, so the run looks complete — which is exactly why
            # this has to be caught here. With no dependency install, every import answers TS2307 and
            # the flood is attributed to the changed files: 1320 errors on auth-arcana, not one of
            # them the author's. Both halves are required and each is separately falsifiable: the
            # manifest declares dependencies with no node_modules anywhere above the deployable, AND
            # the compiler actually emitted unresolved-module diagnostics. The second half is what the
            # first alone got wrong — the ts-mini fixture declares dependencies it never installs and
            # resolves them through generated `paths`, so it compiles clean and is measured as before.
            uninstalled = self.dependency_install_missing(dep) if unresolved else None
            if uninstalled:
                why = (f"{unresolved} of {n_err} diagnostic(s) are unresolved modules and {uninstalled}; "
                       f"a type check over an unresolved module graph measures the absent install, not this change")
                self.record(vid, "type_check", f"{tsc} -p {gen} --noEmit --incremental false --listFiles", eids, rc, out,
                            started, secs, f"{cfg}: exit {rc}, {n_err} error(s), {unresolved} unresolved-module — "
                                           f"not_measured: dependencies not installed",
                            {e: ("not_measured", why) for e in eids})
                continue
            verdicts = {}
            for eid in eids:
                n = self.entities[eid]["node"]
                # TypeScript exit statuses 0/1/2 are normal completion states;
                # timeout, signal or launcher failure cannot prove completeness.
                if rc not in (0, 1, 2):
                    verdicts[eid] = ("not_measured", f"{cfg}: abnormal compiler exit {rc}; incomplete type check")
                    continue
                if global_errors:
                    verdicts[eid] = ("failed", f"{cfg}: global compiler diagnostic: " + "; ".join(global_errors[:3]))
                    continue
                if rc != 0 and n_err == 0:
                    verdicts[eid] = ("not_measured", f"{cfg}: compiler exit {rc} without recognized diagnostics; no successful type check")
                    continue
                if n["type"] == "deployable_unit":
                    verdicts[eid] = ("verified", f"{cfg}: 0 errors") if n_err == 0 else ("failed", f"{cfg}: {n_err} error(s) in {len(errors_by_file)} file(s)")
                    continue
                path = n.get("path")
                if path in errors_by_file:
                    verdicts[eid] = ("failed", f"{cfg}: " + "; ".join(errors_by_file[path][:3]))
                elif path not in listed:
                    verdicts[eid] = ("not_measured", f"{cfg} does not include {path}")
                elif n_err == 0:
                    verdicts[eid] = ("verified", f"{cfg}: project compiles, 0 errors")
                else:
                    verdicts[eid] = ("not_measured", f"{cfg}: {n_err} error(s) in other files ({', '.join(sorted(errors_by_file)[:3])}); not attributable to {path}")
            summary = f"{cfg}: exit {rc}, {n_err} error(s), {len(listed)} files listed"
            self.record(vid, "type_check", f"{tsc} -p {gen} --noEmit --incremental false --listFiles", eids, rc, out, started, secs, summary, verdicts)

    def dependency_install_missing(self, dep: str) -> str | None:
        """Why module resolution cannot work in this tree — or None, meaning the compiler is believed.

        `tsc` in a tree whose dependencies were never installed answers TS2307 for every import, and
        the compiler EXITS NORMALLY, so the run looks complete and the flood is attributed to the
        changed files: 1320 errors on auth-arcana, not one of them the author's. That is a `failed`
        verdict bought with a measurement that could not have happened, which is precisely what the
        third verdict exists for.

        This half answers only "was there an install?": the deployable's own manifest declares
        dependencies AND no `node_modules` exists at the deployable or any ancestor up to the exec
        root. It is deliberately NOT sufficient on its own — the caller requires unresolved-module
        diagnostics to have actually appeared, because a tree can resolve its imports through tsconfig
        `paths` with no install at all (the ts-mini fixture does exactly that, and an earlier version
        of this rule silenced it). A manifest declaring no dependencies needs no install; an installed
        tree keeps every diagnostic it earns, including a TS2307 for a module the change deleted.

        Installing the dependencies here instead was the other option on the table (A2-233). It is
        refused for the gate's default path: `npm ci` inside a verifier makes the verdict depend on a
        registry reachable at that moment and on post-install scripts of the tree being judged, i.e.
        it makes the measurement less reproducible than saying it was not made. A repository that
        wants the type check measured installs its dependencies before the gate runs — which is what
        every CI job already does, and why this branch is quiet in CI and loud on a bare clone."""
        prefix = "" if dep in ("", ".") else dep.rstrip("/") + "/"
        pkg = prefix + "package.json"
        declared: dict = {}
        if self.tree_head.exists(pkg):
            try:
                doc = json.loads(self.tree_head.text(pkg))
            except json.JSONDecodeError:
                doc = {}
            if isinstance(doc, dict):
                for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    section = doc.get(field)
                    if isinstance(section, dict):
                        declared.update(section)
        if not declared:
            return None
        # node_modules is never in the Git tree: probe the filesystem the compiler will actually read.
        root = self.exec_root.resolve()
        probe = (root / dep).resolve() if dep not in ("", ".") else root
        while True:
            if (probe / "node_modules").is_dir():
                return None
            if probe == root or probe.parent == probe:
                return (f"{len(declared)} dependency(ies) declared in {pkg} and no node_modules under "
                        f"{dep or '.'}: tsc cannot resolve modules, so its diagnostics would measure the "
                        f"absent install, not this change")
            probe = probe.parent

    def norm_tsc_path(self, p: str, dep: str) -> str:
        p = p.strip()
        try:
            rp = Path(p) if Path(p).is_absolute() else (self.exec_root / dep / p)
            return rp.resolve().relative_to(self.exec_root.resolve()).as_posix()
        except ValueError:
            return p

    def tsconfigs_for(self, dep: str, path: str | None) -> list[str]:
        prof = (self.profile.get("deployables") or {}).get(dep, {})
        prefix = "" if dep in ("", ".") else dep + "/"
        cfgs = list(prof.get("tsconfig") or [])
        if "tsconfig" not in prof:
            if self.tree_head.exists(prefix + "tsconfig.json"):
                cfgs.append(prefix + "tsconfig.json")
        if path is not None:
            test_cfg = prof.get("tsconfig_test") or (prefix + "tsconfig.test.json" if self.tree_head.exists(prefix + "tsconfig.test.json") else None)
            rel = path[len(prefix):]
            is_test = bool(re.search(r"\.(spec|test)\.[cm]?[jt]sx?$", rel) or rel.startswith(("test/", "__tests__/", "e2e/")))
            if test_cfg and is_test:
                cfgs = [test_cfg]
        if prof.get("synthetic_tsconfig") is not None and not cfgs:
            cfgs.append(f"synthetic:{dep}")
        return cfgs

    def generated_tsconfig(self, dep: str, cfg: str) -> Path:
        # A relocated extending config changes implicit @types discovery. For the
        # ordinary path use the source config itself; CLI flags enforce no emit.
        if not cfg.startswith("synthetic:") and not self.profile.get("tsconfig_overlay"):
            return self.exec_root / cfg
        gen_dir = self.out_dir / "tsconfig"
        gen_dir.mkdir(exist_ok=True)
        name = re.sub(r"[^a-z0-9]+", "-", f"{dep}-{cfg}".lower()).strip("-") + ".json"
        gen = gen_dir / name
        overlay = self.profile.get("tsconfig_overlay") or {}
        co = {"noEmit": True, "incremental": False}
        doc = {"compilerOptions": co}
        if cfg.startswith("synthetic:"):
            syn = (self.profile["deployables"][dep].get("synthetic_tsconfig") or {})
            doc["include"] = [str(self.exec_root / dep / inc) for inc in syn.get("include", ["src"])]
        else:
            doc["extends"] = str(self.exec_root / cfg)
            try:
                base_cfg0 = build_graph.load_jsonc(self.tree_head.text(cfg)) or {}
            except Exception:  # noqa: BLE001
                base_cfg0 = {}
            if "include" not in base_cfg0 and "files" not in base_cfg0 and "extends" not in base_cfg0:
                # tsc's implicit `**/*` is relative to the config that declares nothing: make it explicit for the generated file
                doc["include"] = [str(self.exec_root / dep / "**/*")]
                doc["exclude"] = [str(self.exec_root / dep / x) for x in ("node_modules", "dist", ".next", "coverage")]
        if overlay:
            co.update(overlay.get("compilerOptions", {}))
            base_cfg = {}
            if not cfg.startswith("synthetic:"):
                try:
                    base_cfg = build_graph.load_jsonc(self.tree_head.text(cfg)) or {}
                except Exception:  # noqa: BLE001
                    base_cfg = {}
            paths = dict((base_cfg.get("compilerOptions") or {}).get("paths") or {})
            troot = Path(self.profile_ref).parent / overlay.get("typings_root", "typings") if self.profile_ref and not self.profile_ref.startswith("(") else VFIX / "typings"
            for pkg in overlay.get("stub_packages", []):
                paths[pkg] = [str(troot / pkg / "index.d.ts")]
            paths.update(overlay.get("paths_override", {}))
            co["baseUrl"] = str(self.exec_root / dep)
            co["paths"] = paths
            doc["files"] = [str(troot / g) for g in overlay.get("global_typings", [])]
        gen.write_text(json.dumps(doc, indent=1))
        return gen

    def v_contract_diff(self):
        ents = self.needing("contract_diff")
        if not ents:
            return
        started = now_iso()
        t0 = time.monotonic()
        cmd = f"{contract_diff.TOOL}.run_diff(base={self.tree_base.meta.get('source_commit', '?')[:12]}, head={'worktree' if self.mode == 'worktree' else self.head[:12]}, graph=head graph)"
        try:
            res = contract_diff.run_diff(self.tree_base, self.tree_head, graph=self.graph_head, repo_name=self.repo.name)
        except contract_diff.Refusal as r:
            self.record("v-contract-diff", "contract_diff", cmd, ents, 2, f"REFUSAL {r.code}: {r.detail}", started, round(time.monotonic() - t0, 2),
                        f"refusal {r.code}", {e: ("not_measured", f"contract_diff refused: {r.code}") for e in ents}, "txt")
            return
        contracts = res["contracts"]
        by_from: dict[str, list[dict]] = {}
        for e in res["edges"]:
            by_from.setdefault(e["edge"]["from"], []).append(e)
        verdicts = {}
        for eid in ents:
            n = self.entities[eid]["node"]
            if n["type"] == "contract":
                c = contracts.get(eid)
                if c is None:
                    verdicts[eid] = ("not_measured", "contract not extracted at either revision (kind outside zod / class-validator / union / enum)")
                    continue
                breaking = [ch for ch in c["changes"] if ch["severity"] == "breaking"]
                if c["status"] == "removed":
                    verdicts[eid] = ("failed", "CONTRACT_REMOVED")
                elif breaking:
                    verdicts[eid] = ("failed", "; ".join(f"{ch['code']} {ch['detail']}"[:120] for ch in breaking[:3]))
                else:
                    verdicts[eid] = ("verified", f"{c['status']}: no breaking change ({len(c['changes'])} change(s))")
                continue
            edges = by_from.get(eid, [])
            if not edges:
                # a code unit / route reached through a contract hop but consuming no contract edge at head
                verdicts[eid] = ("verified", "no contract edge from this entity at head; nothing to project") if n["type"] != "route" or True else ("not_measured", "")
                continue
            vs = [x["verdict"] for x in edges]
            if "failed" in vs:
                bad = [x for x in edges if x["verdict"] == "failed"]
                verdicts[eid] = ("failed", "; ".join(f"{x['edge']['to']}: {'; '.join(x['reasons'][:2])}"[:160] for x in bad[:2]))
            elif "not_measured" in vs:
                nm = [x for x in edges if x["verdict"] == "not_measured"]
                verdicts[eid] = ("not_measured", "; ".join(f"{x['edge']['to']}: {'; '.join(x['reasons'][:2])}"[:160] for x in nm[:2]))
            else:
                verdicts[eid] = ("verified", f"{len(edges)} contract edge(s) verified (consumer ⊆ provider)")
        s = res["summary"]
        summary = f"{s['contracts_base']}→{s['contracts_head']} contracts, breaking {s['breaking']}, edges {s['edge_verdicts']}"
        self.record("v-contract-diff", "contract_diff", cmd, ents, contract_diff.exit_code_for(res), res, started, round(time.monotonic() - t0, 2), summary, verdicts, "json")

    def v_route_config(self):
        ents = self.needing("route_config_consistency")
        if not ents:
            return
        started = now_iso()
        t0 = time.monotonic()
        prefixes: dict[str, str | None] = {}
        registered: dict[str, tuple[set[str], list[str]]] = {}
        log, verdicts = [], {}
        for eid in ents:
            n = self.entities[eid]["node"]
            path = n.get("path") or ""
            dep = deployable_of(path, self.deployables)
            problems, notes = [], []
            if "rc03" in self.fr_rules:
                if eid not in self.head_nodes:
                    consumers = [e["from"] for e in self.idx.rev.get(eid, []) if e["type"] == "consumes_contract"]
                    if consumers:
                        problems.append(f"ROUTE_REMOVED_WITH_CONSUMER: not served at head, consumers {consumers[:3]}")
                    else:
                        notes.append("route no longer served at head, no consumer bound to it")
                        verdicts[eid] = ("verified", notes[-1])
                        log.append(f"{eid}: {notes[-1]}")
                        continue
            if dep is None:
                verdicts[eid] = ("not_measured", f"controller {path} lies in no deployable")
                continue
            if dep not in prefixes:
                pf = None
                prof = (self.profile.get("deployables") or {}).get(dep, {})
                prefix = "" if dep in ("", ".") else dep + "/"
                candidates = [prefix + "src/main" + ext for ext in (".ts", ".mts")
                              if self.tree_head.exists(prefix + "src/main" + ext)]
                root_file = prof.get("root_module_file") or (candidates[0] if len(candidates) == 1 else None)
                if root_file and deployable_of(root_file, self.deployables) == dep and self.tree_head.exists(root_file):
                    m = re.search(r"""setGlobalPrefix\(\s*['"]([^'"]*)['"]""", build_graph.strip_comments(self.tree_head.text(root_file)))
                    if m:
                        pf = "/" + m.group(1).strip("/")
                else:
                    root_file = None
                prefixes[dep] = pf
                registered[dep] = nest_registered_files(self.scan_head, root_file) if root_file else (set(), ["no src/main.ts"])
            want = (n.get("attrs") or {}).get("global_prefix")
            want = ("/" + want.strip("/")) if want else None
            if "rc01" in self.fr_rules and want is not None and want != prefixes[dep]:   # a route built without a prefix attr is excluded from it (e.g. health)
                problems.append(f"PREFIX_MISMATCH: route built with prefix {want!r}, bootstrap at head sets {prefixes[dep]!r}")
            reg, rnotes = registered[dep]
            if "rc02" in self.fr_rules:
                if not reg and rnotes and rnotes[0].startswith("no"):
                    verdicts[eid] = ("not_measured", f"RC-02 not evaluable: {rnotes[0]}")
                    log.append(f"{eid}: not_measured {rnotes[0]}")
                    continue
                if path not in reg:
                    problems.append(f"UNREGISTERED_CONTROLLER: {path} is registered in no @Module reachable from the root module ({rnotes[-1] if rnotes else ''})")
            if problems:
                verdicts[eid] = ("failed", "; ".join(problems)[:300])
            else:
                verdicts[eid] = ("verified", f"served at head, prefix {prefixes[dep]!r} consistent" + (" (route excluded from the prefix)" if want is None else "") + ", controller registered")
            log.append(f"{eid}: {verdicts[eid][0]} — {verdicts[eid][1]}")
        failed = sum(1 for v in verdicts.values() if v[0] == "failed")
        self.record("v-route-config", "config_schema", "verify.py route_config_consistency RC-01 prefix / RC-02 registration / RC-03 served", ents,
                    1 if failed else 0, "\n".join(log), started, round(time.monotonic() - t0, 2), f"{len(ents)} route(s), {failed} failed", verdicts)

    def v_schema_diff(self):
        ents = self.needing("schema_diff")
        if not ents:
            return
        started = now_iso()
        t0 = time.monotonic()
        schemas = sorted({self.entities[e]["node"].get("path") for e in ents if self.entities[e]["node"].get("path")} |
                         {p for p in self.tree_head.paths if p.endswith("schema.prisma")})
        diffs, parse_err, log = {}, [], []
        for sp in schemas:
            b = prisma_lite(self.tree_base.text(sp)) if self.tree_base.exists(sp) else {"models": {}, "enums": {}, "parse_errors": []}
            h = prisma_lite(self.tree_head.text(sp)) if self.tree_head.exists(sp) else {"models": {}, "enums": {}, "parse_errors": ["schema removed"]}
            parse_err += [f"{sp}: {x}" for x in h["parse_errors"]]
            diffs[sp] = prisma_diff(b, h)
        validate = {"ran": False}
        prisma = find_bin("prisma", self.a.prisma, self.exec_root, self.top, list(self.deployables))
        for sp in schemas:
            if not prisma or not self.tree_head.exists(sp):
                continue
            env = {} if os.environ.get("DATABASE_URL") else {"DATABASE_URL": "postgresql://verify:verify@localhost:5432/verify"}
            rc, out, secs = run_cmd([prisma, "validate", "--schema", str(self.exec_root / sp)], self.exec_root, env=env, timeout=120)
            validate = {"ran": True, "schema": sp, "exit_code": rc, "seconds": secs, "tail": out[-600:]}
            log.append(f"prisma validate {sp}: exit {rc} ({secs}s)")
        verdicts = {}
        consumers = {}
        for eid in ents:
            n = self.entities[eid]["node"]
            model = n["id"].split(":", 1)[1]
            sp = n.get("path") or (schemas[0] if schemas else None)
            ch = (diffs.get(sp) or {}).get(model, [])
            breaking = [c for c in ch if c["severity"] == "breaking"]
            if validate["ran"] and validate["exit_code"] != 0:
                verdicts[eid] = ("failed", f"PRISMA_INVALID: prisma validate exit {validate['exit_code']}")
                continue
            if parse_err and any(x.startswith(sp or "") for x in parse_err):
                verdicts[eid] = ("failed", "SCHEMA_PARSE_ERROR: " + parse_err[0])
                continue
            if breaking:
                cons = [e["from"] for e in self.idx.rev.get(eid, []) if e["type"] == "maps_model" and e["from"].startswith("code_unit:")]
                consumers[eid] = cons
                refs = []
                for cu in cons:
                    cp = cu.split(":", 1)[1]
                    if not self.tree_head.exists(cp):
                        continue
                    code = build_graph.strip_comments(self.tree_head.text(cp))
                    for c in breaking:
                        fld = c.get("field")
                        if c["code"] in ("MODEL_REMOVED", "ENUM_REMOVED", "ENUM_VALUE_REMOVED"):
                            if re.search(r"\b" + re.escape(model) + r"\b", code) or re.search(r"\." + re.escape(model[0].lower() + model[1:]) + r"\b", code):
                                refs.append(f"{cp} references {model}")
                        elif fld and re.search(r"\b" + re.escape(fld) + r"\b", code):
                            refs.append(f"{cp} references {model}.{fld}")
                if refs:
                    verdicts[eid] = ("failed", "; ".join(f"{c['code']} {c['detail']}" for c in breaking[:2]) + " — " + "; ".join(sorted(set(refs))[:3]))
                elif not cons:
                    verdicts[eid] = ("verified", "breaking change " + "; ".join(c["code"] for c in breaking[:3]) + " on a model with no code consumer in the graph")
                else:
                    verdicts[eid] = ("verified", "breaking change " + "; ".join(c["code"] for c in breaking[:3]) + f" not referenced by its {len(cons)} consumer(s)")
                continue
            if not validate["ran"]:
                verdicts[eid] = ("not_measured", f"schema-lite diff clean ({len(ch)} compatible change(s)); prisma validate not run (CLI unavailable)")
            else:
                verdicts[eid] = ("verified", f"no breaking change ({len(ch)} compatible change(s)); prisma validate exit 0")
        out = {"schemas": schemas, "diffs": diffs, "parse_errors": parse_err, "validate": validate, "consumers": consumers, "log": log}
        failed = sum(1 for v in verdicts.values() if v[0] == "failed")
        self.record("v-schema-diff", "schema_diff", "verify.py prisma-lite diff base→head" + (f" + {prisma} validate" if prisma else " (prisma CLI unavailable)"),
                    ents, 1 if failed else 0, out, started, round(time.monotonic() - t0, 2),
                    f"{len(schemas)} schema(s), {sum(len(v) for d in diffs.values() for v in d.values())} change(s), {failed} failed, validate {'exit ' + str(validate.get('exit_code')) if validate['ran'] else 'not run'}", verdicts, "json")

    def v_workflow_config(self):
        for eid in self.needing("config_schema"):
            path = self.entity_file(eid) or ""
            if not workflow_config.is_workflow(path):
                continue
            raw = self.tree_head.files.get(path)
            if raw is None:
                verdict = ("not_measured", "workflow removed/renamed; retirement semantics require separate evidence")
            elif build_graph.sha_bytes(raw) != self.entities[eid]["node"].get("content_hash"):
                verdict = ("not_measured", "workflow source hash differs from selected graph node")
            else:
                verdict = workflow_config.validate(raw)
            vid = "v-workflow-config-" + hashlib.sha256(path.encode()).hexdigest()[:16]
            self.record(vid, "config_schema", "workflow_config.validate exact head bytes", [eid],
                        0 if verdict[0] == "verified" else 1, verdict[1], now_iso(), 0.0,
                        verdict[1], {eid: verdict})

    def v_config_schema(self):
        self.v_workflow_config()
        ents = [e for e in self.needing("config_schema")
                if not workflow_config.is_workflow(self.entity_file(e) or "")]
        if not ents:
            return
        started = now_iso()
        t0 = time.monotonic()
        viol, declared, sources, vendored_report = config_violations(self.graph_head, self.tree_head, self.scan_head, self.profile.get("env_declaration_files") or [])
        # AUP-GRAPH-006:gate3b — keys read ONLY by vendored foreign code, so a config_key entity in the impact set
        # is not silently "verified" for the wrong reason (it would otherwise fall through to the baseline branch).
        vendored_keys: dict[str, str] = {}
        for r in vendored_report.values():
            for k in r["keys"]:
                vendored_keys.setdefault(k, r["owner"])
        frozen, new = self.split_baseline(viol)
        by_entity: dict[str, list[dict]] = {}
        for v in new:
            by_entity.setdefault(v["entity"], []).append(v)
        frozen_by: dict[str, list[dict]] = {}
        for v in frozen:
            frozen_by.setdefault(v["entity"], []).append(v)
        verdicts = {}
        for eid in ents:
            n = self.entities[eid]["node"]
            if not sources:
                verdicts[eid] = ("not_measured", "the repository declares no env source (.env.example / env.schema / compose environment)")
                continue
            if n["type"] == "config_key":
                key = n.get("symbol") or eid.split(":", 1)[1]
                readers = [v for v in new if v["key"] == key]
                if key in declared:
                    verdicts[eid] = ("verified", f"{key} declared in {', '.join(sources)}")
                elif FRAMEWORK_ENV_RE.match(key):
                    verdicts[eid] = ("verified", f"{key} is framework-owned (no declaration required)")
                elif readers:
                    verdicts[eid] = ("failed", f"UNDECLARED_CONFIG_KEY {key}: read by {', '.join(sorted({r['entity'] for r in readers}))}")
                elif key in vendored_keys:
                    verdicts[eid] = ("verified", f"{key} is read only by VENDORED foreign code owned by {vendored_keys[key]} "
                                                 f"(GraphAdmissionBundle/v1); this repository reads it nowhere, so it is not this "
                                                 f"repository's key to declare")
                else:
                    verdicts[eid] = ("verified", f"{key} undeclared but frozen in the baseline for every reader")
                continue
            mine = by_entity.get(eid, [])
            if mine:
                verdicts[eid] = ("failed", "; ".join(f"UNDECLARED_CONFIG_KEY {v['key']}" for v in mine[:4]))
            else:
                fz = frozen_by.get(eid, [])
                verdicts[eid] = ("verified", f"every key read is declared" + (f" ({len(fz)} frozen undeclared key(s): {', '.join(v['key'] for v in fz[:4])})" if fz else ""))
        out = {"declared_sources": sources, "declared_count": len(declared), "new": new, "frozen": frozen,
               "vendored_not_attributed": list(vendored_report.values())}
        failed = sum(1 for v in verdicts.values() if v[0] == "failed")
        self.record("v-config-schema", "config_schema", "verify.py config_schema: keys read at head ⊆ declared keys", ents, 1 if failed else 0, out,
                    started, round(time.monotonic() - t0, 2),
                    f"{len(sources)} source(s), {len(new)} new / {len(frozen)} frozen undeclared reads, {failed} failed"
                    + (f"; {sum(len(r['files']) for r in vendored_report.values())} vendored file(s) not attributed to this repository "
                       f"({', '.join(sorted(vendored_report))})" if vendored_report else ""), verdicts, "json")

    def v_fitness(self):
        ents = self.needing("fitness_rules")
        if not ents:
            return
        started = now_iso()
        t0 = time.monotonic()
        viol = fitness_violations(self.graph_head, self.tree_head, self.scan_head, self.fr_rules)
        frozen, new = self.split_baseline(viol)
        by_entity: dict[str, list[dict]] = {}
        for v in new:
            by_entity.setdefault(v["entity"], []).append(v)
        frozen_by: dict[str, list[dict]] = {}
        for v in frozen:
            frozen_by.setdefault(v["entity"], []).append(v)
        verdicts = {}
        for eid in ents:
            n = self.entities[eid]["node"]
            if n["type"] == "deployable_unit":
                dep = (n.get("path") or "").rstrip("/")
                mine = [v for v in new if deployable_of(v["entity"].split(":", 1)[1], self.deployables) == dep]
                if mine:
                    verdicts[eid] = ("failed", f"{len(mine)} new violation(s) in {dep}: " + "; ".join(f"{v['rule']} {v['entity']}" for v in mine[:3]))
                else:
                    fz = [v for v in frozen if deployable_of(v["entity"].split(":", 1)[1], self.deployables) == dep]
                    verdicts[eid] = ("verified", f"no new violation in {dep}" + (f" ({len(fz)} frozen)" if fz else ""))
                continue
            mine = by_entity.get(eid, [])
            if mine:
                verdicts[eid] = ("failed", "; ".join(f"{v['rule']}: {v['detail']}"[:200] for v in mine[:3]))
            else:
                fz = frozen_by.get(eid, [])
                verdicts[eid] = ("verified", "no new fitness violation" + (f" ({len(fz)} frozen: {', '.join(v['rule'] for v in fz)})" if fz else ""))
        out = {"rules": self.matrix["fitness_rules"], "baseline": self.baseline_ref, "baseline_status": self.baseline_status,
               "new": new, "frozen": frozen}
        failed = sum(1 for v in verdicts.values() if v[0] == "failed")
        self.record("v-fitness", "fitness_rules", "verify.py fitness_rules FR-01..FR-05 over the head graph + head sources", ents, 1 if failed else 0, out,
                    started, round(time.monotonic() - t0, 2), f"{len(viol)} finding(s): {len(new)} new / {len(frozen)} frozen; {failed} entity(ies) failed", verdicts, "json")

    def v_doc_reference(self):
        ents = self.needing("doc_reference")
        if not ents:
            return
        started = now_iso()
        t0 = time.monotonic()
        changed_paths = {f["path"] for f in self.change_files}
        head_routes = {nid for nid in self.head_nodes if nid.startswith("route:")}
        head_models = {nid for nid in self.head_nodes if nid.startswith("data_model:")}
        prefix = None
        for nid, n in self.head_nodes.items():
            if nid.startswith("route:") and (n.get("attrs") or {}).get("global_prefix"):
                prefix = "/" + n["attrs"]["global_prefix"].strip("/")
                break
        verdicts, log = {}, []
        for eid in ents:
            n = self.entities[eid]["node"]
            p = n.get("path")
            if not p or not self.tree_head.exists(p):
                verdicts[eid] = ("verified", "document absent at head: it references nothing any more")
                continue
            txt = self.tree_head.text(p)
            dangling, checked = [], 0
            for ref in sorted(set(re.findall(r"(?<![\w/])((?:apps|packages|src|contracts|tools|receipts|docs|governance|universal-program|science)/[\w./-]+\.[A-Za-z0-9]+)", txt))):
                if self.tree_base.exists(ref) or self.tree_head.exists(ref):
                    checked += 1
                    if not self.tree_head.exists(ref):
                        dangling.append(f"path {ref}")
            for meth, rp in set(re.findall(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[\w/:${}.-]+)", txt)):
                rp2 = rp[len(prefix):] if prefix and rp.startswith(prefix + "/") else rp
                rid = f"route:{meth} {rp2}"
                if rid in self.idx.nodes or rid in head_routes:
                    checked += 1
                    if rid not in head_routes:
                        dangling.append(f"route {meth} {rp}")
            for model in set(re.findall(r"\bmodel\s+([A-Z]\w+)\b", txt)):
                mid = f"data_model:{model}"
                if mid in self.idx.nodes or mid in head_models:
                    checked += 1
                    if mid not in head_models:
                        dangling.append(f"model {model}")
            if dangling:
                verdicts[eid] = ("failed", "DANGLING_REFERENCE: " + "; ".join(dangling[:4]))
            else:
                verdicts[eid] = ("verified", f"{checked} reference(s) resolve at head")
            log.append(f"{p}: {verdicts[eid][0]} — {verdicts[eid][1]}")
        failed = sum(1 for v in verdicts.values() if v[0] == "failed")
        self.record("v-doc-reference", "doc_reference", "verify.py doc_reference: path / route / model references of affected documents resolve at head",
                    ents, 1 if failed else 0, "\n".join(log), started, round(time.monotonic() - t0, 2), f"{len(ents)} document(s), {failed} failed", verdicts)

    def v_canary(self):
        """AUP-GRAPH-008: the live-contour verifier for the classes the calibration could not measure offline.

        A canary result (tools/graph/deploy_gate.py canary) lists entities with tri-valued verdicts.
        An entity that needs a canary and is not listed is not_measured — never verified (matrix P6,
        contract rule C1). This verifier never probes anything itself: it consumes evidence.
        """
        ents = set(self.needing("canary")) | {e for e, ent in self.entities.items() if ent.get("inferred_boundary")}
        if not ents:
            return
        started, t0 = now_iso(), time.monotonic()
        self.canary_verified.difference_update(ents)
        listed: dict[str, dict] = {}
        sources = []
        rank = {"failed": 2, "not_measured": 1, "verified": 0}
        for path in self.canary_paths:
            candidate = self.head if self.mode == "diff" else self.repo.head()
            rows, errors, doc = canary_evidence.consume(path, self.top, candidate,
                dirty=self.mode != "diff" and self.repo.dirty())
            sources.append({"path": rel_ref(Path(path)), "errors": errors,
                            "subject": doc.get("subject"), "environment": doc.get("environment"),
                            "captured_at_utc": doc.get("captured_at_utc")})
            if errors:
                rows = {e: {"entity": e, "verdict": "not_measured",
                            "reason": "CANARY_EVIDENCE_UNVERIFIABLE: " + "; ".join(errors)} for e in ents}
            for eid, v in rows.items():
                cur = listed.get(eid)
                if cur is None or rank[v["verdict"]] > rank[cur["verdict"]]:
                    listed[eid] = {**v, "plan": (doc.get("plan") or {}).get("id") if isinstance(doc.get("plan"), dict) else None,
                                   "phase": doc.get("phase"), "environment": doc.get("environment")}
        verdicts, lines = {}, []
        for eid in sorted(ents):
            cv = listed.get(eid)
            if cv is None:
                verdicts[eid] = ("not_measured",
                                 "INFERRED_BOUNDARY_WITHOUT_CANARY: no canary result lists this entity "
                                 "(matrix P6, observed-edges-and-deploy-gate.v1 rule C1)")
            else:
                verdicts[eid] = (cv["verdict"], f"canary {cv['plan']} ({cv['phase']}) on {cv['environment']}: "
                                                f"{(cv.get('reason') or '')[:200]}")
                if cv["verdict"] == "verified":
                    self.canary_verified.add(eid)
            lines.append(f"{verdicts[eid][0]:12} {eid}  {verdicts[eid][1][:160]}")
        summary = (f"{len(self.canary_paths)} canary result(s); "
                   f"{sum(1 for v in verdicts.values() if v[0] == 'verified')} verified / "
                   f"{sum(1 for v in verdicts.values() if v[0] == 'failed')} failed / "
                   f"{sum(1 for v in verdicts.values() if v[0] == 'not_measured')} not_measured of {len(ents)} entities")
        self.record("v-canary", "canary",
                    "tools/graph/deploy_gate.py canary --plan <plan> --phase pre|post (results supplied with --canary)",
                    sorted(ents), 0, json.dumps({"sources": sources, "verdicts": {k: v for k, v in verdicts.items()}},
                                                ensure_ascii=False, indent=1) + "\n\n" + "\n".join(lines),
                    started, round(time.monotonic() - t0, 2), summary, verdicts, ext="json")

    def v_targeted_test(self):
        if "targeted_test" not in self.selected or "targeted_test" in self.disabled:
            return
        affected = set(self.entities)
        specs: dict[str, set[str]] = {}
        for eid in affected:
            n = self.entities[eid]["node"]
            p = n.get("path") or ""
            if n["type"] == "code_unit" and re.search(r"\.(spec|test)\.[cm]?[jt]sx?$", p):
                specs.setdefault(p, set()).add(eid)
            for e in self.head_rev.get(eid, []):
                if e["type"] == "verifies" and e["from"].startswith("code_unit:"):
                    sp = e["from"].split(":", 1)[1]
                    if re.search(r"\.(spec|test)\.[cm]?[jt]sx?$", sp) and self.tree_head.exists(sp):
                        specs.setdefault(sp, set()).add(eid)
                        specs[sp].add(e["from"])
        if not specs:
            self.notes.append("targeted_test selected: no spec with a verifies edge reaches an affected entity")
            return
        groups: dict[str, list[str]] = {}
        for sp in specs:
            dep = deployable_of(sp, self.deployables) or ""
            groups.setdefault(dep, []).append(sp)
        for dep, sps in sorted(groups.items()):
            started = now_iso()
            prefix = "" if dep in ("", ".") else dep + "/"
            prof = (self.profile.get("deployables") or {}).get(dep, {})
            runner, cmd = None, None
            if prof.get("test"):
                runner, cmd = "profile", list(prof["test"])
            else:
                pj = {}
                if self.tree_head.exists(prefix + "package.json"):
                    try:
                        pj = json.loads(self.tree_head.text(prefix + "package.json"))
                    except json.JSONDecodeError:
                        pj = {}
                script = (pj.get("scripts") or {}).get("test", "")
                if "jest" in script:
                    runner = "jest"
                elif "vitest" in script:
                    runner = "vitest"
            rel = [sp[len(prefix):] for sp in sorted(sps)]
            ents = sorted({e for sp in sps for e in specs[sp]} | {f"code_unit:{sp}" for sp in sps if f"code_unit:{sp}" in self.entities})
            vid = "v-targeted-test-" + (re.sub(r"[^a-z0-9]+", "-", dep.lower()).strip("-") or "root")
            bin_ = find_bin(runner, None, self.exec_root, self.top, [dep]) if runner in ("jest", "vitest") else None
            if runner == "jest" and bin_:
                cmd = [bin_, "--runInBand", "--ci", *rel]
            elif runner == "vitest" and bin_:
                cmd = [bin_, "run", *rel]
            if not cmd:
                self.record(vid, "targeted_test", f"(no runner for {dep or 'root'}: {runner or 'none detected'})", ents, 127, f"runner {runner} not available", started, 0.0,
                            "not_measured: runner unavailable", {e: ("not_measured", f"targeted test runner unavailable for {dep}") for e in ents})
                continue
            rc, out, secs = run_cmd(cmd, self.exec_root / dep if dep else self.exec_root, env={"CI": "1"}, timeout=900)
            status: dict[str, str] = {}
            for line in out.splitlines():
                m = re.match(r"^\s*(PASS|FAIL)\s+(\S+)", line)
                if m:
                    status[m.group(2)] = m.group(1)
                m2 = re.match(r"^\s*([✓✗×])\s+(\S+)", line)
                if m2 and runner == "vitest":
                    status[m2.group(2)] = "PASS" if m2.group(1) == "✓" else "FAIL"
            verdicts = {}
            for sp in sorted(sps):
                r = sp[len(prefix):]
                st = status.get(r) or next((v for k, v in status.items() if k.endswith(r) or r.endswith(k)), None)
                if st is None:
                    st = "PASS" if rc == 0 else "FAIL"
                v = ("verified", f"{r}: {st}") if st == "PASS" else ("failed", f"{r}: {st} (exit {rc})")
                for e in specs[sp]:
                    prev = verdicts.get(e)
                    if prev is None or (v[0] == "failed"):
                        verdicts[e] = v
                sid = f"code_unit:{sp}"
                if sid in self.entities:
                    verdicts[sid] = v if verdicts.get(sid, ("verified", ""))[0] != "failed" else verdicts[sid]
            self.record(vid, "targeted_test", " ".join(cmd), ents, rc, out, started, secs, f"{len(sps)} spec(s), exit {rc}, {sum(1 for v in verdicts.values() if v[0] == 'failed')} failed", verdicts)

    def v_property_check(self):
        if "property_check" not in self.selected or "property_check" in self.disabled:
            return
        checks = self.profile.get("property_checks") or {}
        ran = 0
        for eid in sorted(self.entities):
            cmd = checks.get(eid)
            if not cmd:
                continue
            ran += 1
            started = now_iso()
            rc, out, secs = run_cmd(cmd if isinstance(cmd, list) else ["bash", "-lc", cmd], self.exec_root, timeout=600)
            vid = "v-property-" + re.sub(r"[^a-z0-9]+", "-", eid.lower()).strip("-")[:60]
            self.record(vid, "property_check", cmd if isinstance(cmd, str) else " ".join(cmd), [eid], rc, out, started, secs, f"exit {rc}",
                        {eid: ("verified", "property check exit 0") if rc == 0 else ("failed", f"property check exit {rc}")})
        if not ran:
            self.notes.append("property_check selected: no property declared for an affected node in the profile")

    # ---- baseline
    def load_baseline(self):
        bl, ref = resolve_baseline(self.a, self.top, self.repo.name)
        self.baseline_ref = ref
        if bl is None:
            # auto-freeze at base: pre-existing findings of the base tree are frozen for this run
            base_tree = self.tree_base
            base_graph = self.idx.doc if self.mode == "diff" else build_graph.build(self.top, rev=self.repo.head(), built_at=build_graph.FIXED_BUILT_AT)
            scan = TreeScan(base_tree)
            entries = fitness_violations(base_graph, base_tree, scan, self.fr_rules)
            cv, _, _, _ = config_violations(base_graph, base_tree, scan, self.profile.get("env_declaration_files") or [])
            entries += cv
            exp = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            bl = make_baseline(self.repo.name, base_tree.meta.get("source_commit", "?"), entries, "auto:base-freeze (tools/graph/verify.py)", exp, "auto-base-freeze")
            self.baseline_ref = "(auto-base-freeze: pre-existing findings at base frozen for this run; persist one with --freeze-baseline)"
        self.baseline = bl
        exp = parse_iso(bl.get("expires_at_utc", ""))
        cap = parse_iso(self.captured_at)
        if "baseline_expiry" in self.rules and (exp is None or cap is None or exp <= cap):
            self.baseline_status = "expired" if exp else "invalid-expiry"
            self.events.append({"code": "BASELINE_EXPIRED", "baseline": self.baseline_ref, "expires_at_utc": bl.get("expires_at_utc"),
                                "reason": "frozen findings count as new again; refresh the baseline with --freeze-baseline"})
        else:
            self.baseline_status = "valid"
        self.frozen_fps = {e["fingerprint"] for e in bl.get("entries", [])} if self.baseline_status == "valid" else set()
        self.exemptions = [x for x in bl.get("exemptions", []) if parse_iso(x.get("expires_at_utc", "")) and parse_iso(x["expires_at_utc"]) > cap]

    def split_baseline(self, viol: list[dict]) -> tuple[list[dict], list[dict]]:
        frozen, new = [], []
        for v in viol:
            ex = next((x for x in self.exemptions if x.get("verifier") == v["verifier"] and (x.get("rule") in (None, v["rule"])) and (x.get("entity") in (None, v["entity"]))), None)
            if v["fingerprint"] in self.frozen_fps:
                frozen.append({**v, "status": "frozen"})
            elif ex:
                frozen.append({**v, "status": "exempted", "exemption": ex})
            else:
                new.append(v)
        return frozen, new

    # ---- aggregation
    STRUCTURAL_EXCLUSION_RULE = (
        "DEC-AUP-0034: an affected entity is NOT verdict-owing when all three hold — the verifier matrix "
        "declares neither a mandatory nor a selectable verifier for its node type (so the only verdict it "
        "could ever carry states a property of the MATRIX, not of this change), the change set does not "
        "contain it, and its bytes are identical at base and head. Each one is listed in "
        "structural_exclusions with the content hash at both revisions that proves the byte-identity, and "
        "impact_pair.receipt_problems re-derives that proof from Git rather than believing the receipt.")

    def structural_exclusions(self) -> dict[str, dict]:
        """Entities this change owes no verdict — with the per-entity proof that it owes none.

        A historical receipt is a dated record of a measurement that happened. It does not become
        false when later code changes, and the matrix gives `receipt` no verifier, so the only verdict
        it can carry is `not_measured` for the matrix's own stated reason — I14, "asserted, never
        re-verified". Charging that to the author converts a property of the gate into a `paused_safe`
        on their change. Measured before this rule existed: AUP #111 carried 233 such receipts, which
        means NO change to `tools/graph/` could ever be admitted — the one part of the repository
        permanently unmaintainable was the gate itself; ARAS #195 carried 9 and was unblocked by
        hand-written expiring exemptions for a condition that never expires.

        The three conditions are all necessary and each is separately falsifiable:

          1. The matrix declares NO verifier of any kind for the node type. Not "no verifier ran" and
             not "the verifier was unavailable" — those are real coverage gaps and keep pausing. Today
             this is exactly `receipt` and `work_item`. If the matrix ever gains a verifier for one of
             them, that type stops being excluded with no further edit, which is the reverse_if.
          2. The entity is not in the change set. Editing a receipt is an ordinary change to a file.
          3. Its bytes are identical at base and head. This is what distinguishes "the change did not
             touch it" from "the graph says it is downstream": a file the change did not alter cannot
             have been broken by the change in any way this entity could have recorded.

        The alternative on the table (A2-233) was to let the gate grant itself a named expiring
        exemption for the class. Refused: an exemption carries an owner and an expiry because it is a
        DEBT someone promises to repay, and there is nothing here to repay — the entity was never
        verifiable. `admit_change.structural_covered_entities` already had to special-case the same
        loop twice (`gate_self_update`, `spent_receipt_archive`); this removes the loop at its source
        instead of adding a third case."""
        m = self.matrix
        out: dict[str, dict] = {}
        for eid, ent in self.entities.items():
            if ent.get("changed") or ent.get("required"):
                continue
            node = ent["node"]
            ntype = node.get("type") or eid.split(":", 1)[0]
            spec = m["node_types"].get(ntype)
            if not isinstance(spec, dict) or (spec.get("mandatory") or []) or (spec.get("selectable") or []):
                continue
            path = node.get("path")
            # A node with no file (a `work_item` is an identifier found in a comment) cannot be proved
            # byte-identical, so it is not excluded: the proof is the point, not the node type.
            if not path or not (self.tree_base.exists(path) and self.tree_head.exists(path)):
                continue
            hb, hh = sha_bytes(self.tree_base.files[path]), sha_bytes(self.tree_head.files[path])
            if hb != hh:
                continue
            out[eid] = {"entity": eid, "node_type": ntype, "path": path,
                        "content_hash": {"base": hb, "head": hh},
                        "reason": spec.get("not_measured_reason")
                        or f"the verifier matrix declares no verifier for node type {ntype}",
                        "rule": "DEC-AUP-0034"}
        return out

    SUPERSEDED_SELF_RULE = (
        "DEC-AUP-0035: the entity a receipt can never verify is the PREVIOUS VERSION OF ITSELF. When "
        "a receipt is re-issued at the same path for the same work item — the ordinary case after a "
        "rebase or a second commit on a card — the copy of it standing in the tree is superseded by "
        "construction: this run is the measurement that replaces it, so the only verdict it could "
        "carry is I14 `not_measured` about a document that no longer exists at that path once the "
        "run finishes. It is excluded with the work item and the output path that identify it, both "
        "re-derived from Git by impact_pair.receipt_problems, never asserted.")

    @staticmethod
    def _work_item_id(value) -> str | None:
        if isinstance(value, str):
            return value or None
        if isinstance(value, dict):
            for k in ("task_id", "id", "work_item", "key"):
                if value.get(k):
                    return str(value[k])
        return None

    def _declared_work_item(self, tree, path: str) -> str | None | bool:
        """The work item of the receipt stored at `path` in `tree`.

        False means "there is a file there and it is not a receipt of a readable work item" — a
        distinct answer from None ("no file there"), because only the first one may block the rule."""
        if not tree.exists(path):
            return None
        try:
            doc = json.loads(tree.text(path))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        if not (isinstance(doc, dict) and str(doc.get("schema", "")).endswith("Receipt/v1")):
            return False
        return self._work_item_id(doc.get("work_item")) or False

    def superseded_self_exclusions(self) -> dict[str, dict]:
        """The one entity this run supersedes by construction (DEC-AUP-0035).

        DEC-AUP-0034 excludes an UNCHANGED historical receipt. It cannot reach this case and was not
        meant to: a re-issued receipt changes its own file, so the change set contains it and its
        bytes differ at base and head — conditions (b) and (c) both fail, correctly, because editing
        a receipt IS an ordinary change to a file. What makes this one different is not that the
        file changed; it is WHOSE record it is. The document at that path is the previous draft of
        the very receipt being written now, for the same work item, and control had to hand-write an
        expiring exemption for it on ARAS #195 and #196 — an expiry on a condition that never
        expires, which is exactly what DEC-AUP-0034 refused to institutionalise.

        Three conditions, each separately falsifiable:

          1. The matrix declares NO verifier of any kind for the node type — the same condition as
             DEC-AUP-0034 (1), and the reason the excluded verdict carries no information.
          2. The entity's path is the path this run writes its receipt to (`--out`, relative to the
             repository). A receipt cannot supersede a document it is not replacing.
          3. Every version of that file which exists at base or head declares the SAME work item as
             this run (`--work-item`). A different work item's receipt at that path is a different
             record and keeps its verdict; so does a file that is not a readable receipt at all.
        """
        if not (self.self_receipt_rel and self.work_item):
            return {}
        eid = f"receipt:{self.self_receipt_rel}"
        ent = self.entities.get(eid)
        if ent is None:
            return {}
        node = ent["node"]
        ntype = node.get("type") or "receipt"
        spec = self.matrix["node_types"].get(ntype)
        if not isinstance(spec, dict) or (spec.get("mandatory") or []) or (spec.get("selectable") or []):
            return {}
        path = self.self_receipt_rel
        declared = {rev: self._declared_work_item(tree, path)
                    for rev, tree in (("base", self.tree_base), ("head", self.tree_head))}
        present = [v for v in declared.values() if v is not None]
        if not present or any(v is False or v != self.work_item for v in present):
            return {}
        def digest(tree):
            return sha_bytes(tree.files[path]) if tree.exists(path) else None
        return {eid: {"entity": eid, "node_type": ntype, "path": path,
                      "content_hash": {"base": digest(self.tree_base), "head": digest(self.tree_head)},
                      "reason": (spec.get("not_measured_reason")
                                 or f"the verifier matrix declares no verifier for node type {ntype}")
                                + f"; superseded by construction — this run re-issues the receipt at {path} "
                                  f"for work item {self.work_item}",
                      "rule": "DEC-AUP-0035",
                      "superseded": {"work_item": self.work_item, "receipt_path": path}}}

    def superseded_self_note(self) -> str | None:
        """Why the rule did NOT apply, when a caller was one step away from it.

        Writing the receipt outside the repository is the documented workaround for older defects,
        and under it the rule is unreachable: nothing in the tree is the path this run writes to. A
        reader seeing I14 on a receipt of their own work item has to be told that, or the absence of
        the exclusion looks like a judgement about the document."""
        if self.self_receipt_rel or not self.work_item:
            return None
        out = getattr(self.a, "out", None)
        for eid, ent in self.entities.items():
            if not eid.startswith("receipt:"):
                continue
            path = ent["node"].get("path")
            if path and self._declared_work_item(self.tree_head, path) == self.work_item:
                return (f"DEC-AUP-0035 not applied to {eid}: it declares this run's work item "
                        f"{self.work_item}, but the receipt is being written to "
                        f"{out if out else '(no --out)'}, which is outside this repository, so no "
                        f"path in the tree is the one this run supersedes.")
        return None

    def aggregate(self, q: dict) -> dict:
        m = self.matrix
        verdicts = []
        self.excluded = self.structural_exclusions()
        superseded = self.superseded_self_exclusions()
        if superseded:
            self.excluded.update(superseded)
            for x in superseded.values():
                self.events.append({"code": "SUPERSEDED_SELF_EXCLUSION", "rule": "DEC-AUP-0035",
                                    "entity": x["entity"],
                                    "text": f"the receipt at {x['path']} is the previous version of the one this "
                                            f"run is writing, for the same work item {x['superseded']['work_item']} "
                                            f"— superseded by construction, so it owes this change no verdict"})
        note = self.superseded_self_note()
        if note:
            self.notes.append(note)
            self.events.append({"code": "SUPERSEDED_SELF_NOT_APPLICABLE", "rule": "DEC-AUP-0035", "text": note})
        if self.excluded:
            by_type: dict[str, int] = {}
            for x in self.excluded.values():
                by_type[x["node_type"]] = by_type.get(x["node_type"], 0) + 1
            self.events.append({"code": "STRUCTURAL_EXCLUSION", "rule": "DEC-AUP-0034",
                                "text": f"{len(self.excluded)} affected entity(ies) owe no verdict "
                                        f"({', '.join(f'{k}: {v}' for k, v in sorted(by_type.items()))}): "
                                        f"unchanged at both revisions and given no verifier by the matrix"})
        for eid in sorted(self.entities):
            if eid in self.excluded:
                continue
            ent = self.entities[eid]
            n = ent["node"]
            required = ent["required"]
            got: dict[str, tuple[str, str, str]] = {}   # verifier → (vid, verdict, reason)
            for v in self.verifiers:
                if eid in v["entities"] and eid in self.ev.get(v["id"], {}):
                    vd, why = self.ev[v["id"]][eid]
                    key = self.matrix_id_of(v)
                    prev = got.get(key)
                    if prev is None or vd == "failed" or (vd == "not_measured" and prev[1] == "verified"):
                        got[key] = (v["id"], vd, why)
            failed = [g for g in got.values() if g[1] == "failed"]
            missing = [r for r in required if r not in got]
            nm = [g for g in got.values() if g[1] == "not_measured"]
            rec = {"entity": eid}
            if failed and "aggregate_failed_wins" in self.rules:
                rec["verdict"] = "failed"
                rec["verifier_ids"] = sorted({g[0] for g in got.values()})
                rec["reason"] = "; ".join(f"{g[0]}: {g[2]}" for g in failed)[:600]
            elif (missing or nm) and "missing_required_not_measured" in self.rules:
                rec["verdict"] = "not_measured"
                reasons = []
                for r in missing:
                    if r in self.disabled:
                        reasons.append(f"MANDATORY_VERIFIER_DISABLED: {r}")
                    else:
                        reasons.append(f"required verifier {r} produced no verdict for this entity")
                reasons += [f"{g[0]}: {g[2]}" for g in nm]
                rec["reason"] = "; ".join(reasons)[:600]
                if got:
                    rec["verifier_ids"] = sorted({g[0] for g in got.values()})
            elif not required:
                rec["verdict"] = "not_measured"
                rec["reason"] = m["node_types"].get(n["type"], {}).get("not_measured_reason") or f"no applicable verifier in the matrix for node type {n['type']}"
            elif not got:
                rec["verdict"] = "not_measured"
                rec["reason"] = "required verifiers ran but produced no verdict for this entity"
            else:
                rec["verdict"] = "verified"
                rec["verifier_ids"] = sorted({g[0] for g in got.values()})
                rec["reason"] = "; ".join(f"{g[0]}: {g[2]}" for g in got.values())[:600]
            if rec["verdict"] == "verified" and ent.get("inferred_boundary") and "inferred_boundary_hold" in self.rules:
                if eid in self.canary_verified:
                    rec["reason"] = ("reached through an inferred edge across a service/repo boundary and listed verified by a "
                                     "canary on the live contour (matrix P6 lifted by AUP-GRAPH-008); ") + rec["reason"]
                else:
                    rec["verdict"] = "not_measured"
                    rec["reason"] = ("reached through an inferred edge across a service/repo boundary: a canary must list it "
                                     "before verified (matrix P6, GRAPH-008); ") + rec["reason"]
            verdicts.append(rec)
        if "every_entity_verdict" not in self.rules and verdicts:
            verdicts = verdicts[:-1]   # mutant: drop one verdict
        vs = {v["verdict"] for v in verdicts}
        if "admission_rule" in self.rules:
            if "failed" in vs:
                adm = "refused"
            elif "not_measured" in vs or not verdicts:
                adm = "paused_safe"
            else:
                adm = "admitted"
        else:
            adm = "admitted"
        rec = {"schema": "ChangeAdmissionReceipt/v1", "receipt_id": f"car-verify-{self.captured_at.replace('-', '').replace(':', '')}-{(self.head or self.repo.head())[:8]}",
               "captured_at_utc": self.captured_at, "host": os.uname().nodename, "producer": {"tool": TOOL, "version": VERSION},
               "decision_ref": "DEC-AUP-0008", "repo": q["repo"],
               "graph": {k: q["graph"][k] for k in ("path", "source_commit", "graph_digest", "builder_version", "built_at_utc")},
               "tree": q["tree"], "staleness": {k: v for k, v in q["staleness"].items() if k != "checked_nodes"},
               "change_set": dict(q["change_set"]), "impact_set": {k: v for k, v in q["impact_set"].items() if k != "files"},
               "verifiers": self.verifiers, "verdicts": verdicts, "exemptions": [],
               "structural_exclusions": sorted(self.excluded.values(), key=lambda x: x["entity"]),
               "admission": {"verdict": adm, "rule": "admitted requires every verdict = verified; failed without exemption ⇒ refused; not_measured "
                                                     "without exemption ⇒ paused_safe; exemptions (owner + expiry) are attached by the admitting agent, "
                                                     "never by the verifier (DEC-AUP-0008, matrix P1/P4)",
                             "structural_exclusion_rule": self.STRUCTURAL_EXCLUSION_RULE,
                             "superseded_self_rule": self.SUPERSEDED_SELF_RULE},
               "notes": [f"DRAFT produced by `arcana verify` ({TOOL} {VERSION}) from matrix {rel_ref(MATRIX_PATH)}; selection rule: {self.matrix['selection_rule'][:120]}…",
                         f"profile: {self.profile_ref}; baseline: {self.baseline_ref} ({self.baseline_status}); selected: {sorted(self.selected) or 'none'}; disabled: {sorted(self.disabled) or 'none'}",
                         *self.notes],
               "verify": {"events": self.events, "required_by_entity": {e: ent["required"] for e, ent in sorted(self.entities.items())},
                          "seconds": {"prepare": self.prep_seconds, "verifiers": round(sum(v.get("duration_s", 0) for v in self.verifiers), 2)}}}
        if "head_graph" in q:
            rec["head_graph"] = q["head_graph"]
            rec["revision_selection"] = q["revision_selection"]
            if q["revision_selection"]["unmeasured_head_files"] and adm != "refused":
                rec["admission"]["verdict"] = "paused_safe"
        if "empty_impact_explanation" in q:
            rec["empty_impact_explanation"] = q["empty_impact_explanation"]
        if self.a.work_item:
            rec["work_item"] = self.a.work_item
        if self.self_receipt_rel:
            # The anchor of DEC-AUP-0035: an exclusion claiming "this is the previous version of me"
            # is checkable only against the path this document was actually written to, and
            # admit_change compares this field with where it FOUND the receipt.
            rec["receipt_path"] = self.self_receipt_rel
        return rec

    def matrix_id_of(self, v: dict) -> str:
        vid = v["id"]
        if vid.startswith("v-type-check"):
            return "type_check"
        if vid.startswith("v-route-config"):
            return "route_config_consistency"
        if vid.startswith("v-targeted-test"):
            return "targeted_test"
        if vid.startswith("v-property"):
            return "property_check"
        if vid.startswith("v-crash-"):
            return vid[len("v-crash-"):]
        return {"v-contract-diff": "contract_diff", "v-schema-diff": "schema_diff", "v-config-schema": "config_schema",
                "v-fitness": "fitness_rules", "v-doc-reference": "doc_reference"}.get(vid, v["kind"])

    def run_verifier(self, mid: str, fn) -> None:
        """One verifier's crash costs that verifier's verdicts — never the whole receipt.

        A verifier that raises used to kill the run: no receipt was written at all, and the caller
        read that as «the author skipped the tool» rather than «the tool broke». That is how one
        wrong field name (`contract_diff.Refusal.detail` read as `.reason`, 300e04a → ccd3f57) made
        the gate look unusable on every ordinary Python repository. Containing it does NOT hide the
        crash: the traceback is captured verbatim as the verifier's output, every entity the
        verifier owed a verdict gets `not_measured` naming the exception, and `VERIFIER_CRASHED`
        goes into the receipt's events — so the admission can never be `admitted` on a crash, only
        `paused_safe`. not_measured is not a pass (DEC-AUP-0008).
        """
        started, t0 = now_iso(), time.monotonic()
        try:
            fn()
        except Exception as e:                              # noqa: BLE001 — a verifier bug is a verdict, not an exit
            tb = traceback.format_exc()
            try:
                ents = self.needing(mid)
            except Exception:                               # the entity table itself is unusable
                ents = []
            self.events.append({"code": "VERIFIER_CRASHED", "verifier": mid,
                                "text": f"{type(e).__name__}: {e}"[:400]})
            self.record(f"v-crash-{mid}", mid, f"verify.py {mid} (crashed)", ents, 2, tb, started,
                        round(time.monotonic() - t0, 2), f"crashed: {type(e).__name__}",
                        {eid: ("not_measured", f"{mid} crashed: {type(e).__name__}: {e}"[:300]) for eid in ents})

    # ---- run
    def run(self) -> tuple[dict, int]:
        t_all = time.monotonic()
        try:
            q = self.impact_query()
        except impact.Refusal as r:
            doc = impact.refusal_doc(getattr(self, "idx", None), r, mode="diff" if self.a.diff else "worktree", tree_commit=None, tree_dirty=None,
                                     repo=self.repo, graph_path=getattr(self, "graph_path", None), files=[])
            return doc, 2
        self.change_files = q["change_set"]["files"]
        self.prepare_head()
        self.load_baseline()
        self.collect_entities(q)
        for mid, fn in (("type_check", self.v_type_check), ("contract_diff", self.v_contract_diff),
                        ("route_config_consistency", self.v_route_config), ("schema_diff", self.v_schema_diff),
                        ("config_schema", self.v_config_schema), ("fitness_rules", self.v_fitness),
                        ("doc_reference", self.v_doc_reference), ("canary", self.v_canary),
                        ("targeted_test", self.v_targeted_test), ("property_check", self.v_property_check)):
            self.run_verifier(mid, fn)
        rec = self.aggregate(q)
        rec["verify"]["seconds"]["total"] = round(time.monotonic() - t_all, 2)
        rec["verify"]["events"] = self.events + [{"code": e} for e in q.get("events", [])]
        code = 0 if rec["admission"]["verdict"] == "admitted" else 1
        if q.get("events"):
            code = 3
        return rec, code


def human(rec: dict) -> str:
    if rec.get("schema") != "ChangeAdmissionReceipt/v1":
        r = rec.get("refusal") or {}
        return f"REFUSED {r.get('code')}: {r.get('reason')}"
    counts = {}
    for v in rec["verdicts"]:
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
    lines = [f"arcana verify — {rec['repo'].get('name')} {rec['change_set']['mode']} "
             f"{(rec['change_set'].get('base') or '')[:12]}{'..' if rec['change_set'].get('base') else ''}{(rec['change_set'].get('head') or rec['tree']['commit'])[:12]}",
             f"graph {rec['graph']['source_commit'][:12]} {rec['staleness']['verdict']}; change set {len(rec['change_set']['files'])} file(s); "
             f"impact core {len(rec['impact_set']['deterministic_core'])} / tail {len(rec['impact_set']['inferred_tail'])}",
             f"verifiers: " + ", ".join(f"{v['id']} exit {v['exit_code']} ({v['duration_s']}s)" for v in rec["verifiers"]),
             f"verdicts: {counts}  →  admission {rec['admission']['verdict'].upper()}  ({rec['verify']['seconds']['total']}s)"]
    for v in rec["verdicts"]:
        if v["verdict"] != "verified":
            lines.append(f"  {v['verdict']:12} {v['entity']}: {v.get('reason', '')[:140]}")
    for e in rec["verify"]["events"]:
        lines.append(f"  event {e.get('code')}: {(e.get('reason') or e.get('text') or '')[:160]}")
    return "\n".join(lines)


# ----------------------------------------------------------------------------------------------- freeze baseline
def freeze_baseline(a) -> int:
    repo = impact.Repo(Path(a.repo))
    rev = repo.rev(a.rev or "HEAD")
    tree = build_graph.load_tree_git(repo.top, rev, "")
    graph = build_graph.build(repo.top, rev=rev, built_at=build_graph.FIXED_BUILT_AT)
    scan = TreeScan(tree)
    entries = fitness_violations(graph, tree, scan, {"fr01", "fr02", "fr03", "fr04", "fr05"})
    cv, declared, sources, _ = config_violations(graph, tree, scan, [])
    entries += cv
    bl = make_baseline(repo.name, rev, entries, a.owner, a.expires, "explicit-freeze")
    bl["summary"] = {"entries": len(entries), "by_rule": {}, "env_sources": sources, "declared_keys": len(declared)}
    for e in entries:
        bl["summary"]["by_rule"][e["rule"]] = bl["summary"]["by_rule"].get(e["rule"], 0) + 1
    out = Path(a.freeze_baseline)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dump(bl))
    print(f"FitnessBaseline/v1 {out}: {len(entries)} entries {bl['summary']['by_rule']} frozen at {rev[:12]}, owner {a.owner}, expires {a.expires}")
    return 0


# ----------------------------------------------------------------------------------------------- selftest
FAULTS = [
    # id, verifier that must catch it, failing entity, description, edits: [(path, op, arg1, arg2)]
    {"id": "F12-canary-route-failed", "verifier": "canary", "entity": "route:GET /tasks/:taskId",
     "what": "the live contour answers 404 for a route the change touches: the canary is the only verifier of this class "
             "(AUP-GRAPH-007 measured route recall as not_measured offline), so disabling it lets the mutant survive",
     "canary": [{"entity": "route:GET /tasks/:taskId", "verdict": "failed",
                 "reason": "404 on the live contour: the route is not served", "probe_ids": ["ts-mini-route"]}],
     "edits": [("apps/api/src/tasks/tasks.controller.ts", "append", "// route touched by the canary battery\n", None)]},
    {"id": "S00-clean", "verifier": None, "entity": None, "what": "comment-only edit of tasks.service.ts: nothing may fail",
     "edits": [("apps/api/src/tasks/tasks.service.ts", "append", "// touched by verify0 selftest (no semantic change)\n", None)]},
    {"id": "S01-clean-python", "verifier": None, "entity": None,
     "what": "comment-only edit of a Python unit: its deployable enters the impact set, and AUP-GRAPH-009 "
             "polyglot2 says a deployable holding no TypeScript carries no type_check obligation — without "
             "that rule this fixture is pinned at not_measured 'no tsconfig for deployable' forever",
     "edits": [("services/report/src/report/metrics.py", "append", "# touched by verify0 selftest (no semantic change)\n", None)]},
    {"id": "F01-type-check-caller", "verifier": "type_check", "entity": "code_unit:apps/api/src/tasks/tasks.controller.ts",
     "what": "service method renamed (findOne → findById): the caller no longer compiles, the changed unit itself does",
     "edits": [("apps/api/src/tasks/tasks.service.ts", "replace", "async findOne(taskId: string)", "async findById(taskId: string)")]},
    {"id": "F02-contract-required-field", "verifier": "contract_diff", "entity": "code_unit:apps/api/src/tasks/tasks.service.ts",
     "what": "CreateTaskDto.status made required (FIELD_MADE_REQUIRED): the breaking change sits on a key the reading service uses — consumer ⊄ provider (the contract itself and the route fail too); tsc still passes. The web client is bound to the ROUTE by an inferred http-client edge: not projected onto the DTO (GRAPH-004 limitation, canary in GRAPH-008)",
     "edits": [("apps/api/src/tasks/dto/create-task.dto.ts", "replace", "  @IsIn(['todo', 'done'])\n  @IsOptional()\n  status?: TaskStatus;", "  @IsIn(['todo', 'done'])\n  status: TaskStatus;")]},
    {"id": "F03-route-unregistered", "verifier": "route_config_consistency", "entity": "route:POST /tasks",
     "what": "controller class renamed and dropped from TasksModule.controllers: the file providing POST /tasks is registered in no @Module reachable from the root (RC-02); tsc passes",
     "edits": [("apps/api/src/tasks/tasks.controller.ts", "replace", "export class TasksController {", "export class TaskItemsController {"),
               ("apps/api/src/tasks/tasks.module.ts", "replace", "import { TasksController } from './tasks.controller';\n", ""),
               ("apps/api/src/tasks/tasks.module.ts", "replace", "controllers: [TasksController], ", "")]},
    {"id": "F04-fitness-forbidden-import", "verifier": "fitness_rules", "entity": "code_unit:apps/api/src/tasks/tasks.controller.ts",
     "what": "controller imports PrismaService (transport → persistence, FR-01) — the card's fixture case",
     "edits": [("apps/api/src/tasks/tasks.controller.ts", "replace", "import { TasksService } from './tasks.service';",
                "import { TasksService } from './tasks.service';\nimport { PrismaService } from '../prisma/prisma.service';"),
               ("apps/api/src/tasks/tasks.controller.ts", "replace", "constructor(private readonly tasksService: TasksService) {}",
                "constructor(private readonly tasksService: TasksService, private readonly prisma: PrismaService) {}")]},
    {"id": "F05-schema-field-removed", "verifier": "schema_diff", "entity": "data_model:Task",
     "what": "Task.status removed from schema.prisma while tasks.service.ts still references it (FIELD_REMOVED with a consumer)",
     "edits": [("apps/api/prisma/schema.prisma", "replace", "  status    String\n", "")]},
    {"id": "F06-config-undeclared-key", "verifier": "config_schema", "entity": "code_unit:apps/api/src/tasks/tasks.service.ts",
     "what": "a new process.env.TASKS_SIGNING_KEY read with no declaration (UNDECLARED_CONFIG_KEY); pre-existing undeclared keys are frozen",
     "edits": [("apps/api/src/tasks/tasks.service.ts", "replace", "  private readonly docsUrl = 'https://example.invalid//not-a-comment';",
                "  private readonly docsUrl = 'https://example.invalid//not-a-comment';\n  private readonly signingKey = process.env.TASKS_SIGNING_KEY ?? '';"),
               (".env.example", "write", "DATABASE_URL=\nWEBHOOK_URL=\nWEB_URL=\nNEXT_PUBLIC_API_URL=\nPORT=3500\n", None)]},
    {"id": "F07-doc-dangling", "verifier": "doc_reference", "entity": "document:apps/api/docs/tasks.md",
     "what": "tasks.service.ts moved to task.service.ts with every import updated: code compiles, the docs still name the old path",
     "edits": [("apps/api/src/tasks/tasks.service.ts", "move", "apps/api/src/tasks/task.service.ts", None),
               ("apps/api/src/tasks/tasks.controller.ts", "replace", "'./tasks.service'", "'./task.service'"),
               ("apps/api/src/tasks/tasks.module.ts", "replace", "'./tasks.service'", "'./task.service'"),
               ("apps/api/test/tasks.service.spec.ts", "replace", "'../src/tasks/tasks.service'", "'../src/tasks/task.service'")]},
    {"id": "F08-fitness-cycle", "verifier": "fitness_rules", "entity": "code_unit:apps/api/src/notify/notify.constants.ts",
     "what": "notify.constants.ts value-imports tasks.service.ts: cycle tasks.service → notifier.service → notify.constants → tasks.service (FR-02)",
     "edits": [("apps/api/src/notify/notify.constants.ts", "append", "import { TasksService } from '../tasks/tasks.service';\nexport const SERVICE_NAME = TasksService.name;\n", None)]},
    {"id": "F09-fitness-module-boundary", "verifier": "fitness_rules", "entity": "code_unit:apps/api/src/tasks/tasks.service.ts",
     "what": "tasks.service.ts imports notify's processor (another module's processor is not its surface, FR-03)",
     "edits": [("apps/api/src/tasks/tasks.service.ts", "replace", "import { NotifierService } from '../notify/notifier.service';",
                "import { NotifierService } from '../notify/notifier.service';\nimport { NotifyProcessor } from '../notify/notify.processor';\nexport const PROCESSOR = NotifyProcessor;")]},
    {"id": "F10-fitness-deployable-boundary", "verifier": "fitness_rules", "entity": "code_unit:apps/web/lib/api/tasks.ts",
     "what": "apps/web imports a DTO file of apps/api directly (service → service import, FR-05)",
     "edits": [("apps/web/lib/api/tasks.ts", "replace", "import apiClient from './client';",
                "import apiClient from './client';\nimport { CreateTaskDto } from '../../../api/src/tasks/dto/create-task.dto';\nexport const DTO = CreateTaskDto;")]},
    {"id": "F11-fitness-reuse-marker", "verifier": "fitness_rules", "entity": "code_unit:apps/api/src/tasks/tasks.controller.ts",
     "what": "a new `reuse: @arcanada/never-declared` marker names no dependency / workspace package (FR-04); the pre-existing marker in tasks.service.ts is frozen",
     "edits": [("apps/api/src/tasks/tasks.controller.ts", "append", "// reuse: @arcanada/never-declared — marker for the FR-04 battery\n", None)]},
    {"id": "F12-schema-invalid", "verifier": "schema_diff", "entity": "data_model:Task",
     "what": "schema.prisma made syntactically invalid (unterminated model): prisma validate / parse fails",
     "edits": [("apps/api/prisma/schema.prisma", "append", "\nmodel Broken {\n  id String @id\n", None)]},
]


def apply_edits(root: Path, edits: list[tuple]):
    for path, op, a1, a2 in edits:
        p = root / path
        if op == "append":
            p.write_text(p.read_text() + a1)
        elif op == "write":
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(a1)
        elif op == "replace":
            s = p.read_text()
            if a1 not in s:
                raise SystemExit(f"selftest fixture edit failed: {a1!r} not in {path}")
            p.write_text(s.replace(a1, a2, 1))
        elif op == "move":
            (root / a1).parent.mkdir(parents=True, exist_ok=True)
            p.rename(root / a1)


def fresh_scratch(work: Path) -> Path:
    scratch = work / "ts-mini"
    if scratch.exists():
        shutil.rmtree(scratch)
    shutil.copytree(TS_MINI, scratch)
    env = {"GIT_AUTHOR_NAME": "verify0", "GIT_AUTHOR_EMAIL": "verify0@example.invalid", "GIT_COMMITTER_NAME": "verify0",
           "GIT_COMMITTER_EMAIL": "verify0@example.invalid", "GIT_AUTHOR_DATE": "2026-09-05T00:00:00Z", "GIT_COMMITTER_DATE": "2026-09-05T00:00:00Z",
           "HOME": str(work)}
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"], ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "ts-mini base"]):
        subprocess.run(cmd, cwd=scratch, check=True, capture_output=True, env={**os.environ, **env})
    return scratch


def write_canary(work: Path, name: str, entity_verdicts: list[dict], phase: str = "pre") -> str:
    """Historical unbound negative fixture: no live contour or executed probes."""
    doc = {"schema": "CanaryResult/v1", "card": "AUP-GRAPH-008", "captured_at_utc": now_iso(),
           "producer": {"tool": "verify.py legacy-unbound-fixture", "version": "1"}, "model": "synthetic",
           "provisional_until_fable_review": True, "plan": {"id": f"ts-mini-{name}"}, "environment": "ts-mini-canary-contour",
           "phase": phase, "read_only": True, "resident_version": "fixture", "probes": [], "entity_verdicts": entity_verdicts,
           "counters": {"verified": 0, "failed": 0, "not_measured": 0}}
    p = work / f"canary-{name}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=1))
    return str(p)


def run_scenario(scratch: Path, work: Path, fault: dict, tsc: str | None, prisma: str | None, disable: str = "", disable_rule: str = "",
                 select: str = "", graph_path: Path | None = None, canary: list | None = None) -> tuple[dict, int]:
    # reset the scratch tree to the base commit, apply the fault, run in worktree mode
    subprocess.run(["git", "checkout", "-q", "--", "."], cwd=scratch, check=True, capture_output=True)
    subprocess.run(["git", "clean", "-qfd"], cwd=scratch, check=True, capture_output=True)
    apply_edits(scratch, fault["edits"])
    a = argparse.Namespace(repo=str(scratch), diff=None, worktree=True, files=None, graph=str(graph_path) if graph_path else "auto", max_depth=fault.get("max_depth"),
                           select=select, disable=disable, disable_rule=disable_rule, profile=str(VFIX / "profile.ts-mini.json"), baseline=None,
                           tsc=tsc, prisma=prisma, workdir=str(work / "wd"), out=None, verifier_out=str(work / "vout" / fault["id"] / (disable or disable_rule or "on")),
                           json=False, work_item=None, canary=canary)
    v = Verify(a, load_matrix())
    return v.run()


def selftest(a) -> int:
    t0 = time.monotonic()
    checks: list[dict] = []
    work = Path(a.workdir) if a.workdir else Path(os.environ.get("TMPDIR", "/tmp")) / "arcana-verify-selftest"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    matrix = load_matrix()
    gs, rs = schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH), schema_check.load_schema(schema_check.RECEIPT_SCHEMA_PATH)

    def check(name, ok, **kw):
        checks.append({"name": name, "ok": bool(ok), **kw})
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  {kw}"))

    # M: matrix consistency with the graph schema
    edge_types = set(gs["edge_types"])
    check("matrix covers every edge type of RelationshipGraph/v1", set(matrix["edge_types"]) == edge_types, missing=sorted(edge_types - set(matrix["edge_types"])))
    check("matrix covers every node type", set(matrix["node_types"]) == set(gs["node_types"]))
    bad = [(t, v) for t, d in matrix["edge_types"].items() for v in d["mandatory"] + d["selectable"] if v not in matrix["verifiers"]]
    check("every verifier named by the matrix is defined", not bad, bad=bad)
    kinds = set(rs["fields"]["verifier"]["kind_values"])
    check("every matrix verifier maps to a ChangeAdmissionReceipt/v1 verifier kind", all(v["kind"] in kinds for v in matrix["verifiers"].values()))
    check("tests are selectable, never mandatory (P3)", all("targeted_test" not in d["mandatory"] for d in list(matrix["edge_types"].values()) + list(matrix["node_types"].values())))
    check("contract edges require contract_diff + type_check (spec: contract edge → contract-diff + type-check of both sides)",
          {"contract_diff", "type_check"} <= set(matrix["edge_types"]["implements_contract"]["mandatory"]) and {"contract_diff", "type_check"} <= set(matrix["edge_types"]["consumes_contract"]["mandatory"]))
    check("route edge requires controller compile + contract-diff + route/config consistency",
          {"type_check", "contract_diff", "route_config_consistency"} <= set(matrix["edge_types"]["provides_route"]["mandatory"]))
    check("data edge requires schema_diff, config edge requires config_schema, any code node requires fitness_rules",
          "schema_diff" in matrix["edge_types"]["maps_model"]["mandatory"] and "config_schema" in matrix["edge_types"]["reads_config"]["mandatory"]
          and "fitness_rules" in matrix["node_types"]["code_unit"]["mandatory"])
    hints = {t: d.get("mandatory_verifier_hint", "") for t, d in gs["edge_types"].items()}
    check("matrix mandatory sets agree with the graph schema's mandatory_verifier_hint text",
          "contract" in hints["implements_contract"] and "type-check" in hints["imports"] and "schema" in hints["maps_model"] and "config" in hints["reads_config"])

    scratch = fresh_scratch(work)
    tsc = a.tsc or find_bin("tsc", None, scratch, scratch, [])
    prisma = a.prisma or find_bin("prisma", None, scratch, scratch, [])
    limitations = ["Historical unbound canary assertions are negative controls, not measured fault-kill calibration. Committed-source HTTP/consumer regressions run separately within this selftest."]
    if not tsc:
        limitations.append("tsc not available: type_check rows are not_measured in the battery")
    if not prisma:
        limitations.append("prisma CLI not available: prisma validate half of schema_diff not run in the battery")
    # base graph of the scratch repo (its HEAD): built once, reused by every scenario (worktree mode: graph at HEAD)
    base_graph = work / "graph-base.json"
    base_graph.write_bytes(build_graph.dump_graph(build_graph.build(scratch, rev="HEAD", built_at=build_graph.FIXED_BUILT_AT)))

    scenarios: dict[str, dict] = {}
    battery = {"faults": [], "rules": []}
    for fault in FAULTS:
        fc = [write_canary(work, fault["id"], fault["canary"])] if fault.get("canary") else None
        rec, code = run_scenario(scratch, work, fault, tsc, prisma, graph_path=base_graph, canary=fc)
        scenarios[fault["id"]] = rec
        fid = fault["id"]
        if rec.get("schema") != "ChangeAdmissionReceipt/v1":
            check(f"{fid}: draft produced", False, refusal=rec.get("refusal"))
            continue
        cls = schema_check.classify(rec, gs, rs)
        check(f"{fid}: draft is ChangeAdmissionReceipt/v1 conformant", cls["verdict"] == "conformant", codes=cls.get("codes"))
        imp = rec["impact_set"]
        # Under a global fallback the whole repository is ONE measurement, and impact.py still lists
        # every node in deterministic_core so a reader can see the blast radius — those rows ARE the
        # radius, not N separate entities to verify. `impact_pair.selected()` already draws that
        # line (and says so, citing muneral #32/#55/#60); this assertion did not, so it demanded a
        # verdict per node and F06 — whose fixture writes .env.example, a `global_config` path —
        # failed with all 59 entities "missing" while the receipt was correct. Reuse selected()
        # rather than re-deriving the rule: a second implementation of one rule is how the polyglot2
        # discharge ended up half-applied.
        seeds = [n for f in rec["change_set"]["files"]
                 for n in (f.get("node_ids") or ([f["node_id"]] if f.get("node_id") else []))]
        want = impact_pair.selected({"impact_set": imp, "seeds": seeds})
        if not imp.get("global_fallback", {}).get("triggered"):
            want = {e["entity"] for e in imp["deterministic_core"] + imp["inferred_tail"]} | set(seeds)
        have = {v["entity"] for v in rec["verdicts"]}
        # A structurally excluded entity is ACCOUNTED FOR, not missing (DEC-AUP-0034): it owes no
        # verdict because the matrix gives its node type no verifier and its bytes did not change.
        # The two sets must still be disjoint and must still cover `want` exactly — an entity that
        # slipped into both, or into neither, is the failure this check exists to catch.
        excluded = {x["entity"] for x in rec.get("structural_exclusions", [])}
        check(f"{fid}: every affected entity and changed node has exactly one tri-valued verdict or a recorded "
              f"structural exclusion ({len(want)})",
              want == have | excluded and not (have & excluded) and len(have) == len(rec["verdicts"])
              and all(v["verdict"] in ("verified", "failed", "not_measured") for v in rec["verdicts"]),
              missing=sorted(want - have - excluded), extra=sorted((have | excluded) - want),
              both=sorted(have & excluded))
        by = {v["entity"]: v for v in rec["verdicts"]}
        failed = {v["entity"]: v for v in rec["verdicts"] if v["verdict"] == "failed"}
        if fault["verifier"] is None:
            check(f"{fid}: no entity failed", not failed, failed={k: v["reason"][:100] for k, v in failed.items()})
            nm = {v["entity"]: v["reason"][:80] for v in rec["verdicts"] if v["verdict"] == "not_measured"}
            # `RC-02 not evaluable` joins the list for the same reason the others are on it: the
            # verifier reports that its own precondition is absent, not that the entity went
            # unchecked. RC-02 asks whether a controller is registered under the NestJS root module,
            # and a Python service has no src/main.ts to read — the check is inapplicable, and saying
            # so is more honest than a verdict. Distinct from polyglot2 above, which removes an
            # obligation that can never be discharged; this one keeps not_measured and merely stops
            # the selftest from reading an inapplicable verifier as an omission.
            allowed = all(e.startswith(("work_item:", "receipt:")) or "inferred edge" in r or "does not include" in r or "unavailable" in r
                          or "not run" in r or "INFERRED_BOUNDARY_WITHOUT_CANARY" in r or "not evaluable" in r for e, r in nm.items())
            check(f"{fid}: not_measured only for work items / receipts / inferred boundary / canary-required entities / uncovered spec ({len(nm)})",
                  allowed, not_measured=nm)
            check(f"{fid}: admission is paused_safe (not_measured blocks unqualified admission), never admitted", rec["admission"]["verdict"] == "paused_safe")
            v_serv = by.get("code_unit:apps/api/src/tasks/tasks.service.ts", {})
            if v_serv:  # asserted where the TypeScript unit is in the impact set; S01 edits a Python one
                check(f"{fid}: the changed unit is verified by type_check + fitness_rules + contract_diff (its required set: no config / model edge of its own)",
                      v_serv.get("verdict") == "verified" and {"v-fitness", "v-type-check-apps-api-tsconfig", "v-contract-diff"} <= set(v_serv.get("verifier_ids", [])),
                      got=v_serv.get("verifier_ids"), verdict=v_serv.get("verdict"), reason=v_serv.get("reason", "")[:200])
                check(f"{fid}: pre-existing findings are frozen, not failed (reuse marker @arcanada/canonical-json, undeclared env keys)",
                      "frozen" in v_serv.get("reason", ""), reason=v_serv.get("reason", "")[:300])
            # AUP-GRAPH-009 polyglot2: a deployable holding no TypeScript must not carry a type_check
            # obligation it can never discharge. The fixture's Rust and Python deployables are the
            # subject; apps/api is the control, and it must KEEP the requirement — a rule that drops
            # the obligation everywhere would pass the first half of this check and is caught by the
            # second.
            non_ts = {e: by[e] for e in ("deployable_unit:crates/greeter-core", "deployable_unit:crates/greeter-cli",
                                         "deployable_unit:services/report") if e in by}
            # Assert on the OBLIGATION, not on one phrasing of its failure. An earlier version of
            # this check looked for "no tsconfig for deployable" and a mutant that removed the rule
            # SURVIVED it: without the discharge the reason reads "required verifier type_check
            # produced no verdict" instead, and a string match on the other wording stayed green.
            bad = {e: v.get("reason", "")[:90] for e, v in non_ts.items()
                   if "type_check" in v.get("reason", "") or v.get("verdict") == "not_measured"}
            ts_dep = by.get("deployable_unit:apps/api", {})
            # The control is asserted only where it is in scope. An assertion that cannot fail on a
            # fixture proves nothing about it, and `0 Rust/Python` would read as a pass — so the
            # subject count is printed and S01 is the fixture that makes it non-zero.
            ctl_ok = ("v-type-check-apps-api-tsconfig" in set(ts_dep.get("verifier_ids", []))) if ts_dep else True
            check(f"{fid}: {len(non_ts)} non-TypeScript deployable(s) carry no type_check obligation"
                  + (", TypeScript control still does" if ts_dep else " (TS control out of scope here)"),
                  not bad and ctl_ok,
                  non_ts_blocked_on_tsconfig=bad, ts_deployable_verifiers=ts_dep.get("verifier_ids"))
            continue
        if fault["verifier"] == "canary":
            legacy = by.get(fault["entity"], {})
            check(f"{fid}: historical unbound assertion remains not_measured, never a measured failure",
                  legacy.get("verdict") == "not_measured" and rec["admission"]["verdict"] != "admitted")
            battery.setdefault("legacy_unbound_controls", []).append({"fault": fid, "verdict": legacy.get("verdict"),
                "measurement": "not_measured: no actual source-bound probes in this historical fixture"})
            continue
        ent = fault["entity"]
        vrec = by.get(ent, {})
        vid_prefix = {"type_check": "v-type-check", "contract_diff": "v-contract-diff", "route_config_consistency": "v-route-config", "schema_diff": "v-schema-diff",
                      "config_schema": "v-config-schema", "fitness_rules": "v-fitness", "doc_reference": "v-doc-reference",
                      "canary": "v-canary"}[fault["verifier"]]
        caught = vrec.get("verdict") == "failed" and vid_prefix in (vrec.get("reason") or "")
        if fault["verifier"] == "type_check" and not tsc:
            caught = None
        if fault["verifier"] == "schema_diff" and fid == "F12-schema-invalid" and not prisma:
            caught = vrec.get("verdict") == "failed"
        check(f"{fid}: {fault['verifier']} fails {ent} (enabled → fault killed)", caught is not False, verdict=vrec.get("verdict"), reason=(vrec.get("reason") or "")[:240])
        check(f"{fid}: admission refused", rec["admission"]["verdict"] == "refused")
        # mutant: disable the verifier → the same fault must SURVIVE (no failed verdict for it) and the draft must not be admitted
        mrec, _ = run_scenario(scratch, work, fault, tsc, prisma, disable=fault["verifier"], graph_path=base_graph,
                               canary=([write_canary(work, fault["id"], fault["canary"])] if fault.get("canary") else None))
        mby = {v["entity"]: v for v in mrec.get("verdicts", [])}
        mv = mby.get(ent, {})
        survived = mv.get("verdict") == "not_measured" and "MANDATORY_VERIFIER_DISABLED" in (mv.get("reason") or "")
        others_failed = {e: v["reason"][:80] for e, v in mby.items() if v["verdict"] == "failed"}
        ev = [e for e in mrec.get("verify", {}).get("events", []) if e.get("code") == "MANDATORY_VERIFIER_DISABLED"]
        check(f"{fid}: with {fault['verifier']} disabled the mutant SURVIVES ({ent} not_measured, MANDATORY_VERIFIER_DISABLED event, draft never admitted)",
              survived and bool(ev) and mrec["admission"]["verdict"] != "admitted", verdict=mv.get("verdict"), reason=(mv.get("reason") or "")[:160], others_failed=others_failed)
        battery["faults"].append({"fault": fid, "verifier": fault["verifier"], "entity": ent, "what": fault["what"],
                                  "killed_when_enabled": bool(caught) if caught is not None else "not_measured (tsc absent)",
                                  "survived_when_disabled": survived, "other_verifiers_failed_when_disabled": others_failed})
    # per-verifier summary: every mandatory verifier is load-bearing
    for vid in MANDATORY_IDS:
        if vid == "canary":
            result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(Path(__file__).parent),
                                     "-p", "test_canary_evidence.py"], capture_output=True, text=True)
            check("canary source/probe binding: committed-source, HTTP producer and actual consumer regressions",
                  result.returncode == 0, output=(result.stdout + result.stderr)[-2000:])
            continue
        rows = [r for r in battery["faults"] if r["verifier"] == vid]
        check(f"mandatory verifier {vid}: ≥ 1 fault killed when enabled and surviving when disabled",
              any(r["killed_when_enabled"] is True and r["survived_when_disabled"] for r in rows) or (vid == "type_check" and not tsc), rows=len(rows))

    # internal-rule mutation battery over F01/F04/S00 expectations
    rule_exp = {
        "aggregate_failed_wins": ("F04-fitness-forbidden-import", lambda r: {v["entity"]: v for v in r["verdicts"]}["code_unit:apps/api/src/tasks/tasks.controller.ts"]["verdict"] == "failed"),
        "missing_required_not_measured": ("F04-fitness-forbidden-import", None),   # checked below with disable
        "disabled_mandatory_event": ("F04-fitness-forbidden-import", None),
        "inferred_boundary_hold": ("S00-unlimited", lambda r: any(v["entity"] == "code_unit:apps/web/__tests__/tasks.test.ts" and v["verdict"] == "not_measured" and "inferred edge" in v["reason"] for v in r["verdicts"])),
        "baseline_expiry": ("S00-clean", lambda r: not any(v["verdict"] == "failed" for v in r["verdicts"])),
        "admission_rule": ("F04-fitness-forbidden-import", lambda r: r["admission"]["verdict"] == "refused"),
        "every_entity_verdict": ("S00-clean", lambda r: schema_check.classify(r, gs, rs)["verdict"] == "conformant"),
        "changed_node_outgoing": ("F06-config-undeclared-key", lambda r: {v["entity"]: v for v in r["verdicts"]}["code_unit:apps/api/src/tasks/tasks.service.ts"]["verdict"] == "failed"),
    }
    s00 = next(f for f in FAULTS if f["id"] == "S00-clean")
    urec, _ = run_scenario(scratch, work, {**s00, "id": "S00-unlimited", "max_depth": -1}, tsc, prisma, graph_path=base_graph)
    uby = {v["entity"]: v for v in urec["verdicts"]}
    wt = uby.get("code_unit:apps/web/__tests__/tasks.test.ts", {})
    check("inferred boundary hold (P6): the web test reached only through the inferred http-client edge is not_measured although tsc + fitness verified it",
          wt.get("verdict") == "not_measured"
          and ("inferred edge" in wt.get("reason", "") or "INFERRED_BOUNDARY_WITHOUT_CANARY" in wt.get("reason", ""))
          and {"v-type-check-apps-web-tsconfig", "v-fitness"} <= set(wt.get("verifier_ids", [])),
          verdict=wt.get("verdict"), reason=wt.get("reason", "")[:160], ids=wt.get("verifier_ids"))
    # Historical empty-probe assertions are now negative controls. Actual bound
    # positive/failure paths are exercised by test_canary_evidence.py above.
    WEB_TEST = "code_unit:apps/web/__tests__/tasks.test.ts"
    lift = [write_canary(work, "p6-lift", [{"entity": WEB_TEST, "verdict": "verified",
                                            "reason": "probe replayed the consumer call site on the ts-mini contour",
                                            "probe_ids": ["ts-mini-1"]}])]
    lrec, _ = run_scenario(scratch, work, {**s00, "id": "S00-canary-lift", "max_depth": -1}, tsc, prisma,
                           graph_path=base_graph, canary=lift)
    lwt = {v["entity"]: v for v in lrec["verdicts"]}.get(WEB_TEST, {})
    check("P6 remains held for a historical unbound verified assertion",
          lwt.get("verdict") == "not_measured" and "v-canary" in set(lwt.get("verifier_ids", [])) and "canary" in lwt.get("reason", ""),
          verdict=lwt.get("verdict"), ids=lwt.get("verifier_ids"), reason=lwt.get("reason", "")[:160])
    # A historical unbound failure assertion is not a measured candidate failure either.
    failc = [write_canary(work, "p6-fail", [{"entity": WEB_TEST, "verdict": "failed",
                                             "reason": "the replayed call site returned 404 on the live contour",
                                             "probe_ids": ["ts-mini-1"]}])]
    frec, _ = run_scenario(scratch, work, {**s00, "id": "S00-canary-failed", "max_depth": -1}, tsc, prisma,
                           graph_path=base_graph, canary=failc)
    fwt = {v["entity"]: v for v in frec["verdicts"]}.get(WEB_TEST, {})
    check("unbound historical failure remains not_measured and cannot admit",
          fwt.get("verdict") == "not_measured" and frec["admission"]["verdict"] != "admitted",
          verdict=fwt.get("verdict"), admission=frec["admission"]["verdict"])
    for rule, (fid, pred) in rule_exp.items():
        fault = next(f for f in FAULTS if f["id"] == fid) if fid != "S00-unlimited" else {**s00, "id": "S00-unlimited", "max_depth": -1}
        if pred is None:
            mrec, _ = run_scenario(scratch, work, fault, tsc, prisma, disable="fitness_rules", disable_rule=rule, graph_path=base_graph)
            mby = {v["entity"]: v for v in mrec.get("verdicts", [])}
            ent = mby.get("code_unit:apps/api/src/tasks/tasks.controller.ts", {})
            if rule == "missing_required_not_measured":
                killed = ent.get("verdict") != "not_measured" or "MANDATORY_VERIFIER_DISABLED" not in (ent.get("reason") or "")
            else:
                killed = not any(e.get("code") == "MANDATORY_VERIFIER_DISABLED" for e in mrec.get("verify", {}).get("events", []))
        else:
            mrec, _ = run_scenario(scratch, work, fault, tsc, prisma, disable_rule=rule, graph_path=base_graph)
            killed = mrec.get("schema") != "ChangeAdmissionReceipt/v1" or not pred(mrec)
        if rule == "baseline_expiry":
            # disabling expiry handling must be visible: with the rule off an expired baseline is silently trusted — we assert the
            # honest path instead: an expired explicit baseline yields BASELINE_EXPIRED and re-counts the frozen marker
            exp_bl = work / "expired-baseline.json"
            scan = TreeScan(build_graph.load_tree_git(scratch, "HEAD", ""))
            base_doc = json.loads(base_graph.read_text())
            entries = fitness_violations(base_doc, build_graph.load_tree_git(scratch, "HEAD", ""), scan, {"fr01", "fr02", "fr03", "fr04", "fr05"})
            exp_bl.write_bytes(dump(make_baseline("ts-mini", "0" * 40, entries, "selftest", "2026-01-01T00:00:00Z", "explicit-freeze")))
            subprocess.run(["git", "checkout", "-q", "--", "."], cwd=scratch, check=True, capture_output=True)
            apply_edits(scratch, fault["edits"])
            a2 = argparse.Namespace(repo=str(scratch), diff=None, worktree=True, files=None, graph=str(base_graph), max_depth=None, select="", disable="", disable_rule="",
                                    profile=str(VFIX / "profile.ts-mini.json"), baseline=str(exp_bl), tsc=tsc, prisma=prisma, workdir=str(work / "wd"),
                                    out=None, verifier_out=str(work / "vout" / "expired-baseline"), json=False, work_item=None)
            erec, _ = Verify(a2, matrix).run()
            eby = {v["entity"]: v for v in erec["verdicts"]}
            expired_seen = any(e.get("code") == "BASELINE_EXPIRED" for e in erec["verify"]["events"]) and eby["code_unit:apps/api/src/tasks/tasks.service.ts"]["verdict"] == "failed"
            check("expired explicit baseline: BASELINE_EXPIRED event and the frozen FR-04 marker counts again (failed)", expired_seen,
                  reason=eby["code_unit:apps/api/src/tasks/tasks.service.ts"].get("reason", "")[:160])
            a2.disable_rule = "baseline_expiry"
            erec2, _ = Verify(a2, matrix).run()
            killed = not any(e.get("code") == "BASELINE_EXPIRED" for e in erec2["verify"]["events"])
        check(f"rule mutant {rule} disabled → an expectation goes red (killed)", killed)
        battery["rules"].append({"rule": rule, "killed": bool(killed), "scenario": fid})

    # selectable verifiers: targeted_test declared but no runner in the fixture → not_measured rows, never verified; property_check with none declared → note
    fault = next(f for f in FAULTS if f["id"] == "S00-clean")
    srec, _ = run_scenario(scratch, work, fault, tsc, prisma, select="targeted_test,property_check", graph_path=base_graph)
    tt = [v for v in srec["verifiers"] if v["kind"] == "targeted_test"]
    check("selectable targeted_test: runner absent in the fixture ⇒ recorded verifier rows with not_measured, no verified from a test that did not run",
          bool(tt) and all(v["exit_code"] == 127 for v in tt) and all(x["verdict"] != "verified" or "targeted" not in " ".join(x.get("verifier_ids", [])) for x in srec["verdicts"]), rows=len(tt))
    check("selectable property_check: none declared ⇒ note, no verifier row", any("property_check selected" in n for n in srec["notes"]) and not any(v["kind"] == "property_check" for v in srec["verifiers"]))

    # AUP-GRAPH-006:gate3b (hole H7) — config_schema must not attribute a VENDORED bundle's config keys to the caller.
    # Red before / green after over one fixture, with the two deliberate violations still red so the verifier is not
    # switched off, and a negative control directory merely NAMED like a bundle.
    vb_dir = build_graph.VENDORED_BUNDLE_FIXTURE_DIR
    vb_exp = json.loads(build_graph.VENDORED_BUNDLE_EXPECTED_PATH.read_text())
    vb_graph = build_graph.build(vb_dir, worktree=True, built_at=build_graph.FIXED_BUILT_AT)
    vb_tree = build_graph.load_tree_worktree(vb_dir)
    vb_scan = TreeScan(vb_tree)
    vb_after, _, vb_sources, vb_report = config_violations(vb_graph, vb_tree, vb_scan, [])
    # the PRE-gate3b builder: identical graph with the attribution removed
    vb_before_graph = json.loads(json.dumps(vb_graph))
    for n in vb_before_graph["nodes"]:
        if (n.get("attrs") or {}).pop("vendored", None) is not None:
            n["attrs"].pop("vendored_from", None); n["attrs"].pop("vendor_bundle", None); n["attrs"].pop("vendor_ref", None)
    vb_before, _, _, vb_report_before = config_violations(vb_before_graph, vb_tree, vb_scan, [])
    keys_before = sorted({v["key"] for v in vb_before})
    keys_after = sorted({v["key"] for v in vb_after})
    check("vendored-bundle-mini RED BEFORE: without the gate3b attribution config_schema demands the caller declare the "
          "PROGRAM's keys", keys_before == vb_exp["expected_config_violation_keys_before"] and not vb_report_before,
          got=keys_before, expected=vb_exp["expected_config_violation_keys_before"], sources=vb_sources)
    check("vendored-bundle-mini GREEN AFTER: the vendored bundle's keys are not attributed to the caller, and the caller's "
          "OWN undeclared key plus the negative control's key are still red (the verifier is not switched off)",
          keys_after == vb_exp["expected_config_violation_keys_after"], got=keys_after,
          expected=vb_exp["expected_config_violation_keys_after"])
    check("vendored-bundle-mini: the skip is REPORTED, never silent — the owning repository, the files and the keys not "
          "attributed are all named", [r["owner"] for r in vb_report.values()] == ["Arcanada-one/arcanada-universal-program"]
          and sorted(k for r in vb_report.values() for k in r["keys"]) == ["AUP_SKIP_RECEIPT", "MUNERAL_API_KEY"],
          report=list(vb_report.values()))

    # negative control: a wrong expectation must go red (the battery is not vacuous)
    rec = scenarios["F04-fitness-forbidden-import"]
    wrong = {v["entity"]: v for v in rec["verdicts"]}["code_unit:apps/api/src/tasks/tasks.controller.ts"]["verdict"] == "verified"
    check("negative control: asserting the forbidden-import controller is verified goes red", not wrong)

    # freeze-baseline round trip on the scratch base
    bl_out = work / "baseline.json"
    a3 = argparse.Namespace(repo=str(scratch), rev="HEAD", owner="AUP-E29 executor aup-graph", expires="2026-12-05T00:00:00Z", freeze_baseline=str(bl_out))
    subprocess.run(["git", "checkout", "-q", "--", "."], cwd=scratch, check=True, capture_output=True)
    subprocess.run(["git", "clean", "-qfd"], cwd=scratch, check=True, capture_output=True)
    freeze_baseline(a3)
    bl = json.loads(bl_out.read_text())
    check("--freeze-baseline writes FitnessBaseline/v1 with the pre-existing FR-04 marker (ts-mini declares no env source ⇒ no config entries), owner + expiry",
          bl["schema"] == "FitnessBaseline/v1" and any(e["rule"] == "FR-04" for e in bl["entries"]) and not any(e["rule"] == "UNDECLARED_CONFIG_KEY" for e in bl["entries"])
          and bl["summary"]["env_sources"] == [] and bl["owner"] and bl["expires_at_utc"], by_rule=bl["summary"]["by_rule"])

    pilot = None
    if a.pilot:
        pilot = run_pilot(a, check, tsc, prisma)

    ok = sum(1 for c in checks if c["ok"])
    verdict = "PASS" if ok == len(checks) else "FAIL"
    if verdict == "PASS" and pilot and pilot.get("clause_time_budget_met") is False:
        verdict = "PASS_WITH_FINDINGS"
    receipt = {"schema": "ReadinessReceipt/v1", "portion_id": "AUP-GRAPH-005:verify0", "tool": TOOL, "tool_version": VERSION,
               "captured_at_utc": now_iso(), "host": os.uname().nodename, "python": sys.version.split()[0], "verdict": verdict,
               "matrix": {"path": rel_ref(MATRIX_PATH), "sha256": sha_text(MATRIX_PATH.read_text()), "mandatory": MANDATORY_IDS, "selectable": SELECTABLE_IDS,
                          "fitness_rules": sorted(matrix["fitness_rules"])},
               "toolchain": {"tsc": tsc, "prisma": prisma, "node": shutil.which("node")},
               "fixtures": {"tree": rel_ref(TS_MINI), "profile": rel_ref(VFIX / "profile.ts-mini.json"), "typings": rel_ref(VFIX / "typings"),
                            "faults": [{k: f[k] for k in ("id", "verifier", "entity", "what")} for f in FAULTS]},
               "checks": checks, "mutation_battery": battery, "limitations": limitations,
               "summary": {"checks_ok": ok, "checks_total": len(checks), "faults": len(FAULTS), "verifier_mutants_total": sum(1 for f in FAULTS if f["verifier"]),
                           "verifier_mutants_survived_when_disabled": sum(1 for r in battery["faults"] if r["survived_when_disabled"]),
                           "rule_mutants_total": len(battery["rules"]), "rule_mutants_killed": sum(1 for r in battery["rules"] if r["killed"]),
                           "seconds": round(time.monotonic() - t0, 1)}}
    if pilot:
        receipt["pilot"] = pilot
    if a.receipt:
        Path(a.receipt).parent.mkdir(parents=True, exist_ok=True)
        Path(a.receipt).write_bytes(dump(receipt))
        print(f"receipt → {a.receipt}")
    print(f"{verdict}: {ok}/{len(checks)} checks, {receipt['summary']['seconds']}s")
    return 0 if verdict.startswith("PASS") else 1


def run_pilot(a, check, tsc, prisma) -> dict:
    """≥ 10 historical changes of the pilot: graph at the parent, impact, mandatory verifiers (+ targeted tests), draft receipt."""
    repo = impact.Repo(Path(a.pilot))
    before = git(["status", "--porcelain"], repo.top)
    head = repo.head()
    out_dir = Path(a.pilot_out) if a.pilot_out else Path(os.environ.get("TMPDIR", "/tmp")) / "arcana-verify-pilot"
    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(a.workdir) if a.workdir else Path(os.environ.get("TMPDIR", "/tmp")) / "arcana-verify-selftest"
    revs = git(["rev-list", "--no-merges", "HEAD"], repo.top).split()
    selected, skipped = [], []
    graph_cache = {}
    idx_cache = {}
    # same selection rule as impact0's replay: one parent, parent graph builds, ≥ 2 covered modified files
    for c in revs:
        if len(selected) >= a.pilot_commits:
            break
        parents = git(["rev-list", "--parents", "-n", "1", c], repo.top).split()[1:]
        if len(parents) != 1:
            skipped.append({"commit": c[:12], "reason": "root or merge commit"})
            continue
        parent = parents[0]
        files = repo.diff_files(parent, c)
        if parent not in graph_cache:
            doc = build_graph.build(repo.top, rev=parent, built_at=build_graph.FIXED_BUILT_AT)
            gp = out_dir / f"graph-{parent[:12]}.json"
            gp.write_bytes(build_graph.dump_graph(doc))
            graph_cache[parent] = gp
            idx_cache[parent] = impact.GraphIndex(doc)
        idx = idx_cache[parent]
        covered = [f for f in files if f["status"] in ("M", "D", "R") and idx.by_path.get(f["path"])]
        if len(covered) < 2:
            skipped.append({"commit": c[:12], "reason": f"< 2 covered modified files ({len(covered)})"})
            continue
        selected.append((c, parent))
    per_commit = []
    t_all = time.monotonic()
    baseline_ref = BASELINE_DIR / (repo.name.replace("/", "__") + ".v1.json")
    for c, parent in selected:
        subject = git(["log", "-n", "1", "--format=%s", c], repo.top).strip()
        ns = argparse.Namespace(repo=str(repo.top), diff=f"{parent}..{c}", worktree=False, files=None, graph=str(graph_cache[parent]), max_depth=None,
                                select="targeted_test", disable="", disable_rule="", profile=None, baseline="auto", tsc=tsc, prisma=prisma,
                                workdir=str(work / "pilot-wd"), out=None, verifier_out=str(out_dir / f"verify-{c[:12]}.d"), json=False, work_item=None)
        t0 = time.monotonic()
        rec, code = Verify(ns, load_matrix()).run()
        secs = round(time.monotonic() - t0, 1)
        (out_dir / f"verify-{c[:12]}.json").write_bytes(dump(rec))
        row = {"commit": c[:12], "parent": parent[:12], "subject": subject[:90], "seconds": secs, "exit_code": code}
        if rec.get("schema") == "ChangeAdmissionReceipt/v1":
            imp = rec["impact_set"]
            want = {e["entity"] for e in imp["deterministic_core"] + imp["inferred_tail"]} | {n for f in rec["change_set"]["files"] for n in (f.get("node_ids") or ([f["node_id"]] if f.get("node_id") else []))}
            have = {v["entity"] for v in rec["verdicts"]}
            counts = {}
            for v in rec["verdicts"]:
                counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
            cls = schema_check.classify(rec, schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH), schema_check.load_schema(schema_check.RECEIPT_SCHEMA_PATH))
            row.update({"files": len(rec["change_set"]["files"]), "entities": len(want), "verdicts": counts, "every_entity_has_verdict": want == have,
                        "conformant": cls["verdict"] == "conformant", "admission": rec["admission"]["verdict"],
                        "verifiers": [(v["id"], v["exit_code"], v["duration_s"]) for v in rec["verifiers"]],
                        "failed": [(v["entity"], v["reason"][:160]) for v in rec["verdicts"] if v["verdict"] == "failed"][:12],
                        "not_measured_reasons": sorted({re.sub(r"code_unit:\S+|route:[^;]+|contract:\S+", "<x>", v["reason"])[:90] for v in rec["verdicts"] if v["verdict"] == "not_measured"})[:8],
                        "events": [e.get("code") for e in rec["verify"]["events"]], "receipt": rel_ref(out_dir / f"verify-{c[:12]}.json")})
        else:
            row["refusal"] = rec.get("refusal")
        per_commit.append(row)
        print(f"pilot {c[:12]} {secs}s exit {code} {row.get('verdicts')} {row.get('admission')} — {subject[:60]}")
    total = round(time.monotonic() - t_all, 1)
    after = git(["status", "--porcelain"], repo.top)
    drafts = [r for r in per_commit if "admission" in r]
    check(f"pilot: ≥ 10 historical changes verified end to end ({len(drafts)})", len(drafts) >= 10)
    check("pilot: every draft has a verdict for every affected entity and is schema-conformant",
          all(r["every_entity_has_verdict"] and r["conformant"] for r in drafts), bad=[r["commit"] for r in drafts if not (r["every_entity_has_verdict"] and r["conformant"])])
    budget = total <= 600
    check(f"pilot: {len(drafts)} changes verified in {total}s ≤ 600s (card clause)", budget, seconds=total)
    check("pilot: repository untouched (git status --porcelain identical before/after, HEAD unchanged)", before == after and repo.head() == head)
    base_ok = None
    if baseline_ref.is_file():
        bl = json.loads(baseline_ref.read_text())
        base_ok = bl.get("frozen_at_commit") == head
        check(f"pilot: persisted FitnessBaseline/v1 {rel_ref(baseline_ref)} is frozen at the clone HEAD", base_ok, frozen_at=bl.get("frozen_at_commit", "")[:12], head=head[:12])
    return {"repo": repo.name, "path": str(repo.top), "head": head, "commits_selected": len(selected), "commits_skipped": len(skipped), "skipped": skipped[:30],
            "selection_rule": "git rev-list --no-merges HEAD; one parent; ≥ 2 modified/deleted/renamed files with a node in the parent graph (impact0's rule)",
            "seconds_total": total, "clause_time_budget_met": budget, "per_commit": per_commit,
            "baseline": {"path": rel_ref(baseline_ref) if baseline_ref.is_file() else None, "frozen_at_head": base_ok},
            "not_measured_classes": sorted({r for row in drafts for r in row.get("not_measured_reasons", [])})[:30],
            "admissions": {k: sum(1 for r in drafts if r["admission"] == k) for k in ("admitted", "paused_safe", "refused")}}


# ----------------------------------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path)
    ap.add_argument("--diff", help="<base>..<head> (graph at base; clean tree)")
    ap.add_argument("--worktree", action="store_true")
    ap.add_argument("--files", nargs="*")
    ap.add_argument("--graph", default="auto", help="RelationshipGraph/v1 at base/HEAD, or 'auto' to build it from git objects")
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--select", default="", help="selectable verifiers to add: targeted_test,property_check")
    ap.add_argument("--disable", default="", help="mutation battery / diagnostics: disable mandatory verifiers (recorded as MANDATORY_VERIFIER_DISABLED)")
    ap.add_argument("--disable-rule", default="", help="mutation battery only: internal rules " + ",".join(RULES))
    ap.add_argument("--profile", help="VerifyProfile/v1 (default <repo>/.arcana/verify.json or auto-detection)")
    ap.add_argument("--baseline", help="FitnessBaseline/v1 (default <repo>/.arcana/fitness-baseline.json, then the program registry, then auto-freeze at base; 'auto' forces the freeze at base)")
    ap.add_argument("--tsc")
    ap.add_argument("--prisma")
    ap.add_argument("--workdir", help="scratch directory for exports / generated tsconfigs")
    ap.add_argument("--out", type=Path, help="write the ChangeAdmissionReceipt/v1 draft here")
    ap.add_argument("--verifier-out", help="directory for captured verifier outputs (default <workdir>/verifier-out; never beside --out)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--work-item")
    ap.add_argument("--canary", action="append",
                    help="CanaryResult/v1 (tools/graph/deploy_gate.py canary): live-contour evidence for inferred/observed "
                         "boundary entities and canary_required edge types (AUP-GRAPH-008)")
    ap.add_argument("--freeze-baseline", help="write a FitnessBaseline/v1 of the findings at --rev and exit")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--owner", default="")
    ap.add_argument("--expires", default="")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--receipt", help="with --selftest: ReadinessReceipt/v1 path")
    ap.add_argument("--pilot", help="with --selftest: pilot repository for the historical replay")
    ap.add_argument("--pilot-graph", help="(informational) pilot graph at HEAD")
    ap.add_argument("--pilot-out", help="with --pilot: directory for the per-commit drafts")
    ap.add_argument("--pilot-commits", type=int, default=12)
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest(a)
    if a.freeze_baseline:
        if not (a.repo and a.owner and a.expires):
            ap.error("--freeze-baseline needs --repo, --owner and --expires")
        return freeze_baseline(a)
    if not a.repo or not (a.diff or a.worktree or a.files):
        ap.error("--repo and one of --diff / --worktree / --files are required")
    rec, code = Verify(a, load_matrix()).run()
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_bytes(dump(rec))
    print(json.dumps(rec, ensure_ascii=False, indent=1) if a.json else human(rec))
    return code


if __name__ == "__main__":
    sys.exit(main())
