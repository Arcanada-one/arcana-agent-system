#!/usr/bin/env python3
"""Bounded static Pydantic BaseModel → schema-lite (stdlib AST over git-object / file bytes).

Corrected semantics (RCH on 09:37 proposal):
  - ``T | None`` / ``Optional[T]`` controls NULLABILITY only.
  - Presence comes only from default form: no-default / Field(...) /
    Field(default=...) → required; bare default / Field(default=<value>) /
    Field(default_factory=) → optional.
  - Axes are independent (required-nullable is real and must not be collapsed).
  - Same-package static import/name resolution; else explicit unknown.
  - Constraints separate; unresolved constraint names → unknown.
  - ConfigDict: AST-complete ``extra``-only forms extract; unsupported keys /
    incomplete forms remain unknown (never silent drop).
  - Inherited BaseModel subclasses: same-module complete parent shapes merge;
    incomplete inheritance remains unknown.
  - Validators / generics / dynamic / unresolved → unknown (never silent drop).

Exact Pydantic version policy (public pin contract for this tool):
  - Env: ``CONTRACT_DIFF_PYDANTIC_EXACT_VERSION`` = one PEP 440 exact version
    (digits and dots only; no range operators).
  - In-tree file (when present in the scanned file map):
    ``.contract-diff/pydantic-exact-version`` = same single exact version line.
  - When both are present they MUST match; mismatch → ``exact_pin_mismatch``.
  - Absent pin → ``declared_range_only_not_exact_install`` (admission refuses;
    refusal text names the missing pin env/path). This never invents a host
    install or runtime PASS from a declared range alone.
  - Matched exact pin → ``exact_measured_pin:<version>``; version-policy alone
    does not force Refusal (unknowns still refuse before Differ).

Never import/exec/eval candidate application code. No OpenAPI oracle.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from typing import Any

KIND = "pydantic_basemodel"

# Public exact-pin inputs (see module docstring). Relative path is repo-root style.
PYDANTIC_EXACT_PIN_ENV = "CONTRACT_DIFF_PYDANTIC_EXACT_VERSION"
PYDANTIC_EXACT_PIN_RELPATH = ".contract-diff/pydantic-exact-version"
_EXACT_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*([a-zA-Z0-9.-]*)?$")

_SKIP_DIR_FRAGMENTS = (
    "/node_modules/",
    "/.venv/",
    "/venv/",
    "/site-packages/",
    "/__pycache__/",
    "/.tox/",
)


def py_paths(paths: list[str] | set[str]) -> list[str]:
    out = []
    for p in paths:
        if not p.endswith(".py"):
            continue
        norm = "/" + p.replace("\\", "/")
        if any(frag in norm for frag in _SKIP_DIR_FRAGMENTS):
            continue
        if p.startswith("tests/") or "/tests/" in p or p.endswith("_test.py") or p.startswith("test_"):
            # keep fixture trees that intentionally live under tools/graph/fixtures/
            if "/fixtures/" not in p:
                continue
        out.append(p)
    return sorted(out)


@dataclass
class UnknownRecord:
    path: str
    symbol: str
    reason: str


VERSION_POLICY = "declared_range_only_not_exact_install"
VERSION_POLICY_EXACT_PREFIX = "exact_measured_pin:"
VERSION_POLICY_MISMATCH = "exact_pin_mismatch"
VERSION_POLICY_LIMITATION = (
    "pydantic_version_policy=declared_range_only_not_exact_install; "
    "compatibility/admission not_measured until exact supported-version policy is qualified; "
    f"supply exact pin via env {PYDANTIC_EXACT_PIN_ENV} or tree file {PYDANTIC_EXACT_PIN_RELPATH}"
)


def version_policy_blocks_admission(policy: str | None) -> bool:
    """True when version-policy alone must refuse before Differ."""
    if policy is None:
        return True
    if policy.startswith(VERSION_POLICY_EXACT_PREFIX):
        return False
    return True


def resolve_exact_version_pin(
    *,
    env: dict[str, str] | None = None,
    tree_files: dict[str, bytes] | None = None,
) -> tuple[str, str | None]:
    """Return (policy_token, exact_version_or_None).

    Documents the public pin contract used by extract + admission.
    """
    env_map = env if env is not None else os.environ
    raw_env = (env_map.get(PYDANTIC_EXACT_PIN_ENV) or "").strip()
    raw_file = ""
    if tree_files and PYDANTIC_EXACT_PIN_RELPATH in tree_files:
        try:
            raw_file = tree_files[PYDANTIC_EXACT_PIN_RELPATH].decode("utf-8").strip()
        except UnicodeDecodeError:
            return VERSION_POLICY_MISMATCH, None
    # First non-empty line only; ignore comments after '#'.
    if raw_file:
        line = raw_file.splitlines()[0].split("#", 1)[0].strip()
        raw_file = line

    def _valid(v: str) -> bool:
        if not v or any(ch in v for ch in "<>!=,~ "):
            return False
        return bool(_EXACT_VERSION_RE.match(v))

    env_ok = _valid(raw_env) if raw_env else False
    file_ok = _valid(raw_file) if raw_file else False
    if raw_env and not env_ok:
        return VERSION_POLICY_MISMATCH, None
    if raw_file and not file_ok:
        return VERSION_POLICY_MISMATCH, None
    if env_ok and file_ok and raw_env != raw_file:
        return VERSION_POLICY_MISMATCH, None
    if env_ok:
        return f"{VERSION_POLICY_EXACT_PREFIX}{raw_env}", raw_env
    if file_ok:
        return f"{VERSION_POLICY_EXACT_PREFIX}{raw_file}", raw_file
    return VERSION_POLICY, None


@dataclass
class ExtractResult:
    contracts: dict[str, dict] = field(default_factory=dict)
    unknowns: list[UnknownRecord] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    pydantic_version_policy: str | None = None
    pydantic_exact_version: str | None = None
    disabled: bool = False
    py_paths_present: bool = False


def extract_from_tree_files(
    files: dict[str, bytes],
    *,
    disabled: set[str] | None = None,
    env: dict[str, str] | None = None,
) -> ExtractResult:
    """files: posix path → bytes (git Tree.files or directory dump)."""
    disabled = disabled or set()
    present = bool(py_paths(list(files)))
    if "x_pydantic" in disabled:
        return ExtractResult(
            limitations=["python pydantic frontend disabled (x_pydantic)"],
            disabled=True,
            py_paths_present=present,
        )
    texts: dict[str, str] = {}
    for path in py_paths(list(files)):
        try:
            texts[path] = files[path].decode("utf-8")
        except UnicodeDecodeError as e:
            return ExtractResult(
                limitations=[f"{path}: decode error {e}"],
                py_paths_present=present,
            )
    result = extract_from_texts(texts, env=env, tree_files=files)
    result.py_paths_present = present
    return result


def extract_from_texts(
    texts: dict[str, str],
    *,
    env: dict[str, str] | None = None,
    tree_files: dict[str, bytes] | None = None,
) -> ExtractResult:
    modules: dict[str, _Module] = {}
    result = ExtractResult()
    policy, exact = resolve_exact_version_pin(env=env, tree_files=tree_files)
    for path, src in sorted(texts.items()):
        try:
            tree = ast.parse(src, filename=path)
        except SyntaxError as e:
            result.limitations.append(f"{path}: syntax error {e}")
            continue
        modules[path] = _Module.from_ast(path, tree, src)

    # index BaseModel classes + Literal aliases + string consts by path/symbol
    models: dict[tuple[str, str], _Model] = {}
    for path, mod in modules.items():
        for name, model in mod.models.items():
            models[(path, name)] = model

    for (path, name), model in sorted(models.items(), key=lambda x: (x[0][0], x[0][1])):
        schema, unknown = _model_schema(model, modules, models)
        cid = f"contract:{path}#{name}"
        if unknown:
            result.unknowns.append(UnknownRecord(path, name, unknown))
            result.limitations.append(f"{cid}: unknown — {unknown}")
            continue
        contract = {
            "id": cid,
            "kind": KIND,
            "path": path,
            "symbol": name,
            "exported": True,
            "direction": _direction(name),
            "schema": schema,
            "presence_nullability_axes": "independent",
            "pydantic_version_policy": policy,
        }
        if exact:
            contract["pydantic_exact_version"] = exact
        result.contracts[cid] = contract
    if result.contracts or result.unknowns:
        result.pydantic_version_policy = policy
        result.pydantic_exact_version = exact
        if policy == VERSION_POLICY and VERSION_POLICY_LIMITATION not in result.limitations:
            result.limitations.append(VERSION_POLICY_LIMITATION)
        elif policy == VERSION_POLICY_MISMATCH:
            result.limitations.append(
                "pydantic_version_policy=exact_pin_mismatch; "
                f"env {PYDANTIC_EXACT_PIN_ENV} and/or tree {PYDANTIC_EXACT_PIN_RELPATH} conflict or invalid"
            )
        elif exact:
            result.limitations.append(
                f"pydantic_version_policy={policy}; exact pin measured (not a host-install claim)"
            )
    return result


# ------------------------------------------------------------------------------------------------- internals


@dataclass
class _Module:
    path: str
    package: str  # dotted package guess from path
    basemodel_names: set[str]
    field_names: set[str]
    configdict_names: set[str]
    literal_names: set[str]
    imports: dict[str, tuple[str, str]]  # local → (module_spec, imported_name)
    string_consts: dict[str, str]
    literal_aliases: dict[str, list[Any]]
    models: dict[str, _Model]

    @staticmethod
    def from_ast(path: str, tree: ast.AST, src: str) -> _Module:
        pkg = _path_to_pkg(path)
        basemodel, field_n, configdict, literal = set(), set(), set(), set()
        imports: dict[str, tuple[str, str]] = {}
        string_consts: dict[str, str] = {}
        literal_aliases: dict[str, list[Any]] = {}
        models: dict[str, _Model] = {}
        all_classes: dict[str, ast.ClassDef] = {}

        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                level = node.level or 0
                abs_mod = _resolve_relative(pkg, mod, level, path)
                for alias in node.names:
                    local = alias.asname or alias.name
                    imports[local] = (abs_mod, alias.name)
                    if abs_mod in ("pydantic", "pydantic.main") or mod == "pydantic":
                        if alias.name == "BaseModel":
                            basemodel.add(local)
                        elif alias.name == "Field":
                            field_n.add(local)
                        elif alias.name == "ConfigDict":
                            configdict.add(local)
                        elif alias.name == "Literal":
                            # typing.Literal also handled below
                            literal.add(local)
                    if abs_mod in ("typing", "typing_extensions") or mod in ("typing", "typing_extensions"):
                        if alias.name == "Literal":
                            literal.add(local)
                        if alias.name == "Optional":
                            pass  # handled via annotation walk
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    imports[local] = (alias.name, alias.name)

            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                tname = node.targets[0].id
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    string_consts[tname] = node.value.value
                lit_vals = _literal_values(node.value, literal)
                if lit_vals is not None:
                    literal_aliases[tname] = lit_vals

            if isinstance(node, (ast.AnnAssign,)) and isinstance(node.target, ast.Name):
                # Name: ... = Literal[...] rarely; skip
                pass

            if isinstance(node, ast.ClassDef):
                all_classes[node.name] = node

        # Direct proven-BaseModel subclasses, then finite cycle-safe inherited subclasses.
        direct: set[str] = set()
        for name, node in all_classes.items():
            if _extends_proven_basemodel(node, basemodel, imports):
                direct.add(name)
                models[name] = _Model.from_class(
                    path, node, field_n, configdict, src, inherited=False, known_models=set()
                )

        inherited: set[str] = set()
        changed = True
        while changed:
            changed = False
            known = direct | inherited
            for name, node in all_classes.items():
                if name in known:
                    continue
                if _extends_local_model(node, known):
                    inherited.add(name)
                    models[name] = _Model.from_class(
                        path, node, field_n, configdict, src, inherited=True, known_models=known
                    )
                    changed = True
                    # Refresh parent_names on prior models is unnecessary: parents are already known.

        return _Module(
            path=path,
            package=pkg,
            basemodel_names=basemodel,
            field_names=field_n,
            configdict_names=configdict,
            literal_names=literal,
            imports=imports,
            string_consts=string_consts,
            literal_aliases=literal_aliases,
            models=models,
        )


@dataclass
class _Field:
    name: str
    annotation: ast.AST | None
    value: ast.AST | None
    raw: str


@dataclass
class _Model:
    path: str
    name: str
    fields: list[_Field]
    has_configdict: bool
    config_call: ast.Call | None
    config_incomplete: str | None
    parent_names: list[str]
    has_validator: bool
    has_annotated: bool
    inherited: bool
    text: str

    @staticmethod
    def from_class(
        path: str,
        node: ast.ClassDef,
        field_names: set[str],
        configdict_names: set[str],
        src: str,
        *,
        inherited: bool = False,
        known_models: set[str] | None = None,
    ) -> _Model:
        fields: list[_Field] = []
        has_config = False
        config_call: ast.Call | None = None
        config_incomplete: str | None = None
        has_validator = False
        has_annotated = False
        known_models = known_models or set()
        parent_names: list[str] = []
        for b in node.bases:
            if isinstance(b, ast.Name) and b.id in known_models:
                parent_names.append(b.id)
            elif isinstance(b, ast.Name) and b.id not in ("BaseModel",) and b.id not in known_models:
                # Non-BaseModel / unresolved local base left for inheritance residual later.
                pass
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and t.id == "model_config":
                        has_config = True
                        if isinstance(stmt.value, ast.Call) and _call_name(stmt.value) in configdict_names | {
                            "ConfigDict"
                        }:
                            config_call = stmt.value
                        else:
                            config_incomplete = "model_config is not a ConfigDict(...) call"
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                if stmt.target.id == "model_config":
                    has_config = True
                    if isinstance(stmt.value, ast.Call) and _call_name(stmt.value) in configdict_names | {
                        "ConfigDict"
                    }:
                        config_call = stmt.value
                    else:
                        config_incomplete = "model_config annotation is not a ConfigDict(...) call"
                    continue
                if stmt.target.id.startswith("_"):
                    continue
                fields.append(
                    _Field(
                        name=stmt.target.id,
                        annotation=stmt.annotation,
                        value=stmt.value,
                        raw=ast.get_source_segment(src, stmt) or stmt.target.id,
                    )
                )
            if isinstance(stmt, ast.FunctionDef):
                # Methods other than validators are ignored for shape (display helpers etc.).
                for dec in stmt.decorator_list:
                    dname = _call_name(dec)
                    if dname in ("field_validator", "model_validator", "computed_field", "validator", "root_validator"):
                        has_validator = True
            # ConfigDict(...) usage anywhere in class
            for child in ast.walk(stmt):
                if isinstance(child, ast.Call) and _call_name(child) in configdict_names | {"ConfigDict"}:
                    has_config = True
                    if config_call is None and not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                        # ConfigDict used outside model_config assignment — incomplete.
                        config_incomplete = config_incomplete or "ConfigDict used outside model_config assignment"
                    elif config_call is None and isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                        config_call = child
                if isinstance(child, ast.Name) and child.id == "Annotated":
                    has_annotated = True
                if isinstance(child, ast.Attribute) and child.attr == "Annotated":
                    has_annotated = True
        text = ast.get_source_segment(src, node) or node.name
        return _Model(
            path=path,
            name=node.name,
            fields=fields,
            has_configdict=has_config,
            config_call=config_call,
            config_incomplete=config_incomplete,
            parent_names=parent_names,
            has_validator=has_validator,
            has_annotated=has_annotated,
            inherited=inherited,
            text=text,
        )


def _parse_configdict(model: _Model) -> tuple[dict | None, str | None]:
    """Return (config_dict, error). None config with None error means no model_config."""
    if not model.has_configdict:
        return None, None
    if model.config_incomplete:
        return None, f"ConfigDict incomplete: {model.config_incomplete}"
    if model.config_call is None:
        return None, "ConfigDict/model_config present but call unresolved"
    call = model.config_call
    if call.args:
        return None, "ConfigDict positional args unsupported"
    out: dict[str, Any] = {}
    for kw in call.keywords:
        if kw.arg is None:
            return None, "ConfigDict **kwargs unsupported"
        if kw.arg == "extra":
            if isinstance(kw.value, ast.Constant) and kw.value.value in ("forbid", "ignore", "allow"):
                out["extra"] = kw.value.value
            else:
                return None, "ConfigDict extra non-literal or unsupported value"
        else:
            return None, f"ConfigDict keyword {kw.arg} unsupported"
    return out, None


def _merge_inherited_fields(
    model: _Model,
    modules: dict[str, _Module],
    models: dict[tuple[str, str], _Model],
    _stack: set[tuple[str, str]] | None = None,
) -> tuple[list[_Field] | None, dict | None, str | None]:
    """Merge same-module parent fields (parents first). Also returns merged model_config.

    Fail-closed when any ancestor is incomplete (validators / bad ConfigDict / cycles).
    """
    stack = _stack or set()
    key = (model.path, model.name)
    if key in stack:
        return None, None, "inherited BaseModel cycle unresolved"
    stack = set(stack)
    stack.add(key)

    if model.has_validator:
        return None, None, "validators unsupported in first slice"
    if model.has_annotated:
        return None, None, "Annotated unsupported in first slice"

    own_config, cfg_err = _parse_configdict(model)
    if cfg_err:
        return None, None, cfg_err

    merged_fields: list[_Field] = []
    parent_config: dict | None = None
    if model.inherited or model.parent_names:
        if not model.parent_names:
            return None, None, "inherited BaseModel subclass missing resolvable same-module parent"
        if len(model.parent_names) != 1:
            return None, None, "multiple inherited BaseModel bases unsupported"
        parent = models.get((model.path, model.parent_names[0]))
        if parent is None:
            return None, None, (
                f"inherited BaseModel parent {model.parent_names[0]} unresolved in same module"
            )
        p_fields, p_config, p_err = _merge_inherited_fields(parent, modules, models, stack)
        if p_err:
            return None, None, f"incomplete inheritance via {parent.name}: {p_err}"
        assert p_fields is not None
        merged_fields.extend(p_fields)
        parent_config = p_config

    # Own fields override same-named parent fields.
    by_name = {f.name: f for f in merged_fields}
    for f in model.fields:
        by_name[f.name] = f
    # Stable order: parent order then new own fields.
    seen: set[str] = set()
    ordered: list[_Field] = []
    for f in merged_fields:
        if f.name in by_name and f.name not in seen:
            ordered.append(by_name[f.name])
            seen.add(f.name)
    for f in model.fields:
        if f.name not in seen:
            ordered.append(f)
            seen.add(f.name)

    # Child model_config overrides parent when both present; else inherit parent config.
    final_config = own_config if own_config is not None else parent_config
    return ordered, final_config, None


def _model_schema(
    model: _Model,
    modules: dict[str, _Module],
    models: dict[tuple[str, str], _Model],
) -> tuple[dict | None, str | None]:
    fields, model_config, err = _merge_inherited_fields(model, modules, models)
    if err:
        return None, err
    assert fields is not None

    mod = modules[model.path]
    props: dict[str, dict] = {}
    for f in fields:
        prop, ferr = _field_schema(f, mod, modules, models)
        if ferr:
            return None, f"field {f.name}: {ferr}"
        assert prop is not None
        props[f.name] = prop
    required = sorted(k for k, v in props.items() if not v.get("optional"))
    schema: dict[str, Any] = {"kind": "object", "properties": props, "required": required}
    if model_config:
        schema["model_config"] = model_config
    return schema, None


def _field_schema(
    f: _Field,
    mod: _Module,
    modules: dict[str, _Module],
    models: dict[tuple[str, str], _Model],
) -> tuple[dict | None, str | None]:
    if f.annotation is None:
        return None, "missing annotation"

    base, nullable, ann_err = _annotation_type(f.annotation, mod, modules, models)
    if ann_err:
        return None, ann_err
    assert base is not None

    presence, constraints, c_err = _presence_and_constraints(f.value, mod)
    if c_err:
        return None, c_err

    schema = dict(base)
    if nullable:
        schema["nullable"] = True
    if presence != "required":
        schema["optional"] = True
        schema["presence_kind"] = presence
    else:
        schema["presence_kind"] = "required"
    if constraints:
        schema["constraints"] = constraints
    return schema, None


def _presence_and_constraints(value: ast.AST | None, mod: _Module) -> tuple[str, dict, str | None]:
    """Return (presence_kind, constraints, error)."""
    if value is None:
        return "required", {}, None

    # Field(...) call
    if isinstance(value, ast.Call) and _call_name(value) in mod.field_names | {"Field"}:
        constraints: dict[str, Any] = {}
        presence = "required"
        if value.args:
            first = value.args[0]
            if isinstance(first, ast.Constant) and first.value is ...:
                presence = "required"
            else:
                presence = "field_default"
        for kw in value.keywords:
            if kw.arg == "default":
                # Field(default=...) is the keyword form of required Ellipsis, not optional.
                if isinstance(kw.value, ast.Constant) and kw.value.value is ...:
                    presence = "required"
                else:
                    presence = "field_default"
            elif kw.arg == "default_factory":
                presence = "default_factory"
            elif kw.arg in ("min_length", "max_length", "ge", "le", "gt", "lt", "multiple_of", "min_items", "max_items"):
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, (int, float)):
                    constraints[kw.arg] = kw.value.value
                else:
                    return "required", {}, f"non-literal constraint {kw.arg}"
            elif kw.arg == "pattern":
                pat, err = _resolve_pattern(kw.value, mod)
                if err:
                    return "required", {}, err
                constraints["pattern"] = pat
            elif kw.arg in ("alias", "validation_alias", "serialization_alias"):
                return "required", {}, f"unsupported Field wire alias ({kw.arg})"
            elif kw.arg in (
                "description",
                "title",
                "examples",
                "json_schema_extra",
            ):
                continue
            elif kw.arg is None:
                return "required", {}, "unsupported Field **kwargs"
            else:
                return "required", {}, f"unsupported Field keyword {kw.arg}"
        return presence, constraints, None

    # bare default
    return "bare_default", {}, None


def _resolve_pattern(node: ast.AST, mod: _Module) -> tuple[str | None, str | None]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, None
    if isinstance(node, ast.Name) and node.id in mod.string_consts:
        return mod.string_consts[node.id], None
    return None, "unresolved pattern (non-literal / foreign name)"


def _annotation_type(
    ann: ast.AST,
    mod: _Module,
    modules: dict[str, _Module],
    models: dict[tuple[str, str], _Model],
) -> tuple[dict | None, bool, str | None]:
    """Return (schema, nullable, error). Nullability stripped from unions with None."""
    nullable = False
    core = ann

    # Optional[T]
    if isinstance(ann, ast.Subscript) and _name_of(ann.value) in ("Optional",):
        nullable = True
        core = ann.slice if not isinstance(ann.slice, ast.Tuple) else ann.slice.elts[0]

    # T | None / None | T / Union[T, None]
    union_elts = _union_elts(ann)
    if union_elts is not None:
        non_none = []
        for el in union_elts:
            if _is_none_type(el):
                nullable = True
            else:
                non_none.append(el)
        if len(non_none) != 1:
            return None, False, "unsupported union (only T|None supported)"
        core = non_none[0]

    return _core_type(core, mod, modules, models, nullable)


def _core_type(
    core: ast.AST,
    mod: _Module,
    modules: dict[str, _Module],
    models: dict[tuple[str, str], _Model],
    nullable: bool,
) -> tuple[dict | None, bool, str | None]:
    # list[T]
    if isinstance(core, ast.Subscript) and _name_of(core.value) in ("list", "List"):
        inner = core.slice if not isinstance(core.slice, ast.Tuple) else core.slice.elts[0]
        item, n2, err = _annotation_type(inner, mod, modules, models)
        if err:
            return None, False, err
        assert item is not None
        if n2:
            item = dict(item)
            item["nullable"] = True
        return {"kind": "array", "items": item}, nullable, None

    # dict / Dict — open object
    if isinstance(core, ast.Name) and core.id in ("dict", "Dict"):
        return {"kind": "object", "properties": {}, "required": [], "open": True}, nullable, None
    if isinstance(core, ast.Subscript) and _name_of(core.value) in ("dict", "Dict"):
        return {"kind": "object", "properties": {}, "required": [], "open": True}, nullable, None

    # Literal[...]
    if isinstance(core, ast.Subscript) and _name_of(core.value) in mod.literal_names | {"Literal"}:
        vals = []
        sl = core.slice
        elts = sl.elts if isinstance(sl, ast.Tuple) else [sl]
        for el in elts:
            if isinstance(el, ast.Constant) and isinstance(el.value, (str, int, bool)) or (
                isinstance(el, ast.Constant) and el.value is None
            ):
                vals.append(el.value)
            else:
                return None, False, "non-literal Literal member"
        return {"kind": "enum", "values": vals}, nullable, None

    # Name → scalar / alias / model ref
    if isinstance(core, ast.Name):
        prim = {"str": "string", "int": "integer", "float": "number", "bool": "boolean"}
        if core.id in prim:
            return {"kind": prim[core.id]}, nullable, None
        if core.id in mod.literal_aliases:
            return {"kind": "enum", "values": list(mod.literal_aliases[core.id])}, nullable, None
        # same-module model
        if (mod.path, core.id) in models:
            return {"kind": "ref", "name": core.id, "path": mod.path}, nullable, None
        # import resolution
        resolved = _resolve_name(core.id, mod, modules, models)
        if resolved is None:
            return None, False, f"unresolved type name {core.id}"
        rpath, rname, kind = resolved
        if kind == "literal_alias":
            vals = modules[rpath].literal_aliases[rname]
            return {"kind": "enum", "values": list(vals)}, nullable, None
        if kind == "model":
            return {"kind": "ref", "name": rname, "path": rpath}, nullable, None
        return None, False, f"unsupported resolved kind for {core.id}"

    if isinstance(core, ast.Attribute):
        return None, False, f"unsupported attribute type {_name_of(core)}"

    return None, False, f"unsupported annotation {type(core).__name__}"


def _resolve_name(
    name: str,
    mod: _Module,
    modules: dict[str, _Module],
    models: dict[tuple[str, str], _Model],
) -> tuple[str, str, str] | None:
    if name in mod.literal_aliases:
        return mod.path, name, "literal_alias"
    if (mod.path, name) in models:
        return mod.path, name, "model"
    imp = mod.imports.get(name)
    if not imp:
        return None
    spec, imported = imp
    # map module spec → path among scanned modules
    target_paths = _module_spec_to_paths(spec, modules)
    for tpath in target_paths:
        tmod = modules[tpath]
        if imported in tmod.literal_aliases:
            return tpath, imported, "literal_alias"
        if (tpath, imported) in models:
            return tpath, imported, "model"
        # re-export: imported local may itself be an import in target — one hop
        if imported in tmod.imports:
            hop = _resolve_name(imported, tmod, modules, models)
            if hop:
                return hop
    return None


def _module_spec_to_paths(spec: str, modules: dict[str, _Module]) -> list[str]:
    if not spec:
        return []
    # convert dotted module to path suffixes
    rel = spec.replace(".", "/")
    cands = []
    for path in modules:
        noext = path[:-3] if path.endswith(".py") else path
        if noext.replace("\\", "/").endswith(rel) or noext.replace("\\", "/") == rel:
            cands.append(path)
        # package __init__
        if noext.replace("\\", "/").endswith(rel + "/__init__"):
            cands.append(path)
    return sorted(set(cands))


def _union_elts(ann: ast.AST) -> list[ast.AST] | None:
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
        elts: list[ast.AST] = []

        def walk(n: ast.AST):
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr):
                walk(n.left)
                walk(n.right)
            else:
                elts.append(n)

        walk(ann)
        return elts
    if isinstance(ann, ast.Subscript) and _name_of(ann.value) == "Union":
        sl = ann.slice
        return list(sl.elts) if isinstance(sl, ast.Tuple) else [sl]
    return None


def _is_none_type(n: ast.AST) -> bool:
    return (isinstance(n, ast.Constant) and n.value is None) or (isinstance(n, ast.Name) and n.id == "None")


def _is_pydantic_module(spec: str) -> bool:
    return spec == "pydantic" or spec.startswith("pydantic.")


def _extends_proven_basemodel(
    node: ast.ClassDef,
    basemodel_names: set[str],
    imports: dict[str, tuple[str, str]],
) -> bool:
    """True only when a base is a BaseModel name/path proven via a pydantic import."""
    for b in node.bases:
        if isinstance(b, ast.Subscript):
            return False
        if isinstance(b, ast.Name) and b.id in basemodel_names:
            return True
        if isinstance(b, ast.Attribute) and b.attr == "BaseModel" and isinstance(b.value, ast.Name):
            imp = imports.get(b.value.id)
            if imp and _is_pydantic_module(imp[0]):
                return True
    return False


def _extends_local_model(node: ast.ClassDef, known_models: set[str]) -> bool:
    """True when a base is a same-module name already known as a Pydantic model (cycle-safe caller)."""
    for b in node.bases:
        if isinstance(b, ast.Subscript):
            return False
        if isinstance(b, ast.Name) and b.id in known_models:
            return True
    return False


def _literal_values(node: ast.AST, literal_names: set[str]) -> list[Any] | None:
    if isinstance(node, ast.Subscript) and _name_of(node.value) in literal_names | {"Literal"}:
        sl = node.slice
        elts = sl.elts if isinstance(sl, ast.Tuple) else [sl]
        vals = []
        for el in elts:
            if isinstance(el, ast.Constant):
                vals.append(el.value)
            else:
                return None
        return vals
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _name_of(node.func)
    return _name_of(node)


def _name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _path_to_pkg(path: str) -> str:
    p = path.replace("\\", "/")
    if p.endswith(".py"):
        p = p[:-3]
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    return p.replace("/", ".")


def _resolve_relative(pkg: str, module: str, level: int, path: str) -> str:
    if level == 0:
        return module
    parts = pkg.split(".")
    # drop module filename component already: pkg is file module path
    # for from .x import Y in pkg/a.py, pkg=pkg.a → parent pkg
    base = parts[: max(0, len(parts) - level)]
    if module:
        return ".".join([*base, *module.split(".")]) if base else module
    return ".".join(base)


def _direction(symbol: str) -> str:
    if re.search(r"(?i)(response|output|event|result|reply|view|projection)$", symbol):
        return "output"
    if re.search(r"(?i)(request|input|body|query|params|payload|dto|command)$", symbol):
        return "input"
    return "bidirectional"
