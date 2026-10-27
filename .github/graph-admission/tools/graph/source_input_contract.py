"""Strict parsing and byte binding for an explicit source-input contract.

The declaration records a repository's claimed source/consumer relationship. It is
not trust, deployment authority, or a verdict: the verifier still checks bytes and
runs the exact, pinned positive and negative controls declared for an affected pair.
Only explicit entries are modeled; file extensions never imply coverage.
"""
from __future__ import annotations

import ast
import hashlib
import json
import posixpath
import re
import shutil
from pathlib import PurePosixPath

MANIFEST_PATH = ".arcana/source-inputs.json"
SCHEMA = "SourceInputContract/v1"
HEX = re.compile(r"^[0-9a-f]{64}$")
ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]*$")
SAFE_ENV = {"CI", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "LC_ALL", "TZ"}
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CONTROLS = 32
MAX_TIMEOUT = 600


class ContractError(ValueError):
    """The explicit declaration is malformed or cannot be safely evaluated."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _path(value, field: str, *, code_only: bool = False) -> str:
    if value == "." and field.endswith(".cwd"):
        return value
    if (not isinstance(value, str) or not value or len(value) > 512 or "\\" in value
            or "\x00" in value or any(ord(c) < 32 for c in value)
            or value.startswith(("~", "/")) or re.match(r"^[A-Za-z]:/", value)):
        raise ContractError(f"{field} must be a bounded repository-relative POSIX path")
    p = PurePosixPath(value)
    if p.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise ContractError(f"{field} escapes or ambiguously names the repository")
    if code_only and p.suffix not in {".py"}:
        raise ContractError(f"{field} must name an explicit Python source/control file")
    return value


def _digest(value, field: str) -> str:
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ContractError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _exact_keys(value, required: set[str], optional: set[str], field: str):
    if not isinstance(value, dict):
        raise ContractError(f"{field} must be an object")
    missing = required - value.keys()
    extra = value.keys() - required - optional
    if missing or extra:
        raise ContractError(f"{field} fields mismatch (missing={sorted(missing)}, unknown={sorted(extra)})")


def _bound_names(tree: ast.AST) -> set[str]:
    """Collect names rebound anywhere in the bounded AST model.

    This deliberately ignores Python scope resolution: a binding in any nested
    scope makes the name unsuitable as static provenance throughout this file.
    """
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bound.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    # A star import may bind __file__ from an unknown module.
                    bound.add("__file__")
                else:
                    bound.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                bound.update(arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs))
                if args.vararg:
                    bound.add(args.vararg.arg)
                if args.kwarg:
                    bound.add(args.kwarg.arg)
        elif isinstance(node, ast.Lambda):
            args = node.args
            bound.update(arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs))
            if args.vararg:
                bound.add(args.vararg.arg)
            if args.kwarg:
                bound.add(args.kwarg.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchAs) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchStar) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
    return bound


def _pathlib_constructor_names(tree: ast.AST, *, file_io_only: bool = False) -> set[str]:
    """Return unambiguous local names imported directly as pathlib constructors."""
    constructors = {"Path"} if file_io_only else {"Path", "PurePath", "PurePosixPath"}
    imports: dict[str, set[str]] = {}
    ambiguous: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                ambiguous.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound_name = alias.asname or alias.name
                if node.module == "pathlib" and alias.name in constructors:
                    imports.setdefault(bound_name, set()).add(alias.name)
                else:
                    ambiguous.add(bound_name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            ambiguous.update(arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs))
            if args.vararg:
                ambiguous.add(args.vararg.arg)
            if args.kwarg:
                ambiguous.add(args.kwarg.arg)
            if not isinstance(node, ast.Lambda):
                ambiguous.add(node.name)
        elif isinstance(node, ast.ClassDef):
            ambiguous.add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            ambiguous.add(node.name)
        elif isinstance(node, ast.MatchAs) and node.name:
            ambiguous.add(node.name)
        elif isinstance(node, ast.MatchStar) and node.name:
            ambiguous.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            ambiguous.add(node.rest)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            ambiguous.add(node.id)
    return {name for name, origins in imports.items() if len(origins) == 1 and name not in ambiguous}


def _is_file_anchor(node, constructors: set[str], file_anchor_trusted: bool) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "__file__" and file_anchor_trusted
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return (node.func.id in constructors and len(node.args) == 1
                and _is_file_anchor(node.args[0], constructors, file_anchor_trusted))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return (node.func.attr == "resolve" and not node.args
                and _is_file_anchor(node.func.value, constructors, file_anchor_trusted))
    return False


def _literal_read_path(node, consumer_path: str, constructors: set[str],
                       file_anchor_trusted: bool) -> str | None:
    """Resolve only direct string paths and __file__-anchored literal pathlib paths."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        candidate = node.value
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
          and node.func.id in constructors):
        return (_literal_read_path(node.args[0], consumer_path, constructors, file_anchor_trusted)
                if len(node.args) == 1 else None)
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "resolve" and not node.args:
        return _literal_read_path(node.func.value, consumer_path, constructors, file_anchor_trusted)
    elif isinstance(node, ast.Name) and node.id == "__file__":
        if not file_anchor_trusted:
            return None
        candidate = consumer_path
    elif isinstance(node, ast.Attribute) and node.attr == "parent":
        parent = _literal_read_path(node.value, consumer_path, constructors, file_anchor_trusted)
        if parent is None:
            return None
        parts = PurePosixPath(parent).parts
        if not parts:
            return "."
        candidate = PurePosixPath(*parts[:-1]).as_posix() or "."
    elif (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute)
          and node.value.attr == "parents"
          and _is_file_anchor(node.value.value, constructors, file_anchor_trusted)
          and isinstance(node.slice, ast.Constant) and type(node.slice.value) is int and node.slice.value >= 0):
        parent_parts = PurePosixPath(consumer_path).parent.parts
        index = node.slice.value
        if index > len(parent_parts):
            return None
        candidate = PurePosixPath(*parent_parts[:len(parent_parts) - index]).as_posix() or "."
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        base = _literal_read_path(node.left, consumer_path, constructors, file_anchor_trusted)
        if base is None or not isinstance(node.right, ast.Constant) or not isinstance(node.right.value, str):
            return None
        suffix = PurePosixPath(node.right.value)
        if suffix.is_absolute() or ".." in suffix.parts:
            return None
        candidate = (PurePosixPath(base) / suffix).as_posix()
    else:
        return None
    if candidate == ".":
        return candidate
    try:
        return _path(candidate, "consumer literal read path")
    except ContractError:
        return None


def _is_path_file_io_receiver(node, consumer_path: str, constructors: set[str],
                              file_anchor_trusted: bool) -> bool:
    """Accept only a literal expression rooted in a trusted pathlib.Path object."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return (node.func.id in constructors and len(node.args) == 1
                and _literal_read_path(node, consumer_path, constructors, file_anchor_trusted) is not None)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return (node.func.attr == "resolve" and not node.args
                and _is_path_file_io_receiver(node.func.value, consumer_path, constructors,
                                              file_anchor_trusted))
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        return _is_path_file_io_receiver(node.value, consumer_path, constructors, file_anchor_trusted)
    if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute)
            and node.value.attr == "parents"
            and isinstance(node.slice, ast.Constant) and type(node.slice.value) is int
            and node.slice.value >= 0):
        return _is_path_file_io_receiver(node.value.value, consumer_path, constructors,
                                         file_anchor_trusted)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return (_is_path_file_io_receiver(node.left, consumer_path, constructors, file_anchor_trusted)
                and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)
                and _literal_read_path(node, consumer_path, constructors, file_anchor_trusted) is not None)
    return False


def _open_api_origins(tree: ast.AST, reader_names: set[str], module_names: set[str],
                      unsafe_reader_names: set[str], unsafe_module_names: set[str]) -> tuple[dict[str, str], dict[str, str]]:
    """Resolve only the existing bounded reader and os/io/builtins module aliases."""
    modules: dict[str, set[str]] = {}
    readers: dict[str, set[str]] = {}
    assignments: dict[str, list[ast.AST]] = {}

    if "open" in reader_names and "open" not in unsafe_reader_names and "open" not in _bound_names(tree):
        readers.setdefault("open", set()).add("builtin")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"os", "io", "builtins"}:
                    modules.setdefault(alias.asname or alias.name, set()).add(alias.name)
                elif not alias.asname and alias.name.split(".", 1)[0] in {"os", "io", "builtins"}:
                    origin = alias.name.split(".", 1)[0]
                    modules.setdefault(origin, set()).add(origin)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound_name = alias.asname or alias.name
                if node.module in {"builtins", "io", "os"} and alias.name == "open":
                    readers.setdefault(bound_name, set()).add("os" if node.module == "os" else "builtin")
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(value)

    for _ in range(len(assignments) + 1):
        changed = False
        for name, values in assignments.items():
            if name in module_names and name not in unsafe_module_names:
                for value in values:
                    if isinstance(value, ast.Name) and value.id in modules:
                        before = len(modules.setdefault(name, set()))
                        modules[name].update(modules[value.id])
                        changed |= len(modules[name]) != before
            if name in reader_names and name not in unsafe_reader_names:
                for value in values:
                    origins: set[str] = set()
                    if isinstance(value, ast.Name):
                        origins.update(readers.get(value.id, set()))
                    elif isinstance(value, ast.Attribute) and value.attr == "open" and isinstance(value.value, ast.Name):
                        origins.update(modules.get(value.value.id, set()))
                    if origins:
                        before = len(readers.setdefault(name, set()))
                        readers[name].update("os" if origin == "os" else "builtin" for origin in origins)
                        changed |= len(readers[name]) != before
        if not changed:
            break

    safe_modules = {name: next(iter(origins)) for name, origins in modules.items()
                    if name in module_names and name not in unsafe_module_names and len(origins) == 1}
    safe_readers = {name: next(iter(origins)) for name, origins in readers.items()
                    if name in reader_names and name not in unsafe_reader_names and len(origins) == 1}
    return safe_readers, safe_modules


def _read_mode_permitted(call: ast.Call, positional_index: int, *, default_read: bool,
                         max_positional: int) -> bool:
    """Return true only for a qualified literal read-only mode and call shape."""
    if len(call.args) > max_positional or any(keyword.arg is None for keyword in call.keywords):
        return False
    if any(keyword.arg != "mode" for keyword in call.keywords):
        return False
    keywords = [keyword.value for keyword in call.keywords if keyword.arg == "mode"]
    positional = call.args[positional_index] if len(call.args) > positional_index else None
    if len(keywords) > 1 or (positional is not None and keywords):
        return False
    mode_node = positional if positional is not None else (keywords[0] if keywords else None)
    if mode_node is None:
        return default_read
    if not isinstance(mode_node, ast.Constant) or not isinstance(mode_node.value, str):
        return False
    mode = mode_node.value
    if not mode or mode[0] not in "rwax":
        return False
    modifiers = mode[1:]
    if (any(char not in "bt+" for char in modifiers) or len(set(modifiers)) != len(modifiers)
            or ("b" in modifiers and "t" in modifiers)):
        return False
    return mode[0] == "r" and "+" not in modifiers


def _os_open_read_permitted(call: ast.Call, module_origins: dict[str, str]) -> bool:
    """Recognize a bounded os.open shape with read-only flags and no dir_fd redirect."""
    if len(call.args) < 1 or len(call.args) > 3 or any(keyword.arg is None for keyword in call.keywords):
        return False
    if any(keyword.arg not in {"flags", "mode"} for keyword in call.keywords):
        return False
    keywords = [keyword.value for keyword in call.keywords if keyword.arg == "flags"]
    positional = call.args[1] if len(call.args) > 1 else None
    if len(keywords) > 1 or (positional is not None and keywords):
        return False
    flags = positional if positional is not None else (keywords[0] if keywords else None)
    if flags is None:
        return False
    mode_keywords = [keyword.value for keyword in call.keywords if keyword.arg == "mode"]
    if len(mode_keywords) > 1 or (len(call.args) > 2 and mode_keywords):
        return False
    if len(call.args) > 2 and type(call.args[2]) is not ast.Constant:
        return False
    if len(call.args) > 2 and (type(call.args[2].value) is not int or call.args[2].value < 0):
        return False
    if mode_keywords and (not isinstance(mode_keywords[0], ast.Constant)
                          or type(mode_keywords[0].value) is not int or mode_keywords[0].value < 0):
        return False
    if isinstance(flags, ast.Constant) and type(flags.value) is int:
        return flags.value == 0
    return (isinstance(flags, ast.Attribute) and flags.attr == "O_RDONLY"
            and isinstance(flags.value, ast.Name) and module_origins.get(flags.value.id) == "os")


def _open_aliases(tree: ast.AST) -> tuple[set[str], set[str], set[str], set[str]]:
    """Return recognized readers/modules and names whose imported binding is ambiguous.

    This bounded model recognizes direct imports and simple assignment aliases of
    ``open``/``os.open``/``io.open``/``builtins.open``. Any other binding or
    rebinding of a recognized name (including parameters, destructuring, loop,
    context-manager, exception, match, deletion, and import bindings) makes that
    name unresolved. A recognized write to ``builtins.open`` also invalidates
    bare and imported builtin-open aliases. This is not complete Python I/O
    discovery; unsupported dynamic forms must not be described as covered.
    """
    readers = {"open"}
    modules: dict[str, str] = {}
    module_imports: dict[str, set[str]] = {}
    candidates: dict[str, list[ast.AST]] = {}
    unsafe: set[str] = set()
    unsafe_modules: set[str] = set()
    other_imports: set[str] = set()
    builtin_reader_imports: set[str] = set()
    unsupported_bindings: set[str] = set()
    simple_assignment_targets: set[int] = set()
    store_names: list[tuple[int, str]] = []
    shadowed: set[str] = set()
    open_member_rebindings: set[str] = set()

    def reader_expr(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in readers and node.id not in unsafe
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return (node.value.id not in unsafe_modules
                    and modules.get(node.value.id) in {"os", "io", "builtins"}
                    and node.attr == "open")
        return False

    def unsafe_reader_expr(node: ast.AST) -> bool:
        return ((isinstance(node, ast.Name) and node.id in unsafe)
                or (isinstance(node, ast.Attribute) and node.attr == "open"
                    and isinstance(node.value, ast.Name) and node.value.id in unsafe_modules))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"os", "io", "builtins"}:
                    module_imports.setdefault(alias.asname or alias.name, set()).add(alias.name)
                elif not alias.asname and alias.name.split(".", 1)[0] in {"os", "io", "builtins"}:
                    root_module = alias.name.split(".", 1)[0]
                    module_imports.setdefault(root_module, set()).add(root_module)
                else:
                    other_imports.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound_name = alias.asname or alias.name
                if node.module in {"builtins", "os", "io"} and alias.name == "open":
                    readers.add(alias.asname or alias.name)
                    if node.module == "builtins":
                        builtin_reader_imports.add(bound_name)
                elif node.module in {"os", "io", "builtins"}:
                    if bound_name in {"os", "io", "builtins"}:
                        other_imports.add(bound_name)
                else:
                    other_imports.add(bound_name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    candidates.setdefault(target.id, []).append(value)
                    if not isinstance(node, ast.NamedExpr) and value is not None:
                        simple_assignment_targets.add(id(target))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            shadowed.update(arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs))
            if args.vararg:
                shadowed.add(args.vararg.arg)
            if args.kwarg:
                shadowed.add(args.kwarg.arg)
            if not isinstance(node, ast.Lambda):
                unsupported_bindings.add(node.name)
        elif isinstance(node, ast.ClassDef):
            unsupported_bindings.add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            unsupported_bindings.add(node.name)
        elif isinstance(node, ast.MatchAs) and node.name:
            unsupported_bindings.add(node.name)
        elif isinstance(node, ast.MatchStar) and node.name:
            unsupported_bindings.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            unsupported_bindings.add(node.rest)
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                store_names.append((id(node), node.id))
        elif (isinstance(node, ast.Attribute) and node.attr == "open"
              and isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name)):
            open_member_rebindings.add(node.value.id)

    unsupported_bindings.update(name for ident, name in store_names if ident not in simple_assignment_targets)

    for name, imported_modules in module_imports.items():
        if len(imported_modules) == 1:
            modules[name] = next(iter(imported_modules))
        else:
            unsafe_modules.add(name)

    # Resolve simple module aliases such as ``reader = os`` after all imports
    # have been collected, so statement order cannot change the static result.
    for _ in range(len(candidates) + 1):
        changed = False
        for name, values in candidates.items():
            if name not in modules:
                for value in values:
                    if isinstance(value, ast.Name) and value.id in modules:
                        modules[name] = modules[value.id]
                        changed = True
                        break
        if not changed:
            break

    imported_names = set(module_imports)
    recognized_names = set(modules) | imported_names
    conflicting_roles = set(readers).intersection(recognized_names)
    unsafe.update(conflicting_roles)
    unsafe_modules.update(conflicting_roles)
    unsafe_modules.update((unsupported_bindings | shadowed | other_imports).intersection(recognized_names))
    unsafe_modules.update(open_member_rebindings.intersection(recognized_names))
    unsafe_modules.update(shadowed.intersection(set(modules) | imported_names))
    for _ in range(len(candidates) + 1):
        changed = False
        for name, values in candidates.items():
            if name in modules and any(
                    not isinstance(value, ast.Name) or modules.get(value.id) != modules[name]
                    or value.id in unsafe_modules for value in values):
                if name not in unsafe_modules:
                    unsafe_modules.add(name)
                    changed = True
            elif name not in modules and any(
                    isinstance(value, ast.Name) and value.id in imported_names | unsafe_modules
                    for value in values):
                unsafe_modules.add(name)
                changed = True
        if not changed:
            break

    if any(modules.get(name) == "builtins" for name in open_member_rebindings):
        # A write through any recognized builtins module alias makes bare and
        # imported builtin-open names ambiguous for this whole consumer.
        unsafe.add("open")
        unsafe.update(builtin_reader_imports)

    # Resolve aliases and propagate ambiguous source bindings through aliases.
    intrinsically_unsafe_readers = unsupported_bindings | shadowed | other_imports
    unsafe.update(intrinsically_unsafe_readers.intersection(readers))
    for _ in range(2 * len(candidates) + 1):
        changed = False
        for name, values in candidates.items():
            if name not in readers and any(reader_expr(value) for value in values):
                readers.add(name)
                changed = True
            if name in readers and (name in intrinsically_unsafe_readers
                                    or any(not reader_expr(value) for value in values)):
                if name not in unsafe:
                    unsafe.add(name)
                    changed = True
            elif name not in readers and any(unsafe_reader_expr(value) for value in values):
                if name not in unsafe:
                    unsafe.add(name)
                    changed = True
        if not changed:
            break
    return readers, set(modules) | imported_names | unsafe_modules, unsafe, unsafe_modules


def literal_source_reads(consumer_path: str, consumer_bytes: bytes) -> tuple[list[dict], list[dict]]:
    """Extract literal Python file reads without executing code or guessing dynamic paths."""
    try:
        tree = ast.parse(consumer_bytes.decode("utf-8"), filename=consumer_path)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ContractError("consumer source is not parseable UTF-8 Python") from exc
    reads, unresolved = [], []
    reader_names, module_names, unsafe_reader_names, unsafe_module_names = _open_aliases(tree)
    reader_api_origins, module_api_origins = _open_api_origins(
        tree, reader_names, module_names, unsafe_reader_names, unsafe_module_names)
    path_constructors = _pathlib_constructor_names(tree)
    file_io_constructors = _pathlib_constructor_names(tree, file_io_only=True)
    file_anchor_trusted = "__file__" not in _bound_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        path_node, operation, api_origin, requires_path_receiver = None, None, None, False
        if isinstance(node.func, ast.Name) and node.func.id in unsafe_reader_names:
            operation = "unclassified-open-alias"
            path_node = None
        elif isinstance(node.func, ast.Name) and node.func.id in reader_names:
            operation = "open-alias" if node.func.id != "open" else "open"
            path_node = node.args[0] if node.args else None
            api_origin = reader_api_origins.get(node.func.id)
        elif (isinstance(node.func, ast.Attribute) and node.func.attr == "open"
              and isinstance(node.func.value, ast.Name) and node.func.value.id in unsafe_module_names):
            operation = "unclassified-module-open-alias"
            path_node = None
        elif (isinstance(node.func, ast.Attribute) and node.func.attr == "open"
              and isinstance(node.func.value, ast.Name) and node.func.value.id in module_names):
            operation = node.func.value.id + ".open"
            path_node = node.args[0] if node.args else None
            api_origin = module_api_origins.get(node.func.value.id)
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {"open", "read_text", "read_bytes"}:
            operation = node.func.attr
            path_node = node.func.value
            requires_path_receiver = True
            api_origin = "path" if node.func.attr == "open" else "read-method"
        else:
            continue
        trusted_receiver = (not requires_path_receiver or
                            _is_path_file_io_receiver(path_node, consumer_path, file_io_constructors,
                                                     file_anchor_trusted))
        read_permitted = False
        if api_origin in {"builtin", "builtins", "io", "path"}:
            read_permitted = _read_mode_permitted(node, 0 if api_origin == "path" else 1,
                                                  default_read=True,
                                                  max_positional=1 if api_origin == "path" else 2)
        elif api_origin == "os":
            read_permitted = _os_open_read_permitted(node, module_api_origins)
        elif api_origin == "read-method":
            read_permitted = True
        path = (_literal_read_path(path_node, consumer_path, path_constructors, file_anchor_trusted)
                if path_node is not None and trusted_receiver and read_permitted else None)
        row = {"operation": operation, "line": node.lineno, "column": node.col_offset}
        if path is None:
            unresolved.append(row)
        else:
            reads.append({**row, "path": path})
    return sorted(reads, key=lambda row: (row["line"], row["column"], row["path"])), unresolved


def resolve_control_target(execution_path: str, cwd: str, argv: list[str], prefix: str) -> str:
    """Resolve the one supported command target and bind it to execution_path."""
    if not argv or not re.fullmatch(r"python3(?:\.[0-9]+)?", argv[0]):
        raise ContractError(prefix + " has an unsupported Python command form")
    command = argv[1:]

    def resolve(token: str) -> str:
        if not token or token.startswith("/") or "\\" in token or "\x00" in token:
            raise ContractError(prefix + " has an unsupported control target")
        combined = token if cwd == "." else cwd + "/" + token
        normalized = posixpath.normpath(combined)
        if normalized in {".", ".."} or normalized.startswith("../"):
            raise ContractError(prefix + " control target escapes the repository")
        try:
            return _path(normalized, prefix + ".argv target", code_only=True)
        except ContractError as exc:
            raise ContractError(prefix + " has an unsupported control target") from exc

    if command and not command[0].startswith("-"):
        target = resolve(command[0])
    elif command[:2] == ["-m", "unittest"]:
        selectors = command[2:]
        if not selectors or any(token.startswith("-") for token in selectors):
            raise ContractError(prefix + " unittest control form is unsupported")
        if cwd == ".":
            module_path = execution_path
        elif execution_path.startswith(cwd + "/"):
            module_path = execution_path[len(cwd) + 1:]
        else:
            raise ContractError(prefix + " unittest target is outside its import root")
        module = module_path[:-3].replace("/", ".")
        if not all(part.isidentifier() for part in module.split(".")):
            raise ContractError(prefix + " unittest module target is unsupported")
        for selector in selectors:
            parts = selector.split(".")
            if ((selector != module and not selector.startswith(module + ".")) or
                    any(not part.isidentifier() for part in parts)):
                raise ContractError(prefix + " unittest selectors do not bind to execution_path")
        target = execution_path
    elif command[:2] == ["-m", "pytest"]:
        if len(command) != 3 or command[2].startswith("-"):
            raise ContractError(prefix + " pytest control form is unsupported")
        token, *selectors = command[2].split("::")
        if any(not part.isidentifier() for part in selectors):
            raise ContractError(prefix + " pytest selector form is unsupported")
        target = resolve(token)
    else:
        raise ContractError(prefix + " argv must directly execute its pinned script or test module")
    if target != execution_path:
        raise ContractError(prefix + " actual argv target differs from execution_path")
    return target


def validate_control(control, entry, index: int) -> list[str]:
    prefix = f"inputs[{index}].controls"
    _exact_keys(control, {"id", "role", "execution_path", "execution_sha256", "argv", "cwd",
                          "interpreter", "interpreter_sha256", "environment", "timeout_seconds",
                          "expected_exit_code", "expected_output_contains"}, set(), prefix)
    if (not isinstance(control["id"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", control["id"])
            or not isinstance(control["role"], str) or control["role"] not in {"positive", "negative"}):
        raise ContractError(prefix + " id/role is invalid")
    execution_path = _path(control["execution_path"], prefix + ".execution_path", code_only=True)
    execution_hash = _digest(control["execution_sha256"], prefix + ".execution_sha256")
    if execution_path not in entry["control_sources"]:
        raise ContractError(prefix + " execution file is not listed in control_sources")
    if entry["control_sources"][execution_path] != execution_hash:
        raise ContractError(prefix + " execution file pin differs from control_sources")
    argv = control["argv"]
    if (not isinstance(argv, list) or not 2 <= len(argv) <= 64
            or any(not isinstance(x, str) or not x or len(x) > 1024 or "\x00" in x for x in argv)):
        raise ContractError(prefix + ".argv must be a bounded nonempty string array")
    if any(x in {"-c", "-", "--eval", "--execute"} for x in argv):
        raise ContractError(prefix + " inline-code execution is refused")
    interpreter = control["interpreter"]
    if (not isinstance(interpreter, str) or not re.fullmatch(r"python3(?:\.[0-9]+)?", interpreter)
            or argv[0] != interpreter):
        raise ContractError(prefix + " must use its pinned Python 3 interpreter as argv[0]")
    _digest(control["interpreter_sha256"], prefix + ".interpreter_sha256")
    cwd = _path(control["cwd"], prefix + ".cwd")
    env = control["environment"]
    if not isinstance(env, dict) or any(not isinstance(k, str) or not ENV_KEY.fullmatch(k)
                                         or k not in SAFE_ENV or not isinstance(v, str)
                                         or len(v) > 256 or "\x00" in v for k, v in env.items()):
        raise ContractError(prefix + ".environment contains an unsupported key or value")
    timeout = control["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT:
        raise ContractError(prefix + ".timeout_seconds must be an integer from 1 to 600")
    rc = control["expected_exit_code"]
    if isinstance(rc, bool) or not isinstance(rc, int) or not 0 <= rc <= 255:
        raise ContractError(prefix + ".expected_exit_code must be an integer from 0 to 255")
    expected = control["expected_output_contains"]
    if not isinstance(expected, str) or not expected.strip() or len(expected) > 512:
        raise ContractError(prefix + ".expected_output_contains must be a nonempty bounded oracle")

    # Resolve the target as the child process will: script and test paths are
    # interpreted relative to cwd, never relative to the verifier's repository root.
    resolve_control_target(execution_path, cwd, argv, prefix)
    if any(token in {";", "&&", "||", "|", ">", "<", "`"} or "$" in token for token in argv):
        raise ContractError(prefix + " shell syntax is refused")
    return [execution_path, cwd]


def parse(raw: bytes, files: dict[str, bytes] | None = None,
          file_modes: dict[str, str] | None = None) -> list[dict]:
    if not isinstance(raw, bytes) or len(raw) > MAX_MANIFEST_BYTES:
        raise ContractError("source-input manifest is not a bounded byte string")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(f"duplicate JSON member: {key}")
            result[key] = value
        return result
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                         parse_constant=lambda value: (_ for _ in ()).throw(ContractError("non-JSON number")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("source-input manifest is not valid UTF-8 JSON") from exc
    if files is not None and MANIFEST_PATH not in files:
        raise ContractError("source-input manifest is absent from measured tree")
    if file_modes is not None and file_modes.get(MANIFEST_PATH) not in {"100644", "100755"}:
        raise ContractError("source-input manifest is not a regular Git file")
    _exact_keys(doc, {"schema", "inputs"}, set(), "manifest")
    if doc["schema"] != SCHEMA or not isinstance(doc["inputs"], list) or not 1 <= len(doc["inputs"]) <= 256:
        raise ContractError("manifest schema or inputs cardinality is invalid")
    seen = set()
    entries = []
    consumer_reads = {}
    for i, entry in enumerate(doc["inputs"]):
        prefix = f"inputs[{i}]"
        _exact_keys(entry, {"source_path", "source_sha256", "consumer_path", "consumer_sha256",
                            "control_sources", "controls"}, set(), prefix)
        source = _path(entry["source_path"], prefix + ".source_path")
        consumer = _path(entry["consumer_path"], prefix + ".consumer_path", code_only=True)
        identity = (source, consumer)
        if source == consumer or identity in seen:
            raise ContractError(prefix + " source/consumer identity is duplicate or self-referential")
        seen.add(identity)
        _digest(entry["source_sha256"], prefix + ".source_sha256")
        _digest(entry["consumer_sha256"], prefix + ".consumer_sha256")
        controls = entry["control_sources"]
        if not isinstance(controls, dict) or not controls or len(controls) > 32:
            raise ContractError(prefix + ".control_sources must pin one or more explicit files")
        normalized = {}
        for path, digest in controls.items():
            normalized[_path(path, prefix + ".control_sources key", code_only=True)] = _digest(
                digest, prefix + ".control_sources digest")
        if consumer not in normalized or normalized[consumer] != entry["consumer_sha256"]:
            raise ContractError(prefix + " consumer bytes are not identically pinned in control_sources")
        rows = entry["controls"]
        if not isinstance(rows, list) or not 2 <= len(rows) <= MAX_CONTROLS:
            raise ContractError(prefix + ".controls must include bounded positive and negative controls")
        ids, roles = set(), set()
        for control in rows:
            validate_control(control, {**entry, "control_sources": normalized}, i)
            if control["id"] in ids:
                raise ContractError(prefix + " duplicate control id")
            ids.add(control["id"])
            roles.add(control["role"])
        if roles != {"positive", "negative"}:
            raise ContractError(prefix + " needs both positive and negative controls")
        if any(c["role"] == "positive" and c["expected_exit_code"] != 0 for c in rows):
            raise ContractError(prefix + " positive controls must require exit zero")
        entry = {**entry, "source_path": source, "consumer_path": consumer,
                 "control_sources": normalized}
        if files is not None:
            for path, expected in [(source, entry["source_sha256"]),
                                   (consumer, entry["consumer_sha256"]), *normalized.items()]:
                if path not in files:
                    raise ContractError(f"pinned source-input file is missing: {path}")
                if sha256(files[path]) != expected:
                    raise ContractError(f"pinned source-input bytes differ: {path}")
                if file_modes is not None and file_modes.get(path) not in {"100644", "100755"}:
                    raise ContractError(f"pinned source-input path is not a regular Git file: {path}")
            reads, unresolved_reads = literal_source_reads(consumer, files[consumer])
            matches = [row for row in reads if row["path"] == source]
            if not matches:
                raise ContractError("consumer has no statically bound literal read of source_path")
            consumer_reads[consumer] = (reads, unresolved_reads)
            entry["read_occurrences"] = matches
        entries.append(entry)
    if files is not None:
        declared_by_consumer = {}
        for entry in entries:
            declared_by_consumer.setdefault(entry["consumer_path"], set()).add(entry["source_path"])
        for consumer, declared in declared_by_consumer.items():
            reads, unresolved = consumer_reads[consumer]
            if unresolved:
                lines = sorted({row["line"] for row in unresolved})
                raise ContractError(f"consumer has unresolved dynamic file reads at lines {lines}")
            unbound = sorted({row["path"] for row in reads} - declared)
            if unbound:
                raise ContractError(f"consumer has unbound literal file reads: {unbound}")
    return entries


def interpreter_matches(command: str, expected_sha256: str) -> bool:
    resolved = shutil.which(command)
    if not resolved:
        return False
    try:
        with open(resolved, "rb") as stream:
            return sha256(stream.read()) == expected_sha256
    except OSError:
        return False
