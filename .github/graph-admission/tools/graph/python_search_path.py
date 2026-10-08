"""Bounded, non-executing interpretation of explicit per-file Python search paths.

Only top-level Path(__file__).resolve(), parent/parents[N], literal `/` joins,
name assignments and sys.path.insert(0, str(path)) are admitted. Unknown path
mutations suppress absolute resolution rather than choosing a guessed provider.
Paths refer to Git tree names; no host filesystem or module is imported.
"""
from __future__ import annotations

import ast
import posixpath
from collections import deque

MAX_MODULE_CONTEXTS = 32
MAX_TOTAL_CONTEXTS = 2048
# Closed source-model assumptions, not a host import or general stdlib exemption.
# A matching Git module anywhere defeats this assumption conservatively.
PATH_NEUTRAL_STDLIB = frozenset({'sys', 'pathlib', 'functools', 'copy', 'json', 'unittest',
                               'collections', 'dataclasses', 'decimal', 'hashlib', 'math', 're', 'typing',
                               'glob', 'heapq'})


def import_roots(text: str, file: str, *, incoming=(), final_roots=None) -> tuple[dict[int, list[str] | None], list[str]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError):
        return {}, []  # Existing lexical extraction still handles otherwise parseable constructs.
    names: dict[str, tuple[str, str]] = {}
    roots: list[str] = list(incoming)
    blocked = False
    by_line: dict[int, list[str] | None] = {}
    limitations: list[str] = []

    def value(node):
        if isinstance(node, ast.Name):
            return ('path', '/repo/' + file) if node.id == '__file__' and node.id not in names else names.get(node.id)
        if isinstance(node, ast.Call) and not node.keywords:
            if isinstance(node.func, ast.Name) and names.get(node.func.id) == ('alias', 'Path') and len(node.args) == 1:
                v = value(node.args[0])
                return v if v and v[0] == 'path' else None
            if isinstance(node.func, ast.Name) and node.func.id == 'str' and 'str' not in names and len(node.args) == 1:
                return value(node.args[0])
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'resolve' and not node.args:
                return value(node.func.value)
        if isinstance(node, ast.Attribute) and node.attr == 'parent':
            v = value(node.value)
            return ('path', posixpath.dirname(v[1])) if v and v[0] == 'path' else None
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute)
                and node.value.attr == 'parents' and isinstance(node.slice, ast.Constant)
                and type(node.slice.value) is int and 0 <= node.slice.value <= 32):
            v = value(node.value.value)
            if v and v[0] == 'path':
                p = v[1]
                for _ in range(node.slice.value + 1):
                    p = posixpath.dirname(p)
                return ('path', p)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            v = value(node.left)
            if v and v[0] == 'path' and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str):
                s = node.right.value
                if s and not s.startswith('/') and '\\' not in s and '..' not in s.split('/'):
                    return ('path', posixpath.normpath(v[1] + '/' + s))
        return None

    def sys_path(node):
        return (isinstance(node, ast.Attribute) and node.attr == 'path'
                and isinstance(node.value, ast.Name) and names.get(node.value.id) == ('alias', 'sys'))

    for stmt in tree.body:
        mutations = [n for n in ast.walk(stmt) if sys_path(n)]
        if mutations:
            call = stmt.value if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) else None
            exact = (call and isinstance(call.func, ast.Attribute) and sys_path(call.func.value)
                     and call.func.attr == 'insert' and not call.keywords and len(call.args) == 2
                     and isinstance(call.args[0], ast.Constant) and type(call.args[0].value) is int
                     and call.args[0].value == 0)
            v = value(call.args[1]) if exact else None
            if v and v[0] == 'path' and (v[1] == '/repo' or v[1].startswith('/repo/')) and not blocked:
                roots.insert(0, v[1][len('/repo'):].lstrip('/'))
            else:
                blocked = True
                limitations.append(f'python: unresolved sys.path mutation at {file}:{stmt.lineno}; absolute imports not resolved')
        for node in ast.walk(stmt):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                by_line[node.lineno] = None if blocked else list(roots)
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                names[alias.asname or alias.name.split('.')[0]] = ('alias', 'sys') if alias.name == 'sys' else ('unknown', '')
        elif isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                names[alias.asname or alias.name] = ('alias', 'Path') if stmt.module == 'pathlib' and alias.name == 'Path' and not stmt.level else ('unknown', '')
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            v = value(stmt.value) if not isinstance(stmt, ast.AugAssign) else None
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                for node in ast.walk(target):
                    if isinstance(node, ast.Name):
                        names[node.id] = v or ('unknown', '')
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names[stmt.name] = ('unknown', '')
        else:
            # Conditional assignments/imports cannot establish a deterministic anchor.
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    names[node.id] = ('unknown', '')
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        names[alias.asname or alias.name.split('.')[0]] = ('unknown', '')
    if final_roots is not None:
        final_roots[:] = [] if blocked else roots
    return by_line, limitations


def contextual_imports(files, modes, discovered_roots):
    """Explore explicit caller roots without executing modules or inventing siblings.

    Returned dependencies are contextual may-edges. Unknown mutation is unresolved;
    exhaustion raises before a truncated dependency graph can escape to a consumer.
    """
    parsed = {}
    limitations = set()

    def neutral_import(module):
        root = (module or '').split('.')[0]
        if root not in PATH_NEUTRAL_STDLIB:
            return False
        return not any(p == root + '.py' or p.endswith('/' + root + '.py')
                       or p == root + '/__init__.py' or p.endswith('/' + root + '/__init__.py')
                       for p in files)

    for file, text in sorted(files.items()):
        try:
            tree = ast.parse(text)
        except (SyntaxError, RecursionError):
            parsed[file] = (None, 'unparseable source')
            continue
        aliases = {'sys'} | {a.asname or a.name for n in ast.walk(tree)
                            if isinstance(n, ast.Import) for a in n.names if a.name == 'sys'}
        cache = any(isinstance(n, ast.Attribute) and n.attr == 'modules'
                    and isinstance(n.value, ast.Name) and n.value.id in aliases for n in ast.walk(tree))
        sys_indirections = [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
                            and n.module == 'sys' and not n.level]
        cache = cache or any(a.name == 'modules' for n in sys_indirections for a in n.names)
        _, errors = import_roots(text, file)
        reason = 'module cache access/mutation' if cache else ('unresolved path mutation' if errors else None)
        if sys_indirections and not reason:
            reason = 'unsupported sys indirection'
        if not reason and any(isinstance(n, ast.ImportFrom) and n.level and not n.module for n in ast.walk(tree)):
            reason = 'unsupported bare relative import effects'
        indirect_sys = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                           and n.func.id == 'getattr' and n.args and isinstance(n.args[0], ast.Name)
                           and n.args[0].id in aliases for n in ast.walk(tree))
        dynamic = any(isinstance(n, ast.Call) and (
            isinstance(n.func, ast.Name) and n.func.id in {'__import__', 'exec', 'eval'}
            or isinstance(n.func, ast.Attribute) and n.func.attr in {'import_module', 'exec_module', 'reload'})
            for n in ast.walk(tree))
        if not reason and (indirect_sys or dynamic):
            reason = 'unsupported sys indirection' if indirect_sys else 'dynamic import effects'
        seen_import = False
        for statement in tree.body:
            if any(isinstance(n, ast.Attribute) and n.attr == 'path'
                   and isinstance(n.value, ast.Name) and n.value.id in aliases for n in ast.walk(statement)):
                if seen_import:
                    reason = reason or 'unresolved later path mutation'
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                modules = [a.name for a in statement.names] if isinstance(statement, ast.Import) else [statement.module]
                if ((isinstance(statement, ast.ImportFrom) and statement.level)
                        or any(not neutral_import(m) for m in modules)):
                    seen_import = True
        if modes.get(file) == '120000':
            reason = 'symlink source'
        parsed[file] = (tree, reason)
        if reason:
            limitations.add(f'python: caller-context unresolved at {file}: {reason}')

    def specs(tree, *, initialization=False):
        rows = []
        def initialized_nodes(node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return
            yield node
            for child in ast.iter_child_nodes(node):
                yield from initialized_nodes(child)
        # Class bodies execute at import; only function/method bodies defer imports.
        nodes = initialized_nodes(tree) if initialization else ast.walk(tree)
        for node in nodes:
            if isinstance(node, ast.Import):
                rows.extend((node.lineno, 0, alias.name) for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                rows.append((node.lineno, node.level, node.module))
        return sorted(rows)

    def resolve(file, level, module, roots):
        rel = module.replace('.', '/')
        if level:
            directory = posixpath.dirname(file)
            for _ in range(level - 1):
                directory = posixpath.dirname(directory)
            candidates = [posixpath.join(directory, rel)]
        else:
            candidates = [posixpath.join(root, rel) for root in (*roots, *discovered_roots)]
        for candidate in candidates:
            for target in (candidate + '/__init__.py', candidate + '.py'):
                if target not in files:
                    continue
                if modes.get(target) == '120000':
                    limitations.add(f'python: caller-context unresolved at {file}: symlink provider {target}')
                    return None
                return target
        return None

    effect_cache = {}
    effect_contexts = set()

    def canonical_roots(roots):
        # Repeated identical Git roots select the same first provider. Preserve
        # first occurrence order rather than generating infinite duplicate states.
        return tuple(dict.fromkeys(roots))

    def imports_and_effects(file, incoming, chain=(), *, initialization=False):
        incoming = canonical_roots(incoming)
        tree, reason = parsed[file]
        if tree is None or reason:
            return [], None
        key = (file, tuple(incoming))
        if key in chain:
            limitations.add(f'python: caller-context unresolved at {file}: cyclic import effects')
            return [], None
        effect_contexts.add(key)
        if len(effect_contexts) > MAX_TOTAL_CONTEXTS or len(chain) >= MAX_MODULE_CONTEXTS:
            raise ValueError(f'python caller-context effect cap exhausted at {file}; incomplete graph refused')
        final = []
        by_line, errors = import_roots(files[file], file, incoming=incoming, final_roots=final)
        if errors:
            return [], None
        rows, active = [], None
        direct_lines = {n.lineno for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))}
        from_specs = {(n.lineno, n.level, n.module or '') for n in ast.walk(tree)
                      if isinstance(n, ast.ImportFrom)}
        for line, level, module in specs(tree, initialization=initialization):
            roots = by_line.get(line) if active is None else active
            if roots is None:
                return rows, None
            roots = canonical_roots(roots)
            if '.' in module:
                limitations.add(f'python: caller-context unresolved at {file}:{line}: dotted package initialization effects not modeled')
                return rows, None
            if not level and neutral_import(module):
                continue
            target = resolve(file, level, module, roots)
            if not target:
                limitations.add(f'python: caller-context unresolved at {file}:{line}: downstream import effects from {module}')
                return rows, None
            if target != file:
                rows.append((line, target, tuple(roots)))
            if (line, level, module) in from_specs and target.endswith('/__init__.py'):
                limitations.add(f'python: caller-context unresolved at {file}:{line}: from-package initialization effects not modeled')
                return rows, None
            child_key = (target, tuple(roots))
            if child_key not in effect_cache:
                _, effect_cache[child_key] = imports_and_effects(target, roots, (*chain, key), initialization=True)
            outgoing = effect_cache[child_key]
            if outgoing is None or line not in direct_lines:
                limitations.add(f'python: caller-context unresolved at {file}:{line}: downstream import effects from {target}')
                return rows, None
            active = list(outgoing)
        return rows, canonical_roots(final if active is None else active)

    pending = deque()
    visited = set()
    module_roots = {}
    edges = {}

    def enqueue(target, roots, origin):
        roots = canonical_roots(roots)
        key = (target, tuple(roots), origin)
        if key in visited:
            return
        contexts = module_roots.setdefault(target, set())
        contexts.add(tuple(roots))
        if len(contexts) > MAX_MODULE_CONTEXTS or len(visited) >= MAX_TOTAL_CONTEXTS:
            raise ValueError(f'python caller-context cap exhausted at {target}; incomplete graph refused')
        visited.add(key)
        pending.append(key)

    for file, (tree, reason) in parsed.items():
        if tree is None or reason:
            continue
        rows, _ = imports_and_effects(file, ())
        for line, target, roots in rows:
            if not roots:
                continue
            if target and target != file:
                enqueue(target, roots, (file, line))

    while pending:
        file, roots, origin = pending.popleft()
        tree, reason = parsed[file]
        if tree is None or reason:
            continue
        rows, _ = imports_and_effects(file, roots)
        for line, target, at_import in rows:
            if not target or target == file:
                continue
            site = (origin[0], origin[1], tuple(at_import), file, line, target)
            edges.setdefault((file, target), set()).add(site)
            enqueue(target, at_import, origin)
    rows = []
    for (file, target), sites in sorted(edges.items()):
        rows.append({'from': file, 'to': target, 'contexts': [
            {'initiating_caller': caller, 'initiating_line': first_line, 'ordered_roots': list(roots),
             'importing_file': module, 'import_line': line, 'selected_git_provider': provider}
            for caller, first_line, roots, module, line, provider in sorted(sites)]})
    return rows, sorted(limitations)
