"""Fixed native replay entrypoint; observes imports without issuing authority.

Only a supported CPython IMPORT_NAME at the complete selected AST statement can
bind a provider. Observations retain boundary state and every seen source, even
when the consumer later replaces or deletes a sys.modules entry.
"""
import ast
import builtins
import dis
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    revision, occurrence_json = sys.argv[1:]
    occurrence = json.loads(occurrence_json)
    consumer = Path('/input/consumer/src/argana/kc2.py')
    provider_root = Path('/input/provider')
    raw = consumer.read_bytes()
    span = (occurrence['line'], occurrence['end_line'],
            occurrence['column'], occurrence['end_column'])
    # The parser owner's full occurrence identity has already been qualified.
    # This independent runtime check narrows supported replay to one absolute
    # import alias, whose entire AST span maps to exactly one IMPORT_NAME.
    nodes = [n for n in ast.walk(ast.parse(raw)) if isinstance(n, ast.Import)
             and (n.lineno, n.end_lineno, n.col_offset, n.end_col_offset) == span]
    if (occurrence['kind'] != 'import' or occurrence['level'] != 0
            or occurrence['alias_index'] != 0 or len(nodes) != 1
            or len(nodes[0].names) != 1
            or nodes[0].names[0].name != occurrence['module']
            or (nodes[0].names[0].asname or nodes[0].names[0].name.split('.')[0]) != occurrence['local_name']
            or hashlib.sha256(ast.get_source_segment(raw.decode(), nodes[0]).encode()).hexdigest()
               != occurrence['statement_sha256']
            or sha(consumer) != occurrence['source_sha256']):
        raise ValueError('unsupported native occurrence')
    cache_empty = not any(name.startswith('kc2_') for name in sys.modules)
    original_import = builtins.__import__
    seen = {}
    observations = []
    instructions = {}
    observing = False

    def source(value):
        filename = getattr(value, '__file__', None)
        if not filename:
            return None
        path = Path(filename)
        if not path.is_relative_to(provider_root):
            return None
        spec = getattr(value, '__spec__', None)
        if (path.suffix != '.py' or path.is_symlink() or path.resolve() != path
                or spec is None or spec.origin != str(path)
                or type(spec.loader).__name__ != 'SourceFileLoader'):
            raise ValueError('unsupported observed native source')
        row = {'path': str(path.relative_to(provider_root)), 'sha256': sha(path)}
        seen[row['path']] = row
        return row

    def census():
        result = {}
        for name, value in list(sys.modules.items()):
            row = source(value)
            if row is not None:
                result[name] = row
        return result

    def observe(name, globals=None, locals=None, fromlist=(), level=0):
        nonlocal observing
        if observing:
            # Imports performed by introspection (e.g. pathlib's ntpath) are
            # instrument code, not consumer/provider operations.
            return original_import(name, globals, locals, fromlist, level)
        caller = sys._getframe(1)
        observing = True
        try:
            candidate = False
            if caller.f_code.co_filename == str(consumer):
                code = caller.f_code
                if code not in instructions:
                    instructions[code] = {i.offset: i for i in dis.get_instructions(code)}
                instruction = instructions[code].get(caller.f_lasti)
                if instruction is not None and instruction.opname == 'IMPORT_NAME':
                    pos = instruction.positions
                    candidate = (pos.lineno, pos.end_lineno, pos.col_offset, pos.end_col_offset) == span
                    if candidate and (instruction.argval != occurrence['module']
                                      or name != occurrence['module'] or level != 0 or fromlist):
                        raise ValueError('unsupported import operation at selected span')
            before = census()
            paths = list(sys.path)
        finally:
            observing = False
        loaded = original_import(name, globals, locals, fromlist, level)
        observing = True
        try:
            after = census()
            returned = source(loaded)
            if candidate:
                if returned is None or sys.modules.get(name) is not loaded:
                    raise ValueError('ambiguous returned native provider')
                observations.append({'occurrence': occurrence, 'opcode': 'IMPORT_NAME',
                                     'provider': returned, 'loader': type(loaded.__spec__.loader).__name__,
                                     'search_path': paths, 'cache_before': before, 'cache_after': after})
        finally:
            observing = False
        return loaded

    # Include module-level loads and nested imports in the retained census.
    builtins.__import__ = observe
    try:
        spec = importlib.util.spec_from_file_location('native_argana_kc2', consumer)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        store = module.Kc2Store(str(provider_root), revision=revision)
        store._load()
        store._store_dir()
        observing = True
        try:
            census()
        finally:
            observing = False
        if builtins.__import__ is not observe:
            raise ValueError('native observation hook replaced')
    finally:
        builtins.__import__ = original_import
    if len(observations) != 1:
        raise ValueError('selected import absent or repeated/ambiguous')
    boundary = observations[0]
    provider = boundary['provider']
    transitive = [seen[k] for k in sorted(seen) if k != provider['path']]
    print(json.dumps({'consumer_sha256': sha(consumer), 'provider_sha256': provider['sha256'],
            'provider_path': provider['path'], 'occurrence': occurrence, 'import_observation': boundary,
            'loader': boundary['loader'], 'cache_empty': cache_empty,
            'search_path': boundary['search_path'], 'transitive_inputs': transitive,
            'interpreter': {'implementation': sys.implementation.name.capitalize().replace('Cpython', 'CPython'),
                            'version': sys.version.split()[0], 'executable_sha256': sha(Path(sys.executable))}}))


if __name__ == '__main__':
    main()
