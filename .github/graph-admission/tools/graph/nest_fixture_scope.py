"""DEC-AUP-0147 compiler-derived inline harness facts, never author declarations."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import fixture_contracts

HERE = Path(__file__).resolve().parent


def compiler_library_for(repo, subdir=''):
    current = Path(repo) / (subdir or '')
    root = Path(repo).resolve()
    while True:
        candidate = current / 'node_modules/typescript/lib/typescript.js'
        if candidate.is_file():
            return candidate.resolve()
        if current.resolve() == root or current == current.parent:
            return None
        current = current.parent


def project_inline_harness(tree, *, repo, commit, root_module_file, compiler_library):
    """Native-selected Git source and SDK are inputs; uncertainty never qualifies a fixture."""
    output = {'schema': 'InlineNestHarnessProjection/v1', 'source_commit': commit,
              'compiler': None, 'root_binding': None, 'options_binding': [],
              'controllers': [], 'limitations': []}
    candidates = [p for p in tree.paths if p.endswith(('.spec.ts', '.test.ts', '.spec.tsx', '.test.tsx'))
                  and '@Controller' in tree.text(p)]
    if not candidates:
        return output
    if not repo or not compiler_library or not root_module_file:
        output['limitations'].append('INLINE_HARNESS_CONTEXT_UNAVAILABLE')
        return output
    try:
        prefix = (tree.meta.get('subdir') or '').strip('/')
        selected_root = Path(repo).resolve() / prefix
        snapshot = fixture_contracts.GitSnapshot.read(Path(repo), commit)
        if snapshot.commit != tree.meta.get('source_commit') or tree.meta.get('source_tree') != 'git-objects':
            raise ValueError('SOURCE_SNAPSHOT_MISMATCH')
        bindings = {}
        for path, raw in tree.files.items():
            physical = prefix + '/' + path if prefix else path
            blob = snapshot.blobs.get(physical)
            if blob is None or blob.data != raw:
                raise ValueError('SOURCE_SNAPSHOT_MISMATCH')
            if path.endswith(('.ts', '.tsx', '.js', '.jsx', '.mts', '.cts', '.json')):
                declaration = {'path': physical, 'git_blob': blob.oid,
                               'sha256': hashlib.sha256(raw).hexdigest()}
                snapshot.bound(declaration)
                bindings[path] = declaration
        if root_module_file not in bindings:
            raise ValueError('PRODUCTION_ROOT_UNBOUND')
        output['root_binding'] = bindings[root_module_file]
        library = Path(compiler_library).resolve()
        expected = compiler_library_for(repo, prefix)
        if library != expected:
            raise ValueError('COMPILER_SELECTION_MISMATCH')
        package_path = library.parent.parent / 'package.json'
        package = json.loads(package_path.read_text())
        if package.get('name') != 'typescript':
            raise ValueError('COMPILER_PACKAGE_MISMATCH')
        package_root = Path(root_module_file).parent
        config = None
        while True:
            path = (package_root / 'tsconfig.json').as_posix()
            if path in bindings:
                config = path
                break
            if package_root.as_posix() == '.' or package_root == package_root.parent:
                break
            package_root = package_root.parent
        if config is None:
            raise ValueError('COMPILER_OPTIONS_UNBOUND')
        options = json.loads(tree.text(config))
        if 'extends' in options:
            raise ValueError('COMPILER_OPTIONS_EXTENDS_UNRESOLVED')
        output['options_binding'] = [bindings[config]]
        node = shutil.which('node')
        if not node:
            raise ValueError('NODE_UNAVAILABLE')
        helper = HERE / 'inline_nest_harness.cjs'
        execution_paths = {'compiler': library, 'package': package_path, 'helper': helper, 'node': Path(node).resolve()}
        execution_hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in execution_paths.items()}
        payload = {'root': str(selected_root), 'root_module_file': root_module_file,
                   'candidates': candidates, 'compilerOptions': options.get('compilerOptions', {}),
                   'files': [{'path': p, 'text': tree.files[p].decode('utf-8')} for p in bindings]}
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': '/nonexistent',
               'LANG': 'C.UTF-8', 'NODE_OPTIONS': ''}
        result = subprocess.run([node, str(helper), str(library)], input=json.dumps(payload).encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, env=env)
        if result.returncode:
            raise ValueError('COMPILER_PROJECTION_FAILED')
        if any(hashlib.sha256(path.read_bytes()).hexdigest() != execution_hashes[name]
               for name, path in execution_paths.items()):
            raise ValueError('COMPILER_EXECUTION_INPUT_DRIFT')
        facts = fixture_contracts.strict_json(result.stdout)
        if facts.get('schema') != 'InlineNestHarnessCompilerFacts/v1' or facts.get('compiler_version') != package.get('version'):
            raise ValueError('COMPILER_OUTPUT_MISMATCH')
        output['compiler'] = {'version': package['version'], 'sha256': execution_hashes['compiler'],
                              'package_sha256': execution_hashes['package'],
                              'helper_sha256': execution_hashes['helper'],
                              'node_sha256': execution_hashes['node']}
        identity_inputs = []
        for member in facts['identity_inputs']:
            path = Path(member['file'])
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != member['sha256']:
                raise ValueError('COMPILER_IDENTITY_INPUT_MISMATCH')
            identity_inputs.append({'path': str(path), 'sha256': member['sha256']})
        output['compiler']['identity_inputs'] = identity_inputs
        dependencies = sorted(set(facts['reached_sources']) | set(candidates) | {root_module_file, config})
        for path in dependencies:
            if path not in bindings:
                raise ValueError('COMPILER_DEPENDENCY_UNBOUND')
        dependency_bindings = [bindings[p] for p in dependencies]
        for controller in facts['controllers']:
            if controller['path'] not in candidates or controller['path'] not in bindings:
                raise ValueError('COMPILER_CONTROLLER_UNBOUND')
            fixture_contracts.exact_keys(controller, {'path', 'class_name', 'span', 'scope', 'reason_codes',
                'production_reachable', 'test_module_registration', 'route_spans'}, 'COMPILER_CONTROLLER_SHAPE')
            if controller['scope'] not in ('fixture', 'production', 'unknown'):
                raise ValueError('COMPILER_SCOPE_INVALID')
            controller['compiler_binding'] = {k: output['compiler'][k] for k in
                ('version', 'sha256', 'package_sha256', 'helper_sha256')}
            controller['compiler_binding']['declaration_inputs'] = sorted(
                ({'path': x['path'].split('/node_modules/', 1)[-1], 'sha256': x['sha256']} for x in identity_inputs),
                key=lambda x: x['path'])
            controller['root_binding'] = output['root_binding']
            controller['options_binding'] = output['options_binding']
            controller['source_binding'] = bindings[controller['path']]
            controller['physical_dependencies'] = dependencies
            controller['dependency_bindings'] = dependency_bindings
            output['controllers'].append(controller)
        output['limitations'].extend(facts['production_unknown'])
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError, KeyError, TypeError):
        output['controllers'] = []
        output['limitations'].append('INLINE_HARNESS_PROJECTION_UNRESOLVED')
    return output


def controller_at(projection, path, offset):
    """Only an exact compiler route decorator span can qualify the regex site."""
    return next((c for c in projection.get('controllers', []) if c['path'] == path and
                 any(s['start_utf8'] <= offset < s['end_utf8'] for s in c['route_spans'])), None)


def graph_identity(controller):
    """Portable source identity, not a trusted verdict; the verifier recomputes it."""
    return {k: controller[k] for k in ('class_name', 'span', 'source_binding', 'test_module_registration',
                                      'compiler_binding', 'root_binding', 'options_binding')}


def dependency_map(projection):
    return {c['path'] + '#' + c['class_name']: set(c['physical_dependencies'])
            for c in projection.get('controllers', [])}
