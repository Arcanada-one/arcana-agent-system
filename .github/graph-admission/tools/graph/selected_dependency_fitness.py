"""Native foreign architecture fitness; no serialized verdict or KC authority.

The native owner supplies exact allowed sources and independently qualified engine
pins. The existing builder and fitness rules run on complete immutable Git bytes.
Unsupported rule coverage remains unknown even when the measured rules pass.
"""
from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path, PurePosixPath
import subprocess
import sys

import selected_dependency as sd

RULES = frozenset({'fr01', 'fr02', 'fr03', 'fr04', 'fr05'})
ROOT = Path(__file__).resolve().parent


def engine_pins():
    """Read bindings for native qualification, never qualify them on an author's behalf."""
    files = {p.relative_to(ROOT).as_posix(): p for p in ROOT.glob('*.py')}
    files['verifier-matrix.v1.json'] = ROOT.parents[1] / 'contracts/graph-verified-change/verifier-matrix.v1.json'
    files['runtime/python'] = Path(sys.executable).resolve()
    files['runtime/git'] = Path('/usr/bin/git')
    # YAML changes the canonical graph; bind the actual parser, including C extension.
    import yaml
    files.update({'runtime/yaml/' + p.relative_to(Path(yaml.__file__).parent).as_posix(): p
                  for p in Path(yaml.__file__).parent.rglob('*')
                  if p.is_file() and p.suffix in {'.py', '.so'}})
    return {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(files.items())}


class _ReadOnlyStore(sd.GitObjectStore):
    def git(self, *args, input=None):
        env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_NO_REPLACE_OBJECTS': '1',
               'GIT_NO_LAZY_FETCH': '1', 'GIT_ALLOW_PROTOCOL': '',
               'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0'}
        return subprocess.run(['/usr/bin/git', '--no-replace-objects', '-C', str(self.path),
                               '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                               '-c', 'protocol.allow=never', *args], input=input, env=env,
                              check=True, capture_output=True, timeout=30).stdout


def _snapshot(store, identity):
    """Complete bounded object read; no checkout, hooks, fetch or source execution."""
    import build_graph
    entries = []
    for row in filter(None, store.git('ls-tree', '-rz', identity['commit']).split(b'\0')):
        metadata, raw_path = row.split(b'\t', 1)
        mode, kind, oid = metadata.decode('ascii').split()
        path = raw_path.decode('utf-8')
        if (mode not in {'100644', '100755'} or kind != 'blob' or path.startswith('/')
                or '\\' in path or any(p in {'', '.', '..'} for p in path.split('/'))
                or str(PurePosixPath(path)) != path):
            raise ValueError('unsupported tree entry')
        entries.append((path, mode, oid))
    if not entries or len(entries) > 10000:
        raise ValueError('unsupported tree size')
    request = b''.join(oid.encode() + b'\n' for _, _, oid in entries)
    sizes = store.git('cat-file', '--batch-check', input=request).splitlines()
    if len(sizes) != len(entries):
        raise ValueError('incomplete object inventory')
    sizes_out = []
    for (_, _, oid), row in zip(entries, sizes):
        actual, kind, size = row.decode('ascii').split()
        if actual != oid or kind != 'blob' or not 0 <= int(size) <= 8 * 1024 * 1024:
            raise ValueError('unsupported object')
        sizes_out.append(int(size))
    if sum(sizes_out) > 64 * 1024 * 1024:
        raise ValueError('tree exceeds bound')
    raw = store.git('cat-file', '--batch', input=request)
    files, modes, offset = {}, {}, 0
    for (path, mode, oid), size in zip(entries, sizes_out):
        end = raw.index(b'\n', offset)
        if raw[offset:end] != f'{oid} blob {size}'.encode():
            raise ValueError('object binding differs')
        offset = end + 1
        files[path] = raw[offset:offset + size]
        if len(files[path]) != size or raw[offset + size:offset + size + 1] != b'\n':
            raise ValueError('incomplete object bytes')
        offset += size + 1
        modes[path] = mode
    if offset != len(raw):
        raise ValueError('extra object bytes')
    return build_graph.Tree(files, {'source_repo': identity['repository'],
        'source_commit': identity['commit'], 'source_tree': 'git-objects', 'dirty': False,
        'file_modes': modes, 'subdir': None, 'rev': identity['commit']})


@dataclasses.dataclass(frozen=True)
class FitnessMeasurement:
    verdict: str
    reasons: tuple[str, ...]
    rule_outcomes: tuple[tuple[str, str], ...] = ()
    graph_digest: str | None = None
    evidence_digest: str | None = None


class CanonicalForeignFitness:
    """A process-local capability; an envelope cannot create or configure it.

    Fixed FR01–05, no baselines/exemptions/disabled rules. This dispatch does not
    extend canonical Python cycle coverage, type checking or boundary canaries.
    """
    def __init__(self, *, allowed_sources, required_engine_pins):
        sources = list(allowed_sources)
        if not all(sd._identity_supported(source) for source in sources):
            raise ValueError('native source allowlist is invalid')
        self._allowed = frozenset(sd.digest(source) for source in sources)
        self._pins = dict(required_engine_pins) if required_engine_pins is not None else None

    def measure(self, identity, *, repositories):
        if not sd._identity_supported(identity) or sd.digest(identity) not in self._allowed:
            return FitnessMeasurement('not_measured', ('SOURCE_NOT_AUTHORIZED',))
        if not self._pins:
            return FitnessMeasurement('not_measured', ('ENGINE_NOT_QUALIFIED',))
        try:
            if engine_pins() != self._pins:
                return FitnessMeasurement('failed', ('ENGINE_BINDING_MISMATCH',))
            configured = repositories.get(identity['repository'])
            if type(configured) is not sd.GitObjectStore:
                return FitnessMeasurement('not_measured', ('SOURCE_STORE_UNAVAILABLE',))
            store = _ReadOnlyStore(configured.path)
            actual, _ = store.inspect(identity)
            if actual != identity:
                return FitnessMeasurement('failed', ('SOURCE_BINDING_MISMATCH',))
            tree = _snapshot(store, identity)
            import build_graph, verify
            graph = build_graph.Builder(tree, set(), build_graph.DEFAULT_WORK_ITEM_PATTERN).build(build_graph.FIXED_BUILT_AT)
            local = 'code_unit:' + identity['path']
            if not any(n['id'] == local for n in graph['nodes']):
                return FitnessMeasurement('not_measured', ('SOURCE_NOT_A_CODE_UNIT',))
            scan = verify.TreeScan(tree)
            violations = [v for v in verify.fitness_violations(graph, tree, scan, set(RULES))
                          if v['entity'] == local]
            outcomes = {rule: 'verified' for rule in RULES}
            # FR01/FR03's patterns, FR02's cycle walk and FR04's reuse-marker
            # extraction are TS/JS. FR05 needs a source deployable boundary.
            # No violations on an unsupported language is not measured coverage.
            deployables = {n['path'].rstrip('/'): n for n in graph['nodes']
                           if n['type'] == 'deployable_unit' and n.get('path')}
            if identity['path'] not in scan.ts:
                for rule in ('fr01', 'fr02', 'fr03', 'fr04'):
                    outcomes[rule] = 'not_measured'
            elif not verify.deployable_of(identity['path'], deployables):
                outcomes['fr02'] = 'not_measured'
            if not verify.deployable_of(identity['path'], deployables):
                outcomes['fr05'] = 'not_measured'
            if graph['manifest']['stats']['unresolved_relative_imports'] or graph['manifest']['stats']['dropped_dangling_edges']:
                outcomes = {rule: 'not_measured' for rule in RULES}
            for violation in violations:
                outcomes[violation['rule'].lower().replace('-', '')] = 'failed'
            if engine_pins() != self._pins:
                return FitnessMeasurement('failed', ('ENGINE_BINDING_CHANGED',))
            verdict = ('failed' if 'failed' in outcomes.values() else
                       'not_measured' if 'not_measured' in outcomes.values() else 'verified')
            reasons = tuple(sorted({v['rule'] for v in violations})) or (
                ('CANONICAL_FITNESS_COVERAGE_INCOMPLETE',) if verdict == 'not_measured' else ('CANONICAL_FITNESS_VERIFIED',))
            evidence = {'identity': identity, 'engine_pins': self._pins, 'rules': outcomes,
                        'graph_digest': graph['manifest']['graph_digest'], 'violations': violations}
            return FitnessMeasurement(verdict, reasons, tuple(sorted(outcomes.items())),
                                      graph['manifest']['graph_digest'], sd.digest(evidence))
        except (OSError, ValueError, KeyError, ImportError, subprocess.SubprocessError):
            return FitnessMeasurement('not_measured', ('CANONICAL_FITNESS_INPUT_UNAVAILABLE',))
