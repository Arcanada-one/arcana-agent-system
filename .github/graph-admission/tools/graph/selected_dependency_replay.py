"""Bounded KC loader replay in a cold, network-free, read-only sandbox.

This is a reviewed native capability, not an envelope-selected entrypoint. The
configured policy pins entire input trees and the runner bytes independently.
Unsupported consumers/hosts fail closed to an unavailable measurement.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import resource
import subprocess
import tempfile

from selected_dependency import NativeContradiction, NativeLoadMeasurement

RUNNER = Path(__file__).with_name('selected_dependency_runner.py')


def _bounded_child():
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class ArganaNativeReplay:
    """Native-only configuration: allowlisted repo/commit/tree tuples + runner SHA.

    This constructor is never called from envelope fields. Main/manifest/key
    possession does not put a tuple on this allowlist or authorize execution.
    """
    def __init__(self, *, allowed_trees, runner_sha256, interpreter=Path('/usr/bin/python3'),
                 sandbox=Path('/usr/bin/bwrap')):
        self.allowed_trees = frozenset(allowed_trees)
        self.runner_sha256 = runner_sha256
        self.interpreter = interpreter
        self.sandbox = sandbox

    @staticmethod
    def materialize(store, identity, target):
        rows = store.git('ls-tree', '-r', '-z', identity['commit']).split(b'\0')
        total = 0
        for row in filter(None, rows):
            metadata, rawpath = row.split(b'\t', 1)
            mode, kind, oid = metadata.decode().split()
            path = rawpath.decode('utf-8')
            if (mode not in {'100644', '100755'} or kind != 'blob' or path.startswith('/')
                    or '\\' in path or any(p in {'', '.', '..'} for p in path.split('/'))):
                raise ValueError('unsupported tree entry in native replay')
            size = int(store.git('cat-file', '-s', oid))
            total += size
            if size > 8 * 1024 * 1024 or total > 64 * 1024 * 1024:
                raise ValueError('replay tree exceeds bounded input size')
            dest = target / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(store.git('cat-file', 'blob', oid))
            dest.chmod(0o400)

    def __call__(self, envelope, *, repositories):
        from selected_dependency import digest
        c, p = envelope['consumer'], envelope['provider']
        if c['path'] != 'src/argana/kc2.py':
            raise ValueError('native entrypoint unsupported')
        if any((x['repository'], x['commit'], x['tree_oid']) !=
               (p['repository'], p['commit'], p['tree_oid']) for x in envelope['transitive_inputs']):
            raise ValueError('native transitive input roots unsupported')
        for identity in [c, p, *envelope['transitive_inputs']]:
            key = (identity['repository'], identity['commit'], identity['tree_oid'])
            if key not in self.allowed_trees:
                raise ValueError('input tree lacks independently configured replay authority')
        if hashlib.sha256(RUNNER.read_bytes()).hexdigest() != self.runner_sha256:
            raise ValueError('native runner differs from reviewed bytes')
        module = envelope['occurrence']['module']
        if module not in {'kc2_defs', 'kc2_store'}:
            raise ValueError('native module observation unsupported')
        # The subprocess has no host /home, /etc, /proc, environment, credentials,
        # writable source, host network or caller-selected executable/argv.
        with tempfile.TemporaryDirectory(prefix='selected-native-replay-') as directory:
            root = Path(directory)
            self.materialize(repositories[c['repository']], c, root / 'consumer')
            self.materialize(repositories[p['repository']], p, root / 'provider')
            runner = root / 'runner.py'
            runner.write_bytes(RUNNER.read_bytes())
            command = [str(self.sandbox), '--unshare-all', '--die-with-parent',
                       '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
                       '--ro-bind', '/lib64', '/lib64', '--dev', '/dev', '--tmpfs', '/tmp',
                       '--ro-bind', str(root), '/input', '--clearenv',
                       '--setenv', 'PATH', '/usr/bin:/bin', '--chdir', '/input',
                       str(self.interpreter), '-I', '-S', '/input/runner.py',
                       p['commit'], json.dumps(envelope['occurrence'], sort_keys=True)]
            completed = subprocess.run(command, capture_output=True, check=True, timeout=60,
                                       preexec_fn=_bounded_child)
            if len(completed.stdout) > 1024 * 1024:
                raise ValueError('native output exceeds bounded record size')
            measured = json.loads(completed.stdout)
        if measured['consumer_sha256'] != c['sha256'] or measured['provider_sha256'] != p['sha256']:
            raise NativeContradiction('materialized native sources differ')
        if measured['provider_path'] != p['path'] or measured['occurrence'] != envelope['occurrence']:
            raise NativeContradiction('native provider/occurrence differs')
        observed = {(x['path'], x['sha256']) for x in measured['transitive_inputs']}
        declared = {(x['path'], x['sha256']) for x in envelope['transitive_inputs']}
        if observed != declared:
            raise NativeContradiction('transitive native source census differs')
        return NativeLoadMeasurement(digest(envelope), p, measured['interpreter'], measured['loader'],
                                     tuple(measured['search_path']), measured['cache_empty'],
                                     tuple(envelope['transitive_inputs']), self.runner_sha256, measured['import_observation'])
