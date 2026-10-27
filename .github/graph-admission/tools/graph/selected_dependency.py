"""DEC0146: source-bound selected imports; no fetching or author-code execution.

Repositories and replay are supplied by the native verifier, never by an envelope.
An independently configured replay hook is the measurement boundary. This module
checks its complete binding; declarations and serialized verdicts are not evidence.
Qualification is source selection only, not semantic, runtime or KC admission.
"""
from __future__ import annotations

import dataclasses
import copy
import contextlib
import contextvars
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from urllib.parse import quote

import python_search_path

IDENTITY = frozenset({'repository', 'commit', 'tree_oid', 'path', 'mode', 'blob_oid', 'sha256'})
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
LIMITATIONS = ('Source selection only; semantic verification, installed runtime and KC authority remain separate.',)


class NativeContradiction(ValueError):
    """A measured contradiction from the independently configured replay hook."""


_native_configuration = contextvars.ContextVar('selected_dependency_native_configuration', default=None)


@contextlib.contextmanager
def native_configuration(*, selections, repositories, replay=None, foreign_fitness=None):
    """Process-local native configuration, never decoded from a receipt verdict.

    Selection keys are (canonical subject repository, full subject commit).
    The context supplies independent Git stores and the reviewed replay capability
    to issuance AND recheck; nothing changes when no context is configured.
    """
    if foreign_fitness is not None:
        from selected_dependency_fitness import CanonicalForeignFitness
        if type(foreign_fitness) is not CanonicalForeignFitness:
            raise TypeError('foreign fitness requires the native canonical capability')
    configured = {'selections': copy.deepcopy(selections), 'repositories': dict(repositories),
                  'replay': replay, 'foreign_fitness': foreign_fitness}
    token = _native_configuration.set(configured)
    try:
        yield
    finally:
        _native_configuration.reset(token)


def current_native_configuration():
    return _native_configuration.get()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


@dataclasses.dataclass(frozen=True)
class GitObjectStore:
    """Independently configured local Git store; the envelope cannot supply this path."""
    path: Path

    def git(self, *args):
        return subprocess.run(['git', '--no-replace-objects', '-C', str(self.path), *args],
                              check=True, capture_output=True, timeout=30).stdout

    def inspect(self, identity):
        commit, path = identity['commit'], identity['path']
        if self.git('cat-file', '-t', commit).strip() != b'commit':
            raise ValueError('selection is not a commit')
        tree = self.git('rev-parse', commit + '^{tree}').decode().strip()
        # Literal pathspec, so a declaration cannot reinterpret Git path grammar.
        rows = self.git('ls-tree', '-z', commit, '--', ':(literal)' + path).split(b'\0')
        rows = [r for r in rows if r]
        if len(rows) != 1:
            raise ValueError('selected path is absent or ambiguous')
        metadata, found = rows[0].split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        if found.decode() != path or mode not in {'100644', '100755'} or kind != 'blob':
            raise ValueError('selected source is not a regular Git blob')
        size = int(self.git('cat-file', '-s', oid))
        if size > 4 * 1024 * 1024:
            raise OverflowError('source exceeds bounded qualification size')
        raw = self.git('cat-file', 'blob', oid)
        actual = dict(identity, tree_oid=tree, mode=mode, blob_oid=oid,
                      sha256=hashlib.sha256(raw).hexdigest())
        return actual, raw


@dataclasses.dataclass(frozen=True)
class NativeLoadMeasurement:
    """Native hook output, not a JSON receipt accepted from an author.

    The hook observes a SourceFileLoader in its reviewed isolated replay and
    canonicalizes loaded origins against independently materialized Git inputs.
    All transitive inputs must be declared in the requested selection.
    """
    binding_digest: str
    provider: dict
    interpreter: dict
    loader: str
    search_path: tuple[str, ...]
    cache_empty: bool
    transitive_inputs: tuple[dict, ...]
    tool_sha256: str
    import_observation: dict | None = None


@dataclasses.dataclass(frozen=True)
class QualificationResult:
    verdict: str
    reason_codes: tuple[str, ...]
    consumer: dict | None
    provider: dict | None
    occurrence: dict | None
    binding_digest: str | None = None
    evidence_digest: str | None = None
    limitations: tuple[str, ...] = LIMITATIONS


def _identity_supported(row):
    if not isinstance(row, dict) or set(row) != IDENTITY:
        return False
    if not all(isinstance(v, str) for v in row.values()):
        return False
    path = row['path']
    return (bool(row['repository']) and '\x00' not in row['repository']
            and bool(HEX40.fullmatch(row['commit']))
            and bool(HEX40.fullmatch(row['tree_oid']))
            and bool(HEX40.fullmatch(row['blob_oid']))
            and bool(HEX64.fullmatch(row['sha256']))
            and row['mode'] in {'100644', '100755'}
            and bool(path) and not path.startswith('/') and '\\' not in path
            and '\x00' not in path and all(p not in {'', '.', '..'} for p in path.split('/'))
            and str(PurePosixPath(path)) == path)


def node_id(identity):
    if not _identity_supported(identity):
        raise ValueError('unsupported selected source identity')
    return 'code_unit:git:' + quote(identity['repository'], safe='') + '@' + identity['commit'] + ':' + quote(identity['path'], safe='')


def selection_key(envelope):
    """Stable source occurrence key across revisions; never a qualification result."""
    c, o = envelope['consumer'], envelope['occurrence']
    return digest({'repository': c['repository'], 'path': c['path'],
                   'occurrence': {k: v for k, v in o.items() if k != 'source_sha256'}})


def qualify_selected_dependency(envelope, *, repositories, replay=None):
    """Validate exact objects and occurrence before asking the native replay hook.

    No string verdict, timestamp, host alias or author-supplied receipt can pass.
    Missing replay/dependency/capability stays unknown; contradictions dominate.
    """
    c = p = o = binding = None

    def result(verdict, code, evidence=None):
        return QualificationResult(verdict, (code,), c, p, o, binding, evidence)

    keys = {'schema', 'consumer', 'provider', 'occurrence', 'transitive_inputs'}
    if not isinstance(envelope, dict) or set(envelope) != keys or envelope.get('schema') != 'SelectedDependencyEnvelope/v1':
        return result('not_measured', 'SELECTED_ENVELOPE_UNSUPPORTED')
    c, p, o = envelope['consumer'], envelope['provider'], envelope['occurrence']
    inputs = envelope['transitive_inputs']
    if not isinstance(inputs, list) or len(inputs) > 128 or not isinstance(o, dict):
        return result('not_measured', 'SELECTED_ENVELOPE_UNSUPPORTED')
    rows = [c, p, *inputs]
    if not all(_identity_supported(row) for row in rows):
        return result('not_measured', 'SELECTED_IDENTITY_UNSUPPORTED')
    binding = digest(envelope)
    missing = False
    consumer_raw = None
    for i, row in enumerate(rows):
        store = repositories.get(row['repository'])
        if not isinstance(store, GitObjectStore):
            missing = True
            continue
        try:
            actual, raw = store.inspect(row)
        except (subprocess.SubprocessError, OSError, OverflowError):
            missing = True
            continue
        except ValueError:
            return result('failed', 'SELECTED_OBJECT_CONTRADICTION')
        if actual != row:
            return result('failed', 'SELECTED_OBJECT_CONTRADICTION')
        if i == 0:
            consumer_raw = raw
    # Check all available evidence even when another repository is unavailable.
    leaf = getattr(python_search_path, 'qualify_import_occurrence', None)
    if consumer_raw is not None and leaf is not None:
        occurrence = leaf(consumer_raw, o)
        if occurrence['status'] == 'contradiction':
            return result('failed', 'SELECTED_OCCURRENCE_CONTRADICTION')
        if occurrence['status'] != 'bound':
            missing = True
    else:
        missing = True
    if missing:
        return result('not_measured', 'SELECTED_INPUT_NOT_MEASURED')
    if replay is None:
        return result('not_measured', 'SELECTED_NATIVE_REPLAY_MISSING')
    # replay is an independently configured native capability. This API does not
    # look it up from envelope data or import/execute the declared source itself.
    try:
        measured = replay(envelope, repositories=repositories)
    except NativeContradiction:
        return result('failed', 'SELECTED_NATIVE_BINDING_CONTRADICTION')
    except Exception:
        return result('not_measured', 'SELECTED_NATIVE_REPLAY_UNAVAILABLE')
    if not isinstance(measured, NativeLoadMeasurement):
        return result('not_measured', 'SELECTED_NATIVE_REPLAY_UNSUPPORTED')
    if measured.binding_digest != binding or measured.provider != p:
        return result('failed', 'SELECTED_NATIVE_BINDING_CONTRADICTION')
    if list(measured.transitive_inputs) != inputs:
        return result('failed', 'SELECTED_NATIVE_INPUTS_CONTRADICTION')
    if (measured.loader != 'SourceFileLoader' or measured.cache_empty is not True
            or not measured.search_path or not all(isinstance(x, str) and x for x in measured.search_path)
            or not isinstance(measured.interpreter, dict)
            or set(measured.interpreter) != {'implementation', 'version', 'executable_sha256'}
            or measured.interpreter.get('implementation') != 'CPython'
            or not isinstance(measured.interpreter.get('version'), str)
            or not isinstance(measured.interpreter.get('executable_sha256'), str)
            or not HEX64.fullmatch(measured.interpreter.get('executable_sha256', ''))
            or not isinstance(measured.tool_sha256, str) or not HEX64.fullmatch(measured.tool_sha256)):
        return result('not_measured', 'SELECTED_NATIVE_CONTEXT_UNSUPPORTED')
    boundary = measured.import_observation
    if (not isinstance(boundary, dict) or set(boundary) != {
            'occurrence', 'opcode', 'provider', 'loader', 'search_path', 'cache_before', 'cache_after'}
            or boundary['occurrence'] != o or boundary['opcode'] != 'IMPORT_NAME'
            or boundary['provider'] != {'path': p['path'], 'sha256': p['sha256']}
            or boundary['loader'] != measured.loader
            or boundary['search_path'] != list(measured.search_path)
            or not isinstance(boundary['cache_before'], dict)
            or not isinstance(boundary['cache_after'], dict)
            or boundary['cache_after'].get(o['module']) != boundary['provider']):
        return result('not_measured', 'SELECTED_NATIVE_OPERATION_UNSUPPORTED')
    return result('verified', 'SELECTED_SOURCE_BOUND', digest(dataclasses.asdict(measured)))


def attach_to_graph(graph, consumer_tree, envelope, *, repositories, replay=None, foreign_consumer=False):
    """Attach only to the independently built consumer at its exact revision.

    Retain unknown/refused qualification on the consumer. Even a qualified
    selection stays an inferred boundary owing the normal canary/semantic checks.
    No host capture path becomes a source node.
    """
    measured = qualify_selected_dependency(envelope, repositories=repositories, replay=replay)
    c = measured.consumer
    if not isinstance(c, dict) or not _identity_supported(c):
        return measured
    local = node_id(c) if foreign_consumer else 'code_unit:' + c['path']
    raw = consumer_tree.files.get(c['path'])
    if (consumer_tree.meta.get('source_repo') != c['repository']
            or consumer_tree.meta.get('source_commit') != c['commit'] or raw is None
            or hashlib.sha256(raw).hexdigest() != c['sha256']
            or (local not in graph.nodes and not foreign_consumer)):
        return dataclasses.replace(measured, verdict='failed',
                                   reason_codes=('SELECTED_CONSUMER_GRAPH_CONTRADICTION',), evidence_digest=None)
    if foreign_consumer and local not in graph.nodes:
        graph.node(local, 'code_unit', 'sha256:' + c['sha256'], attrs={'selected_source_identity': c})
    node = graph.nodes[local]
    if node['content_hash'] != 'sha256:' + c['sha256']:
        return dataclasses.replace(measured, verdict='failed',
                                   reason_codes=('SELECTED_CONSUMER_GRAPH_CONTRADICTION',), evidence_digest=None)
    key = selection_key(envelope)
    facts = node.setdefault('attrs', {}).setdefault('selected_dependencies', {})
    fact = {'envelope': envelope, 'qualification': dataclasses.asdict(measured)}
    if key in facts and facts[key] != fact:
        return dataclasses.replace(measured, verdict='failed',
                                   reason_codes=('SELECTED_OCCURRENCE_SELECTION_CONFLICT',), evidence_digest=None)
    facts[key] = fact
    if measured.verdict != 'verified':
        return measured
    p = measured.provider
    foreign = node_id(p)
    graph.node(foreign, 'code_unit', 'sha256:' + p['sha256'],
               attrs={'selected_source_identity': p, 'selected_binding_digest': measured.binding_digest})
    graph.edge(local, 'imports', foreign, 'inferred',
               inferred_by='native-selected-dependency', boundary='repo',
               via=key, symbol=measured.occurrence['local_name'])
    return measured


def paired_obligations(base_graph, head_graph):
    """Union both source versions on provider, consumer, evidence change/removal.

    Facts are graph output, not a new provider resolver. Their requalification
    remains mandatory; this function selects obligations without verifying them.
    """
    def facts(graph):
        result = {}
        for node in graph['nodes']:
            for key, fact in node.get('attrs', {}).get('selected_dependencies', {}).items():
                result[(node['id'], key)] = fact
        return result

    before, after = facts(base_graph), facts(head_graph)
    selected = {'base': set(), 'head': set()}
    for key in before.keys() | after.keys():
        if before.get(key) == after.get(key):
            continue
        for role, rows in (('base', before), ('head', after)):
            fact = rows.get(key)
            if fact is None:
                continue
            selected[role].add(key[0])
            selected[role].add(node_id(fact['envelope']['provider']))
    return {role: sorted(ids) for role, ids in selected.items()}


def build_selected_graph(repo, *, rev, envelopes, repositories, replay=None, built_at=None):
    """Opt-in native graph view, reusing the existing builder and verifier engine.

    The subject graph remains at its original revision. A foreign consumer and
    selected provider retain their distinct exact identities. This does not edit
    a historical oracle or reinterpret a provider predicate requiring the subject.
    """
    import build_graph
    import schema_check
    doc = build_graph.build(Path(repo), rev=rev, built_at=built_at or build_graph.FIXED_BUILT_AT)
    graph = build_graph.Graph()
    graph.nodes = {n['id']: copy.deepcopy(n) for n in doc['nodes']}
    for edge in doc['edges']:
        graph.edge(edge['from'], edge['type'], edge['to'], edge['provenance'],
                   **{k: copy.deepcopy(v) for k, v in edge.items() if k not in {'from', 'type', 'to', 'provenance'}})
    results = []
    for envelope in envelopes:
        consumer = envelope.get('consumer', {}) if isinstance(envelope, dict) else {}
        if not _identity_supported(consumer):
            raise ValueError('unsupported native graph consumer selection')
        store = repositories.get(consumer['repository'])
        if not isinstance(store, GitObjectStore):
            raise ValueError('native graph consumer store unavailable')
        tree = build_graph.load_tree_git(store.path, consumer['commit'], '')
        # Origin metadata is only a consistency check; the independently configured
        # store and exact object membership establish the source selection.
        if tree.meta['source_repo'] != consumer['repository']:
            raise ValueError('configured consumer repository identity differs')
        result = attach_to_graph(graph, tree, envelope, repositories=repositories,
                                 replay=replay, foreign_consumer=True)
        if result.verdict == 'failed' or node_id(consumer) not in graph.nodes:
            # A rejected attachment must never return the unextended subject as
            # an apparently successful selected view. No partial graph escapes.
            raise NativeContradiction('selected graph attachment contradicts native inputs')
        results.append(result)
    doc['nodes'], doc['edges'] = graph.finalize()
    doc['manifest']['node_count'] = len(doc['nodes'])
    doc['manifest']['edge_count'] = len(doc['edges'])
    doc['manifest']['limitations'].append('DEC0146 selected foreign source view; inferred boundaries retain semantic/canary obligations; no historical oracle or runtime admission')
    doc['manifest']['graph_digest'] = schema_check.graph_digest(doc)
    errors = schema_check.check_graph(doc, schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH))
    if errors:
        raise ValueError('selected source graph is not native schema conformant')
    return doc, results
