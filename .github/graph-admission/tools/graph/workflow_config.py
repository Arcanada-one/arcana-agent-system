"""Bounded workflow configuration shape check; no hosted/expression/shell validation.

PyYAML is optional at verification time only. Graph construction stays stdlib-only.
No YAML constructors run: inspect the representation tree using BaseLoader.
"""
import re


class OutOfScope(Exception):
    """Valid GitHub syntax this bounded checker deliberately does not cover.

    Reporting that as `failed` claims the workflow is malformed when the truth is
    that nothing was measured about it — and under DEC-AUP-0008 not_measured is a
    third verdict, never to be collapsed into pass or fail. Malformed YAML and
    shapes GitHub itself rejects stay `failed`.

    Job-level `uses:`, `services`, `strategy` and a `runs-on` label array were in
    this class until they were measured for SHAPE (not interpreted); the triggers
    outside `events` still are.

    `workflow_dispatch.inputs` was in NEITHER class and should have been in one:
    it was reported `failed`, which claimed 41 workflows in 19 repos are malformed
    when GitHub accepts every one of them. It is now measured for shape (A2-233).
    """


def is_workflow(path):
    return bool(re.fullmatch(r'\.github/workflows/[^/]+\.ya?ml', path))


def validate(raw):
    try:
        import yaml
    except ImportError:
        return 'not_measured', 'PyYAML unavailable; workflow configuration not measured'
    try:
        text = raw.decode('utf-8')
        if len(raw) > 1024 * 1024:
            raise ValueError('workflow exceeds supported 1 MiB limit')
        for token in yaml.scan(text):
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken,
                                  yaml.tokens.TagToken, yaml.tokens.DirectiveToken)):
                raise ValueError('aliases, anchors, tags and directives are unsupported')
        node = yaml.compose(text, Loader=yaml.BaseLoader)
        def convert(n, depth=0):
            if depth > 40:
                raise ValueError('YAML nesting exceeds supported depth')
            if isinstance(n, yaml.ScalarNode):
                return n.value
            if isinstance(n, yaml.SequenceNode):
                return [convert(v, depth + 1) for v in n.value]
            if isinstance(n, yaml.MappingNode):
                out = {}
                for k, v in n.value:
                    if not isinstance(k, yaml.ScalarNode) or not k.value or k.value == '<<' or k.value in out:
                        raise ValueError('duplicate, merge or non-scalar mapping key')
                    out[k.value] = convert(v, depth + 1)
                return out
            raise ValueError('empty or unsupported YAML node')
        doc = convert(node)
        def mapping(value, allowed=None):
            if not isinstance(value, dict):
                raise ValueError('expected mapping')
            if allowed is not None and set(value) - set(allowed.split()):
                raise ValueError('unsupported fields: ' + ', '.join(sorted(set(value) - set(allowed.split()))))
        def scalar(value):
            if not isinstance(value, str):
                raise ValueError('expected scalar')
        def scalar_map(value):
            mapping(value)
            for v in value.values():
                scalar(v)
        def string_list(value):
            if not isinstance(value, list) or not value or any(not isinstance(v, str) or not v for v in value):
                raise ValueError('expected nonempty scalar list')
        def common(value):
            for key in ('name', 'run-name', 'if', 'timeout-minutes', 'continue-on-error'):
                if key in value:
                    scalar(value[key])
            for key in ('env', 'outputs'):
                if key in value:
                    scalar_map(value[key])
            if 'permissions' in value:
                perm = value['permissions']
                if isinstance(perm, str):
                    if perm not in ('read-all', 'write-all'):
                        raise ValueError('unsupported permissions scalar')
                else:
                    scalar_map(perm)
                    if any(v not in ('read', 'write', 'none') for v in perm.values()):
                        raise ValueError('unsupported permission level')
            if 'concurrency' in value:
                c = value['concurrency']
                if not isinstance(c, str):
                    mapping(c, 'group cancel-in-progress')
                    if not c.get('group'):
                        raise ValueError('concurrency group required')
                    scalar_map(c)
            if 'defaults' in value:
                mapping(value['defaults'], 'run')
                for defaults in value['defaults'].values():
                    mapping(defaults, 'shell working-directory')
                    scalar_map(defaults)
        mapping(doc, 'name run-name on permissions env defaults concurrency jobs')
        common(doc)
        if not doc.get('on') or not isinstance(doc['on'], (str, list, dict)):
            raise ValueError('nonempty on declaration required')
        trigger = doc['on']
        events = {'push', 'pull_request', 'workflow_dispatch', 'workflow_run'}
        names = [trigger] if isinstance(trigger, str) else trigger
        if isinstance(trigger, list):
            string_list(trigger)
        github_events = events | {
            'workflow_call', 'schedule', 'release', 'issues', 'issue_comment',
            'pull_request_target', 'pull_request_review', 'pull_request_review_comment',
            'create', 'delete', 'fork', 'gollum', 'label', 'milestone', 'page_build',
            'project', 'project_card', 'project_column', 'public', 'registry_package',
            'repository_dispatch', 'status', 'watch', 'check_run', 'check_suite',
            'deployment', 'deployment_status', 'discussion', 'discussion_comment',
            'merge_group', 'branch_protection_rule',
        }
        if any(not isinstance(k, str) or k not in events for k in names):
            unknown = [k for k in names if not isinstance(k, str) or k not in github_events]
            if unknown:
                raise ValueError('unsupported trigger; supported: push, pull_request, workflow_dispatch, workflow_run')
            raise OutOfScope('trigger outside this bounded checker: '
                             + ', '.join(k for k in names if k not in events))
        if 'workflow_run' in names and not isinstance(trigger, dict):
            raise ValueError('workflow_run requires explicit workflows configuration')
        if isinstance(trigger, dict):
            for event, cfg in trigger.items():
                if event == 'workflow_run':
                    mapping(cfg, 'workflows types branches branches-ignore')
                    string_list(cfg.get('workflows'))
                    for filters in cfg.values():
                        string_list(filters)
                    if set(cfg.get('types', [])) - {'completed', 'requested', 'in_progress'}:
                        raise ValueError('unsupported workflow_run activity type')
                    if 'branches' in cfg and 'branches-ignore' in cfg:
                        raise ValueError('workflow_run branch filters are mutually exclusive')
                    continue
                if cfg == '':
                    continue
                if event == 'workflow_dispatch':
                    # `inputs:` is ordinary GitHub syntax, and the allowed-key set was empty, so every
                    # workflow that declares one was reported `failed` — "malformed workflow" about 41
                    # workflows in 19 repos that GitHub itself accepts (A2-227). That is exactly the
                    # collapse `OutOfScope` above exists to prevent, in the other direction: a shape
                    # this checker had simply never been taught. It is taught here rather than excused,
                    # because the shape IS bounded — the same way a reusable job's `with:` block is.
                    # What the values MEAN (expressions, defaults at dispatch time) stays NOT_MEASURED.
                    mapping(cfg, 'inputs')
                    if 'inputs' in cfg:
                        mapping(cfg['inputs'])
                        for input_id, spec in cfg['inputs'].items():
                            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', input_id):
                                raise ValueError('unsupported workflow_dispatch input id')
                            mapping(spec, 'description default required type options')
                            for key in ('description', 'default', 'required', 'type'):
                                if key in spec:
                                    scalar(spec[key])
                            if spec.get('type') == 'choice':
                                string_list(spec.get('options'))
                            elif 'options' in spec:
                                raise ValueError('workflow_dispatch options require type: choice')
                    continue
                mapping(cfg, 'branches branches-ignore tags tags-ignore paths paths-ignore types')
                for filters in cfg.values():
                    string_list(filters)
        jobs = doc.get('jobs')
        mapping(jobs)
        if not jobs:
            raise ValueError('at least one job required')
        for name, job in jobs.items():
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', name):
                raise ValueError('unsupported job id')
            # A job is one of two shapes, and conflating them is what made this checker report
            # not_measured for every caller that uses either. `uses:` at job level calls another
            # workflow: it has no `runs-on` and no `steps` — the called workflow supplies both.
            reusable = 'uses' in job
            if reusable:
                mapping(job, 'name needs if permissions concurrency uses with secrets')
                scalar(job['uses'])
                if 'with' in job:
                    mapping(job['with'])
                    for v in job['with'].values():
                        if not isinstance(v, str):
                            raise ValueError('reusable-workflow input must be a scalar')
                if 'secrets' in job and not isinstance(job['secrets'], (str, dict)):
                    raise ValueError('unsupported secrets shape')
            else:
                # MEASURED 2026-09-19. `environment:` made every change to a
                # workflow using it REFUSED — reproduced on the already-merged
                # b4aadf23, so the file could not be edited at all. It is
                # ordinary GitHub syntax that this bounded checker does not
                # cover, which is exactly what OutOfScope is for: reporting it
                # as `failed` claims the workflow is malformed when the truth
                # is that nothing was measured about the deployment
                # environment, its protection rules or its reviewers.
                #
                # It is raised OutOfScope rather than added to the allowed set,
                # because allowing it would report `verified` — a claim that
                # the field was checked, when nothing about it is.
                if 'environment' in job:
                    raise OutOfScope('job-level `environment` outside this bounded checker')
                mapping(job, 'name needs if runs-on permissions env defaults concurrency outputs '
                             'steps timeout-minutes continue-on-error services strategy')
            common(job)
            if 'needs' in job:
                if isinstance(job['needs'], list):
                    string_list(job['needs'])
                else:
                    scalar(job['needs'])
            if reusable:
                continue
            # `runs-on: [self-hosted, linux, ci-general]` is ordinary GitHub syntax for a label
            # set. Declaring it out of scope made the WHOLE file not_measured for every caller on
            # self-hosted runners — and not_measured is never a pass, so those callers could not be
            # measured at all. A label set is a nonempty list of nonempty strings and nothing else,
            # which is the check `needs` already uses.
            runs_on = job.get('runs-on')
            if isinstance(runs_on, list):
                string_list(runs_on)
                # BaseLoader makes every scalar a str, so `[self-hosted, 5]` arrives as ['self-hosted',
                # '5'] and a type check alone accepts it. Measured while counter-checking this very
                # change: that mutation passed as `verified`. A runner label is not a number.
                for label in runs_on:
                    if re.fullmatch(r'[+-]?[0-9]+(\.[0-9]+)?', label):
                        raise ValueError(f'runs-on label is a number, not a label: {label!r}')
            elif not isinstance(runs_on, str) or not runs_on:
                raise ValueError('literal/scalar runs-on or a label array required')
            # `services` and `strategy` are validated for SHAPE, never interpreted: a service is a
            # named image with optional env/ports/options, a strategy is a matrix with optional
            # fail-fast. Accepting the shape is what lets the rest of the file be measured; the
            # container itself is still nothing this checker reasons about.
            for svc in (job.get('services') or {}).values() if isinstance(job.get('services'), dict) else []:
                mapping(svc, 'image credentials env ports volumes options')
                scalar(svc.get('image', ''))
            if 'strategy' in job:
                mapping(job['strategy'], 'matrix fail-fast max-parallel')
            steps = job.get('steps')
            if not isinstance(steps, list) or not steps:
                raise ValueError('nonempty steps required')
            for step in steps:
                mapping(step, 'id name if uses run with env shell working-directory timeout-minutes continue-on-error')
                common(step)
                for field in ('id', 'shell', 'working-directory'):
                    if field in step:
                        scalar(step[field])
                if ('run' in step) == ('uses' in step):
                    raise ValueError('exactly one run or uses required')
                key = 'run' if 'run' in step else 'uses'
                if not isinstance(step[key], str) or not step[key].strip():
                    raise ValueError('nonempty scalar run/uses required')
                if key == 'run' and 'with' in step:
                    raise ValueError('with on run is unsupported')
                if key == 'uses' and ('shell' in step or 'working-directory' in step):
                    raise ValueError('shell/working-directory on uses is unsupported')
                for field in ('env', 'with'):
                    if field in step:
                        mapping(step[field])
                        if any(not isinstance(v, str) for v in step[field].values()):
                            raise ValueError('env/with values must be scalars')
        return 'verified', 'bounded workflow configuration shape valid; expressions, shell, actions and hosted execution NOT_MEASURED'
    except OutOfScope as ex:
        return 'not_measured', 'workflow configuration not measured: ' + str(ex)
    except (ValueError, UnicodeError, yaml.YAMLError, RecursionError) as ex:
        return 'failed', 'unsupported/malformed workflow configuration: ' + str(ex)
