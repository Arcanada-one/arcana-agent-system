"""Consume committed full-suite CI records, authenticated again against GitHub.

No workflow dispatch, suite execution, token lookup, generic URL, or cache-only trust.
The profile's explicit full_test remains the declaration; evidence never declares it.
"""
import hashlib
import json
import re
import shlex
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import PurePosixPath

import canary_evidence

SCHEMA = "GitHubFullSuiteEvidence/v1"
MAX_BYTES = 16 * 1024 * 1024
PERSONAL_DEP = "crates/disk-personal"
PERSONAL_CMD = ["python3", "../../scripts/full-test-group.py", "disk-personal"]
# Exact independently qualified source707 workflow body. Inert data, never executed.
PERSONAL_WRAPPER = r'''set -euo pipefail
source scripts/ci-ensure-cc.sh
PERSONAL_CARGO_BIN="$(rustup which --toolchain 1.97.1 cargo)"
PERSONAL_RUSTC_BIN="$(rustup which --toolchain 1.97.1 rustc)"
PATH="$(dirname "$PERSONAL_CARGO_BIN"):$PATH"
export PERSONAL_CARGO_BIN PERSONAL_RUSTC_BIN PATH
export CARGO_TARGET_DIR="$RUNNER_TEMP/personal-provider-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
# A fresh capability observation; failure preserves the environment gap.
python3 - <<'PYPROBE'
import ctypes, json, os, platform, sys
if sys.platform != "linux" or platform.machine() not in ("x86_64", "aarch64"):
    raise SystemExit("required supported Linux openat2 ABI unavailable")
class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
libc = ctypes.CDLL(None, use_errno=True)
root = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
how = OpenHow(os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0, 0x0d)
try:
    ctypes.set_errno(0)
    fd = libc.syscall(437, root, b".", ctypes.byref(how), ctypes.sizeof(how))
    error = ctypes.get_errno()
    print(json.dumps({"probe": "read-only openat2", "resolve": 13, "errno": error, "success": fd >= 0}), flush=True)
    if fd < 0:
        raise SystemExit(127)
    os.close(fd)
finally:
    os.close(root)
PYPROBE
bash scripts/test-personal-provider.sh
# Execute the declared group itself. Historical foundation CI is not
# full-group evidence. Preserve the profile's 1800-second deadline.
command -v timeout
python3 --version
git rev-parse HEAD
sha256sum scripts/full-test-group.py .arcana/verify.json Cargo.lock
set +e
(
  cd crates/disk-personal
  timeout --signal=TERM --kill-after=10s 1800s python3 ../../scripts/full-test-group.py disk-personal
)
personal_full_exit=$?
set -e
printf 'PERSONAL_FULL_PROCESS_EXIT=%s\n' "$personal_full_exit"
exit "$personal_full_exit"
'''


def github(endpoint):
    cli = shutil.which("gh")
    if not cli:
        raise ValueError("authenticated GitHub CLI unavailable")
    p = subprocess.run([cli, "api", "--hostname", "github.com", endpoint],
                       capture_output=True, timeout=60)
    if p.returncode:
        raise ValueError("authenticated GitHub evidence read refused or unavailable")
    if len(p.stdout) > MAX_BYTES:
        raise ValueError("GitHub evidence exceeds bounded size")
    return p.stdout


def _git(repo, *args):
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=10)
    if p.returncode:
        raise ValueError("committed CI evidence Git binding unavailable")
    return p.stdout


def _blob(repo, head, path):
    q = PurePosixPath(path)
    if (not isinstance(path, str) or q.is_absolute() or ".." in q.parts
            or not path.startswith("receipts/graph/") or q.suffix not in (".json", ".log", ".txt")):
        raise ValueError("CI evidence must be an inert repository-relative graph record")
    entry = _git(repo, "ls-tree", "-z", head, "--", path).split(b"\t", 1)[0]
    if not entry.startswith(b"100644 blob "):
        raise ValueError("CI evidence must be a committed non-executable regular blob")
    raw = _git(repo, "show", head + ":" + path)
    if len(raw) > MAX_BYTES:
        raise ValueError("committed evidence exceeds bounded size")
    return raw


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def workflow_step(raw, job_key, step_name, command, *, deployable=".", timeout=None,
                  workspace_packages=None):
    """Inspect YAML representation only; no constructors, expressions or shell execution."""
    import yaml
    for token in yaml.scan(raw.decode()):
        if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken,
                              yaml.tokens.TagToken, yaml.tokens.DirectiveToken)):
            raise ValueError("workflow aliases/tags/directives unsupported")
    doc = yaml.load(raw, Loader=yaml.BaseLoader)
    job = doc["jobs"][job_key]
    if job.get("uses") or job.get("continue-on-error") not in (None, "false") or job.get("strategy"):
        raise ValueError("reusable/matrix/tolerated job not supported by full-suite importer")
    matches = [s for s in job["steps"] if s.get("name") == step_name]
    if len(matches) != 1:
        raise ValueError("full-suite step is absent or ambiguous")
    step = matches[0]
    if (step.get("if") or step.get("uses") or step.get("continue-on-error") not in (None, "false")
            or step.get("working-directory") or job.get("defaults") or doc.get("defaults")):
        raise ValueError("conditional/tolerated/relocated full-suite step not supported")
    if step.get("shell") not in (None, "bash"):
        raise ValueError("full-suite step shell unsupported")
    if deployable != ".":
        # pnpm's exact package selector runs the declared package's entire test
        # script from a root workflow. It is not a shell cd or a test-file filter.
        # The caller supplies identities read from this measured Git source,
        # never from the evidence record or the live worktree.
        if (workspace_packages is not None and deployable in workspace_packages
                and command == ["pnpm", "--filter", workspace_packages[deployable], "test"]):
            _literal_command(step, command)
            return {**job, "full_binding": "pnpm_workspace_test/v1",
                    "execution_cwd": ".", "test_cwd": deployable}
        # One maintained, reviewed wrapper; never interpret caller-supplied shell.
        # Exact bytes bind setup, subshell cwd, TERM/kill deadline, captured status
        # and final status propagation. No generic multiline/script admission.
        if (deployable != PERSONAL_DEP or command != PERSONAL_CMD or timeout != 1800
                or step.get("run") != PERSONAL_WRAPPER):
            raise ValueError("nested FULL requires the exact personal cwd/1800-second wrapper")
        return {**job, "full_binding": "persist_personal_wrapper/v1"}
    _literal_command(step, command)
    return {**job, "full_binding": "literal_argv/v1"}


def _literal_command(step, command):
    if shlex.split(step.get("run", "")) != command:
        raise ValueError("workflow step is not exactly the declared full_test argv")
    if "\n" in step.get("run", "").strip() or any(x in step.get("run", "") for x in ("${{", ";", "&&", "||", "|", ">", "$", "`")):
        raise ValueError("full-suite step must be one literal unfiltered command")


def workspace_test_packages(repo, source, dep, command):
    """Bounded literal workspace membership and unique package identity at source."""
    if (len(command) != 4 or command[:2] != ["pnpm", "--filter"] or command[3] != "test"
            or not re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", command[2])):
        raise ValueError("nested workspace FULL requires one exact package test selector")
    import yaml
    raw = _git(repo, "show", source + ":pnpm-workspace.yaml").decode()
    for token in yaml.scan(raw):
        if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken,
                              yaml.tokens.TagToken, yaml.tokens.DirectiveToken)):
            raise ValueError("workspace aliases/tags/directives unsupported")
    doc = yaml.load(raw, Loader=yaml.BaseLoader)
    members = doc.get("packages") if isinstance(doc, dict) else None
    if (not isinstance(members, list) or not members or len(members) > 256
            or any(not isinstance(p, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*", p)
                   for p in members) or len(set(members)) != len(members) or dep not in members):
        raise ValueError("nested FULL requires unique literal committed workspace paths")
    packages = {}
    for path in members:
        package_path = path + "/package.json"
        entry = _git(repo, "ls-tree", source, "--", package_path).split(b"\t", 1)[0]
        if not entry.startswith(b"100644 blob "):
            raise ValueError("workspace package must be a committed regular JSON blob")
        package = json.loads(_git(repo, "show", source + ":" + package_path))
        if not isinstance(package, dict):
            raise ValueError("workspace package must be a JSON object")
        name = package.get("name")
        if not isinstance(name, str) or name in packages.values():
            raise ValueError("workspace package identity absent or ambiguous")
        packages[path] = name
        if path == dep:
            scripts = package.get("scripts")
            if not isinstance(scripts, dict) or not isinstance(scripts.get("test"), str) or not scripts["test"].strip():
                raise ValueError("workspace package has no declared test script")
    if packages[dep] != command[2]:
        raise ValueError("package selector differs from the declared deployable identity")
    return packages


def consume(repo, head, repository, dep, command, evidence_path, *, read_api=None):
    """Only production callers use the authenticated adapter; tests inject an explicit fixture."""
    api = github if read_api is None else read_api
    result = {"schema": "FullSuiteCIConsumption/v1", "evidence": evidence_path,
              "head": head, "deployable": dep, "verdict": "not_measured", "errors": []}
    try:
        doc = json.loads(_blob(repo, head, evidence_path))
        if doc.get("schema") != SCHEMA or doc.get("scope") != "global_fallback_full_suite":
            raise ValueError("not a declared full-suite CI evidence record")
        if doc.get("repository") != repository or not re.fullmatch(r"[\w.-]+/[\w.-]+", repository):
            raise ValueError("CI evidence repository differs from authentic receiving origin")
        if doc.get("deployable") != dep or doc.get("command") != command:
            raise ValueError("CI evidence differs from declared deployable/full_test")
        measured = doc["source_commit"]
        checkout = doc["checkout_commit"]
        if not all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{40}", x) for x in (measured, checkout)):
            raise ValueError("CI source/checkout must be exact Git OIDs")
        delta_errors = canary_evidence.record_delta_errors(repo, measured, head)
        if delta_errors:
            raise ValueError("CI source is not current code: " + "; ".join(delta_errors))
        profile = json.loads(_git(repo, "show", head + ":.arcana/verify.json"))
        declared = profile.get("deployables", {}).get(dep, {})
        if declared.get("full_test") != command:
            raise ValueError("explicit full_test declaration is not committed at receiving head")
        run_id, job_id, attempt = doc["run_id"], doc["job_id"], doc["run_attempt"]
        if any(type(x) is not int or x <= 0 for x in (run_id, job_id, attempt)):
            raise ValueError("CI run/job/attempt must be positive integer identities")
        prefix = "repos/" + repository
        run = json.loads(api(f"{prefix}/actions/runs/{run_id}"))
        job = json.loads(api(f"{prefix}/actions/jobs/{job_id}"))
        if (run.get("id") != run_id or run.get("head_sha") != measured
                or run.get("repository", {}).get("full_name") != repository
                or run.get("head_repository", {}).get("full_name") != repository
                or run.get("run_attempt") != attempt or job.get("id") != job_id or job.get("run_id") != run_id
                or job.get("run_attempt") != attempt or run.get("path") != doc["workflow"]
                or run.get("status") != "completed" or job.get("status") != "completed"):
            raise ValueError("authenticated CI identity/attempt/source/completion mismatch")
        # A completed failure is a genuine failure, never evidence that can lift FULL.
        if run.get("conclusion") != "success" or job.get("conclusion") != "success":
            result["verdict"] = "failed"
            raise ValueError("authenticated complete CI run/job failed")
        workflow = _git(repo, "show", measured + ":" + doc["workflow"])
        packages = (workspace_test_packages(repo, measured, dep, command)
                    if dep != "." and command[:2] == ["pnpm", "--filter"] else None)
        definition = workflow_step(workflow, doc["job_key"], doc["step"], command,
                                   deployable=dep, timeout=declared.get("full_test_timeout_seconds", 900),
                                   workspace_packages=packages)
        if job.get("name") != definition.get("name", doc["job_key"]):
            raise ValueError("authenticated job does not match declared workflow job")
        steps = [s for s in job.get("steps", []) if s.get("name") == doc["step"]]
        if len(steps) != 1 or steps[0].get("status") != "completed" or steps[0].get("conclusion") != "success":
            raise ValueError("full-suite step skipped/failed/incomplete/ambiguous")
        step = steps[0]
        start = datetime.fromisoformat(step["started_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(step["completed_at"].replace("Z", "+00:00"))
        if end <= start:
            raise ValueError("full-suite duration is unmeasured")
        for oid in (measured, checkout):
            commit = json.loads(api(f"{prefix}/git/commits/{oid}"))
            if commit.get("sha") != oid:
                raise ValueError("authenticated Git commit identity mismatch")
            result.setdefault("trees", {})[oid] = commit["tree"]["sha"]
        local_tree = _git(repo, "rev-parse", measured + "^{tree}").decode().strip()
        if set(result["trees"].values()) != {local_tree}:
            raise ValueError("actual checkout tree differs from measured source tree")
        log = api(f"{prefix}/actions/jobs/{job_id}/logs")
        local_log = _blob(repo, head, doc["log"]["path"])
        if _digest(log) != doc["log"]["sha256"] or local_log != log:
            raise ValueError("committed log differs from authenticated job log bytes")
        lines = log.decode("utf-8", errors="strict").splitlines()
        checkout_seen = []
        for i, line in enumerate(lines[:-1]):
            if "[command]" in line and "git log -1 --format=%H" in line:
                checkout_seen += re.findall(r"\b[0-9a-f]{40}\b", lines[i + 1])
        if checkout_seen != [checkout]:
            raise ValueError("actual checkout Git identity missing or ambiguous in authenticated log")
        output = []
        # Actions step timestamps have second precision; job log timestamps have
        # fractional seconds. Include the final second bucket for this exact
        # wrapper, whose output is further bounded by both commands and exit.
        log_end = (end + timedelta(seconds=1)
                   if definition.get("full_binding") == "persist_personal_wrapper/v1" else end)
        for line in lines:
            stamp, sep, text = line.partition(" ")
            if not sep:
                continue
            try:
                when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except ValueError:
                continue
            if start <= when < log_end or (when == end and log_end == end):
                output.append(re.sub(r"\x1b\[[0-9;]*m", "", text))
        text = "\n".join(output)
        if definition.get("full_binding") == "persist_personal_wrapper/v1":
            text = personal_full_output(repo, measured, text)
        if not re.search(r"(?:\b[1-9]\d* passed\b|\b[1-9]\d* passing\b|# pass [1-9]\d*|Ran [1-9]\d* tests?\b)", text):
            raise ValueError("full-suite step has no measured non-skipped tests")
        counted = re.findall(r"Ran (\d+) tests?", text)
        skipped = re.findall(r"OK \(skipped=(\d+)\)", text)
        if (counted and skipped and not re.search(r"\b[1-9]\d* passed\b|# pass [1-9]\d*", text)
                and sum(map(int, skipped)) >= sum(map(int, counted))):
            raise ValueError("full-suite step only measured skipped tests")
        if definition.get("full_binding") in ("literal_argv/v1", "pnpm_workspace_test/v1") and shlex.join(command) not in text:
            raise ValueError("authenticated step log lacks the exact declared command")
        result.update(verdict="verified", source_commit=measured, checkout_commit=checkout,
                      run_id=run_id, job_id=job_id, run_attempt=attempt, duration_s=(end-start).total_seconds(),
                      log_sha256=_digest(log), workflow_sha256=_digest(workflow),
                      cwd=dep, workflow_binding=definition.get("full_binding", "literal_argv/v1"),
                      execution_cwd=definition.get("execution_cwd", dep),
                      output=text, measurement="authenticated complete declared CI full suite; no local replay")
    except (ValueError, KeyError, TypeError, OSError, ImportError, subprocess.SubprocessError) as ex:
        result["errors"].append(str(ex))
    return result


def personal_full_output(repo, source, text):
    """Bind actual group output, excluding earlier foundation and echoed shell."""
    lines = text.splitlines()
    for path in ("scripts/full-test-group.py", ".arcana/verify.json", "Cargo.lock"):
        expected = hashlib.sha256(_git(repo, "show", source + ":" + path)).hexdigest() + "  " + path
        if lines.count(expected) != 1:
            raise ValueError("personal FULL source hash output missing or ambiguous: " + path)
    modes = ["+ cargo test -p disk-personal --locked " + flags + " -- --include-ignored"
             for flags in ("--no-default-features", "--all-features")]
    marker = "PERSONAL_FULL_PROCESS_EXIT=0"
    if (any(lines.count(mode) != 1 for mode in modes) or lines.count(marker) != 1
            or [line for line in lines if line.startswith("PERSONAL_FULL_PROCESS_EXIT=")] != [marker]):
        raise ValueError("personal FULL both feature modes/actual exit missing or ambiguous")
    first, second, end = (lines.index(modes[0]), lines.index(modes[1]), lines.index(marker))
    if not first < second < end:
        raise ValueError("personal FULL feature modes/exit are out of order")
    for segment in (lines[first:second], lines[second:end]):
        counts = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                            r"\d+ measured; (\d+) filtered out;", "\n".join(segment), re.MULTILINE)
        if (not counts or not sum(int(row[0]) for row in counts)
                or any(any(int(n) for n in row[1:]) for row in counts)):
            raise ValueError("personal FULL feature mode has no positive complete unfiltered inventory")
    return "\n".join(lines[first:end + 1])


def receipt_errors(repo, head, repository, rows):
    """Admission reauthenticates an imported VERIFIED row; author JSON is not CI authority."""
    errors = []
    for row in rows:
        if row.get("measurement_origin") != "authenticated_github_ci":
            continue
        if not any(v == "verified" for v in row.get("entity_verdicts", {}).values()):
            continue
        paths = row.get("ci_evidence", [])
        if (row.get("scope") != "global_fallback_full_suite" or row.get("kind") != "targeted_test"
                or len(paths) != 1 or row.get("exit_code") != 0):
            errors.append("FULL_CI_EVIDENCE_UNVERIFIABLE: invalid imported full-suite row")
            continue
        try:
            doc = json.loads(_blob(repo, head, paths[0]))
            proof = consume(repo, head, repository, doc["deployable"], doc["command"], paths[0])
            if proof["verdict"] != "verified" or proof.get("source_commit") != row.get("ci_source_commit"):
                errors.append("FULL_CI_EVIDENCE_UNVERIFIABLE: " + "; ".join(proof.get("errors", [])))
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
            errors.append("FULL_CI_EVIDENCE_UNVERIFIABLE: committed imported evidence missing")
    return errors
