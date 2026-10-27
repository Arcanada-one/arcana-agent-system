"""Consume committed full-suite CI records, authenticated again against GitHub.

No workflow dispatch, suite execution, token lookup, generic URL, or cache-only trust.
The profile's explicit full_test remains the declaration; evidence never declares it.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from pathlib import PurePosixPath
from urllib.parse import quote

# The hosted root-typecheck collector runs this file with `python3 -I`; isolated
# mode excludes the script directory from sys.path. Load the sibling from the
# already authenticated graph bundle by exact path, without restoring cwd or
# ambient Python import paths.
_canary_path = Path(__file__).resolve().with_name("canary_evidence.py")
_canary_spec = importlib.util.spec_from_file_location("_graph_canary_evidence", _canary_path)
if _canary_spec is None or _canary_spec.loader is None:
    raise RuntimeError("canary_evidence module cannot be loaded from the graph bundle")
canary_evidence = importlib.util.module_from_spec(_canary_spec)
_canary_spec.loader.exec_module(canary_evidence)

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


def canonical_digest_hex(value):
    """Normalize only full-suite CI's canonical ``sha256:<lowercase hex>`` reference."""
    match = re.fullmatch(r"sha256:([0-9a-f]{64})", value) if isinstance(value, str) else None
    return match.group(1) if match else None


SQLITE_DEP = "crates/disk-personal/sqlite-abi"
SQLITE_CMD = ["python3", "../../../scripts/full-test-group.py", "disk-personal-sqlite"]
SQLITE_WRAPPER = 'set -euo pipefail\nsource scripts/ci-ensure-cc.sh\nSQLITE_CARGO_BIN="$(rustup which --toolchain 1.97.1 cargo)"\nSQLITE_RUSTC_BIN="$(rustup which --toolchain 1.97.1 rustc)"\nPATH="$(dirname "$SQLITE_CARGO_BIN"):$PATH"\nexport SQLITE_CARGO_BIN SQLITE_RUSTC_BIN PATH\nexport CARGO_TARGET_DIR="$RUNNER_TEMP/sqlite-abi-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"\nevidence_dir="$(mktemp -d "$RUNNER_TEMP/sqlite-full.XXXXXX")"\ngit rev-parse HEAD\n"$SQLITE_CARGO_BIN" --version\n"$SQLITE_RUSTC_BIN" --version\npython3 -B scripts/ci-sqlite-full-evidence.py inventory --input "$evidence_dir/input.json"\nset +e\n(\n  cd crates/disk-personal/sqlite-abi\n  timeout --signal=TERM --kill-after=10s 1800s python3 ../../../scripts/full-test-group.py disk-personal-sqlite\n) > "$evidence_dir/full.log" 2>&1\nsqlite_full_exit=$?\nset -e\ncat "$evidence_dir/full.log"\nprintf \'SQLITE_FULL_PROCESS_EXIT=%s\\n\' "$sqlite_full_exit"\nif [[ "$sqlite_full_exit" -ne 0 ]]; then\n  exit "$sqlite_full_exit"\nfi\npython3 -B scripts/ci-sqlite-full-evidence.py verify --input "$evidence_dir/input.json" --log "$evidence_dir/full.log" --out "$evidence_dir/result.json"\nprintf \'SQLITE_FULL_INVENTORY_EXIT=0\\n\'\n'

# Exact reviewed current PERSIST source6dfa composition. Inert data only.
PERSONAL_CONDITIONAL_JOB = json.loads('{"env":{"CARGO_BUILD_JOBS":"2"},"name":"Personal provider foundation (Rust 1.97.1)","runs-on":["arcana-dbs-ci"],"steps":[{"uses":"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1","with":{"persist-credentials":"false","ref":"${{ github.event.pull_request.head.sha || github.sha }}"}},{"id":"selector","name":"Select exact prior personal job or cold execution","run":"python3 -B scripts/ci-personal-job-reuse.py select"},{"id":"guard","if":"always()","name":"Observe current personal confinement capability","run":"python3 -B scripts/ci-personal-job-reuse.py guard"},{"id":"isolate","if":"steps.selector.outputs.mode == \'execute\'","name":"Isolate Rust state for this job","run":"python3 scripts/ci-isolate-rust.py prepare"},{"id":"toolchain","if":"steps.selector.outputs.mode == \'execute\'","uses":"dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4","with":{"components":"rustfmt, clippy","toolchain":"1.97.1"}},{"id":"resolution","if":"steps.selector.outputs.mode == \'execute\'","name":"Verify isolated Rust resolution","run":"python3 scripts/ci-isolate-rust.py verify 1.97.1"},{"id":"execute","if":"steps.selector.outputs.mode == \'execute\'","name":"Verify the synthetic foundation and production refusal","run":"set -euo pipefail\\nsource scripts/ci-ensure-cc.sh\\nPERSONAL_CARGO_BIN=\\"$(rustup which --toolchain 1.97.1 cargo)\\"\\nPERSONAL_RUSTC_BIN=\\"$(rustup which --toolchain 1.97.1 rustc)\\"\\nPATH=\\"$(dirname \\"$PERSONAL_CARGO_BIN\\"):$PATH\\"\\nexport PERSONAL_CARGO_BIN PERSONAL_RUSTC_BIN PATH\\nexport CARGO_TARGET_DIR=\\"$RUNNER_TEMP/personal-provider-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT\\"\\nbash scripts/test-personal-provider.sh\\n# Execute the declared group itself. Historical foundation CI is not\\n# full-group evidence. Preserve the profile\'s 1800-second deadline.\\ncommand -v timeout\\npython3 --version\\ngit rev-parse HEAD\\nsha256sum scripts/full-test-group.py .arcana/verify.json Cargo.lock\\nset +e\\n(\\n  cd crates/disk-personal\\n  timeout --signal=TERM --kill-after=10s 1800s python3 ../../scripts/full-test-group.py disk-personal\\n) > \\"$PERSONAL_REUSE_DIR/full.log\\" 2>&1\\npersonal_full_exit=$?\\nprintf \'%s\\\\n\' \\"$personal_full_exit\\" > \\"$PERSONAL_REUSE_DIR/suite-exit.txt\\"\\nset -e\\ncat \\"$PERSONAL_REUSE_DIR/full.log\\"\\nprintf \'PERSONAL_FULL_PROCESS_EXIT=%s\\\\n\' \\"$personal_full_exit\\"\\nexit \\"$personal_full_exit\\"\\n"},{"id":"reuse","if":"steps.selector.outputs.mode == \'reuse\'","name":"Verify exact receiving record without rerunning prior tests","run":"python3 -B scripts/ci-personal-job-reuse.py verify"},{"env":{"PERSONAL_REUSE_STEPS_JSON":"${{ toJSON(steps) }}"},"id":"receiving_verdict","if":"always()","name":"Require actual execution or verified receiving status","run":"python3 -B scripts/ci-personal-job-reuse.py record"},{"if":"always()","name":"Retain personal receiving decision and execution manifest","uses":"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a","with":{"if-no-files-found":"error","name":"personal-job-reuse-${{ github.run_id }}-${{ github.run_attempt }}","path":"${{ env.PERSONAL_REUSE_DIR }}/","retention-days":"14"}}],"timeout-minutes":"55"}')
PERSONAL_HELPER_SHA256 = "13bd21d607c43b64aebc843d1bcd6f6efc624f1a6b6af0aee04689ed1ef135d4"
PERSONAL_INPUTS_SHA256 = "ea03151948e96d1806050dfc49611ac785c67b8d40598f2cf735008b813010c2"
PERSONAL_GROUP_SHA256 = "6cae9880060042206f917dee00d8dc351f32e8fc6ecbc55cce3e78733fbbe437"

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
    if (job_key == "personal-provider" and deployable == PERSONAL_DEP
            and command == PERSONAL_CMD and timeout == 1800
            and step_name == "Require actual execution or verified receiving status"
            and job == PERSONAL_CONDITIONAL_JOB
            and not doc.get("defaults")):
        return {**job, "full_binding": "persist_personal_conditional/v1"}
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
        if deployable == SQLITE_DEP and command == SQLITE_CMD and timeout == 1800 and step.get("run") == SQLITE_WRAPPER:
            return {**job, "full_binding": "persist_sqlite_wrapper/v1"}
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
    raw = step.get("run", "").strip()
    if shlex.split(raw) != command:
        raise ValueError("workflow step is not exactly the declared full_test argv")
    # GitHub expressions expand before the shell, including inside quotes.
    # Inner bash -c payloads remain literal arguments to the outer shell.
    if any(x in raw for x in ("${{", "\n", "\r")) or not command or "=" in command[0]:
        raise ValueError("full-suite step must be one literal unfiltered command")
    if command[0] in {"if", "then", "else", "elif", "fi", "for", "while", "until",
                       "do", "done", "case", "esac", "in", "select", "function", "time", "coproc"}:
        raise ValueError("full-suite step must invoke a literal command")
    quote = None
    for char in raw:
        if quote == "'":
            if char == "'":
                quote = None
        elif quote == '"':
            if char == '"':
                quote = None
            elif char in "$`\\":
                raise ValueError("full-suite double-quoted argument must be literal")
        elif char in "'\"":
            quote = char
        elif not (char.isascii() and (char.isalnum() or char in "_./:=,@%+- \t")):
            # Refuse expansion, redirection, pipelines, background jobs, comments
            # and escapes. This bounded grammar never executes or interprets them.
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


def consume(repo, head, repository, dep, command, evidence_path, *, read_api=None, _depth=0):
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
        if end < start or (end == start and definition.get("full_binding") != "persist_personal_conditional/v1"):
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
        if definition.get("full_binding") == "persist_personal_conditional/v1":
            branch = personal_conditional(repo, head, doc, job, workflow, lines, api, result, _depth)
            result.update(branch, log_sha256=_digest(log), workflow_sha256=_digest(workflow),
                          cwd=dep, execution_cwd=dep, workflow_binding=definition["full_binding"])
            return result
        output = []
        # Actions step timestamps have second precision; job log timestamps have
        # fractional seconds. Include the final second bucket for this exact
        # wrapper, whose output is further bounded by both commands and exit.
        log_end = (end + timedelta(seconds=1)
                   if definition.get("full_binding") in ("persist_personal_wrapper/v1", "persist_sqlite_wrapper/v1") else end)
        for line in lines:
            stamp, sep, text = line.partition(" ")
            if not sep:
                continue
            try:
                when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except ValueError:
                continue
            if start <= when < log_end or (when == end and log_end == end):
                output.append(text)
        if definition.get("full_binding") in ("literal_argv/v1", "pnpm_workspace_test/v1"):
            output = literal_step_output(lines, job, step, command, start, end, output)
        text = "\n".join(output)
        if definition.get("full_binding") == "persist_sqlite_wrapper/v1":
            text = sqlite_full_output(repo, measured, text, repository, run_id, attempt, doc["job_key"])
        text = re.sub(r"\x1b\[[0-9;]*m", "", text)
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
    except (ValueError, KeyError, TypeError, OSError, ImportError, zipfile.BadZipFile, subprocess.SubprocessError) as ex:
        result["errors"].append(str(ex))
    return result



def personal_tracked_closure(repo, source):
    """Same byte/mode/OID inventory as the qualified caller; no exclusions."""
    raw = _git(repo, "ls-tree", "-r", "-z", "--full-tree", source)
    rows = []
    for row in raw.split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            raise ValueError("personal tracked closure contains symlink/submodule/unknown mode")
        rows.append((path, metadata + b"\t" + path + b"\0"))
    if not rows or len({p for p, _ in rows}) != len(rows):
        raise ValueError("personal tracked closure empty or ambiguous")
    objects = b"".join(row.split(b"\t", 1)[0].split()[2] + b"\n" for _, row in rows)
    checked = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch-check"],
                             input=objects, capture_output=True, timeout=15)
    if checked.returncode or len(checked.stdout.splitlines()) != len(rows) or b" missing" in checked.stdout:
        raise ValueError("personal tracked closure contains missing Git objects")
    inventory = b"".join(row for _, row in sorted(rows))
    return {"sha256": hashlib.sha256(inventory).hexdigest(), "count": len(rows),
            "bytes": len(inventory), "encoding": "sorted NUL(path bytes, mode, Git blob OID); all tracked files",
            "excluded_paths": []}


def personal_artifact(repo, head, doc, api):
    """Authenticate one fixed archive and compare committed manifest bytes, no extraction."""
    import io
    import zipfile
    declared = doc["personal_job"]
    identity = declared["artifact_id"]
    if type(identity) is not int or identity <= 0:
        raise ValueError("personal artifact ID unknown")
    prefix = "repos/" + doc["repository"]
    response = json.loads(api(f"{prefix}/actions/runs/{doc['run_id']}/artifacts?per_page=100"))
    if response.get("total_count", 101) > 100:
        raise ValueError("personal artifact inventory exceeds bounded page")
    name = f"personal-job-reuse-{doc['run_id']}-{doc['run_attempt']}"
    matches = [a for a in response["artifacts"] if a.get("name") == name and a.get("expired") is False]
    if len(matches) != 1 or matches[0].get("id") != identity:
        raise ValueError("personal named artifact missing/ambiguous/wrong ID")
    meta = matches[0]
    if (type(meta.get("size_in_bytes")) is not int or not 0 < meta["size_in_bytes"] <= 4*1024*1024
            or meta.get("digest") != declared["artifact_sha256"]):
        raise ValueError("personal artifact digest/size unknown")
    archive = api(f"{prefix}/actions/artifacts/{identity}/zip")
    if len(archive) > 4*1024*1024 or _digest(archive) != meta["digest"]:
        raise ValueError("personal artifact bytes differ from authenticated digest")
    members = {}
    try:
        zipped = zipfile.ZipFile(io.BytesIO(archive))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError("personal artifact is not a valid bounded ZIP") from exc
    with zipped:
        for name in ("manifest.json", "decision.json", "guard.json", "full.log"):
            infos = [i for i in zipped.infolist() if i.filename == name]
            if not infos and name == "full.log":
                continue  # reuse never claims a current execution log
            if (len(infos) != 1 or infos[0].file_size > MAX_BYTES
                    or infos[0].flag_bits & 1 or infos[0].is_dir()):
                raise ValueError("personal artifact member absent/ambiguous/oversized")
            members[name] = zipped.read(infos[0])
    local = _blob(repo, head, declared["manifest"]["path"])
    if _digest(local) != declared["manifest"]["sha256"] or local != members["manifest.json"]:
        raise ValueError("personal committed manifest differs from authenticated archive")
    return {k: json.loads(v) for k, v in members.items() if k.endswith(".json")}, members.get("full.log")


def personal_json_seen(text, expected, *, prefix=""):
    matches = 0
    for line in text.splitlines():
        if prefix and not line.startswith(prefix):
            continue
        try:
            value = json.loads(line[len(prefix):])
        except (ValueError, TypeError):
            continue
        matches += value == expected
    if matches != 1:
        raise ValueError("personal JSON observation missing/ambiguous in authentic step log")


def personal_step_output(lines, step):
    """Use fractional log stamps, preserving the final second and real Run boundaries."""
    start = datetime.fromisoformat(step["started_at"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(step["completed_at"].replace("Z", "+00:00"))
    if end < start:
        raise ValueError("personal step time order unknown")
    rows = []
    for line in lines:
        stamp, _, text = line.partition(" ")
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if start <= when < end + timedelta(seconds=1):
            rows.append(text)
    # Authentication of the exact JSON marker/manifest/full bytes additionally
    # binds observations; a neighboring step's counts are never a FULL proof.
    return "\n".join(rows), (end-start).total_seconds()


def personal_conditional(repo, head, doc, job, workflow, lines, api, result, depth):
    """Complete maintained execute/reuse contract. Unknown input always refuses."""
    if doc["repository"] != "Arcanada-one/disk-arcana":
        raise ValueError("personal composition is qualified only for original caller repository")
    source = doc["source_commit"]
    for path, digest in (("scripts/ci-personal-job-reuse.py", PERSONAL_HELPER_SHA256),
                         ("scripts/ci_personal_inputs.py", PERSONAL_INPUTS_SHA256),
                         ("scripts/full-test-group.py", PERSONAL_GROUP_SHA256)):
        if hashlib.sha256(_git(repo, "show", source + ":" + path)).hexdigest() != digest:
            raise ValueError("personal maintained helper/input/group source generation differs: " + path)
    by_id = {}
    previous = -1
    for declaration in PERSONAL_CONDITIONAL_JOB["steps"]:
        name = declaration.get("name", "Run " + declaration.get("uses", ""))
        candidates = [s for s in job["steps"] if s.get("name") == name]
        if len(candidates) != 1 or candidates[0].get("status") != "completed":
            raise ValueError("personal individual step absent/incomplete/ambiguous: " + name)
        step = candidates[0]
        if type(step.get("number")) is not int or step["number"] <= previous:
            raise ValueError("personal workflow step ordering differs")
        previous = step["number"]
        if step.get("conclusion") in ("failure", "cancelled", "timed_out", "action_required"):
            result["verdict"] = "failed"
            raise ValueError("authenticated personal step failed: " + name)
        by_id[declaration.get("id", name)] = step
    for key in ("Run actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "selector", "guard", "receiving_verdict", "Retain personal receiving decision and execution manifest"):
        if by_id[key].get("conclusion") != "success":
            raise ValueError("personal required step did not succeed: " + key)
    objects, full_log = personal_artifact(repo, head, doc, api)
    decision, guard, manifest = (objects[k] for k in ("decision.json", "guard.json", "manifest.json"))
    if decision.get("schema") != "PersonalJobReuse/v1" or decision.get("mode") not in ("execute", "reuse"):
        raise ValueError("unknown personal selector branch")
    current = decision["current"]
    closure = personal_tracked_closure(repo, source)
    if (current.get("repository") != doc["repository"] or current.get("head") != source
            or current.get("tree") != result["trees"][source] or current.get("closure") != closure
            or current.get("workflow_sha256") != hashlib.sha256(workflow).hexdigest()
            or current.get("receiver_policy_sha256") != PERSONAL_HELPER_SHA256
            or current.get("declared_argv") != PERSONAL_CMD or current.get("cwd") != PERSONAL_DEP
            or current.get("features") != ["--no-default-features", "--all-features"]
            or current.get("timeout_seconds") != 1800):
        raise ValueError("personal source/tree/full closure/workflow/helper/profile binding differs")
    if (guard.get("schema") != "PersonalCurrentCapability/v1" or guard.get("head") != source
            or guard.get("run_id") != str(doc["run_id"]) or guard.get("attempt") != str(doc["run_attempt"])
            or guard.get("job") != "personal-provider" or guard.get("system") != "Linux"
            or guard.get("machine") not in ("x86_64", "aarch64") or guard.get("syscall") != 437
            or type(guard.get("syscall")) is not int or type(guard.get("resolve")) is not int
            or guard.get("resolve") != 13 or type(guard.get("errno")) is not int
            or guard.get("errno") != 0 or guard.get("success") is not True):
        raise ValueError("personal current openat2 capability absent or differently bound")
    if not isinstance(decision.get("reason"), str):
        raise ValueError("personal selector reason is missing or not a string")
    # Exact helper select emits only mode/reason; whole decision stays in the
    # authenticated artifact and its current source/input fields are checked above.
    selector_output = {"mode": decision["mode"], "reason": decision["reason"]}
    for key, value in (("selector", selector_output), ("guard", guard)):
        text, _ = personal_step_output(lines, by_id[key])
        personal_json_seen(text, value)
    executed = ("isolate", "toolchain", "resolution", "execute")
    before = current.get("tool_environment_binding")
    final_text, _ = personal_step_output(lines, by_id["receiving_verdict"])
    if decision["mode"] == "execute":
        if any(by_id[k].get("conclusion") != "success" for k in executed) or by_id["reuse"].get("conclusion") != "skipped":
            raise ValueError("personal cold execution incomplete or wrong branch outcomes")
        if (manifest.get("schema") != "PersonalJobExecution/v1" or manifest.get("tests_executed_now") is not True
                or type(manifest.get("suite_exit")) is not int or manifest.get("suite_exit") != 0
                or manifest.get("current_steps_success") is not True
                or manifest.get("current_capability_observation") != guard):
            raise ValueError("personal cold manifest does not prove actual successful execution")
        for key in ("repository", "head", "tree", "closure", "workflow_sha256", "receiver_policy_sha256",
                    "declared_argv", "cwd", "features", "timeout_seconds"):
            if manifest.get(key) != current.get(key):
                raise ValueError("personal cold manifest current binding differs: " + key)
        identity = manifest.get("prior_identity")
        if identity != {"source_commit": source, "checkout_commit": doc["checkout_commit"],
                        "run_id": doc["run_id"], "run_attempt": doc["run_attempt"], "job_id": None}:
            raise ValueError("personal cold manifest has unauthenticated job identity")
        personal_json_seen(final_text, manifest, prefix="PERSONAL_JOB_EXECUTION_MANIFEST=")
        text, duration = personal_step_output(lines, by_id["execute"])
        if full_log is None or manifest.get("full_log_sha256") != hashlib.sha256(full_log).hexdigest():
            raise ValueError("personal cold raw full log digest missing/mismatched")
        if full_log.decode("utf-8").strip() not in text:
            raise ValueError("personal full log is not output of authenticated execute step")
        cleaned = re.sub(r"\x1b\[[0-9;]*m", "", text)
        if any(int(n) > 0 for n in re.findall(r"test result: (?:ok|FAILED)\. \d+ passed; (\d+) failed;", cleaned)):
            result["verdict"] = "failed"
            raise ValueError("authenticated personal FULL inventory observed failed tests")
        output = personal_full_output(repo, source, cleaned)
        if not 0 < duration <= 1800:
            raise ValueError("personal cold FULL duration unknown or exceeds original deadline")
        result.update(tests_executed_now=True, executed_inventory_validated=True)
        if not isinstance(before, dict) or before.get("complete") is not True:
            raise ValueError("personal required current tool/environment inputs incomplete; real cold execution cannot lift FULL")
        after = manifest.get("tool_environment_binding")
        eq = manifest.get("input_equivalence", {})
        digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if (manifest.get("before_tool_environment_binding") != before or after != before
                or eq.get("schema") != "PersonalExecutionInputEquivalence/v1"
                or eq.get("complete") is not True or eq.get("equal") is not True
                or eq.get("before_sha256") != digest(before) or eq.get("after_sha256") != digest(after)):
            raise ValueError("personal cold pre/post inputs incomplete or changed; nonreusable and not unqualified FULL")
        return {"verdict": "verified", "source_commit": source, "checkout_commit": doc["checkout_commit"],
                "run_id": doc["run_id"], "job_id": doc["job_id"], "run_attempt": doc["run_attempt"],
                "tests_executed_now": True, "duration_s": duration, "output": output,
                "measurement": "authenticated current cold declared personal FULL; exact complete equal inputs"}
    # A receiver never turns a skipped execution into tests executed now.
    if depth >= 1 or any(by_id[k].get("conclusion") != "skipped" for k in executed) or by_id["reuse"].get("conclusion") != "success":
        raise ValueError("personal reuse chain/wrong branch/setup execution unsupported")
    if (manifest.get("schema") != "PersonalJobReuse/v1" or manifest.get("mode") != "REUSED_PRIOR_COMPLETED_JOB"
            or manifest.get("tests_executed_now") is not False or manifest.get("current_head") != source
            or manifest.get("current_closure_sha256") != closure["sha256"]
            or manifest.get("current_capability_observation") != guard
            or manifest.get("canonical_record_delta_verdict") != "verified"):
        raise ValueError("personal reuse manifest current source/guard/mode differs")
    text, _ = personal_step_output(lines, by_id["reuse"])
    personal_json_seen(text, manifest)
    result["tests_executed_now"] = False
    if not isinstance(before, dict) or before.get("complete") is not True:
        raise ValueError("personal reuse current tool/environment inputs incomplete")
    for key in ("repository", "workflow_sha256", "declared_argv", "cwd", "features", "receiver_policy_sha256"):
        if manifest.get(key) != current.get(key):
            raise ValueError("personal receiving current declaration differs: " + key)
    personal_json_seen(final_text, {"mode": "REUSED_PRIOR_COMPLETED_JOB", "tests_executed_now": False,
                                   "receiving_checks": "success"})
    prior = decision["prior"]
    prior_manifest = decision["manifest"]
    if prior_manifest.get("schema") != "PersonalJobExecution/v1" or prior_manifest.get("tests_executed_now") is not True:
        raise ValueError("personal reuse has no actual cold prior execution manifest")
    for key in ("repository", "closure", "tool_environment_binding", "receiver_policy_sha256",
                "workflow_sha256", "declared_argv", "cwd", "features", "timeout_seconds"):
        if prior_manifest.get(key) != current.get(key):
            raise ValueError("personal prior/current complete inputs differ: " + key)
    if prior_manifest.get("tool_environment_binding", {}).get("complete") is not True:
        raise ValueError("personal prior inputs incomplete")
    prior_path = doc["personal_job"]["prior_evidence_path"]
    committed_prior = json.loads(_blob(repo, head, prior_path))
    if prior != committed_prior:
        raise ValueError("personal selector prior record differs from committed prior evidence")
    proof = consume(repo, head, doc["repository"], PERSONAL_DEP, PERSONAL_CMD, prior_path, read_api=api, _depth=depth+1)
    if proof.get("verdict") != "verified" or proof.get("tests_executed_now", True) is not True:
        if proof.get("verdict") == "failed":
            result["verdict"] = "failed"
        raise ValueError("personal prior FULL not independently authenticated: " + "; ".join(proof.get("errors", [])))
    authentic_prior_manifest = json.loads(_blob(repo, head, prior["personal_job"]["manifest"]["path"]))
    if _digest(_blob(repo, head, prior["personal_job"]["manifest"]["path"])) != prior["personal_job"]["manifest"]["sha256"]:
        raise ValueError("personal prior manifest committed digest mismatch")
    # The actual emitted manifest has job_id=None; the prior receiver adds only
    # the numeric job ID returned by authenticated GitHub metadata.
    expected_prior = json.loads(json.dumps(authentic_prior_manifest))
    if expected_prior.get("prior_identity", {}).get("job_id") is not None:
        raise ValueError("personal prior manifest invented its completed job ID")
    expected_prior["prior_identity"]["job_id"] = prior["job_id"]
    if prior_manifest != expected_prior:
        raise ValueError("personal selector prior manifest differs from authenticated cold manifest")
    for key in ("source_commit", "checkout_commit", "run_id", "job_id", "run_attempt"):
        if prior_manifest.get("prior_identity", {}).get(key) != prior.get(key):
            raise ValueError("personal prior manifest numeric identity differs")
        if manifest.get("prior_" + key) != prior.get(key):
            raise ValueError("personal receiving prior identity differs")
    if (manifest.get("prior_log_sha256") != prior["log"]["sha256"]
            or manifest.get("tool_environment_binding") != before
            or manifest.get("receiver_policy_sha256") != current["receiver_policy_sha256"]):
        raise ValueError("personal receiving prior log/policy/environment differs")
    # Never trust decision.canonical as an assertion; prior consume above redoes
    # authentication and canonical source record delta on this actual repository.
    return {"verdict": "verified", "source_commit": source, "checkout_commit": doc["checkout_commit"],
            "run_id": doc["run_id"], "job_id": doc["job_id"], "run_attempt": doc["run_attempt"],
            "tests_executed_now": False, "duration_s": proof["duration_s"], "output": proof["output"],
            "reused_from": {k: proof[k] for k in ("source_commit", "checkout_commit", "run_id", "job_id", "run_attempt", "log_sha256")},
            "measurement": "authenticated REUSED_PRIOR_COMPLETED_JOB; no current suite execution"}


def literal_step_output(lines, job, step, command, start, end, legacy_output):
    """Second-precision API completion needs the exact authenticated Run boundary.

    No boundary means the prior conservative window remains; never borrow a
    subsequent step's counts to lift an empty FULL measurement.
    """
    events = []
    for line in lines:
        stamp, sep, text = line.partition(" ")
        if not sep:
            continue
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        events.append((when, text))
    limit = end + timedelta(seconds=1)
    candidates = []
    for index, (when, text) in enumerate(events):
        if not start <= when < limit or not text.startswith("##[group]Run "):
            continue
        try:
            if shlex.split(text[len("##[group]Run "):]) == command:
                candidates.append(index)
        except ValueError:
            continue
    if not candidates:
        return legacy_output
    if len(candidates) != 1:
        raise ValueError("declared FULL Run boundary is ambiguous")
    begin = candidates[0]
    if events[begin][0] >= end:
        raise ValueError("declared FULL Run boundary starts after completion")
    following = next((i for i in range(begin + 1, len(events))
                      if events[i][1].startswith("##[group]")), len(events))
    actual_steps = job.get("steps", [])
    next_steps = actual_steps[actual_steps.index(step) + 1:]
    adjacent = next((s for s in next_steps if s.get("started_at") and s.get("status") != "skipped"), None)
    if adjacent is not None:
        adjacent_start = datetime.fromisoformat(adjacent["started_at"].replace("Z", "+00:00"))
        if adjacent_start < limit and (following == len(events)
                or not adjacent_start <= events[following][0] < limit):
            raise ValueError("adjacent CI step lacks a bounded output delimiter")
    output = [text for when, text in events[begin:following] if start <= when < limit]
    if not output:
        raise ValueError("declared FULL output is empty")
    return output


def sqlite_full_output(repo, source, text, repository, run_id, attempt, job_key):
    """Read exact SQLite input/inventory/log binding; never execute its helper."""
    lines = text.splitlines()
    def unique(prefix):
        values = [line[len(prefix):] for line in lines if line.startswith(prefix)]
        if len(values) != 1:
            raise ValueError("SQLite FULL missing or ambiguous " + prefix)
        return json.loads(values[0])
    before = unique("SQLITE_FULL_INPUT=")
    after = unique("SQLITE_FULL_INVENTORY=")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("SQLite FULL input/inventory must be objects")
    paths = ["Cargo.toml", "Cargo.lock", ".arcana/verify.json", ".github/workflows/ci.yml",
             "scripts/full-test-group.py", "scripts/ci-ensure-cc.sh",
             "scripts/ci-sqlite-full-evidence.py", "scripts/tests/test_ci_sqlite_full_evidence.py"]
    paths += [SQLITE_DEP + "/" + p for p in ("Cargo.toml", "src/lib.rs", "src/registration.rs", "src/test_vfs.rs")]
    expected = {p: hashlib.sha256(_git(repo, "show", source + ":" + p)).hexdigest() for p in paths}
    if expected["scripts/ci-sqlite-full-evidence.py"] != "18971acc34ed83ebe45ac8e84d14357cc710f1bbac798104477544d66b33066b":
        raise ValueError("SQLite inventory helper is not the reviewed contract")
    declaration = {"full_test": SQLITE_CMD, "full_test_timeout_seconds": 1800}
    tree = _git(repo, "rev-parse", source + "^{tree}").decode().strip()
    if (before.get("schema") != "SQLiteFullInput/v1" or before.get("head") != source
            or before.get("tree") != tree or before.get("cwd") != SQLITE_DEP
            or before.get("declaration") != declaration or before.get("source_sha256") != expected):
        raise ValueError("SQLite FULL source/input/declaration identity differs")
    context = before.get("ci", {})
    if not isinstance(context, dict):
        raise ValueError("SQLite FULL CI context must be an object")
    if (any(context.get(k) != v for k, v in {
            "GITHUB_REPOSITORY": repository, "GITHUB_RUN_ID": str(run_id),
            "GITHUB_RUN_ATTEMPT": str(attempt), "GITHUB_JOB": job_key, "RUNNER_OS": "Linux"}.items())
            or not re.fullmatch(r"[0-9a-f]{40}", context.get("GITHUB_WORKFLOW_SHA", ""))
            or not context.get("GITHUB_WORKFLOW_REF", "").startswith(repository + "/.github/workflows/ci.yml@")):
        raise ValueError("SQLite FULL CI identity differs")
    tests = []
    for rel, prefix in (("src/lib.rs", "tests::"), ("src/registration.rs", "registration::tests::")):
        raw = _git(repo, "show", source + ":" + SQLITE_DEP + "/" + rel).decode()
        names = re.findall(r"#\[test\]\s+fn\s+(\w+)\s*\(", raw)
        if len(names) != raw.count("#[test]") or "#[ignore" in raw:
            raise ValueError("SQLite FULL source test inventory ambiguous or ignored")
        tests += [prefix + name for name in names]
    tests.sort()
    if len(tests) != 7 or len(set(tests)) != 7 or before.get("tests") != tests:
        raise ValueError("SQLite FULL source test inventory differs")
    commands = ["+ cargo test -p disk-personal-sqlite --locked " + mode + " -- --include-ignored"
                for mode in ("--no-default-features", "--all-features")]
    markers = ["SQLITE_FULL_PROCESS_EXIT=0", "SQLITE_FULL_INVENTORY_EXIT=0"]
    if (any(lines.count(item) != 1 for item in commands + markers)
            or any(line.startswith(prefix) and line != good for prefix, good in
                   (("SQLITE_FULL_PROCESS_EXIT=", markers[0]), ("SQLITE_FULL_INVENTORY_EXIT=", markers[1])) for line in lines)):
        raise ValueError("SQLite FULL actual commands/process/inventory exit missing or ambiguous")
    first, second, end = [lines.index(item) for item in commands + markers[:1]]
    if not lines.index(next(x for x in lines if x.startswith("SQLITE_FULL_INPUT="))) < first < second < end < lines.index(next(x for x in lines if x.startswith("SQLITE_FULL_INVENTORY="))) < lines.index(markers[1]):
        raise ValueError("SQLite FULL input/modes/process/inventory order differs")
    raw_log = ("\n".join(lines[first:end]) + "\n").encode()
    if (after.get("schema") != "SQLiteFullOutput/v1" or after.get("input") != before
            or after.get("log_bytes") != len(raw_log) or after.get("log_sha256") != hashlib.sha256(raw_log).hexdigest()):
        raise ValueError("SQLite FULL measured log/input digest differs")
    expected_modes = {}
    for mode, segment in zip(("--no-default-features", "--all-features"), (lines[first:second], lines[second:end])):
        body = re.sub(r"\x1b\[[0-9;]*m", "", "\n".join(segment))
        cases = re.findall(r"^test (\S+) \.\.\. (\S+)(?: .*)?$", body, re.MULTILINE)
        counts = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", body, re.MULTILINE)
        if (sorted(name for name, _ in cases) != tests or any(status != "ok" for _, status in cases)
                or not counts or sum(int(row[0]) for row in counts) != 7
                or any(any(int(n) for n in row[1:]) for row in counts)):
            raise ValueError("SQLite FULL feature mode has incomplete/failed/skipped/filtered inventory")
        expected_modes[mode] = {"passed": 7, "tests": tests}
    if after.get("modes") != expected_modes:
        raise ValueError("SQLite FULL reported inventories differ from measured output")
    return "\n".join(lines[first:end + 1])


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
            if "tests_executed_now" in proof and (row.get("tests_executed_now") is not proof["tests_executed_now"]
                    or row.get("ci_reused_from") != proof.get("reused_from")
                    or row.get("ci_measurement") != proof.get("measurement")):
                errors.append("FULL_CI_EVIDENCE_UNVERIFIABLE: executed/reused provenance projection differs")
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
            errors.append("FULL_CI_EVIDENCE_UNVERIFIABLE: committed imported evidence missing")
    return errors


# A distinct typed input. It never uses the full-suite scope, profile declaration or consumer.
ROOT_TYPECHECK_SCHEMA = "GitHubTypecheckEvidence/v1"
ROOT_TYPECHECK_REPO = "Arcanada-one/auth-arcana"
ROOT_TYPECHECK_WORKFLOW = ".github/workflows/ci.yml"
ROOT_TYPECHECK_JOB = "main-package-tsc"
ROOT_TYPECHECK_JOB_NAME = "Type-check main package"
ROOT_TYPECHECK_COMMAND = ["pnpm", "exec", "tsc", "--noEmit"]
ROOT_TYPECHECK_STEP_COMMANDS = {
    "pnpm install --frozen-lockfile",
    "pnpm exec prisma generate",
    "pnpm exec tsc --noEmit",
}
ROOT_TYPECHECK_INPUTS = (
    "tsconfig.json", "package.json", "pnpm-lock.yaml", ".npmrc", "pnpm-workspace.yaml",
    "prisma/schema.prisma", "prisma.config.ts",
)
ROOT_TYPECHECK_BASE_KEYS = {
    "schema", "scope", "repository", "source_commit", "base", "head", "verdict", "errors",
}
ROOT_TYPECHECK_RECORD_KEYS = ROOT_TYPECHECK_BASE_KEYS | {
    "workflow_sha256", "workflow_blob_oid", "job_key", "job_name", "runner_labels", "step_command",
    "step_source", "checkout_action", "tsconfig_path", "tsconfig_blob_oid", "tsconfig_sha256",
    "source_inputs", "entity", "run_id", "run_attempt", "job_id", "workflow", "workflow_path",
    "workflow_commit", "pr_number", "run_conclusion", "command", "cwd", "checkout_commit",
    "step_name", "step_number", "process_pid", "numeric_process_exit", "step_started_at",
    "step_completed_at", "step_status", "step_conclusion", "step_outcomes", "trees", "log_members",
    "compiler_log_member_sha256", "original_log",
}


def _github_with_token(endpoint, token):
    """Read one GitHub endpoint with only the explicitly supplied ephemeral token."""
    if not isinstance(token, str) or not token:
        raise ValueError("explicit Auth GITHUB_TOKEN is absent; ambient credentials are not a fallback")
    cli = shutil.which("gh")
    if not cli:
        raise ValueError("authenticated GitHub CLI unavailable")
    env = {key: value for key, value in os.environ.items()
           if key not in {"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN"}}
    env["GH_TOKEN"] = token
    proc = subprocess.run([cli, "api", "--hostname", "github.com", endpoint], capture_output=True,
                          timeout=60, env=env)
    if proc.returncode:
        raise ValueError("explicit-token GitHub read refused or unavailable")
    if len(proc.stdout) > MAX_BYTES:
        raise ValueError("GitHub typecheck metadata exceeds bounded size")
    return proc.stdout


def _tracked_source(repo, source, path):
    """Exact regular tracked source bytes and object id; no working-tree substitution."""
    entry = _git(repo, "ls-tree", "-z", source, "--", path)
    rows = [row for row in entry.split(b"\0") if row]
    if len(rows) != 1:
        raise ValueError("typecheck source path absent or ambiguous: " + path)
    metadata, actual = rows[0].split(b"\t", 1)
    mode, kind, oid = metadata.split()
    if (actual.decode("utf-8", "strict") != path or mode != b"100644" or kind != b"blob"
            or not re.fullmatch(rb"[0-9a-f]{40}", oid)):
        raise ValueError("typecheck source must be a regular tracked blob: " + path)
    raw = _git(repo, "show", source + ":" + path)
    return raw, oid.decode("ascii")


def root_typecheck_source_binding(repo, source):
    """Qualify the one supported committed Auth root project/compiler workflow shape."""
    import yaml

    workflow, workflow_oid = _tracked_source(repo, source, ROOT_TYPECHECK_WORKFLOW)
    for token in yaml.scan(workflow.decode("utf-8", "strict")):
        if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken,
                              yaml.tokens.TagToken, yaml.tokens.DirectiveToken)):
            raise ValueError("Auth CI workflow aliases/tags/directives are unsupported")

    class UniqueLoader(yaml.BaseLoader):
        pass

    def mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if key in result:
                raise ValueError("Auth CI workflow contains a duplicate mapping key")
            result[key] = loader.construct_object(value_node)
        return result

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    doc = yaml.load(workflow, Loader=UniqueLoader)
    triggers = doc.get("on") if isinstance(doc, dict) else None
    if (not isinstance(doc, dict) or not isinstance(triggers, dict)
            or set(triggers) != {"push", "pull_request"} or triggers.get("pull_request") not in (None, "", {})
            or doc.get("permissions") != {"contents": "read"}):
        raise ValueError("Auth workflow must be the exact pull_request workflow with contents: read")
    jobs = doc.get("jobs")
    job = jobs.get(ROOT_TYPECHECK_JOB) if isinstance(jobs, dict) else None
    if (not isinstance(job, dict) or job.get("name") != ROOT_TYPECHECK_JOB_NAME
            or job.get("if") is not None or job.get("strategy") is not None
            or job.get("continue-on-error") not in (None, "false") or job.get("uses") is not None
            or job.get("permissions") is not None or job.get("env") is not None
            or job.get("defaults") is not None or job.get("container") is not None
            or job.get("services") is not None or doc.get("defaults") is not None
            or doc.get("env") is not None):
        raise ValueError("Auth main-package-tsc job is absent or outside the supported simple job shape")
    runner = job.get("runs-on")
    if runner != ["self-hosted", "linux", "docker", "ci-general"]:
        raise ValueError("Auth compiler runner labels differ from the qualified literal runner")
    steps = job.get("steps")
    if not isinstance(steps, list) or len(steps) != 6:
        raise ValueError("Auth compiler job steps are absent or outside the bounded supported shape")
    checkout = [s for s in steps if isinstance(s, dict) and isinstance(s.get("uses"), str)
                and s["uses"].startswith("actions/checkout@")]
    if (len(checkout) != 1 or not re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout[0]["uses"])
            or checkout[0].get("with") != {"persist-credentials": "false"}
            or checkout[0].get("if") is not None):
        raise ValueError("Auth compiler job checkout is not one literal full-SHA, nonpersistent checkout")
    if any(isinstance(step, dict) and "uses" in step
           and (not isinstance(step["uses"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", step["uses"]))
           for step in steps):
        raise ValueError("every Auth compiler job action must be pinned to a full commit SHA")
    pnpm_setup = [s for s in steps if isinstance(s, dict)
                  and isinstance(s.get("uses"), str) and s["uses"].startswith("pnpm/action-setup@")]
    node_setup = [s for s in steps if isinstance(s, dict)
                  and isinstance(s.get("uses"), str) and s["uses"].startswith("actions/setup-node@")]
    if (len(pnpm_setup) != 1 or pnpm_setup[0]["uses"] !=
            "pnpm/action-setup@ea17c68df8912ef543352723c149a84f56e3d413"
            or pnpm_setup[0].get("with") != {"dest": "${{ runner.temp }}/setup-pnpm"}
            or len(node_setup) != 1 or node_setup[0]["uses"] !=
            "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020"
            or node_setup[0].get("with") != {"node-version": "24", "cache": "pnpm"}):
        raise ValueError("Auth compiler toolchain setup differs from the exact qualified pinned actions")
    by_command = {}
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("run"), str):
            continue
        command = step["run"].strip()
        if command in ROOT_TYPECHECK_STEP_COMMANDS:
            by_command.setdefault(command, []).append(step)
    if set(by_command) != ROOT_TYPECHECK_STEP_COMMANDS or any(len(v) != 1 for v in by_command.values()):
        raise ValueError("Auth CI must contain unique frozen install, Prisma generation and literal tsc steps")
    for command, matches in by_command.items():
        step = matches[0]
        if (step.get("if") is not None or step.get("continue-on-error") not in (None, "false")
                or step.get("working-directory") is not None or step.get("shell") not in (None, "bash")
                or step.get("env") is not None):
            raise ValueError("Auth CI compiler prerequisite/step is conditional, tolerated or relocated")
    if ([steps.index(checkout[0]), steps.index(pnpm_setup[0]), steps.index(node_setup[0]),
         steps.index(by_command["pnpm install --frozen-lockfile"][0]),
         steps.index(by_command["pnpm exec prisma generate"][0]),
         steps.index(by_command["pnpm exec tsc --noEmit"][0])] != list(range(6))):
        raise ValueError("Auth compiler checkout/setup/install/generate/tsc ordering differs")
    compiler = by_command["pnpm exec tsc --noEmit"][0]
    if any(s.get("if") is not None or s.get("continue-on-error") not in (None, "false")
           for s in steps if isinstance(s, dict)):
        raise ValueError("Auth compiler job contains a conditional or tolerated step")
    tsconfig, tsconfig_oid = _tracked_source(repo, source, "tsconfig.json")
    tsconfig_doc = json.loads(tsconfig)
    if (not isinstance(tsconfig_doc, dict) or set(tsconfig_doc) != {"compilerOptions", "include", "exclude"}
            or not isinstance(tsconfig_doc.get("compilerOptions"), dict)
            or not isinstance(tsconfig_doc.get("include"), list)
            or not tsconfig_doc["include"] or tsconfig_doc.get("exclude") is None):
        raise ValueError("root tsconfig is not a regular, self-contained declared project")
    source_inputs = {}
    for path in ROOT_TYPECHECK_INPUTS:
        try:
            raw, oid = _tracked_source(repo, source, path)
            source_inputs[path] = {"present": True, "blob_oid": oid, "sha256": _digest(raw)}
        except ValueError as exc:
            if path in ("tsconfig.json", "package.json", "pnpm-lock.yaml"):
                raise
            if "absent or ambiguous" not in str(exc):
                raise
            source_inputs[path] = {"present": False, "blob_oid": None, "sha256": None}
    return {
        "workflow_sha256": _digest(workflow), "workflow_blob_oid": workflow_oid,
        "job_key": ROOT_TYPECHECK_JOB, "job_name": ROOT_TYPECHECK_JOB_NAME,
        "runner_labels": runner,
        "step_command": ROOT_TYPECHECK_COMMAND, "step_source": compiler["run"].strip(),
        "checkout_action": checkout[0]["uses"], "tsconfig_path": "tsconfig.json",
        "tsconfig_blob_oid": tsconfig_oid, "tsconfig_sha256": _digest(tsconfig),
        "source_inputs": source_inputs,
    }


def _regular_bytes(path, maximum=MAX_BYTES):
    path = Path(path)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > maximum:
        raise ValueError("typecheck evidence input is not a bounded regular file")
    raw = path.read_bytes()
    if len(raw) != st.st_size:
        raise ValueError("typecheck evidence changed during read")
    return raw


def _job_log_members(raw):
    """Return complete bounded log archive members; preserve the archive bytes separately."""
    if raw.startswith(b"PK\x03\x04"):
        members = {}
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > 128:
                raise ValueError("GitHub job-log archive is empty or exceeds the member bound")
            total = 0
            for info in infos:
                name = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if (name.is_absolute() or ".." in name.parts or info.is_dir() or info.flag_bits & 1
                        or stat.S_ISLNK(mode) or info.file_size > MAX_BYTES or info.filename in members):
                    raise ValueError("GitHub job-log archive has an unsafe/duplicate member")
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise ValueError("GitHub job-log member size mismatch")
                total += len(data)
                if total > MAX_BYTES:
                    raise ValueError("GitHub job-log archive expands beyond the total byte bound")
                members[info.filename] = data
        return members
    return {"original-job.log": raw}


def _step_log(members, step):
    if set(members) == {"original-job.log"}:
        return members["original-job.log"].decode("utf-8", "strict")
    number = step.get("number")
    if type(number) is not int or number <= 0:
        raise ValueError("GitHub typecheck step number is unavailable")
    candidates = [data for name, data in members.items()
                  if PurePosixPath(name).name.startswith(f"{number}_")]
    if len(candidates) != 1:
        raise ValueError("GitHub job log does not uniquely bind the selected step number")
    return candidates[0].decode("utf-8", "strict")


def _typecheck_record(repo, evidence_root):
    path = Path(evidence_root)
    if (not path.is_absolute() or path.name != "ci-typecheck" or path.parent.name != "current-candidate"
            or path.is_symlink() or path.exists()):
        raise ValueError("root typecheck evidence root must be a fresh absolute path")
    parent = path.parent.resolve(strict=True)
    if parent != path.parent.absolute():
        raise ValueError("root typecheck evidence parent must not cross a symlink")
    root = parent / path.name
    if root.is_relative_to(Path(repo).resolve()):
        raise ValueError("root typecheck evidence must remain outside the checked-out payload")
    root.mkdir(mode=0o700)
    return root


def _write_typecheck_record(root, document, log_raw=None):
    if log_raw is not None:
        log_path = root / "original-job.log"
        with log_path.open("xb") as stream:
            stream.write(log_raw)
        document["original_log"] = {"path": "original-job.log", "bytes": len(log_raw), "sha256": _digest(log_raw)}
    target = root / "record.json"
    with target.open("xb") as stream:
        stream.write((json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode())


def collect_root_typecheck(repo, repository, source, base, event_file, evidence_root, *, token=None,
                           read_api=None):
    """Collect only one exact completed Auth PR typecheck run. No run is ever started or retried."""
    root = _typecheck_record(repo, evidence_root)
    record = {"schema": ROOT_TYPECHECK_SCHEMA, "scope": "root_tsconfig_typecheck",
              "repository": repository, "source_commit": source, "base": base, "head": source,
              "verdict": "not_measured", "errors": []}
    log_raw = None
    try:
        if Path.cwd().resolve(strict=True) != Path(repo).resolve(strict=True):
            raise ValueError("Auth typecheck collector must run from the exact repository root")
        if repository != ROOT_TYPECHECK_REPO or not re.fullmatch(r"[0-9a-f]{40}", source) \
                or not re.fullmatch(r"[0-9a-f]{40}", base):
            raise ValueError("root typecheck collection is limited to exact Auth repository/base/head")
        if not token:
            raise ValueError("explicit Auth GITHUB_TOKEN is missing; no ambient credential fallback")
        event = json.loads(_regular_bytes(event_file).decode("utf-8", "strict"))
        pr = event.get("pull_request") if isinstance(event, dict) else None
        if (not isinstance(pr, dict) or type(pr.get("number")) is not int
                or (pr.get("head") or {}).get("sha") != source
                or (pr.get("base") or {}).get("sha") != base):
            raise ValueError("current Program candidate range does not match its exact Auth pull_request event")
        api = (lambda endpoint: _github_with_token(endpoint, token)) if read_api is None else read_api
        branch = (pr.get("head") or {}).get("ref")
        if not isinstance(branch, str) or not branch:
            raise ValueError("Auth pull_request branch identity unavailable")
        endpoint = ("repos/Arcanada-one/auth-arcana/actions/workflows/ci.yml/runs"
                    f"?event=pull_request&branch={quote(branch, safe='')}&per_page=100")
        listing = json.loads(api(endpoint))
        runs = listing.get("workflow_runs") if isinstance(listing, dict) else None
        if (not isinstance(runs, list) or type(listing.get("total_count")) is not int
                or listing["total_count"] != len(runs)):
            raise ValueError("exact Auth PR run listing is incomplete or paginated; uniqueness is not established")
        matches = [run for run in runs or [] if isinstance(run, dict)
                   and run.get("path", "").split("@", 1)[0] == ROOT_TYPECHECK_WORKFLOW
                   and run.get("event") == "pull_request"
                   and any(isinstance(item, dict) and item.get("number") == pr["number"]
                           and (item.get("head") or {}).get("sha") == source
                           and (item.get("base") or {}).get("sha") == base
                           for item in run.get("pull_requests", []))]
        if len(matches) != 1:
            raise ValueError("exact Auth PR has no unique associated ci.yml workflow run")
        run = matches[0]
        run_id, attempt = run.get("id"), run.get("run_attempt")
        if type(run_id) is not int or run_id <= 0 or type(attempt) is not int or attempt <= 0:
            raise ValueError("Auth CI run/current attempt identity is not a positive integer")
        current_run = json.loads(api(f"repos/{ROOT_TYPECHECK_REPO}/actions/runs/{run_id}"))
        if (current_run.get("id") != run_id or current_run.get("run_attempt") != attempt
                or current_run.get("event") != "pull_request"
                or current_run.get("path", "").split("@", 1)[0] != ROOT_TYPECHECK_WORKFLOW
                or current_run.get("head_sha") != run.get("head_sha")
                or current_run.get("repository", {}).get("full_name") != ROOT_TYPECHECK_REPO
                or current_run.get("head_repository", {}).get("full_name") != ROOT_TYPECHECK_REPO
                or current_run.get("status") != "completed"):
            raise ValueError("Auth CI run detail does not confirm the exact current completed attempt")
        if (run.get("repository", {}).get("full_name") != ROOT_TYPECHECK_REPO
                or run.get("head_repository", {}).get("full_name") != ROOT_TYPECHECK_REPO):
            raise ValueError("Auth CI run repository identity is not canonical same-repository PR")
        if run.get("status") != "completed":
            raise ValueError("exact Auth CI run is not completed; no wait or retry was started")
        job_list = json.loads(api(f"repos/{ROOT_TYPECHECK_REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"))
        jobs = job_list.get("jobs") if isinstance(job_list, dict) else None
        if (not isinstance(jobs, list) or type(job_list.get("total_count")) is not int
                or job_list["total_count"] != len(jobs)):
            raise ValueError("exact Auth attempt job listing is incomplete or paginated; uniqueness is not established")
        selected = [item for item in jobs or [] if isinstance(item, dict)
                    and item.get("name") == ROOT_TYPECHECK_JOB_NAME]
        if len(selected) != 1:
            raise ValueError("Auth CI attempt has no unique Type-check main package job")
        job = selected[0]
        binding = root_typecheck_source_binding(repo, source)
        job_id = job.get("id")
        if (type(job_id) is not int or job_id <= 0 or job.get("run_id") != run_id
                or job.get("run_attempt") != attempt or job.get("status") != "completed"):
            raise ValueError("Auth compiler job numeric identity/attempt is unbound")
        record.update(binding, entity="deployable_unit:.", run_id=run_id, run_attempt=attempt, job_id=job_id,
                      workflow=ROOT_TYPECHECK_WORKFLOW, workflow_path=run.get("path"),
                      workflow_commit=run.get("head_sha"), pr_number=pr["number"],
                      run_conclusion=current_run.get("conclusion"),
                      job_key=ROOT_TYPECHECK_JOB, job_name=ROOT_TYPECHECK_JOB_NAME,
                      command=ROOT_TYPECHECK_COMMAND, cwd=".",
                      checkout_commit=run.get("head_sha"),
                      step_name="Run pnpm exec tsc --noEmit", step_number=None,
                      process_pid="NOT_RETAINED", numeric_process_exit="NOT_RETAINED")
        steps = job.get("steps")
        if not isinstance(steps, list):
            raise ValueError("Auth compiler job step metadata is missing")
        compiler_steps = [s for s in steps if isinstance(s, dict)
                          and s.get("name") == "Run pnpm exec tsc --noEmit"]
        if len(compiler_steps) != 1:
            raise ValueError("Auth compiler step metadata is absent or ambiguous")
        compiler = compiler_steps[0]
        record["step_number"] = compiler.get("number")
        record["step_started_at"] = compiler.get("started_at")
        record["step_completed_at"] = compiler.get("completed_at")
        record["step_status"] = compiler.get("status")
        record["step_conclusion"] = compiler.get("conclusion")
        by_command = {"pnpm install --frozen-lockfile": "Run pnpm install --frozen-lockfile",
                      "pnpm exec prisma generate": "Run pnpm exec prisma generate",
                      "pnpm exec tsc --noEmit": "Run pnpm exec tsc --noEmit"}
        for command, name in by_command.items():
            candidates = [s for s in steps if isinstance(s, dict) and s.get("name") == name]
            if len(candidates) != 1 or candidates[0].get("status") != "completed":
                raise ValueError("Auth compiler prerequisite step absent/incomplete: " + name)
            record.setdefault("step_outcomes", {})[command] = candidates[0].get("conclusion")
        log_raw = api(f"repos/{ROOT_TYPECHECK_REPO}/actions/jobs/{job_id}/logs")
        if len(log_raw) > MAX_BYTES:
            raise ValueError("complete Auth job log exceeds bounded size")
        members = _job_log_members(log_raw)
        selected_log = _step_log(members, compiler)
        run_line = "##[group]Run pnpm exec tsc --noEmit"
        if selected_log.count(run_line) != 1 or "pnpm exec tsc --noEmit" not in selected_log:
            raise ValueError("authenticated original job log lacks one literal compiler step boundary")
        checkout_commit = run.get("head_sha")
        if not isinstance(checkout_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", checkout_commit):
            raise ValueError("Auth workflow run checkout commit is not a full Git OID")
        for oid in (source, checkout_commit):
            commit = json.loads(api(f"repos/{ROOT_TYPECHECK_REPO}/git/commits/{oid}"))
            if commit.get("sha") != oid or not isinstance((commit.get("tree") or {}).get("sha"), str):
                raise ValueError("GitHub-authenticated Auth source/checkout commit identity unavailable")
            record.setdefault("trees", {})[oid] = commit["tree"]["sha"]
        local_source_tree = _git(repo, "rev-parse", source + "^{tree}").decode().strip()
        if (record["trees"][source] != local_source_tree
                or record["trees"][checkout_commit] != local_source_tree):
            raise ValueError("Auth compiler checkout whole Git tree differs from exact current candidate source")
        record["checkout_commit"] = checkout_commit
        record["log_members"] = {name: {"bytes": len(data), "sha256": _digest(data)}
                                 for name, data in sorted(members.items())}
        record["compiler_log_member_sha256"] = _digest(selected_log.encode("utf-8"))
        outcomes = record["step_outcomes"]
        job_conclusion = job.get("conclusion")
        if compiler.get("status") == "completed" and compiler.get("conclusion") == "success" \
                and job_conclusion == "success" \
                and all(outcomes.get(c) == "success" for c in by_command):
            record["verdict"] = "verified"
        elif compiler.get("status") == "completed" and compiler.get("conclusion") == "failure":
            record["verdict"] = "failed"
        else:
            raise ValueError("Auth compiler run/job/prerequisites are not all completed successfully")
        _write_typecheck_record(root, record, log_raw)
        return record
    except Exception as exc:
        record["errors"] = [str(exc)[:500]]
        _write_typecheck_record(root, record, log_raw)
        return record


def consume_root_typecheck(repo, repository, base, head, evidence_root, *, token=None, read_api=None):
    """Reauthenticate one externally retained typed root row; never trust its claimed verdict."""
    result = {"schema": ROOT_TYPECHECK_SCHEMA, "scope": "root_tsconfig_typecheck",
              "verdict": "not_measured", "errors": []}
    try:
        root = Path(evidence_root)
        if (not root.is_absolute() or root.name != "ci-typecheck" or root.parent.name != "current-candidate"
                or root.is_symlink() or not root.is_dir()):
            raise ValueError("root typecheck evidence directory is missing or unsafe")
        parent = root.parent.resolve(strict=True)
        if parent != root.parent.absolute():
            raise ValueError("root typecheck evidence path crosses a symlinked candidate directory")
        root = root.resolve(strict=True)
        if root.is_relative_to(Path(repo).resolve(strict=True)):
            raise ValueError("root typecheck evidence is inside the authenticated repository payload")
        entries = sorted(path.name for path in root.iterdir())
        if ("record.json" not in entries or len(entries) > 2
                or any(name not in {"record.json", "original-job.log"} for name in entries)):
            raise ValueError("root typecheck evidence directory contains an unexpected member")
        if any(not stat.S_ISREG(path.lstat().st_mode) for path in root.iterdir()):
            raise ValueError("root typecheck evidence directory contains a non-regular member")
        record_raw = _regular_bytes(root / "record.json", 1024 * 1024)
        doc = json.loads(record_raw)
        if (not isinstance(doc, dict) or not ROOT_TYPECHECK_BASE_KEYS.issubset(doc)
                or set(doc) - ROOT_TYPECHECK_RECORD_KEYS
                or (doc.get("verdict") in ("verified", "failed")
                    and set(doc) != ROOT_TYPECHECK_RECORD_KEYS)
                or doc.get("schema") != ROOT_TYPECHECK_SCHEMA
                or doc.get("scope") != "root_tsconfig_typecheck"
                or doc.get("repository") != repository or repository != ROOT_TYPECHECK_REPO
                or doc.get("source_commit") != head or doc.get("head") != head
                or doc.get("base") != base or doc.get("entity") != "deployable_unit:."
                or doc.get("workflow") != ROOT_TYPECHECK_WORKFLOW
                or doc.get("job_key") != ROOT_TYPECHECK_JOB
                or doc.get("command") != ROOT_TYPECHECK_COMMAND or doc.get("cwd") != "."):
            raise ValueError("typed Auth root evidence schema/repository/tree/range/project binding mismatch")
        result.update({k: doc.get(k) for k in ("run_id", "run_attempt", "job_id", "source_commit",
                      "checkout_commit", "step_name", "step_number", "step_started_at", "step_completed_at",
                      "step_conclusion", "run_conclusion", "workflow_sha256", "tsconfig_sha256", "source_inputs")})
        if doc.get("verdict") == "not_measured":
            result["errors"] = doc.get("errors", [])
            return result
        if not isinstance(token, str) or not token:
            raise ValueError("explicit Auth GITHUB_TOKEN unavailable; no ambient credential fallback")
        log_meta = doc.get("original_log")
        if (not isinstance(log_meta, dict) or log_meta.get("path") != "original-job.log"
                or type(log_meta.get("bytes")) is not int):
            raise ValueError("original complete Auth job log binding is missing")
        log_raw = _regular_bytes(root / "original-job.log")
        if len(log_raw) != log_meta["bytes"] or _digest(log_raw) != log_meta.get("sha256"):
            raise ValueError("original complete Auth job log bytes differ from their record")
        api = (lambda endpoint: _github_with_token(endpoint, token)) if read_api is None else read_api
        prefix = "repos/" + ROOT_TYPECHECK_REPO
        run = json.loads(api(f"{prefix}/actions/runs/{doc['run_id']}"))
        job = json.loads(api(f"{prefix}/actions/jobs/{doc['job_id']}"))
        pull_requests = run.get("pull_requests")
        pr_matches = [item for item in pull_requests or [] if isinstance(item, dict)
                      and item.get("number") == doc.get("pr_number")
                      and (item.get("head") or {}).get("sha") == head
                      and (item.get("base") or {}).get("sha") == base]
        if (run.get("id") != doc["run_id"] or run.get("run_attempt") != doc["run_attempt"]
                or run.get("event") != "pull_request" or run.get("repository", {}).get("full_name") != repository
                or run.get("head_repository", {}).get("full_name") != repository
                or run.get("path", "").split("@", 1)[0] != ROOT_TYPECHECK_WORKFLOW
                or len(pr_matches) != 1
                or run.get("status") != "completed" or run.get("conclusion") != doc.get("run_conclusion")
                or job.get("id") != doc["job_id"]
                or job.get("run_id") != doc["run_id"] or job.get("run_attempt") != doc["run_attempt"]
                or job.get("name") != ROOT_TYPECHECK_JOB_NAME or job.get("status") != "completed"):
            raise ValueError("authenticated Auth run/job/current-attempt identity mismatch")
        if run.get("head_sha") != doc.get("checkout_commit"):
            raise ValueError("authenticated Auth workflow checkout commit differs from the retained record")
        for oid in (head, doc["checkout_commit"]):
            commit = json.loads(api(f"{prefix}/git/commits/{oid}"))
            if commit.get("sha") != oid or not isinstance((commit.get("tree") or {}).get("sha"), str):
                raise ValueError("authenticated Auth source/checkout Git tree is unavailable")
            if commit["tree"]["sha"] != (doc.get("trees") or {}).get(oid):
                raise ValueError("authenticated Auth source/checkout tree differs from the retained record")
        if _git(repo, "rev-parse", head + "^{tree}").decode().strip() != doc["trees"][head]:
            raise ValueError("Auth source tree differs from the exact current candidate tree")
        binding = root_typecheck_source_binding(repo, head)
        for key, value in binding.items():
            if doc.get(key) != value:
                raise ValueError("committed Auth workflow/project source binding differs: " + key)
        jobs = json.loads(api(f"{prefix}/actions/runs/{doc['run_id']}/attempts/{doc['run_attempt']}/jobs?per_page=100"))
        listed_jobs = jobs.get("jobs") if isinstance(jobs, dict) else None
        if (not isinstance(listed_jobs, list) or type(jobs.get("total_count")) is not int
                or jobs["total_count"] != len(listed_jobs)):
            raise ValueError("authenticated Auth attempt job listing is incomplete")
        job_rows = [row for row in listed_jobs if isinstance(row, dict)
                    and row.get("id") == doc["job_id"]]
        if len(job_rows) != 1:
            raise ValueError("Auth attempt job identity is absent or ambiguous")
        current_job = job_rows[0]
        prerequisite_names = {
            "pnpm install --frozen-lockfile": "Run pnpm install --frozen-lockfile",
            "pnpm exec prisma generate": "Run pnpm exec prisma generate",
            "pnpm exec tsc --noEmit": "Run pnpm exec tsc --noEmit",
        }
        current_outcomes = {}
        for command, name in prerequisite_names.items():
            candidates = [s for s in current_job.get("steps", []) if isinstance(s, dict)
                          and s.get("name") == name]
            if len(candidates) != 1 or candidates[0].get("status") != "completed":
                raise ValueError("authenticated Auth compiler prerequisite is absent/incomplete: " + name)
            current_outcomes[command] = candidates[0].get("conclusion")
        if doc.get("step_outcomes") != current_outcomes:
            raise ValueError("authenticated Auth compiler prerequisite outcomes differ from the record")
        compiler_steps = [s for s in current_job.get("steps", []) if isinstance(s, dict)
                          and s.get("name") == doc["step_name"]]
        if len(compiler_steps) != 1:
            raise ValueError("authenticated compiler step is absent or ambiguous")
        compiler = compiler_steps[0]
        if (compiler.get("number") != doc["step_number"] or compiler.get("status") != "completed"
                or compiler.get("conclusion") != doc["step_conclusion"]
                or compiler.get("started_at") != doc["step_started_at"]
                or compiler.get("completed_at") != doc["step_completed_at"]):
            raise ValueError("authenticated compiler step metadata differs from the record")
        fresh_log = api(f"{prefix}/actions/jobs/{doc['job_id']}/logs")
        if _digest(fresh_log) != log_meta["sha256"] or fresh_log != log_raw:
            raise ValueError("freshly authenticated original job log differs from retained bytes")
        members = _job_log_members(fresh_log)
        selected_log = _step_log(members, compiler)
        if _digest(selected_log.encode("utf-8")) != doc.get("compiler_log_member_sha256"):
            raise ValueError("authenticated compiler step log binding differs")
        if (selected_log.count("##[group]Run pnpm exec tsc --noEmit") != 1
                or "pnpm exec tsc --noEmit" not in selected_log):
            raise ValueError("authenticated original job log does not show the literal compiler invocation")
        if doc.get("verdict") == "failed":
            if compiler.get("conclusion") != "failure" or job.get("conclusion") != "failure":
                raise ValueError("claimed failed compiler outcome is not authenticated")
            result["verdict"] = "failed"
            return result
        if (doc.get("verdict") != "verified" or compiler.get("conclusion") != "success"
                or job.get("conclusion") != "success"):
            raise ValueError("root CI row is not an authenticated successful compiler result")
        result.update(verdict="verified", output="authenticated exact Auth root tsconfig typecheck; no local replay",
                      duration_s=0.0, measurement="authenticated_github_ci")
    except (ValueError, KeyError, TypeError, OSError, ImportError, subprocess.SubprocessError,
            zipfile.BadZipFile, UnicodeError, json.JSONDecodeError) as exc:
        result["errors"].append(str(exc))
    return result


def root_typecheck_receipt_errors(repo, base, head, repository, rows, evidence_root, *, token=None):
    """Admission reauthenticates each imported CI-verified root typecheck row independently."""
    errors = []
    relevant = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ci_evidence = row.get("ci_evidence")
        typed_evidence = (
            isinstance(ci_evidence, str) and ci_evidence.startswith("ci-typecheck/")
        ) or (
            isinstance(ci_evidence, list)
            and any(isinstance(path, str) and path.startswith("ci-typecheck/") for path in ci_evidence)
        )
        if (row.get("id") == "v-type-check-root-tsconfig-ci"
                or row.get("command") == "authenticated GitHub root tsconfig typecheck; no local replay"
                or row.get("scope") == "root_tsconfig_typecheck"
                or row.get("measurement_origin") == "authenticated_github_ci"
                or typed_evidence):
            relevant.append(row)
    for row in relevant:
        if row.get("scope") != "root_tsconfig_typecheck" or row.get("kind") != "type_check":
            errors.append("TYPECHECK_CI_EVIDENCE_UNVERIFIABLE: imported CI row has an unknown type/scope")
            continue
        entity_verdicts = row.get("entity_verdicts")
        if (row.get("measurement_origin") != "authenticated_github_ci"
                or not isinstance(entity_verdicts, dict) or set(entity_verdicts) != {"deployable_unit:."}
                or row.get("entities") != ["deployable_unit:."]):
            errors.append("TYPECHECK_CI_EVIDENCE_UNVERIFIABLE: typed row must bind only the root deployable entity")
            continue
        claimed = entity_verdicts["deployable_unit:."]
        expected_exit = {"verified": 0, "failed": 1, "not_measured": 125}.get(claimed)
        if (row.get("id") != "v-type-check-root-tsconfig-ci"
                or row.get("command") != "authenticated GitHub root tsconfig typecheck; no local replay"
                or type(row.get("exit_code")) is not int or row.get("exit_code") != expected_exit
                or row.get("process_pid") != "NOT_RETAINED"
                or row.get("numeric_process_exit") != "NOT_RETAINED"
                or row.get("ci_repository") != repository
                or row.get("ci_source_base") != base):
            errors.append("TYPECHECK_CI_EVIDENCE_UNVERIFIABLE: typed row projection is malformed")
            continue
        if claimed == "not_measured":
            continue
        paths = row.get("ci_evidence") or []
        if (len(paths) != 1 or paths[0] != "ci-typecheck/record.json" or evidence_root is None):
            errors.append("TYPECHECK_CI_EVIDENCE_UNVERIFIABLE: exact candidate record path missing")
            continue
        try:
            proof = consume_root_typecheck(repo, repository, base, head,
                                           evidence_root, token=token)
            if proof.get("verdict") != claimed:
                errors.append("TYPECHECK_CI_EVIDENCE_UNVERIFIABLE: " + "; ".join(proof.get("errors", [])))
            elif row.get("ci_source_commit") != proof.get("source_commit"):
                errors.append("TYPECHECK_CI_EVIDENCE_UNVERIFIABLE: source commit projection differs")
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
            errors.append("TYPECHECK_CI_EVIDENCE_UNVERIFIABLE: authenticated record missing")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect the one exact authenticated Auth root typecheck record")
    sub = parser.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect-root-typecheck")
    collect.add_argument("--repo", required=True)
    collect.add_argument("--repo-name", required=True)
    collect.add_argument("--source", required=True)
    collect.add_argument("--base", required=True)
    collect.add_argument("--event-file", required=True)
    collect.add_argument("--evidence-root", required=True)
    args = parser.parse_args(argv)
    token = os.environ.pop("GH_TOKEN", None)
    result = collect_root_typecheck(args.repo, args.repo_name, args.source, args.base,
                                    args.event_file, args.evidence_root, token=token)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
