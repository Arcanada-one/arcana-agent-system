"""Versioned process observations. Trusted plans, not an untrusted-code sandbox."""
import hashlib
import json
import os
import selectors
import stat
import re
import math
from datetime import datetime, timezone
import signal
import subprocess
import time
from pathlib import Path

MAX_CAPTURE = 1024 * 1024
MAX_TIMEOUT = 120


def digest(value):
    return hashlib.sha256(value).hexdigest()


def file_digest(path, limit=512 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("not a bounded regular execution artifact")
        value, total = hashlib.sha256(), 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk: break
            total += len(chunk)
            if total > limit: raise ValueError("execution artifact grew beyond bound")
            value.update(chunk)
        return value.hexdigest(), total
    finally:
        os.close(fd)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def hash_valid(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def strings(value, nonempty=False):
    return isinstance(value, list) and (bool(value) or not nonempty) and all(isinstance(x, str) and bool(x) and "\0" not in x for x in value) and len(set(value)) == len(value)


def manifest_errors(items, required=False):
    if not isinstance(items, list) or required and not items:
        return ["invalid execution/artifact manifest"]
    paths = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"] or "\0" in item["path"] or not Path(item["path"]).is_absolute() or not hash_valid(item.get("sha256")):
            return ["manifest requires absolute regular-file paths and SHA256"]
        paths.append(item["path"])
    return [] if len(set(paths)) == len(paths) else ["duplicate manifest paths"]


def plan_probe_errors(p):
    if not isinstance(p, dict) or p.get("kind") != "process":
        return ["v2 supports explicitly tagged process probes only; HTTP remains v1"]
    errors = []
    if not isinstance(p.get("id"), str) or not p["id"]:
        errors.append("missing process id")
    argv = p.get("argv")
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x or "\0" in x for x in argv) or not Path(argv[0]).is_absolute():
        errors.append("process argv requires an absolute executable and nonempty strings")
    cwd = p.get("cwd")
    if not isinstance(cwd, str) or not cwd or "\0" in cwd or Path(cwd).is_absolute() or ".." in Path(cwd).parts:
        errors.append("process cwd must be repository relative")
    keys = p.get("env_keys", [])
    if not strings(keys) or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) for k in keys):
        errors.append("invalid environment key selection")
    timeout = p.get("timeout_seconds")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT:
        errors.append("invalid process timeout")
    capture = p.get("capture_limit_bytes", MAX_CAPTURE)
    if type(capture) is not int or not 1 <= capture <= MAX_CAPTURE:
        errors.append("invalid process capture bound")
    expect = p.get("expect")
    if not isinstance(expect, dict):
        return errors + ["missing process expectations"]
    if set(expect) - {"exit_codes", "signals", "stdout_contains", "stderr_contains"}:
        errors.append("unknown process expectations")
    codes, signals = expect.get("exit_codes"), expect.get("signals")
    if (codes is None) == (signals is None):
        errors.append("declare exactly one expected exit or signal set")
    values = codes if codes is not None else signals
    if not isinstance(values, list) or not values or any(type(v) is not int or not (0 if codes is not None else 1) <= v <= 255 for v in values):
        errors.append("invalid expected termination values")
    for name in ("stdout_contains", "stderr_contains"):
        if not strings(expect.get(name, [])):
            errors.append("invalid bounded output assertions")
    errors.extend(manifest_errors(p.get("execution_files"), required=True))
    errors.extend(manifest_errors(p.get("artifacts", [])))
    if not hash_valid(p.get("executable_sha256")):
        errors.append("missing expected executable digest")
    entities = p.get("entities")
    if not strings(entities, nonempty=True) or any(not re.fullmatch(r"(?:code_unit|config_key):.+", e) for e in entities):
        errors.append("process evidence supports only code units and config keys")
    if p.get("mutating") is not True or any(k in p for k in ("status", "url", "method", "path", "auth")):
        errors.append("process requires explicit mutation scope and no HTTP fields")
    return errors


def plan_errors(plan):
    if not isinstance(plan, dict) or plan.get("schema") != "CanaryPlan/v2":
        return ["not a CanaryPlan/v2"]
    errors = []
    for key in ("id", "owner", "environment"):
        if not isinstance(plan.get(key), str) or not plan[key].strip():
            errors.append("missing named plan " + key)
    if plan.get("read_only") is not False:
        errors.append("process plans require explicit non-read-only ownership")
    probes = plan.get("probes")
    if not isinstance(probes, list) or not probes:
        return errors + ["missing original process probes"]
    for probe in probes:
        errors.extend(plan_probe_errors(probe))
    if not errors and len({p["id"] for p in probes}) != len(probes):
        errors.append("duplicate original probe ids")
    return errors


def expected_outcome(p, result):
    """Recompute from original expectations; digest-only matches trust the producer."""
    term = result["termination"]
    kind = term["kind"]
    if result.get("executed") is not True or result.get("execution_identity_unchanged") is not True or result.get("capture_complete") is not True or kind in ("spawn_error", "timeout", "capture_limit", "capture_error") or result.get("artifacts_verifiable") is not True:
        return "not_measured"
    expect = p["expect"]
    matches = kind == "exit" and term.get("code") in expect.get("exit_codes", []) or kind == "signal" and term.get("signal") in expect.get("signals", [])
    return "verified" if matches and all(c["matched"] for c in result["output_checks"]) and all(a["matched"] for a in result["artifacts"]) else "failed"


def result_errors(result):
    errors = []
    if any(k in result for k in ("status", "url", "method")):
        errors.append("process result contains HTTP fields")
    for key in ("executed", "execution_identity_unchanged", "capture_complete", "artifacts_verifiable"):
        if type(result.get(key)) is not bool: errors.append("missing process state " + key)
    term = result.get("termination")
    allowed = {"exit": {"kind", "code"}, "signal": {"kind", "signal"}, "spawn_error": {"kind", "category"}, "capture_error": {"kind", "category"}, "timeout": {"kind"}, "capture_limit": {"kind"}}
    if not isinstance(term, dict) or not isinstance(term.get("kind"), str) or term["kind"] not in allowed:
        return errors + ["invalid process termination"]
    if set(term) != allowed[term["kind"]]: errors.append("contradictory process termination fields")
    if term["kind"] == "exit" and (type(term.get("code")) is not int or not 0 <= term["code"] <= 255): errors.append("invalid actual exit code")
    if term["kind"] == "signal" and (type(term.get("signal")) is not int or not 1 <= term["signal"] <= 255): errors.append("invalid actual signal")
    if term["kind"] in ("spawn_error", "capture_error") and not isinstance(term.get("category"), str): errors.append("invalid error category")
    if (term["kind"] == "spawn_error") != (result.get("executed") is False): errors.append("inconsistent spawn state")
    streams = result.get("streams")
    if not isinstance(streams, dict) or set(streams) != {"stdout", "stderr"}:
        errors.append("invalid process streams")
    else:
        for stream in streams.values():
            if not isinstance(stream, dict) or type(stream.get("captured_bytes")) is not int or stream["captured_bytes"] < 0 or not hash_valid(stream.get("sha256")) or stream.get("capture") != "digest_only" or type(stream.get("truncated")) is not bool: errors.append("invalid process stream observation")
    dates = []
    for key in ("started_at_utc", "finished_at_utc"):
        try:
            value = datetime.fromisoformat(result[key].replace("Z", "+00:00"))
            if value.tzinfo is None: raise ValueError()
            dates.append(value)
        except (KeyError, TypeError, ValueError, AttributeError): errors.append("invalid process observation timestamp")
    if len(dates) == 2 and dates[1] < dates[0]: errors.append("process timestamps reversed")
    elapsed = result.get("elapsed_ms")
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0: errors.append("invalid elapsed time")
    checks = result.get("output_checks")
    if not isinstance(checks, list) or any(not isinstance(c, dict) or c.get("stream") not in ("stdout", "stderr") or not isinstance(c.get("expected"), str) or type(c.get("matched")) is not bool for c in checks): errors.append("invalid process output checks")
    for key in ("execution_files", "artifacts"):
        items = result.get(key)
        if not isinstance(items, list) or any(not isinstance(i, dict) or not isinstance(i.get("path"), str) or type(i.get("matched")) is not bool or (i.get("sha256") is not None and not hash_valid(i["sha256"])) or (i.get("bytes") is not None and (type(i["bytes"]) is not int or i["bytes"] < 0)) for i in items): errors.append("invalid observed manifest " + key)
    if not hash_valid(result.get("invocation_digest")): errors.append("invalid invocation digest")
    if result.get("executable_sha256") is not None and not hash_valid(result["executable_sha256"]): errors.append("invalid executable digest")
    if not strings(result.get("environment_keys")): errors.append("invalid observed environment names")
    return errors


def bound_errors(doc, path, read_regular):
    """Read original hash-bound plan and recompute its full entity/probe coverage."""
    try:
        ref = doc["plan"]
        raw = read_regular(Path(path).parent / ref["path"])
        if ref.get("digest") not in (digest(raw), "sha256:" + digest(raw)):
            return ["original process plan digest mismatch"]
        plan = json.loads(raw)
        errors = plan_errors(plan)
        if errors: return errors
        if plan["id"] != ref["id"] or plan["environment"] != doc["environment"] or plan["owner"] != doc.get("mutating_owner") or doc.get("read_only") is not False or plan.get("subject") != doc.get("subject"):
            return ["process plan identity/subject differs from result"]
        if doc.get("source_binding_errors") != []:
            return ["producer could not preserve source attribution"]
        plans = {p["id"]: p for p in plan["probes"]}
        if {p["id"] for p in doc["probes"]} != set(plans): return ["process result omits or adds original probes"]
        expected_entities = {}
        for p in plan["probes"]:
            for entity in p["entities"]: expected_entities.setdefault(entity, []).append(p["id"])
        if {r["entity"] for r in doc["entity_verdicts"]} != set(expected_entities): errors.append("process entity inventory differs from original plan")
        for row in doc["entity_verdicts"]:
            if row["probe_ids"] != expected_entities.get(row["entity"]): errors.append("entity must reference all original applicable probes")
        for result in doc["probes"]:
            p = plans[result["id"]]
            if result.get("kind") != "process" or result.get("invocation_digest") != digest(canonical(p)):
                errors.append("process invocation differs from original plan")
            checks = [(name.split("_")[0], text) for name in ("stdout_contains", "stderr_contains") for text in p["expect"].get(name, [])]
            if [(c["stream"], c["expected"]) for c in result["output_checks"]] != checks: errors.append("output assertions differ from original plan")
            if result["execution_identity_unchanged"] and (not result["execution_files"] or not all(i["matched"] for i in result["execution_files"])):
                errors.append("unchanged execution identity contradicts required input hashes")
            if result["outcome"] != expected_outcome(p, result): errors.append("process verdict contradicts actual observations")
            if not set(result["environment_keys"]).issubset(p.get("env_keys", [])): errors.append("undeclared process environment names")
            if result["executed"]:
                if result.get("executable_sha256") != p["executable_sha256"]: errors.append("executable identity differs from original plan")
                try:
                    if file_digest(p["argv"][0])[0] != p["executable_sha256"]: errors.append("executable changed since observation")
                except (OSError, ValueError): errors.append("executable is no longer verifiable")
            cap = p.get("capture_limit_bytes", MAX_CAPTURE)
            captured = sum(x["captured_bytes"] for x in result["streams"].values())
            if captured > cap:
                errors.append("combined captured bytes exceed original plan limit")
            if any(x["truncated"] != (not result["capture_complete"]) for x in result["streams"].values()):
                errors.append("stream truncation contradicts capture completeness")
            if result["termination"]["kind"] == "capture_limit" and (result["capture_complete"] or captured != cap):
                errors.append("capture limit termination contradicts captured bytes or completeness")
            for key in ("execution_files", "artifacts"):
                actuals, expected = result[key], p.get(key, [])
                if [a["path"] for a in actuals] != [a["path"] for a in expected]: errors.append("manifest differs from original plan")
                for actual, item in zip(actuals, expected):
                    # Execution inputs remain hash-verifiable; streams are deliberately not retained.
                    try:
                        h, size = file_digest(item["path"], MAX_CAPTURE if key == "artifacts" else 512 * 1024 * 1024)
                        if actual.get("sha256") != h or actual.get("bytes") != size or actual["matched"] != (h == item["sha256"]): errors.append("artifact or execution input changed/unverifiable")
                    except (OSError, ValueError):
                        if result["outcome"] != "not_measured": errors.append("required artifact or execution input unavailable")
        return errors
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError):
        return ["original process plan cannot be verified"]


def observed_manifest(items, limit):
    result = []
    for item in items:
        try:
            h, size = file_digest(item["path"], limit)
            result.append({"path": item["path"], "sha256": h, "bytes": size, "matched": h == item["sha256"]})
        except (OSError, ValueError):
            result.append({"path": item["path"], "sha256": None, "bytes": None, "matched": False})
    return result


def absent(p, category):
    """Complete, non-admitting observation when no child could be started."""
    stamp = datetime.now(timezone.utc).isoformat()
    return {"id": p["id"], "kind": "process", "executed": False, "termination": {"kind": "spawn_error", "category": category},
            "outcome": "not_measured", "reason": "Owned process was not executed", "execution_identity_unchanged": False,
            "capture_complete": False, "artifacts_verifiable": False, "executable_sha256": None,
            "invocation_digest": digest(canonical(p)), "environment_keys": [], "elapsed_ms": 0,
            "started_at_utc": stamp, "finished_at_utc": stamp,
            "execution_files": observed_manifest(p["execution_files"], 512 * 1024 * 1024),
            "artifacts": observed_manifest(p.get("artifacts", []), MAX_CAPTURE),
            "streams": {name: {"captured_bytes": 0, "sha256": digest(b""), "capture": "digest_only", "truncated": True} for name in ("stdout", "stderr")},
            "output_checks": [{"stream": name, "expected": text, "matched": False} for name in ("stdout", "stderr") for text in p["expect"].get(name + "_contains", [])]}


def run(p, repo, artifact_root=None):
    """Linux waitid keeps leader/PGID reserved until all group signals finish.

    Escaped descendants are outside this cleanup guarantee. Open inherited pipes
    after group termination make capture incomplete, never a successful probe.
    """
    errors = plan_probe_errors(p)
    if errors: raise ValueError("; ".join(errors))
    result = absent(p, "NotStarted")
    if not hasattr(os, "WNOWAIT"): return result
    started = time.monotonic()
    proc, selector = None, None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    cap = p.get("capture_limit_bytes", MAX_CAPTURE)
    def capture(name, block):
        remaining = cap - sum(map(len, buffers.values()))
        buffers[name].extend(block[:max(0, remaining)])
        return len(block) <= remaining
    try:
        cwd = (Path(repo) / p["cwd"]).resolve()
        cwd.relative_to(Path(repo).resolve())
        # Do not resolve away a symlink: the explicit executable itself must be regular.
        executable = Path(p["argv"][0])
        h, _ = file_digest(executable)
        if h != p["executable_sha256"] or not all(i["matched"] for i in result["execution_files"]):
            result["termination"]["category"] = "ExecutionIdentityMismatch"
            return result
        env = {key: os.environ[key] for key in p.get("env_keys", []) if key in os.environ}
        result["executable_sha256"] = h
        result["environment_keys"] = sorted(env)
        proc = subprocess.Popen(p["argv"], cwd=cwd, env=env, shell=False,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        result["executed"] = True
        selector = selectors.DefaultSelector()
        for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        deadline = started + p["timeout_seconds"]
        while True:
            info = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            overflow = False
            for key, _ in selector.select(.02):
                try: block = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError: continue
                if block: overflow = not capture(key.data, block) or overflow
                else: selector.unregister(key.fileobj)
            if overflow:
                result["termination"] = {"kind": "capture_limit"}; break
            if info is not None:
                result["termination"] = {"kind": "exit", "code": info.si_status} if info.si_code == os.CLD_EXITED else {"kind": "signal", "signal": info.si_status}
                break
            if time.monotonic() >= deadline:
                result["termination"] = {"kind": "timeout"}; break
        # No poll/wait has reaped the leader; its PID cannot be reused here.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try: os.killpg(proc.pid, sig)
            except ProcessLookupError: pass
            if sig == signal.SIGTERM: time.sleep(.05)
        proc.wait(timeout=5)
        # No group signals after this reap. Descendants can have escaped setsid.
        drain_deadline = time.monotonic() + .2
        while selector.get_map() and time.monotonic() < drain_deadline:
            for key, _ in selector.select(.02):
                try: block = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError: continue
                if not block: selector.unregister(key.fileobj)
                elif not capture(key.data, block): result["termination"] = {"kind": "capture_limit"}
        result["capture_complete"] = not bool(selector.get_map()) and result["termination"]["kind"] != "capture_limit"
        result["cleanup"] = {"group_signalled_before_leader_reaped": True,
                             "escaped_descendants": "not_proven_absent", "sandbox": False}
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result["termination"] = {"kind": "spawn_error" if proc is None else "capture_error", "category": type(exc).__name__}
    finally:
        if proc is not None and proc.returncode is None:
            # Only this runner waits for the leader. None means still unreaped.
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=5)
        if selector is not None: selector.close()
        if proc is not None:
            for pipe in (proc.stdout, proc.stderr):
                if pipe: pipe.close()
    result["artifacts"] = observed_manifest(p.get("artifacts", []), MAX_CAPTURE)
    result["artifacts_verifiable"] = all(a["sha256"] is not None for a in result["artifacts"])
    after = observed_manifest(p["execution_files"], 512 * 1024 * 1024)
    result["execution_identity_unchanged"] = after == result["execution_files"] and all(a["matched"] for a in after)
    try:
        result["execution_identity_unchanged"] = result["execution_identity_unchanged"] and file_digest(p["argv"][0])[0] == p["executable_sha256"]
    except (OSError, ValueError): result["execution_identity_unchanged"] = False
    result["output_checks"] = []
    for name, data in buffers.items():
        result["streams"][name] = {"captured_bytes": len(data), "sha256": digest(data), "capture": "digest_only", "truncated": not result["capture_complete"]}
        for text in p["expect"].get(name + "_contains", []):
            result["output_checks"].append({"stream": name, "expected": text, "matched": text in data.decode("utf8", "replace")})
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    result["outcome"] = expected_outcome(p, result)
    result["reason"] = "Actual owned process termination and original-plan assertions; escaped descendants are not proven absent"
    result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    return result
