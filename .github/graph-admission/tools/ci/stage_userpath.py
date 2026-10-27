#!/usr/bin/env python3
"""Capture current-source CLI results and run SharedVerifierV1 on an isolated temporary fixture.

This records two separate subjects: the Program source being exercised and the synthetic fixture
repository being admitted. A fixture admission is never represented as admission of the Program
candidate or as work-item evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True


SOURCE_FILES = (
    "tools/ci/stage_userpath.py",
    "tools/graph/ci_gate.py",
    "tools/graph/test_stage_userpath.py",
    "tools/graph/build_graph.py",
    "tools/graph/impact.py",
    "tools/graph/verify.py",
    "tools/graph/admit_change.py",
    "tools/graph/source_input_contract.py",
    "tools/graph/test_source_input_contract.py",
    "contracts/graph-verified-change/source-input-contract.v1.json",
    "tools/graph/test_ci_gate_stage_input.py",
    ".github/workflows/ci.yml",
    ".github/workflows/graph-admission.yml",
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


def write_bytes(root: Path, relative: str, raw: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def file_ref(path: Path, evidence_root: Path) -> dict:
    raw = path.read_bytes()
    return {"path": path.relative_to(evidence_root).as_posix(), "sha256": sha256(raw), "bytes": len(raw)}


def program_source_binding(repo: Path, repo_name: str, head: str, tools_root: Path) -> dict:
    """Bind the Program implementation either to its own Git tree or the caller's vendored bundle."""
    if tools_root.is_symlink() or not tools_root.is_dir():
        raise ValueError("Program tools root is missing or unsafe")
    if repo_name == "Arcanada-one/arcanada-universal-program":
        files = []
        for relative in SOURCE_FILES:
            mode = subprocess.run(["git", "-C", str(repo), "ls-tree", head, "--", relative],
                                  capture_output=True, text=True)
            if mode.returncode != 0 or mode.stdout.split(maxsplit=1)[0:1] not in (["100644"], ["100755"]):
                raise ValueError(f"Program source is not a regular committed file: {relative}")
            rc = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{head}:{relative}"],
                                capture_output=True).returncode
            if rc != 0:
                raise ValueError(f"Program source is not present at candidate head: {relative}")
            raw = subprocess.run(["git", "-C", str(repo), "show", f"{head}:{relative}"],
                                 check=True, capture_output=True).stdout
            files.append({"path": relative, "sha256": sha256(raw)})
        return {"origin": "candidate_program_tree", "program_ref": head,
                "bundle_digest": None, "manifest_sha256": None, "files": files}

    manifest_path = tools_root / "BUNDLE.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("pinned Program bundle manifest is missing or unsafe")
    raw_manifest = manifest_path.read_bytes()
    manifest = json.loads(raw_manifest.decode("utf-8"))
    if (not isinstance(manifest, dict) or manifest.get("schema") != "GraphAdmissionBundle/v1"
            or manifest.get("program_repo") != "Arcanada-one/arcanada-universal-program"
            or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("program_ref", "")))
            or not isinstance(manifest.get("files"), list)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(manifest.get("bundle_digest", "")))):
        raise ValueError("pinned Program bundle manifest is malformed")
    files = []
    seen = set()
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or entry.get("verified_by_the_job") is False:
            continue
        relative, digest = entry.get("path"), entry.get("sha256")
        if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
                or ".." in Path(relative).parts or "\\" in relative
                or relative in seen or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(digest or ""))):
            raise ValueError("pinned Program bundle source inventory is malformed")
        seen.add(relative)
        cursor = tools_root
        for component in Path(relative).parts:
            cursor = cursor / component
            if cursor.is_symlink():
                raise ValueError(f"pinned Program bundle source is a symlink: {relative}")
        if not cursor.is_file() or "sha256:" + sha256(cursor.read_bytes()) != digest:
            raise ValueError(f"pinned Program bundle source differs from its manifest: {relative}")
        files.append({"path": relative, "sha256": digest})
    if not files:
        raise ValueError("pinned Program bundle source inventory is empty")
    return {"origin": "pinned_program_bundle", "program_ref": manifest["program_ref"],
            "bundle_digest": manifest["bundle_digest"], "manifest_sha256": sha256(raw_manifest),
            "files": files}


def candidate_cli_outcome(repo: Path, repo_name: str, base: str, head: str,
                          candidate_root: Path, evidence_root: Path,
                          program_source: dict, tools_root: Path) -> dict:
    """Publish the same-run current-source CLI captures; this is provenance, not admission."""
    if candidate_root.is_symlink() or not candidate_root.is_dir():
        raise ValueError("current-source CLI capture root is missing or unsafe")
    if not candidate_root.is_absolute():
        raise ValueError("current-source CLI capture root must be absolute")
    resolved_root = candidate_root.resolve(strict=True)
    if evidence_root.resolve(strict=True) not in resolved_root.parents:
        raise ValueError("current-source CLI capture root escapes the stage result directory")
    expected_scripts = {
        "build": ["python3", str(tools_root / "tools/graph/build_graph.py"), ".", "--rev", base,
                  "--out", str(candidate_root / "base-graph.json")],
        "verify": ["python3", str(tools_root / "tools/graph/verify.py"), "--repo", ".", "--diff", f"{base}..{head}",
                   "--graph", str(candidate_root / "base-graph.json"), "--out",
                   str(candidate_root / "receipt.json"), "--json", "--workdir",
                   str(candidate_root / "work"), "--verifier-out", str(candidate_root / "verifier-out"),
                   "--phase-log", str(candidate_root / "phase.jsonl")],
    }
    explanation_path = candidate_root / "empty-impact-explanation.json"
    explanation_digest_path = candidate_root / "empty-impact-explanation.sha256"
    explanation_input = None
    explanation_present = (explanation_path.exists() or explanation_path.is_symlink()
                           or explanation_digest_path.exists() or explanation_digest_path.is_symlink())
    if explanation_present:
        if (explanation_path.is_symlink() or not explanation_path.is_file()
                or explanation_digest_path.is_symlink() or not explanation_digest_path.is_file()):
            raise ValueError("current-source empty-impact explanation input is missing or unsafe")
        explanation_raw = explanation_path.read_bytes()
        if len(explanation_raw) > 65536:
            raise ValueError("current-source empty-impact explanation input exceeds the size limit")
        expected_digest = sha256(explanation_raw)
        if explanation_digest_path.read_text(encoding="ascii") != expected_digest + "\n":
            raise ValueError("current-source empty-impact explanation bytes differ from their pre-verify digest")
        try:
            explanation_input = json.loads(explanation_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError("current-source empty-impact explanation input is not UTF-8 JSON") from None
        expected_scripts["verify"].extend(["--empty-impact-explanation", str(explanation_path)])
    if repo_name == "Arcanada-one/auth-arcana":
        expected_scripts["verify"].extend(["--root-typecheck-ci-root", str(candidate_root / "ci-typecheck")])
    commands = []
    for name in ("build", "verify"):
        argv_path = candidate_root / f"{name}.argv.nul"
        if argv_path.is_symlink() or not argv_path.is_file():
            if name == "verify" and not (candidate_root / "verify.pid").exists():
                continue
            raise ValueError(f"current-source {name} argv capture is missing")
        raw_argv = argv_path.read_bytes()
        if not raw_argv.endswith(b"\0"):
            raise ValueError(f"current-source {name} argv capture is incomplete")
        argv = [part.decode("utf-8") for part in raw_argv[:-1].split(b"\0")]
        if argv != expected_scripts[name]:
            raise ValueError(f"current-source {name} argv differs from the supported invocation")
        cwd_path = candidate_root / f"{name}.cwd"
        start_path = candidate_root / f"{name}-start.utc"
        end_path = candidate_root / f"{name}-end.utc"
        pid_path = candidate_root / f"{name}.pid"
        exit_path = candidate_root / f"{name}.exit"
        refs = {}
        for item in (cwd_path, start_path, end_path, pid_path, exit_path,
                     candidate_root / f"{name}.stdout", candidate_root / f"{name}.stderr"):
            if item.is_symlink() or not item.is_file():
                raise ValueError(f"current-source {name} capture is missing: {item.name}")
            refs[item.name] = file_ref(item, evidence_root)
        cwd = cwd_path.read_text(encoding="utf-8").strip()
        if cwd != str(repo.resolve()):
            raise ValueError(f"current-source {name} cwd differs from the exact candidate repository")
        pid_text = pid_path.read_text(encoding="ascii").strip()
        exit_text = exit_path.read_text(encoding="ascii").strip()
        if not pid_text.isdigit() or not exit_text.isdigit():
            raise ValueError(f"current-source {name} PID/exit capture is malformed")
        start = start_path.read_text(encoding="ascii").strip()
        end = end_path.read_text(encoding="ascii").strip()
        started = datetime.fromisoformat(start.replace("Z", "+00:00"))
        ended = datetime.fromisoformat(end.replace("Z", "+00:00"))
        if started.tzinfo is None or ended.tzinfo is None or ended < started:
            raise ValueError(f"current-source {name} timestamps are invalid")
        artifacts = {}
        for label, filename in (("base_graph", "base-graph.json"),) if name == "build" else (
                ("raw_candidate_car", "receipt.json"), ("phase_log", "phase.jsonl")):
            item = candidate_root / filename
            if item.is_file() and not item.is_symlink():
                artifacts[label] = file_ref(item, evidence_root)
        if name == "verify" and explanation_input is not None:
            receipt_path = candidate_root / "receipt.json"
            if receipt_path.is_symlink() or not receipt_path.is_file():
                raise ValueError("current-source verifier did not retain a regular raw CAR for its explanation input")
            try:
                receipt_doc = json.loads(receipt_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                raise ValueError("current-source raw CAR is unavailable for explanation input binding") from None
            explanation_doc = (receipt_doc.get("empty_impact_explanation")
                               if isinstance(receipt_doc, dict) else None)
            binding = explanation_doc.get("binding") if isinstance(explanation_doc, dict) else None
            if not isinstance(binding, dict) or binding.get("input") != explanation_input:
                raise ValueError("current-source explanation bytes do not match the native raw CAR binding")
            artifacts["explanation_input"] = file_ref(explanation_path, evidence_root)
            artifacts["explanation_input_sha256"] = file_ref(explanation_digest_path, evidence_root)
        commands.append({"id": name, "argv": argv, "cwd": cwd, "pid": int(pid_text),
                         "start_utc": start, "end_utc": end, "exit_code": int(exit_text),
                         "capture_refs": {"argv": file_ref(argv_path, evidence_root),
                                          "cwd": refs[cwd_path.name], "pid": refs[pid_path.name],
                                          "start": refs[start_path.name], "end": refs[end_path.name],
                                          "exit": refs[exit_path.name]},
                         "stdout": refs[f"{name}.stdout"], "stderr": refs[f"{name}.stderr"],
                         "artifacts": artifacts})
    interpreter_path = Path(shutil.which("python3") or "").resolve(strict=True)
    interpreter_raw = interpreter_path.read_bytes()
    return {
        "kind": "ProgramCurrentSourceCLIOutcome/v1",
        "subject": {"repository": repo_name, "base": base, "head": head,
                    "tree": git(repo, "rev-parse", f"{head}^{{tree}}"),
                    "changed_paths": git(repo, "diff", "--name-only", f"{base}..{head}").splitlines()},
        "program_source": program_source,
        "working_tree": "clean_at_capture",
        "interpreter": {"path": str(interpreter_path), "sha256": sha256(interpreter_raw)},
        "commands": commands,
        "raw_candidate_car": file_ref(candidate_root / "receipt.json", evidence_root)
        if (candidate_root / "receipt.json").is_file() and not (candidate_root / "receipt.json").is_symlink()
        else None,
        "admission": "not_claimed_by_process_outcome",
    }


def materialize_fixture(tools_root: Path, fixture: Path) -> dict:
    graph_dir = str(tools_root / "tools/graph")
    if graph_dir not in sys.path:
        sys.path.insert(0, graph_dir)
    namespace = runpy.run_path(str(tools_root / "tools/graph/test_source_input_contract.py"))
    source_path = namespace["INPUT_PATH"]
    schema_path = namespace["SCHEMA_PATH"]
    consumer_path = namespace["CONSUMER_PATH"]
    control_path = namespace["CONTROL_PATH"]
    source = b'{"value":3}\n'
    schema = namespace["SCHEMA_SOURCE"]
    consumer = namespace["CONSUMER_SOURCE"]
    control = namespace["CONTROL_SOURCE"]
    manifest = namespace["make_contract"](source, consumer, schema=schema)
    interpreter = Path(shutil.which("python3") or sys.executable).resolve()
    interpreter_sha = sha256(interpreter.read_bytes())
    for entry in manifest["inputs"]:
        for control_row in entry["controls"]:
            control_row["interpreter_sha256"] = interpreter_sha

    def dump_manifest(value: dict) -> bytes:
        return (json.dumps(value, separators=(",", ":")) + "\n").encode()

    write_bytes(fixture, source_path, source)
    write_bytes(fixture, schema_path, schema)
    write_bytes(fixture, consumer_path, consumer)
    write_bytes(fixture, control_path, control)
    write_bytes(fixture, ".arcana/source-inputs.json", dump_manifest(manifest))
    subprocess.run(["git", "init", "--initial-branch=main", str(fixture)], check=True,
                   capture_output=True, text=True)

    def fixture_git(*args: str) -> str:
        result = subprocess.run(["git", "-C", str(fixture), *args], check=True,
                                capture_output=True, text=True)
        return result.stdout.strip()

    fixture_git("config", "user.name", "Arcanada")
    fixture_git("config", "user.email", "arcanada-stage-fixture@localhost")
    fixture_git("add", "-A")
    subprocess.run(["git", "-C", str(fixture), "-c", "commit.gpgsign=false", "commit", "-m",
                    "fixture: bind source, consumer, and executable controls"], check=True,
                   capture_output=True, text=True)
    base = fixture_git("rev-parse", "HEAD")

    source = b'{"value":4}\n'
    write_bytes(fixture, source_path, source)
    manifest["inputs"][0]["source_sha256"] = sha256(source)
    write_bytes(fixture, ".arcana/source-inputs.json", dump_manifest(manifest))
    fixture_git("add", source_path, ".arcana/source-inputs.json")
    subprocess.run(["git", "-C", str(fixture), "-c", "commit.gpgsign=false", "commit", "-m",
                    "fixture: update source bytes with exact declaration pin"], check=True,
                   capture_output=True, text=True)
    head = fixture_git("rev-parse", "HEAD")
    return {
        "repository_role": "temporary synthetic source-input fixture",
        "base": base,
        "head": head,
        "tree": fixture_git("rev-parse", f"{head}^{{tree}}"),
        "changed_paths": fixture_git("diff", "--name-only", f"{base}..{head}").splitlines(),
        "python3_sha256": interpreter_sha,
        "source": {"path": source_path, "sha256": sha256(source)},
        "schema": {"path": schema_path, "sha256": sha256(schema)},
        "consumer": {"path": consumer_path, "sha256": sha256(consumer)},
        "control": {"path": control_path, "sha256": sha256(control)},
        "manifest": {"path": ".arcana/source-inputs.json",
                     "sha256_at_head": sha256((fixture / ".arcana/source-inputs.json").read_bytes())},
    }


def run_step(name: str, argv: list[str], cwd: Path, output_root: Path,
             evidence_root: Path, artifacts: dict[str, Path]) -> dict:
    start = utc_now()
    proc = subprocess.run(argv, cwd=cwd, capture_output=True,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    end = utc_now()
    stdout = proc.stdout
    stderr = proc.stderr
    (output_root / f"{name}.stdout").write_bytes(stdout)
    (output_root / f"{name}.stderr").write_bytes(stderr)
    return {
        "id": name,
        "argv": argv,
        "cwd": str(cwd.resolve()),
        "cwd_role": "candidate repository",
        "start_utc": start,
        "end_utc": end,
        "exit_code": proc.returncode,
        "stdout": {"path": (output_root / f"{name}.stdout").relative_to(evidence_root).as_posix(),
                   "sha256": sha256(stdout), "bytes": len(stdout)},
        "stderr": {"path": (output_root / f"{name}.stderr").relative_to(evidence_root).as_posix(),
                   "sha256": sha256(stderr), "bytes": len(stderr)},
        "artifacts": {
            label: ({"path": path.relative_to(evidence_root).as_posix(),
                     "sha256": sha256(path.read_bytes()), "bytes": path.stat().st_size}
                    if path.is_file() else None)
            for label, path in artifacts.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--repo-name", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--tools-root", type=Path,
                        help="Program source root (self-repository) or the caller's vendored signed bundle")
    parser.add_argument("--candidate-root", type=Path,
                        help="same-run raw current-source build/verify capture directory")
    args = parser.parse_args()

    repo = args.repo.resolve(strict=True)
    tools_root_argument = args.tools_root or repo
    if tools_root_argument.is_symlink():
        raise ValueError("Program tools root cannot be a symlink")
    tools_root = tools_root_argument.resolve(strict=True)
    out = args.out.resolve()
    workdir = args.workdir.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)
    if out.exists() or out.is_symlink():
        raise ValueError("result output already exists")
    evidence_root = out.parent
    started = utc_now()
    result = {
        "kind": "ProgramStageUserpath/v1",
        "started_at_utc": started,
        "completed_at_utc": None,
        "exit_code": None,
        "candidate": {"repository": args.repo_name, "base": args.base, "head": args.head, "tree": None},
        "fixture": None,
        "fixture_repository": None,
        "program_source": None,
        "candidate_cli_outcome": None,
        "runner_invocation": {"argv": [str(Path(sys.executable).resolve()), *sys.argv],
                              "cwd": str(Path.cwd().resolve())},
        "steps": [],
        "fixture_gate": None,
        "verdict": "refused",
        "refusal": None,
        "candidate_admission": "not_measured_by_fixture_gate",
        "interpreter": {"path": str(Path(sys.executable).resolve()),
                        "sha256": sha256(Path(sys.executable).resolve().read_bytes())},
    }
    try:
        if workdir != evidence_root and evidence_root not in workdir.parents:
            raise ValueError("workdir must be contained by the result directory")
        actual_head = git(repo, "rev-parse", "HEAD")
        if actual_head != args.head:
            raise ValueError("candidate checkout HEAD differs from the explicit head")
        dirty = git(repo, "status", "--porcelain")
        if dirty:
            raise ValueError("candidate checkout is dirty; source identity is not attributable")
        if (not args.repo_name or not re.fullmatch(r"[0-9a-f]{40}", args.base)
                or not re.fullmatch(r"[0-9a-f]{40}", args.head)):
            raise ValueError("repository/base/head binding is malformed")
        if subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", args.base, args.head],
                          capture_output=True).returncode != 0:
            raise ValueError("explicit candidate base is not an ancestor of head")
        result["candidate"]["tree"] = git(repo, "rev-parse", f"{args.head}^{{tree}}")
        git(repo, "cat-file", "-e", f"{args.base}^{{commit}}")
        candidate_paths = git(repo, "diff", "--name-only", f"{args.base}..{args.head}").splitlines()
        result["candidate"]["changed_paths"] = candidate_paths
        if tools_root != repo and repo not in tools_root.parents:
            raise ValueError("Program tools root must be the candidate checkout or its contained vendored bundle")
        program_source = program_source_binding(repo, args.repo_name, args.head, tools_root)
        result["program_source"] = program_source

        if args.candidate_root is not None:
            result["candidate_cli_outcome"] = candidate_cli_outcome(
                repo, args.repo_name, args.base, args.head, args.candidate_root, evidence_root,
                program_source, tools_root)

        output_root = workdir / "steps"
        output_root.mkdir(parents=True, exist_ok=True)
        fixture = workdir / "fixture-repository"
        if fixture.exists() or fixture.is_symlink():
            raise ValueError("temporary fixture destination already exists")
        fixture.mkdir()
        fixture_tuple = materialize_fixture(tools_root, fixture)
        result["fixture"] = fixture_tuple
        result["fixture_repository"] = fixture.relative_to(evidence_root).as_posix()
        graph = output_root / "fixture-base-graph.json"
        impact = output_root / "fixture-impact.json"
        receipt = output_root / "fixture-raw-car.json"
        gate_out = output_root / "fixture-gate.json"
        verify_work = output_root / "verify-work"
        verifier_out = output_root / "verifier-out"
        argv_sets = (
            ("build", [sys.executable, str(tools_root / "tools/graph/build_graph.py"), str(fixture),
                       "--rev", fixture_tuple["base"], "--out", str(graph)],
             {"base_graph": graph}),
            ("impact", [sys.executable, str(tools_root / "tools/graph/impact.py"), "--graph", str(graph),
                        "--repo", str(fixture), "--diff",
                        f"{fixture_tuple['base']}..{fixture_tuple['head']}", "--json", "--out", str(impact)],
             {"impact": impact}),
            ("verify", [sys.executable, str(tools_root / "tools/graph/verify.py"), "--repo", str(fixture),
                        "--diff", f"{fixture_tuple['base']}..{fixture_tuple['head']}", "--graph", str(graph),
                        "--out", str(receipt), "--json", "--workdir", str(verify_work),
                        "--verifier-out", str(verifier_out), "--phase-log", str(output_root / "phase.jsonl")],
             {"raw_fixture_car": receipt, "phase_log": output_root / "phase.jsonl"}),
            ("gate", [sys.executable, str(tools_root / "tools/graph/admit_change.py"), "gate", "--repo", str(fixture),
                      "--range", f"{fixture_tuple['base']}..{fixture_tuple['head']}", "--receipt", str(receipt),
                      "--out", str(gate_out), "--json", "--workdir", str(output_root / "gate-work")],
             {"fixture_gate": gate_out}),
        )
        for name, argv, artifacts in argv_sets:
            record = run_step(name, argv, repo, output_root, evidence_root, artifacts)
            result["steps"].append(record)
            if record["exit_code"] != 0:
                result["refusal"] = f"{name} exited {record['exit_code']}"
                break
        if gate_out.is_file():
            gate_doc = json.loads(gate_out.read_text(encoding="utf-8"))
            result["fixture_gate"] = {
                "subject_role": "temporary synthetic fixture only",
                "repository": gate_doc.get("repo", {}).get("name") if isinstance(gate_doc.get("repo"), dict) else None,
                "range": {"base": (gate_doc.get("range") or {}).get("base"),
                          "head": (gate_doc.get("range") or {}).get("head")},
                "verdict": gate_doc.get("verdict"),
                "exit_code": gate_doc.get("exit_code"),
                "reason_codes": gate_doc.get("reason_codes", []),
                "raw_receipt_sha256": sha256(receipt.read_bytes()) if receipt.is_file() else None,
                "output": {"path": gate_out.relative_to(evidence_root).as_posix(),
                           "sha256": sha256(gate_out.read_bytes()),
                           "bytes": gate_out.stat().st_size},
            }
            if gate_doc.get("verdict") != "admit" or gate_doc.get("exit_code") != 0:
                result["refusal"] = "fixture ordinary gate did not admit the exact fixture range"
        if result["refusal"] is None and len(result["steps"]) == 4:
            result["verdict"] = "completed"
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, json.JSONDecodeError) as exc:
        result["refusal"] = f"{type(exc).__name__}: {exc}"
    result["completed_at_utc"] = utc_now()
    result["exit_code"] = 0 if result["verdict"] == "completed" else 1
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(out), "verdict": result["verdict"], "refusal": result["refusal"]},
                     sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
