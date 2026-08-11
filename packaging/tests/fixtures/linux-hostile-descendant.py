#!/usr/bin/env python3
"""Create a setsid/double-fork descendant and continuously advance a marker."""

import json
import os
from pathlib import Path
import sys
import time


def proc_identity(pid: int) -> dict[str, object]:
    stat_fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
    cgroup_lines = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines()
    unified = [line.split("::", 1)[1] for line in cgroup_lines if "::" in line]
    if len(unified) != 1:
        raise RuntimeError("unified cgroup identity unavailable")
    return {"pid": pid, "start_time": int(stat_fields[21]), "cgroup": unified[0]}


def try_cgroup_escape(cgroup: str) -> list[dict[str, str]]:
    targets = ["/sys/fs/cgroup/cgroup.procs"]
    parent = str(Path("/sys/fs/cgroup") / cgroup.lstrip("/")).rsplit("/", 1)[0]
    targets.append(f"{parent}/cgroup.procs")
    results: list[dict[str, str]] = []
    for target in targets:
        try:
            Path(target).write_text(f"{os.getpid()}\n", encoding="ascii")
        except OSError as error:
            results.append({"target": target, "result": "denied", "errno": str(error.errno)})
        else:
            results.append({"target": target, "result": "succeeded", "errno": "0"})
    return results


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def descendant(root: Path) -> None:
    identity = proc_identity(os.getpid())
    identity["escape_attempts"] = try_cgroup_escape(str(identity["cgroup"]))
    write_json(root / "descendant.json", identity)
    marker = root / "marker"
    counter = 0
    while True:
        counter += 1
        marker.write_text(f"{counter}\n", encoding="ascii")
        time.sleep(0.05)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: linux-hostile-descendant.py OUTPUT_DIRECTORY")
    root = Path(sys.argv[1])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.setpgid(0, 0)
    except PermissionError:
        if os.getpgrp() != os.getpid():
            raise
    write_json(root / "leader.json", proc_identity(os.getpid()))

    child = os.fork()
    if child == 0:
        os.setsid()
        grandchild = os.fork()
        if grandchild == 0:
            descendant(root)
        os._exit(0)
    os.waitpid(child, 0)
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
