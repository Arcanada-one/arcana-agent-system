#!/usr/bin/env python3
"""AUP-MIG-013 rebuild0 -- cross-host rebuild, handoff and evidence parity.

    rebuild.py rebuild --twice ...             -> one package digest + handoff envelope
    rebuild.py handoff-canary ...               -> exactly one idempotent effect (DEVS side)
    rebuild.py verify-handoff ...               -> offline manifest validation + target readback (Mac stand-in)
    rebuild.py reconcile ...                    -> terminal result from an UNKNOWN, no repeated effect
    rebuild.py --selftest [--out DIR]           -> hermetic fixture/mutation/rule battery

stdlib only. Real host effects only ever touch a task-owned rehearsal
target the caller names with ``--target`` -- never ``datarim-history``,
``aup``, or any ``datarim/`` path.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import core  # noqa: E402
import fixtures  # noqa: E402
from backend import RehearsalTarget  # noqa: E402
from package import HandoffEnvelope, JobPackageInputs, PortabilityError, build_envelope, build_package  # noqa: E402


def _write(out: str | None, payload: dict) -> None:
    text = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text)
    print(text, end="")


def cmd_rebuild(args: argparse.Namespace) -> int:
    inputs = JobPackageInputs(
        kc2_revision=args.kc2_revision,
        muneral_work_revision=args.muneral_revision,
        policy_pin=args.policy_pin,
        model_pin=args.model_pin,
        tool_pin=args.tool_pin,
        audience=args.audience,
        clock=args.clock,
        random_seed=args.seed,
    )
    try:
        if args.twice:
            result = core.twice_check(inputs)
            pkg = result["package"]
            if result["verdict"] != "PASS":
                _write(args.out, {"schema": "ReadinessReceipt/v1", "verdict": result["verdict"], "trace": result["trace"]})
                return 1
        else:
            pkg = build_package(inputs)
        envelope = build_envelope(pkg, expiry=args.expiry)
    except PortabilityError as e:
        _write(args.out, {"schema": "ReadinessReceipt/v1", "verdict": "NONPORTABLE", "findings": e.findings})
        return 1
    receipt = {
        "schema": "ReadinessReceipt/v1",
        "verdict": "PASS",
        "manifest": pkg.to_dict(),
        "envelope": envelope.to_dict(),
        "twice_checked": bool(args.twice),
    }
    _write(args.out, receipt)
    return 0


def cmd_handoff_canary(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text())
    target = RehearsalTarget(Path(args.target))
    result = core.handoff_canary(
        target, args.idempotency_key, {"digest": manifest["digest"], "manifest_path": args.manifest},
        simulate_network_loss=args.simulate_network_loss,
    )
    _write(args.out, {"schema": "MigHandoffCanaryResult/v1", "status": result.status, "reason": result.reason, "idempotency_key": result.idempotency_key})
    return 0 if result.status in ("APPLIED", "ALREADY_APPLIED") else 2


def cmd_verify_handoff(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text())
    envelope = json.loads(Path(args.envelope).read_text())
    target = RehearsalTarget(Path(args.target)) if args.target else None
    result = core.verify_handoff(
        manifest, envelope, expected_audience=args.expected_audience, target=target,
        idempotency_key=args.idempotency_key, trace_claims_applied=args.trace_claims_applied,
    )
    _write(args.out, {"schema": "MigHandoffVerifyResult/v1", **{k: result[k] for k in ("verdict", "reasons", "not_measured")}})
    return 0 if result["verdict"] == "PASS" else 1


def cmd_reconcile(args: argparse.Namespace) -> int:
    target = RehearsalTarget(Path(args.target))
    result = core.reconcile(target, args.idempotency_key)
    _write(args.out, {"schema": "MigReconcileResult/v1", "status": result.status, "reason": result.reason})
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    report = fixtures.run_selftest()
    if args.out:
        outdir = Path(args.out)
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "selftest.json").write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    print(f"selftest {report['passed']}/{report['total']} {'PASS' if report['all_pass'] else 'FAIL'}")
    if not report["all_pass"]:
        for c in report["checks"]:
            if not c["ok"]:
                print(f"  FAIL {c['name']}: {c['detail']}")
    return 0 if report["all_pass"] else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="AUP-MIG-013 rebuild0")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--out")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("rebuild")
    r.add_argument("--twice", action="store_true")
    r.add_argument("--kc2-revision", required=True)
    r.add_argument("--muneral-revision", required=True)
    r.add_argument("--policy-pin", required=True)
    r.add_argument("--model-pin", required=True)
    r.add_argument("--tool-pin", required=True)
    r.add_argument("--audience", required=True)
    r.add_argument("--clock", required=True)
    r.add_argument("--seed", type=int, required=True)
    r.add_argument("--expiry", required=True)
    r.add_argument("--out")
    r.set_defaults(func=cmd_rebuild)

    hc = sub.add_parser("handoff-canary")
    hc.add_argument("--manifest", required=True)
    hc.add_argument("--target", required=True)
    hc.add_argument("--idempotency-key", required=True)
    hc.add_argument("--simulate-network-loss", action="store_true")
    hc.add_argument("--out")
    hc.set_defaults(func=cmd_handoff_canary)

    vh = sub.add_parser("verify-handoff")
    vh.add_argument("--manifest", required=True)
    vh.add_argument("--envelope", required=True)
    vh.add_argument("--expected-audience", required=True)
    vh.add_argument("--target")
    vh.add_argument("--idempotency-key", required=True)
    vh.add_argument("--trace-claims-applied", action="store_true")
    vh.add_argument("--out")
    vh.set_defaults(func=cmd_verify_handoff)

    rc = sub.add_parser("reconcile")
    rc.add_argument("--target", required=True)
    rc.add_argument("--idempotency-key", required=True)
    rc.add_argument("--out")
    rc.set_defaults(func=cmd_reconcile)

    args = p.parse_args(argv)
    if args.selftest:
        return cmd_selftest(args)
    if not args.cmd:
        p.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
