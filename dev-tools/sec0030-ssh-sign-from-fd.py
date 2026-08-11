#!/usr/bin/env python3
"""Sign a governance manifest from a sealed, non-dumpable Linux memfd."""

import argparse
import ctypes
import fcntl
import os
from pathlib import Path
import resource
import subprocess
import sys
from typing import NoReturn


PR_SET_DUMPABLE = 4
MAX_PRIVATE_KEY_BYTES = 64 * 1024


def fail(message: str) -> NoReturn:
    raise SystemExit(f"SEC0030_MEMORY_SIGN_FAIL: {message}")


def read_bounded(descriptor: int) -> bytearray:
    value = bytearray()
    while True:
        chunk = os.read(descriptor, 8192)
        if not chunk:
            break
        value.extend(chunk)
        if len(value) > MAX_PRIVATE_KEY_BYTES:
            fail("private key exceeds the size limit")
    if not value:
        fail("private key is empty")
    return value


def public_fields(value: bytes) -> tuple[bytes, bytes]:
    fields = value.strip().split()
    if len(fields) < 2:
        fail("public key is malformed")
    return fields[0], fields[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-fd", type=int, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if args.key_fd < 3:
        fail("private key must arrive on a non-standard file descriptor")
    if not args.public_key.is_file() or not args.manifest.is_file():
        fail("public key or manifest is unavailable")
    if sys.platform != "linux" or not hasattr(os, "memfd_create"):
        fail("sealed memfd signing requires a Linux operator host")

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        fail("could not disable process dumpability")

    secret = read_bounded(args.key_fd)
    descriptor = os.memfd_create("sec0030-governance-key", os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, secret)
        secret[:] = b"\0" * len(secret)
        del secret
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE,
        )
        key_reference = f"/proc/self/fd/{descriptor}"
        derived = subprocess.run(
            ["ssh-keygen", "-y", "-f", key_reference],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(descriptor,),
        ).stdout
        if public_fields(derived) != public_fields(args.public_key.read_bytes()):
            fail("private key does not match the pinned public key")
        signature_path = Path(f"{args.manifest}.sig")
        if signature_path.exists():
            fail("signature output already exists")
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-Y",
                "sign",
                "-f",
                key_reference,
                "-n",
                "sec0030-governance",
                str(args.manifest),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(descriptor,),
        )
        if not signature_path.is_file():
            fail("ssh-keygen did not create a signature")
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    main()
