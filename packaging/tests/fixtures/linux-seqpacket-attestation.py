#!/usr/bin/env python3
"""Exercise per-message credentials and AppArmor on an inherited seqpacket FD."""

import argparse
import os
import socket
import struct
import subprocess
from collections.abc import Sequence


SCM_SECURITY = 0x03


def connect(listener: socket.socket, address: bytes) -> tuple[socket.socket, socket.socket]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.connect(address)
    accepted, _ = listener.accept()
    accepted.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    if hasattr(socket, "SO_PASSSEC"):
        accepted.setsockopt(socket.SOL_SOCKET, socket.SO_PASSSEC, 1)
    return client, accepted


def sender(profile: str, helper: str, descriptor: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        ["aa-exec", "-p", profile, "--", helper, str(descriptor)],
        pass_fds=(descriptor,),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def reap_process(process: subprocess.Popen[bytes], timeout: float = 1.0) -> bool:
    reaped = True
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                reaped = False
    for stream in (process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()
    return reaped


def communicate_bounded(
    process: subprocess.Popen[bytes], timeout: float = 5.0
) -> tuple[bytes, bytes]:
    try:
        return process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        reap_process(process)
        raise SystemExit(f"sender timed out after {timeout:g}s") from error


def cleanup(children: Sequence[subprocess.Popen[bytes]], sockets: Sequence[socket.socket]) -> None:
    failed = False
    for child in reversed(children):
        try:
            failed = not reap_process(child) or failed
        except OSError:
            failed = True
    for descriptor in reversed(sockets):
        try:
            descriptor.close()
        except OSError:
            failed = True
    if failed:
        raise RuntimeError("attestation fixture cleanup could not reap every child and socket")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", required=True)
    parser.add_argument("--trusted-profile", required=True)
    parser.add_argument("--denied-profile", required=True)
    parser.add_argument("--address", required=True)
    args = parser.parse_args()

    address = b"\0" + args.address.encode("ascii")
    sockets: list[socket.socket] = []
    children: list[subprocess.Popen[bytes]] = []
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        sockets.append(listener)
        listener.bind(address)
        listener.listen(2)

        trusted_client, trusted_server = connect(listener, address)
        sockets.extend((trusted_client, trusted_server))
        trusted_server.settimeout(2)
        trusted = sender(args.trusted_profile, args.helper, trusted_client.fileno())
        children.append(trusted)
        trusted_client.close()
        data, ancillary, flags, _ = trusted_server.recvmsg(256, 1024)
        _, trusted_stderr = communicate_bounded(trusted)
        if trusted.returncode != 0:
            raise SystemExit(f"trusted sender failed generically: status={trusted.returncode}")
        if data != b"sec0030-attestation":
            raise SystemExit("trusted payload mismatch")
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise SystemExit("trusted message metadata was truncated")

        credentials = [
            value
            for level, kind, value in ancillary
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
        ]
        if len(credentials) != 1:
            raise SystemExit("expected exactly one SCM_CREDENTIALS record")
        credential_pid, credential_uid, credential_gid = struct.unpack("3i", credentials[0])
        if credential_pid != trusted.pid:
            raise SystemExit("SCM_CREDENTIALS did not identify the inherited-FD sender")
        if credential_uid != os.getuid() or credential_gid != os.getgid():
            raise SystemExit("SCM_CREDENTIALS user identity mismatch")
        security_labels = [
            value
            for level, kind, value in ancillary
            if level == socket.SOL_SOCKET and kind == SCM_SECURITY
        ]
        ancillary_status = "present" if security_labels else "absent"
        trusted_server.close()

        denied_client, denied_server = connect(listener, address)
        sockets.extend((denied_client, denied_server))
        denied_server.settimeout(0.5)
        denied = sender(args.denied_profile, args.helper, denied_client.fileno())
        children.append(denied)
        denied_client.close()
        try:
            denied_data, _, _, _ = denied_server.recvmsg(256, 1024)
        except TimeoutError:
            pass
        else:
            communicate_bounded(denied)
            if denied_data == b"sec0030-attestation" and denied.returncode == 0:
                print(
                    "SEC0030_LINUX_ATTESTATION_BLOCKED "
                    "fd_handoff_wrong_label=delivered "
                    f"scm_credentials=actual_sender credential_label_ancillary={ancillary_status}"
                )
                raise SystemExit(78)
            raise SystemExit("wrong-label sender unexpectedly delivered a packet with invalid state")
        _, denied_stderr = communicate_bounded(denied)
        if denied.returncode == 0:
            raise SystemExit("wrong-label sender unexpectedly reported success")
        if denied.returncode != 13:
            raise SystemExit(f"wrong-label sender failed generically: status={denied.returncode}")
        if trusted_stderr or denied_stderr:
            raise SystemExit("sender emitted unexpected diagnostics")
        denied_server.close()

        print(
            "SEC0030_LINUX_ATTESTATION_BLOCKED "
            f"scm_credentials_pid={credential_pid} fd_handoff=actual_sender "
            f"apparmor_wrong_label=denied credential_label_ancillary={ancillary_status} "
            "receiver_label_authorization=unimplemented"
        )
        raise SystemExit(78)
    finally:
        cleanup(children, sockets)


if __name__ == "__main__":
    main()
