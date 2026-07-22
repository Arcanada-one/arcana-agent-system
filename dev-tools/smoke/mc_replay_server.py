#!/usr/bin/env python3
"""Minimal one-purpose loopback Model-Connector replay responder.

Binds `127.0.0.1:0` (ephemeral, never exposed), prints the chosen port as
`PORT=<n>` on the first stdout line, then serves the canned body from
`MC_BODY_FILE` with HTTP status `MC_STATUS` for every `POST /execute`. A bare
`GET /` is a 200 readiness probe. No new Cargo/network dependency — stdlib
only. Used by `arcana-smoke.sh` S2/S3 so the gate does not need a live mesh.
"""

import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MC_STATUS = int(os.environ.get("MC_STATUS", "201"))
MC_BODY_FILE = os.environ.get("MC_BODY_FILE", "")

_BODY = b""
if MC_BODY_FILE:
    with open(MC_BODY_FILE, "rb") as fh:
        _BODY = fh.read()


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (stdlib naming)
        self._reply(200, b'{"ready":true}')

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        self._reply(MC_STATUS, _BODY)

    def log_message(self, *_args):  # silence request logging
        pass


def main():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    print("PORT=%d" % server.server_address[1], flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
