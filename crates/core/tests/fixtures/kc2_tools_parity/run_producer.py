#!/usr/bin/env python3
"""Run corpus.json through talomnia's kc2_tools_profile.read_profile_contract.

Usage: run_producer.py <talomnia ontology dir (holds src/ and schemas/)> corpus.json > producer.json

Read-only on talomnia: it imports the producer-side reader from the given checkout (pin
b3fe119921357964d68d77980b10b9f80135d831) and writes nothing there.
Each case is wrapped as ONE canonical whole-document byte string (what the producer-side
reader consumes) with the raw digested halves inserted verbatim.
"""
import hashlib
import json
import sys
from pathlib import Path

ont = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ont / "src"))
sys.dont_write_bytecode = True
import kc2_tools_profile as kp  # noqa: E402

corpus = json.load(open(sys.argv[2]))
out = {}
for c in corpus["cases"]:
    if c.get("aras_only"):
        out[c["id"]] = {"result": "N/A"}
        continue
    pre = c["preimage"]
    # split the two raw halves with the same first-value rule as the consumer would not know:
    # the generator emits body then manifest, so split via a raw JSON decoder
    dec = json.JSONDecoder()
    try:
        _, end = dec.raw_decode(pre)
    except ValueError:
        out[c["id"]] = {"result": "N/A", "why": "preimage is not two JSON values"}
        continue
    body_raw, man_raw = pre[:end], pre[end:]
    digest = c.get("digest_override") or "sha256:" + hashlib.sha256(pre.encode()).hexdigest()
    parts = [f'"body":{body_raw}', f'"closure_manifest":{man_raw}', f'"contract_digest":"{digest}"']
    if c["hint_kind"] is not None:
        parts.append(f'"kind":{json.dumps(c["hint_kind"])}')
    if c["hint_schema_version"] is not None:
        parts.append(f'"schema_version":{json.dumps(c["hint_schema_version"])}')
    raw = ("{" + ",".join(parts) + "}").encode()
    kwargs = {"schema_dir": ont / "schemas"}
    if c.get("pin") == "wrong-blob":
        pinned = kp.schema_blob_ids(ont / "schemas")
        first = sorted(pinned)[0]
        pinned[first] = "0" * 40
        kwargs["pinned_schema_blobs"] = pinned
    r = kp.read_profile_contract(raw, **kwargs)
    out[c["id"]] = {"result": "ACCEPT" if r.ok else "REFUSE", "code": r.code,
                    "allow": list(r.allow) if r.allow is not None else None, "detail": r.detail[:200]}
json.dump(out, sys.stdout, indent=1, sort_keys=True)
print()
