#!/usr/bin/env python3
"""Generate corpus.json: the shared fixture corpus for the ARAS-vs-talomnia strict-reader parity run.

Every case is SYNTHETIC. A case is the raw digested preimage text (body || closure_manifest),
the envelope hints ARAS receives outside the digest, and the profile the caller requested.
Producer side (run_producer.py) wraps the same raw halves into one canonical whole-document
byte string and feeds it to talomnia's kc2_tools_profile.read_profile_contract.

Usage: generate_corpus.py > corpus.json
"""
import json
import sys

P = "arcanada-kc2-tools/v1"
D0 = "sha256:" + "0" * 64
D1 = "sha256:" + "1" * 64


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def body(tools="default", **over):
    b = {
        "canonicalization": {"name": "json-c14n-pilot", "version": "v1"},
        "conflict_records": [],
        "embedded": [],
        "envelope_unverified": [],
        "projection": [
            {"assertions": ["synthetic assertion"],
             "source": {"content_digest": D1, "revision_id": "synthetic-pin@r1"}}
        ],
        "quarantined": [],
        "reduction": "closure-only",
        "refusals": [],
        "scope": {"project": "synthetic"},
        "task": {"goal": "synthetic goal"},
        "verdict": "T",
        "verdicts": {},
    }
    if tools == "default":
        tools = {"profile": P, "allow": ["read", "write"]}
    if tools is not None:
        b["tools"] = tools
    for k, v in over.items():
        if v is ABSENT:
            b.pop(k, None)
        else:
            b[k] = v
    return b


ABSENT = object()


def manifest(**over):
    m = {"revisions": [["synthetic-pin@r1", D1]], "snapshot_digest": D0}
    for k, v in over.items():
        if v is ABSENT:
            m.pop(k, None)
        else:
            m[k] = v
    return m


CASES = []


def add(cid, group, pre, *, schema_version=P, kind="KnowledgeContract", requested=P,
        aras_only=False, producer_only=False, note="", **extra):
    c = {"id": cid, "group": group, "preimage": pre, "hint_schema_version": schema_version,
         "hint_kind": kind, "requested": requested, "aras_only": aras_only,
         "producer_only": producer_only, "note": note}
    c.update(extra)
    CASES.append(c)


def std(b, m=None):
    return canon(b) + canon(m if m is not None else manifest())


def tools(allow, **kw):
    t = {"profile": P, "allow": allow}
    t.update(kw)
    return t


# ---- positives ----
add("POS-read-write", "positive", std(body()))
add("POS-deny-all", "positive", std(body({"profile": P, "allow": []}), manifest(revisions=[])))
add("POS-all-four", "positive", std(body({"profile": P, "allow": ["edit", "grep", "read", "write"]})))
add("POS-nonempty-allow-empty-revisions", "positive-policy-source", std(body(), manifest(revisions=[])),
    note="ARAS refuses with CONTRACT_POLICY_SOURCE_UNRESOLVED (consumer rule); pinned reader has no such check")
add("POS-hint-absent", "positive-hint", std(body()), schema_version=None, kind=None,
    note="no envelope hints at all")

# ---- M1 ..: marker ----
add("M1-unknown-inner-marker", "M1", std(body({"profile": "other/v9", "allow": ["read"]})))
add("M1-typed-marker", "M1", std(body({"profile": 7, "allow": ["read"]})))
add("M1-null-marker", "M1", std(body({"profile": None, "allow": ["read"]})))
add("M2-profile-absent", "M2", std(body({"allow": ["read"]})))
add("M3-tools-absent", "M3", std(body(None)))
add("M4-empty-tools-object", "M4", std(body({})))
add("M4-allow-absent", "M4", std(body({"profile": P})))
add("M4-tools-null", "M4", std({**body(), "tools": None}))
add("M4-allow-null", "M4", std(body({"profile": P, "allow": None})))
add("M4-allow-non-string", "M4", std(body({"profile": P, "allow": [1]})))
add("M5-shell", "M5", std(body({"profile": P, "allow": ["shell"]})))
add("M5-five-entries", "M5", std(body({"profile": P, "allow": ["edit", "grep", "read", "write", "shell"]})))
add("M5-case-variant", "M5", std(body({"profile": P, "allow": ["Read"]})))
add("M5-alias", "M5", std(body({"profile": P, "allow": ["cat"]})))
add("M6-wildcard", "M6", std(body({"profile": P, "allow": ["*"]})))
add("M7-duplicate", "M7", std(body({"profile": P, "allow": ["read", "read"]})))
add("M7-out-of-order", "M7", std(body({"profile": P, "allow": ["write", "read"]})))
add("M8-extra-tools-property", "M8", std(body({"profile": P, "allow": ["read"], "extra": 1})))
add("M9-tools-empty-array", "M9", std(body([])))
add("P25-positional-tools", "P25", std(body([["read"]])))
add("P25-allow-not-array", "M9", std(body({"profile": P, "allow": "read"})))

# ---- M10 duplicate raw keys ----
b = canon(body())
add("M10-duplicate-top-key", "M10", b[:-1] + ',"scope":{"project":"x"}}' + canon(manifest()))
b2 = canon(body({"profile": P, "allow": ["read"]}))
add("M10-duplicate-allow-key", "M10",
    b2.replace('"allow":["read"]', '"allow":["read"],"allow":["write"]') + canon(manifest()))

# ---- M11 canonical bytes ----
add("M11-pretty-printed", "M11", json.dumps(body(), sort_keys=True, indent=1) + canon(manifest()))
add("M11-unsorted-keys", "M11", json.dumps(body(), separators=(",", ":")) + canon(manifest()))
add("M11-raw-non-ascii", "M11",
    json.dumps(body(task={"goal": "synthetic é"}), sort_keys=True, separators=(",", ":"),
               ensure_ascii=False) + canon(manifest()))
add("M11-whitespace-between-halves", "M11", canon(body()) + " " + canon(manifest()))
add("M11-float", "M11", canon(body(task={"goal": "x", "bounds": {"n": 1}})).replace('"n":1', '"n":1.5')
    + canon(manifest()))
add("M11-float-one-point-zero", "M11",
    canon(body(task={"goal": "x", "bounds": {"n": 1}})).replace('"n":1', '"n":1.0') + canon(manifest()))
add("M11-float-exponent", "M11",
    canon(body(task={"goal": "x", "bounds": {"n": 1}})).replace('"n":1', '"n":1e2') + canon(manifest()))
add("O-float-and-schema-invalid", "O",
    canon(body(verdict="F", task={"goal": "x", "bounds": {"n": 1}})).replace('"n":1', '"n":1.5')
    + canon(manifest()), note="parse-time float refusal precedes the schema")
add("M11-escape-uppercase-hex", "M11",
    canon(body(task={"goal": "é"})).replace("\\u00e9", "\\u00E9") + canon(manifest()))

add("M11-bignum-in-open-bounds", "M11-bignum",
    canon(body(task={"goal": "g", "bounds": {"n": 1}})).replace('"n":1', '"n":123456789012345678901234567890')
    + canon(manifest()),
    note="Python integers are unbounded; the ARAS reader refuses integers beyond i64/u64")

# ---- M12 closed shapes (member sets) ----
add("M12-extra-body-member", "M12", std(body(zzz=1)))
add("M12-missing-body-member", "M12", std(body(verdicts=ABSENT)))
add("M12-body-only-tools", "M12", canon({"tools": {"profile": P, "allow": ["read"]}}) + canon(manifest()))
add("M12-extra-manifest-member", "M12", std(body(), manifest(extra=1)))
add("M12-manifest-missing-snapshot", "M12", std(body(), manifest(snapshot_digest=ABSENT)))
add("M12-manifest-missing-revisions", "M12", std(body(), manifest(revisions=ABSENT)))
add("M12-revisions-not-array", "M12", std(body(), manifest(revisions="x")))
add("M12-body-not-object", "M12", "[]" + canon(manifest()))
add("M12-manifest-not-object", "M12", canon(body()) + "[]")

# ---- value shapes inside the closed members (item 4) ----
add("V-scope-empty", "V-scope", std(body(scope={})))
add("V-scope-two-axes", "V-scope", std(body(scope={"project": "a", "space": "b"})))
add("V-scope-unknown-axis", "V-scope", std(body(scope={"galaxy": "a"})))
add("V-scope-open-values", "V-scope-open", std(body(scope={"project": 5})),
    note="scope values are not vocabulary-checked")
add("V-scope-not-object", "V-scope", std(body(scope="project")))
add("V-embedded-nonempty", "V-embedded", std(body(embedded=["x"])))
add("V-refusals-nonempty", "V-refusals", std(body(refusals=["x"])))
add("V-reduction-bad", "V-reduction", std(body(reduction="whatever")))
add("V-reduction-exact", "V-reduction", std(body(reduction="exact(3)")))
add("V-reduction-object", "V-reduction", std(body(reduction={})))
add("V-verdict-F", "V-verdict", std(body(verdict="F")))
add("V-verdict-K", "V-verdict", std(body(verdict="K")))
add("V-verdict-synthetic", "V-verdict", std(body(verdict="synthetic")))
add("V-verdicts-as-array", "V-verdicts", std(body(verdicts=[])))
add("V-verdicts-bad-value", "V-verdicts", std(body(verdicts={"a": "X"})))
add("V-verdicts-open-keys", "V-verdicts-open", std(body(verdicts={"any key at all": "U", "b": "F"})),
    note="verdict keys are producer-defined")
add("V-canonicalization-string", "V-canon", std(body(canonicalization="json-c14n-pilot/v1")))
add("V-canonicalization-wrong-name", "V-canon",
    std(body(canonicalization={"name": "other", "version": "v1"})))
add("V-task-unknown-field", "V-task", std(body(task={"goal": "g", "zzz": 1})))
add("V-task-string", "V-task", std(body(task="goal")))
add("V-task-open-items", "V-task-open",
    std(body(task={"goal": "g", "inputs": [1, {"a": [None]}, "x"], "outputs": [True],
                   "required_capability_types": ["t"], "bounds": {"n": 1, "s": {"k": [1]}}})),
    note="task.inputs/outputs items and task.bounds values are producer-defined")
add("V-task-bad-capability-types", "V-task", std(body(task={"goal": "g", "required_capability_types": [1]})))
add("V-projection-object", "V-projection", std(body(projection={})))
add("V-projection-bad-revision-id", "V-projection",
    std(body(projection=[{"assertions": [], "source": {"content_digest": D1, "revision_id": "BAD"}}])))
add("V-projection-item-extra", "V-projection",
    std(body(projection=[{"assertions": [], "source": {"content_digest": D1, "revision_id": "a@r1"}, "x": 1}])))
add("V-projection-empty", "V-projection", std(body(projection=[])))
add("V-conflict-unresolved", "V-conflict",
    std(body(conflict_records=[{"about": "a", "kind": "ConflictRecord", "resolution": "UNRESOLVED",
                                "parties": [{"authority_class": "c", "content_digest": D1,
                                             "key": "k", "revision_id": "a@r1"}]}])))
add("V-conflict-bad", "V-conflict", std(body(conflict_records=[{"kind": "ConflictRecord"}])))
add("V-envelope-unverified-ok", "V-envelope",
    std(body(envelope_unverified=[{"condition": "c", "provider": "p"}])))
add("V-envelope-unverified-bad", "V-envelope", std(body(envelope_unverified=[{"provider": "p"}])))
add("V-quarantined-ok", "V-quarantined",
    std(body(quarantined=[{"addr": "a", "key": "k", "revision_id": None}])))
add("V-quarantined-bad", "V-quarantined", std(body(quarantined=[{"addr": "a"}])))
add("V-snapshot-digest-malformed", "V-manifest", std(body(), manifest(snapshot_digest="synthetic")))
add("V-snapshot-digest-uppercase", "V-manifest", std(body(), manifest(snapshot_digest="sha256:" + "A" * 64)))
add("V-revision-pair-three", "V-manifest", std(body(), manifest(revisions=[["a@r1", D1, "x"]])))
add("V-revision-pair-object", "V-manifest", std(body(), manifest(revisions=[{"a": 1}])))

# ---- R1 envelope hints (outside the digest) ----
add("R1-hint-version-unknown", "R1", std(body()), schema_version="something-else",
    note="KC-SWE: any other unknown marker -> CONTRACT_PROFILE_INVALID")
add("R1-hint-kind-wrong", "R1", std(body()), kind="Nope",
    note="not named by KC-SWE; pinned reader: schema const -> INVALID; ARAS: POLICY_UNBOUND")
add("R1-hint-agrees", "R1", std(body()))

# ---- KC-SWE interpretation points ----
add("K1-hint-talomnia-v1", "K1", std(body()), schema_version="talomnia-ontology/v1")
add("K2-hint-talomnia-v2", "K2", std(body()), schema_version="talomnia-ontology/v2")
add("K3-hint-tools-v2", "K3", std(body()), schema_version="arcanada-kc2-tools/v2")
add("K3-hint-tools-v10", "K3", std(body()), schema_version="arcanada-kc2-tools/v10")
add("K3-hint-tools-v0", "K3", std(body()), schema_version="arcanada-kc2-tools/v0")
add("K3-hint-tools-v2-trailing-newline", "K3", std(body()), schema_version="arcanada-kc2-tools/v2\n",
    note="Python re `$` also matches before a trailing newline")
add("K4-hint-other-unknown", "K4", std(body()), schema_version="other/v9")
add("K4-hint-case-variant", "K4", std(body()), schema_version="ARCANADA-KC2-TOOLS/V1")
add("K4-hint-suffix-junk", "K4", std(body()), schema_version="arcanada-kc2-tools/v1x")
add("K4-hint-empty-string", "K4", std(body()), schema_version="")
add("K5-pinned-blob-mismatch", "K5", std(body()), pin="wrong-blob",
    note="deliberately wrong pinned schema blob")
add("K6-requested-talomnia-v2", "K-requested", std(body()), requested="talomnia-ontology/v2",
    aras_only=True, note="requested profile is an ARAS call parameter; no producer analogue")
add("K6-requested-tools-v2", "K-requested", std(body()), requested="arcanada-kc2-tools/v2", aras_only=True)
add("K6-requested-empty", "K-requested", std(body()), requested="", aras_only=True)
add("K6-inner-marker-v2", "K3-inner", std(body({"profile": "arcanada-kc2-tools/v2", "allow": ["read"]})),
    note="inner marker names another version while the hint/requested one is v1")

# ---- multi-fault ordering ----
add("O-body-member-missing-and-allow-absent", "O",
    std(body({"profile": P}, verdicts=ABSENT)))
add("O-noncanonical-and-schema-invalid", "O",
    json.dumps(body(verdict="F"), sort_keys=True, indent=1) + canon(manifest()))
add("O-allow-unordered-and-noncanonical", "O",
    json.dumps(body({"profile": P, "allow": ["write", "read"]}), sort_keys=True, indent=1) + canon(manifest()))
add("O-bad-digest-and-invalid", "O", std(body(verdict="F")), digest_override="sha256:" + "f" * 64,
    note="shipped order: ARAS checks the digest first, the pinned reader last")
add("O-bad-digest-valid-shape", "O", std(body()), digest_override="sha256:" + "f" * 64)

# ---- ARAS-only: consumer route / envelope ----
add("N-opaque-text-preimage", "M13", "plain contract text", aras_only=True, route="opaque-text")
add("N-envelope-tools-differs", "R-envelope", std(body()), aras_only=True,
    envelope_tools=["read", "write", "grep"])
add("N-envelope-projection-differs", "R-envelope", std(body()), aras_only=True, envelope_projection_wrong=True)

json.dump({"profile": P, "cases": CASES}, sys.stdout, indent=1, sort_keys=True)
print()
