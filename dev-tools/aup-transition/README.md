# AUP transition instruments landed in arcana-agent-system

Proposal landings from the Arcanada Universal Program (program of record:
`Arcanada-one/arcanada-universal-program`). Nothing here activates anything, builds into the
binary, or runs in CI; every tool is stdlib Python 3.12 with its own `--selftest`.

| Path | Program card | What it is |
|---|---|---|
| `rebuild/` | AUP-MIG-013 `rebuild0` | Cross-host rebuild, handoff and evidence parity: canonical job package from explicit pinned inputs (KC2/Muneral/policy/model/tool pins, audience folded into the digest, explicit clock+seed), a portability-checked handoff envelope, an idempotent-effect rehearsal target, digest/authority/trace-parity verification and network-loss reconciliation. `python3 dev-tools/aup-transition/rebuild/rebuild.py --selftest` |

Sibling proposals not yet merged into `main` at the time this branch was cut (see each PR for its
own copy of this table until the repo broker reconciles the stack): `fault_drill/` (AUP-MIG-014
`fault0`, PR #151), `data_gate/` (AUP-MIG-015 `gate0`, PR #152), `cutover/` (AUP-MIG-016 `coord0`,
PR #153, stacked on #151).
