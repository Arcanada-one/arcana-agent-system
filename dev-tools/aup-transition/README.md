# AUP transition instruments landed in arcana-agent-system

Proposal landings from the Arcanada Universal Program (program of record:
`Arcanada-one/arcanada-universal-program`). Nothing here activates anything, builds into the
binary, or runs in CI; every tool is stdlib Python 3.12 with its own `--selftest`.

| Path | Program card | What it is |
|---|---|---|
| `fault_drill/` | AUP-MIG-014 `fault0` | Fault matrix × MIG-016 cutover states with an independent oracle: the executable acceptance oracle for the runtime resume/recovery behaviour this repository will implement (crash-safe resume, keyed transitions, idempotent effects, PAUSED_SAFE protocol, known-good rollback, break-glass expiry). `python3 dev-tools/aup-transition/fault_drill/fault_drill.py --selftest` |
