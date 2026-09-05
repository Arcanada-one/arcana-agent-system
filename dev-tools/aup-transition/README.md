# AUP transition instruments landed in arcana-agent-system

Proposal landings from the Arcanada Universal Program (program of record:
`Arcanada-one/arcanada-universal-program`). Nothing here activates anything, builds into the
binary, or runs in CI; every tool is stdlib Python 3.12 with its own `--selftest`.

| Path | Program card | What it is |
|---|---|---|
| `fault_drill/` | AUP-MIG-014 `fault0` | Fault matrix × MIG-016 cutover states with an independent oracle: the executable acceptance oracle for the runtime resume/recovery behaviour this repository will implement (crash-safe resume, keyed transitions, idempotent effects, PAUSED_SAFE protocol, known-good rollback, break-glass expiry). `python3 dev-tools/aup-transition/fault_drill/fault_drill.py --selftest` |
| `cutover/` | AUP-MIG-016 `coord0` | The cutover coordinator itself: DEC-AUP-0012's nine-state readiness ladder (persisted, one evidence gate and one transition receipt per step, the receipt written before the state advances) and AUP-E25's eight-phase cutover window (crash-safe resume from the recorded state, keyed transitions, idempotent keyed effects, reconciliation by readback, PAUSED_SAFE, controlled abort only before the commit), reconciled by an explicit table in which every phase names the ladder state that authorises it. Fence / lease / barrier / host activation are interfaces with a **simulated** backend only — `Backends.real()` refuses. It re-runs the `fault_drill/` matrix and oracle of AUP-MIG-014 against itself, unchanged. `python3 dev-tools/aup-transition/cutover/drill.py --selftest` |
