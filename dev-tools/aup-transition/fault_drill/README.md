# AUP-MIG-014 `fault0` — fault drill for the MIG-016 cutover coordinator

Rehearses a failure in every transition state of the cutover coordinator that AUP-MIG-016 will build,
and proves safe recovery **without an automatic return to legacy** — against an oracle that shares no
code with the coordinator. Everything is simulated: no host, service, process, tmux server or
repository is touched; the only writes are the receipts under `--out`.

| file | role |
|---|---|
| `world.py` | deterministic environment: tick clock, services (Muneral / KC2 / Scrutator), network, auth, known-good generation pins (code/config/schema/policy), hosts `mac` / `devs` with an idempotent activation ledger, lanes with owner classes, the **effect ledger keyed by idempotency key** (the generic effect counter), and the server-side **writer authority** (single lease / fencing token / writer epoch, rejects stale epochs) |
| `coordinator.py` | the system under test: `QUIESCING → FENCED → FINAL_SYNC → VALIDATED → WRITE_COMMITTED → HOSTS_ACTIVATING → OBSERVING → COMPLETE`, `PAUSED_SAFE`, controlled `ABORTED` (pre-commit only). Every transition = durable observation → durable intent → keyed effect(s) → checkpoint; resume rebuilds from the journal, reuses observations, reconciles a dangling intent by **readback**, never re-issues blind. 16 switchable **mutants** (`M01..M16`) each disable one protective rule |
| `oracle.py` | independent rule table `O01..O18` over the trace (journal + events + effect ledger + authority log + final state) |
| `scenarios.py` | the fault matrix, injection hooks, the runner (crash → restart → resume twice → clear → resume twice → run; abort clause; rollback drill; stale-epoch writer; break-glass fixtures), the spec's expectation table |
| `fault_drill.py` | CLI: `--selftest`, `--drill --out <dir>`, `--replay <dir>` |

## Fault matrix

`crash` × 4 injection points (`before_observation`, `after_observation`, `after_effect`, `after_checkpoint`)
× 8 states, plus `lease_expiry`, `auth_revoke`, `corrupt_config`, `muneral_unavailable`, `kc2_unavailable`,
`scrutator_unavailable`, `network_loss`, `host_loss_mac`, `host_loss_devs`, `source_set_epoch_change`,
`abort_request` × 8 states = **120 scenarios**. A fault "at state S" hits the transition *into* S, so the
durable state at that moment is S's predecessor (this is why `auth_revoke@WRITE_COMMITTED` can still abort).

## What the oracle enforces (AUP-E25 § MIG-014 acceptance)

* before `WRITE_COMMITTED` a controlled abort is possible; after it only forward recovery or `PAUSED_SAFE` (O02)
* a repeated resume never changes the state twice (O04); the model is consulted once per observation key (O18)
* generic effect counter ≤ 1 (O03); an `UNKNOWN` effect outcome is reconciled by readback, never re-issued (O12)
* partial Mac/DEVS activation keeps the server-side rejection of the old writer epoch (O06) and never stops a
  foreign or unknown lane (O05); a host whose lanes cannot be classified blocks the fence (O17)
* corrupt known-good generation ⇒ pause, rollback refused (O07); rollback never restores legacy hooks (O09)
* break-glass without expiry or past it is refused (O08); a revoked run is never resumed from a stale checkpoint (O10)
* lease must be valid for every effect under the fence (O14); a changed `SourceSetEpoch` before commit ⇒
  `PAUSED_SAFE(REVALIDATION_REQUIRED)` (O16); transitions are keyed by migration id, SourceSetEpoch and target
  writer epoch (O13); every pause has a reason (O15); replay makes no model call and reproduces the live
  transition sequence (O11); the order of states is linear (O01)

## Selftest = evidence, not reassurance

`python3 tools/mig/fault_drill/fault_drill.py --selftest` runs the reference matrix (must satisfy every oracle
rule **and** the expectation table), replays it from the saved observations (0 model calls, identical transition
digests), runs the **mutation battery** (each of the 16 coordinator mutants must be killed by the oracle),
the **rule battery** (each oracle rule disabled in turn must be the one that fires on some mutant, otherwise
the rule is untested and the selftest fails) and a negative control of the selftest itself.

`--drill --out <dir>` writes `transitions.json`, `fence.json`, `lease.json`, `reconciliation.json`,
`rollback.json` (keyed records), `observations.json` (for replay), `scenarios.json`, `replay.json`, `summary.json`.

## Not measured here

Real hosts, the real Muneral authority, real tmux lanes and the real MIG-016 coordinator (which does not exist
yet — this drill is its executable acceptance oracle). The live canary on DEVS is the next card (`fault1`,
DEC-AUP-0011).
