# AUP-MIG-016 `coord0` — the cutover coordinator

The real, crash-safe coordinator of AUP-E25 § AUP-MIG-016 and DEC-AUP-0012. It replaces the
*simulated* coordinator of the MIG-014 fault drill (`tools/mig/fault_drill/`), which called itself
"the executable acceptance oracle of the MIG-016 coordinator, which does not exist yet".

It still touches **no host, no writer epoch, no fence and no repository**: the fence, lease, barrier
and host-activation backends are interfaces with a simulated implementation only, and
`Backends.real()` refuses with the decision id that still has to be satisfied.

| file | role |
|---|---|
| `coordinator.py` | the two machines and the CLI: the durable **ladder** (`receipts/cutover/state.json`, DEC-AUP-0012) and the crash-safe **window** (`QUIESCING → … → COMPLETE`, AUP-E25), plus the vocabulary map and the 28 switchable mutants |
| `gates.py` | one evidence evaluator per ladder transition, tri-valued (`PASS` / `BLOCK` / `NOT_MEASURED`), read-only over `receipts/` |
| `backends.py` | `FenceBackend`, `LeaseBackend`, `HostActivationBackend`, `BarrierStore` + the simulated implementations; `ProductionCutoverBarrier/v1` and its schema-distinctness proof against the DAT-018 `CandidateBarrierReceipt` |
| `gate_oracle.py` | the independent oracle of everything this card adds (rules `G01..G10`); shares no code with `coordinator.py` |
| `drill.py` | the MIG-014 fault matrix re-run against the real coordinator, the gate-refusal and ladder drills, `--selftest` |

## Two state vocabularies, reconciled (`--reconciliation`)

DEC-AUP-0012 names nine states, AUP-E25 names eight. They are not the same machine: the decision's
states are the **readiness ladder** (one evidence gate each, durable in `state.json`), the spec's are
the **execution phases of the cutover window**. Each phase names the minimum ladder state that
authorises it, and **the decision wins on gating**:

| ladder state (DEC-AUP-0012) | authorises the phase (AUP-E25) |
|---|---|
| `FILES_AUTHORITATIVE` | — (baseline) |
| `SHADOW_PROJECTION` | — (dark launch; no spec analogue) |
| `FROZEN` | `QUIESCING` |
| `FENCE_ENFORCED` | `FENCED` |
| `PROJECTION_VERIFIED` | — (spec folds it into `VALIDATED`) |
| `DELTA_IMPORTED` | `FINAL_SYNC` |
| `ROLLBACK_DRILLED` | `VALIDATED` |
| `SWITCHING` | `WRITE_COMMITTED`, `HOSTS_ACTIVATING`, `OBSERVING` |
| `MUNERAL_AUTHORITATIVE` | `COMPLETE` |

Three order/vocabulary conflicts between the two documents are **recorded and held**, not resolved by
a silent default (`ORDER_CONFLICTS`, printed by `--reconciliation`).

## What this card may write

`receipts/cutover/state.json` at `FILES_AUTHORITATIVE`, with its transition receipt — **and nothing
else**. `advance()` refuses every transition (`CARD_SCOPE_COORD0`) even when handed a passing gate;
the first real transition is the next card under DEC-AUP-0012.

## Commands

    coordinator.py --status                  # the persisted ladder state
    coordinator.py --reconciliation          # the two-vocabulary map + the held conflicts
    coordinator.py --init                    # create the state file at FILES_AUTHORITATIVE (idempotent)
    coordinator.py --gates --out <file>      # evaluate every gate against the real receipts
    coordinator.py --advance <STATE>         # attempt a transition (refused: card scope, then the gate)
    coordinator.py --drill --out <dir>       # the fault matrix + gate refusal + ladder drills
    coordinator.py --selftest                # reference + replay + mutation battery + rule battery

## The protocol (per phase)

    durable observation → durable intent → keyed effect(s) → durable RECEIPT → checkpoint → transition

A crash at any of the five boundaries is recovered from the journal: an observation is reused (no
second model call), a dangling intent is reconciled by **readback** and never re-issued blind, a
receipt already written is **reused verbatim** (byte-identical, so a resume can never leave two
receipts for one transition), a checkpointed phase is never re-run, and a repeated resume is a no-op.
The receipt boundary is the step the MIG-014 matrix did not know about, so the drill adds one crash
scenario per phase for it (120 reused + 8 = 128).

## Evidence

`--selftest` fails unless **all** of it holds:

* the reference matrix (128 scenarios) satisfies the MIG-014 oracle (`O01..O18`, unchanged), the new
  gate oracle (`G01..G10`) *and* the spec's expectation table;
* replay from the saved observations makes 0 model calls and reproduces every transition digest;
* the window pauses safe at every ladder position with `GATE_NOT_SATISFIED:<state>` and issues no
  effect for an unauthorised phase (9 positions);
* the ladder refuses to advance under card scope, refuses a blocking gate, survives a crash between
  the receipt and the state write, and finishes that transition on resume — exactly once;
* the live gates over the program's real receipts produce no oracle violation, and a fixture in which
  the measurable requirements pass reads `NOT_MEASURED`, never `PASS`;
* every one of the 28 mutants is killed and every one of the 28 oracle rules fires on some mutant (two
  of the 28 mutants — the delta-batch checklist normaliser's, COORD-FIX0 — are killed by a dedicated
  fixture comparison, not by the shared gate oracle: see `gates.py::_delta_batch`);
* the selftest's own negative controls go red.

## Not measured here

Real hosts, the real Muneral writer authority, the real GitHub ruleset, real tmux lanes — all
simulated. The live ladder is never advanced by the drill. Whether the *evidence* the gates ask for is
true of the world is the producing cards' job; this tool only reads what they wrote.
