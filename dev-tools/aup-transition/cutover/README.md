# AUP-MIG-016 `coord0` / `coord1` — the cutover coordinator

The real, crash-safe coordinator of AUP-E25 § AUP-MIG-016 and DEC-AUP-0012. It replaces the
*simulated* coordinator of the MIG-014 fault drill (`tools/mig/fault_drill/`), which called itself
"the executable acceptance oracle of the MIG-016 coordinator, which does not exist yet".

It still touches **no host, no writer epoch, no fence and no repository**: the fence, lease, barrier
and host-activation backends are interfaces with a simulated implementation only, and
`Backends.real()` refuses with the decision id that still has to be satisfied.

| file | role |
|---|---|
| `coordinator.py` | the two machines and the CLI: the durable **ladder** (`receipts/cutover/state.json`, DEC-AUP-0012) and the crash-safe **window** (`QUIESCING → … → COMPLETE`, AUP-E25), plus the vocabulary map, the ladder rollback and the 33 switchable mutants |
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

## Who may write the ladder

By default nobody: `advance()` refuses every transition (`CARD_SCOPE_COORD0`) even when handed a
passing gate. A transition is taken only by a card that says so explicitly — `--enable-advance` plus
`--portion <its execution-state portion>` — and only when that transition's gate reads `PASS` over the
real receipts. `coord0` created the state file at `FILES_AUTHORITATIVE` and nothing else.

**`coord1` took the first real transition, `FILES_AUTHORITATIVE → SHADOW_PROJECTION`** (2026-09-06,
gate report `receipts/cutover/gates-20260906T033704Z.json`, `E1.1`/`E1.2`/`E1.3` all `PASS`). It is a
**dark launch**: the state authorises no window phase at all (`reconciliation.dark_launch`), so no
freeze, no fence, no single-writer switch, no writer epoch and no write to `datarim/` follows from it.
Its transition receipt carries the complete digested list of the receipts the gate rested on
(`relied_on`, 43 documents over three classes), the gate report it agrees with, the reconciliation
entry for the state entered, and the rollback note that says how to undo it.

## The way back

Inside the **dark-launch band** (up to and including `SHADOW_PROJECTION`, `DARK_LAUNCH_TOP`) a
transition is reversed by the coordinator itself: `--rollback-to <previous state> --enable-rollback
--reason '<why>'` writes a `CutoverRollbackReceipt/v1` **before** the state file moves and appends to
the history (never rewrites it). It refuses without the flag, without a reason, for anything but the
immediately preceding state, and — the load-bearing one — from any state above the band, whose
external effects (freeze, fence, writer epoch) belong to the cards that activated them
(`ROLLBACK_BEYOND_DARK_LAUNCH`). `--rollback-rehearsal --out <file>` proves the way back on a *copy*
of the ladder and writes a `CutoverRollbackRehearsal/v1` that includes the source state file's digest
before and after — identical, or the rehearsal fails.

## Commands

    coordinator.py --status                  # the persisted ladder state
    coordinator.py --reconciliation          # the two-vocabulary map + the held conflicts
    coordinator.py --init                    # create the state file at FILES_AUTHORITATIVE (idempotent)
    coordinator.py --gates --out <file>      # evaluate every gate against the real receipts
    coordinator.py --advance <STATE> --enable-advance --portion <id> [--gate-report <file>]
                                             # take a transition: refused unless enabled, next, and PASS
    coordinator.py --rollback-to <STATE> --enable-rollback --reason '<why>' --portion <id>
                                             # the way back, inside the dark-launch band only
    coordinator.py --rollback-rehearsal --out <file>   # prove the way back on a copy; ladder untouched
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
* the ladder rollback returns a dark-launch transition to its baseline state document (history aside),
  keeps the transition receipt, writes its own receipt first, and refuses in all four unsafe cases; the
  rehearsal proves the same on a copy while leaving the source state file byte-identical;
* the live gates over the program's real receipts produce no oracle violation, and a fixture in which
  the measurable requirements pass reads `NOT_MEASURED`, never `PASS`;
* every one of the 33 mutants is killed and every one of the 28 oracle rules fires on some mutant (six
  of the 33 — the delta-batch checklist normaliser's, COORD-FIX0; the derived-marker requirement's,
  SHADOW-MARKER0; and two of the rollback's, COORD1 — are killed by a dedicated fixture/outcome
  comparison rather than by the shared gate oracle, because each still leaves a structurally valid
  record behind: see `gates.py::_delta_batch`, `gates.py::_derived_marker`, `drill.py::ladder_rollback`);
* the selftest's own negative controls go red.

## Not measured here

Real hosts, the real Muneral writer authority, the real GitHub ruleset, real tmux lanes — all
simulated. The live ladder is never advanced or rolled back by the drill or by the rehearsal. Whether the *evidence* the gates ask for is
true of the world is the producing cards' job; this tool only reads what they wrote.
