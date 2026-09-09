# AUP-MIG-013 `rebuild0` — cross-host rebuild, handoff and evidence parity

Proves the AUP-E25 § MIG-013 acceptance clauses for real, stdlib only, both halves run **HERE**
(this session is the DEVS executor; the Mac half has no separate host in this life, so
`verify-handoff` is run here as its explicit stand-in — never silently claimed as a real second
host). Reuses the receipt/selftest conventions of `tools/mig/cutover`, `tools/mig/data_gate` and
`tools/mig/fault_drill`; never rewrites them.

| file | role |
|---|---|
| `package.py` | `JobPackageInputs` (kc2/Muneral/policy/model/tool pins, audience, explicit clock + random seed, canonical NFC/LF encoding), canonical digest, `HandoffEnvelope` (digest/audience/expiry/canonical refs — never a secret or a private absolute path), the portability scanner |
| `backend.py` | `RehearsalTarget`: a task-owned local git repo standing in for the DEVS rehearsal target (never `datarim-history`, `aup`, or any `datarim/` path); the one idempotent effect (`canary/handoff/<idempotency_key>.json`, committed), read back through git objects at `HEAD`, never the working tree |
| `core.py` | `twice_check` (rebuild the same inputs twice, assert one digest), `verify_handoff` (digest recompute, audience-pin check, target readback, trace/target parity, missing-link typing), `handoff_canary`, `reconcile` — every check has a named mutant switch (`active_mutants`) for the selftest's mutation battery |
| `oracle.py` | independent rule table `R01..R07` over a fixture's trace; shares no code with `core.py` |
| `fixtures.py` | 10 hermetic fixtures (`F0` green control + `F1..F9`, one per named failure scenario + the twice-determinism proof + the missing-link diagnostic), the mutation battery and the rule battery, `--selftest` |
| `rebuild.py` | CLI: `rebuild [--twice]`, `handoff-canary`, `verify-handoff`, `reconcile`, `--selftest` |

## Commands

    rebuild.py rebuild --twice --kc2-revision R --muneral-revision R --policy-pin P \
        --model-pin M --tool-pin T --audience A --clock ISO8601 --seed N --expiry ISO8601 --out F
    rebuild.py handoff-canary --manifest F --target DIR --idempotency-key K [--simulate-network-loss] --out F
    rebuild.py verify-handoff --manifest F --envelope F --expected-audience A --target DIR \
        --idempotency-key K [--trace-claims-applied] --out F
    rebuild.py reconcile --target DIR --idempotency-key K --out F
    rebuild.py --selftest [--out DIR]                # must end "selftest N/N PASS"

## Determinism (`rebuild --twice`)

Every digest input is an explicit argument — nothing in `package.py` calls a wall clock, a random
source or reads the environment. `--twice` builds the package twice from the same explicit inputs
and asserts one digest; the audience is folded into the digest itself, so a post-build audience
swap is caught the same way a mutated byte or a mutated source revision is (`DIGEST_MISMATCH`),
not by a separate code path.

## The rehearsal target

The brief allows either the Muneral pilot project (`15be398a-…`) or a task-owned clone. This card
uses a task-owned **local** git repository (`/home/dev/aup/aup-mig013-rehearsal`, never pushed
anywhere) rather than the pilot project, because Muneral's identity scope is **global, not
per-project** (`muneral-identity-scope-global-not-project` precedent): a rehearsal write against an
already-imported identity's `idempotencyKey`/`batch_key` on the pilot project can permanently burn
the canonical batch_key. The mechanism under test — one effect per idempotency key, target readback
through canonical refs, `UNKNOWN → reconcile` without a repeat — does not depend on which git
repository plays the target, so the safer substitution changes no acceptance clause it exercises.

## What `verify-handoff` checks, in order

`NONPORTABLE` (private absolute path / secret literal, checked independently of the build-time
guard) → `NOT_MEASURED` (target unreachable — a missing-link diagnostic, never defaulted to PASS or
omitted, I4) → `DIGEST_MISMATCH` (recomputed digest vs. manifest vs. envelope) → `REJECTED`
(`AUTHORITY_SUBSTITUTED`: a self-consistent, digest-matching envelope whose audience does not equal
the audience pinned by the *original* rebuild receipt — this is what makes it distinct from a
digest mutation: the attacker's rebuild is internally consistent, only the out-of-band pin catches
it) → `DETECTED` (`TRACE_WITHOUT_TARGET_EFFECT`: a trace claims the effect landed, target readback
disagrees) → `PASS`.

## Selftest = evidence, not reassurance

`python3 tools/mig/rebuild/rebuild.py --selftest` runs, hermetically (every `RehearsalTarget` lives
under a `TemporaryDirectory`):

* **10 fixtures**: a green control that must mint a real `PASS` (otherwise the battery is vacuous),
  plus one per spec failure scenario — mutated byte / mutated audience / mutated source revision
  (all three land on `DIGEST_MISMATCH`, the same recompute path, on three different fields), transport
  substituting authority (`REJECTED`, digest self-consistent), a trace with no target effect
  (`DETECTED`), a private absolute path (`NONPORTABLE`, both build-time and verify-time), network loss
  (`UNKNOWN` → `reconcile` → `APPLIED` via readback, one effect total) and an unreachable target
  (`NOT_MEASURED`, the missing-link diagnostic) — plus the twice-determinism proof;
* a **negative control**: an inert mutant name must change no fixture's verdict;
* a **mutation battery**: 7 named mutants (`M01..M07`), each disabling exactly one protective check
  in `core.py`; each must be killed by its paired fixture;
* a **rule battery**: each of the 7 oracle rules must be the *only* rule that fires for its paired
  (fixture, mutant), and must fire on *nothing* when that mutant is absent — otherwise the rule is
  untested and could be deleted without the battery noticing;
* a **determinism check**: the green control's own digest is stable across two independent runs.

## Not measured here

A real KC2 service revision (only the KC2 baseline **documents** tracked in this program repo are
git-resolvable from this host; the pin used by the real run names that document revision explicitly
and is not a live KC2 build — see the receipt's `missing_or_unavailable`). The real Mac host (its
half is run here as an explicit stand-in, never claimed as a second real host). Muneral project
`15be398a-…` as a live rehearsal target (see above — the task-owned local repo is used instead by
deliberate substitution, recorded, not silently assumed equivalent). Muneral task status transition
(agent key: `POST assign` → 201; `PATCH .../status` → 404, not the JWT-only 401 seen on other
cards' route shape — recorded as observed, not retried; work item stays in its Muneral-side state).
