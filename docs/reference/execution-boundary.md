# Execution boundary — reference

Status: **partial slice landed; credentialed path NOT enabled; no shipped spawn
site migrated yet.**

This document describes `crates/execution-boundary`. It records what the crate
guarantees, what it demonstrably does **not**, and the operator constraint that
follows. The limits section is as important as the guarantees section: a
redactor trusted beyond its reach is worse than no redactor.

## Why this exists

A provider API credential reached an agent's environment, was enumerated by the
agent, and was emitted into terminal scrollback and durable transcripts. Prompt
instructions did not prevent it and cannot: a process that holds a credential
can always reveal it, through a language runtime, a child process, an encoding,
or a crash dump.

So the boundary is not "tell the agent not to print secrets". The boundary is
that the agent never holds the credential at all.

## Guarantees

### Clean-environment construction (`env_policy`)

The child environment is **constructed, not inherited**. `CleanEnv::build` takes
a sandbox home and a `PATH`, validates both, and emits six fixed variables.
There is no API that accepts a source environment, so there is no path by which
a parent variable reaches a child.

This is a correction of an earlier design that allowlisted variable *names* and
copied their *values* through unexamined. That left `PATH`, `TERM`, `LANG`,
`LC_ALL`, `TZ` and `COLORTERM` as six unconstrained channels out of exactly the
environment the design distrusts — and an inherited `PATH` additionally re-opens
a code-execution channel, since an agent-writable directory can shadow every
helper a vendor CLI invokes.

Validation is fail-closed. A sandbox home that is relative, contains `..`, or
aliases a real user home is refused; so is a `PATH` with an empty or relative
component, and a `TERM` outside a closed set (`TERM` steers terminfo file
resolution, so it is an input to a lookup, not an opaque string).

`CleanEnv::apply` performs `env_clear()` itself, so a caller cannot layer clean
variables on top of a full inherited environment by forgetting to clear. `Debug`
redacts values.

### Streaming output quarantine (`scanner`)

Output is buffered and released only once proven free of every supported
representation of a known sentinel:

| Transform | Forms covered |
|---|---|
| Raw | UTF-8 bytes, and therefore bearer/header and JSON-string forms |
| Base64 | Standard and URL alphabets, padded and unpadded, all three embedding phases |
| Hex | Upper and lower case |
| Percent | `%XX`, upper and lower case |
| JSON | `\uXXXX` escapes |

Nesting is decoded to two layers, with a 64 KiB encoded-candidate window, a
32 KiB decoded window, and 1 MiB of total unreleased output.

Three properties are worth calling out:

- **Chunk-boundary safety.** The retained tail is sized for a complete *nested*
  occurrence — `MAX_EXPANSION^depth` — not merely a single-layer one. Sizing it
  from single-layer forms (as an earlier revision did) let every depth-2 payload
  stream past at ordinary chunk sizes, because `hex(\u…)` is twelve times the
  raw sentinel while the tail was only six.
- **Separator and wrap tolerance.** Candidate data is scanned as-is, with
  whitespace stripped, and with byte-dump separators stripped. Without this,
  `base64(1)`'s default 76-column wrap and any `xxd`/`openssl`/C-array/`\xNN`
  hex dump walk straight through, because each separated token decodes as an
  independent fragment.
- **Phase recovery.** Runs are decoded at every quantum offset, so a run whose
  front was truncated by an earlier release is still decoded in the correct
  phase.

Every failure path is terminal and releases nothing, including already-buffered
bytes: detection, an over-limit encoded window, an over-limit **decoded** window,
and buffer exhaustion. The decoded-window case is called out because an earlier
revision short-circuited it and released the bytes, which made "write more than
32 KiB" a complete bypass.

Construction is fallible. An empty sentinel set is a hard error, not a
zero-retention pass-through that reports success while quarantining nothing.

### False-positive control

A benign corpus — build output, hex digests, Base64 blobs, percent-encoded URLs,
JSON escapes — is committed with a pinned **SHA-256** identity (a byte-sum, used
earlier, is permutation- and swap-invariant and therefore not an identity). The
threshold is zero blocks, zero replacements, and byte-identical release across
eight chunk schedules plus per-line delivery.

### Structural spawn gate

`spawn_gate.rs` pins the raw spawn inventory per file, across the whole
repository, and detects aliased imports (`use std::process::Command as Cmd`)
alongside `posix_spawn`/`exec*` spellings. It is verified by a meta-test, and
was confirmed to fail on an injected aliased spawn site before being accepted.

| Site | Class |
|---|---|
| `crates/supervisor/src/spawn.rs` | shipped runtime — migration target |
| `crates/connectors/src/coworker.rs` | shipped runtime — migration target |
| `crates/tools/src/bash.rs` | shipped runtime — migration target |
| `crates/cli/build.rs` | build-time |
| `crates/supervisor/src/bin/heartbeat-child.rs` | documented test fixture |
| `crates/execution-boundary/**` | sanctioned boundary owner |

## What this does NOT do

### The crate has no runtime callers yet

The three shipped spawn sites are **unchanged** and still inherit the full
parent environment. This crate is the mechanism the migration will use; it is
not yet enforced anywhere. Any statement that subprocesses currently cross this
boundary would be false.

### The scanner's reach is bounded

Confirmed to pass through, because they are outside the closed transform set:
base32, ascii85, ROT13, reversal, per-character interleaving with junk,
compression (`gzip | base64`), and any encryption. Also not caught: a secret
emitted **non-contiguously** across unrelated writes, where the two halves never
co-occur in one retention window.

An honest one-line summary: *the scanner catches a naive `echo $KEY` and
canonical encodings of it, including wrapped and separator-formatted ones; it
does not survive an arbitrary transform or a sufficiently patient emitter.*

A supervised child MUST feed stdout and stderr into **one shared scanner**. Two
independent instances do not see each other's buffers, so a secret split across
the two streams would pass. `push_stream` exists to make the shared-instance
usage the obvious one.

### Not addressed at all

- **argv** — a credential passed as `--api-key <secret>` is world-readable in
  `/proc/<pid>/cmdline`. There is no argv policy yet.
- **Inherited file descriptors** — no close-on-exec sweep. An fd left open on a
  credential file survives `exec` and defeats the environment guarantee entirely.
- **Same-uid inspection** — a descendant running as the same uid can read
  `/proc/<parent>/environ` and `ptrace` the parent. Environment reconstruction
  does not isolate a secret held by the supervisor; only a uid split does.
- Process-group lifecycle, TTY/resize/timeout/signal parity, and the restrictive
  transcript writer.

### A design tension worth naming

The scanner requires the plaintext sentinel to be resident in the supervisor in
order to detect it, and it materialises roughly a dozen derived copies. That is
in tension with the architecture's goal, and it is the reason the scanner is
defence in depth rather than the boundary: the real fix is that the supervisor
should not hold the credential either — the broker should.

## Operator constraint

**This crate MUST NOT be registered as the credentialed execution path until the
broker exists and descendants run under a distinct uid.**

This constraint is currently prose, not a mechanical gate. Treat it accordingly.
