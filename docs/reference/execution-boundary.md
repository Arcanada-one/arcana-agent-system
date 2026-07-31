# Execution boundary — reference

Status: **partial slice landed; credentialed path NOT enabled.**

This document describes `crates/execution-boundary`, the first tracked slice of
the per-host execution boundary. It records what the crate guarantees today,
what it deliberately does not, and the operator constraint that follows.

## Why this exists

A provider API credential reached an agent's environment, was enumerated by the
agent, and was emitted into terminal scrollback and durable transcripts. Prompt
instructions did not prevent it and cannot: a process that holds a credential
can always reveal it, through a language runtime, a child process, an encoding,
or a crash dump.

So the boundary is not "tell the agent not to print secrets". The boundary is
that the agent never holds the credential at all.

## What the crate guarantees today

### Clean-environment reconstruction (`env_policy`)

The child environment is **cleared and rebuilt**, never filtered. Only names in
`ALLOWLIST` survive (`PATH`, `LANG`, `LC_ALL`, `TZ`, `TERM`, `COLORTERM`), and
`HOME` is reconstructed to a caller-supplied sandbox root.

The distinction matters. A denylist requires someone to remember to ban each new
secret variable; the day a new provider is added, the denylist is already wrong.
An allowlist excludes the new variable by default. `clean_env.rs` proves exactly
this with a variable no denylist could have anticipated.

`HOME` is reconstructed rather than inherited because vendor CLIs read
credentials from config homes. Inheriting `HOME` would reopen the channel that
clearing the environment just closed.

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

Nesting is decoded to **two** layers. Bounds are 64 KiB per encoded candidate
window, 32 KiB per decoded window, and 1 MiB of total unreleased output.

Two properties are worth calling out:

- **Chunk-boundary safety.** The scanner retains a tail sized to the longest
  representation, so a sentinel split across any two chunks is still caught. The
  test suite asserts this at *every* split position, including for encoded
  payloads.
- **Base64 phase invariance.** A secret embedded mid-stream is encoded against a
  phase it does not itself determine, so naively encoding the secret and
  searching for it fails. The scanner precomputes the alignment-invariant core
  for each of the three phases and additionally decodes candidate runs in
  reverse.

Every failure path is terminal. Detection, an over-limit encoded window, and
buffer exhaustion all latch the scanner; a poisoned scanner releases nothing
further, including bytes already buffered. There is no truncate-and-continue
path, because a partial release is still a release.

### False-positive control

A benign corpus — build output, hex digests, Base64 blobs, percent-encoded URLs,
JSON escapes — is committed with a pinned identity. The acceptance threshold is
zero blocks, zero replacements, and byte-identical release across eight chunk
schedules plus per-line and single-byte-drip delivery. Changing the corpus fails
the identity test on purpose: a corpus change must be a deliberate, reviewed act,
not a quiet accommodation of a new false positive.

### Structural spawn gate

`spawn_gate.rs` pins the raw `Command::new` inventory. The classification of the
workspace at the time of writing:

| Site | Class |
|---|---|
| `crates/supervisor/src/spawn.rs` | shipped runtime — migration target |
| `crates/connectors/src/coworker.rs` | shipped runtime — migration target |
| `crates/tools/src/bash.rs` | shipped runtime — migration target |
| `crates/cli/build.rs` | build-time |
| `crates/supervisor/src/bin/heartbeat-child.rs` | documented test fixture |
| `crates/tools/tests/webfetch_tool.rs` | test-only |

A new raw spawn outside this inventory fails CI. The three shipped-runtime
entries are recorded as migration targets, not excused.

## What this crate does NOT do

It is not the credential boundary. It provides isolation and quarantine only.

Not yet implemented:

- the privilege-separated credential broker, its permissioned local IPC, and
  peer / executable / session / generation / capability validation;
- quota, expiry, replay and idempotency enforcement;
- the metadata-only causal audit;
- process-group lifecycle, TTY, resize, timeout, cancellation and signal parity;
- the restrictive transcript writer with symlink rejection and retention;
- Linux systemd and macOS launchd packaging with a separate broker identity;
- migration of the three shipped-runtime spawn sites.

## Operator constraint

**This crate MUST NOT be registered as the credentialed execution path until the
broker exists.** Until then no route may carry a provider credential.

The quarantine scanner is defence in depth and must never be presented as the
control that makes credential exposure safe. While an agent can read a bearer
credential, a redactor is a mitigation for accidents, not a defence against
transformation or against exfiltration over an allowed network path.
