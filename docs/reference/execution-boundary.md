# Execution boundary — reference

Status: **all three shipped spawn sites migrated for credential-free execution;
credentialed provider mode remains mechanically DISABLED.**

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
The optional Bash `env_vars` input remains schema-compatible, but any non-empty
map is refused. A name-based exception cannot prove that a value under `MY_VAR`
is not credential material, and shell/loader variables can execute before a
shell wrapper sweeps descriptors. No API accepts a source environment, so there
is no path by which a parent or caller value reaches a child.

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
| `crates/supervisor/src/spawn.rs` | shipped runtime — migrated |
| `crates/connectors/src/coworker.rs` | shipped runtime — migrated |
| `crates/tools/src/bash.rs` | shipped runtime — migrated |
| `crates/cli/build.rs` | build-time |
| `crates/supervisor/src/bin/heartbeat-child.rs` | documented test fixture |
| `crates/execution-boundary/**` | sanctioned boundary owner |

### Process and transcript lifecycle

`ProcessSpec` is the single shipped subprocess constructor. It validates an
absolute executable, constructs the environment, sweeps inherited descriptors,
uses a new process group, captures exit-versus-signal status, enforces timeout
and cancellation, and kills the owned group after every leader exit as well as
on timeout, cancellation or a dropped execution future. A leader exiting during
the SIGTERM grace period never suppresses the final group SIGKILL. Stdout and
stderr feed one bounded collector. Before release, the scanner conservatively
tests whether each sentinel representation can be reconstructed by interleaving
bytes from both streams in either scheduler order; pipe-reader scheduling is not
trusted as a total order.

PTY creation uses a real pseudo-terminal and supports resize. A PTY request that
also asks for quarantine or transcript persistence is refused: the raw PTY API
cannot enforce those policies before releasing bytes.

Optional transcript persistence is wired into `ProcessSpec`. The writer scans
the complete observation-ordered stream and performs the same scheduler-
independent stdout/stderr reconstruction check as the process collector. It
applies a serialized-byte limit that includes record framing,
walks every path component through `openat`/`O_NOFOLLOW`, creates and prunes files
relative to a retained owner-only directory descriptor, writes mode `0600`, and
uses length-delimited binary stream records so process output cannot forge
stdout/stderr labels. Retention is bounded by age and count. Pre-existing
no-sync/no-index markers must be regular owner-only files with exact expected
content; an empty `.stignore` cannot masquerade as sync exclusion. The writer
also reopens the configured namespace and compares directory identity before and
after the write. A successful write returns an opaque artifact identifier, not a
pathname. Retrieval is available only through the originating writer capability,
which resolves that identifier relative to its retained directory descriptor;
later namespace replacement therefore cannot redirect a returned path.

### Broker protocol and mock IPC

The separate broker binary implements the closed capability policy and a
permissioned mock-only local IPC path. Quota cost is derived from policy, not
from the caller. Idempotency keys are syntax- and capacity-bounded, bound to a
SHA-256 fingerprint of the complete request and peer, and durably reserved
before a provider side effect. Completed mock responses survive restart; a
crash after reservation returns `in_progress` rather than repeating work.

Audit writes are owner-only, synchronous and metadata-only. Policy decisions,
quota/replay outcomes, output scan results, locally rejected provider requests,
and transport/body failures with unknown provider outcome are distinct terminal
events. They fail closed if their audit write cannot be persisted.

## Limits and blocked gates

### Credential-bearing IPC is intentionally unavailable

The broker refuses non-mock startup before reading the credential source. The
former stream-UDS design sampled connection credentials and a mutable process
path; a connected descriptor can be handed to another process, so that design
cannot authenticate the sender of each request. It is not used as a weaker
fallback.

The remaining supported designs are platform-specific:

- Linux: `SOCK_SEQPACKET`, kernel-added credentials on every message, and an
  enforcing per-message LSM label, with descendants born inside a cgroup-v2
  service and teardown proven by `populated 0`.
- macOS: launchd/XPC audit-token and exact code-signing validation, plus an
  entitled lineage/containment backend. A filesystem UDS plus PID lookup is not
  equivalent.

Until those empirical backends exist, credentialed execution is `BLOCKED` and
the installed production service fails closed.

### The scanner's reach is bounded

Confirmed to pass through, because they are outside the closed transform set:
base32, ascii85, ROT13, reversal, per-character interleaving with junk,
compression (`gzip | base64`), and any encryption. Also not caught: a secret
emitted **non-contiguously** across unrelated writes, where the two halves never
co-occur in one retention window.

An honest one-line summary: *the scanner catches a naive `echo $KEY` and
canonical encodings of it, including wrapped and separator-formatted ones; it
does not survive an arbitrary transform or a sufficiently patient emitter.*

A supervised child MUST feed stdout and stderr into **one shared scanner** and
call `check_distributed` before release. Two independent instances do not see
each other's buffers, and channel-arrival order is scheduler-dependent.

### Remaining execution limits

- Process groups contain ordinary children and grandchildren, but a hostile
  child can call `setsid` or double-fork out of that group. This path is
  credential-free; it must not be advertised as the strong descendant
  container required for credentialed execution.
- Executable validation is path-based and cannot make check-plus-exec atomic on
  every supported Unix platform. Release ownership and packaging are required
  controls; a future manager-created execution backend must use verified file
  identity.
- `BashTool.env_vars` is accepted only when empty. Arbitrary caller values would
  create both a benign-name credential channel and shell/loader control channel.
- `coworker` runs with a sandbox HOME. Relative targets retain the caller's
  working directory, but configurations stored only in the real user home are
  deliberately unavailable. Credentialed Coworker use awaits the broker path.
- Hosted Linux/macOS jobs compile, test, and rehearse the mock lifecycle. They
  do not prove production service-manager identities, LSM/XPC attestation,
  cgroup escape resistance, Keychain access, debugger denial, or an entitled
  macOS containment backend. V-AC-7 remains `BLOCKED`.

### A design tension worth naming

The scanner requires the plaintext sentinel to be resident in the supervisor in
order to detect it, and it materialises roughly a dozen derived copies. That is
in tension with the architecture's goal, and it is the reason the scanner is
defence in depth rather than the boundary: the real fix is that the supervisor
should not hold the credential either — the broker should.

## Operator constraint

Do not enable credentialed execution. The binary enforces this mechanically by
refusing non-mock mode; lifecycle failure ends with both activation endpoints
disabled. Generation names are immutable binary-plus-policy identities pinned by
a root-owned SHA-256 manifest outside the broker-writable state directory.
Release publication requires exact current `main`, app-bound protected checks
for that SHA (including both hosted platform contracts), authoritative no-bypass
tag-protection readback, signed/attested payloads and checksums, and the configured
independent protected-environment reviewer with self-review disabled. Provider
rotation, Vault write, platform attestation, strong descendant containment, and
live platform evidence must all pass before the credential gate can change.
