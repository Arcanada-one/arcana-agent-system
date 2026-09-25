# CLI exit codes & connector environment

Information-oriented reference for the `arcana` subcommand exit-code namespace
and the Model-Connector environment overrides.

## Exit-code namespace

`arcana` subcommands use the following outcome namespace so an automated caller
(CI, the smoke gate) can tell a dead capability from an infrastructure error.
Not every subcommand emits every code:

| Code | Meaning | Examples |
|------|---------|----------|
| `0` | Success — the capability ran and produced a positive result. | `whoami` cascade Allowed with a non-empty audit record; `mc-ping` returned a non-empty `result`; `kb-read` completed exactly one authenticated search with nonzero hits and cited a returned `source_path`. |
| `1` | Operational / infrastructure error, or a fail-closed `kb-read` grounding failure. | bootstrap failure; async-runtime start failure; connector transport error (DNS/TLS/connect/timeout); the advertised audit-log path is missing or empty; `kb-read` credential, audit, search-count, hit, or citation failure. |
| `2` | Capability-assertion failed — the probe ran, but the capability is dead. | `whoami` cascade **Denied**; `mc-ping` got a degenerate `201 {"status":"success","result":""}` (empty result). |

Rationale: control-plane green (exit 0) while the data plane is dead is the
dominant false-green failure mode. A blanket `0` on any `Ok(response)` or on a
denied cascade hides a broken capability behind a passing check. Splitting
"the probe could not run" (`1`) from "the probe ran and the capability is dead"
(`2`) lets a harness record `SKIP(env:unreachable)` for a transport error while
still failing hard on a degenerate result.

### `mc-ping` error discrimination

`mc-ping` maps **every** `ConnectorError` to a single non-zero code — the exit
code cannot tell *which* contract failed. Assert on the stderr `Display`
message instead:

| Condition | stderr substring |
|-----------|------------------|
| `ARCANA_MC_TOKEN` unset/empty | `missing API key (set ARCANA_MC_TOKEN)` |
| upstream HTTP 200 (only 201 is success) | `unexpected HTTP status 200 (expected 201)` |
| `201 {"status":"error"}` | `upstream logical error [<kind>]: <message>` |
| transport failure | `transport error: <detail>` (→ treat as unreachable) |

### `arcana run` exit codes

`run` is the headless task runner (see
[`../how-to/run-one-task-unattended.md`](../how-to/run-one-task-unattended.md)):

| Code | Condition |
|------|-----------|
| `0` | The run reached `Completed`, executed at least one tool call, **and** left an effect — the working tree after the run differs from the working tree before it, unless the task was dispatched with `--read-only`. |
| `1` | The run failed, or never started: `--live` prerequisites unmet, `--cwd` unresolvable, no task, unreadable `permissions.toml`, audit-log setup failure, `NoAction` (the model answered without executing a single tool call), `ResponseTruncated` (two replies in a row were cut off by the model's output limit mid tool call), `UnsupportedToolCallFormat` (the model asked for a tool in an encoding this runner cannot execute, and repeated it after being told the one it reads), `RequestTooLarge` (the transcript could not be compacted into the connector's 100 000-character per-field request limit), `NoEffect` (the run completed and the working tree is byte-for-byte what it was — see below), `ClaimedButAbsent` (the run changed something, and the final message named a path that is not on disk), or any other non-`Completed` terminal verdict (including `PermissionDenied` on a refused tool call). |
| `3` | `--work-item` only: the run itself would have exited `0`, but its receipt is NOT attached to the work item (`EVIDENCE_NOT_ATTACHED` on stderr; see below). A run that already failed keeps its own code. |
| `130` | The operator interrupted the run; the spend line reports what the interrupted dispatch cost. |

The last line of stdout is always `ARCANA_RUN_DONE <json>`, printed even when
the run never started — a runner reads the marker rather than interpreting its
absence, which is indistinguishable from a crash. Its `compactions` field
counts the turns on which the transcript had to be shortened to stay inside the
request contract; non-zero means the model answered from a summary of part of
its own history, which is worth knowing before comparing two runs of the same
card.

`NoEffect` is not a `TerminalReason`: the driver ended the run legitimately and
has no business knowing what a working tree is. It is decided above the driver,
where the disk is visible, by comparing a digest of `--cwd` taken before the
first model call with one taken after the last — excluding `.git/`, the
runner's own `.arcana/`, and everything `.gitignore` excludes. It exists
because a tool-call count cannot tell reading from writing: pilot A2-278's runs
2 and 4 executed nine and three calls, all of them `read` or `grep`, wrote
nothing, and exited `0` with `"completed":true` while describing a file that
does not exist. The marker's `effect` object carries both digests, the executed
tools by name, and `claimed_but_absent` — the paths the model's closing
sentence named and the disk denies — a non-empty `claimed_but_absent` is its own
refusal, `ClaimedButAbsent`, because the digest alone does not cover it: the
first live run under this check wrote an empty probe file, which moved the
digest, and then described a page it never wrote. `effect.tree_changed: null` means the walk
could not complete and refuses nothing; a refusal has to be provable.

`RequestTooLarge` is separate from `ContextWindowExhausted`, and the difference
is which side refused. `ContextWindowExhausted` is about the **model** — its
context window — and is answered by choosing a model with a larger one.
`RequestTooLarge` is about the **wire**: Model Connector's `/execute` caps
`prompt` and `systemPrompt` at 100 000 UTF-16 code units *each*
(`src/connectors/dto/execute.dto.ts:53,55`) and rejects an over-long field with
an HTTP 400 before any model is reached, so a larger model would not help and
the refusal costs nothing. Measured 2026-09-23: a run that had executed five
tool calls and cloned a repository died at turn 10 on that 400, reported as
`ConnectorFatal` — which names the connector for a limit the caller overran.

`ConnectorFatal` carries the same `error` detail a denial does: the status, how
many attempts were made this turn, over how long, and why the loop stopped —
`HTTP 502 after 6 attempt(s) over 63s — the 5 re-dispatch(es) allowed for a
transient gateway failure in front of the Model Connector are spent: …`. Pilot
A2-204c5 (2026-09-23) printed `"error": null` beside it, and a reader could not
tell an upstream that was down for an hour from a retry policy that gave up
after four seconds.

`UnsupportedToolCallFormat` is separate from `NoAction` for the same reason
`NoAction` is separate from `Completed`: the two look identical in a marker
line and call for opposite fixes. "The model would not act" is answered by a
better prompt or a better model; "the model acted in a dialect this runner
threw away" is answered in the runner. Measured 2026-09-23 on
`deepseek-v4-flash`, the second was being reported as the first — and before
that, as success. Native `invoke` markup is now translated and executed rather
than counted here; this verdict is what remains when the attempt is one we will
not run unseen.

`NoAction` is its own verdict because the failure it names is invisible
otherwise. Asked in plain language to create a file, a model answered `The file
has been created successfully.` in one turn, called nothing, created nothing —
and the run reported `"completed":true` and exited `0`. The marker now carries
`tool_calls`, the number of tool calls the executor actually carried out, and
`"completed":true` with `"tool_calls":0` cannot be printed.

### Evidence: `run --work-item` and `attach-receipt`

At the end of `arcana run --work-item <id>`, after
`receipts/ReadinessReceipt-<id>.json` is written, the run attaches that receipt
to the work item with `POST /tasks/<id>/evidence`: the sha256 of the receipt's
bytes as read back from disk, `application/json`, and a locator — by default
`file://<absolute path of the receipt>`, or the value of `--evidence-uri`. The
default is the one locator that is true when the attach happens (the receipt
has not been published anywhere else yet); it resolves only on the host that
wrote it, and the digest, not the path, is what identifies the bytes. Muneral
keeps the first locator for a digest and answers the same bytes under a
different one with `409 EVIDENCE_DIGEST_CONFLICT`, so pick `--evidence-uri`
before the first attach, not after.

Attaching evidence does not move the work item's status; that stays with the
control plane.

The outcome is said three times: one `evidence:` line on stdout when it landed,
or one `EVIDENCE_NOT_ATTACHED` line on stderr that names the kept receipt, its
sha256 and the retry command when it did not; an `evidence` object
(`EvidenceAttachOutcome/v1`) in the done-marker; and the same object in
`receipts/ReadinessReceipt-<id>.evidence.json`. A marker of any run without
`--work-item` has no `evidence` key. A failed attach never deletes the receipt.

The retry sends the same bytes again, and a claim that did land the first time
is answered `200` with `idempotent: true` rather than a second record:

```bash
arcana attach-receipt --work-item "<work-item-id>" --receipt "$CWD/receipts/ReadinessReceipt-<work-item-id>.json"
```

Pass `--evidence-uri` with the locator of the first attempt when it was not the
default, and `--record <PATH>` to keep the outcome in a file.

| Code | `attach-receipt` condition |
|------|-----------|
| `0` | Attached: a new record (`201`) or a repeat of a stored one (`200`, `idempotent: true`). |
| `1` | Could not start: no key file, unusable `ARCANA_MUNERAL_URL`, async-runtime failure. |
| `3` | Not attached: Muneral unreachable, `401`/`403`/`404`, `409 EVIDENCE_DIGEST_CONFLICT`, a `400` with a `code`, or a success that names other bytes. |

### `mcp serve` exit codes

`arcana mcp serve` uses the same namespace:

| Code | Condition |
|------|-----------|
| `0` | The server ran (stdio or loopback HTTP) and shut down cleanly after the peer disconnected. |
| `1` | Operational failure: async-runtime start, server assembly (audit dir / `permissions.toml`), or transport error. |
| `2` | `--bind` rejected: the requested address is not loopback (Tier-1 loopback only). Emitted by the bind guard **before** any listener is created. |

The loopback HTTP transport (`--bind`) requires the default `http` build
feature; a build with `--no-default-features` serves stdio only and returns `1`
with a clear message if `--bind` is requested.

## Connector environment overrides

| Variable | Purpose | Default |
|----------|---------|---------|
| `ARCANA_MC_TOKEN` | Bearer token for the Model Connector. Unset/empty → exit path with the `missing API key` message. | *(required)* |
| `ARCANA_MC_BASE_URL` | Diagnostic override accepted only by hidden `mc-ping`, including a loopback replay fixture (`http://127.0.0.1:PORT`). Production `kb-read`, `demo --live`, the interactive `--live` session and `run` reject every override except the exact canonical endpoint — and now FAIL on the rejection instead of silently running offline. | `https://connector.arcanada.ai` |
| `ARCANA_MC_TIMEOUT_SECS` | Per-attempt model budget, `5`..`600` whole seconds; the same number `--request-timeout` sets. A value that is not a whole number of seconds is refused, not silently replaced. | `120` |
| `ARCANA_MC_CONNECT_TIMEOUT_SECS` | How long to wait for TCP+TLS before any byte of the request is sent, `1`..`60` whole seconds. Separate from the model budget on purpose: they bound different failures. Measured from a fleet host on 2026-09-23, `connector.arcanada.ai` connects in ~11 ms of TCP and ~33 ms through TLS, so the default is ~300× the healthy case and exists to bound a black hole. Raise it only where the path itself is slow — a relay, a satellite link; raising it does not help a healthy edge, it only lengthens the pause before the retry. A connect timeout is transient and the turn is re-dispatched. | `10` |

`ARCANA_MC_BASE_URL` lets the smoke gate exercise hidden `mc-ping` against a
recorded fixture server without a live mesh. It is not an agent-loop replay
surface: `kb-read` accepts only `https://connector.arcanada.ai`. See
[`../../dev-tools/smoke/`](../../dev-tools/smoke/).
