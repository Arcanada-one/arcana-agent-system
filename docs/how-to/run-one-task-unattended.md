# Run one task unattended

Task-oriented guide to `arcana run` — one task, one working directory, no
human at the prompt.

Use it when a runner (a card dispatcher, a CI step, a `tmux` session that must
survive a laptop going offline) needs the agent to actually change files and
report whether it worked.

## The command

```bash
arcana run --cwd /path/to/worktree --prompt-stdin <<'TASK'
Add a `--version` flag to the CLI and update the README.
TASK
```

| Flag | Meaning |
|------|---------|
| `--cwd <dir>` | The working directory. Every tool is rooted here and paths outside it are refused. Required. |
| `--prompt <text>` | The task, given literally. |
| `--prompt-stdin` | Read the task from stdin. Preferred: no quoting, no shell metacharacters, no task text in the process list. |
| `--max-turns <n>` | Connector-attempt cap (default `24`). |
| `--max-cost-usd <n>` | Spend cap for the run. |
| `--model <id>` | Pin a model instead of the saved `arcana models use` choice. |
| `--request-timeout <secs>` | How long one model turn may take upstream, `5`..`600` (default `120`). `ARCANA_MC_TIMEOUT_SECS` sets the same number. The separate TCP+TLS connect budget is `ARCANA_MC_CONNECT_TIMEOUT_SECS` (`1`..`60`, default `10`). |
| `--context-budget <units>` | Ceiling the serialized transcript is held under, in UTF-16 code units, `1`..`100000` (default `90000`). Lower it for a model whose own context window is below the connector's field limit, or to exercise compaction deliberately. A value above `100000` is refused before the run starts. The run prints the number it is working to. |
| `--tool-result-budget <units>` | Ceiling on ONE tool result inside the transcript, in UTF-16 code units, `240`..=`--context-budget` (default `8000`). Output past it is elided head-and-tail, the whole of it goes to `.arcana/tool-output/`, and the marker left behind names that file. Lower it to exercise that path deliberately. Below `240` (the marker's own size) or above this run's transcript ceiling is refused before the run starts. |
| `--save-transcript <path>` | Append the exact request of every dispatch to this file. Off by default — it is the conversation in clear text. Per dispatch, not once at the end: a run that compacts does not carry its early turns into the last request. A path that cannot be appended to is refused before the run starts. |

Exactly one of `--prompt` and `--prompt-stdin` is required.

`run` is **always live**. It needs `ARCANA_MC_TOKEN` and it costs money. There
is no offline mode: the offline connector replays two canned turns, and
replaying them against a real working directory would produce a receipt for
work that never happened.

## Reading the result

The last line of stdout is always the done-marker:

```
ARCANA_RUN_DONE {"completed":true,"reason":"Completed","turns":3,"tool_calls":2,"cost_usd_micros":59,"workspace":"/path/to/worktree","error":null}
```

It is printed even when the run never started, so a runner never has to
interpret its absence — which looks identical to a crash.

| Field | Meaning |
|-------|---------|
| `completed` | The run did the work. Never `true` with `tool_calls` at `0`. |
| `reason` | The terminal verdict (`Completed`, `NoAction`, `ResponseTruncated`, `UnsupportedToolCallFormat`, `PermissionDenied`, `MaxTurns`, `NotStarted`, …). |
| `turns` | Connector attempts consumed. |
| `tool_calls` | Tool calls the executor **actually carried out**. Not intent: a call the policy refused, or one the model only described in prose, is not counted. |
| `cost_usd_micros` | Spend for the run, in micro-USD. |

| Exit code | Meaning |
|-----------|---------|
| `0` | The run completed and executed at least one tool call. `completed` is `true`. |
| `1` | The run failed, or never started (no key, unreachable connector, bad `--cwd`, missing task, unreadable `permissions.toml`), or ended on `NoAction`, `ResponseTruncated` or `UnsupportedToolCallFormat`. |
| `130` | The operator interrupted it. The spend line above the marker is what the interrupted dispatch cost. |

### A run that claimed to have done the work

`tool_calls` exists because a claim is not evidence. Asked in plain language to
create a file, a model answered `The file has been created successfully.` in
one turn, called no tool, created no file — and the run printed
`"completed":true` and exited `0`. Three runs in five did this.

Two things stop it now:

* When the first answer contains no tool call, the loop tells the model once
  that nothing was executed and asks it to act. This costs one extra dispatch
  and recovers most such runs.
* If the model still answers without acting, the run ends on `NoAction`:
  `"completed":false`, exit `1`. The final text is still printed — it is paid
  for — but it is not a verdict.

A run that legitimately needs no change ("check whether X is true") must
therefore still demonstrate it with a tool call, for example by reading the
file it is reporting on. That is the intended trade: the command exists to
change a working directory, and an unattended run that changed nothing and was
read as success is the failure this whole surface is for.

### A reply that ran out of room

`NoAction` answers "the model would not act". A different failure looks
identical from the outside and needs the opposite response: the model *was*
acting and its reply was cut off by its own output limit part-way through the
`tool_call` block. Measured 2026-09-23 asking DeepSeek for a 3000-word file —
~9148 output tokens of `tool_call`, no closing fence, no file, $0.040 spent,
verdict `NoAction`.

The loop now tells them apart. A block that opened and never closed is a
cut-off reply:

* the half-written call is **never executed**, even when the JSON inside it
  happens to be complete — the model never said it had finished emitting it;
* the fragment is discarded rather than fed back into the history as something
  the model said;
* the turn is re-dispatched **once**, carrying an instruction to do the work in
  smaller pieces (write the first part of the file now, append the rest in
  later turns). That re-dispatch spends a turn from `--max-turns` and is
  charged against `--max-cost-usd` like any other attempt;
* if the second reply is cut off too, the run ends on `ResponseTruncated`:
  `"completed":false`, exit `1`, and a message that names the output limit
  instead of blaming the model for not acting.

What this does not catch: a reply truncated before it opened a `tool_call`
fence at all is indistinguishable from a short answer. Model Connector returns
no finish/stop reason for ARAS to read
(`src/connectors/interfaces/connector.interface.ts:42`; the DeepSeek adapter
does not decode `choices[].finish_reason` either), so an open fence is the only
local evidence there is.

Every tool call, allowed or denied, is appended to the audit log named on the
second line of stdout (`~/.local/state/arcana/run/audit.log`, mode 0600).

## What the agent may do

Registered tools: `read`, `write`, `edit`, `grep`, `bash`. `webfetch`,
`arcana_search` and `model_call` are deliberately **not** registered — each
reaches outside the working directory by definition, and the workspace policy
could not confine them.

The policy that replaces the interactive prompt:

* **Paths** (`read` / `write` / `edit` / `grep`) are canonicalized — symlinks,
  `..`, the lot — and must land inside `--cwd`. Prefer relative paths.
* **Shell commands** run in `--cwd`, under the execution boundary's clean
  environment (`HOME` is a sandbox dir, `PATH` is the safe system path). A
  command is refused when it names a path outside the working directory, walks
  out with `..`, or starts a refused program: privilege escalation (`sudo`,
  `su`, `doas`), host lifecycle and service control, package managers, raw
  device and filesystem tools, ownership and permission changes, signals to
  other processes (`kill`, `pkill`), remote shells and file copies (`ssh`,
  `scp`, `rsync`), `rm` with recursive **and** force flags, `git push --force`,
  `git reset --hard`, `git clean`, `git stash`, `git filter-branch`.
* **`.arcana/permissions.toml`** inside the working directory (and the
  XDG user file) is still honoured, and its denials come first. Unlike the
  interactive session, a rule file that fails to parse **stops the run** —
  there is nobody to read a warning, and running on under a policy the
  operator did not write is worse than not running.
* `ARCANA_PERMISSION_AUTO=deny` still stops everything. `ARCANA_PERMISSION_AUTO=allow`
  no longer waives the workspace boundary: the boundary is evaluated before it.

A refused call ends the run with `PermissionDenied` rather than looping.

**The model is told this list, in full, in its system prompt.** It is generated
from the same constants the policy evaluates, so a command added to the floor
appears in the next run's prompt without anybody editing prose, and it names
the permitted alternatives — `rm -r <dir>` without `-f` deletes a tree and is
allowed; `mkdir` a fresh sub-directory rather than reaching for `git clean`.

That disclosure is deliberate and it is not a downgrade. A floor refusal is
still never handed *back* to the model as a correction — answering a model that
has just probed for an effect invites a hunt for a synonym the list does not
carry. Telling it the rule before it acts is a different act, and the cost of
not doing it was measured: pilot A2-231 (2026-09-23) ran 78 turns, 62 tool
calls and $0.27, then asked for `rm -rf` on its own scratch directory and lost
all of it to a flag. The floor was right; the model had never been told, and
`rm -r` would have done what it wanted. This is also not a security boundary in
the first place — see *What this is not* below.

### What this is not

The path checks are exact. **The shell check is a heuristic over the command
string, not a sandbox.** There is no namespace, no seccomp filter and no
chroot under it, so an obfuscated payload — a path assembled inside a
`python3 -c`, a base64 blob, a path passed through a variable the policy never
sees expanded — can still reach outside the working directory.

Run it in something you can throw away: a disposable checkout or a git
worktree, on a host whose integrity does not depend on this check.

## Why a task can silently do nothing (and no longer does)

The driver executes exactly one tool-call encoding — a fenced
```` ```tool_call ```` block whose body is `{"name": ..., "input": ...}`. `run`
states that format and the tool catalogue in its system prompt, built from the
tools that are actually registered, so the description cannot drift from the
dispatcher. If you are adding a surface that drives the agent loop, do the
same, and test it by the file on disk rather than by what the model said it
did.

What changed is what happens to a reply that is *not* in that encoding. It used
to fail closed to "this was the final answer" — including when the reply was
plainly a request to run a command. Measured 2026-09-23 on `deepseek-v4-flash`,
turn one of a real task arrived as DeepSeek's own markup:

```text
<｜｜DSML｜｜ invoke name="bash">
<｜｜DSML｜｜ parameter name="command" string="true">ls -la</｜｜DSML｜｜ parameter>
</｜｜DSML｜｜ invoke>
```

The loop read it as prose and ended the run `"completed":true`,
`"reason":"Completed"` with nothing done. The model had asked for a shell
command in the only dialect it knew; the runner answered by calling the job
finished.

A reply that asks for a tool is no longer an answer, whatever it is written in:

* **`invoke` markup** — DeepSeek's `DSML` form and the sentinel-less
  `<invoke name="…"><parameter name="…">…</parameter></invoke>` form — is
  translated into a real call and executed. Those tags exist for nothing else,
  so a closed one is not a guess about intent. The translated call goes through
  the whole permission cascade exactly like a canonical one.
* **The `<tool_call>` XML wrapper** — `<tool_call>{"name": …, "arguments": …}
  </tool_call>`, what the Hermes/Qwen function-calling chat template instructs
  a model to emit — is translated and executed on the same terms. It cost a run
  the same way the `invoke` markup did: measured 2026-09-23, the last reply of
  a long task was a complete, correct `bash` call in the wrapper, and the run
  ended `Completed` with that text handed back as the answer. The bar is a
  *closed* wrapper whose body is a JSON object naming a tool; an unclosed one,
  or one wrapped around an apology, is corrected instead. A `` `<tool_call>` ``
  written inside backticks stays prose — a model explaining the format has
  answered, and an answer must not cost a turn.
* **Anything else recognisable** — a `tool_call` block whose body is not usable
  JSON, a bare OpenAI-shaped `{"name": …, "arguments": …}` object — is **not**
  executed. The model is told once, in full, what encoding this runner reads,
  and the run ends on `UnsupportedToolCallFormat` (`"completed":false`, exit
  `1`) if the next reply is in an unreadable format too. A JSON object shaped
  like a tool call can appear inside an explanation of tool calling, so it is
  corrected rather than run.
* **Arguments under any spelling** — `input`, `arguments`, `parameters`, `args`,
  including OpenAI's JSON-encoded-string form — reach the tool. They used to be
  read only under `input`, so a call spelt any other way was dispatched with no
  arguments at all and refused for a mistake the model had not made. A block
  that names a tool and carries no arguments under *any* spelling is corrected
  rather than dispatched as JSON `null`, which could only ever be a schema
  denial.

A ```` ```bash ```` block, a shell transcript, or a description of what you
would run is still only text: it names no tool, so there is nothing to
translate and nothing to correct.

## Long runs: the transcript and the request contract

Every turn sends the whole conversation so far. Model Connector's `/execute`
caps `prompt` and `systemPrompt` at **100 000 UTF-16 code units each**
(`src/connectors/dto/execute.dto.ts:53,55`) and refuses an over-long field with
an HTTP 400 before the model is reached — so a long run used to end, mid-work,
on a validation error it could have avoided. Measured 2026-09-23: a run that
had executed five tool calls and cloned a repository died at turn 10.

Three things keep a request inside that contract, by construction:

* **The instructions travel separately.** The tool catalogue, the wire format
  and the workspace boundary go in `systemPrompt`, which has its own 100 000
  and does not compete with the transcript for room.
* **Every tool result is bounded when it enters the transcript** — head and
  tail, with a marker stating how many characters were removed. Nothing is
  lost: the complete output is written to `.arcana/tool-output/` inside the
  working directory and the marker names the file, so the model reads the part
  it needs with one more tool call instead of re-running the command. Those
  files are runner artefacts and are untracked; a `git diff` or a patch built
  from one is unaffected.
* **Older turns are folded into a summary** when the transcript still does not
  fit — oldest first, never the task framing and never the turn being answered.
  The run says so on stderr (`arcana: transcript compacted …`) and counts it in
  the done-marker's `compactions` field, because a model answering from a
  summary of its own history is a fact the reader of a log deserves.

The ceiling is `--context-budget`, default 90 000 — ten percent under the wall,
so a dispatch that touches 100 000 is a defect in the guard rather than a
budget set slightly too high. Lowering it is how the folding is exercised on
purpose: a six-file task run at `--context-budget 12000` on `deepseek-flash`
compacted five times, folded nine entries into one summary at the first
overflow (29 064 → 1 217 characters), and still finished with the right file on
disk (`"compactions":5,"completed":true,"tool_calls":20`, $0.015).

A request that still cannot be made to fit ends the run on `RequestTooLarge`,
naming the limit — never on `ConnectorFatal`, which would blame the connector
for keeping its contract. The counting is in UTF-16 code units, the unit the
server counts in: on Russian or Chinese text a byte count is wrong by a factor
of three, in the direction that sends an over-limit request.

## When the runner throws a reply away

A reply the loop cannot act on — a tool call in a format it cannot read, or one
the model's output limit cut off mid-block — is written to
`.arcana/rejected/NNNN-turnT.txt` inside the working directory, byte for byte
with nothing prepended, and the line on stderr names the file:

```
arcana: the model asked for a tool as a fenced `tool_call` block — your `tool_call`
block named `edit` but carried no arguments; put them in an `input` object …;
nothing was executed — the reply as the model sent it is in
/path/to/worktree/.arcana/rejected/0003-turn34.txt
```

Read the file, not the message. The message is what the runner made of the
reply; the file is what the model sent, and a correction is only ever as good as
the reply it was written against. This exists because a run that died
`UnsupportedToolCallFormat` on the one call that mattered used to leave nothing
at all: the audit log keeps `input_hash`/`output_hash` and no text.

Two more things the same defect asked for:

* **`audit.log` carries per-turn request sizes** — one
  `{"kind":"dispatch","fields":{"turn","model","prompt_utf16","system_prompt_utf16"}}`
  record per dispatch, written before the request goes out. Sizes, never text:
  that is what makes the log safe to keep. `system_prompt_utf16` is `null` when
  there is no system prompt, not `0`.
* **`--save-transcript <path>`** keeps the requests themselves, when you ask for
  them. That is the only way to read a compacted run afterwards.

The directory is untracked, like `.arcana/tool-output/`: it is the runner's
evidence about the run, not the task's output, so it does not turn up in a patch
the task hands back.

## Slow turns

A reasoning model writing a long file takes minutes, and a run used to die on
the first turn that did: the client waited a fixed 120 s, and any turn slower
than that ended the whole run as `ConnectorFatal` — an hour of work lost to one
slow answer.

Two numbers govern a turn now, and both come from `--request-timeout`
(default `120`, or `ARCANA_MC_TIMEOUT_SECS`):

* the **model budget** travels with the request, so the Model Connector gives
  the dispatch that long. Without it the server applies the connector's own
  default, which is 30 s for most API connectors — no client-side patience can
  widen that;
* the **wait** is the budget plus what the server may spend around it: up to
  60 s of queue, a second server-side attempt, and backoff. At the default
  that is 310 s. The client never gives up on a turn the server is still
  working on.

A turn that still fails in a way that says nothing about the request is
re-dispatched before the run ends. Each re-dispatch is an ordinary attempt: it
consumes a turn from `--max-turns` and is charged against `--max-cost-usd`, so
a connector that is down cannot quietly spend the run's whole budget. Errors
that will fail identically forever — a missing key, an unknown connector id, a
policy refusal — are not retried.

How many re-dispatches depends on **who** refused, because the two answers heal
on different clocks:

| Failure | Re-dispatches | Pause |
|---|---|---|
| A gateway status (502, 503, 504, 520–524) whose body is neither the connector-response envelope nor a `NestJS` envelope — i.e. the edge in front of Model Connector, not Model Connector | 5 | 2 s, 4 s, 8 s, 16 s, 30 s, each shortened by up to half at random |
| Anything else transient — a client timeout, a `retryable` envelope Model Connector authored, a 429 | 2 | 2 s flat |
| An upstream that named its own `retryAfter` | as above | what it asked for, capped at 60 s |

Worst case, five gateway re-dispatches add **60 s of waiting** to a turn on top
of the five dispatches themselves; jitter only ever shortens a pause, so that
is a ceiling and not an average. Across all classes a single turn may spend at
most 120 s asleep between re-dispatches — the bound that matters when an
upstream names a long `retryAfter` — and a turn that reaches it ends the run
saying so rather than waiting on.

The asymmetry is the point. An envelope Model Connector authored already has
Model Connector's own server-side attempts behind it, so a long client wait on
top buys little. An edge verdict means the request never reached a decision at
all: measured on pilot A2-204c5 (2026-09-23), a 94-turn run with its work
finished died on **three** `HTTP 502 … error code: 502` — 16 bytes of
Cloudflare — inside about four seconds, which is not a serious attempt to
outlast an edge.

> **A gateway retry is not paid for twice.** Model Connector settles the charge
> in the same transaction as the request row *before* the response is written
> to the socket, so a request the edge cut may already have been executed and
> billed. Every dispatch therefore carries an `Idempotency-Key` —
> `arcana.<run-uuid>.<turn>`, the same value on every re-dispatch of one turn
> and a fresh one on the next — and a request that was executed under it comes
> back as a stored replay rather than a second provider call. The retry line
> says so:
>
> ```
> arcana: HTTP 502 is the gateway in front of the Model Connector, not the Model
> Connector — retrying this turn in 4.0s (2 of 5) — the cut request may already
> have been executed and charged upstream, so the re-dispatch carries the same
> Idempotency-Key and is replayed rather than charged again
> ```
>
> A failure Model Connector itself reported carries no such clause: there the
> provider call failed, the hold was released and nothing was charged.
>
> Before A2-234 no key was sent, and the same line could only warn that the
> re-dispatch "may be a paid duplicate" — which, with five gateway
> re-dispatches allowed, was up to five charges for one turn.

A third class joins the two in the table above. When the first attempt of a
turn is **still running upstream**, Model Connector refuses the re-dispatch
with `idempotency_conflict` rather than starting a second paid request. The
loop waits it out on the same key and the patient schedule, because the answer
is being produced and is already paid for — and because reissuing under a new
key is precisely what would be dispatched and charged twice:

```
arcana: the first attempt of this turn is still running upstream — waiting for
the answer it is already producing rather than dispatching a second paid one,
retrying this turn in 8.0s (3 of 5)
```

Two other answers are terminal. `idempotency_replay_unavailable` means the
request completed and was charged exactly once but its answer was too large to
store — the run stops and the verdict says the turn was paid for, rather than
implying it never ran. `idempotency_key_reused` means the key belonged to a
different request; nothing of ours was dispatched or charged under it, so the
turn is re-dispatched under a fresh key, and the line that reports it says
outright that it is a defect in `arcana` rather than in the connector.

When the re-dispatches are spent, the run ends `ConnectorFatal` — and the
verdict names the status, the attempts and how long they took, in the marker's
`error` field and on stderr:

```
arcana run: the Model Connector could not complete the request (ConnectorFatal):
HTTP 502 after 6 attempt(s) over 63s — the 5 re-dispatch(es) allowed for a
transient gateway failure in front of the Model Connector are spent: upstream
returned a non-contract error body (16 bytes): error code: 502
```

Without those three numbers "the upstream is down" and "the retry policy was
four seconds long" read identically, which is exactly what the pilot's
`"error": null` left behind.

Raising the budget above 120 s only helps where the Model Connector is reached
directly. The public origin sits behind an edge proxy that cuts any single
request at about 125 s (measured 2026-09-23: three `/execute` calls cut at
125.1 s, 125.2 s and 125.3 s with HTTP 524), and no client setting moves that
ceiling. A turn that genuinely needs longer than the edge allows needs a
different shape of request, not a longer timeout.
