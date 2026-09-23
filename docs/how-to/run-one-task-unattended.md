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
| `--request-timeout <secs>` | How long one model turn may take upstream, `5`..`600` (default `120`). `ARCANA_MC_TIMEOUT_SECS` sets the same number. |

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
| `reason` | The terminal verdict (`Completed`, `NoAction`, `PermissionDenied`, `MaxTurns`, `NotStarted`, …). |
| `turns` | Connector attempts consumed. |
| `tool_calls` | Tool calls the executor **actually carried out**. Not intent: a call the policy refused, or one the model only described in prose, is not counted. |
| `cost_usd_micros` | Spend for the run, in micro-USD. |

| Exit code | Meaning |
|-----------|---------|
| `0` | The run completed and executed at least one tool call. `completed` is `true`. |
| `1` | The run failed, or never started (no key, unreachable connector, bad `--cwd`, missing task, unreadable `permissions.toml`), or ended on `NoAction`. |
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

### What this is not

The path checks are exact. **The shell check is a heuristic over the command
string, not a sandbox.** There is no namespace, no seccomp filter and no
chroot under it, so an obfuscated payload — a path assembled inside a
`python3 -c`, a base64 blob, a path passed through a variable the policy never
sees expanded — can still reach outside the working directory.

Run it in something you can throw away: a disposable checkout or a git
worktree, on a host whose integrity does not depend on this check.

## Why a task can silently do nothing (and no longer does)

The driver recognises exactly one tool-call encoding — a fenced
```` ```tool_call ```` block whose body is `{"name": ..., "input": ...}` — and
fails closed to "this was the final answer" on anything else. A model that has
not been told so answers a request to run a command with a ```` ```bash ````
block, which reads exactly like an action and is only text.

`run` states the wire format and the tool catalogue in its system prompt,
built from the tools that are actually registered, so the description cannot
drift from the dispatcher. If you are adding a surface that drives the agent
loop, do the same, and test it by the file on disk rather than by what the
model said it did.

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

A turn that still fails in a way that says nothing about the request — a
timeout, a gateway status, an upstream envelope marked `retryable` — is
re-dispatched up to twice before the run ends. Each re-dispatch is an ordinary
attempt: it consumes a turn from `--max-turns` and is charged against
`--max-cost-usd`, so a connector that is down cannot quietly spend the run's
whole budget. Errors that will fail identically forever — a missing key, an
unknown connector id, a policy refusal — are not retried.

Raising the budget above 120 s only helps where the Model Connector is reached
directly. The public origin sits behind an edge proxy that cuts any single
request at about 125 s (measured 2026-09-23: three `/execute` calls cut at
125.1 s, 125.2 s and 125.3 s with HTTP 524), and no client setting moves that
ceiling. A turn that genuinely needs longer than the edge allows needs a
different shape of request, not a longer timeout.
