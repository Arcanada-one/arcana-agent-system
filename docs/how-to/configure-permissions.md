# How to configure tool permissions

This guide shows how to restrict what the `arcana` CLI is allowed to do
on your machine. Read the [`permissions.toml` reference](../reference/permissions-toml.md)
first if you have not seen the file format before.

## Step 1 — pick a file location

User-level (recommended for personal rules that follow you across
projects):

```bash
mkdir -p ~/.config/arcana
$EDITOR ~/.config/arcana/permissions.toml
```

Project-local (committed into a repo to enforce team-wide rules):

```bash
mkdir -p .arcana
$EDITOR .arcana/permissions.toml
```

The cascade reads the user-level file first, then merges any
project-local file on top. Both are optional.

## Step 2 — start from a safe baseline

Copy this minimal restrictive baseline:

```toml
schema_version = 1

# Bash: read-only git/cargo only.
[tool.bash]
allow_commands = [
  '^git (status|log|diff|show|branch)',
  '^cargo (build|test|check|clippy|fmt)',
]
deny_commands = [
  'rm -rf',
  '^sudo ',
  '> /dev/sd[a-z]',
]

# WebFetch: docs surfaces only.
[tool.webfetch]
allow_hosts = [
  '^docs\.rs$',
  '^crates\.io$',
  '\.rust-lang\.org$',
]

# Read/Edit/Write: stay inside the workspace; never touch secrets.
[tool.read]
allow_paths = ['^/Users/[^/]+/(arcanada|Projects)/']
deny_paths  = ['/\.env(\.|$)', '\.pem$', '\.key$']

[tool.write]
allow_paths = ['^/Users/[^/]+/(arcanada|Projects)/']
deny_paths  = ['/\.env(\.|$)', '\.pem$', '\.key$']

[tool.edit]
allow_paths = ['^/Users/[^/]+/(arcanada|Projects)/']
deny_paths  = ['/\.env(\.|$)', '\.pem$', '\.key$']

# MCP: default-deny is the invariant; whitelist explicitly.
[mcp]
allow = []
```

## Step 3 — verify your rules compile

The first time you run any tool after editing `permissions.toml`, the
loader compiles every pattern. A bad regex shows up as a startup error
with the offending pattern, section, and the underlying `regex` error:

```
permissions.toml: invalid regex `(unclosed` at [tool.bash]: regex parse error ...
```

Fix the file and re-run.

## Step 4 — broaden cautiously

When a tool gets denied during a real workflow, the cascade surfaces a
reason like:

```
denied by deny_commands rule `rm -rf` on tool `bash`
```

or

```
command does not match any allow_commands rule on tool `bash`
```

The first form means you matched a `deny_*` — keep the deny and run the
command outside the agent. The second form means you need to extend the
`allow_*` list. Add the narrowest pattern that covers your case, never
`'.*'`. Project-local rules are additive, so a team-wide
`.arcana/permissions.toml` can layer extra denies on top of personal
allows without conflicts.

## Step 5 — MCP tools

MCP tools (any tool name starting with `mcp:`) default to **`Deny`**.
To grant access you write an explicit `[mcp] allow` pattern that
matches the post-prefix name:

```toml
[mcp]
allow = [
  '^linear/',                # everything in the Linear MCP server
  '^slack/list-channels$',   # one specific Slack tool
]
```

The `mcp:` prefix is stripped before matching, so `mcp:linear/list-issues`
matches the pattern `^linear/`.

## Interactive mode (Layer 4)

When a built-in tool falls through Layer 3 without an allow/deny
match, the cascade hands the decision to Layer 4. Today this is
controlled by the `ARCANA_PERMISSION_AUTO` environment variable:

| Value | Behaviour |
|---|---|
| `allow` | Approve every fallthrough silently |
| `deny` | Reject every fallthrough silently |
| `ask` (default) | Without a TTY, reject and report `"no terminal for interactive prompt"` |

A future release will replace `ask` with a TTY prompt
(`yes` / `no` / `yes-once` / `yes-forever`) when the CLI runs in an
interactive shell. Until then, set `ARCANA_PERMISSION_AUTO=allow` in
development shells and write explicit rules for CI.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Cascade refuses with `unsupported schema_version` | Bump your file to `schema_version = 1` |
| Startup error citing a regex at a specific line | Fix the regex (RE2 grammar, no lookahead/lookbehind) |
| `no explicit allow for MCP tool` on every MCP call | You need a `[mcp] allow` entry |
| Built-in tool always denied via Layer 4 | `ARCANA_PERMISSION_AUTO` is `deny` or unset on a non-TTY |
| Project rules don't seem to apply | Confirm `.arcana/permissions.toml` is in the current working directory the CLI was launched from |
