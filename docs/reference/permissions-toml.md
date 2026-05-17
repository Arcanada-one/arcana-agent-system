# `permissions.toml` reference

Permission rules for the `arcana` CLI. The file is consulted by Layer 3
(`RuleLayer`) of the 4-layer permission cascade
(`Schema → HookBridge → Rule → Interactive`).

## Discovery

The cascade loads rules from two paths in this order:

1. **User-level** — `$XDG_CONFIG_HOME/arcana/permissions.toml`
   (default `~/.config/arcana/permissions.toml`). Resolved via the
   `xdg` crate.
2. **Project-local** — `.arcana/permissions.toml` in the current working
   directory, when present.

Both files are optional. Missing files are tolerated; a file that exists
must parse. Rules from both sources are merged additively per tool —
`allow_*` and `deny_*` patterns from each file all apply, with
`deny_*` evaluated before `allow_*` (see [Evaluation order](#evaluation-order)).

## Hard limits

| Constraint | Value |
|---|---|
| File size cap | 64 KiB |
| `schema_version` invariant | `1` (this build) |
| Regex flavour | RE2-style (Rust `regex` crate; no backtracking) |

A file larger than the cap, declaring an unsupported `schema_version`, or
containing an uncompilable pattern is rejected with a diagnostic. The
loader does NOT silently fall back to an empty rule set; the operator
must fix the file.

## Schema

```toml
schema_version = 1

# Per-built-in-tool sections. Each may set any subset of the five fields.
[tool.<name>]
allow_commands = ['<regex>', ...]   # for shell-command-shaped inputs
deny_commands  = ['<regex>', ...]
allow_hosts    = ['<regex>', ...]   # for URL inputs (host is extracted)
allow_paths    = ['<regex>', ...]   # for filesystem-path inputs
deny_paths     = ['<regex>', ...]

# MCP rules. Tools whose name starts with `mcp:` follow these.
[mcp]
allow = ['<regex>', ...]            # default-deny without an explicit match
```

### Input field selection

`RuleLayer` reads input JSON fields by convention:

| Tool family | Input field consulted |
|---|---|
| `bash` | `command` (string) |
| `webfetch` | `url` (string; host extracted) |
| `read` / `write` / `edit` / similar | `path` (string) |

Tools that publish their input via a different field name are not
restricted by Layer 3 today; the schema gate (Layer 1) is their first
defence. Backlog items ARAS-0021 / ARAS-0022 / ARAS-0023 wire enforcement
into the tool implementations themselves.

## Evaluation order

For a built-in tool with both deny and allow patterns:

1. If the input matches any `deny_*` pattern → **`Deny`** (cascade short
   circuits with reason `"denied by <field> rule \`<pattern>\` on tool
   \`<name>\`"`).
2. If the corresponding `allow_*` set is non-empty:
   * Input matches → **`Allow`** (cascade short circuits).
   * Input does NOT match → **`Deny`** (`"<input-field> does not match any
     allow_<field> rule on tool \`<name>\`"`).
3. If neither side fires → **`Defer`** to Layer 4 (Interactive).

For MCP tools (`mcp:<name>`):

1. Strip the `mcp:` prefix.
2. If any `[mcp] allow` pattern matches → **`Allow`**.
3. Otherwise → **`Deny`** (`"no explicit allow for MCP tool: <name>"`).

This is the **default-deny invariant** for MCP tools (PRD-ARAS-0001
§ 9.2 V-AC-15). It is not configurable; an operator who wants a
permissive MCP posture authors a broad pattern (e.g. `allow = [".*"]`)
explicitly.

## Worked example

```toml
schema_version = 1

# Bash: read-only git/cargo subcommands, hard deny on destructive commands.
[tool.bash]
allow_commands = [
  '^git (status|log|diff|show)',
  '^cargo (build|test|check)',
]
deny_commands = [
  'rm -rf',
  '^sudo ',
]

# WebFetch: docs and GitHub only.
[tool.webfetch]
allow_hosts = [
  '^docs\.rs$',
  '^crates\.io$',
  '\.github\.com$',
]

# Read: inside the workspace; never a secret file.
[tool.read]
allow_paths = ['^/Users/[^/]+/(arcanada|Projects)/']
deny_paths  = ['/\.env', '\.pem$', '\.key$']

# MCP: Linear tools only.
[mcp]
allow = ['^linear/']
```

## Trust model

`permissions.toml` is operator-authored. Trust boundary follows the
local-developer model already used by Claude Code's `settings.json`:
the file is writable by the operator and any process running with the
operator's permissions, and the system is not designed to defend
against an attacker who has already obtained write access to the
operator's home directory. Layer 3 protects against **mistakes** — a
careless `bash` invocation, a typo'd path — not against a hostile
user-account compromise.

## See also

- `docs/how-to/configure-permissions.md` — operator-facing setup guide.
- `crates/core/src/permission/` — implementation.
