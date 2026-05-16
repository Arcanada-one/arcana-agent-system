# Security Policy

> Per Arcanada Ecosystem Security Policy Mandate.
> Canonical template: Datarim `templates/SECURITY.md`.
> Bootstrap stub — full content lands in Phase 1.

## Reporting

Report vulnerabilities to **security@arcanada.one** (forwarded to `paxbeach@gmail.com`). Public GitHub issues for security topics will be closed and asked to redirect to email.

## Supported Versions

| Version | Supported |
|---|---|
| 0.x | development only — no production usage yet |

## Disclosure SLA

- 72h acknowledgement
- 7d triage
- 90d HIGH/CRITICAL fix
- 180d MEDIUM
- best-effort LOW
- coordinated public disclosure within 14 days of fix or 120 days after report (whichever sooner)

## CI Gate Floor

Stack: `rust_cargo`.

- `cargo audit --deny warnings`
- `cargo-deny check advisories licenses`

Reusable workflow invocation: `Arcanada-one/datarim/.github/workflows/reusable-security-audit.yml@main` with `stack: rust_cargo`. (Wired during Phase 1 once `Arcanada-one/arcana-agent-system` repo exists.)

## Accepted Risks

Source-of-truth: `accepted-risk.yml`. Currently empty.

## Hardening Baseline

*(populated in Phase 1 — based on Claude Code references + ecosystem patterns)*

## Standards Mapping

*(populated in Phase 1)*

## Embargo Policy

Standard 90-day embargo for HIGH/CRITICAL. Coordinated disclosure preferred.

## Hall of Fame

*(empty)*

## Scope

In scope: source under `Arcanada-one/arcana-agent-system` and any published artefacts on crates.io / GitHub Releases.
Out of scope: third-party crates (report upstream); reference materials in `claude-code-origin/` and `claude-code-haha/` (not part of this project's source).
