# How-to: testing

> Stub — full strategy lands during Phase 1 plan.

## Commands

```bash
cargo test --workspace                 # unit + integration
cargo test --workspace -- --nocapture  # with stdout
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Coverage expectation

Unit tests: ≥80% line coverage on `crates/core` once it grows past skeleton.
Integration tests: at least one E2E scenario per ecosystem connector (Auth Arcana, MC, Vault, Scrutator) before declaring connector READY.

## CI gates

- `cargo build --release` — clean compile.
- `cargo test --workspace`.
- `cargo clippy -- -D warnings`.
- `cargo audit --deny warnings` (security floor per Arcanada Ecosystem Security Policy Mandate).
- `cargo deny check advisories licenses`.
