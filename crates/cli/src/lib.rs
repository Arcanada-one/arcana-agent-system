//! Library facade for the `arcana` CLI binary.
//!
//! Hosts modules that are exercised both by the binary (`main.rs`) and by
//! integration tests. The binary stays a thin entrypoint; the substantive
//! logic lives here so it can be unit-tested without spawning a subprocess.

pub mod bootstrap;
pub mod demo;
pub mod kb_read;
pub mod permission_prompt;
pub mod repl;
