//! Process supervisor for the `arcana` runtime.
//!
//! A [`Supervisor`] spawns OS children under **process-group ownership**, so a
//! wedged child — and any grandchildren it forks — is always terminable via a
//! `SIGTERM`→`SIGKILL` group escalation (Supreme Directive law 4:
//! detectable/isolatable/terminable). Liveness is watched through a **stdout
//! heartbeat line-protocol** owned by the supervisor; a per-child **wall-clock
//! deadline** bounds runaway work independently of liveness. Crash-looping
//! children are **restarted** within a bounded [`policy::RestartPolicy`] and then
//! **escalated** (a returned signal plus an audit event — never an autonomous
//! hard-gated action). **Budgets** cap concurrency (a [`tokio::sync::Semaphore`])
//! and aggregate cost (the reused `arcana_core::cost::CostTracker`).
//!
//! Every lifecycle event flows into the **existing** Blake3 `audit.log` through
//! the additive `arcana_core::hooks::audit::AuditLog::record_event` seam — the
//! supervisor never opens a second audit sink, and only hashes are persisted.
//!
//! # Security stance
//!
//! Tier-0: there is **no network listener**. The heartbeat is a line-protocol
//! over the child's already-owned stdout file descriptor — no socket, bind, or
//! accept. Signal delivery and process-group control use **safe** wrappers only
//! (`std`/`tokio` `process_group`, the `nix` crate); the workspace
//! `unsafe_code = "forbid"` lint is upheld, and there is no raw `libc`.

#![cfg(unix)]

pub mod error;
pub mod heartbeat;
pub mod policy;
pub mod spawn;
pub mod supervisor;
pub mod terminate;

pub use error::SupervisorError;
pub use policy::{ChildSpec, RestartPolicy, SupervisionOutcome, SupervisorConfig, TerminationCause};
pub use spawn::{spawn_process_group, SpawnedChild};
pub use supervisor::{ChildHandle, Supervisor};
pub use terminate::terminate_group;
