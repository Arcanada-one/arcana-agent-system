//! `arcana-skills` — the skills-engine.
//!
//! A skill is **declarative data**, not code: a [`plan::SkillPlan`] names the
//! stages a skill runs, the model each stage uses, its agent-count, limits,
//! tool allowlist, and metrics, plus a template↔instance distinction and a
//! `draft → validated → production` maturity ladder. The
//! [`interpreter::SkillInterpreter`] loads a plan from a data file **on every
//! invocation** and executes its stages in declared order, each stage routed
//! through the already-merged `arcana_core::execution::CapabilityExecutor`
//! (single Blake3 audit + permission cascade). Because the plan is re-read from
//! disk each run, a bumped on-disk version is picked up on the *next run* of
//! the same binary — a data reload, never a recompile.
//!
//! The engine opens **no** audit sink and **no** dispatch path of its own; the
//! executor it borrows is the sole execution authority.

pub mod builder;
pub mod interpreter;
pub mod plan;
