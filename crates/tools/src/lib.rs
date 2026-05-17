//! Built-in tools for the arcana agent.
//!
//! Each tool implements the `arcana_core::Tool` trait and is dispatched
//! through `ToolDispatcher`. The set is intentionally minimal in Phase 1:
//! filesystem I/O (Read, Write, Edit), text search (Grep), shell execution
//! (Bash), and HTTP fetch (`WebFetch`). All tools declare a JSON Schema for
//! input; the schema layer of the permission cascade validates against it
//! before dispatch.

pub mod bash;
pub mod edit;
pub mod grep;
pub mod read;
pub mod webfetch;
pub mod write;
