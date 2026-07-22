//! Built-in tools for the arcana agent.
//!
//! Each tool implements the `arcana_core::Tool` trait and is dispatched
//! through `ToolDispatcher`. The set is intentionally minimal in Phase 1:
//! filesystem I/O (Read, Write, Edit), text search (Grep), shell execution
//! (Bash), HTTP fetch (`WebFetch`), and ecosystem knowledge-base search
//! (`ArcanaSearch`, backed by Scrutator). All tools declare a JSON Schema
//! for input; the schema layer of the permission cascade validates against
//! it before dispatch.

pub mod arcana_search;
pub mod bash;
pub mod edit;
pub mod grep;
pub mod model_call;
pub mod path_guard;
pub mod read;
pub mod webfetch;
pub mod write;
