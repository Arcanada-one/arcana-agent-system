//! Layer 4: interactive / auto-mode tail of the cascade.
//!
//! Provides a sealed [`InteractiveLayer`] trait extending [`PermissionLayer`]
//! plus an [`AutoFromEnv`] implementation that resolves the verdict from the
//! `ARCANA_PERMISSION_AUTO` environment variable without touching the
//! terminal. The CLI ships a [`ReadlinePrompt`](https://docs.rs/rustyline)
//! implementation in `crates/cli`; the TUI (ARAS-0015) will eventually add
//! a `RatatuiPrompt`.

use std::env;

use async_trait::async_trait;
use serde_json::Value;

use super::{LayerDecision, PermissionLayer};

/// Environment variable consulted by [`AutoFromEnv`].
pub const ENV_AUTO_DIRECTIVE: &str = "ARCANA_PERMISSION_AUTO";

/// Marker trait for the Layer-4 family. Any concrete impl MUST also be a
/// [`PermissionLayer`]; the marker exists so the cascade builder can assert
/// the tail layer's identity at composition time.
pub trait InteractiveLayer: PermissionLayer {}

/// Parsed value of the `ARCANA_PERMISSION_AUTO` env var.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractiveDirective {
    /// Resolve every call to `Allow` without prompting.
    Allow,
    /// Resolve every call to `Deny` without prompting.
    Deny,
    /// Defer to a terminal prompt; when no terminal is available this
    /// resolves to `Deny("no terminal for interactive prompt")`.
    Ask,
}

impl InteractiveDirective {
    /// Parse a directive from a string. Unknown values fall back to
    /// [`InteractiveDirective::Ask`] — the most conservative default.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" => Self::Allow,
            "deny" => Self::Deny,
            _ => Self::Ask,
        }
    }
}

/// Auto-mode interactive layer driven by the `ARCANA_PERMISSION_AUTO`
/// environment variable.
///
/// Behaviour:
/// * `allow` → `Allow`.
/// * `deny` → `Deny("auto-deny")`.
/// * `ask` (default) → `Deny("no terminal for interactive prompt")`. The CLI
///   replaces this layer with a `ReadlinePrompt` when stdin is a TTY.
pub struct AutoFromEnv {
    directive: InteractiveDirective,
}

impl AutoFromEnv {
    /// Construct a layer by reading `ARCANA_PERMISSION_AUTO` from the
    /// process environment at call time.
    #[must_use]
    pub fn from_env() -> Self {
        let directive = env::var(ENV_AUTO_DIRECTIVE).map_or(InteractiveDirective::Ask, |raw| {
            InteractiveDirective::parse(&raw)
        });
        Self { directive }
    }

    /// Construct a layer with an explicit directive — exposed for tests
    /// and CLI bootstrap that resolves the directive elsewhere.
    #[must_use]
    pub fn with_directive(directive: InteractiveDirective) -> Self {
        Self { directive }
    }
}

#[async_trait]
impl PermissionLayer for AutoFromEnv {
    fn name(&self) -> &'static str {
        "interactive_auto"
    }

    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        match self.directive {
            InteractiveDirective::Allow => LayerDecision::Allow,
            InteractiveDirective::Deny => LayerDecision::Deny("auto-deny".to_string()),
            InteractiveDirective::Ask => {
                LayerDecision::Deny("no terminal for interactive prompt".to_string())
            }
        }
    }
}

impl InteractiveLayer for AutoFromEnv {}
