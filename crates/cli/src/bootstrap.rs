//! CLI bootstrap — assembles the canonical default permission cascade.
//!
//! `assemble()` wires the Phase 1 chain documented in
//! `docs/reference/architecture.md`: `Schema -> HookBridge -> Rule ->
//! Interactive`.
//!
//! 1. [`SchemaLayer`] validates payloads against the tools registered in a
//!    fresh [`ToolDispatcher`] (only the [`WhoamiProbe`] smoke tool exists
//!    in this build — real tool registration is a separate concern).
//! 2. [`HookBridgeLayer`] wraps a [`HookChain`] carrying an [`AuditHook`]
//!    that appends JSON lines to `<state_dir>/audit.log`. The default entry
//!    point resolves `state_dir` via the XDG state directory
//!    (`~/.local/state/arcana`, created on demand).
//! 3. [`RuleLayer::load`] reads the XDG user-level `permissions.toml` and
//!    an optional project-local `.arcana/permissions.toml`; missing files
//!    are tolerated (see `RuleLayer::load` doc comment).
//! 4. The interactive tail is [`ReadlinePrompt`] when stdin is a TTY,
//!    otherwise [`AutoFromEnv`] (`ARCANA_PERMISSION_AUTO`).
//!
//! [`assemble_at`] takes the state/project paths explicitly so tests never
//! touch the operator's real XDG directories; [`assemble`] is the
//! production entry point that resolves the default paths.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::hooks::audit::{AuditHook, AuditHookError};
use arcana_core::hooks::HookChain;
use arcana_core::permission::{
    AutoFromEnv, HookBridgeLayer, PermissionCascade, PermissionLayer, RuleLayer, RuleLoadError,
    SchemaLayer,
};
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolOutput};
use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::permission_prompt::ReadlinePrompt;

/// Project-local rule file, resolved relative to the current working
/// directory — mirrors `permissions.toml`'s own XDG-plus-project cascade.
const PROJECT_RULES_RELATIVE: &str = ".arcana/permissions.toml";

/// Failure modes raised while assembling the default cascade.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The XDG state directory or the audit log file could not be
    /// created/opened.
    #[error("audit log setup failed: {0}")]
    Audit(#[from] AuditHookError),
    /// An existing `permissions.toml` failed to parse.
    #[error("permissions.toml load failed: {0}")]
    Rules(#[from] RuleLoadError),
}

/// Assembled result of [`assemble`] / [`assemble_at`].
pub struct Bootstrap {
    /// The fully wired cascade, ready for `cascade.evaluate(tool, input)`.
    pub cascade: PermissionCascade,
    /// Absolute path to the audit log file the `HookBridge` layer writes.
    pub audit_log_path: PathBuf,
}

/// Assemble the canonical default permission cascade using the real XDG
/// state directory (`~/.local/state/arcana`, honouring `XDG_STATE_HOME`)
/// and the project-local `.arcana/permissions.toml` (relative to cwd).
///
/// # Errors
/// See [`assemble_at`].
pub fn assemble() -> Result<Bootstrap, BootstrapError> {
    let state_dir = xdg::BaseDirectories::with_prefix("arcana").map_or_else(
        |_| PathBuf::from(".arcana-state"),
        |base| base.get_state_home(),
    );
    let project_rules_path = PathBuf::from(PROJECT_RULES_RELATIVE);
    assemble_at(&state_dir, &project_rules_path)
}

/// Same as [`assemble`], but with the state directory and project rule
/// path passed explicitly — the seam integration tests use to stay off
/// the operator's real `~/.local/state` and `~/.config`.
///
/// # Errors
/// Returns [`BootstrapError::Audit`] when `state_dir` cannot be created or
/// the audit log file cannot be opened, and [`BootstrapError::Rules`] when
/// an existing `permissions.toml` fails to parse.
pub fn assemble_at(
    state_dir: &Path,
    project_rules_path: &Path,
) -> Result<Bootstrap, BootstrapError> {
    let audit_hook = AuditHook::new(state_dir)?;
    let audit_log_path = state_dir.join("audit.log");

    let mut dispatcher = ToolDispatcher::new();
    // Registration only fails on duplicate names; a single fresh probe
    // tool can never collide.
    let _ = dispatcher.register(Arc::new(WhoamiProbe));
    let dispatcher = Arc::new(dispatcher);

    let mut chain = HookChain::new();
    chain.push(Arc::new(audit_hook));

    let cancel = CancellationToken::new();
    let cost = Arc::new(CostTracker::new());

    let user_rules_path = RuleLayer::xdg_user_path().ok();
    let rule_layer = RuleLayer::load(user_rules_path.as_deref(), Some(project_rules_path))?;

    let interactive: Arc<dyn PermissionLayer> = if std::io::stdin().is_terminal() {
        match ReadlinePrompt::with_terminal() {
            Ok(prompt) => Arc::new(prompt),
            Err(_) => Arc::new(AutoFromEnv::from_env()),
        }
    } else {
        Arc::new(AutoFromEnv::from_env())
    };

    let cascade = PermissionCascade::new(vec![
        Arc::new(SchemaLayer::new(dispatcher)),
        Arc::new(HookBridgeLayer::new(Arc::new(chain), cancel, cost)),
        Arc::new(rule_layer),
        interactive,
    ]);

    Ok(Bootstrap {
        cascade,
        audit_log_path,
    })
}

/// Trivial always-schema-valid tool registered purely so the `whoami`
/// smoke command has something for the cascade to walk end-to-end
/// (`SchemaLayer` denies outright on an unregistered tool name, which
/// would never reach `HookBridge`/`AuditHook`).
struct WhoamiProbe;

#[async_trait]
impl Tool for WhoamiProbe {
    fn name(&self) -> &'static str {
        "whoami"
    }

    fn description(&self) -> &'static str {
        "Bootstrap smoke probe — reports the local identity the cascade sees."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({ "type": "object" })
    }

    async fn execute(&self, _input: Value) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            content: local_identity(),
            metadata: None,
        })
    }
}

/// Best-effort local OS identity (`$USER`, falling back to `$USERNAME`,
/// then `"unknown"`). Not the Auth Arcana identity — `arcana login`
/// (ARAS-0008) owns that surface once the upstream device-code endpoint
/// ships; this is a bootstrap-only placeholder.
#[must_use]
pub fn local_identity() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::match_wildcard_for_single_variants
)]
mod tests {
    use super::*;

    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn local_identity_is_never_empty() {
        assert!(!local_identity().is_empty());
    }

    #[tokio::test]
    async fn assemble_at_wires_audit_log_at_state_dir() {
        let state = tempdir().unwrap();
        let project_rules = state.path().join("unused-project-rules.toml");

        let bootstrap = assemble_at(state.path(), &project_rules).unwrap();
        assert_eq!(bootstrap.audit_log_path, state.path().join("audit.log"));

        let _ = bootstrap.cascade.evaluate("whoami", json!({})).await;
        let audit_log_path = bootstrap.audit_log_path.clone();
        // Drop the cascade (and with it the sole `AuditHook` / `WorkerGuard`
        // reference) to force the non-blocking writer to flush before we
        // read the file back — mirrors `crates/core/tests/hooks_audit.rs`.
        drop(bootstrap);

        let contents = std::fs::read_to_string(&audit_log_path).unwrap();
        assert!(
            contents.contains("\"tool\":\"whoami\""),
            "expected whoami audit record, got: {contents}"
        );
        assert!(
            contents.contains("\"phase\":\"pre\""),
            "expected pre-tool phase, got: {contents}"
        );
    }

    #[tokio::test]
    async fn assemble_at_denies_unregistered_tool_at_schema_layer() {
        use arcana_core::permission::CascadeOutcome;

        let state = tempdir().unwrap();
        let project_rules = state.path().join("unused-project-rules.toml");
        let bootstrap = assemble_at(state.path(), &project_rules).unwrap();

        let outcome = bootstrap.cascade.evaluate("no_such_tool", json!({})).await;
        match outcome {
            CascadeOutcome::Denied { layer, reason } => {
                assert_eq!(layer, "schema");
                assert!(reason.contains("unknown tool"));
            }
            other => panic!("expected Denied at schema layer, got {other:?}"),
        }

        // The unknown-tool call never reached HookBridge, so no audit
        // record should have been written for it.
        let contents = std::fs::read_to_string(&bootstrap.audit_log_path).unwrap();
        assert!(!contents.contains("no_such_tool"));
    }

    #[tokio::test]
    async fn assemble_at_tolerates_missing_permissions_toml() {
        let state = tempdir().unwrap();
        let missing_project_rules = state.path().join("does-not-exist/permissions.toml");

        // Should not error even though the project rules path does not exist.
        let bootstrap = assemble_at(state.path(), &missing_project_rules).unwrap();
        let outcome = bootstrap.cascade.evaluate("whoami", json!({})).await;
        // Schema + HookBridge defer, Rule defers (no rules loaded), and the
        // non-interactive tail (no TTY under `cargo test`) denies — the
        // exact verdict is not the point here, only that loading tolerated
        // the missing file instead of raising `BootstrapError::Rules`.
        assert!(matches!(
            outcome,
            arcana_core::permission::CascadeOutcome::Allowed { .. }
                | arcana_core::permission::CascadeOutcome::Denied { .. }
        ));
    }
}
