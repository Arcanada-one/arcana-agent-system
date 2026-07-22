#![allow(dead_code, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use arcana_core::cost::CostTracker;
use arcana_core::execution::{CapabilityError, CapabilityExecutor};
use arcana_core::hooks::audit::AuditLog;
use arcana_core::hooks::{HookChain, HookContext};
use arcana_core::permission::{LayerDecision, PermissionCascade, PermissionLayer};
use arcana_core::tool::{Tool, ToolDispatcher, ToolError, ToolOutput};
use async_trait::async_trait;
use serde_json::Value;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

struct AllowLayer;

#[async_trait]
impl PermissionLayer for AllowLayer {
    fn name(&self) -> &'static str {
        "test-allow"
    }

    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::Allow
    }
}

/// Test-only facade that drives a concrete built-in through the same sealed
/// executor path used by production.
pub struct Harness {
    name: String,
    schema: Value,
    executor: CapabilityExecutor,
    _audit_dir: TempDir,
}

impl Harness {
    pub fn new<T: Tool + 'static>(tool: T) -> Self {
        let name = tool.name().to_owned();
        let schema = tool.input_schema();
        let mut registry = ToolDispatcher::new();
        registry.register(Arc::new(tool)).expect("register tool");
        let audit_dir = TempDir::new().expect("audit tempdir");
        let audit = AuditLog::new(audit_dir.path()).expect("audit log");
        let executor = CapabilityExecutor::new(
            registry,
            PermissionCascade::new(vec![Arc::new(AllowLayer)]),
            HookChain::new(),
            audit,
        );
        Self {
            name,
            schema,
            executor,
            _audit_dir: audit_dir,
        }
    }

    pub async fn execute(&self, input: Value) -> Result<ToolOutput, ToolError> {
        let ctx = HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()));
        match self.executor.execute(&ctx, &self.name, input).await {
            Ok(result) => Ok(result.output),
            Err(CapabilityError::Tool(err)) => Err(err),
            Err(CapabilityError::Denied {
                layer: "schema",
                reason,
            }) => Err(ToolError::InvalidInput(reason)),
            Err(err) => Err(ToolError::ExecutionFailed(err.to_string())),
        }
    }

    pub fn validate_input(&self, input: &Value) -> Result<(), ToolError> {
        let validator = jsonschema::validator_for(&self.schema)
            .map_err(|err| ToolError::ExecutionFailed(format!("schema compile: {err}")))?;
        if validator.is_valid(input) {
            return Ok(());
        }
        Err(ToolError::InvalidInput(
            validator
                .iter_errors(input)
                .map(|err| err.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }
}
