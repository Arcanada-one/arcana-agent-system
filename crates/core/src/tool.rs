//! Tool trait + dispatcher seam.
//!
//! Tools are the only place the agent loop is permitted to perform
//! external I/O. The trait is intentionally minimal in Phase 1: name,
//! human-readable description, JSON-Schema for the input, and an async
//! `execute` step. Built-in tools (Read/Edit/Write/Bash/Grep/WebFetch)
//! land in a subsequent task; the dispatcher here only owns the registry
//! and the lookup path.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;

/// Successful tool result fed back into the agent loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub content: String,
    pub metadata: Option<Value>,
}

/// Recoverable failure surface emitted by a tool implementation.
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    #[error("not implemented")]
    NotImplemented,
    #[error("permission denied: {0}")]
    PermissionDenied(String),
}

/// Trait every concrete tool implements.
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn input_schema(&self) -> Value;
    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError>;

    /// Validate `input` against the JSON Schema returned by [`Tool::input_schema`].
    ///
    /// The default implementation compiles the schema with `jsonschema` and
    /// rejects mismatched payloads as [`ToolError::InvalidInput`]. Concrete
    /// tools rarely override this — they only need a precise `input_schema`.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::ExecutionFailed`] when the schema itself fails
    /// to compile, and [`ToolError::InvalidInput`] when the payload does
    /// not satisfy the schema.
    async fn validate_input(&self, input: &Value) -> Result<(), ToolError> {
        let schema = self.input_schema();
        let validator = jsonschema::validator_for(&schema)
            .map_err(|err| ToolError::ExecutionFailed(format!("schema compile: {err}")))?;
        if validator.is_valid(input) {
            return Ok(());
        }
        let detail = validator
            .iter_errors(input)
            .map(|err| err.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Err(ToolError::InvalidInput(detail))
    }
}

/// Move-only input minted by the canonical capability executor.
///
/// The private field and crate-private constructor make raw tool execution
/// impossible for callers. Tool implementations may only consume an
/// invocation that [`crate::execution::CapabilityExecutor`] created after the
/// fail-closed cascade, final schema validation, and durable decision audit.
///
/// ```compile_fail,E0451
/// use arcana_core::tool::ToolInvocation;
/// use serde_json::json;
///
/// let forged = ToolInvocation { input: json!({"unsafe": true}) };
/// ```
#[derive(Debug)]
pub struct ToolInvocation {
    input: Value,
}

impl ToolInvocation {
    pub(crate) fn new(input: Value) -> Self {
        Self { input }
    }

    /// Consume the single-use invocation and return its validated input.
    #[must_use]
    pub fn into_input(self) -> Value {
        self.input
    }
}

/// Failure modes raised by the dispatcher itself, not by an individual tool.
#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("tool not registered: {0}")]
    Unknown(String),
    #[error("tool already registered: {0}")]
    DuplicateRegistration(String),
    #[error(transparent)]
    Tool(#[from] ToolError),
}

/// Owns the active tool set and routes calls by name.
#[derive(Default)]
pub struct ToolDispatcher {
    tools: HashMap<String, Arc<dyn Tool>>,
}

impl ToolDispatcher {
    /// Construct an empty dispatcher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool by its declared name.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::DuplicateRegistration`] when a tool with
    /// the same name is already registered.
    pub fn register(&mut self, tool: Arc<dyn Tool>) -> Result<(), DispatchError> {
        let name = tool.name().to_owned();
        if self.tools.contains_key(&name) {
            return Err(DispatchError::DuplicateRegistration(name));
        }
        self.tools.insert(name, tool);
        Ok(())
    }

    /// Number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// True when no tools are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Resolve a tool inside the fused executor/schema boundary.
    ///
    /// External callers cannot obtain the raw registered implementation:
    ///
    /// ```compile_fail,E0624
    /// use arcana_core::tool::ToolDispatcher;
    /// let registry = ToolDispatcher::new();
    /// let _bypass = registry.get("bash");
    /// ```
    pub(crate) fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.get(name).cloned()
    }
}
