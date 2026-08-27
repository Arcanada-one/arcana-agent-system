//! The MCP `ServerHandler` adapter over the capability core.
//!
//! `ArcanaMcpServer` answers `tools/list` from the held tool set and routes
//! `tools/call` through a per-call `CapabilityExecutor` assembled from the
//! reused core layers (`Schema → Rule → SuspendLayer`). It adds no permission,
//! tool, hook, or audit logic: the cascade and executor are the unchanged core.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arcana_core::cost::CostTracker;
use arcana_core::execution::{CapabilityError, CapabilityExecutor, CapabilityOutput};
use arcana_core::hooks::audit::{AuditHookError, AuditLog};
use arcana_core::hooks::{HookChain, HookContext};
use arcana_core::permission::{
    LayerDecision, PermissionCascade, PermissionLayer, RuleLayer, RuleLoadError, SchemaLayer,
};
use arcana_core::tool::{Tool, ToolDispatcher};
use rmcp::ErrorData;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, JsonObject, PaginatedRequestParams, ServerCapabilities,
    ServerInfo,
};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::builtins::IdentityTool;
use crate::envelope::{self, InteractionRequired};
use crate::suspend::{
    InteractionAnnounce, InteractionResolution, PendingInteraction, PendingInteractions,
    SuspendLayer,
};

/// The control tool name; feeds a resolution into a parked call. Never listed
/// by `tools/list` (it is not a capability-core tool).
pub const RESUME_TOOL: &str = "arcana.resume";

/// Failure modes raised while assembling a per-call executor or the server.
#[derive(Debug, Error)]
pub enum AssembleError {
    #[error("tool registration failed: {0}")]
    Dispatch(String),
    #[error("audit log setup failed: {0}")]
    Audit(#[from] AuditHookError),
    #[error("permissions.toml load failed: {0}")]
    Rules(#[from] RuleLoadError),
}

/// MCP server adapter exposing the capability core.
pub struct ArcanaMcpServer {
    tools: Vec<Arc<dyn Tool>>,
    upstream_layers: Vec<Arc<dyn PermissionLayer>>,
    audit_dir: PathBuf,
    pending: PendingInteractions,
}

impl ArcanaMcpServer {
    /// Construct a server from an explicit tool set, the upstream cascade
    /// layers (everything before the terminal `SuspendLayer`), and the audit
    /// directory. Used directly by the contract tests to inject cascade
    /// behaviour; production callers use [`ArcanaMcpServer::assemble`].
    #[must_use]
    pub fn new(
        tools: Vec<Arc<dyn Tool>>,
        upstream_layers: Vec<Arc<dyn PermissionLayer>>,
        audit_dir: PathBuf,
    ) -> Self {
        Self {
            tools,
            upstream_layers,
            audit_dir,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Assemble the production server: the reused `Schema → Rule` upstream over
    /// the supplied tool set, with the state directory as the audit sink. The
    /// terminal `SuspendLayer` is appended per call.
    ///
    /// # Errors
    ///
    /// Returns [`AssembleError`] when a tool cannot be registered, the rule
    /// file fails to parse, or the audit directory is unusable.
    pub fn assemble(
        state_dir: &Path,
        project_rules: &Path,
        tools: Vec<Arc<dyn Tool>>,
    ) -> Result<Self, AssembleError> {
        let mut schema_dispatcher = ToolDispatcher::new();
        for tool in &tools {
            schema_dispatcher
                .register(tool.clone())
                .map_err(|err| AssembleError::Dispatch(err.to_string()))?;
        }
        let user_rules = RuleLayer::xdg_user_path().ok();
        let rule_layer = RuleLayer::load(user_rules.as_deref(), Some(project_rules))?;
        let upstream: Vec<Arc<dyn PermissionLayer>> = vec![
            Arc::new(SchemaLayer::new(Arc::new(schema_dispatcher))),
            Arc::new(rule_layer),
        ];
        Ok(Self::new(tools, upstream, state_dir.to_path_buf()))
    }

    /// Production default: a single built-in identity tool over the reused
    /// upstream. The capability-core registry is otherwise the CLI's concern.
    ///
    /// # Errors
    ///
    /// Returns [`AssembleError`] — see [`ArcanaMcpServer::assemble`].
    pub fn assemble_default(state_dir: &Path, project_rules: &Path) -> Result<Self, AssembleError> {
        Self::assemble(state_dir, project_rules, vec![Arc::new(IdentityTool)])
    }

    /// Build a fresh per-call executor: a private dispatcher over the tool set,
    /// the upstream layers plus the supplied terminal, an empty hook chain, and
    /// a fresh audit handle.
    fn build_executor(
        &self,
        terminal: Arc<dyn PermissionLayer>,
    ) -> Result<CapabilityExecutor, AssembleError> {
        let mut dispatcher = ToolDispatcher::new();
        for tool in &self.tools {
            dispatcher
                .register(tool.clone())
                .map_err(|err| AssembleError::Dispatch(err.to_string()))?;
        }
        let mut layers = self.upstream_layers.clone();
        layers.push(terminal);
        // A `ReplaceInput` resolution from the SuspendLayer mutates the input
        // but does not itself allow; this trailing layer proceeds with the
        // operator-authorized (replaced) input. An `allow`/`deny` resolution
        // short-circuits at the SuspendLayer and never reaches it.
        layers.push(Arc::new(ProceedLayer));
        let cascade = PermissionCascade::new(layers);
        let audit = AuditLog::new(&self.audit_dir)?;
        Ok(CapabilityExecutor::new(
            dispatcher,
            cascade,
            HookChain::new(),
            audit,
        ))
    }

    /// Route a capability `tools/call`: spawn the executor, then race the
    /// task's completion against a suspension announcement.
    async fn handle_capability(
        &self,
        tool_name: &str,
        input: Value,
    ) -> Result<CallToolResult, ErrorData> {
        let (announce_tx, mut announce_rx) = oneshot::channel::<InteractionAnnounce>();
        let (resolution_tx, resolution_rx) = oneshot::channel::<InteractionResolution>();
        let (result_tx, mut result_rx) =
            oneshot::channel::<Result<CapabilityOutput, CapabilityError>>();

        let token = Uuid::new_v4().to_string();
        let prompt = format!("capability '{tool_name}' requires interactive authorization");
        let terminal = Arc::new(SuspendLayer::new(token, prompt, announce_tx, resolution_rx));
        let executor = self
            .build_executor(terminal)
            .map_err(|err| ErrorData::internal_error(err.to_string(), None))?;

        let ctx = HookContext::new(CancellationToken::new(), Arc::new(CostTracker::new()));
        let tool_owned = tool_name.to_owned();
        tokio::spawn(async move {
            let outcome = executor.execute(&ctx, &tool_owned, input).await;
            let _ = result_tx.send(outcome);
        });

        tokio::select! {
            biased;
            announced = &mut announce_rx => match announced {
                Ok(announce) => Ok(self.park(announce, resolution_tx, result_rx)),
                // The task ran to completion (allow/deny/error) without ever
                // reaching the SuspendLayer; the announce sender was dropped.
                Err(_) => Ok(map_execution_result(result_rx.await)),
            },
            outcome = &mut result_rx => Ok(map_execution_result(outcome)),
        }
    }

    /// Record a parked interaction and return the `InteractionRequired` envelope.
    fn park(
        &self,
        announce: InteractionAnnounce,
        resolution_tx: oneshot::Sender<InteractionResolution>,
        result_rx: oneshot::Receiver<Result<CapabilityOutput, CapabilityError>>,
    ) -> CallToolResult {
        let interaction = InteractionRequired {
            token: announce.token.clone(),
            tool: announce.tool,
            prompt: announce.prompt,
            pending_input: announce.pending_input,
        };
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(
                announce.token,
                PendingInteraction {
                    resolution_tx,
                    result_rx,
                },
            );
        }
        envelope::map_interaction_required(&interaction)
    }

    /// Handle `arcana.resume`: feed the resolution into the parked call and map
    /// its final output.
    async fn handle_resume(&self, args: &Value) -> Result<CallToolResult, ErrorData> {
        let Some(token) = args.get("token").and_then(Value::as_str) else {
            return Ok(envelope::map_denied("resume: missing token".to_owned()));
        };
        let pending = self
            .pending
            .lock()
            .ok()
            .and_then(|mut map| map.remove(token));
        let Some(pending) = pending else {
            return Ok(envelope::map_denied(
                "unknown or expired interaction token".to_owned(),
            ));
        };
        let resolution = parse_resolution(args.get("resolution"));
        if pending.resolution_tx.send(resolution).is_err() {
            return Ok(envelope::map_denied(
                "suspended call is no longer active".to_owned(),
            ));
        }
        Ok(map_execution_result(pending.result_rx.await))
    }

    /// rmcp tool descriptors for `tools/list` (the resume control tool excluded).
    fn tool_descriptors(&self) -> Vec<rmcp::model::Tool> {
        self.tools
            .iter()
            .map(|tool| {
                rmcp::model::Tool::new(
                    tool.name(),
                    tool.description(),
                    Arc::new(to_json_object(tool.input_schema())),
                )
            })
            .collect()
    }
}

impl ServerHandler for ArcanaMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }

    // Nothing here awaits: the descriptors are already in memory. Returning a
    // ready future rather than declaring `async` says so at the signature, and
    // keeps clippy's `unused_async_trait_impl` (new in 1.98) quiet without an
    // allow attribute that older toolchains would reject as an unknown lint.
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::ListToolsResult, ErrorData>> {
        std::future::ready(Ok(rmcp::model::ListToolsResult {
            tools: self.tool_descriptors(),
            ..Default::default()
        }))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let input = Value::Object(request.arguments.unwrap_or_default());
        if request.name == RESUME_TOOL {
            self.handle_resume(&input).await
        } else {
            self.handle_capability(&request.name, input).await
        }
    }
}

/// Map a spawned execution result (or a dropped channel) to an envelope.
fn map_execution_result(
    outcome: Result<Result<CapabilityOutput, CapabilityError>, oneshot::error::RecvError>,
) -> CallToolResult {
    match outcome {
        Ok(Ok(output)) => envelope::map_completed(output.output.content, &output.effective_input),
        Ok(Err(err)) => envelope::map_denied(err.to_string()),
        Err(_) => {
            envelope::map_denied("execution task dropped before returning a result".to_owned())
        }
    }
}

/// Parse the `arcana.resume` resolution argument.
fn parse_resolution(value: Option<&Value>) -> InteractionResolution {
    match value {
        Some(Value::String(verb)) if verb == "allow" => InteractionResolution::Allow,
        Some(Value::String(verb)) if verb == "deny" => {
            InteractionResolution::Deny("resume: denied by caller".to_owned())
        }
        Some(Value::Object(map)) => match map.get("replace_input") {
            Some(replacement) => InteractionResolution::ReplaceInput(replacement.clone()),
            None => InteractionResolution::Deny("resume: unrecognized resolution".to_owned()),
        },
        _ => InteractionResolution::Deny("resume: unrecognized resolution".to_owned()),
    }
}

/// Trailing cascade layer that proceeds with the current (already
/// operator-authorized) input. Only reached when the terminal `SuspendLayer`
/// returned `ReplaceInput` — i.e. the caller resolved a suspension with a
/// modified payload and asked to proceed.
struct ProceedLayer;

#[async_trait::async_trait]
impl PermissionLayer for ProceedLayer {
    fn name(&self) -> &'static str {
        "mcp_proceed"
    }
    async fn evaluate(&self, _tool: &str, _input: &Value) -> LayerDecision {
        LayerDecision::Allow
    }
}

/// Coerce a JSON-Schema `Value` to the `JsonObject` rmcp descriptors expect.
fn to_json_object(schema: Value) -> JsonObject {
    match schema {
        Value::Object(map) => map,
        other => {
            let mut wrapper = JsonObject::new();
            wrapper.insert("schema".to_owned(), other);
            wrapper
        }
    }
}
