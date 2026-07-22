//! Minimal built-in tool for the production `arcana mcp serve` entrypoint.
//!
//! The MCP adapter is transport + envelope only; it does not own a tool
//! registry. So `tools/list` is not empty on the default stdio server, the
//! entrypoint exposes one trivial, side-effect-free identity probe (mirroring
//! the CLI bootstrap's `whoami` smoke tool). The CLI wires its real tool set
//! through [`crate::server::ArcanaMcpServer::assemble`] as that registry lands.

use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde_json::{Value, json};

/// Reports the local OS identity the cascade sees. No side effects.
pub struct IdentityTool;

#[async_trait]
impl Tool for IdentityTool {
    fn name(&self) -> &'static str {
        "whoami"
    }

    fn description(&self) -> &'static str {
        "Report the local OS identity the capability cascade sees."
    }

    fn input_schema(&self) -> Value {
        json!({ "type": "object", "properties": {}, "additionalProperties": false })
    }

    async fn execute(&self, _invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let identity = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_owned());
        Ok(ToolOutput {
            content: identity,
            metadata: None,
        })
    }
}
