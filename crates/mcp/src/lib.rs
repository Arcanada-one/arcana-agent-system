//! `arcana-mcp` — an MCP server adapter over the arcana capability core.
//!
//! This crate is a **pure adapter**: it exposes the existing
//! `ToolDispatcher` + `PermissionCascade` + `CapabilityExecutor` (with hooks
//! and the mandatory audit log) as an MCP server (`arcana mcp serve`). It adds
//! no permission, tool, hook, or audit logic of its own. Two facts vanilla MCP
//! cannot carry ride an extended response envelope: the post-`ReplaceInput`
//! `effective_args`, and an `InteractionRequired` suspend/resume channel for
//! `Defer` decisions.
//!
//! Transport is loopback only (Tier-1): stdio by default, or an optional
//! `--bind <loopback>` HTTP listener guarded by [`bind_guard::guard_loopback`].

pub mod bind_guard;

/// Run `arcana mcp serve`. `bind` selects the transport: `None` → stdio,
/// `Some(addr)` → a loopback-guarded HTTP listener.
///
/// Returns a process exit code (0 = clean shutdown, non-zero = setup or
/// transport failure, including a rejected non-loopback bind).
#[must_use]
pub fn run_mcp_serve(bind: Option<String>) -> i32 {
    // Full transport wiring lands in later phases; for now the bind guard is
    // enforced up-front so a non-loopback `--bind` is rejected before any
    // listener is created.
    if let Some(raw) = bind.as_deref() {
        match bind_guard::guard_loopback(raw) {
            Ok(addr) => {
                eprintln!("arcana mcp serve: loopback bind {addr} accepted (transport wiring pending)");
                0
            }
            Err(err) => {
                eprintln!("{err}");
                2
            }
        }
    } else {
        eprintln!("arcana mcp serve: stdio transport (wiring pending)");
        0
    }
}
