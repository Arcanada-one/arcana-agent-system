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
pub mod builtins;
pub mod envelope;
#[cfg(feature = "http")]
pub mod http;
pub mod server;
pub mod suspend;

use std::path::PathBuf;

use server::ArcanaMcpServer;

/// Project-local permission rule file, resolved relative to the cwd.
const PROJECT_RULES_RELATIVE: &str = ".arcana/permissions.toml";

/// Resolve the XDG state directory (the audit sink), mirroring the CLI.
fn state_dir() -> PathBuf {
    xdg::BaseDirectories::with_prefix("arcana")
        .map_or_else(|_| PathBuf::from(".arcana-state"), |base| base.get_state_home())
}

/// Serve the default production server over stdio until the peer disconnects.
///
/// # Errors
///
/// Returns a boxed error when assembly or the transport handshake fails.
pub async fn serve_stdio() -> Result<(), Box<dyn std::error::Error>> {
    use rmcp::ServiceExt;
    use rmcp::transport::stdio;

    let server = ArcanaMcpServer::assemble_default(&state_dir(), &PathBuf::from(PROJECT_RULES_RELATIVE))?;
    let running = server.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}

/// Run `arcana mcp serve`. `bind` selects the transport: `None` → stdio,
/// `Some(addr)` → a loopback-guarded HTTP listener.
///
/// Returns a process exit code (0 = clean shutdown, non-zero = setup or
/// transport failure, including a rejected non-loopback bind).
#[must_use]
pub fn run_mcp_serve(bind: Option<&str>) -> i32 {
    if let Some(raw) = bind {
        // Enforce the loopback guard *before* any listener is created.
        match bind_guard::guard_loopback(raw) {
            Ok(addr) => run_http(addr),
            Err(err) => {
                eprintln!("{err}");
                2
            }
        }
    } else {
        run_stdio()
    }
}

/// Block on the stdio server, mapping the outcome to an exit code.
fn run_stdio() -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("arcana mcp serve: runtime initialization failed: {err}");
            return 1;
        }
    };
    match runtime.block_on(serve_stdio()) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("arcana mcp serve: {err}");
            1
        }
    }
}

/// Loopback HTTP transport entrypoint. The address is already guarded by
/// [`bind_guard::guard_loopback`]; full streamable-HTTP serving is wired via
/// the optional `transport-streamable-http-server` feature.
fn run_http(addr: std::net::SocketAddr) -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("arcana mcp serve: runtime initialization failed: {err}");
            return 1;
        }
    };
    match runtime.block_on(serve_http(addr)) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("arcana mcp serve: {err}");
            1
        }
    }
}

#[cfg(feature = "http")]
async fn serve_http(addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    crate::http::serve(addr).await
}

#[cfg(not(feature = "http"))]
#[allow(clippy::unused_async)]
async fn serve_http(addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    Err(format!(
        "arcana mcp serve --bind {addr}: loopback HTTP transport requires the 'http' feature; \
         rebuild with --features http (stdio transport needs no feature)"
    )
    .into())
}
