//! Optional loopback HTTP transport for `arcana mcp serve --bind`.
//!
//! Compiled only with the `http` feature. The bind address is already vetted
//! by [`crate::bind_guard::guard_loopback`]; the rmcp streamable-HTTP server
//! additionally restricts `Host` to loopback by default (anti DNS-rebinding).
//! Each accepted connection runs the same `ArcanaMcpServer` handler as stdio.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::server::ArcanaMcpServer;

/// Bind `addr` (loopback, pre-guarded) and serve the MCP handler over HTTP
/// until interrupted.
///
/// # Errors
///
/// Returns a boxed error when the listener cannot bind or an accept fails.
pub async fn serve(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let state = crate::state_dir();
    let project_rules = PathBuf::from(crate::PROJECT_RULES_RELATIVE);

    let service = StreamableHttpService::new(
        move || {
            ArcanaMcpServer::assemble_default(&state, &project_rules)
                .map_err(|err| std::io::Error::other(err.to_string()))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!(
        "arcana mcp serve: loopback HTTP listening on http://{}",
        listener.local_addr()?
    );

    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let hyper_service = TowerToHyperService::new(service.clone());
        tokio::spawn(async move {
            let _ = ConnBuilder::new(TokioExecutor::new())
                .serve_connection(io, hyper_service)
                .await;
        });
    }
}
