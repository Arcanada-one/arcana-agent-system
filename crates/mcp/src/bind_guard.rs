//! Tier-1 loopback bind guard for `arcana mcp serve --bind`.
//!
//! The MCP server is strictly loopback (Tier-1) — below the Tier-2 mesh tier
//! governed by the workspace `network-exposure-check.sh`. This guard refuses
//! any non-loopback [`SocketAddr`] (including a Tailscale mesh IP) *before* a
//! listener is ever created, so the server can never escalate to a tier that
//! would demand a mesh-exposure descriptor entry.

use std::net::SocketAddr;

use thiserror::Error;

/// Failure raised when a requested bind address is not usable for the
/// loopback-only MCP server.
#[derive(Debug, Error)]
pub enum BindGuardError {
    /// The string could not be parsed as a `host:port` socket address.
    #[error("mcp serve: invalid bind address '{raw}': {source}")]
    Parse {
        raw: String,
        #[source]
        source: std::net::AddrParseError,
    },
    /// The address parsed but is not a loopback address.
    #[error(
        "mcp serve: refusing non-loopback bind '{0}' — Tier-1 loopback only (127.0.0.1 / ::1)"
    )]
    NonLoopback(SocketAddr),
}

/// Parse `raw` as a socket address and accept it only when the IP is a
/// loopback address (`127.0.0.0/8` or `::1`).
///
/// # Errors
///
/// Returns [`BindGuardError::Parse`] when `raw` is not a valid socket address,
/// and [`BindGuardError::NonLoopback`] when it is valid but not loopback.
pub fn guard_loopback(raw: &str) -> Result<SocketAddr, BindGuardError> {
    let addr: SocketAddr = raw.parse().map_err(|source| BindGuardError::Parse {
        raw: raw.to_owned(),
        source,
    })?;
    if addr.ip().is_loopback() {
        Ok(addr)
    } else {
        Err(BindGuardError::NonLoopback(addr))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ipv4_loopback() {
        let addr = guard_loopback("127.0.0.1:0").expect("loopback ipv4 accepted");
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn accepts_ipv6_loopback() {
        let addr = guard_loopback("[::1]:0").expect("loopback ipv6 accepted");
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn rejects_unspecified() {
        let err = guard_loopback("0.0.0.0:0").expect_err("0.0.0.0 must be refused");
        assert!(
            err.to_string().contains("non-loopback"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_mesh_ip() {
        let err =
            guard_loopback("100.106.230.125:0").expect_err("mesh IP must be refused (stricter than mesh tier)");
        assert!(matches!(err, BindGuardError::NonLoopback(_)), "unexpected error: {err}");
    }
}
