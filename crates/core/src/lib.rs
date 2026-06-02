//! arcana-core — agent loop, tool dispatcher, context management.
//!
//! Skeleton stage; real surface lands in subsequent releases.

pub mod agent_loop;
pub mod connector;
pub mod cost;
pub mod hooks;
pub mod permission;
pub mod tool;

#[must_use]
pub fn skeleton_marker() -> &'static str {
    "arcana-core bootstrap"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_returns_bootstrap_string() {
        assert_eq!(skeleton_marker(), "arcana-core bootstrap");
    }
}
