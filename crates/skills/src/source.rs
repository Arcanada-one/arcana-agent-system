//! — the production skills-store **cutover** seam.
//!
//! The production agent driver must load its skills from the untrusted KB via
//! [`ScrutatorStore`] (the full 0047 gate chain), reserving the trusted
//! [`FileStore`] for bundled/offline bootstrap ids only. This module is that
//! single decision point: [`SkillSourceMode`] chooses the backend, and
//! [`select_skill_store`] builds the boxed [`SkillStore`] the interpreter drives.
//!
//! **Fail-closed by construction.** The default mode is [`SkillSourceMode::Production`]:
//! an absent, blank, or unset selector never silently yields the trusted local
//! path (which trusts its bytes by fiat). Only an explicit `bootstrap` / `file`
//! selector opts into [`FileStore`]; an unrecognised selector is a hard error,
//! not a silent default. In production mode a store outage propagates as
//! [`crate::SkillError::StoreUnavailable`] from the [`ScrutatorStore`] — there is
//! deliberately **no** `FileStore` fallback that would run a different skill.

use std::sync::Arc;

use crate::store::{FetchConn, FileStore, ScrutatorStore, SkillStore};

/// The environment variable the production driver reads to choose its skills
/// source. Unset ⇒ [`SkillSourceMode::Production`] (fail-closed).
pub const ENV_SKILL_SOURCE: &str = "ARCANA_SKILLS_SOURCE";

/// Which backend the production driver loads skills from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SkillSourceMode {
    /// Untrusted-KB source: every skill load is routed through a
    /// [`ScrutatorStore`] (`trust_class` fence → blake3 keystone → parse →
    /// schema validate, then the interpreter's maturity / tool-ceiling / model
    /// gates). The fail-closed default.
    #[default]
    Production,
    /// Bundled/offline source: the trusted [`FileStore`] serves local ids only.
    /// Must be opted into explicitly — it is never the silent default.
    Bootstrap,
}

/// An unrecognised [`ENV_SKILL_SOURCE`] value. Carried so the driver can fail
/// loudly rather than silently pick a backend.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unrecognised {ENV_SKILL_SOURCE} value `{value}`: expected `production`/`scrutator` or `bootstrap`/`file`"
)]
pub struct UnknownSkillSource {
    /// The offending selector value.
    pub value: String,
}

impl SkillSourceMode {
    /// Resolve a mode from an explicit selector string (typically the value of
    /// [`ENV_SKILL_SOURCE`]). `None` or a blank string defaults **fail-closed**
    /// to [`SkillSourceMode::Production`]; the match is case-insensitive.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownSkillSource`] for any non-blank value that is not one of
    /// the accepted aliases — never a silent fallback to a default mode.
    pub fn from_selector(selector: Option<&str>) -> Result<Self, UnknownSkillSource> {
        match selector.map(str::trim) {
            None | Some("") => Ok(Self::Production),
            Some(value) => match value.to_ascii_lowercase().as_str() {
                "production" | "scrutator" | "kb" => Ok(Self::Production),
                "bootstrap" | "file" | "offline" => Ok(Self::Bootstrap),
                _ => Err(UnknownSkillSource {
                    value: value.to_owned(),
                }),
            },
        }
    }

    /// Resolve the mode from the process environment ([`ENV_SKILL_SOURCE`]).
    ///
    /// # Errors
    ///
    /// Returns [`UnknownSkillSource`] when the variable is set to an
    /// unrecognised value (an unset/blank variable is the fail-closed
    /// [`SkillSourceMode::Production`] default).
    pub fn from_env() -> Result<Self, UnknownSkillSource> {
        let raw = std::env::var(ENV_SKILL_SOURCE).ok();
        Self::from_selector(raw.as_deref())
    }
}

/// Build the boxed [`SkillStore`] the interpreter drives, per `mode`.
///
/// * [`SkillSourceMode::Production`] ⇒ a [`ScrutatorStore`] over `scrutator_conn`
///   (the full 0047 gate chain; a store outage fails closed to
///   [`crate::SkillError::StoreUnavailable`], never a local fallback).
/// * [`SkillSourceMode::Bootstrap`] ⇒ a trusted [`FileStore`]; `scrutator_conn`
///   is unused (bundled ids are read from the local filesystem trust root).
///
/// The connector is always supplied so the caller's composition root stays a
/// single expression regardless of mode; it is simply not wired in bootstrap.
#[must_use]
pub fn select_skill_store<C>(mode: SkillSourceMode, scrutator_conn: Arc<C>) -> Box<dyn SkillStore>
where
    C: FetchConn + 'static,
{
    match mode {
        SkillSourceMode::Production => Box::new(ScrutatorStore::new(scrutator_conn)),
        SkillSourceMode::Bootstrap => Box::new(FileStore),
    }
}
