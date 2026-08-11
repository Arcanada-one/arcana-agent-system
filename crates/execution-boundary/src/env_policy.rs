//! Clean-environment construction (D-REQ-02 / V-AC-2).
//!
//! # Why nothing is inherited
//!
//! An earlier revision allowlisted variable *names* and copied their *values*
//! through unexamined. That is not a clean environment: `PATH`, `TERM`, `LANG`,
//! `LC_ALL`, `TZ` and `COLORTERM` are six unconstrained channels out of the
//! contaminated parent, and an inherited `PATH` additionally re-opens a
//! code-execution channel by letting an agent-writable directory shadow every
//! helper a vendor CLI invokes.
//!
//! So this module inherits **nothing**. The child environment is *constructed*
//! from constants plus two explicitly-supplied, validated values. There is no
//! path by which a parent variable reaches a child, which makes the guarantee
//! structural rather than dependent on the quality of an allowlist.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// The complete constructed child environment. Caller-supplied values are not
/// accepted: a name-based filter cannot prove that a value under a benign name
/// is not credential material.
pub const ALLOWLIST: &[&str] = &["PATH", "HOME", "LANG", "LC_ALL", "TZ", "TERM"];

/// Terminal types a child may be told it has. A closed set: `TERM` steers
/// terminfo file resolution, so an arbitrary value is an input to a lookup.
pub const ALLOWED_TERMS: &[&str] = &["dumb", "xterm", "xterm-256color", "vt100", "screen"];

/// Substrings that mark a variable name as credential-shaped.
const CREDENTIAL_MARKERS: &[&str] = &[
    "API_KEY",
    "APIKEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "SESSION",
    "AUTH",
];

/// Whether a name looks credential-shaped.
///
/// This is an assertion aid for tests and callers, **not** a filter: nothing in
/// this module inherits a variable, so there is nothing for a filter to catch.
#[must_use]
pub fn looks_like_credential_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    CREDENTIAL_MARKERS.iter().any(|m| upper.contains(m))
        || upper.ends_with("_KEY")
        || upper.ends_with("_ID") && upper.contains("ACCESS")
}

/// Why a clean environment could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvError {
    #[error("sandbox home must be an absolute path")]
    HomeNotAbsolute,
    #[error("sandbox home must not contain a parent-directory component")]
    HomeHasParentComponent,
    #[error("sandbox home must not be a real user home directory")]
    HomeIsRealUserHome,
    #[error("sandbox home is not valid UTF-8")]
    HomeNotUtf8,
    #[error("PATH must not be empty")]
    PathEmpty,
    #[error("every PATH component must be an absolute path")]
    PathComponentNotAbsolute,
    #[error("TERM value is not in the allowed set")]
    TermNotAllowed,
    #[error("caller-declared environment variables are disabled at the execution boundary")]
    CallerVariablesUnsupported,
}

/// A constructed, credential-free child environment.
///
/// `Debug` deliberately redacts values: an earlier revision derived `Debug`,
/// so a single `debug!(?env)` would have printed everything it held.
#[derive(Clone, PartialEq, Eq)]
pub struct CleanEnv {
    vars: BTreeMap<String, String>,
}

impl fmt::Debug for CleanEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CleanEnv")
            .field("names", &self.vars.keys().collect::<Vec<_>>())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl CleanEnv {
    /// Construct the child environment from constants plus validated inputs.
    ///
    /// # Errors
    /// [`EnvError`] when the sandbox home or `PATH` would reintroduce a channel
    /// the design closes. Validation is fail-closed: a questionable value is
    /// refused rather than sanitised.
    pub fn build(sandbox_home: &Path, path: &str) -> Result<Self, EnvError> {
        Self::build_with_term(sandbox_home, path, "dumb")
    }

    /// As [`Self::build`], with an explicit terminal type from [`ALLOWED_TERMS`].
    ///
    /// # Errors
    /// [`EnvError`] as for [`Self::build`], plus [`EnvError::TermNotAllowed`].
    pub fn build_with_term(sandbox_home: &Path, path: &str, term: &str) -> Result<Self, EnvError> {
        if !sandbox_home.is_absolute() {
            return Err(EnvError::HomeNotAbsolute);
        }
        if sandbox_home
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new(".."))
        {
            return Err(EnvError::HomeHasParentComponent);
        }
        // A sandbox that aliases a real home defeats the purpose: vendor CLIs
        // would find the very config homes this is meant to hide.
        let home_str = sandbox_home.to_str().ok_or(EnvError::HomeNotUtf8)?;
        if home_str.starts_with("/home/") || home_str.starts_with("/Users/") {
            let depth = sandbox_home.components().count();
            if depth <= 3 {
                return Err(EnvError::HomeIsRealUserHome);
            }
        }
        if path.trim().is_empty() {
            return Err(EnvError::PathEmpty);
        }
        if path
            .split(':')
            .any(|c| c.is_empty() || !Path::new(c).is_absolute())
        {
            return Err(EnvError::PathComponentNotAbsolute);
        }
        if !ALLOWED_TERMS.contains(&term) {
            return Err(EnvError::TermNotAllowed);
        }

        let mut vars = BTreeMap::new();
        vars.insert("PATH".to_owned(), path.to_owned());
        vars.insert("HOME".to_owned(), home_str.to_owned());
        // Fixed, non-inherited locale and timezone. Deterministic output is a
        // secondary benefit; the primary one is that these carry nothing.
        vars.insert("LANG".to_owned(), "C.UTF-8".to_owned());
        vars.insert("LC_ALL".to_owned(), "C.UTF-8".to_owned());
        vars.insert("TZ".to_owned(), "UTC".to_owned());
        vars.insert("TERM".to_owned(), term.to_owned());

        Ok(Self { vars })
    }

    /// The child variables, sorted by name.
    pub fn vars(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of variables handed to the child.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// Whether the environment is empty. Never true for a built environment.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// Look a variable up by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    /// Preserve input compatibility while refusing every caller-supplied value.
    ///
    /// The previous name-based exception accepted a credential under a benign
    /// name and also admitted loader/shell control variables before descriptor
    /// isolation. An empty map is accepted so existing callers that omit the
    /// optional field keep working; every non-empty map fails closed.
    ///
    /// # Errors
    /// Rejects every non-empty caller map.
    pub fn with_declared_vars(self, vars: &BTreeMap<String, String>) -> Result<Self, EnvError> {
        if vars.is_empty() {
            Ok(self)
        } else {
            Err(EnvError::CallerVariablesUnsupported)
        }
    }

    /// The sandbox `HOME` handed to the child.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        PathBuf::from(self.vars.get("HOME").cloned().unwrap_or_default())
    }

    /// Apply to a command, clearing inherited state first.
    ///
    /// This is the only supported way to use a [`CleanEnv`]. Handing the map to
    /// a caller that forgets `env_clear` would layer clean variables on top of
    /// the full inherited environment — the API now performs the clear itself
    /// so that mistake is not available.
    pub fn apply(&self, cmd: &mut std::process::Command) {
        cmd.env_clear();
        for (k, v) in &self.vars {
            cmd.env(k, v);
        }
    }
}
