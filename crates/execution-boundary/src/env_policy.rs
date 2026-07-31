//! Clean-environment reconstruction (D-REQ-02 / V-AC-2).
//!
//! The launcher never *filters* the inherited environment — filtering is a
//! denylist, and denylists lose. It clears everything and reconstructs a fixed
//! minimal allowlist, so a newly-introduced secret variable is excluded by
//! default rather than by remembering to ban it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The complete set of variables a supervised child may inherit.
///
/// `HOME` is deliberately absent: it is reconstructed to a caller-supplied
/// sandbox root so vendor CLIs cannot reach a credential-bearing config home.
pub const ALLOWLIST: &[&str] = &["PATH", "LANG", "LC_ALL", "TZ", "TERM", "COLORTERM"];

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
    "SESSION",
    "AUTH",
];

/// Heuristic used only as a structural assertion: no allowlisted name may ever
/// look credential-shaped. It is not, and must not be used as, a filter.
#[must_use]
pub fn looks_like_credential_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    CREDENTIAL_MARKERS.iter().any(|m| upper.contains(m)) || upper.ends_with("_KEY")
}

/// A reconstructed, credential-free child environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanEnv {
    vars: BTreeMap<String, String>,
}

impl CleanEnv {
    /// Reconstruct from an arbitrary (possibly contaminated) source environment.
    ///
    /// Only [`ALLOWLIST`] names survive, and a surviving name that is
    /// credential-shaped is dropped as a defence-in-depth backstop.
    #[must_use]
    pub fn reconstruct<I, K, V>(source: I, sandbox_home: &Path) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut vars = BTreeMap::new();
        for (k, v) in source {
            let name = k.as_ref();
            if ALLOWLIST.contains(&name) && !looks_like_credential_name(name) {
                vars.insert(name.to_owned(), v.as_ref().to_owned());
            }
        }
        vars.insert("HOME".to_owned(), sandbox_home.display().to_string());
        vars.entry("PATH".to_owned())
            .or_insert_with(|| "/usr/bin:/bin".to_owned());
        Self { vars }
    }

    /// The reconstructed variables, sorted by name.
    pub fn vars(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of variables handed to the child.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// Whether the reconstructed environment is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// Look a variable up by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    /// The sandbox `HOME` handed to the child.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        PathBuf::from(self.vars.get("HOME").cloned().unwrap_or_default())
    }
}
