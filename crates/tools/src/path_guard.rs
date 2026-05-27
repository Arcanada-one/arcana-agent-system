//! Path-traversal protection seam (CWE-22) for filesystem tools.
//!
//! Every filesystem tool (`Read`, `Write`, `Edit`) routes its user-supplied
//! `path` argument through [`check`] before any I/O. The guard canonicalizes
//! the input (resolving `..`, `.`, symlinks) and matches the canonical
//! `PathBuf` against the active [`ToolRuleSet`]'s `deny_paths` and
//! `allow_paths` regular expressions.
//!
//! The shipped default ([`ToolRuleSet::default`]) is permissive — all paths
//! are allowed. Production rule loading is wired by the CLI bootstrap step
//! in a follow-up task (see `docs/reference/architecture.md` § Permission
//! layer). Tools constructed via `::new(rules)` consume an `Arc<ToolRuleSet>`
//! from the upstream cascade.
//!
//! Canonicalization is path-existence aware: when the input file exists, the
//! kernel resolves the full path; when it does not (a typical case for
//! `Write` creating a new file), the helper canonicalizes the *parent* and
//! re-joins the filename. This closes a TOCTOU window where a tool might
//! match the original path string against `deny_paths` but then perform I/O
//! against a different inode after traversal.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arcana_core::permission::rule::ToolRuleSet;
use arcana_core::tool::ToolError;

/// Resolve `input` to an absolute, canonical [`PathBuf`].
///
/// When `input` is relative, it is joined onto `cwd` first. The kernel's
/// canonicalization is applied when the target exists; otherwise the parent
/// directory is canonicalized and the filename is re-appended. A path whose
/// parent also does not exist is returned cleaned but un-resolved (the tool
/// will fail later with a more precise I/O error).
///
/// # Errors
///
/// Returns [`ToolError::PermissionDenied`] when `input` is empty or has no
/// filename component — the guard refuses to dispatch under those inputs
/// because a downstream tool could not distinguish them from a directory
/// listing request.
pub fn resolve(input: &str, cwd: &Path) -> Result<PathBuf, ToolError> {
    if input.is_empty() {
        return Err(ToolError::PermissionDenied(
            "empty path is not allowed".to_owned(),
        ));
    }
    let raw = Path::new(input);
    let absolute = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };
    if let Ok(canonical) = std::fs::canonicalize(&absolute) {
        return Ok(canonical);
    }
    let Some(parent) = absolute.parent() else {
        return Ok(absolute);
    };
    let Some(file_name) = absolute.file_name() else {
        return Err(ToolError::PermissionDenied(format!(
            "path has no filename component: {}",
            absolute.display()
        )));
    };
    if let Ok(canonical_parent) = std::fs::canonicalize(parent) {
        return Ok(canonical_parent.join(file_name));
    }
    Ok(absolute)
}

/// Validate `input` against `rules` and return the canonical [`PathBuf`].
///
/// The check applies, in order:
///
/// 1. Resolution — `input` is canonicalized via [`resolve`].
/// 2. Deny — any match against `rules.deny_paths` short-circuits with
///    [`ToolError::PermissionDenied`].
/// 3. Allow — when `rules.allow_paths` is non-empty, the canonical path
///    MUST match at least one entry; otherwise the call is denied.
///
/// An empty `ToolRuleSet` (the shipped default) approves every input.
///
/// # Errors
///
/// Returns [`ToolError::PermissionDenied`] when any of the steps above
/// rejects the input; the carried message names the matching rule and the
/// canonical path for operator-facing diagnostics.
pub fn check(input: &str, rules: &Arc<ToolRuleSet>, cwd: &Path) -> Result<PathBuf, ToolError> {
    let canonical = resolve(input, cwd)?;
    let canonical_str = canonical.to_string_lossy();
    if let Some(rule) = rules
        .deny_paths
        .iter()
        .find(|re| re.is_match(&canonical_str))
    {
        return Err(ToolError::PermissionDenied(format!(
            "path `{}` denied by deny_paths rule `{}`",
            canonical.display(),
            rule.as_str()
        )));
    }
    if !rules.allow_paths.is_empty()
        && !rules
            .allow_paths
            .iter()
            .any(|re| re.is_match(&canonical_str))
    {
        return Err(ToolError::PermissionDenied(format!(
            "path `{}` does not match any allow_paths rule",
            canonical.display()
        )));
    }
    Ok(canonical)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use regex::Regex;
    use std::path::PathBuf;

    fn permissive() -> Arc<ToolRuleSet> {
        Arc::new(ToolRuleSet::default())
    }

    /// Deny rule that covers `/etc/passwd` on both Linux (`/etc/passwd`) and
    /// macOS (canonicalized `/private/etc/passwd` because `/etc` is a symlink).
    /// Production rule sets should follow the same pattern — the guard always
    /// matches against the canonical path.
    const ETC_PASSWD_PATTERN: &str = r"^/(private/)?etc/passwd$";

    fn deny_etc_passwd() -> Arc<ToolRuleSet> {
        Arc::new(ToolRuleSet {
            deny_paths: vec![Regex::new(ETC_PASSWD_PATTERN).expect("regex")],
            ..Default::default()
        })
    }

    fn allow_tmp_only() -> Arc<ToolRuleSet> {
        Arc::new(ToolRuleSet {
            allow_paths: vec![Regex::new(r"^/(private/)?tmp(/.*)?$").expect("regex")],
            ..Default::default()
        })
    }

    #[test]
    #[cfg(unix)]
    fn resolve_existing_absolute() {
        let resolved = resolve("/etc/passwd", Path::new("/")).expect("resolve");
        assert!(resolved.is_absolute());
        // canonicalize may resolve symlinks (e.g. /etc → /private/etc on macOS);
        // we only assert the filename and that the path is absolute.
        assert_eq!(resolved.file_name().expect("filename"), "passwd");
    }

    #[test]
    #[cfg(unix)]
    fn resolve_existing_traversal_collapses() {
        let resolved = resolve("../etc/passwd", Path::new("/tmp")).expect("resolve");
        assert_eq!(resolved.file_name().expect("filename"), "passwd");
        // Path must NOT contain `..` after resolution.
        assert!(
            !resolved
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
            "canonical path retained traversal: {}",
            resolved.display()
        );
    }

    #[test]
    fn resolve_nonexisting_in_existing_parent() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let target = format!("{}/does-not-exist.txt", tmpdir.path().display());
        let resolved = resolve(&target, Path::new("/")).expect("resolve");
        assert_eq!(
            resolved.file_name().expect("filename"),
            "does-not-exist.txt"
        );
        assert!(resolved.is_absolute());
    }

    #[test]
    fn resolve_root_parent_edge() {
        // A non-existent absolute path whose parent also does not exist
        // is returned as-is (cleaned), not Err.
        let resolved = resolve("/definitely/missing/dir/file", Path::new("/")).expect("resolve");
        assert_eq!(resolved, PathBuf::from("/definitely/missing/dir/file"));
    }

    #[test]
    #[cfg(unix)]
    fn check_deny_blocks_direct() {
        let err = check("/etc/passwd", &deny_etc_passwd(), Path::new("/"))
            .expect_err("should deny /etc/passwd");
        match err {
            ToolError::PermissionDenied(msg) => {
                assert!(msg.contains("deny_paths"), "msg: {msg}");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn check_deny_blocks_via_traversal() {
        // cwd=/tmp + "../etc/passwd" canonicalizes to /etc/passwd → deny.
        let err = check("../etc/passwd", &deny_etc_passwd(), Path::new("/tmp"))
            .expect_err("traversal must hit deny rule");
        assert!(matches!(err, ToolError::PermissionDenied(_)));
    }

    #[test]
    #[cfg(unix)]
    fn check_allow_required_pass() {
        // /tmp prefix or /private/tmp (macOS canonical) is allow-listed.
        let resolved =
            check("/tmp", &allow_tmp_only(), Path::new("/")).expect("/tmp must pass allow_paths");
        assert!(resolved.is_absolute());
    }

    #[test]
    #[cfg(unix)]
    fn check_allow_required_fail() {
        let err = check("/etc/hosts", &allow_tmp_only(), Path::new("/"))
            .expect_err("/etc/hosts must miss allow_paths");
        match err {
            ToolError::PermissionDenied(msg) => assert!(msg.contains("allow_paths"), "msg: {msg}"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn check_permissive_default_allows_any() {
        let resolved = check("/etc/passwd", &permissive(), Path::new("/"))
            .expect("permissive default must allow");
        assert!(resolved.is_absolute());
    }

    #[test]
    #[cfg(unix)]
    fn check_deny_message_carries_pattern() {
        let err = check("/etc/passwd", &deny_etc_passwd(), Path::new("/")).expect_err("deny");
        let ToolError::PermissionDenied(msg) = err else {
            panic!("expected PermissionDenied");
        };
        assert!(
            msg.contains(ETC_PASSWD_PATTERN),
            "deny msg lost the regex pattern: {msg}"
        );
    }
}
