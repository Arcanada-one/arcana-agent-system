//! Layer 3: `permissions.toml` rule check.
//!
//! Loads regex-based allow/deny rules from `~/.config/arcana/permissions.toml`
//! (user-level, XDG) and optionally from `.arcana/permissions.toml`
//! (project-local). User and project rule sets are merged additively (deny
//! patterns from both apply; allow patterns from both apply). The MCP
//! posture is invariant: MCP tools default to `Deny` unless an explicit
//! allow pattern matches the tool name.
//!
//! Built-in tools default to `Defer` when no rule matches, letting the
//! Interactive layer or the cascade tail resolve the call.

use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::{LayerDecision, PermissionLayer};

/// Hard cap on `permissions.toml` size; protects against giant
/// adversarial files exhausting the regex compiler.
pub const MAX_RULE_FILE_BYTES: u64 = 64 * 1024;

const MCP_TOOL_PREFIX: &str = "mcp:";
const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Failure modes raised by [`RuleLayer::load`].
#[derive(Debug, Error)]
pub enum RuleLoadError {
    #[error("rule file too large: {0} bytes (cap {MAX_RULE_FILE_BYTES} bytes)")]
    TooLarge(u64),
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("toml parse error in {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "unsupported schema_version {found} in {path} (this build supports {SUPPORTED_SCHEMA_VERSION})"
    )]
    SchemaVersion { path: PathBuf, found: u32 },
    #[error("invalid regex `{pattern}` at [{section}] in {path}: {source}")]
    BadRegex {
        path: PathBuf,
        section: String,
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Pre-compiled rule set for one tool.
#[derive(Debug, Default, Clone)]
pub struct ToolRuleSet {
    pub allow_commands: Vec<Regex>,
    pub deny_commands: Vec<Regex>,
    pub allow_hosts: Vec<Regex>,
    pub allow_paths: Vec<Regex>,
    pub deny_paths: Vec<Regex>,
}

/// Pre-compiled MCP rule set.
#[derive(Debug, Default, Clone)]
pub struct McpRuleSet {
    pub allow: Vec<Regex>,
}

/// Compiled rules sourced from a single TOML file.
#[derive(Debug, Default, Clone)]
struct RuleSnapshot {
    tools: std::collections::BTreeMap<String, ToolRuleSet>,
    mcp: McpRuleSet,
}

/// Permission layer that consults compiled rules.
#[derive(Debug)]
pub struct RuleLayer {
    user: RuleSnapshot,
    project: RuleSnapshot,
}

impl RuleLayer {
    /// Construct an empty layer (no rules — built-ins defer, MCP defaults
    /// to deny). Useful for tests and the default boot path before the
    /// operator authors a `permissions.toml`.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            user: RuleSnapshot::default(),
            project: RuleSnapshot::default(),
        }
    }

    /// Load user-level and (optionally) project-local rule files. Missing
    /// files are tolerated; parse / size / schema errors are surfaced.
    ///
    /// # Errors
    ///
    /// Returns [`RuleLoadError`] when a file exceeds the size cap, fails to
    /// parse, declares an unsupported schema version, or contains an
    /// uncompilable regex.
    pub fn load(
        user_path: Option<&Path>,
        project_path: Option<&Path>,
    ) -> Result<Self, RuleLoadError> {
        let user = match user_path {
            Some(p) if p.exists() => load_snapshot(p)?,
            _ => RuleSnapshot::default(),
        };
        let project = match project_path {
            Some(p) if p.exists() => load_snapshot(p)?,
            _ => RuleSnapshot::default(),
        };
        Ok(Self { user, project })
    }

    /// Resolve the canonical user-level path via XDG.
    ///
    /// # Errors
    ///
    /// Propagates the underlying `xdg::BaseDirectoriesError` when the
    /// XDG layout cannot be initialised (e.g. unreadable `$HOME`).
    pub fn xdg_user_path() -> Result<PathBuf, xdg::BaseDirectoriesError> {
        let base = xdg::BaseDirectories::with_prefix("arcana")?;
        Ok(base.get_config_file("permissions.toml"))
    }

    fn match_tool(&self, tool: &str, input: &Value) -> Option<LayerDecision> {
        let user = self.user.tools.get(tool);
        let project = self.project.tools.get(tool);
        if user.is_none() && project.is_none() {
            return None;
        }
        let merged = merge_tool_rules(user, project);
        match_tool_rules(tool, &merged, input)
    }

    fn match_mcp(&self, tool: &str) -> LayerDecision {
        let stripped = tool.strip_prefix(MCP_TOOL_PREFIX).unwrap_or(tool);
        for snapshot in [&self.user, &self.project] {
            if snapshot.mcp.allow.iter().any(|re| re.is_match(stripped)) {
                return LayerDecision::Allow;
            }
        }
        LayerDecision::Deny(format!("no explicit allow for MCP tool: {tool}"))
    }
}

#[async_trait]
impl PermissionLayer for RuleLayer {
    fn name(&self) -> &'static str {
        "rule"
    }

    async fn evaluate(&self, tool: &str, input: &Value) -> LayerDecision {
        if tool.starts_with(MCP_TOOL_PREFIX) {
            return self.match_mcp(tool);
        }
        self.match_tool(tool, input).unwrap_or(LayerDecision::Defer)
    }
}

fn merge_tool_rules(user: Option<&ToolRuleSet>, project: Option<&ToolRuleSet>) -> ToolRuleSet {
    let mut merged = ToolRuleSet::default();
    for source in [user, project].into_iter().flatten() {
        merged
            .allow_commands
            .extend(source.allow_commands.iter().cloned());
        merged
            .deny_commands
            .extend(source.deny_commands.iter().cloned());
        merged
            .allow_hosts
            .extend(source.allow_hosts.iter().cloned());
        merged
            .allow_paths
            .extend(source.allow_paths.iter().cloned());
        merged.deny_paths.extend(source.deny_paths.iter().cloned());
    }
    merged
}

fn match_tool_rules(tool: &str, rules: &ToolRuleSet, input: &Value) -> Option<LayerDecision> {
    let command = input.get("command").and_then(Value::as_str);
    let host = input
        .get("url")
        .and_then(Value::as_str)
        .and_then(extract_host);
    let path = input.get("path").and_then(Value::as_str);

    if let Some(cmd) = command {
        if let Some(rx) = rules.deny_commands.iter().find(|re| re.is_match(cmd)) {
            return Some(LayerDecision::Deny(format!(
                "denied by deny_commands rule `{pat}` on tool `{tool}`",
                pat = rx.as_str(),
            )));
        }
    }
    if let Some(p) = path {
        if let Some(rx) = rules.deny_paths.iter().find(|re| re.is_match(p)) {
            return Some(LayerDecision::Deny(format!(
                "denied by deny_paths rule `{pat}` on tool `{tool}`",
                pat = rx.as_str(),
            )));
        }
    }
    if let Some(cmd) = command {
        if !rules.allow_commands.is_empty() {
            if rules.allow_commands.iter().any(|re| re.is_match(cmd)) {
                return Some(LayerDecision::Allow);
            }
            return Some(LayerDecision::Deny(format!(
                "command does not match any allow_commands rule on tool `{tool}`"
            )));
        }
    }
    if let Some(h) = host {
        if !rules.allow_hosts.is_empty() {
            if rules.allow_hosts.iter().any(|re| re.is_match(&h)) {
                return Some(LayerDecision::Allow);
            }
            return Some(LayerDecision::Deny(format!(
                "host does not match any allow_hosts rule on tool `{tool}`"
            )));
        }
    }
    if let Some(p) = path {
        if !rules.allow_paths.is_empty() {
            if rules.allow_paths.iter().any(|re| re.is_match(p)) {
                return Some(LayerDecision::Allow);
            }
            return Some(LayerDecision::Deny(format!(
                "path does not match any allow_paths rule on tool `{tool}`"
            )));
        }
    }
    None
}

fn extract_host(url: &str) -> Option<String> {
    let scheme_end = url.find("://").map_or(0, |i| i + 3);
    let after_scheme = &url[scheme_end..];
    let end = after_scheme
        .find(['/', '?', '#', ':'])
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..end];
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn load_snapshot(path: &Path) -> Result<RuleSnapshot, RuleLoadError> {
    let meta = fs::metadata(path).map_err(|source| RuleLoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.len() > MAX_RULE_FILE_BYTES {
        return Err(RuleLoadError::TooLarge(meta.len()));
    }
    let text = fs::read_to_string(path).map_err(|source| RuleLoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let raw: RawConfig = toml::from_str(&text).map_err(|source| RuleLoadError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    if raw.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(RuleLoadError::SchemaVersion {
            path: path.to_path_buf(),
            found: raw.schema_version,
        });
    }
    compile_snapshot(path, raw)
}

fn compile_snapshot(path: &Path, raw: RawConfig) -> Result<RuleSnapshot, RuleLoadError> {
    let mut tools = std::collections::BTreeMap::new();
    for (name, raw_tool) in raw.tool {
        let mut set = ToolRuleSet::default();
        let section = format!("tool.{name}");
        compile_into(
            &mut set.allow_commands,
            &raw_tool.allow_commands,
            path,
            &section,
            "allow_commands",
        )?;
        compile_into(
            &mut set.deny_commands,
            &raw_tool.deny_commands,
            path,
            &section,
            "deny_commands",
        )?;
        compile_into(
            &mut set.allow_hosts,
            &raw_tool.allow_hosts,
            path,
            &section,
            "allow_hosts",
        )?;
        compile_into(
            &mut set.allow_paths,
            &raw_tool.allow_paths,
            path,
            &section,
            "allow_paths",
        )?;
        compile_into(
            &mut set.deny_paths,
            &raw_tool.deny_paths,
            path,
            &section,
            "deny_paths",
        )?;
        tools.insert(name, set);
    }
    let mut mcp = McpRuleSet::default();
    if let Some(mcp_raw) = raw.mcp {
        compile_into(&mut mcp.allow, &mcp_raw.allow, path, "mcp", "allow")?;
    }
    Ok(RuleSnapshot { tools, mcp })
}

fn compile_into(
    sink: &mut Vec<Regex>,
    patterns: &[String],
    path: &Path,
    section: &str,
    _field: &str,
) -> Result<(), RuleLoadError> {
    for pattern in patterns {
        let compiled = Regex::new(pattern).map_err(|source| RuleLoadError::BadRegex {
            path: path.to_path_buf(),
            section: section.to_string(),
            pattern: pattern.clone(),
            source,
        })?;
        sink.push(compiled);
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    schema_version: u32,
    #[serde(default)]
    tool: std::collections::BTreeMap<String, RawToolRules>,
    #[serde(default)]
    mcp: Option<RawMcp>,
}

#[derive(Debug, Default, Deserialize)]
struct RawToolRules {
    #[serde(default)]
    allow_commands: Vec<String>,
    #[serde(default)]
    deny_commands: Vec<String>,
    #[serde(default)]
    allow_hosts: Vec<String>,
    #[serde(default)]
    allow_paths: Vec<String>,
    #[serde(default)]
    deny_paths: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawMcp {
    #[serde(default)]
    allow: Vec<String>,
}
