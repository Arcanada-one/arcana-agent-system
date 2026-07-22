//! `ArcanaSearchTool` — agent-callable wrapper around Scrutator's hybrid
//! search (`POST /v1/search`), so the agent can query the Arcanada
//! knowledge base directly from a tool call.
//!
//! Thin by design: the tool parses/validates the input, delegates the HTTP
//! round-trip to [`arcana_connectors::ScrutatorClient`], and renders the
//! hits into an LLM-readable summary (`ToolOutput::content`) plus the raw
//! structured results (`ToolOutput::metadata`).

use arcana_connectors::scrutator::{ScrutatorError, SearchQuery};
use arcana_connectors::ScrutatorClient;
use arcana_core::tool::{Tool, ToolError, ToolInvocation, ToolOutput};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

/// Snippet length cap for the human-readable summary; the full content is
/// still available via `ToolOutput::metadata`.
const SNIPPET_MAX_CHARS: usize = 400;

#[derive(Debug, Deserialize)]
struct ArcanaSearchInput {
    query: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    source_type: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    min_score: Option<f64>,
    #[serde(default)]
    include_content: Option<bool>,
}

pub struct ArcanaSearchTool {
    client: ScrutatorClient,
}

impl ArcanaSearchTool {
    /// Build a tool client from `ARCANA_SCRUTATOR_URL` (falls back to the
    /// default Scrutator mesh endpoint — see
    /// [`arcana_connectors::scrutator::ScrutatorClient::try_from_env`]).
    ///
    /// # Errors
    /// Returns [`ScrutatorError`] if the resolved base URL is malformed or
    /// the underlying HTTP client fails to build.
    pub fn from_env() -> Result<Self, ScrutatorError> {
        Ok(Self {
            client: ScrutatorClient::try_from_env()?,
        })
    }

    /// Build a tool against an explicit client (tests / non-default
    /// deployments).
    #[must_use]
    pub fn with_client(client: ScrutatorClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Tool for ArcanaSearchTool {
    fn name(&self) -> &'static str {
        "arcana_search"
    }

    fn description(&self) -> &'static str {
        "Hybrid search over the Arcanada knowledge base via Scrutator. \
         Returns ranked chunks with source path, score, and snippet."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": { "type": "string", "minLength": 1 },
                "namespace": { "type": "string", "minLength": 1 },
                "project": { "type": "string", "minLength": 1 },
                "source_type": { "type": "string", "minLength": 1 },
                "limit": { "type": "integer", "minimum": 1, "maximum": 50 },
                "min_score": { "type": "number", "minimum": 0.0 },
                "include_content": { "type": "boolean" }
            },
            "additionalProperties": false
        })
    }

    async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput, ToolError> {
        let input = invocation.into_input();
        let parsed: ArcanaSearchInput = serde_json::from_value(input)
            .map_err(|err| ToolError::InvalidInput(err.to_string()))?;

        let mut query = SearchQuery::new(parsed.query.clone());
        query.namespace = parsed.namespace;
        query.project = parsed.project;
        query.source_type = parsed.source_type;
        query.limit = parsed.limit;
        query.min_score = parsed.min_score;
        query.include_content = parsed.include_content;

        let response = self
            .client
            .search(&query)
            .await
            .map_err(|err| ToolError::ExecutionFailed(err.to_string()))?;

        let content = render_summary(&parsed.query, &response.results);
        let metadata = json!({
            "query": parsed.query,
            "count": response.results.len(),
            "results": response.results,
        });

        Ok(ToolOutput {
            content,
            metadata: Some(metadata),
        })
    }
}

fn render_summary(query: &str, hits: &[arcana_connectors::scrutator::SearchHit]) -> String {
    if hits.is_empty() {
        return format!("No results for query: \"{query}\"");
    }
    let mut lines = Vec::with_capacity(hits.len() + 1);
    lines.push(format!("{} result(s) for \"{query}\":", hits.len()));
    for (i, hit) in hits.iter().enumerate() {
        let snippet = truncate(&hit.content, SNIPPET_MAX_CHARS);
        lines.push(format!(
            "{}. [score={:.3}] {} (chunk {})\n   {}",
            i + 1,
            hit.score,
            hit.source_path,
            hit.chunk_index,
            snippet
        ));
    }
    lines.join("\n")
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    let truncated: String = text.chars().take(max_chars).collect();
    format!("{truncated}…")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use arcana_connectors::scrutator::SearchHit;

    fn hit(source_path: &str, score: f64, content: &str) -> SearchHit {
        SearchHit {
            chunk_id: "c1".into(),
            content: content.into(),
            source_path: source_path.into(),
            source_type: "markdown".into(),
            chunk_index: 0,
            score,
            namespace: None,
            project: None,
            metadata: None,
            content_hash: String::new(),
            source_id: String::new(),
        }
    }

    #[test]
    fn render_summary_empty_results() {
        let summary = render_summary("nothing here", &[]);
        assert_eq!(summary, "No results for query: \"nothing here\"");
    }

    #[test]
    fn render_summary_lists_source_and_score() {
        let hits = vec![hit("docs/a.md", 0.9123, "hello world")];
        let summary = render_summary("q", &hits);
        assert!(summary.contains("docs/a.md"));
        assert!(summary.contains("0.912"));
        assert!(summary.contains("hello world"));
    }

    #[test]
    fn truncate_adds_ellipsis_past_cap() {
        let long = "x".repeat(SNIPPET_MAX_CHARS + 50);
        let out = truncate(&long, SNIPPET_MAX_CHARS);
        assert_eq!(out.chars().count(), SNIPPET_MAX_CHARS + 1);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_leaves_short_text_untouched() {
        assert_eq!(truncate("short", SNIPPET_MAX_CHARS), "short");
    }
}
