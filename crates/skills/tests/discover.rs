//! ARAS-0050 Phase-3 — semantic skill *discovery* over the `SkillSearch` seam.
//!
//! These tests cover the discovery half of the two-phase firewall:
//!
//! * `discover(intent)` returns only **production**-maturity candidates, and a
//!   draft/validated skill is excluded **server-side** (the fixture backend
//!   applies the `min_maturity` floor before ranking — the store never
//!   post-filters).
//! * a discovered [`SkillCandidate`] cannot authorize a run: it carries a
//!   SHA-256 `content_hash`, never a blake3 anchor, and there is no
//!   `SkillCandidate → SkillPin` bridge (compile-fail on the type; here we prove
//!   the *security consequence* — a candidate-derived pin fails closed with
//!   `HashMismatch`, before parse, before any execution).
//! * the quality bar (V-AC-14): **precision@1 >= 0.90** and **recall@5 == 1.0**
//!   over a labelled corpus of >= 20 production skill-plans, ranked by a
//!   deterministic field-weighted IR scorer standing in for Scrutator's hybrid
//!   search (no live Scrutator required).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arcana_skills::{
    DiscoverQuery, Maturity, ScrutatorStore, SearchUnavailable, SkillCandidate, SkillDiscovery,
    SkillError, SkillHit, SkillPin, SkillSearch, SkillStore, SKILLS_NAMESPACE, SKILL_TRUST_CLASS,
};
use async_trait::async_trait;
use serde_json::json;

// ---------------------------------------------------------------------------
// Fixture corpus: a labelled set of skill plans + a deterministic IR backend
// that mimics Scrutator's hybrid search server-side (maturity filter + rank).
// ---------------------------------------------------------------------------

/// A corpus fixture skill: the searchable fields (name / keywords / summary) a
/// Scrutator index would carry, plus the non-authorizing proposal metadata.
struct SkillDoc {
    name: &'static str,
    version: u32,
    maturity: Maturity,
    keywords: &'static [&'static str],
    summary: &'static str,
}

impl SkillDoc {
    fn content_hash(&self) -> String {
        // A SHA-256-shaped ingest digest (staleness signal) — deliberately NOT a
        // blake3 run-path anchor. Deterministic from the name for the fixture.
        format!("sha256:{}", blake3::hash(self.name.as_bytes()).to_hex())
    }

    /// Every searchable token, tagged by field weight (name=3, keyword=2,
    /// summary=1), for the IR scorer.
    fn field_tokens(&self) -> Vec<(String, f64)> {
        let mut out = Vec::new();
        for t in tokenize(self.name) {
            out.push((t, 3.0));
        }
        for kw in self.keywords {
            for t in tokenize(kw) {
                out.push((t, 2.0));
            }
        }
        for t in tokenize(self.summary) {
            out.push((t, 1.0));
        }
        out
    }
}

const STOPWORDS: &[&str] = &[
    "a", "an", "the", "to", "for", "of", "and", "or", "with", "my", "in", "on", "from", "into",
    "by", "that", "this", "as", "is", "be", "it",
];

fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|t| t.len() >= 2 && !STOPWORDS.contains(&t.as_str()))
        .collect()
}

/// The labelled production corpus (>= 20 plans) with one natural-language intent
/// each. Every intent contains at least one corpus-distinctive keyword for its
/// target skill, so a field-weighted + IDF ranker resolves it top-1.
fn production_corpus() -> Vec<(SkillDoc, &'static str)> {
    vec![
        (
            SkillDoc {
                name: "codegen-review",
                version: 3,
                maturity: Maturity::Production,
                keywords: &["code", "review", "pull", "request", "diff"],
                summary: "review a pull request diff for code quality problems",
            },
            "review my pull request code diff for quality issues",
        ),
        (
            SkillDoc {
                name: "sql-migration",
                version: 2,
                maturity: Maturity::Production,
                keywords: &["sql", "database", "migration", "schema", "alter"],
                summary: "generate a database schema migration alter script",
            },
            "generate a sql database migration alter script",
        ),
        (
            SkillDoc {
                name: "dependency-audit",
                version: 1,
                maturity: Maturity::Production,
                keywords: &["dependency", "vulnerability", "cve", "audit", "package"],
                summary: "audit project dependencies for known cve vulnerabilities",
            },
            "audit project dependency packages for known cve vulnerability",
        ),
        (
            SkillDoc {
                name: "log-summarize",
                version: 4,
                maturity: Maturity::Production,
                keywords: &["log", "summarize", "error", "trace", "incident"],
                summary: "summarize error logs and traces from a production incident",
            },
            "summarize error log traces from a production incident",
        ),
        (
            SkillDoc {
                name: "api-fuzz",
                version: 2,
                maturity: Maturity::Production,
                keywords: &["fuzz", "endpoint", "payload", "rest"],
                summary: "fuzz a rest api endpoint with malformed payloads",
            },
            "fuzz a rest endpoint with malformed payloads",
        ),
        (
            SkillDoc {
                name: "unit-test-gen",
                version: 5,
                maturity: Maturity::Production,
                keywords: &["unit", "test", "coverage", "assertion"],
                summary: "generate unit tests to raise assertion coverage",
            },
            "generate unit tests to raise assertion coverage",
        ),
        (
            SkillDoc {
                name: "docstring-write",
                version: 1,
                maturity: Maturity::Production,
                keywords: &["docstring", "comment", "annotate", "function"],
                summary: "write docstring comments annotating functions",
            },
            "write docstring comments annotating a function",
        ),
        (
            SkillDoc {
                name: "regex-build",
                version: 2,
                maturity: Maturity::Production,
                keywords: &["regex", "pattern", "expression", "validate"],
                summary: "build a regex pattern expression to validate input",
            },
            "build a regex pattern expression to validate input",
        ),
        (
            SkillDoc {
                name: "json-schema",
                version: 3,
                maturity: Maturity::Production,
                keywords: &["json", "contract", "structure", "validate"],
                summary: "produce a json schema validating a data contract structure",
            },
            "produce a json schema validating a data contract structure",
        ),
        (
            SkillDoc {
                name: "commit-message",
                version: 1,
                maturity: Maturity::Production,
                keywords: &["commit", "message", "conventional"],
                summary: "draft a conventional commit message for a code change",
            },
            "draft a conventional commit message for a code change",
        ),
        (
            SkillDoc {
                name: "dockerfile-lint",
                version: 2,
                maturity: Maturity::Production,
                keywords: &["dockerfile", "container", "lint", "layer"],
                summary: "lint a dockerfile container image for layer problems",
            },
            "lint a dockerfile container image for layer problems",
        ),
        (
            SkillDoc {
                name: "yaml-config",
                version: 1,
                maturity: Maturity::Production,
                keywords: &["yaml", "config", "deploy", "manifest"],
                summary: "author a yaml deploy configuration manifest",
            },
            "author a yaml deploy configuration manifest",
        ),
        (
            SkillDoc {
                name: "perf-profile",
                version: 3,
                maturity: Maturity::Production,
                keywords: &["performance", "profile", "latency", "hotspot"],
                summary: "profile performance latency to find a hotspot",
            },
            "profile performance latency to find a hotspot",
        ),
        (
            SkillDoc {
                name: "i18n-extract",
                version: 2,
                maturity: Maturity::Production,
                keywords: &["i18n", "translation", "locale", "internationalize"],
                summary: "extract translatable strings for locale internationalization",
            },
            "extract translatable strings for locale i18n internationalization",
        ),
        (
            SkillDoc {
                name: "accessibility-audit",
                version: 1,
                maturity: Maturity::Production,
                keywords: &["accessibility", "a11y", "aria", "wcag", "contrast"],
                summary: "audit page accessibility aria contrast against wcag",
            },
            "audit page accessibility a11y aria contrast against wcag",
        ),
        (
            SkillDoc {
                name: "graphql-query",
                version: 2,
                maturity: Maturity::Production,
                keywords: &["graphql", "query", "resolver", "field"],
                summary: "write a graphql query resolver over schema fields",
            },
            "write a graphql query resolver over fields",
        ),
        (
            SkillDoc {
                name: "secret-scan",
                version: 3,
                maturity: Maturity::Production,
                keywords: &["secret", "credential", "token", "leak"],
                summary: "scan a repository for leaked secret credential tokens",
            },
            "scan a repository for leaked secret credential tokens",
        ),
        (
            SkillDoc {
                name: "changelog-gen",
                version: 1,
                maturity: Maturity::Production,
                keywords: &["changelog", "release", "notes", "semver"],
                summary: "generate release notes changelog for a semver version",
            },
            "generate release notes changelog for a semver version",
        ),
        (
            SkillDoc {
                name: "terraform-plan",
                version: 2,
                maturity: Maturity::Production,
                keywords: &["terraform", "infrastructure", "provision", "resource"],
                summary: "plan terraform infrastructure to provision cloud resources",
            },
            "plan terraform infrastructure to provision cloud resources",
        ),
        (
            SkillDoc {
                name: "shell-script",
                version: 1,
                maturity: Maturity::Production,
                keywords: &["shell", "bash", "script", "automation"],
                summary: "write a bash shell script for cli automation",
            },
            "write a bash shell script for cli automation",
        ),
        (
            SkillDoc {
                name: "markdown-table",
                version: 2,
                maturity: Maturity::Production,
                keywords: &["markdown", "table", "align", "render"],
                summary: "format a markdown table with aligned rendered columns",
            },
            "format a markdown table with aligned columns",
        ),
        (
            SkillDoc {
                name: "csv-transform",
                version: 1,
                maturity: Maturity::Production,
                keywords: &["csv", "transform", "delimiter", "parse"],
                summary: "transform csv data by parsing delimiter columns",
            },
            "transform csv data by parsing delimiter columns",
        ),
    ]
}

/// Non-production decoys that MUST NOT surface in discovery even on a perfect
/// intent match — proves the maturity floor is enforced server-side.
fn decoys() -> Vec<SkillDoc> {
    vec![
        SkillDoc {
            name: "auto-deploy-prod",
            version: 1,
            maturity: Maturity::Draft,
            keywords: &["auto", "deploy", "rollout", "production"],
            summary: "automatically deploy and rollout straight to production",
        },
        SkillDoc {
            name: "codegen-review",
            version: 4,
            maturity: Maturity::Draft,
            keywords: &["code", "review", "pull", "request", "diff"],
            summary: "review a pull request diff for code quality problems",
        },
        SkillDoc {
            name: "sql-migration",
            version: 3,
            maturity: Maturity::Validated,
            keywords: &["sql", "database", "migration", "schema", "alter"],
            summary: "generate a database schema migration alter script",
        },
    ]
}

/// In-memory `SkillSearch` backend: applies the `min_maturity` floor
/// **server-side** (before ranking), then ranks the surviving docs with a
/// field-weighted IDF scorer (a deterministic stand-in for Scrutator's hybrid
/// search). Never returns a hit below the floor.
struct FixtureSearch {
    docs: Vec<SkillDoc>,
    idf: HashMap<String, f64>,
}

impl FixtureSearch {
    fn new(docs: Vec<SkillDoc>) -> Self {
        // IDF over the whole indexed corpus (all maturities) — the ranker is
        // corpus-statistical; the maturity floor is a separate server-side gate.
        let n = docs.len() as f64;
        let mut df: HashMap<String, usize> = HashMap::new();
        for d in &docs {
            let mut seen = HashSet::new();
            for (t, _) in d.field_tokens() {
                if seen.insert(t.clone()) {
                    *df.entry(t).or_insert(0) += 1;
                }
            }
        }
        let idf = df
            .into_iter()
            .map(|(t, c)| (t, (1.0 + n / (1.0 + c as f64)).ln()))
            .collect();
        Self { docs, idf }
    }

    fn score(&self, intent_tokens: &HashSet<String>, doc: &SkillDoc) -> f64 {
        // Best field weight per matched query token × its IDF.
        let mut best: HashMap<String, f64> = HashMap::new();
        for (t, w) in doc.field_tokens() {
            let e = best.entry(t).or_insert(0.0);
            if w > *e {
                *e = w;
            }
        }
        intent_tokens
            .iter()
            .filter_map(|t| {
                best.get(t)
                    .map(|w| w * self.idf.get(t).copied().unwrap_or(0.0))
            })
            .sum()
    }
}

#[async_trait]
impl SkillSearch for FixtureSearch {
    async fn search(&self, query: &DiscoverQuery) -> Result<Vec<SkillHit>, SearchUnavailable> {
        assert_eq!(
            query.namespace, SKILLS_NAMESPACE,
            "discovery must scope to skills"
        );
        let intent: HashSet<String> = tokenize(&query.intent).into_iter().collect();
        let mut hits: Vec<SkillHit> = self
            .docs
            .iter()
            // SERVER-SIDE maturity floor: never emit a hit below the requested
            // floor. Draft/validated are excluded here, not in the store.
            .filter(|d| d.maturity >= query.min_maturity)
            .map(|d| SkillHit {
                name: d.name.to_owned(),
                version: d.version,
                content_hash: d.content_hash(),
                maturity: d.maturity,
                score: self.score(&intent, d),
            })
            .filter(|h| h.score > 0.0)
            .collect();
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(hits)
    }
}

fn full_index() -> FixtureSearch {
    let mut docs: Vec<SkillDoc> = production_corpus().into_iter().map(|(d, _)| d).collect();
    docs.extend(decoys());
    FixtureSearch::new(docs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// V-AC-14 — precision@1 >= 0.90 and recall@5 == 1.0 over the labelled corpus.
#[tokio::test]
async fn discovery_quality_bar_precision_recall() {
    let labels: Vec<(String, &'static str)> = production_corpus()
        .iter()
        .map(|(d, intent)| ((*intent).to_owned(), d.name))
        .collect();
    let n = labels.len();
    assert!(n >= 20, "corpus must have >= 20 labelled plans, got {n}");

    let discovery = SkillDiscovery::new(Arc::new(full_index()));

    let mut top1_hits = 0usize;
    let mut in_top5 = 0usize;
    for (intent, expected) in &labels {
        let candidates = discovery.discover(intent, 5).await.expect("discover ok");
        assert!(
            !candidates.is_empty(),
            "no candidates for intent `{intent}`"
        );
        if candidates[0].name == *expected {
            top1_hits += 1;
        }
        if candidates.iter().take(5).any(|c| c.name == *expected) {
            in_top5 += 1;
        }
    }

    let precision_at_1 = top1_hits as f64 / n as f64;
    let recall_at_5 = in_top5 as f64 / n as f64;
    println!(
        "ARAS-0050 discovery eval: corpus={n} precision@1={precision_at_1:.3} recall@5={recall_at_5:.3}"
    );
    assert!(
        precision_at_1 >= 0.90,
        "precision@1 {precision_at_1:.3} < 0.90 (top1={top1_hits}/{n})"
    );
    assert!(
        (recall_at_5 - 1.0).abs() < f64::EPSILON,
        "recall@5 {recall_at_5:.3} != 1.0 (in_top5={in_top5}/{n})"
    );
}

/// `discover` returns **only** production candidates; a draft sibling of a
/// matched skill never appears (excluded server-side, not post-filtered).
#[tokio::test]
async fn discover_returns_only_production() {
    let discovery = SkillDiscovery::new(Arc::new(full_index()));
    let candidates = discovery
        .discover("review my pull request code diff for quality issues", 10)
        .await
        .expect("discover ok");

    assert!(!candidates.is_empty());
    for c in &candidates {
        assert_eq!(
            c.maturity,
            Maturity::Production,
            "a non-production candidate crossed the seam: {c:?}"
        );
    }
    // The production codegen-review is proposed…
    assert_eq!(candidates[0].name, "codegen-review");
    assert_eq!(
        candidates[0].version, 3,
        "the production (v3) plan, not the draft v4"
    );
}

/// A draft skill is NOT discoverable even when the intent matches its fields
/// perfectly — the maturity floor is enforced server-side.
#[tokio::test]
async fn draft_skill_not_discoverable() {
    let discovery = SkillDiscovery::new(Arc::new(full_index()));
    // This intent matches ONLY the `auto-deploy-prod` DRAFT decoy's keywords;
    // no production skill covers "auto rollout to production".
    let candidates = discovery
        .discover(
            "automatically deploy and rollout straight to production",
            10,
        )
        .await
        .expect("discover ok");

    assert!(
        candidates.iter().all(|c| c.name != "auto-deploy-prod"),
        "a draft skill must never be discoverable, got {candidates:?}"
    );
    assert!(
        candidates
            .iter()
            .all(|c| c.maturity == Maturity::Production),
        "only production candidates may be returned"
    );
}

/// A hit BELOW the requested floor is dropped by the backend; the discovery
/// query always pins `min_maturity == Production` and `namespace == skills`.
#[tokio::test]
async fn discover_query_pins_production_floor_and_namespace() {
    struct Spy {
        captured: std::sync::Mutex<Option<DiscoverQuery>>,
    }
    #[async_trait]
    impl SkillSearch for Spy {
        async fn search(&self, query: &DiscoverQuery) -> Result<Vec<SkillHit>, SearchUnavailable> {
            *self.captured.lock().unwrap() = Some(query.clone());
            Ok(vec![])
        }
    }
    let spy = Arc::new(Spy {
        captured: std::sync::Mutex::new(None),
    });
    let discovery = SkillDiscovery::new(spy.clone());
    let _ = discovery
        .discover("anything", 3)
        .await
        .expect("discover ok");
    let q = spy
        .captured
        .lock()
        .unwrap()
        .clone()
        .expect("query captured");
    assert_eq!(q.min_maturity, Maturity::Production);
    assert_eq!(q.namespace, SKILLS_NAMESPACE);
    assert_eq!(q.limit, 3);
}

/// A backend failure fails closed to `StoreUnavailable` — discovery never
/// fabricates candidates.
#[tokio::test]
async fn discover_backend_down_fails_closed() {
    struct Down;
    #[async_trait]
    impl SkillSearch for Down {
        async fn search(&self, _q: &DiscoverQuery) -> Result<Vec<SkillHit>, SearchUnavailable> {
            Err(SearchUnavailable("connection refused".into()))
        }
    }
    let discovery = SkillDiscovery::new(Arc::new(Down));
    let err = discovery
        .discover("review my pull request", 5)
        .await
        .expect_err("a down backend must fail closed");
    assert!(
        matches!(err, SkillError::StoreUnavailable { .. }),
        "got {err:?}"
    );
}

/// The firewall: a candidate obtained from `discover()` cannot authorize a run.
/// Its `content_hash` is a SHA-256 staleness signal, not a blake3 anchor; even
/// if a naive caller fed it to a `SkillPin`, the fetched bytes' real blake3 will
/// not match → `HashMismatch`, before parse, before any execution. There is no
/// `SkillCandidate → SkillPin` conversion (compile-fail on the type).
#[tokio::test]
async fn discovered_candidate_cannot_construct_pin() {
    struct FixedConn(Vec<u8>);
    #[async_trait]
    impl arcana_skills::FetchConn for FixedConn {
        async fn fetch(
            &self,
            _source_id: &str,
        ) -> Result<arcana_skills::FetchedContent, arcana_skills::FetchUnavailable> {
            Ok(arcana_skills::FetchedContent {
                bytes: self.0.clone(),
                trust_class: SKILL_TRUST_CLASS.to_owned(),
                namespace: SKILLS_NAMESPACE.to_owned(),
            })
        }
    }

    let discovery = SkillDiscovery::new(Arc::new(full_index()));
    let candidates = discovery
        .discover("review my pull request code diff for quality issues", 1)
        .await
        .expect("discover ok");
    let candidate: &SkillCandidate = &candidates[0];
    assert!(
        candidate.content_hash.starts_with("sha256:"),
        "a candidate carries a SHA-256 signal, not a blake3 anchor"
    );

    // The real plan bytes for that skill.
    let plan = json!({
        "schema_version": 1,
        "name": candidate.name,
        "version": candidate.version,
        "kind": "instance",
        "maturity": "production",
        "stages": [{
            "id": "s1",
            "model": { "literal": "m-default" },
            "agent_count": 1,
            "limits": { "max_turns": 1, "max_cost_usd": 0.0, "context_budget_chars": 1024 },
            "tools": [],
            "metrics": [],
            "action": { "capability": "echo", "input": {} }
        }],
        "defaults": { "model": { "literal": "m-default" } }
    });
    let bytes = serde_json::to_vec(&plan).unwrap();

    // Naively derive a pin's trust anchor from the candidate's content_hash.
    let forged = SkillPin::new(
        candidate.name.clone(),
        candidate.version,
        candidate.content_hash.clone(),
        "kb:skill:codegen-review:3",
    );
    let store = ScrutatorStore::new(Arc::new(FixedConn(bytes)));
    let err = store
        .load(&forged)
        .await
        .expect_err("a discovered candidate can never authorize a run");
    assert!(
        matches!(err, SkillError::HashMismatch { .. }),
        "got {err:?}"
    );
}
