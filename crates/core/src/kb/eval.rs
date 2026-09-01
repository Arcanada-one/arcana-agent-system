//! RAGAS-style **offline** evaluation harness for the agent↔KB cascade
//! (backlog, the harness deferred to a measured v2).
//!
//! Computes the three RAGAS retrieval-quality metrics over a fixture QA set:
//!
//! * **context precision** — of the retrieved contexts, the fraction that are
//!   relevant to the reference answer (are they signal or distractors?);
//! * **context recall** — of the reference answer's claims, the fraction the
//!   retrieved contexts actually cover (did retrieval bring back enough?);
//! * **faithfulness** — of the *generated* answer's claims, the fraction
//!   grounded in the retrieved contexts (is the answer supported, not
//!   hallucinated?).
//!
//! ## Deterministic, no network / no LLM
//! RAGAS proper uses an LLM judge for the claim↔context entailment decision.
//! That is a **residual follow-up** (a live-arm, v2): wiring a real
//! model here would make the harness non-deterministic and network-bound, which
//! this v1 explicitly avoids. Instead the entailment decision is a [`Judge`]
//! trait seam. The shipped [`LexicalJudge`] is an embedding-free lexical proxy
//! (content-token containment above a threshold) — fully deterministic and
//! offline, so the harness runs in unit tests with no external dependency. A
//! real-LLM judge (or a cross-encoder NLI judge) is a drop-in `impl Judge`; see
//! the module residual note.

use std::collections::HashSet;

use serde::Serialize;

/// One offline QA evaluation item: a question, the contexts retrieval returned,
/// the answer the agent generated, and the reference ("ground-truth") answer.
#[derive(Debug, Clone)]
pub struct QaItem {
    /// The user question (informational — not scored directly).
    pub question: String,
    /// The retrieved contexts (chunks / sections) handed to grounding.
    pub contexts: Vec<String>,
    /// The answer the agent produced from the contexts.
    pub answer: String,
    /// The reference answer used to judge recall / context relevance.
    pub ground_truth: String,
}

/// The claim↔context entailment decision — the one judgement RAGAS delegates to
/// an LLM. Kept behind a trait so the deterministic [`LexicalJudge`] serves the
/// offline harness while a live-LLM / NLI judge can be plugged in later without
/// touching the metric arithmetic.
pub trait Judge: Send + Sync {
    /// Does `context` support (entail) `claim`?
    fn supports(&self, claim: &str, context: &str) -> bool;
}

/// Embedding-free lexical judge: `context` supports `claim` when the fraction of
/// `claim`'s content tokens present in `context` meets `threshold`. Deterministic
/// and offline — the default judge for the v1 harness.
#[derive(Debug, Clone, Copy)]
pub struct LexicalJudge {
    /// Minimum content-token containment for a claim to count as supported.
    pub threshold: f64,
}

impl Default for LexicalJudge {
    fn default() -> Self {
        // 0.6 of a claim's content tokens must appear in the context. Chosen so
        // paraphrase/support passes while topical-but-off distractors fail.
        Self { threshold: 0.6 }
    }
}

impl Judge for LexicalJudge {
    fn supports(&self, claim: &str, context: &str) -> bool {
        let claim_tokens = content_tokens(claim);
        if claim_tokens.is_empty() {
            return false;
        }
        let context_tokens: HashSet<String> = content_tokens(context).into_iter().collect();
        let hit = claim_tokens
            .iter()
            .filter(|t| context_tokens.contains(*t))
            .count();
        #[allow(clippy::cast_precision_loss)]
        let containment = hit as f64 / claim_tokens.len() as f64;
        containment >= self.threshold
    }
}

/// Per-item RAGAS scores.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ItemScores {
    /// Relevant contexts / total contexts.
    pub context_precision: f64,
    /// Covered reference claims / total reference claims.
    pub context_recall: f64,
    /// Grounded answer claims / total answer claims.
    pub faithfulness: f64,
}

/// Corpus-level RAGAS report — the mean of each metric over the QA set.
#[derive(Debug, Clone, Serialize)]
pub struct EvalReport {
    /// Number of QA items scored.
    pub n: usize,
    /// Mean context precision.
    pub context_precision: f64,
    /// Mean context recall.
    pub context_recall: f64,
    /// Mean faithfulness.
    pub faithfulness: f64,
    /// The per-item scores (in corpus order).
    pub per_item: Vec<ItemScores>,
}

/// Score a single QA item with `judge`.
///
/// A context is *relevant* when it supports at least one reference-answer claim;
/// a reference claim is *covered* when at least one context supports it; an
/// answer claim is *grounded* when at least one context supports it. Empty
/// denominators (no contexts / no claims) score `0.0` — an item that retrieved
/// nothing, or an answer that asserts nothing, earns no credit.
#[must_use]
pub fn score_item(item: &QaItem, judge: &dyn Judge) -> ItemScores {
    let truth_claims = claims(&item.ground_truth);
    let answer_claims = claims(&item.answer);

    let context_precision = fraction(item.contexts.len(), |i| {
        let ctx = &item.contexts[i];
        truth_claims.iter().any(|c| judge.supports(c, ctx))
    });
    let context_recall = fraction(truth_claims.len(), |i| {
        let claim = &truth_claims[i];
        item.contexts.iter().any(|ctx| judge.supports(claim, ctx))
    });
    let faithfulness = fraction(answer_claims.len(), |i| {
        let claim = &answer_claims[i];
        item.contexts.iter().any(|ctx| judge.supports(claim, ctx))
    });

    ItemScores {
        context_precision,
        context_recall,
        faithfulness,
    }
}

/// Evaluate a whole corpus, returning the per-item scores and their means.
#[must_use]
pub fn evaluate(corpus: &[QaItem], judge: &dyn Judge) -> EvalReport {
    let per_item: Vec<ItemScores> = corpus.iter().map(|it| score_item(it, judge)).collect();
    let n = per_item.len();
    #[allow(clippy::cast_precision_loss)]
    let mean = |sel: fn(&ItemScores) -> f64| -> f64 {
        if n == 0 {
            return 0.0;
        }
        let sum: f64 = per_item.iter().map(sel).sum();
        sum / n as f64
    };
    EvalReport {
        n,
        context_precision: mean(|s| s.context_precision),
        context_recall: mean(|s| s.context_recall),
        faithfulness: mean(|s| s.faithfulness),
        per_item,
    }
}

/// `count(pred) / len`, with `0.0` for an empty denominator.
fn fraction(len: usize, mut pred: impl FnMut(usize) -> bool) -> f64 {
    if len == 0 {
        return 0.0;
    }
    let hits = (0..len).filter(|i| pred(*i)).count();
    #[allow(clippy::cast_precision_loss)]
    {
        hits as f64 / len as f64
    }
}

/// Split a passage into claims (sentence-grained). Splits on `.`, `;`, `?`, `!`
/// and newlines; empties are dropped. Deterministic — no NLP model.
fn claims(text: &str) -> Vec<String> {
    text.split(['.', ';', '?', '!', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Lowercased content tokens: alphanumeric runs, length ≥ 2, minus a small
/// closed-class stopword set. Deterministic and allocation-light.
fn content_tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 2)
        .map(str::to_lowercase)
        .filter(|w| !is_stopword(w))
        .collect()
}

fn is_stopword(w: &str) -> bool {
    matches!(
        w,
        "the"
            | "and"
            | "for"
            | "are"
            | "was"
            | "were"
            | "with"
            | "that"
            | "this"
            | "from"
            | "has"
            | "have"
            | "not"
            | "its"
            | "into"
            | "than"
            | "then"
            | "over"
            | "per"
            | "via"
            | "any"
            | "all"
    )
}

/// A fixture QA corpus (>=8 items) spanning the cascade's regimes: high-quality
/// grounded answers, answers with distractor contexts (lower precision), and one
/// unfaithful answer (a claim absent from the contexts) so faithfulness < 1.
/// Deterministic — the harness scores this with no network access.
#[must_use]
pub fn fixture_corpus() -> Vec<QaItem> {
    vec![
        QaItem {
            question: "What does the KB cascade escalate on?".into(),
            contexts: vec![
                "The agent-side cascade escalates past the chunk only on explicit triggers.".into(),
                "A full-source fetch happens on explicit triggers, never implicit widening.".into(),
            ],
            answer: "The cascade escalates only on explicit triggers.".into(),
            ground_truth: "The cascade escalates past the chunk only on explicit triggers.".into(),
        },
        QaItem {
            question: "Where does grounding cite-or-abstain run?".into(),
            contexts: vec![
                "Grounding cite-or-abstain and NLI faithfulness stay in Argana.".into(),
                "The cascade delivers sanitize and cascade only; Argana consumes the admission.".into(),
                // distractor: topical but does not support the reference.
                "The size-guard caps evidence at a fraction of the context window.".into(),
            ],
            answer: "Grounding cite-or-abstain stays in Argana.".into(),
            ground_truth: "Grounding cite-or-abstain stays in Argana.".into(),
        },
        QaItem {
            question: "How is the session cache keyed?".into(),
            contexts: vec![
                "The session cache is content addressed keyed on source id and content hash.".into(),
                "A changed content hash misses the cache and refetches.".into(),
            ],
            answer: "The session cache is keyed on source id and content hash.".into(),
            ground_truth: "The session cache is keyed on source id and content hash.".into(),
        },
        QaItem {
            question: "What tokenizer does the size-guard use?".into(),
            contexts: vec![
                "The size-guard counts tokens with a tiktoken o200k_base BPE tokenizer.".into(),
                // distractor.
                "Trust class dispatch admits evidence with no cross promotion.".into(),
            ],
            answer: "The size-guard counts tokens with a tiktoken o200k_base tokenizer.".into(),
            ground_truth: "The size-guard counts tokens with the tiktoken o200k_base tokenizer.".into(),
        },
        QaItem {
            question: "What happens to a skill trust class in the evidence path?".into(),
            contexts: vec![
                "A skill trust class is refused in the evidence path with no cross promotion.".into(),
                "Trust dispatch runs before any fetch.".into(),
            ],
            answer: "A skill trust class is refused with no cross promotion.".into(),
            ground_truth: "A skill trust class is refused with no cross promotion.".into(),
        },
        QaItem {
            question: "What does the untrusted envelope do?".into(),
            contexts: vec![
                "The untrusted envelope nonce fences and datamarks the injectable evidence.".into(),
                "The behaviour gate is carried out of band, never inside the injectable payload.".into(),
            ],
            answer: "The untrusted envelope nonce fences and datamarks the injectable evidence.".into(),
            ground_truth: "The untrusted envelope nonce fences and datamarks the injectable evidence.".into(),
        },
        QaItem {
            question: "How does the guard counter lost in the middle?".into(),
            contexts: vec![
                "The size-guard reranks the answer bearing span to the edge of the window.".into(),
                // distractor.
                "The cascade owns policy while Scrutator ships signals.".into(),
                // distractor.
                "Provenance is carried out of band as struct fields never the body.".into(),
            ],
            answer: "The guard reranks the answer bearing span to the edge.".into(),
            ground_truth: "The size-guard reranks the answer bearing span to the edge of the window.".into(),
        },
        QaItem {
            question: "What does a fetch failure do?".into(),
            contexts: vec![
                "A fetch failure with no verified cache entry fails closed.".into(),
                "The cascade never falls back to a different source.".into(),
            ],
            // Unfaithful answer: the second sentence is NOT in any context.
            answer: "A fetch failure fails closed. The cascade then retries three times against a backup mirror.".into(),
            ground_truth: "A fetch failure with no verified cache entry fails closed.".into(),
        },
        QaItem {
            question: "Who owns retrieval policy?".into(),
            contexts: vec![
                "Scrutator ships signals while the agent owns policy.".into(),
                "There is no server side expansion of retrieved context.".into(),
            ],
            answer: "The agent owns retrieval policy; Scrutator only ships signals.".into(),
            ground_truth: "The agent owns policy while Scrutator ships signals.".into(),
        },
    ]
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    #[test]
    fn fixture_corpus_has_at_least_eight_items() {
        assert!(fixture_corpus().len() >= 8, "need >=8 fixture QA items");
    }

    #[test]
    fn lexical_judge_supports_paraphrase_but_rejects_distractor() {
        let j = LexicalJudge::default();
        assert!(j.supports(
            "the session cache is keyed on source id and content hash",
            "The session cache is content addressed keyed on source id and content hash.",
        ));
        assert!(!j.supports(
            "the session cache is keyed on source id and content hash",
            "The size-guard caps evidence at a fraction of the context window.",
        ));
    }

    #[test]
    fn harness_scores_fixture_corpus_in_expected_ranges() {
        let judge = LexicalJudge::default();
        let report = evaluate(&fixture_corpus(), &judge);
        // Measured on this fixture set (deterministic LexicalJudge, threshold
        // 0.6): precision≈0.463, recall=1.000, faithfulness≈0.944, n=9.
        assert_eq!(report.n, 9);
        // Every metric is a well-formed fraction.
        for s in &report.per_item {
            for v in [s.context_precision, s.context_recall, s.faithfulness] {
                assert!((0.0..=1.0).contains(&v), "metric out of [0,1]: {v}");
            }
        }
        // Answers are drawn from the contexts → recall is high.
        assert!(
            report.context_recall > 0.8,
            "context_recall too low: {}",
            report.context_recall
        );
        // Distractor contexts drag precision below perfect.
        assert!(
            report.context_precision < 1.0,
            "distractors should lower precision: {}",
            report.context_precision
        );
        assert!(
            report.context_precision < report.context_recall,
            "distractors → precision < recall"
        );
        // One unfaithful answer (backup-mirror claim) → faithfulness < 1.
        assert!(
            report.faithfulness < 1.0,
            "unfaithful fixture should pull faithfulness below 1: {}",
            report.faithfulness
        );
        assert!(report.faithfulness > 0.5, "most answers are grounded");
    }

    #[test]
    fn unfaithful_item_is_detected() {
        // The fetch-failure fixture has an ungrounded "backup mirror" claim.
        let corpus = fixture_corpus();
        let item = corpus
            .iter()
            .find(|q| q.answer.contains("backup mirror"))
            .unwrap();
        let s = score_item(item, &LexicalJudge::default());
        assert!(
            s.faithfulness < 1.0,
            "ungrounded claim must lower faithfulness: {}",
            s.faithfulness
        );
        assert!(s.context_recall >= 0.99, "the reference claim IS covered");
    }

    // ---- the mock-judge seam: a scripted judge is pluggable --------------

    /// A deterministic scripted judge: supports iff the (claim, context) pair is
    /// in the allow-set. Proves the metric arithmetic is judge-agnostic and that
    /// a non-lexical judge (a stand-in for a live LLM) plugs into the same seam.
    struct MockJudge {
        allow: Vec<(&'static str, &'static str)>,
    }

    impl Judge for MockJudge {
        fn supports(&self, claim: &str, context: &str) -> bool {
            self.allow
                .iter()
                .any(|(c, ctx)| claim.contains(c) && context.contains(ctx))
        }
    }

    #[test]
    fn mock_judge_is_pluggable_and_gives_exact_fractions() {
        let item = QaItem {
            question: "q".into(),
            contexts: vec!["alpha context".into(), "unrelated distractor".into()],
            answer: "claim one is here. claim two is here".into(),
            ground_truth: "claim one is here".into(),
        };
        // Judge supports only "claim one" against the "alpha" context.
        let judge = MockJudge {
            allow: vec![("claim one", "alpha")],
        };
        let s = score_item(&item, &judge);
        // 1 of 2 contexts relevant.
        assert_eq!(s.context_precision, 0.5);
        // The single ground-truth claim is covered.
        assert_eq!(s.context_recall, 1.0);
        // 1 of 2 answer claims grounded ("claim two" is not in the allow-set).
        assert_eq!(s.faithfulness, 0.5);
    }

    #[test]
    fn empty_contexts_and_empty_answer_score_zero() {
        let item = QaItem {
            question: "q".into(),
            contexts: vec![],
            answer: String::new(),
            ground_truth: "some reference claim".into(),
        };
        let s = score_item(&item, &LexicalJudge::default());
        assert_eq!(s.context_precision, 0.0);
        assert_eq!(s.context_recall, 0.0);
        assert_eq!(s.faithfulness, 0.0);
    }
}
