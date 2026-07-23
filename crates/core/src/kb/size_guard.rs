//! Size-guard — cap admitted evidence at a **fraction of the model's context
//! window**, and counter lost-in-the-middle by reranking the answer-bearing
//! span to the edge.
//!
//! The cap is the *consumer's* policy (the agent knows its active model's window
//! via the Model Connector), NOT a KB constant. When a source exceeds the cap,
//! the guard keeps a parent-section-sized window around the hit offsets rather
//! than the whole document, then rotates that window so the answer-bearing span
//! leads — >30% of mid-context signal is otherwise lost. Token counting uses a
//! real model-aware BPE tokenizer (`tiktoken-rs`, `o200k_base` — the encoding
//! for the current GPT-4o/4.1/5 families), so the size-guard fraction is
//! measured in the same unit the model bills, eliminating the proxy over/under-
//! fetch of the ARAS-0049 whitespace-word estimate. The encoder is lazily
//! initialised once (`OnceLock`) from a compile-time-embedded vocab — offline
//! and deterministic. Untrusted evidence is tokenised with `encode_ordinary`,
//! so `<|endoftext|>`-style byte sequences in the body are treated as ordinary
//! text, never as special tokens. Empirical cap tuning is a deferred v2 concern.

use std::sync::OnceLock;

use tiktoken_rs::{o200k_base, CoreBPE, Rank};

/// The lazily-initialised BPE encoder shared across all guard invocations.
///
/// `o200k_base` embeds its vocabulary at build time, so this never touches the
/// network and is fully deterministic for tests.
static ENCODER: OnceLock<CoreBPE> = OnceLock::new();

#[allow(clippy::expect_used)] // embedded o200k_base vocab is compiled in; init is infallible in practice.
fn encoder() -> &'static CoreBPE {
    ENCODER.get_or_init(|| o200k_base().expect("embedded o200k_base vocabulary must initialise"))
}

/// Real model-aware token count of `text` (ordinary encoding — no special-token
/// recognition, safe for untrusted evidence bodies).
#[must_use]
pub fn count_tokens(text: &str) -> usize {
    encoder().encode_ordinary(text).len()
}

/// A piece of evidence body plus the offset of its answer-bearing span.
#[derive(Debug, Clone)]
pub struct EvidenceBody {
    /// The evidence text (a chunk, a parent section, or a whole source).
    pub text: String,
    /// Byte offset of the answer-bearing span within `text` (0 when `text` is
    /// itself the hit chunk).
    pub answer_offset: u64,
}

impl EvidenceBody {
    /// A body whose whole text is the answer (the chunk-sufficient path).
    #[must_use]
    pub fn whole(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            answer_offset: 0,
        }
    }
}

/// The result of applying the size-guard.
#[derive(Debug, Clone)]
pub struct GuardedContent {
    /// The admitted text — at most `cap_tokens` real BPE tokens.
    pub text: String,
    /// Real BPE token count of `text`.
    pub token_count: usize,
    /// Whether the source exceeded the cap and was windowed.
    pub truncated: bool,
    /// Whether the answer-bearing span was rotated to the front (rerank).
    pub reranked: bool,
}

/// The context-window fraction cap.
#[derive(Debug, Clone, Copy)]
pub struct SizeGuard {
    context_window_tokens: u64,
    max_fraction: f64,
}

impl SizeGuard {
    /// Build a guard from the active model's window and the per-source fraction
    /// (e.g. `0.25` = at most a quarter of the window per source).
    #[must_use]
    pub fn new(context_window_tokens: u64, max_fraction: f64) -> Self {
        Self {
            context_window_tokens,
            max_fraction,
        }
    }

    /// The per-source token cap = `floor(window * fraction)`.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn cap_tokens(&self) -> usize {
        (self.context_window_tokens as f64 * self.max_fraction).floor() as usize
    }

    /// Apply the guard to `body`. Under-cap bodies pass through unchanged;
    /// over-cap bodies are windowed to the parent section around the answer and
    /// rotated so the answer leads (lost-in-the-middle counter).
    #[must_use]
    pub fn apply(&self, body: &EvidenceBody) -> GuardedContent {
        let cap = self.cap_tokens().max(1);
        let enc = encoder();
        let tokens = enc.encode_ordinary(&body.text);
        if tokens.len() <= cap {
            return GuardedContent {
                text: body.text.clone(),
                token_count: tokens.len(),
                truncated: false,
                reranked: false,
            };
        }

        // Windowed parent-section around the answer token.
        let answer_idx = token_index_at_byte(enc, &body.text, body.answer_offset, &tokens);
        let half = cap / 2;
        let mut start = answer_idx.saturating_sub(half);
        let end = (start + cap).min(tokens.len());
        start = end.saturating_sub(cap);
        let window = &tokens[start..end];

        // Rerank: rotate the window so the answer-bearing span leads the edge.
        let local = answer_idx
            .saturating_sub(start)
            .min(window.len().saturating_sub(1));
        let mut ordered: Vec<Rank> = Vec::with_capacity(window.len());
        ordered.extend_from_slice(&window[local..]);
        ordered.extend_from_slice(&window[..local]);

        // `decode_bytes` cannot fail for ranks we just produced; `from_utf8_lossy`
        // keeps us panic-free and multibyte-safe when a rotation seam or window
        // edge splits a codepoint (the ARAS-0049 H2 invariant, at token grain).
        let bytes = enc.decode_bytes(&ordered).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        GuardedContent {
            token_count: ordered.len(),
            text,
            truncated: true,
            reranked: true,
        }
    }
}

/// Map a byte offset to the BPE token index it falls in (clamped).
///
/// The offset is server-derived and may land mid-UTF-8-codepoint; indexing
/// `text[..clamped]` there would panic. We walk the clamp down to the nearest
/// char boundary first (`str::floor_char_boundary` is still unstable on the
/// pinned toolchain, so this is the manual equivalent — the ARAS-0049 H2 fix),
/// then accumulate per-token byte lengths until the clamped offset is covered.
fn token_index_at_byte(enc: &CoreBPE, text: &str, byte: u64, tokens: &[Rank]) -> usize {
    let mut clamped = usize::try_from(byte).unwrap_or(usize::MAX).min(text.len());
    while clamped > 0 && !text.is_char_boundary(clamped) {
        clamped -= 1;
    }
    // The token whose byte span [acc, acc+len) contains the clamped offset.
    let mut acc = 0usize;
    for (i, tok) in tokens.iter().enumerate() {
        let len = enc.decode_bytes(&[*tok]).map_or(0, |b| b.len());
        if clamped < acc + len {
            return i;
        }
        acc += len;
    }
    tokens.len().saturating_sub(1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cap_is_floor_of_window_times_fraction() {
        let g = SizeGuard::new(1000, 0.25);
        assert_eq!(g.cap_tokens(), 250);
    }

    #[test]
    fn under_cap_body_passes_through_unchanged() {
        let g = SizeGuard::new(100, 0.5); // cap 50
        let body = EvidenceBody::whole("one two three four five");
        let out = g.apply(&body);
        assert!(!out.truncated);
        assert!(!out.reranked);
        assert_eq!(out.text, "one two three four five");
        // token_count is now the real BPE token count, not the word count.
        assert_eq!(out.token_count, count_tokens("one two three four five"));
    }

    #[test]
    fn over_cap_body_is_windowed_under_cap() {
        let g = SizeGuard::new(20, 0.5); // cap 10
        let text = (0..100)
            .map(|n| format!("w{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        // Answer near the far end so we prove windowing + rerank both fire.
        let answer_byte = text.find("w80").unwrap() as u64;
        let body = EvidenceBody {
            text,
            answer_offset: answer_byte,
        };
        let out = g.apply(&body);
        assert!(out.truncated);
        assert!(out.reranked);
        assert!(out.token_count <= g.cap_tokens(), "guard exceeded the cap");
        // Lost-in-the-middle counter: the answer token leads the admitted span.
        // (A leading-space token may prefix it, so compare after trimming.)
        assert!(
            out.text.trim_start().starts_with("w80"),
            "answer span was not reranked to the edge: {}",
            out.text
        );
    }

    #[test]
    fn mid_codepoint_offset_does_not_panic_and_clamps_down() {
        let enc = encoder();
        let text = "слово мир";
        let tokens = enc.encode_ordinary(text);
        // Offset 1 lands inside the 2-byte Cyrillic 'с' of the first word; it
        // must clamp down to the char boundary at 0 (the H2 fix) and resolve to
        // the same token as offset 0 — never panic on the mid-codepoint index.
        let at0 = token_index_at_byte(enc, text, 0, &tokens);
        let at1 = token_index_at_byte(enc, text, 1, &tokens);
        assert_eq!(at0, at1, "mid-codepoint offset must clamp to the boundary");
        // An offset inside the second word resolves to a later-or-equal token.
        let at_mir = token_index_at_byte(enc, text, "слово ".len() as u64, &tokens);
        assert!(at_mir >= at1);
    }

    #[test]
    fn punctuation_dense_body_capped_by_real_tokens_not_words() {
        // Few whitespace "words" but many real tokens: punctuation/code explodes
        // the BPE token count. Under the old whitespace-word proxy this passes
        // through (1 word <= cap 10); under real tokens it MUST be capped.
        let g = SizeGuard::new(40, 0.25); // cap = 10 tokens
        let text = "a=(1+2)*3-4/5%6;b={x:1,y:2,z:3};c=[7,8,9,10,11,12];d->e->f->g!!??";
        assert_eq!(
            text.split_whitespace().count(),
            1,
            "precondition: a single whitespace word"
        );
        let out = g.apply(&EvidenceBody::whole(text));
        assert!(
            out.truncated,
            "token-dense body must be capped by real tokens, not word count"
        );
        assert!(
            out.token_count <= g.cap_tokens(),
            "admitted tokens ({}) exceed cap ({})",
            out.token_count,
            g.cap_tokens()
        );
    }

    #[test]
    fn cjk_body_capped_by_real_tokens_when_word_count_is_one() {
        // No ASCII whitespace → whitespace-word count is 1, but tokens >> words.
        let g = SizeGuard::new(40, 0.25); // cap = 10 tokens
        let text = "私はロボットです。人間の生命は大切である。".repeat(3);
        assert_eq!(
            text.split_whitespace().count(),
            1,
            "precondition: a single whitespace word"
        );
        let out = g.apply(&EvidenceBody::whole(&text));
        assert!(out.truncated, "CJK body must be token-capped");
        assert!(
            out.token_count <= g.cap_tokens(),
            "admitted tokens ({}) exceed cap ({})",
            out.token_count,
            g.cap_tokens()
        );
        assert!(!out.text.is_empty());
    }

    #[test]
    fn windowing_over_cap_multibyte_body_mid_codepoint_does_not_panic() {
        let g = SizeGuard::new(20, 0.5); // cap 10
                                         // 100 multibyte (Cyrillic) words → over-cap, forces word_index_at_byte.
        let text = (0..100)
            .map(|n| format!("сл{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        // Offset 1 is mid the first 2-byte char — must not panic.
        let body = EvidenceBody {
            text,
            answer_offset: 1,
        };
        let out = g.apply(&body);
        assert!(out.truncated);
        assert!(out.token_count <= g.cap_tokens(), "guard exceeded the cap");
        assert!(!out.text.is_empty());
    }
}
