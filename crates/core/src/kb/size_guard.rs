//! Size-guard — cap admitted evidence at a **fraction of the model's context
//! window**, and counter lost-in-the-middle by reranking the answer-bearing
//! span to the edge.
//!
//! The cap is the *consumer's* policy (the agent knows its active model's window
//! via the Model Connector), NOT a KB constant. When a source exceeds the cap,
//! the guard keeps a parent-section-sized window around the hit offsets rather
//! than the whole document, then rotates that window so the answer-bearing span
//! leads — >30% of mid-context signal is otherwise lost. The token estimate here
//! is a whitespace-word proxy `[unverified]`, deliberately coarse and
//! deterministic; empirical cap tuning is a deferred v2 concern.

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
    /// The admitted text — at most `cap_tokens` word-tokens.
    pub text: String,
    /// Word-token count of `text`.
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
        let words: Vec<&str> = body.text.split_whitespace().collect();
        if words.len() <= cap {
            return GuardedContent {
                text: body.text.clone(),
                token_count: words.len(),
                truncated: false,
                reranked: false,
            };
        }

        // Windowed parent-section around the answer word.
        let answer_idx = word_index_at_byte(&body.text, body.answer_offset);
        let half = cap / 2;
        let mut start = answer_idx.saturating_sub(half);
        let mut end = (start + cap).min(words.len());
        start = end.saturating_sub(cap);
        end = end.max(start + 1);
        let window = &words[start..end];

        // Rerank: rotate the window so the answer-bearing span leads the edge.
        let local = answer_idx
            .saturating_sub(start)
            .min(window.len().saturating_sub(1));
        let mut ordered: Vec<&str> = Vec::with_capacity(window.len());
        ordered.extend_from_slice(&window[local..]);
        ordered.extend_from_slice(&window[..local]);

        let text = ordered.join(" ");
        GuardedContent {
            token_count: ordered.len(),
            text,
            truncated: true,
            reranked: true,
        }
    }
}

/// Map a byte offset to the whitespace-word index it falls in (clamped).
///
/// The offset is server-derived and may land mid-UTF-8-codepoint; slicing
/// `text[..clamped]` there would panic. We walk the clamp down to the nearest
/// char boundary first (`str::floor_char_boundary` is still unstable on the
/// pinned toolchain, so this is the manual equivalent).
fn word_index_at_byte(text: &str, byte: u64) -> usize {
    let mut clamped = usize::try_from(byte).unwrap_or(usize::MAX).min(text.len());
    while clamped > 0 && !text.is_char_boundary(clamped) {
        clamped -= 1;
    }
    // Words fully before the offset ≈ the answer word's index.
    text[..clamped].split_whitespace().count()
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
        assert_eq!(out.token_count, 5);
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
        assert!(
            out.text.starts_with("w80"),
            "answer span was not reranked to the edge: {}",
            out.text
        );
    }

    #[test]
    fn mid_codepoint_offset_does_not_panic_and_clamps_down() {
        // Offset 1 lands inside the 2-byte Cyrillic 'с' of the first word.
        assert_eq!(word_index_at_byte("слово мир", 1), 0);
        // A boundary offset behaves normally.
        assert_eq!(word_index_at_byte("слово мир", "слово".len() as u64), 1);
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
