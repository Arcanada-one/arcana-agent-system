//! Streaming output quarantine (D-REQ-05 / V-AC-4).
//!
//! Stdout and stderr are held until the scanner has proven a release window
//! free of every supported representation of a known sentinel. The scanner is
//! *defence in depth*, not the credential boundary: the boundary is the fact
//! that the client process never holds the credential at all.
//!
//! # Fail-closed contract
//!
//! These conditions latch the scanner into a poisoned state that releases no
//! further bytes, including bytes already buffered:
//!
//! - a sentinel is detected in any supported representation;
//! - an encoded candidate run exceeds `max_encoded_window`;
//! - a decoded window exceeds `max_decoded_window`;
//! - the unreleased buffer exceeds `max_unreleased`.
//!
//! Nesting beyond `max_depth` is **not** a poisoning condition — it is the
//! declared edge of the transform budget. Input nested more deeply than the
//! budget is out of scope for this control, and the crate does not claim
//! otherwise.
//!
//! # What this scanner does not catch
//!
//! Stated plainly, because a redactor that is trusted beyond its reach is worse
//! than no redactor:
//!
//! - representations outside the closed transform set — base32, ascii85, ROT13,
//!   reversal, compression, or any encryption;
//! - a secret emitted non-contiguously across unrelated writes, where the
//!   released bytes never co-occur in one window;
//! - a secret split across two *separate scanner instances*. A supervised child
//!   MUST feed stdout and stderr into **one** shared scanner; see
//!   [`QuarantineScanner::push_stream`].

use crate::codec::{
    b64_decode_lenient, b64_encode, hex_decode_lenient, hex_encode, is_b64_byte, is_hex_byte,
    json_u_decode_lenient, json_u_escape_all, percent_decode_lenient, percent_encode_all,
    B64Alphabet,
};

/// Largest expansion any single supported transform applies, in bytes-out per
/// byte-in. JSON `\uXXXX` escaping is the worst at six.
const MAX_EXPANSION_PER_LAYER: usize = 6;

/// Bounds fixed by D-REQ-05. Changing any of these requires security review and
/// regenerated benign-corpus identity evidence.
#[derive(Clone, Copy, Debug)]
pub struct ScannerConfig {
    /// Largest encoded candidate run that will be decoded (64 KiB).
    pub max_encoded_window: usize,
    /// Largest decoded window that will be re-scanned (32 KiB).
    pub max_decoded_window: usize,
    /// Total unreleased output buffer cap (1 MiB).
    pub max_unreleased: usize,
    /// Maximum nested transform layers (2).
    pub max_depth: u8,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_encoded_window: 64 * 1024,
            max_decoded_window: 32 * 1024,
            max_unreleased: 1024 * 1024,
            max_depth: 2,
        }
    }
}

/// Why a scanner could not be constructed. Construction is fallible on purpose:
/// a scanner with no sentinel is a pass-through wearing a quarantine's name.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ScannerInit {
    #[error("no sentinels supplied; a quarantine with nothing to detect is a pass-through")]
    NoSentinels,
    #[error("an empty sentinel was supplied")]
    EmptySentinel,
    #[error("retention window ({retention} B) does not fit the unreleased buffer ({max} B)")]
    RetentionExceedsBuffer { retention: usize, max: usize },
}

/// Why the scanner stopped. Every variant is terminal and releases nothing.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ScanError {
    #[error("sentinel detected in output; release blocked")]
    SentinelDetected,
    #[error("encoded candidate window exceeded the configured limit")]
    EncodedWindowExceeded,
    #[error("decoded window exceeded the configured limit")]
    DecodedWindowExceeded,
    #[error("unreleased output buffer exhausted")]
    BufferExhausted,
}

/// Which stream a chunk arrived on. Both feed one scanner so a secret split
/// across stdout and stderr cannot slip between two independent instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// A precomputed set of byte patterns that all denote the same sentinel.
struct SentinelForms {
    raw: Vec<u8>,
    forms: Vec<Vec<u8>>,
}

impl SentinelForms {
    fn new(raw: Vec<u8>) -> Self {
        let mut forms: Vec<Vec<u8>> = Vec::new();
        let push = |forms: &mut Vec<Vec<u8>>, s: String| {
            if !s.is_empty() {
                forms.push(s.into_bytes());
            }
        };

        push(&mut forms, hex_encode(&raw, false));
        push(&mut forms, hex_encode(&raw, true));
        push(&mut forms, percent_encode_all(&raw, false));
        push(&mut forms, percent_encode_all(&raw, true));
        push(&mut forms, json_u_escape_all(&raw, false));
        push(&mut forms, json_u_escape_all(&raw, true));

        // Base64 is alignment-sensitive: a sentinel embedded mid-stream is
        // encoded against a phase this sentinel alone does not determine. Emit
        // the alignment-invariant core for each of the three phases so an
        // embedded occurrence still matches verbatim.
        for alphabet in [B64Alphabet::Standard, B64Alphabet::Url] {
            for phase in 0usize..3 {
                let mut data = vec![0u8; phase];
                data.extend_from_slice(&raw);
                let encoded = b64_encode(&data, alphabet, false);
                let lead = (phase * 8).div_ceil(6);
                let drop_tail = usize::from(!(phase + raw.len()).is_multiple_of(3));
                if encoded.len() > lead + drop_tail {
                    let core = &encoded[lead..encoded.len() - drop_tail];
                    if core.len() >= 4 {
                        forms.push(core.as_bytes().to_vec());
                    }
                }
            }
        }

        Self { raw, forms }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Strip ASCII whitespace. Defeats line-wrapped Base64 (`base64(1)` wraps at 76
/// by default) and wrapped hex, both of which otherwise split a candidate run.
fn strip_whitespace(data: &[u8]) -> Vec<u8> {
    data.iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect()
}

/// Strip whitespace and the separators that byte-dump formats interleave —
/// `xxd`/`hexdump` spaces, `openssl` colons, C-array commas, `\x`/`0x` prefixes.
/// Without this, `xxd` output walks straight through the hex branch, because
/// each separated token decodes as an independent fragment.
fn strip_separators(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == b'\\' && i + 1 < data.len() && (data[i + 1] == b'x' || data[i + 1] == b'X') {
            i += 2;
            continue;
        }
        if b == b'0'
            && i + 1 < data.len()
            && (data[i + 1] == b'x' || data[i + 1] == b'X')
            && i + 2 < data.len()
            && is_hex_byte(data[i + 2])
        {
            i += 2;
            continue;
        }
        if b.is_ascii_whitespace() || matches!(b, b':' | b',' | b';' | b'|') {
            i += 1;
            continue;
        }
        out.push(b);
        i += 1;
    }
    out
}

/// Streaming, fail-closed output quarantine.
#[must_use = "a scanner that is dropped without finish() silently truncates output"]
pub struct QuarantineScanner {
    sentinels: Vec<SentinelForms>,
    cfg: ScannerConfig,
    buf: Vec<u8>,
    retention: usize,
    poisoned: Option<ScanError>,
}

impl QuarantineScanner {
    /// Build a scanner for the given sentinels.
    ///
    /// # Errors
    /// [`ScannerInit`] when the sentinel set is empty, contains an empty
    /// sentinel, or when the required retention does not fit the buffer. None of
    /// these may degrade silently into a pass-through.
    pub fn new(sentinels: Vec<Vec<u8>>, cfg: ScannerConfig) -> Result<Self, ScannerInit> {
        if sentinels.is_empty() {
            return Err(ScannerInit::NoSentinels);
        }
        if sentinels.iter().any(Vec::is_empty) {
            return Err(ScannerInit::EmptySentinel);
        }
        let longest_raw = sentinels.iter().map(Vec::len).max().unwrap_or(0);
        let sentinels: Vec<SentinelForms> = sentinels.into_iter().map(SentinelForms::new).collect();

        // Retention must be able to hold a complete *nested* occurrence, not
        // merely a single-layer one. A depth-N encoding can expand the raw
        // sentinel by MAX_EXPANSION_PER_LAYER^N, so sizing retention from
        // single-layer forms (as an earlier revision did) let every depth-2
        // payload stream past at ordinary chunk sizes.
        let expansion = MAX_EXPANSION_PER_LAYER.saturating_pow(u32::from(cfg.max_depth).max(1));
        let retention = longest_raw.saturating_mul(expansion).saturating_add(8);
        if retention >= cfg.max_unreleased {
            return Err(ScannerInit::RetentionExceedsBuffer {
                retention,
                max: cfg.max_unreleased,
            });
        }

        Ok(Self {
            sentinels,
            cfg,
            buf: Vec::new(),
            retention,
            poisoned: None,
        })
    }

    /// Bytes held back at every chunk boundary.
    #[must_use]
    pub fn retention(&self) -> usize {
        self.retention
    }

    /// Whether the scanner has latched a terminal stop.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    fn poison(&mut self, err: ScanError) -> ScanError {
        self.buf.clear();
        self.poisoned = Some(err.clone());
        err
    }

    /// Feed a chunk from a named stream.
    ///
    /// Both streams of one child MUST use the same scanner: a secret split
    /// across stdout and stderr is only caught when both halves land in one
    /// buffer.
    ///
    /// # Errors
    /// Any [`ScanError`] is terminal: nothing is released now or later.
    pub fn push_stream(&mut self, _stream: Stream, chunk: &[u8]) -> Result<Vec<u8>, ScanError> {
        self.push(chunk)
    }

    /// Feed a chunk; returns the bytes that are proven safe to release.
    ///
    /// # Errors
    /// Any [`ScanError`] is terminal: nothing is released now or later.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, ScanError> {
        if let Some(err) = &self.poisoned {
            return Err(err.clone());
        }
        if self.buf.len() + chunk.len() > self.cfg.max_unreleased {
            return Err(self.poison(ScanError::BufferExhausted));
        }
        self.buf.extend_from_slice(chunk);

        match self.scan_all(&self.buf.clone()) {
            Err(e) => Err(self.poison(e)),
            Ok(true) => Err(self.poison(ScanError::SentinelDetected)),
            Ok(false) => {
                let release_len = self.buf.len().saturating_sub(self.retention);
                Ok(self.buf.drain(..release_len).collect())
            }
        }
    }

    /// Flush the retained tail after the stream ends.
    ///
    /// # Errors
    /// Any [`ScanError`] is terminal: nothing is released.
    pub fn finish(&mut self) -> Result<Vec<u8>, ScanError> {
        if let Some(err) = &self.poisoned {
            return Err(err.clone());
        }
        match self.scan_all(&self.buf.clone()) {
            Err(e) => Err(self.poison(e)),
            Ok(true) => Err(self.poison(ScanError::SentinelDetected)),
            Ok(false) => Ok(std::mem::take(&mut self.buf)),
        }
    }

    /// Scan the data as-is, then with whitespace stripped, then with byte-dump
    /// separators stripped. The extra passes are what make wrapped Base64 and
    /// `xxd`-shaped hex detectable at all.
    fn scan_all(&self, data: &[u8]) -> Result<bool, ScanError> {
        if self.scan(data, 0)? {
            return Ok(true);
        }
        let ws = strip_whitespace(data);
        if ws.len() != data.len() && self.scan(&ws, 0)? {
            return Ok(true);
        }
        let sep = strip_separators(data);
        if sep.len() != data.len() && sep != ws && self.scan(&sep, 0)? {
            return Ok(true);
        }
        Ok(false)
    }

    /// Check one decoded window against the configured bound.
    ///
    /// Exceeding the bound is a **terminal stop**, not a skipped check. An
    /// earlier revision short-circuited here and released the bytes, which made
    /// "write more than 32 KiB" a complete bypass.
    fn scan_decoded(&self, decoded: &[u8], depth: u8) -> Result<bool, ScanError> {
        if decoded.len() > self.cfg.max_decoded_window {
            return Err(ScanError::DecodedWindowExceeded);
        }
        self.scan(decoded, depth + 1)
    }

    /// True when `data` denotes a sentinel in any supported representation.
    fn scan(&self, data: &[u8], depth: u8) -> Result<bool, ScanError> {
        for s in &self.sentinels {
            if contains(data, &s.raw) {
                return Ok(true);
            }
            for form in &s.forms {
                if contains(data, form) {
                    return Ok(true);
                }
            }
        }
        if depth >= self.cfg.max_depth {
            // The declared edge of the transform budget, not a failure.
            return Ok(false);
        }

        // Reverse direction: decode candidate runs and re-scan. This catches
        // nesting and Base64 phase shifts that forward forms cannot.
        //
        // Each run is decoded at every quantum offset. A run whose front was
        // truncated by an earlier release starts at an arbitrary phase, so
        // decoding only from offset 0 would shift every byte and miss the
        // sentinel entirely.
        for alphabet in [B64Alphabet::Standard, B64Alphabet::Url] {
            for run in maximal_runs(data, |b| is_b64_byte(b, alphabet), 8) {
                if run.len() > self.cfg.max_encoded_window {
                    return Err(ScanError::EncodedWindowExceeded);
                }
                for offset in 0..4usize {
                    if offset >= run.len() {
                        break;
                    }
                    if let Some(decoded) = b64_decode_lenient(&run[offset..], alphabet) {
                        if self.scan_decoded(&decoded, depth)? {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        for run in maximal_runs(data, is_hex_byte, 8) {
            if run.len() > self.cfg.max_encoded_window {
                return Err(ScanError::EncodedWindowExceeded);
            }
            for offset in 0..2usize {
                if offset >= run.len() {
                    break;
                }
                if let Some(decoded) = hex_decode_lenient(&run[offset..]) {
                    if self.scan_decoded(&decoded, depth)? {
                        return Ok(true);
                    }
                }
            }
        }
        if data.contains(&b'%') {
            let decoded = percent_decode_lenient(data);
            if decoded != data && self.scan_decoded(&decoded, depth)? {
                return Ok(true);
            }
        }
        if contains(data, b"\\u") {
            let decoded = json_u_decode_lenient(data);
            if decoded != data && self.scan_decoded(&decoded, depth)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Maximal runs of bytes satisfying `pred`, at least `min_len` long.
fn maximal_runs<F: Fn(u8) -> bool>(data: &[u8], pred: F, min_len: usize) -> Vec<&[u8]> {
    let mut runs = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if pred(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                runs.push(&data[s..i]);
            }
        }
    }
    if let Some(s) = start {
        if data.len() - s >= min_len {
            runs.push(&data[s..]);
        }
    }
    runs
}
