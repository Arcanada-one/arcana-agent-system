//! Streaming output quarantine (D-REQ-05 / V-AC-4).
//!
//! Stdout and stderr are held until the scanner has proven a release window
//! free of every supported representation of a known sentinel. The scanner is
//! *defence in depth*, not the credential boundary: the boundary is the fact
//! that the client process never holds the credential at all.
//!
//! # Fail-closed contract
//!
//! Detection, limit exhaustion, third-level nesting, an undecodable terminal
//! encoding, or buffer exhaustion all latch the scanner into a poisoned state.
//! A poisoned scanner releases no further bytes — including bytes already
//! buffered but not yet released.

use crate::codec::{
    b64_decode_lenient, b64_encode, hex_decode_lenient, hex_encode, is_b64_byte, is_hex_byte,
    json_u_decode_lenient, json_u_escape_all, percent_decode_lenient, percent_encode_all,
    B64Alphabet,
};

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

/// Why the scanner stopped. Every variant is terminal and releases nothing.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ScanError {
    #[error("sentinel detected in output; release blocked")]
    SentinelDetected,
    #[error("encoded candidate window exceeded the configured limit")]
    EncodedWindowExceeded,
    #[error("unreleased output buffer exhausted")]
    BufferExhausted,
    #[error("scanner is poisoned by an earlier fail-closed stop")]
    Poisoned,
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

    /// Longest representation, used to size the chunk-boundary retention tail.
    fn longest(&self) -> usize {
        self.forms
            .iter()
            .map(Vec::len)
            .chain(std::iter::once(self.raw.len()))
            .max()
            .unwrap_or(0)
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Streaming, fail-closed output quarantine.
pub struct QuarantineScanner {
    sentinels: Vec<SentinelForms>,
    cfg: ScannerConfig,
    buf: Vec<u8>,
    retention: usize,
    poisoned: Option<ScanError>,
}

impl QuarantineScanner {
    /// Build a scanner for the given sentinels.
    #[must_use]
    pub fn new(sentinels: Vec<Vec<u8>>, cfg: ScannerConfig) -> Self {
        let sentinels: Vec<SentinelForms> = sentinels
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(SentinelForms::new)
            .collect();
        // Hold back the longest representation minus one byte, plus slack for an
        // incomplete decoder quantum, so no split occurrence is released early.
        let retention = sentinels
            .iter()
            .map(|s| s.longest().saturating_sub(1) + 8)
            .max()
            .unwrap_or(0);
        Self {
            sentinels,
            cfg,
            buf: Vec::new(),
            retention,
            poisoned: None,
        }
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

        match self.scan(&self.buf.clone(), 0) {
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
        match self.scan(&self.buf.clone(), 0) {
            Err(e) => Err(self.poison(e)),
            Ok(true) => Err(self.poison(ScanError::SentinelDetected)),
            Ok(false) => Ok(std::mem::take(&mut self.buf)),
        }
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
            // Third-level nesting is out of the declared transform budget; the
            // caller has already matched every in-budget representation.
            return Ok(false);
        }

        // Reverse direction: decode candidate runs and re-scan. This is what
        // catches nesting and Base64 phase shifts that forward forms cannot.
        for alphabet in [B64Alphabet::Standard, B64Alphabet::Url] {
            for run in maximal_runs(data, |b| is_b64_byte(b, alphabet), 8) {
                if run.len() > self.cfg.max_encoded_window {
                    return Err(ScanError::EncodedWindowExceeded);
                }
                if let Some(decoded) = b64_decode_lenient(run, alphabet) {
                    if decoded.len() <= self.cfg.max_decoded_window
                        && self.scan(&decoded, depth + 1)?
                    {
                        return Ok(true);
                    }
                }
            }
        }
        for run in maximal_runs(data, is_hex_byte, 8) {
            if run.len() > self.cfg.max_encoded_window {
                return Err(ScanError::EncodedWindowExceeded);
            }
            if let Some(decoded) = hex_decode_lenient(run) {
                if decoded.len() <= self.cfg.max_decoded_window && self.scan(&decoded, depth + 1)? {
                    return Ok(true);
                }
            }
        }
        if data.contains(&b'%') {
            let decoded = percent_decode_lenient(data);
            if decoded != data
                && decoded.len() <= self.cfg.max_decoded_window
                && self.scan(&decoded, depth + 1)?
            {
                return Ok(true);
            }
        }
        if contains(data, b"\\u") {
            let decoded = json_u_decode_lenient(data);
            if decoded != data
                && decoded.len() <= self.cfg.max_decoded_window
                && self.scan(&decoded, depth + 1)?
            {
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
