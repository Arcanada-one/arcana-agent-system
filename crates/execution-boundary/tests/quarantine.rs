//! Falsification floor for the streaming output quarantine (V-AC-4).
//!
//! Every fixture uses a freshly-written **synthetic** sentinel. No real
//! credential, credential prefix, or credential-shaped real value appears in
//! this file or in any artifact it produces.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arcana_execution_boundary::codec::{
    b64_encode, hex_encode, json_u_escape_all, percent_encode_all, B64Alphabet,
};
use arcana_execution_boundary::{QuarantineScanner, ScanError, ScannerConfig};

/// Synthetic, non-credential sentinel. Not issued by any provider.
const SENTINEL: &str = "SYNTHETIC-SEC0030-SENTINEL-do-not-issue-0123456789";

fn scanner() -> QuarantineScanner {
    QuarantineScanner::new(vec![SENTINEL.as_bytes().to_vec()], ScannerConfig::default())
}

/// Feed `data` as a single chunk plus a finish; collect the released bytes.
fn run_whole(data: &[u8]) -> Result<Vec<u8>, ScanError> {
    let mut s = scanner();
    let mut out = s.push(data)?;
    out.extend(s.finish()?);
    Ok(out)
}

/// Feed `data` split at `at`; collect released bytes.
fn run_split(data: &[u8], at: usize) -> Result<Vec<u8>, ScanError> {
    let mut s = scanner();
    let mut out = s.push(&data[..at])?;
    out.extend(s.push(&data[at..])?);
    out.extend(s.finish()?);
    Ok(out)
}

fn assert_blocked(payload: &[u8], label: &str) {
    let r = run_whole(payload);
    assert_eq!(
        r.err(),
        Some(ScanError::SentinelDetected),
        "representation `{label}` was NOT blocked"
    );
}

#[test]
fn raw_form_is_blocked() {
    assert_blocked(format!("prefix {SENTINEL} suffix").as_bytes(), "raw");
}

#[test]
fn bearer_and_json_forms_are_blocked() {
    assert_blocked(
        format!("Authorization: Bearer {SENTINEL}\r\n").as_bytes(),
        "bearer header",
    );
    assert_blocked(
        format!(r#"{{"api_key":"{SENTINEL}"}}"#).as_bytes(),
        "json string",
    );
}

#[test]
fn hex_forms_are_blocked() {
    for upper in [false, true] {
        let enc = hex_encode(SENTINEL.as_bytes(), upper);
        assert_blocked(format!("out={enc}").as_bytes(), "hex");
    }
}

#[test]
fn base64_forms_are_blocked() {
    for alphabet in [B64Alphabet::Standard, B64Alphabet::Url] {
        for pad in [false, true] {
            let enc = b64_encode(SENTINEL.as_bytes(), alphabet, pad);
            assert_blocked(format!("blob:{enc}").as_bytes(), "base64");
        }
    }
}

/// A sentinel embedded mid-stream is encoded at an arbitrary Base64 phase.
#[test]
fn base64_embedded_at_every_phase_is_blocked() {
    for alphabet in [B64Alphabet::Standard, B64Alphabet::Url] {
        for phase in 0..3usize {
            let mut data = vec![b'A'; phase];
            data.extend_from_slice(SENTINEL.as_bytes());
            data.extend_from_slice(b"TRAILINGBYTES");
            let enc = b64_encode(&data, alphabet, true);
            assert_blocked(enc.as_bytes(), &format!("base64 phase {phase}"));
        }
    }
}

#[test]
fn percent_and_json_escape_forms_are_blocked() {
    for upper in [false, true] {
        assert_blocked(
            percent_encode_all(SENTINEL.as_bytes(), upper).as_bytes(),
            "percent",
        );
        assert_blocked(
            json_u_escape_all(SENTINEL.as_bytes(), upper).as_bytes(),
            r"json \u",
        );
    }
}

/// Depth-two nesting: Base64 of a hex encoding.
#[test]
fn depth_two_nesting_is_blocked() {
    let inner = hex_encode(SENTINEL.as_bytes(), false);
    let outer = b64_encode(inner.as_bytes(), B64Alphabet::Standard, true);
    assert_blocked(outer.as_bytes(), "base64(hex)");
}

/// The chunk-boundary guarantee: no split position may leak the sentinel.
#[test]
fn every_split_position_is_blocked() {
    let payload = format!("leading benign text {SENTINEL} trailing benign text").into_bytes();
    for at in 0..=payload.len() {
        let r = run_split(&payload, at);
        assert_eq!(
            r.err(),
            Some(ScanError::SentinelDetected),
            "split at {at} leaked the sentinel"
        );
    }
}

/// Encoded *and* chunk-split simultaneously.
#[test]
fn encoded_plus_split_is_blocked() {
    let payload = b64_encode(SENTINEL.as_bytes(), B64Alphabet::Standard, true).into_bytes();
    for at in 0..=payload.len() {
        assert_eq!(
            run_split(&payload, at).err(),
            Some(ScanError::SentinelDetected),
            "encoded split at {at} leaked the sentinel"
        );
    }
}

/// A poisoned scanner stays poisoned and releases nothing further.
#[test]
fn poisoned_scanner_latches() {
    let mut s = scanner();
    assert!(s.push(SENTINEL.as_bytes()).is_err());
    assert!(s.is_poisoned());
    assert_eq!(s.push(b"harmless").err(), Some(ScanError::SentinelDetected));
    assert_eq!(s.finish().err(), Some(ScanError::SentinelDetected));
}

/// Buffer exhaustion is a fail-closed stop, not a truncation.
#[test]
fn buffer_exhaustion_fails_closed() {
    let cfg = ScannerConfig {
        max_unreleased: 1024,
        ..ScannerConfig::default()
    };
    let mut s = QuarantineScanner::new(vec![SENTINEL.as_bytes().to_vec()], cfg);
    assert_eq!(
        s.push(&vec![b'x'; 4096]).err(),
        Some(ScanError::BufferExhausted)
    );
    assert!(s.is_poisoned());
}

// ---------------------------------------------------------------------------
// Benign corpus: zero blocks, zero replacements, byte-identical release.
// ---------------------------------------------------------------------------

/// Representative benign agent output, including shapes that superficially
/// resemble the transform set (hex digests, Base64 blobs, percent-encoded URLs,
/// JSON escapes) but contain no sentinel.
const BENIGN_CORPUS: &[&str] = &[
    "Compiling arcana-core v0.1.0 (/src/crates/core)\n",
    "    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.21s\n",
    "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
    "SHA256: E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\n",
    "blob: aGVsbG8gd29ybGQgdGhpcyBpcyBiZW5pZ24gYmFzZTY0IG91dHB1dA==\n",
    "url: https://example.com/a%2Fb%20c?q=%7Bjson%7D\n",
    r#"{"msg":"lineAB done","ok":true}"#,
    "warning: unused variable `x`\n  --> src/lib.rs:12:9\n",
    "test result: ok. 41 passed; 0 failed; 0 ignored\n",
    "\u{1F512} audit clean: 0 advisories\n",
];

fn corpus_bytes() -> Vec<u8> {
    BENIGN_CORPUS.concat().into_bytes()
}

/// Pins the corpus identity. A corpus change must be a deliberate, reviewed act.
#[test]
fn benign_corpus_identity_is_pinned() {
    // Length + a simple checksum stand in for the recorded SHA-256 identity
    // without pulling a hashing dependency into the boundary crate.
    let bytes = corpus_bytes();
    let sum: u64 = bytes.iter().map(|&b| u64::from(b)).sum();
    assert_eq!(
        (bytes.len(), sum),
        (538, 42_665),
        "benign corpus changed; regenerate corpus identity evidence under security review"
    );
}

/// Zero blocks and byte-identical release across every required chunk schedule.
#[test]
fn benign_corpus_is_released_byte_identically() {
    let bytes = corpus_bytes();

    let whole = run_whole(&bytes).expect("benign corpus must not block");
    assert_eq!(whole, bytes, "whole-corpus release was not byte-identical");

    // Required chunk schedules: every fixed size, plus per-line, plus a
    // pathological 1-byte drip.
    for size in [1usize, 2, 3, 7, 16, 64, 256, 1024] {
        let mut s = scanner();
        let mut out = Vec::new();
        for chunk in bytes.chunks(size) {
            out.extend(
                s.push(chunk)
                    .unwrap_or_else(|e| panic!("benign corpus blocked at chunk size {size}: {e}")),
            );
        }
        out.extend(s.finish().expect("benign finish must not block"));
        assert_eq!(out, bytes, "chunk schedule {size} was not byte-identical");
    }

    for line in BENIGN_CORPUS {
        let mut s = scanner();
        let mut out = s.push(line.as_bytes()).expect("benign line must not block");
        out.extend(s.finish().expect("benign finish must not block"));
        assert_eq!(out, line.as_bytes(), "per-line release was not identical");
    }
}
