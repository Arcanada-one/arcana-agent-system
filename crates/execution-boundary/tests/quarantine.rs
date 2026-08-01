//! Falsification floor for the streaming output quarantine (V-AC-4).
//!
//! Every fixture uses a freshly-written **synthetic** sentinel. No real
//! credential, credential prefix, or credential-shaped real value appears in
//! this file or in any artifact it produces.
//!
//! Tests marked REGRESSION correspond to defects found by the independent
//! adversarial review and confirmed empirically before being fixed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::format_collect,
    clippy::redundant_closure_for_method_calls,
    // SHA-256's working variables are named a..h in the specification.
    clippy::many_single_char_names
)]

use arcana_execution_boundary::codec::{
    b64_encode, hex_encode, json_u_escape_all, percent_encode_all, B64Alphabet,
};
use arcana_execution_boundary::{QuarantineScanner, ScanError, ScannerConfig, ScannerInit, Stream};

/// Synthetic, non-credential sentinel. Not issued by any provider.
const SENTINEL: &str = "SYNTHETIC-SEC0030-SENTINEL-do-not-issue-0123456789";

fn scanner() -> QuarantineScanner {
    QuarantineScanner::new(vec![SENTINEL.as_bytes().to_vec()], ScannerConfig::default())
        .expect("scanner")
}

fn run_whole(data: &[u8]) -> Result<Vec<u8>, ScanError> {
    let mut s = scanner();
    let mut out = s.push(data)?;
    out.extend(s.finish()?);
    Ok(out)
}

fn run_chunked(data: &[u8], size: usize) -> Result<Vec<u8>, ScanError> {
    let mut s = scanner();
    let mut out = Vec::new();
    for chunk in data.chunks(size.max(1)) {
        out.extend(s.push(chunk)?);
    }
    out.extend(s.finish()?);
    Ok(out)
}

fn assert_blocked(payload: &[u8], label: &str) {
    assert_eq!(
        run_whole(payload).err(),
        Some(ScanError::SentinelDetected),
        "representation `{label}` was NOT blocked"
    );
}

/// Blocked (for any terminal reason) at every chunk size — the property that
/// matters is that nothing is released, not which error fires.
fn assert_blocked_at_all_chunk_sizes(payload: &[u8], label: &str) {
    for size in [1usize, 2, 3, 7, 16, 32, 64, 100, 128, 256, 1024] {
        assert!(
            run_chunked(payload, size).is_err(),
            "`{label}` leaked at chunk size {size}"
        );
    }
}

// --- representation coverage ----------------------------------------------

#[test]
fn raw_bearer_and_json_forms_are_blocked() {
    assert_blocked(format!("prefix {SENTINEL} suffix").as_bytes(), "raw");
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
        assert_blocked(
            format!("out={}", hex_encode(SENTINEL.as_bytes(), upper)).as_bytes(),
            "hex",
        );
    }
}

#[test]
fn base64_forms_are_blocked() {
    for alphabet in [B64Alphabet::Standard, B64Alphabet::Url] {
        for pad in [false, true] {
            assert_blocked(
                format!("blob:{}", b64_encode(SENTINEL.as_bytes(), alphabet, pad)).as_bytes(),
                "base64",
            );
        }
    }
}

#[test]
fn base64_embedded_at_every_phase_is_blocked() {
    for alphabet in [B64Alphabet::Standard, B64Alphabet::Url] {
        for phase in 0..3usize {
            let mut data = vec![b'A'; phase];
            data.extend_from_slice(SENTINEL.as_bytes());
            data.extend_from_slice(b"TRAILINGBYTES");
            assert_blocked(
                b64_encode(&data, alphabet, true).as_bytes(),
                &format!("base64 phase {phase}"),
            );
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

// --- REGRESSION: wrapped and separated encodings ---------------------------

/// REGRESSION: `base64(1)` wraps at 76 columns and `openssl base64` at 64. A
/// newline split the candidate run and broke the verbatim core match, so a
/// plainly-wrapped secret was released.
#[test]
fn line_wrapped_base64_is_blocked() {
    let encoded = b64_encode(SENTINEL.as_bytes(), B64Alphabet::Standard, true);
    for cols in [16usize, 40, 64, 76] {
        let wrapped: String = encoded
            .as_bytes()
            .chunks(cols)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert_blocked(wrapped.as_bytes(), &format!("base64 wrapped at {cols}"));
    }
}

/// REGRESSION: wrapped base64 of a *longer* payload with the sentinel embedded
/// at an offset — the shape a real `kubectl get secret -o yaml` produces.
#[test]
fn line_wrapped_base64_with_embedded_sentinel_is_blocked() {
    for offset in [0usize, 7, 13, 31, 50] {
        let mut plain = vec![b'x'; offset];
        plain.extend_from_slice(SENTINEL.as_bytes());
        plain.extend_from_slice(&[b'y'; 40]);
        let encoded = b64_encode(&plain, B64Alphabet::Standard, true);
        let wrapped: String = encoded
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert_blocked(wrapped.as_bytes(), &format!("wrapped b64 offset {offset}"));
    }
}

/// REGRESSION: `xxd`, `hexdump`, `openssl`, C arrays and `\xNN` escapes all
/// interleave separators, which split each byte into an independently-decoded
/// fragment. Every one of these was released.
#[test]
fn separated_hex_dumps_are_blocked() {
    let bytes = SENTINEL.as_bytes();
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let cases = [
        ("space separated (xxd)", hex.join(" ")),
        ("colon separated (openssl)", hex.join(":")),
        ("comma separated (C array)", hex.join(", ")),
        (
            r"\xNN escapes",
            hex.iter().map(|h| format!("\\x{h}")).collect::<String>(),
        ),
        (
            "0xNN prefixed",
            hex.iter()
                .map(|h| format!("0x{h}"))
                .collect::<Vec<_>>()
                .join(" "),
        ),
        (
            "grouped 4 bytes",
            hex.chunks(4)
                .map(|c| c.concat())
                .collect::<Vec<_>>()
                .join(" "),
        ),
    ];
    for (label, payload) in cases {
        assert_blocked(payload.as_bytes(), label);
    }
}

// --- REGRESSION: nesting and retention -------------------------------------

#[test]
fn depth_two_nesting_is_blocked() {
    let inner = hex_encode(SENTINEL.as_bytes(), false);
    assert_blocked(
        b64_encode(inner.as_bytes(), B64Alphabet::Standard, true).as_bytes(),
        "base64(hex)",
    );
}

/// REGRESSION: retention was sized from single-layer forms only, so any
/// depth-two payload longer than the retention tail streamed straight through
/// at ordinary chunk sizes. `hex(\u)` is 12x the raw sentinel; retention was 6x.
#[test]
fn nested_forms_are_blocked_at_every_chunk_size() {
    let json_u = json_u_escape_all(SENTINEL.as_bytes(), false);
    assert_blocked_at_all_chunk_sizes(hex_encode(json_u.as_bytes(), false).as_bytes(), "hex(\\u)");
    assert_blocked_at_all_chunk_sizes(
        b64_encode(json_u.as_bytes(), B64Alphabet::Standard, true).as_bytes(),
        "b64(\\u)",
    );
    let hex_form = hex_encode(SENTINEL.as_bytes(), false);
    assert_blocked_at_all_chunk_sizes(
        b64_encode(hex_form.as_bytes(), B64Alphabet::Standard, true).as_bytes(),
        "b64(hex)",
    );
}

/// REGRESSION: exceeding `max_decoded_window` short-circuited the recursive
/// scan and RELEASED the bytes, making "write more than 32 KiB" a complete
/// bypass. It must be a terminal stop, exactly like the encoded-window bound.
#[test]
fn oversized_decoded_window_fails_closed_and_releases_nothing() {
    let mut payload = percent_encode_all(SENTINEL.as_bytes(), false).into_bytes();
    payload.extend(std::iter::repeat_n(b'f', 40_000));

    let mut s = scanner();
    let released = s.push(&payload);
    assert!(
        released.is_err(),
        "an oversized decoded window must never release bytes"
    );
    assert!(s.is_poisoned(), "the scanner must latch");

    // The same shape wrapped in base64: encoded run under 64 KiB, decoded over
    // 32 KiB. Previously released ~53 KB containing a recoverable sentinel.
    let mut inner = hex_encode(SENTINEL.as_bytes(), false).into_bytes();
    inner.extend(std::iter::repeat_n(b'z', 40_000));
    let outer = b64_encode(&inner, B64Alphabet::Standard, true);
    let mut s2 = scanner();
    assert!(
        s2.push(outer.as_bytes()).is_err(),
        "base64-wrapped oversized decode must fail closed"
    );
}

/// The release path must be exercised *with a sentinel present* — a payload
/// well beyond the retention tail, split at many positions.
#[test]
fn sentinel_beyond_retention_is_blocked_at_every_split() {
    let mut payload = vec![b'a'; 4000];
    payload.extend_from_slice(SENTINEL.as_bytes());
    payload.extend(std::iter::repeat_n(b'b', 4000));
    assert!(payload.len() > scanner().retention() * 2);

    for at in (0..payload.len()).step_by(97) {
        let mut s = scanner();
        let first = s.push(&payload[..at]);
        let result = first.and_then(|mut out| {
            let rest = s.push(&payload[at..])?;
            out.extend(rest);
            out.extend(s.finish()?);
            Ok(out)
        });
        assert!(result.is_err(), "split at {at} leaked the sentinel");
    }
}

#[test]
fn every_split_position_is_blocked() {
    let payload = format!("leading benign text {SENTINEL} trailing benign text").into_bytes();
    for at in 0..=payload.len() {
        let mut s = scanner();
        let r = s
            .push(&payload[..at])
            .and_then(|_| s.push(&payload[at..]))
            .and_then(|_| s.finish());
        assert!(r.is_err(), "split at {at} leaked the sentinel");
    }
}

// --- REGRESSION: construction and stream separation ------------------------

/// REGRESSION: an empty sentinel set silently produced a zero-retention
/// pass-through that reported success while quarantining nothing.
#[test]
fn empty_sentinel_set_is_a_construction_error() {
    assert_eq!(
        QuarantineScanner::new(vec![], ScannerConfig::default()).err(),
        Some(ScannerInit::NoSentinels)
    );
    assert_eq!(
        QuarantineScanner::new(vec![vec![]], ScannerConfig::default()).err(),
        Some(ScannerInit::EmptySentinel)
    );
}

/// REGRESSION: a secret split across stdout and stderr slipped between two
/// independent scanner instances. One shared scanner must catch it.
#[test]
fn split_across_stdout_and_stderr_is_blocked() {
    let bytes = SENTINEL.as_bytes();
    let (a, b) = bytes.split_at(25);
    let mut s = scanner();
    let first = s.push_stream(Stream::Stdout, a);
    let result = first.and_then(|_| s.push_stream(Stream::Stderr, b));
    let result = result.and_then(|_| s.finish());
    assert!(
        result.is_err(),
        "a cross-stream split must be caught by the shared scanner"
    );
}

#[test]
fn nested_form_split_across_streams_is_blocked_independent_of_schedule() {
    let inner = hex_encode(SENTINEL.as_bytes(), false);
    let nested = b64_encode(inner.as_bytes(), B64Alphabet::Standard, false);
    let (prefix, suffix) = nested.as_bytes().split_at(nested.len() / 2);
    let mut s = scanner();
    assert_eq!(
        s.check_distributed(prefix, suffix).err(),
        Some(ScanError::SentinelDetected)
    );
}

#[test]
fn poisoned_scanner_latches() {
    let mut s = scanner();
    assert!(s.push(SENTINEL.as_bytes()).is_err());
    assert!(s.is_poisoned());
    assert!(s.push(b"harmless").is_err());
    assert!(s.finish().is_err());
}

#[test]
fn buffer_exhaustion_fails_closed() {
    let cfg = ScannerConfig {
        max_unreleased: 8192,
        ..ScannerConfig::default()
    };
    let mut s = QuarantineScanner::new(vec![SENTINEL.as_bytes().to_vec()], cfg).expect("scanner");
    assert_eq!(
        s.push(&vec![b'x'; 16_384]).err(),
        Some(ScanError::BufferExhausted)
    );
    assert!(s.is_poisoned());
}

/// A retention window that cannot fit the buffer is a construction error, not a
/// silently-degraded scanner.
#[test]
fn retention_larger_than_buffer_is_rejected() {
    let cfg = ScannerConfig {
        max_unreleased: 64,
        ..ScannerConfig::default()
    };
    assert!(matches!(
        QuarantineScanner::new(vec![SENTINEL.as_bytes().to_vec()], cfg).err(),
        Some(ScannerInit::RetentionExceedsBuffer { .. })
    ));
}

// --- benign corpus ---------------------------------------------------------

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

// --- SHA-256, so the corpus identity is a real digest ---------------------

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }
    h.iter().map(|w| format!("{w:08x}")).collect()
}

#[test]
fn sha256_matches_known_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// REGRESSION: the corpus identity was a byte-sum, which is permutation- and
/// swap-invariant. It is now a real digest.
#[test]
fn benign_corpus_identity_is_pinned() {
    assert_eq!(
        sha256_hex(&corpus_bytes()),
        "c1b5189300e7485adc755d1dad3ea8a72d240b56dfb76dbf936cd9868757289b",
        "benign corpus changed; regenerate corpus identity evidence under security review"
    );
}

#[test]
fn benign_corpus_is_released_byte_identically() {
    let bytes = corpus_bytes();
    assert_eq!(
        run_whole(&bytes).expect("benign corpus must not block"),
        bytes
    );
    for size in [1usize, 2, 3, 7, 16, 64, 256, 1024] {
        assert_eq!(
            run_chunked(&bytes, size)
                .unwrap_or_else(|e| panic!("benign corpus blocked at chunk size {size}: {e}")),
            bytes,
            "chunk schedule {size} was not byte-identical"
        );
    }
    for line in BENIGN_CORPUS {
        assert_eq!(
            run_whole(line.as_bytes()).expect("benign line must not block"),
            line.as_bytes()
        );
    }
}
