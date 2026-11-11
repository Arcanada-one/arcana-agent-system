//! Q3 (KCLIVE-11, KC-Brain decision 2026-11-07): an integer beyond this reader's supported range
//! `[i64::MIN, u64::MAX]` must produce the typed `CONTRACT_READER_UNSUPPORTED`, never a rounding,
//! normalisation or silent accept - on EVERY route that reads the digested bytes. Boundary cases:
//! the largest supported, the smallest unsupported, and the negative side. Bodies are SYNTHETIC.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use arcana_core::contract::{
    digest_of, verify, verify_with, CanonicalBlock, ContractDocument, ReaderMode, STRICT_PROFILE,
};
use base64::Engine as _;

/// A legacy-shaped contract (no profile marker): the body carries `n` as an open value.
fn legacy_doc(n: &str) -> (String, ContractDocument) {
    let bytes = format!("{{\"goal\":\"g\",\"n\":{n}}}{{\"k\":1}}");
    let digest = digest_of(bytes.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes.as_bytes());
    (
        digest.clone(),
        ContractDocument {
            digest,
            canonical: Some(CanonicalBlock {
                bytes_b64: Some(b64),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
}

const SUPPORTED: &[&str] = &[
    "18446744073709551615",
    "9223372036854775807",
    "-9223372036854775808",
];
const UNSUPPORTED: &[&str] = &[
    "18446744073709551616",
    "-9223372036854775809",
    "-18446744073709551616",
    "1267650600228229401496703205376",
];

fn code_of(
    r: Result<arcana_core::contract::ContractBinding, arcana_core::contract::ContractRefusal>,
) -> String {
    match r {
        Ok(_) => "ACCEPT".to_owned(),
        Err(e) => e.code().to_owned(),
    }
}

#[test]
fn legacy_route_accepts_the_domain_edges_exactly() {
    for n in SUPPORTED {
        let (d, doc) = legacy_doc(n);
        let b = verify(&d, &doc).unwrap();
        assert!(b.projection().contains(&format!("\"n\": {n}")), "{n}");
    }
}

#[test]
fn legacy_route_refuses_every_integer_beyond_the_domain_with_the_typed_code_never_rounding() {
    for n in UNSUPPORTED {
        let (d, doc) = legacy_doc(n);
        assert_eq!(
            code_of(verify(&d, &doc)),
            "CONTRACT_READER_UNSUPPORTED",
            "{n}"
        );
        let (d, doc) = legacy_doc(n);
        let err = verify_with(&d, &doc, ReaderMode::Legacy).unwrap_err();
        assert!(err.to_string().contains("refuses rather than round"), "{n}");
    }
}

#[test]
fn legacy_route_leaves_a_beyond_domain_digit_run_inside_a_string_or_a_float_alone() {
    // only an INTEGER token is refused: the same digits in a string, and a float literal, are not
    for lit in ["\"18446744073709551616\"", "1.5e30", "1.0"] {
        let (d, doc) = legacy_doc(lit);
        assert_eq!(code_of(verify(&d, &doc)), "ACCEPT", "{lit}");
    }
}

#[test]
fn strict_route_refuses_the_same_beyond_domain_integers_with_the_typed_code() {
    // a legacy-shaped body is not a valid strict contract, so the strict reader may refuse it for
    // other reasons on the supported edge; the point here is that beyond the domain the code is
    // the typed capability one and a supported edge never gets it.
    for n in UNSUPPORTED {
        let (d, doc) = legacy_doc(n);
        let got = code_of(verify_with(
            &d,
            &doc,
            ReaderMode::Strict {
                profile: STRICT_PROFILE,
            },
        ));
        assert_eq!(got, "CONTRACT_READER_UNSUPPORTED", "{n}");
    }
    for n in SUPPORTED {
        let (d, doc) = legacy_doc(n);
        let got = code_of(verify_with(
            &d,
            &doc,
            ReaderMode::Strict {
                profile: STRICT_PROFILE,
            },
        ));
        assert_ne!(got, "CONTRACT_READER_UNSUPPORTED", "{n}");
    }
}
