//! The strict `arcanada-kc2-tools/v1` reader: a VALIDATOR over bytes that
//! [`super::verify_with`] has already re-hashed.
//!
//! Nothing here hashes, binds or builds a preimage. It looks at the verified
//! `canonical(body) ‖ canonical(closure_manifest)` bytes and answers whether
//! they conform to the profile, refusing with a typed code when they do not.
//!
//! Two things in this file look like canonicalisation and are not:
//!
//! * [`render_canonical`] re-renders a PARSED half in the existing
//!   `json-c14n-pilot/v1` form (sorted keys, `,`/`:` separators, `ensure_ascii`,
//!   integers only — talomnia-knowledge `ontology/src/canonical.py`) purely so
//!   the result can be compared byte for byte with the half the digest was
//!   computed over. Its output is never hashed and never adopted; a mismatch is a
//!   refusal. Digest computation is untouched ([`super::digest_of`]).
//! * The twelve body members and two manifest members are named only so a
//!   closed key set can be enforced. Their value shapes are NOT validated here:
//!   that is the normative v2 schema owned by talomnia-knowledge, pinned in
//!   [`super::TALOMNIA_SCHEMA_PIN`] (empty until it exists).

use std::fmt;

use serde::de::IgnoredAny;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::{ContractDocument, ContractRefusal, ContractTools, STRICT_PROFILE, TOOL_VOCABULARY};

/// The twelve body members the KC2 v2 producer emits (ACTION-POLICY-PROPOSAL §1).
pub const V2_BODY_MEMBERS: [&str; 12] = [
    "task",
    "scope",
    "projection",
    "embedded",
    "reduction",
    "conflict_records",
    "refusals",
    "verdicts",
    "envelope_unverified",
    "verdict",
    "quarantined",
    "canonicalization",
];

/// The two closure-manifest members (v2 structure).
pub const MANIFEST_MEMBERS: [&str; 2] = ["snapshot_digest", "revisions"];

/// The top-level `kind` literal of the profile object.
pub const PROFILE_KIND: &str = "KnowledgeContract";

/// What a conforming profile body yields.
pub(super) struct StrictPolicy {
    /// `body.tools.allow`, exactly as written (validated, never normalised).
    pub allow: Vec<String>,
    /// `{body, closure_manifest}` as parsed from the verified bytes.
    pub projection: Value,
}

/// Validate verified `bytes` against the strict profile `profile`.
pub(super) fn derive(
    digest: &str,
    profile: &str,
    bytes: &[u8],
    document: &ContractDocument,
) -> Result<StrictPolicy, ContractRefusal> {
    let canon = |detail: String| ContractRefusal::CanonicalInvalid {
        digest: digest.to_owned(),
        detail,
    };
    let invalid = |detail: String| ContractRefusal::ProfileInvalid {
        digest: digest.to_owned(),
        detail,
    };
    let required = |detail: String| ContractRefusal::ProfileRequired {
        digest: digest.to_owned(),
        detail,
    };

    let text = std::str::from_utf8(bytes).map_err(|err| ContractRefusal::Unverifiable {
        digest: digest.to_owned(),
        detail: format!("the digested bytes are not UTF-8: {err}"),
    })?;
    let (body_text, manifest_text) = split_raw(text).ok_or_else(|| {
        canon(
            "the preimage is not exactly two concatenated JSON values \
             (canonical(body) then canonical(closure_manifest)); an opaque or text preimage \
             cannot qualify for the strict profile"
                .to_owned(),
        )
    })?;

    let body = parse_half("body", body_text).map_err(canon)?;
    let manifest = parse_half("closure_manifest", manifest_text).map_err(canon)?;

    // Exact canonical round-trip: a hash that matches ambiguous, re-ordered or
    // re-spaced JSON is not profile conformance.
    for (name, half, text) in [
        ("body", &body, body_text),
        ("closure_manifest", &manifest, manifest_text),
    ] {
        let rendered = render_canonical(half).map_err(|why| canon(format!("{name}: {why}")))?;
        if rendered != text {
            return Err(canon(format!(
                "{name} is not the exact json-c14n-pilot/v1 form of itself (digest matched \
                 non-canonical bytes)"
            )));
        }
    }

    let (Value::Object(body_map), Value::Object(manifest_map)) = (&body, &manifest) else {
        return Err(canon(
            "body and closure_manifest must both be JSON objects".to_owned(),
        ));
    };

    // ---- body.tools: required, closed, explicit ----
    let Some(tools) = body_map.get("tools") else {
        return Err(required(
            "body.tools is absent; the strict profile never falls back to a default tool set"
                .to_owned(),
        ));
    };
    check_exact_keys(
        "body",
        body_map,
        V2_BODY_MEMBERS
            .iter()
            .copied()
            .chain(std::iter::once("tools")),
    )
    .map_err(invalid)?;
    check_exact_keys(
        "closure_manifest",
        manifest_map,
        MANIFEST_MEMBERS.iter().copied(),
    )
    .map_err(invalid)?;
    if !manifest_map.get("revisions").is_some_and(Value::is_array) {
        return Err(invalid(
            "closure_manifest.revisions is not an array".to_owned(),
        ));
    }

    let allow = validate_tools(digest, profile, tools)?;

    let derived = check_envelope(digest, profile, document, &body, &manifest, &allow)?;

    // ---- policy source: a non-empty allow must be justified by pinned revisions ----
    let revisions_empty = manifest_map
        .get("revisions")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    if !allow.is_empty() && revisions_empty {
        return Err(ContractRefusal::PolicySourceUnresolved {
            digest: digest.to_owned(),
            detail: "body.tools.allow is non-empty but closure_manifest.revisions pins no \
                     policy source, so no native constraint justifies it"
                .to_owned(),
        });
    }

    Ok(StrictPolicy {
        allow,
        projection: derived,
    })
}

/// `body.tools`: a closed object with exactly `profile` and `allow`.
fn validate_tools(
    digest: &str,
    profile: &str,
    tools: &Value,
) -> Result<Vec<String>, ContractRefusal> {
    let invalid = |detail: String| ContractRefusal::ProfileInvalid {
        digest: digest.to_owned(),
        detail,
    };
    let required = |detail: String| ContractRefusal::ProfileRequired {
        digest: digest.to_owned(),
        detail,
    };
    let Value::Object(tools) = tools else {
        return Err(invalid(format!(
            "body.tools must be an object with exactly `profile` and `allow`, found {}",
            kind_of(tools)
        )));
    };
    let Some(marker) = tools.get("profile") else {
        return Err(required("body.tools.profile is absent".to_owned()));
    };
    let Some(allow) = tools.get("allow") else {
        return Err(required(
            "body.tools.allow is absent; a missing allow is never read as deny-all".to_owned(),
        ));
    };
    if let Some(extra) = tools
        .keys()
        .find(|key| *key != "profile" && *key != "allow")
    {
        return Err(invalid(format!(
            "body.tools has the unknown member `{extra}`"
        )));
    }
    match marker {
        Value::String(found) if found == profile => {}
        Value::String(found) => {
            return Err(invalid(format!(
                "body.tools.profile is `{found}`, the reader was asked for `{profile}`"
            )))
        }
        other => {
            return Err(invalid(format!(
                "body.tools.profile must be the string `{profile}`, found {}",
                kind_of(other)
            )))
        }
    }
    let allow = parse_allow(allow).map_err(invalid)?;
    Ok(allow)
}

/// Envelope copies and dispatch hints (all outside the digest) must agree with
/// the verified bytes. Returns the projection derived from those bytes.
fn check_envelope(
    digest: &str,
    profile: &str,
    document: &ContractDocument,
    body: &Value,
    manifest: &Value,
    allow: &[String],
) -> Result<Value, ContractRefusal> {
    // ---- top-level dispatch hints (outside the digest) must agree ----
    let diverges = |detail: String| ContractRefusal::PolicyUnbound {
        digest: digest.to_owned(),
        detail,
    };
    if let Some(kind) = document.kind.as_deref() {
        if kind != PROFILE_KIND {
            return Err(diverges(format!(
                "the envelope kind is `{kind}`, the profile object is `{PROFILE_KIND}`"
            )));
        }
    }
    if let Some(hint) = document.schema_version.as_deref() {
        if hint != STRICT_PROFILE || hint != profile {
            return Err(diverges(format!(
                "the envelope schema_version hint `{hint}` disagrees with the digested \
                 body.tools.profile `{profile}`"
            )));
        }
    }

    let derived = serde_json::json!({ "body": body, "closure_manifest": manifest });
    match &document.projection {
        Value::Null => {}
        shown if *shown == derived => {}
        _ => {
            return Err(diverges(
                "the envelope projection differs from the body/closure_manifest in the digested \
                 bytes"
                    .to_owned(),
            ))
        }
    }
    if let Some(shown) = document.tools.as_ref() {
        let derived_tools = ContractTools {
            allow: allow.to_vec(),
        };
        if *shown != derived_tools {
            return Err(diverges(
                "the envelope tools differ from the tools in the digested bytes".to_owned(),
            ));
        }
    }
    Ok(derived)
}

fn check_exact_keys<'a>(
    what: &str,
    map: &Map<String, Value>,
    expected: impl Iterator<Item = &'a str> + Clone,
) -> Result<(), String> {
    if let Some(missing) = expected.clone().find(|key| !map.contains_key(*key)) {
        return Err(format!("{what} is missing the required member `{missing}`"));
    }
    let known: Vec<&str> = expected.collect();
    if let Some(extra) = map.keys().find(|key| !known.contains(&key.as_str())) {
        return Err(format!("{what} has the unknown member `{extra}`"));
    }
    Ok(())
}

fn parse_allow(value: &Value) -> Result<Vec<String>, String> {
    let Value::Array(items) = value else {
        return Err(format!(
            "body.tools.allow must be an array, found {}",
            kind_of(value)
        ));
    };
    if items.len() > TOOL_VOCABULARY.len() {
        return Err(format!(
            "body.tools.allow has {} entries; the profile allows at most {}",
            items.len(),
            TOOL_VOCABULARY.len()
        ));
    }
    let mut allow: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(name) = item else {
            return Err(format!(
                "body.tools.allow entries must be strings, found {}",
                kind_of(item)
            ));
        };
        if !TOOL_VOCABULARY.contains(&name.as_str()) {
            return Err(format!(
                "`{name}` is outside the closed vocabulary {TOOL_VOCABULARY:?} (no alias, \
                 wildcard, shell or case folding)"
            ));
        }
        if let Some(previous) = allow.last() {
            if previous == name {
                return Err(format!("body.tools.allow lists `{name}` more than once"));
            }
            if previous.as_str() > name.as_str() {
                return Err(format!(
                    "body.tools.allow is not ASCII-ascending (`{previous}` before `{name}`)"
                ));
            }
        }
        allow.push(name.clone());
    }
    Ok(allow)
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

// ---------------------------------------------------------------------------
// raw bytes: the two halves, duplicate keys, canonical comparison
// ---------------------------------------------------------------------------

/// `text` split at the end of its first JSON value, or `None` unless it is
/// exactly two values with nothing after the second.
fn split_raw(text: &str) -> Option<(&str, &str)> {
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<IgnoredAny>();
    stream.next()?.ok()?;
    let offset = stream.byte_offset();
    stream.next()?.ok()?;
    if stream.next().is_some() || stream.byte_offset() != text.len() {
        return None;
    }
    Some(text.split_at(offset))
}

/// A JSON value parsed so that a duplicate object key is an error rather than
/// "the last one wins".
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Strict(Value::Number(n)))
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(v.to_owned())))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(v)))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Strict(Value::Array(items)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Strict, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate object key `{key}`")));
            }
            let Strict(value) = access.next_value()?;
            map.insert(key, value);
        }
        Ok(Strict(Value::Object(map)))
    }
}

fn parse_half(name: &str, text: &str) -> Result<Value, String> {
    serde_json::from_str::<Strict>(text)
        .map(|Strict(value)| value)
        .map_err(|err| format!("{name} is not strictly parseable JSON: {err}"))
}

/// The `json-c14n-pilot/v1` rendering of `value`, for COMPARISON only.
///
/// Sorted keys (code-point order == UTF-8 byte order), `,`/`:` separators,
/// every char outside `0x20..=0x7e` escaped as lowercase `\uXXXX` (surrogate
/// pairs above the BMP), integers only.
pub fn render_canonical(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    render(value, &mut out)?;
    Ok(out)
}

fn render(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) if n.is_i64() || n.is_u64() => out.push_str(&n.to_string()),
        Value::Number(n) => {
            return Err(format!(
                "non-integer number {n}: the canonical form forbids floats"
            ))
        }
        Value::String(s) => render_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                render(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                render_string(key, out);
                out.push(':');
                if let Some(item) = map.get(key) {
                    render(item, out)?;
                }
            }
            out.push('}');
        }
    }
    Ok(())
}

fn render_string(s: &str, out: &mut String) {
    use fmt::Write as _;
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Golden vectors produced by the REFERENCE canonicaliser
    /// (talomnia-knowledge `ontology/src/canonical.py` at
    /// `1f900d7ac718abb864b7571073a4fba3097645ee`, sha256 of the file
    /// `910cfec6…cbb9f`): `canonical_bytes(value)` for each input.
    const VECTORS: [(&str, &str); 4] = [
        (
            r#"{"b":1,"a":[1,2,{"z":null,"y":true}]}"#,
            r#"{"a":[1,2,{"y":true,"z":null}],"b":1}"#,
        ),
        (
            "{\"k\":\"\u{e9}\u{7f}\\u0001\\\"\\\\\\n\\t\\r\\b\\f\u{1F600} ~\"}",
            r#"{"k":"\u00e9\u007f\u0001\"\\\n\t\r\b\f\ud83d\ude00 ~"}"#,
        ),
        (
            "{\"\u{43a}\u{43b}\u{44e}\u{447}\":\"\u{437}\u{43d}\u{430}\u{447}\u{435}\u{43d}\u{438}\u{435}\",\"a\":-5,\"A\":0}",
            r#"{"A":0,"a":-5,"\u043a\u043b\u044e\u0447":"\u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0435"}"#,
        ),
        (
            r#"{"big":18446744073709551615,"":""}"#,
            r#"{"":"","big":18446744073709551615}"#,
        ),
    ];

    #[test]
    fn the_comparison_rendering_matches_the_reference_canonicaliser() {
        for (input, expected) in VECTORS {
            let parsed: Value = serde_json::from_str(input).expect("vector parses");
            assert_eq!(
                render_canonical(&parsed).expect("renders"),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn floats_are_not_canonical() {
        let parsed: Value = serde_json::from_str(r#"{"a":1.0}"#).unwrap();
        assert!(render_canonical(&parsed).is_err());
    }

    #[test]
    fn a_duplicate_key_is_an_error_not_last_wins() {
        let err = parse_half("body", r#"{"a":1,"a":2}"#).unwrap_err();
        assert!(err.contains("duplicate object key `a`"), "{err}");
        assert!(parse_half("body", r#"{"a":{"b":1,"b":2}}"#).is_err());
    }
}
