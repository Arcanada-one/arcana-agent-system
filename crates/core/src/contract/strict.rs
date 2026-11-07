//! The strict `arcanada-kc2-tools/v1` reader: a VALIDATOR over bytes that
//! [`super::verify_with`] has already re-hashed.
//!
//! Nothing here hashes, binds or builds a preimage. It looks at the verified
//! `canonical(body) ‖ canonical(closure_manifest)` bytes and answers whether
//! they conform to the profile, refusing with a typed code when they do not.
//!
//! The SHAPE of those bytes (top-level members, the twelve body members, the closure manifest,
//! `body.tools`, every value inside them) is NOT written down here. It is the normative schema
//! owned by talomnia-knowledge, vendored byte for byte and pinned by blob id
//! ([`super::TALOMNIA_SCHEMA_PIN`]), and enforced with the `jsonschema` crate over the pinned
//! files. What a schema keyword cannot state stays here, in the order the pinned reference reader
//! (`kc2_tools_profile.py`) applies it: profile-marker classification, required-vs-invalid for the
//! load-bearing `body.tools` members, marker agreement, strictly ascending `allow`, exact canonical
//! bytes, and the consumer-only envelope/policy-source checks.
//!
//! One thing in this file looks like canonicalisation and is not: [`render_canonical`] re-renders
//! a PARSED half in the existing `json-c14n-pilot/v1` form (sorted keys, `,`/`:` separators,
//! `ensure_ascii`, integers only - talomnia-knowledge `ontology/src/canonical.py`) purely so the
//! result can be compared byte for byte with the half the digest was computed over. Its output is
//! never hashed and never adopted; a mismatch is a refusal. Digest computation is untouched
//! ([`super::digest_of`]).

use std::fmt;

use jsonschema::{Retrieve, Uri};
use serde::de::IgnoredAny;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::{
    ContractDocument, ContractRefusal, ContractTools, SchemaPin, PROFILE_SCHEMA, TOOL_VOCABULARY,
};

/// The top-level `kind` literal of the profile object.
pub const PROFILE_KIND: &str = "KnowledgeContract";

/// Profile markers of the legacy `talomnia-ontology` line: they carry no tools profile.
const LEGACY_VERSIONS: [&str; 2] = ["talomnia-ontology/v1", "talomnia-ontology/v2"];

/// What a conforming profile body yields.
pub(super) struct StrictPolicy {
    /// `body.tools.allow`, exactly as written (validated, never normalised).
    pub allow: Vec<String>,
    /// `{body, closure_manifest}` as parsed from the verified bytes.
    pub projection: Value,
}

/// `arcanada-kc2-tools/v<digits>` - the family of tools-profile markers (the pinned reader's
/// `^arcanada-kc2-tools/v[0-9]+$`, ASCII digits, nothing after them).
fn is_profile_family(marker: &str) -> bool {
    marker
        .strip_prefix("arcanada-kc2-tools/v")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether the bytes the digest covers, or the envelope's `schema_version` hint, are marked with a
/// tools profile; `Some(why)` if so. Used by the LEGACY route to refuse such contracts.
///
/// Marked means: `body.tools` (top level of the first value) carries a `profile` member, in ANY
/// occurrence of those keys (a duplicate `tools` or `profile` key cannot hide the mark behind
/// last-wins parsing), or the envelope hint is a `arcanada-kc2-tools/vN` marker. A pre-profile
/// contract has `tools: {allow}` or no `tools`, so actual legacy bytes are never marked.
///
/// Bytes that are not two parseable JSON values would otherwise reach the legacy opaque-text
/// route, which takes the DEFAULT tool set - wider than a profile contract's own `allow`. For
/// those the mark is the profile family name appearing anywhere in the text.
pub(super) fn profile_mark(bytes: &[u8], document: &ContractDocument) -> Option<String> {
    if let Some(hint) = document.schema_version.as_deref() {
        if is_profile_family(hint) {
            return Some(format!("the envelope schema_version names `{hint}`"));
        }
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let parsed = split_raw(text).and_then(|(body_text, _)| {
        serde_json::from_str::<BodyMark>(body_text)
            .ok()
            .map(|m| m.0)
    });
    match parsed {
        Some(true) => Some("body.tools carries a `profile` member".to_owned()),
        Some(false) => None,
        None => text
            .contains("arcanada-kc2-tools")
            .then(|| "the unparseable bytes name the arcanada-kc2-tools profile family".to_owned()),
    }
}

/// `true` if the body object has a `tools` member that is an object with a `profile` member.
struct BodyMark(bool);

impl<'de> Deserialize<'de> for BodyMark {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = BodyMark;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<BodyMark, A::Error> {
                let mut marked = false;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "tools" {
                        marked |= map.next_value::<ToolsMark>()?.0;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(BodyMark(marked))
            }
            fn visit_unit<E: de::Error>(self) -> Result<BodyMark, E> {
                Ok(BodyMark(false))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<BodyMark, E> {
                Ok(BodyMark(false))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<BodyMark, E> {
                Ok(BodyMark(false))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<BodyMark, E> {
                Ok(BodyMark(false))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<BodyMark, E> {
                Ok(BodyMark(false))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<BodyMark, E> {
                Ok(BodyMark(false))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<BodyMark, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(BodyMark(false))
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// `true` if the value is an object with a `profile` member.
struct ToolsMark(bool);

impl<'de> Deserialize<'de> for ToolsMark {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ToolsMark;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ToolsMark, A::Error> {
                let mut marked = false;
                while let Some(key) = map.next_key::<String>()? {
                    marked |= key == "profile";
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(ToolsMark(marked))
            }
            fn visit_unit<E: de::Error>(self) -> Result<ToolsMark, E> {
                Ok(ToolsMark(false))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<ToolsMark, E> {
                Ok(ToolsMark(false))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<ToolsMark, E> {
                Ok(ToolsMark(false))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<ToolsMark, E> {
                Ok(ToolsMark(false))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<ToolsMark, E> {
                Ok(ToolsMark(false))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<ToolsMark, E> {
                Ok(ToolsMark(false))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ToolsMark, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(ToolsMark(false))
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// Classify a top-level profile marker the way the pinned reader does: the legacy
/// `talomnia-ontology` versions need a profile (`CONTRACT_PROFILE_REQUIRED`), another version of
/// this family is beyond this reader (`CONTRACT_READER_UNSUPPORTED`), anything else unknown is
/// `CONTRACT_PROFILE_INVALID`. `Ok` only for exactly `profile`.
fn classify_marker(digest: &str, profile: &str, marker: &str) -> Result<(), ContractRefusal> {
    if marker == profile {
        return Ok(());
    }
    if LEGACY_VERSIONS.contains(&marker) {
        return Err(ContractRefusal::ProfileRequired {
            digest: digest.to_owned(),
            detail: format!(
                "the envelope schema_version `{marker}` carries no `{profile}` marker; strict mode                  never falls back to a legacy or default tool set"
            ),
        });
    }
    if is_profile_family(marker) {
        return Err(ContractRefusal::ReaderUnsupported {
            requested: marker.to_owned(),
            detail: format!("profile `{marker}` is outside this reader's capability (`{profile}`)"),
        });
    }
    Err(ContractRefusal::ProfileInvalid {
        digest: digest.to_owned(),
        detail: format!("unknown profile marker `{marker}` in the envelope schema_version"),
    })
}

/// Resolves the `$ref`s between the pinned schema files from the pinned bytes, never from the
/// network or the file system.
struct PinnedFiles(Vec<(&'static str, Value)>);

impl Retrieve for PinnedFiles {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let name = uri.path().as_str().rsplit('/').next().unwrap_or_default();
        self.0
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| format!("`{name}` is not one of the pinned schema files").into())
    }
}

/// Validate the digested halves against the pinned profile schema. The schema describes the whole
/// persisted contract, so it is run over `{body, closure_manifest, contract_digest, kind,
/// schema_version}` rebuilt from the VERIFIED bytes (never from envelope copies).
fn check_schema(
    digest: &str,
    profile: &str,
    pin: &SchemaPin,
    body: &Value,
    manifest: &Value,
) -> Result<(), ContractRefusal> {
    let unsupported = |detail: String| ContractRefusal::ReaderUnsupported {
        requested: profile.to_owned(),
        detail,
    };
    let mut files = Vec::with_capacity(pin.schemas.len());
    for schema in pin.schemas {
        let value = serde_json::from_slice::<Value>(schema.bytes).map_err(|err| {
            unsupported(format!(
                "pinned schema `{}` is not JSON: {err}",
                schema.name
            ))
        })?;
        files.push((schema.name, value));
    }
    let root = files
        .iter()
        .find(|(name, _)| *name == PROFILE_SCHEMA)
        .map(|(_, value)| value.clone())
        .ok_or_else(|| unsupported(format!("the pin does not hold `{PROFILE_SCHEMA}`")))?;
    let validator = jsonschema::options()
        .with_retriever(PinnedFiles(files))
        .build(&root)
        .map_err(|err| unsupported(format!("schema enforcement unavailable: {err}")))?;
    let whole = serde_json::json!({
        "body": body,
        "closure_manifest": manifest,
        "contract_digest": digest,
        "kind": PROFILE_KIND,
        "schema_version": profile,
    });
    let problems: Vec<String> = validator
        .iter_errors(&whole)
        .take(5)
        .map(|err| format!("{err} (at `{}`)", err.instance_path()))
        .collect();
    if problems.is_empty() {
        return Ok(());
    }
    Err(ContractRefusal::ProfileInvalid {
        digest: digest.to_owned(),
        detail: format!(
            "the digested contract does not conform to the pinned {PROFILE_SCHEMA}: {}",
            problems.join("; ")
        ),
    })
}

/// Validate verified `bytes` against the strict profile `profile`.
pub(super) fn derive(
    digest: &str,
    profile: &str,
    bytes: &[u8],
    document: &ContractDocument,
    pin: &SchemaPin,
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

    let body = parse_half_or_refuse(digest, profile, "body", body_text)?;
    let manifest = parse_half_or_refuse(digest, profile, "closure_manifest", manifest_text)?;

    // The envelope's profile marker (outside the digest) is classified first, as the pinned
    // reader classifies its top-level marker. An absent hint is allowed: integrity comes from the
    // digested inner marker below.
    if let Some(hint) = document.schema_version.as_deref() {
        classify_marker(digest, profile, hint)?;
    }

    let Value::Object(body_map) = &body else {
        return Err(invalid(format!(
            "body must be an object, found {}",
            kind_of(&body)
        )));
    };

    // ---- body.tools: required members, then inner-marker agreement ----
    let Some(tools) = body_map.get("tools") else {
        return Err(required(
            "body.tools is absent; the strict profile never falls back to a default tool set"
                .to_owned(),
        ));
    };
    let Value::Object(tools_map) = tools else {
        return Err(invalid(format!(
            "body.tools must be an object with exactly `profile` and `allow`, found {}",
            kind_of(tools)
        )));
    };
    let Some(marker) = tools_map.get("profile") else {
        return Err(required("body.tools.profile is absent".to_owned()));
    };
    if !tools_map.contains_key("allow") {
        return Err(required(
            "body.tools.allow is absent; a missing allow is never read as deny-all".to_owned(),
        ));
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

    // ---- the pinned schema: every member and every value inside it ----
    check_schema(digest, profile, pin, &body, &manifest)?;

    // The schema fixes the vocabulary, uniqueness and size; strictly ascending order is what a
    // keyword cannot state.
    let allow = parse_allow(&tools_map["allow"]).map_err(invalid)?;

    // Exact canonical round-trip: a hash that matches ambiguous, re-ordered or re-spaced JSON is
    // not profile conformance.
    for (name, half, half_text) in [
        ("body", &body, body_text),
        ("closure_manifest", &manifest, manifest_text),
    ] {
        let rendered = render_canonical(half).map_err(|why| canon(format!("{name}: {why}")))?;
        if rendered != half_text {
            return Err(canon(format!(
                "{name} is not the exact json-c14n-pilot/v1 form of itself (digest matched \
                 non-canonical bytes)"
            )));
        }
    }

    let derived = check_envelope(digest, document, &body, &manifest, &allow)?;

    // ---- policy source: a non-empty allow must be justified by pinned revisions ----
    let revisions_empty = manifest
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

/// Envelope copies (all outside the digest) must agree with the verified bytes. Returns the
/// projection derived from those bytes. The envelope `schema_version` hint was classified earlier.
fn check_envelope(
    digest: &str,
    document: &ContractDocument,
    body: &Value,
    manifest: &Value,
    allow: &[String],
) -> Result<Value, ContractRefusal> {
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
    // The canonical form has integers only, and the pinned reader rejects every non-integer
    // literal (`1.0` and `1e2` included) at parse time, before any schema check: so does this one.
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
        Err(E::custom(format!(
            "non-integer number {v}: the canonical form forbids floats"
        )))
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

/// Why a digested half did not parse: a defect of the bytes, or a value this reader cannot hold.
enum HalfError {
    /// Not strictly parseable canonical JSON (`CONTRACT_CANONICAL_INVALID`).
    Invalid(String),
    /// A well-formed canonical integer outside this reader's declared domain
    /// (`CONTRACT_READER_UNSUPPORTED`): a capability limit, never a rounding or a truncation.
    Unsupported(String),
}

impl fmt::Display for HalfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (Self::Invalid(text) | Self::Unsupported(text)) = self;
        f.write_str(text)
    }
}

/// [`parse_half`] with its failure mapped to the typed refusal: `CONTRACT_CANONICAL_INVALID` for a
/// defect of the bytes, `CONTRACT_READER_UNSUPPORTED` for a capability limit.
fn parse_half_or_refuse(
    digest: &str,
    profile: &str,
    name: &str,
    text: &str,
) -> Result<Value, ContractRefusal> {
    parse_half(name, text).map_err(|err| match err {
        HalfError::Invalid(detail) => ContractRefusal::CanonicalInvalid {
            digest: digest.to_owned(),
            detail,
        },
        HalfError::Unsupported(detail) => ContractRefusal::ReaderUnsupported {
            requested: profile.to_owned(),
            detail,
        },
    })
}

fn parse_half(name: &str, text: &str) -> Result<Value, HalfError> {
    serde_json::from_str::<Strict>(text)
        .map(|Strict(value)| value)
        .map_err(|err| {
            // A lone surrogate escape is not a Unicode scalar value: it is a defect of the bytes
            // (the normative decision: CONTRACT_CANONICAL_INVALID before hashing), so it wins
            // over a capability limit found anywhere in the same half, whatever the order.
            if !has_lone_surrogate_escape(text) {
                if let Some(literal) = integer_outside_domain(text) {
                    return HalfError::Unsupported(format!(
                        "{name} holds the integer {}, outside the integer domain this reader \
                         supports [{}, {}] (declared capability limit C1, see `INTEGER_DOMAIN`): \
                         the canonical form has exact unbounded integers, this reader refuses \
                         rather than round or truncate",
                        abbreviate(&literal),
                        INTEGER_DOMAIN.0,
                        INTEGER_DOMAIN.1
                    ));
                }
            }
            HalfError::Invalid(format!("{name} is not strictly parseable JSON: {err}"))
        })
}

/// `true` when a JSON string in `text` holds a `\uD800..\uDFFF` escape that is not part of a
/// high-then-low pair (keys and values alike; escapes only, since raw UTF-8 cannot encode one).
fn has_lone_surrogate_escape(text: &str) -> bool {
    let b = text.as_bytes();
    let hex = |i: usize| -> Option<u32> {
        let h = text.get(i..i + 4)?;
        u32::from_str_radix(h, 16).ok()
    };
    let mut i = 0;
    let mut in_string = false;
    while i < b.len() {
        match b[i] {
            b'"' => in_string = !in_string,
            b'\\' if in_string => {
                if b.get(i + 1) == Some(&b'u') {
                    if let Some(unit) = hex(i + 2) {
                        if (0xD800..0xDC00).contains(&unit) {
                            let low = b.get(i + 6) == Some(&b'\\')
                                && b.get(i + 7) == Some(&b'u')
                                && hex(i + 8).is_some_and(|u| (0xDC00..0xE000).contains(&u));
                            if !low {
                                return true;
                            }
                            i += 12;
                            continue;
                        }
                        if (0xDC00..0xE000).contains(&unit) {
                            return true;
                        }
                    }
                    i += 6;
                    continue;
                }
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// A long integer literal shortened for a message (the full literal can have thousands of digits).
fn abbreviate(literal: &str) -> String {
    if literal.len() <= 40 {
        literal.to_owned()
    } else {
        format!(
            "{}...{} ({} chars)",
            &literal[..20],
            &literal[literal.len() - 10..],
            literal.len()
        )
    }
}

/// C1 - the canonical VALUE DOMAIN this reader supports (reviewed decision, KCLIVE-11 / PR273).
///
/// The normative canonical form (`talomnia-knowledge` `canonical.py`, Python) has unbounded
/// integers, `\uXXXX` escapes for every non-ASCII char (surrogate pairs above the BMP), and lets a
/// lone escaped surrogate through. This reader supports:
///
/// * integers in `[i64::MIN, u64::MAX]` - anything outside refuses, fail-closed, with the typed
///   `CONTRACT_READER_UNSUPPORTED` (a reader capability, not a defect of the bytes: the canonical
///   domain has exact unbounded integers) and a message that names this restriction. Never
///   rounded, truncated or read as a float. The Python reference reader accepts exact integers up
///   to 4300 decimal digits and refuses longer ones with the same typed code;
/// * all Unicode scalar values, including non-BMP text, as escaped surrogate PAIRS;
/// * NOT a lone surrogate escape (`"\ud800"`): it is not a Unicode scalar value and `serde_json`
///   refuses it, so it refuses here as non-strictly-parseable.
///
/// Why restricted rather than supported: bignums need `serde_json`'s `arbitrary_precision`, a
/// workspace-wide feature that changes how EVERY `Value` number in the legacy route is held and
/// compared; the brief forbids altering legacy canonicalisation, and nothing in the profile or a
/// producer needs an integer above `u64`. The restriction is measured against the real chain
/// (`kc2_tools_e2e`: the producer, Argana and the pinned reader accept 2^64 and 2^200 in an open
/// task value; this reader refuses with `CONTRACT_READER_UNSUPPORTED`) and named, with its reason, in that test's `KNOWN_DIFFERENCES`.
/// Reverse if a producer legitimately emits an integer above `u64`: then lift it with an
/// arbitrary-precision number type confined to this module, not the shared `serde_json`.
pub const INTEGER_DOMAIN: (&str, &str) = ("-9223372036854775808", "18446744073709551615");

/// First integer literal (outside strings) that is not an `i64` or `u64`, if any.
fn integer_outside_domain(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            match b {
                b'\\' => i += 1,
                b'"' => in_string = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if b == b'-' || b.is_ascii_digit() {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let integral = !matches!(bytes.get(i), Some(b'.' | b'e' | b'E'));
            let literal = &text[start..i];
            if integral
                && !literal.trim_start_matches('-').is_empty()
                && literal.parse::<i64>().is_err()
                && literal.parse::<u64>().is_err()
            {
                return Some(literal.to_owned());
            }
            continue;
        }
        i += 1;
    }
    None
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
        assert!(
            err.to_string().contains("duplicate object key `a`"),
            "{err}"
        );
        assert!(parse_half("body", r#"{"a":{"b":1,"b":2}}"#).is_err());
    }
}
