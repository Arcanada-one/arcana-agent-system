//! Dependency-free encoders/decoders for the closed transform set.
//!
//! The transform set is fixed by the SEC-0030 security consilium and MUST NOT be
//! widened without security review plus regenerated benign-corpus identity
//! evidence:
//!
//! - raw UTF-8 bytes (and therefore bearer/header and JSON-string forms),
//! - RFC 4648 standard Base64 and Base64url, padded and unpadded,
//! - upper- and lower-case hexadecimal,
//! - URL percent encoding,
//! - JSON `\uXXXX` escapes.
//!
//! Every decoder here is *detection-oriented*: it is deliberately lenient about
//! surrounding bytes (it decodes maximal alphabet runs) because its job is to
//! find an obfuscated secret, not to faithfully parse a wire format.

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Which Base64 alphabet a transform uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum B64Alphabet {
    Standard,
    Url,
}

impl B64Alphabet {
    fn table(self) -> &'static [u8; 64] {
        match self {
            Self::Standard => B64_STD,
            Self::Url => B64_URL,
        }
    }

    fn value(self, byte: u8) -> Option<u8> {
        // Linear scan over 64 entries: the buffers here are bounded by
        // `max_encoded_window`, and avoiding a lookup table keeps this
        // allocation-free and obviously correct.
        self.table()
            .iter()
            .position(|&c| c == byte)
            .map(|i| u8::try_from(i).unwrap_or(0))
    }
}

/// Encode `data` as Base64 in the given alphabet.
#[must_use]
pub fn b64_encode(data: &[u8], alphabet: B64Alphabet, pad: bool) -> String {
    let table = alphabet.table();
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(table[((n >> 6) & 63) as usize] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(table[(n & 63) as usize] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// Decode a maximal Base64 run. Returns `None` when the run is not decodable.
///
/// Trailing bytes that do not form a complete quantum are dropped rather than
/// treated as an error: a stream chunk may legitimately split a quantum, and the
/// scanner's retention window guarantees the remainder is re-examined.
#[must_use]
pub fn b64_decode_lenient(run: &[u8], alphabet: B64Alphabet) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(run.len() / 4 * 3);
    for &byte in run {
        if byte == b'=' {
            break;
        }
        let v = alphabet.value(byte)?;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap_or(0));
        }
    }
    Some(out)
}

/// True when `byte` belongs to the given Base64 alphabet (padding excluded).
#[must_use]
pub fn is_b64_byte(byte: u8, alphabet: B64Alphabet) -> bool {
    alphabet.table().contains(&byte)
}

/// Encode `data` as hexadecimal.
#[must_use]
pub fn hex_encode(data: &[u8], upper: bool) -> String {
    let digits = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(digits[usize::from(b >> 4)] as char);
        out.push(digits[usize::from(b & 0x0F)] as char);
    }
    out
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// True when `byte` is a hexadecimal digit.
#[must_use]
pub fn is_hex_byte(byte: u8) -> bool {
    hex_val(byte).is_some()
}

/// Decode a maximal hexadecimal run, dropping a trailing odd nibble.
#[must_use]
pub fn hex_decode_lenient(run: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(run.len() / 2);
    for pair in run.chunks(2) {
        if pair.len() < 2 {
            break;
        }
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Fully percent-encode every byte (`%XX`), the obfuscation-worst-case form.
#[must_use]
pub fn percent_encode_all(data: &[u8], upper: bool) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    for &b in data {
        out.push('%');
        out.push_str(&hex_encode(&[b], upper));
    }
    out
}

/// Decode every `%XX` sequence found in `data`, passing other bytes through.
#[must_use]
pub fn percent_decode_lenient(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'%' && i + 2 < data.len() {
            if let (Some(hi), Some(lo)) = (hex_val(data[i + 1]), hex_val(data[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

/// Fully `\uXXXX`-escape every byte, the obfuscation-worst-case JSON form.
#[must_use]
pub fn json_u_escape_all(data: &[u8], upper: bool) -> String {
    let mut out = String::with_capacity(data.len() * 6);
    for &b in data {
        out.push_str("\\u00");
        out.push_str(&hex_encode(&[b], upper));
    }
    out
}

/// Decode every `\uXXXX` escape found in `data`, passing other bytes through.
///
/// Only the Latin-1 range is materialised as a single byte; higher code points
/// are emitted as their UTF-8 encoding so a secret escaped in full still
/// reassembles.
#[must_use]
pub fn json_u_decode_lenient(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\\' && i + 5 < data.len() && (data[i + 1] == b'u' || data[i + 1] == b'U') {
            let digits = &data[i + 2..i + 6];
            if digits.iter().all(|&d| is_hex_byte(d)) {
                let mut cp: u32 = 0;
                for &d in digits {
                    cp = (cp << 4) | u32::from(hex_val(d).unwrap_or(0));
                }
                if let Some(ch) = char::from_u32(cp) {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                i += 6;
                continue;
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}
