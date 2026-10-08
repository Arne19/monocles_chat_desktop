//! XMPP verification URIs — the `xmpp:<jid>?omemo-sid-<device>=<fingerprint>` codes clients
//! show as a QR for out-of-band key verification (XEP-0147 style query components).
//!
//! Two parameters carry identity keys, and the distinction matters because the monocles
//! Android client runs two OMEMO stacks with *separate* identity keys under the same device
//! id:
//!
//! * `omemo-sid-<device>` — the parameter every OMEMO client understands. Across the
//!   ecosystem it means the XEP-0384 v0.3 ("legacy") key, so that is what monocles Android
//!   puts there whenever it has one. We have no legacy stack at all, so our own code puts
//!   our PQ OMEMO2 key here: it is the only key we have, there is no legacy key it could be
//!   confused with, and every client — including monocles Android builds that predate the
//!   `omemo-pq-sid-` parameter — can read it.
//! * `omemo-pq-sid-<device>` — the PQ OMEMO2 (`urn:monocles:omemo-pq:1`) key. This is the
//!   one we must pick up when reading an Android code: their `omemo-sid-` entry is a legacy
//!   key we can never establish a session with.
//!
//! Trust is keyed by the fingerprint *value* on both sides, so a reader may simply try every
//! fingerprint it finds against the keys it knows; the parameter only says which stack the
//! key belongs to.

/// Which OMEMO stack a fingerprint in a URI belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintKind {
    /// `omemo-sid-` — legacy XEP-0384 v0.3 key (or, from a client without a legacy stack,
    /// simply "the key it has").
    Omemo,
    /// `omemo-pq-sid-` — PQ OMEMO2 key.
    OmemoPq,
}

pub const OMEMO_PARAM: &str = "omemo-sid-";
pub const OMEMO_PQ_PARAM: &str = "omemo-pq-sid-";

/// One identity key from (or for) a verification URI. `hex` is the bare 64-character lowercase
/// hex of the 32-byte Curve25519 key — libsignal's `0x05` type prefix stripped, no grouping
/// spaces — which is the form these URIs use everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriFingerprint {
    pub kind: FingerprintKind,
    pub device_id: i64,
    pub hex: String,
}

impl UriFingerprint {
    /// Build an entry from a serialized identity key (33 bytes with the `0x05` prefix, or 32
    /// without).
    pub fn from_identity_key(kind: FingerprintKind, device_id: i64, identity_key: &[u8]) -> Self {
        let key = if identity_key.len() == 33 && identity_key[0] == 0x05 {
            &identity_key[1..]
        } else {
            identity_key
        };
        Self { kind, device_id, hex: hex::encode(key) }
    }
}

/// A parsed verification URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUri {
    /// The bare JID the fingerprints belong to.
    pub jid: String,
    pub fingerprints: Vec<UriFingerprint>,
}

impl ParsedUri {
    /// Every fingerprint, whichever stack it was labelled with. Trust is keyed by value, so a
    /// key belonging to a stack we do not run simply matches nothing.
    pub fn all_hex(&self) -> Vec<String> {
        self.fingerprints.iter().map(|f| f.hex.clone()).collect()
    }
}

/// Render `xmpp:<jid>?<params>` for a QR code / shareable link.
pub fn verification_uri(bare_jid: &str, fingerprints: &[UriFingerprint]) -> String {
    let mut out = format!("xmpp:{}", encode_jid(bare_jid));
    for (i, fp) in fingerprints.iter().enumerate() {
        out.push(if i == 0 { '?' } else { ';' });
        out.push_str(match fp.kind {
            FingerprintKind::Omemo => OMEMO_PARAM,
            FingerprintKind::OmemoPq => OMEMO_PQ_PARAM,
        });
        out.push_str(&fp.device_id.to_string());
        out.push('=');
        out.push_str(&fp.hex);
    }
    out
}

/// Parse a scanned/pasted verification URI. Accepts `xmpp:` URIs and the `https://<host>/i/…`
/// invite links monocles/Conversations generate; returns `None` when there is no usable JID.
///
/// Unknown parameters are ignored, and a repeated parameter keeps its first value rather than
/// failing the whole parse — the input is attacker-supplied (a scanned code, a link on a web
/// page) and must never be able to do more than be rejected.
pub fn parse(input: &str) -> Option<ParsedUri> {
    let input = input.trim();
    let lower = input.to_ascii_lowercase();

    if lower.starts_with("xmpp:") {
        let rest = &input["xmpp:".len()..];
        return match rest.split_once('?') {
            Some((jid, query)) => finish(jid, Some(query), ';'),
            None => finish(rest, None, ';'),
        };
    }

    if lower.starts_with("https://") || lower.starts_with("http://") {
        let after_scheme = input.split_once("//")?.1;
        let (_host, path) = after_scheme.split_once('/')?;
        let (path, query) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path, None),
        };
        // https://<host>/i/<jid> and the older https://<host>/i/<user>/<domain>
        let mut segments = path.split('/').filter(|s| !s.is_empty());
        if segments.next()? != "i" {
            return None;
        }
        let first = segments.next()?;
        return match segments.next() {
            Some(domain) if !first.contains('@') => {
                finish(&format!("{first}@{domain}"), query, '&')
            }
            _ => finish(first, query, '&'),
        };
    }

    None
}

fn finish(jid_part: &str, query: Option<&str>, separator: char) -> Option<ParsedUri> {
    let jid = percent_decode(jid_part).trim().to_string();
    if jid.is_empty() || !jid.contains('@') {
        return None;
    }
    let mut seen: Vec<String> = Vec::new();
    let mut fingerprints = Vec::new();
    for pair in query.unwrap_or("").split(separator) {
        let Some((key, value)) = pair.split_once('=') else { continue };
        let key = percent_decode(key).to_ascii_lowercase();
        if seen.contains(&key) {
            continue; // first occurrence wins
        }
        seen.push(key.clone());
        let (kind, suffix) = if let Some(id) = key.strip_prefix(OMEMO_PQ_PARAM) {
            (FingerprintKind::OmemoPq, id)
        } else if let Some(id) = key.strip_prefix(OMEMO_PARAM) {
            (FingerprintKind::Omemo, id)
        } else {
            continue;
        };
        let Ok(device_id) = suffix.parse::<i64>() else { continue };
        // A device id is a positive 31-bit integer; a negative one is not a device.
        if device_id < 0 {
            continue;
        }
        let Some(hex) = normalize_fingerprint(&percent_decode(value)) else { continue };
        fingerprints.push(UriFingerprint { kind, device_id, hex });
        if fingerprints.len() >= MAX_URI_FINGERPRINTS {
            break;
        }
    }
    Some(ParsedUri { jid, fingerprints })
}

/// Upper bound on how many fingerprints one URI may carry. A legitimate code holds the sender's
/// key per stack plus one per other verified device of the same account — a couple of dozen at
/// the very outside. Without a cap, a single scanned code could ask us to write hundreds of rows
/// into the identity table. Matches monocles Android's `XmppUri.MAX_FINGERPRINTS`.
const MAX_URI_FINGERPRINTS: usize = 64;

/// Lowercase, whitespace-free hex of the 32-byte key, or `None` when the value is not a
/// fingerprint (wrong length, non-hex). A leading `05` type byte is stripped.
pub fn normalize_fingerprint(value: &str) -> Option<String> {
    let hex: String = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let hex = match hex.len() {
        64 => hex,
        66 if hex.starts_with("05") => hex[2..].to_string(),
        _ => return None,
    };
    Some(hex)
}

/// Percent-encode the characters that would break the query part of an `xmpp:` URI. JIDs are
/// otherwise left readable, the way the other clients render them.
fn encode_jid(jid: &str) -> String {
    let mut out = String::with_capacity(jid.len());
    for c in jid.chars() {
        match c {
            '?' | ';' | '#' | '%' | ' ' => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            // From the bytes: slicing the str could split a multi-byte character and panic.
            if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PQ: &str = "1122334455667788112233445566778811223344556677881122334455667788";
    const LEGACY: &str = "99aabbccddeeff0099aabbccddeeff0099aabbccddeeff0099aabbccddeeff00";

    #[test]
    fn percent_before_multibyte_character_does_not_panic() {
        assert_eq!(percent_decode("a%€b"), "a%€b");
        assert_eq!(percent_decode("%e2%82%ac"), "€");
        assert!(parse("xmpp:a%€@b.org").is_some());
    }

    #[test]
    fn round_trip_own_uri() {
        let fp = UriFingerprint {
            kind: FingerprintKind::Omemo,
            device_id: 42,
            hex: PQ.to_string(),
        };
        let uri = verification_uri("me@example.com", &[fp.clone()]);
        assert_eq!(uri, format!("xmpp:me@example.com?omemo-sid-42={PQ}"));
        let parsed = parse(&uri).expect("parses");
        assert_eq!(parsed.jid, "me@example.com");
        assert_eq!(parsed.fingerprints, vec![fp]);
    }

    #[test]
    fn reads_both_stacks_from_an_android_code() {
        // What monocles Android generates: the legacy key in the standard parameter, the PQ
        // key — the one we can actually use — in its own.
        let uri = format!("xmpp:a@b.com?omemo-sid-7={LEGACY};omemo-pq-sid-7={PQ}");
        let parsed = parse(&uri).expect("parses");
        assert_eq!(
            parsed.fingerprints,
            vec![
                UriFingerprint { kind: FingerprintKind::Omemo, device_id: 7, hex: LEGACY.into() },
                UriFingerprint { kind: FingerprintKind::OmemoPq, device_id: 7, hex: PQ.into() },
            ]
        );
        assert_eq!(parsed.all_hex(), vec![LEGACY.to_string(), PQ.to_string()]);
    }

    #[test]
    fn strips_type_byte_and_grouping() {
        let uri = format!("xmpp:a@b.com?omemo-pq-sid-1=05{}", PQ.to_uppercase());
        let parsed = parse(&uri).expect("parses");
        assert_eq!(parsed.fingerprints[0].hex, PQ);
    }

    #[test]
    fn invite_links() {
        let uri = format!("https://conversations.im/i/a@b.com?omemo-sid-3={PQ}");
        let parsed = parse(&uri).expect("parses");
        assert_eq!(parsed.jid, "a@b.com");
        assert_eq!(parsed.fingerprints[0].device_id, 3);

        let split = format!("https://monocles.chat/i/a/b.com?omemo-sid-3={PQ}");
        assert_eq!(parse(&split).expect("parses").jid, "a@b.com");
    }

    #[test]
    fn percent_encoded_jid() {
        let parsed = parse(&format!("xmpp:a%40b.com?omemo-sid-1={PQ}")).expect("parses");
        assert_eq!(parsed.jid, "a@b.com");
    }

    #[test]
    fn hostile_input_is_rejected_not_fatal() {
        assert!(parse("").is_none());
        assert!(parse("https://example.com/nothing").is_none());
        assert!(parse("xmpp:not-a-jid").is_none());
        // Junk values are skipped, the JID still parses.
        let parsed = parse("xmpp:a@b.com?omemo-sid-1=zzzz;omemo-sid-x=1234;name=x").unwrap();
        assert!(parsed.fingerprints.is_empty());
        // A repeated parameter keeps the first value instead of blowing up.
        let parsed = parse(&format!("xmpp:a@b.com?omemo-sid-1={PQ};omemo-sid-1={LEGACY}")).unwrap();
        assert_eq!(parsed.fingerprints.len(), 1);
        assert_eq!(parsed.fingerprints[0].hex, PQ);
        // A device id is a positive integer; a negative one names no device.
        let parsed = parse(&format!("xmpp:a@b.com?omemo-sid--1={PQ}")).unwrap();
        assert!(parsed.fingerprints.is_empty());
    }

    /// One scanned code must not be able to ask us to write an unbounded number of identity
    /// rows. Mirrors monocles Android's `XmppUri.MAX_FINGERPRINTS`.
    #[test]
    fn fingerprint_count_is_capped() {
        let query = (0..MAX_URI_FINGERPRINTS * 3)
            .map(|i| format!("omemo-sid-{i}={PQ}"))
            .collect::<Vec<_>>()
            .join(";");
        let parsed = parse(&format!("xmpp:a@b.com?{query}")).expect("parses");
        assert_eq!(parsed.fingerprints.len(), MAX_URI_FINGERPRINTS);
        assert_eq!(parsed.jid, "a@b.com", "the JID still parses past the cap");
    }

    #[test]
    fn from_identity_key_strips_prefix() {
        let mut serialized = vec![0x05u8];
        serialized.extend_from_slice(&[0x11u8; 32]);
        let fp = UriFingerprint::from_identity_key(FingerprintKind::Omemo, 1, &serialized);
        assert_eq!(fp.hex, hex::encode([0x11u8; 32]));
    }
}
