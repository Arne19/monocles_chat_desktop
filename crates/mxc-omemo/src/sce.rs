//! XEP-0420 Stanza Content Encryption envelope (`urn:xmpp:sce:1`).
//!
//! All per-conversation data (body, markers, receipts, reactions, replies, …) goes
//! *inside* `<content>`; the envelope also carries `<rpad>`, `<time>`, and the
//! `<from>/<to>` binding that the receiver MUST verify (proto-XEP §4.6.1).
//!
//! This is the plaintext that gets AES-256-GCM encrypted into the OMEMO2 `<payload>`.
//! It is pure (de)serialization + binding checks, hence unit-testable standalone.

use quick_xml::events::Event;
use quick_xml::Reader;
use rand::RngCore;

use crate::{OmemoError, Result};

pub const NS_SCE: &str = "urn:xmpp:sce:1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Raw XML of the children inside `<content>` (already-namespaced elements).
    pub content_inner: String,
    pub from: String,
    pub to: String,
    /// RFC3339 timestamp, e.g. `2026-05-27T12:34:56Z`.
    pub time: Option<String>,
}

impl Envelope {
    /// Build a body-only envelope (the common case); callers append more `<content>`
    /// children by passing pre-serialized XML in `extra_content`.
    pub fn new(body: &str, from: &str, to: &str, time: Option<String>, extra_content: &str) -> Self {
        let content_inner = format!(
            "<body xmlns='jabber:client'>{}</body>{}",
            xml_escape(body),
            extra_content
        );
        Envelope { content_inner, from: from.to_string(), to: to.to_string(), time }
    }

    /// Build an envelope whose `<content>` is the given pre-serialized XML (e.g. a
    /// `<reactions>`/`<displayed>`/`<received>` metadata element, with no `<body>`).
    pub fn with_content(content_inner: &str, from: &str, to: &str, time: Option<String>) -> Self {
        Envelope {
            content_inner: content_inner.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            time,
        }
    }

    /// Serialize to envelope XML with size-class padding (proto-XEP §4.6.3): `<rpad>` is sized
    /// so the serialized envelope lands exactly on [`padded_envelope_length`]. The AES-GCM
    /// ciphertext length then reveals only a coarse size class of the content instead of its
    /// length.
    pub fn to_xml(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("<envelope xmlns='{NS_SCE}'>"));
        s.push_str("<content>");
        s.push_str(&self.content_inner);
        s.push_str("</content>");
        if let Some(t) = &self.time {
            s.push_str(&format!("<time stamp='{}'/>", xml_escape(t)));
        }
        s.push_str(&format!("<from jid='{}'/>", xml_escape(&self.from)));
        s.push_str(&format!("<to jid='{}'/>", xml_escape(&self.to)));
        // Everything except <rpad> is in place: pad to the size class. The pad alphabet is
        // ASCII (1 char == 1 UTF-8 byte, no XML escaping), so the final length is byte-exact.
        let unpadded = s.len() + RPAD_ELEMENT_OVERHEAD + "</envelope>".len();
        let target = padded_envelope_length(unpadded);
        s.push_str(&format!("<rpad>{}</rpad>", random_pad_chars(target - unpadded)));
        s.push_str("</envelope>");
        s
    }

    /// Parse an envelope and (optionally) the body text out of `<content>`.
    pub fn from_xml(xml: &str) -> Result<Self> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(false);

        let mut from = String::new();
        let mut to = String::new();
        let mut time = None;
        let mut content_inner = String::new();

        let mut depth_in_content = 0usize;
        let mut in_content = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Err(e) => return Err(OmemoError::BundleParse(e.to_string())),
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) => {
                    let name = e.name().as_ref().to_vec();
                    if name == b"content" && !in_content {
                        in_content = true;
                    } else if in_content {
                        depth_in_content += 1;
                        content_inner.push_str(&reconstruct_start(&e));
                    }
                }
                Ok(Event::End(e)) => {
                    let name = e.name().as_ref().to_vec();
                    if name == b"content" && depth_in_content == 0 {
                        in_content = false;
                    } else if in_content {
                        depth_in_content = depth_in_content.saturating_sub(1);
                        content_inner.push_str(&format!("</{}>", String::from_utf8_lossy(&name)));
                    }
                }
                Ok(Event::Empty(e)) => {
                    let name = e.name().as_ref().to_vec();
                    // The `!in_content` guards matter: the affixes live beside <content>, never
                    // inside it, and they are what verify_binding/check_sce_binding are checked
                    // against. Without the guard a <to/>, <from/> or <time/> element carried as
                    // ordinary content — legitimately or not — would silently overwrite the real
                    // affix (last one wins) and move the binding and replay checks onto a value
                    // the envelope author chose. It is not a privilege gain today (whoever writes
                    // the envelope already writes the affixes), but it makes the checks depend on
                    // where an element happens to sit rather than on the envelope structure.
                    match name.as_slice() {
                        b"from" if !in_content => from = attr_str(&e, b"jid"),
                        b"to" if !in_content => to = attr_str(&e, b"jid"),
                        b"time" if !in_content => {
                            let s = attr_str(&e, b"stamp");
                            if !s.is_empty() { time = Some(s); }
                        }
                        _ if in_content => content_inner.push_str(&reconstruct_empty(&e)),
                        _ => {}
                    }
                }
                Ok(Event::Text(t)) if in_content => {
                    content_inner.push_str(&String::from_utf8_lossy(t.as_ref()));
                }
                // quick-xml 0.40 emits entity references (`&lt;`, `&amp;`, `&#60;`, …) inside
                // text as their own GeneralRef events rather than leaving them in the Text bytes.
                // content_inner holds RAW (still-escaped) XML — body() unescapes it later — so we
                // reconstruct the `&name;` form here. Dropping it (as the `_` arm would) silently
                // strips `<`, `>`, `&` from bodies/markers carried in <content>.
                Ok(Event::GeneralRef(r)) if in_content => {
                    if let Ok(name) = r.decode() {
                        content_inner.push('&');
                        content_inner.push_str(&name);
                        content_inner.push(';');
                    }
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(Envelope { content_inner, from, to, time })
    }

    /// Extract the plaintext `<body>` from `content_inner`, if present.
    pub fn body(&self) -> Option<String> {
        let open = self.content_inner.find("<body")?;
        let gt = self.content_inner[open..].find('>')? + open + 1;
        let close = self.content_inner[gt..].find("</body>")? + gt;
        Some(xml_unescape(&self.content_inner[gt..close]))
    }

    /// XEP-0420 §4.5 binding check: the envelope `<to>` MUST match `expected_to`
    /// (our bare JID for inbound) and `<from>` MUST match the stanza sender.
    pub fn verify_binding(&self, expected_to: &str, expected_from: &str) -> Result<()> {
        if !self.to.eq_ignore_ascii_case(expected_to) {
            return Err(OmemoError::BadSignature("sce <to> mismatch"));
        }
        if !self.from.eq_ignore_ascii_case(expected_from) {
            return Err(OmemoError::BadSignature("sce <from> mismatch"));
        }
        Ok(())
    }
}

/// Smallest envelope size class, and the granularity below 4 KiB (proto-XEP §4.6.3). Receivers
/// ignore `<rpad>`, so parity with Android is not needed for interop — but it is needed for
/// privacy: differing padding would itself fingerprint the sending client.
const PAD_BUCKET: usize = 256;

/// The padded size of an envelope that is `unpadded` bytes long including an empty `<rpad>`:
/// Padmé (Nikitin et al., PETS 2019) of `unpadded + 1`, rounded up to a multiple of
/// [`PAD_BUCKET`]. Always at least one byte larger, so `<rpad>` is never empty. Byte-identical
/// to Android's `XmppOmemo2Message.paddedEnvelopeLength`.
///
/// Below 4 KiB this is the plain 256-byte bucket, which already hides the length of almost every
/// chat message. Above it, fixed buckets leak ever more as messages grow, while Padmé keeps the
/// overhead at most 12% and the leak to O(log log L) bits. Deterministic on purpose: random
/// padding is averaged away by an observer who sees many messages of a similar length.
pub(crate) fn padded_envelope_length(unpadded: usize) -> usize {
    let x = unpadded as u64 + 1;
    let e = 63 - x.leading_zeros(); // floor(log2 x)
    let s = 32 - e.leading_zeros(); // floor(log2 e) + 1, 0 for e = 0
    let mask = (1u64 << (e - s)) - 1;
    let padme = (x + mask) & !mask;
    padme.div_ceil(PAD_BUCKET as u64) as usize * PAD_BUCKET
}
/// Serialized size of an empty `<rpad></rpad>` element.
const RPAD_ELEMENT_OVERHEAD: usize = "<rpad></rpad>".len();

const RPAD_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Exactly `len` random ASCII chars, none of which need XML escaping.
fn random_pad_chars(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len).map(|_| RPAD_ALPHABET[rng.next_u32() as usize % RPAD_ALPHABET.len()] as char).collect()
}

/// Read an attribute as its decoded value (entities resolved), for comparison against a
/// plain string such as a JID or a timestamp.
fn attr_str(e: &quick_xml::events::BytesStart, key: &[u8]) -> String {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .map(|a| match a.normalized_value(quick_xml::XmlVersion::Implicit1_0) {
            Ok(v) => v.into_owned(),
            // An unresolvable entity leaves the raw bytes; the binding check then simply
            // fails to match, which is the safe direction.
            Err(_) => String::from_utf8_lossy(&a.value).into_owned(),
        })
        .unwrap_or_default()
}

fn reconstruct_start(e: &quick_xml::events::BytesStart) -> String {
    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    format!("<{}{}>", name, attrs_str(e))
}
fn reconstruct_empty(e: &quick_xml::events::BytesStart) -> String {
    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    format!("<{}{}/>", name, attrs_str(e))
}
/// Re-emit an element's attributes as XML.
///
/// `content_inner` holds raw (still-escaped) XML that gets re-parsed downstream, so every
/// attribute value has to be written back in a form that survives that second parse. Copying
/// `a.value` verbatim does not: quick-xml hands back the value exactly as it appeared, which
/// for a double-quoted source attribute may contain an unescaped `'` — and we always emit with
/// `'` delimiters. `<x a="it's"/>` then came back out as `<x a='it's'/>`, malformed, and the
/// re-parse failed, dropping the whole message as a decrypt failure. Android reaches this with
/// ordinary content: its serializer only escapes when it sees `<`, `&`, `"` or a control char,
/// so a lone apostrophe goes out raw inside `"…"` — an OGP link preview whose `rdf:about` URL
/// contains one is enough.
///
/// Decoding and re-escaping (rather than escaping the raw value) is what keeps this correct in
/// both directions: escaping raw bytes would turn an already-escaped `&amp;` into `&amp;amp;`.
fn attrs_str(e: &quick_xml::events::BytesStart) -> String {
    let mut s = String::new();
    for a in e.attributes().flatten() {
        let value = match a.normalized_value(quick_xml::XmlVersion::Implicit1_0) {
            Ok(v) => xml_escape(&v),
            // Unresolvable entity: keep the source bytes rather than corrupting them, and
            // escape only the delimiter so the output still parses.
            Err(_) => String::from_utf8_lossy(&a.value).replace('\'', "&apos;"),
        };
        s.push(' ');
        s.push_str(&String::from_utf8_lossy(a.key.as_ref()));
        s.push_str("='");
        s.push_str(&value);
        s.push('\'');
    }
    s
}

/// Escape for either an attribute value or a text node — `'` and `"` included, since every
/// attribute this module writes uses `'` delimiters.
fn xml_escape(s: &str) -> String {
    quick_xml::escape::escape(s).into_owned()
}
/// Inverse of [`xml_escape`]. Resolves the predefined entities *and* numeric character
/// references; the previous hand-rolled three-way replace left `&apos;`, `&quot;` and `&#39;`
/// visible to the user as literal text.
fn xml_unescape(s: &str) -> String {
    match quick_xml::escape::unescape(s) {
        Ok(v) => v.into_owned(),
        Err(_) => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_and_binding() {
        let env = Envelope::new(
            "hello <pq> world & co",
            "alice@example.com",
            "bob@example.com",
            Some("2026-05-27T12:34:56Z".into()),
            "",
        );
        let xml = env.to_xml();
        let parsed = Envelope::from_xml(&xml).expect("parse");

        assert_eq!(parsed.from, "alice@example.com");
        assert_eq!(parsed.to, "bob@example.com");
        assert_eq!(parsed.time.as_deref(), Some("2026-05-27T12:34:56Z"));
        assert_eq!(parsed.body().as_deref(), Some("hello <pq> world & co"));

        parsed.verify_binding("bob@example.com", "alice@example.com").unwrap();
        assert!(parsed.verify_binding("eve@example.com", "alice@example.com").is_err());
    }

    /// An attribute value containing a raw apostrophe, exactly as Android's serializer emits it
    /// (double-quoted, `'` not escaped — its escape trigger is `<`, `&`, `"` and control chars).
    /// `content_inner` is re-parsed downstream, so the reconstruction has to stay well-formed;
    /// before the fix this produced `rdf:about='https://x.test/it's'` and the re-parse failed,
    /// losing the entire message.
    #[test]
    fn attribute_with_raw_apostrophe_reparses() {
        let xml = concat!(
            "<envelope xmlns='urn:xmpp:sce:1'><content>",
            "<body xmlns=\"jabber:client\">hi</body>",
            "<Description xmlns=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"",
            " about=\"https://x.test/what's-new?a=1&amp;b=2\"/>",
            "</content><time stamp='2026-08-10T10:00:00Z'/>",
            "<from jid='alice@example.com'/><to jid='bob@example.com'/></envelope>"
        );
        let parsed = Envelope::from_xml(xml).expect("envelope parses");

        // The downstream re-parse (messaging.rs wraps content_inner in a <content> element).
        let wrapped = format!("<content xmlns='jabber:client'>{}</content>", parsed.content_inner);
        let el: minidom::Element = wrapped.parse().expect("content re-parses");

        let desc = el
            .children()
            .find(|c| c.name() == "Description")
            .expect("Description survived");
        // And the value itself round-trips: the `&amp;` must not have become `&amp;amp;`.
        assert_eq!(desc.attr("about"), Some("https://x.test/what's-new?a=1&b=2"));
        assert_eq!(parsed.body().as_deref(), Some("hi"));
    }

    /// `<to>`/`<from>`/`<time>` are affixes of the envelope, not content. An element with one of
    /// those names inside `<content>` must stay content and must not move the binding or replay
    /// check onto a value chosen by whoever wrote the envelope.
    #[test]
    fn affix_names_inside_content_do_not_override_the_affixes() {
        let xml = concat!(
            "<envelope xmlns='urn:xmpp:sce:1'><content>",
            "<body xmlns='jabber:client'>hi</body>",
            "<to jid='mallory@evil.test'/><from jid='mallory@evil.test'/>",
            "<time stamp='1999-01-01T00:00:00Z'/>",
            "</content><time stamp='2026-08-10T10:00:00Z'/>",
            "<from jid='alice@example.com'/><to jid='bob@example.com'/></envelope>"
        );
        let parsed = Envelope::from_xml(xml).expect("envelope parses");

        assert_eq!(parsed.from, "alice@example.com");
        assert_eq!(parsed.to, "bob@example.com");
        assert_eq!(parsed.time.as_deref(), Some("2026-08-10T10:00:00Z"));
        parsed.verify_binding("bob@example.com", "alice@example.com").unwrap();
        // …and they are still delivered as content rather than swallowed.
        assert!(parsed.content_inner.contains("mallory@evil.test"));
    }

    /// The predefined entities and numeric references all have to survive into the displayed
    /// body; the old hand-rolled unescape knew only `&lt;`, `&gt;` and `&amp;`.
    #[test]
    fn body_resolves_all_entity_forms() {
        let xml = concat!(
            "<envelope xmlns='urn:xmpp:sce:1'><content>",
            "<body xmlns='jabber:client'>it&apos;s &quot;quoted&quot; &#39;n &amp; 5&lt;6</body>",
            "</content><time stamp='2026-08-10T10:00:00Z'/>",
            "<from jid='alice@example.com'/><to jid='bob@example.com'/></envelope>"
        );
        let parsed = Envelope::from_xml(xml).expect("envelope parses");
        assert_eq!(parsed.body().as_deref(), Some("it's \"quoted\" 'n & 5<6"));
    }

    /// Our own serializer emits `'`-delimited attributes, so a value containing an apostrophe
    /// has to be escaped on the way out too.
    #[test]
    fn our_own_output_escapes_the_attribute_delimiter() {
        let env = Envelope::new(
            "it's fine",
            "alice@example.com",
            "bob@example.com",
            Some("2026-08-10T10:00:00Z".into()),
            "<x xmlns='urn:x' u='a&amp;b'/>",
        );
        let parsed = Envelope::from_xml(&env.to_xml()).expect("round trip");
        assert_eq!(parsed.body().as_deref(), Some("it's fine"));
        let wrapped = format!("<content xmlns='jabber:client'>{}</content>", parsed.content_inner);
        let el: minidom::Element = wrapped.parse().expect("content re-parses");
        assert_eq!(
            el.children().find(|c| c.name() == "x").and_then(|c| c.attr("u")),
            Some("a&b")
        );
    }

    #[test]
    fn envelope_is_bucket_padded() {
        for body_len in [0usize, 1, 17, 200, 255, 256, 300, 1000] {
            let body: String = "x".repeat(body_len);
            let env = Envelope::new(
                &body,
                "alice@example.com",
                "bob@example.com",
                Some("2026-05-27T12:34:56Z".into()),
                "",
            );
            let xml = env.to_xml();
            assert_eq!(
                xml.len() % PAD_BUCKET,
                0,
                "envelope with body_len={body_len} not on a {PAD_BUCKET}-byte boundary (len {})",
                xml.len()
            );
        }
        // Large envelopes land exactly on their Padmé size class.
        for body_len in [5000usize, 70_000] {
            let env = Envelope::new(&"x".repeat(body_len), "a@b.c", "d@e.f", None, "");
            let xml = env.to_xml();
            assert_eq!(xml.len(), padded_envelope_length(xml.len() - 1), "body_len={body_len}");
        }
    }

    /// Known answers shared with Android's `paddedEnvelopeLengthKnownAnswers` and the proto-XEP.
    #[test]
    fn padded_envelope_length_known_answers() {
        for (unpadded, padded) in [
            (0, 256), (1, 256), (255, 256), (256, 512), (1000, 1024), (4095, 4096),
            (4096, 4352), (4097, 4352), (5000, 5120), (10000, 10240), (65536, 67584),
            (100000, 100352), (1000000, 1015808),
        ] {
            assert_eq!(padded_envelope_length(unpadded), padded, "unpadded {unpadded}");
        }
    }
}
