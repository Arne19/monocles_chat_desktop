//! XEP-0231 Bits of Binary (`urn:xmpp:bob`) — used for **inline stickers**.
//!
//! monocles Android sends a small sticker (≤100 KiB) by embedding its raw bytes as a
//! `<data xmlns='urn:xmpp:bob' cid='…'>base64</data>` element *inside* the encrypted
//! XEP-0420 SCE envelope, so the image is fully end-to-end encrypted and never touches an
//! HTTP upload server. The content-id (`cid`) is a XEP-0231 reference of the form
//! `sha-256+<hex>@bob.xmpp.org` (matching Android's `BobTransfer`/`CryptoHelper`, which uses
//! the SHA-256 digest as the first/preferred cid). Larger stickers fall back to a normal
//! encrypted file upload.
//!
//! This module owns the cid computation, the `<data>` (de)serialization, and an on-disk
//! cache so the bytes survive past the one message that carried them (the UI renders the
//! sticker out of this cache, keyed by the cid).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use minidom::Element;
use sha2::{Digest, Sha256};

pub const NS_BOB: &str = "urn:xmpp:bob";

/// Inline-embed cutoff: stickers at or below this size go inline (BoB); larger ones use an
/// encrypted HTTP upload. Matches monocles Android's 100 KiB threshold.
pub const MAX_INLINE: usize = 100 * 1024;

/// The XEP-0231 content-id (scheme-specific part) for `bytes`: `sha-256+<hex>@bob.xmpp.org`.
/// This is what goes in the `<data cid>` attribute and (prefixed with `cid:`) in `<img src>`.
pub fn cid_ssp(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha-256+{}@bob.xmpp.org", hex::encode(digest))
}

/// The full `cid:` URI for `bytes` (the form used as a message body / `<img src>`).
pub fn cid_uri(bytes: &[u8]) -> String {
    format!("cid:{}", cid_ssp(bytes))
}

/// Build the `<data xmlns='urn:xmpp:bob' …>base64</data>` element carrying `bytes`.
pub fn data_element(cid_ssp: &str, mime: &str, bytes: &[u8]) -> Element {
    Element::builder("data", NS_BOB)
        .attr(crate::ncname("cid"), cid_ssp)
        .attr(crate::ncname("type"), mime)
        .attr(crate::ncname("max-age"), "86400")
        .append(B64.encode(bytes))
        .build()
}

/// The XHTML-IM wrapper monocles Android renders the sticker from: an `<img src='cid:…'/>`.
/// We send it alongside the BoB data so Android clients display the sticker inline.
pub fn xhtml_img(cid_uri: &str) -> Element {
    let img = Element::builder("img", "http://www.w3.org/1999/xhtml")
        .attr(crate::ncname("src"), cid_uri)
        .build();
    let body = Element::builder("body", "http://www.w3.org/1999/xhtml")
        .append(img)
        .build();
    Element::builder("html", "http://jabber.org/protocol/xhtml-im")
        .append(body)
        .build()
}

/// Extract `(cid_ssp, bytes)` from a received `<data xmlns='urn:xmpp:bob'>` element.
pub fn parse_data(el: &Element) -> Option<(String, Vec<u8>)> {
    if el.name() != "data" || el.ns() != NS_BOB {
        return None;
    }
    let cid = el.attr("cid")?.to_string();
    let bytes = B64.decode(el.text().trim()).ok()?;
    Some((cid, bytes))
}

/// The SHA-256 hex out of a `cid:sha-256+<hex>@bob.xmpp.org` URI (or its scheme-specific part).
/// Returns `None` for cids that aren't SHA-256 (we only key the cache by SHA-256).
fn cid_hex(cid: &str) -> Option<String> {
    let ssp = cid.strip_prefix("cid:").unwrap_or(cid);
    let (algo, rest) = ssp.split_once('+')?;
    if !algo.eq_ignore_ascii_case("sha-256") {
        return None;
    }
    let hex = rest.split('@').next()?;
    if hex.is_empty() {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

/// The on-disk cache path for a sticker, keyed by its cid's SHA-256 hex (deterministic, so
/// both the proto layer that saves the bytes and the UI that renders them agree). Returns
/// `None` for non-`cid:` / non-SHA-256 references.
pub fn cache_path(cid: &str) -> Option<std::path::PathBuf> {
    let hex = cid_hex(cid)?;
    Some(cache_dir().join(hex))
}

/// The sticker cache directory (files in it are encrypted, see `mxc_store::cache`).
pub fn cache_dir() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            std::path::PathBuf::from(home).join(".cache")
        });
    base.join("monocles-chat").join("bob")
}

/// Every sticker reference in the XHTML-IM `<html>` payload's `<img>` elements, as
/// `(cid_ssp, alt)` — the cid's scheme-specific part (`sha-256+<hex>@bob.xmpp.org`) and the
/// `alt` text (the `:shortcode:` fallback, if any). monocles Android sends stickers/custom-emoji
/// *by reference* this way — the bytes are fetched separately via [`fetch`] — and the `alt`
/// marks where in the body text the sticker belongs.
pub fn img_refs(content: &Element) -> Vec<(String, Option<String>)> {
    fn walk(el: &Element, out: &mut Vec<(String, Option<String>)>) {
        if el.name() == "img" {
            if let Some(ssp) = el.attr("src").and_then(|s| s.strip_prefix("cid:")) {
                if !out.iter().any(|(c, _)| c == ssp) {
                    let alt = el.attr("alt").filter(|a| !a.is_empty()).map(String::from);
                    out.push((ssp.to_string(), alt));
                }
            }
        }
        for c in el.children() {
            walk(c, out);
        }
    }
    let mut out = Vec::new();
    if let Some(html) = content.get_child("html", "http://jabber.org/protocol/xhtml-im") {
        walk(html, &mut out);
    }
    out
}

/// Just the cids from [`img_refs`].
pub fn img_cids(content: &Element) -> Vec<String> {
    img_refs(content).into_iter().map(|(c, _)| c).collect()
}

/// XEP-0231 BoB fetch: request the bytes for `cid_ssp` from `to_full` (the sender's *full*
/// JID — BoB data is per-session) and return them. Used to retrieve a referenced sticker that
/// wasn't carried inline. Mirrors monocles Android's `BobTransfer`.
pub async fn fetch(
    w: &crate::client::Writer,
    to_full: &str,
    cid_ssp: &str,
) -> anyhow::Result<Vec<u8>> {
    let id = crate::xeps::roster::new_id("bob");
    let iq = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("to"), to_full)
        .attr(crate::ncname("id"), &id)
        .append(Element::builder("data", NS_BOB).attr(crate::ncname("cid"), cid_ssp).build())
        .build();
    let reply = crate::xeps::iq::request(w, iq).await?;
    let data = reply
        .get_child("data", NS_BOB)
        .ok_or_else(|| anyhow::anyhow!("BoB reply missing <data>"))?;
    let (_, bytes) =
        parse_data(data).ok_or_else(|| anyhow::anyhow!("BoB reply <data> unparseable"))?;
    Ok(bytes)
}

/// Whether `cid` (a `cid:`/ssp reference) already has its bytes in the local cache.
pub fn is_cached(cid: &str) -> bool {
    cache_path(cid).map(|p| p.exists()).unwrap_or(false)
}

/// Persist sticker `bytes` into the (encrypted) cache under `cid` (no-op if already present).
pub fn save(cid: &str, bytes: &[u8]) -> std::io::Result<()> {
    let Some(path) = cache_path(cid) else {
        return Ok(());
    };
    if path.exists() {
        return Ok(());
    }
    mxc_store::cache::write(&path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_round_trips_through_cache_path() {
        let bytes = b"sticker-bytes";
        let ssp = cid_ssp(bytes);
        assert!(ssp.starts_with("sha-256+") && ssp.ends_with("@bob.xmpp.org"));
        let uri = cid_uri(bytes);
        assert_eq!(uri, format!("cid:{ssp}"));
        // Both the ssp and the full uri resolve to the same cache file.
        assert_eq!(cache_path(&ssp), cache_path(&uri));
        assert!(cache_path(&ssp).is_some());
        // A non-sha-256 cid has no cache path.
        assert!(cache_path("cid:sha-1+abcd@bob.xmpp.org").is_none());
    }

    #[test]
    fn survives_full_sce_envelope_round_trip() {
        // Build the sticker exactly as `send_sticker_stanza` does, push it through the SCE
        // envelope serialize → parse, then re-parse the content like the receive path, and
        // confirm the BoB bytes come back intact (catches any envelope reconstruction bug).
        use mxc_omemo::sce::Envelope;

        let bytes = vec![0u8, 1, 2, 250, 255, 13, 10, 42];
        let ssp = cid_ssp(&bytes);
        let uri = format!("cid:{ssp}");
        let extra = format!(
            "{}{}",
            String::from(&xhtml_img(&uri)),
            String::from(&data_element(&ssp, "image/png", &bytes)),
        );
        let env = Envelope::new(&uri, "a@x", "b@y", None, &extra);
        let parsed = Envelope::from_xml(&env.to_xml()).expect("parse envelope");
        assert_eq!(parsed.body().as_deref(), Some(uri.as_str()));

        let wrapped = format!("<content xmlns='jabber:client'>{}</content>", parsed.content_inner);
        let content: minidom::Element = wrapped.parse().expect("parse content");
        let data = content.get_child("data", NS_BOB).expect("find <data>");
        let (cid, decoded) = parse_data(data).expect("parse data");
        assert_eq!(cid, ssp);
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn img_cids_extracted_from_xhtml() {
        // The form monocles Android sends: body shortcode + an <html><img src="cid:…"/>, no
        // inline <data>.
        let content: Element = "<content xmlns='jabber:client'>\
            <body>:racoon_silly2:</body>\
            <html xmlns='http://jabber.org/protocol/xhtml-im'>\
            <body xmlns='http://www.w3.org/1999/xhtml'>\
            <img src='cid:sha-256+abcdef@bob.xmpp.org' alt=':racoon_silly2:'/>\
            </body></html></content>"
            .parse()
            .unwrap();
        assert_eq!(img_cids(&content), vec!["sha-256+abcdef@bob.xmpp.org".to_string()]);
    }

    #[test]
    fn data_element_round_trip() {
        let bytes = vec![1u8, 2, 3, 4, 250, 251];
        let ssp = cid_ssp(&bytes);
        let el = data_element(&ssp, "image/png", &bytes);
        let (parsed_cid, parsed_bytes) = parse_data(&el).expect("parse");
        assert_eq!(parsed_cid, ssp);
        assert_eq!(parsed_bytes, bytes);
    }
}
