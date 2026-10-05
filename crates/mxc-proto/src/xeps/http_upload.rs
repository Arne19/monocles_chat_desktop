//! XEP-0363 HTTP File Upload + `aesgcm://` file encryption (compatible with monocles
//! Android / Conversations).
//!
//! Sending: the file is encrypted with **AES-256-GCM** (12-byte IV, 128-bit tag appended),
//! the ciphertext is uploaded via an upload slot, and the download URL is rewritten to the
//! `aesgcm://` scheme with the fragment `hex(IV ‖ KEY)` (44 bytes). The key never touches
//! the server; it travels inside the (OMEMO2-encrypted) message body.
//!
//! Receiving: parse the `aesgcm://` URL, GET the ciphertext over https, split the fragment
//! into IV+KEY and AES-GCM-decrypt.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use minidom::Element;

use crate::client::{AccountConfig, Writer};
use crate::xeps::iq;
use crate::xeps::roster::new_id;

const NS_UPLOAD: &str = "urn:xmpp:http:upload:0";
const NS_DISCO_ITEMS: &str = "http://jabber.org/protocol/disco#items";
const NS_DISCO_INFO: &str = "http://jabber.org/protocol/disco#info";

/// Size cap for media fetched without the user asking (chat images/audio, story media).
pub const AUTO_DOWNLOAD_LIMIT: u64 = 16 * 1024 * 1024;
/// Size cap for a file the user explicitly chose to download.
pub const MANUAL_DOWNLOAD_LIMIT: u64 = 256 * 1024 * 1024;

fn http_client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            // A sender-chosen server must not be able to hang a download forever.
            .connect_timeout(std::time::Duration::from_secs(20))
            .read_timeout(std::time::Duration::from_secs(60))
            // Redirects stay on HTTPS and off our own machine/LAN (see checked_url).
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    attempt.error("too many redirects")
                } else if attempt.url().scheme() != "https" || is_local_target(attempt.url()) {
                    attempt.error("refusing redirect to a non-https or local address")
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .expect("reqwest client")
    })
}

/// Whether `url` points at this machine or a private/link-local network. File URLs come from
/// message senders; fetching them (often automatically) must not turn us into a client for
/// probing or poking services on our LAN (router admin pages, local daemons, ...). Literal
/// addresses and local names only - a public name resolving to a private address isn't caught.
fn is_local_target(url: &url::Url) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};
    fn v4_local(ip: Ipv4Addr) -> bool {
        ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_unspecified()
            || ip.is_broadcast()
            || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64) // 100.64.0.0/10 (CGNAT)
    }
    fn v6_local(ip: Ipv6Addr) -> bool {
        let seg0 = ip.segments()[0];
        ip.is_loopback()
            || ip.is_unspecified()
            || (seg0 & 0xfe00) == 0xfc00 // unique local fc00::/7
            || (seg0 & 0xffc0) == 0xfe80 // link-local fe80::/10
            || ip.to_ipv4_mapped().is_some_and(v4_local)
    }
    match url.host() {
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost") || d.ends_with(".local")
        }
        Some(url::Host::Ipv4(ip)) => v4_local(ip),
        Some(url::Host::Ipv6(ip)) => v6_local(ip),
        None => true,
    }
}

/// Parse a received file URL, requiring https (XEP-0363 download URLs are https) and a
/// non-local host.
fn checked_url(raw: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(raw).map_err(|e| anyhow::anyhow!("bad file url: {e}"))?;
    if url.scheme() != "https" {
        anyhow::bail!("refusing non-https file url");
    }
    if is_local_target(&url) {
        anyhow::bail!("refusing file url pointing at a local address");
    }
    Ok(url)
}

/// GET `url` into memory, refusing anything larger than `max` bytes - checked against the
/// announced Content-Length and again while streaming, since a server may lie or send none.
async fn fetch_capped(url: url::Url, max: u64) -> anyhow::Result<Vec<u8>> {
    let mut resp = http_client().get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("download GET failed: HTTP {}", resp.status());
    }
    if let Some(len) = resp.content_length() {
        if len > max {
            anyhow::bail!("file too large ({len} bytes, limit {max})");
        }
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() as u64 + chunk.len() as u64 > max {
            anyhow::bail!("file too large (over the {max} byte limit)");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Cache of discovered upload-service JIDs, keyed by server domain.
fn service_cache() -> &'static Mutex<HashMap<String, String>> {
    static C: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A granted upload slot.
struct Slot {
    put_url: String,
    get_url: String,
    headers: Vec<(String, String)>,
}

/// Discover the server's HTTP-upload service (disco#items on the domain, then disco#info
/// on each item looking for `urn:xmpp:http:upload:0`). Cached per domain.
async fn discover_service(w: &Writer, domain: &str) -> anyhow::Result<String> {
    if let Some(s) = service_cache().lock().unwrap().get(domain).cloned() {
        return Ok(s);
    }

    let items_req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("to"), domain)
        .attr(crate::ncname("id"), new_id("disco-items"))
        .append(Element::builder("query", NS_DISCO_ITEMS).build())
        .build();
    let items_reply = iq::request(w, items_req).await?;

    let mut candidates = Vec::new();
    if let Some(query) = items_reply.get_child("query", NS_DISCO_ITEMS) {
        for item in query.children().filter(|c| c.name() == "item") {
            if let Some(jid) = item.attr("jid") {
                candidates.push(jid.to_string());
            }
        }
    }

    for jid in candidates {
        let info_req = Element::builder("iq", "jabber:client")
            .attr(crate::ncname("type"), "get")
            .attr(crate::ncname("to"), &jid)
            .attr(crate::ncname("id"), new_id("disco-info"))
            .append(Element::builder("query", NS_DISCO_INFO).build())
            .build();
        let Ok(info) = iq::request(w, info_req).await else { continue };
        if let Some(query) = info.get_child("query", NS_DISCO_INFO) {
            let has_upload = query
                .children()
                .filter(|c| c.name() == "feature")
                .any(|f| f.attr("var") == Some(NS_UPLOAD));
            if has_upload {
                service_cache().lock().unwrap().insert(domain.to_string(), jid.clone());
                return Ok(jid);
            }
        }
    }
    anyhow::bail!("no HTTP upload service (urn:xmpp:http:upload:0) found on {domain}")
}

/// Request an upload slot for a file of `size` bytes.
async fn request_slot(
    w: &Writer,
    service: &str,
    filename: &str,
    size: u64,
    content_type: &str,
) -> anyhow::Result<Slot> {
    let request = Element::builder("request", NS_UPLOAD)
        .attr(crate::ncname("filename"), filename)
        .attr(crate::ncname("size"), size.to_string())
        .attr(crate::ncname("content-type"), content_type)
        .build();
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("to"), service)
        .attr(crate::ncname("id"), new_id("slot"))
        .append(request)
        .build();
    let reply = iq::request(w, req).await?;

    let slot = reply
        .get_child("slot", NS_UPLOAD)
        .ok_or_else(|| anyhow::anyhow!("upload slot response missing <slot>"))?;
    let put = slot.get_child("put", NS_UPLOAD).ok_or_else(|| anyhow::anyhow!("no <put>"))?;
    let get = slot.get_child("get", NS_UPLOAD).ok_or_else(|| anyhow::anyhow!("no <get>"))?;
    let put_url = put.attr("url").ok_or_else(|| anyhow::anyhow!("no put url"))?.to_string();
    let get_url = get.attr("url").ok_or_else(|| anyhow::anyhow!("no get url"))?.to_string();
    let headers = allowed_headers(put);
    Ok(Slot { put_url, get_url, headers })
}

/// AES-256-GCM encrypt; returns `(iv‖key combo (44 bytes), ciphertext‖tag)`.
/// XEP-0363 §5: only `Authorization`, `Cookie` and `Expires` may be taken from the slot, and
/// their values must not contain newlines (header injection). Everything else the service
/// sends is dropped, like Conversations' `Put.ALLOWED_HEADERS`.
fn allowed_headers(put: &Element) -> Vec<(String, String)> {
    const ALLOWED: [&str; 3] = ["Authorization", "Cookie", "Expires"];
    put.children()
        .filter(|c| c.name() == "header")
        .filter_map(|h| {
            let name = ALLOWED.iter().find(|a| h.attr("name").is_some_and(|n| n.eq_ignore_ascii_case(a)))?;
            let value = h.text();
            if value.contains(['\r', '\n']) {
                return None;
            }
            Some((name.to_string(), value))
        })
        .collect()
}

fn aesgcm_encrypt(plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use rand::RngCore;
    let mut combo = [0u8; 44]; // 12-byte IV + 32-byte key
    rand::rng().fill_bytes(&mut combo);
    let (iv, key) = combo.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("aesgcm key: {e}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(iv), plaintext)
        .map_err(|e| anyhow::anyhow!("aesgcm encrypt: {e}"))?;
    Ok((combo.to_vec(), ciphertext))
}

/// AES-256-GCM decrypt using an iv‖key combo (44 bytes = 12-IV, or 48 = 16-IV).
fn aesgcm_decrypt(combo: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    // The fragment is IV ‖ KEY: a 12-byte IV (current clients) or a 16-byte one (older
    // Conversations-based clients). Aes256Gcm's nonce is 12 bytes - handing it 16 used to
    // panic - so the 16-byte variant needs its own cipher type.
    type Aes256Gcm16 = aes_gcm::AesGcm<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U16>;
    let err = |e: aes_gcm::Error| anyhow::anyhow!("aesgcm decrypt (bad key or corrupt file): {e}");
    match combo.len() {
        44 => {
            let (iv, key) = combo.split_at(12);
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("aesgcm key: {e}"))?;
            cipher.decrypt(Nonce::from_slice(iv), ciphertext).map_err(err)
        }
        48 => {
            let (iv, key) = combo.split_at(16);
            let cipher = Aes256Gcm16::new_from_slice(key).map_err(|e| anyhow::anyhow!("aesgcm key: {e}"))?;
            cipher.decrypt(aes_gcm::aead::generic_array::GenericArray::from_slice(iv), ciphertext).map_err(err)
        }
        n => anyhow::bail!("unexpected aesgcm key length {n}"),
    }
}

/// Rewrite an `https://` get URL into an `aesgcm://` URL carrying the key in the fragment.
fn to_aesgcm_url(get_url: &str, combo: &[u8]) -> String {
    let body = get_url.strip_prefix("https").unwrap_or(get_url);
    format!("aesgcm{body}#{}", hex::encode(combo))
}

/// Whether `s` looks like an `aesgcm://` URL we can download + decrypt.
pub fn is_aesgcm_url(s: &str) -> bool {
    s.starts_with("aesgcm://") && s.contains('#')
}

/// Encrypt + upload `bytes` and return the `aesgcm://` URL to share.
pub async fn upload_encrypted(
    w: &Writer,
    cfg: &AccountConfig,
    bytes: &[u8],
    filename: &str,
    content_type: &str,
) -> anyhow::Result<String> {
    let domain = cfg.bare().split('@').nth(1).unwrap_or(cfg.bare()).to_string();
    let service = discover_service(w, &domain).await?;

    let (combo, ciphertext) = aesgcm_encrypt(bytes)?;
    let slot = request_slot(w, &service, filename, ciphertext.len() as u64, content_type).await?;

    let mut req = http_client().put(&slot.put_url).header("Content-Type", content_type);
    for (name, value) in &slot.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req.body(ciphertext).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("upload PUT failed: HTTP {}", resp.status());
    }
    Ok(to_aesgcm_url(&slot.get_url, &combo))
}

/// Upload `bytes` **unencrypted** and return the plain `https://` GET URL. Used for Stories,
/// which are broadcast to contacts (presence access), not encrypted per-recipient.
pub async fn upload_plain(
    w: &Writer,
    cfg: &AccountConfig,
    bytes: &[u8],
    filename: &str,
    content_type: &str,
) -> anyhow::Result<String> {
    let domain = cfg.bare().split('@').nth(1).unwrap_or(cfg.bare()).to_string();
    let service = discover_service(w, &domain).await?;
    let slot = request_slot(w, &service, filename, bytes.len() as u64, content_type).await?;

    let mut req = http_client().put(&slot.put_url).header("Content-Type", content_type);
    for (name, value) in &slot.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req.body(bytes.to_vec()).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("upload PUT failed: HTTP {}", resp.status());
    }
    Ok(slot.get_url)
}

/// Download an `aesgcm://` URL (at most `max` bytes) and decrypt it, returning the plaintext.
pub async fn download_decrypt(aesgcm_url: &str, max: u64) -> anyhow::Result<Vec<u8>> {
    let (url, frag) = aesgcm_url
        .split_once('#')
        .ok_or_else(|| anyhow::anyhow!("aesgcm url has no key fragment"))?;
    let https = format!("https{}", url.strip_prefix("aesgcm").unwrap_or(url));
    let combo = hex::decode(frag).map_err(|e| anyhow::anyhow!("bad key fragment: {e}"))?;
    let ciphertext = fetch_capped(checked_url(&https)?, max).await?;
    aesgcm_decrypt(&combo, &ciphertext)
}

/// Download a plain (unencrypted) `https://` URL (at most `max` bytes).
pub async fn download_plain(url: &str, max: u64) -> anyhow::Result<Vec<u8>> {
    fetch_capped(checked_url(url)?, max).await
}

/// Download a received file URL - encrypted (`aesgcm://`) or plain `https://` - refusing
/// anything over `max` bytes ([`AUTO_DOWNLOAD_LIMIT`] / [`MANUAL_DOWNLOAD_LIMIT`]).
pub async fn download_any(url: &str, max: u64) -> anyhow::Result<Vec<u8>> {
    if is_aesgcm_url(url) {
        download_decrypt(url, max).await
    } else {
        download_plain(url, max).await
    }
}

/// Best-effort content type from a filename extension.
pub fn guess_mime(filename: &str) -> &'static str {
    let ext = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "log" => "text/plain",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn only_allowed_headers_survive() {
        let put: Element = "<put xmlns='urn:xmpp:http:upload:0' url='https://u/x'>\
            <header name='authorization'>Basic abc</header>\
            <header name='Cookie'>a=b</header>\
            <header name='Host'>evil.example</header>\
            <header name='Expires'>Tue\nX-Injected: 1</header>\
            </put>"
            .parse()
            .unwrap();
        assert_eq!(
            allowed_headers(&put),
            vec![("Authorization".to_string(), "Basic abc".to_string()), ("Cookie".to_string(), "a=b".to_string())]
        );
    }
}

#[cfg(test)]
mod download_tests {
    use super::*;

    #[test]
    fn only_public_https_urls_are_fetched() {
        assert!(checked_url("https://upload.example.org/a/b.jpg").is_ok());
        for bad in [
            "http://upload.example.org/a.jpg",
            "file:///etc/passwd",
            "https://localhost/x",
            "https://printer.local/x",
            "https://127.0.0.1/x",
            "https://192.168.1.1/admin",
            "https://10.0.0.5/x",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.1.1/x",
            "https://[::1]/x",
            "https://[fd00::1]/x",
            "https://[::ffff:192.168.0.1]/x",
        ] {
            assert!(checked_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn aesgcm_accepts_12_and_16_byte_ivs() {
        use aes_gcm::aead::generic_array::GenericArray;
        type Aes256Gcm16 = aes_gcm::AesGcm<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U16>;
        let key = [7u8; 32];
        // 12-byte IV (current format)
        let iv12 = [1u8; 12];
        let ct = Aes256Gcm::new_from_slice(&key).unwrap().encrypt(Nonce::from_slice(&iv12), &b"hi"[..]).unwrap();
        let combo: Vec<u8> = iv12.iter().chain(key.iter()).copied().collect();
        assert_eq!(aesgcm_decrypt(&combo, &ct).unwrap(), b"hi");
        // 16-byte IV (older clients) - used to panic
        let iv16 = [2u8; 16];
        let ct = Aes256Gcm16::new_from_slice(&key).unwrap().encrypt(GenericArray::from_slice(&iv16), &b"yo"[..]).unwrap();
        let combo: Vec<u8> = iv16.iter().chain(key.iter()).copied().collect();
        assert_eq!(aesgcm_decrypt(&combo, &ct).unwrap(), b"yo");
        assert!(aesgcm_decrypt(&[0u8; 40], &ct).is_err());
    }
}
