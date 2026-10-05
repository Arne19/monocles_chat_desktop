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

fn http_client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| reqwest::Client::builder().build().expect("reqwest client"))
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
    let iv_len = match combo.len() {
        44 => 12,
        48 => 16,
        n => anyhow::bail!("unexpected aesgcm key length {n}"),
    };
    let (iv, key) = combo.split_at(iv_len);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("aesgcm key: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(iv), ciphertext)
        .map_err(|e| anyhow::anyhow!("aesgcm decrypt (bad key or corrupt file): {e}"))
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

/// Download an `aesgcm://` URL and decrypt it, returning the plaintext file bytes.
pub async fn download_decrypt(aesgcm_url: &str) -> anyhow::Result<Vec<u8>> {
    let (url, frag) = aesgcm_url
        .split_once('#')
        .ok_or_else(|| anyhow::anyhow!("aesgcm url has no key fragment"))?;
    let https = format!("https{}", url.strip_prefix("aesgcm").unwrap_or(url));
    let combo = hex::decode(frag).map_err(|e| anyhow::anyhow!("bad key fragment: {e}"))?;

    let resp = http_client().get(&https).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("download GET failed: HTTP {}", resp.status());
    }
    let ciphertext = resp.bytes().await?;
    aesgcm_decrypt(&combo, &ciphertext)
}

/// Download a plain (unencrypted) `http(s)://` URL, returning the raw file bytes.
pub async fn download_plain(url: &str) -> anyhow::Result<Vec<u8>> {
    let resp = http_client().get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("download GET failed: HTTP {}", resp.status());
    }
    Ok(resp.bytes().await?.to_vec())
}

/// Download a file URL, transparently handling both encrypted (`aesgcm://`) and plain
/// (`http(s)://`) links and returning the decoded file bytes.
pub async fn download_any(url: &str) -> anyhow::Result<Vec<u8>> {
    if is_aesgcm_url(url) {
        download_decrypt(url).await
    } else {
        download_plain(url).await
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
