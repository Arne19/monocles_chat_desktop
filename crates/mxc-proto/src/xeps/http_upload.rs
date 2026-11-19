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

/// The client for uploads (PUT to the account's own upload slot).
fn http_client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| build_client(false))
}

/// The client for downloads from sender-chosen URLs: like [`http_client`], but every host name
/// (also of each redirect hop) goes through [`PublicOnlyResolver`].
fn download_client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| build_client(true))
}

fn build_client(public_only: bool) -> reqwest::Client {
    let builder = reqwest::Client::builder();
    let builder = if public_only {
        builder.dns_resolver(std::sync::Arc::new(PublicOnlyResolver {
            // Not std::env::vars(): it panics on any non-UTF-8 variable. Such ones are skipped
            // (hyper-util ignores a non-UTF-8 proxy value as well).
            proxy_hosts: env_proxy_hosts_from(
                std::env::vars_os()
                    .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))),
            ),
        }))
    } else {
        builder
    };
    // The system's roots minus the refused ones (tls_roots). If they can't be read, keep
    // reqwest's default platform verifier as before.
    let builder = match crate::tls_roots::http_roots() {
        Some(roots) => builder.tls_certs_only(roots),
        None => builder,
    };
    builder
        // A sender-chosen server must not be able to hang a download forever.
        .connect_timeout(std::time::Duration::from_secs(20))
        .read_timeout(std::time::Duration::from_secs(60))
        // Redirects stay on HTTPS and off our own machine/LAN (see checked_url).
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                attempt.error("too many redirects")
            } else if attempt.url().scheme() != "https" || is_local_target(attempt.url()) {
                attempt.error("refusing redirect to a non-https or local address")
            } else if is_hidden_target(attempt.url()) {
                attempt.error("refusing redirect to a Tor/I2P hidden service (not supported)")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .expect("reqwest client")
}

/// Resolves download hosts with the system resolver (as reqwest's default does) and refuses a
/// name if any of its addresses is local ([`is_local_ip`]): a public name pointing at (or
/// rebinding to) a LAN or loopback address must not turn a sender's file URL into a request to
/// a local service. reqwest connects to exactly the addresses returned here, so a second lookup
/// can't swap them.
///
/// reqwest also honours the `HTTP(S)_PROXY`/`ALL_PROXY` environment variables, and then resolves
/// the proxy's name here, while the proxy resolves the target. The proxy's own name (often
/// `localhost` or a LAN host) is therefore let through, or every download would fail; the
/// local-address check thus applies to direct connections, as on Android.
struct PublicOnlyResolver {
    /// Host names of the environment's HTTP(S) proxies, lower-case.
    proxy_hosts: Vec<String>,
}

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let is_proxy = self.proxy_hosts.contains(&normalize_host(&host));
        Box::pin(async move {
            let addrs = resolve_public(&host, is_proxy).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// The host names of the proxies configured in the environment (as reqwest reads them). IP
/// literals are left out: reqwest never resolves those.
fn env_proxy_hosts_from(vars: impl IntoIterator<Item = (String, String)>) -> Vec<String> {
    const KEYS: [&str; 6] =
        ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];
    let mut hosts = Vec::new();
    for (key, value) in vars {
        let value = value.trim();
        if !KEYS.contains(&key.as_str()) || value.is_empty() {
            continue;
        }
        let with_scheme =
            if value.contains("://") { value.to_string() } else { format!("http://{value}") };
        if let Ok(url) = url::Url::parse(&with_scheme) {
            // Non-special schemes (socks5://) give even an IP literal as an opaque "domain".
            if let Some(url::Host::Domain(host)) = url.host() {
                let host = normalize_host(host);
                let literal = host.trim_matches(|c| c == '[' || c == ']').parse::<std::net::IpAddr>().is_ok();
                if !literal && !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
    }
    hosts
}

async fn resolve_public(
    host: &str,
    is_proxy: bool,
) -> Result<Vec<std::net::SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    // Never reached for them (checked_url and the redirect policy refuse first), but a hidden
    // service name must never go to the system resolver.
    if crate::hidden::is_hidden_service_host(host) {
        return Err(format!("not resolving Tor/I2P hidden-service name {host}").into());
    }
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, 0)).await?.collect();
    if is_proxy {
        // the user's own proxy, which carries all their traffic anyway
        return Ok(addrs);
    }
    refuse_local(host, addrs)
}

fn refuse_local(
    host: &str,
    addrs: Vec<std::net::SocketAddr>,
) -> Result<Vec<std::net::SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    if addrs.iter().any(|a| is_local_ip(a.ip())) {
        return Err(format!("refusing download from {host}: resolves to a local address").into());
    }
    Ok(addrs)
}

/// Loopback, private (RFC 1918, ULA, CGNAT), link-local, unspecified, broadcast and multicast
/// addresses, including IPv4-mapped IPv6 forms (as Android's `HttpConnectionManager.isLocalAddress`).
fn is_local_ip(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    fn v4_local(ip: Ipv4Addr) -> bool {
        ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_unspecified()
            || ip.is_broadcast()
            || ip.is_multicast()
            || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64) // 100.64.0.0/10 (CGNAT)
    }
    fn v6_local(ip: Ipv6Addr) -> bool {
        let seg0 = ip.segments()[0];
        ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || (seg0 & 0xfe00) == 0xfc00 // unique local fc00::/7
            || (seg0 & 0xffc0) == 0xfe80 // link-local fe80::/10
            || ip.to_ipv4_mapped().is_some_and(v4_local)
    }
    match ip {
        IpAddr::V4(ip) => v4_local(ip),
        IpAddr::V6(ip) => v6_local(ip),
    }
}

/// Whether `url`'s host is a `.onion`/`.i2p` name: unreachable without Tor/I2P, and resolving it
/// through the system resolver would leak it (see crate::hidden).
fn is_hidden_target(url: &url::Url) -> bool {
    matches!(url.host(), Some(url::Host::Domain(host)) if crate::hidden::is_hidden_service_host(host))
}

/// Whether `url` points at this machine or a private/link-local network. File URLs come from
/// message senders; fetching them (often automatically) must not turn us into a client for
/// probing or poking services on our LAN (router admin pages, local daemons, ...). Literal
/// addresses and local names here; a public name resolving to a local address is refused when it
/// is resolved (download_client's [`PublicOnlyResolver`]).
fn is_local_target(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost") || d.ends_with(".local")
        }
        Some(url::Host::Ipv4(ip)) => is_local_ip(ip.into()),
        Some(url::Host::Ipv6(ip)) => is_local_ip(ip.into()),
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
    if is_hidden_target(&url) {
        anyhow::bail!("refusing Tor/I2P hidden-service url: not supported");
    }
    Ok(url)
}

/// GET `url` into memory, refusing anything larger than `max` bytes - checked against the
/// announced Content-Length and again while streaming, since a server may lie or send none.
async fn fetch_capped(url: url::Url, max: u64) -> anyhow::Result<Vec<u8>> {
    let mut resp = download_client().get(url).send().await?;
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
    // Both URLs must be https: the file (or its ciphertext) and the link we hand out must not go
    // over plain HTTP. No local-address check here: the slot comes from our own server's upload
    // service, and self-hosted servers on a LAN legitimately hand out LAN addresses.
    for u in [&put_url, &get_url] {
        let parsed = url::Url::parse(u).map_err(|e| anyhow::anyhow!("bad upload slot url: {e}"))?;
        if parsed.scheme() != "https" {
            anyhow::bail!("refusing non-https upload slot url");
        }
        if is_hidden_target(&parsed) {
            anyhow::bail!("refusing Tor/I2P hidden-service upload slot url: not supported");
        }
    }
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

/// The content type a PQ OMEMO2 file is uploaded with: the upload service only ever stores
/// ciphertext, and what kind of file it is travels inside the encryption (XEP-0447
/// `<file-sharing/>`), like its name and size. Same as monocles Android.
pub const OPAQUE_MIME: &str = "application/octet-stream";

/// A random upload name for a PQ OMEMO2 file: 32 hex characters, no extension, nothing taken
/// from the file or the message.
pub fn opaque_upload_name() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// [`upload_encrypted`] for a file shared in a chat. In a PQ OMEMO2 chat the upload service
/// learns neither the name nor the type ([`opaque_upload_name`], [`OPAQUE_MIME`]); the receiver
/// gets both from the encrypted `<file-sharing/>`. Otherwise the file's own name and type are
/// used, which an unencrypted chat shows anyway.
pub async fn upload_shared_file(
    w: &Writer,
    cfg: &AccountConfig,
    bytes: &[u8],
    filename: &str,
    content_type: &str,
    omemo2: bool,
) -> anyhow::Result<String> {
    if omemo2 {
        upload_encrypted(w, cfg, bytes, &opaque_upload_name(), OPAQUE_MIME).await
    } else {
        upload_encrypted(w, cfg, bytes, filename, content_type).await
    }
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
        "mov" => "video/quicktime",
        "3gp" => "video/3gpp",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
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
            "https://abcdef.onion/x",
            "https://upload.example.i2p/x",
            "https://ABCDEF.ONION./x",
        ] {
            assert!(checked_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn local_ip_classification() {
        for local in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
            "0.0.0.0", "255.255.255.255", "224.0.0.1", "::1", "::", "fe80::1", "fd00::1", "ff02::1",
            "::ffff:192.168.0.1",
        ] {
            assert!(is_local_ip(local.parse().unwrap()), "{local}");
        }
        for public in ["93.184.216.34", "2606:4700::1111", "100.128.0.1"] {
            assert!(!is_local_ip(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn any_local_address_refuses_the_name() {
        let public: std::net::SocketAddr = "93.184.216.34:0".parse().unwrap();
        let lan: std::net::SocketAddr = "192.168.1.1:0".parse().unwrap();
        assert!(refuse_local("files.example.org", vec![public]).is_ok());
        assert!(refuse_local("files.example.org", vec![public, lan]).is_err());
    }

    #[tokio::test]
    async fn resolver_refuses_names_resolving_locally() {
        // localhost resolves offline (hosts file) to loopback.
        assert!(resolve_public("localhost", false).await.is_err());
        // a hidden service name is refused before any lookup, even as a "proxy"
        assert!(resolve_public("abcdef.onion", false).await.is_err());
        assert!(resolve_public("abcdef.onion", true).await.is_err());
    }

    #[tokio::test]
    async fn the_environment_proxy_may_be_local() {
        use reqwest::dns::Resolve;
        let with_proxy = PublicOnlyResolver { proxy_hosts: vec!["localhost".to_string()] };
        assert!(with_proxy.resolve("localhost".parse().unwrap()).await.is_ok());
        let without = PublicOnlyResolver { proxy_hosts: Vec::new() };
        assert!(without.resolve("localhost".parse().unwrap()).await.is_err());
    }

    #[test]
    fn proxy_hosts_from_environment() {
        let vars = [
            ("HTTPS_PROXY", "localhost:3128"),
            ("http_proxy", "http://Proxy.Corp.:8080/"),
            ("ALL_PROXY", "socks5://127.0.0.1:1080"),
            ("all_proxy", "  "),
            ("HTTP_PROXY", "::not a url::"),
            ("NO_PROXY", "intranet.example"),
            ("PATH", "/usr/bin"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        assert_eq!(env_proxy_hosts_from(vars), vec!["localhost".to_string(), "proxy.corp".to_string()]);
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
