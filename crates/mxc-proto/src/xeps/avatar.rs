//! XEP-0084 user avatars + XEP-0172 nick, via PEP.
//!
//! Avatar fetch is two-step: read `urn:xmpp:avatar:metadata` for the current `<info id>`
//! (the image's SHA-1), then read that item from `urn:xmpp:avatar:data`. Both are
//! triggered on demand (e.g. opening a chat) or by a PEP `+notify`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use async_channel::Sender;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::client::{AccountConfig, Writer};
use crate::event::Event;
use crate::xeps::{pep, vcard};

/// Last avatar hash (XEP-0153 `vcard-temp:x:update`) seen per JID, to fetch only on change.
static AVATAR_HASHES: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

/// Record `hash` for `jid`; returns true only if it's a *genuine change* from a previously
/// known hash (so the caller should re-fetch for a live update). First sight is recorded
/// silently and returns false — the initial avatar is loaded via the explicit fetch paths.
pub fn avatar_hash_changed(jid: &str, hash: &str) -> bool {
    let map = AVATAR_HASHES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map.lock().unwrap();
    match map.get(jid) {
        Some(prev) if prev == hash => false,
        Some(_) => {
            map.insert(jid.to_string(), hash.to_string());
            true
        }
        None => {
            map.insert(jid.to_string(), hash.to_string());
            false
        }
    }
}

/// Fetch the best available avatar for `jid` and emit [`Event::Avatar`] (empty `data` = none).
/// Rooms use the vCard photo; contacts try PEP (XEP-0084) then fall back to vCard (XEP-0153).
pub async fn fetch_best(
    w: &Writer,
    events: &Sender<Event>,
    account_id: i64,
    jid: &str,
    is_muc: bool,
) {
    let data = if is_muc {
        vcard::fetch_photo(w, jid).await.ok().flatten().unwrap_or_default()
    } else {
        match pep_photo(w, jid).await {
            Ok(Some(bytes)) => bytes,
            _ => vcard::fetch_photo(w, jid).await.ok().flatten().unwrap_or_default(),
        }
    };
    let _ = events.send(Event::Avatar { account_id, jid: jid.to_string(), data }).await;
}

/// Lowercase hex SHA-1 — the identifier XEP-0084 and XEP-0153 use for avatar images.
pub fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    Sha1::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Live update for a contact whose presence advertised avatar `hash` (XEP-0153): the PEP avatar
/// (self-verifying via its id) or else the vCard photo, which must hash to `hash` — otherwise
/// nothing is emitted and the current avatar stays (Conversations: "Hash in vCard update did
/// not match").
pub async fn fetch_for_hash(w: &Writer, events: &Sender<Event>, account_id: i64, jid: &str, hash: &str) {
    let data = match pep_photo(w, jid).await {
        Ok(Some(bytes)) => bytes,
        _ => match vcard::fetch_photo(w, jid).await.ok().flatten() {
            Some(bytes) if sha1_hex(&bytes).eq_ignore_ascii_case(hash) => bytes,
            Some(_) => {
                tracing::warn!(%jid, "vCard avatar does not match advertised hash; ignoring");
                return;
            }
            None => return,
        },
    };
    let _ = events.send(Event::Avatar { account_id, jid: jid.to_string(), data }).await;
}

pub const NODE_METADATA: &str = "urn:xmpp:avatar:metadata";
pub const NODE_DATA: &str = "urn:xmpp:avatar:data";
pub const NS_METADATA: &str = "urn:xmpp:avatar:metadata";
pub const NS_DATA: &str = "urn:xmpp:avatar:data";
pub const NODE_NICK: &str = "http://jabber.org/protocol/nick";
pub const NS_NICK: &str = "http://jabber.org/protocol/nick";

/// Fetch `jid`'s PEP (XEP-0084) avatar image bytes, if it publishes one.
pub async fn pep_photo(w: &Writer, jid: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let meta = pep::items(w, Some(jid), NODE_METADATA, Some(1)).await?;
    let Some((_, metadata)) = pep::extract_items(&meta).into_iter().next() else {
        return Ok(None);
    };
    let Some(info) = metadata.get_child("info", NS_METADATA) else {
        return Ok(None);
    };
    let Some(id) = info.attr("id") else { return Ok(None) };

    // Fetch the data item with that SHA-1 id.
    let data_reply = pep::items(w, Some(jid), NODE_DATA, None).await?;
    for (item_id, payload) in pep::extract_items(&data_reply) {
        if item_id.as_deref() == Some(id) && payload.name() == "data" {
            let raw = B64
                .decode(payload.text().trim())
                .map_err(|e| anyhow::anyhow!("avatar base64: {e}"))?;
            // XEP-0084: the item id IS the SHA-1 of the image — verify it (Conversations
            // rejects in-band avatars whose hash doesn't match).
            if !sha1_hex(&raw).eq_ignore_ascii_case(id) {
                anyhow::bail!("avatar hash mismatch for {jid}");
            }
            return Ok(Some(raw));
        }
    }
    Ok(None)
}

/// Fetch (if available) `jid`'s PEP avatar image bytes and emit an [`Event::Avatar`].
pub async fn fetch(
    w: &Writer,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    jid: &str,
) -> anyhow::Result<()> {
    if let Some(raw) = pep_photo(w, jid).await? {
        let _ = events
            .send(Event::Avatar { account_id: cfg.account_id, jid: jid.to_string(), data: raw })
            .await;
    }
    Ok(())
}

/// Fetch `jid`'s published nickname (XEP-0172), if any.
pub async fn fetch_nick(
    w: &Writer,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    jid: &str,
) -> anyhow::Result<()> {
    let reply = pep::items(w, Some(jid), NODE_NICK, Some(1)).await?;
    if let Some((_, payload)) = pep::extract_items(&reply).into_iter().next() {
        if payload.name() == "nick" {
            let _ = events
                .send(Event::NickUpdated {
                    account_id: cfg.account_id,
                    jid: jid.to_string(),
                    nick: payload.text(),
                })
                .await;
        }
    }
    Ok(())
}

/// Publish our own avatar (XEP-0084): the image bytes to `urn:xmpp:avatar:data` under their
/// SHA-1 hex id, then the pointing `<metadata><info>` under the same id. The id MUST be the
/// real SHA-1 — monocles Android verifies the fetched bytes against it and drops mismatches.
/// `data` should be pre-scaled by the caller (servers cap PEP item sizes; ~192px JPEG is the
/// Android convention).
pub async fn publish(
    w: &Writer,
    data: &[u8],
    mime: &str,
    width: u32,
    height: u32,
) -> anyhow::Result<()> {
    let id = sha1_hex(data);
    let payload = minidom::Element::builder("data", NS_DATA).append(B64.encode(data)).build();
    pep::publish(w, NODE_DATA, Some(&id), payload, Some(pep::publish_options("open"))).await?;

    let info = minidom::Element::builder("info", NS_METADATA)
        .attr(crate::ncname("id"), &id)
        .attr(crate::ncname("bytes"), data.len().to_string())
        .attr(crate::ncname("type"), mime)
        .attr(crate::ncname("width"), width.to_string())
        .attr(crate::ncname("height"), height.to_string())
        .build();
    let meta = minidom::Element::builder("metadata", NS_METADATA).append(info).build();
    pep::publish(w, NODE_METADATA, Some(&id), meta, Some(pep::publish_options("open"))).await?;
    Ok(())
}

/// Publish our own nickname (XEP-0172) — what peers show in subscription requests etc.
pub async fn publish_nick(w: &Writer, nick: &str) -> anyhow::Result<()> {
    let payload = minidom::Element::builder("nick", NODE_NICK).append(nick).build();
    pep::publish(w, NODE_NICK, Some("current"), payload, Some(pep::publish_options("open")))
        .await?;
    Ok(())
}
