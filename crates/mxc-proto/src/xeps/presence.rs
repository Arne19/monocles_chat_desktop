//! Presence: send our initial presence (with XEP-0115 caps) and track contacts'.

use async_channel::Sender;
use minidom::Element;

use mxc_store::Store;

use crate::client::{AccountConfig, Writer};
use crate::event::Event;
use crate::xeps::caps;

/// Send a presence broadcast with our availability + status message and XEP-0115 caps.
/// `show` is the RFC 6121 value ("" = available/online, else "chat"/"away"/"xa"/"dnd");
/// `status` is the free-text message (empty = none).
pub fn send_presence(w: &Writer, show: &str, status: &str) -> anyhow::Result<()> {
    let mut pres = Element::builder("presence", "jabber:client");
    if !show.is_empty() {
        pres = pres.append(Element::builder("show", "jabber:client").append(show).build());
    }
    if !status.is_empty() {
        pres = pres.append(Element::builder("status", "jabber:client").append(status).build());
    }
    pres = pres.append(caps::caps_element());
    w.send(pres.build())
}

/// Send initial available presence with caps attached (no show/status). Kept for callers that
/// just want a plain "online" broadcast; the stored show/status are sent from bootstrap.
pub fn send_initial(w: &Writer) -> anyhow::Result<()> {
    send_presence(w, "", "")
}

pub async fn handle_incoming(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    pres: &Element,
) -> anyhow::Result<()> {
    let from = match pres.attr("from") {
        Some(f) => f.to_string(),
        None => return Ok(()),
    };
    let ptype = pres.attr("type").unwrap_or("available");

    // XEP-0153: presence advertises the sender's current avatar hash. Re-fetch on a genuine
    // change (live updates) — for both 1:1 contacts and MUC occupants. Initial loads come
    // from the explicit fetch paths, so first sight here doesn't trigger a fetch.
    if let Some(photo) = pres
        .get_child("x", "vcard-temp:x:update")
        .and_then(|x| x.get_child("photo", "vcard-temp:x:update"))
    {
        let hash = photo.text();
        let is_occupant = pres.get_child("x", "http://jabber.org/protocol/muc#user").is_some();
        let bare = from.split('/').next().unwrap_or(&from).to_string();
        // Track per occupant JID (`room/nick`) in a MUC, else per contact bare JID.
        let key = if is_occupant { from.clone() } else { bare.clone() };
        if !hash.is_empty() && crate::xeps::avatar::avatar_hash_changed(&key, &hash) {
            if is_occupant {
                if let Some((room, nick)) = from.split_once('/') {
                    let data = crate::xeps::vcard::fetch_photo(w, &from)
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    // The photo must be the one the presence advertised (XEP-0153 hash).
                    if crate::xeps::avatar::sha1_hex(&data).eq_ignore_ascii_case(&hash) {
                        let _ = events
                            .send(Event::MucAvatar {
                                account_id: cfg.account_id,
                                room: room.to_string(),
                                nick: nick.to_string(),
                                data,
                            })
                            .await;
                    } else {
                        tracing::warn!(%from, "occupant vCard avatar does not match advertised hash; ignoring");
                    }
                }
            } else if !bare.eq_ignore_ascii_case(cfg.bare()) {
                crate::xeps::avatar::fetch_for_hash(w, events, cfg.account_id, &bare, &hash).await;
            }
        }
    }

    // MUC occupant presence (XEP-0045): the `<x muc#user><item>` carries each occupant's
    // affiliation and — in a non-anonymous room — their real bare JID. Track these so we can
    // build the OMEMO crypto-target list on send and resolve a sender's real JID on receive.
    // Self-presence (status 110) also tells us our own XEP-0421 occupant id.
    if let Some(x) = pres.get_child("x", "http://jabber.org/protocol/muc#user") {
        let is_self = x
            .children()
            .any(|c| c.name() == "status" && c.attr("code") == Some("110"));
        // Only for a room we actually have (Conversations ignores MUC presence for rooms it
        // hasn't joined). Creating the conversation here would let any sender spawn a fake room
        // — or pin their own JID's conversation kind to "muc", turning their later 1:1
        // messages into MUC-PMs without the SCE `<to>` binding.
        let is_our_room = match from.split_once('/') {
            Some((room, _)) => {
                store.conversation_kind(cfg.account_id, room).await.ok().flatten().as_deref() == Some("muc")
            }
            None => false,
        };
        if let Some((room, nick)) = from.split_once('/').filter(|_| is_our_room) {
            if let Ok(conv) = store.conversation_id(cfg.account_id, room, "muc").await {
                if ptype == "unavailable" {
                    let _ = store.remove_muc_occupant(conv, nick).await;
                } else if let Some(item) = x.get_child("item", "http://jabber.org/protocol/muc#user") {
                    let real = item.attr("jid").map(|j| j.split('/').next().unwrap_or(j));
                    let aff = item.attr("affiliation");
                    let _ = store.upsert_muc_occupant(conv, nick, real, aff).await;
                }
                if is_self {
                    if let Some(occ) =
                        super::origin::only_child_id(pres, "occupant-id", "urn:xmpp:occupant-id:0")
                    {
                        let _ = store.set_muc_self_occupant(conv, &occ).await;
                    }
                }
            }
        }
    }

    match ptype {
        "unavailable" => {
            store.clear_presence(cfg.account_id, &from).await?;
            let _ = events
                .send(Event::Presence {
                    account_id: cfg.account_id,
                    full_jid: from,
                    show: None,
                    status: Some("offline".into()),
                })
                .await;
        }
        "available" => {
            let show = pres.get_child("show", "jabber:client").map(|e| e.text());
            let status = pres.get_child("status", "jabber:client").map(|e| e.text());
            let priority = pres
                .get_child("priority", "jabber:client")
                .and_then(|e| e.text().parse::<i64>().ok())
                .unwrap_or(0);
            let caps_hash = pres
                .get_child("c", "http://jabber.org/protocol/caps")
                .and_then(|c| c.attr("ver").map(str::to_string));
            store
                .set_presence(
                    cfg.account_id,
                    &from,
                    show.as_deref(),
                    status.as_deref(),
                    priority,
                    caps_hash.as_deref(),
                )
                .await?;
            let _ = events
                .send(Event::Presence {
                    account_id: cfg.account_id,
                    full_jid: from,
                    show,
                    status,
                })
                .await;
        }
        // RFC 6121 subscription handshake. A bare `subscribed` we send only takes effect when
        // the contact has an *inbound* request pending — so if we silently drop their
        // `subscribe`, re-granting presence can never complete. Handle it here.
        "subscribe" => {
            // The contact asks to see our presence (RFC 6121 §3.1, mirroring Android's
            // PresenceParser): note their advertised nick, then either auto-approve (if we'd
            // pre-approved them) or surface a prompt to the user.
            let bare = from.split('/').next().unwrap_or(&from).to_string();
            let nick = pres
                .get_child("nick", "http://jabber.org/protocol/nick")
                .map(|n| n.text())
                .filter(|t| !t.is_empty());
            if let Some(n) = &nick {
                let _ = events
                    .send(Event::NickUpdated {
                        account_id: cfg.account_id,
                        jid: bare.clone(),
                        nick: n.clone(),
                    })
                    .await;
            }
            if store.take_presence_preapproval(cfg.account_id, &bare).await.unwrap_or(false) {
                tracing::info!(%bare, "auto-approving pre-approved subscription request");
                crate::xeps::roster::set_subscription(w, cfg.bare(), &bare, "subscribed", None)?;
            } else {
                tracing::info!(%bare, "inbound presence subscription request");
                let _ = events
                    .send(Event::SubscriptionRequest { account_id: cfg.account_id, jid: bare, nick })
                    .await;
            }
        }
        // `unsubscribe` / `subscribed` / `unsubscribed`: like Android we don't act on these
        // directly — the authoritative state arrives as a roster push, which refreshes the UI.
        _ => {}
    }
    Ok(())
}
