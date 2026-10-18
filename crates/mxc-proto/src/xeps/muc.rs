//! XEP-0045 Multi-User Chat: join/leave rooms.
//!
//! Incoming `<message type='groupchat'>` and MAM from rooms are handled by
//! [`super::messaging`] (it sets the conversation kind to `muc`). Joining is a directed
//! presence to `room/nick` carrying the MUC `<x>` (with a `maxstanzas='0'` history hint,
//! since we backfill via MAM instead).

use async_channel::Sender;
use minidom::Element;

use mxc_store::Store;

use crate::client::{AccountConfig, Writer};
use crate::event::Event;
use crate::xeps::roster::new_id;
use crate::xeps::{caps, iq, vcard};

pub const NS_MUC: &str = "http://jabber.org/protocol/muc";
const NS_DISCO_INFO: &str = "http://jabber.org/protocol/disco#info";
const NS_MUC_ADMIN: &str = "http://jabber.org/protocol/muc#admin";
const NS_XDATA: &str = "jabber:x:data";

/// Fetch a room's profile via XEP-0045 disco#info: its name (`<identity>`), and the
/// `muc#roominfo_*` data-form fields (description, subject, occupant count). The room's photo
/// comes from its vcard-temp (the same source used for the room avatar). Best-effort: returns
/// whatever could be read.
pub async fn room_profile(w: &Writer, room: &str) -> vcard::VcardDetails {
    let mut out = vcard::VcardDetails::default();

    // Room avatar photo (vcard-temp PHOTO), same source as the conversation/list avatar.
    out.photo = vcard::fetch_photo(w, room).await.ok().flatten();

    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("to"), room)
        .attr(crate::ncname("id"), new_id("disco-info"))
        .append(Element::builder("query", NS_DISCO_INFO).build())
        .build();
    let Ok(reply) = iq::request(w, req).await else { return out };
    let Some(query) = reply.get_child("query", NS_DISCO_INFO) else { return out };

    // Room name from the conference identity.
    if let Some(name) = query
        .children()
        .find(|c| c.name() == "identity" && c.attr("category") == Some("conference"))
        .and_then(|id| id.attr("name"))
    {
        let name = name.trim();
        if !name.is_empty() {
            out.fields.push(("Name".to_string(), name.to_string()));
        }
    }

    // muc#roominfo_* fields live in a result data form.
    if let Some(form) = query.children().find(|c| c.name() == "x" && c.ns() == NS_XDATA) {
        // A field may carry multiple <value> children (text-multi splits each line into its
        // own <value>); join them with newlines so multi-line descriptions aren't truncated.
        let field = |var: &str| -> Option<String> {
            let f = form
                .children()
                .find(|f| f.name() == "field" && f.attr("var") == Some(var))?;
            let joined = f
                .children()
                .filter(|c| c.name() == "value")
                .map(|v| v.text())
                .collect::<Vec<_>>()
                .join("\n");
            let trimmed = joined.trim().to_string();
            (!trimmed.is_empty()).then_some(trimmed)
        };
        if let Some(desc) = field("muc#roominfo_description") {
            out.fields.push(("Description".to_string(), desc));
        }
        // The live subject/topic is added separately (from the stored groupchat <subject>),
        // which is more complete than disco's muc#roominfo_subject snapshot.
        if let Some(lang) = field("muc#roominfo_lang") {
            out.fields.push(("Language".to_string(), lang));
        }
        if let Some(occupants) = field("muc#roominfo_occupants") {
            out.fields.push(("Occupants".to_string(), occupants));
        }
    }

    out
}

/// Join `room` (bare JID) as `nick`, optionally with a `password` for a protected room.
/// Records/updates the MUC conversation row (and stores the password for re-joining).
pub async fn join(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    room: &str,
    nick: &str,
    password: Option<&str>,
) -> anyhow::Result<()> {
    store.upsert_muc(cfg.account_id, room, None, Some(nick), true).await?;

    let password = password.filter(|p| !p.is_empty());
    if let Some(pw) = password {
        store.set_muc_password(cfg.account_id, room, pw).await?;
    }

    // XEP-0359: does the room stamp stanza-ids? Learn it before the first room message
    // arrives so its `<stanza-id by=room>` can be trusted (best-effort; unknown = untrusted).
    super::stanza_id::discover(w, cfg.account_id, room).await;

    // XEP-0045 join: <x><history maxstanzas='0'/>[<password>…</password>]</x>.
    let mut x = Element::builder("x", NS_MUC)
        .append(Element::builder("history", NS_MUC).attr(crate::ncname("maxstanzas"), "0").build());
    if let Some(pw) = password {
        x = x.append(Element::builder("password", NS_MUC).append(pw).build());
    }
    // The room answers with every current occupant's presence, then ours: drop what we knew
    // about it (we may have missed departures while disconnected) before any of that arrives.
    let _ = events.send(Event::MucJoining { account_id: cfg.account_id, room: room.to_string() }).await;
    // XEP-0272 Muji: the call coordinator forgets the room's old participant state, and if we're
    // still in its group call (a reconnect), the join presence keeps announcing it.
    super::muji::mark_room_joining(cfg.account_id, room);
    super::muji::mark_room_joined(cfg.account_id, room);
    let mut presence = Element::builder("presence", "jabber:client")
        .attr(crate::ncname("to"), format!("{room}/{nick}"))
        .append(x.build())
        .append(caps::caps_element());
    if let Some(muji) = super::muji::active_payload(cfg.account_id, room) {
        presence = presence.append(muji);
    }
    w.send(presence.build())?;

    if let Ok(items) = store.conversations(cfg.account_id).await {
        let _ = events.send(Event::ConversationsUpdated { account_id: cfg.account_id, items }).await;
    }
    Ok(())
}

/// Discover a room's OMEMO capability and member roster after joining.
///
/// 1. disco#info → cache the `muc_membersonly` + `muc_nonanonymous` features (OMEMO is offered
///    only when both hold, matching monocles Android's `isPrivateAndNonAnonymous`); emits
///    [`Event::MucPrivacy`] so the open chat can enable/disable the lock.
/// 2. For an OMEMO-capable room, query the member/admin/owner affiliation lists so we know the
///    real bare JIDs of *offline* members too (live occupants come in via presence), giving the
///    full crypto-target set. Best-effort throughout.
pub async fn configure_room(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    room: &str,
) -> anyhow::Result<()> {
    let conv = store.conversation_id(cfg.account_id, room, "muc").await?;

    // --- room features (disco#info) ---
    let mut members_only = false;
    let mut non_anonymous = false;
    let mut moderation = None;
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("to"), room)
        .attr(crate::ncname("id"), new_id("disco-info"))
        .append(Element::builder("query", NS_DISCO_INFO).build())
        .build();
    if let Ok(reply) = iq::request(w, req).await {
        if let Some(query) = reply.get_child("query", NS_DISCO_INFO) {
            super::stanza_id::set_supported(cfg.account_id, room, super::stanza_id::advertises(query));
            moderation = super::moderation::advertised(query);
            for f in query.children().filter(|c| c.name() == "feature") {
                match f.attr("var") {
                    Some("muc_membersonly") => members_only = true,
                    Some("muc_nonanonymous") => non_anonymous = true,
                    _ => {}
                }
            }
        }
    }
    super::moderation::set_supported(cfg.account_id, room, moderation);
    store.set_muc_features(conv, members_only, non_anonymous).await?;
    let omemo_capable = members_only && non_anonymous;
    let _ = events
        .send(Event::MucPrivacy {
            account_id: cfg.account_id,
            room: room.to_string(),
            omemo_capable,
            moderation: moderation.is_some(),
        })
        .await;

    // --- member roster (only meaningful when real JIDs are exposed) ---
    if omemo_capable {
        for affiliation in ["owner", "admin", "member"] {
            let Ok(reply) = iq::request(w, affiliation_query(room, affiliation)).await else { continue };
            let Some(query) = reply.get_child("query", NS_MUC_ADMIN) else { continue };
            for item in query.children().filter(|c| c.name() == "item") {
                let Some(jid) = item.attr("jid") else { continue };
                let real_bare = jid.split('/').next().unwrap_or(jid);
                // Offline members have no nick; key them by their real JID so they still count
                // as crypto targets (online occupants are also keyed by nick via presence —
                // muc_member_jids de-dups on real_jid). Don't overwrite ourselves.
                if real_bare.eq_ignore_ascii_case(cfg.bare()) {
                    continue;
                }
                let aff = item.attr("affiliation").or(Some(affiliation));
                let _ = store.upsert_muc_occupant(conv, real_bare, Some(real_bare), aff).await;
            }
        }
    }
    Ok(())
}

/// A XEP-0045 request for `room`'s list of JIDs with `affiliation`.
fn affiliation_query(room: &str, affiliation: &str) -> Element {
    Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("to"), room)
        .attr(crate::ncname("id"), new_id("muc-aff"))
        .append(
            Element::builder("query", NS_MUC_ADMIN)
                .append(Element::builder("item", NS_MUC_ADMIN).attr(crate::ncname("affiliation"), affiliation).build())
                .build(),
        )
        .build()
}

/// The bare JIDs in a muc#admin list reply (other than `own_bare`), with their affiliation
/// (the item's own, else the one asked for).
fn affiliation_items(reply: &Element, asked: &str, own_bare: &str) -> Vec<(String, String)> {
    let Some(query) = reply.get_child("query", NS_MUC_ADMIN) else { return Vec::new() };
    query
        .children()
        .filter(|c| c.name() == "item")
        .filter_map(|item| {
            let jid = item.attr("jid")?;
            let bare = jid.split('/').next().unwrap_or(jid);
            if bare.is_empty() || bare.eq_ignore_ascii_case(own_bare) {
                return None;
            }
            Some((bare.to_string(), item.attr("affiliation").unwrap_or(asked).to_string()))
        })
        .collect()
}

/// XEP-0045 §9.5/§9.8/§10.5/§10.8: fetch `room`'s owner, admin, member and outcast lists
/// (offline members and bans included), concurrently, and report them as
/// [`Event::MucAffiliations`]. Lists we may not read (e.g. outcasts as a plain member) are
/// skipped; if none could be read, [`Event::MucAffiliationsFailed`] says why.
pub async fn fetch_affiliations(
    w: &Writer,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    room: &str,
) -> anyhow::Result<()> {
    const LISTS: [&str; 4] = ["owner", "admin", "member", "outcast"];
    let replies =
        futures::future::join_all(LISTS.map(|affiliation| iq::request(w, affiliation_query(room, affiliation)))).await;
    let mut items = Vec::new();
    let mut first_error = None;
    let mut any = false;
    for (affiliation, reply) in LISTS.iter().zip(replies) {
        match reply {
            Ok(reply) => {
                any = true;
                items.extend(affiliation_items(&reply, affiliation, cfg.bare()));
            }
            Err(e) => {
                tracing::debug!(%room, %affiliation, error = %e, "affiliation list refused");
                first_error.get_or_insert(e.to_string());
            }
        }
    }
    let event = if any {
        Event::MucAffiliations { account_id: cfg.account_id, room: room.to_string(), items }
    } else {
        Event::MucAffiliationsFailed {
            account_id: cfg.account_id,
            room: room.to_string(),
            error: first_error.unwrap_or_default(),
        }
    };
    let _ = events.send(event).await;
    Ok(())
}

/// A XEP-0045 admin `<item/>` change for `room`, with an optional reason.
fn admin_item(room: &str, attrs: &[(&str, &str)], reason: Option<&str>) -> Element {
    let mut item = Element::builder("item", NS_MUC_ADMIN);
    for (k, v) in attrs {
        item = item.attr(crate::ncname(k), *v);
    }
    if let Some(r) = reason.map(str::trim).filter(|r| !r.is_empty()) {
        item = item.append(Element::builder("reason", NS_MUC_ADMIN).append(r).build());
    }
    Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("to"), room)
        .attr(crate::ncname("id"), new_id("muc-admin"))
        .append(Element::builder("query", NS_MUC_ADMIN).append(item.build()).build())
        .build()
}

/// XEP-0045 §8.2 kick: set occupant `nick`'s role to `none` (we must be a moderator, and they
/// may not be an admin or owner — the room enforces both).
pub async fn kick(w: &Writer, room: &str, nick: &str, reason: Option<&str>) -> anyhow::Result<()> {
    iq::request(w, admin_item(room, &[("nick", nick), ("role", "none")], reason))
        .await
        .map_err(|e| anyhow::anyhow!("Couldn't remove {nick}: {e}"))?;
    Ok(())
}

/// XEP-0045 affiliation change of the bare `jid` (§9 admin / §10 owner use cases): `outcast`
/// bans (and removes them from the room), `none`/`member`/`admin`/`owner` revoke or grant
/// membership and rights. We must outrank them as admin, or be an owner for admin/owner
/// changes — the room enforces it.
pub async fn set_affiliation(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    room: &str,
    jid: &str,
    affiliation: &str,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(affiliation, "outcast" | "none" | "member" | "admin" | "owner"),
        "unknown affiliation {affiliation}"
    );
    let bare = jid.split('/').next().unwrap_or(jid);
    iq::request(w, admin_item(room, &[("jid", bare), ("affiliation", affiliation)], reason))
        .await
        .map_err(|e| match affiliation {
            "outcast" => anyhow::anyhow!("Couldn't ban {bare}: {e}"),
            _ => anyhow::anyhow!("Couldn't change the permissions of {bare}: {e}"),
        })?;
    // Keep the stored roster (the OMEMO crypto targets) in step with the change.
    if let Ok(conv) = store.conversation_id(cfg.account_id, room, "muc").await {
        let _ = store.set_muc_affiliation_by_jid(conv, bare, affiliation).await;
    }
    let _ = events
        .send(Event::MucAffiliationChanged {
            account_id: cfg.account_id,
            room: room.to_string(),
            jid: bare.to_string(),
            affiliation: affiliation.to_string(),
        })
        .await;
    Ok(())
}

/// Leave a room (unavailable presence to room/nick).
pub fn leave(w: &Writer, room: &str, nick: &str) -> anyhow::Result<()> {
    let presence = Element::builder("presence", "jabber:client")
        .attr(crate::ncname("to"), format!("{room}/{nick}"))
        .attr(crate::ncname("type"), "unavailable")
        .build();
    w.send(presence)
}

#[cfg(test)]
mod admin_tests {
    use super::*;

    #[test]
    fn kick_and_ban_items() {
        let kick = admin_item("room@muc", &[("nick", "spammer"), ("role", "none")], Some(" flood "));
        assert_eq!(kick.attr("type"), Some("set"));
        assert_eq!(kick.attr("to"), Some("room@muc"));
        let item = kick.get_child("query", NS_MUC_ADMIN).unwrap().get_child("item", NS_MUC_ADMIN).unwrap();
        assert_eq!((item.attr("nick"), item.attr("role")), (Some("spammer"), Some("none")));
        assert_eq!(item.get_child("reason", NS_MUC_ADMIN).unwrap().text(), "flood");

        let ban = admin_item("room@muc", &[("jid", "s@x"), ("affiliation", "outcast")], Some(""));
        let item = ban.get_child("query", NS_MUC_ADMIN).unwrap().get_child("item", NS_MUC_ADMIN).unwrap();
        assert_eq!((item.attr("jid"), item.attr("affiliation")), (Some("s@x"), Some("outcast")));
        assert!(item.get_child("reason", NS_MUC_ADMIN).is_none());
    }

    #[test]
    fn affiliation_list_items() {
        let reply: Element = "<iq xmlns='jabber:client' type='result'>            <query xmlns='http://jabber.org/protocol/muc#admin'>              <item affiliation='outcast' jid='spam@x'><reason>flood</reason></item>              <item jid='me@example.org/res'/>              <item jid='bob@x/phone'/>              <item nick='nojid'/>            </query></iq>"
            .parse()
            .unwrap();
        assert_eq!(
            affiliation_items(&reply, "outcast", "ME@example.org"),
            vec![("spam@x".to_string(), "outcast".to_string()), ("bob@x".to_string(), "outcast".to_string())]
        );
    }
}
