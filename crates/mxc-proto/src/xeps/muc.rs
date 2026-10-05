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
    let presence = Element::builder("presence", "jabber:client")
        .attr(crate::ncname("to"), format!("{room}/{nick}"))
        .append(x.build())
        .append(caps::caps_element())
        .build();
    w.send(presence)?;

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
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("to"), room)
        .attr(crate::ncname("id"), new_id("disco-info"))
        .append(Element::builder("query", NS_DISCO_INFO).build())
        .build();
    if let Ok(reply) = iq::request(w, req).await {
        if let Some(query) = reply.get_child("query", NS_DISCO_INFO) {
            super::stanza_id::set_supported(cfg.account_id, room, super::stanza_id::advertises(query));
            for f in query.children().filter(|c| c.name() == "feature") {
                match f.attr("var") {
                    Some("muc_membersonly") => members_only = true,
                    Some("muc_nonanonymous") => non_anonymous = true,
                    _ => {}
                }
            }
        }
    }
    store.set_muc_features(conv, members_only, non_anonymous).await?;
    let omemo_capable = members_only && non_anonymous;
    let _ = events
        .send(Event::MucPrivacy {
            account_id: cfg.account_id,
            room: room.to_string(),
            omemo_capable,
        })
        .await;

    // --- member roster (only meaningful when real JIDs are exposed) ---
    if omemo_capable {
        for affiliation in ["owner", "admin", "member"] {
            let req = Element::builder("iq", "jabber:client")
                .attr(crate::ncname("type"), "get")
                .attr(crate::ncname("to"), room)
                .attr(crate::ncname("id"), new_id("muc-aff"))
                .append(
                    Element::builder("query", NS_MUC_ADMIN)
                        .append(Element::builder("item", NS_MUC_ADMIN).attr(crate::ncname("affiliation"), affiliation).build())
                        .build(),
                )
                .build();
            let Ok(reply) = iq::request(w, req).await else { continue };
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

/// Leave a room (unavailable presence to room/nick).
pub fn leave(w: &Writer, room: &str, nick: &str) -> anyhow::Result<()> {
    let presence = Element::builder("presence", "jabber:client")
        .attr(crate::ncname("to"), format!("{room}/{nick}"))
        .attr(crate::ncname("type"), "unavailable")
        .build();
    w.send(presence)
}
