//! XEP-0237 roster fetch/push + add/remove contacts (RFC-6121 roster semantics).

use async_channel::Sender;
use minidom::Element;

use mxc_store::{RosterItem, Store};

use crate::client::{AccountConfig, Writer};
use crate::event::Event;
use crate::xeps::iq;

const NS_ROSTER: &str = "jabber:iq:roster";

/// Fetch the roster (called from bootstrap), parse the reply, and persist it.
pub async fn request(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
) -> anyhow::Result<()> {
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("id"), new_id("roster"))
        .append(Element::builder("query", NS_ROSTER).build())
        .build();
    let reply = iq::request(w, req).await?;
    if let Some(query) = reply.get_child("query", NS_ROSTER) {
        handle_roster_payload(store, cfg, events, query).await?;
    }
    Ok(())
}

/// Parse a `<query xmlns=jabber:iq:roster>` (result or push), persist, and emit an event.
pub async fn handle_roster_payload(
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    query: &Element,
) -> anyhow::Result<()> {
    for item in query.children().filter(|c| c.name() == "item") {
        let jid = item.attr("jid").unwrap_or_default().to_string();
        if jid.is_empty() {
            continue;
        }
        let subscription = item.attr("subscription").unwrap_or("none").to_string();
        if subscription == "remove" {
            store.remove_roster_item(cfg.account_id, &jid).await?;
            continue;
        }
        let groups: Vec<String> = item
            .children()
            .filter(|c| c.name() == "group")
            .map(|g| g.text())
            .collect();
        let row = RosterItem {
            jid,
            name: item.attr("name").map(str::to_string),
            subscription,
            ask: item.attr("ask").map(str::to_string),
            groups: Some(serde_json_array(&groups)),
        };
        store.replace_roster_item(cfg.account_id, &row).await?;
        // Keep an open contact-details dialog's presence toggles in sync with the server's
        // confirmation of a subscription change.
        let _ = events
            .send(Event::Subscription {
                account_id: cfg.account_id,
                jid: row.jid.clone(),
                subscription: row.subscription.clone(),
                ask: row.ask.clone(),
            })
            .await;
    }

    let items = store.roster(cfg.account_id).await?;
    let _ = events
        .send(Event::RosterUpdated {
            account_id: cfg.account_id,
            items,
        })
        .await;
    Ok(())
}

pub fn add_contact(w: &Writer, from: &str, jid: &str, name: Option<&str>) -> anyhow::Result<()> {
    let mut item = Element::builder("item", NS_ROSTER).attr(crate::ncname("jid"), jid);
    if let Some(n) = name {
        item = item.attr(crate::ncname("name"), n);
    }
    let iq = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("roster-set"))
        .append(Element::builder("query", NS_ROSTER).append(item.build()).build())
        .build();
    w.send(iq)?;
    // Then send a subscription request presence (carrying our nick, like Android).
    set_subscription(w, from, jid, "subscribe", Some(local_part(from)))
}

/// The local part of a bare JID, used as a display nick (matches Android's getDisplayName
/// fallback) when we don't have a richer name configured.
fn local_part(jid: &str) -> &str {
    jid.split('@').next().unwrap_or(jid)
}

/// Send an RFC 6121 presence-subscription stanza (`subscribe`/`unsubscribe`/`subscribed`/
/// `unsubscribed`) to `jid`. The server responds with a roster push reflecting the new state.
/// `from` is our bare JID and `nick` (only attached to `subscribe`) lets the peer show who's
/// asking — both mirror the monocles Android client.
pub fn set_subscription(
    w: &Writer,
    from: &str,
    jid: &str,
    type_: &str,
    nick: Option<&str>,
) -> anyhow::Result<()> {
    let mut pres = Element::builder("presence", "jabber:client")
        .attr(crate::ncname("from"), from)
        .attr(crate::ncname("to"), jid)
        .attr(crate::ncname("type"), type_);
    if type_ == "subscribe" {
        if let Some(n) = nick.filter(|n| !n.is_empty()) {
            pres = pres
                .append(Element::builder("nick", "http://jabber.org/protocol/nick").append(n).build());
        }
    }
    w.send(pres.build())
}

pub fn remove_contact(w: &Writer, jid: &str) -> anyhow::Result<()> {
    let item = Element::builder("item", NS_ROSTER)
        .attr(crate::ncname("jid"), jid)
        .attr(crate::ncname("subscription"), "remove")
        .build();
    let iq = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("roster-del"))
        .append(Element::builder("query", NS_ROSTER).append(item).build())
        .build();
    w.send(iq)
}

/// Acknowledge a roster-push iq (`type=set`) with an empty result.
pub fn ack_iq(w: &Writer, push: &Element) -> anyhow::Result<()> {
    let mut b = Element::builder("iq", "jabber:client").attr(crate::ncname("type"), "result");
    if let Some(id) = push.attr("id") {
        b = b.attr(crate::ncname("id"), id);
    }
    w.send(b.build())
}

fn serde_json_array(items: &[String]) -> String {
    // tiny JSON array encoder to avoid pulling serde here
    let mut s = String::from("[");
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        s.push_str(&it.replace('\\', "\\\\").replace('"', "\\\""));
        s.push('"');
    }
    s.push(']');
    s
}

/// A fresh stanza/session id: `prefix-` + 128 random bits. Must be unguessable — iq ids,
/// MAM query ids and Jingle session ids are what a remote party would have to know to forge
/// a reply into one of our exchanges.
pub(crate) fn new_id(prefix: &str) -> String {
    use rand::RngCore;
    let mut raw = [0u8; 16];
    rand::rng().fill_bytes(&mut raw);
    let mut id = String::with_capacity(prefix.len() + 33);
    id.push_str(prefix);
    id.push('-');
    for b in raw {
        id.push_str(&format!("{b:02x}"));
    }
    id
}
