//! Social-feed Stories (`urn:xmpp:pubsub-social-feed:stories:0`), compatible with monocles
//! chat for Android.
//!
//! A story is a PEP item on the publisher's own node, carrying an Atom `<entry>` with an
//! `<link rel="enclosure">` to the (plaintext-uploaded) media. The node is presence-access
//! and items expire after 24h. We subscribe via caps `+notify` to receive contacts' stories,
//! fetch on demand, and cache them in [`mxc_store`].

use async_channel::Sender;
use minidom::Element;

use mxc_store::Store;

use crate::client::{AccountConfig, Writer};
use crate::event::Event;
use crate::xeps::pep;

pub const NS_STORIES: &str = "urn:xmpp:pubsub-social-feed:stories:0";
const NS_ATOM: &str = "http://www.w3.org/2005/Atom";
const NS_XDATA: &str = "jabber:x:data";
const NS_PUBSUB_PUBLISH_OPTIONS: &str = "http://jabber.org/protocol/pubsub#publish-options";

/// `<x type=submit>` publish-options matching Android: presence access, 24h expiry, persisted.
fn publish_options() -> Element {
    let field = |var: &str, value: &str| {
        Element::builder("field", NS_XDATA)
            .attr(crate::ncname("var"), var)
            .append(Element::builder("value", NS_XDATA).append(value).build())
            .build()
    };
    Element::builder("x", NS_XDATA)
        .attr(crate::ncname("type"), "submit")
        .append(field("FORM_TYPE", NS_PUBSUB_PUBLISH_OPTIONS))
        .append(field("pubsub#access_model", "presence"))
        .append(field("pubsub#persist_items", "true"))
        .append(field("pubsub#max_items", "120"))
        .append(field("pubsub#item_expire", "86400"))
        .append(field("pubsub#send_last_published_item", "on_sub_and_presence"))
        .build()
}

/// Publish a story: an Atom `<entry>` linking to `url` (already uploaded). Returns the item id.
pub async fn publish(
    w: &Writer,
    cfg: &AccountConfig,
    url: &str,
    media_type: &str,
    title: &str,
) -> anyhow::Result<()> {
    let uuid = crate::xeps::roster::new_id("story");
    let ts = crate::xeps::rfc3339_now();
    let effective_title = if title.trim().is_empty() {
        format!("Story {}", chrono::Utc::now().format("%Y-%m-%d %H:%M"))
    } else {
        title.to_string()
    };

    let entry = Element::builder("entry", NS_ATOM)
        .append(Element::builder("id", NS_ATOM).append(format!("urn:uuid:{uuid}")).build())
        .append(Element::builder("title", NS_ATOM).append(effective_title.as_str()).build())
        .append(Element::builder("updated", NS_ATOM).append(ts.as_str()).build())
        .append(Element::builder("published", NS_ATOM).append(ts.as_str()).build())
        .append(
            Element::builder("author", NS_ATOM)
                .append(Element::builder("uri", NS_ATOM).append(format!("xmpp:{}", cfg.bare())).build())
                .build(),
        )
        .append(
            Element::builder("link", NS_ATOM)
                .attr(crate::ncname("rel"), "enclosure")
                .attr(crate::ncname("href"), url)
                .attr(crate::ncname("type"), media_type)
                .attr(crate::ncname("title"), effective_title.as_str())
                .build(),
        )
        .build();

    pep::publish(w, NS_STORIES, Some(&uuid), entry, Some(publish_options())).await?;
    Ok(())
}

/// Parsed story fields from one Atom `<entry>` item.
struct Parsed {
    uuid: String,
    url: String,
    media_type: String,
    title: Option<String>,
    published: i64,
}

/// Parse one Atom `<entry>` (the PEP item payload) into story fields, verifying the author
/// matches `contact`. `item_id` is the enclosing PubSub `<item id=…>` (needed for retraction);
/// when absent we fall back to the entry's own `urn:uuid:` atom id.
fn parse_item(item_id: Option<&str>, entry: &Element, contact: &str) -> Option<Parsed> {
    // If an author URI is present, it must match the publisher.
    if let Some(uri) = entry
        .get_child("author", NS_ATOM)
        .and_then(|a| a.get_child("uri", NS_ATOM))
        .map(|u| u.text())
    {
        if let Some(jid) = uri.strip_prefix("xmpp:") {
            let jid_bare = jid.split('/').next().unwrap_or(jid);
            if !jid_bare.eq_ignore_ascii_case(contact) {
                return None;
            }
        }
    }

    // The media is an <link rel="enclosure" href=.. type=..>.
    let link = entry
        .children()
        .find(|c| c.name() == "link" && c.attr("rel") == Some("enclosure"))?;
    let url = link.attr("href")?.to_string();
    let media_type = link.attr("type").unwrap_or("application/octet-stream").to_string();
    let title = entry.get_child("title", NS_ATOM).map(|t| t.text()).filter(|t| !t.is_empty());

    // published/updated timestamp → unix seconds (fall back to now).
    let ts_text = entry
        .get_child("published", NS_ATOM)
        .or_else(|| entry.get_child("updated", NS_ATOM))
        .map(|e| e.text());
    let published = ts_text
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t.trim()).ok())
        .map(|dt| dt.timestamp())
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

    // Identify the item for retraction: prefer the PubSub item id, else the entry's atom id
    // (`urn:uuid:<uuid>`). Without a stable id we can't reliably delete it later, so skip.
    let uuid = item_id
        .map(str::to_string)
        .or_else(|| {
            entry
                .get_child("id", NS_ATOM)
                .map(|e| e.text())
                .map(|t| t.trim().strip_prefix("urn:uuid:").unwrap_or(t.trim()).to_string())
                .filter(|s| !s.is_empty())
        })?;
    Some(Parsed { uuid, url, media_type, title, published })
}

/// Store the parsed items (each an `(item_id, <entry>)` pair) published by `contact`,
/// returning how many were stored.
async fn store_items(store: &Store, account_id: i64, contact: &str, items: &[(Option<String>, Element)]) -> usize {
    let mut n = 0;
    for (id, entry) in items {
        if let Some(p) = parse_item(id.as_deref(), entry, contact) {
            if store
                .upsert_story(account_id, &p.uuid, contact, &p.url, &p.media_type, p.title.as_deref(), p.published)
                .await
                .is_ok()
            {
                n += 1;
            }
        }
    }
    n
}

/// Fetch `jid`'s stories (None = our own) and cache them. Best-effort.
pub async fn fetch(w: &Writer, store: &Store, cfg: &AccountConfig, jid: Option<&str>) {
    let contact = jid.unwrap_or(cfg.bare()).to_string();
    let Ok(reply) = pep::items(w, jid, NS_STORIES, None).await else { return };
    let items = pep::extract_items(&reply);
    store_items(store, cfg.account_id, &contact, &items).await;
}

/// Handle an incoming PEP notification (`<message><event><items node=stories>`). Returns true
/// if it was a stories event (and thus consumed).
pub async fn handle_event(store: &Store, cfg: &AccountConfig, events: &Sender<Event>, msg: &Element) -> bool {
    let Some(event) = msg.get_child("event", "http://jabber.org/protocol/pubsub#event") else {
        return false;
    };
    let Some(items) = event.get_child("items", "http://jabber.org/protocol/pubsub#event") else {
        return false;
    };
    if items.attr("node") != Some(NS_STORIES) {
        return false;
    }
    let from = msg.attr("from").unwrap_or_default();
    let contact = from.split('/').next().unwrap_or(from).to_string();

    // Retractions remove the item; published items are parsed + stored.
    for retract in items.children().filter(|c| c.name() == "retract") {
        if let Some(id) = retract.attr("id") {
            // Only the publisher's own story (`contact` = the event's sender) can be retracted.
            let _ = store.delete_story(cfg.account_id, &contact, id).await;
        }
    }
    let published: Vec<(Option<String>, Element)> = items
        .children()
        .filter(|c| c.name() == "item")
        .filter_map(|c| {
            c.get_child("entry", NS_ATOM)
                .map(|e| (c.attr("id").map(str::to_string), e.clone()))
        })
        .collect();
    let stored = store_items(store, cfg.account_id, &contact, &published).await;

    if stored > 0 || items.children().any(|c| c.name() == "retract") {
        let _ = events.send(Event::StoriesUpdated { account_id: cfg.account_id }).await;
    }
    true
}

/// Retract one of our own stories. If the server no longer has the item (`item-not-found` —
/// e.g. it already expired, or was stored under a stale client-side id), we still drop the
/// local copy so the UI can clear it.
pub async fn retract(w: &Writer, store: &Store, cfg: &AccountConfig, uuid: &str) -> anyhow::Result<()> {
    match pep::retract(w, NS_STORIES, uuid).await {
        Ok(_) => {}
        Err(e) if e.to_string().contains("item-not-found") => {
            tracing::info!(%uuid, "story already gone on server; removing local copy");
        }
        Err(e) => return Err(e),
    }
    store.delete_story(cfg.account_id, cfg.bare(), uuid).await?;
    Ok(())
}
