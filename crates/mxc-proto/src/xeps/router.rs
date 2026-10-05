//! Top-level stanza demultiplexer: routes an incoming `<message>`/`<presence>`/`<iq>`
//! to the right handler. Awaited iq *replies* are intercepted earlier by
//! [`super::iq::try_resolve`] in the reader loop, so here we only see requests/pushes.

use async_channel::Sender;
use minidom::Element;

use mxc_store::Store;

use crate::client::{AccountConfig, Writer};
use crate::event::Event;
use crate::xeps::jingle::CallRegistry;
use crate::xeps::{disco, jingle, messaging, presence, roster};

pub async fn handle_stanza(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    calls: &CallRegistry,
    stanza: Element,
) -> anyhow::Result<()> {
    match stanza.name() {
        "message" => messaging::handle_incoming(w, store, cfg, events, calls, &stanza).await,
        "presence" => {
            // XEP-0272 Muji: drive any active group call off occupant `<muji>` presence.
            jingle::observe_muji_presence(w, calls, cfg, events, &stanza).await;
            presence::handle_incoming(w, store, cfg, events, &stanza).await
        }
        "iq" => handle_iq(w, store, cfg, events, calls, &stanza).await,
        other => {
            tracing::trace!(other, "ignoring unknown top-level stanza");
            Ok(())
        }
    }
}

async fn handle_iq(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    calls: &CallRegistry,
    iq: &Element,
) -> anyhow::Result<()> {
    let iq_type = iq.attr("type").unwrap_or("");

    // XEP-0166 Jingle session IQs (calls).
    if iq.get_child("jingle", jingle::NS_JINGLE_SESSION).is_some()
        && jingle::handle_iq(w, calls, cfg, events, iq).await
    {
        return Ok(());
    }

    // Roster pushes (RFC 6121 §2.1.6): only a `set` from our own server is a push. Anyone else
    // could otherwise add/remove/rename our contacts. Replies to our own roster fetch never get
    // here (iq::try_resolve consumes them), so an unsolicited `result` is ignored as well.
    if let Some(query) = iq.get_child("query", "jabber:iq:roster") {
        if iq_type == "set" {
            if super::origin::from_server(iq.attr("from"), cfg.bare()) {
                roster::handle_roster_payload(store, cfg, events, query).await?;
                roster::ack_iq(w, iq)?;
            } else {
                tracing::warn!(from = ?iq.attr("from"), "rejecting roster push from foreign entity");
                w.send(error_iq(iq, "cancel", "forbidden"))?;
            }
        }
        return Ok(());
    }

    // disco#info / disco#items requests against us.
    if iq_type == "get" {
        if iq.get_child("query", "http://jabber.org/protocol/disco#info").is_some() {
            disco::answer_info(w, iq)?;
            return Ok(());
        }
        if iq.get_child("query", "http://jabber.org/protocol/disco#items").is_some() {
            disco::answer_items(w, iq)?;
            return Ok(());
        }
    }

    tracing::trace!(iq_type, "unhandled iq");
    Ok(())
}

/// An `<iq type='error'>` answering `req` with a stanza error condition.
fn error_iq(req: &Element, error_type: &str, condition: &str) -> Element {
    let mut b = Element::builder("iq", "jabber:client").attr(crate::ncname("type"), "error");
    if let Some(id) = req.attr("id") {
        b = b.attr(crate::ncname("id"), id);
    }
    if let Some(from) = req.attr("from") {
        b = b.attr(crate::ncname("to"), from);
    }
    let error = Element::builder("error", "jabber:client")
        .attr(crate::ncname("type"), error_type)
        .append(Element::builder(condition, "urn:ietf:params:xml:ns:xmpp-stanzas").build())
        .build();
    b.append(error).build()
}
