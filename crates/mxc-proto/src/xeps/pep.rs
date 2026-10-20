//! XEP-0163 PEP over XEP-0060 PubSub: publish and fetch items.
//!
//! Used for bookmarks2 (XEP-0402), avatars (XEP-0084), nick (XEP-0172), and — in
//! Phase 2 — the OMEMO2 device list and bundles. All requests go through
//! [`super::iq::request`] so callers get the typed reply back.

use minidom::Element;

use crate::client::Writer;
use crate::xeps::iq;
use crate::xeps::roster::new_id;

pub const NS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";
pub const NS_PUBSUB_OWNER: &str = "http://jabber.org/protocol/pubsub#owner";

/// Publish a single item to a PEP node on our own account.
///
/// `publish_options` (e.g. an access-model `pubsub#publish-options` form) is attached
/// when provided — needed for `open`/`whitelist` node config (bookmarks, OMEMO bundles).
pub async fn publish(
    w: &Writer,
    node: &str,
    item_id: Option<&str>,
    payload: Element,
    publish_options: Option<Element>,
) -> anyhow::Result<Element> {
    let mut item = Element::builder("item", NS_PUBSUB);
    if let Some(id) = item_id {
        item = item.attr(crate::ncname("id"), id);
    }
    let item = item.append(payload).build();

    let publish = Element::builder("publish", NS_PUBSUB)
        .attr(crate::ncname("node"), node)
        .append(item)
        .build();

    let mut pubsub = Element::builder("pubsub", NS_PUBSUB).append(publish);
    if let Some(opts) = publish_options {
        pubsub = pubsub.append(opts);
    }

    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("pep-pub"))
        .append(pubsub.build())
        .build();
    iq::request(w, req).await
}

/// Retract (delete) a single item from a PEP node on our own account.
pub async fn retract(w: &Writer, node: &str, item_id: &str) -> anyhow::Result<Element> {
    let retract = Element::builder("retract", NS_PUBSUB)
        .attr(crate::ncname("node"), node)
        .attr(crate::ncname("notify"), "true")
        .append(Element::builder("item", NS_PUBSUB).attr(crate::ncname("id"), item_id).build())
        .build();
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("pep-retract"))
        .append(Element::builder("pubsub", NS_PUBSUB).append(retract).build())
        .build();
    iq::request(w, req).await
}

/// Fetch up to `max_items` items from `node` on `jid` (None = our own account).
pub async fn items(
    w: &Writer,
    jid: Option<&str>,
    node: &str,
    max_items: Option<u32>,
) -> anyhow::Result<Element> {
    let mut items_el = Element::builder("items", NS_PUBSUB).attr(crate::ncname("node"), node);
    if let Some(m) = max_items {
        items_el = items_el.attr(crate::ncname("max_items"), m.to_string());
    }
    let pubsub = Element::builder("pubsub", NS_PUBSUB).append(items_el.build()).build();

    let mut req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("id"), new_id("pep-get"));
    if let Some(j) = jid {
        req = req.attr(crate::ncname("to"), j);
    }
    let req = req.append(pubsub).build();
    iq::request(w, req).await
}

/// Fetch one specific item by id from `node` on `jid` (e.g. an OMEMO2 bundle keyed by
/// device id).
pub async fn item(
    w: &Writer,
    jid: Option<&str>,
    node: &str,
    item_id: &str,
) -> anyhow::Result<Element> {
    let items_el = Element::builder("items", NS_PUBSUB)
        .attr(crate::ncname("node"), node)
        .append(Element::builder("item", NS_PUBSUB).attr(crate::ncname("id"), item_id).build())
        .build();
    let pubsub = Element::builder("pubsub", NS_PUBSUB).append(items_el).build();
    let mut req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("id"), new_id("pep-item"));
    if let Some(j) = jid {
        req = req.attr(crate::ncname("to"), j);
    }
    iq::request(w, req.append(pubsub).build()).await
}

/// Pull the `<item>` children (with their payloads) out of a pubsub result iq.
pub fn extract_items(reply: &Element) -> Vec<(Option<String>, Element)> {
    let mut out = Vec::new();
    let Some(pubsub) = reply.get_child("pubsub", NS_PUBSUB) else {
        return out;
    };
    let Some(items) = pubsub.get_child("items", NS_PUBSUB) else {
        return out;
    };
    for item in items.children().filter(|c| c.name() == "item") {
        let id = item.attr("id").map(str::to_string);
        if let Some(payload) = item.children().next() {
            out.push((id, payload.clone()));
        }
    }
    out
}

/// Like [`extract_items`], plus each item's service-stamped `publisher` attribute (present when
/// the node has `pubsub#itempublisher` enabled): `(item id, publisher, payload)`.
pub fn extract_items_with_publisher(reply: &Element) -> Vec<(Option<String>, Option<String>, Element)> {
    let mut out = Vec::new();
    let Some(items) = reply
        .get_child("pubsub", NS_PUBSUB)
        .and_then(|p| p.get_child("items", NS_PUBSUB))
    else {
        return out;
    };
    for item in items.children().filter(|c| c.name() == "item") {
        if let Some(payload) = item.children().next() {
            out.push((
                item.attr("id").map(str::to_string),
                item.attr("publisher").map(str::to_string),
                payload.clone(),
            ));
        }
    }
    out
}

const NS_XDATA: &str = "jabber:x:data";

fn xdata_field(var: &str, value: &str) -> Element {
    Element::builder("field", NS_XDATA)
        .attr(crate::ncname("var"), var)
        .append(Element::builder("value", NS_XDATA).append(value).build())
        .build()
}

/// Build a `pubsub#publish-options` data form pinning an access model (e.g. "open").
pub fn publish_options(access_model: &str) -> Element {
    publish_options_fields(&[("pubsub#access_model", access_model)])
}

/// Build a `pubsub#publish-options` data form with the given `(var, value)` preconditions.
pub fn publish_options_fields(fields: &[(&str, &str)]) -> Element {
    let field_form_type = Element::builder("field", NS_XDATA)
        .attr(crate::ncname("var"), "FORM_TYPE")
        .attr(crate::ncname("type"), "hidden")
        .append(
            Element::builder("value", NS_XDATA)
                .append("http://jabber.org/protocol/pubsub#publish-options")
                .build(),
        )
        .build();
    let mut x = Element::builder("x", NS_XDATA)
        .attr(crate::ncname("type"), "submit")
        .append(field_form_type);
    for (var, value) in fields {
        x = x.append(xdata_field(var, value));
    }
    Element::builder("publish-options", NS_PUBSUB).append(x.build()).build()
}

/// Whether a publish carrying publish-options was refused because the node's configuration
/// doesn't match them (XEP-0060 §7.1.5: `<conflict/>` + `<precondition-not-met/>`). The IQ
/// error only carries the defined condition, and a publish has no other reason to conflict.
pub fn is_precondition_not_met(e: &anyhow::Error) -> bool {
    let s = e.to_string();
    s.contains("conflict") || s.contains("precondition-not-met")
}

/// Reconfigure one of our own PEP nodes (XEP-0060 §8.2): fetch its config form and submit it
/// back with `fields` overridden. Fields the server's form doesn't offer are left out, so an
/// option it doesn't support (e.g. `item_expire`) can't make the whole submission fail.
pub async fn configure_node(w: &Writer, node: &str, fields: &[(&str, &str)]) -> anyhow::Result<()> {
    let configure = |x: Option<Element>| {
        let mut c = Element::builder("configure", NS_PUBSUB_OWNER).attr(crate::ncname("node"), node);
        if let Some(x) = x {
            c = c.append(x);
        }
        Element::builder("pubsub", NS_PUBSUB_OWNER).append(c.build()).build()
    };
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("id"), new_id("pep-cfg"))
        .append(configure(None))
        .build();
    let reply = iq::request(w, req).await?;
    let form = reply
        .get_child("pubsub", NS_PUBSUB_OWNER)
        .and_then(|p| p.get_child("configure", NS_PUBSUB_OWNER))
        .and_then(|c| c.get_child("x", NS_XDATA))
        .ok_or_else(|| anyhow::anyhow!("no configuration form for node {node}"))?;

    let mut x = Element::builder("x", NS_XDATA).attr(crate::ncname("type"), "submit");
    for field in form.children().filter(|c| c.is("field", NS_XDATA)) {
        let Some(var) = field.attr("var") else { continue };
        if let Some((_, value)) = fields.iter().find(|(v, _)| *v == var) {
            x = x.append(xdata_field(var, value));
        } else {
            let mut f = Element::builder("field", NS_XDATA).attr(crate::ncname("var"), var);
            for value in field.children().filter(|c| c.is("value", NS_XDATA)) {
                f = f.append(Element::builder("value", NS_XDATA).append(value.text()).build());
            }
            x = x.append(f.build());
        }
    }
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("pep-cfg"))
        .append(configure(Some(x.build())))
        .build();
    iq::request(w, req).await?;
    Ok(())
}
