//! XEP-0359 stanza-id trust. A `<stanza-id by=X>` is only meaningful if X actually stamps
//! (and therefore strips forged) stanza-ids — which it signals by advertising `urn:xmpp:sid:0`
//! in disco#info. Otherwise any sender can attach `<stanza-id by=X id=…>` and steer our dedup /
//! reaction / retraction targeting. Mirrors Conversations' `StanzaIdManager`: trust our
//! account's ids only if the account advertises the feature, a room's only if the room does.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use minidom::Element;

use crate::client::Writer;
use crate::xeps::iq;
use crate::xeps::roster::new_id;

pub const NS_SID: &str = "urn:xmpp:sid:0";
const NS_DISCO_INFO: &str = "http://jabber.org/protocol/disco#info";

/// (account id, lowercased bare JID) of archives known to stamp stanza-ids.
static SUPPORTED: OnceLock<Mutex<HashSet<(i64, String)>>> = OnceLock::new();

fn supported() -> &'static Mutex<HashSet<(i64, String)>> {
    SUPPORTED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Record whether `jid` advertises stanza-id support (from a disco#info result).
pub fn set_supported(account_id: i64, jid: &str, yes: bool) {
    let key = (account_id, jid.to_ascii_lowercase());
    let mut s = supported().lock().unwrap();
    if yes {
        s.insert(key);
    } else {
        s.remove(&key);
    }
}

/// Whether `<stanza-id by=jid>` may be trusted. Unknown (not yet discovered) = no.
pub fn is_supported(account_id: i64, jid: &str) -> bool {
    supported().lock().unwrap().contains(&(account_id, jid.to_ascii_lowercase()))
}

/// Whether a disco#info `<query>` advertises `urn:xmpp:sid:0`.
pub fn advertises(query: &Element) -> bool {
    query.children().any(|c| c.name() == "feature" && c.attr("var") == Some(NS_SID))
}

/// disco#info `jid` and record its stanza-id support. Best-effort: on failure the entity
/// stays untrusted.
pub async fn discover(w: &Writer, account_id: i64, jid: &str) {
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("to"), jid)
        .attr(crate::ncname("id"), new_id("disco-sid"))
        .append(Element::builder("query", NS_DISCO_INFO).build())
        .build();
    match iq::request(w, req).await {
        Ok(reply) => {
            let yes = reply.get_child("query", NS_DISCO_INFO).is_some_and(advertises);
            set_supported(account_id, jid, yes);
        }
        Err(e) => tracing::debug!(%jid, error = %e, "stanza-id disco failed"),
    }
}

/// The trusted `<stanza-id>` of `msg` assigned by `by`, if `by` is known to stamp them.
pub fn trusted(msg: &Element, account_id: i64, by: &str) -> Option<String> {
    if !is_supported(account_id, by) {
        return None;
    }
    // Exactly one stanza-id by this archive: a second one means one of them was slipped in and
    // we can't tell which (Conversations 539b55d83), so use neither.
    let mut matching = msg
        .children()
        .filter(|c| c.name() == "stanza-id" && c.ns() == NS_SID)
        .filter(|c| c.attr("by").is_some_and(|b| super::origin::jid_eq(b, by)));
    let only = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    only.attr("id").map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_with(by: &str, id: &str) -> Element {
        Element::builder("message", "jabber:client")
            .append(
                Element::builder("stanza-id", NS_SID)
                    .attr(crate::ncname("by"), by)
                    .attr(crate::ncname("id"), id)
                    .build(),
            )
            .build()
    }

    #[test]
    fn only_trusted_when_supported_and_by_matches() {
        let msg = msg_with("Room@muc.example.org", "abc");
        assert_eq!(trusted(&msg, 7, "room@muc.example.org"), None);
        set_supported(7, "room@muc.example.org", true);
        assert_eq!(trusted(&msg, 7, "room@muc.example.org").as_deref(), Some("abc"));
        assert_eq!(trusted(&msg, 8, "room@muc.example.org"), None);
        assert_eq!(trusted(&msg_with("evil@x", "abc"), 7, "room@muc.example.org"), None);
        // two stanza-ids by the same archive: ambiguous, neither is used
        let dup = Element::builder("message", "jabber:client")
            .append(msg_with("room@muc.example.org", "forged").get_child("stanza-id", NS_SID).unwrap().clone())
            .append(msg_with("room@muc.example.org", "abc").get_child("stanza-id", NS_SID).unwrap().clone())
            .build();
        assert_eq!(trusted(&dup, 7, "room@muc.example.org"), None);
        set_supported(7, "room@muc.example.org", false);
        assert_eq!(trusted(&msg, 7, "room@muc.example.org"), None);
    }
}
