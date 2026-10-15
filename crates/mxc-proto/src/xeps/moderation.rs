//! XEP-0425 Message Moderation: a room moderator asks the MUC to retract someone's message.
//!
//! The current spec (v0.3, `urn:xmpp:message-moderate:1`) wraps a XEP-0424 `<retract/>` in a
//! `<moderate id=STANZA-ID/>` IQ to the room; the room then broadcasts
//! `<retract id><moderated/><reason/></retract>` from its bare JID and may replace the archived
//! original with a `<retracted><moderated/></retracted>` tombstone. Rooms that only speak the
//! legacy `:0` form (XEP-0422 `<apply-to>` fastening) get that instead, as monocles Android
//! sends it. The `id` is always the room-assigned XEP-0359 stanza-id, never the origin-id.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use futures::StreamExt;
use minidom::Element;

use crate::client::Writer;
use crate::xeps::iq;
use crate::xeps::roster::new_id;

pub const NS_MODERATE: &str = "urn:xmpp:message-moderate:1";
pub const NS_MODERATE_0: &str = "urn:xmpp:message-moderate:0";
pub const NS_RETRACT: &str = "urn:xmpp:message-retract:1";
pub const NS_RETRACT_0: &str = "urn:xmpp:message-retract:0";
pub const NS_FASTEN: &str = "urn:xmpp:fasten:0";

/// Which moderation protocol a room advertises in disco#info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V0,
}

/// (account id, lowercased room JID) → the newest moderation version the room advertises.
static SUPPORTED: OnceLock<Mutex<HashMap<(i64, String), Version>>> = OnceLock::new();

fn supported() -> &'static Mutex<HashMap<(i64, String), Version>> {
    SUPPORTED.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The moderation version a room's disco#info `<query>` advertises (`:1` preferred).
pub fn advertised(query: &Element) -> Option<Version> {
    let has = |ns: &str| query.children().any(|c| c.name() == "feature" && c.attr("var") == Some(ns));
    if has(NS_MODERATE) {
        Some(Version::V1)
    } else if has(NS_MODERATE_0) {
        Some(Version::V0)
    } else {
        None
    }
}

/// Record a room's moderation support (from its disco#info result).
pub fn set_supported(account_id: i64, room: &str, version: Option<Version>) {
    let key = (account_id, room.to_ascii_lowercase());
    let mut s = supported().lock().unwrap();
    match version {
        Some(v) => s.insert(key, v),
        None => s.remove(&key),
    };
}

/// The moderation version `room` supports, if it was discovered.
pub fn version(account_id: i64, room: &str) -> Option<Version> {
    supported().lock().unwrap().get(&(account_id, room.to_ascii_lowercase())).copied()
}

/// The moderation request IQ for `stanza_id` in `room`, in the room's protocol version.
fn request(room: &str, stanza_id: &str, reason: Option<&str>, version: Version) -> Element {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    let payload = match version {
        Version::V1 => {
            let mut moderate = Element::builder("moderate", NS_MODERATE)
                .attr(crate::ncname("id"), stanza_id)
                .append(Element::builder("retract", NS_RETRACT).build());
            if let Some(r) = reason {
                moderate = moderate.append(Element::builder("reason", NS_MODERATE).append(r).build());
            }
            moderate.build()
        }
        Version::V0 => {
            let mut moderate = Element::builder("moderate", NS_MODERATE_0)
                .append(Element::builder("retract", NS_RETRACT_0).build());
            if let Some(r) = reason {
                moderate = moderate.append(Element::builder("reason", NS_MODERATE_0).append(r).build());
            }
            Element::builder("apply-to", NS_FASTEN)
                .attr(crate::ncname("id"), stanza_id)
                .append(moderate.build())
                .build()
        }
    };
    Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("to"), room)
        .attr(crate::ncname("id"), new_id("moderate"))
        .append(payload)
        .build()
}

/// Ask `room` to retract the message with room stanza-id `stanza_id`. Nothing changes locally
/// on success: the room's broadcast tombstones it (see [`moderation_target`]), for every
/// occupant alike.
pub async fn moderate(
    w: &Writer,
    account_id: i64,
    room: &str,
    stanza_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    let Some(version) = version(account_id, room) else {
        anyhow::bail!("Unable to moderate: the room doesn't support message moderation");
    };
    iq::request(w, request(room, stanza_id, reason, version))
        .await
        .map_err(|e| anyhow::anyhow!("Unable to moderate: {e}"))?;
    Ok(())
}

/// How many of a banned occupant's newest messages "moderate recent" removes at most.
pub const RECENT_LIMIT: i64 = 50;

/// How many moderation requests "moderate recent" keeps in flight at once.
const RECENT_CONCURRENCY: usize = 8;

/// After a ban: moderate the occupant's newest messages in `room` (Android's "Moderate
/// messages?"). The occupant is identified by XEP-0421 `occupant_id` when known, else by
/// `nick`. Each removal is its own request (a few in flight at once); a refused one doesn't
/// stop the rest, and the error reports how many failed.
pub async fn moderate_recent(
    w: &Writer,
    store: &mxc_store::Store,
    account_id: i64,
    room: &str,
    nick: &str,
    occupant_id: Option<&str>,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    let conv = store.conversation_id(account_id, room, "muc").await?;
    let targets = store
        .recent_room_stanza_ids_from(conv, occupant_id, &format!("{room}/{nick}"), RECENT_LIMIT)
        .await?;
    let total = targets.len();
    let errors: Vec<anyhow::Error> = futures::stream::iter(targets)
        .map(|stanza_id| async move { moderate(w, account_id, room, &stanza_id, reason).await })
        .buffer_unordered(RECENT_CONCURRENCY)
        .filter_map(|r| async move { r.err() })
        .collect()
        .await;
    match errors.first() {
        None => Ok(()),
        Some(first) => anyhow::bail!("Couldn't remove {} of {total} messages. {first}", errors.len()),
    }
}

/// A moderation broadcast in `content` (a groupchat message the caller has verified comes from
/// the bare room JID): the targeted room stanza-id and the moderator's reason, if any.
pub fn moderation_target(content: &Element) -> Option<(String, Option<String>)> {
    // v1: <retract id xmlns=retract:1><moderated xmlns=moderate:1/><reason/></retract>
    if let Some(retract) = content.get_child("retract", NS_RETRACT) {
        if retract.get_child("moderated", NS_MODERATE).is_some() {
            let id = retract.attr("id")?;
            return Some((id.to_string(), reason(retract, NS_RETRACT)));
        }
    }
    // Legacy: <apply-to id xmlns=fasten:0><moderated xmlns=moderate:0><retract/><reason/>
    let fasten = content.get_child("apply-to", NS_FASTEN)?;
    let moderated = fasten.get_child("moderated", NS_MODERATE_0)?;
    moderated.get_child("retract", NS_RETRACT_0)?;
    let id = fasten.attr("id")?;
    Some((id.to_string(), reason(moderated, NS_MODERATE_0)))
}

/// A moderation tombstone (XEP-0425 §6, archived in place of the original): the reason, if any.
/// `None` when `content` isn't one. The outer `Option` marks a tombstone, the inner the reason.
pub fn tombstone(content: &Element) -> Option<Option<String>> {
    let retracted = content.get_child("retracted", NS_RETRACT)?;
    retracted.get_child("moderated", NS_MODERATE)?;
    Some(reason(retracted, NS_RETRACT))
}

fn reason(parent: &Element, ns: &str) -> Option<String> {
    parent
        .get_child("reason", ns)
        .map(|r| r.text().trim().to_string())
        .filter(|r| !r.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> Element {
        xml.parse().unwrap()
    }

    #[test]
    fn v1_request_matches_the_spec_example() {
        let iq = request("room@muc.example.com", "stanza-id-1", Some(" Spam "), Version::V1);
        assert_eq!(iq.attr("to"), Some("room@muc.example.com"));
        assert_eq!(iq.attr("type"), Some("set"));
        let m = iq.get_child("moderate", NS_MODERATE).unwrap();
        assert_eq!(m.attr("id"), Some("stanza-id-1"));
        assert!(m.get_child("retract", NS_RETRACT).is_some());
        assert_eq!(m.get_child("reason", NS_MODERATE).unwrap().text(), "Spam");
        // No reason → no <reason/>.
        let iq = request("room@muc.example.com", "stanza-id-1", Some("  "), Version::V1);
        assert!(iq.get_child("moderate", NS_MODERATE).unwrap().get_child("reason", NS_MODERATE).is_none());
    }

    #[test]
    fn v0_request_is_fastened() {
        let iq = request("room@muc", "sid", Some("Spam"), Version::V0);
        let fasten = iq.get_child("apply-to", NS_FASTEN).unwrap();
        assert_eq!(fasten.attr("id"), Some("sid"));
        let m = fasten.get_child("moderate", NS_MODERATE_0).unwrap();
        assert!(m.get_child("retract", NS_RETRACT_0).is_some());
        assert_eq!(m.get_child("reason", NS_MODERATE_0).unwrap().text(), "Spam");
    }

    #[test]
    fn advertised_prefers_v1() {
        let q = |f: &str| parse(&format!(
            "<query xmlns='http://jabber.org/protocol/disco#info'>{f}</query>"
        ));
        assert_eq!(advertised(&q("<feature var='urn:xmpp:message-moderate:0'/><feature var='urn:xmpp:message-moderate:1'/>")), Some(Version::V1));
        assert_eq!(advertised(&q("<feature var='urn:xmpp:message-moderate:0'/>")), Some(Version::V0));
        assert_eq!(advertised(&q("<feature var='muc_open'/>")), None);
    }

    #[test]
    fn parses_v1_broadcast() {
        let msg = parse(
            "<message xmlns='jabber:client' type='groupchat' from='room@muc'>\
               <retract id='stanza-id-1' xmlns='urn:xmpp:message-retract:1'>\
                 <moderated by='room@muc/macbeth' xmlns='urn:xmpp:message-moderate:1'/>\
                 <reason>Inappropriate</reason>\
               </retract></message>",
        );
        assert_eq!(moderation_target(&msg), Some(("stanza-id-1".into(), Some("Inappropriate".into()))));
    }

    #[test]
    fn parses_legacy_broadcast() {
        let msg = parse(
            "<message xmlns='jabber:client' type='groupchat' from='room@muc'>\
               <apply-to id='sid' xmlns='urn:xmpp:fasten:0'>\
                 <moderated by='room@muc/m' xmlns='urn:xmpp:message-moderate:0'>\
                   <retract xmlns='urn:xmpp:message-retract:0'/><reason>Spam</reason>\
                 </moderated></apply-to></message>",
        );
        assert_eq!(moderation_target(&msg), Some(("sid".into(), Some("Spam".into()))));
    }

    #[test]
    fn plain_retraction_is_not_a_moderation() {
        let msg = parse(
            "<message xmlns='jabber:client' type='groupchat' from='room@muc/alice'>\
               <retract id='x' xmlns='urn:xmpp:message-retract:1'/></message>",
        );
        assert_eq!(moderation_target(&msg), None);
        // A <moderated> in a foreign namespace doesn't count either.
        let msg = parse(
            "<message xmlns='jabber:client' type='groupchat' from='room@muc'>\
               <retract id='x' xmlns='urn:xmpp:message-retract:1'><moderated xmlns='urn:example'/></retract></message>",
        );
        assert_eq!(moderation_target(&msg), None);
    }

    #[test]
    fn parses_mam_tombstone() {
        let msg = parse(
            "<message xmlns='jabber:client' type='groupchat' from='room@muc/oldhag'>\
               <retracted stamp='2019-09-20T23:19:12Z' xmlns='urn:xmpp:message-retract:1'>\
                 <moderated by='witch@shakespeare.example' xmlns='urn:xmpp:message-moderate:1'/>\
                 <reason>Off topic</reason>\
               </retracted></message>",
        );
        assert_eq!(tombstone(&msg), Some(Some("Off topic".into())));
        let plain = parse("<message xmlns='jabber:client'><body>hi</body></message>");
        assert_eq!(tombstone(&plain), None);
    }
}
