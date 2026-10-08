//! XEP-0030 service discovery + the feature set we advertise.
//!
//! The advertised features feed XEP-0115 caps (see [`super::caps`]). The list mirrors
//! what the monocles Android client announces so peers negotiate the same options.

use minidom::Element;

/// Our disco#info identity.
pub const CLIENT_CATEGORY: &str = "client";
pub const CLIENT_TYPE: &str = "pc";
pub const CLIENT_NAME: &str = "monocles chat";

/// Feature vars we advertise (subset wired in Phase 0; grows per phase).
/// Keep sorted — XEP-0115 ver hashing is order-sensitive.
pub const FEATURES: &[&str] = &[
    "http://jabber.org/protocol/caps",
    "http://jabber.org/protocol/chatstates",       // XEP-0085
    "http://jabber.org/protocol/disco#info",        // XEP-0030
    "http://jabber.org/protocol/disco#items",
    "jabber:iq:version",                            // XEP-0092
    "jabber:x:oob",                                 // XEP-0066
    "urn:monocles:omemo-pq:1",                      // PQ OMEMO2 (proto-XEP OMEMO-PQXDH)
    "urn:monocles:omemo-pq:1:devices+notify",       // PEP +notify for device list
    "urn:monocles:omemo-pq:1:pqxdh",                // PQXDH capability (diagnostics, §11.3)
    "urn:monocles:omemo-pq:1:spqr",                 // SPQR capability (diagnostics, §11.3)
    "urn:xmpp:chat-markers:0",                      // XEP-0333
    // Jingle A/V calling (XEP-0166/0167/0176/0320/0353). Android gates the in-call
    // "switch to video" button on the peer advertising `…:apps:rtp:video`, so all of these
    // must be present for the audio→video upgrade to be offered. Keep sorted (caps hash).
    "urn:xmpp:jingle-message:0",                    // XEP-0353 JMI
    "urn:xmpp:jingle:1",                            // XEP-0166
    "urn:xmpp:jingle:apps:dtls:0",                  // XEP-0320 DTLS-SRTP
    "urn:xmpp:jingle:apps:rtp:1",                   // XEP-0167 RTP sessions
    "urn:xmpp:jingle:apps:rtp:audio",              // audio media
    "urn:xmpp:jingle:apps:rtp:video",              // video media (enables the upgrade button)
    "urn:xmpp:jingle:muji:0",                       // XEP-0272 Muji (group calls)
    "urn:xmpp:jingle:transports:ice-udp:1",        // XEP-0176 ICE-UDP
    "urn:xmpp:message-correct:0",                   // XEP-0308
    "urn:xmpp:message-retract:1",                   // XEP-0424
    "urn:xmpp:microblog:0+notify",                  // XEP-0472 feed PEP push
    "urn:xmpp:ping",                                // XEP-0199
    "urn:xmpp:pubsub-social-feed:stories:0+notify", // Stories PEP push
    "urn:xmpp:reactions:0",                         // XEP-0444
    "urn:xmpp:receipts",                            // XEP-0184
    "urn:xmpp:reply:0",                             // XEP-0461
    "urn:xmpp:sid:0",                               // XEP-0359 stanza/origin id
];

/// Build the `<query xmlns=disco#info>` reply body for our client.
pub fn info_query() -> Element {
    let mut q = Element::builder("query", "http://jabber.org/protocol/disco#info")
        .append(
            Element::builder("identity", "http://jabber.org/protocol/disco#info")
                .attr(crate::ncname("category"), CLIENT_CATEGORY)
                .attr(crate::ncname("type"), CLIENT_TYPE)
                .attr(crate::ncname("name"), CLIENT_NAME)
                .build(),
        )
        .build();
    for f in FEATURES {
        q.append_child(
            Element::builder("feature", "http://jabber.org/protocol/disco#info")
                .attr(crate::ncname("var"), *f)
                .build(),
        );
    }
    q
}

/// Reply to a disco#info `get` with our capabilities.
pub fn answer_info(w: &crate::client::Writer, req: &Element) -> anyhow::Result<()> {
    w.send(result_iq(req, info_query()))
}

/// We expose no disco#items (no sub-services) → empty result.
pub fn answer_items(w: &crate::client::Writer, req: &Element) -> anyhow::Result<()> {
    let q = Element::builder("query", "http://jabber.org/protocol/disco#items").build();
    w.send(result_iq(req, q))
}

/// Wrap a payload as an `<iq type=result>` mirroring id/from↔to of `req`.
pub(crate) fn result_iq(req: &Element, payload: Element) -> Element {
    let mut b = Element::builder("iq", "jabber:client").attr(crate::ncname("type"), "result");
    if let Some(id) = req.attr("id") {
        b = b.attr(crate::ncname("id"), id);
    }
    if let Some(from) = req.attr("from") {
        b = b.attr(crate::ncname("to"), from);
    }
    b.append(payload).build()
}
