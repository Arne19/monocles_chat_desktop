//! XEP-0272 Muji — multiparty Jingle (group calls).
//!
//! A Muji conference *is* a MUC. Participants coordinate through their MUC presence: each
//! announces a `<muji>` payload (first `<preparing/>`, then the media `<content>` codec
//! advertisement) and then establishes a **full mesh** of ordinary 1:1 Jingle RTP sessions —
//! one per other participant — each tagged with `<muji room=…/>`. This module owns only the
//! Muji *presence* coordination + the glare tie-break; the per-pair sessions reuse the 1:1
//! machinery in [`super::jingle`] / [`super::jingle_sdp`].

use minidom::Element;

use crate::client::Writer;
use crate::xeps::{caps, jingle_sdp};

/// XEP-0272 Muji namespace.
pub const NS_MUJI: &str = "urn:xmpp:jingle:muji:0";

/// A peer occupant's advertised Muji state, parsed from their MUC presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MujiState {
    /// `<muji><preparing/></muji>` — allocating streams, not yet callable.
    Preparing,
    /// `<muji>` with `<content>` and no `<preparing/>` — ready to be called.
    Ready,
}

/// Build our `<muji>` presence payload. While `prepared` is false we advertise only
/// `<preparing/>`; once true we advertise the media `<content>` codec set (Opus audio, plus
/// VP8 video when `video`) and drop `<preparing/>`. The payload-types are advisory (XEP-0272
/// §codec coordination) — our engine's set is fixed, and the real per-pair sessions still run
/// a full SDP offer/answer.
///
/// `device` is our OMEMO device id, advertised as the `device` attribute (wire-compatible with
/// the monocles/Conversations Android client): a peer reads it to know which device to OMEMO-
/// encrypt its per-pair DTLS fingerprint to. Without it, an Android peer with required OMEMO
/// verification cannot encrypt to us and refuses the leg.
pub fn muji_payload(prepared: bool, video: bool, device: Option<u32>) -> Element {
    let mut muji = Element::builder("muji", NS_MUJI);
    if let Some(dev) = device {
        muji = muji.attr(crate::ncname("device"), dev.to_string());
    }
    if !prepared {
        return muji.append(Element::builder("preparing", NS_MUJI).build()).build();
    }
    // Audio content (Opus).
    let audio = Element::builder("content", NS_MUJI)
        .attr(crate::ncname("creator"), "initiator")
        .attr(crate::ncname("name"), "voice")
        .append(
            Element::builder("description", jingle_sdp::NS_RTP)
                .attr(crate::ncname("media"), "audio")
                .append(
                    Element::builder("payload-type", jingle_sdp::NS_RTP)
                        .attr(crate::ncname("id"), "111")
                        .attr(crate::ncname("name"), "opus")
                        .attr(crate::ncname("clockrate"), "48000")
                        .attr(crate::ncname("channels"), "2")
                        .build(),
                )
                .build(),
        )
        .build();
    muji = muji.append(audio);
    if video {
        let vid = Element::builder("content", NS_MUJI)
            .attr(crate::ncname("creator"), "initiator")
            .attr(crate::ncname("name"), "webcam")
            .append(
                Element::builder("description", jingle_sdp::NS_RTP)
                    .attr(crate::ncname("media"), "video")
                    .append(
                        Element::builder("payload-type", jingle_sdp::NS_RTP)
                            .attr(crate::ncname("id"), "96")
                            .attr(crate::ncname("name"), "VP8")
                            .attr(crate::ncname("clockrate"), "90000")
                            .build(),
                    )
                    .build(),
            )
            .build();
        muji = muji.append(vid);
    }
    muji.build()
}

/// Send a directed MUC presence to `room/nick` carrying an optional `<muji>` payload (plus our
/// caps). `muji = None` re-sends a plain presence with no `<muji>` — i.e. we have left the
/// conference (XEP-0272: drop `<muji>` first, *then* terminate the Jingle sessions).
pub fn send_muji_presence(
    w: &Writer,
    room: &str,
    nick: &str,
    muji: Option<Element>,
) -> anyhow::Result<()> {
    let mut pres = Element::builder("presence", "jabber:client")
        .attr(crate::ncname("to"), format!("{room}/{nick}"))
        .append(caps::caps_element());
    if let Some(m) = muji {
        pres = pres.append(m);
    }
    w.send(pres.build())
}

/// Inspect an occupant's presence for a `<muji>` element and classify it. Returns `None` when
/// there is no `<muji>` (the occupant is not participating, or has left the conference).
pub fn parse_muji_state(presence: &Element) -> Option<MujiState> {
    parse_muji(presence).map(|(state, _)| state)
}

/// Like [`parse_muji_state`], plus the advertised OMEMO device id (`device` attribute). A value
/// outside 1..=2³¹-1 or that doesn't parse is treated as absent (it comes from another occupant).
pub fn parse_muji(presence: &Element) -> Option<(MujiState, Option<u32>)> {
    let muji = presence.get_child("muji", NS_MUJI)?;
    let device = muji
        .attr("device")
        .and_then(|d| d.parse::<u32>().ok())
        .filter(|d| (1..=i32::MAX as u32).contains(d));
    Some((parse_state(muji), device))
}

fn parse_state(muji: &Element) -> MujiState {
    if muji.get_child("preparing", NS_MUJI).is_some() {
        MujiState::Preparing
    } else if muji.children().any(|c| c.name() == "content") {
        MujiState::Ready
    } else {
        // A bare `<muji/>` with neither preparing nor content — treat as preparing.
        MujiState::Preparing
    }
}

// --- presence persistence hooks ----------------------------------------------------------------
//
// While we're in a room's call, EVERY presence we send to that room must keep carrying `<muji>`:
// a presence without it tells the other participants we left, and they hang up their legs to us.
// The MUC join (re-sent on every non-resumed reconnect) is built in `muc::join`, which has no
// access to the call registry — so the active payloads live here. Everything runs on the
// per-account actor thread, hence thread-local.

thread_local! {
    static ACTIVE: std::cell::RefCell<std::collections::HashMap<(i64, String), Element>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
    static JOINING: std::cell::RefCell<std::collections::HashSet<(i64, String)>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
    static JOINED: std::cell::RefCell<std::collections::HashSet<(i64, String)>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

/// We sent the join presence to `room`: its occupants may coordinate group calls with us.
pub fn mark_room_joined(account_id: i64, room: &str) {
    JOINED.with(|j| {
        j.borrow_mut().insert((account_id, super::jingle::room_key(room)));
    });
}

/// We left `room` (or were removed from it).
pub fn forget_room(account_id: i64, room: &str) {
    JOINED.with(|j| {
        j.borrow_mut().remove(&(account_id, super::jingle::room_key(room)));
    });
}

/// Whether `room` is a MUC we joined — synchronous on purpose: the presence handler must not
/// await before applying a presence, or a later presence of the same occupant (ready after
/// preparing, available after unavailable) can overtake it.
pub fn is_room_joined(account_id: i64, room: &str) -> bool {
    JOINED.with(|j| j.borrow().contains(&(account_id, super::jingle::room_key(room))))
}

/// Record (or with `None`, clear) the `<muji>` payload our presence to `room` must carry.
pub fn set_active_payload(account_id: i64, room: &str, payload: Option<Element>) {
    ACTIVE.with(|a| {
        let mut a = a.borrow_mut();
        match payload {
            Some(p) => {
                a.insert((account_id, super::jingle::room_key(room)), p);
            }
            None => {
                a.remove(&(account_id, super::jingle::room_key(room)));
            }
        }
    });
}

/// The `<muji>` payload to attach to a presence we send to `room`, if we're in its call.
pub fn active_payload(account_id: i64, room: &str) -> Option<Element> {
    ACTIVE.with(|a| a.borrow().get(&(account_id, super::jingle::room_key(room))).cloned())
}

/// We're (re)joining `room`: it is about to replay every occupant's presence, so the Muji state
/// we saw before (participants who left while we were disconnected) must be forgotten. Consumed
/// by the call coordinator on the room's next presence.
pub fn mark_room_joining(account_id: i64, room: &str) {
    JOINING.with(|j| {
        j.borrow_mut().insert((account_id, super::jingle::room_key(room)));
    });
}

/// Whether `room` was (re)joined since the last call; clears the mark.
pub fn take_room_joining(account_id: i64, room: &str) -> bool {
    JOINING.with(|j| j.borrow_mut().remove(&(account_id, super::jingle::room_key(room))))
}

/// Glare tie-break (XEP-0272 §6): when two ready participants could each initiate a Jingle
/// session with the other, only one must. Deterministically pick the participant whose
/// occupant JID (`room/nick`) is lexicographically greater as the initiator. Both sides see the
/// same pair of occupant JIDs, so exactly one returns `true`.
///
/// Only the nicks (resource parts) are compared: the room is the same for both by definition,
/// but the two clients may spell it differently (letter case from a bookmark / the UI vs. the
/// server's presence `from`). Comparing it let them disagree — both waiting for the other, so the
/// leg never came up and the re-mesh churned. Same as Android's `Muji.shouldInitiate`.
pub fn should_initiate(my_occupant_jid: &str, their_occupant_jid: &str) -> bool {
    // Android compares Java Strings (UTF-16 code units); for the BMP that's the same order as
    // Rust's byte-wise UTF-8 comparison, so both clients pick the same initiator.
    nick(my_occupant_jid) > nick(their_occupant_jid)
}

fn nick(occupant_jid: &str) -> &str {
    occupant_jid.split_once('/').map(|(_, n)| n).unwrap_or(occupant_jid)
}

/// Maximum number of remote participants we keep a per-pair leg with (full mesh: one ICE agent
/// and one uplink copy of our media per peer). Same limit as monocles Android.
pub const MAX_PEERS: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    fn presence_with(muji: Element) -> Element {
        Element::builder("presence", "jabber:client").append(muji).build()
    }

    #[test]
    fn device_attribute_is_validated() {
        let ok = presence_with(muji_payload(true, false, Some(12345)));
        assert_eq!(parse_muji(&ok), Some((MujiState::Ready, Some(12345))));
        for bad in ["0", "-5", "abc", "4294967295"] {
            let el = Element::builder("muji", NS_MUJI)
                .attr(crate::ncname("device"), bad)
                .append(Element::builder("preparing", NS_MUJI).build())
                .build();
            assert_eq!(parse_muji(&presence_with(el)), Some((MujiState::Preparing, None)), "device={bad}");
        }
    }

    #[test]
    fn tie_break_is_antisymmetric() {
        let (a, b) = ("room@muc.example/alice", "room@muc.example/bob");
        assert_ne!(should_initiate(a, b), should_initiate(b, a));
        assert!(!should_initiate(a, a));
        // the room's spelling must not decide it — only the nicks
        assert!(should_initiate("Room@muc.example/bob", "room@muc.example/alice"));
        assert!(!should_initiate("room@muc.example/alice", "Room@muc.example/bob"));
    }

    #[test]
    fn active_payload_round_trip() {
        assert!(active_payload(1, "r@muc").is_none());
        set_active_payload(1, "r@muc", Some(muji_payload(true, true, None)));
        assert!(active_payload(1, "r@muc").is_some());
        set_active_payload(1, "r@muc", None);
        assert!(active_payload(1, "r@muc").is_none());
        mark_room_joining(1, "R@MUC");
        assert!(take_room_joining(1, "r@muc"));
        assert!(!take_room_joining(1, "r@muc"));
        assert!(!is_room_joined(1, "r@muc"));
        mark_room_joined(1, "R@Muc");
        assert!(is_room_joined(1, "r@muc"));
        assert!(!is_room_joined(2, "r@muc"));
        forget_room(1, "r@MUC");
        assert!(!is_room_joined(1, "r@muc"));
    }
}
