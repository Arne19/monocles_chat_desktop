//! XEP-0353 Jingle Message Initiation (call ringing) + XEP-0166 Jingle session orchestration.
//!
//! Signalling lives here; the media (RTP) is handled by [`mxc_media`]'s GStreamer engine, which
//! this module drives via SDP/ICE. JMI rings the peer (`propose`/`proceed`/`reject`/`retract`);
//! once both sides agree, a [`mxc_media::CallEngine`] is created and its SDP/ICE is mapped to
//! Jingle IQs (`session-initiate`/`session-accept`/`transport-info`/`session-terminate`) by
//! [`super::jingle_sdp`]. Stanzas mirror monocles chat for Android for interop.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use async_channel::Sender;
use minidom::Element;

use crate::client::{AccountConfig, Writer};
use crate::event::{CallState, ConfParticipant, Event};
use crate::xeps::jingle_sdp;
use crate::xeps::muji::{self, MujiState};
use crate::xeps::roster::new_id;

pub const NS_JMI: &str = "urn:xmpp:jingle-message:0";
pub const NS_RTP: &str = "urn:xmpp:jingle:apps:rtp:1";
/// XEP-0166 Jingle session namespace (re-exported for the router's IQ dispatch).
pub const NS_JINGLE_SESSION: &str = "urn:xmpp:jingle:1";
const NS_HINTS: &str = "urn:xmpp:hints";
/// OMEMO-verified DTLS-SRTP (gultsch draft): the DTLS `<fingerprint>` is OMEMO2-encrypted so the
/// peer can authenticate it, preventing a MITM on the call's DTLS. Mirrors monocles Android.
const NS_OMEMO_DTLS: &str = "http://gultsch.de/xmpp/drafts/omemo/dlts-srtp-verification";
const NS_RECEIPTS: &str = "urn:xmpp:receipts";
const NS_CLIENT: &str = "jabber:client";

// ============================ call registry ================================

/// A live media call (the engine + who we're talking to).
struct ActiveCall {
    engine: mxc_media::CallEngine,
    peer_full: String,
    /// The peer's current Jingle `<content>` set (audio, plus video after an upgrade). Kept so a
    /// `content-add`/`content-accept` delta can be merged into a full SDP for the engine.
    remote_contents: Vec<Element>,
    /// Whether the call currently carries video (audio→video upgrade flips this).
    video: bool,
    /// A peer's incoming video `content-add` awaiting the user's consent (the new video
    /// `<content>` elements). Applied on accept, dropped on decline.
    pending_video: Vec<Element>,
    /// Whether the peer OMEMO-encrypted its DTLS fingerprint. We mirror this: only encrypt our
    /// own fingerprint when the peer did, so a plaintext call stays plaintext both ways (Android
    /// aborts if it sent a plaintext offer but receives an encrypted answer).
    peer_used_omemo: bool,
    /// For a Muji (XEP-0272) per-pair session, the conference room bare JID it belongs to;
    /// `None` for an ordinary 1:1 call. Muji sessions opportunistically OMEMO-verify their DTLS
    /// fingerprint (like 1:1) and carry a `<muji room=…/>` on their session-initiate.
    room: Option<String>,
    /// Whether we are the Jingle session initiator (we sent the session-initiate).
    we_initiator: bool,
    /// Muji: names of the contents negotiated on this leg so far — a renegotiation signals only
    /// the contents that are new (a content-add/-accept must not repeat an existing name).
    negotiated: Vec<String>,
    /// Muji: whether our current local description sends video on some m-line.
    sends_video: bool,
    /// Muji: our video content-add awaits the peer's content-accept/-reject.
    video_offer_pending: bool,
    /// Muji: don't offer our camera on this leg again before this instant (the peer refused it).
    video_retry_after: Option<std::time::Instant>,
    /// Muji: ICE has connected at least once (renegotiation is only signalled after that).
    connected: bool,
    /// Muji leg of a call placed under the OMEMO2 lock: DTLS fingerprints MUST be OMEMO2-encrypted
    /// both ways, from a trusted identity — never cleartext (a leg that can't comply fails).
    require_verified: bool,
    /// Muji: the OMEMO device id the room advertised for the peer (`<muji device>`); the device
    /// that encrypted the peer's fingerprint must be this one.
    peer_device: Option<u32>,
    /// The peer's negotiated DTLS role (`active`/`passive`), once known. The stored peer
    /// description may still say `actpass` (it was an offer); when we rebuild the peer's
    /// description for a renegotiation it must carry the role actually in use — an ANSWER with
    /// `a=setup:actpass` is invalid and webrtcbin can't apply it (→ no video after an upgrade).
    peer_setup: Option<String>,
    /// The OMEMO2 identity (fingerprint, device) that authenticated this leg's DTLS fingerprint at
    /// setup. Once set, every renegotiated fingerprint (content-add/-accept) must be encrypted and
    /// come from this same identity — otherwise a renegotiation could quietly drop the call's
    /// verification (cleartext) or switch identity. Mirrors Android's `OmemoVerification`.
    verified_identity: Option<(String, i64)>,
    /// Call-trust level of this leg's DTLS fingerprint (0 = not OMEMO-authenticated or the
    /// identity isn't trusted, 1 = trusted, 2 = manually verified). Muji legs report it per
    /// participant in `ConferenceUpdate` instead of the 1:1 `CallVerified` indicator.
    trust: i64,
}

/// At most this many video contents per group-call leg: the peer's camera, plus a second m-line
/// when one side upgrades over a receive-only one. More would only be a resource-exhaustion
/// attack (each accepted m-line is decoded).
const MAX_MUJI_VIDEO_CONTENTS: usize = 2;

/// How long a Muji leg waits before offering our camera again after the peer refused it.
const MUJI_VIDEO_RETRY: std::time::Duration = std::time::Duration::from_secs(30);
/// How long an incoming 1:1 call rings before it is treated as missed.
const INCOMING_RING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

// ============================ Muji conference (group calls) ================

/// Per-pair call state of a remote participant, surfaced to the conference UI.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberCallState {
    Connecting,
    Active,
    Ended,
}

impl MemberCallState {
    fn as_str(self) -> &'static str {
        match self {
            MemberCallState::Connecting => "connecting",
            MemberCallState::Active => "active",
            MemberCallState::Ended => "ended",
        }
    }
}

/// A remote participant of a Muji conference we're in.
struct Member {
    /// Their occupant JID (`room/nick`) — for the display name + avatar.
    occupant_jid: String,
    /// Their real full JID (`user@host/resource`, from the MUC presence `<item jid>`) — how we
    /// address their per-pair Jingle. Routing to the occupant JID via the MUC is unreliable
    /// peer-to-peer (esp. between two non-server clients); the real JID routes directly.
    real_jid: String,
    /// The per-pair Jingle session id, once one exists.
    sid: Option<String>,
    state: MemberCallState,
    /// When this member's leg last (re)started connecting — used by the re-mesh to drop a leg
    /// that never reaches `Active` (a stuck / one-sided session) and try again.
    connecting_since: std::time::Instant,
}

/// A peer's observed Muji presence: readiness + their real full JID for direct Jingle addressing.
#[derive(Clone)]
struct MujiPeer {
    state: MujiState,
    real_jid: String,
    /// The OMEMO device id advertised in their `<muji device>`, if any.
    device: Option<u32>,
}

/// A live Muji group call we're participating in, keyed in [`Calls::conferences`] by room JID.
struct Conference {
    nick: String,
    /// Our own occupant JID (`room/nick`), used for the glare tie-break + as Jingle initiator.
    our_occupant: String,
    /// Whether we send video in this call (from the start, or after upgrading mid-call).
    video: bool,
    /// Placed/joined while the room's encryption was OMEMO2: every leg must be verified.
    verified: bool,
    /// For the call history (one row per group call): the room as the store spells it, when we
    /// placed/joined, whether we started the call (no participant was in it yet) or joined a
    /// running one, and whether any leg ever connected.
    stored_room: String,
    started_at: String,
    outgoing: bool,
    answered: bool,
    /// The room has rebroadcast our READY `<muji>` (XEP-0272: only then do we start legs — a leg
    /// request travels directly and could overtake our presence, which goes via the room).
    announced: bool,
    /// Whether our mic is muted across the whole conference (applied to each per-pair engine).
    muted: bool,
    /// Whether our camera is on (applied to each per-pair engine; new legs inherit it).
    camera_enabled: bool,
    /// Active screen share kept alive while sharing (its Drop ends the portal cast). The capture
    /// itself is switched in at the shared camera hub, so all legs relay it.
    screen: Option<mxc_media::ScreenShare>,
    /// Remote participants, keyed by occupant JID.
    members: HashMap<String, Member>,
}

/// Bookkeeping for the call-history log: kept per session id from the call's start until it
/// ends, when a [`call_log`](mxc_store) row is written.
struct CallMeta {
    peer: String,
    outgoing: bool,
    video: bool,
    /// Whether the call connected (vs. missed / not answered).
    answered: bool,
    /// RFC3339 start time.
    ts: String,
}

/// Per-account call bookkeeping, shared (single-threaded) between command handling, incoming
/// stanza handling, and the per-call engine-event pump.
pub struct Calls {
    /// Live media sessions, keyed by Jingle session id.
    active: HashMap<String, ActiveCall>,
    /// Calls we placed and are ringing out: sid → whether video was offered.
    proposed: HashMap<String, bool>,
    /// Calls ringing in: sid → (caller full JID, video).
    incoming: HashMap<String, (String, bool)>,
    /// Call-history metadata, kept until the call ends (then logged).
    meta: HashMap<String, CallMeta>,
    /// Active Muji group calls, keyed by room bare JID.
    conferences: HashMap<String, Conference>,
    /// Latest observed Muji presence state per occupant, keyed by room then occupant JID.
    /// Tracked independently of [`conferences`] so a call we join *after* peers announced their
    /// `<muji>` still sees who is already ready.
    muji_seen: HashMap<String, HashMap<String, MujiPeer>>,
    /// Rooms for which we've surfaced a group-call invite (so we prompt once per call, and emit a
    /// cancellation when the call ends). Only used while we are NOT in that conference.
    invited: std::collections::HashSet<String>,
    /// Sessions we ended locally, as (sid, peer full JID) — bounded. The peer's own
    /// `session-terminate` for such a session usually crosses ours; it's acknowledged quietly
    /// instead of being answered with an unknown-session error (see `handle_iq`).
    recently_ended: std::collections::VecDeque<(String, String)>,
    /// Sink for decoded video frames, forwarded to the UI (tagged with the call's sid).
    video_tx: Sender<crate::event::CallVideoFrame>,
    /// For persisting the call history.
    store: mxc_store::Store,
    account_id: i64,
}

pub type CallRegistry = Rc<RefCell<Calls>>;

pub fn registry(
    video_tx: Sender<crate::event::CallVideoFrame>,
    store: mxc_store::Store,
    account_id: i64,
) -> CallRegistry {
    Rc::new(RefCell::new(Calls {
        active: HashMap::new(),
        proposed: HashMap::new(),
        incoming: HashMap::new(),
        meta: HashMap::new(),
        conferences: HashMap::new(),
        muji_seen: HashMap::new(),
        invited: std::collections::HashSet::new(),
        recently_ended: std::collections::VecDeque::new(),
        video_tx,
        store,
        account_id,
    }))
}

/// A room's bare JID as the conference key: bare JIDs are case-insensitive, and the room string
/// reaches us spelled differently (from the UI / a bookmark, from the server's presence `from`,
/// from a peer's `<muji room>`). Keying by the raw string made the desktop not recognise its own
/// call — it declined every leg a peer initiated, which then retried forever.
pub fn room_key(room: &str) -> String {
    bare(room).to_lowercase()
}

const RECENTLY_ENDED_CAP: usize = 32;

/// Remove a live session from the registry, remembering it as recently ended.
fn remove_active(calls: &CallRegistry, sid: &str) -> Option<ActiveCall> {
    let mut c = calls.borrow_mut();
    let call = c.active.remove(sid)?;
    remember_ended(&mut c.recently_ended, sid, &call.peer_full);
    Some(call)
}

fn remember_ended(ring: &mut std::collections::VecDeque<(String, String)>, sid: &str, peer_full: &str) {
    if ring.len() >= RECENTLY_ENDED_CAP {
        ring.pop_front();
    }
    ring.push_back((sid.to_string(), peer_full.to_string()));
}

/// Whether `from` is the peer of session `sid` that we ended recently.
fn was_recently_ended(ring: &std::collections::VecDeque<(String, String)>, sid: &str, from: &str) -> bool {
    ring.iter().any(|(s, peer)| s == sid && super::origin::jid_eq(peer, from))
}

fn bare(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}

fn now() -> String {
    crate::xeps::rfc3339_now()
}

/// Mark a call as answered/connected (for the history outcome).
fn mark_answered(calls: &CallRegistry, sid: &str) {
    if let Some(m) = calls.borrow_mut().meta.get_mut(sid) {
        m.answered = true;
    }
}

/// Write the call-history row for a finished call (idempotent — only the first call with a
/// given sid logs, since the metadata is removed).
fn log_call_end(calls: &CallRegistry, sid: &str) {
    let (store, account, meta) = {
        let mut c = calls.borrow_mut();
        (c.store.clone(), c.account_id, c.meta.remove(sid))
    };
    if let Some(m) = meta {
        let dir = if m.outgoing { "out" } else { "in" };
        let store = store.clone();
        let (peer, dir, video, answered, ts) = (m.peer, dir.to_string(), m.video, m.answered, m.ts);
        tokio::task::spawn_local(async move {
            let _ = store.insert_call_log(account, &peer, &dir, video, answered, &ts, false).await;
        });
    }
}

/// Write the call-history row for a group call that ended (one row per call, not per leg; the
/// peer is the room, so the Calls list can show the group).
fn log_conference_end(store: &mxc_store::Store, account_id: i64, conf: &Conference) {
    let store = store.clone();
    let (room, dir, video, answered, ts) = (
        conf.stored_room.clone(),
        // "in" only if we joined a running call AND a leg connected: the Calls list shows
        // in + unanswered as a missed call, which a group call never is (retried/failed legs).
        if !conf.outgoing && conf.answered { "in" } else { "out" }.to_string(),
        conf.video,
        conf.answered,
        conf.started_at.clone(),
    );
    tokio::task::spawn_local(async move {
        let _ = store.insert_call_log(account_id, &room, &dir, video, answered, &ts, true).await;
    });
}

/// Whether we're already in a call other than `sid`: a group call (also while waiting alone, with
/// no leg yet) or a ringing / placed / live 1:1 call. Only one call at a time (monocles Muji
/// profile, "Concurrent Calls"). Group-call legs are not checked through this: they belong to the
/// conference we're in.
fn is_busy_except(c: &Calls, sid: &str) -> bool {
    !c.conferences.is_empty()
        || c.incoming.keys().any(|s| s != sid)
        || c.proposed.keys().any(|s| s != sid)
        || c.active.keys().any(|s| s != sid)
}

/// Whether we're in any call (for refusing to place a new 1:1 call).
pub fn is_busy(calls: &CallRegistry) -> bool {
    is_busy_except(&calls.borrow(), "")
}

// ============================ JMI (ringing) ================================

fn jmi(to: &str, action: &str, sid: &str) -> Element {
    jmi_with_device(to, action, sid, None)
}

/// Like [`jmi`], but optionally advertises our OMEMO2 device id (`<device id=… xmlns=…>`) so the
/// peer encrypts the call's DTLS fingerprint to us (OMEMO-verified calls). Android puts this on
/// the `proceed`; the caller reads it to encrypt the session-initiate.
fn jmi_with_device(to: &str, action: &str, sid: &str, own_device: Option<u32>) -> Element {
    let mut intent = Element::builder(action, NS_JMI).attr(crate::ncname("id"), sid);
    if let Some(dev) = own_device {
        intent = intent.append(
            Element::builder("device", NS_OMEMO_DTLS).attr(crate::ncname("id"), dev.to_string()).build(),
        );
    }
    Element::builder("message", NS_CLIENT)
        .attr(crate::ncname("to"), to)
        .attr(crate::ncname("type"), "chat")
        .append(intent.build())
        .append(Element::builder("store", NS_HINTS).build())
        .build()
}

/// Ring `to` (bare JID) to start a call. `sid` is the session id; record it as proposed.
pub fn propose(w: &Writer, calls: &CallRegistry, to: &str, sid: &str, video: bool) -> anyhow::Result<()> {
    {
        let mut c = calls.borrow_mut();
        c.proposed.insert(sid.to_string(), video);
        c.meta.insert(sid.to_string(), CallMeta {
            peer: bare(to).to_string(),
            outgoing: true,
            video,
            answered: false,
            ts: now(),
        });
    }
    let mut propose = Element::builder("propose", NS_JMI).attr(crate::ncname("id"), sid).append(
        Element::builder("description", NS_RTP).attr(crate::ncname("media"), "audio").build(),
    );
    if video {
        propose = propose.append(Element::builder("description", NS_RTP).attr(crate::ncname("media"), "video").build());
    }
    let msg = Element::builder("message", NS_CLIENT)
        .attr(crate::ncname("to"), to)
        .attr(crate::ncname("type"), "chat")
        .append(propose.build())
        .append(Element::builder("request", NS_RECEIPTS).build())
        .append(Element::builder("store", NS_HINTS).build())
        .build();
    w.send(msg)
}

/// Decline a ringing call: reject to the caller and to our own devices.
pub fn reject(w: &Writer, calls: &CallRegistry, caller: &str, own_bare: &str, sid: &str) -> anyhow::Result<()> {
    calls.borrow_mut().incoming.remove(sid);
    log_call_end(calls, sid);
    w.send(jmi(caller, "reject", sid))?;
    w.send(jmi(own_bare, "reject", sid))
}

/// Cancel an outgoing call we placed (peer hasn't answered yet).
pub fn retract(w: &Writer, calls: &CallRegistry, to: &str, sid: &str) -> anyhow::Result<()> {
    calls.borrow_mut().proposed.remove(sid);
    w.send(jmi(to, "retract", sid))
}

// ============================ Jingle session IQs ===========================

fn jingle_iq(to: &str, sid: &str, initiator: &str, action: &str, body: Vec<Element>) -> Element {
    let mut jingle = Element::builder("jingle", jingle_sdp::NS_JINGLE)
        .attr(crate::ncname("action"), action)
        .attr(crate::ncname("sid"), sid)
        .attr(crate::ncname("initiator"), initiator);
    for b in body {
        jingle = jingle.append(b);
    }
    Element::builder("iq", NS_CLIENT)
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("to"), to)
        .attr(crate::ncname("id"), new_id("jingle"))
        .append(jingle.build())
        .build()
}

/// Acknowledge a received Jingle IQ with an empty result.
fn ack(w: &Writer, iq: &Element) {
    let mut b = Element::builder("iq", NS_CLIENT).attr(crate::ncname("type"), "result");
    if let Some(from) = iq.attr("from") {
        b = b.attr(crate::ncname("to"), from);
    }
    if let Some(id) = iq.attr("id") {
        b = b.attr(crate::ncname("id"), id);
    }
    let _ = w.send(b.build());
}

/// Reject a Jingle IQ for a session that doesn't exist (or isn't the sender's) with
/// `item-not-found` + `<unknown-session/>` (XEP-0166 §8).
fn unknown_session(w: &Writer, iq: &Element) {
    let mut b = Element::builder("iq", NS_CLIENT).attr(crate::ncname("type"), "error");
    if let Some(from) = iq.attr("from") {
        b = b.attr(crate::ncname("to"), from);
    }
    if let Some(id) = iq.attr("id") {
        b = b.attr(crate::ncname("id"), id);
    }
    let error = Element::builder("error", NS_CLIENT)
        .attr(crate::ncname("type"), "cancel")
        .append(Element::builder("item-not-found", "urn:ietf:params:xml:ns:xmpp-stanzas").build())
        .append(Element::builder("unknown-session", "urn:xmpp:jingle:errors:1").build())
        .build();
    let _ = w.send(b.append(error).build());
}

/// Whether a JMI message for `sid` comes from that call's peer (bare JID): the contact we
/// rang, or who rang us. Session ids are only unguessable, not secret from the peer's server,
/// so the sender must match too (Conversations keys sessions by (peer, sid)).
fn jmi_from_peer(calls: &CallRegistry, sid: &str, from: &str) -> bool {
    calls
        .borrow()
        .meta
        .get(sid)
        .is_some_and(|m| m.peer.eq_ignore_ascii_case(bare(from)))
}

/// Pull `(ufrag, pwd, mid)` out of our local SDP for addressing trickle `transport-info`.
/// Takes the **first** of each: with BUNDLE the single ICE transport lives on the first m-line
/// (the bundle owner, e.g. `audio0`); the later video m-line is `bundle-only` and must NOT be
/// used to tag candidates, or the peer can't apply them and ICE fails.
fn local_transport(sdp: &str) -> (String, String, String) {
    let mut ufrag = String::new();
    let mut pwd = String::new();
    let mut mid = String::new();
    for line in sdp.lines() {
        if let Some(v) = line.strip_prefix("a=ice-ufrag:") {
            if ufrag.is_empty() {
                ufrag = v.trim().to_string();
            }
        } else if let Some(v) = line.strip_prefix("a=ice-pwd:") {
            if pwd.is_empty() {
                pwd = v.trim().to_string();
            }
        } else if let Some(v) = line.strip_prefix("a=mid:") {
            if mid.is_empty() {
                mid = v.trim().to_string();
            }
        }
    }
    if mid.is_empty() {
        mid = "0".to_string();
    }
    (ufrag, pwd, mid)
}

// ===================== OMEMO-verified DTLS (call verification) =====================

/// Rebuild a `<transport>` with its `<fingerprint>` (any namespace) replaced by `new_fp`.
fn transport_with_fingerprint(transport: &Element, new_fp: Element) -> Element {
    let mut b = Element::builder("transport", transport.ns());
    // minidom 0.19 iterates attrs as ((namespace, NcName), value); copy each preserving its
    // namespace so the rebuilt <transport> is byte-identical apart from the swapped fingerprint.
    for ((ns, name), v) in transport.attrs() {
        b = b.attr_ns(ns.clone(), name.clone(), v.clone());
    }
    for child in transport.children() {
        if child.name() != "fingerprint" {
            b = b.append(child.clone());
        }
    }
    b.append(new_fp).build()
}

/// Rebuild a `<content>` with its `<transport>` replaced by `new_transport`.
fn content_with_transport(content: &Element, new_transport: Element) -> Element {
    let mut b = Element::builder("content", content.ns());
    for ((ns, name), v) in content.attrs() {
        b = b.attr_ns(ns.clone(), name.clone(), v.clone());
    }
    for child in content.children() {
        if child.name() != "transport" {
            b = b.append(child.clone());
        }
    }
    b.append(new_transport).build()
}

/// OMEMO2-encrypt the plaintext DTLS fingerprint in each content's transport. Best-effort unless
/// `strict`: on any failure / missing session the plaintext fingerprint is left as-is so the call
/// still connects — just unverified. With `strict` (a verified group-call leg) any failure
/// returns `None` instead: the leg must fail rather than leak a cleartext fingerprint. Mirrors
/// Android's `encryptTransport`. (`encrypt_for` only ever encrypts to trusted devices.)
async fn encrypt_call_fingerprints(
    w: &Writer,
    store: &mxc_store::Store,
    cfg: &AccountConfig,
    peer_bare: &str,
    contents: Vec<Element>,
    strict: bool,
) -> Option<Vec<Element>> {
    let mut out = Vec::with_capacity(contents.len());
    for content in contents {
        out.push(encrypt_one_fingerprint(w, store, cfg, peer_bare, content, strict).await?);
    }
    Some(out)
}

async fn encrypt_one_fingerprint(
    w: &Writer,
    store: &mxc_store::Store,
    cfg: &AccountConfig,
    peer_bare: &str,
    content: Element,
    strict: bool,
) -> Option<Element> {
    let Some(transport) = content.get_child("transport", jingle_sdp::NS_ICE) else {
        return Some(content);
    };
    let Some(fp) = transport.get_child("fingerprint", jingle_sdp::NS_DTLS) else {
        return Some(content);
    };
    let hex = fp.text();
    let setup = fp.attr("setup").unwrap_or("actpass").to_string();
    let hash = fp.attr("hash").unwrap_or("sha-256").to_string();
    // Wrap the DTLS fingerprint in an SCE envelope (XEP-0420) — same as messages, so the whole
    // thing is bound to sender/recipient/time — then OMEMO2-encrypt it. The SCE `<content>` is
    // the plaintext `<fingerprint xmlns=…dtls:0>` element; both clients agree on this shape.
    let fp_inner = format!(
        "<fingerprint xmlns='{}' hash='{}' setup='{}'>{}</fingerprint>",
        jingle_sdp::NS_DTLS,
        hash,
        setup,
        hex.trim()
    );
    let envelope = mxc_omemo::sce::Envelope::with_content(
        &fp_inner,
        cfg.bare(),
        peer_bare,
        Some(crate::xeps::rfc3339_now()),
    );
    let encrypted = match crate::xeps::omemo::encrypt_for(w, store, cfg, peer_bare, envelope.to_xml().as_bytes()).await {
        Ok(e) => e,
        Err(e) if strict => {
            tracing::warn!(error = %e, "OMEMO call-fingerprint encrypt failed — verified leg, refusing cleartext");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "OMEMO call-fingerprint encrypt failed — sending plaintext");
            return Some(content);
        }
    };
    let new_fp = Element::builder("fingerprint", NS_OMEMO_DTLS)
        .attr(crate::ncname("setup"), setup)
        .attr(crate::ncname("hash"), hash)
        .append(encrypted)
        .build();
    Some(content_with_transport(&content, transport_with_fingerprint(transport, new_fp)))
}

/// Whether every content that carries a DTLS fingerprint carries it OMEMO-encrypted (checked
/// BEFORE decrypting, on a verified group-call leg).
fn all_fingerprints_encrypted(contents: &[Element]) -> bool {
    contents.iter().all(|c| match c.get_child("transport", jingle_sdp::NS_ICE) {
        Some(t) => t.get_child("fingerprint", jingle_sdp::NS_DTLS).is_none(),
        None => true,
    })
}

/// A renegotiation (content-add/-accept) on a leg whose setup was OMEMO-authenticated must keep
/// that authentication: every fingerprint encrypted (`was_encrypted`, checked before decrypting),
/// decrypted, and from the identity that authenticated the leg. A leg that was never
/// authenticated (`identity` None) imposes nothing here.
fn keeps_leg_identity(
    identity: &Option<(String, i64)>,
    was_encrypted: bool,
    contents: &[Element],
    verified: &Option<(String, i64, i64)>,
) -> bool {
    let Some((fp, device)) = identity else { return true };
    was_encrypted
        && all_fingerprints_decrypted(contents)
        && verified.as_ref().is_some_and(|(vfp, vdev, _)| vfp == fp && vdev == device)
}

/// Number of video contents in a content set.
fn video_contents(contents: &[Element]) -> usize {
    contents
        .iter()
        .filter(|c| c.get_child("description", jingle_sdp::NS_RTP).and_then(|d| d.attr("media")) == Some("video"))
        .count()
}

/// Whether every DTLS fingerprint could be decrypted back to plaintext (checked AFTER decrypting:
/// a failed decryption leaves the encrypted element in place).
fn all_fingerprints_decrypted(contents: &[Element]) -> bool {
    contents.iter().all(|c| match c.get_child("transport", jingle_sdp::NS_ICE) {
        Some(t) => t.get_child("fingerprint", NS_OMEMO_DTLS).is_none(),
        None => true,
    })
}

/// The `a=setup:` value of an SDP (first occurrence — BUNDLE shares one transport).
fn sdp_setup(sdp: &str) -> Option<String> {
    sdp.lines()
        .find_map(|l| l.trim_end().strip_prefix("a=setup:"))
        .map(str::to_string)
}

/// The DTLS `setup` of the first content carrying a fingerprint.
fn contents_setup(contents: &[Element]) -> Option<String> {
    contents.iter().find_map(|c| {
        c.get_child("transport", jingle_sdp::NS_ICE)?
            .get_child("fingerprint", jingle_sdp::NS_DTLS)?
            .attr("setup")
            .map(str::to_string)
    })
}

fn opposite_setup(setup: &str) -> Option<String> {
    match setup {
        "active" => Some("passive".to_string()),
        "passive" => Some("active".to_string()),
        _ => None,
    }
}

/// Replace `setup='actpass'` on every content's DTLS fingerprint with the peer's negotiated role
/// (no-op while the role is unknown).
fn with_peer_setup(contents: Vec<Element>, peer_setup: Option<&str>) -> Vec<Element> {
    let Some(role) = peer_setup else { return contents };
    contents
        .into_iter()
        .map(|content| {
            let Some(transport) = content.get_child("transport", jingle_sdp::NS_ICE) else {
                return content;
            };
            let Some(fp) = transport.get_child("fingerprint", jingle_sdp::NS_DTLS) else {
                return content;
            };
            if fp.attr("setup") != Some("actpass") {
                return content;
            }
            let mut b = Element::builder("fingerprint", jingle_sdp::NS_DTLS);
            for ((ns, name), v) in fp.attrs() {
                if name.as_str() != "setup" {
                    b = b.attr_ns(ns.clone(), name.clone(), v.clone());
                }
            }
            let new_fp = b.attr(crate::ncname("setup"), role).append(fp.text()).build();
            content_with_transport(&content, transport_with_fingerprint(transport, new_fp))
        })
        .collect()
}

/// Whether a local SDP sends video on some m-line (direction absent = sendrecv).
fn sdp_sends_video(sdp: &str) -> bool {
    let mut result = false;
    // Some(sends) while inside a video section.
    let mut cur: Option<bool> = None;
    for line in sdp.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("m=") {
            result |= cur == Some(true);
            cur = rest.starts_with("video").then_some(true);
        } else if let Some(sends) = cur.as_mut() {
            match line {
                "a=recvonly" | "a=inactive" => *sends = false,
                "a=sendrecv" | "a=sendonly" => *sends = true,
                _ => {}
            }
        }
    }
    result || cur == Some(true)
}

/// A verified group-call leg that can't be verified: terminate it with `security-error` (only
/// that leg — the rest of the call goes on, as on Android).
async fn fail_verified_leg(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    account_id: i64,
    sid: &str,
    peer_full: &str,
    room: Option<&str>,
) {
    tracing::warn!(%sid, %peer_full, "verified group-call leg could not be verified — terminating it");
    let reason = Element::builder("reason", jingle_sdp::NS_JINGLE)
        .append(Element::builder("security-error", jingle_sdp::NS_JINGLE).build())
        .build();
    let _ = w.send(jingle_iq(peer_full, sid, "", "session-terminate", vec![reason]));
    terminate_local(calls, sid);
    log_call_end(calls, sid);
    set_member_state(calls, sid, MemberCallState::Ended);
    match room {
        Some(r) => {
            emit_conference(calls, events, account_id, r).await;
            end_conference_if_empty(w, calls, events, account_id, r).await;
        }
        None => {
            emit(events, account_id, sid, bare(peer_full), false, CallState::Ended {
                reason: "Call verification failed".into(),
            })
            .await
        }
    }
}

/// Decrypt any OMEMO-verified DTLS fingerprints back to plaintext (so webrtcbin can use them),
/// returning the peer's verified OMEMO2 identity fingerprint + whether it's trusted, if any
/// content carried one. Contents without an OMEMO fingerprint pass through unchanged.
async fn decrypt_call_fingerprints(
    store: &mxc_store::Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    sender_bare: &str,
    contents: Vec<Element>,
) -> (Vec<Element>, Option<(String, i64, i64)>) {
    let mut out = Vec::with_capacity(contents.len());
    // (peer fingerprint, peer device id, call-trust level 0/1/2)
    let mut verified: Option<(String, i64, i64)> = None;
    for content in contents {
        let (c, v) = decrypt_one_fingerprint(store, cfg, events, sender_bare, content).await;
        if v.is_some() {
            verified = v;
        }
        out.push(c);
    }
    (out, verified)
}

async fn decrypt_one_fingerprint(
    store: &mxc_store::Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    sender_bare: &str,
    content: Element,
) -> (Element, Option<(String, i64, i64)>) {
    let Some(transport) = content.get_child("transport", jingle_sdp::NS_ICE) else {
        return (content, None);
    };
    let Some(gfp) = transport.get_child("fingerprint", NS_OMEMO_DTLS) else {
        return (content, None);
    };
    let Some(encrypted) = gfp.children().find(|c| c.name() == "encrypted") else {
        return (content, None);
    };
    let setup = gfp.attr("setup").unwrap_or("active").to_string();
    let hash = gfp.attr("hash").unwrap_or("sha-256").to_string();
    // A call fingerprint is a 1:1 message addressed to us, so the payload context binding (§5.4.2)
    // and the SCE `<to>` (verified below) are both our own bare JID.
    let dec = match crate::xeps::omemo::decrypt_message(store, cfg, events, encrypted, sender_bare, Some(cfg.bare())).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "OMEMO call-fingerprint decrypt failed");
            return (content, None);
        }
    };
    // The decrypted payload is an SCE envelope wrapping the real `<fingerprint xmlns=…dtls:0>`.
    let env = match mxc_omemo::sce::Envelope::from_xml(&String::from_utf8_lossy(&dec.envelope)) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "OMEMO call-fingerprint: bad SCE envelope");
            return (content, None);
        }
    };
    // SCE binding (XEP-0420 §4.5): the envelope must be addressed from the peer to us — guards
    // against reflection/replay. Required before we trust the identity (the shield).
    let bound = env.verify_binding(cfg.bare(), sender_bare).is_ok();
    // Extract the inner (authenticated) DTLS fingerprint element.
    let wrapped = format!("<c xmlns='urn:x'>{}</c>", env.content_inner);
    let Ok(parsed) = wrapped.parse::<Element>() else {
        return (content, None);
    };
    let Some(fpe) = parsed.get_child("fingerprint", jingle_sdp::NS_DTLS) else {
        tracing::warn!("OMEMO call-fingerprint: SCE content has no DTLS fingerprint");
        return (content, None);
    };
    let new_fp = Element::builder("fingerprint", jingle_sdp::NS_DTLS)
        .attr(crate::ncname("setup"), fpe.attr("setup").unwrap_or(&setup))
        .attr(crate::ncname("hash"), fpe.attr("hash").unwrap_or(&hash))
        .append(fpe.text().trim())
        .build();
    // Map the peer's stored OMEMO2 identity trust to a call-trust level for the UI:
    //   0 = authenticated only (decrypt + SCE binding held, but identity not trusted)
    //   1 = BTBV-trusted   (store trust == 1)  → lock icon
    //   2 = manually verified (store trust == 3) → shield icon
    // The plaintext fingerprint is returned either way so the call always connects; the trust
    // level only drives the indicator. Levels 1/2 require the SCE binding (anti-reflection).
    let store_trust = store
        .omemo_identity(cfg.account_id, sender_bare, dec.sender_device as i64)
        .await
        .ok()
        .flatten()
        .map(|i| i.trust)
        .unwrap_or(0);
    let trust_level: i64 = if !bound {
        0
    } else {
        match store_trust {
            1 => 1,
            3 => 2,
            _ => 0,
        }
    };
    let content = content_with_transport(&content, transport_with_fingerprint(transport, new_fp));
    (content, Some((dec.fingerprint, dec.sender_device as i64, trust_level)))
}

// ============================ call lifecycle ===============================

/// Create the media engine for a call and pump its SDP/ICE events out as Jingle stanzas.
#[allow(clippy::too_many_arguments)]
fn start_call(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    sid: String,
    peer_full: String,
    role: mxc_media::Role,
    video: bool,
    room: Option<String>,
    initiator: String,
) -> anyhow::Result<()> {
    tracing::info!(?role, video, %sid, %peer_full, muji = room.is_some(), "start_call: creating media engine");
    // Group (Muji) legs share one camera capture (a v4l2 camera opens once); 1:1 calls don't.
    let (engine, rx, video_rx) = mxc_media::CallEngine::new(role, video, room.is_some())?;
    tracing::info!(%sid, "start_call: media engine created");
    let video_tx = calls.borrow().video_tx.clone();
    calls.borrow_mut().active.insert(
        sid.clone(),
        ActiveCall {
            engine,
            peer_full: peer_full.clone(),
            remote_contents: Vec::new(),
            video,
            pending_video: Vec::new(),
            peer_used_omemo: false,
            room: room.clone(),
            we_initiator: role == mxc_media::Role::Caller,
            negotiated: Vec::new(),
            sends_video: false,
            video_offer_pending: false,
            video_retry_after: None,
            connected: false,
            require_verified: false,
            peer_device: None,
            peer_setup: None,
            verified_identity: None,
            trust: 0,
        },
    );

    // Forward decoded video frames to the UI, tagged with this call's sid.
    {
        let video_tx = video_tx.clone();
        let sid = sid.clone();
        tokio::task::spawn_local(async move {
            while let Ok(f) = video_rx.recv().await {
                let _ = video_tx.try_send(crate::event::CallVideoFrame {
                    sid: sid.clone(),
                    width: f.width,
                    height: f.height,
                    data: f.data,
                    local: f.local,
                });
            }
        });
    }

    let w = w.clone();
    let events = events.clone();
    let calls = calls.clone();
    let account_id = cfg.account_id;
    // For OMEMO-verified DTLS: encrypt our fingerprint to the peer before sending.
    let store = calls.borrow().store.clone();
    let cfg = cfg.clone();
    // Muji per-pair sessions opportunistically OMEMO-encrypt their DTLS fingerprint (same as 1:1,
    // matching Android) and tag their session-initiate with `<muji room=…/>`.
    let is_muji = room.is_some();
    tokio::task::spawn_local(async move {
        let (mut ufrag, mut pwd, mut mid) = (String::new(), String::new(), "0".to_string());
        let peer_bare = bare(&peer_full).to_string();
        // One initial offer/answer per session: a second one would carry different ICE
        // credentials / DTLS certificate than what the peer already bound to.
        let mut sent_initial = false;
        while let Ok(ev) = rx.recv().await {
            match ev {
                mxc_media::EngineEvent::LocalDescription { kind, sdp, renegotiation } => {
                    if !renegotiation && std::mem::replace(&mut sent_initial, true) {
                        tracing::warn!(%sid, "dropping duplicate initial local description");
                        continue;
                    }
                    let (u, p, m) = local_transport(&sdp);
                    ufrag = u;
                    pwd = p;
                    mid = m;
                    // Muji legs advertise honest `senders` (a receive-only m-line is not "both").
                    let (we_initiator, require_verified) = calls
                        .borrow()
                        .active
                        .get(&sid)
                        .map(|c| (c.we_initiator, c.require_verified))
                        .unwrap_or((matches!(kind, mxc_media::SdpKind::Offer), false));
                    if is_muji {
                        if let Some(call) = calls.borrow_mut().active.get_mut(&sid) {
                            call.sends_video = sdp_sends_video(&sdp);
                        }
                    }
                    if renegotiation {
                        // Mid-call upgrade: send ONLY the newly-added (video) content as a Jingle
                        // content-add (our re-offer) / content-accept (our answer to the peer's
                        // content-add). The audio content is already negotiated.
                        let (contents, mids) = if is_muji {
                            jingle_sdp::sdp_to_contents_for(&sdp, we_initiator)
                        } else {
                            jingle_sdp::sdp_to_contents(&sdp)
                        };
                        let negotiated: Vec<String> = calls
                            .borrow()
                            .active
                            .get(&sid)
                            .map(|c| c.negotiated.clone())
                            .unwrap_or_default();
                        let mut video: Vec<Element> = contents
                            .into_iter()
                            .filter(|c| {
                                if is_muji {
                                    // Group legs: only contents that are new on this leg. An
                                    // answer to a senders change (content-modify) adds nothing, so
                                    // nothing is sent for it.
                                    !negotiated.iter().any(|n| Some(n.as_str()) == c.attr("name"))
                                } else {
                                    c.get_child("description", jingle_sdp::NS_RTP)
                                        .and_then(|d| d.attr("media"))
                                        .map(|md| md == "video")
                                        .unwrap_or(false)
                                }
                            })
                            .collect();
                        if !video.is_empty() {
                            let names: Vec<String> =
                                video.iter().filter_map(|c| c.attr("name")).map(str::to_string).collect();
                            // Mirror the call's verification state for the upgrade too (a verified
                            // group leg always encrypts, and fails rather than going cleartext).
                            let do_encrypt = require_verified
                                || calls.borrow().active.get(&sid).map(|c| c.peer_used_omemo).unwrap_or(false);
                            if do_encrypt {
                                match encrypt_call_fingerprints(&w, &store, &cfg, &peer_bare, video, require_verified).await {
                                    Some(v) => video = v,
                                    None => {
                                        fail_verified_leg(&w, &calls, &events, account_id, &sid, &peer_full, room.as_deref()).await;
                                        break;
                                    }
                                }
                            }
                            // The content-add must carry the FULL BUNDLE group (audio + the new
                            // video mid): the peer (Conversations/monocles) adopts THIS group for
                            // the merged session, so omitting it leaves two m-lines sharing one
                            // transport with no a=group:BUNDLE → its setRemoteDescription fails.
                            let mut group = Element::builder("group", jingle_sdp::NS_GROUP)
                                .attr(crate::ncname("semantics"), "BUNDLE");
                            for name in &mids {
                                group = group.append(
                                    Element::builder("content", jingle_sdp::NS_JINGLE)
                                        .attr(crate::ncname("name"), name.as_str())
                                        .build(),
                                );
                            }
                            video.push(group.build());
                            let action = match kind {
                                mxc_media::SdpKind::Offer => "content-add",
                                mxc_media::SdpKind::Answer => "content-accept",
                            };
                            if is_muji {
                                if let Some(call) = calls.borrow_mut().active.get_mut(&sid) {
                                    match kind {
                                        mxc_media::SdpKind::Offer => call.video_offer_pending = true,
                                        // our content-accept completes the peer's content-add
                                        mxc_media::SdpKind::Answer => call.negotiated.extend(names.iter().cloned()),
                                    }
                                }
                            }
                            let iq = jingle_iq(&peer_full, &sid, &initiator, action, video);
                            // The full IQ carries ICE candidates (IP addresses): trace only.
                            tracing::info!(%sid, action, contents = ?names, "sending renegotiation (video upgrade)");
                            tracing::trace!(%sid, xml = %String::from(&iq), "renegotiation IQ");
                            let _ = w.send(iq);
                        }
                        if is_muji {
                            // e.g. the peer's camera just appeared / disappeared on this leg
                            emit_conference(&calls, &events, account_id, room.as_deref().unwrap_or("")).await;
                        }
                    } else {
                        let action = match kind {
                            mxc_media::SdpKind::Offer => "session-initiate",
                            mxc_media::SdpKind::Answer => "session-accept",
                        };
                        let (contents, mids) = if is_muji {
                            jingle_sdp::sdp_to_contents_for(&sdp, we_initiator)
                        } else {
                            jingle_sdp::sdp_to_contents(&sdp)
                        };
                        if is_muji {
                            if let Some(call) = calls.borrow_mut().active.get_mut(&sid) {
                                call.negotiated = mids.clone();
                            }
                        }
                        if matches!(kind, mxc_media::SdpKind::Answer) {
                            // We answered: the peer (offerer) takes the opposite DTLS role.
                            if let Some(ours) = sdp_setup(&sdp) {
                                if let Some(call) = calls.borrow_mut().active.get_mut(&sid) {
                                    call.peer_setup = opposite_setup(&ours);
                                }
                            }
                        }
                        if !contents.is_empty() {
                            // Encrypt the DTLS fingerprint on the initial OFFER (bootstraps
                            // verification — the callee handles an encrypted offer fine), but on
                            // the ANSWER only if the peer encrypted theirs. Mirroring avoids the
                            // Android abort where it sent a plaintext offer (its own encrypt
                            // failed) but we replied encrypted. This applies to Muji group-call
                            // legs too: Android opportunistically OMEMO-encrypts each per-pair
                            // fingerprint, so we must encrypt (and mirror) ours to interop and to
                            // give verified group calls. `encrypt_call_fingerprints` is best-effort
                            // — if no OMEMO session can be built it leaves the fingerprint
                            // plaintext, so an unverified group call still works.
                            let do_encrypt = require_verified
                                || matches!(kind, mxc_media::SdpKind::Offer)
                                || calls.borrow().active.get(&sid).map(|c| c.peer_used_omemo).unwrap_or(false);
                            let contents = if do_encrypt {
                                // A verified group leg never falls back to a cleartext fingerprint.
                                match encrypt_call_fingerprints(&w, &store, &cfg, &peer_bare, contents, require_verified).await {
                                    Some(c) => c,
                                    None => {
                                        fail_verified_leg(&w, &calls, &events, account_id, &sid, &peer_full, room.as_deref()).await;
                                        break;
                                    }
                                }
                            } else {
                                contents
                            };
                            let mut group = Element::builder("group", jingle_sdp::NS_GROUP).attr(crate::ncname("semantics"), "BUNDLE");
                            for name in &mids {
                                group = group.append(Element::builder("content", jingle_sdp::NS_JINGLE).attr(crate::ncname("name"), name.as_str()).build());
                            }
                            let mut body = contents;
                            body.push(group.build());
                            // Tag a Muji session-initiate with the conference room (XEP-0272), so
                            // the peer routes it into the right group call rather than ringing it.
                            if let (true, Some(r)) = (matches!(kind, mxc_media::SdpKind::Offer), room.as_deref()) {
                                body.push(Element::builder("muji", muji::NS_MUJI).attr(crate::ncname("room"), r).build());
                            }
                            let _ = w.send(jingle_iq(&peer_full, &sid, &initiator, action, body));
                        }
                    }
                }
                mxc_media::EngineEvent::IceCandidate { candidate, .. } => {
                    let value = candidate.strip_prefix("candidate:").unwrap_or(&candidate);
                    if let Some(cand) = jingle_sdp::candidate_to_jingle(value) {
                        let transport = Element::builder("transport", jingle_sdp::NS_ICE)
                            .attr(crate::ncname("ufrag"), ufrag.as_str())
                            .attr(crate::ncname("pwd"), pwd.as_str())
                            .append(cand)
                            .build();
                        let content = Element::builder("content", jingle_sdp::NS_JINGLE)
                            .attr(crate::ncname("creator"), "initiator")
                            .attr(crate::ncname("name"), mid.as_str())
                            .append(transport)
                            .build();
                        let _ = w.send(jingle_iq(&peer_full, &sid, &initiator, "transport-info", vec![content]));
                    }
                }
                mxc_media::EngineEvent::Connected => {
                    tracing::info!(%sid, "call media connected (ICE)");
                    mark_answered(&calls, &sid);
                    if is_muji {
                        if let Some(call) = calls.borrow_mut().active.get_mut(&sid) {
                            call.connected = true;
                        }
                        set_member_state(&calls, &sid, MemberCallState::Active);
                        if let Some(r) = room.as_deref() {
                            if let Some(conf) = calls.borrow_mut().conferences.get_mut(r) {
                                conf.answered = true; // for the call history
                            }
                        }
                        emit_conference(&calls, &events, account_id, room.as_deref().unwrap_or("")).await;
                        if let Some(r) = room.as_deref() {
                            // We send video in this call but this leg doesn't carry it yet (we
                            // answered an audio-only offer): add our camera now.
                            ensure_leg_video(&calls, r, &sid);
                            // Serialized mesh: now that this leg is up, start the next pending peer's.
                            let conf_video = calls.borrow().conferences.get(r).map(|c| c.video).unwrap_or(video);
                            initiate_next_pending(&w, &calls, &events, &cfg, r, conf_video).await;
                        }
                    } else {
                        emit(&events, account_id, &sid, &peer_bare, video, CallState::Active).await;
                    }
                }
                mxc_media::EngineEvent::Failed(reason) => {
                    tracing::warn!(%sid, %reason, "call media failed");
                    remove_active(&calls, &sid);
                    log_call_end(&calls, &sid);
                    if is_muji {
                        set_member_state(&calls, &sid, MemberCallState::Ended);
                        emit_conference(&calls, &events, account_id, room.as_deref().unwrap_or("")).await;
                        // This leg freed the serialization slot — start the next pending peer's.
                        if let Some(r) = room.as_deref() {
                            let conf_video = calls.borrow().conferences.get(r).map(|c| c.video).unwrap_or(video);
                            initiate_next_pending(&w, &calls, &events, &cfg, r, conf_video).await;
                            end_conference_if_empty(&w, &calls, &events, account_id, r).await;
                        }
                    } else {
                        emit(&events, account_id, &sid, &peer_bare, video, CallState::Ended { reason }).await;
                    }
                    break;
                }
            }
        }
    });
    Ok(())
}

/// Accept a ringing incoming call: bring up the (callee) engine, then send JMI `proceed` to the
/// caller + `accept` to our own devices. The caller's `session-initiate` then drives the answer.
pub fn accept(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    sid: &str,
    peer_hint: &str,
    own_device: Option<u32>,
) -> anyhow::Result<()> {
    let (caller_full, video) = calls
        .borrow_mut()
        .incoming
        .remove(sid)
        .unwrap_or_else(|| (peer_hint.to_string(), false));
    mark_answered(calls, sid); // we picked up
    start_call(w, calls, events, cfg, sid.to_string(), caller_full.clone(), mxc_media::Role::Callee, video, None, cfg.bare().to_string())?;
    // Advertise our OMEMO2 device on the proceed so the caller encrypts the DTLS fingerprint to
    // us (OMEMO-verified call). The self-`accept` carbon carries no device, matching Android.
    w.send(jmi_with_device(&caller_full, "proceed", sid, own_device))?;
    w.send(jmi(cfg.bare(), "accept", sid))
}

/// Hang up / cancel a call. If it's a live session, send `session-terminate`; if it's still
/// ringing out, `retract`. Either way tear down any engine.
pub fn hang_up(w: &Writer, calls: &CallRegistry, peer_hint: &str, sid: &str) -> anyhow::Result<()> {
    let active = remove_active(&calls, sid);
    calls.borrow_mut().proposed.remove(sid);
    calls.borrow_mut().incoming.remove(sid);
    log_call_end(calls, sid);
    if let Some(call) = active {
        let reason = Element::builder("reason", jingle_sdp::NS_JINGLE)
            .append(Element::builder("success", jingle_sdp::NS_JINGLE).build())
            .build();
        let _ = w.send(jingle_iq(&call.peer_full, sid, "", "session-terminate", vec![reason]));
        call.engine.hang_up();
        Ok(())
    } else {
        w.send(jmi(peer_hint, "retract", sid))
    }
}

// ============================ incoming handling ============================

/// Inspect an incoming `<message>` for a JMI element; if present, drive the call state.
/// Returns `true` if the message was a JMI stanza (and thus consumed).
pub async fn handle_message(
    w: &Writer,
    calls: &CallRegistry,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    msg: &Element,
) -> bool {
    let actions = ["propose", "ringing", "proceed", "reject", "retract", "accept", "finish"];
    let Some(el) = msg.children().find(|c| c.ns() == NS_JMI && actions.contains(&c.name())) else {
        return false;
    };
    let action = el.name().to_string();
    let Some(sid) = el.attr("id").map(str::to_string) else { return true };
    let from = msg.attr("from").unwrap_or_default().to_string();
    let peer_bare = bare(&from).to_string();
    let video = el.children().any(|d| d.name() == "description" && d.attr("media") == Some("video"));
    tracing::info!(%action, %sid, %from, video, "JMI received");

    // Our own reflected accept/reject (another of our devices took the call).
    if peer_bare.eq_ignore_ascii_case(cfg.bare()) && (action == "accept" || action == "reject") {
        calls.borrow_mut().incoming.remove(&sid);
        log_call_end(calls, &sid);
        emit(events, cfg.account_id, &sid, &peer_bare, video, CallState::Ended {
            reason: "Handled on another device".into(),
        })
        .await;
        return true;
    }

    match action.as_str() {
        "propose" => {
            // Only one call at a time: while in a group call (also waiting alone) or another 1:1
            // call, don't ring — record a missed call. No `reject`: another of our devices may
            // still answer it (Android only rejects when it has no other device).
            let busy = is_busy_except(&calls.borrow(), &sid);
            if busy {
                tracing::info!(%sid, %from, "busy — not ringing for the incoming call");
                calls.borrow_mut().meta.insert(sid.clone(), CallMeta {
                    peer: peer_bare.clone(),
                    outgoing: false,
                    video,
                    answered: false,
                    ts: now(),
                });
                log_call_end(calls, &sid);
                emit(events, cfg.account_id, &sid, &peer_bare, video, CallState::Ended {
                    reason: "Missed: already in a call".into(),
                })
                .await;
                return true;
            }
            calls.borrow_mut().incoming.insert(sid.clone(), (from.clone(), video));
            calls.borrow_mut().meta.insert(sid.clone(), CallMeta {
                peer: peer_bare.clone(),
                outgoing: false,
                video,
                answered: false,
                ts: now(),
            });
            emit(events, cfg.account_id, &sid, &peer_bare, video, CallState::Incoming).await;
            // Stop ringing after a while if nobody answered and the caller's `retract` never
            // came: a lingering ringing call would otherwise count as "in a call" (busy) forever.
            {
                let calls = calls.clone();
                let events = events.clone();
                let (account_id, sid, peer_bare) = (cfg.account_id, sid.clone(), peer_bare.clone());
                tokio::task::spawn_local(async move {
                    tokio::time::sleep(INCOMING_RING_TIMEOUT).await;
                    let still_ringing = calls.borrow_mut().incoming.remove(&sid).is_some();
                    if still_ringing {
                        tracing::info!(%sid, "incoming call not answered in time — missed");
                        log_call_end(&calls, &sid);
                        emit(&events, account_id, &sid, &peer_bare, video, CallState::Ended {
                            reason: "Missed call".into(),
                        })
                        .await;
                    }
                });
            }
            // Tell the caller we're ringing (XEP-0353 `ringing`, to its full JID). Android shows
            // "Discovering devices" until a callee device rings and, for contacts it shares
            // presence with, gives up after ~6 s without one. Like Android, only answer callers
            // in our roster (or our own account) — `ringing` reveals that we're online.
            let store = calls.borrow().store.clone();
            let known = peer_bare.eq_ignore_ascii_case(cfg.bare())
                || matches!(
                    store.roster_item(cfg.account_id, &peer_bare).await,
                    Ok(Some(item)) if item.subscription != "remove"
                );
            if known {
                if let Err(e) = w.send(jmi(&from, "ringing", &sid)) {
                    tracing::warn!(error = %e, %sid, "send JMI ringing");
                }
            } else {
                tracing::debug!(%sid, %from, "caller not in roster — not sending JMI ringing");
            }
        }
        "ringing" => {
            // The peer's device is ringing for a call we placed; it answers with proceed/reject.
            if jmi_from_peer(calls, &sid, &from) && calls.borrow().proposed.contains_key(&sid) {
                tracing::debug!(%sid, %from, "peer is ringing");
            }
        }
        "proceed" => {
            if !jmi_from_peer(calls, &sid, &from) {
                tracing::warn!(%sid, %from, "ignoring JMI proceed from someone we didn't call");
                return true;
            }
            // The peer accepted our call → bring up the caller engine (it offers).
            let proposed = calls.borrow_mut().proposed.remove(&sid);
            if let Some(video) = proposed {
                mark_answered(calls, &sid);
                if let Err(e) = start_call(w, calls, events, cfg, sid.clone(), from.clone(), mxc_media::Role::Caller, video, None, cfg.bare().to_string()) {
                    tracing::warn!(error = %e, "start caller engine");
                }
                emit(events, cfg.account_id, &sid, &peer_bare, video, CallState::Connecting).await;
            }
        }
        "reject" | "retract" | "finish" if !jmi_from_peer(calls, &sid, &from) => {
            tracing::warn!(%sid, %from, %action, "ignoring JMI from someone not in this call");
        }
        "reject" => {
            terminate_local(calls, &sid);
            // our outgoing call was declined: it no longer counts as a call in progress (busy)
            calls.borrow_mut().proposed.remove(&sid);
            log_call_end(calls, &sid);
            emit(events, cfg.account_id, &sid, &peer_bare, video, CallState::Ended { reason: "Call declined".into() }).await;
        }
        "retract" | "finish" => {
            terminate_local(calls, &sid);
            calls.borrow_mut().incoming.remove(&sid);
            calls.borrow_mut().proposed.remove(&sid);
            log_call_end(calls, &sid);
            emit(events, cfg.account_id, &sid, &peer_bare, video, CallState::Ended { reason: "Caller cancelled".into() }).await;
        }
        _ => {}
    }
    true
}

/// Handle an incoming Jingle session IQ (`<iq><jingle>…`). Returns `true` if consumed.
pub async fn handle_iq(
    w: &Writer,
    calls: &CallRegistry,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    iq: &Element,
) -> bool {
    let Some(jingle) = iq.get_child("jingle", jingle_sdp::NS_JINGLE) else {
        return false;
    };
    let action = jingle.attr("action").unwrap_or("");
    let Some(sid) = jingle.attr("sid").map(str::to_string) else {
        ack(w, iq);
        return true;
    };
    let from = iq.attr("from").unwrap_or_default().to_string();
    tracing::debug!(%action, %sid, %from, "Jingle session IQ received");

    // SECURITY: a session is bound to the full JID it was negotiated with (Conversations keys
    // sessions by (peer, sid)). Without this, anyone who learned a sid could answer our offer
    // (session-accept → the call connects to them), inject ICE candidates or hang us up.
    // The only session that may start here is a Muji leg, which has its own participant check
    // below; a caller may also terminate a call that's still ringing in.
    let bound = calls.borrow().active.get(&sid).map(|c| super::origin::jid_eq(&c.peer_full, &from));
    let allowed = match bound {
        Some(ok) => ok,
        None => {
            (action == "session-initiate" && jingle.get_child("muji", muji::NS_MUJI).is_some())
                || (action == "session-terminate"
                    && calls
                        .borrow()
                        .incoming
                        .get(&sid)
                        .is_some_and(|(caller, _)| super::origin::jid_eq(caller, &from)))
        }
    };
    if !allowed
        && action == "session-terminate"
        && was_recently_ended(&calls.borrow().recently_ended, &sid, &from)
    {
        // Their terminate crossed ours for a session we already ended: nothing left to do, and it
        // is that session's own peer — acknowledge instead of answering with an error.
        tracing::debug!(%sid, %from, "session-terminate for a session we already ended");
        ack(w, iq);
        return true;
    }
    if !allowed {
        tracing::warn!(%action, %sid, %from, "rejecting Jingle IQ for a session that isn't the sender's");
        unknown_session(w, iq);
        return true;
    }
    // Crossed content-adds on a group-call leg (both sides turned their camera on at once): as the
    // session initiator ours wins (XEP-0166 tie-break); the peer accepts ours instead.
    if action == "content-add"
        && calls
            .borrow()
            .active
            .get(&sid)
            .is_some_and(|c| c.room.is_some() && c.video_offer_pending && c.we_initiator)
    {
        tie_break(w, iq);
        return true;
    }
    ack(w, iq); // every accepted Jingle IQ gets an empty result
    // (room, we_initiator, require_verified, peer_device) of a Muji leg we already have.
    let muji_leg = calls
        .borrow()
        .active
        .get(&sid)
        .and_then(|c| c.room.clone().map(|r| (r, c.we_initiator, c.require_verified, c.peer_device)));

    match action {
        "session-initiate" | "session-accept" => {
            let kind = if action == "session-initiate" {
                mxc_media::SdpKind::Offer
            } else {
                mxc_media::SdpKind::Answer
            };
            // XEP-0272 Muji: a session-initiate tagged with `<muji room=…>` belongs to a group
            // call. If we're participating in that conference (and the sender is a participant),
            // spin up a callee engine for it (no JMI ring — Muji peers call each other directly).
            if action == "session-initiate" {
                if let Some(room) = jingle
                    .get_child("muji", muji::NS_MUJI)
                    .and_then(|m| m.attr("room"))
                    .map(room_key)
                {
                    if !calls.borrow().active.contains_key(&sid)
                        && !accept_muji_initiate(w, calls, events, cfg, &room, &from, &sid).await
                    {
                        return true;
                    }
                }
            }
            let (leg_room, we_initiator, require_verified, peer_device) = calls
                .borrow()
                .active
                .get(&sid)
                .map(|c| (c.room.clone(), c.we_initiator, c.require_verified, c.peer_device))
                .unwrap_or((None, false, false, None));
            let owned: Vec<Element> =
                jingle.children().filter(|c| c.name() == "content").cloned().collect();
            if require_verified && !all_fingerprints_encrypted(&owned) {
                fail_verified_leg(w, calls, events, cfg.account_id, &sid, &from, leg_room.as_deref()).await;
                return true;
            }
            // OMEMO-verified DTLS: decrypt the fingerprint(s) back to plaintext for webrtcbin and
            // capture the peer's verified OMEMO2 identity (for the call shield).
            let store = calls.borrow().store.clone();
            let (contents, verified) =
                decrypt_call_fingerprints(&store, cfg, events, bare(&from), owned).await;
            if leg_room.is_some() && !muji_leg_acceptable(&contents, &verified, require_verified, peer_device) {
                fail_verified_leg(w, calls, events, cfg.account_id, &sid, &from, leg_room.as_deref()).await;
                return true;
            }
            let refs: Vec<&Element> = contents.iter().collect();
            let sdp = if leg_room.is_some() {
                // the sender's description: honest directions on group-call legs
                jingle_sdp::contents_to_sdp_for(&refs, !we_initiator)
            } else {
                jingle_sdp::contents_to_sdp(&refs)
            };
            if let Some(sdp) = sdp {
                let mut c = calls.borrow_mut();
                if let Some(call) = c.active.get_mut(&sid) {
                    if let Err(e) = call.engine.set_remote_description(kind, &sdp) {
                        tracing::warn!(error = %e, "set remote description");
                    }
                    // Remember the peer's (plaintext) content set so a later content-add/accept
                    // (video upgrade) can be merged into a full SDP.
                    call.remote_contents = contents.clone();
                    if kind == mxc_media::SdpKind::Answer {
                        // The peer answered: its DTLS role is the one it chose there.
                        if let Some(setup) = contents_setup(&contents).filter(|s| s != "actpass") {
                            call.peer_setup = Some(setup);
                        }
                    }
                    // Mirror the peer: only encrypt our fingerprint back if they encrypted theirs.
                    call.peer_used_omemo = verified.is_some();
                    call.verified_identity =
                        verified.as_ref().map(|(fp, device, _)| (fp.clone(), *device));
                    call.trust = verified.as_ref().map(|(_, _, t)| *t).unwrap_or(0);
                }
            }
            if let Some(room) = leg_room.as_deref() {
                // Group call: the per-leg trust goes into the conference's participant list. The
                // 1:1 indicator (`CallVerified`) is global and Muji legs never reset it, so feeding
                // it here made it over-claim — and leak into the next, possibly cleartext, 1:1 call.
                emit_conference(calls, events, cfg.account_id, room).await;
            } else if let Some((fingerprint, device_id, trust)) = verified {
                tracing::info!(%sid, trust, device_id, "call OMEMO2-authenticated");
                let _ = events
                    .send(Event::CallVerified {
                        account_id: cfg.account_id,
                        sid: sid.clone(),
                        fingerprint,
                        device_id,
                        trust,
                    })
                    .await;
            }
        }
        // Peer accepted our audio→video upgrade: merge their video answer content into the full
        // remote SDP and apply it as the renegotiation answer, then switch the UI to video.
        "content-accept" => {
            let new_owned: Vec<Element> =
                jingle.children().filter(|c| c.name() == "content").cloned().collect();
            if let Some((room, _, true, _)) = &muji_leg {
                if !all_fingerprints_encrypted(&new_owned) {
                    fail_verified_leg(w, calls, events, cfg.account_id, &sid, &from, Some(room)).await;
                    return true;
                }
            }
            let identity = calls.borrow().active.get(&sid).and_then(|c| c.verified_identity.clone());
            let was_encrypted = all_fingerprints_encrypted(&new_owned);
            let store = calls.borrow().store.clone();
            let (new_contents, verified) =
                decrypt_call_fingerprints(&store, cfg, events, bare(&from), new_owned).await;
            if let Some((room, _, require_verified, peer_device)) = &muji_leg {
                if !muji_leg_acceptable(&new_contents, &verified, *require_verified, *peer_device) {
                    fail_verified_leg(w, calls, events, cfg.account_id, &sid, &from, Some(room)).await;
                    return true;
                }
            }
            if !keeps_leg_identity(&identity, was_encrypted, &new_contents, &verified) {
                tracing::warn!(%sid, "content-accept would drop/switch the call's OMEMO verification");
                let room = muji_leg.as_ref().map(|(r, ..)| r.clone());
                fail_verified_leg(w, calls, events, cfg.account_id, &sid, &from, room.as_deref()).await;
                return true;
            }
            let mut applied = false;
            {
                let mut c = calls.borrow_mut();
                if let Some(call) = c.active.get_mut(&sid) {
                    let mut full = call.remote_contents.clone();
                    full.extend(new_contents.iter().cloned());
                    // This becomes the peer's ANSWER: it must name the DTLS role in use, not
                    // the `actpass` its original offer carried.
                    let full = with_peer_setup(full, call.peer_setup.as_deref());
                    let refs: Vec<&Element> = full.iter().collect();
                    let sdp = if call.room.is_some() {
                        jingle_sdp::contents_to_sdp_for(&refs, !call.we_initiator)
                    } else {
                        jingle_sdp::contents_to_sdp(&refs)
                    };
                    if let Some(sdp) = sdp {
                        match call.engine.set_remote_description(mxc_media::SdpKind::Answer, &sdp) {
                            Ok(()) => {
                                call.remote_contents = full;
                                call.video = true;
                                call.video_offer_pending = false;
                                call.negotiated.extend(
                                    new_contents.iter().filter_map(|c| c.attr("name")).map(str::to_string),
                                );
                                applied = true;
                            }
                            Err(e) => tracing::warn!(error = %e, "content-accept set remote"),
                        }
                    }
                }
            }
            if applied {
                tracing::info!(%sid, "content-accept applied — call upgraded to video");
                match &muji_leg {
                    // a group-call leg: the conference view (not a 1:1 call screen) updates
                    Some((room, ..)) => emit_conference(calls, events, cfg.account_id, room).await,
                    None => emit(events, cfg.account_id, &sid, bare(&from), true, CallState::Active).await,
                }
            }
        }
        "content-reject" => {
            tracing::info!(%sid, "peer rejected our video upgrade (content-reject)");
            if let Some(call) = calls.borrow_mut().active.get_mut(&sid) {
                if call.room.is_some() {
                    call.video_offer_pending = false;
                    call.video_retry_after = Some(std::time::Instant::now() + MUJI_VIDEO_RETRY);
                }
            }
        }
        // XEP-0272 Muji: a participant turned their camera on — accept it without asking.
        "content-add" if muji_leg.is_some() => {
            muji_content_add(w, calls, events, cfg, &sid, &from, jingle).await;
        }
        // XEP-0272 Muji: the peer changed who sends on existing contents (e.g. it turned its
        // camera on over a video m-line it so far only received on). Apply it as a re-offer.
        "content-modify" if muji_leg.is_some() => {
            muji_content_modify(calls, &sid, jingle);
        }
        // Peer is upgrading the call to video: stash their new video content and ask the user
        // for consent (Android-style). `accept_video_upgrade` / `decline_video_upgrade` act on it.
        "content-add" => {
            let new_owned: Vec<Element> =
                jingle.children().filter(|c| c.name() == "content").cloned().collect();
            // Decrypt the OMEMO-verified fingerprint now so the stashed (consent-pending) content
            // is plaintext-ready when the user accepts.
            let identity = calls.borrow().active.get(&sid).and_then(|c| c.verified_identity.clone());
            let was_encrypted = all_fingerprints_encrypted(&new_owned);
            let store = calls.borrow().store.clone();
            let (new_contents, verified) =
                decrypt_call_fingerprints(&store, cfg, events, bare(&from), new_owned).await;
            if !keeps_leg_identity(&identity, was_encrypted, &new_contents, &verified) {
                tracing::warn!(%sid, "content-add would drop/switch the call's OMEMO verification");
                fail_verified_leg(w, calls, events, cfg.account_id, &sid, &from, None).await;
                return true;
            }
            let mut prompt = false;
            {
                let mut c = calls.borrow_mut();
                if let Some(call) = c.active.get_mut(&sid) {
                    if !call.video && !new_contents.is_empty() {
                        call.pending_video = new_contents;
                        prompt = true;
                    }
                }
            }
            if prompt {
                tracing::info!(%sid, "content-add received — prompting user for video consent");
                let _ = events
                    .send(Event::CallVideoUpgradeRequest {
                        account_id: cfg.account_id,
                        sid: sid.clone(),
                        peer: bare(&from).to_string(),
                    })
                    .await;
            }
        }
        "transport-info" => {
            if let Some(content) = jingle.get_child("content", jingle_sdp::NS_JINGLE) {
                if let Some(transport) = content.get_child("transport", jingle_sdp::NS_ICE) {
                    let calls = calls.borrow();
                    if let Some(call) = calls.active.get(&sid) {
                        for c in transport.children().filter(|c| c.name() == "candidate") {
                            if let Some(line) = jingle_sdp::candidate_to_sdp(c) {
                                call.engine.add_remote_ice(0, &format!("candidate:{line}"));
                            }
                        }
                    }
                }
            }
        }
        "session-terminate" => {
            // Log the peer's reason (e.g. failed-application + text) — invaluable when a
            // content-add/renegotiation is rejected.
            let reason = jingle
                .get_child("reason", jingle_sdp::NS_JINGLE)
                .map(|r| {
                    let cond = r
                        .children()
                        .find(|c| c.name() != "text")
                        .map(|c| c.name().to_string())
                        .unwrap_or_default();
                    let text = r
                        .get_child("text", jingle_sdp::NS_JINGLE)
                        .map(|t| t.text())
                        .unwrap_or_default();
                    format!("{cond} {text}")
                })
                .unwrap_or_default();
            tracing::info!(%sid, %reason, "session-terminate received");
            // A Muji per-pair session ending just drops that one participant from the
            // conference (the call continues with the others); a 1:1 session ends the call.
            let muji_room = calls.borrow().active.get(&sid).and_then(|c| c.room.clone());
            terminate_local(calls, &sid);
            log_call_end(calls, &sid);
            if let Some(room) = muji_room {
                set_member_state(calls, &sid, MemberCallState::Ended);
                emit_conference(calls, events, cfg.account_id, &room).await;
                end_conference_if_empty(w, calls, events, cfg.account_id, &room).await;
            } else {
                emit(events, cfg.account_id, &sid, bare(&from), false, CallState::Ended {
                    reason: "Call ended".into(),
                })
                .await;
            }
        }
        _ => {}
    }
    true
}

/// Reply to a Jingle IQ with a `<tie-break/>` error (XEP-0166 §8): crossed requests, ours wins.
fn tie_break(w: &Writer, iq: &Element) {
    let mut b = Element::builder("iq", NS_CLIENT).attr(crate::ncname("type"), "error");
    if let Some(from) = iq.attr("from") {
        b = b.attr(crate::ncname("to"), from);
    }
    if let Some(id) = iq.attr("id") {
        b = b.attr(crate::ncname("id"), id);
    }
    let error = Element::builder("error", NS_CLIENT)
        .attr(crate::ncname("type"), "cancel")
        .append(Element::builder("conflict", "urn:ietf:params:xml:ns:xmpp-stanzas").build())
        .append(Element::builder("tie-break", "urn:xmpp:jingle:errors:1").build())
        .build();
    let _ = w.send(b.append(error).build());
}

/// Whether the (decrypted) contents of a group-call leg are acceptable: the OMEMO device that
/// encrypted the fingerprint must be the one the room advertised for the peer; and on a verified
/// leg every fingerprint must have been encrypted, decrypted, SCE-bound and from a trusted
/// identity (call-trust ≥ 1).
fn muji_leg_acceptable(
    contents: &[Element],
    verified: &Option<(String, i64, i64)>,
    require_verified: bool,
    peer_device: Option<u32>,
) -> bool {
    if let (Some((_, device, _)), Some(advertised)) = (verified, peer_device) {
        if *device != advertised as i64 {
            tracing::warn!(device, advertised, "muji: fingerprint encrypted by another device than advertised");
            return false;
        }
    }
    if !require_verified {
        return true;
    }
    all_fingerprints_decrypted(contents)
        && verified.as_ref().is_some_and(|(_, _, trust)| *trust >= 1)
}

/// A `<content>` with its `senders` replaced.
fn content_with_senders(content: &Element, senders: &str) -> Element {
    let mut b = Element::builder("content", content.ns());
    for ((ns, name), v) in content.attrs() {
        if name.as_str() != "senders" {
            b = b.attr_ns(ns.clone(), name.clone(), v.clone());
        }
    }
    b = b.attr(crate::ncname("senders"), senders);
    for child in content.children() {
        b = b.append(child.clone());
    }
    b.build()
}

/// A stub `<content>` (name, creator, senders, media only) for content-modify / content-reject.
fn content_stub(content: &Element, senders: Option<&str>) -> Element {
    let media = content
        .get_child("description", jingle_sdp::NS_RTP)
        .and_then(|d| d.attr("media"))
        .unwrap_or("video");
    let mut b = Element::builder("content", jingle_sdp::NS_JINGLE)
        .attr(crate::ncname("creator"), content.attr("creator").unwrap_or("initiator"))
        .attr(crate::ncname("name"), content.attr("name").unwrap_or(""));
    if let Some(s) = senders.or(content.attr("senders")) {
        b = b.attr(crate::ncname("senders"), s);
    }
    b.append(Element::builder("description", jingle_sdp::NS_RTP).attr(crate::ncname("media"), media).build())
        .append(Element::builder("transport", jingle_sdp::NS_ICE).build())
        .build()
}

/// Decide on an incoming Muji session-initiate and, if acceptable, start the callee leg. Returns
/// false if it was refused (a session-terminate has been sent).
async fn accept_muji_initiate(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    room: &str,
    from: &str,
    sid: &str,
) -> bool {
    enum Decision {
        /// (Jingle reason, explanatory text — logged by the peer to diagnose a failing call)
        Refuse(&'static str, &'static str),
        Accept {
            our_occupant: String,
            video: bool,
            verified: bool,
            occupant: String,
            device: Option<u32>,
            /// A leg to this participant that the new one replaces: (sid, address).
            replace: Option<(String, String)>,
        },
    }
    let decision = {
        let c = calls.borrow();
        match c.conferences.get(room) {
            None => {
                tracing::debug!(%room, %from, "refusing muji session-initiate for a conference we're not in");
                Decision::Refuse("decline", "not-in-conference")
            }
            Some(conf) => {
                // SECURITY: only accept a Muji leg from someone who is actually a participant of
                // this room: the `from` must be exactly the real full JID the (non-anonymous) MUC
                // vouched for in that occupant's `<item jid>` (with a `<muji>` advert). Without
                // this, any JID that learns we're in a call could inject unsolicited media (it
                // auto-accepts, no ring). Any advertised state counts: a peer sends <preparing/>,
                // then ready, then initiates at once — and its initiate (direct) can overtake its
                // ready presence (via the MUC).
                let peer = c.muji_seen.get(room).and_then(|m| {
                    m.iter()
                        .find(|(_, p)| super::origin::jid_eq(&p.real_jid, from))
                        .map(|(occ, p)| (occ.clone(), p.device))
                        .or_else(|| {
                            // The MUC may report ANOTHER session of the caller's account (a client
                            // restarted while its old session lingers in the room, or a
                            // multi-session nick). Accept if exactly one participant has the
                            // caller's bare JID — the account the MUC vouched for; it's then
                            // re-addressed to the calling session below.
                            let mut same: Vec<_> = m
                                .iter()
                                .filter(|(_, p)| bare(&p.real_jid).eq_ignore_ascii_case(bare(from)))
                                .collect();
                            if same.len() == 1 {
                                let (occ, p) = same.remove(0);
                                tracing::info!(%room, occupant = %occ, room_reported = %p.real_jid, %from,
                                    "muji: participant calls from another session of its account");
                                Some((occ.clone(), p.device))
                            } else {
                                None
                            }
                        })
                });
                match peer {
                    None => {
                        tracing::warn!(%room, %from, "rejecting muji session-initiate from a non-participant");
                        Decision::Refuse("security-error", "not-a-participant")
                    }
                    Some((occupant, device)) => {
                        let existing = conf
                            .members
                            .get(&occupant)
                            .and_then(|m| m.sid.clone().map(|s| (s, m.real_jid.clone(), m.state)));
                        let legs = conf.members.values().filter(|m| m.sid.is_some()).count();
                        let accept = |replace| Decision::Accept {
                            our_occupant: conf.our_occupant.clone(),
                            video: conf.video,
                            verified: conf.verified,
                            occupant: occupant.clone(),
                            device,
                            replace,
                        };
                        match existing {
                            // A working leg stays.
                            Some((_, _, MemberCallState::Active)) => Decision::Refuse("decline", "duplicate"),
                            // Crossed initiates (both sides started a leg — e.g. they disagree on
                            // the occupant-JID tie-break because the server rewrote a nick), or the
                            // peer restarting its stuck leg: keep the leg with the smaller session
                            // id. Both sides compare the same two ids, so they always keep the SAME
                            // leg — deciding by the occupant tie-break could make each side kill
                            // the other's leg, forever.
                            Some((old_sid, _, _)) if old_sid.as_str() < sid => {
                                Decision::Refuse("decline", "duplicate")
                            }
                            Some((old_sid, addr, _)) => accept(Some((old_sid, addr))),
                            None if legs >= muji::MAX_PEERS => {
                                tracing::warn!(%room, %from, "rejecting muji session-initiate: participant limit reached");
                                Decision::Refuse("busy", "limit")
                            }
                            None => accept(None),
                        }
                    }
                }
            }
        }
    };
    match decision {
        Decision::Refuse(reason, text) => {
            tracing::info!(%room, %from, reason, text, "refusing muji session-initiate");
            let reason = Element::builder("reason", jingle_sdp::NS_JINGLE)
                .append(Element::builder(reason, jingle_sdp::NS_JINGLE).build())
                .append(Element::builder("text", jingle_sdp::NS_JINGLE).append(text).build())
                .build();
            let _ = w.send(jingle_iq(from, sid, "", "session-terminate", vec![reason]));
            false
        }
        Decision::Accept { our_occupant, video, verified, occupant, device, replace } => {
            // Address this participant at the session that actually calls us from now on.
            if let Some(p) = calls.borrow_mut().muji_seen.get_mut(room).and_then(|m| m.get_mut(&occupant)) {
                p.real_jid = from.to_string();
            }
            if let Some((old_sid, addr)) = replace {
                if let Some(call) = remove_active(&calls, &old_sid) {
                    let reason = Element::builder("reason", jingle_sdp::NS_JINGLE)
                        .append(Element::builder("success", jingle_sdp::NS_JINGLE).build())
                        .build();
                    let _ = w.send(jingle_iq(&addr, &old_sid, "", "session-terminate", vec![reason]));
                    call.engine.hang_up();
                }
            }
            if let Err(e) = start_call(
                w, calls, events, cfg, sid.to_string(), from.to_string(),
                mxc_media::Role::Callee, video, Some(room.to_string()), our_occupant,
            ) {
                tracing::warn!(error = %e, "start muji callee engine");
                return false;
            }
            configure_muji_leg(calls, sid, verified, device);
            register_member_session(calls, room, &occupant, from, sid);
            apply_conf_state_to_leg(calls, room, sid);
            true
        }
    }
}

/// Set a freshly created group-call leg's verification requirement + the peer's advertised device
/// (before its first offer/answer goes out — the engine's pump only runs once we yield).
fn configure_muji_leg(calls: &CallRegistry, sid: &str, require_verified: bool, peer_device: Option<u32>) {
    if let Some(call) = calls.borrow_mut().active.get_mut(sid) {
        call.require_verified = require_verified;
        call.peer_device = peer_device;
    }
}

/// A group-call participant added a video content (turned their camera on). Accept it without a
/// prompt: with our own camera if we send video in this conference, otherwise receive-only —
/// first narrowing the content's `senders` to the adder (content-modify on its pending
/// content-add, XEP-0166), then answering recv-only. Mirrors monocles Android.
async fn muji_content_add(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    sid: &str,
    from: &str,
    jingle: &Element,
) {
    let new_owned: Vec<Element> = jingle.children().filter(|c| c.name() == "content").cloned().collect();
    let Some((room, we_initiator, require_verified, peer_device, peer_full, negotiated, identity, video_now)) =
        calls.borrow().active.get(sid).and_then(|c| {
            c.room.clone().map(|r| {
                (
                    r,
                    c.we_initiator,
                    c.require_verified,
                    c.peer_device,
                    c.peer_full.clone(),
                    c.negotiated.clone(),
                    c.verified_identity.clone(),
                    video_contents(&c.remote_contents),
                )
            })
        })
    else {
        return;
    };
    let reject = |contents: &[Element]| {
        let stubs = contents.iter().map(|c| content_stub(c, None)).collect();
        let _ = w.send(jingle_iq(&peer_full, sid, "", "content-reject", stubs));
    };
    let only_new_video = !new_owned.is_empty()
        && new_owned.iter().all(|c| {
            c.get_child("description", jingle_sdp::NS_RTP).and_then(|d| d.attr("media")) == Some("video")
                && !negotiated.iter().any(|n| Some(n.as_str()) == c.attr("name"))
        });
    if !only_new_video || video_now + new_owned.len() > MAX_MUJI_VIDEO_CONTENTS {
        tracing::warn!(%sid, video_now, "muji: refusing content-add (not video, or too many video contents)");
        reject(&new_owned);
        return;
    }
    let was_encrypted = all_fingerprints_encrypted(&new_owned);
    if require_verified && !was_encrypted {
        fail_verified_leg(w, calls, events, cfg.account_id, sid, &peer_full, Some(&room)).await;
        return;
    }
    let store = calls.borrow().store.clone();
    let (new_contents, verified) = decrypt_call_fingerprints(&store, cfg, events, bare(from), new_owned).await;
    if !muji_leg_acceptable(&new_contents, &verified, require_verified, peer_device)
        || !keeps_leg_identity(&identity, was_encrypted, &new_contents, &verified)
    {
        fail_verified_leg(w, calls, events, cfg.account_id, sid, &peer_full, Some(&room)).await;
        return;
    }
    let (send_video, camera_enabled) = calls
        .borrow()
        .conferences
        .get(&room)
        .map(|c| (c.video, c.camera_enabled))
        .unwrap_or((false, false));
    let contents = if send_video {
        new_contents
    } else {
        let adder_only = if we_initiator { "responder" } else { "initiator" };
        let stubs = new_contents.iter().map(|c| content_stub(c, Some(adder_only))).collect();
        let narrow = jingle_iq(&peer_full, sid, "", "content-modify", stubs);
        match super::iq::request(w, narrow).await {
            Ok(_) => new_contents.iter().map(|c| content_with_senders(c, adder_only)).collect(),
            Err(e) => {
                tracing::info!(%sid, error = %e, "peer refused receive-only for its content-add");
                reject(&new_contents);
                return;
            }
        }
    };
    let applied = {
        let mut c = calls.borrow_mut();
        match c.active.get_mut(sid) {
            Some(call) => {
                let mut full = call.remote_contents.clone();
                full.extend(contents);
                // Keep the established DTLS roles across the re-offer (as Android does).
                let full = with_peer_setup(full, call.peer_setup.as_deref());
                let refs: Vec<&Element> = full.iter().collect();
                match jingle_sdp::contents_to_sdp_for(&refs, !we_initiator) {
                    Some(sdp) => {
                        let res = if send_video {
                            let res = call.engine.apply_video_offer(&sdp);
                            // Adding the camera branch selects the live camera: keep the user's
                            // camera-off choice for this conference.
                            call.engine.set_video_enabled(camera_enabled);
                            res
                        } else {
                            call.engine.apply_remote_offer(&sdp)
                        };
                        match res {
                            Ok(()) => {
                                call.remote_contents = full;
                                call.video = true;
                                true
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "muji content-add: apply offer");
                                false
                            }
                        }
                    }
                    None => false,
                }
            }
            None => false,
        }
    };
    if applied {
        tracing::info!(%sid, send_video, "muji content-add accepted — answering with content-accept");
        emit_conference(calls, events, cfg.account_id, &room).await;
    }
}

/// A group-call peer changed `senders` of contents already negotiated on the leg: apply the
/// modified description as a re-offer and answer it locally (the peer completes its side from the
/// acknowledged IQ; our answer adds no content, so the pump sends nothing). A content-modify for
/// our own pending content-add (the peer only narrowing it to receive-only) needs nothing — its
/// content-accept carries the agreed senders.
fn muji_content_modify(calls: &CallRegistry, sid: &str, jingle: &Element) {
    let changes: Vec<(String, String)> = jingle
        .children()
        .filter(|c| c.name() == "content")
        .filter_map(|c| Some((c.attr("name")?.to_string(), c.attr("senders")?.to_string())))
        .filter(|(_, s)| matches!(s.as_str(), "both" | "initiator" | "responder" | "none"))
        .collect();
    let mut c = calls.borrow_mut();
    let Some(call) = c.active.get_mut(sid) else { return };
    if changes.is_empty()
        || call.video_offer_pending
        || !changes.iter().all(|(n, _)| call.negotiated.contains(n))
    {
        return;
    }
    let full: Vec<Element> = call
        .remote_contents
        .iter()
        .map(|content| {
            match changes.iter().find(|(n, _)| Some(n.as_str()) == content.attr("name")) {
                Some((_, senders)) => content_with_senders(content, senders),
                None => content.clone(),
            }
        })
        .collect();
    let offer = with_peer_setup(full.clone(), call.peer_setup.as_deref());
    let refs: Vec<&Element> = offer.iter().collect();
    let Some(sdp) = jingle_sdp::contents_to_sdp_for(&refs, !call.we_initiator) else { return };
    match call.engine.apply_remote_offer(&sdp) {
        Ok(()) => {
            tracing::info!(%sid, ?changes, "muji content-modify applied");
            call.remote_contents = full;
        }
        Err(e) => tracing::warn!(error = %e, "muji content-modify: apply offer"),
    }
}

/// Group call: make sure leg `sid` carries our camera because we send video in this conference —
/// a content-add of a new video m-line (the peer accepts it, receive-only or with its own camera).
/// Safe to call repeatedly (on connect, upgrade, every re-mesh tick): does nothing while the leg
/// isn't connected, already sends video, has a content-add in flight, or is backing off after
/// the peer refused.
fn ensure_leg_video(calls: &CallRegistry, room: &str, sid: &str) {
    let mut c = calls.borrow_mut();
    let Some(camera_enabled) = c.conferences.get(room).filter(|conf| conf.video).map(|conf| conf.camera_enabled)
    else {
        return;
    };
    let Some(call) = c.active.get_mut(sid) else { return };
    if !call.connected
        || call.sends_video
        || call.video_offer_pending
        || call.video_retry_after.is_some_and(|t| std::time::Instant::now() < t)
    {
        return;
    }
    tracing::info!(%sid, %room, "muji: adding our camera to leg");
    call.video_offer_pending = true;
    if let Err(e) = call.engine.offer_video() {
        tracing::warn!(error = %e, "muji: offer video on leg");
        call.video_offer_pending = false;
        call.video_retry_after = Some(std::time::Instant::now() + MUJI_VIDEO_RETRY);
    }
    // Adding the camera branch selects the live camera: keep the user's camera-off choice (the
    // peer then gets black frames, like every other leg while the camera is off).
    call.engine.set_video_enabled(camera_enabled);
}

/// Mute / unmute the microphone on the active call `sid`.
pub fn set_mute(calls: &CallRegistry, sid: &str, muted: bool) {
    if let Some(call) = calls.borrow().active.get(sid) {
        call.engine.set_mic_muted(muted);
    }
}

/// Turn the camera on/off on the active video call `sid`.
pub fn set_camera(calls: &CallRegistry, sid: &str, enabled: bool) {
    if let Some(call) = calls.borrow().active.get(sid) {
        call.engine.set_video_enabled(enabled);
    }
}

/// Start screen sharing on call `sid` with a stream already obtained from the ScreenCast portal.
/// The screen replaces the camera as the outgoing video track; if the call was audio-only the
/// engine adds a video branch and re-offers (→ `content-add`). The portal negotiation itself is
/// done by the caller (it's async and must not hold the registry borrow); see `client.rs`.
pub fn start_screen_share(calls: &CallRegistry, sid: &str, screen: mxc_media::ScreenShare) {
    if let Some(call) = calls.borrow().active.get(sid) {
        if let Err(e) = call.engine.start_screen_share(screen) {
            tracing::warn!(error = %e, "start_screen_share");
        }
    }
}

/// Stop screen sharing on call `sid`; the outgoing video track switches back to the camera.
pub fn stop_screen_share(calls: &CallRegistry, sid: &str) {
    if let Some(call) = calls.borrow().active.get(sid) {
        call.engine.stop_screen_share();
    }
}

/// Upgrade the active audio call `sid` to video (XEP-0166 content-add): adds a video branch to
/// the engine and re-offers; the engine's renegotiation offer is sent as `content-add` and the
/// peer's `content-accept` completes it.
pub fn upgrade_to_video(calls: &CallRegistry, sid: &str) {
    if let Some(call) = calls.borrow().active.get(sid) {
        if call.video {
            return; // already a video call
        }
        if let Err(e) = call.engine.upgrade_to_video() {
            tracing::warn!(error = %e, "upgrade_to_video");
        }
    }
}

/// User accepted a peer's incoming video upgrade: apply their pending video content as a
/// renegotiation offer (+ add our camera), and tell the UI to switch to video. The engine's
/// answer is sent back as `content-accept` by the per-call event pump.
pub async fn accept_video_upgrade(
    calls: &CallRegistry,
    events: &Sender<Event>,
    account_id: i64,
    sid: &str,
) {
    let (applied, peer) = {
        let mut c = calls.borrow_mut();
        match c.active.get_mut(sid) {
            Some(call) if !call.video && !call.pending_video.is_empty() => {
                let pending = std::mem::take(&mut call.pending_video);
                let mut full = call.remote_contents.clone();
                full.extend(pending);
                let refs: Vec<&Element> = full.iter().collect();
                let ok = match jingle_sdp::contents_to_sdp(&refs) {
                    Some(sdp) => match call.engine.apply_video_offer(&sdp) {
                        Ok(()) => {
                            call.remote_contents = full;
                            call.video = true;
                            true
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "accept video upgrade: apply offer");
                            false
                        }
                    },
                    None => false,
                };
                (ok, bare(&call.peer_full).to_string())
            }
            _ => (false, String::new()),
        }
    };
    if applied {
        tracing::info!(%sid, "video upgrade accepted — answering with content-accept");
        emit(events, account_id, sid, &peer, true, CallState::Active).await;
    }
}

/// User declined a peer's incoming video upgrade: drop the pending content and reply
/// `content-reject` so the peer stops offering.
pub fn decline_video_upgrade(w: &Writer, calls: &CallRegistry, initiator: &str, sid: &str) {
    let (pending, peer_full) = {
        let mut c = calls.borrow_mut();
        match c.active.get_mut(sid) {
            Some(call) => (std::mem::take(&mut call.pending_video), call.peer_full.clone()),
            None => (Vec::new(), String::new()),
        }
    };
    if pending.is_empty() {
        return;
    }
    tracing::info!(%sid, "video upgrade declined — sending content-reject");
    let _ = w.send(jingle_iq(&peer_full, sid, initiator, "content-reject", pending));
}

/// Tear down a local media engine for `sid` if present.
fn terminate_local(calls: &CallRegistry, sid: &str) {
    if let Some(call) = remove_active(&calls, sid) {
        call.engine.hang_up();
    }
}

async fn emit(events: &Sender<Event>, account_id: i64, sid: &str, peer: &str, video: bool, state: CallState) {
    let _ = events
        .send(Event::CallUpdate {
            account_id,
            sid: sid.to_string(),
            peer: peer.to_string(),
            video,
            state,
        })
        .await;
}

// ===================== Muji conference lifecycle (group calls) =====================

/// Snapshot a conference's remote participants and push a [`Event::ConferenceUpdate`]. When the
/// conference no longer exists (we left), emits `active: false` with an empty list so the UI
/// closes the conference view.
async fn emit_conference(calls: &CallRegistry, events: &Sender<Event>, account_id: i64, room: &str) {
    let (active, video, participants) = {
        let c = calls.borrow();
        match c.conferences.get(room) {
            Some(conf) => (
                true,
                conf.video,
                conf.members
                    .values()
                    .map(|m| ConfParticipant {
                        jid: m.occupant_jid.clone(),
                        name: m.occupant_jid.rsplit('/').next().unwrap_or(&m.occupant_jid).to_string(),
                        state: m.state.as_str().to_string(),
                        sid: m.sid.clone().unwrap_or_default(),
                        trust: m
                            .sid
                            .as_ref()
                            .and_then(|sid| c.active.get(sid))
                            .map(|a| a.trust)
                            .unwrap_or(0),
                    })
                    .collect::<Vec<_>>(),
            ),
            None => (false, false, Vec::new()),
        }
    };
    let _ = events
        .send(Event::ConferenceUpdate {
            account_id,
            room: room.to_string(),
            active,
            video,
            participants,
        })
        .await;
}

/// Ensure a member entry exists for `occupant` (Connecting), so the UI lists them while we wait.
fn ensure_member(calls: &CallRegistry, room: &str, occupant: &str, real_jid: &str) {
    let mut c = calls.borrow_mut();
    if let Some(conf) = c.conferences.get_mut(room) {
        conf.members.entry(occupant.to_string()).or_insert_with(|| Member {
            occupant_jid: occupant.to_string(),
            real_jid: real_jid.to_string(),
            sid: None,
            state: MemberCallState::Connecting,
            connecting_since: std::time::Instant::now(),
        });
    }
}

/// Record that the per-pair session `sid` belongs to `occupant` (addressed at `real_jid`) in `room`.
fn register_member_session(calls: &CallRegistry, room: &str, occupant: &str, real_jid: &str, sid: &str) {
    let mut c = calls.borrow_mut();
    if let Some(conf) = c.conferences.get_mut(room) {
        let m = conf.members.entry(occupant.to_string()).or_insert_with(|| Member {
            occupant_jid: occupant.to_string(),
            real_jid: real_jid.to_string(),
            sid: None,
            state: MemberCallState::Connecting,
            connecting_since: std::time::Instant::now(),
        });
        m.real_jid = real_jid.to_string();
        m.sid = Some(sid.to_string());
        m.state = MemberCallState::Connecting;
        m.connecting_since = std::time::Instant::now();
    }
}

/// Apply the conference's current mic/camera state to a freshly-created leg, so a re-mesh'd or
/// late-joining leg matches the rest of the call (otherwise a new leg would un-mute / re-enable the
/// camera). Screen share is switched in at the shared hub, so legs inherit it automatically.
fn apply_conf_state_to_leg(calls: &CallRegistry, room: &str, sid: &str) {
    let (muted, camera_enabled) = match calls.borrow().conferences.get(room) {
        Some(conf) => (conf.muted, conf.camera_enabled),
        None => return,
    };
    if muted {
        set_mute(calls, sid, true);
    }
    if !camera_enabled {
        set_camera(calls, sid, false);
    }
}

/// Update the call-state of whichever member owns session `sid` (across all conferences).
fn set_member_state(calls: &CallRegistry, sid: &str, state: MemberCallState) {
    let mut c = calls.borrow_mut();
    for conf in c.conferences.values_mut() {
        for m in conf.members.values_mut() {
            if m.sid.as_deref() == Some(sid) {
                m.state = state;
                return;
            }
        }
    }
}

/// Decide whether to initiate (per the glare tie-break) a per-pair session with a ready peer,
/// and do so. If the peer should call us instead, just register them as a pending member.
#[allow(clippy::too_many_arguments)]
async fn maybe_initiate(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    room: &str,
    peer_occupant: &str,
    peer_addr: &str, // the peer's real full JID to address the Jingle to
    video: bool,
) {
    enum Act {
        Skip,
        Initiate(String), // our occupant JID (the Jingle initiator)
        Wait,
        Defer, // we should initiate, but a leg is already negotiating ICE — one at a time
    }
    let act = {
        let c = calls.borrow();
        match c.conferences.get(room) {
            None => Act::Skip,
            Some(conf) => {
                let has_session = conf.members.get(peer_occupant).map(|m| m.sid.is_some()).unwrap_or(false);
                let legs = conf.members.values().filter(|m| m.sid.is_some()).count();
                if has_session {
                    Act::Skip
                } else if !conf.announced {
                    Act::Wait // not yet: the room hasn't confirmed our participation
                } else if legs >= muji::MAX_PEERS {
                    tracing::warn!(%room, %peer_occupant, "muji: not meshing — participant limit reached");
                    Act::Skip
                } else if muji::should_initiate(&conf.our_occupant, peer_occupant) {
                    // Serialize leg setup: only one per-pair leg negotiates ICE at a time.
                    // libnice 0.1.22 crashes (priv_conn_check_tick_stream_nominate assertion) when
                    // several NiceAgents run connectivity checks concurrently under load, which is
                    // exactly what happens when we mesh with N peers at once. The re-mesh's 12s
                    // stuck-timeout is the safety net so a wedged leg can't block the mesh forever.
                    if has_connecting_leg(&c, room) {
                        Act::Defer
                    } else {
                        Act::Initiate(conf.our_occupant.clone())
                    }
                } else {
                    Act::Wait
                }
            }
        }
    };
    match act {
        Act::Skip => {
            tracing::info!(%room, %peer_occupant, "muji maybe_initiate: skip (already have a session)");
            return;
        }
        Act::Defer => {
            tracing::info!(%room, %peer_occupant, "muji maybe_initiate: defer (a leg is still connecting — one at a time)");
            return;
        }
        Act::Wait => {
            tracing::info!(%room, %peer_occupant, "muji maybe_initiate: wait (peer initiates per tie-break)");
            ensure_member(calls, room, peer_occupant, peer_addr);
        }
        Act::Initiate(our_occ) => {
            tracing::info!(%room, %peer_occupant, %peer_addr, "muji maybe_initiate: initiating (we win the tie-break)");
            let sid = new_id("muji");
            let (verified, device) = {
                let c = calls.borrow();
                (
                    c.conferences.get(room).map(|cf| cf.verified).unwrap_or(false),
                    c.muji_seen.get(room).and_then(|m| m.get(peer_occupant)).and_then(|p| p.device),
                )
            };
            match start_call(
                w, calls, events, cfg, sid.clone(), peer_addr.to_string(),
                mxc_media::Role::Caller, video, Some(room.to_string()), our_occ,
            ) {
                Ok(()) => {
                    configure_muji_leg(calls, &sid, verified, device);
                    register_member_session(calls, room, peer_occupant, peer_addr, &sid);
                    apply_conf_state_to_leg(calls, room, &sid);
                }
                Err(e) => tracing::warn!(error = %e, "start muji caller engine"),
            }
        }
    }
    emit_conference(calls, events, cfg.account_id, room).await;
}

/// Whether a per-pair leg of `room` is currently negotiating ICE (has a session id but hasn't
/// reached `Active` yet). Used to serialize leg setup so only one `NiceAgent` runs connectivity
/// checks at a time (a libnice 0.1.22 crash otherwise — see `maybe_initiate`).
fn has_connecting_leg(c: &Calls, room: &str) -> bool {
    c.conferences
        .get(room)
        .map(|conf| {
            conf.members
                .values()
                .any(|m| m.sid.is_some() && m.state == MemberCallState::Connecting)
        })
        .unwrap_or(false)
}

/// After a leg settles (connected or ended), start the next pending peer's leg — the other half of
/// the one-leg-at-a-time serialization. Picks one ready peer we should initiate to and have no
/// session with; does nothing while a leg is still connecting.
async fn initiate_next_pending(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    room: &str,
    video: bool,
) {
    let next = {
        let c = calls.borrow();
        if has_connecting_leg(&c, room) {
            return; // a leg is still negotiating — it will kick the next one when it settles
        }
        if !c.conferences.get(room).is_some_and(|conf| conf.announced) {
            return; // the room hasn't confirmed our participation yet
        }
        let Some(conf) = c.conferences.get(room) else { return };
        c.muji_seen.get(room).and_then(|seen| {
            seen.iter()
                .filter(|(occ, p)| {
                    p.state == MujiState::Ready
                        && muji::should_initiate(&conf.our_occupant, occ)
                        && conf.members.get(*occ).map(|m| m.sid.is_none()).unwrap_or(true)
                })
                .map(|(occ, p)| (occ.clone(), p.real_jid.clone()))
                .next()
        })
    };
    if let Some((occ, addr)) = next {
        maybe_initiate(w, calls, events, cfg, room, &occ, &addr, video).await;
    }
}

/// Periodic mesh reconciliation: drop legs that never reached `Active` (stuck / one-sided) or
/// that died, then (re)initiate with any ready peer we have no live leg to. This heals an
/// incomplete mesh (a leg that failed to establish on one side never retried) and re-establishes
/// a leg after a mid-call ICE failure — the difference between "survives one leaver" and not.
async fn remesh(w: &Writer, calls: &CallRegistry, events: &Sender<Event>, cfg: &AccountConfig, room: &str) {
    const STUCK_AFTER: std::time::Duration = std::time::Duration::from_secs(12);
    // 1. Members to drop: Ended, or Connecting for too long (never answered / ICE never came up).
    let to_drop: Vec<(String, Option<String>, String)> = {
        let c = calls.borrow();
        match c.conferences.get(room) {
            Some(conf) => conf
                .members
                .iter()
                .filter(|(occ, m)| {
                    m.state == MemberCallState::Ended
                        // a leg that never came up; a participant we're only WAITING for (no
                        // session yet — the peer initiates) is kept, dropping it just churned the UI
                        || (m.state == MemberCallState::Connecting
                            && m.sid.is_some()
                            && m.connecting_since.elapsed() > STUCK_AFTER)
                        // ...unless they no longer advertise `<muji>` at all (e.g. they left while
                        // we were reconnecting, which forgets the room's presences): a ghost
                        || (m.sid.is_none()
                            && !c.muji_seen.get(room).is_some_and(|seen| seen.contains_key(*occ)))
                })
                .map(|(occ, m)| (occ.clone(), m.sid.clone(), m.real_jid.clone()))
                .collect(),
            None => return,
        }
    };
    for (occ, sid, addr) in &to_drop {
        if let Some(conf) = calls.borrow_mut().conferences.get_mut(room) {
            conf.members.remove(occ);
        }
        if let Some(sid) = sid {
            if let Some(call) = remove_active(&calls, sid) {
                let reason = Element::builder("reason", jingle_sdp::NS_JINGLE)
                    .append(Element::builder("success", jingle_sdp::NS_JINGLE).build())
                    .build();
                let _ = w.send(jingle_iq(addr, sid, "", "session-terminate", vec![reason]));
                call.engine.hang_up();
            }
        }
        tracing::info!(%room, occupant = %occ, "muji remesh: dropped stuck/ended leg, will retry");
    }
    // 2. (Re)initiate with every ready peer we now have no member for (maybe_initiate dedups +
    //    applies the tie-break, so this only initiates where we should).
    let (video, ready): (bool, Vec<(String, String)>) = {
        let c = calls.borrow();
        let video = c.conferences.get(room).map(|cf| cf.video).unwrap_or(false);
        let ready = c
            .muji_seen
            .get(room)
            .map(|m| {
                m.iter()
                    .filter(|(_, p)| p.state == MujiState::Ready)
                    .map(|(occ, p)| (occ.clone(), p.real_jid.clone()))
                    .collect()
            })
            .unwrap_or_default();
        (video, ready)
    };
    for (occ, addr) in ready {
        maybe_initiate(w, calls, events, cfg, room, &occ, &addr, video).await;
    }
    // Only push a conference update when this tick actually changed the mesh (dropped a stuck /
    // dead leg). In steady state nothing changes, and emitting every tick would make the UI rebuild
    // the video tiles every 8s — a visible flicker (the avatar placeholder flashes for a frame).
    // New legs that `maybe_initiate` started emit their own updates as they connect.
    if !to_drop.is_empty() {
        emit_conference(calls, events, cfg.account_id, room).await;
    }
    // 3. Self-heal: every connected leg carries our camera if we send video.
    ensure_video_on_legs(calls, room);
    // 4. Nobody left (missed by the event paths, e.g. after a reconnect): end the call.
    end_conference_if_empty(w, calls, events, cfg.account_id, room).await;
}

/// [`ensure_leg_video`] for every leg of `room`'s conference.
fn ensure_video_on_legs(calls: &CallRegistry, room: &str) {
    let sids: Vec<String> = calls
        .borrow()
        .conferences
        .get(room)
        .map(|conf| conf.members.values().filter_map(|m| m.sid.clone()).collect())
        .unwrap_or_default();
    for sid in sids {
        ensure_leg_video(calls, room, &sid);
    }
}

/// The room rebroadcast our READY `<muji>` (or, with `timed_out`, didn't within a few seconds):
/// other participants know us now, so start the legs we initiate (XEP-0272 "wait until the MUC
/// rebroadcasts its presence"). Idempotent.
async fn mark_announced(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    room: &str,
    timed_out: bool,
) {
    let (video, ready) = {
        let mut c = calls.borrow_mut();
        let Some(conf) = c.conferences.get_mut(room) else { return };
        if conf.announced {
            return;
        }
        conf.announced = true;
        let video = conf.video;
        let ready: Vec<(String, String)> = c
            .muji_seen
            .get(room)
            .map(|m| {
                m.iter()
                    .filter(|(_, p)| p.state == MujiState::Ready)
                    .map(|(occ, p)| (occ.clone(), p.real_jid.clone()))
                    .collect()
            })
            .unwrap_or_default();
        (video, ready)
    };
    if timed_out {
        tracing::warn!(%room, "muji: the room did not reflect our <muji> presence in time — meshing anyway");
    } else {
        tracing::info!(%room, "muji: room confirmed our participation");
    }
    for (occupant, addr) in ready {
        maybe_initiate(w, calls, events, cfg, room, &occupant, &addr, video).await;
    }
    emit_conference(calls, events, cfg.account_id, room).await;
}

/// Upgrade our participation in the audio group call in `room` to video: advertise the new
/// 'webcam' content (XEP-0272 "Adding a Content Type": `<preparing/>`, then the content), then
/// bring our camera onto every connected leg (legs created later start with video).
pub async fn upgrade_group_call_to_video(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    room: &str,
) {
    let room = &room_key(room);
    let nick = {
        let mut c = calls.borrow_mut();
        let Some(conf) = c.conferences.get_mut(room) else { return };
        if conf.video {
            None
        } else {
            conf.video = true;
            conf.camera_enabled = true;
            Some(conf.nick.clone())
        }
    };
    if let Some(nick) = nick {
        let device = {
            let store = calls.borrow().store.clone();
            crate::xeps::omemo::own_device_id(&store, cfg).await.ok()
        };
        // We may have left the call while looking up the device id: don't advertise `<muji>`
        // for a call we're no longer in.
        if !calls.borrow().conferences.get(room).is_some_and(|c| c.video) {
            return;
        }
        let ready = muji::muji_payload(true, true, device);
        muji::set_active_payload(cfg.account_id, room, Some(ready.clone()));
        let _ = muji::send_muji_presence(w, cfg.account_id, room, &nick, Some(muji::muji_payload(false, true, device)));
        let _ = muji::send_muji_presence(w, cfg.account_id, room, &nick, Some(ready));
        tracing::info!(%room, "muji: upgraded our participation to video");
    }
    ensure_video_on_legs(calls, room);
    emit_conference(calls, events, cfg.account_id, room).await;
}

/// End our part in `room`'s call WITHOUT sending presence (we're no longer an occupant — a
/// directed presence would re-join the room): we left the room, were kicked/banned, or it was
/// destroyed. Also forgets the room's participants and any pending invite.
pub async fn on_room_left(w: &Writer, calls: &CallRegistry, events: &Sender<Event>, account_id: i64, room: &str) {
    let room = &room_key(room);
    muji::forget_room(account_id, room);
    let (sessions, was_invited) = {
        let mut c = calls.borrow_mut();
        let removed = c.conferences.remove(room);
        if let Some(conf) = &removed {
            log_conference_end(&c.store, c.account_id, conf);
        }
        let sessions: Vec<(String, String)> = removed
            .map(|conf| conf.members.values().filter_map(|m| m.sid.clone().map(|s| (s, m.real_jid.clone()))).collect())
            .unwrap_or_default();
        c.muji_seen.remove(room);
        (sessions, c.invited.remove(room))
    };
    muji::set_active_payload(account_id, room, None);
    for (sid, addr) in sessions {
        if let Some(call) = remove_active(&calls, &sid) {
            let reason = Element::builder("reason", jingle_sdp::NS_JINGLE)
                .append(Element::builder("gone", jingle_sdp::NS_JINGLE).build())
                .build();
            let _ = w.send(jingle_iq(&addr, &sid, "", "session-terminate", vec![reason]));
            call.engine.hang_up();
        }
        log_call_end(calls, &sid);
    }
    if was_invited {
        let _ = events
            .send(Event::ConferenceInviteCancelled { account_id, room: room.to_string() })
            .await;
    }
    emit_conference(calls, events, account_id, room).await;
}

/// Drop a participant who left the conference: terminate their per-pair session (if any) and
/// remove them from the member list.
fn remove_member(w: &Writer, calls: &CallRegistry, room: &str, occupant: &str) {
    let sid = {
        let mut c = calls.borrow_mut();
        match c.conferences.get_mut(room) {
            Some(conf) => conf
                .members
                .remove(occupant)
                .and_then(|m| m.sid.map(|s| (s, m.real_jid))),
            None => None,
        }
    };
    if let Some((sid, addr)) = sid {
        if let Some(call) = remove_active(&calls, &sid) {
            let reason = Element::builder("reason", jingle_sdp::NS_JINGLE)
                .append(Element::builder("success", jingle_sdp::NS_JINGLE).build())
                .build();
            let _ = w.send(jingle_iq(&addr, &sid, "", "session-terminate", vec![reason]));
            call.engine.hang_up();
        }
    }
}

/// Start / join a Muji group call in `room` (we must already be a MUC occupant). Creates the
/// conference, announces our `<muji>` presence (preparing → ready), then meshes with the peers
/// already advertising a ready `<muji>`.
pub async fn place_group_call(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    room: &str,
    video: bool,
) {
    // The store is keyed by the room as stored; the call registry by the normalized key.
    let stored_room = room;
    let room = &room_key(room);
    let store = calls.borrow().store.clone();
    // Group calls are gated to private groups (members-only + non-anonymous): Muji's per-pair
    // Jingle needs the participants' real JIDs, which only such rooms expose.
    if !store.muc_omemo_capable(cfg.account_id, stored_room).await.unwrap_or(false) {
        tracing::warn!(%room, "place_group_call: refusing — room is not a private (non-anonymous) group");
        return;
    }
    let nick = match store.muc_nick_by_jid(cfg.account_id, stored_room).await {
        Ok(Some(n)) => n,
        _ => {
            tracing::warn!(%room, "place_group_call: no stored MUC nick (not joined?)");
            return;
        }
    };
    // The nick the room actually gave us, if it reflected one (a presence to a stale nick is a
    // rename request).
    let nick = muji::room_nick(cfg.account_id, room).unwrap_or(nick);
    let our_occupant = format!("{room}/{nick}");
    if calls.borrow().conferences.contains_key(room) {
        // Already in this call (e.g. a second "join"): replacing the conference would orphan its
        // legs and start a second re-mesh loop.
        emit_conference(calls, events, cfg.account_id, room).await;
        return;
    }
    // Only one call at a time: not during a 1:1 call or another room's group call.
    let busy = {
        let c = calls.borrow();
        c.conferences.keys().any(|r| r != room)
            || !c.incoming.is_empty()
            || !c.proposed.is_empty()
            || c.active.values().any(|a| a.room.is_none())
    };
    if busy {
        tracing::warn!(%room, "place_group_call: refusing — already in another call");
        return;
    }
    // The group call is PQ OMEMO2-verified only when placed with the room's encryption set to
    // OMEMO2 (same rule as Android's conversation lock); otherwise legs verify opportunistically.
    let verified = store
        .conversation_encryption(cfg.account_id, stored_room)
        .await
        .ok()
        .flatten()
        .is_some_and(|e| e == "omemo2");
    // A second "join" may have created the conference while we awaited the lookup above.
    if calls.borrow().conferences.contains_key(room) {
        emit_conference(calls, events, cfg.account_id, room).await;
        return;
    }
    let started_at = now();
    let had_invite = {
        let mut c = calls.borrow_mut();
        // We started the call unless someone was already in it.
        let outgoing = !c
            .muji_seen
            .get(room)
            .is_some_and(|seen| seen.values().any(|p| p.state == MujiState::Ready));
        c.conferences.insert(
            room.to_string(),
            Conference {
                nick: nick.clone(),
                our_occupant,
                video,
                verified,
                stored_room: stored_room.to_string(),
                started_at: started_at.clone(),
                outgoing,
                answered: false,
                announced: false,
                muted: false,
                camera_enabled: true,
                screen: None,
                members: HashMap::new(),
            },
        );
        // We're joining now → any pending "join" invite for this room is moot.
        c.invited.remove(room)
    };
    if had_invite {
        let _ = events
            .send(Event::ConferenceInviteCancelled { account_id: cfg.account_id, room: room.to_string() })
            .await;
    }
    tracing::info!(%room, video, verified, "place_group_call: announcing muji presence");
    // Advertise our OMEMO device id so peers (Android) can OMEMO-encrypt their per-pair DTLS
    // fingerprint to us; None if OMEMO isn't set up (the leg then stays plaintext).
    let device = {
        let store = calls.borrow().store.clone();
        crate::xeps::omemo::own_device_id(&store, cfg).await.ok()
    };
    // We may have left again while looking up the device id: then don't advertise `<muji>` (it
    // would stay stored and be re-sent on every re-join, for a call we're not in).
    if !calls.borrow().conferences.get(room).is_some_and(|c| c.started_at == started_at) {
        tracing::info!(%room, "place_group_call: left while joining — not announcing");
        return;
    }
    // XEP-0272: announce `<preparing/>` then the ready content. Our codec set is fixed, so we
    // can advertise readiness immediately.
    // Every later presence to the room (e.g. the re-join after a reconnect) keeps carrying it.
    muji::set_active_payload(cfg.account_id, room, Some(muji::muji_payload(true, video, device)));
    let _ = muji::send_muji_presence(w, cfg.account_id, room, &nick, Some(muji::muji_payload(false, video, device)));
    let _ = muji::send_muji_presence(w, cfg.account_id, room, &nick, Some(muji::muji_payload(true, video, device)));
    // XEP-0272: mesh only once the room has rebroadcast our `<muji>` (see `mark_announced`,
    // driven by our reflected self-presence). This timer is the safety net if it never arrives.
    emit_conference(calls, events, cfg.account_id, room).await;
    {
        let w = w.clone();
        let calls = calls.clone();
        let events = events.clone();
        let cfg = cfg.clone();
        let room = room.to_string();
        tokio::task::spawn_local(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            mark_announced(&w, &calls, &events, &cfg, &room, true).await;
        });
    }

    // Periodic re-mesh while we're in this call: heal legs that never connected (stuck /
    // one-sided) and re-establish after an ICE failure. Exits once we leave the conference.
    {
        let w = w.clone();
        let calls = calls.clone();
        let events = events.clone();
        let cfg = cfg.clone();
        let room = room.to_string();
        tokio::task::spawn_local(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                if !calls.borrow().conferences.contains_key(&room) {
                    break; // left the call
                }
                remesh(&w, &calls, &events, &cfg, &room).await;
            }
        });
    }
}

/// Leave a Muji group call: drop our `<muji>` presence first (XEP-0272 ordering), then
/// terminate every per-pair session.
pub async fn leave_group_call(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    cfg: &AccountConfig,
    room: &str,
) {
    leave_conference(w, calls, events, cfg.account_id, room).await;
}

/// End the call in `room` if we're alone in it: no live leg and nobody else advertising `<muji>`
/// — but only once a leg had connected (a call nobody has joined yet keeps waiting). Run both when
/// a leg ends and when a participant's `<muji>` goes away: the peer's `session-terminate` (direct)
/// and presence (via the MUC) arrive in either order, and checking only one of them left us alone
/// in an empty call, still advertising `<muji>`.
async fn end_conference_if_empty(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    account_id: i64,
    room: &str,
) {
    let room = &room_key(room);
    let empty = {
        let c = calls.borrow();
        c.conferences.get(room).is_some_and(|conf| {
            conf.answered
                && conf.members.values().all(|m| m.state == MemberCallState::Ended)
                && c.muji_seen.get(room).map_or(true, |seen| seen.is_empty())
        })
    };
    if empty {
        tracing::info!(%room, "muji: everyone else left — ending the call");
        leave_conference(w, calls, events, account_id, room).await;
    }
}

async fn leave_conference(
    w: &Writer,
    calls: &CallRegistry,
    events: &Sender<Event>,
    account_id: i64,
    room: &str,
) {
    let room = &room_key(room);
    let (nick, sessions) = {
        let mut c = calls.borrow_mut();
        match c.conferences.remove(room) {
            Some(conf) => {
                log_conference_end(&c.store, c.account_id, &conf);
                // Others stay in the call: treat its invite as already shown, so their next
                // presence (status, avatar, …) doesn't offer us the call we just left. Cleared
                // when the last of them drops `<muji>` (see `observe_muji_presence`).
                if c.muji_seen.get(room).is_some_and(|seen| !seen.is_empty()) {
                    c.invited.insert(room.to_string());
                }
                let sessions: Vec<(String, String)> = conf
                    .members
                    .values()
                    .filter_map(|m| m.sid.clone().map(|s| (s, m.real_jid.clone())))
                    .collect();
                (Some(conf.nick), sessions)
            }
            None => (None, Vec::new()),
        }
    };
    muji::set_active_payload(account_id, room, None);
    if let Some(nick) = nick {
        let _ = muji::send_muji_presence(w, account_id, room, &nick, None);
    }
    for (sid, addr) in sessions {
        if let Some(call) = remove_active(&calls, &sid) {
            let reason = Element::builder("reason", jingle_sdp::NS_JINGLE)
                .append(Element::builder("success", jingle_sdp::NS_JINGLE).build())
                .build();
            let _ = w.send(jingle_iq(&addr, &sid, "", "session-terminate", vec![reason]));
            call.engine.hang_up();
        }
    }
    // NOTE: do NOT clear `muji_seen` here. We're leaving the *call*, not the MUC — the other
    // participants are still in the call and still advertising `<muji>`, but they won't re-send
    // that presence just because we left. `muji_seen` is kept current by MUC presence (entries
    // are removed when a peer actually drops `<muji>`), so preserving it is what lets us re-mesh
    // with the still-running call when we rejoin via the call button. Clearing it made rejoin
    // initiate to nobody (only the legs peers started came up) → a half-broken call.
    emit_conference(calls, events, account_id, room).await;
}

/// Mute / unmute our microphone across every per-pair session of a group call.
pub fn set_group_mute(calls: &CallRegistry, room: &str, muted: bool) {
    let room = &room_key(room);
    let sids: Vec<String> = {
        let mut c = calls.borrow_mut();
        match c.conferences.get_mut(room) {
            Some(conf) => {
                conf.muted = muted;
                conf.members.values().filter_map(|m| m.sid.clone()).collect()
            }
            None => Vec::new(),
        }
    };
    for sid in sids {
        set_mute(calls, &sid, muted);
    }
}

/// Turn our camera on/off across every per-pair session of a group call. The state is remembered
/// on the conference so legs created later (re-mesh / new joiners) inherit it.
pub fn set_group_camera(calls: &CallRegistry, room: &str, enabled: bool) {
    let room = &room_key(room);
    let sids: Vec<String> = {
        let mut c = calls.borrow_mut();
        match c.conferences.get_mut(room) {
            Some(conf) => {
                conf.camera_enabled = enabled;
                conf.members.values().filter_map(|m| m.sid.clone()).collect()
            }
            None => Vec::new(),
        }
    };
    for sid in sids {
        set_camera(calls, &sid, enabled);
    }
}

/// Start sharing the screen `screen` (already negotiated via the portal) to the whole group: the
/// shared camera hub switches its source to the screen, so every leg relays it. The portal handle
/// is kept alive on the conference until [`stop_group_screen_share`].
pub fn start_group_screen_share(calls: &CallRegistry, room: &str, screen: mxc_media::ScreenShare) {
    let room = &room_key(room);
    let (fd, node_id) = (screen.raw_fd(), screen.node_id());
    {
        let mut c = calls.borrow_mut();
        let Some(conf) = c.conferences.get_mut(room) else { return };
        conf.screen = Some(screen); // keep the portal session alive while we share
    }
    if let Err(e) = mxc_media::share_screen_to_group(fd, node_id) {
        tracing::warn!(error = %e, "start_group_screen_share");
        // Roll back the stored handle so state stays consistent.
        if let Some(conf) = calls.borrow_mut().conferences.get_mut(room) {
            conf.screen = None;
        }
    }
}

/// Stop a group screen share: the hub returns to the camera and the portal cast ends.
pub fn stop_group_screen_share(calls: &CallRegistry, room: &str) {
    let room = &room_key(room);
    mxc_media::stop_group_screen_share();
    if let Some(conf) = calls.borrow_mut().conferences.get_mut(room) {
        conf.screen = None; // drop → portal session ends the cast
    }
}

/// Whether we are currently sharing our screen to the group call in `room`.
pub fn group_screen_sharing(calls: &CallRegistry, room: &str) -> bool {
    let room = &room_key(room);
    calls.borrow().conferences.get(room).map(|c| c.screen.is_some()).unwrap_or(false)
}

/// Observe an occupant's MUC presence for a `<muji>` payload and drive the conference: track
/// who is ready, mesh (via the tie-break) when both we and a peer are ready, and drop members
/// who leave. Called from the stanza router for every presence.
pub async fn observe_muji_presence(
    w: &Writer,
    calls: &CallRegistry,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    pres: &Element,
) {
    const NS_MUC_USER: &str = "http://jabber.org/protocol/muc#user";
    let Some(from) = pres.attr("from") else { return };
    let Some((stored_room, nick)) = from.split_once('/') else { return }; // occupant JIDs only
    let ptype = pres.attr("type").unwrap_or("available");
    if ptype == "error" {
        return; // says nothing about anyone's call participation
    }
    let room = room_key(stored_room);
    let occupant = format!("{room}/{nick}");
    let x = pres.get_child("x", NS_MUC_USER);
    let has_status = |code: &str| {
        x.is_some_and(|x| x.children().any(|c| c.name() == "status" && c.attr("code") == Some(code)))
    };
    let item = x.and_then(|x| x.get_child("item", NS_MUC_USER));
    let unavailable = ptype == "unavailable";
    let nick_change = unavailable && has_status("303");
    let parsed = if unavailable { None } else { muji::parse_muji(pres) };

    // The room reflected our own presence: remember the nick it gave us (it may differ from the
    // one we asked for) — status updates are sent to our CURRENT occupant JID.
    if !unavailable && has_status("110") && muji::is_room_joined(cfg.account_id, &room) {
        muji::set_room_nick(cfg.account_id, &room, nick);
    }

    // Cheap filter first: only a presence carrying `<muji>`, or one for a room whose call we track,
    // matters here (this runs for EVERY presence).
    let tracked = {
        let c = calls.borrow();
        c.conferences.contains_key(&room) || c.muji_seen.contains_key(&room)
    };
    // We left / were removed from a room with no call state (with call state, `on_room_left`
    // below handles it): forget it, or a later status update would be sent to it — and a presence
    // to a room we're not in re-joins it (after a kick, even against the moderator's will).
    if unavailable && !nick_change && has_status("110") && !tracked {
        muji::forget_room(cfg.account_id, &room);
    }
    if parsed.is_none() && !tracked {
        return;
    }
    // SECURITY: only occupants of a MUC we joined coordinate group calls. The router hands us
    // every presence, and a contact's own `user@host/res` would otherwise pose as an occupant of
    // "room" `user@host` — with a forged `<muji>` + `muc#user <item jid>` it could plant
    // participants and pop "join group call" prompts. (Android only feeds MUC presences.)
    if !muji::is_room_joined(cfg.account_id, &room) {
        tracing::debug!(%from, "ignoring <muji> presence from outside a joined MUC");
        return;
    }

    // We (re)joined the room: it replays every occupant's presence, so forget what we saw before
    // (participants who left while we were disconnected would otherwise linger forever).
    if muji::take_room_joining(cfg.account_id, &room) {
        calls.borrow_mut().muji_seen.remove(&room);
    }

    // Our own occupant presence (status 110).
    if has_status("110") {
        if unavailable && !nick_change {
            // We left the room, were kicked/banned, or it went away: our call there is over.
            if calls.borrow().conferences.contains_key(&room) || calls.borrow().muji_seen.contains_key(&room) {
                tracing::info!(%room, "muji: we are no longer in the room — ending its call");
                on_room_left(w, calls, events, cfg.account_id, &room).await;
            }
            return;
        }
        if unavailable {
            return; // our new-nick presence follows
        }
        let (reannounce, confirm) = {
            let mut c = calls.borrow_mut();
            match c.conferences.get_mut(&room) {
                Some(conf) => {
                    // Track our (possibly renamed) occupant JID — the tie-break input.
                    conf.our_occupant = occupant.clone();
                    if let Some((_, nick)) = occupant.split_once('/') {
                        conf.nick = nick.to_string();
                    }
                    let confirm = !conf.announced && matches!(parsed, Some((MujiState::Ready, _)));
                    // The room reflected a presence of ours without `<muji>`: peers now think we
                    // left. Re-assert participation.
                    (parsed.is_none().then(|| conf.nick.clone()), confirm)
                }
                None => (None, false),
            }
        };
        tracing::debug!(%room, %occupant, muji = ?parsed, "muji: reflected self-presence");
        if confirm {
            mark_announced(w, calls, events, cfg, &room, false).await;
        }
        if let Some(nick) = reannounce {
            if let Some(payload) = muji::active_payload(cfg.account_id, &room) {
                tracing::info!(%room, "muji: reflected self-presence lost <muji> — re-announcing");
                let _ = muji::send_muji_presence(w, cfg.account_id, &room, &nick, Some(payload));
            }
        }
        return;
    }

    // A participant renaming (unavailable + 303, new nick in <item nick>): keep their leg — it's
    // keyed by real JID on Android and must survive here too — and move our bookkeeping over.
    if nick_change {
        if let Some(new_nick) = item.and_then(|i| i.attr("nick")) {
            let new_occupant = format!("{room}/{new_nick}");
            let mut c = calls.borrow_mut();
            if let Some(peer) = c.muji_seen.get_mut(&room).and_then(|m| m.remove(&occupant)) {
                c.muji_seen.entry(room.clone()).or_default().insert(new_occupant.clone(), peer);
            }
            if let Some(conf) = c.conferences.get_mut(&room) {
                if let Some(mut m) = conf.members.remove(&occupant) {
                    m.occupant_jid = new_occupant.clone();
                    conf.members.insert(new_occupant, m);
                }
            }
        }
        return;
    }

    // The occupant's REAL full JID (non-anonymous MUC exposes it in `<item jid>`). Muji legs are
    // addressed to — and authenticated against — it, so an advert without one is ignored (no
    // fallback to the occupant JID, XEP-0272 forbids that addressing).
    let real_jid = item
        .and_then(|i| i.attr("jid"))
        .filter(|j| j.contains('/'))
        .map(str::to_string);
    let state = match (parsed, &real_jid) {
        (Some(p), Some(_)) => Some(p),
        _ => None,
    };

    // Track raw Muji state regardless of whether we're in the call yet.
    let previous = {
        let mut c = calls.borrow_mut();
        let seen = c.muji_seen.entry(room.clone()).or_default();
        let previous = seen.remove(&occupant);
        if let (Some((s, device)), Some(addr)) = (state, &real_jid) {
            seen.insert(occupant.clone(), MujiPeer { state: s, real_jid: addr.clone(), device });
        }
        previous
    };

    let in_conf = calls.borrow().conferences.contains_key(&room);
    if state.is_some() || in_conf {
        tracing::debug!(%occupant, ?state, in_conf, "muji presence observed");
    }

    if !in_conf {
        // We're not in this room's call. If someone is advertising a group call, surface a
        // one-tap "join" invite (once per call); when the call ends, cancel the invite.
        let (any_participant, already_invited) = {
            let c = calls.borrow();
            let any = c.muji_seen.get(&room).map(|m| !m.is_empty()).unwrap_or(false);
            (any, c.invited.contains(&room))
        };
        if any_participant && !already_invited {
            calls.borrow_mut().invited.insert(room.clone());
            // A muted group must not ring: any occupant can toggle `<muji>` at will.
            let store = calls.borrow().store.clone();
            let mode = match store.conversation_notify_mode(cfg.account_id, stored_room).await {
                Ok(Some(m)) => Some(m),
                // the conversation may be stored with another spelling of the room
                _ => store.conversation_notify_mode(cfg.account_id, &room).await.ok().flatten(),
            };
            if mode.as_deref() == Some("none") {
                return;
            }
            // Name someone who is actually in the call (prefer a READY participant), not whoever
            // sent the presence that happened to trigger this.
            let participant = {
                let c = calls.borrow();
                c.muji_seen.get(&room).and_then(|seen| {
                    seen.iter()
                        .find(|(_, p)| p.state == MujiState::Ready)
                        .or_else(|| seen.iter().next())
                        .map(|(occ, _)| occ.clone())
                })
            }
            .unwrap_or_else(|| occupant.clone());
            let nick = participant.rsplit('/').next().unwrap_or(&participant).to_string();
            tracing::info!(%room, %nick, "muji: group-call invite");
            let _ = events
                .send(Event::ConferenceInvite { account_id: cfg.account_id, room: room.clone(), from: nick })
                .await;
        } else if !any_participant && already_invited {
            calls.borrow_mut().invited.remove(&room);
            let _ = events
                .send(Event::ConferenceInviteCancelled { account_id: cfg.account_id, room: room.clone() })
                .await;
        }
        return; // not in this conference — nothing else to coordinate
    }

    // A different real JID behind this occupant JID than before: the old one's leg goes.
    if let (Some(prev), Some(addr)) = (&previous, &real_jid) {
        if state.is_some() && !super::origin::jid_eq(&prev.real_jid, addr) {
            remove_member(w, calls, &room, &occupant);
        }
    }
    match (state, real_jid) {
        (Some((MujiState::Ready, _)), Some(addr)) => {
            let video = calls.borrow().conferences.get(&room).map(|c| c.video).unwrap_or(false);
            maybe_initiate(w, calls, events, cfg, &room, &occupant, &addr, video).await;
        }
        (Some((MujiState::Preparing, _)), Some(addr)) => {
            ensure_member(calls, &room, &occupant, &addr);
            emit_conference(calls, events, cfg.account_id, &room).await;
        }
        _ => {
            remove_member(w, calls, &room, &occupant);
            emit_conference(calls, events, cfg.account_id, &room).await;
            end_conference_if_empty(w, calls, events, cfg.account_id, &room).await;
        }
    }
}

#[cfg(test)]
mod muji_leg_tests {
    use super::*;

    const AUDIO: &str = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\na=sendrecv\r\n";

    #[test]
    fn sends_video_follows_direction() {
        assert!(!sdp_sends_video(AUDIO));
        assert!(sdp_sends_video(&format!("{AUDIO}m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=sendrecv\r\n")));
        assert!(!sdp_sends_video(&format!("{AUDIO}m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\na=recvonly\r\n")));
        // a later sending video m-line counts even after a receive-only one
        assert!(sdp_sends_video(&format!(
            "{AUDIO}m=video 9 X 96\r\na=mid:1\r\na=recvonly\r\nm=video 9 X 96\r\na=mid:2\r\na=sendonly\r\n"
        )));
        // a sending video m-line followed by audio
        assert!(sdp_sends_video(&format!("m=video 9 X 96\r\na=mid:1\r\n{AUDIO}")));
    }

    fn content(fp_ns: &str) -> Element {
        let fp = Element::builder("fingerprint", fp_ns).build();
        let transport = Element::builder("transport", jingle_sdp::NS_ICE).append(fp).build();
        Element::builder("content", jingle_sdp::NS_JINGLE)
            .attr(crate::ncname("name"), "1")
            .attr(crate::ncname("senders"), "both")
            .append(transport)
            .build()
    }

    #[test]
    fn verified_leg_requirements() {
        let plain = vec![content(jingle_sdp::NS_DTLS)];
        let encrypted = vec![content(NS_OMEMO_DTLS)];
        assert!(!all_fingerprints_encrypted(&plain));
        assert!(all_fingerprints_encrypted(&encrypted));
        assert!(all_fingerprints_decrypted(&plain));
        assert!(!all_fingerprints_decrypted(&encrypted));

        let trusted = Some(("fp".to_string(), 7, 1));
        let untrusted = Some(("fp".to_string(), 7, 0));
        // opportunistic leg: anything goes, except a device other than the advertised one
        assert!(muji_leg_acceptable(&plain, &None, false, Some(7)));
        assert!(!muji_leg_acceptable(&plain, &Some(("fp".into(), 8, 1)), false, Some(7)));
        // verified leg: decrypted, trusted, right device
        assert!(muji_leg_acceptable(&plain, &trusted, true, Some(7)));
        assert!(!muji_leg_acceptable(&plain, &untrusted, true, Some(7)));
        assert!(!muji_leg_acceptable(&plain, &None, true, None));
        assert!(!muji_leg_acceptable(&encrypted, &trusted, true, None));
    }

    #[test]
    fn actpass_is_replaced_by_the_negotiated_role() {
        let fp = Element::builder("fingerprint", jingle_sdp::NS_DTLS)
            .attr(crate::ncname("hash"), "sha-256")
            .attr(crate::ncname("setup"), "actpass")
            .append("AA:BB")
            .build();
        let transport = Element::builder("transport", jingle_sdp::NS_ICE).append(fp).build();
        let content = Element::builder("content", jingle_sdp::NS_JINGLE)
            .attr(crate::ncname("name"), "0")
            .append(transport)
            .build();
        let fixed = with_peer_setup(vec![content.clone()], Some("passive"));
        let fp = fixed[0]
            .get_child("transport", jingle_sdp::NS_ICE)
            .unwrap()
            .get_child("fingerprint", jingle_sdp::NS_DTLS)
            .unwrap();
        assert_eq!(fp.attr("setup"), Some("passive"));
        assert_eq!(fp.attr("hash"), Some("sha-256"));
        assert_eq!(fp.text(), "AA:BB");
        assert_eq!(contents_setup(&fixed).as_deref(), Some("passive"));
        // unknown role → unchanged
        assert_eq!(contents_setup(&with_peer_setup(vec![content], None)).as_deref(), Some("actpass"));
        assert_eq!(opposite_setup("active").as_deref(), Some("passive"));
        assert_eq!(sdp_setup("v=0\r\na=setup:active\r\n").as_deref(), Some("active"));
    }

    fn video(name: &str, fp_ns: &str) -> Element {
        let fp = Element::builder("fingerprint", fp_ns).build();
        Element::builder("content", jingle_sdp::NS_JINGLE)
            .attr(crate::ncname("name"), name)
            .append(Element::builder("description", jingle_sdp::NS_RTP).attr(crate::ncname("media"), "video").build())
            .append(Element::builder("transport", jingle_sdp::NS_ICE).append(fp).build())
            .build()
    }

    #[test]
    fn renegotiation_keeps_leg_identity() {
        let decrypted = vec![content(jingle_sdp::NS_DTLS)];
        let identity = Some(("fp".to_string(), 7));
        let same = Some(("fp".to_string(), 7, 1));
        // never authenticated → nothing required
        assert!(keeps_leg_identity(&None, false, &decrypted, &None));
        // authenticated → encrypted + decrypted + same identity
        assert!(keeps_leg_identity(&identity, true, &decrypted, &same));
        assert!(!keeps_leg_identity(&identity, false, &decrypted, &same), "cleartext downgrade");
        assert!(!keeps_leg_identity(&identity, true, &decrypted, &Some(("other".into(), 7, 1))));
        assert!(!keeps_leg_identity(&identity, true, &decrypted, &Some(("fp".into(), 8, 1))));
        assert!(!keeps_leg_identity(&identity, true, &[content(NS_OMEMO_DTLS)], &same), "undecryptable");
    }

    #[test]
    fn video_contents_are_counted() {
        let set = vec![content(jingle_sdp::NS_DTLS), video("1", jingle_sdp::NS_DTLS), video("2", jingle_sdp::NS_DTLS)];
        assert_eq!(video_contents(&set), 2);
        assert!(video_contents(&set) + 1 > MAX_MUJI_VIDEO_CONTENTS);
    }

    #[test]
    fn recently_ended_ring() {
        let mut ring = std::collections::VecDeque::new();
        remember_ended(&mut ring, "sid-1", "peer@example.org/phone");
        assert!(was_recently_ended(&ring, "sid-1", "peer@example.org/phone"));
        assert!(was_recently_ended(&ring, "sid-1", "Peer@Example.org/phone"), "bare JID is case-insensitive");
        assert!(!was_recently_ended(&ring, "sid-1", "peer@example.org/laptop"), "other session");
        assert!(!was_recently_ended(&ring, "sid-1", "mallory@example.org/phone"), "other peer");
        assert!(!was_recently_ended(&ring, "sid-2", "peer@example.org/phone"), "unknown sid");
        for i in 0..RECENTLY_ENDED_CAP {
            remember_ended(&mut ring, &format!("x-{i}"), "p@e/r");
        }
        assert_eq!(ring.len(), RECENTLY_ENDED_CAP);
        assert!(!was_recently_ended(&ring, "sid-1", "peer@example.org/phone"), "oldest evicted");
    }

    #[test]
    fn senders_rewrite_keeps_everything_else() {
        let c = content(jingle_sdp::NS_DTLS);
        let r = content_with_senders(&c, "initiator");
        assert_eq!(r.attr("senders"), Some("initiator"));
        assert_eq!(r.attr("name"), Some("1"));
        assert!(r.get_child("transport", jingle_sdp::NS_ICE).is_some());
        let stub = content_stub(&c, Some("responder"));
        assert_eq!(stub.attr("senders"), Some("responder"));
        assert_eq!(
            stub.get_child("description", jingle_sdp::NS_RTP).and_then(|d| d.attr("media")),
            Some("video")
        );
    }
}
