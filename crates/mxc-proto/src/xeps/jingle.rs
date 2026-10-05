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
}

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
}

/// A live Muji group call we're participating in, keyed in [`Calls::conferences`] by room JID.
struct Conference {
    nick: String,
    /// Our own occupant JID (`room/nick`), used for the glare tie-break + as Jingle initiator.
    our_occupant: String,
    video: bool,
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
        video_tx,
        store,
        account_id,
    }))
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
            let _ = store.insert_call_log(account, &peer, &dir, video, answered, &ts).await;
        });
    }
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

/// OMEMO2-encrypt the plaintext DTLS fingerprint in each content's transport (best-effort: on
/// any failure / missing session, the plaintext fingerprint is left as-is so the call still
/// connects — just unverified). Mirrors Android's `encryptTransport`.
async fn encrypt_call_fingerprints(
    w: &Writer,
    store: &mxc_store::Store,
    cfg: &AccountConfig,
    peer_bare: &str,
    contents: Vec<Element>,
) -> Vec<Element> {
    let mut out = Vec::with_capacity(contents.len());
    for content in contents {
        out.push(encrypt_one_fingerprint(w, store, cfg, peer_bare, content).await);
    }
    out
}

async fn encrypt_one_fingerprint(
    w: &Writer,
    store: &mxc_store::Store,
    cfg: &AccountConfig,
    peer_bare: &str,
    content: Element,
) -> Element {
    let Some(transport) = content.get_child("transport", jingle_sdp::NS_ICE) else {
        return content;
    };
    let Some(fp) = transport.get_child("fingerprint", jingle_sdp::NS_DTLS) else {
        return content;
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
        Err(e) => {
            tracing::warn!(error = %e, "OMEMO call-fingerprint encrypt failed — sending plaintext");
            return content;
        }
    };
    let new_fp = Element::builder("fingerprint", NS_OMEMO_DTLS)
        .attr(crate::ncname("setup"), setup)
        .attr(crate::ncname("hash"), hash)
        .append(encrypted)
        .build();
    content_with_transport(&content, transport_with_fingerprint(transport, new_fp))
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
        while let Ok(ev) = rx.recv().await {
            match ev {
                mxc_media::EngineEvent::LocalDescription { kind, sdp, renegotiation } => {
                    let (u, p, m) = local_transport(&sdp);
                    ufrag = u;
                    pwd = p;
                    mid = m;
                    if renegotiation {
                        // Mid-call upgrade: send ONLY the newly-added (video) content as a Jingle
                        // content-add (our re-offer) / content-accept (our answer to the peer's
                        // content-add). The audio content is already negotiated.
                        let (contents, mids) = jingle_sdp::sdp_to_contents(&sdp);
                        let mut video: Vec<Element> = contents
                            .into_iter()
                            .filter(|c| {
                                c.get_child("description", jingle_sdp::NS_RTP)
                                    .and_then(|d| d.attr("media"))
                                    .map(|md| md == "video")
                                    .unwrap_or(false)
                            })
                            .collect();
                        if !video.is_empty() {
                            // Mirror the call's verification state for the upgrade too.
                            let do_encrypt = calls.borrow().active.get(&sid).map(|c| c.peer_used_omemo).unwrap_or(false);
                            if do_encrypt {
                                video = encrypt_call_fingerprints(&w, &store, &cfg, &peer_bare, video).await;
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
                            let iq = jingle_iq(&peer_full, &sid, &initiator, action, video);
                            tracing::info!(%sid, action, xml = %String::from(&iq), "sending renegotiation (video upgrade)");
                            let _ = w.send(iq);
                        }
                    } else {
                        let action = match kind {
                            mxc_media::SdpKind::Offer => "session-initiate",
                            mxc_media::SdpKind::Answer => "session-accept",
                        };
                        let (contents, mids) = jingle_sdp::sdp_to_contents(&sdp);
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
                            let do_encrypt = matches!(kind, mxc_media::SdpKind::Offer)
                                || calls.borrow().active.get(&sid).map(|c| c.peer_used_omemo).unwrap_or(false);
                            let contents = if do_encrypt {
                                encrypt_call_fingerprints(&w, &store, &cfg, &peer_bare, contents).await
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
                        set_member_state(&calls, &sid, MemberCallState::Active);
                        emit_conference(&calls, &events, account_id, room.as_deref().unwrap_or("")).await;
                        // Serialized mesh: now that this leg is up, start the next pending peer's.
                        if let Some(r) = room.as_deref() {
                            initiate_next_pending(&w, &calls, &events, &cfg, r, video).await;
                        }
                    } else {
                        emit(&events, account_id, &sid, &peer_bare, video, CallState::Active).await;
                    }
                }
                mxc_media::EngineEvent::Failed(reason) => {
                    tracing::warn!(%sid, %reason, "call media failed");
                    calls.borrow_mut().active.remove(&sid);
                    log_call_end(&calls, &sid);
                    if is_muji {
                        set_member_state(&calls, &sid, MemberCallState::Ended);
                        emit_conference(&calls, &events, account_id, room.as_deref().unwrap_or("")).await;
                        // This leg freed the serialization slot — start the next pending peer's.
                        if let Some(r) = room.as_deref() {
                            initiate_next_pending(&w, &calls, &events, &cfg, r, video).await;
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
    let active = calls.borrow_mut().active.remove(sid);
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
    let actions = ["propose", "proceed", "reject", "retract", "accept", "finish"];
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
            calls.borrow_mut().incoming.insert(sid.clone(), (from.clone(), video));
            calls.borrow_mut().meta.insert(sid.clone(), CallMeta {
                peer: peer_bare.clone(),
                outgoing: false,
                video,
                answered: false,
                ts: now(),
            });
            emit(events, cfg.account_id, &sid, &peer_bare, video, CallState::Incoming).await;
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
            log_call_end(calls, &sid);
            emit(events, cfg.account_id, &sid, &peer_bare, video, CallState::Ended { reason: "Call declined".into() }).await;
        }
        "retract" | "finish" => {
            terminate_local(calls, &sid);
            calls.borrow_mut().incoming.remove(&sid);
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
    if !allowed {
        tracing::warn!(%action, %sid, %from, "rejecting Jingle IQ for a session that isn't the sender's");
        unknown_session(w, iq);
        return true;
    }
    ack(w, iq); // every accepted Jingle IQ gets an empty result

    match action {
        "session-initiate" | "session-accept" => {
            let kind = if action == "session-initiate" {
                mxc_media::SdpKind::Offer
            } else {
                mxc_media::SdpKind::Answer
            };
            // XEP-0272 Muji: a session-initiate tagged with `<muji room=…>` belongs to a group
            // call. If we're participating in that conference, spin up a callee engine for it
            // (no JMI ring — Muji peers call each other directly via presence coordination).
            if action == "session-initiate" {
                if let Some(room) = jingle
                    .get_child("muji", muji::NS_MUJI)
                    .and_then(|m| m.attr("room"))
                    .map(str::to_string)
                {
                    let setup = {
                        let c = calls.borrow();
                        if c.active.contains_key(&sid) {
                            None // already have this session
                        } else {
                            c.conferences.get(&room).map(|conf| (conf.our_occupant.clone(), conf.video))
                        }
                    };
                    match setup {
                        Some((our_occ, conf_video)) => {
                            // SECURITY: only accept a Muji leg from someone who is actually a
                            // participant of this room — i.e. an occupant who announced `<muji>`
                            // presence, whose real JID the (non-anonymous) MUC vouched for in
                            // `<item jid>`. Without this, any JID that learns we're in a call could
                            // send a `<muji room=…>` session-initiate and inject unsolicited media
                            // (it auto-accepts with no ring). Match on the bare JID.
                            let occupant = {
                                let c = calls.borrow();
                                c.muji_seen.get(&room).and_then(|m| {
                                    m.iter()
                                        .find(|(occ, p)| {
                                            bare(&p.real_jid) == bare(&from) || bare(occ) == bare(&from)
                                        })
                                        .map(|(occ, _)| occ.clone())
                                })
                            };
                            let Some(occupant) = occupant else {
                                tracing::warn!(%room, %from, "rejecting muji session-initiate from a non-participant");
                                let reason = Element::builder("reason", jingle_sdp::NS_JINGLE)
                                    .append(Element::builder("security-error", jingle_sdp::NS_JINGLE).build())
                                    .build();
                                let _ = w.send(jingle_iq(&from, &sid, "", "session-terminate", vec![reason]));
                                return true;
                            };
                            if let Err(e) = start_call(
                                w, calls, events, cfg, sid.clone(), from.clone(),
                                mxc_media::Role::Callee, conf_video, Some(room.clone()), our_occ,
                            ) {
                                tracing::warn!(error = %e, "start muji callee engine");
                            } else {
                                register_member_session(calls, &room, &occupant, &from, &sid);
                                apply_conf_state_to_leg(calls, &room, &sid);
                            }
                        }
                        None if !calls.borrow().active.contains_key(&sid) => {
                            tracing::debug!(%room, %from, "ignoring muji session-initiate for a conference we're not in");
                            return true;
                        }
                        None => {}
                    }
                }
            }
            let owned: Vec<Element> =
                jingle.children().filter(|c| c.name() == "content").cloned().collect();
            // OMEMO-verified DTLS: decrypt the fingerprint(s) back to plaintext for webrtcbin and
            // capture the peer's verified OMEMO2 identity (for the call shield).
            let store = calls.borrow().store.clone();
            let (contents, verified) =
                decrypt_call_fingerprints(&store, cfg, events, bare(&from), owned).await;
            let refs: Vec<&Element> = contents.iter().collect();
            if let Some(sdp) = jingle_sdp::contents_to_sdp(&refs) {
                let mut c = calls.borrow_mut();
                if let Some(call) = c.active.get_mut(&sid) {
                    if let Err(e) = call.engine.set_remote_description(kind, &sdp) {
                        tracing::warn!(error = %e, "set remote description");
                    }
                    // Remember the peer's (plaintext) content set so a later content-add/accept
                    // (video upgrade) can be merged into a full SDP.
                    call.remote_contents = contents.clone();
                    // Mirror the peer: only encrypt our fingerprint back if they encrypted theirs.
                    call.peer_used_omemo = verified.is_some();
                }
            }
            if let Some((fingerprint, device_id, trust)) = verified {
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
            let store = calls.borrow().store.clone();
            let (new_contents, _verified) =
                decrypt_call_fingerprints(&store, cfg, events, bare(&from), new_owned).await;
            let mut applied = false;
            {
                let mut c = calls.borrow_mut();
                if let Some(call) = c.active.get_mut(&sid) {
                    let mut full = call.remote_contents.clone();
                    full.extend(new_contents.iter().cloned());
                    let refs: Vec<&Element> = full.iter().collect();
                    if let Some(sdp) = jingle_sdp::contents_to_sdp(&refs) {
                        match call.engine.set_remote_description(mxc_media::SdpKind::Answer, &sdp) {
                            Ok(()) => {
                                call.remote_contents = full;
                                call.video = true;
                                applied = true;
                            }
                            Err(e) => tracing::warn!(error = %e, "content-accept set remote"),
                        }
                    }
                }
            }
            if applied {
                tracing::info!(%sid, "content-accept applied — call upgraded to video");
                emit(events, cfg.account_id, &sid, bare(&from), true, CallState::Active).await;
            }
        }
        "content-reject" => {
            tracing::info!(%sid, "peer rejected our video upgrade (content-reject)");
        }
        // Peer is upgrading the call to video: stash their new video content and ask the user
        // for consent (Android-style). `accept_video_upgrade` / `decline_video_upgrade` act on it.
        "content-add" => {
            let new_owned: Vec<Element> =
                jingle.children().filter(|c| c.name() == "content").cloned().collect();
            // Decrypt the OMEMO-verified fingerprint now so the stashed (consent-pending) content
            // is plaintext-ready when the user accepts.
            let store = calls.borrow().store.clone();
            let (new_contents, _verified) =
                decrypt_call_fingerprints(&store, cfg, events, bare(&from), new_owned).await;
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
    if let Some(call) = calls.borrow_mut().active.remove(sid) {
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
    peer_addr: &str, // the peer's real full JID to address the Jingle to (falls back to occupant)
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
                if has_session {
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
            match start_call(
                w, calls, events, cfg, sid.clone(), peer_addr.to_string(),
                mxc_media::Role::Caller, video, Some(room.to_string()), our_occ,
            ) {
                Ok(()) => {
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
                .filter(|(_, m)| {
                    m.state == MemberCallState::Ended
                        || (m.state == MemberCallState::Connecting
                            && m.connecting_since.elapsed() > STUCK_AFTER)
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
            if let Some(call) = calls.borrow_mut().active.remove(sid) {
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
        if let Some(call) = calls.borrow_mut().active.remove(&sid) {
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
    let store = calls.borrow().store.clone();
    // Group calls are gated to private groups (members-only + non-anonymous): Muji's per-pair
    // Jingle needs the participants' real JIDs, which only such rooms expose.
    if !store.muc_omemo_capable(cfg.account_id, room).await.unwrap_or(false) {
        tracing::warn!(%room, "place_group_call: refusing — room is not a private (non-anonymous) group");
        return;
    }
    let nick = match store.muc_nick_by_jid(cfg.account_id, room).await {
        Ok(Some(n)) => n,
        _ => {
            tracing::warn!(%room, "place_group_call: no stored MUC nick (not joined?)");
            return;
        }
    };
    let our_occupant = format!("{room}/{nick}");
    let had_invite = {
        let mut c = calls.borrow_mut();
        c.conferences.insert(
            room.to_string(),
            Conference {
                nick: nick.clone(),
                our_occupant,
                video,
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
    tracing::info!(%room, video, "place_group_call: announcing muji presence");
    // Advertise our OMEMO device id so peers (Android) can OMEMO-encrypt their per-pair DTLS
    // fingerprint to us; None if OMEMO isn't set up (the leg then stays plaintext).
    let device = {
        let store = calls.borrow().store.clone();
        crate::xeps::omemo::own_device_id(&store, cfg).await.ok()
    };
    // XEP-0272: announce `<preparing/>` then the ready content. Our codec set is fixed, so we
    // can advertise readiness immediately.
    let _ = muji::send_muji_presence(w, room, &nick, Some(muji::muji_payload(false, video, device)));
    let _ = muji::send_muji_presence(w, room, &nick, Some(muji::muji_payload(true, video, device)));
    // Mesh with anyone already ready.
    let ready: Vec<(String, String)> = calls
        .borrow()
        .muji_seen
        .get(room)
        .map(|m| {
            m.iter()
                .filter(|(_, p)| p.state == MujiState::Ready)
                .map(|(occ, p)| (occ.clone(), p.real_jid.clone()))
                .collect()
        })
        .unwrap_or_default();
    for (occupant, addr) in ready {
        maybe_initiate(w, calls, events, cfg, room, &occupant, &addr, video).await;
    }
    emit_conference(calls, events, cfg.account_id, room).await;

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
    let (nick, sessions) = {
        let mut c = calls.borrow_mut();
        match c.conferences.remove(room) {
            Some(conf) => {
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
    if let Some(nick) = nick {
        let _ = muji::send_muji_presence(w, room, &nick, None);
    }
    for (sid, addr) in sessions {
        if let Some(call) = calls.borrow_mut().active.remove(&sid) {
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
    emit_conference(calls, events, cfg.account_id, room).await;
}

/// Mute / unmute our microphone across every per-pair session of a group call.
pub fn set_group_mute(calls: &CallRegistry, room: &str, muted: bool) {
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
    mxc_media::stop_group_screen_share();
    if let Some(conf) = calls.borrow_mut().conferences.get_mut(room) {
        conf.screen = None; // drop → portal session ends the cast
    }
}

/// Whether we are currently sharing our screen to the group call in `room`.
pub fn group_screen_sharing(calls: &CallRegistry, room: &str) -> bool {
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
    let Some(from) = pres.attr("from") else { return };
    let Some((room, _nick)) = from.split_once('/') else { return }; // occupant JIDs only
    // Skip our own occupant presence (self-presence carries status code 110).
    if let Some(x) = pres.get_child("x", "http://jabber.org/protocol/muc#user") {
        if x.children().any(|c| c.name() == "status" && c.attr("code") == Some("110")) {
            return;
        }
    }
    let occupant = from.to_string();
    let room = room.to_string();
    let ptype = pres.attr("type").unwrap_or("available");
    let state = if ptype == "unavailable" { None } else { muji::parse_muji_state(pres) };
    // The occupant's REAL full JID (non-anonymous MUC exposes it in `<item jid>`). We address
    // their per-pair Jingle here so it routes directly instead of via the MUC (which is
    // unreliable peer-to-peer). Empty → fall back to the occupant JID.
    let real_jid = pres
        .get_child("x", "http://jabber.org/protocol/muc#user")
        .and_then(|x| x.get_child("item", "http://jabber.org/protocol/muc#user"))
        .and_then(|item| item.attr("jid"))
        .map(str::to_string)
        .unwrap_or_default();

    // Track raw Muji state regardless of whether we're in the call yet.
    {
        let mut c = calls.borrow_mut();
        match state {
            Some(s) => {
                let addr = if real_jid.is_empty() { occupant.clone() } else { real_jid.clone() };
                c.muji_seen
                    .entry(room.clone())
                    .or_default()
                    .insert(occupant.clone(), MujiPeer { state: s, real_jid: addr });
            }
            None => {
                if let Some(m) = c.muji_seen.get_mut(&room) {
                    m.remove(&occupant);
                }
            }
        }
    }

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
            let nick = occupant.rsplit('/').next().unwrap_or(&occupant).to_string();
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

    let addr = if real_jid.is_empty() { occupant.clone() } else { real_jid.clone() };
    match state {
        Some(MujiState::Ready) => {
            let video = calls.borrow().conferences.get(&room).map(|c| c.video).unwrap_or(false);
            maybe_initiate(w, calls, events, cfg, &room, &occupant, &addr, video).await;
        }
        Some(MujiState::Preparing) => {
            ensure_member(calls, &room, &occupant, &addr);
            emit_conference(calls, events, cfg.account_id, &room).await;
        }
        None => {
            remove_member(w, calls, &room, &occupant);
            emit_conference(calls, events, cfg.account_id, &room).await;
        }
    }
}
