//! Messaging: outgoing/incoming `<message>` handling across the Phase-1 XEP set.
//!
//! Wires: bodies, XEP-0085 chat states, XEP-0184 receipts, XEP-0333 markers,
//! XEP-0359 origin/stanza ids, XEP-0444 reactions, XEP-0461 replies, XEP-0308
//! corrections, XEP-0424 retraction, XEP-0280 carbons, XEP-0313 MAM unwrap,
//! XEP-0203 delayed delivery. The OMEMO2 path (PHASE 2) hands the SCE plaintext to
//! `mxc-omemo` before send and decrypts on receive.

use async_channel::Sender;
use minidom::Element;

use mxc_store::messages::{Direction, NewMessage};
use mxc_store::Store;

use mxc_omemo::sce::Envelope;

use crate::client::{AccountConfig, Writer};
use crate::command::Encryption;
use crate::event::Event;
use crate::xeps::carbons::{self, CarbonKind};
use crate::xeps::omemo;
use crate::xeps::roster::new_id;

const NS_CLIENT: &str = "jabber:client";
const NS_RECEIPTS: &str = "urn:xmpp:receipts";
const NS_MARKERS: &str = "urn:xmpp:chat-markers:0";
const NS_CHATSTATES: &str = "http://jabber.org/protocol/chatstates";
const NS_SID: &str = "urn:xmpp:sid:0";
const NS_REACTIONS: &str = "urn:xmpp:reactions:0";
const NS_REPLY: &str = "urn:xmpp:reply:0";
const NS_CORRECT: &str = "urn:xmpp:message-correct:0";
const NS_RETRACT: &str = "urn:xmpp:message-retract:1";
const NS_FALLBACK: &str = "urn:xmpp:fallback:0";
const NS_OOB: &str = "jabber:x:oob";
/// XEP-0447 Stateless File Sharing. monocles Android describes every file of a message with one
/// `<file-sharing/>` element — this is how a message carrying SEVERAL files arrives, since the
/// body URLs and `<x oob>` only ever describe the first one.
const NS_SFS: &str = "urn:xmpp:sfs:0";
/// XEP-0446 file metadata (name/media-type/size/dimensions), inside `<file-sharing/>`.
const NS_FILE_META: &str = "urn:xmpp:file:metadata:0";
/// XEP-0103 URL address — the source form Android uses (`<url-data target='…'/>`).
const NS_URL_DATA: &str = "http://jabber.org/protocol/url-data";
const NS_MAM: &str = "urn:xmpp:mam:2";
const NS_DELAY: &str = "urn:xmpp:delay";
const NS_FORWARD: &str = "urn:xmpp:forward:0";

// ============================ outgoing =====================================

pub async fn send_message(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    body: &str,
    encryption: Encryption,
    reply_to: Option<String>,
    online: bool,
    id: Option<String>,
) -> anyhow::Result<()> {
    // Reuse the UI-chosen id when present so the persist below dedups against the row the UI
    // already stored + rendered (otherwise generate one for non-UI callers).
    let origin_id = id.unwrap_or_else(|| new_id("msg"));

    // Build + send the stanza only when connected. Offline we still persist the message and
    // mark it 'pending' so the outbox flushes it on reconnect (and so encryption happens then,
    // when the OMEMO session/bundles are reachable — never on a cold offline send).
    if online {
        send_text_stanza(w, store, cfg, to, body, encryption, &reply_to, &origin_id, &[]).await?;
    }

    let kind = store.conversation_kind(cfg.account_id, to).await?;
    let conv_kind = match kind.as_deref() {
        Some("muc") => "muc",
        Some("muc_pm") => "muc_pm",
        _ => "chat",
    };
    let conv = store.conversation_id(cfg.account_id, to, conv_kind).await?;
    let now = crate::xeps::rfc3339_now();
    persist_and_emit(
        store, cfg, events, conv,
        NewMessage {
            conversation_id: conv,
            stanza_id: None,
            origin_id: Some(origin_id.clone()),
            counterpart: to.to_string(),
            direction: Direction::Out,
            body: Some(body.to_string()),
            encryption: enc_str(encryption).into(),
            reply_to,
            omemo_fingerprint: None,
            attachment: None,
            occupant_id: None,
            timestamp: now,
            thread: None,
        },
        false,
        /*live=*/ true,
        /*mentioned=*/ false,
        /*reply_to_me=*/ false,
    ).await?;

    // Reflect delivery state in the footer. Online: 'sent' (so the offline outbox won't later
    // re-send it). Offline: 'pending' ("sending…") until the outbox flushes it on reconnect.
    let state = if online { "sent" } else { "pending" };
    store.set_message_state(&origin_id, state).await?;
    let _ = events
        .send(Event::MessageState { marker_id: origin_id, state: state.into() })
        .await;
    Ok(())
}

/// Build + send a 1:1/MUC text message stanza (no local persistence). Shared by the live
/// send path and the offline-outbox flush, so both produce byte-identical stanzas (same
/// `origin_id`, so delivery receipts still match the stored message).
async fn send_text_stanza(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    to: &str,
    body: &str,
    encryption: Encryption,
    reply_to: &Option<String>,
    origin_id: &str,
    file_payloads: &[Element],
) -> anyhow::Result<()> {
    let kind = store.conversation_kind(cfg.account_id, to).await?;
    let is_muc = kind.as_deref() == Some("muc");
    // A 'muc_pm' chat sends to the full occupant JID (room@host/nick) as a private message.
    let is_muc_pm = kind.as_deref() == Some("muc_pm");
    let msg_type = if is_muc { "groupchat" } else { "chat" };

    let mut msg = Element::builder("message", NS_CLIENT)
        .attr(crate::ncname("to"), to)
        .attr(crate::ncname("type"), msg_type)
        .attr(crate::ncname("id"), origin_id)
        .append(Element::builder("origin-id", NS_SID).attr(crate::ncname("id"), origin_id).build());

    // Mark MUC private messages so the recipient treats them as such (XEP-0045 §7.5).
    if is_muc_pm {
        msg = msg.append(Element::builder("x", NS_MUC_USER).build());
    }

    // Receipts/markers are 1:1 semantics; skip for groupchat (PMs keep them).
    if !is_muc {
        msg = msg
            .append(Element::builder("request", NS_RECEIPTS).build())
            .append(Element::builder("markable", NS_MARKERS).build());
    }

    // A file message's payloads — the <x xmlns='jabber:x:oob'><url>, the <fallback> spans that
    // mark the URLs inside the body, and (for several files) one <file-sharing/> per file — go
    // on the outer stanza for plaintext and INSIDE the SCE envelope for OMEMO2, so that for an
    // encrypted chat the file names, sizes and the aesgcm URLs (whose fragment is the key) are
    // never readable by the server. See build_file_oob / build_multi_file_payloads.
    let file_oob: &[Element] = file_payloads;
    match encryption {
        Encryption::None => {
            if let Some(rid) = reply_to {
                msg = msg.append(Element::builder("reply", NS_REPLY).attr(crate::ncname("id"), rid).attr(crate::ncname("to"), to).build());
            }
            msg = msg.append(Element::builder("body", NS_CLIENT).append(body).build());
            for el in file_oob {
                msg = msg.append(el.clone());
            }
        }
        Encryption::Omemo2 => {
            // Body (and reply) live INSIDE the SCE envelope; the outer stanza carries only
            // the <encrypted> element, the EME hint, a store hint, and a fallback body.
            let mut extra = match reply_to {
                Some(rid) => format!("<reply xmlns='{NS_REPLY}' id='{rid}' to='{to}'/>"),
                None => String::new(),
            };
            for el in file_oob {
                extra.push_str(&String::from(el));
            }
            let env = Envelope::new(body, cfg.bare(), to, Some(crate::xeps::rfc3339_now()), &extra);
            // Payload context binding (§5.4.2) uses the SCE <to>: the counterpart (1:1) or room
            // JID (MUC). A MUC private message's <to> is an occupant full JID with no canonical
            // bare form, so bind None — the receiver does the same (see check_sce_binding below).
            let binding_to = if is_muc_pm { None } else { Some(to) };
            let encrypted = encrypt_envelope(w, store, cfg, to, is_muc, binding_to, env.to_xml().as_bytes()).await?;
            msg = msg
                .append(encrypted)
                .append(omemo::eme_hint())
                .append(Element::builder("store", "urn:xmpp:hints").build())
                .append(
                    Element::builder("body", NS_CLIENT)
                        .append("This message is PQ OMEMO2 encrypted.")
                        .build(),
                );
        }
    }

    w.send(msg.build())
}

/// Encrypt an SCE envelope for a conversation, choosing the recipient set by kind: a 1:1 chat
/// encrypts to the single counterpart (`to`); an encrypted MUC encrypts to every room member's
/// real bare JID (XEP-0045 + OMEMO, like monocles Android's getCryptoTargets). Our own other
/// devices are always included by `omemo::encrypt_for_recipients`.
async fn encrypt_envelope(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    to: &str,
    is_muc: bool,
    binding_to: Option<&str>,
    envelope_xml: &[u8],
) -> anyhow::Result<Element> {
    if is_muc {
        let conv = store.conversation_id(cfg.account_id, to, "muc").await?;
        let members = store.muc_member_jids(conv, cfg.bare()).await?;
        if members.is_empty() {
            anyhow::bail!("no known members to encrypt to in {to} (room not joined or anonymous)");
        }
        omemo::encrypt_for_recipients(w, store, cfg, &members, binding_to, envelope_xml).await
    } else {
        omemo::encrypt_for_recipients(w, store, cfg, &[to.to_string()], binding_to, envelope_xml)
            .await
    }
}

/// Flush the offline outbox: (re)send every message queued while disconnected, oldest first,
/// updating each to 'sent' as it goes. A message that still fails is left pending to retry on
/// the next reconnect. Call this once a connection comes online.
pub async fn flush_outbox(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
) -> anyhow::Result<()> {
    let pending = store.pending_messages(cfg.account_id).await?;
    if pending.is_empty() {
        return Ok(());
    }
    tracing::info!(count = pending.len(), "flushing offline outbox");
    for m in pending {
        let encryption = if m.encryption == "omemo2" { Encryption::Omemo2 } else { Encryption::None };
        if let Err(e) =
            send_text_stanza(w, store, cfg, &m.to, &m.body, encryption, &m.reply_to, &m.origin_id, &[]).await
        {
            tracing::warn!(error = %e, to = %m.to, "outbox: send failed, keeping pending");
            continue;
        }
        store.set_message_state(&m.origin_id, "sent").await?;
        let _ = events
            .send(Event::MessageState { marker_id: m.origin_id, state: "sent".into() })
            .await;
    }
    Ok(())
}

const NS_HINTS: &str = "urn:xmpp:hints";
const NS_MUC_USER: &str = "http://jabber.org/protocol/muc#user";
const NS_ATTENTION: &str = "urn:xmpp:attention:0";
const NS_OCCUPANT: &str = "urn:xmpp:occupant-id:0";

/// Whether `s` is composed only of emoji shortcodes (`:name:`) and whitespace — i.e. it carries
/// no real text, so a message that also has one sticker image should render as just that sticker.
fn is_shortcode_only(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return true;
    }
    t.split_whitespace().all(|tok| {
        tok.len() >= 2
            && tok.starts_with(':')
            && tok.ends_with(':')
            && tok[1..tok.len() - 1].chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '+'))
    })
}

/// Is the conversation with `to` OMEMO2-encrypted?
async fn is_omemo(store: &Store, cfg: &AccountConfig, to: &str) -> bool {
    matches!(
        store.conversation_encryption(cfg.account_id, to).await.ok().flatten().as_deref(),
        Some("omemo2")
    )
}

/// Send metadata element(s) — chat-state, marker, receipt, reaction, correction,
/// retraction. When the conversation is OMEMO2-encrypted, the elements are wrapped in an
/// SCE envelope and encrypted (proto-XEP §4.6: ALL per-conversation metadata lives inside
/// the encryption, never on the outer stanza); otherwise they ride a plaintext message.
async fn send_meta(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    to: &str,
    elements: Vec<Element>,
    archive: bool,
) -> anyhow::Result<()> {
    let hint = if archive { "store" } else { "no-store" };
    // Metadata for a room (correction/retraction/etc.) is a `groupchat` message addressed to
    // the room; a 1:1 (or MUC private message) is a `chat` to the counterpart.
    let kind = store.conversation_kind(cfg.account_id, to).await?;
    let is_muc = kind.as_deref() == Some("muc");
    let is_muc_pm = kind.as_deref() == Some("muc_pm");
    let msg_type = if is_muc { "groupchat" } else { "chat" };
    if is_omemo(store, cfg, to).await {
        let content: String = elements.iter().map(String::from).collect();
        let env = Envelope::with_content(&content, cfg.bare(), to, Some(crate::xeps::rfc3339_now()));
        let binding_to = if is_muc_pm { None } else { Some(to) };
        let encrypted = encrypt_envelope(w, store, cfg, to, is_muc, binding_to, env.to_xml().as_bytes()).await?;
        let msg = Element::builder("message", NS_CLIENT)
            .attr(crate::ncname("to"), to)
            .attr(crate::ncname("type"), msg_type)
            .append(encrypted)
            .append(omemo::eme_hint())
            .append(Element::builder(hint, NS_HINTS).build())
            .build();
        w.send(msg)
    } else {
        let mut msg = Element::builder("message", NS_CLIENT)
            .attr(crate::ncname("to"), to)
            .attr(crate::ncname("type"), msg_type)
            .append(Element::builder(hint, NS_HINTS).build());
        for el in elements {
            msg = msg.append(el);
        }
        w.send(msg.build())
    }
}

pub async fn send_chat_state(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    to: &str,
    state: &str,
) -> anyhow::Result<()> {
    let el = Element::builder(state, NS_CHATSTATES).build();
    send_meta(w, store, cfg, to, vec![el], false).await
}

pub async fn send_read_marker(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    to: &str,
    stanza_id: &str,
) -> anyhow::Result<()> {
    let el = Element::builder("displayed", NS_MARKERS).attr(crate::ncname("id"), stanza_id).build();
    send_meta(w, store, cfg, to, vec![el], false).await
}

/// Send a XEP-0444 `<reactions>` stanza referencing `ref_id` with the full emoji set. Group
/// chats use a plaintext `type="groupchat"` message to the room (reactions are reflected back
/// by the MUC); 1:1 chats go through [`send_meta`] (encrypted when the chat is OMEMO2).
async fn send_reaction_stanza(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    to: &str,
    is_muc: bool,
    ref_id: &str,
    emojis: &[String],
) -> anyhow::Result<()> {
    if is_muc {
        // In an encrypted room, the reaction (like all metadata) is wrapped in SCE and
        // encrypted to the members; send_meta handles the groupchat type + encryption.
        if is_omemo(store, cfg, to).await {
            return send_meta(w, store, cfg, to, vec![reactions_element(ref_id, emojis)], true).await;
        }
        let msg = Element::builder("message", NS_CLIENT)
            .attr(crate::ncname("to"), to)
            .attr(crate::ncname("type"), "groupchat")
            .attr(crate::ncname("id"), new_id("rx"))
            .append(reactions_element(ref_id, emojis))
            .append(Element::builder("store", NS_HINTS).build())
            .build();
        w.send(msg)
    } else {
        send_meta(w, store, cfg, to, vec![reactions_element(ref_id, emojis)], true).await
    }
}

fn reactions_element(target_id: &str, emojis: &[String]) -> Element {
    let mut r = Element::builder("reactions", NS_REACTIONS).attr(crate::ncname("id"), target_id);
    for e in emojis {
        r = r.append(Element::builder("reaction", NS_REACTIONS).append(e.as_str()).build());
    }
    r.build()
}

/// XEP-0444: react to a message. Toggles a single emoji (clears it if we already set it),
/// sends the full replacement set (encrypted when the chat is OMEMO2), and updates our
/// local copy + UI so the chip appears immediately.
pub async fn react(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    target_id: &str,
    emojis: &[String],
) -> anyhow::Result<()> {
    let is_muc = store.conversation_kind(cfg.account_id, to).await?.as_deref() == Some("muc");
    let kind = if is_muc { "muc" } else { "chat" };
    let conv = store.conversation_id(cfg.account_id, to, kind).await?;
    let target = store.message_by_marker(conv, target_id).await?;

    // XEP-0444 §5: the reaction references the MUC-assigned stanza-id in a group chat, and
    // the origin-id (our marker) in a 1:1 chat.
    let ref_id = match (&target, is_muc) {
        (Some(t), true) => t.stanza_id.clone().unwrap_or_else(|| target_id.to_string()),
        _ => target_id.to_string(),
    };

    let Some(target) = target else {
        // We don't have the message locally — just emit the picked reaction(s).
        return send_reaction_stanza(w, store, cfg, to, is_muc, &ref_id, emojis).await;
    };

    // The key our own reactions are stored under: in a MUC, our XEP-0421 occupant id (so the
    // reflected copy folds onto the same key); in 1:1, our bare JID. Fall back to the bare
    // JID if we don't know our occupant id yet.
    let reactor_key = if is_muc {
        store.muc_self_occupant(conv).await?.unwrap_or_else(|| cfg.bare().to_string())
    } else {
        cfg.bare().to_string()
    };

    // Toggle each picked emoji within our current reaction set so multiple reactions can
    // coexist (re-picking one removes it). XEP-0444 is replace-semantics, so we then send
    // the full updated set.
    let mut desired = store.reactions_of(target.id, &reactor_key).await?;
    for e in emojis {
        if let Some(pos) = desired.iter().position(|x| x == e) {
            desired.remove(pos);
        } else {
            desired.push(e.clone());
        }
    }

    send_reaction_stanza(w, store, cfg, to, is_muc, &ref_id, &desired).await?;
    store.set_reactions(target.id, &reactor_key, Some("You"), &desired).await?;
    let tallies = store.reactions(target.id).await?;
    let _ = events
        .send(Event::ReactionsUpdated {
            account_id: cfg.account_id,
            conversation_id: conv,
            message_id: target.id,
            tallies,
        })
        .await;
    Ok(())
}

/// XEP-0308: correct a message (encrypted when the chat is OMEMO2) + update our copy.
pub async fn send_correction(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    target_id: &str,
    new_body: &str,
    conversation_id: i64,
) -> anyhow::Result<()> {
    let replace = Element::builder("replace", NS_CORRECT).attr(crate::ncname("id"), target_id).build();
    let body = Element::builder("body", NS_CLIENT).append(new_body).build();
    send_meta(w, store, cfg, to, vec![replace, body], true).await?;

    if let Some(mid) = store.apply_correction(conversation_id, target_id, new_body).await? {
        if let Some(row) = fetch_row(store, conversation_id, mid).await {
            let _ = events.send(Event::MessageEdited {
                account_id: cfg.account_id, conversation_id, message: row,
            }).await;
        }
    }
    Ok(())
}

/// XEP-0424: retract a message (encrypted when the chat is OMEMO2) + tombstone our copy.
pub async fn send_retraction(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    target_id: &str,
    conversation_id: i64,
) -> anyhow::Result<()> {
    let retract = Element::builder("retract", NS_RETRACT).attr(crate::ncname("id"), target_id).build();
    let fallback = Element::builder("fallback", NS_FALLBACK).attr(crate::ncname("for"), NS_RETRACT).build();
    let body = Element::builder("body", NS_CLIENT).append("[This message was retracted]").build();
    send_meta(w, store, cfg, to, vec![retract, fallback, body], true).await?;

    if let Some((mid, old_body)) = store.retract_message(conversation_id, target_id).await? {
        let _ = events.send(Event::MessageRetracted {
            account_id: cfg.account_id, conversation_id, message_id: mid, body: old_body,
        }).await;
    }
    Ok(())
}

/// Encrypt + HTTP-upload a file (aesgcm), then send its `aesgcm://` URL as the message body —
/// OMEMO2-wrapped when the chat is encrypted. An optional `caption` is delivered in the SAME
/// message: the body becomes "caption url", with an `<x xmlns='jabber:x:oob'><url>` element and
/// a `<fallback for='oob'>` marking the URL span — all inside the encrypted SCE envelope for
/// OMEMO2, so the caption is end-to-end encrypted (matches monocles Android's wire format).
pub async fn send_file(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    path: &str,
    caption: Option<&str>,
) -> anyhow::Result<()> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| anyhow::anyhow!("read {path}: {e}"))?;
    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();
    let mime = crate::xeps::http_upload::guess_mime(&filename);

    let url = crate::xeps::http_upload::upload_encrypted(w, cfg, &bytes, &filename, mime).await?;

    let encryption = if is_omemo(store, cfg, to).await {
        Encryption::Omemo2
    } else {
        Encryption::None
    };

    let caption = caption.map(str::trim).filter(|c| !c.is_empty());
    // A file send only reaches here after a successful HTTP upload, i.e. we're online.
    let origin_id = new_id("msg");

    // No caption: byte-identical to the legacy path (body = url, no OOB, no attachment).
    let Some(caption) = caption else {
        send_text_stanza(w, store, cfg, to, &url, encryption, &None, &origin_id, &[]).await?;
        persist_file_message(store, cfg, events, to, &url, None, encryption, &origin_id).await?;
        return Ok(());
    };

    // Caption: wire body = "caption url" with the URL span marked for stripping.
    let wire_body = format!("{caption} {url}");
    let start = caption.chars().count() + 1; // +1 for the separating space
    let end = start + url.chars().count();
    let file = FileWire { url: &url, fallback_span: Some((start, end)) };
    send_text_stanza(w, store, cfg, to, &wire_body, encryption, &None, &origin_id, &build_file_oob(&file)).await?;
    // Stored locally: body = caption, file URL in the attachment column.
    persist_file_message(
        store, cfg, events, to, caption, Some(attachment_json(&url)), encryption, &origin_id,
    )
    .await
}

/// Share SEVERAL files in ONE message (XEP-0447), the way monocles Android does: every file is
/// uploaded (encrypted, `aesgcm://`), the body lists the caption followed by one URL per file,
/// each URL span is marked as a fallback for both `jabber:x:oob` and `urn:xmpp:sfs:0`, and every
/// file gets a `<file-sharing/>` element carrying its own source and metadata.
///
/// For OMEMO2 chats all of that lives inside the SCE envelope — the `<url-data target>` holds the
/// `aesgcm://` URL whose fragment is the file key, so it must never appear on the outer stanza.
///
/// A single path is handed to [`send_file`], keeping that (already interoperable) wire format
/// byte-for-byte unchanged.
pub async fn send_files(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    paths: &[String],
    caption: Option<&str>,
) -> anyhow::Result<()> {
    let caption = caption.map(str::trim).filter(|c| !c.is_empty());
    match paths {
        [] => return Ok(()),
        [one] => return send_file(w, store, cfg, events, to, one, caption).await,
        _ => {}
    }

    // Upload first: a failed upload must not leave a half-described message on the wire.
    let mut uploaded: Vec<serde_json::Value> = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| anyhow::anyhow!("read {path}: {e}"))?;
        let name = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let mime = crate::xeps::http_upload::guess_mime(&name);
        let size = bytes.len() as i64;
        let url = crate::xeps::http_upload::upload_encrypted(w, cfg, &bytes, &name, mime).await?;
        uploaded.push(serde_json::json!({
            "url": url, "mime": mime, "name": name, "size": size,
        }));
    }

    let encryption =
        if is_omemo(store, cfg, to).await { Encryption::Omemo2 } else { Encryption::None };
    let origin_id = new_id("msg");

    let urls: Vec<&str> = uploaded.iter().map(|f| f["url"].as_str().unwrap_or_default()).collect();
    let (wire_body, spans) = build_multi_file_body(caption, &urls);
    let payloads = build_multi_file_payloads(&uploaded, &spans, &origin_id);
    send_text_stanza(w, store, cfg, to, &wire_body, encryption, &None, &origin_id, &payloads)
        .await?;
    // Stored locally as ONE message: body = caption, every file in the attachment column.
    persist_file_message(
        store,
        cfg,
        events,
        to,
        caption.unwrap_or(""),
        attachment_json_files(&uploaded),
        encryption,
        &origin_id,
    )
    .await
}

/// The wire body of a multi-file message — the caption (when there is one) followed by every
/// URL on its own line — together with each URL's span. Spans are counted in code points, which
/// is what XEP-0428 specifies and what the receiving side strips.
fn build_multi_file_body(caption: Option<&str>, urls: &[&str]) -> (String, Vec<(usize, usize)>) {
    let mut body = caption.unwrap_or("").to_string();
    let mut spans = Vec::with_capacity(urls.len());
    for url in urls {
        if !body.is_empty() {
            body.push('\n');
        }
        let start = body.chars().count();
        body.push_str(url);
        spans.push((start, body.chars().count()));
    }
    (body, spans)
}

/// The payload elements for a multi-file message: a `<fallback>` per file for each namespace
/// that describes it, and one `<file-sharing/>` per file.
///
/// Deliberately NO `<x xmlns='jabber:x:oob'>`. A single-file message needs it (that is how the
/// receiver learns the body's URL is a file), but here every file already has a `<file-sharing/>`
/// — and monocles Android's parser *overwrites* the first file's metadata with the OOB
/// element's URL-only view whichever order the two arrive in, so adding it would cost the first
/// file its name and size for no gain. Clients that understand neither still see the URLs in
/// the body.
fn build_multi_file_payloads(
    files: &[serde_json::Value],
    spans: &[(usize, usize)],
    origin_id: &str,
) -> Vec<Element> {
    let mut out = Vec::new();
    for (start, end) in spans {
        for ns in [NS_OOB, NS_SFS] {
            out.push(
                Element::builder("fallback", NS_FALLBACK)
                    .attr(crate::ncname("for"), ns)
                    .append(
                        Element::builder("body", NS_FALLBACK)
                            .attr(crate::ncname("start"), start.to_string())
                            .attr(crate::ncname("end"), end.to_string())
                            .build(),
                    )
                    .build(),
            );
        }
    }
    for (i, file) in files.iter().enumerate() {
        let Some(url) = file["url"].as_str() else { continue };
        let mut meta = Element::builder("file", NS_FILE_META);
        for (tag, value) in [("name", file["name"].as_str()), ("media-type", file["mime"].as_str())]
        {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                meta = meta.append(Element::builder(tag, NS_FILE_META).append(value).build());
            }
        }
        if let Some(size) = file["size"].as_i64().filter(|s| *s > 0) {
            meta = meta
                .append(Element::builder("size", NS_FILE_META).append(size.to_string()).build());
        }
        out.push(
            Element::builder("file-sharing", NS_SFS)
                .attr(crate::ncname("disposition"), "inline")
                // XEP-0447 requires an id per element once a message describes several files;
                // the receiver uses it to line each file up with its own row.
                .attr(crate::ncname("id"), format!("{origin_id}-{i}"))
                .append(meta.build())
                .append(
                    Element::builder("sources", NS_SFS)
                        .append(
                            Element::builder("url-data", NS_URL_DATA)
                                .attr(crate::ncname("target"), url)
                                .build(),
                        )
                        .build(),
                )
                .build(),
        );
    }
    out
}

/// Persist + emit an outgoing file message and mark it 'sent' (file sends only happen online).
#[allow(clippy::too_many_arguments)]
async fn persist_file_message(
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    body: &str,
    attachment: Option<String>,
    encryption: Encryption,
    origin_id: &str,
) -> anyhow::Result<()> {
    let kind = store.conversation_kind(cfg.account_id, to).await?;
    let conv_kind = match kind.as_deref() {
        Some("muc") => "muc",
        Some("muc_pm") => "muc_pm",
        _ => "chat",
    };
    let conv = store.conversation_id(cfg.account_id, to, conv_kind).await?;
    let now = crate::xeps::rfc3339_now();
    persist_and_emit(
        store, cfg, events, conv,
        NewMessage {
            conversation_id: conv,
            stanza_id: None,
            origin_id: Some(origin_id.to_string()),
            counterpart: to.to_string(),
            direction: Direction::Out,
            body: Some(body.to_string()),
            encryption: enc_str(encryption).into(),
            reply_to: None,
            omemo_fingerprint: None,
            attachment,
            occupant_id: None,
            timestamp: now,
            thread: None,
        },
        false,
        /*live=*/ true,
        /*mentioned=*/ false,
        /*reply_to_me=*/ false,
    ).await?;
    store.set_message_state(origin_id, "sent").await?;
    let _ = events
        .send(Event::MessageState { marker_id: origin_id.to_string(), state: "sent".into() })
        .await;
    Ok(())
}

/// Send a **sticker** as a standalone message (independent of the text input).
///
/// - **Encrypted chat (OMEMO2):** sent as an **encrypted image** — uploaded (XEP-0363, AES-GCM
///   `aesgcm://`) with the URL carried inside the SCE envelope. Never an inline plaintext-fetchable
///   BoB blob.
/// - **Plaintext chat:** sent as a real inline sticker — XEP-0231 Bits of Binary `<data>` plus an
///   XHTML `<img src='cid:…'/>` on the message (large ones, >100 KiB, fall back to a plain upload).
pub async fn send_sticker(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    path: &str,
) -> anyhow::Result<()> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| anyhow::anyhow!("read {path}: {e}"))?;
    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sticker")
        .to_string();
    let mime = crate::xeps::http_upload::guess_mime(&filename);

    // Encrypted chat, or a too-large image → upload (encrypted when OMEMO2) and send the URL.
    if is_omemo(store, cfg, to).await || bytes.len() > super::bob::MAX_INLINE {
        let url = crate::xeps::http_upload::upload_encrypted(w, cfg, &bytes, &filename, mime).await?;
        let encryption = if is_omemo(store, cfg, to).await {
            Encryption::Omemo2
        } else {
            Encryption::None
        };
        return send_message(w, store, cfg, events, to, &url, encryption, None, true, None).await;
    }

    // Plaintext chat → a genuine inline sticker (XEP-0231 BoB) carried on the cleartext message.
    let cid_ssp = super::bob::cid_ssp(&bytes);
    let cid_uri = format!("cid:{cid_ssp}");
    let _ = super::bob::save(&cid_uri, &bytes);

    let origin_id = new_id("msg");
    send_plain_sticker_stanza(w, store, cfg, to, &cid_uri, &cid_ssp, mime, &bytes, &origin_id).await?;

    let conv_kind = match store.conversation_kind(cfg.account_id, to).await?.as_deref() {
        Some("muc") => "muc",
        Some("muc_pm") => "muc_pm",
        _ => "chat",
    };
    let conv = store.conversation_id(cfg.account_id, to, conv_kind).await?;
    let now = crate::xeps::rfc3339_now();
    persist_and_emit(
        store, cfg, events, conv,
        NewMessage {
            conversation_id: conv,
            stanza_id: None,
            origin_id: Some(origin_id.clone()),
            counterpart: to.to_string(),
            direction: Direction::Out,
            body: Some(cid_uri),
            encryption: enc_str(Encryption::None).into(),
            reply_to: None,
            omemo_fingerprint: None,
            attachment: None,
            occupant_id: None,
            timestamp: now,
            thread: None,
        },
        false,
        /*live=*/ true,
        /*mentioned=*/ false,
        /*reply_to_me=*/ false,
    ).await?;
    store.set_message_state(&origin_id, "sent").await?;
    let _ = events
        .send(Event::MessageState { marker_id: origin_id, state: "sent".into() })
        .await;
    Ok(())
}

/// Build + send a **plaintext** inline-BoB sticker stanza (no SCE, no local persistence): a
/// cleartext `<message>` carrying the `<body>` (`cid:` reference), the XHTML `<img src='cid:…'/>`,
/// and the `<data xmlns='urn:xmpp:bob'>` with the bytes.
#[allow(clippy::too_many_arguments)]
async fn send_plain_sticker_stanza(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    to: &str,
    cid_uri: &str,
    cid_ssp: &str,
    mime: &str,
    bytes: &[u8],
    origin_id: &str,
) -> anyhow::Result<()> {
    let kind = store.conversation_kind(cfg.account_id, to).await?;
    let is_muc = kind.as_deref() == Some("muc");
    let is_muc_pm = kind.as_deref() == Some("muc_pm");
    let msg_type = if is_muc { "groupchat" } else { "chat" };

    let mut msg = Element::builder("message", NS_CLIENT)
        .attr(crate::ncname("to"), to)
        .attr(crate::ncname("type"), msg_type)
        .attr(crate::ncname("id"), origin_id)
        .append(Element::builder("origin-id", NS_SID).attr(crate::ncname("id"), origin_id).build());
    if is_muc_pm {
        msg = msg.append(Element::builder("x", NS_MUC_USER).build());
    }
    if !is_muc {
        msg = msg
            .append(Element::builder("request", NS_RECEIPTS).build())
            .append(Element::builder("markable", NS_MARKERS).build());
    }
    msg = msg
        .append(Element::builder("body", NS_CLIENT).append(cid_uri).build())
        .append(super::bob::xhtml_img(cid_uri))
        .append(super::bob::data_element(cid_ssp, mime, bytes))
        .append(Element::builder("store", NS_HINTS).build());
    w.send(msg.build())
}

// ============================ WebXDC =======================================

/// Send a `.xdc` WebXDC app: upload it (encrypted when OMEMO2) and send a file message that
/// carries a fresh `<thread>` — the instance key that subsequent status updates reference.
pub async fn send_webxdc_file(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    path: &str,
) -> anyhow::Result<()> {
    let bytes = tokio::fs::read(path).await.map_err(|e| anyhow::anyhow!("read {path}: {e}"))?;
    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app.xdc")
        .to_string();
    let url = crate::xeps::http_upload::upload_encrypted(w, cfg, &bytes, &filename, "application/webxdc+zip").await?;
    let thread = new_id("webxdc");
    let omemo = is_omemo(store, cfg, to).await;
    let encryption = if omemo { Encryption::Omemo2 } else { Encryption::None };
    let origin_id = new_id("msg");

    let kind = store.conversation_kind(cfg.account_id, to).await?;
    let is_muc = kind.as_deref() == Some("muc");
    let is_muc_pm = kind.as_deref() == Some("muc_pm");
    let msg_type = if is_muc { "groupchat" } else { "chat" };
    let mut msg = Element::builder("message", NS_CLIENT)
        .attr(crate::ncname("to"), to)
        .attr(crate::ncname("type"), msg_type)
        .attr(crate::ncname("id"), &origin_id)
        .append(Element::builder("origin-id", NS_SID).attr(crate::ncname("id"), &origin_id).build());
    if is_muc_pm {
        msg = msg.append(Element::builder("x", NS_MUC_USER).build());
    }
    if !is_muc {
        msg = msg
            .append(Element::builder("request", NS_RECEIPTS).build())
            .append(Element::builder("markable", NS_MARKERS).build());
    }
    let thread_el = super::webxdc::thread_element(&thread);
    match encryption {
        Encryption::None => {
            msg = msg
                .append(Element::builder("body", NS_CLIENT).append(url.as_str()).build())
                .append(thread_el);
        }
        Encryption::Omemo2 => {
            let env = Envelope::new(&url, cfg.bare(), to, Some(crate::xeps::rfc3339_now()), &String::from(&thread_el));
            let binding_to = if is_muc_pm { None } else { Some(to) };
            let encrypted = encrypt_envelope(w, store, cfg, to, is_muc, binding_to, env.to_xml().as_bytes()).await?;
            msg = msg
                .append(encrypted)
                .append(omemo::eme_hint())
                .append(Element::builder("store", NS_HINTS).build())
                .append(Element::builder("body", NS_CLIENT).append("This message is PQ OMEMO2 encrypted.").build());
        }
    }
    w.send(msg.build())?;

    let conv_kind = match kind.as_deref() {
        Some("muc") => "muc",
        Some("muc_pm") => "muc_pm",
        _ => "chat",
    };
    let conv = store.conversation_id(cfg.account_id, to, conv_kind).await?;
    let now = crate::xeps::rfc3339_now();
    persist_and_emit(
        store, cfg, events, conv,
        NewMessage {
            conversation_id: conv,
            stanza_id: None,
            origin_id: Some(origin_id.clone()),
            counterpart: to.to_string(),
            direction: Direction::Out,
            body: Some(url),
            encryption: enc_str(encryption).into(),
            reply_to: None,
            omemo_fingerprint: None,
            attachment: None,
            occupant_id: None,
            timestamp: now,
            thread: Some(thread),
        },
        false, /*live=*/ true, /*mentioned=*/ false, /*reply_to_me=*/ false,
    ).await?;
    store.set_message_state(&origin_id, "sent").await?;
    let _ = events.send(Event::MessageState { marker_id: origin_id, state: "sent".into() }).await;
    Ok(())
}

/// Send a WebXDC status update (the app called `sendUpdate`). Stored + echoed to our own view, and
/// sent to the chat (inside the SCE envelope when OMEMO2) tied to the app's `<thread>`.
#[allow(clippy::too_many_arguments)]
pub async fn send_webxdc_update(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    to: &str,
    thread: &str,
    payload: Option<&str>,
    info: Option<&str>,
    document: Option<&str>,
    summary: Option<&str>,
    notify: Option<&str>,
) -> anyhow::Result<()> {
    let kind = store.conversation_kind(cfg.account_id, to).await?;
    let is_muc = kind.as_deref() == Some("muc");
    let is_muc_pm = kind.as_deref() == Some("muc_pm");
    let msg_type = if is_muc { "groupchat" } else { "chat" };
    let x = super::webxdc::build_update_x(payload, document, summary, notify);
    let thread_el = super::webxdc::thread_element(thread);
    let origin_id = new_id("wxdc");

    let mut msg = Element::builder("message", NS_CLIENT)
        .attr(crate::ncname("to"), to)
        .attr(crate::ncname("type"), msg_type)
        .attr(crate::ncname("id"), &origin_id)
        .append(Element::builder("origin-id", NS_SID).attr(crate::ncname("id"), &origin_id).build());
    if is_muc_pm {
        msg = msg.append(Element::builder("x", NS_MUC_USER).build());
    }
    if is_omemo(store, cfg, to).await {
        let extra = format!("{}{}", String::from(&x), String::from(&thread_el));
        let env = Envelope::new(info.unwrap_or(""), cfg.bare(), to, Some(crate::xeps::rfc3339_now()), &extra);
        let binding_to = if is_muc_pm { None } else { Some(to) };
        let encrypted = encrypt_envelope(w, store, cfg, to, is_muc, binding_to, env.to_xml().as_bytes()).await?;
        msg = msg
            .append(encrypted)
            .append(omemo::eme_hint())
            .append(Element::builder("store", NS_HINTS).build())
            .append(Element::builder("body", NS_CLIENT).append("This message is PQ OMEMO2 encrypted.").build());
    } else {
        if let Some(i) = info.filter(|s| !s.is_empty()) {
            msg = msg.append(Element::builder("body", NS_CLIENT).append(i).build());
        }
        msg = msg.append(x).append(thread_el).append(Element::builder("store", NS_HINTS).build());
    }
    w.send(msg.build())?;

    // Record our own update so the local app view sees it immediately (and others' replays match).
    let serial = store
        .insert_webxdc_update(cfg.account_id, thread, Some(&origin_id), Some(cfg.bare()), info, document, summary, payload)
        .await?;
    let _ = events
        .send(Event::WebxdcUpdate { account_id: cfg.account_id, thread: thread.to_string(), serial })
        .await;

    // An update's `info` is shown in the chat (like monocles Android): render our own as an
    // outgoing message now; the reflected carbon/echo dedups against this origin id.
    if let Some(i) = info.filter(|s| !s.is_empty()) {
        let conv_kind = match kind.as_deref() {
            Some("muc") => "muc",
            Some("muc_pm") => "muc_pm",
            _ => "chat",
        };
        let conv = store.conversation_id(cfg.account_id, to, conv_kind).await?;
        let now = crate::xeps::rfc3339_now();
        let encryption = if is_omemo(store, cfg, to).await { Encryption::Omemo2 } else { Encryption::None };
        persist_and_emit(
            store, cfg, events, conv,
            NewMessage {
                conversation_id: conv,
                stanza_id: None,
                origin_id: Some(origin_id.clone()),
                counterpart: to.to_string(),
                direction: Direction::Out,
                body: Some(i.to_string()),
                encryption: enc_str(encryption).into(),
                reply_to: None,
                omemo_fingerprint: None,
                attachment: None,
                occupant_id: None,
                timestamp: now,
                thread: Some(thread.to_string()),
            },
            false, /*live=*/ true, /*mentioned=*/ false, /*reply_to_me=*/ false,
        ).await?;
        store.set_message_state(&origin_id, "sent").await?;
        let _ = events.send(Event::MessageState { marker_id: origin_id, state: "sent".into() }).await;
    }
    Ok(())
}

/// Send ephemeral WebXDC realtime data (not stored) for `thread`.
pub async fn send_webxdc_realtime(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    to: &str,
    thread: &str,
    data_b64: &str,
) -> anyhow::Result<()> {
    let kind = store.conversation_kind(cfg.account_id, to).await?;
    let is_muc = kind.as_deref() == Some("muc");
    let is_muc_pm = kind.as_deref() == Some("muc_pm");
    let msg_type = if is_muc { "groupchat" } else { "chat" };
    let x = super::webxdc::build_realtime_x(data_b64);
    let thread_el = super::webxdc::thread_element(thread);

    let mut msg = Element::builder("message", NS_CLIENT).attr(crate::ncname("to"), to).attr(crate::ncname("type"), msg_type);
    if is_muc_pm {
        msg = msg.append(Element::builder("x", NS_MUC_USER).build());
    }
    if is_omemo(store, cfg, to).await {
        let extra = format!("{}{}", String::from(&x), String::from(&thread_el));
        let env = Envelope::with_content(&extra, cfg.bare(), to, Some(crate::xeps::rfc3339_now()));
        let binding_to = if is_muc_pm { None } else { Some(to) };
        let encrypted = encrypt_envelope(w, store, cfg, to, is_muc, binding_to, env.to_xml().as_bytes()).await?;
        msg = msg
            .append(encrypted)
            .append(omemo::eme_hint())
            .append(Element::builder("no-store", NS_HINTS).build());
    } else {
        msg = msg.append(x).append(thread_el).append(Element::builder("no-store", NS_HINTS).build());
    }
    w.send(msg.build())
}

/// Download + decrypt a received `aesgcm://` file into the downloads folder, then emit
/// [`Event::FileSaved`].
pub async fn download_file(
    events: &Sender<Event>,
    cfg: &AccountConfig,
    url: &str,
    filename: &str,
) -> anyhow::Result<()> {
    let bytes = crate::xeps::http_upload::download_any(url).await?;
    let dir = download_dir();
    tokio::fs::create_dir_all(&dir).await.ok();
    let path = unique_path(&dir, filename);
    tokio::fs::write(&path, &bytes)
        .await
        .map_err(|e| anyhow::anyhow!("save {}: {e}", path.display()))?;
    let _ = events
        .send(Event::FileSaved {
            account_id: cfg.account_id,
            url: url.to_string(),
            path: path.to_string_lossy().into_owned(),
        })
        .await;
    Ok(())
}

fn download_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("XDG_DOWNLOAD_DIR") {
        if !d.is_empty() {
            return std::path::PathBuf::from(d);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::Path::new(&home).join("Downloads")
}

/// A non-colliding path in `dir` for `filename` (appends ` (n)` before the extension).
fn unique_path(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let candidate = dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match filename.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (filename.to_string(), String::new()),
    };
    for n in 1..1000 {
        let p = dir.join(format!("{stem} ({n}){ext}"));
        if !p.exists() {
            return p;
        }
    }
    candidate
}

// ============================ incoming =====================================

/// Entry point for an inbound top-level `<message>`. Unwraps carbons/MAM, then routes.
pub async fn handle_incoming(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    calls: &super::jingle::CallRegistry,
    msg: &Element,
) -> anyhow::Result<()> {
    // --- XEP-0353 Jingle Message Initiation (call ringing) — handled before normal messaging.
    if super::jingle::handle_message(w, calls, cfg, events, msg).await {
        return Ok(());
    }

    // --- Social-feed Stories PEP notifications.
    if super::stories::handle_event(store, cfg, events, msg).await {
        return Ok(());
    }

    // --- carbons (XEP-0280): only trusted if outer-from is our bare JID ---
    if let Some((inner, kind)) = carbons::unwrap(msg, cfg.bare()) {
        let dir = match kind {
            CarbonKind::Sent => Direction::Out,
            CarbonKind::Received => Direction::In,
        };
        return process_payload(w, store, cfg, events, &inner, dir, None, /*live=*/ false, None).await;
    }

    // --- MAM (XEP-0313): <result><forwarded><delay/><message/></forwarded></result> ---
    // Already vetted by `mam::screen_result` on the reader loop (queryid, archive `from`,
    // and in-room inner `from` for MUC archives).
    if let Some(result) = msg.get_child("result", NS_MAM) {
        if let Some(fwd) = result.get_child("forwarded", NS_FORWARD) {
            if let Some(inner) = fwd.get_child("message", NS_CLIENT) {
                let ts = delay_stamp(fwd);
                let dir = direction_of(&inner, cfg.bare());
                // The `<result id>` is the archive id (= the live `<stanza-id>` for the queried
                // archive). Use it as the authoritative stanza-id so a MAM copy dedups against
                // the live one even when the forwarded message omits its `<stanza-id>`.
                let mam_id = result.attr("id").map(str::to_string);
                return process_payload(w, store, cfg, events, &inner, dir, ts, false, mam_id).await;
            }
        }
        return Ok(());
    }

    let dir = direction_of(msg, cfg.bare());
    let ts = delay_stamp(msg);
    process_payload(w, store, cfg, events, msg, dir, ts, /*live=*/ true, None).await
}

/// Which stored messages an incoming correction/retraction may target: `(direction, occupant
/// id filter)` for [`Store::find_from_sender`], or `None` if it may target none. Our own
/// side may edit our own messages. A MUC participant is identified by their XEP-0421
/// occupant id — without one a MUC edit can't be attributed and is refused (nicks are
/// reusable), exactly like Conversations. In 1:1 / MUC-PM the conversation already pins the
/// counterpart, so the direction suffices.
fn sender_filter<'a>(kind: &str, own_side: bool, occupant_id: Option<&'a str>) -> Option<(&'static str, Option<&'a str>)> {
    if own_side {
        Some(("out", None))
    } else if kind == "muc" {
        occupant_id.map(|occ| ("in", Some(occ)))
    } else {
        Some(("in", None))
    }
}

/// Tolerated skew for the SCE `<time>` binding (proto-XEP §4.6.2): ±7 days, generous
/// enough to absorb badly wrong sender clocks.
const SCE_MAX_SKEW_DAYS: i64 = 7;

/// Enforce the XEP-0420 §4.5 / proto-XEP §4.6.1–§4.6.2 SCE envelope binding. Returns `Err(reason)`
/// when the decrypted message MUST be dropped (not surfaced): a `<from>` that isn't the
/// authenticated sender, a `<to>` that isn't the expected recipient (when `expected_to` is
/// `Some`), or a `<time>` failing the XEP-0420 (v0.5.0) verification rule. Defends against the
/// stanza-rerouting attack (§6.9) and long-tail replays (§6.11).
///
/// Per XEP-0420 v0.5.0 the `<time>` stamp is checked against **the sending time derived from
/// the stanza itself** (`stanza_ts`: the delay/MAM stamp, or the receive time for live
/// stanzas) — NOT the local clock alone. This makes MAM catch-up of arbitrary age pass (an old
/// archived message carries an equally old delay stamp), which matters because this check runs
/// after the ratchet has already advanced — a rejected envelope is irrecoverably destroyed —
/// while an old ciphertext replayed as a *fresh* message is rejected (its stamp disagrees with
/// the stanza's sending time). Future-dated stamps beyond the window are always rejected. A
/// missing or unparseable `<time>` is REJECTED: it is a required affix in this SCE profile
/// (§4.6.0) whose sole purpose is replay detection, so tolerating its absence would let an
/// attacker strip it to bypass that defence. A missing `<from>`/`<to>` is parsed as empty and
/// so fails the match — matching Android's hard-abort behaviour.
fn check_sce_binding(
    env: &Envelope,
    sender_bare: &str,
    expected_to: Option<&str>,
    stanza_ts: Option<&str>,
) -> Result<(), String> {
    if !env.from.eq_ignore_ascii_case(sender_bare) {
        return Err(format!("SCE <from> '{}' != authenticated sender '{}'", env.from, sender_bare));
    }
    if let Some(exp) = expected_to {
        if !env.to.eq_ignore_ascii_case(exp) {
            return Err(format!("SCE <to> '{}' != expected recipient '{}'", env.to, exp));
        }
    }
    // <time> is a REQUIRED affix in this profile (§4.6.0): reject a missing or
    // unparseable stamp rather than skipping the replay check (fail-open would
    // let an attacker strip <time> to bypass the defence).
    let stamp = env
        .time
        .as_ref()
        .ok_or_else(|| "SCE envelope missing required <time>".to_string())?;
    let t = chrono::DateTime::parse_from_rfc3339(stamp)
        .map_err(|_| format!("SCE <time> unparseable stamp: '{stamp}'"))?
        .with_timezone(&chrono::Utc);
    let now = chrono::Utc::now();
    let max_skew = SCE_MAX_SKEW_DAYS * 24 * 60 * 60;
    if (t - now).num_seconds() > max_skew {
        return Err(format!("SCE <time> '{stamp}' too far in the future"));
    }
    let reference = stanza_ts
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|r| r.with_timezone(&chrono::Utc))
        .unwrap_or(now);
    if (t - reference).num_seconds().abs() > max_skew {
        return Err(format!(
            "SCE <time> '{stamp}' inconsistent with stanza sending time — possible replay"
        ));
    }
    Ok(())
}

/// XEP-0420 "Server-processed Elements": elements the server must be able to read are
/// forbidden inside the SCE `<content>` and MUST be discarded by receivers when found
/// there — XEP-0334 processing hints, XEP-0359 stanza/origin IDs, XEP-0033 extended
/// addressing, and the XEP-0380 EME marker. This is not mere conformance hygiene: our
/// handlers for these element types deliberately read them from the (unencrypted,
/// server-attested) outer stanza, so accepting a copy from inside the envelope would
/// let a sender smuggle *authenticated-looking* routing/archive/dedup directives —
/// e.g. a forged `<stanza-id>` to poison duplicate suppression — past that design.
fn strip_server_processed(content: Element) -> Element {
    fn forbidden(el: &Element) -> bool {
        el.ns() == "urn:xmpp:hints"
            || (el.ns() == NS_SID && matches!(el.name(), "stanza-id" | "origin-id"))
            || el.ns() == "http://jabber.org/protocol/address"
            || (el.ns() == "urn:xmpp:eme:0" && el.name() == "encryption")
    }
    if !content.children().any(forbidden) {
        return content;
    }
    let mut filtered = Element::bare(content.name().to_string(), content.ns());
    for child in content.children() {
        if forbidden(child) {
            tracing::warn!(
                name = child.name(),
                ns = %child.ns(),
                "discarding server-processed element inside SCE <content> (XEP-0420)"
            );
            continue;
        }
        filtered.append_child(child.clone());
    }
    filtered
}

/// Persist a visible "could not be decrypted" placeholder for an OMEMO2 *content* message
/// (one carrying the outer OMEMO fallback `<body>`) whose payload failed to decrypt or
/// failed the SCE binding/`<time>` check. Mirrors Android's
/// `ENCRYPTION_AXOLOTL_OMEMO2_FAILED` placeholder: dropping silently would let tampering
/// (or a bug) go entirely unnoticed by the user. Metadata-only stanzas (chat states,
/// receipts — no outer body) stay invisible. Best-effort; dedup via origin/stanza id.
#[allow(clippy::too_many_arguments)]
async fn persist_decrypt_failure(
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    msg: &Element,
    conv: i64,
    counterpart_full: &str,
    direction: Direction,
    ts: &str,
    occupant_id: Option<String>,
    stanza_id: Option<String>,
    live: bool,
) {
    if msg.get_child("body", NS_CLIENT).is_none() {
        return; // metadata-only stanza: nothing renderable was lost
    }
    let origin_id =
        msg.get_child("origin-id", NS_SID).and_then(|e| e.attr("id").map(str::to_string));
    let row = NewMessage {
        conversation_id: conv,
        stanza_id,
        origin_id,
        counterpart: counterpart_full.to_string(),
        direction,
        body: Some("⚠ This message could not be decrypted.".to_string()),
        encryption: "omemo2-failed".into(),
        reply_to: None,
        omemo_fingerprint: None,
        attachment: None,
        occupant_id,
        timestamp: ts.to_string(),
        thread: None,
    };
    if let Err(e) = persist_and_emit(
        store, cfg, events, conv, row,
        /*bump_unread=*/ direction == Direction::In && live,
        live, false, false,
    )
    .await
    {
        tracing::warn!(error = %e, "failed to persist decrypt-failure placeholder");
    }
}

/// Handle the content of a (possibly-unwrapped) message. For OMEMO2 the body + all
/// metadata are recovered from the decrypted SCE envelope; for plaintext, from the stanza.
async fn process_payload(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    msg: &Element,
    direction: Direction,
    ts_override: Option<String>,
    live: bool,
    mam_id: Option<String>,
) -> anyhow::Result<()> {
    let from = msg.attr("from").unwrap_or_default().to_string();
    let to = msg.attr("to").unwrap_or_default().to_string();
    // counterpart bare JID: the *other* party.
    let counterpart_full = match direction {
        Direction::In => from.clone(),
        Direction::Out => to.clone(),
    };
    let bare = counterpart_full.split('/').next().unwrap_or(&counterpart_full).to_string();
    if bare.is_empty() {
        return Ok(());
    }
    // A MUC private message (XEP-0045 §7.5): a non-groupchat message to/from a room occupant
    // (`room@host/nick`). It gets its OWN conversation keyed by the full occupant JID and kind
    // 'muc_pm', so it shows as a separate "private message" chat rather than inline in the room.
    let is_muc_pm = msg.attr("type") != Some("groupchat")
        && counterpart_full.contains('/')
        && (msg.get_child("x", NS_MUC_USER).is_some()
            || store.conversation_kind(cfg.account_id, &bare).await.ok().flatten().as_deref()
                == Some("muc"));
    let (conv_key, kind): (&str, &str) = if is_muc_pm {
        (counterpart_full.as_str(), "muc_pm")
    } else if msg.attr("type") == Some("groupchat") {
        (bare.as_str(), "muc")
    } else {
        (bare.as_str(), "chat")
    };
    let conv = store.conversation_id(cfg.account_id, conv_key, kind).await?;
    // The canonical id for reactions/retractions/dedup is the `<stanza-id>` stamped by the
    // *relevant* archive — the room for a MUC, our account otherwise — and only if that archive
    // advertises XEP-0359 (else the sender could have forged it; see stanza_id.rs). Failing
    // that, the MAM `<result id>` (already vetted by mam::screen_result). Never an arbitrary
    // `<stanza-id>`: its `by` is sender-controlled. Note: a MUC message can also arrive via the
    // account archive, where the MAM result id is the account id, *not* the room id —
    // preferring the by=room `<stanza-id>` keeps everyone's reactions on the same key.
    let want_by = if kind == "muc" { bare.as_str() } else { cfg.bare() };
    // Delivered as a (screened) MAM result rather than live or as a carbon.
    let from_archive = mam_id.is_some();
    let stanza_id = super::stanza_id::trusted(msg, cfg.account_id, want_by).or(mam_id);
    // Effective message timestamp (delay-corrected) for the stored row.
    let ts = ts_override.unwrap_or_else(|| crate::xeps::rfc3339_now());

    // The actual sender is the inner message's `from` (correct for sent-carbons too).
    let sender_bare = from.split('/').next().unwrap_or(&from).to_string();

    // XEP-0421 occupant id (MUC). If this stanza is from our own nick, it tells us our own
    // occupant id — remember it so we can attribute/toggle our own reactions consistently.
    // Only an unambiguous one (exactly one element) counts - see origin::only_child_id.
    let occupant_id = super::origin::only_child_id(msg, "occupant-id", NS_OCCUPANT);
    // For an OMEMO MUC message the crypto sender is the occupant's *real* bare JID (we encrypt
    // to/decrypt under real JIDs, never the room JID). Resolve it from the message's
    // `<x muc#user><item jid>` (preferred — also refreshes our occupant cache) or, failing
    // that, the occupant table populated from presence. Falls back to `sender_bare`.
    let mut omemo_sender_bare = sender_bare.clone();
    let mut is_own_muc_echo = false;
    if kind == "muc" {
        let nick = from.split('/').nth(1).unwrap_or("").to_string();
        // A real JID carried on the stanza itself. Only the room's own archive attaches this
        // authoritatively (the copy reached us via mam::screen_result, from the room); on a live
        // message the `<x muc#user>` may have been written by the sending occupant — many
        // services pass client payloads through — so it could claim anyone's real JID. Live
        // messages resolve through the presence-derived occupant table instead (Conversations:
        // the true counterpart is only read from a message for MAM results). It never updates
        // that table: an archived nick→JID mapping may be stale.
        let item_jid = if from_archive {
            msg.get_child("x", NS_MUC_USER)
                .and_then(|x| x.get_child("item", NS_MUC_USER))
                .and_then(|item| item.attr("jid").map(str::to_string))
        } else {
            None
        };
        if !nick.is_empty() {
            let resolved = item_jid
                .as_deref()
                .map(|j| j.split('/').next().unwrap_or(j).to_string())
                .or(store.muc_occupant_real_jid(conv, &nick).await.ok().flatten());
            if let Some(real) = resolved {
                omemo_sender_bare = real;
            }
            // Our own reflected groupchat message — we never encrypt to our sending device, so
            // an encrypted echo can't (and needn't) be decrypted; we keep the local plaintext.
            if store.muc_nick(conv).await.unwrap_or(None).as_deref() == Some(nick.as_str()) {
                is_own_muc_echo = true;
            }
        }
        if let Some(occ) = &occupant_id {
            if !nick.is_empty() && store.muc_nick(conv).await.unwrap_or(None).as_deref() == Some(nick.as_str()) {
                let _ = store.set_muc_self_occupant(conv, occ).await;
            }
        }
        // XEP-0045 §8.1 room subject/topic. The room sends its current subject (live) right
        // after we join; only trust live stanzas so backward history paging can't clobber it
        // with a stale topic.
        if live {
            if let Some(subject) = msg.get_child("subject", NS_CLIENT) {
                let _ = store.set_muc_subject(conv, &subject.text()).await;
            }
        }
    }

    // Our own encrypted message reflected by the room: skip the (impossible) self-decrypt and
    // just backfill the room-assigned stanza-id onto the locally-stored copy, so reactions to
    // our own messages resolve. (Plaintext echoes still flow through the normal dedup below.)
    if is_own_muc_echo && msg.get_child("encrypted", omemo::NS_OMEMO2).is_some() {
        if let Some(origin) = msg.get_child("origin-id", NS_SID).and_then(|e| e.attr("id")) {
            if let Some(sid) = &stanza_id {
                let _ = store.backfill_stanza_id(conv, origin, sid, occupant_id.as_deref()).await;
            }
        }
        return Ok(());
    }

    // Expected SCE `<to>` recipient (§4.6.1): the room bare JID for a groupchat; the counterpart
    // for our own carbon-sent copy; our own bare JID for an incoming 1:1. A muc_pm uses an
    // occupant-scoped `<to>` with no canonical bare form, so it's left unbound (`None`). This is
    // ALSO the payload context-binding recipient (§5.4.2), so it must be computed *before*
    // decryption (the GCM AAD depends on it) and reused for the SCE `<to>` check below.
    let expected_to: Option<&str> = if kind == "muc" {
        Some(bare.as_str())
    } else if kind == "muc_pm" {
        None
    } else if matches!(direction, Direction::Out) {
        Some(bare.as_str())
    } else {
        Some(cfg.bare())
    };

    // Recover the per-conversation content: for OMEMO2 the decrypted SCE envelope content
    // (body + ALL metadata); for plaintext, the stanza itself.
    let (content, encryption, fingerprint) =
        if let Some(enc_el) = msg.get_child("encrypted", omemo::NS_OMEMO2) {
            match omemo::decrypt_message(store, cfg, events, enc_el, &omemo_sender_bare, expected_to).await {
                Ok(dec) => {
                    // A key-exchange message consumed one of our one-time pre-keys; top up
                    // + republish the bundle so we don't run out / advertise consumed keys.
                    if dec.was_kex {
                        if let Err(e) = omemo::maintain_and_republish(w, store, cfg).await {
                            tracing::warn!(error = %e, "omemo prekey replenish");
                        }
                    }
                    // XEP-0384 heartbeat: a long one-directional chain reached the ratchet-counter
                    // threshold, so reply with an empty OMEMO message to force a DH-ratchet step
                    // (restores break-in recovery, bounds skipped-key storage). Best-effort.
                    if dec.heartbeat_due {
                        if let Err(e) =
                            omemo::send_heartbeat(w, store, cfg, &omemo_sender_bare, dec.sender_device)
                                .await
                        {
                            tracing::warn!(error = %e, "omemo heartbeat failed");
                        }
                    }
                    // Peer-initiated sessions never delivered the sender's pq_ik (it only
                    // travels in the published bundle) — pin it now if it is missing, so the
                    // hybrid fingerprint can be displayed. Best-effort, once per device per run.
                    if let Err(e) = omemo::reconcile_pq_pin_if_missing(
                        w,
                        store,
                        cfg,
                        &omemo_sender_bare,
                        dec.sender_device,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "omemo pq pin reconciliation failed");
                    }
                    // A key-transport message (no <payload>) re-synced the session as a side
                    // effect of decrypting the key; there is no content to display.
                    if dec.key_transport {
                        return Ok(());
                    }
                    match Envelope::from_xml(&String::from_utf8_lossy(&dec.envelope)) {
                        Ok(env) => {
                            // Enforce the SCE envelope binding (§4.6.1/§4.6.2): the `<from>` must be
                            // the authenticated sender, the `<to>` the expected recipient (computed
                            // above), and the `<time>` within the skew window — else drop the
                            // message (a stanza-rerouting / replay defence). The reference for the
                            // `<time>` window is NOT the stored (display) timestamp: see
                            // sce_time_reference — a sender's own `<delay/>` must not be able to
                            // move the window onto the ciphertext it is replaying.
                            let sce_reference = sce_time_reference(msg, live, &ts);
                            if let Err(reason) =
                                check_sce_binding(&env, &omemo_sender_bare, expected_to, Some(sce_reference.as_str()))
                            {
                                tracing::warn!(%reason, "omemo SCE binding rejected");
                                persist_decrypt_failure(
                                    store, cfg, events, msg, conv, &counterpart_full,
                                    direction, &ts, occupant_id.clone(), stanza_id.clone(), live,
                                )
                                .await;
                                return Ok(());
                            }
                            // Re-parse the SCE <content> children into a queryable element.
                            let wrapped = format!("<content xmlns='{NS_CLIENT}'>{}</content>", env.content_inner);
                            match wrapped.parse::<Element>() {
                                Ok(el) => (strip_server_processed(el), "omemo2", Some(dec.fingerprint)),
                                Err(e) => {
                                    tracing::warn!(error = %e, "omemo SCE content parse failed");
                                    persist_decrypt_failure(
                                        store, cfg, events, msg, conv, &counterpart_full,
                                        direction, &ts, occupant_id.clone(), stanza_id.clone(), live,
                                    )
                                    .await;
                                    return Ok(());
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "omemo SCE parse failed");
                            persist_decrypt_failure(
                                store, cfg, events, msg, conv, &counterpart_full,
                                direction, &ts, occupant_id.clone(), stanza_id.clone(), live,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "omemo decrypt failed");
                    // Surface a visible failure placeholder for content messages (silent
                    // loss would hide tampering or session breakage from the user)…
                    persist_decrypt_failure(
                        store, cfg, events, msg, conv, &counterpart_full,
                        direction, &ts, occupant_id.clone(), stanza_id.clone(), live,
                    )
                    .await;
                    // …then recover: couldn't decrypt a message from this peer (e.g. a stale
                    // session after a reset on either side). Forget any cached
                    // establish-failure for them, then proactively re-handshake with a
                    // key-transport heal so their *next* message decrypts even if we never
                    // send one ourselves (Android-style recovery).
                    omemo::forget_jid_failures(cfg.account_id, &omemo_sender_bare);
                    if let Some(sid) = enc_el
                        .get_child("header", omemo::NS_OMEMO2)
                        .and_then(|h| h.attr("sid"))
                        .and_then(|s| s.parse::<u32>().ok())
                    {
                        if let Err(he) =
                            omemo::heal_session(w, store, cfg, &omemo_sender_bare, sid).await
                        {
                            tracing::warn!(error = %he, "omemo heal failed");
                        }
                    }
                    return Ok(());
                }
            }
        } else {
            (msg.clone(), "none", None)
        };

    // Whether this stanza was sent by us (another of our devices, or our own MUC reflection,
    // which arrives as Direction::In from our nick).
    let own_side = direction == Direction::Out || is_own_muc_echo;

    // --- markers (0333) / receipts (0184) / chat-states (0085) from the content ---
    // Only the counterpart (an incoming stanza in this conversation) can confirm delivery/read
    // of one of *our* messages in this conversation. Our own devices' markers (carbons/echoes)
    // say nothing about the peer, and an id from another conversation is never touched.
    let from_peer = direction == Direction::In && !is_own_muc_echo;
    for (el, ns, state) in [("received", NS_RECEIPTS, "received"), ("displayed", NS_MARKERS, "displayed")] {
        if let Some(id) = content.get_child(el, ns).and_then(|e| e.attr("id")) {
            if from_peer && store.mark_outgoing_state(conv, id, state).await? {
                let _ = events.send(Event::MessageState { marker_id: id.into(), state: state.into() }).await;
            }
        }
    }
    if live {
        for st in ["composing", "paused", "active", "gone", "inactive"] {
            if content.get_child(st, NS_CHATSTATES).is_some() {
                let _ = events.send(Event::ChatState { full_jid: from.clone(), state: st.into() }).await;
            }
        }
    }

    // XEP-0444 reactions (full replace for the reactor).
    if let Some(reactions) = content.get_child("reactions", NS_REACTIONS) {
        if let Some(target) = reactions.attr("id") {
            let emojis: Vec<String> = reactions
                .children()
                .filter(|c| c.name() == "reaction")
                .map(|r| r.text())
                .collect();
            // Attribute the reaction to a reactor key. In a MUC (XEP-0444 + XEP-0421) that is
            // the sender's stable occupant id; our own reactions are keyed by *our* occupant
            // id too (see react()), so a reflected own-reaction lands on the same key and
            // doesn't double-count. In 1:1 it's our bare JID (out) or the counterpart's (in).
            let reactor = if kind == "muc" {
                match &occupant_id {
                    Some(occ) => occ.clone(),
                    // No occupant id: the room doesn't support XEP-0421 — fall back to the
                    // full occupant JID so different participants stay distinct.
                    None => from.clone(),
                }
            } else if direction == Direction::Out {
                cfg.bare().to_string()
            } else {
                bare.clone()
            };
            // Display name for the reaction tooltip: "You" for our own, the MUC nick for
            // group-chat participants, else the 1:1 counterpart's bare JID.
            let is_self = direction == Direction::Out
                || (kind == "muc"
                    && occupant_id.is_some()
                    && store.muc_self_occupant(conv).await.unwrap_or(None) == occupant_id);
            let reactor_nick = if is_self {
                "You".to_string()
            } else if kind == "muc" {
                from.split('/').nth(1).unwrap_or(&from).to_string()
            } else {
                bare.clone()
            };
            // Like Conversations, a reaction for a message we don't have is dropped.
            if let Some(target_msg) = store.message_by_marker(conv, target).await? {
                store.set_reactions(target_msg.id, &reactor, Some(&reactor_nick), &emojis).await?;
                let tallies = store.reactions(target_msg.id).await?;
                let _ = events.send(Event::ReactionsUpdated {
                    account_id: cfg.account_id, conversation_id: conv, message_id: target_msg.id, tallies,
                }).await;
            }
        }
        return Ok(());
    }

    // XEP-0424 retraction.
    // Only the original sender may retract (find_from_sender); in a MUC the room itself may
    // additionally moderate (XEP-0425: from the bare room JID, targeting the room stanza-id).
    if let Some(retract) = content.get_child("retract", NS_RETRACT) {
        if let Some(target) = retract.attr("id") {
            let is_moderation = kind == "muc"
                && !from.contains('/')
                && retract.children().any(|c| c.name() == "moderated");
            let mid = if is_moderation {
                store.find_by_stanza_id(conv, target).await?
            } else {
                match sender_filter(kind, own_side, occupant_id.as_deref()) {
                    // Like corrections: an encrypted message can only be retracted under the
                    // same OMEMO fingerprint, else the peer's server could forge a plaintext
                    // retraction and delete it. (OMEMO2 retractions travel inside the SCE
                    // envelope on both clients, so this costs no legitimate retraction.)
                    Some((dir, occ)) => {
                        store.find_from_sender(conv, target, dir, occ, Some(fingerprint.as_deref())).await?
                    }
                    None => None,
                }
            };
            match mid {
                Some(mid) => {
                    let old_body = store.retract_message_id(mid).await?;
                    let _ = events.send(Event::MessageRetracted {
                        account_id: cfg.account_id, conversation_id: conv, message_id: mid, body: old_body,
                    }).await;
                }
                None => tracing::debug!(%from, %target, "ignoring retraction: no message from this sender"),
            }
        }
        return Ok(());
    }

    // WebXDC (urn:xmpp:webxdc:0) status update / realtime data — an *invisible* message tied to a
    // `.xdc` app instance by its `<thread>`. Stored (or forwarded for realtime) and pushed to an
    // open app view; never shown as a chat bubble.
    if let Some(x) = content.get_child("x", super::webxdc::NS_WEBXDC) {
        if let Some(thread) = content.get_child("thread", NS_CLIENT).map(|t| t.text()).filter(|s| !s.is_empty()) {
            // The crypto sender (real bare JID in a MUC) authored the update.
            let info = content.get_child("body", NS_CLIENT).map(|b| b.text()).filter(|s| !s.is_empty());
            let wxdc_origin = msg.get_child("origin-id", NS_SID).and_then(|e| e.attr("id"));
            super::webxdc::handle_incoming_update(
                store, cfg, events, &thread, &omemo_sender_bare, wxdc_origin, x, info.as_deref(),
            ).await?;
            // An update's `info` is a human-readable line shown in the chat (like monocles Android):
            // with `info`, fall through so it renders as a normal message; without, it's invisible
            // (pure app-state sync / realtime).
            if info.is_none() {
                return Ok(());
            }
        }
    }

    // Stickers (XEP-0231 BoB). Two wire forms, both handled:
    //  • inline: a `<data xmlns='urn:xmpp:bob'>` element carries the bytes;
    //  • by reference: an XHTML `<img src='cid:…' alt=':shortcode:'/>`, bytes fetched via a BoB IQ.
    // We persist any inline bytes, fetch any referenced-but-missing ones, then rewrite the body so
    // each sticker sits where its `:shortcode:` fallback was (a `cid:` token the UI renders as a
    // small inline image). A sticker-only message becomes a bare `cid:` body (a big standalone
    // sticker).
    //
    // PRIVACY: a BoB fetch is a *cleartext* IQ, so we NEVER fetch for an encrypted message — that
    // would leak the sticker image of an E2EE chat onto the wire. An encrypted sticker MUST be
    // carried inline (`<data>` inside the SCE envelope); if it isn't, we fall back to its text.
    for data in content.children().filter(|c| c.name() == "data" && c.ns() == super::bob::NS_BOB) {
        if let Some((cid, bytes)) = super::bob::parse_data(data) {
            let _ = super::bob::save(&cid, &bytes);
        }
    }
    // All sticker references: `<img>` refs (with their `:shortcode:` alt) ∪ inline `<data>` cids.
    let mut refs = super::bob::img_refs(&content);
    for data in content.children().filter(|c| c.name() == "data" && c.ns() == super::bob::NS_BOB) {
        if let Some(cid) = data.attr("cid") {
            if !refs.iter().any(|(s, _)| s == cid) {
                refs.push((cid.to_string(), None));
            }
        }
    }
    for (ssp, _) in &refs {
        let uri = format!("cid:{ssp}");
        if !super::bob::is_cached(&uri) && encryption != "omemo2" {
            // Cleartext fetch — only for an unencrypted chat. Best-effort; on failure we fall
            // back to the text/shortcode body rather than a broken image.
            match super::bob::fetch(w, &from, ssp).await {
                Ok(bytes) => {
                    let _ = super::bob::save(&uri, &bytes);
                }
                Err(e) => tracing::warn!(error = %e, cid = %ssp, "BoB sticker fetch"),
            }
        }
    }
    let cached: Vec<(String, Option<String>)> = refs
        .into_iter()
        .filter(|(ssp, _)| super::bob::is_cached(&format!("cid:{ssp}")))
        .collect();

    let raw_body_opt = content.get_child("body", NS_CLIENT).map(|b| b.text());
    let synthesized = if cached.is_empty() {
        None
    } else {
        let raw = raw_body_opt.clone().unwrap_or_default();
        let trimmed = raw.trim();
        // A sticker-only message (no text, or just the `:shortcode:`/`cid:`) → a bare `cid:` body
        // (rendered as one big standalone sticker).
        if cached.len() == 1
            && (trimmed.is_empty() || trimmed.starts_with("cid:") || is_shortcode_only(trimmed))
        {
            Some(format!("cid:{}", cached[0].0))
        } else {
            // Text + sticker(s): put each `cid:` token where its `:shortcode:` was, else append.
            let mut b = raw;
            for (ssp, alt) in &cached {
                let uri = format!("cid:{ssp}");
                let placed = alt
                    .as_deref()
                    .and_then(|a| b.find(a).map(|p| (p, a.len())))
                    .map(|(p, len)| b.replace_range(p..p + len, &uri))
                    .is_some();
                if !placed && !b.contains(&uri) {
                    if !b.is_empty() {
                        b.push(' ');
                    }
                    b.push_str(&uri);
                }
            }
            Some(b)
        }
    };
    let Some(raw_body) = synthesized.or(raw_body_opt) else {
        return Ok(());
    };
    // Drop the XEP-0461 `> quoted…` fallback prefix — we render the quote from the reply target.
    let body = strip_reply_fallback(&content, &raw_body);
    // File share with a caption: an <x xmlns='jabber:x:oob'><url> (inside the decrypted SCE for
    // OMEMO2, on the outer stanza for plaintext) carries the file URL, while the body holds the
    // caption with the URL span marked by a <fallback for='oob'>. Pull the URL into the
    // attachment column and strip its span so `body` is just the caption. Files without a
    // caption keep body = URL and no attachment (unchanged legacy behavior).
    // A message may share SEVERAL files (XEP-0447): one <file-sharing/> per file, each with its
    // own URL and metadata, while the body lists every URL and <x oob> names only the first.
    // When they are present they are authoritative — they describe the same files the body URLs
    // do, with names and sizes the URL alone cannot give us.
    let sfs = sfs_files(&content);
    let (body, attachment) = match attachment_json_files(&sfs) {
        Some(json) => {
            let stripped = strip_fallback_spans(&content, &body, &[NS_OOB, NS_SFS]);
            // Senders that describe their files but mark no fallback span leave the URLs in the
            // body; the files are rendered from `attachment`, so drop them and keep the caption.
            (strip_file_urls(&stripped, &sfs), Some(json))
        }
        None => match oob_file_url(&content) {
            Some(url) => (strip_fallback_for(&content, &body, NS_OOB), Some(attachment_json(&url))),
            None => (body, None),
        },
    };

    // XEP-0308 correction of an existing message.
    // Only the original sender may correct (find_from_sender); a correction that matches no
    // message of theirs falls through and is shown as a new message, like Conversations.
    if let Some(replace) = content.get_child("replace", NS_CORRECT) {
        if let Some(target) = replace.attr("id") {
            let mid = match sender_filter(kind, own_side, occupant_id.as_deref()) {
                Some((dir, occ)) => {
                    store.find_from_sender(conv, target, dir, occ, Some(fingerprint.as_deref())).await?
                }
                None => None,
            };
            if let Some(mid) = mid {
                store.correct_message(mid, target, &body, encryption, fingerprint.as_deref()).await?;
                if let Some(row) = fetch_row(store, conv, mid).await {
                    let _ = events.send(Event::MessageEdited {
                        account_id: cfg.account_id, conversation_id: conv, message: row,
                    }).await;
                }
                return Ok(());
            }
        }
    }

    let origin_id = msg.get_child("origin-id", NS_SID).and_then(|e| e.attr("id").map(str::to_string));
    let reply_to = content.get_child("reply", NS_REPLY).and_then(|e| e.attr("id").map(str::to_string));

    // For MUC notification filtering: is this incoming message a highlight (mentions our
    // nick/name, is a private MUC message directed at us, or buzzes us with XEP-0224
    // attention), and/or does it reply to one of our own messages?
    let mut mentioned = false;
    let mut reply_to_me = false;
    if direction == Direction::In && kind == "muc" {
        // XEP-0224 attention ("buzz") counts as a highlight.
        let is_attention = content.get_child("attention", NS_ATTENTION).is_some()
            || msg.get_child("attention", NS_ATTENTION).is_some();
        // Highlight on our MUC nick *and* our display name (the account's local part), like
        // monocles Android matches both getActualNick() and getActualName().
        let mut names: Vec<String> = Vec::new();
        if let Ok(Some(nick)) = store.muc_nick(conv).await {
            if !nick.is_empty() {
                names.push(nick);
            }
        }
        let display = cfg.bare().split('@').next().unwrap_or("").to_string();
        if !display.is_empty() && !names.iter().any(|n| n == &display) {
            names.push(display);
        }
        mentioned = is_attention || names.iter().any(|n| mentions_nick(&body, n));

        if let Some(target) = &reply_to {
            if let Ok(Some(replied)) = store.message_by_marker(conv, target).await {
                reply_to_me = replied.direction == "out";
            }
        }
    }

    // Auto-send a delivery receipt for live 1:1 / MUC-PM messages that requested one (encrypted
    // when the conversation is OMEMO2). For a PM the receipt goes to the occupant JID.
    if live
        && direction == Direction::In
        && (kind == "chat" || kind == "muc_pm")
        && msg.get_child("request", NS_RECEIPTS).is_some()
    {
        // Reference the message's own id (origin-id = the sender's @id) so the sender can
        // match the receipt; fall back to the server stanza-id.
        if let Some(rid) = origin_id.clone().or_else(|| stanza_id.clone()) {
            let received = Element::builder("received", NS_RECEIPTS).attr(crate::ncname("id"), &rid).build();
            let target = if kind == "muc_pm" { conv_key } else { bare.as_str() };
            let _ = send_meta(w, store, cfg, target, vec![received], false).await;
        }
    }

    persist_and_emit(
        store, cfg, events, conv,
        NewMessage {
            conversation_id: conv,
            stanza_id,
            origin_id,
            counterpart: counterpart_full,
            direction,
            body: Some(body),
            encryption: encryption.into(),
            reply_to,
            omemo_fingerprint: fingerprint,
            attachment,
            occupant_id,
            timestamp: ts,
            thread: content.get_child("thread", NS_CLIENT).map(|t| t.text()).filter(|s| !s.is_empty()),
        },
        /*bump_unread=*/ direction == Direction::In && live,
        live,
        mentioned,
        reply_to_me,
    ).await
}

// ============================ helpers ======================================

/// XEP-0461 + XEP-0428: a reply carries a fallback `> quoted…` prefix in its body, marked by
/// `<fallback for='urn:xmpp:reply:0'><body start=.. end=../></fallback>`. We render the quote
/// from the referenced message, so strip that fallback range from the displayed body (matching
/// monocles Android). `start`/`end` are codepoint offsets; a missing `<body>` range means the
/// whole body is fallback.
fn strip_reply_fallback(content: &Element, body: &str) -> String {
    strip_fallback_for(content, body, NS_REPLY)
}

/// Strip the body span marked by `<fallback for='for_ns'><body start=.. end=..></fallback>`
/// (XEP-0428). `start`/`end` are codepoint offsets; a missing `<body>` range means the whole
/// body is fallback. Shared by the reply-quote prefix and the OOB file-URL span (caption).
fn strip_fallback_for(content: &Element, body: &str, for_ns: &str) -> String {
    for fb in content.children().filter(|c| c.name() == "fallback" && c.ns() == NS_FALLBACK) {
        if fb.attr("for") != Some(for_ns) {
            continue;
        }
        let Some(range) = fb.children().find(|c| c.name() == "body") else {
            return String::new(); // no range → entire body is the fallback
        };
        let chars: Vec<char> = body.chars().collect();
        let start = range.attr("start").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        let end = range.attr("end").and_then(|s| s.parse::<usize>().ok()).unwrap_or(chars.len());
        if start <= end && end <= chars.len() {
            let mut out: String = chars[..start].iter().collect();
            out.extend(&chars[end..]);
            return out;
        }
    }
    body.to_string()
}

/// Extract a file-share URL from an `<x xmlns='jabber:x:oob'><url>…</url></x>` element inside
/// the (already-decrypted) content. Android places this inside the SCE envelope for captioned
/// OMEMO2 files, and on the outer stanza for plaintext ones.
fn oob_file_url(content: &Element) -> Option<String> {
    let url = content
        .get_child("x", NS_OOB)?
        .get_child("url", NS_OOB)?
        .text();
    let url = url.trim();
    if url.is_empty() { None } else { Some(url.to_string()) }
}

/// Build the JSON stored in the `attachment` column for a file URL (mime guessed from the name).
fn attachment_json(url: &str) -> String {
    let name = url.rsplit('/').next().unwrap_or("");
    let name = name.split(['?', '#']).next().unwrap_or(name);
    let mime = crate::xeps::http_upload::guess_mime(name);
    serde_json::json!({ "url": url, "mime": mime }).to_string()
}

/// Every file described by XEP-0447 `<file-sharing/>` elements in `content`, in order.
///
/// Read from `content` only — for an OMEMO2 message that is the decrypted SCE envelope, so a
/// `<file-sharing/>` smuggled onto the outer stanza by the server or an attacker is never seen
/// here. That is deliberate and matches the sending client: the sources carry the `aesgcm://`
/// URL whose fragment is the file key, so this element only ever exists encrypted (or in a
/// plaintext chat, where the whole stanza is in the clear anyway).
///
/// Each entry is `{url, mime, name, size?, width?, height?, duration?}`; files without a usable
/// source are skipped.
fn sfs_files(content: &Element) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for sharing in content.children().filter(|c| c.name() == "file-sharing" && c.ns() == NS_SFS) {
        let url = sharing
            .get_child("sources", NS_SFS)
            .and_then(|s| s.get_child("url-data", NS_URL_DATA))
            .and_then(|u| u.attr("target"))
            .map(str::trim)
            .filter(|u| !u.is_empty());
        let Some(url) = url else { continue };
        let meta = sharing.get_child("file", NS_FILE_META);
        let text = |name: &str| {
            meta.and_then(|m| m.get_child(name, NS_FILE_META))
                .map(|e| e.text())
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
        };
        let number = |name: &str| text(name).and_then(|t| t.parse::<i64>().ok());
        // Fall back to the URL's last path segment / a guess from it, the way a caption-less
        // single file already arrives — Android always sends both, other clients may not.
        let url_name = {
            let n = url.rsplit('/').next().unwrap_or("");
            n.split(['?', '#']).next().unwrap_or(n).to_string()
        };
        let name = text("name").unwrap_or_else(|| url_name.clone());
        let mime = text("media-type")
            .unwrap_or_else(|| crate::xeps::http_upload::guess_mime(&name).to_string());
        let mut entry = serde_json::json!({ "url": url, "mime": mime, "name": name });
        let obj = entry.as_object_mut().expect("json object");
        for (key, value) in [
            ("size", number("size")),
            ("width", number("width")),
            ("height", number("height")),
            // XEP-0446 <length/> is milliseconds.
            ("duration", number("length")),
        ] {
            if let Some(v) = value.filter(|v| *v > 0) {
                obj.insert(key.to_string(), serde_json::json!(v));
            }
        }
        out.push(entry);
    }
    out
}

/// The `attachment` column value for a message carrying `files`. The first file's `url`/`mime`
/// stay at the top level so everything that already reads a single attachment keeps working;
/// `files` carries all of them for the multi-file renderer.
fn attachment_json_files(files: &[serde_json::Value]) -> Option<String> {
    let first = files.first()?;
    Some(
        serde_json::json!({
            "url": first.get("url").cloned().unwrap_or_default(),
            "mime": first.get("mime").cloned().unwrap_or_default(),
            "files": files,
        })
        .to_string(),
    )
}

/// Remove the shared files' own URLs from `body`, leaving the caption. A safety net for senders
/// that describe their files but mark no fallback span: the URLs would otherwise show as text
/// beside the very files they point at. A caption that *is* one of the upload URLs carries no
/// information, so nothing is lost.
fn strip_file_urls(body: &str, files: &[serde_json::Value]) -> String {
    let mut out = body.to_string();
    for url in files.iter().filter_map(|f| f.get("url").and_then(|u| u.as_str())) {
        if out.contains(url) {
            out = out.replace(url, "");
        }
    }
    if out == body {
        return out;
    }
    out.trim().to_string()
}

/// Remove every `<fallback>` body span of the given namespaces from `body`.
///
/// [`strip_fallback_for`] handles one span, which is all a single file needs. A multi-file
/// message appends one URL per file and marks each of them — twice over, once for
/// `jabber:x:oob` and once for `urn:xmpp:sfs:0` — so the spans have to be collected, merged
/// (the two namespaces mark the *same* ranges) and cut from the end, or every removal would
/// invalidate the offsets of the ones after it.
fn strip_fallback_spans(content: &Element, body: &str, for_ns: &[&str]) -> String {
    let chars: Vec<char> = body.chars().collect();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for fb in content.children().filter(|c| c.name() == "fallback" && c.ns() == NS_FALLBACK) {
        if !fb.attr("for").is_some_and(|f| for_ns.contains(&f)) {
            continue;
        }
        let Some(range) = fb.children().find(|c| c.name() == "body") else {
            return String::new(); // no range → the entire body is the fallback
        };
        let start = range.attr("start").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        let end = range.attr("end").and_then(|s| s.parse::<usize>().ok()).unwrap_or(chars.len());
        if start <= end && end <= chars.len() {
            spans.push((start, end));
        }
    }
    if spans.is_empty() {
        return body.to_string();
    }
    spans.sort_unstable();
    // Merge overlapping/duplicate spans so a range marked by both namespaces is cut once.
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut out = chars;
    for (start, end) in merged.into_iter().rev() {
        out.drain(start..end);
    }
    out.into_iter().collect::<String>().trim().to_string()
}

/// A file share to put on the wire: the URL plus, when a caption precedes it in the body, the
/// codepoint span of the URL so the receiver can strip it (XEP-0066 OOB + XEP-0428 fallback).
struct FileWire<'a> {
    url: &'a str,
    fallback_span: Option<(usize, usize)>,
}

/// Build the `<x xmlns='jabber:x:oob'><url></x>` (and, for a caption, the `<fallback for='oob'>`)
/// elements. Used both directly (plaintext outer stanza) and serialized into the SCE envelope
/// (OMEMO2), so both clients agree on one wire shape (matches monocles Android).
fn build_file_oob(f: &FileWire) -> Vec<Element> {
    let mut v = vec![Element::builder("x", NS_OOB)
        .append(Element::builder("url", NS_OOB).append(f.url).build())
        .build()];
    if let Some((start, end)) = f.fallback_span {
        v.push(
            Element::builder("fallback", NS_FALLBACK)
                .attr(crate::ncname("for"), NS_OOB)
                .append(
                    Element::builder("body", NS_FALLBACK)
                        .attr(crate::ncname("start"), start.to_string())
                        .attr(crate::ncname("end"), end.to_string())
                        .build(),
                )
                .build(),
        );
    }
    v
}

fn enc_str(e: Encryption) -> &'static str {
    match e {
        Encryption::None => "none",
        Encryption::Omemo2 => "omemo2",
    }
}

/// Whether `body` mentions `nick` at a word boundary — mirroring monocles Android's highlight
/// pattern `(?<=^|\s)nick(?=\s|$|\p{Punct})`: the nick must start at the beginning or after
/// whitespace, and be followed by whitespace, end-of-text, or punctuation. Case-sensitive,
/// like the Android client.
fn mentions_nick(body: &str, nick: &str) -> bool {
    if nick.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(off) = body[from..].find(nick) {
        let idx = from + off;
        let before_ok = idx == 0
            || body[..idx].chars().next_back().map(|c| c.is_whitespace()).unwrap_or(true);
        let after = &body[idx + nick.len()..];
        let after_ok = after
            .chars()
            .next()
            .map(|c| c.is_whitespace() || c.is_ascii_punctuation())
            .unwrap_or(true);
        if before_ok && after_ok {
            return true;
        }
        from = idx + 1;
    }
    false
}

/// Direction of a message relative to us: from our own bare JID ⇒ outgoing.
fn direction_of(msg: &Element, our_bare: &str) -> Direction {
    let from = msg.attr("from").unwrap_or_default();
    let from_bare = from.split('/').next().unwrap_or(from);
    if from_bare.eq_ignore_ascii_case(our_bare) {
        Direction::Out
    } else {
        Direction::In
    }
}

/// XEP-0203 delay stamp on an element (or its `<forwarded>` wrapper).
fn delay_stamp(el: &Element) -> Option<String> {
    el.get_child("delay", NS_DELAY)
        .and_then(|d| d.attr("stamp").map(str::to_string))
}

/// Reference time the SCE `<time>` affix is checked against (proto-XEP §4.6.2).
///
/// Deliberately NOT the timestamp we store for display: that one honours the sender's own
/// `<delay/>`, which is right for ordering and wrong here. A peer replaying an old ciphertext
/// can attach a `<delay/>` matching the stamp sealed inside the envelope and thereby move the
/// reference onto the replay itself, neutralising the check. Only an intermediary's delay may
/// move it:
///
/// * MAM and carbons (`live == false`) already carry a server-attested stamp (the delay inside
///   `<forwarded>`) or fall back to now — take `stored_ts` as-is.
/// * Groupchat history replay is the acknowledged exception: the room's delay carries the room's
///   JID, which an occupant can forge, but rejecting it would destroy legitimate backlog.
/// * Any other live stanza: accept a `<delay/>` only when it names someone other than the sender
///   (offline storage stamps the server's JID), otherwise use the receive time.
fn sce_time_reference(msg: &Element, live: bool, stored_ts: &str) -> String {
    if !live || msg.attr("type") == Some("groupchat") {
        return stored_ts.to_string();
    }
    let sender_bare = msg
        .attr("from")
        .map(|f| f.split('/').next().unwrap_or(f).to_ascii_lowercase());
    for d in msg.children().filter(|c| c.is("delay", NS_DELAY)) {
        let Some(stamp) = d.attr("stamp") else { continue };
        // Sender-asserted (or unattributed) delays carry no weight here.
        let Some(f) = d.attr("from") else { continue };
        let f_bare = f.split('/').next().unwrap_or(f).to_ascii_lowercase();
        if Some(&f_bare) == sender_bare.as_ref() {
            continue;
        }
        return stamp.to_string();
    }
    crate::xeps::rfc3339_now()
}

async fn fetch_row(store: &Store, conv: i64, message_id: i64) -> Option<mxc_store::MessageRow> {
    store
        .recent_messages(conv, 200)
        .await
        .ok()
        .and_then(|rows| rows.into_iter().find(|r| r.id == message_id))
}

/// Insert a message (dedup-aware), bump unread if asked, and emit the UI events.
async fn persist_and_emit(
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    conv: i64,
    msg: NewMessage,
    bump_unread: bool,
    live: bool,
    mentioned: bool,
    reply_to_me: bool,
) -> anyhow::Result<()> {
    if let Some(id) = store.insert_message(&msg).await? {
        // File caption metadata isn't part of the INSERT (compile-time-checked) statement;
        // attach it now so the row fetched + emitted below already carries it.
        if let Some(att) = &msg.attachment {
            store.set_attachment(id, att).await.ok();
        }
        if bump_unread {
            store.bump_unread(conv).await.ok();
        }
        if let Some(row) = fetch_row(store, conv, id).await {
            let _ = events.send(Event::MessageStored {
                account_id: cfg.account_id, conversation_id: conv, message: row, live,
                mentioned, reply_to_me,
            }).await;
        }
        if let Ok(items) = store.conversations(cfg.account_id).await {
            let _ = events.send(Event::ConversationsUpdated { account_id: cfg.account_id, items }).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod sticker_tests {
    use super::is_shortcode_only;

    #[test]
    fn shortcode_only_detection() {
        assert!(is_shortcode_only(""));
        assert!(is_shortcode_only(":racoon_silly2:"));
        assert!(is_shortcode_only("  :a:  :b-c:  "));
        assert!(!is_shortcode_only("hello"));
        assert!(!is_shortcode_only(":a: and text"));
        assert!(!is_shortcode_only("cid:sha-256+ab@bob.xmpp.org"));
    }
}

#[cfg(test)]
mod sce_binding_tests {
    use super::check_sce_binding;
    use mxc_omemo::sce::Envelope;

    fn env(time: Option<String>) -> Envelope {
        Envelope::new("hi", "alice@x", "bob@y", time, "")
    }

    #[test]
    fn valid_time_passes() {
        let now = crate::xeps::rfc3339_now();
        assert!(check_sce_binding(&env(Some(now.clone())), "alice@x", Some("bob@y"), Some(&now)).is_ok());
    }

    #[test]
    fn missing_time_rejected() {
        let now = crate::xeps::rfc3339_now();
        let e = check_sce_binding(&env(None), "alice@x", Some("bob@y"), Some(&now));
        assert!(e.unwrap_err().contains("missing required <time>"));
    }

    #[test]
    fn unparseable_time_rejected() {
        let now = crate::xeps::rfc3339_now();
        let e = check_sce_binding(&env(Some("not-a-timestamp".into())), "alice@x", Some("bob@y"), Some(&now));
        assert!(e.unwrap_err().contains("unparseable"));
    }

    #[test]
    fn future_time_rejected() {
        let future = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
        let now = crate::xeps::rfc3339_now();
        assert!(check_sce_binding(&env(Some(future)), "alice@x", Some("bob@y"), Some(&now)).is_err());
    }

    #[test]
    fn stale_ciphertext_replayed_as_live_rejected() {
        // SCE stamp is 30 days old but the stanza claims to be sent now → replay.
        let old = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        let now = crate::xeps::rfc3339_now();
        assert!(check_sce_binding(&env(Some(old)), "alice@x", Some("bob@y"), Some(&now)).is_err());
    }

    #[test]
    fn old_mam_message_passes() {
        // Both the SCE stamp and the stanza (delay) stamp are equally old → legitimate MAM.
        let old = (chrono::Utc::now() - chrono::Duration::days(365)).to_rfc3339();
        assert!(check_sce_binding(&env(Some(old.clone())), "alice@x", Some("bob@y"), Some(&old)).is_ok());
    }
}

#[cfg(test)]
mod sce_time_reference_tests {
    use super::sce_time_reference;
    use minidom::Element;

    fn msg(msg_type: &str, delay: &str) -> Element {
        format!(
            "<message xmlns='jabber:client' type='{msg_type}' from='alice@x/phone' to='bob@y'>{delay}</message>"
        )
        .parse()
        .expect("parse")
    }

    fn old() -> String {
        (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339()
    }

    #[test]
    fn sender_asserted_delay_is_ignored_on_live_stanza() {
        // The replay vector: the peer backdates their own stanza to match the stamp sealed
        // inside the replayed envelope. The reference must stay at the receive time.
        let old = old();
        let d = format!("<delay xmlns='urn:xmpp:delay' from='alice@x' stamp='{old}'/>");
        let r = sce_time_reference(&msg("chat", &d), true, &old);
        assert_ne!(r, old, "sender's own delay must not move the reference");
    }

    #[test]
    fn unattributed_delay_is_ignored_on_live_stanza() {
        let old = old();
        let d = format!("<delay xmlns='urn:xmpp:delay' stamp='{old}'/>");
        assert_ne!(sce_time_reference(&msg("chat", &d), true, &old), old);
    }

    #[test]
    fn server_delay_is_honoured_on_live_stanza() {
        // Offline storage: the delay names the server, not the sender → legitimately old.
        let old = old();
        let d = format!("<delay xmlns='urn:xmpp:delay' from='x' stamp='{old}'/>");
        assert_eq!(sce_time_reference(&msg("chat", &d), true, &old), old);
    }

    #[test]
    fn groupchat_history_keeps_the_stanza_timestamp() {
        let old = old();
        let d = format!("<delay xmlns='urn:xmpp:delay' from='room@conf' stamp='{old}'/>");
        assert_eq!(sce_time_reference(&msg("groupchat", &d), true, &old), old);
    }

    #[test]
    fn mam_and_carbons_keep_the_stanza_timestamp() {
        let old = old();
        assert_eq!(sce_time_reference(&msg("chat", ""), false, &old), old);
    }
}

#[cfg(test)]
mod file_caption_tests {
    use super::*;
    use minidom::Element;

    /// Re-parse SCE `content_inner` into a queryable element exactly like handle_incoming does.
    fn content_of(inner: &str) -> Element {
        format!("<content xmlns='{NS_CLIENT}'>{inner}</content>")
            .parse::<Element>()
            .expect("content parse")
    }

    #[test]
    fn captioned_file_wire_round_trips() {
        let url = "aesgcm://upload.example.com/abc/photo.jpg#deadbeef";
        let caption = "look at this 📷";
        // Sender side: body = "caption url" with the URL span marked.
        let wire_body = format!("{caption} {url}");
        let start = caption.chars().count() + 1;
        let end = start + url.chars().count();
        let file = FileWire { url, fallback_span: Some((start, end)) };
        let mut extra = String::new();
        for el in &build_file_oob(&file) {
            extra.push_str(&String::from(el));
        }
        // Wrap in the real SCE envelope and round-trip it (encryption is orthogonal).
        let env = Envelope::new(&wire_body, "a@x", "b@y", None, &extra);
        let parsed = Envelope::from_xml(&env.to_xml()).expect("env parse");
        assert_eq!(parsed.body().as_deref(), Some(wire_body.as_str()));

        // Receiver side: recover the URL and strip the fallback span to get the caption back.
        let content = content_of(&parsed.content_inner);
        assert_eq!(oob_file_url(&content).as_deref(), Some(url));
        let body = strip_fallback_for(&content, &wire_body, NS_OOB);
        assert_eq!(body, format!("{caption} "));
        // Attachment JSON carries the URL for the renderer.
        assert!(attachment_json(url).contains(url));
    }

    #[test]
    fn caption_less_file_has_no_oob() {
        // No caption → body is just the URL, no OOB element (byte-identical to legacy).
        let oob = build_file_oob(&FileWire { url: "https://x/y.png", fallback_span: None });
        assert_eq!(oob.len(), 1); // <x><url> only, no <fallback>
        let content = content_of("");
        assert_eq!(oob_file_url(&content), None);
    }

    /// One `<file-sharing/>` exactly as monocles Android serializes it.
    fn sfs_el(url: &str, name: &str, mime: &str, extra: &str) -> String {
        format!(
            "<file-sharing xmlns='{NS_SFS}' disposition='inline'>\
               <file xmlns='{NS_FILE_META}'>\
                 <name>{name}</name><media-type>{mime}</media-type>{extra}\
               </file>\
               <sources xmlns='{NS_SFS}'>\
                 <url-data xmlns='{NS_URL_DATA}' target='{url}'/>\
               </sources>\
             </file-sharing>"
        )
    }

    #[test]
    fn multi_file_message_yields_every_file_and_a_clean_caption() {
        let caption = "holiday pics";
        let urls = [
            "aesgcm://up.example.com/a/one.jpg#aa",
            "aesgcm://up.example.com/b/two.jpg#bb",
            "aesgcm://up.example.com/c/notes.pdf#cc",
        ];
        // Android's wire shape: caption, then one URL per file, each span marked as a fallback
        // for BOTH jabber:x:oob and urn:xmpp:sfs:0.
        let mut body = caption.to_string();
        let mut extra = String::new();
        for (i, url) in urls.iter().enumerate() {
            let sep = if i == 0 { " " } else { "\n" };
            let start = body.chars().count();
            body.push_str(sep);
            body.push_str(url);
            let end = body.chars().count();
            for ns in [NS_OOB, NS_SFS] {
                extra.push_str(&format!(
                    "<fallback xmlns='{NS_FALLBACK}' for='{ns}'>\
                       <body start='{start}' end='{end}'/></fallback>"
                ));
            }
        }
        extra.push_str(&sfs_el(urls[0], "one.jpg", "image/jpeg", "<size>1234</size><width>800</width><height>600</height>"));
        extra.push_str(&sfs_el(urls[1], "two.jpg", "image/jpeg", ""));
        extra.push_str(&sfs_el(urls[2], "notes.pdf", "application/pdf", "<size>99</size>"));
        // The first file is also described by <x oob>, as Android does.
        extra.push_str(&String::from(
            &build_file_oob(&FileWire { url: urls[0], fallback_span: None })[0],
        ));

        let content = content_of(&extra);
        let files = sfs_files(&content);
        assert_eq!(files.len(), 3, "one entry per <file-sharing/>");
        assert_eq!(files[0]["url"], urls[0]);
        assert_eq!(files[0]["name"], "one.jpg");
        assert_eq!(files[0]["mime"], "image/jpeg");
        assert_eq!(files[0]["size"], 1234);
        assert_eq!(files[0]["width"], 800);
        assert_eq!(files[2]["mime"], "application/pdf");
        assert!(files[1].get("size").is_none(), "absent metadata stays absent");

        // Every URL span is removed exactly once, leaving just the caption.
        assert_eq!(strip_fallback_spans(&content, &body, &[NS_OOB, NS_SFS]), caption);

        // The stored attachment keeps the single-file shape *and* the full list.
        let json = attachment_json_files(&files).expect("attachment json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["url"], urls[0], "first file stays readable by single-file callers");
        assert_eq!(value["files"].as_array().expect("files array").len(), 3);
    }

    #[test]
    fn file_sharing_without_a_source_is_skipped() {
        let content = content_of(&format!(
            "<file-sharing xmlns='{NS_SFS}'><file xmlns='{NS_FILE_META}'><name>x.png</name></file></file-sharing>"
        ));
        assert!(sfs_files(&content).is_empty());
        assert!(attachment_json_files(&[]).is_none());
    }

    #[test]
    fn missing_metadata_falls_back_to_the_url() {
        let url = "https://up.example.com/x/report.pdf";
        let content = content_of(&format!(
            "<file-sharing xmlns='{NS_SFS}'><sources xmlns='{NS_SFS}'>\
               <url-data xmlns='{NS_URL_DATA}' target='{url}'/></sources></file-sharing>"
        ));
        let files = sfs_files(&content);
        assert_eq!(files[0]["name"], "report.pdf");
        assert_eq!(files[0]["mime"], "application/pdf");
    }

    #[test]
    fn unmarked_urls_are_removed_from_the_caption() {
        // A sender that describes its files but marks no fallback span: the URLs must not show
        // as text next to the files they point at, and the caption must survive.
        let urls = ["https://up.example.com/a/one.jpg", "https://up.example.com/b/two.jpg"];
        let extra = format!(
            "{}{}",
            sfs_el(urls[0], "one.jpg", "image/jpeg", ""),
            sfs_el(urls[1], "two.jpg", "image/jpeg", "")
        );
        let content = content_of(&extra);
        let files = sfs_files(&content);
        let body = format!("two shots {} {}", urls[0], urls[1]);
        let body = strip_fallback_spans(&content, &body, &[NS_OOB, NS_SFS]);
        assert_eq!(strip_file_urls(&body, &files), "two shots");
    }

    #[test]
    fn multi_file_send_round_trips_through_the_receiver() {
        // Everything the sender builds, fed back through the receiving path: the caption must
        // come back clean and all three files must be described.
        let caption = "three things 🎁";
        let files = [
            serde_json::json!({"url":"aesgcm://u/1#a","mime":"image/png","name":"a.png","size":10}),
            serde_json::json!({"url":"aesgcm://u/2#b","mime":"image/png","name":"b.png","size":20}),
            serde_json::json!({"url":"aesgcm://u/3#c","mime":"application/pdf","name":"c.pdf","size":30}),
        ];
        let urls: Vec<&str> = files.iter().map(|f| f["url"].as_str().unwrap()).collect();
        let (wire_body, spans) = build_multi_file_body(Some(caption), &urls);
        assert_eq!(wire_body, format!("{caption}\n{}\n{}\n{}", urls[0], urls[1], urls[2]));

        let payloads = build_multi_file_payloads(&files, &spans, "msg-1");
        let mut inner = String::new();
        for el in &payloads {
            inner.push_str(&String::from(el));
        }
        // Through the real SCE envelope, as an OMEMO2 chat would carry it.
        let env = Envelope::new(&wire_body, "a@x", "b@y", None, &inner);
        let parsed = Envelope::from_xml(&env.to_xml()).expect("env parse");
        let content = content_of(&parsed.content_inner);

        let received = sfs_files(&content);
        assert_eq!(received.len(), 3);
        for (sent, got) in files.iter().zip(&received) {
            assert_eq!(got["url"], sent["url"]);
            assert_eq!(got["name"], sent["name"]);
            assert_eq!(got["mime"], sent["mime"]);
            assert_eq!(got["size"], sent["size"]);
        }
        let body = strip_fallback_spans(&content, &wire_body, &[NS_OOB, NS_SFS]);
        assert_eq!(strip_file_urls(&body, &received), caption);
        // No <x oob>: it would cost the first file its metadata on the Android side, where the
        // OOB element overwrites what <file-sharing/> described (see build_multi_file_payloads).
        assert_eq!(oob_file_url(&content), None);
    }

    #[test]
    fn multi_file_body_without_a_caption_starts_at_the_first_url() {
        let (body, spans) = build_multi_file_body(None, &["u1", "u2"]);
        assert_eq!(body, "u1\nu2");
        assert_eq!(spans, vec![(0, 2), (3, 5)]);
    }

    #[test]
    fn a_whole_body_fallback_still_clears_the_body() {
        let content = content_of(&format!(
            "<fallback xmlns='{NS_FALLBACK}' for='{NS_SFS}'/>"
        ));
        assert_eq!(strip_fallback_spans(&content, "anything", &[NS_SFS]), "");
    }
}

#[cfg(test)]
mod sender_filter_tests {
    use super::sender_filter;

    #[test]
    fn muc_edits_need_occupant_id() {
        assert_eq!(sender_filter("muc", false, Some("occ")), Some(("in", Some("occ"))));
        assert_eq!(sender_filter("muc", false, None), None);
        assert_eq!(sender_filter("muc", true, None), Some(("out", None)));
        assert_eq!(sender_filter("chat", false, None), Some(("in", None)));
        assert_eq!(sender_filter("chat", true, None), Some(("out", None)));
        assert_eq!(sender_filter("muc_pm", false, None), Some(("in", None)));
    }
}
