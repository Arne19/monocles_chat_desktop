//! XEP-0313 Message Archive Management — paged history backfill.
//!
//! Issues a MAM query with an RSM `<before>` cursor for a conversation. The matched
//! archive messages arrive as separate `<message><result><forwarded>…` stanzas which the
//! reader loop routes through [`super::messaging::handle_incoming`] (it unwraps the MAM
//! envelope + `<delay>`). The query's iq *result* carries the `<fin>` + RSM bounds, which
//! we use to advance the stored cursor.
//!
//! Every query registers its `queryid` with the archive it targets; [`screen_result`] drops
//! any `<result>` that doesn't answer one of our queries from that archive (anti-spoofing).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use async_channel::Sender;
use minidom::Element;

use mxc_store::Store;

use crate::client::{AccountConfig, Writer};
use crate::event::Event;
use crate::xeps::iq;
use crate::xeps::roster::new_id;

const NS_MAM: &str = "urn:xmpp:mam:2";
const NS_RSM: &str = "http://jabber.org/protocol/rsm";
const NS_DATA: &str = "jabber:x:data";

const NS_FORWARD: &str = "urn:xmpp:forward:0";
const NS_CLIENT: &str = "jabber:client";

const PAGE: u32 = 50;

/// The archive a pending query was sent to.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Archive {
    /// Our own account archive (no `to` on the query).
    Account,
    /// A MUC room archive (bare room JID).
    Room(String),
}

/// Pending queries: `queryid` → (account, archive). Process-global like [`iq`]'s registry,
/// so the account id is part of the entry.
static QUERIES: OnceLock<Mutex<HashMap<String, (i64, Archive)>>> = OnceLock::new();

fn queries() -> &'static Mutex<HashMap<String, (i64, Archive)>> {
    QUERIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Unregisters its `queryid` when dropped (reply, error, timeout or cancellation alike).
struct QueryGuard(String);

impl Drop for QueryGuard {
    fn drop(&mut self) {
        if let Ok(mut q) = queries().lock() {
            q.remove(&self.0);
        }
    }
}

/// Register a new query against `archive` and return its unguessable `queryid`. Keep the
/// guard alive until the query's iq reply has arrived: the server sends every `<result>`
/// before that reply, and [`screen_result`] runs on the reader loop in stream order.
fn begin_query(account_id: i64, archive: Archive) -> (String, QueryGuard) {
    let id = new_id("mam");
    queries().lock().unwrap().insert(id.clone(), (account_id, archive));
    (id.clone(), QueryGuard(id))
}

fn bare(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}

/// Gatekeeper for inbound MAM results, called synchronously on the reader loop **before**
/// the stanza is handed to a spawned handler (a spawned task could otherwise run after the
/// query's guard was already dropped). Returns `false` if the stanza must be dropped.
///
/// A `<result xmlns='urn:xmpp:mam:2'>` is accepted only if
/// * its `queryid` belongs to a query this account is still waiting on,
/// * the outer `from` is the archive we queried (absent or our own bare JID for the account
///   archive, exactly the room's bare JID for a MUC archive), and
/// * for a MUC archive, the forwarded message's `from` is in that room — otherwise the room
///   could inject messages "from" arbitrary JIDs (e.g. a contact, or ourselves).
///
/// Stanzas without a MAM `<result>` pass through unchanged.
pub fn screen_result(stanza: &Element, account_id: i64, our_bare: &str) -> bool {
    if stanza.name() != "message" {
        return true;
    }
    let Some(result) = stanza.get_child("result", NS_MAM) else {
        return true;
    };
    let archive = result.attr("queryid").and_then(|id| {
        queries()
            .lock()
            .unwrap()
            .get(id)
            .filter(|(acc, _)| *acc == account_id)
            .map(|(_, a)| a.clone())
    });
    let Some(archive) = archive else {
        tracing::debug!(from = ?stanza.attr("from"), "dropping MAM result for unknown queryid");
        return false;
    };
    let outer_from = stanza.attr("from");
    let valid_outer = match &archive {
        Archive::Account => outer_from.is_none_or(|f| bare(f).eq_ignore_ascii_case(our_bare)),
        Archive::Room(room) => outer_from.is_some_and(|f| f.eq_ignore_ascii_case(room)),
    };
    if !valid_outer {
        tracing::debug!(from = ?outer_from, "dropping MAM result with invalid from");
        return false;
    }
    // Same lookup as `messaging::handle_incoming`, so we vet the message it will process.
    let inner = result.get_child("forwarded", NS_FORWARD).and_then(|f| f.get_child("message", NS_CLIENT));
    match &archive {
        Archive::Room(room) => {
            let inner_from = inner.and_then(|m| m.attr("from"));
            if !inner_from.is_some_and(|f| bare(f).eq_ignore_ascii_case(room)) {
                tracing::debug!(from = ?inner_from, "dropping implausible from in MUC MAM archive");
                return false;
            }
        }
        // Group chat messages belong to the room's archive; one surfacing from our personal
        // archive is never trusted (Conversations: "received group chat message on regular
        // MAM request. skipping").
        Archive::Account => {
            if inner.and_then(|m| m.attr("type")) == Some("groupchat") {
                tracing::debug!(from = ?inner.and_then(|m| m.attr("from")), "dropping groupchat message from account archive");
                return false;
            }
        }
    }
    true
}

fn archive_for(jid: &str, is_muc: bool) -> Archive {
    if is_muc {
        Archive::Room(bare(jid).to_string())
    } else {
        Archive::Account
    }
}

pub async fn load_page(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    conversation_id: i64,
    before: Option<String>,
) -> anyhow::Result<()> {
    let Some((jid, kind)) = store.conversation_target(conversation_id).await? else {
        return Ok(());
    };
    // MUC private messages aren't reliably archived per-occupant; re-querying the account MAM
    // with the full occupant JID just re-delivers (and can duplicate) live PMs. Skip MAM.
    if kind == "muc_pm" {
        return Ok(());
    }
    let is_muc = kind == "muc";

    // Cursor: explicit `before`, else the oldest id we already have (page backwards).
    let cursor = match before {
        Some(b) => Some(b),
        None => store.mam_cursor(cfg.account_id, &jid).await?.and_then(|c| c.first_id),
    };

    // Filter form: bind to this conversation (1:1 uses `with`; MUC queries the room MAM).
    let mut form = Element::builder("x", NS_DATA).attr(crate::ncname("type"), "submit").append(
        field("FORM_TYPE", NS_MAM, true),
    );
    if !is_muc {
        form = form.append(field("with", &jid, false));
    }

    // RSM: page backwards from the cursor, newest-of-page last.
    let mut set = Element::builder("set", NS_RSM)
        .append(Element::builder("max", NS_RSM).append(PAGE.to_string()).build());
    if let Some(c) = &cursor {
        set = set.append(Element::builder("before", NS_RSM).append(c.as_str()).build());
    } else {
        // empty <before/> = last page (most recent)
        set = set.append(Element::builder("before", NS_RSM).build());
    }

    let (query_id, _guard) = begin_query(cfg.account_id, archive_for(&jid, is_muc));
    let query = Element::builder("query", NS_MAM)
        .attr(crate::ncname("queryid"), query_id)
        .append(form.build())
        .append(set.build())
        .build();

    let mut req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("mam-iq"));
    if is_muc {
        req = req.attr(crate::ncname("to"), &jid); // query the MUC's archive
    }
    let req = req.append(query).build();

    let reply = iq::request(w, req).await?;

    // Parse <fin complete=..><set><first/><last/></set></fin>.
    if let Some(fin) = reply.get_child("fin", NS_MAM) {
        let complete = fin.attr("complete") == Some("true");
        let (first, last) = fin
            .get_child("set", NS_RSM)
            .map(|s| {
                (
                    s.get_child("first", NS_RSM).map(|e| e.text()),
                    s.get_child("last", NS_RSM).map(|e| e.text()),
                )
            })
            .unwrap_or((None, None));
        store
            .set_mam_cursor(cfg.account_id, &jid, first.as_deref(), last.as_deref(), complete)
            .await?;
    }

    // Tell the UI the conversation likely gained backfilled messages.
    if let Ok(items) = store.conversations(cfg.account_id).await {
        let _ = events.send(Event::ConversationsUpdated { account_id: cfg.account_id, items }).await;
    }
    Ok(())
}

/// Catch up on messages received since we last synced this conversation's archive: page
/// *forward* from the stored `last_id` until the server reports `complete`. The archived
/// messages arrive as separate stanzas (deduped on insert), so we only drive the paging here.
/// With no sync point yet, fall back to fetching the most recent page.
pub async fn catch_up(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    conversation_id: i64,
) -> anyhow::Result<()> {
    let Some((jid, kind)) = store.conversation_target(conversation_id).await? else {
        return Ok(());
    };
    // See `load_page`: don't drive MAM for MUC private messages.
    if kind == "muc_pm" {
        return Ok(());
    }
    let is_muc = kind == "muc";

    let Some(mut after) = store.mam_cursor(cfg.account_id, &jid).await?.and_then(|c| c.last_id)
    else {
        // Never synced → grab the most recent page (which records the cursor).
        return load_page(w, store, cfg, events, conversation_id, None).await;
    };

    // Page forward; bounded so a huge backlog can't loop forever in one go.
    for _ in 0..100 {
        let (complete, last) = query_after(w, cfg.account_id, &jid, is_muc, &after).await?;
        match last {
            Some(last_id) => {
                // Advance only the newest cursor (COALESCE keeps `first_id`).
                store
                    .set_mam_cursor(cfg.account_id, &jid, None, Some(&last_id), complete)
                    .await?;
                after = last_id;
            }
            None => break,
        }
        if complete {
            break;
        }
    }

    if let Ok(items) = store.conversations(cfg.account_id).await {
        let _ = events.send(Event::ConversationsUpdated { account_id: cfg.account_id, items }).await;
    }
    Ok(())
}

/// Cursor key for the *account* archive (1:1 + carbons), distinct from any per-conversation
/// cursor (which is keyed by contact JID). The leading control char is invalid in a JID, so it
/// can never collide with a real `with` archive — including the "Note to self" chat with our own
/// bare JID.
const ACCOUNT_ARCHIVE: &str = "\u{1}account";

/// Catch up the **account archive** (all 1:1 conversations + carbons) after a reconnect: page
/// forward from the last account-level archive id we synced. This is what fills the gap created
/// while the client was closed — including messages from contacts we had no local conversation
/// with yet (a forwarded archive message creates the conversation via `handle_incoming`). MUC
/// rooms have their own per-room archive and are caught up separately in `bootstrap`.
///
/// On the very first run (no cursor) we don't backfill the whole history — we just fetch the most
/// recent page (deduped on insert) and record its newest id as the baseline, so subsequent
/// restarts page forward from there.
pub async fn catch_up_account(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
) -> anyhow::Result<()> {
    match store.mam_cursor(cfg.account_id, ACCOUNT_ARCHIVE).await?.and_then(|c| c.last_id) {
        // No baseline yet → fetch the most recent page and record where the archive currently
        // ends; we rely on live delivery for anything newer this session.
        None => {
            let page = query_account(w, cfg.account_id, None).await?;
            if let Some(last_id) = page.last {
                store
                    .set_mam_cursor(cfg.account_id, ACCOUNT_ARCHIVE, None, Some(&last_id), page.complete)
                    .await?;
            }
        }
        // Have a baseline → page forward until the server reports the archive is exhausted.
        Some(mut after) => {
            for _ in 0..200 {
                let page = query_account(w, cfg.account_id, Some(&after)).await?;
                match page.last {
                    Some(last_id) => {
                        store
                            .set_mam_cursor(
                                cfg.account_id,
                                ACCOUNT_ARCHIVE,
                                None,
                                Some(&last_id),
                                page.complete,
                            )
                            .await?;
                        after = last_id;
                    }
                    None => break,
                }
                if page.complete {
                    break;
                }
            }
        }
    }

    if let Ok(items) = store.conversations(cfg.account_id).await {
        let _ = events.send(Event::ConversationsUpdated { account_id: cfg.account_id, items }).await;
    }
    Ok(())
}

struct Page {
    complete: bool,
    last: Option<String>,
}

/// Run one account-archive MAM page: `<after>` the cursor, or — when `after` is `None` — the
/// most recent page (empty `<before/>`). No `with` filter and no `to`, so the query targets our
/// own account archive (1:1 + carbons across every contact).
async fn query_account(w: &Writer, account_id: i64, after: Option<&str>) -> anyhow::Result<Page> {
    let form = Element::builder("x", NS_DATA)
        .attr(crate::ncname("type"), "submit")
        .append(field("FORM_TYPE", NS_MAM, true))
        .build();
    let mut set =
        Element::builder("set", NS_RSM).append(Element::builder("max", NS_RSM).append(PAGE.to_string()).build());
    set = match after {
        Some(a) => set.append(Element::builder("after", NS_RSM).append(a).build()),
        None => set.append(Element::builder("before", NS_RSM).build()), // empty <before/> = last page
    };
    let (query_id, _guard) = begin_query(account_id, Archive::Account);
    let query = Element::builder("query", NS_MAM)
        .attr(crate::ncname("queryid"), query_id)
        .append(form)
        .append(set.build())
        .build();
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "set")
        .attr(crate::ncname("id"), new_id("mam-iq"))
        .append(query)
        .build();
    let reply = iq::request(w, req).await?;

    if let Some(fin) = reply.get_child("fin", NS_MAM) {
        let complete = fin.attr("complete") == Some("true");
        let last = fin
            .get_child("set", NS_RSM)
            .and_then(|s| s.get_child("last", NS_RSM))
            .map(|e| e.text());
        Ok(Page { complete, last })
    } else {
        Ok(Page { complete: true, last: None })
    }
}

/// Run one forward MAM page (`<after>`), returning `(complete, last_id_of_page)`.
async fn query_after(
    w: &Writer,
    account_id: i64,
    jid: &str,
    is_muc: bool,
    after: &str,
) -> anyhow::Result<(bool, Option<String>)> {
    let mut form = Element::builder("x", NS_DATA)
        .attr(crate::ncname("type"), "submit")
        .append(field("FORM_TYPE", NS_MAM, true));
    if !is_muc {
        form = form.append(field("with", jid, false));
    }
    let set = Element::builder("set", NS_RSM)
        .append(Element::builder("max", NS_RSM).append(PAGE.to_string()).build())
        .append(Element::builder("after", NS_RSM).append(after).build())
        .build();
    let (query_id, _guard) = begin_query(account_id, archive_for(jid, is_muc));
    let query = Element::builder("query", NS_MAM)
        .attr(crate::ncname("queryid"), query_id)
        .append(form.build())
        .append(set)
        .build();
    let mut req =
        Element::builder("iq", "jabber:client").attr(crate::ncname("type"), "set").attr(crate::ncname("id"), new_id("mam-iq"));
    if is_muc {
        req = req.attr(crate::ncname("to"), jid);
    }
    let reply = iq::request(w, req.append(query).build()).await?;

    if let Some(fin) = reply.get_child("fin", NS_MAM) {
        let complete = fin.attr("complete") == Some("true");
        let last = fin
            .get_child("set", NS_RSM)
            .and_then(|s| s.get_child("last", NS_RSM))
            .map(|e| e.text());
        Ok((complete, last))
    } else {
        Ok((true, None))
    }
}

fn field(var: &str, value: &str, hidden: bool) -> Element {
    let mut f = Element::builder("field", NS_DATA).attr(crate::ncname("var"), var);
    if hidden {
        f = f.attr(crate::ncname("type"), "hidden");
    }
    f.append(Element::builder("value", NS_DATA).append(value).build()).build()
}

#[cfg(test)]
mod screen_tests {
    use super::*;

    const ME: &str = "me@example.org";
    const ROOM: &str = "room@muc.example.org";

    fn result(outer_from: Option<&str>, queryid: &str, inner_from: &str) -> Element {
        let inner = Element::builder("message", NS_CLIENT)
            .attr(crate::ncname("from"), inner_from)
            .append(Element::builder("body", NS_CLIENT).append("hi").build())
            .build();
        let fwd = Element::builder("forwarded", NS_FORWARD).append(inner).build();
        let res = Element::builder("result", NS_MAM)
            .attr(crate::ncname("queryid"), queryid)
            .attr(crate::ncname("id"), "arch-1")
            .append(fwd)
            .build();
        let mut msg = Element::builder("message", NS_CLIENT);
        if let Some(f) = outer_from {
            msg = msg.attr(crate::ncname("from"), f);
        }
        msg.append(res).build()
    }

    #[test]
    fn non_mam_stanzas_pass() {
        let msg = Element::builder("message", NS_CLIENT).attr(crate::ncname("from"), "x@y").build();
        assert!(screen_result(&msg, 1, ME));
    }

    #[test]
    fn unknown_or_finished_query_is_dropped() {
        assert!(!screen_result(&result(Some(ME), "mam-nope", "a@b/c"), 1, ME));
        let (id, guard) = begin_query(1, Archive::Account);
        assert!(screen_result(&result(Some(ME), &id, "a@b/c"), 1, ME));
        drop(guard);
        assert!(!screen_result(&result(Some(ME), &id, "a@b/c"), 1, ME));
    }

    #[test]
    fn query_of_other_account_is_dropped() {
        let (id, _g) = begin_query(1, Archive::Account);
        assert!(!screen_result(&result(Some(ME), &id, "a@b/c"), 2, ME));
    }

    #[test]
    fn account_archive_requires_own_from() {
        let (id, _g) = begin_query(1, Archive::Account);
        assert!(screen_result(&result(None, &id, "a@b/c"), 1, ME));
        assert!(screen_result(&result(Some(ME), &id, "a@b/c"), 1, ME));
        assert!(!screen_result(&result(Some("evil@attacker.org"), &id, "a@b/c"), 1, ME));
        assert!(!screen_result(&result(Some(ROOM), &id, "a@b/c"), 1, ME));
    }

    #[test]
    fn room_archive_requires_room_from_and_in_room_sender() {
        let (id, _g) = begin_query(1, Archive::Room(ROOM.into()));
        assert!(screen_result(&result(Some(ROOM), &id, "room@muc.example.org/alice"), 1, ME));
        // outer from must be the room itself
        assert!(!screen_result(&result(None, &id, "room@muc.example.org/alice"), 1, ME));
        assert!(!screen_result(&result(Some(ME), &id, "room@muc.example.org/alice"), 1, ME));
        assert!(!screen_result(&result(Some("room@muc.example.org/x"), &id, "room@muc.example.org/a"), 1, ME));
        // the room must not forge senders outside itself
        assert!(!screen_result(&result(Some(ROOM), &id, "contact@example.org/phone"), 1, ME));
        assert!(!screen_result(&result(Some(ROOM), &id, ME), 1, ME));
    }

    #[test]
    fn query_ids_are_random() {
        let (a, _ga) = begin_query(1, Archive::Account);
        let (b, _gb) = begin_query(1, Archive::Account);
        assert_ne!(a, b);
        assert_eq!(a.len(), "mam-".len() + 32);
    }

    #[test]
    fn groupchat_in_account_archive_is_dropped() {
        let (id, _g) = begin_query(1, Archive::Account);
        let xml = format!(
            "<message xmlns='{NS_CLIENT}' from='{ME}'><result xmlns='{NS_MAM}' queryid='{id}' id='a'>\
             <forwarded xmlns='{NS_FORWARD}'><message xmlns='{NS_CLIENT}' type='groupchat' \
             from='room@muc.example.org/alice'><body>hi</body></message></forwarded></result></message>"
        );
        let stanza: Element = xml.parse().unwrap();
        assert!(!screen_result(&stanza, 1, ME));
    }
}
