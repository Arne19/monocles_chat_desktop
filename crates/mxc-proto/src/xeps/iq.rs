//! IQ request/response correlation.
//!
//! tokio-xmpp surfaces the stream as a flat sequence of stanzas, so a `get`/`set` that
//! expects a typed reply needs us to match the response `id` back to the awaiting task.
//! This is a tiny process-global registry of pending iq ids → oneshot senders (there is
//! effectively one connection per runtime). [`request`] sends an iq and awaits its
//! result; the router calls [`try_resolve`] on every inbound iq to fulfil waiters.
//!
//! A reply is only accepted from the entity the request was addressed to (or from our own
//! server for requests addressed to it), like Conversations' spoofed-iq check — otherwise
//! anyone who guessed an id could answer e.g. an OMEMO bundle fetch with their own keys.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use minidom::Element;
use tokio::sync::oneshot;

use super::origin;

struct Pending {
    /// The request's `to` (None = our own account/server).
    to: Option<String>,
    tx: oneshot::Sender<Element>,
}

static PENDING: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();

fn pending() -> &'static Mutex<HashMap<String, Pending>> {
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Unregisters the id when the request ends (reply, error, timeout or cancellation alike).
struct Guard(String);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut p) = pending().lock() {
            p.remove(&self.0);
        }
    }
}

fn register(id: &str, to: Option<&str>) -> oneshot::Receiver<Element> {
    let (tx, rx) = oneshot::channel();
    pending()
        .lock()
        .unwrap()
        .insert(id.to_string(), Pending { to: to.map(str::to_string), tx });
    rx
}

/// Whether a reply from `from` may answer a request that was addressed to `to`.
fn valid_reply_origin(to: Option<&str>, from: Option<&str>, our_bare: &str) -> bool {
    if origin::to_server(to, our_bare) {
        origin::from_server(from, our_bare)
    } else {
        matches!((to, from), (Some(t), Some(f)) if origin::jid_eq(t, f))
    }
}

/// If `iq` is a result/error reply we're awaiting, deliver it and return `true`. A reply with
/// a known id but the wrong sender is swallowed (returns `true`) and the waiter keeps waiting
/// for the genuine one.
pub fn try_resolve(iq: &Element, our_bare: &str) -> bool {
    if iq.name() != "iq" {
        return false;
    }
    match iq.attr("type") {
        Some("result") | Some("error") => {}
        _ => return false,
    }
    let Some(id) = iq.attr("id") else { return false };
    let mut map = pending().lock().unwrap();
    let Some(entry) = map.get(id) else { return false };
    if !valid_reply_origin(entry.to.as_deref(), iq.attr("from"), our_bare) {
        tracing::warn!(from = ?iq.attr("from"), to = ?entry.to, "ignoring spoofed iq reply");
        return true;
    }
    if let Some(p) = map.remove(id) {
        let _ = p.tx.send(iq.clone());
    }
    true
}

/// Send an iq (which MUST carry an `id`) and await its reply (30s timeout).
/// Returns `Err` if the reply is `type='error'`.
///
/// Safe to call only from a task *other* than the reader loop (e.g. spawned command or
/// bootstrap tasks), since it awaits a reply the reader loop must deliver.
pub async fn request(w: &crate::client::Writer, iq: Element) -> anyhow::Result<Element> {
    let id = iq
        .attr("id")
        .ok_or_else(|| anyhow::anyhow!("iq request missing id"))?
        .to_string();
    let rx = register(&id, iq.attr("to"));
    let _guard = Guard(id.clone());
    w.send(iq)?;
    let reply = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .map_err(|_| anyhow::anyhow!("iq {id} timed out"))??;
    if reply.attr("type") == Some("error") {
        let condition = reply
            .get_child("error", "jabber:client")
            .and_then(|e| e.children().next().map(|c| c.name().to_string()))
            .unwrap_or_else(|| "unknown".into());
        anyhow::bail!("iq {id} error: {condition}");
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::valid_reply_origin;

    const ME: &str = "me@example.org";

    #[test]
    fn server_bound_requests_need_server_replies() {
        for to in [None, Some(ME), Some("example.org")] {
            assert!(valid_reply_origin(to, None, ME));
            assert!(valid_reply_origin(to, Some(ME), ME));
            assert!(valid_reply_origin(to, Some("example.org"), ME));
            assert!(!valid_reply_origin(to, Some("evil@attacker.org"), ME));
            assert!(!valid_reply_origin(to, Some("me@example.org/other"), ME));
        }
    }

    #[test]
    fn remote_requests_need_reply_from_target() {
        let to = Some("bob@example.net");
        assert!(valid_reply_origin(to, Some("bob@example.net"), ME));
        assert!(valid_reply_origin(to, Some("Bob@Example.net"), ME));
        assert!(!valid_reply_origin(to, None, ME));
        assert!(!valid_reply_origin(to, Some("example.org"), ME));
        assert!(!valid_reply_origin(to, Some("eve@example.net"), ME));
        assert!(!valid_reply_origin(to, Some("bob@example.net/res"), ME));
    }
}
