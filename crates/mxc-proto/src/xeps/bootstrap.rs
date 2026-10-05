//! Post-login bootstrap, run (in a spawned task) once the resource is bound.
//!
//! Order: enable carbons → fetch roster → fetch bookmarks2 (+autojoin MUCs) →
//! send initial presence → push the conversation list. OMEMO2 device/bundle publish
//! is added in Phase 2.

use async_channel::Sender;

use mxc_store::Store;

use crate::client::{AccountConfig, Writer};
use crate::event::Event;
use crate::xeps::{bookmarks, carbons, extdisco, mam, muc, omemo, presence, roster};

pub async fn run(w: &Writer, store: &Store, cfg: &AccountConfig, events: &Sender<Event>) {
    // XEP-0359: learn whether our account stamps stanza-ids before any archive/live message is
    // processed — until then `<stanza-id by=us>` is untrusted (see stanza_id.rs).
    super::stanza_id::discover(w, cfg.account_id, cfg.bare()).await;

    // XEP-0280: mirror across devices.
    if let Err(e) = carbons::enable(w) {
        tracing::warn!(error = %e, "enable carbons");
    }

    // XEP-0215: discover STUN/TURN relays so calls can traverse NAT (best-effort; falls back to
    // public STUN). Done early so the relays are ready before the user places a call.
    extdisco::fetch(w, cfg).await;

    // XEP-0237 roster.
    if let Err(e) = roster::request(w, store, cfg, events).await {
        let _ = events.send(Event::Toast { text: format!("roster fetch failed: {e}"), important: false }).await;
    }

    // XEP-0402 bookmarks2 → upsert MUC conversations, then auto-join.
    if let Err(e) = bookmarks::fetch(w, store, cfg).await {
        tracing::warn!(error = %e, "bookmarks fetch");
    }
    match store.autojoin_mucs(cfg.account_id).await {
        Ok(rooms) => {
            for room in rooms {
                let nick = store
                    .muc_nick(room.id)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| cfg.bare().split('@').next().unwrap_or("user").to_string());
                let password = store.muc_password(room.id).await.ok().flatten();
                if let Err(e) =
                    muc::join(w, store, cfg, events, &room.jid, &nick, password.as_deref()).await
                {
                    tracing::warn!(room = %room.jid, error = %e, "muc autojoin");
                    continue;
                }
                // Discover OMEMO capability + member roster (best-effort).
                if let Err(e) = muc::configure_room(w, store, cfg, events, &room.jid).await {
                    tracing::warn!(room = %room.jid, error = %e, "muc configure");
                }
                // Catch up on messages posted to the room while we were away.
                if let Err(e) = mam::catch_up(w, store, cfg, events, room.id).await {
                    tracing::warn!(room = %room.jid, error = %e, "muc mam catch-up");
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "autojoin query"),
    }

    // Initial presence (with caps) — restore our last chosen availability + status message.
    let (show, status) = store.own_presence().await.unwrap_or_default();
    if let Err(e) = presence::send_presence(w, &show, &status) {
        let _ = events.send(Event::Toast { text: format!("presence failed: {e}"), important: false }).await;
    }

    // XEP-0313: catch up the account archive (all 1:1 chats + carbons) so messages received
    // while the client was closed are fetched on restart. MUC rooms are caught up per-room above.
    if let Err(e) = mam::catch_up_account(w, store, cfg, events).await {
        tracing::warn!(error = %e, "account mam catch-up");
    }

    // PQ OMEMO2: ensure our identity exists, publish our bundle (incl. <kem-spk>/
    // <kem-prekeys>) under urn:monocles:omemo-pq:1:bundles, and add our device id to the list.
    if let Err(e) = omemo::ensure_initialized(w, store, cfg, events).await {
        tracing::warn!(error = %e, "omemo2 init");
    }

    if let Ok(items) = store.conversations(cfg.account_id).await {
        let _ = events.send(Event::ConversationsUpdated { account_id: cfg.account_id, items }).await;
    }
}
