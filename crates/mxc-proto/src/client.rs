//! The core client actor: owns the tokio-xmpp connection and the [`Store`], translates
//! UI [`Command`]s into stanzas, and lifts incoming stanzas into [`Event`]s.
//!
//! ## Concurrency model
//! The connection is a single stream/sink, so we cannot read and "request-and-await" on
//! the same task without deadlocking. Instead:
//! - one **reader loop** exclusively owns the `tokio_xmpp::Client`; it reads stanzas,
//!   resolves pending iq replies ([`xeps::iq`]), dispatches inbound handlers, and drains
//!   an **outgoing channel** by calling `send_stanza`.
//! - handlers never touch the client; they hold a [`Writer`] (an unbounded sender into
//!   that outgoing channel). Sending is therefore synchronous and never blocks reading.
//! - command + bootstrap work that must *await an iq reply* runs in **`spawn_local` tasks**,
//!   so the reader loop stays free to deliver the reply.
//!
//! The whole actor runs on a **dedicated thread with a current-thread runtime + LocalSet**.
//! This is required because the PQ-OMEMO2 layer (libsignal's `#[async_trait(?Send)]` store
//! traits + `rand::ThreadRng`) is `!Send` and cannot be `tokio::spawn`ed. The UI talks to
//! it over `async-channel` (which is `Send`), so the threading is invisible to GTK.
//!
//! ## tokio-xmpp version note
//! Targets xmpp-rs `tokio-xmpp` 6.x (`Client` as a `Stream<Item = Event>`,
//! `Event::{Online,Stanza,Disconnected}`, `send_stanza`). The wire layer here works on raw
//! `minidom::Element`, so incoming/outgoing `Stanza`s are converted at this boundary via
//! `xso::transform`. This module is the single place to reconcile if the pin differs.

use async_channel::{Receiver, Sender};
use futures_util::StreamExt;
use minidom::Element;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use mxc_store::Store;

use crate::command::Command;
use crate::event::{ConnectionState, Event};
use crate::xeps;

/// Configuration to bring an account online.
#[derive(Clone)]
pub struct AccountConfig {
    pub account_id: i64,
    pub jid: String,
    /// Plaintext password (held only in memory for SCRAM auth/reconnect). Wrapped in
    /// `Zeroizing` so every copy is wiped from memory when dropped.
    password: zeroize::Zeroizing<String>,
}

impl AccountConfig {
    pub fn new(account_id: i64, jid: String, password: String) -> Self {
        Self { account_id, jid, password: zeroize::Zeroizing::new(password) }
    }

    /// A transient copy of the password for handing to the XMPP client.
    pub fn password(&self) -> String {
        self.password.as_str().to_owned()
    }

    /// Our own bare JID (used for carbon trust + SCE binding).
    pub fn bare(&self) -> &str {
        self.jid.split('/').next().unwrap_or(&self.jid)
    }
}

/// A cheap, clonable handle for sending stanzas onto the connection's outgoing queue.
#[derive(Clone)]
pub struct Writer(mpsc::UnboundedSender<Element>);

impl Writer {
    /// Queue a stanza for sending. Non-blocking; the reader loop flushes it.
    pub fn send(&self, stanza: Element) -> anyhow::Result<()> {
        self.0
            .send(stanza)
            .map_err(|_| anyhow::anyhow!("connection writer closed"))
    }
}

/// Handle the UI keeps: send commands, receive events.
#[derive(Clone)]
pub struct ClientHandle {
    pub commands: Sender<Command>,
    pub events: Receiver<Event>,
    /// Decoded video frames for active calls (high-rate, kept off the `events` stream).
    pub video: Receiver<crate::event::CallVideoFrame>,
}

/// Spawn the core actor on its own thread (current-thread runtime + LocalSet) and return
/// the UI handle. A dedicated thread is required because the OMEMO2 layer is `!Send`.
pub fn spawn(store: Store, accounts: Vec<AccountConfig>) -> ClientHandle {
    // Pin the process-wide rustls crypto provider. tokio-xmpp and reqwest both pull in
    // rustls; with more than one provider linked, rustls can't auto-select and panics at
    // TLS setup. Installing aws-lc-rs explicitly is idempotent (Err if already set).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (cmd_tx, cmd_rx) = async_channel::unbounded::<Command>();
    let (evt_tx, evt_rx) = async_channel::unbounded::<Event>();
    // Video frames flow on their own bounded channel (drop under backpressure, not buffer).
    let (vid_tx, vid_rx) = async_channel::bounded::<crate::event::CallVideoFrame>(8);

    let actor = CoreActor { store, events: evt_tx, video: vid_tx };
    std::thread::Builder::new()
        .name("mxc-core".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build core runtime");
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, actor.run(accounts, cmd_rx));
        })
        .expect("spawn core thread");

    ClientHandle { commands: cmd_tx, events: evt_rx, video: vid_rx }
}

#[derive(Clone)]
struct CoreActor {
    store: Store,
    events: Sender<Event>,
    /// Sink for decoded call video frames (forwarded to the UI via `ClientHandle::video`).
    video: Sender<crate::event::CallVideoFrame>,
}

impl CoreActor {
    async fn run(self, accounts: Vec<AccountConfig>, commands: Receiver<Command>) {
        let Some(cfg) = accounts.into_iter().next() else {
            warn!("no accounts configured");
            return;
        };
        if let Err(e) = self.connection_loop(cfg, commands).await {
            let _ = self
                .events
                .send(Event::Connection(ConnectionState::Disconnected { reason: e.to_string() }))
                .await;
        }
    }

    async fn connection_loop(
        &self,
        cfg: AccountConfig,
        commands: Receiver<Command>,
    ) -> anyhow::Result<()> {
        use tokio_xmpp::{Client as XmppClient, Event as XmppEvent};

        let _ = self.events.send(Event::Connection(ConnectionState::Connecting)).await;

        // tokio-xmpp 6: Client::new_with_connector drives a `StanzaStream` that negotiates
        // SCRAM, resource bind, and XEP-0198 SM where the server supports them, and reconnects
        // internally. Our custom connector still prefers XEP-0368 direct TLS (5223) with a
        // STARTTLS (5222 + SRV) fallback.
        let jid: tokio_xmpp::jid::Jid = cfg
            .jid
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid jid {}: {e}", cfg.jid))?;
        // Prefer XEP-0368 direct TLS on 5223 (works through firewalls that block STARTTLS
        // 5222), falling back to STARTTLS automatically. See [`crate::directtls`].
        // A reconnecting client factory. tokio-xmpp's `set_reconnect` only re-establishes an
        // *already-online* session — it does NOT retry a failed initial connect (e.g. starting
        // offline). So we drive reconnection ourselves and keep this loop alive throughout,
        // which is also what lets offline-composed messages still be handled (persisted +
        // queued in the outbox) instead of being dropped on a dead core.
        // tokio-xmpp 6 replaced `new_with_config(AsyncConfig{..})` + `set_reconnect(true)` with
        // `new_with_connector(jid, password, connector, timeouts)`; the StanzaStream reconnects
        // on its own. We keep the outer self-driven reconnect loop below as a belt-and-braces
        // rebuild path (also covers a fully failed initial connect).
        let make_client = || {
            XmppClient::new_with_connector(
                jid.clone(),
                cfg.password(),
                crate::directtls::PreferDirectTls,
                tokio_xmpp::xmlstream::Timeouts::default(),
            )
        };
        let mut client = make_client();

        // Outgoing stanza queue (handlers → reader loop → socket).
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Element>();
        let writer = Writer(out_tx);

        // Active-call bookkeeping (JMI + Jingle media), owned on this (actor) thread so its
        // `Rc` never crosses a thread boundary. Shared by the reader + command handlers.
        let calls = xeps::jingle::registry(self.video.clone(), self.store.clone(), cfg.account_id);

        // Connection state, read when handling a SendMessage so we know whether to send now or
        // queue it in the offline outbox. Lives here (not on the !Send CoreActor) like `calls`.
        let online = std::rc::Rc::new(std::cell::Cell::new(false));

        // Self-driven reconnect: when the stream closes we arm a backoff timer (instead of
        // exiting) and stop polling the stream until it fires, then rebuild the client. The
        // command branch keeps running the whole time, so offline sends are still serviced.
        let mut backoff = std::time::Duration::from_secs(2);
        let mut reconnect_timer: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;

        loop {
            tokio::select! {
                // --- drain outgoing queue (only once online) ---
                // Gated on `online`: sending a stanza mid-handshake (e.g. a FetchAvatar/
                // FetchOwnKeys IQ the UI fires during an early/instant open, before SASL+bind
                // finish) corrupts the stream so it never reaches Online. Stanzas buffer in
                // `out_rx` until the session is up, then flush.
                Some(stanza) = out_rx.recv(), if online.get() => {
                    // The XEP layer emits raw `Element`s; tokio-xmpp 6's `send_stanza` wants a
                    // typed `Stanza` (iq/message/presence). Convert at the boundary.
                    match xso::transform::<tokio_xmpp::Stanza, _>(&stanza) {
                        Ok(st) => {
                            if let Err(e) = client.send_stanza(st).await {
                                warn!(error = %e, "send failed");
                            }
                        }
                        Err(e) => warn!(error = %e, "dropping non-stanza outgoing element"),
                    }
                }

                // --- incoming stream events (paused while waiting to reconnect) ---
                ev = client.next(), if reconnect_timer.is_none() => {
                    let Some(ev) = ev else {
                        // Stream closed (lost link, or a failed initial connect). Arm a backoff
                        // and keep serving commands; don't exit the core.
                        online.set(false);
                        let _ = self.events.send(Event::Connection(
                            ConnectionState::Disconnected { reason: "reconnecting".into() })).await;
                        reconnect_timer = Some(Box::pin(tokio::time::sleep(backoff)));
                        backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
                        continue;
                    };
                    match ev {
                        XmppEvent::Online { bound_jid, resumed, .. } => {
                            info!(%bound_jid, resumed, "online");
                            online.set(true);
                            backoff = std::time::Duration::from_secs(2); // reset on success
                            let _ = self.events.send(Event::Connection(
                                ConnectionState::Online { full_jid: bound_jid.to_string() })).await;
                            if !resumed {
                                // Spawn bootstrap so it can await iq replies without
                                // blocking the reader loop.
                                let w = writer.clone();
                                let store = self.store.clone();
                                let cfg = cfg.clone();
                                let events = self.events.clone();
                                tokio::task::spawn_local(async move {
                                    xeps::bootstrap::run(&w, &store, &cfg, &events).await;
                                });
                            }
                            // Flush any messages composed while offline (best-effort; leaves
                            // still-failing ones pending for the next reconnect).
                            {
                                let w = writer.clone();
                                let store = self.store.clone();
                                let cfg = cfg.clone();
                                let events = self.events.clone();
                                tokio::task::spawn_local(async move {
                                    if let Err(e) = xeps::messaging::flush_outbox(&w, &store, &cfg, &events).await {
                                        warn!(error = %e, "outbox flush");
                                    }
                                });
                            }
                        }
                        XmppEvent::Disconnected(err) => {
                            warn!(%err, "disconnected");
                            online.set(false);
                            let _ = self.events.send(Event::Connection(
                                ConnectionState::Disconnected { reason: err.to_string() })).await;
                        }
                        XmppEvent::Stanza(stanza) => {
                            // tokio-xmpp 6 delivers a typed `Stanza`; the XEP layer works on raw
                            // `Element`, so convert back at the boundary.
                            let stanza: Element = match xso::transform::<Element, _>(&stanza) {
                                Ok(el) => el,
                                Err(e) => {
                                    debug!(error = %e, "could not lift incoming stanza to element");
                                    continue;
                                }
                            };
                            // Resolve awaited iq replies first; otherwise dispatch.
                            if xeps::iq::try_resolve(&stanza, cfg.bare()) {
                                continue;
                            }
                            // Vet MAM results here, in stream order: their query is
                            // unregistered as soon as its iq reply (resolved above) arrives,
                            // which a spawned handler could otherwise race.
                            if !xeps::mam::screen_result(&stanza, cfg.account_id, cfg.bare()) {
                                continue;
                            }
                            // Spawn the handler so the reader loop stays free to deliver
                            // iq replies it awaits (e.g. the PEP fetches an encrypted
                            // auto-receipt needs); otherwise handling would block reading
                            // and deadlock against its own requests.
                            let w = writer.clone();
                            let store = self.store.clone();
                            let cfg = cfg.clone();
                            let events = self.events.clone();
                            let calls = calls.clone();
                            tokio::task::spawn_local(async move {
                                if let Err(e) = xeps::router::handle_stanza(
                                    &w, &store, &cfg, &events, &calls, stanza).await
                                {
                                    debug!(error = %e, "stanza handling error");
                                }
                            });
                        }
                    }
                }

                // --- reconnect backoff elapsed → rebuild the client and try again ---
                _ = async {
                    match reconnect_timer.as_mut() {
                        Some(s) => s.as_mut().await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    reconnect_timer = None;
                    let _ = self.events.send(Event::Connection(ConnectionState::Connecting)).await;
                    client = make_client();
                }

                // --- outgoing commands from the UI ---
                cmd = commands.recv() => {
                    match cmd {
                        Ok(Command::Shutdown) | Err(_) => {
                            info!("core shutting down");
                            break;
                        }
                        Ok(cmd) => {
                            // Spawn so command handlers may await iq replies.
                            let actor = self.clone();
                            let w = writer.clone();
                            let cfg = cfg.clone();
                            let calls = calls.clone();
                            // Capture user-initiated send context so a failure is surfaced
                            // instead of vanishing: SendMessage restores the composer text;
                            // SendFile shows a toast naming the file.
                            enum FailCtx {
                                Msg { to: String, body: String },
                                File { name: String },
                                Publish { what: &'static str },
                                Other,
                            }
                            let fail_ctx = match &cmd {
                                Command::SendMessage { to, body, .. } => {
                                    FailCtx::Msg { to: to.clone(), body: body.clone() }
                                }
                                Command::SendFile { path, .. }
                                | Command::SendSticker { path, .. }
                                | Command::SendWebxdcFile { path, .. } => {
                                    FailCtx::File {
                                        name: std::path::Path::new(path)
                                            .file_name()
                                            .map(|n| n.to_string_lossy().into_owned())
                                            .unwrap_or_else(|| path.clone()),
                                    }
                                }
                                Command::SendFiles { paths, .. } => FailCtx::File {
                                    name: match paths.len() {
                                        1 => std::path::Path::new(&paths[0])
                                            .file_name()
                                            .map(|n| n.to_string_lossy().into_owned())
                                            .unwrap_or_else(|| paths[0].clone()),
                                        n => format!("{n} files"),
                                    },
                                },
                                Command::PublishStory { .. } => FailCtx::Publish { what: "story" },
                                Command::PublishPost { .. } => FailCtx::Publish { what: "post" },
                                _ => FailCtx::Other,
                            };
                            let is_online = online.get();
                            tokio::task::spawn_local(async move {
                                if let Err(e) = actor.handle_command(&w, &cfg, &calls, is_online, cmd).await {
                                    match fail_ctx {
                                        FailCtx::Msg { to, body } => {
                                            let _ = actor.events.send(Event::SendFailed {
                                                account_id: cfg.account_id,
                                                to,
                                                body,
                                                reason: e.to_string(),
                                            }).await;
                                        }
                                        FailCtx::File { name } => {
                                            let _ = actor.events.send(Event::Toast {
                                                text: format!("Couldn't send {name}: {e}"),
                                                important: true,
                                            }).await;
                                        }
                                        FailCtx::Publish { what } => {
                                            let _ = actor.events.send(Event::PublishDone {
                                                account_id: cfg.account_id,
                                                what: what.to_string(),
                                                error: Some(format!("{e:#}")),
                                            }).await;
                                        }
                                        FailCtx::Other => {
                                            let _ = actor.events.send(Event::Toast {
                                                text: format!("command failed: {e}"),
                                                important: false,
                                            }).await;
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Emit `Event::ContactKeys` for a contact's key screen. Shared by `FetchContactKeys` and
    /// the out-of-band verification path, which has to refresh the same list.
    async fn emit_contact_keys(&self, account_id: i64, jid: String) -> anyhow::Result<()> {
        let mut devices = Vec::new();
        for id in self.store.list_omemo_identities(account_id, &jid).await?.into_iter() {
            devices.push(crate::event::DeviceKey {
                device_id: id.device_id,
                fingerprint: device_fingerprint(&self.store, account_id, &jid, &id.identity_key).await,
                trust: id.trust,
                active: id.active,
            });
        }
        let _ = self.events.send(Event::ContactKeys { account_id, jid, devices }).await;
        Ok(())
    }

    /// Emit `Event::OwnKeys` for the key screen: this device's hybrid fingerprint plus our other
    /// devices. Shared by `FetchOwnKeys` and `ResetOmemo2Identities`.
    async fn emit_own_keys(&self, cfg: &AccountConfig, account_id: i64) -> anyhow::Result<()> {
        let own_device_id = self.store.omemo_own_device_id(account_id).await?.unwrap_or(0);
        // Our own device shows the hybrid (classical + ML-DSA-87) fingerprint.
        let own_fingerprint = match (
            self.store.omemo_own_identity_pub(account_id).await?,
            self.store.omemo_own_pq_identity_pub(account_id).await?,
        ) {
            (Some(ik), Some(pq)) => mxc_omemo::hybrid_fingerprint_display(&ik, &pq),
            (Some(ik), _) => mxc_omemo::fingerprint(&ik),
            _ => String::new(),
        };
        // The QR/link a contact verifies us by. It carries the CLASSICAL identity key (the
        // value both sides key trust on), not the hybrid string we display, and uses the
        // plain `omemo-sid-` parameter: we have no legacy stack, so this is the only key we
        // have and every client — including monocles Android builds from before the
        // `omemo-pq-sid-` parameter existed — can read it. See `crate::uri`.
        let verification_uri = match self.store.omemo_own_identity_pub(account_id).await? {
            Some(ik) if own_device_id != 0 => crate::uri::verification_uri(
                cfg.bare(),
                &[crate::uri::UriFingerprint::from_identity_key(
                    crate::uri::FingerprintKind::Omemo,
                    own_device_id,
                    &ik,
                )],
            ),
            _ => String::new(),
        };
        let mut devices = Vec::new();
        for id in self
            .store
            .list_omemo_identities(account_id, cfg.bare())
            .await?
            .into_iter()
            .filter(|id| id.device_id != own_device_id)
        {
            devices.push(crate::event::DeviceKey {
                device_id: id.device_id,
                fingerprint: device_fingerprint(&self.store, account_id, cfg.bare(), &id.identity_key)
                    .await,
                trust: id.trust,
                active: id.active,
            });
        }
        debug!(
            own_device_id,
            own_fingerprint_empty = own_fingerprint.is_empty(),
            other_devices = devices.len(),
            "omemo: emit_own_keys"
        );
        let auto_trust = self.store.auto_trust_new_keys().await.unwrap_or(true);
        let (presence_show, presence_status) = self.store.own_presence().await.unwrap_or_default();
        let _ = self
            .events
            .send(Event::OwnKeys {
                account_id,
                jid: cfg.bare().to_string(),
                own_device_id,
                own_fingerprint,
                verification_uri,
                devices,
                auto_trust,
                presence_show,
                presence_status,
            })
            .await;
        Ok(())
    }

    async fn handle_command(
        &self,
        w: &Writer,
        cfg: &AccountConfig,
        calls: &xeps::jingle::CallRegistry,
        online: bool,
        cmd: Command,
    ) -> anyhow::Result<()> {
        match cmd {
            Command::SendMessage { to, body, encryption, reply_to, id, .. } => {
                xeps::messaging::send_message(
                    w, &self.store, cfg, &self.events, &to, &body, encryption, reply_to, online, id,
                )
                .await
            }
            Command::SendChatState { to, state, .. } => {
                xeps::messaging::send_chat_state(w, &self.store, cfg, &to, &state).await
            }
            Command::MarkRead { to, stanza_id, conversation_id, .. } => {
                self.store.clear_unread(conversation_id).await.ok();
                xeps::messaging::send_read_marker(w, &self.store, cfg, &to, &stanza_id).await
            }
            Command::React { to, target_id, emojis, .. } => {
                xeps::messaging::react(w, &self.store, cfg, &self.events, &to, &target_id, &emojis).await
            }
            Command::Correct { to, target_id, new_body, conversation_id, .. } => {
                xeps::messaging::send_correction(
                    w, &self.store, cfg, &self.events, &to, &target_id, &new_body, conversation_id,
                )
                .await
            }
            Command::Retract { to, target_id, conversation_id, .. } => {
                xeps::messaging::send_retraction(
                    w, &self.store, cfg, &self.events, &to, &target_id, conversation_id,
                )
                .await
            }
            Command::LoadHistory { conversation_id, before, .. } => {
                xeps::mam::load_page(w, &self.store, cfg, &self.events, conversation_id, before).await
            }
            Command::SyncHistory { conversation_id, .. } => {
                xeps::mam::catch_up(w, &self.store, cfg, &self.events, conversation_id).await
            }
            Command::AddContact { account_id, jid, name } => {
                // Pre-approve them seeing us (Android's createContact autoGrant), so when they
                // accept and subscribe back it's granted automatically rather than prompting.
                let _ = self.store.set_presence_preapproval(account_id, &jid).await;
                xeps::roster::add_contact(w, cfg.bare(), &jid, name.as_deref())
            }
            Command::RemoveContact { account_id, jid } => {
                // A roster `subscription="remove"` makes the server cancel both presence
                // subscriptions automatically (RFC 6121 §2.5.2) — no explicit unsubscribe needed.
                xeps::roster::remove_contact(w, &jid)?;
                // Server pushes the roster removal (refreshing the contact list); also drop
                // the local conversation + history, and any stale presence pre-approval.
                let _ = self.store.clear_presence_preapproval(account_id, &jid).await;
                let _ = self.store.delete_conversation(account_id, &jid).await;
                if let Ok(items) = self.store.conversations(account_id).await {
                    let _ = self.events.send(Event::ConversationsUpdated { account_id, items }).await;
                }
                Ok(())
            }
            Command::JoinMuc { room, nick, password, .. } => {
                xeps::muc::join(w, &self.store, cfg, &self.events, &room, &nick, password.as_deref())
                    .await?;
                // Discover OMEMO capability + member roster (best-effort).
                if let Err(e) = xeps::muc::configure_room(w, &self.store, cfg, &self.events, &room).await {
                    tracing::warn!(error = %e, %room, "muc configure");
                }
                // User-initiated join → publish a XEP-0402 bookmark so the room syncs to our
                // other devices and auto-joins next time. Best-effort.
                if let Err(e) = xeps::bookmarks::save(w, &room, None, Some(&nick), true).await {
                    tracing::warn!(error = %e, "bookmark save");
                }
                Ok(())
            }
            Command::LeaveMuc { account_id, room } => {
                let nick = self
                    .store
                    .muc_nick_by_jid(account_id, &room)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| cfg.bare().split('@').next().unwrap_or("user").to_string());
                let _ = xeps::muc::leave(w, &room, &nick);
                if let Err(e) = xeps::bookmarks::remove(w, &room).await {
                    tracing::warn!(error = %e, "bookmark remove");
                }
                self.store.delete_conversation(account_id, &room).await?;
                if let Ok(items) = self.store.conversations(account_id).await {
                    let _ = self.events.send(Event::ConversationsUpdated { account_id, items }).await;
                }
                Ok(())
            }
            Command::DeleteChat { account_id, jid } => {
                self.store.delete_conversation(account_id, &jid).await?;
                if let Ok(items) = self.store.conversations(account_id).await {
                    let _ = self.events.send(Event::ConversationsUpdated { account_id, items }).await;
                }
                Ok(())
            }
            Command::FetchPeerInfo { jid, .. } => {
                // best-effort; absence of a published avatar/nick is not an error
                let _ = xeps::avatar::fetch(w, cfg, &self.events, &jid).await;
                let _ = xeps::avatar::fetch_nick(w, cfg, &self.events, &jid).await;
                Ok(())
            }
            Command::FetchMucAvatar { account_id, room, nick } => {
                // best-effort; the UI keeps the generated initials avatar if there's no photo
                let occupant = format!("{room}/{nick}");
                let data = xeps::vcard::fetch_photo(w, &occupant).await.ok().flatten().unwrap_or_default();
                let _ = self
                    .events
                    .send(Event::MucAvatar { account_id, room, nick, data })
                    .await;
                Ok(())
            }
            Command::FetchAvatar { account_id, jid, is_muc } => {
                xeps::avatar::fetch_best(w, &self.events, account_id, &jid, is_muc).await;
                Ok(())
            }
            Command::SendFile { to, path, caption, .. } => {
                xeps::messaging::send_file(w, &self.store, cfg, &self.events, &to, &path, caption.as_deref()).await
            }
            Command::SendFiles { to, paths, caption, .. } => {
                xeps::messaging::send_files(w, &self.store, cfg, &self.events, &to, &paths, caption.as_deref()).await
            }
            Command::SendSticker { to, path, .. } => {
                xeps::messaging::send_sticker(w, &self.store, cfg, &self.events, &to, &path).await
            }
            Command::DownloadFile { url, filename, .. } => {
                xeps::messaging::download_file(&self.events, cfg, &url, &filename).await
            }
            Command::SendWebxdcFile { to, path, .. } => {
                xeps::messaging::send_webxdc_file(w, &self.store, cfg, &self.events, &to, &path).await
            }
            Command::SendWebxdcUpdate { to, thread, payload, info, document, summary, notify, .. } => {
                xeps::messaging::send_webxdc_update(
                    w, &self.store, cfg, &self.events, &to, &thread,
                    payload.as_deref(), info.as_deref(), document.as_deref(), summary.as_deref(),
                    notify.as_deref(),
                ).await
            }
            Command::SendWebxdcRealtime { to, thread, data_b64, .. } => {
                xeps::messaging::send_webxdc_realtime(w, &self.store, cfg, &to, &thread, &data_b64).await
            }
            Command::SetOmemoTrust { jid, device_id, trust, .. } => {
                self.store.set_omemo_trust(cfg.account_id, &jid, device_id, trust).await?;
                Ok(())
            }
            Command::FetchOwnKeys { account_id } => self.emit_own_keys(cfg, account_id).await,
            Command::ResetOmemo2Identities { account_id } => {
                // Wipe all cached peer state (sessions, identities/trust, PQ pins, device lists)
                // and the in-memory failure caches, then re-advertise our (unchanged) bundle so
                // peers can re-establish. Our own identity/fingerprint is preserved.
                self.store.reset_omemo2_peer_state(account_id).await?;
                xeps::omemo::forget_caches(account_id);
                if let Err(e) = xeps::omemo::ensure_initialized(w, &self.store, cfg, &self.events).await {
                    warn!(error = %e, "omemo: republish after reset failed (will retry on reconnect)");
                }
                // Refresh the keys screen (now empty until sessions rebuild) and confirm.
                self.emit_own_keys(cfg, account_id).await?;
                let _ = self
                    .events
                    .send(Event::Toast {
                        text: "PQ OMEMO2 keys reset — they will rebuild as you exchange messages.".into(),
                        important: true,
                    })
                    .await;
                Ok(())
            }
            Command::RegenerateOmemo2Identity { account_id } => {
                // LAST RESORT (suspected key compromise): wipe our own hybrid identity and all
                // peer state, mint a new identity/device id, retract the old bundle and publish
                // the new one. The fingerprint changes — contacts must verify us again. Unlike
                // the peer reset above, a failure here matters (we may be left key-less until
                // reconnect), so it is propagated.
                xeps::omemo::regenerate_own_identity(w, &self.store, cfg).await?;
                // Refresh the keys screen (new own fingerprint, peers empty until rebuilt).
                self.emit_own_keys(cfg, account_id).await?;
                let _ = self
                    .events
                    .send(Event::Toast {
                        text: "New PQ OMEMO2 identity generated — your fingerprint changed; contacts must verify you again.".into(),
                        important: true,
                    })
                    .await;
                Ok(())
            }
            Command::SetPresence { show, status, .. } => {
                self.store.set_own_presence(&show, &status).await?;
                xeps::presence::send_presence(w, &show, &status)
            }
            Command::PublishAvatar { account_id, data, mime, width, height } => {
                xeps::avatar::publish(w, &data, &mime, width, height).await?;
                // Same path as an incoming avatar: the UI caches it to disk + repaints.
                let _ = self
                    .events
                    .send(Event::Avatar { account_id, jid: cfg.bare().to_string(), data })
                    .await;
                Ok(())
            }
            Command::SetNick { nick, .. } => xeps::avatar::publish_nick(w, &nick).await,
            Command::FetchNick { jid, .. } => {
                xeps::avatar::fetch_nick(w, cfg, &self.events, &jid).await
            }
            Command::SetAutoTrust { value, .. } => {
                self.store.set_auto_trust_new_keys(value).await?;
                Ok(())
            }
            Command::SetNotify { account_id, jid, mode } => {
                self.store.set_notify_mode(account_id, &jid, &mode).await?;
                // Refresh the list so the new mode (+ its bell indicator) shows immediately.
                if let Ok(items) = self.store.conversations(account_id).await {
                    let _ = self.events.send(Event::ConversationsUpdated { account_id, items }).await;
                }
                Ok(())
            }
            Command::StartPrivate { account_id, occupant_jid } => {
                self.store.conversation_id(account_id, &occupant_jid, "muc_pm").await?;
                if let Ok(items) = self.store.conversations(account_id).await {
                    let _ = self.events.send(Event::ConversationsUpdated { account_id, items }).await;
                }
                Ok(())
            }
            Command::FetchContactKeys { account_id, jid } => {
                self.emit_contact_keys(account_id, jid).await
            }
            Command::VerifyOmemoFingerprints { account_id, jid, fingerprints } => {
                // Out-of-band verification (scanned QR / pasted link). Trust is keyed by the
                // identity-key VALUE, so we simply match every fingerprint from the code
                // against the keys we hold for this JID; anything else in the code (e.g. the
                // legacy OMEMO key of a monocles Android device) matches nothing and is
                // silently ignored rather than treated as an error.
                let mut verified = 0usize;
                for id in self.store.list_omemo_identities(account_id, &jid).await? {
                    let hex = crate::uri::UriFingerprint::from_identity_key(
                        crate::uri::FingerprintKind::OmemoPq,
                        id.device_id,
                        &id.identity_key,
                    )
                    .hex;
                    if !fingerprints.iter().any(|f| f.eq_ignore_ascii_case(&hex)) {
                        continue;
                    }
                    verified += 1;
                    // trust = 3 is "manually verified" (shield), the state the call-verify
                    // path uses: it also pins the peer's PQ identity for good, which a
                    // blind-trust (1) does not.
                    if id.trust != 3 {
                        self.store.set_omemo_trust(account_id, &jid, id.device_id, 3).await?;
                    }
                }
                debug!(%jid, offered = fingerprints.len(), verified, "omemo: verify from uri");
                // Refresh whichever key screen is showing this JID.
                if jid == cfg.bare() {
                    self.emit_own_keys(cfg, account_id).await?;
                } else {
                    self.emit_contact_keys(account_id, jid.clone()).await?;
                }
                let text = if verified == 0 {
                    // Either the code is for somebody else, or their devices have not been
                    // fetched yet — never silently claim a verification that did not happen.
                    "No matching device keys — nothing was verified".to_string()
                } else if verified == 1 {
                    "1 device key verified".to_string()
                } else {
                    format!("{verified} device keys verified")
                };
                let _ = self.events.send(Event::Toast { text, important: verified == 0 }).await;
                Ok(())
            }
            Command::FetchVcard { account_id, jid, is_muc } => {
                let details = if is_muc {
                    let mut d = xeps::muc::room_profile(w, &jid).await;
                    // Add the live room subject/topic captured from groupchat <subject>, right
                    // after the (shorter) disco description.
                    if let Ok(conv) = self.store.conversation_id(account_id, &jid, "muc").await {
                        if let Ok(Some(subject)) = self.store.muc_subject(conv).await {
                            let subject = subject.trim();
                            if !subject.is_empty() {
                                let pos = d
                                    .fields
                                    .iter()
                                    .position(|(l, _)| l == "Description")
                                    .map(|i| i + 1)
                                    .unwrap_or(d.fields.len());
                                d.fields.insert(pos, ("Topic".to_string(), subject.to_string()));
                            }
                        }
                    }
                    d
                } else {
                    xeps::vcard::fetch_details(w, &jid).await.unwrap_or_default()
                };
                let _ = self
                    .events
                    .send(Event::Vcard {
                        account_id,
                        jid,
                        photo: details.photo.unwrap_or_default(),
                        fields: details.fields,
                    })
                    .await;
                Ok(())
            }
            Command::FetchSubscription { account_id, jid } => {
                let item = self.store.roster_item(account_id, &jid).await?;
                let (subscription, ask) = item
                    .map(|i| (i.subscription, i.ask))
                    .unwrap_or_else(|| ("none".to_string(), None));
                let _ = self
                    .events
                    .send(Event::Subscription { account_id, jid, subscription, ask })
                    .await;
                Ok(())
            }
            Command::SetSubscription { account_id, jid, action } => {
                use crate::command::Subscription;
                // Mirror Android's PREEMPTIVE_GRANT: granting presence-out records a local
                // pre-approval so an inbound `subscribe` (which a bare `subscribed` can't
                // satisfy on its own) is auto-approved; revoking clears it.
                match action {
                    Subscription::Subscribed => {
                        let _ = self.store.set_presence_preapproval(account_id, &jid).await;
                    }
                    Subscription::Unsubscribed => {
                        let _ = self.store.clear_presence_preapproval(account_id, &jid).await;
                    }
                    _ => {}
                }
                let nick = cfg.bare().split('@').next().unwrap_or(cfg.bare()).to_string();
                xeps::roster::set_subscription(w, cfg.bare(), &jid, action.as_type(), Some(&nick))
            }
            Command::PlaceCall { account_id, to, video } => {
                let sid = xeps::roster::new_id("call");
                tracing::info!(%to, video, %sid, "PlaceCall: sending JMI propose");
                xeps::jingle::propose(w, calls, &to, &sid, video)?;
                let _ = self
                    .events
                    .send(Event::CallUpdate {
                        account_id,
                        sid,
                        peer: to,
                        video,
                        state: crate::event::CallState::Outgoing,
                    })
                    .await;
                Ok(())
            }
            Command::AcceptCall { sid, peer, .. } => {
                // Advertise our OMEMO2 device on the proceed so the caller OMEMO-verifies the call.
                let own_device = xeps::omemo::own_device_id(&self.store, cfg).await.ok();
                xeps::jingle::accept(w, calls, &self.events, cfg, &sid, &peer, own_device)
            }
            Command::DeclineCall { sid, peer, .. } => {
                xeps::jingle::reject(w, calls, &peer, cfg.bare(), &sid)
            }
            Command::CancelCall { sid, peer, .. } => {
                xeps::jingle::hang_up(w, calls, &peer, &sid)
            }
            Command::SetCallMute { sid, muted, .. } => {
                xeps::jingle::set_mute(calls, &sid, muted);
                Ok(())
            }
            Command::SetCallCamera { sid, enabled, .. } => {
                xeps::jingle::set_camera(calls, &sid, enabled);
                Ok(())
            }
            Command::SetCallScreenShare { account_id, sid, enabled } => {
                let active = if enabled {
                    // Run the portal picker first (async) — must not hold the call-registry borrow
                    // across the await — then splice the resulting PipeWire stream into the call.
                    match mxc_media::capture_screen().await {
                        Ok(screen) => {
                            xeps::jingle::start_screen_share(calls, &sid, screen);
                            true
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "screen share: portal capture failed");
                            false
                        }
                    }
                } else {
                    xeps::jingle::stop_screen_share(calls, &sid);
                    false
                };
                // Authoritative state back to the UI (resets the button if the picker was cancelled).
                let _ = self
                    .events
                    .send(Event::CallScreenShare { account_id, sid, active })
                    .await;
                Ok(())
            }
            Command::UpgradeCallToVideo { sid, .. } => {
                xeps::jingle::upgrade_to_video(calls, &sid);
                Ok(())
            }
            Command::AcceptVideoUpgrade { account_id, sid } => {
                xeps::jingle::accept_video_upgrade(calls, &self.events, account_id, &sid).await;
                Ok(())
            }
            Command::DeclineVideoUpgrade { sid, .. } => {
                xeps::jingle::decline_video_upgrade(w, calls, cfg.bare(), &sid);
                Ok(())
            }
            Command::PlaceGroupCall { room, video, .. } => {
                xeps::jingle::place_group_call(w, calls, &self.events, cfg, &room, video).await;
                Ok(())
            }
            Command::LeaveGroupCall { room, .. } => {
                xeps::jingle::leave_group_call(w, calls, &self.events, cfg, &room).await;
                Ok(())
            }
            Command::SetGroupCallMute { room, muted, .. } => {
                xeps::jingle::set_group_mute(calls, &room, muted);
                Ok(())
            }
            Command::SetGroupCallCamera { room, enabled, .. } => {
                xeps::jingle::set_group_camera(calls, &room, enabled);
                Ok(())
            }
            Command::SetGroupCallScreenShare { account_id, room, enabled } => {
                let active = if enabled {
                    // Portal picker first (async) — must not hold the call-registry borrow across
                    // the await — then switch the shared camera hub to the screen for all legs.
                    match mxc_media::capture_screen().await {
                        Ok(screen) => {
                            xeps::jingle::start_group_screen_share(calls, &room, screen);
                            xeps::jingle::group_screen_sharing(calls, &room)
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "group screen share: portal capture failed");
                            false
                        }
                    }
                } else {
                    xeps::jingle::stop_group_screen_share(calls, &room);
                    false
                };
                let _ = self
                    .events
                    .send(Event::ConferenceScreenShare { account_id, room, active })
                    .await;
                Ok(())
            }
            Command::PublishStory { account_id, path, title } => {
                let (url, mime) = upload_broadcast_media(w, cfg, &path).await?;
                xeps::stories::publish(w, cfg, &url, &mime, &title).await?;
                // Don't depend on the PEP echo (+notify) to show our own story.
                xeps::stories::fetch(w, &self.store, cfg, None).await;
                let _ = self.events.send(Event::StoriesUpdated { account_id }).await;
                let _ = self
                    .events
                    .send(Event::PublishDone { account_id, what: "story".into(), error: None })
                    .await;
                Ok(())
            }
            Command::FetchStories { account_id } => {
                // Our own stories + every contact we're subscribed to.
                xeps::stories::fetch(w, &self.store, cfg, None).await;
                if let Ok(roster) = self.store.roster(account_id).await {
                    for item in roster {
                        if matches!(item.subscription.as_str(), "both" | "to") {
                            xeps::stories::fetch(w, &self.store, cfg, Some(&item.jid)).await;
                        }
                    }
                }
                let _ = self.events.send(Event::StoriesUpdated { account_id }).await;
                Ok(())
            }
            Command::RetractStory { account_id, uuid } => {
                xeps::stories::retract(w, &self.store, cfg, &uuid).await?;
                let _ = self.events.send(Event::StoriesUpdated { account_id }).await;
                Ok(())
            }
            Command::FetchFeed { account_id, jid } => {
                xeps::microblog::refresh(w, &self.store, account_id, &self.events, Some(&jid), &jid).await;
                Ok(())
            }
            Command::PublishPost { account_id, title, content, attachment_path, attachment, link, edit } => {
                let attachment = if attachment_path.is_empty() {
                    attachment
                } else {
                    Some(upload_broadcast_media(w, cfg, &attachment_path).await?)
                };
                let extras = xeps::microblog::PostExtras {
                    attachment,
                    link: Some(link).filter(|l| !l.trim().is_empty()),
                    edit,
                };
                xeps::microblog::publish_post(w, cfg, &title, &content, &extras).await?;
                // Re-fetch our own feed so the new post shows up.
                xeps::microblog::refresh(w, &self.store, account_id, &self.events, None, cfg.bare()).await;
                let _ = self
                    .events
                    .send(Event::PublishDone { account_id, what: "post".into(), error: None })
                    .await;
                Ok(())
            }
            Command::FetchComments { account_id, service, node } => {
                let comments = xeps::microblog::fetch_comments(w, &service, &node).await;
                let _ = self.events.send(Event::FeedComments { account_id, service, node, comments }).await;
                Ok(())
            }
            Command::PublishComment { account_id, service, node, content } => {
                xeps::microblog::publish_comment(w, cfg, &service, &node, &content).await?;
                // Re-fetch the comments so the new one shows up.
                let comments = xeps::microblog::fetch_comments(w, &service, &node).await;
                let _ = self.events.send(Event::FeedComments { account_id, service, node, comments }).await;
                Ok(())
            }
            Command::RetractPost { account_id, post_id } => {
                xeps::pep::retract(w, xeps::microblog::NS_MICROBLOG, &post_id).await?;
                let _ = self.store.delete_feed_post(account_id, cfg.bare(), &post_id).await;
                xeps::microblog::refresh(w, &self.store, account_id, &self.events, None, cfg.bare()).await;
                Ok(())
            }
            Command::RetractComment { account_id, service, node, comment_id } => {
                xeps::microblog::retract_comment(w, &service, &node, &comment_id).await?;
                let comments = xeps::microblog::fetch_comments(w, &service, &node).await;
                let _ = self.events.send(Event::FeedComments { account_id, service, node, comments }).await;
                Ok(())
            }
            Command::Connect { .. } | Command::Disconnect { .. } | Command::Shutdown => Ok(()),
        }
    }
}

/// Prepare and upload a file for a public broadcast (Story / feed post attachment): read it,
/// strip its metadata (refusing media that can't be cleaned, see [`crate::media_strip`]) and
/// upload it unencrypted under a random name — the original file name can identify too.
/// Returns the URL and the uploaded type.
async fn upload_broadcast_media(w: &Writer, cfg: &AccountConfig, path: &str) -> anyhow::Result<(String, String)> {
    let bytes = tokio::fs::read(path).await?;
    let ext = std::path::Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .filter(|e| !e.is_empty() && e.len() <= 5 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| "bin".into());
    let fallback = xeps::http_upload::guess_mime(&format!("x.{ext}"));
    let (bytes, mime) =
        tokio::task::spawn_blocking(move || crate::media_strip::prepare_for_broadcast(bytes, fallback)).await??;
    let name = format!("{}.{ext}", xeps::microblog::uuid_v4());
    let url = xeps::http_upload::upload_plain(w, cfg, &bytes, &name, &mime).await?;
    Ok((url, mime))
}

/// The fingerprint to display for one OMEMO2 device: the *hybrid* (classical + ML-DSA-87)
/// fingerprint when a post-quantum identity is pinned for it, otherwise the classical one
/// (e.g. a device we have only just seen but not yet built a session toward). `identity_key`
/// is the device's serialized (33-byte) classical identity key.
///
/// `jid` is the bare JID that owns the key — required, because the pin is scoped to it (a
/// classical `<ik>` is public, so a fingerprint alone does not name one device's pin).
async fn device_fingerprint(
    store: &Store,
    account_id: i64,
    jid: &str,
    identity_key: &[u8],
) -> String {
    let pin_key = mxc_omemo::pq_pin_key(identity_key);
    match store
        .get_pinned_omemo2_pq_identity(account_id, jid, &pin_key)
        .await
        .ok()
        .flatten()
    {
        Some(pq) => mxc_omemo::hybrid_fingerprint_display(identity_key, &pq),
        None => mxc_omemo::fingerprint(identity_key),
    }
}
