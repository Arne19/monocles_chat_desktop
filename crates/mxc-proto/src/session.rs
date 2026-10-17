//! The XMPP session: tokio-xmpp's [`StanzaStream`] (reconnection, XEP-0198 resumption, resource
//! binding) fed by our own login ([`crate::sasl_auth`]) instead of tokio-xmpp's.
//!
//! tokio-xmpp's `Client` hard-wires its own SASL step, so this replaces it with the small part of
//! it the core used: `next()` (online / resumed / stanza) and `send_stanza()`.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::{mpsc, oneshot};
use tokio_xmpp::connect::ServerConnector;
use tokio_xmpp::jid::Jid;
use tokio_xmpp::stanzastream::{Connection, Event, StanzaStage, StanzaState, StanzaStream, StreamEvent};
use tokio_xmpp::xmlstream::Timeouts;
use tokio_xmpp::Stanza;

use crate::sasl_auth::{self, LoginError};

/// What the login task reports back to the core.
#[derive(Debug, Clone)]
pub enum LoginNotice {
    /// Authenticated with a mechanism of this priority; remember it for the account.
    Pinned(i32),
    /// Authentication was refused for a security reason (likely an active attack).
    Refused(String),
}

pub enum SessionEvent {
    Online { bound_jid: Jid, resumed: bool },
    Stanza(Stanza),
}

pub struct Session {
    stream: StanzaStream,
    bound_jid: Option<Jid>,
}

const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
/// After a refused (security) login retry much less eagerly.
const REFUSED_RETRY_DELAY: Duration = Duration::from_secs(300);

impl Session {
    /// `pinned` holds the priority of the strongest mechanism used for the account so far
    /// (-1: none) and is updated on every successful login.
    pub fn new<C: ServerConnector>(
        jid: Jid,
        password: zeroize::Zeroizing<String>,
        connector: C,
        timeouts: Timeouts,
        pinned: Arc<AtomicI32>,
        notices: mpsc::UnboundedSender<LoginNotice>,
    ) -> Self {
        let reconnector = Box::new(move |_location: Option<String>, slot: oneshot::Sender<Connection>| {
            let jid = jid.clone();
            let connector = connector.clone();
            let password = password.clone();
            let pinned = pinned.clone();
            let notices = notices.clone();
            tokio::spawn(async move {
                let mut delay = Duration::from_secs(1);
                loop {
                    let pin = pinned.load(Ordering::SeqCst);
                    match sasl_auth::login(connector.clone(), jid.clone(), &password, timeouts, pin).await {
                        Ok((features, stream, mech)) => {
                            if mech.priority() != pin {
                                pinned.store(mech.priority(), Ordering::SeqCst);
                                let _ = notices.send(LoginNotice::Pinned(mech.priority()));
                            }
                            // If the StanzaStream is gone the fresh stream is simply dropped.
                            let _ = slot.send(Connection {
                                stream: stream.box_stream(),
                                features,
                                identity: jid,
                            });
                            return;
                        }
                        Err(e) => {
                            let refused = matches!(e, LoginError::Refused(_));
                            if refused {
                                tracing::error!(error = %e, "login refused");
                                let _ = notices.send(LoginNotice::Refused(e.to_string()));
                            } else {
                                tracing::warn!(error = %e, ?delay, "login failed, retrying");
                            }
                            tokio::time::sleep(if refused { REFUSED_RETRY_DELAY } else { delay }).await;
                            delay = (delay * 2).min(MAX_RETRY_DELAY);
                        }
                    }
                }
            });
        });
        Self { stream: StanzaStream::new(reconnector, 16), bound_jid: None }
    }

    /// The next event; `None` when the stream is gone for good.
    pub async fn next(&mut self) -> Option<SessionEvent> {
        loop {
            match self.stream.next().await? {
                Event::Stanza(stanza) => return Some(SessionEvent::Stanza(stanza)),
                Event::Stream(StreamEvent::Reset { bound_jid, .. }) => {
                    self.bound_jid = Some(bound_jid.clone());
                    return Some(SessionEvent::Online { bound_jid, resumed: false });
                }
                Event::Stream(StreamEvent::Resumed) => {
                    if let Some(bound_jid) = self.bound_jid.clone() {
                        return Some(SessionEvent::Online { bound_jid, resumed: true });
                    }
                }
                Event::Stream(StreamEvent::Suspended) => {}
            }
        }
    }

    /// Queue `stanza` and wait until it was written to the stream.
    pub async fn send_stanza(&mut self, mut stanza: Stanza) -> std::io::Result<()> {
        ensure_id(&mut stanza);
        let mut token = self.stream.send(Box::new(stanza)).await;
        match token.wait_for(StanzaStage::Sent).await {
            Some(StanzaState::Sent { .. }) | Some(StanzaState::Acked { .. }) => Ok(()),
            Some(StanzaState::Failed { error }) => Err(error.into_io_error()),
            Some(StanzaState::Queued) | Some(StanzaState::Dropped) | None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "stream disconnected fatally before stanza could be sent",
            )),
        }
    }
}

/// Give a stanza an id if it has none (IQs must have one; XEP-0198 tracking wants one).
fn ensure_id(stanza: &mut Stanza) {
    let fresh = || crate::xeps::roster::new_id("st");
    match stanza {
        Stanza::Iq(iq) => {
            if iq.id().is_empty() {
                *iq.id_mut() = fresh();
            }
        }
        Stanza::Message(message) => {
            message.id.get_or_insert_with(|| xmpp_parsers::message::Id(fresh()));
        }
        Stanza::Presence(presence) => {
            presence.id.get_or_insert_with(fresh);
        }
    }
}
