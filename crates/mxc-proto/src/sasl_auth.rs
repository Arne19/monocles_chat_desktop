//! SASL login with the client rules of XEP-0440 (SASL Channel-Binding Type Capability) v1.0.0 and
//! XEP-0474 (SASL SCRAM Downgrade Protection) v0.5.0. Same policy as monocles Android.
//!
//! This replaces tokio-xmpp's built-in login, which tries a fixed list (SCRAM-SHA-256,
//! SCRAM-SHA-1, PLAIN, ANONYMOUS) and has several gaps: on TLS 1.3 both SCRAM variants are
//! renamed `-PLUS`, so a server without channel binding was authenticated with PLAIN; the
//! announced channel-binding types were ignored; there was no downgrade protection hash and no
//! pinning, so a stripped mechanism list went unnoticed; and the SCRAM server signature (`v=`)
//! was never verified.
//!
//! [`plan`] decides what to do from the announcements (pure, unit tested); [`login`] runs it.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::str::FromStr;

use base64::Engine;
use futures::{SinkExt, StreamExt};
use sasl::client::mechanisms::{Plain, Scram};
use sasl::client::Mechanism;
use sasl::common::scram::{Sha1, Sha256};
use sasl::common::ChannelBinding;
use sha2::Digest;
use tokio_xmpp::connect::ServerConnector;
use tokio_xmpp::jid::Jid;
use tokio_xmpp::xmlstream::{
    FallibleStreamElement, ReadError, StreamHeader, Timeouts, XmppStream, XmppStreamElement,
};
use xmpp_parsers::sasl::{Auth, Mechanism as XmppMechanism, Nonza, Response};
use xmpp_parsers::sasl_cb::Type as BindingType;
use xmpp_parsers::stream_features::StreamFeatures;

/// Lowest priority of a SCRAM mechanism. Once one of these (or better) was used, PLAIN is never
/// accepted again for the account (XEP-0474 §6).
pub const SCRAM_MIN_PRIORITY: i32 = 20;

/// RFC 5802 recommends at least 4096 iterations; the upper bound keeps a hostile server from
/// making key derivation take minutes.
const MIN_ITERATIONS: u32 = 4096;
const MAX_ITERATIONS: u32 = 10_000_000;

const SEPARATOR: char = '\u{1e}';
const SEPARATOR_MECHANISMS_BINDINGS: char = '\u{1f}';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mech {
    ScramSha256Plus,
    ScramSha1Plus,
    ScramSha256,
    ScramSha1,
    Plain,
}

impl Mech {
    pub fn name(self) -> &'static str {
        match self {
            Mech::ScramSha256Plus => "SCRAM-SHA-256-PLUS",
            Mech::ScramSha1Plus => "SCRAM-SHA-1-PLUS",
            Mech::ScramSha256 => "SCRAM-SHA-256",
            Mech::ScramSha1 => "SCRAM-SHA-1",
            Mech::Plain => "PLAIN",
        }
    }

    /// Same scale as monocles Android's `SaslMechanism.getPriority()`.
    pub fn priority(self) -> i32 {
        match self {
            Mech::ScramSha256Plus => 40,
            Mech::ScramSha1Plus => 35,
            Mech::ScramSha256 => 25,
            Mech::ScramSha1 => 20,
            Mech::Plain => 10,
        }
    }

    pub fn is_scram(self) -> bool {
        self != Mech::Plain
    }

    fn uses_sha1(self) -> bool {
        matches!(self, Mech::ScramSha1 | Mech::ScramSha1Plus)
    }
}

/// The GS2 channel-binding flag sent in the SCRAM client-first-message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gs2 {
    /// `p=tls-exporter`: channel binding in use.
    Plus,
    /// `y`: we support channel binding but the server doesn't seem to.
    Y,
    /// `n`: no channel binding on this connection.
    N,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub mech: Mech,
    pub gs2: Gs2,
    /// Authentication fails unless the server-first-message carries a matching XEP-0474 hash.
    pub require_ssdp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("no supported SASL mechanism offered ({0})")]
    NoMechanism(String),
    #[error("possible downgrade attack: {0}")]
    Downgrade(String),
    #[error("{0}")]
    Invalid(String),
}

fn offered(mechanisms: &BTreeSet<String>, mech: Mech) -> bool {
    mechanisms.contains(mech.name())
}

/// Decide how to authenticate (SASL1).
///
/// * `bindings`: the XEP-0440 announcement, `None` if the server sent none.
/// * `exporter_available`: tls-exporter data exists for this connection (TLS 1.3).
/// * `pinned`: priority of the strongest mechanism used for this account so far, or -1.
pub fn plan(
    mechanisms: &BTreeSet<String>,
    bindings: Option<&[BindingType]>,
    exporter_available: bool,
    pinned: i32,
) -> Result<Plan, Refusal> {
    let plus_offered = offered(mechanisms, Mech::ScramSha256Plus) || offered(mechanisms, Mech::ScramSha1Plus);
    let bindings_announced = bindings.is_some_and(|b| !b.is_empty());
    // tls-exporter is the only binding we can compute. Without an announcement (rule 4 is
    // undefined for SASL1) we may still try it.
    let binding_usable = exporter_available
        && (!bindings_announced || bindings.is_some_and(|b| b.contains(&BindingType::TlsExporter)));
    // Rule 6 as relaxed by XEP-0474: PLUS and types announced, none usable -> continue without
    // channel binding, but only with a valid downgrade protection hash.
    let without_binding = plus_offered && bindings_announced && !binding_usable;
    // Rules 4 and 5 only demand an abort with SASL2; with SASL1 a non-PLUS login sends "y", so
    // a server that really supports channel binding refuses it.

    let (mech, gs2) = if plus_offered && binding_usable {
        if offered(mechanisms, Mech::ScramSha256Plus) {
            (Mech::ScramSha256Plus, Gs2::Plus)
        } else {
            (Mech::ScramSha1Plus, Gs2::Plus)
        }
    } else if let Some(mech) = [Mech::ScramSha256, Mech::ScramSha1]
        .into_iter()
        .find(|m| offered(mechanisms, *m))
    {
        let gs2 = if without_binding || !exporter_available { Gs2::N } else { Gs2::Y };
        (mech, gs2)
    } else if offered(mechanisms, Mech::Plain) {
        if without_binding {
            return Err(Refusal::Downgrade(
                "no usable channel binding and PLAIN cannot prove the announced lists".into(),
            ));
        }
        (Mech::Plain, Gs2::N)
    } else {
        return Err(Refusal::NoMechanism(
            mechanisms.iter().cloned().collect::<Vec<_>>().join(", "),
        ));
    };

    let mut require_ssdp = without_binding;
    if pinned > mech.priority() {
        if mech.is_scram() {
            // XEP-0474 v0.5.0: don't pin a concrete SCRAM mechanism - a weaker one is fine
            // once the server's hash proves the announced lists genuine.
            require_ssdp = true;
        } else {
            return Err(Refusal::Downgrade(format!(
                "{} after a stronger mechanism was used for this account",
                mech.name()
            )));
        }
    }
    Ok(Plan { mech, gs2, require_ssdp })
}

fn binding_name(binding: &BindingType) -> &'static str {
    match binding {
        BindingType::TlsUnique => "tls-unique",
        BindingType::TlsServerEndPoint => "tls-server-end-point",
        BindingType::TlsUniqueForTelnet => "tls-unique-for-telnet",
        BindingType::TlsExporter => "tls-exporter",
    }
}

/// The XEP-0474 hash input: the sorted mechanisms, and - if the server used XEP-0440 - the
/// sorted channel-binding types ("i;octet" collation, i.e. byte order).
pub fn ssdp_input(
    mechanisms: &BTreeSet<String>,
    bindings: Option<&[BindingType]>,
) -> Result<String, Refusal> {
    for m in mechanisms {
        if m.is_empty() || m.contains(SEPARATOR) || m.contains(SEPARATOR_MECHANISMS_BINDINGS) {
            return Err(Refusal::Invalid("illegal SASL mechanism name".into()));
        }
    }
    // BTreeSet<String> iterates in byte order.
    let mut out = mechanisms.iter().map(String::as_str).collect::<Vec<_>>().join(&SEPARATOR.to_string());
    if let Some(bindings) = bindings {
        let mut names: Vec<&str> = bindings.iter().map(binding_name).collect();
        names.sort_unstable();
        out.push(SEPARATOR_MECHANISMS_BINDINGS);
        out.push_str(&names.join(&SEPARATOR.to_string()));
    }
    Ok(out)
}

fn ssdp_hash(mech: Mech, input: &str) -> String {
    let digest = if mech.uses_sha1() {
        sha1::Sha1::digest(input.as_bytes()).to_vec()
    } else {
        sha2::Sha256::digest(input.as_bytes()).to_vec()
    };
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// The value of attribute `key` in a SCRAM message; duplicates are refused.
fn scram_attribute(message: &[u8], key: char) -> Result<Option<String>, Refusal> {
    let text = std::str::from_utf8(message).map_err(|_| Refusal::Invalid("server-first-message is not UTF-8".into()))?;
    let mut found = None;
    for part in text.split(',') {
        let mut chars = part.chars();
        if chars.next() == Some(key) && chars.next() == Some('=') {
            if found.is_some() {
                return Err(Refusal::Invalid(format!("duplicate '{key}' attribute")));
            }
            found = Some(part[2..].to_string());
        }
    }
    Ok(found)
}

/// Checks on the SCRAM server-first-message before it is answered: the iteration count and the
/// XEP-0474 hash. A mismatching hash is always a downgrade; a missing one when `required`.
pub fn check_server_first(
    server_first: &[u8],
    mech: Mech,
    ssdp_input: &str,
    required: bool,
) -> Result<(), Refusal> {
    let iterations = scram_attribute(server_first, 'i')?
        .and_then(|i| i.parse::<u32>().ok())
        .ok_or_else(|| Refusal::Invalid("server did not send an iteration count".into()))?;
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(Refusal::Invalid(format!("unacceptable SCRAM iteration count {iterations}")));
    }
    match scram_attribute(server_first, 'h')? {
        Some(h) if h == ssdp_hash(mech, ssdp_input) => Ok(()),
        Some(_) => Err(Refusal::Downgrade("mismatch in the downgrade protection hash (XEP-0474)".into())),
        None if required => Err(Refusal::Downgrade(
            "the server did not send a downgrade protection hash (XEP-0474) although one was required".into(),
        )),
        None => Ok(()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error(transparent)]
    Refused(#[from] Refusal),
    #[error("authentication failed: {0}")]
    Failed(String),
    #[error(transparent)]
    Xmpp(#[from] tokio_xmpp::Error),
}

impl LoginError {
    /// Whether this looks like an active attack rather than a network or credential problem.
    pub fn is_downgrade(&self) -> bool {
        matches!(self, LoginError::Refused(Refusal::Downgrade(_)))
    }
}

fn new_mechanism(
    plan: &Plan,
    username: &str,
    password: &str,
    exporter: ChannelBinding,
) -> Result<Box<dyn Mechanism + Send>, LoginError> {
    let binding = match plan.gs2 {
        Gs2::Plus => exporter,
        Gs2::Y => ChannelBinding::Unsupported,
        Gs2::N => ChannelBinding::None,
    };
    let failed = |e: sasl::Error| LoginError::Failed(format!("{e:?}"));
    Ok(match plan.mech {
        Mech::ScramSha256 | Mech::ScramSha256Plus => {
            Box::new(Scram::<Sha256>::new(username, password.to_owned(), binding).map_err(failed)?)
        }
        Mech::ScramSha1 | Mech::ScramSha1Plus => {
            Box::new(Scram::<Sha1>::new(username, password.to_owned(), binding).map_err(failed)?)
        }
        Mech::Plain => Box::new(Plain::new(username, password)),
    })
}

/// Connect, authenticate by [`plan`] and restart the stream: a stream ready for resource
/// binding, plus the mechanism priority to pin on success.
pub async fn login<C: ServerConnector>(
    server: C,
    jid: Jid,
    password: &str,
    timeouts: Timeouts,
    pinned: i32,
) -> Result<(StreamFeatures, XmppStream<C::Stream>, Mech), LoginError> {
    let username = jid
        .node()
        .ok_or_else(|| LoginError::Failed("the account JID has no local part".into()))?
        .as_str()
        .to_owned();
    let (pending, exporter) = server.connect(&jid, xmpp_parsers::ns::JABBER_CLIENT, timeouts).await?;
    let (features, mut stream) = pending
        .recv_features::<FallibleStreamElement>()
        .await
        .map_err(|e| LoginError::Failed(format!("receiving stream features: {e}")))?;
    let bindings = features.sasl_cb.as_ref().map(|cb| cb.types.as_slice());
    let exporter_available = matches!(exporter, ChannelBinding::TlsExporter(_));
    let plan = plan(&features.sasl_mechanisms, bindings, exporter_available, pinned)?;
    let ssdp_input = ssdp_input(&features.sasl_mechanisms, bindings)?;
    tracing::info!(
        mechanism = plan.mech.name(),
        gs2 = ?plan.gs2,
        require_ssdp = plan.require_ssdp,
        "authenticating"
    );

    let mut mechanism = new_mechanism(&plan, &username, password, exporter)?;
    let mechanism_name =
        XmppMechanism::from_str(plan.mech.name()).map_err(|e| LoginError::Failed(e.to_string()))?;
    stream
        .send(&XmppStreamElement::Sasl(Nonza::Auth(Auth {
            mechanism: mechanism_name,
            data: mechanism.initial(),
        })))
        .await
        .map_err(tokio_xmpp::Error::Io)?;

    let mut first_challenge = true;
    loop {
        let element = match stream.next().await {
            None => return Err(tokio_xmpp::Error::Disconnected.into()),
            Some(Err(ReadError::SoftTimeout)) => continue,
            Some(Err(ReadError::HardError(e))) => return Err(tokio_xmpp::Error::Io(e).into()),
            Some(Err(ReadError::ParseError(e))) => {
                return Err(LoginError::Failed(format!("parse error during SASL: {e}")))
            }
            Some(Err(ReadError::StreamFooterReceived)) => return Err(tokio_xmpp::Error::Disconnected.into()),
            Some(Ok(element)) => element
                .into_read_error()
                .map_err(|e| LoginError::Failed(format!("unexpected element during SASL: {e:?}")))?,
        };
        match element {
            XmppStreamElement::Sasl(Nonza::Challenge(challenge)) => {
                if first_challenge && plan.mech.is_scram() {
                    check_server_first(&challenge.data, plan.mech, &ssdp_input, plan.require_ssdp)?;
                }
                first_challenge = false;
                let data = mechanism
                    .response(&challenge.data)
                    .map_err(|e| LoginError::Failed(format!("{e:?}")))?;
                stream
                    .send(&XmppStreamElement::Sasl(Nonza::Response(Response { data })))
                    .await
                    .map_err(tokio_xmpp::Error::Io)?;
            }
            XmppStreamElement::Sasl(Nonza::Success(success)) => {
                // Mutual authentication: the server must prove it knows the password too.
                mechanism
                    .success(&success.data)
                    .map_err(|e| LoginError::Failed(format!("server signature not verified: {e:?}")))?;
                break;
            }
            XmppStreamElement::Sasl(Nonza::Failure(failure)) => {
                return Err(LoginError::Failed(format!("{:?}", failure.defined_condition)));
            }
            XmppStreamElement::Sasl(_) => {}
            other => return Err(LoginError::Failed(format!("unexpected element during SASL: {other:?}"))),
        }
    }

    let stream = stream
        .initiate_reset()
        .send_header(StreamHeader {
            to: Some(Cow::Borrowed(jid.domain().as_str())),
            from: None,
            id: None,
        })
        .await
        .map_err(tokio_xmpp::Error::Io)?;
    let (features, stream) = stream
        .recv_features()
        .await
        .map_err(|e| LoginError::Failed(format!("receiving stream features: {e}")))?;
    Ok((features, stream, plan.mech))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mechs(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    const ALL: &[&str] = &["PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"];

    #[test]
    fn prefers_channel_binding_when_usable() {
        let p = plan(&mechs(ALL), Some(&[BindingType::TlsExporter]), true, -1).unwrap();
        assert_eq!(p, Plan { mech: Mech::ScramSha256Plus, gs2: Gs2::Plus, require_ssdp: false });
        let p = plan(&mechs(&["SCRAM-SHA-1", "SCRAM-SHA-1-PLUS"]), None, true, -1).unwrap();
        assert_eq!(p.mech, Mech::ScramSha1Plus);
    }

    /// The old tokio-xmpp login fell through to PLAIN here (both SCRAM names became -PLUS).
    #[test]
    fn tls13_server_without_channel_binding_uses_scram_with_y() {
        let p = plan(&mechs(&["PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256"]), None, true, -1).unwrap();
        assert_eq!(p, Plan { mech: Mech::ScramSha256, gs2: Gs2::Y, require_ssdp: false });
    }

    #[test]
    fn without_tls_exporter_data_scram_sends_n() {
        let p = plan(&mechs(&["SCRAM-SHA-256"]), None, false, -1).unwrap();
        assert_eq!(p.gs2, Gs2::N);
    }

    /// XEP-0474 rule 6: PLUS and types announced, none usable -> "n" plus a required hash.
    #[test]
    fn unusable_announced_binding_continues_without_it_but_requires_ssdp() {
        let p = plan(&mechs(ALL), Some(&[BindingType::TlsServerEndPoint]), true, -1).unwrap();
        assert_eq!(p, Plan { mech: Mech::ScramSha256, gs2: Gs2::N, require_ssdp: true });
        let p = plan(&mechs(ALL), Some(&[BindingType::TlsExporter]), false, -1).unwrap();
        assert_eq!(p, Plan { mech: Mech::ScramSha256, gs2: Gs2::N, require_ssdp: true });
    }

    #[test]
    fn unusable_binding_never_falls_back_to_plain() {
        let r = plan(&mechs(&["PLAIN", "SCRAM-SHA-256-PLUS"]), Some(&[BindingType::TlsServerEndPoint]), true, -1);
        assert!(matches!(r, Err(Refusal::Downgrade(_))));
    }

    #[test]
    fn plain_is_allowed_only_before_scram_was_used() {
        assert_eq!(plan(&mechs(&["PLAIN"]), None, true, -1).unwrap().mech, Mech::Plain);
        let r = plan(&mechs(&["PLAIN"]), None, true, Mech::ScramSha1.priority());
        assert!(matches!(r, Err(Refusal::Downgrade(_))));
    }

    /// XEP-0474 v0.5.0: a weaker SCRAM variant is accepted, but only with a valid hash.
    #[test]
    fn weaker_scram_than_pinned_requires_ssdp() {
        let p = plan(&mechs(&["SCRAM-SHA-1"]), None, true, Mech::ScramSha256Plus.priority()).unwrap();
        assert_eq!(p.mech, Mech::ScramSha1);
        assert!(p.require_ssdp);
        let p = plan(&mechs(ALL), Some(&[BindingType::TlsExporter]), true, Mech::ScramSha256Plus.priority()).unwrap();
        assert!(!p.require_ssdp);
    }

    #[test]
    fn nothing_supported() {
        assert!(matches!(plan(&mechs(&["ANONYMOUS"]), None, true, -1), Err(Refusal::NoMechanism(_))));
    }

    /// The example of XEP-0474 §4.
    #[test]
    fn ssdp_hash_matches_the_spec_example() {
        let input = ssdp_input(
            &mechs(&["SCRAM-SHA-1", "SCRAM-SHA-1-PLUS"]),
            Some(&[BindingType::TlsServerEndPoint, BindingType::TlsExporter]),
        )
        .unwrap();
        assert_eq!(ssdp_hash(Mech::ScramSha1Plus, &input), "G6k/rBLDqgOhRRaCuuatSDFkJ08=");
    }

    #[test]
    fn ssdp_input_without_xep0440_has_no_binding_part() {
        let input = ssdp_input(&mechs(&["SCRAM-SHA-256", "PLAIN"]), None).unwrap();
        assert_eq!(input, "PLAIN\u{1e}SCRAM-SHA-256");
    }

    fn server_first(extra: &str) -> Vec<u8> {
        format!("r=abc123,s=QSXCR+Q6sek8bf92,i=4096{extra}").into_bytes()
    }

    #[test]
    fn server_first_checks() {
        let input = ssdp_input(&mechs(&["SCRAM-SHA-256"]), None).unwrap();
        let h = ssdp_hash(Mech::ScramSha256, &input);
        assert!(check_server_first(&server_first(""), Mech::ScramSha256, &input, false).is_ok());
        assert!(matches!(
            check_server_first(&server_first(""), Mech::ScramSha256, &input, true),
            Err(Refusal::Downgrade(_))
        ));
        assert!(check_server_first(&server_first(&format!(",h={h}")), Mech::ScramSha256, &input, true).is_ok());
        assert!(matches!(
            check_server_first(&server_first(",h=AAAA"), Mech::ScramSha256, &input, false),
            Err(Refusal::Downgrade(_))
        ));
        assert!(matches!(
            check_server_first(&server_first(&format!(",h={h},h={h}")), Mech::ScramSha256, &input, false),
            Err(Refusal::Invalid(_))
        ));
    }

    #[test]
    fn iteration_count_bounds() {
        let input = ssdp_input(&mechs(&["SCRAM-SHA-256"]), None).unwrap();
        let low = b"r=abc,s=QSXCR+Q6sek8bf92,i=1000".to_vec();
        let high = b"r=abc,s=QSXCR+Q6sek8bf92,i=4000000000".to_vec();
        assert!(check_server_first(&low, Mech::ScramSha256, &input, false).is_err());
        assert!(check_server_first(&high, Mech::ScramSha256, &input, false).is_err());
    }

    // ---- end to end: login() against a scripted server over an in-memory pipe ----

    use std::sync::{Arc, Mutex};
    use tokio::io::{BufStream, DuplexStream};
    use tokio_xmpp::xmlstream::{accept_stream, initiate_stream, PendingFeaturesRecv};

    type Pipe = BufStream<DuplexStream>;

    #[derive(Clone, Debug)]
    struct FakeConnector(Arc<Mutex<Option<Pipe>>>);

    impl ServerConnector for FakeConnector {
        type Stream = Pipe;
        async fn connect(
            &self,
            jid: &Jid,
            ns: &'static str,
            timeouts: Timeouts,
        ) -> Result<(PendingFeaturesRecv<Pipe>, ChannelBinding), tokio_xmpp::Error> {
            let io = self.0.lock().unwrap().take().expect("connect called once");
            let header = StreamHeader { to: Some(Cow::Owned(jid.domain().to_string())), from: None, id: None };
            Ok((initiate_stream(io, ns, header, timeouts).await?, ChannelBinding::None))
        }
    }

    /// What the client sent: the mechanism, its initial response, and the SCRAM client-final
    /// message if it got that far.
    #[derive(Debug, Default)]
    struct Seen {
        mechanism: Option<String>,
        initial: Vec<u8>,
        client_final: Option<Vec<u8>>,
    }

    /// Serve one login attempt. `h` is the downgrade protection attribute to put into the
    /// server-first-message (None: omit it). Answers the client-final with a bogus signature.
    async fn serve(io: Pipe, mechanisms: &[&str], h: Option<String>, sign: bool) -> Seen {
        let mut seen = Seen::default();
        let accepted = accept_stream(io, xmpp_parsers::ns::JABBER_CLIENT, Timeouts::default()).await.unwrap();
        let pending = accepted
            .send_header(StreamHeader { to: None, from: Some(Cow::Borrowed("example.org")), id: Some(Cow::Borrowed("s1")) })
            .await
            .unwrap();
        let features = StreamFeatures { sasl_mechanisms: mechs(mechanisms), ..Default::default() };
        let mut stream = pending.send_features::<XmppStreamElement>(&features).await.unwrap();
        let mut client_first_bare = String::new();
        let mut server_first_sent = String::new();
        while let Some(Ok(element)) = stream.next().await {
            match element {
                XmppStreamElement::Sasl(Nonza::Auth(auth)) => {
                    seen.mechanism = Some(format!("{:?}", auth.mechanism));
                    seen.initial = auth.data.clone();
                    let client_first = String::from_utf8(auth.data).unwrap();
                    let nonce = client_first.split("r=").nth(1).unwrap().to_string();
                    let mut server_first = format!("r={nonce}srv,s=QSXCR+Q6sek8bf92,i=4096");
                    if let Some(h) = &h {
                        server_first.push_str(&format!(",h={h}"));
                    }
                    client_first_bare = client_first.splitn(3, ',').nth(2).unwrap().to_string();
                    server_first_sent = server_first.clone();
                    let challenge = xmpp_parsers::sasl::Challenge { data: server_first.into_bytes() };
                    stream.send(&XmppStreamElement::Sasl(Nonza::Challenge(challenge))).await.unwrap();
                }
                XmppStreamElement::Sasl(Nonza::Response(response)) => {
                    let client_final = String::from_utf8(response.data.clone()).unwrap();
                    seen.client_final = Some(response.data);
                    let v = if sign {
                        let without_proof = client_final.rsplit_once(",p=").unwrap().0;
                        let auth_message = format!("{client_first_bare},{server_first_sent},{without_proof}");
                        server_signature_sha256("password", b"QSXCR+Q6sek8bf92", &auth_message)
                    } else {
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()
                    };
                    let success = xmpp_parsers::sasl::Success { data: format!("v={v}").into_bytes() };
                    stream.send(&XmppStreamElement::Sasl(Nonza::Success(success))).await.unwrap();
                }
                _ => {}
            }
        }
        seen
    }

    async fn run(mechanisms: &[&str], h: Option<String>, pinned: i32, sign: bool) -> (Result<Mech, String>, Seen) {
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let connector = FakeConnector(Arc::new(Mutex::new(Some(BufStream::new(client_io)))));
        let jid: Jid = "alice@example.org".parse().unwrap();
        let client = async move {
            login(connector, jid, "password", Timeouts::default(), pinned)
                .await
                .map(|(_, _, mech)| mech)
                .map_err(|e| e.to_string())
        };
        let server = serve(BufStream::new(server_io), mechanisms, h, sign);
        tokio::time::timeout(std::time::Duration::from_secs(10), async { tokio::join!(client, server) })
            .await
            .expect("login finished")
    }

    /// RFC 5802 ServerSignature for SCRAM-SHA-256 (salt is base64 as sent).
    fn server_signature_sha256(password: &str, salt_b64: &[u8], auth_message: &str) -> String {
        use hmac::{Hmac, Mac};
        type H = Hmac<sha2::Sha256>;
        let b64 = base64::engine::general_purpose::STANDARD;
        let salt = b64.decode(salt_b64).unwrap();
        let mac = |key: &[u8], data: &[u8]| {
            let mut m = H::new_from_slice(key).unwrap();
            m.update(data);
            m.finalize().into_bytes().to_vec()
        };
        // Hi(): PBKDF2-HMAC-SHA256, one block
        let mut u = mac(password.as_bytes(), &[salt.as_slice(), &[0, 0, 0, 1]].concat());
        let mut salted = u.clone();
        for _ in 1..4096 {
            u = mac(password.as_bytes(), &u);
            salted.iter_mut().zip(&u).for_each(|(a, b)| *a ^= b);
        }
        let server_key = mac(&salted, b"Server Key");
        b64.encode(mac(&server_key, auth_message.as_bytes()))
    }

    /// A correct server signature passes; login then restarts the stream (the scripted server
    /// stops there, so the error comes from the restart - after authentication succeeded).
    #[tokio::test]
    async fn e2e_valid_server_signature_is_accepted() {
        let (result, seen) = run(&["SCRAM-SHA-256"], None, -1, true).await;
        assert!(seen.client_final.is_some());
        let err = result.unwrap_err();
        // the scripted server closes instead of answering the restarted stream header
        assert!(err.starts_with("I/O error") && err.contains("eof"), "{err}");
    }

    fn hash_for(mechanisms: &[&str], mech: Mech) -> String {
        ssdp_hash(mech, &ssdp_input(&mechs(mechanisms), None).unwrap())
    }

    /// Without TLS binding data a plain SCRAM login is "n"; the bogus server signature is caught.
    #[tokio::test]
    async fn e2e_scram_without_binding_and_server_signature_is_verified() {
        let offered = ["PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256"];
        let (result, seen) = run(&offered, None, -1, false).await;
        assert!(seen.mechanism.unwrap().contains("ScramSha256"));
        assert!(seen.initial.starts_with(b"n,,n=alice,r="));
        assert!(seen.client_final.is_some(), "client answered the server-first-message");
        let err = result.unwrap_err();
        assert!(err.contains("server signature not verified"), "{err}");
    }

    /// Pinned to a stronger mechanism: a weaker SCRAM without the hash is refused before the
    /// client-final-message (and thus any proof of the password) is sent.
    #[tokio::test]
    async fn e2e_weaker_scram_without_hash_is_refused() {
        let (result, seen) = run(&["SCRAM-SHA-1"], None, Mech::ScramSha256.priority(), false).await;
        assert!(result.unwrap_err().contains("downgrade"));
        assert!(seen.client_final.is_none());
    }

    #[tokio::test]
    async fn e2e_weaker_scram_with_matching_hash_proceeds() {
        let offered = ["SCRAM-SHA-1"];
        let h = hash_for(&offered, Mech::ScramSha1);
        let (result, seen) = run(&offered, Some(h), Mech::ScramSha256.priority(), false).await;
        assert!(seen.client_final.is_some());
        // proceeds to the (bogus) server signature, which still fails
        assert!(result.unwrap_err().contains("server signature"));
    }

    #[tokio::test]
    async fn e2e_mismatching_hash_is_a_downgrade() {
        let (result, seen) = run(&["SCRAM-SHA-256"], Some("AAAA".into()), -1, false).await;
        assert!(result.unwrap_err().contains("downgrade"));
        assert!(seen.client_final.is_none());
    }

    /// After SCRAM was used, a server offering only PLAIN never sees the password.
    #[tokio::test]
    async fn e2e_plain_after_scram_is_never_sent() {
        let (result, seen) = run(&["PLAIN"], None, Mech::ScramSha1.priority(), false).await;
        assert!(result.unwrap_err().contains("downgrade"));
        assert!(seen.mechanism.is_none(), "no <auth/> was sent");
    }

}
