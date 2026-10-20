//! Connecting to the server, with the same policy as monocles Android:
//!
//! * **DNSSEC**: the SRV (`_xmpps-client` / `_xmpp-client`, XEP-0368) and A/AAAA records are
//!   resolved with a validating resolver. A server endpoint is "DNSSEC verified" when the SRV
//!   *and* address records validated. If validation fails the lookup is retried without it, as
//!   on Android, and the endpoint is simply not verified.
//! * **DANE** (RFC 6698 / RFC 7673): for a DNSSEC-verified endpoint the `_port._tcp.host` TLSA
//!   records are fetched. A DANE-EE match is trusted on its own; a PKIX-EE match still needs
//!   the CA check; TLSA records that match nothing reject the certificate. Without usable
//!   records the normal CA check applies - unless "Enforce DANE" is on, then it fails.
//!   A *bogus* TLSA answer (DNSSEC validation failed, as opposed to an unsigned zone) always
//!   rejects the certificate (RFC 6698 §4.1), like Android's MiniDNS 1.1.3 does.
//! * A lookup only counts as validated when the whole answer chain is: the requested records
//!   *and* any CNAME/DNAME that led to them. Otherwise an unsigned (forged) CNAME could point
//!   into a zone the attacker signs themselves.
//! * **TLS 1.3 only** when "Require TLS 1.3" is on (the default), else TLS 1.2 or 1.3.
//!
//! tokio-xmpp's own connectors build their rustls configuration internally, so none of this can
//! be added to them; this replaces them (direct TLS first, STARTTLS as fallback, like before).

use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use hickory_resolver::proto::rr::rdata::tlsa::{CertUsage, Matching, Selector, TLSA};
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use hickory_resolver::TokioResolver;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sasl::common::ChannelBinding;
use sha2::Digest;
use tokio::io::BufStream;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_xmpp::connect::ServerConnector;
use tokio_xmpp::jid::Jid;
use tokio_xmpp::xmlstream::{
    initiate_stream, FallibleStreamElement, PendingFeaturesRecv, ReadError, StreamHeader, Timeouts,
    XmppStreamElement,
};
use tokio_xmpp::Error;

/// `settings` keys (app-wide, read on every connection attempt).
pub const SETTING_REQUIRE_TLS13: &str = "require_tls_v1_3";
pub const SETTING_ENFORCE_DANE: &str = "enforce_dane";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How the current connection was secured, for the UI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkSecurity {
    pub dnssec: bool,
    pub dane: bool,
    pub tls13: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsPolicy {
    pub require_tls13: bool,
    pub enforce_dane: bool,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self { require_tls13: true, enforce_dane: false }
    }
}

impl TlsPolicy {
    /// The current settings; defaults when unset or unreadable.
    pub async fn load(store: &mxc_store::Store) -> Self {
        let flag = |v: Option<String>, default: bool| v.map(|v| v == "1").unwrap_or(default);
        let d = Self::default();
        Self {
            require_tls13: flag(store.setting(SETTING_REQUIRE_TLS13).await.ok().flatten(), d.require_tls13),
            enforce_dane: flag(store.setting(SETTING_ENFORCE_DANE).await.ok().flatten(), d.enforce_dane),
        }
    }
}

/// The connector handed to the session. Reads the policy from the store on every attempt, so a
/// changed setting applies to the next (re)connection.
#[derive(Clone)]
pub struct SecureConnector {
    store: mxc_store::Store,
    report: Arc<Mutex<LinkSecurity>>,
    /// Built on first use, inside the runtime that connects: hickory runs its connection tasks on
    /// the runtime it was created in, and every login runs its core on a fresh runtime - a
    /// process-wide resolver would outlive it and hang the next login.
    dns: Arc<OnceLock<Resolvers>>,
}

impl SecureConnector {
    pub fn new(store: mxc_store::Store, report: Arc<Mutex<LinkSecurity>>) -> Self {
        Self { store, report, dns: Arc::new(OnceLock::new()) }
    }

    fn resolvers(&self) -> &Resolvers {
        self.dns.get_or_init(Resolvers::new)
    }
}

impl fmt::Debug for SecureConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureConnector").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------------
// DNS

struct Resolvers {
    validating: TokioResolver,
    plain: TokioResolver,
}

impl Resolvers {
    fn new() -> Self {
        let builder = || {
            TokioResolver::builder_tokio().unwrap_or_else(|e| {
                tracing::warn!(error = %e, "no system DNS configuration, using defaults");
                TokioResolver::builder_with_config(
                    hickory_resolver::config::ResolverConfig::default(),
                    hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
                )
            })
        };
        let mut validating = builder();
        validating.options_mut().validate = true;
        validating.options_mut().edns0 = true;
        Resolvers {
            validating: validating.build().expect("validating resolver"),
            plain: builder().build().expect("resolver"),
        }
    }
}

/// The DNSSEC outcome of a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Validation {
    /// The requested records and every CNAME/DNAME leading to them validated.
    Secure,
    /// Unsigned, unvalidated or unavailable: usable, but not DNSSEC-verified.
    Insecure,
    /// DNSSEC validation failed: someone tampered with the answer (or a signature broke).
    Bogus,
}

/// The validation state of a whole answer chain. RRSIGs are only the evidence and carry no
/// state of their own; every other answer record (the requested type plus the CNAMEs/DNAMEs that
/// led there) has to be `Secure`, and a single `Bogus` one makes the whole answer bogus.
fn chain_validation(answers: &[Record], rtype: RecordType) -> Validation {
    let chain = || answers.iter().filter(|r| r.record_type() != RecordType::RRSIG);
    if chain().any(|r| r.proof.is_bogus()) {
        Validation::Bogus
    } else if chain().any(|r| r.record_type() == rtype) && chain().all(|r| r.proof.is_secure()) {
        Validation::Secure
    } else {
        Validation::Insecure
    }
}

/// Records of `rtype` at `name` and the DNSSEC state of the answer.
async fn lookup(dns: &Resolvers, name: &str, rtype: RecordType) -> (Vec<Record>, Validation) {
    let pick = |answers: &[Record]| -> Vec<Record> {
        answers.iter().filter(|r| r.record_type() == rtype).cloned().collect()
    };
    match dns.validating.lookup(name, rtype).await {
        Ok(found) => (pick(found.answers()), chain_validation(found.answers(), rtype)),
        Err(e) if e.is_no_records_found() => (Vec::new(), Validation::Insecure),
        Err(NetError::Dns(DnsError::Nsec { proof, .. })) if proof.is_bogus() => {
            // A denial of existence that failed validation: the records may well exist and be
            // suppressed by an attacker. Callers decide what that means (see `tlsa_records`).
            tracing::debug!(%name, ?rtype, "DNSSEC: bogus denial of existence");
            (Vec::new(), Validation::Bogus)
        }
        Err(e) => {
            // As on Android: a failed validation (or a resolver that strips DNSSEC data) falls
            // back to plain DNS - the endpoint then just isn't verified.
            tracing::debug!(%name, ?rtype, error = %e, "DNSSEC lookup failed, retrying without validation");
            match dns.plain.lookup(name, rtype).await {
                Ok(found) => (pick(found.answers()), Validation::Insecure),
                Err(_) => (Vec::new(), Validation::Insecure),
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Endpoint {
    host: String,
    port: u16,
    direct_tls: bool,
    /// The SRV record named this host with DNSSEC (or there was no SRV: the domain itself).
    name_secure: bool,
    priority: u16,
    weight: u16,
}

async fn endpoints(dns: &Resolvers, domain: &str) -> Vec<Endpoint> {
    let mut out = Vec::new();
    for (service, direct_tls) in [("_xmpps-client", true), ("_xmpp-client", false)] {
        let (records, validation) = lookup(dns, &format!("{service}._tcp.{domain}."), RecordType::SRV).await;
        let secure = validation == Validation::Secure;
        for r in records {
            if let RData::SRV(srv) = &r.data {
                let host = srv.target.to_ascii();
                let host = host.trim_end_matches('.');
                if host.is_empty() {
                    continue; // "." - service decidedly not available
                }
                out.push(Endpoint {
                    host: host.to_string(),
                    port: srv.port,
                    direct_tls,
                    name_secure: secure,
                    priority: srv.priority,
                    weight: srv.weight,
                });
            }
        }
    }
    if out.is_empty() {
        // No SRV: the domain itself, direct TLS on 5223 first (XEP-0368), then STARTTLS on 5222.
        for (port, direct_tls) in [(5223, true), (5222, false)] {
            out.push(Endpoint { host: domain.to_string(), port, direct_tls, name_secure: true, priority: 0, weight: 0 });
        }
    }
    sort_endpoints(&mut out);
    out
}

/// Lowest priority first; at equal priority direct TLS first, then the heavier weight.
fn sort_endpoints(endpoints: &mut [Endpoint]) {
    endpoints.sort_by(|a, b| {
        a.priority.cmp(&b.priority).then(b.direct_tls.cmp(&a.direct_tls)).then(b.weight.cmp(&a.weight))
    });
}

/// The endpoint's addresses and whether they all validated.
async fn addresses(dns: &Resolvers, host: &str) -> (Vec<IpAddr>, bool) {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return (vec![ip], false);
    }
    let (v6, v6_validation) = lookup(dns, &format!("{host}."), RecordType::AAAA).await;
    let (v4, v4_validation) = lookup(dns, &format!("{host}."), RecordType::A).await;
    let (v6_secure, v4_secure) = (v6_validation == Validation::Secure, v4_validation == Validation::Secure);
    let mut ips = Vec::new();
    for r in v6.iter().chain(v4.iter()) {
        match &r.data {
            RData::AAAA(a) => ips.push(IpAddr::V6(a.0)),
            RData::A(a) => ips.push(IpAddr::V4(a.0)),
            _ => {}
        }
    }
    let secure = !ips.is_empty() && (v6.is_empty() || v6_secure) && (v4.is_empty() || v4_secure);
    (ips, secure)
}

/// The TLSA records of an endpoint, as far as DANE is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tlsa {
    /// DNSSEC-validated records.
    Validated(Vec<TLSA>),
    /// None, or not validated (unsigned zone, no DNSSEC endpoint): DANE does not apply.
    Unavailable,
    /// The TLSA answer failed DNSSEC validation: the connection must be aborted.
    Bogus,
}

/// How often a bogus TLSA answer is looked up again before the connection is refused.
const BOGUS_TLSA_RETRIES: usize = 2;

/// The TLSA records for `host:port`.
async fn tlsa_records(dns: &Resolvers, host: &str, port: u16) -> Tlsa {
    let name = format!("_{port}._tcp.{host}.");
    let first = lookup(dns, &name, RecordType::TLSA).await;
    // Each retry gets a fresh resolver: `clear_cache()` would leave hickory's DNSSEC
    // validation cache - and so the bogus verdict - in place.
    let retry = || {
        let name = &name;
        async move { lookup(&Resolvers::new(), name, RecordType::TLSA).await }
    };
    settle_tlsa(host, port, first, retry).await
}

/// Decide what a TLSA lookup means for DANE. A bogus answer is retried (`retry`, at most
/// [`BOGUS_TLSA_RETRIES`] times) because the system resolvers can disagree: on networks where
/// one of them strips DNSSEC data, the SRV/A lookups may validate while the TLSA answer happens
/// to come from the stripping one and is bogus, which would refuse a correctly configured
/// server. Only an **upgrade** counts: a retry that validates (`Secure`) is used; anything else,
/// including an `Insecure` plain-DNS fallback, keeps the answer bogus. Otherwise an attacker
/// could turn a forgery into "DANE does not apply" by also making the validating lookup fail.
/// A real forgery is bogus on every attempt, so it is still refused.
async fn settle_tlsa<F, Fut>(host: &str, port: u16, first: (Vec<Record>, Validation), mut retry: F) -> Tlsa
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = (Vec<Record>, Validation)>,
{
    match first.1 {
        Validation::Secure => return validated_tlsa(&first.0),
        Validation::Insecure => return Tlsa::Unavailable,
        Validation::Bogus => {}
    }
    for attempt in 1..=BOGUS_TLSA_RETRIES {
        let (records, validation) = retry().await;
        if validation == Validation::Secure {
            tracing::warn!(
                %host,
                port,
                attempt,
                "DANE: the TLSA answer was bogus on one resolver but validated on retry; a resolver \
                 on this network may strip DNSSEC data"
            );
            return validated_tlsa(&records);
        }
    }
    tracing::warn!(%host, port, "DANE: the TLSA answer failed DNSSEC validation");
    Tlsa::Bogus
}

fn validated_tlsa(records: &[Record]) -> Tlsa {
    Tlsa::Validated(
        records
            .iter()
            .filter_map(|r| match &r.data {
                RData::TLSA(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------------------------
// DANE

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaneResult {
    /// A DANE-EE (usage 3) record matched: trusted without the CA check.
    DaneEe,
    /// A PKIX-EE (usage 1) record matched: the CA check must pass too.
    PkixEe,
    /// Usable records exist but none matched: reject.
    Mismatch,
    /// No validated or usable records: the normal CA check applies.
    NotApplicable,
}

/// RFC 6698 matching of the end-entity certificate against validated TLSA records. Only the
/// end-entity usages (1, 3) are supported, like monocles Android.
pub fn evaluate_dane(cert_der: &[u8], records: Option<&[TLSA]>) -> DaneResult {
    let Some(records) = records else { return DaneResult::NotApplicable };
    let mut usable = false;
    let mut pkix_ee = false;
    for r in records {
        if !matches!(r.cert_usage, CertUsage::DaneEe | CertUsage::PkixEe) {
            continue;
        }
        let selected: Vec<u8> = match r.selector {
            Selector::Full => cert_der.to_vec(),
            Selector::Spki => match spki(cert_der) {
                Some(s) => s,
                None => {
                    usable = true; // an unparsable certificate can't match
                    continue;
                }
            },
            _ => continue,
        };
        let association: Vec<u8> = match r.matching {
            Matching::Raw => selected,
            Matching::Sha256 => sha2::Sha256::digest(&selected).to_vec(),
            Matching::Sha512 => sha2::Sha512::digest(&selected).to_vec(),
            _ => continue,
        };
        usable = true;
        if association == r.cert_data {
            if r.cert_usage == CertUsage::DaneEe {
                return DaneResult::DaneEe;
            }
            pkix_ee = true;
        }
    }
    if pkix_ee {
        DaneResult::PkixEe
    } else if usable {
        DaneResult::Mismatch
    } else {
        DaneResult::NotApplicable
    }
}

/// The DER of the certificate's SubjectPublicKeyInfo.
fn spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    Some(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// rustls certificate verification with DANE in front of the CA (webpki) check.
#[derive(Debug)]
struct DaneVerifier {
    pkix: Arc<WebPkiServerVerifier>,
    tlsa: Tlsa,
    enforce: bool,
    verified: Arc<AtomicBool>,
}

impl ServerCertVerifier for DaneVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let records = match &self.tlsa {
            // RFC 6698 §4.1: a bogus TLSA answer aborts the connection, enforced or not.
            Tlsa::Bogus => {
                return Err(rustls::Error::General(
                    "DANE: the server's TLSA records failed DNSSEC validation".into(),
                ))
            }
            Tlsa::Validated(records) => Some(records.as_slice()),
            Tlsa::Unavailable => None,
        };
        match evaluate_dane(end_entity, records) {
            DaneResult::DaneEe => {
                self.verified.store(true, Ordering::SeqCst);
                Ok(ServerCertVerified::assertion())
            }
            DaneResult::PkixEe => {
                let ok = self.pkix.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
                self.verified.store(true, Ordering::SeqCst);
                Ok(ok)
            }
            DaneResult::Mismatch => Err(rustls::Error::General(
                "DANE: the certificate does not match the server's TLSA records".into(),
            )),
            DaneResult::NotApplicable if self.enforce => Err(rustls::Error::General(
                "DANE is enforced but the server is not verified via DANE".into(),
            )),
            DaneResult::NotApplicable => {
                self.pkix.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.pkix.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.pkix.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.pkix.supported_verify_schemes()
    }
}

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
static TLS12_AND_13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13, &rustls::version::TLS12];

fn protocol_versions(policy: TlsPolicy) -> &'static [&'static rustls::SupportedProtocolVersion] {
    if policy.require_tls13 { TLS13_ONLY } else { TLS12_AND_13 }
}

fn tls_config(policy: TlsPolicy, verifier: DaneVerifier) -> Result<rustls::ClientConfig, Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(protocol_versions(policy))
        .map_err(|e| Error::Io(std::io::Error::other(e)))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(config)
}

fn pkix_verifier() -> Result<Arc<WebPkiServerVerifier>, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .map_err(|e| Error::Io(std::io::Error::other(e)))
}

// ---------------------------------------------------------------------------------------------
// Connecting

type Tls = TlsStream<TcpStream>;

fn header(domain: &str) -> StreamHeader<'_> {
    StreamHeader { to: Some(Cow::Borrowed(domain)), from: None, id: None }
}

async fn starttls(tcp: TcpStream, domain: &str, ns: &'static str, timeouts: Timeouts) -> Result<TcpStream, Error> {
    let pending = initiate_stream(BufStream::new(tcp), ns, header(domain), timeouts).await?;
    let (features, mut stream) = pending
        .recv_features::<FallibleStreamElement>()
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    if !features.can_starttls() {
        return Err(Error::Protocol(tokio_xmpp::error::ProtocolError::NoTls));
    }
    stream
        .send(&XmppStreamElement::Starttls(xmpp_parsers::starttls::Nonza::Request(
            xmpp_parsers::starttls::Request,
        )))
        .await?;
    loop {
        match stream.next().await.map(|v| v.and_then(|v| v.into_read_error())) {
            Some(Ok(XmppStreamElement::Starttls(xmpp_parsers::starttls::Nonza::Proceed(_)))) => break,
            Some(Ok(_)) | Some(Err(ReadError::SoftTimeout)) => {}
            Some(Err(ReadError::HardError(e))) => return Err(e.into()),
            Some(Err(ReadError::ParseError(e))) => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e).into())
            }
            None | Some(Err(ReadError::StreamFooterReceived)) => return Err(Error::Disconnected),
        }
    }
    Ok(stream.into_inner().into_inner())
}

impl SecureConnector {
    #[allow(clippy::too_many_arguments)]
    async fn try_endpoint(
        &self,
        endpoint: &Endpoint,
        addr: IpAddr,
        dnssec: bool,
        policy: TlsPolicy,
        jid: &Jid,
        ns: &'static str,
        timeouts: Timeouts,
    ) -> Result<(PendingFeaturesRecv<BufStream<Tls>>, ChannelBinding), Error> {
        let domain = jid.domain().as_str();
        // DANE only for a DNSSEC-verified endpoint named by host (RFC 7673).
        let tlsa = if dnssec && endpoint.host.parse::<IpAddr>().is_err() {
            tlsa_records(self.resolvers(), &endpoint.host, endpoint.port).await
        } else {
            Tlsa::Unavailable
        };
        let verified = Arc::new(AtomicBool::new(false));
        let verifier = DaneVerifier { pkix: pkix_verifier()?, tlsa, enforce: policy.enforce_dane, verified: verified.clone() };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config(policy, verifier)?));

        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(addr, endpoint.port)))
            .await
            .map_err(|_| Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")))??;
        let tcp = if endpoint.direct_tls { tcp } else { starttls(tcp, domain, ns, timeouts).await? };
        // The certificate must be valid for the JID domain (RFC 6120 §13.7.2.1), and SNI names it.
        let server_name = ServerName::try_from(domain.to_string())
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
        let tls = connector.connect(server_name, tcp).await?;

        let (_, connection) = tls.get_ref();
        let tls13 = connection.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
        let binding = if tls13 {
            let data = connection
                .export_keying_material(vec![0u8; 32], b"EXPORTER-Channel-Binding", None)
                .map_err(|e| Error::Io(std::io::Error::other(e)))?;
            ChannelBinding::TlsExporter(data)
        } else {
            ChannelBinding::None
        };
        let dane = verified.load(Ordering::SeqCst);
        *self.report.lock().unwrap() = LinkSecurity { dnssec, dane, tls13 };
        tracing::info!(host = %endpoint.host, port = endpoint.port, direct_tls = endpoint.direct_tls, dnssec, dane, tls13, "connected");
        Ok((initiate_stream(BufStream::new(tls), ns, header(domain), timeouts).await?, binding))
    }
}

impl ServerConnector for SecureConnector {
    type Stream = BufStream<Tls>;

    async fn connect(
        &self,
        jid: &Jid,
        ns: &'static str,
        timeouts: Timeouts,
    ) -> Result<(PendingFeaturesRecv<Self::Stream>, ChannelBinding), Error> {
        let policy = TlsPolicy::load(&self.store).await;
        let domain = jid.domain().as_str();
        let mut last_error = None;
        for endpoint in endpoints(self.resolvers(), domain).await {
            let (ips, addresses_secure) = addresses(self.resolvers(), &endpoint.host).await;
            let dnssec = endpoint.name_secure && addresses_secure;
            for ip in ips {
                match self.try_endpoint(&endpoint, ip, dnssec, policy, jid, ns, timeouts).await {
                    Ok(connected) => return Ok(connected),
                    Err(e) => {
                        tracing::warn!(host = %endpoint.host, port = endpoint.port, %ip, error = %e, "connection attempt failed");
                        last_error = Some(e);
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, format!("no address found for {domain}")))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(usage: CertUsage, selector: Selector, matching: Matching, data: Vec<u8>) -> TLSA {
        TLSA::new(usage, selector, matching, data)
    }

    /// A real certificate (the first bundled webpki root, DER) to match against.
    fn cert() -> Vec<u8> {
        webpki_root_certs::TLS_SERVER_ROOT_CERTS[0].as_ref().to_vec()
    }

    fn answer(name: &str, data: RData, proof: hickory_resolver::proto::dnssec::Proof) -> Record {
        let mut r = Record::from_rdata(hickory_resolver::proto::rr::Name::from_ascii(name).unwrap(), 300, data);
        r.proof = proof;
        r
    }

    fn tlsa_answer(proof: hickory_resolver::proto::dnssec::Proof) -> Record {
        let tlsa = record(CertUsage::DaneEe, Selector::Full, Matching::Sha256, vec![0; 32]);
        answer("_5223._tcp.target.example.", RData::TLSA(tlsa), proof)
    }

    fn cname_answer(proof: hickory_resolver::proto::dnssec::Proof) -> Record {
        let target = hickory_resolver::proto::rr::Name::from_ascii("_5223._tcp.target.example.").unwrap();
        answer("_5223._tcp.xmpp.example.", RData::CNAME(hickory_resolver::proto::rr::rdata::CNAME(target)), proof)
    }

    /// Run `settle_tlsa` with a scripted first answer and scripted retries; returns the
    /// outcome and how many retries were made.
    async fn settle(first: Validation, retries: &[Validation]) -> (Tlsa, usize) {
        use hickory_resolver::proto::dnssec::Proof;
        let answer = |v: Validation| -> (Vec<Record>, Validation) {
            let proof = match v {
                Validation::Secure => Proof::Secure,
                Validation::Insecure => Proof::Insecure,
                Validation::Bogus => Proof::Bogus,
            };
            (vec![tlsa_answer(proof)], v)
        };
        let calls = std::cell::Cell::new(0);
        let script = retries.to_vec();
        let tlsa = settle_tlsa("xmpp.example", 5223, answer(first), || {
            let n = calls.get();
            calls.set(n + 1);
            let v = *script.get(n).expect("more retries than scripted");
            async move { answer(v) }
        })
        .await;
        (tlsa, calls.get())
    }

    #[tokio::test]
    async fn bogus_tlsa_is_retried_but_only_an_upgrade_counts() {
        use Validation::*;
        // Mixed resolvers: bogus first, validated on retry → DANE applies with those records.
        let (tlsa, retries) = settle(Bogus, &[Secure]).await;
        assert!(matches!(tlsa, Tlsa::Validated(ref r) if r.len() == 1), "{tlsa:?}");
        assert_eq!(retries, 1);
        let (tlsa, retries) = settle(Bogus, &[Bogus, Secure]).await;
        assert!(matches!(tlsa, Tlsa::Validated(_)));
        assert_eq!(retries, 2);
        // An insecure retry must not downgrade a bogus answer to "DANE n/a".
        let (tlsa, _) = settle(Bogus, &[Insecure, Insecure]).await;
        assert_eq!(tlsa, Tlsa::Bogus);
        // A persistent forgery stays bogus, with a bounded number of retries.
        let (tlsa, retries) = settle(Bogus, &[Bogus, Bogus]).await;
        assert_eq!(tlsa, Tlsa::Bogus);
        assert_eq!(retries, BOGUS_TLSA_RETRIES);
        // Secure or insecure answers are final: no retry.
        let (tlsa, retries) = settle(Secure, &[]).await;
        assert!(matches!(tlsa, Tlsa::Validated(_)));
        assert_eq!(retries, 0);
        let (tlsa, retries) = settle(Insecure, &[]).await;
        assert_eq!(tlsa, Tlsa::Unavailable);
        assert_eq!(retries, 0);
    }

    #[test]
    fn chain_validation_requires_the_whole_chain() {
        use hickory_resolver::proto::dnssec::Proof;
        let tlsa = RecordType::TLSA;
        assert_eq!(chain_validation(&[tlsa_answer(Proof::Secure)], tlsa), Validation::Secure);
        assert_eq!(
            chain_validation(&[cname_answer(Proof::Secure), tlsa_answer(Proof::Secure)], tlsa),
            Validation::Secure
        );
        // An unsigned (forgeable) CNAME into a validly signed zone is not a validated answer.
        assert_eq!(
            chain_validation(&[cname_answer(Proof::Insecure), tlsa_answer(Proof::Secure)], tlsa),
            Validation::Insecure
        );
        // Any bogus link makes the whole answer bogus.
        assert_eq!(
            chain_validation(&[cname_answer(Proof::Bogus), tlsa_answer(Proof::Secure)], tlsa),
            Validation::Bogus
        );
        assert_eq!(chain_validation(&[tlsa_answer(Proof::Bogus)], tlsa), Validation::Bogus);
        assert_eq!(chain_validation(&[tlsa_answer(Proof::Indeterminate)], tlsa), Validation::Insecure);
        // A validated CNAME alone (the target type is missing) is not a validated TLSA answer.
        assert_eq!(chain_validation(&[cname_answer(Proof::Secure)], tlsa), Validation::Insecure);
        assert_eq!(chain_validation(&[], tlsa), Validation::Insecure);
    }

    #[test]
    fn bogus_tlsa_rejects_the_certificate_even_when_dane_is_not_enforced() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let verifier = |tlsa, enforce| DaneVerifier {
            pkix: pkix_verifier().unwrap(),
            tlsa,
            enforce,
            verified: Arc::new(AtomicBool::new(false)),
        };
        let cert = CertificateDer::from(cert());
        let name = ServerName::try_from("example.org").unwrap();
        let now = UnixTime::now();
        for enforce in [false, true] {
            let err = verifier(Tlsa::Bogus, enforce)
                .verify_server_cert(&cert, &[], &name, &[], now)
                .expect_err("a bogus TLSA answer must abort");
            assert!(err.to_string().contains("failed DNSSEC validation"), "{err}");
        }
        // Without any TLSA data the CA check decides (a root certificate is not a valid
        // end-entity certificate for example.org) - but not with the DANE error.
        let err = verifier(Tlsa::Unavailable, false).verify_server_cert(&cert, &[], &name, &[], now).unwrap_err();
        assert!(!err.to_string().contains("DANE"), "{err}");
        // A validated DANE-EE match is still trusted on its own.
        let digest = sha2::Sha256::digest(cert.as_ref()).to_vec();
        let matching = Tlsa::Validated(vec![record(CertUsage::DaneEe, Selector::Full, Matching::Sha256, digest)]);
        assert!(verifier(matching, true).verify_server_cert(&cert, &[], &name, &[], now).is_ok());
    }

    #[test]
    fn no_records_means_not_applicable() {
        assert_eq!(evaluate_dane(&cert(), None), DaneResult::NotApplicable);
        assert_eq!(evaluate_dane(&cert(), Some(&[])), DaneResult::NotApplicable);
    }

    #[test]
    fn dane_ee_full_certificate_sha256() {
        let digest = sha2::Sha256::digest(cert()).to_vec();
        let r = record(CertUsage::DaneEe, Selector::Full, Matching::Sha256, digest);
        assert_eq!(evaluate_dane(&cert(), Some(&[r])), DaneResult::DaneEe);
    }

    #[test]
    fn dane_ee_spki_sha512_and_raw() {
        let spki = spki(&cert()).expect("spki");
        assert_eq!(spki[0], 0x30, "SubjectPublicKeyInfo is a DER SEQUENCE");
        let r = record(CertUsage::DaneEe, Selector::Spki, Matching::Sha512, sha2::Sha512::digest(&spki).to_vec());
        assert_eq!(evaluate_dane(&cert(), Some(&[r])), DaneResult::DaneEe);
        let r = record(CertUsage::DaneEe, Selector::Spki, Matching::Raw, spki);
        assert_eq!(evaluate_dane(&cert(), Some(&[r])), DaneResult::DaneEe);
    }

    #[test]
    fn pkix_ee_match_still_needs_the_ca_check() {
        let r = record(CertUsage::PkixEe, Selector::Full, Matching::Sha256, sha2::Sha256::digest(cert()).to_vec());
        assert_eq!(evaluate_dane(&cert(), Some(&[r])), DaneResult::PkixEe);
    }

    #[test]
    fn mismatch_rejects_but_a_matching_rollover_record_wins() {
        let wrong = record(CertUsage::DaneEe, Selector::Full, Matching::Sha256, vec![0u8; 32]);
        assert_eq!(evaluate_dane(&cert(), Some(std::slice::from_ref(&wrong))), DaneResult::Mismatch);
        let right = record(CertUsage::DaneEe, Selector::Full, Matching::Sha256, sha2::Sha256::digest(cert()).to_vec());
        assert_eq!(evaluate_dane(&cert(), Some(&[wrong, right])), DaneResult::DaneEe);
    }

    /// Trust-anchor usages (0, 2) aren't supported (as on Android): they don't count.
    #[test]
    fn trust_anchor_usages_are_ignored() {
        let r = record(CertUsage::DaneTa, Selector::Full, Matching::Sha256, vec![0u8; 32]);
        assert_eq!(evaluate_dane(&cert(), Some(&[r])), DaneResult::NotApplicable);
    }

    #[test]
    fn unparsable_certificate_with_spki_records_is_a_mismatch() {
        let r = record(CertUsage::DaneEe, Selector::Spki, Matching::Sha256, vec![0u8; 32]);
        assert_eq!(evaluate_dane(b"not a certificate", Some(&[r])), DaneResult::Mismatch);
    }

    #[test]
    fn policy_defaults_match_android() {
        assert_eq!(TlsPolicy::default(), TlsPolicy { require_tls13: true, enforce_dane: false });
    }

    #[test]
    fn tls13_only_policy_offers_only_tls13() {
        let only = protocol_versions(TlsPolicy { require_tls13: true, enforce_dane: false });
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].version, rustls::ProtocolVersion::TLSv1_3);
        let both = protocol_versions(TlsPolicy { require_tls13: false, enforce_dane: false });
        assert!(both.iter().any(|v| v.version == rustls::ProtocolVersion::TLSv1_2));
        let verifier = || DaneVerifier {
            pkix: pkix_verifier().unwrap(),
            tlsa: Tlsa::Unavailable,
            enforce: false,
            verified: Arc::new(AtomicBool::new(false)),
        };
        assert!(tls_config(TlsPolicy::default(), verifier()).is_ok());
        assert!(tls_config(TlsPolicy { require_tls13: false, enforce_dane: false }, verifier()).is_ok());
    }

    #[tokio::test]
    async fn policy_is_read_from_the_store() {
        let store = mxc_store::Store::open_in_memory().await.unwrap();
        assert_eq!(TlsPolicy::load(&store).await, TlsPolicy::default());
        store.set_setting(SETTING_REQUIRE_TLS13, "0").await.unwrap();
        store.set_setting(SETTING_ENFORCE_DANE, "1").await.unwrap();
        assert_eq!(TlsPolicy::load(&store).await, TlsPolicy { require_tls13: false, enforce_dane: true });
    }

    #[test]
    fn endpoint_order() {
        let e = |port, direct_tls, priority, weight| Endpoint {
            host: "h".into(), port, direct_tls, name_secure: false, priority, weight,
        };
        let mut v = vec![e(5222, false, 5, 0), e(5223, true, 10, 0), e(5224, true, 5, 0), e(5225, false, 5, 50)];
        sort_endpoints(&mut v);
        let ports: Vec<u16> = v.iter().map(|e| e.port).collect();
        assert_eq!(ports, vec![5224, 5225, 5222, 5223]);
    }

    /// Live check against real servers (network; run with `cargo test -- --ignored live_`):
    /// DNSSEC/DANE detection, TLS 1.3, and that "Enforce DANE" refuses servers without DANE.
    #[tokio::test]
    #[ignore]
    async fn live_link_security() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let store = mxc_store::Store::open_in_memory().await.unwrap();
        let connect = |domain: &'static str| {
            let store = store.clone();
            async move {
                let report = Arc::new(Mutex::new(LinkSecurity::default()));
                let connector = SecureConnector::new(store, report.clone());
                let jid: Jid = format!("probe@{domain}").parse().unwrap();
                let result = connector.connect(&jid, xmpp_parsers::ns::JABBER_CLIENT, Timeouts::default()).await;
                let features = match result {
                    Ok((pending, _)) => pending.recv_features::<FallibleStreamElement>().await.map(|_| ()).map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                let security = report.lock().unwrap().clone();
                println!("{domain}: {features:?} {security:?}");
                (features, security)
            }
        };
        let (ok, sec) = connect("monocles.eu").await;
        assert!(ok.is_ok());
        assert_eq!(sec, LinkSecurity { dnssec: true, dane: true, tls13: true });
        let (ok, sec) = connect("jabber.fr").await;
        assert!(ok.is_ok());
        assert!(sec.dnssec && sec.dane);
        let (ok, sec) = connect("404.city").await;
        assert!(ok.is_ok());
        assert!(sec.dnssec && !sec.dane);
        let (ok, sec) = connect("conversations.im").await;
        assert!(ok.is_ok());
        assert!(!sec.dnssec && !sec.dane && sec.tls13);

        store.set_setting(SETTING_ENFORCE_DANE, "1").await.unwrap();
        let (ok, _) = connect("conversations.im").await;
        assert!(ok.is_err(), "enforced DANE must refuse a server without DANE");
        let (ok, sec) = connect("monocles.eu").await;
        assert!(ok.is_ok() && sec.dane, "enforced DANE still connects to a DANE server");
    }


    /// "Require TLS 1.3" refuses a TLS 1.2-only server. Needs a local TLS 1.2-only server:
    /// `openssl s_server -accept 18443 -tls1_2 -cert cert.pem -key key.pem` (self-signed, so
    /// with TLS 1.2 allowed the handshake gets as far as rejecting the certificate instead).
    #[tokio::test]
    #[ignore]
    async fn live_tls13_only_refuses_tls12_servers() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        async fn handshake(require_tls13: bool) -> Result<(), String> {
            let verifier = DaneVerifier {
                pkix: pkix_verifier().unwrap(),
                tlsa: Tlsa::Unavailable,
                enforce: false,
                verified: Arc::new(AtomicBool::new(false)),
            };
            let policy = TlsPolicy { require_tls13, enforce_dane: false };
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config(policy, verifier).unwrap()));
            let tcp = TcpStream::connect("127.0.0.1:18443").await.map_err(|e| e.to_string())?;
            let name = ServerName::try_from("localhost").unwrap();
            connector.connect(name, tcp).await.map(|_| ()).map_err(|e| e.to_string())
        }
        let strict = handshake(true).await.unwrap_err();
        println!("TLS 1.3 only: {strict}");
        assert!(strict.contains("ProtocolVersion") || strict.contains("protocol version"), "{strict}");
        let relaxed = handshake(false).await.unwrap_err();
        println!("TLS 1.2 allowed: {relaxed}");
        assert!(relaxed.contains("certificate"), "TLS 1.2 negotiated, then the cert was checked: {relaxed}");
    }


    /// Logout + login runs the core on a fresh runtime each time; a second connection from a new
    /// runtime must still resolve (network; `--ignored live_`).
    #[test]
    #[ignore]
    fn live_connects_again_from_a_fresh_runtime() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        for round in 0..2 {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let ok = rt.block_on(async {
                let store = mxc_store::Store::open_in_memory().await.unwrap();
                let connector = SecureConnector::new(store, Arc::new(Mutex::new(LinkSecurity::default())));
                let jid: Jid = "probe@monocles.eu".parse().unwrap();
                tokio::time::timeout(
                    Duration::from_secs(60),
                    connector.connect(&jid, xmpp_parsers::ns::JABBER_CLIENT, Timeouts::default()),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false)
            });
            drop(rt);
            assert!(ok, "connection in runtime #{round}");
        }
    }

}
