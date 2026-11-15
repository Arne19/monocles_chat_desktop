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
//!   A *bogus* TLSA answer (signatures or a denial proof that are present but fail) always
//!   rejects the certificate (RFC 6698 §4.1). An *unverifiable* one - no signatures or no denial
//!   proof although the zone is signed, as a resolver that strips DNSSEC data (or a forwarding,
//!   VPN or split-horizon one) produces - counts as "DANE not verified": fatal only when DANE is
//!   enforced, by the setting or by the account's DANE pin (set once the server proved DANE).
//!   Same rule as monocles Android (Codeberg #564-#566).
//! * TLSA records reached through a CNAME: if the combined answer doesn't validate, the CNAME is
//!   queried on its own, and if it is authenticated the target's TLSA answer is validated on its
//!   own (as Android's DaneVerifier does), so a stripped target zone is unverifiable, not bogus.
//! * A lookup only counts as validated when the whole answer chain is: the requested records
//!   *and* any CNAME/DNAME that led to them. Otherwise an unsigned (forged) CNAME could point
//!   into a zone the attacker signs themselves.
//! * **TLS 1.3 only** when "Require TLS 1.3" is on (the default), else TLS 1.2 or 1.3.
//! * **Name servers**: every system name server validates on its own, and the first secure
//!   answer wins, so a resolver that strips DNSSEC data next to a good one doesn't cost DNSSEC
//!   or DANE (it would turn a signed zone's answers bogus). With a **DNS-over-TLS** server set,
//!   only that server is used, and only over TLS - no fallback to the system's name servers.
//!
//! tokio-xmpp's own connectors build their rustls configuration internally, so none of this can
//! be added to them; this replaces them (direct TLS first, STARTTLS as fallback, like before).

use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
use hickory_resolver::proto::rr::rdata::tlsa::{CertUsage, Matching, Selector, TLSA};
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
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
/// DNS-over-TLS server (hostname or IP); empty = the system's name servers.
pub const SETTING_DNS_SERVER_DOT: &str = "dns_server_dot";

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
    /// Whose DANE pin applies (`accounts.dane_pin`).
    account_id: i64,
    /// Built on first use, inside the runtime that connects: hickory runs its connection tasks on
    /// the runtime it was created in, and every login runs its core on a fresh runtime - a
    /// process-wide resolver would outlive it and hang the next login. Rebuilt when the
    /// DNS-over-TLS setting changes.
    dns: Arc<Mutex<Option<Arc<Resolvers>>>>,
}

impl SecureConnector {
    pub fn new(store: mxc_store::Store, report: Arc<Mutex<LinkSecurity>>, account_id: i64) -> Self {
        Self { store, report, account_id, dns: Arc::new(Mutex::new(None)) }
    }

    /// The policy for this account: the settings, with DANE also enforced once the account is
    /// DANE-pinned (HSTS-style, as on Android: set after the first DANE-verified login, so a
    /// network that later strips DNSSEC can't quietly downgrade the server to the CA check).
    async fn policy(&self) -> TlsPolicy {
        let mut policy = TlsPolicy::load(&self.store).await;
        let pinned = match self.store.dane_pinned(self.account_id).await {
            Ok(pinned) => pinned,
            Err(e) => {
                tracing::warn!(error = %e, "could not read the DANE pin");
                false
            }
        };
        if pinned && !policy.enforce_dane {
            tracing::debug!(account = self.account_id, "DANE enforced by the account's DANE pin");
        }
        policy.enforce_dane |= pinned;
        policy
    }

    async fn resolvers(&self) -> Arc<Resolvers> {
        let dot = dns_over_tls_server(&self.store).await;
        let cached = self.dns.lock().unwrap().clone();
        if let Some(dns) = cached.filter(|dns| dns.dot == dot) {
            return dns;
        }
        let fresh = Arc::new(Resolvers::new(dot).await);
        *self.dns.lock().unwrap() = Some(fresh.clone());
        fresh
    }
}

impl fmt::Debug for SecureConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureConnector").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------------
// DNS

/// The DNS-over-TLS server from the settings (see [`normalize_dot_server`]), or `None`.
pub async fn dns_over_tls_server(store: &mxc_store::Store) -> Option<String> {
    store.setting(SETTING_DNS_SERVER_DOT).await.ok().flatten().and_then(|v| normalize_dot_server(&v))
}

/// A DNS-over-TLS server as entered: a trimmed IP literal, or an ASCII hostname with at least
/// one dot. `None` for anything else, empty included (= not configured). Same rules as
/// Android's `DnsOverTls.normalize`.
pub fn normalize_dot_server(input: &str) -> Option<String> {
    let value = input.trim();
    if value.is_empty() {
        return None;
    }
    if value.parse::<IpAddr>().is_ok() {
        return Some(value.to_string());
    }
    // A .onion/.i2p DoT server is unreachable here and its bootstrap lookup would leak the name.
    if crate::hidden::is_hidden_service_host(value) {
        return None;
    }
    if !value.contains('.') || value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return None;
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return None;
    }
    Name::from_ascii(value).ok()?;
    Some(value.to_string())
}

/// How long a name server that gave a bogus answer (e.g. one that strips DNSSEC data) is asked
/// last, and how long one that didn't answer at all is. Failures count only briefly, so a good
/// server that timed out once is not skipped for long; an error rcode (e.g. SERVFAIL for a broken
/// zone) says nothing about the server and doesn't count. As on Android.
const BOGUS_MARK: Duration = Duration::from_secs(10 * 60);
const FAILED_MARK: Duration = Duration::from_secs(60);

struct Resolvers {
    /// One validating resolver per name server, in configuration order (see [`lookup`]).
    servers: Vec<(IpAddr, TokioResolver)>,
    /// All name servers, without validation, for the Android-like plain-DNS fallback.
    plain: Option<TokioResolver>,
    /// The DNS-over-TLS server these resolvers use, `None` for the system's name servers.
    dot: Option<String>,
    marks: Mutex<Marks>,
}

impl Resolvers {
    /// With `dot`, only that DNS-over-TLS server is used - no fallback to the system's name
    /// servers, so blocking port 853 can't downgrade to a resolver that strips DNSSEC. Its
    /// addresses come from the system resolver; the TLS handshake authenticates the server.
    async fn new(dot: Option<String>) -> Self {
        let (config, options, tls) = match &dot {
            Some(host) => (dot_config(host).await, ResolverOpts::default(), Some(dot_tls_config())),
            None => {
                let (config, options) = hickory_resolver::system_conf::read_system_conf().unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "no system DNS configuration, using defaults");
                    (ResolverConfig::default(), ResolverOpts::default())
                });
                (config, options, None)
            }
        };
        let (domain, search, name_servers) = config.into_parts();
        // One entry per address: resolv.conf-style configurations may list UDP and TCP separately.
        let mut by_ip: Vec<NameServerConfig> = Vec::new();
        for ns in name_servers {
            match by_ip.iter_mut().find(|known| known.ip == ns.ip) {
                Some(known) => known.connections.extend(ns.connections),
                None => by_ip.push(ns),
            }
        }
        let build = |name_servers: Vec<NameServerConfig>, validate: bool| -> Option<TokioResolver> {
            let config = ResolverConfig::from_parts(domain.clone(), search.clone(), name_servers);
            let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(options.clone());
            if let Some(tls) = &tls {
                builder = builder.with_tls_config(tls.clone());
            }
            if validate {
                builder.options_mut().validate = true;
                builder.options_mut().edns0 = true;
            }
            builder.build().map_err(|e| tracing::warn!(error = %e, "unable to build a DNS resolver")).ok()
        };
        let servers = by_ip.iter().filter_map(|ns| Some((ns.ip, build(vec![ns.clone()], true)?))).collect();
        let plain = if by_ip.is_empty() { None } else { build(by_ip, false) };
        Resolvers { servers, plain, dot, marks: Mutex::new(Marks::default()) }
    }
}

/// The name servers of a DNS-over-TLS server (port 853, authenticated as `host`).
async fn dot_config(host: &str) -> ResolverConfig {
    let ips: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => match tokio::net::lookup_host((host, 853)).await {
            Ok(addresses) => {
                let mut ips = Vec::new();
                for ip in addresses.map(|a| a.ip()) {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                ips
            }
            Err(e) => {
                // No addresses means no DNS at all (fail closed), never the system's name servers.
                tracing::warn!(%host, error = %e, "unable to resolve the DNS-over-TLS server");
                Vec::new()
            }
        },
    };
    let name: Arc<str> = Arc::from(host);
    ResolverConfig::from_parts(None, vec![], ips.into_iter().map(|ip| NameServerConfig::tls(ip, name.clone())).collect())
}

/// TLS for DNS-over-TLS: the same root store as XMPP (Mozilla bundle minus the refused roots),
/// TLS 1.2 or 1.3. rustls checks the certificate against the configured host (or IP).
fn dot_tls_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("TLS 1.2 and 1.3 are supported")
        .with_root_certificates(crate::tls_roots::xmpp_roots())
        .with_no_client_auth()
}

/// Name servers to ask last, each until the given time.
#[derive(Default)]
struct Marks(HashMap<IpAddr, Instant>);

impl Marks {
    /// Never shortens an existing mark: a bogus answer outweighs a later timeout.
    fn mark(&mut self, ip: IpAddr, duration: Duration, now: Instant) {
        let until = now + duration;
        self.0.entry(ip).and_modify(|known| *known = (*known).max(until)).or_insert(until);
    }

    fn unmark(&mut self, ip: IpAddr) {
        self.0.remove(&ip);
    }

    fn is_marked(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.0.get(&ip) {
            Some(until) if *until > now => true,
            Some(_) => {
                self.0.remove(&ip);
                false
            }
            None => false,
        }
    }

    /// Unmarked servers first, then the marked ones, each in the given order.
    fn order(&mut self, servers: &[IpAddr], now: Instant) -> Vec<IpAddr> {
        let (mut first, last): (Vec<IpAddr>, Vec<IpAddr>) =
            servers.iter().partition(|ip| !self.is_marked(**ip, now));
        first.extend(last);
        first
    }
}

/// The DNSSEC outcome of a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Validation {
    /// The requested records and every CNAME/DNAME leading to them validated.
    Secure,
    /// Unsigned, unvalidated or unavailable: usable, but not DNSSEC-verified.
    Insecure,
    /// Not validated although the zone is signed, and the evidence is simply missing: no RRSIGs
    /// for the records, or no (signed) NSEC/NSEC3 for a denial. A resolver that strips DNSSEC data
    /// (or a forwarding/VPN/split-horizon one) looks exactly like this, as does an attacker who
    /// strips signatures - so it is not trusted, but only fatal for DANE when DANE is enforced.
    Unverifiable,
    /// DNSSEC validation failed with the evidence present: someone tampered with the answer (or
    /// a signature broke).
    Bogus,
}

impl Validation {
    /// Bogus or unverifiable: another name server may still validate the answer.
    fn is_final(self) -> bool {
        matches!(self, Validation::Secure | Validation::Insecure)
    }
}

/// Whether `answers` carry an RRSIG covering `record`'s RRset (same owner name and type covered,
/// the same pairing hickory uses when it validates).
fn covered_by_rrsig(record: &Record, answers: &[Record]) -> bool {
    answers.iter().any(|sig| {
        sig.name == record.name
            && matches!(&sig.data, RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
                if rrsig.input().type_covered == record.record_type())
    })
}

/// The validation state of a whole answer chain. RRSIGs are only the evidence and carry no
/// state of their own; every other answer record (the requested type plus the CNAMEs/DNAMEs that
/// led there) has to be `Secure`. A bogus record makes the whole answer bogus if its RRSIGs are
/// there (they failed), and unverifiable if none of the bogus records has any (hickory reports a
/// stripped RRset in a signed zone as bogus, `RrsigsNotPresent`, but drops the reason).
///
/// A followed CNAME/DNAME chain is always bogus when a link is: hickory rebuilds the answers of a
/// chain resolved through separate queries from the requested type and the CNAMEs only
/// (`caching_client.rs`, `needs_filtering`), dropping every RRSIG, so missing signatures prove
/// nothing there. For TLSA, [`tlsa_via_cnames`] then looks at the links one by one.
fn chain_validation(answers: &[Record], rtype: RecordType) -> Validation {
    let chain = || answers.iter().filter(|r| r.record_type() != RecordType::RRSIG);
    if chain().any(|r| r.proof.is_bogus()) {
        let followed = chain().any(|r| matches!(r.record_type(), RecordType::CNAME | RecordType::DNAME));
        if followed || chain().filter(|r| r.proof.is_bogus()).any(|r| covered_by_rrsig(r, answers)) {
            Validation::Bogus
        } else {
            Validation::Unverifiable
        }
    } else if chain().any(|r| r.record_type() == rtype) && chain().all(|r| r.proof.is_secure()) {
        Validation::Secure
    } else {
        Validation::Insecure
    }
}

/// What one name server's validating lookup gave.
#[derive(Debug)]
enum Outcome {
    Answer(Vec<Record>, Validation),
    /// No usable answer; `network` if it didn't answer at all (timeout, connection error).
    Failed { network: bool },
}

async fn query_validating(resolver: &TokioResolver, name: &str, rtype: RecordType) -> Outcome {
    match resolver.lookup(name, rtype).await {
        Ok(found) => Outcome::Answer(
            found.answers().iter().filter(|r| r.record_type() == rtype).cloned().collect(),
            chain_validation(found.answers(), rtype),
        ),
        Err(e) if e.is_no_records_found() => Outcome::Answer(Vec::new(), Validation::Insecure),
        Err(NetError::Dns(DnsError::Nsec { proof, response, .. })) if proof.is_bogus() => {
            // A denial of existence that failed validation: the records may well exist and be
            // suppressed by an attacker. Callers decide what that means (see `tlsa_records`).
            // Bogus if signed NSEC/NSEC3 records are there and still don't prove it; unverifiable
            // if the proof (or its signatures) is simply missing.
            let authorities = &response.authorities;
            let signed_denial = authorities.iter().any(|r| {
                matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3) && covered_by_rrsig(r, authorities)
            });
            let validation = if signed_denial { Validation::Bogus } else { Validation::Unverifiable };
            tracing::debug!(%name, ?rtype, ?validation, "DNSSEC: denial of existence not validated");
            Outcome::Answer(Vec::new(), validation)
        }
        Err(e) => {
            let network = matches!(e, NetError::Timeout | NetError::Io(_) | NetError::NoConnections | NetError::Busy);
            tracing::debug!(%name, ?rtype, error = %e, network, "DNSSEC lookup failed");
            Outcome::Failed { network }
        }
    }
}

/// Ask the name servers one after another until one gives a final answer: `Secure`, or
/// `Insecure` (hickory reports that only for a zone proven unsigned, which a resolver that
/// strips DNSSEC data can't fake). A `Bogus` or `Unverifiable` answer - typically a resolver
/// stripping the signatures of a signed zone - is kept, and the next server is asked; servers
/// known to give such answers are skipped once one is at hand. Of those, `Bogus` wins over
/// `Unverifiable`, and neither is ever turned into an insecure answer by a server that fails.
/// `None` if no server answered.
///
/// A server is marked bogus only when another one validated the same query: a zone that is
/// bogus on every server (forged, or broken) says nothing about the servers. Marking them anyway
/// would make the next lookups skip the good server, so after a rejected bogus TLSA answer a
/// reconnect could get an unverified SRV answer from a stripping resolver and no DANE at all.
async fn select<F, Fut>(servers: &[IpAddr], marks: &Mutex<Marks>, mut query: F) -> Option<(Vec<Record>, Validation)>
where
    F: FnMut(IpAddr) -> Fut,
    Fut: std::future::Future<Output = Outcome>,
{
    let order = marks.lock().unwrap().order(servers, Instant::now());
    let mut bogus: Option<(Vec<Record>, Validation)> = None;
    let mut bogus_servers = Vec::new();
    for ip in order {
        if bogus.is_some() && marks.lock().unwrap().is_marked(ip, Instant::now()) {
            continue;
        }
        match query(ip).await {
            Outcome::Answer(records, validation) if !validation.is_final() => {
                tracing::debug!(%ip, ?validation, "DNSSEC: answer not validated, asking the next name server");
                bogus_servers.push(ip);
                // keep the first answer, but a bogus one outweighs an unverifiable one
                match &bogus {
                    None => bogus = Some((records, validation)),
                    Some((_, Validation::Unverifiable)) if validation == Validation::Bogus => {
                        bogus = Some((records, validation))
                    }
                    Some(_) => {}
                }
            }
            Outcome::Answer(records, validation) => {
                if validation == Validation::Secure {
                    let mut marks = marks.lock().unwrap();
                    marks.unmark(ip);
                    for bad in bogus_servers {
                        tracing::warn!(%bad, good = %ip, "DNSSEC: a name server gave a bogus answer that another one validated; it may strip DNSSEC data");
                        marks.mark(bad, BOGUS_MARK, Instant::now());
                    }
                }
                return Some((records, validation));
            }
            Outcome::Failed { network } => {
                if network {
                    marks.lock().unwrap().mark(ip, FAILED_MARK, Instant::now());
                }
            }
        }
    }
    bogus
}

/// Records of `rtype` at `name` and the DNSSEC state of the answer.
async fn lookup(dns: &Resolvers, name: &str, rtype: RecordType) -> (Vec<Record>, Validation) {
    // Catch-all for every SRV/A/AAAA/TLSA/CNAME name (incl. server-published targets): a
    // .onion/.i2p name is never sent to a DNS server (see crate::hidden).
    if crate::hidden::is_hidden_service_host(name) {
        tracing::warn!(%name, ?rtype, "not resolving a Tor/I2P hidden-service name");
        return (Vec::new(), Validation::Insecure);
    }
    let ips: Vec<IpAddr> = dns.servers.iter().map(|(ip, _)| *ip).collect();
    let answer = select(&ips, &dns.marks, |ip| async move {
        match dns.servers.iter().find(|(known, _)| *known == ip) {
            Some((_, resolver)) => query_validating(resolver, name, rtype).await,
            None => Outcome::Failed { network: false },
        }
    })
    .await;
    if let Some(answer) = answer {
        return answer;
    }
    // As on Android: when no validating lookup worked, fall back to plain DNS - the endpoint
    // then just isn't verified. With DNS-over-TLS this goes to the same server.
    tracing::debug!(%name, ?rtype, "DNSSEC lookups failed, retrying without validation");
    let Some(plain) = &dns.plain else {
        return (Vec::new(), Validation::Insecure);
    };
    match plain.lookup(name, rtype).await {
        Ok(found) => (
            found.answers().iter().filter(|r| r.record_type() == rtype).cloned().collect(),
            Validation::Insecure,
        ),
        Err(_) => (Vec::new(), Validation::Insecure),
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

/// The JID domain as an IP address, if it is an IP literal: IPv4 bare, IPv6 in brackets
/// (`[::1]`, as the jid crate keeps it).
fn ip_literal(domain: &str) -> Option<IpAddr> {
    let bare = domain.strip_prefix('[').and_then(|d| d.strip_suffix(']')).unwrap_or(domain);
    bare.parse::<IpAddr>().ok()
}

async fn endpoints(dns: &Resolvers, domain: &str) -> Vec<Endpoint> {
    let mut out = Vec::new();
    // An IP-literal domain has no SRV records; asking would only leak the address to DNS.
    if let Some(ip) = ip_literal(domain) {
        for (port, direct_tls) in [(5223, true), (5222, false)] {
            out.push(Endpoint { host: ip.to_string(), port, direct_tls, name_secure: true, priority: 0, weight: 0 });
        }
        return out;
    }
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
    /// Not validated although the zone is signed: signatures or the denial proof are missing
    /// (stripped, or a forwarding/VPN resolver). DANE does not apply, unless it is enforced (by
    /// the setting or the account's DANE pin) - then the connection is refused.
    Unverifiable,
    /// The TLSA answer failed DNSSEC validation with the evidence present: the connection must
    /// be aborted, enforced or not.
    Bogus,
}

/// How often a bogus TLSA answer is looked up again before the connection is refused.
const BOGUS_TLSA_RETRIES: usize = 2;

/// How many CNAMEs [`tlsa_via_cnames`] follows (Android's `DaneVerifier.MAX_CNAME_CHAIN_LENGTH`).
const MAX_CNAME_CHAIN_LENGTH: usize = 16;

/// The TLSA records for `host:port`.
async fn tlsa_records(dns: &Resolvers, host: &str, port: u16) -> Tlsa {
    let name = format!("_{port}._tcp.{host}.");
    let first = tlsa_via_cnames(&name, |n, t| async move { lookup(dns, &n, t).await }).await;
    // Each retry gets a fresh resolver: `clear_cache()` would leave hickory's DNSSEC
    // validation cache - and so the bogus verdict - in place.
    let retry = || {
        let name = &name;
        let dot = dns.dot.clone();
        async move {
            let fresh = Resolvers::new(dot).await;
            tlsa_via_cnames(name, |n, t| {
                let fresh = &fresh;
                async move { lookup(fresh, &n, t).await }
            })
            .await
        }
    };
    settle_tlsa(host, port, first, retry).await
}

/// The TLSA answer at `name`, following authenticated CNAMEs one link at a time (as Android's
/// `DaneVerifier` does). hickory drops the RRSIGs of a chain it follows itself, so a chained answer
/// that isn't validated is bogus by [`chain_validation`] even when only the target zone was
/// stripped. Then the CNAME at `name` is asked for on its own (not followed, so its signatures stay
/// checkable): only an authenticated one leads on, and the target's own TLSA answer decides -
/// unverifiable if it lacks signatures, bogus if they fail. An unauthenticated or bogus CNAME is no
/// way out (the original verdict stays). A chain longer than [`MAX_CNAME_CHAIN_LENGTH`] gives no
/// usable records (`Insecure`), like Android's `noUsableTlsaRecords`.
async fn tlsa_via_cnames<F, Fut>(name: &str, mut query: F) -> (Vec<Record>, Validation)
where
    F: FnMut(String, RecordType) -> Fut,
    Fut: std::future::Future<Output = (Vec<Record>, Validation)>,
{
    let mut current = name.to_string();
    let mut hops = 0;
    loop {
        let answer = query(current.clone(), RecordType::TLSA).await;
        if answer.1.is_final() {
            return answer;
        }
        let (cnames, validation) = query(current.clone(), RecordType::CNAME).await;
        if validation != Validation::Secure {
            return answer;
        }
        let Ok(owner) = Name::from_ascii(&current) else { return answer };
        let target = cnames.iter().find_map(|r| match &r.data {
            RData::CNAME(cname) if r.name == owner => Some(cname.0.to_ascii()),
            _ => None,
        });
        let Some(target) = target else { return answer };
        hops += 1;
        if hops > MAX_CNAME_CHAIN_LENGTH {
            tracing::warn!(%name, "CNAME chain for the TLSA records exceeds {MAX_CNAME_CHAIN_LENGTH} CNAMEs, not using TLSA records");
            return (Vec::new(), Validation::Insecure);
        }
        tracing::debug!(from = %current, to = %target, "TLSA: following an authenticated CNAME");
        current = target;
    }
}

/// Decide what a TLSA lookup means for DANE. A bogus or unverifiable answer is retried (`retry`, at most
/// [`BOGUS_TLSA_RETRIES`] times) because the system resolvers can disagree: on networks where
/// one of them strips DNSSEC data, the SRV/A lookups may validate while the TLSA answer happens
/// to come from the stripping one and is bogus, which would refuse a correctly configured
/// server. Only an **upgrade** counts: a retry that validates (`Secure`) is used; anything else,
/// including an `Insecure` plain-DNS fallback, keeps the answer bogus. Otherwise an attacker
/// could turn a forgery into "DANE does not apply" by also making the validating lookup fail.
/// A real forgery is bogus on every attempt, so it is still refused. Without an upgrade the
/// result is `Bogus` if any attempt was bogus (never softened to `Unverifiable`), otherwise
/// `Unverifiable`.
async fn settle_tlsa<F, Fut>(host: &str, port: u16, first: (Vec<Record>, Validation), mut retry: F) -> Tlsa
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = (Vec<Record>, Validation)>,
{
    let mut any_bogus = match first.1 {
        Validation::Secure => return validated_tlsa(&first.0),
        Validation::Insecure => return Tlsa::Unavailable,
        Validation::Bogus => true,
        Validation::Unverifiable => false,
    };
    for attempt in 1..=BOGUS_TLSA_RETRIES {
        let (records, validation) = retry().await;
        any_bogus |= validation == Validation::Bogus;
        if validation == Validation::Secure {
            tracing::warn!(
                %host,
                port,
                attempt,
                "DANE: the TLSA answer was not validated on one resolver but was on retry; a \
                 resolver on this network may strip DNSSEC data"
            );
            return validated_tlsa(&records);
        }
    }
    if any_bogus {
        tracing::warn!(%host, port, "DANE: the TLSA answer failed DNSSEC validation");
        Tlsa::Bogus
    } else {
        tracing::warn!(
            %host,
            port,
            "DANE: the TLSA answer has no signatures or denial proof although its zone is signed \
             (stripped, or a forwarding/VPN resolver); DANE not verified"
        );
        Tlsa::Unverifiable
    }
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
            // Unverifiable is "not verified via DANE": fatal below only if DANE is enforced.
            Tlsa::Unavailable | Tlsa::Unverifiable => None,
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
    // Mozilla bundle minus the refused roots (see tls_roots).
    WebPkiServerVerifier::builder_with_provider(
        crate::tls_roots::xmpp_roots(),
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
        dns: &Resolvers,
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
            tlsa_records(dns, &endpoint.host, endpoint.port).await
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
        // An IP-literal domain is checked against the certificate's IP SANs (IPv6 unbracketed).
        let server_name = match ip_literal(domain) {
            Some(ip) => Ok(ServerName::IpAddress(ip.into())),
            None => ServerName::try_from(domain.to_string()),
        }
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
        let policy = self.policy().await;
        let domain = jid.domain().as_str();
        if crate::hidden::is_hidden_service_host(domain) {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("{domain} is a Tor/I2P hidden service; Tor/I2P is not supported by this client"),
            )));
        }
        let mut last_error = None;
        let dns = self.resolvers().await;
        for endpoint in endpoints(&dns, domain).await {
            let (ips, addresses_secure) = addresses(&dns, &endpoint.host).await;
            let dnssec = endpoint.name_secure && addresses_secure;
            for ip in ips {
                match self.try_endpoint(&dns, &endpoint, ip, dnssec, policy, jid, ns, timeouts).await {
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

    #[test]
    fn ip_literal_domains() {
        assert_eq!(ip_literal("192.0.2.1"), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(ip_literal("[2001:db8::1]"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(ip_literal("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(ip_literal("example.org"), None);
        assert_eq!(ip_literal("[example.org]"), None);
    }

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

    /// An RRSIG (its signature never checked here) covering `covered` at `name`.
    fn rrsig_answer(name: &str, covered: RecordType) -> Record {
        use hickory_resolver::proto::dnssec::rdata::{SigInput, RRSIG};
        use hickory_resolver::proto::dnssec::{Algorithm, Proof};
        use hickory_resolver::proto::rr::SerialNumber;
        let owner = hickory_resolver::proto::rr::Name::from_ascii(name).unwrap();
        let input = SigInput {
            type_covered: covered,
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: owner.num_labels(),
            original_ttl: 300,
            sig_expiration: SerialNumber::new(0),
            sig_inception: SerialNumber::new(0),
            key_tag: 0,
            signer_name: hickory_resolver::proto::rr::Name::from_ascii("example.").unwrap(),
        };
        answer(name, RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![0; 64]))), Proof::Bogus)
    }

    /// Run `settle_tlsa` with a scripted first answer and scripted retries; returns the
    /// outcome and how many retries were made.
    async fn settle(first: Validation, retries: &[Validation]) -> (Tlsa, usize) {
        use hickory_resolver::proto::dnssec::Proof;
        let answer = |v: Validation| -> (Vec<Record>, Validation) {
            let proof = match v {
                Validation::Secure => Proof::Secure,
                Validation::Insecure => Proof::Insecure,
                // stripped: bogus records without RRSIGs (settle_tlsa only looks at `v`)
                Validation::Unverifiable | Validation::Bogus => Proof::Bogus,
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

    #[tokio::test]
    async fn unverifiable_tlsa_is_retried_and_never_outweighs_bogus() {
        use Validation::*;
        // Signatures missing on every attempt (a stripping or forwarding resolver): unverifiable.
        let (tlsa, retries) = settle(Unverifiable, &[Unverifiable, Unverifiable]).await;
        assert_eq!(tlsa, Tlsa::Unverifiable);
        assert_eq!(retries, BOGUS_TLSA_RETRIES);
        // A validating retry still upgrades.
        let (tlsa, retries) = settle(Unverifiable, &[Secure]).await;
        assert!(matches!(tlsa, Tlsa::Validated(_)));
        assert_eq!(retries, 1);
        // Any bogus attempt keeps it bogus, before or after unverifiable ones.
        let (tlsa, _) = settle(Unverifiable, &[Bogus, Unverifiable]).await;
        assert_eq!(tlsa, Tlsa::Bogus);
        let (tlsa, _) = settle(Bogus, &[Unverifiable, Unverifiable]).await;
        assert_eq!(tlsa, Tlsa::Bogus);
        // An insecure retry doesn't soften it to "DANE n/a" either.
        let (tlsa, _) = settle(Unverifiable, &[Insecure, Insecure]).await;
        assert_eq!(tlsa, Tlsa::Unverifiable);
    }

    fn cname_to(owner: &str, target: &str) -> Record {
        let target = hickory_resolver::proto::rr::Name::from_ascii(target).unwrap();
        answer(owner, RData::CNAME(hickory_resolver::proto::rr::rdata::CNAME(target)), hickory_resolver::proto::dnssec::Proof::Secure)
    }

    /// Run `tlsa_via_cnames` on a scripted DNS: `(name, type) -> (records, validation)`; a name
    /// without an entry answers `Insecure` and empty. Returns the result and every query made.
    async fn via_cnames(
        name: &str,
        script: &[((&str, RecordType), (Vec<Record>, Validation))],
    ) -> ((Vec<Record>, Validation), Vec<(String, RecordType)>) {
        let asked = std::cell::RefCell::new(Vec::new());
        let result = tlsa_via_cnames(name, |n: String, t| {
            asked.borrow_mut().push((n.clone(), t));
            let found = script
                .iter()
                .find(|((sn, st), _)| *sn == n && *st == t)
                .map(|(_, a)| a.clone())
                .unwrap_or((Vec::new(), Validation::Insecure));
            async move { found }
        })
        .await;
        (result, asked.into_inner())
    }

    #[tokio::test]
    async fn tlsa_behind_an_authenticated_cname_is_validated_on_its_own() {
        use hickory_resolver::proto::dnssec::Proof;
        use Validation::*;
        const NAME: &str = "_5223._tcp.xmpp.example.";
        const TARGET: &str = "_5223._tcp.target.example.";
        let tlsa = RecordType::TLSA;
        let cname = RecordType::CNAME;
        let alias = || (vec![cname_to(NAME, TARGET)], Secure);
        // The Android case: the chained answer is bogus (hickory dropped the RRSIGs), the CNAME
        // validates, the target lacks signatures → unverifiable, not bogus.
        for (target_answer, expected) in [
            ((vec![], Unverifiable), Unverifiable),
            ((vec![tlsa_answer(Proof::Secure)], Secure), Secure),
            ((vec![], Bogus), Bogus),
            ((vec![], Insecure), Insecure),
        ] {
            let script = [((NAME, tlsa), (vec![], Bogus)), ((NAME, cname), alias()), ((TARGET, tlsa), target_answer)];
            let ((records, validation), _) = via_cnames(NAME, &script).await;
            assert_eq!(validation, expected);
            if expected == Secure {
                assert_eq!(records.len(), 1, "the target's records are used");
            }
        }
        // An unauthenticated CNAME is no way out: the original verdict stays.
        for cname_validation in [Unverifiable, Bogus, Insecure] {
            let script = [
                ((NAME, tlsa), (vec![], Bogus)),
                ((NAME, cname), (vec![cname_to(NAME, TARGET)], cname_validation)),
                ((TARGET, tlsa), (vec![tlsa_answer(Proof::Secure)], Secure)),
            ];
            assert_eq!(via_cnames(NAME, &script).await.0 .1, Bogus, "{cname_validation:?}");
        }
        // No alias at the name (validated NODATA, or a CNAME owned by another name).
        let script = [((NAME, tlsa), (vec![], Unverifiable)), ((NAME, cname), (vec![], Secure))];
        assert_eq!(via_cnames(NAME, &script).await.0 .1, Unverifiable);
        let script = [((NAME, tlsa), (vec![], Bogus)), ((NAME, cname), (vec![cname_to("other.example.", TARGET)], Secure))];
        assert_eq!(via_cnames(NAME, &script).await.0 .1, Bogus);
        // Two hops: the last target decides.
        const SECOND: &str = "_5223._tcp.second.example.";
        let script = [
            ((NAME, tlsa), (vec![], Bogus)),
            ((NAME, cname), alias()),
            ((TARGET, tlsa), (vec![], Bogus)),
            ((TARGET, cname), (vec![cname_to(TARGET, SECOND)], Secure)),
            ((SECOND, tlsa), (vec![], Unverifiable)),
        ];
        assert_eq!(via_cnames(NAME, &script).await.0 .1, Unverifiable);
        // A CNAME loop ends after MAX_CNAME_CHAIN_LENGTH hops with no usable records.
        let script = [((NAME, tlsa), (vec![], Bogus)), ((NAME, cname), (vec![cname_to(NAME, NAME)], Secure))];
        let ((records, validation), asked) = via_cnames(NAME, &script).await;
        assert_eq!(validation, Insecure);
        assert!(records.is_empty());
        assert_eq!(asked.len(), 2 * (MAX_CNAME_CHAIN_LENGTH + 1));
        // A final answer never asks for the CNAME.
        let script = [((NAME, tlsa), (vec![tlsa_answer(Proof::Secure)], Secure))];
        let (_, asked) = via_cnames(NAME, &script).await;
        assert_eq!(asked, vec![(NAME.to_string(), tlsa)]);
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
        // Any bogus link whose signatures are there (and failed) makes the whole answer bogus.
        assert_eq!(
            chain_validation(
                &[
                    cname_answer(Proof::Bogus),
                    rrsig_answer("_5223._tcp.xmpp.example.", RecordType::CNAME),
                    tlsa_answer(Proof::Secure)
                ],
                tlsa
            ),
            Validation::Bogus
        );
        assert_eq!(
            chain_validation(&[tlsa_answer(Proof::Bogus), rrsig_answer("_5223._tcp.target.example.", RecordType::TLSA)], tlsa),
            Validation::Bogus
        );
        // Without any signatures for the bogus records (stripped, or a forwarding resolver) the
        // answer is unverifiable instead: not trusted, but only fatal when DANE is enforced.
        assert_eq!(chain_validation(&[tlsa_answer(Proof::Bogus)], tlsa), Validation::Unverifiable);
        // ...but not through a followed CNAME chain: hickory drops the RRSIGs of a chain resolved
        // through separate queries, so their absence proves nothing and a bogus link stays bogus.
        assert_eq!(
            chain_validation(&[cname_answer(Proof::Bogus), tlsa_answer(Proof::Secure)], tlsa),
            Validation::Bogus
        );
        assert_eq!(
            chain_validation(&[cname_answer(Proof::Secure), tlsa_answer(Proof::Bogus)], tlsa),
            Validation::Bogus
        );
        // An RRSIG for another name or type doesn't count as the bogus records' signature.
        assert_eq!(
            chain_validation(&[tlsa_answer(Proof::Bogus), rrsig_answer("_5223._tcp.target.example.", RecordType::A)], tlsa),
            Validation::Unverifiable
        );
        assert_eq!(
            chain_validation(&[tlsa_answer(Proof::Bogus), rrsig_answer("other.example.", RecordType::TLSA)], tlsa),
            Validation::Unverifiable
        );
        // One bogus link with its signature outweighs another one without.
        assert_eq!(
            chain_validation(
                &[
                    cname_answer(Proof::Bogus),
                    tlsa_answer(Proof::Bogus),
                    rrsig_answer("_5223._tcp.target.example.", RecordType::TLSA)
                ],
                tlsa
            ),
            Validation::Bogus
        );
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
    fn unverifiable_tlsa_is_fatal_only_when_dane_is_enforced() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let verifier = |enforce| DaneVerifier {
            pkix: pkix_verifier().unwrap(),
            tlsa: Tlsa::Unverifiable,
            enforce,
            verified: Arc::new(AtomicBool::new(false)),
        };
        let cert = CertificateDer::from(cert());
        let name = ServerName::try_from("example.org").unwrap();
        let now = UnixTime::now();
        // Not enforced: the CA check decides (and refuses this root as an end-entity certificate
        // for example.org), not DANE.
        let err = verifier(false).verify_server_cert(&cert, &[], &name, &[], now).unwrap_err();
        assert!(!err.to_string().contains("DANE"), "{err}");
        // Enforced (setting or the account's DANE pin): refused as not DANE-verified.
        let err = verifier(true).verify_server_cert(&cert, &[], &name, &[], now).unwrap_err();
        assert!(err.to_string().contains("DANE is enforced"), "{err}");
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

    /// A .onion/.i2p account domain is refused before any resolver is built: no DNS query, no
    /// network wait, and an error that says why.
    #[tokio::test]
    async fn a_hidden_service_account_domain_fails_fast() {
        for jid in ["user@abcdefghijklmnop.onion", "user@chat.example.i2p"] {
            let store = mxc_store::Store::open_in_memory().await.unwrap();
            let connector = SecureConnector::new(store, Arc::new(Mutex::new(LinkSecurity::default())), 0);
            let jid: Jid = jid.parse().unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                connector.connect(&jid, "jabber:client", Timeouts::default()),
            )
            .await
            .expect("must fail immediately, not wait for DNS or the network");
            match result {
                Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::Unsupported, "{jid}: {e}"),
                Err(other) => panic!("{jid}: unexpected error {other:?}"),
                Ok(_) => panic!("{jid}: must not connect"),
            }
        }
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
    fn dot_server_input_rules_match_android() {
        assert_eq!(normalize_dot_server("dns.quad9.net").as_deref(), Some("dns.quad9.net"));
        assert_eq!(normalize_dot_server("  dns.quad9.net \n").as_deref(), Some("dns.quad9.net"));
        assert_eq!(normalize_dot_server("9.9.9.9").as_deref(), Some("9.9.9.9"));
        assert_eq!(normalize_dot_server("2620:fe::fe").as_deref(), Some("2620:fe::fe"));
        for invalid in [
            "", "   ", "localhost", "dns quad9.net", "https://dns.quad9.net", "dns.quad9.net:853",
            ".quad9.net", "dns.quad9.net.", "dns..quad9.net", "dns.bücher.de",
            "dns.example.onion", "DNS.EXAMPLE.ONION", "dns.example.i2p",
        ] {
            assert_eq!(normalize_dot_server(invalid), None, "{invalid:?}");
        }
    }

    #[tokio::test]
    async fn dot_server_is_read_from_the_store() {
        let store = mxc_store::Store::open_in_memory().await.unwrap();
        assert_eq!(dns_over_tls_server(&store).await, None);
        store.set_setting(SETTING_DNS_SERVER_DOT, " dns.quad9.net ").await.unwrap();
        assert_eq!(dns_over_tls_server(&store).await.as_deref(), Some("dns.quad9.net"));
        store.set_setting(SETTING_DNS_SERVER_DOT, "not a server").await.unwrap();
        assert_eq!(dns_over_tls_server(&store).await, None);
    }

    #[test]
    fn marks_order_and_expire() {
        let (a, b, c): (IpAddr, IpAddr, IpAddr) =
            ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap(), "192.0.2.3".parse().unwrap());
        let now = Instant::now();
        let mut marks = Marks::default();
        marks.mark(a, FAILED_MARK, now);
        assert_eq!(marks.order(&[a, b, c], now), vec![b, c, a]);
        // a later, shorter mark never shortens a longer one
        marks.mark(b, BOGUS_MARK, now);
        marks.mark(b, FAILED_MARK, now);
        assert!(marks.is_marked(b, now + FAILED_MARK + Duration::from_secs(1)));
        // expired
        assert!(!marks.is_marked(a, now + FAILED_MARK));
        marks.unmark(b);
        assert_eq!(marks.order(&[a, b, c], now), vec![a, b, c]);
    }

    /// Runs `select` over fake name servers; returns the answer and how often each was asked.
    async fn run_select(
        marks: &Mutex<Marks>,
        servers: &[(IpAddr, Outcome)],
    ) -> (Option<Validation>, HashMap<IpAddr, usize>) {
        let asked = Mutex::new(HashMap::new());
        let ips: Vec<IpAddr> = servers.iter().map(|(ip, _)| *ip).collect();
        let answer = select(&ips, marks, |ip| {
            *asked.lock().unwrap().entry(ip).or_insert(0) += 1;
            let outcome = match &servers.iter().find(|(known, _)| *known == ip).unwrap().1 {
                Outcome::Answer(records, validation) => Outcome::Answer(records.clone(), *validation),
                Outcome::Failed { network } => Outcome::Failed { network: *network },
            };
            async move { outcome }
        })
        .await;
        (answer.map(|(_, validation)| validation), asked.into_inner().unwrap())
    }

    fn ips() -> (IpAddr, IpAddr) {
        ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap())
    }

    #[tokio::test]
    async fn an_unverifiable_answer_asks_on_and_never_outweighs_bogus() {
        use Validation::*;
        let (stripping, good) = ips();
        // a stripping resolver next to a validating one: the validated answer wins, and the
        // stripping one is asked last from then on
        let marks = Mutex::new(Marks::default());
        let servers = [(stripping, Outcome::Answer(vec![], Unverifiable)), (good, Outcome::Answer(vec![], Secure))];
        assert_eq!(run_select(&marks, &servers).await.0, Some(Secure));
        assert_eq!(marks.lock().unwrap().order(&[stripping, good], Instant::now()), vec![good, stripping]);
        // unverifiable + bogus: bogus, whichever comes first
        let marks = Mutex::new(Marks::default());
        let servers = [(stripping, Outcome::Answer(vec![], Unverifiable)), (good, Outcome::Answer(vec![], Bogus))];
        assert_eq!(run_select(&marks, &servers).await.0, Some(Bogus));
        let marks = Mutex::new(Marks::default());
        let servers = [(stripping, Outcome::Answer(vec![], Bogus)), (good, Outcome::Answer(vec![], Unverifiable))];
        assert_eq!(run_select(&marks, &servers).await.0, Some(Bogus));
        // unverifiable + a dead server: stays unverifiable, never "insecure"
        let marks = Mutex::new(Marks::default());
        let servers = [(stripping, Outcome::Answer(vec![], Unverifiable)), (good, Outcome::Failed { network: true })];
        assert_eq!(run_select(&marks, &servers).await.0, Some(Unverifiable));
    }

    #[tokio::test]
    async fn a_resolver_that_strips_dnssec_does_not_cost_dane() {
        use Validation::*;
        let (stripping, good) = ips();
        let marks = Mutex::new(Marks::default());
        let servers = [(stripping, Outcome::Answer(vec![], Bogus)), (good, Outcome::Answer(vec![], Secure))];
        assert_eq!(run_select(&marks, &servers).await.0, Some(Secure));
        // afterwards the good one is asked first
        let (validation, asked) = run_select(&marks, &servers).await;
        assert_eq!(validation, Some(Secure));
        assert_eq!(asked.get(&stripping), None);
    }

    #[tokio::test]
    async fn bogus_stays_bogus_and_a_proven_insecure_zone_is_final() {
        use Validation::*;
        let (first, second) = ips();
        let marks = Mutex::new(Marks::default());
        // every server bogus (or failing): bogus, never downgraded to "DANE does not apply"
        let servers = [(first, Outcome::Answer(vec![], Bogus)), (second, Outcome::Failed { network: true })];
        assert_eq!(run_select(&marks, &servers).await.0, Some(Bogus));
        // an unsigned zone: the first insecure answer is final and marks nobody
        let marks = Mutex::new(Marks::default());
        let servers = [(first, Outcome::Answer(vec![], Insecure)), (second, Outcome::Answer(vec![], Secure))];
        let (validation, asked) = run_select(&marks, &servers).await;
        assert_eq!(validation, Some(Insecure));
        assert_eq!(asked.get(&second), None);
        assert_eq!(marks.lock().unwrap().order(&[first, second], Instant::now()), vec![first, second]);
        // nothing answered at all: the caller falls back to plain DNS
        let marks = Mutex::new(Marks::default());
        let servers = [(first, Outcome::Failed { network: true }), (second, Outcome::Failed { network: false })];
        assert_eq!(run_select(&marks, &servers).await.0, None);
    }

    #[tokio::test]
    async fn a_dead_resolver_is_asked_last_but_a_servfail_marks_nothing() {
        use Validation::*;
        let (first, second) = ips();
        let marks = Mutex::new(Marks::default());
        let servers = [(first, Outcome::Failed { network: true }), (second, Outcome::Answer(vec![], Secure))];
        run_select(&marks, &servers).await;
        let (_, asked) = run_select(&marks, &servers).await;
        assert_eq!(asked.get(&first), None, "the dead server costs a timeout only once");
        // an error rcode (not a network failure) doesn't demote the server
        let marks = Mutex::new(Marks::default());
        let servers = [(first, Outcome::Failed { network: false }), (second, Outcome::Answer(vec![], Secure))];
        run_select(&marks, &servers).await;
        assert_eq!(marks.lock().unwrap().order(&[first, second], Instant::now()), vec![first, second]);
    }

    #[tokio::test]
    async fn a_zone_that_is_bogus_everywhere_marks_nobody() {
        use Validation::*;
        let (stripping, good) = ips();
        let marks = Mutex::new(Marks::default());
        // e.g. a forged TLSA answer: bogus on every server, which says nothing about them
        let servers = [(stripping, Outcome::Answer(vec![], Bogus)), (good, Outcome::Answer(vec![], Bogus))];
        assert_eq!(run_select(&marks, &servers).await.0, Some(Bogus));
        assert_eq!(marks.lock().unwrap().order(&[stripping, good], Instant::now()), vec![stripping, good]);
        // so the next lookup (another zone) still reaches the good server
        let servers = [(stripping, Outcome::Answer(vec![], Bogus)), (good, Outcome::Answer(vec![], Secure))];
        let (validation, asked) = run_select(&marks, &servers).await;
        assert_eq!(validation, Some(Secure));
        assert_eq!(asked.get(&good), Some(&1));
    }

    #[tokio::test]
    async fn known_bogus_resolvers_are_skipped_once_a_bogus_answer_is_at_hand() {
        use Validation::*;
        let (stripping, good) = ips();
        let marks = Mutex::new(Marks::default());
        // the stripping server is confirmed bad by the good one
        let servers = [(stripping, Outcome::Answer(vec![], Bogus)), (good, Outcome::Answer(vec![], Secure))];
        run_select(&marks, &servers).await;
        // a zone bogus everywhere: the good server's answer is enough, the known-bad one is skipped
        let servers = [(stripping, Outcome::Answer(vec![], Bogus)), (good, Outcome::Answer(vec![], Bogus))];
        let (validation, asked) = run_select(&marks, &servers).await;
        assert_eq!(validation, Some(Bogus));
        assert_eq!(asked.get(&stripping), None);
        assert_eq!(asked.get(&good), Some(&1));
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
    /// The Unverifiable/Bogus split relies on hickory handing the RRSIGs of a validated (direct,
    /// non-CNAME) answer back to us. If a hickory update starts stripping them, every bogus TLSA
    /// answer would look unverifiable - this catches that.
    #[tokio::test]
    #[ignore]
    async fn live_secure_tlsa_answers_keep_their_rrsigs() {
        let dns = Resolvers::new(None).await;
        let (srv, _) = lookup(&dns, "_xmpps-client._tcp.monocles.eu.", RecordType::SRV).await;
        let Some(RData::SRV(srv)) = srv.first().map(|r| r.data.clone()) else { panic!("no SRV for monocles.eu") };
        let name = format!("_{}._tcp.{}", srv.port, srv.target.to_ascii());
        let mut checked = false;
        for (ip, resolver) in &dns.servers {
            let Ok(found) = resolver.lookup(name.as_str(), RecordType::TLSA).await else { continue };
            if chain_validation(found.answers(), RecordType::TLSA) != Validation::Secure {
                println!("{ip}: not secure (stripping resolver?), skipped");
                continue;
            }
            let tlsa: Vec<&Record> = found.answers().iter().filter(|r| r.record_type() == RecordType::TLSA).collect();
            assert!(!tlsa.is_empty(), "{ip}: no TLSA records at {name}");
            for r in tlsa {
                assert!(covered_by_rrsig(r, found.answers()), "{ip}: TLSA at {name} came back without its RRSIG");
            }
            checked = true;
        }
        assert!(checked, "no name server validated {name}; use a DNSSEC-capable resolver");
    }

    #[tokio::test]
    #[ignore]
    async fn live_link_security() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let store = mxc_store::Store::open_in_memory().await.unwrap();
        let connect = |domain: &'static str| {
            let store = store.clone();
            async move {
                let report = Arc::new(Mutex::new(LinkSecurity::default()));
                let connector = SecureConnector::new(store, report.clone(), 0);
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

    /// DNS-over-TLS (network; `--ignored live_`): DNSSEC and DANE through the DoT server, and
    /// no fallback to the system's name servers when it can't be reached.
    #[tokio::test]
    #[ignore]
    async fn live_dns_over_tls() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let store = mxc_store::Store::open_in_memory().await.unwrap();
        let connect = |store: mxc_store::Store| async move {
            let report = Arc::new(Mutex::new(LinkSecurity::default()));
            let connector = SecureConnector::new(store, report.clone(), 0);
            let jid: Jid = "probe@monocles.eu".parse().unwrap();
            let result = connector.connect(&jid, xmpp_parsers::ns::JABBER_CLIENT, Timeouts::default()).await;
            let ok = match result {
                Ok((pending, _)) => pending.recv_features::<FallibleStreamElement>().await.is_ok(),
                Err(e) => {
                    println!("error: {e}");
                    false
                }
            };
            let security = report.lock().unwrap().clone();
            (ok, security)
        };
        store.set_setting(SETTING_DNS_SERVER_DOT, "dns.quad9.net").await.unwrap();
        let (ok, sec) = connect(store.clone()).await;
        println!("DoT dns.quad9.net: {ok} {sec:?}");
        assert!(ok && sec.dnssec && sec.dane);
        // an IP literal is checked against the certificate's IP SANs
        store.set_setting(SETTING_DNS_SERVER_DOT, "9.9.9.9").await.unwrap();
        let (ok, sec) = connect(store.clone()).await;
        println!("DoT 9.9.9.9: {ok} {sec:?}");
        assert!(ok && sec.dnssec && sec.dane);
        store.set_setting(SETTING_DNS_SERVER_DOT, "dot.invalid").await.unwrap();
        let (ok, _) = connect(store.clone()).await;
        assert!(!ok, "an unreachable DoT server must not fall back to the system's name servers");
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
                let connector = SecureConnector::new(store, Arc::new(Mutex::new(LinkSecurity::default())), 0);
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
