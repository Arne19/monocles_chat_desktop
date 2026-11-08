//! XEP-0215 External Service Discovery.
//!
//! Fetches the account server's STUN/TURN relays so Jingle/`webrtcbin` ICE can traverse NAT.
//! Without a TURN relay, calls fail ICE on restrictive networks (symmetric NAT, UDP-blocking
//! firewalls) where STUN alone can't find a usable candidate pair — this is what monocles
//! Android does too (`IceServers`/`Services`), so it also keeps the two clients on par.

use minidom::Element;

use crate::client::{AccountConfig, Writer};
use crate::xeps::{iq, roster};

const NS_EXTDISCO: &str = "urn:xmpp:extdisco:2";

/// Query the account's server for external services and hand any STUN/TURN relays to the media
/// layer. Best-effort: on failure the media layer keeps its built-in public-STUN fallback.
pub async fn fetch(w: &Writer, cfg: &AccountConfig) {
    let domain = cfg.bare().split('@').nth(1).unwrap_or_default().to_string();
    if domain.is_empty() {
        return;
    }
    let req = Element::builder("iq", "jabber:client")
        .attr(crate::ncname("type"), "get")
        .attr(crate::ncname("to"), &domain)
        .attr(crate::ncname("id"), roster::new_id("extdisco"))
        .append(Element::builder("services", NS_EXTDISCO).build())
        .build();
    let reply = match iq::request(w, req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(error = %e, "XEP-0215 external services unavailable; using STUN only");
            return;
        }
    };
    let Some(services) = reply.get_child("services", NS_EXTDISCO) else {
        return;
    };

    let out = parse_services(services);

    if out.is_empty() {
        tracing::info!("XEP-0215 returned no usable ICE servers; using STUN only");
        return;
    }
    mxc_media::set_ice_servers(out);
}

/// The usable STUN/TURN servers of a XEP-0215 `<services>` element.
fn parse_services(services: &Element) -> Vec<mxc_media::IceServer> {
    let mut out = Vec::new();
    for s in services.children().filter(|c| c.name() == "service") {
        let kind = s.attr("type").unwrap_or_default().to_string();
        if !matches!(kind.as_str(), "stun" | "stuns" | "turn" | "turns") {
            continue;
        }
        let host = s.attr("host").unwrap_or_default().to_string();
        let Some(port) = s.attr("port").and_then(|p| p.parse::<u16>().ok()) else {
            continue;
        };
        if host.is_empty() {
            continue;
        }
        // webrtcbin resolves relay hostnames itself through the system resolver: never hand it a
        // .onion/.i2p name (unreachable here, and the lookup would leak it; see crate::hidden).
        if crate::hidden::is_hidden_service_host(&host) {
            tracing::info!(%host, "ignoring a Tor/I2P hidden-service STUN/TURN server");
            continue;
        }
        let transport = s.attr("transport").unwrap_or("udp").to_string();
        // STUN/TURN over TLS (stuns/turns) requires a TCP transport — skip the invalid combo.
        if matches!(kind.as_str(), "stuns" | "turns") && transport == "udp" {
            continue;
        }
        out.push(mxc_media::IceServer {
            kind,
            host,
            port,
            transport,
            username: s.attr("username").map(str::to_string),
            password: s.attr("password").map(str::to_string),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn services(xml: &str) -> Element {
        xml.parse().expect("valid services element")
    }

    #[test]
    fn hidden_service_relays_are_dropped() {
        let el = services(&format!(
            "<services xmlns='{NS_EXTDISCO}'>\
             <service type='stun' host='stun.example.org' port='3478'/>\
             <service type='turn' host='turn.example.org' port='3478' transport='udp' username='u' password='p'/>\
             <service type='turn' host='relay.abcdef.onion' port='3478'/>\
             <service type='stun' host='STUN.EXAMPLE.I2P.' port='3478'/>\
             </services>"
        ));
        let hosts: Vec<String> = parse_services(&el).into_iter().map(|s| s.host).collect();
        assert_eq!(hosts, vec!["stun.example.org", "turn.example.org"]);
    }

    #[test]
    fn existing_rules_still_apply() {
        let el = services(&format!(
            "<services xmlns='{NS_EXTDISCO}'>\
             <service type='stun' host='noport.example.org'/>\
             <service type='turns' host='tls.example.org' port='5349' transport='udp'/>\
             <service type='turns' host='tls.example.org' port='5349' transport='tcp'/>\
             <service type='ftp' host='other.example.org' port='21'/>\
             <service type='stun' host='' port='3478'/>\
             </services>"
        ));
        let servers = parse_services(&el);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].host, "tls.example.org");
        assert_eq!(servers[0].transport, "tcp");
    }
}
