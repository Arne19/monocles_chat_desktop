//! SDP ⇄ Jingle translation for RTP calls, mirroring monocles chat for Android (Conversations)
//! so the wire format interoperates: XEP-0167 (RTP description), XEP-0176 (ICE-UDP transport +
//! candidates), XEP-0320 (DTLS fingerprint), XEP-0338 (BUNDLE grouping).
//!
//! Handles one content per media section, so audio-only and audio+video calls both work.
//! webrtcbin produces/consumes the SDP; this module converts each media section to/from a
//! Jingle `<content>` element, plus ICE candidates.

use minidom::Element;

pub const NS_JINGLE: &str = "urn:xmpp:jingle:1";
pub const NS_RTP: &str = "urn:xmpp:jingle:apps:rtp:1";
pub const NS_ICE: &str = "urn:xmpp:jingle:transports:ice-udp:1";
pub const NS_DTLS: &str = "urn:xmpp:jingle:apps:dtls:0";
pub const NS_GROUP: &str = "urn:xmpp:jingle:apps:grouping:0";
pub const NS_RTCP_FB: &str = "urn:xmpp:jingle:apps:rtp:rtcp-fb:0";
pub const NS_SSMA: &str = "urn:xmpp:jingle:apps:rtp:ssma:0";

/// One parsed SDP media section.
#[derive(Default, Debug)]
struct Media {
    /// "audio" or "video".
    kind: String,
    mid: String,
    ufrag: String,
    pwd: String,
    fingerprint_hash: String,
    fingerprint: String,
    setup: String,
    /// payload id → rtpmap value ("opus/48000/2", "VP8/90000")
    rtpmap: Vec<(String, String)>,
    fmtp: Vec<(String, String)>,
    rtcp_fb: Vec<(String, String)>,
    ssrc: Option<String>,
    cname: Option<String>,
    candidates: Vec<String>,
    /// The SDP direction attribute (`sendrecv`/`sendonly`/`recvonly`/`inactive`), if present.
    direction: String,
}

/// Parse every media section of an SDP blob.
fn parse_media(sdp: &str) -> Vec<Media> {
    let mut out: Vec<Media> = Vec::new();
    for line in sdp.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("m=") {
            // m=<kind> <port> <proto> <fmt...>
            let mut m = Media::default();
            let mut it = rest.split_whitespace();
            m.kind = it.next().unwrap_or("").to_string();
            out.push(m);
            continue;
        }
        let Some(m) = out.last_mut() else { continue };
        let Some(attr) = line.strip_prefix("a=") else { continue };
        let (key, val) = attr.split_once(':').unwrap_or((attr, ""));
        match key {
            "mid" => m.mid = val.to_string(),
            "ice-ufrag" => m.ufrag = val.to_string(),
            "ice-pwd" => m.pwd = val.to_string(),
            "setup" => m.setup = val.to_string(),
            "fingerprint" => {
                if let Some((hash, fp)) = val.split_once(' ') {
                    m.fingerprint_hash = hash.to_string();
                    m.fingerprint = fp.to_string();
                }
            }
            "rtpmap" => {
                if let Some((id, rest)) = val.split_once(' ') {
                    m.rtpmap.push((id.to_string(), rest.to_string()));
                }
            }
            "fmtp" => {
                if let Some((id, rest)) = val.split_once(' ') {
                    m.fmtp.push((id.to_string(), rest.to_string()));
                }
            }
            "rtcp-fb" => {
                if let Some((id, rest)) = val.split_once(' ') {
                    m.rtcp_fb.push((id.to_string(), rest.to_string()));
                }
            }
            "ssrc" => {
                if let Some((id, rest)) = val.split_once(' ') {
                    m.ssrc.get_or_insert_with(|| id.to_string());
                    if let Some(cname) = rest.strip_prefix("cname:") {
                        m.cname.get_or_insert_with(|| cname.to_string());
                    }
                }
            }
            "candidate" => m.candidates.push(val.to_string()),
            "sendrecv" | "sendonly" | "recvonly" | "inactive" => m.direction = key.to_string(),
            _ => {}
        }
    }
    out
}

/// Jingle `senders` (XEP-0166) for a media section of OUR local SDP. The SDP direction is from
/// our point of view; `senders` names the session role(s) that send. Without a role (`None`) the
/// legacy behaviour applies: always `both`.
fn senders_for_local(direction: &str, we_initiator: Option<bool>) -> &'static str {
    let Some(we_initiator) = we_initiator else { return "both" };
    match direction {
        "inactive" => "none",
        // only we send
        "sendonly" => if we_initiator { "initiator" } else { "responder" },
        // only the peer sends
        "recvonly" => if we_initiator { "responder" } else { "initiator" },
        _ => "both",
    }
}

/// SDP direction for a content of the REMOTE description (from the remote's point of view)
/// given its Jingle `senders` and whether the remote is the session initiator.
fn direction_for_remote(senders: Option<&str>, remote_initiator: Option<bool>) -> &'static str {
    let Some(remote_initiator) = remote_initiator else { return "sendrecv" };
    match senders.unwrap_or("both") {
        "none" => "inactive",
        "initiator" => if remote_initiator { "sendonly" } else { "recvonly" },
        "responder" => if remote_initiator { "recvonly" } else { "sendonly" },
        _ => "sendrecv",
    }
}

/// Build a Jingle `<content>` element for one media section.
fn media_to_content(m: &Media, we_initiator: Option<bool>) -> Element {
    let mut desc = Element::builder("description", NS_RTP).attr(crate::ncname("media"), m.kind.as_str());
    for (id, rtpmap) in &m.rtpmap {
        let mut parts = rtpmap.split('/');
        let name = parts.next().unwrap_or("");
        let clockrate = parts.next().unwrap_or("");
        let channels = parts.next();
        let mut pt = Element::builder("payload-type", NS_RTP).attr(crate::ncname("id"), id.as_str()).attr(crate::ncname("name"), name);
        if !clockrate.is_empty() {
            pt = pt.attr(crate::ncname("clockrate"), clockrate);
        }
        if let Some(ch) = channels {
            pt = pt.attr(crate::ncname("channels"), ch);
        }
        if let Some((_, params)) = m.fmtp.iter().find(|(fid, _)| fid == id) {
            for kv in params.split(';') {
                if let Some((k, v)) = kv.trim().split_once('=') {
                    pt = pt.append(Element::builder("parameter", NS_RTP).attr(crate::ncname("name"), k).attr(crate::ncname("value"), v).build());
                }
            }
        }
        for (_, fb) in m.rtcp_fb.iter().filter(|(fid, _)| fid == id) {
            let mut it = fb.split_whitespace();
            let ty = it.next().unwrap_or("");
            let subtype = it.next();
            let mut fbe = Element::builder("rtcp-fb", NS_RTCP_FB).attr(crate::ncname("type"), ty);
            if let Some(s) = subtype {
                fbe = fbe.attr(crate::ncname("subtype"), s);
            }
            pt = pt.append(fbe.build());
        }
        desc = desc.append(pt.build());
    }
    desc = desc.append(Element::builder("rtcp-mux", NS_RTP).build());
    if let (Some(ssrc), Some(cname)) = (&m.ssrc, &m.cname) {
        desc = desc.append(
            Element::builder("source", NS_SSMA)
                .attr(crate::ncname("ssrc"), ssrc.as_str())
                .append(Element::builder("parameter", NS_SSMA).attr(crate::ncname("name"), "cname").attr(crate::ncname("value"), cname.as_str()).build())
                .build(),
        );
    }

    let mut transport = Element::builder("transport", NS_ICE)
        .attr(crate::ncname("ufrag"), m.ufrag.as_str())
        .attr(crate::ncname("pwd"), m.pwd.as_str());
    if !m.fingerprint.is_empty() {
        let mut fp = Element::builder("fingerprint", NS_DTLS).attr(crate::ncname("hash"), m.fingerprint_hash.as_str());
        if !m.setup.is_empty() {
            fp = fp.attr(crate::ncname("setup"), m.setup.as_str());
        }
        transport = transport.append(fp.append(m.fingerprint.as_str()).build());
    }
    for cand in &m.candidates {
        if let Some(c) = candidate_to_jingle(cand) {
            transport = transport.append(c);
        }
    }

    Element::builder("content", NS_JINGLE)
        .attr(crate::ncname("creator"), "initiator")
        .attr(crate::ncname("name"), if m.mid.is_empty() { m.kind.as_str() } else { m.mid.as_str() })
        .attr(crate::ncname("senders"), senders_for_local(&m.direction, we_initiator))
        .append(desc.build())
        .append(transport.build())
        .build()
}

/// Convert an SDP into Jingle contents + the BUNDLE mid list (one content per media section).
/// Every content is advertised as `senders='both'`; see [`sdp_to_contents_for`].
pub fn sdp_to_contents(sdp: &str) -> (Vec<Element>, Vec<String>) {
    sdp_to_contents_impl(sdp, None)
}

/// Like [`sdp_to_contents`], but `senders` reflects the SDP direction, given whether we are the
/// Jingle session initiator — e.g. a receive-only video m-line is advertised as sent by the peer
/// only, so the peer doesn't wait for (and show a black tile for) video we never send.
pub fn sdp_to_contents_for(sdp: &str, we_initiator: bool) -> (Vec<Element>, Vec<String>) {
    sdp_to_contents_impl(sdp, Some(we_initiator))
}

fn sdp_to_contents_impl(sdp: &str, we_initiator: Option<bool>) -> (Vec<Element>, Vec<String>) {
    let media = parse_media(sdp);
    let mids: Vec<String> = media
        .iter()
        .map(|m| if m.mid.is_empty() { m.kind.clone() } else { m.mid.clone() })
        .collect();
    let contents = media.iter().map(|m| media_to_content(m, we_initiator)).collect();
    (contents, mids)
}

/// Rebuild an SDP webrtcbin can consume from a set of Jingle `<content>` elements. Every m-line
/// is `sendrecv`; see [`contents_to_sdp_for`].
pub fn contents_to_sdp(contents: &[&Element]) -> Option<String> {
    contents_to_sdp_impl(contents, None)
}

/// Like [`contents_to_sdp`], but each m-line's direction follows the content's `senders`, given
/// whether the REMOTE party (whose description this is) is the Jingle session initiator.
pub fn contents_to_sdp_for(contents: &[&Element], remote_initiator: bool) -> Option<String> {
    contents_to_sdp_impl(contents, Some(remote_initiator))
}

fn contents_to_sdp_impl(contents: &[&Element], remote_initiator: Option<bool>) -> Option<String> {
    if contents.is_empty() {
        return None;
    }
    let mids: Vec<&str> = contents.iter().map(|c| c.attr("name").unwrap_or("0")).collect();

    // BUNDLE: every m-line shares one ICE/DTLS transport. webrtcbin only bundles (and only
    // gathers ICE once, on the first m-line) if the answer's m-lines carry *identical* ICE
    // credentials + fingerprint. A responder may put the transport only on the first content,
    // so take the first non-empty transport and apply it to every m-line.
    let primary = contents
        .iter()
        .filter_map(|c| c.get_child("transport", NS_ICE))
        .find(|t| !t.attr("ufrag").unwrap_or("").is_empty());
    let bundle_ufrag = primary.and_then(|t| t.attr("ufrag")).unwrap_or("");
    let bundle_pwd = primary.and_then(|t| t.attr("pwd")).unwrap_or("");
    let bundle_fp = primary.and_then(|t| t.get_child("fingerprint", NS_DTLS));

    let mut s = String::new();
    s.push_str("v=0\r\n");
    s.push_str("o=- 8770656990916039506 2 IN IP4 127.0.0.1\r\n");
    s.push_str("s=-\r\n");
    s.push_str("t=0 0\r\n");
    s.push_str(&format!("a=group:BUNDLE {}\r\n", mids.join(" ")));
    s.push_str("a=msid-semantic: WMS\r\n");

    for content in contents {
        let Some(desc) = content.get_child("description", NS_RTP) else { continue };
        let Some(transport) = content.get_child("transport", NS_ICE) else { continue };
        let mid = content.attr("name").unwrap_or("0");
        let kind = desc.attr("media").unwrap_or("audio");
        let payloads: Vec<&Element> = desc.children().filter(|c| c.name() == "payload-type").collect();
        let ids: Vec<&str> = payloads.iter().filter_map(|p| p.attr("id")).collect();

        s.push_str(&format!("m={kind} 9 UDP/TLS/RTP/SAVPF {}\r\n", ids.join(" ")));
        s.push_str("c=IN IP4 0.0.0.0\r\n");
        s.push_str("a=rtcp-mux\r\n");
        // Shared bundle transport credentials (identical on every m-line).
        s.push_str(&format!("a=ice-ufrag:{bundle_ufrag}\r\n"));
        s.push_str(&format!("a=ice-pwd:{bundle_pwd}\r\n"));
        s.push_str("a=ice-options:trickle\r\n");
        if let Some(fp) = bundle_fp {
            s.push_str(&format!("a=fingerprint:{} {}\r\n", fp.attr("hash").unwrap_or("sha-256"), fp.text()));
            s.push_str(&format!("a=setup:{}\r\n", fp.attr("setup").unwrap_or("active")));
        }
        s.push_str(&format!("a=mid:{mid}\r\n"));
        s.push_str(&format!(
            "a={}\r\n",
            direction_for_remote(content.attr("senders"), remote_initiator)
        ));
        for pt in &payloads {
            let id = pt.attr("id").unwrap_or("");
            let name = pt.attr("name").unwrap_or("");
            let clockrate = pt.attr("clockrate").unwrap_or("90000");
            match pt.attr("channels") {
                Some(ch) => s.push_str(&format!("a=rtpmap:{id} {name}/{clockrate}/{ch}\r\n")),
                None => s.push_str(&format!("a=rtpmap:{id} {name}/{clockrate}\r\n")),
            }
            let params: Vec<String> = pt
                .children()
                .filter(|c| c.name() == "parameter")
                .filter_map(|p| Some(format!("{}={}", p.attr("name")?, p.attr("value")?)))
                .collect();
            if !params.is_empty() {
                s.push_str(&format!("a=fmtp:{id} {}\r\n", params.join(";")));
            }
            for fb in pt.children().filter(|c| c.name() == "rtcp-fb") {
                match fb.attr("subtype") {
                    Some(sub) => s.push_str(&format!("a=rtcp-fb:{id} {} {sub}\r\n", fb.attr("type").unwrap_or(""))),
                    None => s.push_str(&format!("a=rtcp-fb:{id} {}\r\n", fb.attr("type").unwrap_or(""))),
                }
            }
        }
        if let Some(src) = desc.get_child("source", NS_SSMA) {
            if let Some(ssrc) = src.attr("ssrc") {
                let cname = src
                    .children()
                    .find(|p| p.name() == "parameter" && p.attr("name") == Some("cname"))
                    .and_then(|p| p.attr("value"))
                    .unwrap_or("mxc");
                s.push_str(&format!("a=ssrc:{ssrc} cname:{cname}\r\n"));
            }
        }
        for cand in transport.children().filter(|c| c.name() == "candidate") {
            if let Some(line) = candidate_to_sdp(cand) {
                s.push_str(&format!("a=candidate:{line}\r\n"));
            }
        }
    }
    Some(s)
}

/// SDP `candidate:` attribute value → Jingle `<candidate>` element (XEP-0176).
pub fn candidate_to_jingle(value: &str) -> Option<Element> {
    let seg: Vec<&str> = value.split_whitespace().collect();
    if seg.len() < 6 {
        return None;
    }
    let mut extra = std::collections::HashMap::new();
    let mut i = 6;
    while i + 1 < seg.len() {
        extra.insert(seg[i], seg[i + 1]);
        i += 2;
    }
    let mut c = Element::builder("candidate", NS_ICE)
        .attr(crate::ncname("foundation"), seg[0])
        .attr(crate::ncname("component"), seg[1])
        .attr(crate::ncname("protocol"), seg[2].to_lowercase())
        .attr(crate::ncname("priority"), seg[3])
        .attr(crate::ncname("ip"), seg[4])
        .attr(crate::ncname("port"), seg[5])
        .attr(crate::ncname("id"), crate::xeps::roster::new_id("cand"));
    if let Some(t) = extra.get("typ") {
        c = c.attr(crate::ncname("type"), *t);
    }
    if let Some(r) = extra.get("raddr") {
        c = c.attr(crate::ncname("rel-addr"), *r);
    }
    if let Some(r) = extra.get("rport") {
        c = c.attr(crate::ncname("rel-port"), *r);
    }
    if let Some(g) = extra.get("generation") {
        c = c.attr(crate::ncname("generation"), *g);
    }
    Some(c.build())
}

/// Jingle `<candidate>` element → SDP `candidate:` attribute value.
pub fn candidate_to_sdp(c: &Element) -> Option<String> {
    let foundation = c.attr("foundation")?;
    let component = c.attr("component")?;
    let protocol = c.attr("protocol")?;
    let priority = c.attr("priority")?;
    let ip = c.attr("ip")?;
    let port = c.attr("port")?;
    let mut s = format!("{foundation} {component} {protocol} {priority} {ip} {port}");
    if let Some(t) = c.attr("type") {
        s.push_str(&format!(" typ {t}"));
    }
    if let Some(r) = c.attr("rel-addr") {
        s.push_str(&format!(" raddr {r}"));
    }
    if let Some(r) = c.attr("rel-port") {
        s.push_str(&format!(" rport {r}"));
    }
    s.push_str(&format!(" generation {}", c.attr("generation").unwrap_or("0")));
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIO_VIDEO_SDP: &str = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
a=group:BUNDLE 0 1\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=rtcp-mux\r\n\
a=ice-ufrag:aud\r\na=ice-pwd:audpwd\r\na=fingerprint:sha-256 AA:BB\r\na=setup:actpass\r\n\
a=mid:0\r\na=sendrecv\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 useinbandfec=1\r\n\
a=ssrc:42 cname:c\r\na=candidate:1 1 udp 2122260223 1.2.3.4 5000 typ host\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\na=rtcp-mux\r\n\
a=ice-ufrag:aud\r\na=ice-pwd:audpwd\r\na=fingerprint:sha-256 AA:BB\r\na=setup:actpass\r\n\
a=mid:1\r\na=sendrecv\r\na=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 nack\r\na=ssrc:99 cname:c\r\n";

    #[test]
    fn audio_video_round_trip() {
        let (contents, mids) = sdp_to_contents(AUDIO_VIDEO_SDP);
        assert_eq!(mids, vec!["0", "1"]);
        assert_eq!(contents.len(), 2);
        assert_eq!(contents[0].get_child("description", NS_RTP).unwrap().attr("media"), Some("audio"));
        assert_eq!(contents[1].get_child("description", NS_RTP).unwrap().attr("media"), Some("video"));

        let refs: Vec<&Element> = contents.iter().collect();
        let sdp = contents_to_sdp(&refs).unwrap();
        assert!(sdp.contains("m=audio 9 UDP/TLS/RTP/SAVPF 111"));
        assert!(sdp.contains("a=rtpmap:111 opus/48000/2"));
        assert!(sdp.contains("m=video 9 UDP/TLS/RTP/SAVPF 96"));
        assert!(sdp.contains("a=rtpmap:96 VP8/90000"));
        assert!(sdp.contains("a=rtcp-fb:96 nack"));
        assert!(sdp.contains("a=group:BUNDLE 0 1"));
        assert!(sdp.contains("a=fingerprint:sha-256 AA:BB"));
    }

    #[test]
    fn senders_follow_sdp_direction() {
        let recv_video = AUDIO_VIDEO_SDP.replace("a=mid:1\r\na=sendrecv", "a=mid:1\r\na=recvonly");
        // We answer (responder) and only receive video → only the initiator sends it.
        let (contents, _) = sdp_to_contents_for(&recv_video, false);
        assert_eq!(contents[0].attr("senders"), Some("both"));
        assert_eq!(contents[1].attr("senders"), Some("initiator"));
        // As initiator, a receive-only m-line is sent by the responder.
        let (contents, _) = sdp_to_contents_for(&recv_video, true);
        assert_eq!(contents[1].attr("senders"), Some("responder"));
        // Legacy conversion keeps advertising both.
        let (contents, _) = sdp_to_contents(&recv_video);
        assert_eq!(contents[1].attr("senders"), Some("both"));
    }

    #[test]
    fn remote_direction_follows_senders() {
        let (contents, _) = sdp_to_contents_for(
            &AUDIO_VIDEO_SDP.replace("a=mid:1\r\na=sendrecv", "a=mid:1\r\na=recvonly"),
            false,
        );
        let refs: Vec<&Element> = contents.iter().collect();
        // That responder's description, as seen by the initiator: it only receives video.
        let sdp = contents_to_sdp_for(&refs, false).unwrap();
        assert!(sdp.contains("a=mid:1\r\na=recvonly"));
        assert!(sdp.contains("a=mid:0\r\na=sendrecv"));
        // senders='initiator' coming from the initiator → it only sends.
        let sdp = contents_to_sdp_for(&refs, true).unwrap();
        assert!(sdp.contains("a=mid:1\r\na=sendonly"));
    }

    #[test]
    fn candidate_round_trip() {
        let j = candidate_to_jingle("1 1 udp 2122260223 192.168.1.5 51234 typ host generation 0").unwrap();
        assert_eq!(j.attr("foundation"), Some("1"));
        assert_eq!(j.attr("type"), Some("host"));
        let sdp = candidate_to_sdp(&j).unwrap();
        assert!(sdp.starts_with("1 1 udp 2122260223 192.168.1.5 51234 typ host"));
    }
}
