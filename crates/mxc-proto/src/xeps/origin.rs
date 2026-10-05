//! Stanza-origin checks shared by the handlers (mirrors Conversations' `fromServer` /
//! `fromAccount` / `toServer`). A remote party controls everything inside a stanza except the
//! `from` its server stamps, so every "who may say this" decision goes through these.

/// The bare part of a JID string (`local@domain/res` → `local@domain`).
pub fn bare(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}

/// The domain part of a JID string.
pub fn domain(jid: &str) -> &str {
    let b = bare(jid);
    b.rsplit('@').next().unwrap_or(b)
}

/// JID equality: local/domain parts case-insensitive (nodeprep/nameprep fold case), the
/// resource compared exactly. Both must agree on having a resource.
pub fn jid_eq(a: &str, b: &str) -> bool {
    let (ab, ar) = split(a);
    let (bb, br) = split(b);
    ab.eq_ignore_ascii_case(bb) && ar == br
}

fn split(jid: &str) -> (&str, Option<&str>) {
    match jid.split_once('/') {
        Some((b, r)) => (b, Some(r)),
        None => (jid, None),
    }
}

/// Whether `from` is our own server acting for us: absent, our domain, or our bare JID
/// (RFC 6120 §8.1.2.1 / RFC 6121 §2.1.6 — the only legal origins of roster/blocklist pushes and
/// of replies to requests we addressed to the server or our own account).
pub fn from_server(from: Option<&str>, our_bare: &str) -> bool {
    match from {
        None => true,
        Some(f) => jid_eq(f, our_bare) || jid_eq(f, domain(our_bare)),
    }
}

/// Whether a request addressed `to` goes to our own server/account (see [`from_server`]).
pub fn to_server(to: Option<&str>, our_bare: &str) -> bool {
    from_server(to, our_bare)
}

/// Whether `from` is one of our own account's resources (or our bare JID).
pub fn from_account(from: Option<&str>, our_bare: &str) -> bool {
    from.is_some_and(|f| bare(f).eq_ignore_ascii_case(our_bare))
}

/// The `id` of the only `<name xmlns=ns>` child of `el` - None if there is none, or more than
/// one (Conversations 539b55d83): a second copy means something slipped in an id we can't tell
/// apart from the real one, so neither is used. For XEP-0421 occupant ids and similar.
pub fn only_child_id(el: &minidom::Element, name: &str, ns: &str) -> Option<String> {
    let mut found = el.children().filter(|c| c.name() == name && c.ns() == ns);
    let only = found.next()?;
    if found.next().is_some() {
        return None;
    }
    only.attr("id").map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "me@example.org";

    #[test]
    fn server_origin() {
        assert!(from_server(None, ME));
        assert!(from_server(Some("me@example.org"), ME));
        assert!(from_server(Some("Me@Example.org"), ME));
        assert!(from_server(Some("example.org"), ME));
        assert!(!from_server(Some("me@example.org/phone"), ME));
        assert!(!from_server(Some("evil@example.org"), ME));
        assert!(!from_server(Some("evil.org"), ME));
        assert!(!from_server(Some("example.org/x"), ME));
    }

    #[test]
    fn jid_equality() {
        assert!(jid_eq("a@b.org/Res", "A@B.org/Res"));
        assert!(!jid_eq("a@b.org/Res", "a@b.org/res"));
        assert!(!jid_eq("a@b.org", "a@b.org/res"));
    }

    #[test]
    fn only_child_id_requires_uniqueness() {
        let one: minidom::Element =
            "<message xmlns='jabber:client'><occupant-id xmlns='urn:xmpp:occupant-id:0' id='a'/></message>"
                .parse()
                .unwrap();
        assert_eq!(only_child_id(&one, "occupant-id", "urn:xmpp:occupant-id:0").as_deref(), Some("a"));
        let two: minidom::Element = "<message xmlns='jabber:client'>\
            <occupant-id xmlns='urn:xmpp:occupant-id:0' id='forged'/>\
            <occupant-id xmlns='urn:xmpp:occupant-id:0' id='a'/></message>"
            .parse()
            .unwrap();
        assert_eq!(only_child_id(&two, "occupant-id", "urn:xmpp:occupant-id:0"), None);
    }

    #[test]
    fn account_origin() {
        assert!(from_account(Some("me@example.org/laptop"), ME));
        assert!(!from_account(None, ME));
        assert!(!from_account(Some("example.org"), ME));
    }
}
