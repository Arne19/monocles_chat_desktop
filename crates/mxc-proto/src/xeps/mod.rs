//! XEP handler modules.
//!
//! Each module owns the parse/serialize + side-effects for one area, grouped by phase.
//!
//! ## Foundation (Phase 0)
//! - [`disco`] 0030, [`caps`] 0115, [`roster`] 0237, [`presence`], [`bootstrap`], [`router`]
//!
//! ## Plumbing
//! - [`iq`]   request/response correlation over the stream
//! - [`pep`]  XEP-0163/0060 PubSub publish + fetch
//!
//! ## Messaging (Phase 1)
//! - [`messaging`] bodies/0085/0184/0333/0359/0444/0461/0308/0424/0428
//! - [`carbons`]   XEP-0280 message carbons
//! - [`mam`]       XEP-0313 message archive management
//! - [`muc`]       XEP-0045 multi-user chat
//! - [`bookmarks`] XEP-0402 bookmarks2
//! - [`avatar`]    XEP-0084/0153 user avatars, XEP-0172 nick
//!
//! Stream management (0198), ping (0199), CSI (0352), SASL2/Bind2 (0388) are handled by
//! tokio-xmpp during negotiation.

pub mod avatar;
pub mod bob;
pub mod bookmarks;
pub mod bootstrap;
pub mod caps;
pub mod carbons;
pub mod disco;
pub mod extdisco;
pub mod http_upload;
pub mod iq;
pub mod jingle;
pub mod jingle_sdp;
pub mod mam;
pub mod messaging;
pub mod microblog;
pub mod muc;
pub mod muji;
pub mod omemo;
pub mod origin;
pub mod pep;
pub mod presence;
pub mod roster;
pub mod router;
pub mod stanza_id;
pub mod stories;
pub mod vcard;
pub mod webxdc;

/// Current UTC time as a canonical XEP-0082 DateTime: millisecond precision with a
/// `Z` zone designator, e.g. `2026-07-07T08:25:36.119Z`.
///
/// Used for every stamp we put on the wire — most importantly the SCE `<time>`
/// affix (proto-XEP §4.6), which receivers MUST parse to verify the replay window.
/// `chrono`'s default `to_rfc3339()` emits nanosecond precision with a `+00:00`
/// offset; that is valid RFC 3339 too, but XEP-0082 canonicalizes on `Z`, and the
/// uncommon 9-digit fraction is exactly the kind of corner other parsers get wrong
/// (Android < 2026-07-07 rejected it). Millis + `Z` is the interop-safe form.
pub fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
