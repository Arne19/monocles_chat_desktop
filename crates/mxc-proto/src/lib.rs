//! `mxc-proto` — XMPP transport + XEP handlers for monocles chat desktop.
//!
//! No UI here. The crate exposes a [`client::ClientHandle`] (command sink + event
//! source over `async-channel`) that the GTK layer bridges into the glib main loop.
//!
//! The XEP coverage is grouped under [`xeps`]; Phase 0 wires the foundation set
//! (disco/caps/roster/presence/SM/ping/CSI), with messaging and OMEMO2 layered on top.

pub mod client;
pub mod command;
mod directtls;
pub mod event;
pub mod media_strip;
pub mod uri;
pub mod xeps;

/// Wrap an XML attribute name as the [`minidom::rxml::NcName`] that minidom 0.19's
/// `ElementBuilder::attr` now requires (it dropped the old `&str` overload). Every call site
/// passes a string *literal* attribute name, which is a valid NCName by construction, so the
/// validation can't fail in practice — an invalid name is a programming error.
#[inline]
pub(crate) fn ncname(name: &str) -> minidom::rxml::NcName {
    minidom::rxml::NcName::try_from(name).expect("attribute name must be a valid XML NCName")
}

pub use client::{spawn, AccountConfig, ClientHandle};
pub use command::{Command, Encryption, Subscription};
pub use event::{
    CallState, CallVideoFrame, ConfParticipant, ConnectionState, DeviceKey, Event, FeedPost,
};
