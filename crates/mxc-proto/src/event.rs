//! Events emitted by the core (`mxc-proto`) up to the UI (`mxc-app`).
//!
//! The UI never blocks on the network: it sends [`Command`](crate::command::Command)s
//! down and reacts to these events coming up, over `async-channel`.

use mxc_store::{Conversation, MessageRow, RosterItem};

/// One microblog (XEP-0277) post in a social feed, or one comment on a post.
#[derive(Debug, Clone, Default)]
pub struct FeedPost {
    /// PubSub item id (or the entry's atom uuid) — stable id for the post.
    pub id: String,
    /// Author bare JID.
    pub author: String,
    pub title: String,
    pub content: String,
    /// Publish time, unix seconds.
    pub published: i64,
    /// An associated link (atom `<link rel="alternate">`), or empty.
    pub link: String,
    /// An attached media URL (atom `<link rel="enclosure">`) + its MIME, or empty.
    pub attachment_url: String,
    pub attachment_type: String,
    /// The post's comments node (from its `<link rel="replies">`): the service's bare JID and
    /// the node. Empty if the post has none (comments then can't be shown or written).
    pub comments_jid: String,
    pub comments_node: String,
}

/// One of our own OMEMO2 devices, for the key-management UI.
#[derive(Debug, Clone)]
pub struct DeviceKey {
    pub device_id: i64,
    pub fingerprint: String,
    /// 0 = undecided, 1 = trusted/enabled, 2 = untrusted/disabled.
    pub trust: i64,
    /// Whether the device is still present in our published device list.
    pub active: bool,
}

/// State of a 1:1 call (XEP-0353 Jingle Message Initiation + XEP-0166 Jingle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallState {
    /// A peer is ringing us (we received a `propose`).
    Incoming,
    /// We're ringing a peer (we sent a `propose`), awaiting their `proceed`/`reject`.
    Outgoing,
    /// Both sides agreed (JMI `proceed`); the Jingle media session is being negotiated.
    Connecting,
    /// Media is flowing (ICE connected) — an active call.
    Active,
    /// The call finished or never connected; `reason` is a short human-readable cause.
    Ended { reason: String },
}

/// A decoded video frame (RGBA) for an active call, delivered to the UI on a dedicated
/// channel (not the main `Event` stream) so high-rate frames don't compete with signalling.
#[derive(Debug, Clone)]
pub struct CallVideoFrame {
    /// Jingle session id of the call this frame belongs to.
    pub sid: String,
    pub width: u32,
    pub height: u32,
    /// Tightly-packed RGBA8 pixels.
    pub data: Vec<u8>,
    /// True for our own camera preview, false for the remote peer.
    pub local: bool,
}

/// One remote participant in a Muji group call, for the conference UI.
#[derive(Debug, Clone)]
pub struct ConfParticipant {
    /// The participant's occupant JID (`room@host/nick`) — also how we address their Jingle.
    pub jid: String,
    /// Display name (their MUC nick).
    pub name: String,
    /// Per-pair call state: "connecting" | "active" | "ended".
    pub state: String,
    /// The per-pair Jingle session id (empty if no session yet). Lets the UI match this
    /// participant's decoded video frames (which are tagged by sid) to their tile.
    pub sid: String,
}

/// Connection lifecycle, mirrored into the libadwaita header/status.
#[derive(Debug, Clone)]
pub enum ConnectionState {
    Connecting,
    /// Authenticated + resource bound; carries the full JID.
    Online { full_jid: String },
    Disconnected { reason: String },
}

#[derive(Debug, Clone)]
pub enum Event {
    Connection(ConnectionState),

    /// Full roster snapshot after the initial XEP-0237 fetch / a push.
    RosterUpdated { account_id: i64, items: Vec<RosterItem> },

    /// Presence change for a contact full-JID.
    Presence {
        account_id: i64,
        full_jid: String,
        show: Option<String>,
        status: Option<String>,
    },

    /// A new (or backfilled) message was persisted. `live` is true for a freshly delivered
    /// stanza (eligible for a notification) and false for MAM backfill / history paging.
    /// `mentioned`/`reply_to_me` drive MUC notification filtering.
    MessageStored {
        account_id: i64,
        conversation_id: i64,
        message: MessageRow,
        live: bool,
        /// (MUC) the message mentions our nick.
        mentioned: bool,
        /// (MUC) the message replies to one of our messages.
        reply_to_me: bool,
    },

    /// XEP-0308: a message body was corrected; carries the updated row.
    MessageEdited { account_id: i64, conversation_id: i64, message: MessageRow },

    /// XEP-0424: a message was retracted (tombstoned). `body` is what it contained before,
    /// so the UI can delete any media-cache file downloaded for it.
    MessageRetracted { account_id: i64, conversation_id: i64, message_id: i64, body: Option<String> },

    /// XEP-0444: reaction tallies for a message changed.
    /// An outgoing message couldn't be sent; the UI restores the text + warns.
    SendFailed { account_id: i64, to: String, body: String, reason: String },

    ReactionsUpdated {
        account_id: i64,
        conversation_id: i64,
        message_id: i64,
        /// (emoji, count, comma-separated reactor names) per emoji.
        tallies: Vec<(String, i64, String)>,
    },

    /// Conversation list changed (new conv, unread count, MUC joined, last-active).
    ConversationsUpdated { account_id: i64, items: Vec<Conversation> },

    /// Delivery state moved (receipt 0184 / marker 0333).
    MessageState { marker_id: String, state: String },

    /// XEP-0085 chat state from a contact (composing/paused/active/gone).
    ChatState { full_jid: String, state: String },

    /// Decryption / trust prompt: a new OMEMO2 device fingerprint to TOFU-accept.
    OmemoDeviceSeen {
        account_id: i64,
        jid: String,
        device_id: i64,
        fingerprint: String,
    },

    /// XEP-0084 avatar image bytes (PNG/JPEG) for a contact's bare JID.
    Avatar { account_id: i64, jid: String, data: Vec<u8> },

    /// MUC occupant avatar photo (vCard-temp). `data` is empty if the occupant has none.
    MucAvatar { account_id: i64, room: String, nick: String, data: Vec<u8> },

    /// A room's OMEMO capability (private + non-anonymous), discovered on join. The UI uses it
    /// to enable/disable the encryption lock for the open room.
    MucPrivacy { account_id: i64, room: String, omemo_capable: bool },

    /// Our own account profile + PQ OMEMO2 keys (this device + our other devices).
    OwnKeys {
        account_id: i64,
        jid: String,
        own_device_id: i64,
        own_fingerprint: String,
        /// `xmpp:<jid>?omemo-sid-<device>=<key>` for this device — the string behind the QR
        /// code a contact scans to verify us out of band (see [`crate::uri`]). Empty until
        /// our identity exists.
        verification_uri: String,
        devices: Vec<DeviceKey>,
        /// App-wide "auto-trust new keys" setting (for the toggle in the dialog).
        auto_trust: bool,
        /// Our current presence: availability `show` ("" = online) + status message, so the
        /// profile dialog can show + edit them.
        presence_show: String,
        presence_status: String,
    },

    /// A contact's PQ OMEMO2 device keys.
    ContactKeys { account_id: i64, jid: String, devices: Vec<DeviceKey> },

    /// RFC 6121 inbound subscription request: a contact wants to see our presence. The UI
    /// shows an approval prompt (Allow → `Subscribed`, Decline → `Unsubscribed`).
    SubscriptionRequest {
        account_id: i64,
        jid: String,
        /// XEP-0172 nickname the requester advertised, for a friendlier prompt.
        nick: Option<String>,
    },

    /// A contact's current roster subscription state, for the contact-details presence toggles.
    Subscription {
        account_id: i64,
        jid: String,
        /// RFC 6121 subscription: "none" | "to" | "from" | "both".
        subscription: String,
        /// Pending outgoing request ("subscribe") if we've asked but they haven't approved.
        ask: Option<String>,
    },

    /// A contact's / room's vCard profile details for the profile dialog.
    Vcard {
        account_id: i64,
        jid: String,
        /// Photo bytes (empty if none), shown as a large avatar.
        photo: Vec<u8>,
        /// Ordered `(label, value)` profile fields.
        fields: Vec<(String, String)>,
    },

    /// XEP-0172 user nickname for a contact.
    NickUpdated { account_id: i64, jid: String, nick: String },

    /// A received file finished downloading + decrypting to `path`.
    FileSaved { account_id: i64, url: String, path: String },

    /// A new WebXDC status update arrived (or our own was sent) for an app instance `thread`.
    /// An open app view should replay updates past its cursor; `serial` is the new high-water mark.
    WebxdcUpdate { account_id: i64, thread: String, serial: i64 },

    /// Ephemeral WebXDC realtime data for `thread` (base64) — pushed straight to a live app view.
    WebxdcRealtime { account_id: i64, thread: String, data_b64: String },

    /// A WebXDC app asked (via the `notify` API) to show *this* user a system notification with
    /// `text` for instance `thread`.
    WebxdcNotify { account_id: i64, thread: String, text: String },

    /// A call's state changed (ringing / connecting / ended). `video` is whether video was
    /// proposed; `peer` is the other party's bare JID; `sid` the JMI/Jingle session id.
    CallUpdate {
        account_id: i64,
        sid: String,
        peer: String,
        video: bool,
        state: CallState,
    },

    /// The peer asked to upgrade the active audio call to video (Jingle `content-add`). The UI
    /// shows a consent prompt; accept → `Command::AcceptVideoUpgrade`, decline → `…Decline…`.
    CallVideoUpgradeRequest { account_id: i64, sid: String, peer: String },

    /// Authoritative screen-share state for the active call: `active` is true once the portal
    /// picker succeeded and the screen is being sent, false when stopped OR when the user
    /// cancelled the picker (so the UI button doesn't stay stuck "on").
    CallScreenShare { account_id: i64, sid: String, active: bool },

    /// The call's DTLS fingerprint was authenticated via PQ OMEMO2 (MITM-protected).
    /// `fingerprint` is the peer's OMEMO2 identity fingerprint; `device_id` is the peer's OMEMO2
    /// device (so the UI can offer to manually verify that key). `trust` is the call-trust level:
    /// 0 = authenticated but not trusted, 1 = BTBV-trusted (lock icon), 2 = manually verified
    /// (shield icon). Drives the call trust indicator.
    CallVerified {
        account_id: i64,
        sid: String,
        fingerprint: String,
        device_id: i64,
        trust: i64,
    },

    /// XEP-0272 Muji: another member started a group call in `room` we're NOT yet in. `from` is
    /// their nick. The UI shows a one-tap "Join" prompt; accepting calls `PlaceGroupCall`.
    ConferenceInvite { account_id: i64, room: String, from: String },
    /// The group call we were invited to ended (no participants left) — dismiss the prompt.
    ConferenceInviteCancelled { account_id: i64, room: String },
    /// Authoritative screen-share state for a group call (so the UI button resets if the portal
    /// picker was cancelled). `active` is whether we are now sharing our screen to the group.
    ConferenceScreenShare { account_id: i64, room: String, active: bool },

    /// XEP-0272 Muji group-call state changed. `room` is the conference (MUC) bare JID;
    /// `active` is whether we're still in the call (false → the UI closes the conference view);
    /// `participants` is the current set of remote participants and their per-pair states.
    ConferenceUpdate {
        account_id: i64,
        room: String,
        active: bool,
        video: bool,
        participants: Vec<ConfParticipant>,
    },

    /// The cached Stories changed (fetched / received / retracted); the UI re-queries the store.
    StoriesUpdated { account_id: i64 },

    /// A microblog feed's posts, in reply to `Command::FetchFeed` (or after publishing). `jid`
    /// is the feed owner's bare JID; `posts` is newest-first. `public`: the feed is readable by
    /// anyone (access model "open"), so links to its posts may be shared.
    FeedPosts { account_id: i64, jid: String, posts: Vec<FeedPost>, public: bool },

    /// The comments of the comments node `node` on `service` (a post's `<link rel="replies">`),
    /// in reply to `Command::FetchComments` / after `Command::PublishComment`. Oldest-first.
    FeedComments { account_id: i64, service: String, node: String, comments: Vec<FeedPost> },

    /// A contact (or we) published or edited a post (PEP notification, XEP-0472).
    FeedPostReceived { account_id: i64, post: FeedPost },

    /// `author` retracted their post `post_id` (ids are only unique per author).
    FeedPostRetracted { account_id: i64, author: String, post_id: String },

    /// Something changed on the comments node `node` of `service`: refetch it if shown.
    FeedCommentsChanged { account_id: i64, service: String, node: String },

    /// A Story or feed post the user started has been published (`error` None) or failed.
    /// `what` is "story" or "post".
    PublishDone { account_id: i64, what: String, error: Option<String> },

    /// Non-fatal notice surfaced to the user. `important` toasts (e.g. a failed file send the
    /// user explicitly started) are shown; non-important ones (background fetch failures) are
    /// logged only, to avoid noise.
    Toast { text: String, important: bool },
}
