//! Commands sent from the UI down to the core client actor.

/// How a message should be encrypted on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None,
    /// PQ OMEMO2 (`urn:monocles:omemo-pq:1`).
    Omemo2,
}

/// RFC 6121 presence-subscription action, mapped 1:1 to a `<presence type=…>` stanza.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subscription {
    /// Ask to *receive* the contact's presence.
    Subscribe,
    /// Stop receiving the contact's presence.
    Unsubscribe,
    /// Allow the contact to *see* our presence (approve / pre-approve).
    Subscribed,
    /// Stop the contact seeing our presence (deny / revoke).
    Unsubscribed,
}

impl Subscription {
    /// The `type` attribute for the `<presence>` stanza.
    pub fn as_type(self) -> &'static str {
        match self {
            Subscription::Subscribe => "subscribe",
            Subscription::Unsubscribe => "unsubscribe",
            Subscription::Subscribed => "subscribed",
            Subscription::Unsubscribed => "unsubscribed",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Command {
    /// Connect (or reconnect) the given account.
    Connect { account_id: i64 },
    Disconnect { account_id: i64 },

    /// Set our own presence: availability `show` ("" = online, else chat/away/xa/dnd) + a
    /// free-text `status` message. Persisted and re-broadcast (with XEP-0115 caps) immediately.
    SetPresence { account_id: i64, show: String, status: String },

    /// Publish our own avatar (XEP-0084 PEP): pre-scaled image bytes + their mime/dimensions.
    /// Replies with `Event::Avatar` for our own bare JID so the UI caches + shows it.
    PublishAvatar { account_id: i64, data: Vec<u8>, mime: String, width: u32, height: u32 },

    /// Publish our own nickname (XEP-0172 PEP).
    SetNick { account_id: i64, nick: String },

    /// Fetch `jid`'s published nickname (XEP-0172). Replies with `Event::NickUpdated`.
    FetchNick { account_id: i64, jid: String },

    /// Send a chat message to a bare JID.
    SendMessage {
        account_id: i64,
        to: String,
        body: String,
        encryption: Encryption,
        /// XEP-0461 reply-to stanza id, if this is a reply.
        reply_to: Option<String>,
        /// Pre-chosen origin-id (the UI persists + renders the message first, then asks the
        /// core to send it under this id, so the core's persist dedups instead of duplicating).
        /// `None` lets the core generate one (legacy/non-UI callers).
        id: Option<String>,
    },

    /// XEP-0308 correct/replace a previously-sent message.
    Correct {
        account_id: i64,
        conversation_id: i64,
        to: String,
        /// origin/stanza id of the message being corrected.
        target_id: String,
        new_body: String,
    },

    /// XEP-0424 retract a previously-sent message.
    Retract { account_id: i64, conversation_id: i64, to: String, target_id: String },

    /// XEP-0085 chat state (composing/active/paused).
    SendChatState { account_id: i64, to: String, state: String },

    /// XEP-0333 read marker; also zeroes the conversation's unread counter.
    MarkRead { account_id: i64, conversation_id: i64, to: String, stanza_id: String },

    /// XEP-0444 reaction set (full replace per spec).
    React { account_id: i64, to: String, target_id: String, emojis: Vec<String> },

    /// Request older history (XEP-0313 MAM page) for a conversation.
    LoadHistory { account_id: i64, conversation_id: i64, before: Option<String> },

    /// Catch up on messages received since we last synced (forward MAM paging). Used on
    /// opening a conversation and on connect, so messages missed while away appear.
    SyncHistory { account_id: i64, conversation_id: i64 },

    /// Roster management (XEP-0237).
    AddContact { account_id: i64, jid: String, name: Option<String> },
    RemoveContact { account_id: i64, jid: String },

    /// XEP-0045 join a multi-user chat room with a nickname (+ optional room password).
    JoinMuc { account_id: i64, room: String, nick: String, password: Option<String> },

    /// Leave a MUC: send unavailable presence, drop the bookmark, and remove it locally.
    LeaveMuc { account_id: i64, room: String },

    /// Delete a conversation (and its local history) without touching the roster. Used to
    /// close a 1:1 chat.
    DeleteChat { account_id: i64, jid: String },

    /// Fetch a contact's avatar (XEP-0084) + nick (XEP-0172); usually on opening a chat.
    FetchPeerInfo { account_id: i64, jid: String },

    /// Fetch a MUC occupant's avatar photo (vCard-temp / XEP-0153) by room + nick.
    FetchMucAvatar { account_id: i64, room: String, nick: String },

    /// Fetch an avatar for a list row: a contact's PEP avatar, or (if `is_muc`) a room's
    /// vCard photo. Result arrives as `Event::Avatar { jid, data }`.
    FetchAvatar { account_id: i64, jid: String, is_muc: bool },

    /// Encrypt (aesgcm), HTTP-upload (XEP-0363) and send a file to `to`. An optional `caption`
    /// is delivered inside the same (encrypted, for OMEMO2) message.
    SendFile { account_id: i64, to: String, path: String, caption: Option<String> },

    /// Share SEVERAL files in ONE message (XEP-0447): each is uploaded, and the single message
    /// describes all of them. A single path behaves exactly like `SendFile`.
    SendFiles { account_id: i64, to: String, paths: Vec<String>, caption: Option<String> },

    /// Send a sticker (image at `path`) as a standalone message: an encrypted image when the chat
    /// is OMEMO2-encrypted, otherwise an inline XEP-0231 BoB sticker.
    SendSticker { account_id: i64, to: String, path: String },

    /// Download + decrypt a received `aesgcm://` file to the downloads folder.
    DownloadFile { account_id: i64, url: String, filename: String },

    /// Send a `.xdc` WebXDC app (file at `path`); a fresh `<thread>` becomes the instance key.
    SendWebxdcFile { account_id: i64, to: String, path: String },

    /// Send a WebXDC status update (the running app called `sendUpdate`) for instance `thread`.
    /// `notify` is the app's notification dict (selfAddr → text) serialized as JSON.
    SendWebxdcUpdate {
        account_id: i64,
        to: String,
        thread: String,
        payload: Option<String>,
        info: Option<String>,
        document: Option<String>,
        summary: Option<String>,
        notify: Option<String>,
    },

    /// Send ephemeral WebXDC realtime data (base64) for instance `thread`.
    SendWebxdcRealtime { account_id: i64, to: String, thread: String, data_b64: String },

    /// OMEMO2 trust decision (TOFU accept / reject) — flips `omemo_identities.trust`.
    SetOmemoTrust { account_id: i64, jid: String, device_id: i64, trust: i64 },

    /// Fetch our own profile + PQ OMEMO2 keys (this device + our other devices). Replies with
    /// `Event::OwnKeys`.
    FetchOwnKeys { account_id: i64 },

    /// Fetch a contact's PQ OMEMO2 device keys. Replies with `Event::ContactKeys`.
    FetchContactKeys { account_id: i64, jid: String },

    /// Out-of-band verification: mark every device of `jid` whose identity key matches one of
    /// `fingerprints` manually verified (trust = 3). `fingerprints` is bare 64-char hex, as
    /// produced by [`crate::uri::parse`] from a scanned QR code or a pasted verification link.
    /// Fingerprints that match nothing are ignored — they belong to a stack we do not run, or
    /// to a device we have not fetched yet. Replies with a refreshed `Event::ContactKeys` (or
    /// `Event::OwnKeys` for our own JID) and a toast.
    VerifyOmemoFingerprints { account_id: i64, jid: String, fingerprints: Vec<String> },

    /// Wipe all locally cached OMEMO2 *peer* state (sessions, identities + trust, PQ pins,
    /// cached device lists) and re-advertise our (unchanged) bundle, so keys rebuild cleanly on
    /// the next exchange. Our own identity/fingerprint is preserved. The recovery action for
    /// stale OMEMO2 state. Replies with a fresh `Event::OwnKeys`.
    ResetOmemo2Identities { account_id: i64 },

    /// LAST RESORT: wipe our OWN OMEMO2 hybrid identity (classical + ML-DSA-87 key pairs,
    /// device id, all pre-keys) plus all peer state, then generate and publish a brand-new
    /// identity. This device gets a NEW fingerprint and contacts MUST verify it again. Use only
    /// on suspected key compromise. Replies with a fresh `Event::OwnKeys`.
    RegenerateOmemo2Identity { account_id: i64 },

    /// Fetch a contact's / room's profile (photo + fields). For a MUC (`is_muc`), the fields
    /// come from disco#info (room name/description/occupants); otherwise from the contact's
    /// vCard / PEP. Replies with `Event::Vcard`.
    FetchVcard { account_id: i64, jid: String, is_muc: bool },

    /// Fetch a contact's current roster subscription state. Replies with `Event::Subscription`.
    FetchSubscription { account_id: i64, jid: String },

    /// RFC 6121 presence-subscription change (request/approve/revoke). After sending, the
    /// server pushes a roster update, which re-emits `Event::Subscription`.
    SetSubscription { account_id: i64, jid: String, action: Subscription },

    /// Toggle the app-wide "auto-trust new keys" (blind-trust) setting.
    SetAutoTrust { account_id: i64, value: bool },

    /// Set a conversation's notification mode ('all'|'mentioned'|'mentions_replies'|'none').
    SetNotify { account_id: i64, jid: String, mode: String },

    /// Start (create if needed) a MUC private-message conversation with `occupant_jid`
    /// (`room@host/nick`). Emits `ConversationsUpdated` so the new chat appears in the list.
    StartPrivate { account_id: i64, occupant_jid: String },

    /// XEP-0353 Jingle Message Initiation — ring a peer to start an audio (or audio+video) call.
    PlaceCall { account_id: i64, to: String, video: bool },
    /// Accept a ringing incoming call (sends `proceed` to the caller + `accept` to our devices).
    AcceptCall { account_id: i64, sid: String, peer: String },
    /// Decline a ringing incoming call (sends `reject`).
    DeclineCall { account_id: i64, sid: String, peer: String },
    /// Cancel an outgoing call we placed / hang up (sends `retract`).
    CancelCall { account_id: i64, sid: String, peer: String },
    /// Mute / unmute the microphone on an active call.
    SetCallMute { account_id: i64, sid: String, muted: bool },
    /// Turn the camera on/off on an active video call.
    SetCallCamera { account_id: i64, sid: String, enabled: bool },
    /// Start/stop screen sharing on an active call. When enabling, the client runs the
    /// xdg-desktop-portal ScreenCast picker, then the shared screen replaces the camera as the
    /// outgoing video track (upgrading an audio-only call to video first if needed).
    SetCallScreenShare { account_id: i64, sid: String, enabled: bool },
    /// Upgrade an active audio call to video (Jingle content-add renegotiation).
    UpgradeCallToVideo { account_id: i64, sid: String },
    /// Accept a peer's incoming video upgrade (answers their content-add + sends our camera).
    AcceptVideoUpgrade { account_id: i64, sid: String },
    /// Decline a peer's incoming video upgrade (Jingle content-reject).
    DeclineVideoUpgrade { account_id: i64, sid: String },

    /// XEP-0272 Muji — start/join a group call in the MUC `room` (we must already be an
    /// occupant). Announces our `<muji>` presence and meshes with the other ready participants.
    PlaceGroupCall { account_id: i64, room: String, video: bool },
    /// Leave a Muji group call: drop our `<muji>` presence and terminate every per-pair session.
    LeaveGroupCall { account_id: i64, room: String },
    /// Mute / unmute our microphone across every per-pair session of a group call.
    SetGroupCallMute { account_id: i64, room: String, muted: bool },
    /// Turn our camera on/off across every per-pair session of a group video call.
    SetGroupCallCamera { account_id: i64, room: String, enabled: bool },
    /// Start/stop sharing our screen to a group video call. When enabling, the client runs the
    /// xdg-desktop-portal ScreenCast picker; the shared screen then replaces the camera as the
    /// outgoing video for every leg (via the shared camera hub).
    SetGroupCallScreenShare { account_id: i64, room: String, enabled: bool },

    /// Fetch a JID's microblog (XEP-0277) feed posts. Replies with `Event::FeedPosts`.
    FetchFeed { account_id: i64, jid: String },
    /// Publish a microblog post (title + Markdown content) to our own social-feed node.
    /// `attachment_path` is a local file to upload (metadata stripped) and attach, or empty;
    /// `attachment` an already uploaded one (URL, MIME) kept when editing. `link` is a related
    /// web link or empty. `edit` (post id, original publish time) replaces that post.
    PublishPost {
        account_id: i64,
        title: String,
        content: String,
        attachment_path: String,
        attachment: Option<(String, String)>,
        link: String,
        edit: Option<(String, i64)>,
    },
    /// Fetch the comments node `node` on `service` (a post's replies link). Replies with
    /// `Event::FeedComments`.
    FetchComments { account_id: i64, service: String, node: String },
    /// Publish a comment to the comments node `node` on `service`.
    PublishComment { account_id: i64, service: String, node: String, content: String },
    /// Retract one of our own feed posts (from our `urn:xmpp:microblog:0` node).
    RetractPost { account_id: i64, post_id: String },
    /// Retract comment `comment_id` from the comments node `node` on `service` (allowed if we
    /// authored the comment or own the post).
    RetractComment { account_id: i64, service: String, node: String, comment_id: String },

    /// Publish a Story: upload `path` (plaintext, metadata stripped) and publish it to our
    /// stories node.
    PublishStory { account_id: i64, path: String, title: String },
    /// Fetch stories from ourselves + all subscribed contacts. Replies with `StoriesUpdated`.
    FetchStories { account_id: i64 },
    /// Retract one of our own stories.
    RetractStory { account_id: i64, uuid: String },

    /// Graceful shutdown of the whole core runtime.
    Shutdown,
}
