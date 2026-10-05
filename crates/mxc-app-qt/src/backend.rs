//! The `Backend` QObject — the single object QML talks to.
//!
//! This is the Qt-side mirror of the GTK app's `State`: QML calls invokables (e.g.
//! `login`), the Rust side drives the `mxc-proto` core on a tokio runtime, and core
//! `Event`s are marshalled back onto the Qt thread to update QObject properties (which
//! QML bindings observe). The actual core wiring lives in [`crate::core`].

use std::pin::Pin;

use cxx_qt::Threading;
use cxx_qt_lib::QString;

#[cxx_qt::bridge]
pub mod qobject {
    extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    extern "RustQt" {
        /// Exposed to QML as `Backend` under the `de.monocles.chat` import.
        #[qobject]
        #[qml_element]
        #[qproperty(QString, status)]
        #[qproperty(bool, connected)]
        /// The logged-in account's bare JID — set when a session starts (manual or auto-login),
        /// so QML can flip to the shell on auto-login without a button press.
        #[qproperty(QString, account_jid, cxx_name = "accountJid")]
        #[qproperty(QString, own_fingerprint, cxx_name = "ownFingerprint")]
        /// `xmpp:…?omemo-sid-…=<key>` for this device — shown as a QR code (and a copyable
        /// link) so contacts can verify us out of band. Empty until our identity exists.
        #[qproperty(QString, own_verification_uri, cxx_name = "ownVerificationUri")]
        #[qproperty(bool, auto_trust, cxx_name = "autoTrust")]
        /// Our own presence for the profile dialog: availability `show` ("" = online, or
        /// chat/away/xa/dnd) + free-text status message. Filled from `Event::OwnKeys`.
        #[qproperty(QString, own_show, cxx_name = "ownShow")]
        #[qproperty(QString, own_status, cxx_name = "ownStatus")]
        /// Our published nickname (XEP-0172), filled by `fetchNick(accountJid)`.
        #[qproperty(QString, own_nick, cxx_name = "ownNick")]
        /// Whether the donation banner is due (not snoozed in the last week).
        #[qproperty(bool, donation_due, cxx_name = "donationDue")]
        /// Whether the default monocles support-room entry is shown in Contacts (until dismissed).
        #[qproperty(bool, support_room_visible, cxx_name = "supportRoomVisible")]
        /// Chat-background mode: "default" (bundled doodle tile), "none", or "custom".
        #[qproperty(QString, chat_bg_mode, cxx_name = "chatBgMode")]
        /// Custom chat-background image path (used when chatBgMode == "custom").
        #[qproperty(QString, chat_bg_custom_path, cxx_name = "chatBgCustomPath")]
        /// Preferred camera device path for video calls ("" = automatic selection).
        #[qproperty(QString, preferred_camera, cxx_name = "preferredCamera")]
        /// The app version (Cargo package version) — shown in the About dialog.
        #[qproperty(QString, app_version, cxx_name = "appVersion")]
        // --- 1:1 call state (XEP-0353 JMI + XEP-0166 Jingle) ---
        /// True while a call screen should be shown (ringing/connecting/active).
        #[qproperty(bool, call_active, cxx_name = "callActive")]
        /// Other party's bare JID, the JMI/Jingle session id, and whether video was proposed.
        #[qproperty(QString, call_peer, cxx_name = "callPeer")]
        #[qproperty(bool, call_video, cxx_name = "callVideo")]
        /// True while we're sharing our screen on the active call (the shared screen replaces the
        /// camera as the outgoing video). Drives the screen-share button's checked state.
        #[qproperty(bool, call_screen_sharing, cxx_name = "callScreenSharing")]
        /// "incoming" | "outgoing" | "connecting" | "active" | "ended".
        #[qproperty(QString, call_state, cxx_name = "callState")]
        /// Microphone mute state on the active call.
        #[qproperty(bool, call_muted, cxx_name = "callMuted")]
        /// True while a peer's incoming video-upgrade request awaits the user's consent.
        #[qproperty(bool, call_video_request, cxx_name = "callVideoRequest")]
        /// Active call's PQ OMEMO2 trust level: 0 = not authenticated/untrusted (no icon),
        /// 1 = BTBV-trusted (lock icon), 2 = manually verified (shield icon).
        #[qproperty(i32, call_trust, cxx_name = "callTrust")]
        /// The authenticated peer's PQ OMEMO2 identity fingerprint (for the indicator tooltip).
        #[qproperty(QString, call_verified_fp, cxx_name = "callVerifiedFp")]
        /// The authenticated peer's PQ OMEMO2 device id (so the UI can manually verify the key).
        #[qproperty(i64, call_verified_device, cxx_name = "callVerifiedDevice")]
        /// Latest remote / local-preview video frame as a `data:` URL (empty = none yet).
        #[qproperty(QString, remote_frame, cxx_name = "remoteFrame")]
        #[qproperty(QString, local_frame, cxx_name = "localFrame")]
        // --- group call (XEP-0272 Muji) state ---
        /// True while a group call is in progress (shows the conference panel).
        #[qproperty(bool, conference_active, cxx_name = "conferenceActive")]
        /// The conference (MUC) bare JID of the active group call.
        #[qproperty(QString, conference_room, cxx_name = "conferenceRoom")]
        /// Whether the group call carries video (audio-only for now).
        #[qproperty(bool, conference_video, cxx_name = "conferenceVideo")]
        /// Our microphone mute state across the whole group call.
        #[qproperty(bool, conference_muted, cxx_name = "conferenceMuted")]
        /// Whether our camera is on across the whole group video call.
        #[qproperty(bool, conference_camera_on, cxx_name = "conferenceCameraOn")]
        /// Whether we are sharing our screen to the group video call.
        #[qproperty(bool, conference_screen_sharing, cxx_name = "conferenceScreenSharing")]
        /// A pending group-call invite: the room another member started a call in (empty = none)
        /// and the nick who started it. Drives the "Join group call" prompt.
        #[qproperty(QString, conference_invite_room, cxx_name = "conferenceInviteRoom")]
        #[qproperty(QString, conference_invite_from, cxx_name = "conferenceInviteFrom")]
        // --- audio playback (voice messages) ---
        /// The file currently loaded in the audio player ("" = none), its play state, and the
        /// playback position / duration in ms (for the message player bubble).
        #[qproperty(QString, audio_path, cxx_name = "audioPath")]
        #[qproperty(bool, audio_playing, cxx_name = "audioPlaying")]
        #[qproperty(i64, audio_pos, cxx_name = "audioPos")]
        #[qproperty(i64, audio_duration, cxx_name = "audioDuration")]
        type Backend = super::BackendRust;

        /// Open the store, spawn the core for this account and connect. Named `login`
        /// (not `connect`) to avoid clashing with QObject::connect on the C++ side.
        #[qinvokable]
        fn login(self: Pin<&mut Backend>, jid: &QString, password: &QString);

        /// Try to silently re-connect using a previously-saved account + sealed password
        /// (called once at startup). No-op if there's no enabled account with a stored secret.
        #[qinvokable]
        #[cxx_name = "tryAutologin"]
        fn try_autologin(self: Pin<&mut Backend>);

        /// Log out: disconnect, forget the sealed password + autologin, back to the login page.
        #[qinvokable]
        fn logout(self: Pin<&mut Backend>);

        /// "Not now" on the donation banner: hide it for a week.
        #[qinvokable]
        #[cxx_name = "snoozeDonation"]
        fn snooze_donation(self: Pin<&mut Backend>);

        /// Remove the default monocles support-room entry from Contacts (persisted, won't return).
        #[qinvokable]
        #[cxx_name = "dismissSupportRoom"]
        fn dismiss_support_room(self: Pin<&mut Backend>);

        /// Set + persist the chat-background mode ("default" | "none" | "custom").
        #[qinvokable]
        #[cxx_name = "setChatBackgroundMode"]
        fn change_chat_bg_mode(self: Pin<&mut Backend>, mode: &QString);

        /// Set + persist the custom chat-background image path.
        #[qinvokable]
        #[cxx_name = "setChatBackgroundImage"]
        fn change_chat_bg_custom_path(self: Pin<&mut Backend>, path: &QString);

        /// Send a chat message to peer `to` (bare JID); OMEMO2 when `encrypted`. `reply_to`
        /// is the XEP-0461 target marker, or empty for a normal message.
        #[qinvokable]
        #[cxx_name = "sendMessage"]
        fn send_message(
            self: Pin<&mut Backend>,
            to: &QString,
            body: &QString,
            encrypted: bool,
            reply_to: &QString,
        );

        /// Toggle a XEP-0444 reaction `emoji` on message `target` in chat with peer `to`.
        #[qinvokable]
        fn react(self: Pin<&mut Backend>, to: &QString, target: &QString, emoji: &QString);

        /// Join (XEP-0045) a multi-user chat room with `nick`.
        #[qinvokable]
        #[cxx_name = "joinMuc"]
        fn join_muc(self: Pin<&mut Backend>, room: &QString, nick: &QString);

        /// Start a private message with a MUC occupant (`room@host/nick`).
        #[qinvokable]
        #[cxx_name = "startPrivate"]
        fn start_private(self: Pin<&mut Backend>, occupant_jid: &QString);

        /// Lazily fetch one occupant's avatar (deduped) — called per visible members-list
        /// row, NOT for the whole room at once (big rooms froze the app).
        #[qinvokable]
        #[cxx_name = "fetchMucAvatar"]
        fn fetch_muc_avatar(self: Pin<&mut Backend>, occupant_jid: &QString);

        /// Add a contact to the roster (+ request their presence, with pre-approval so their
        /// counter-request is auto-granted). `name` is an optional roster display name.
        #[qinvokable]
        #[cxx_name = "addContact"]
        fn add_contact(self: Pin<&mut Backend>, jid: &QString, name: &QString);

        /// Send the image at `path` as a sticker to peer `to`.
        #[qinvokable]
        #[cxx_name = "sendSticker"]
        fn send_sticker(self: Pin<&mut Backend>, to: &QString, path: &QString);

        /// Send a file (image/document) to peer `to`.
        #[qinvokable]
        #[cxx_name = "sendFile"]
        fn send_file(self: Pin<&mut Backend>, to: &QString, path: &QString);

        /// Send a file with a caption delivered in the same (encrypted, for OMEMO2) message.
        #[qinvokable]
        #[cxx_name = "sendFileWithCaption"]
        fn send_file_with_caption(
            self: Pin<&mut Backend>,
            to: &QString,
            path: &QString,
            caption: &QString,
        );

        /// Share several files in ONE message (XEP-0447), with an optional shared caption.
        /// `paths` is newline-separated — QML hands over the file dialog's selection joined
        /// with "\n". A single path behaves exactly like `sendFileWithCaption`.
        #[qinvokable]
        #[cxx_name = "sendFiles"]
        fn send_files(
            self: Pin<&mut Backend>,
            to: &QString,
            paths: &QString,
            caption: &QString,
        );

        /// Download (+ decrypt, for `aesgcm://`) a shared file to the downloads folder; the
        /// `fileSaved` signal fires with the local path when done (QML opens it).
        #[qinvokable]
        #[cxx_name = "downloadFile"]
        fn download_file(self: Pin<&mut Backend>, url: &QString, filename: &QString);

        /// Fetch a contact's / room's vCard4 profile (reply via `vcardReady`).
        #[qinvokable]
        #[cxx_name = "fetchVcard"]
        fn fetch_vcard(self: Pin<&mut Backend>, jid: &QString, is_muc: bool);

        /// Fetch a contact's RFC 6121 subscription state (reply via `subscriptionChanged`).
        #[qinvokable]
        #[cxx_name = "fetchSubscription"]
        fn fetch_subscription(self: Pin<&mut Backend>, jid: &QString);

        /// Change a presence subscription: `action` is one of
        /// subscribe | unsubscribe (receive their presence) or
        /// subscribed | unsubscribed (let them receive ours).
        #[qinvokable]
        #[cxx_name = "setSubscription"]
        fn set_subscription(self: Pin<&mut Backend>, jid: &QString, action: &QString);

        /// All available sticker image paths, newline-joined (for the sticker drawer).
        #[qinvokable]
        #[cxx_name = "stickerFiles"]
        fn sticker_files(self: &Backend) -> QString;

        /// The stickers folder path (created if missing) — the picker's "open folder" button.
        #[qinvokable]
        #[cxx_name = "stickerDir"]
        fn sticker_dir(self: &Backend) -> QString;

        /// Publish a story: upload the image/video at `path` (+ optional `title`).
        #[qinvokable]
        #[cxx_name = "publishStory"]
        fn publish_story(self: Pin<&mut Backend>, path: &QString, title: &QString);

        /// Fetch stories from ourselves + subscribed contacts.
        #[qinvokable]
        #[cxx_name = "fetchStories"]
        fn fetch_stories(self: Pin<&mut Backend>);

        /// Retract one of our own stories.
        #[qinvokable]
        #[cxx_name = "retractStory"]
        fn retract_story(self: Pin<&mut Backend>, uuid: &QString);

        /// Fetch our own + all followed feeds (XEP-0472).
        #[qinvokable]
        #[cxx_name = "fetchFeeds"]
        fn fetch_feeds(self: Pin<&mut Backend>);

        /// Fetch a post's comments (separate node); reply arrives as `feedsChanged`.
        #[qinvokable]
        #[cxx_name = "fetchComments"]
        fn fetch_comments(self: Pin<&mut Backend>, post_author: &QString, post_id: &QString);

        /// Retract one of our own posts / a comment (ours, or any on our own post).
        #[qinvokable]
        #[cxx_name = "retractPost"]
        fn retract_post(self: Pin<&mut Backend>, post_id: &QString);
        #[qinvokable]
        #[cxx_name = "retractComment"]
        fn retract_comment(self: Pin<&mut Backend>, post_author: &QString, post_id: &QString, comment_id: &QString);

        /// Publish a feed post / a comment on a post.
        #[qinvokable]
        #[cxx_name = "publishPost"]
        fn publish_post(self: Pin<&mut Backend>, title: &QString, content: &QString);
        #[qinvokable]
        #[cxx_name = "publishComment"]
        fn publish_comment(self: Pin<&mut Backend>, post_author: &QString, post_id: &QString, content: &QString);

        /// Toggle our "♥" like on a post.
        #[qinvokable]
        #[cxx_name = "toggleLike"]
        fn toggle_like(self: Pin<&mut Backend>, post_author: &QString, post_id: &QString);

        /// Follow / unfollow a feed (by bare JID); `followedFeeds` lists them (newline-joined).
        #[qinvokable]
        #[cxx_name = "followFeed"]
        fn follow_feed(self: Pin<&mut Backend>, jid: &QString);
        #[qinvokable]
        #[cxx_name = "unfollowFeed"]
        fn unfollow_feed(self: Pin<&mut Backend>, jid: &QString);
        #[qinvokable]
        #[cxx_name = "followedFeeds"]
        fn followed_feeds(self: &Backend) -> QString;

        /// Ring `to` (bare JID) to start an audio (or audio+video) call.
        #[qinvokable]
        #[cxx_name = "placeCall"]
        fn place_call(self: Pin<&mut Backend>, to: &QString, video: bool);

        /// Accept / decline / hang up the current call (uses the tracked sid + peer).
        #[qinvokable]
        #[cxx_name = "acceptCall"]
        fn accept_call(self: Pin<&mut Backend>);
        #[qinvokable]
        #[cxx_name = "declineCall"]
        fn decline_call(self: Pin<&mut Backend>);
        #[qinvokable]
        #[cxx_name = "hangUpCall"]
        fn hang_up_call(self: Pin<&mut Backend>);

        /// Mute / unmute the microphone on the active call.
        #[qinvokable]
        #[cxx_name = "setCallMute"]
        fn set_call_mute(self: Pin<&mut Backend>, muted: bool);

        /// Turn the camera on/off on the active video call.
        #[qinvokable]
        #[cxx_name = "setCallCamera"]
        fn set_call_camera(self: Pin<&mut Backend>, enabled: bool);

        /// Start/stop screen sharing on the active call. Enabling pops the system screen/window
        /// picker; the chosen screen then replaces the camera as the outgoing video.
        #[qinvokable]
        #[cxx_name = "setCallScreenShare"]
        fn set_call_screen_share(self: Pin<&mut Backend>, enabled: bool);

        /// Upgrade the active audio call to video (Jingle content-add renegotiation).
        #[qinvokable]
        #[cxx_name = "upgradeCallToVideo"]
        fn upgrade_call_to_video(self: Pin<&mut Backend>);

        /// Accept the peer's incoming video-upgrade request (clears the prompt).
        #[qinvokable]
        #[cxx_name = "acceptVideoUpgrade"]
        fn accept_video_upgrade(self: Pin<&mut Backend>);

        /// Decline the peer's incoming video-upgrade request (clears the prompt).
        #[qinvokable]
        #[cxx_name = "declineVideoUpgrade"]
        fn decline_video_upgrade(self: Pin<&mut Backend>);

        // --- group calls (XEP-0272 Muji) ---
        /// Start / join a Muji group call in the MUC `room` (we must already be an occupant).
        #[qinvokable]
        #[cxx_name = "placeGroupCall"]
        fn place_group_call(self: Pin<&mut Backend>, room: &QString, video: bool);

        /// Leave the active group call.
        #[qinvokable]
        #[cxx_name = "leaveGroupCall"]
        fn leave_group_call(self: Pin<&mut Backend>);

        /// Mute / unmute our microphone across the whole group call.
        #[qinvokable]
        #[cxx_name = "setConferenceMute"]
        fn set_conference_mute(self: Pin<&mut Backend>, muted: bool);

        /// Turn our camera on/off across the whole group video call.
        #[qinvokable]
        #[cxx_name = "setConferenceCamera"]
        fn set_conference_camera(self: Pin<&mut Backend>, enabled: bool);

        /// Start / stop sharing our screen to the group video call (runs the portal picker).
        #[qinvokable]
        #[cxx_name = "setConferenceScreenShare"]
        fn set_conference_screen_share(self: Pin<&mut Backend>, enabled: bool);

        /// Accept a pending group-call invite (join the inviting room, audio or video).
        #[qinvokable]
        #[cxx_name = "joinGroupCall"]
        fn join_group_call(self: Pin<&mut Backend>, video: bool);

        /// Dismiss a pending group-call invite without joining.
        #[qinvokable]
        #[cxx_name = "dismissGroupCallInvite"]
        fn dismiss_group_call_invite(self: Pin<&mut Backend>);

        // --- voice messages ---
        /// Start / cancel recording a voice message; `stopVoiceAndSend` finalises + sends it to `to`.
        #[qinvokable]
        #[cxx_name = "startVoice"]
        fn start_voice(self: Pin<&mut Backend>) -> bool;
        #[qinvokable]
        #[cxx_name = "stopVoiceAndSend"]
        fn stop_voice_and_send(self: Pin<&mut Backend>, to: &QString);
        #[qinvokable]
        #[cxx_name = "cancelVoice"]
        fn cancel_voice(self: Pin<&mut Backend>);

        /// Play/pause a (downloaded) audio file in the shared player; seek to `ms`.
        #[qinvokable]
        #[cxx_name = "audioToggle"]
        fn audio_toggle(self: Pin<&mut Backend>, path: &QString);
        #[qinvokable]
        #[cxx_name = "audioSeek"]
        fn audio_seek(self: Pin<&mut Backend>, ms: i64);

        /// Open the WebXDC app shared in chat `peer` (instance `thread`, upload `url`):
        /// downloads + extracts it, then emits `webxdcReady` for QML to show the window.
        #[qinvokable]
        #[cxx_name = "openWebxdc"]
        fn open_webxdc(self: Pin<&mut Backend>, peer: &QString, thread: &QString, url: &QString);

        /// The WebXDC app window closed — drop the live instance.
        #[qinvokable]
        #[cxx_name = "closeWebxdc"]
        fn close_webxdc(self: Pin<&mut Backend>);

        /// Whether `room` supports OMEMO (gates the encryption toggle for MUCs).
        #[qinvokable]
        #[cxx_name = "mucOmemoCapable"]
        fn muc_omemo_capable(self: &Backend, room: &QString) -> bool;

        /// JSON array of usable color cameras `[{"name","path"}, …]` for the settings picker.
        #[qinvokable]
        #[cxx_name = "cameraListJson"]
        fn camera_list_json(self: &Backend) -> QString;

        /// Set + persist the preferred camera device path ("" = automatic).
        #[qinvokable]
        #[cxx_name = "selectPreferredCamera"]
        fn change_preferred_camera(self: Pin<&mut Backend>, path: &QString);

        /// Remove a conversation from the chats list (keeps the roster entry).
        #[qinvokable]
        #[cxx_name = "deleteChat"]
        fn delete_chat(self: Pin<&mut Backend>, jid: &QString);
        /// Leave a group chat.
        #[qinvokable]
        #[cxx_name = "leaveMuc"]
        fn leave_muc(self: Pin<&mut Backend>, room: &QString);
        /// Remove a contact from the roster entirely.
        #[qinvokable]
        #[cxx_name = "removeContact"]
        fn remove_contact(self: Pin<&mut Backend>, jid: &QString);

        /// Set OMEMO2 trust for a device of `jid` (1 = trusted/enabled, 2 = untrusted/disabled,
        /// 3 = manually verified).
        #[qinvokable]
        #[cxx_name = "setTrust"]
        fn set_trust(self: Pin<&mut Backend>, jid: &QString, device_id: i64, trust: i64);

        /// Manually verify the active call peer's PQ OMEMO2 key (sets trust = 3 for
        /// `callPeer`/`callVerifiedDevice`) and flip the call indicator to "verified" (shield).
        #[qinvokable]
        #[cxx_name = "verifyCallKey"]
        fn verify_call_key(self: Pin<&mut Backend>);

        /// Verify `jid`'s keys from a scanned QR code or a pasted verification link. Returns
        /// false when the text is not a verification link for that JID (the dialog then shows
        /// an error); a successful hand-off is reported by a toast from the core.
        #[qinvokable]
        #[cxx_name = "verifyFromLink"]
        fn verify_from_link(self: Pin<&mut Backend>, jid: &QString, text: &QString) -> bool;

        /// The QR modules for `text` as `"<size>:<0/1 per module, row-major>"`, or an empty
        /// string when it cannot be encoded. QML draws it on a Canvas — no image codec or SVG
        /// plugin involved.
        #[qinvokable]
        #[cxx_name = "qrMatrix"]
        fn qr_matrix(self: &Backend, text: &QString) -> QString;

        /// Toggle the app-wide "auto-trust new keys" (blind-trust) setting. (Distinct from the
        /// generated `autoTrust` property setter, which only mirrors the server's value.)
        #[qinvokable]
        #[cxx_name = "toggleAutoTrust"]
        fn toggle_auto_trust(self: Pin<&mut Backend>, value: bool);

        /// Reset (wipe + rebuild) our cached OMEMO2 peer keys/sessions — the recovery action for
        /// stale OMEMO2 state. Our own identity (fingerprint) is preserved.
        #[qinvokable]
        #[cxx_name = "resetOmemo2Identities"]
        fn reset_omemo2_identities(self: Pin<&mut Backend>);

        /// LAST RESORT: regenerate our OWN OMEMO2 identity (new key pairs, new device id, new
        /// fingerprint) and wipe all peer state. Contacts must verify this device again. Only
        /// for suspected key compromise.
        #[qinvokable]
        #[cxx_name = "regenerateOmemo2Identity"]
        fn regenerate_omemo2_identity(self: Pin<&mut Backend>);

        /// Set + broadcast our own presence (profile dialog): `show` ∈ ""|chat|away|xa|dnd,
        /// `status` is the free-text message. Persisted and re-sent on reconnect by the core.
        #[qinvokable]
        #[cxx_name = "setPresence"]
        fn set_presence(self: Pin<&mut Backend>, show: &QString, status: &QString);

        /// Publish the image at `path` as our avatar (scaled + JPEG-encoded off-thread).
        #[qinvokable]
        #[cxx_name = "publishAvatar"]
        fn publish_avatar(self: Pin<&mut Backend>, path: &QString);

        /// Publish our nickname (XEP-0172).
        #[qinvokable]
        #[cxx_name = "setNick"]
        fn set_nick(self: Pin<&mut Backend>, nick: &QString);

        /// Fetch a published nickname; ours lands in the `ownNick` property.
        #[qinvokable]
        #[cxx_name = "fetchNick"]
        fn fetch_nick(self: Pin<&mut Backend>, jid: &QString);

        /// The on-disk cached avatar path for `jid` ("" when none cached yet).
        #[qinvokable]
        #[cxx_name = "avatarPathFor"]
        fn avatar_path_for(self: &Backend, jid: &QString) -> QString;

        /// Whether the image file at `path` is animated (GIF / animated WebP) — picks the
        /// QML element: AnimatedImage (QMovie can't read static JPEG) vs plain Image.
        #[qinvokable]
        #[cxx_name = "isAnimatedImage"]
        fn is_animated_image(self: &Backend, path: &QString) -> bool;

        /// Emitted when a room's OMEMO capability changed (re-query `mucOmemoCapable`).
        #[qsignal]
        #[cxx_name = "mucPrivacyChanged"]
        fn muc_privacy_changed(self: Pin<&mut Backend>);

        /// Emitted when the conversation list changed (models should reload).
        #[qsignal]
        #[cxx_name = "conversationsChanged"]
        fn conversations_changed(self: Pin<&mut Backend>);

        /// Emitted when a message was stored in conversation `conversation_id`.
        #[qsignal]
        #[cxx_name = "messageStored"]
        fn message_stored(self: Pin<&mut Backend>, conversation_id: i64);

        /// Emitted when a downloaded file finished saving; `path` is the local file (QML opens it).
        #[qsignal]
        #[cxx_name = "fileSaved"]
        fn file_saved(self: Pin<&mut Backend>, path: QString);

        /// Emitted when the open conversation should reload (e.g. a delivery-state change).
        #[qsignal]
        #[cxx_name = "refreshOpen"]
        fn refresh_open(self: Pin<&mut Backend>);

        /// Emitted when one message's reactions changed — update that row in place (no reload).
        #[qsignal]
        #[cxx_name = "reactionsUpdated"]
        fn reactions_updated(self: Pin<&mut Backend>, message_id: i64, reactions: QString);

        /// Emitted when a vCard arrived for `jid`; `fields` is "label\tvalue" lines.
        #[qsignal]
        #[cxx_name = "vcardReady"]
        fn vcard_ready(self: Pin<&mut Backend>, jid: QString, fields: QString);

        /// Emitted with a contact's RFC 6121 subscription state ("none"|"to"|"from"|"both";
        /// `ask` is "subscribe" while our request awaits their approval, else empty).
        #[qsignal]
        #[cxx_name = "subscriptionChanged"]
        fn subscription_changed(self: Pin<&mut Backend>, jid: QString, subscription: QString, ask: QString);

        /// Emitted when `jid` asks to see our presence (RFC 6121 subscribe) — show an
        /// Allow/Decline prompt. `nick` is their advertised XEP-0172 nickname or empty.
        #[qsignal]
        #[cxx_name = "subscriptionRequest"]
        fn subscription_request(self: Pin<&mut Backend>, jid: QString, nick: QString);

        /// Emitted when OMEMO2 device keys for `jid` arrived (or `__own__` for our own); the
        /// device model showing that JID should `reload()`.
        #[qsignal]
        #[cxx_name = "keysChanged"]
        fn keys_changed(self: Pin<&mut Backend>, jid: QString);

        /// Passive feedback from the core (`Event::Toast`) — shown in the toast banner.
        #[qsignal]
        fn toast(self: Pin<&mut Backend>, text: QString);

        /// Emitted when the call history changed (a call ended) — reload the Calls list.
        #[qsignal]
        #[cxx_name = "callsChanged"]
        fn calls_changed(self: Pin<&mut Backend>);

        /// Emitted when the active group call's participants changed — the `ConferenceModel`
        /// showing them should `load()`.
        #[qsignal]
        #[cxx_name = "conferenceChanged"]
        fn conference_changed(self: Pin<&mut Backend>);

        /// Emitted with a fresh video frame (`data:` URL) for a group-call participant, keyed by
        /// their per-pair session id (`sid`). The matching tile updates its image.
        #[qsignal]
        #[cxx_name = "conferenceFrame"]
        fn conference_frame(self: Pin<&mut Backend>, sid: QString, url: QString);

        /// Emitted when the Stories cache changed — reload the Stories feed.
        #[qsignal]
        #[cxx_name = "storiesChanged"]
        fn stories_changed(self: Pin<&mut Backend>);

        /// Emitted when feed posts arrived (XEP-0472) — reload the Feeds list / open post.
        #[qsignal]
        #[cxx_name = "feedsChanged"]
        fn feeds_changed(self: Pin<&mut Backend>);

        /// Emitted when an opened WebXDC app is extracted + served — QML creates the window.
        #[qsignal]
        #[cxx_name = "webxdcReady"]
        fn webxdc_ready(self: Pin<&mut Backend>, thread: QString, host: QString);

        /// Emitted with new status updates for the running app: `items` is a comma-joined list
        /// of update JSON objects, fed to the app via `__webxdcPushUpdates([items])`.
        #[qsignal]
        #[cxx_name = "webxdcUpdates"]
        fn webxdc_updates(self: Pin<&mut Backend>, thread: QString, items: QString);

        /// Emitted with an ephemeral realtime packet (base64) for the running app.
        #[qsignal]
        #[cxx_name = "webxdcRealtime"]
        fn webxdc_realtime(self: Pin<&mut Backend>, thread: QString, data_b64: QString);

        /// Emitted when an app update addressed a notification to us (`update.notify`).
        #[qsignal]
        #[cxx_name = "webxdcNotify"]
        fn webxdc_notify(self: Pin<&mut Backend>, text: QString);
    }

    // Lets the Rust side obtain a `CxxQtThread` to queue property updates back onto the
    // Qt thread from the tokio event pump (see crate::core).
    impl cxx_qt::Threading for Backend {}
}

/// Backing data for the `Backend` QObject.
pub struct BackendRust {
    status: QString,
    connected: bool,
    account_jid: QString,
    own_fingerprint: QString,
    own_verification_uri: QString,
    auto_trust: bool,
    own_show: QString,
    own_status: QString,
    own_nick: QString,
    donation_due: bool,
    support_room_visible: bool,
    chat_bg_mode: QString,
    chat_bg_custom_path: QString,
    preferred_camera: QString,
    app_version: QString,
    call_active: bool,
    call_peer: QString,
    call_video: bool,
    call_screen_sharing: bool,
    call_state: QString,
    call_muted: bool,
    call_video_request: bool,
    call_trust: i32,
    call_verified_fp: QString,
    call_verified_device: i64,
    remote_frame: QString,
    local_frame: QString,
    conference_active: bool,
    conference_room: QString,
    conference_video: bool,
    conference_muted: bool,
    conference_camera_on: bool,
    conference_screen_sharing: bool,
    conference_invite_room: QString,
    conference_invite_from: QString,
    audio_path: QString,
    audio_playing: bool,
    audio_pos: i64,
    audio_duration: i64,
}

impl Default for BackendRust {
    fn default() -> Self {
        Self {
            status: QString::from("Disconnected"),
            connected: false,
            account_jid: QString::default(),
            own_fingerprint: QString::default(),
            own_verification_uri: QString::default(),
            auto_trust: false,
            own_show: QString::default(),
            own_status: QString::default(),
            own_nick: QString::default(),
            donation_due: false,
            // Shown by default; the startup check hides it if the user dismissed it before.
            support_room_visible: true,
            // Bundled doodle background by default; the startup check applies the saved choice.
            chat_bg_mode: QString::from("default"),
            chat_bg_custom_path: QString::default(),
            // Automatic by default; the startup check applies the saved choice.
            preferred_camera: QString::default(),
            app_version: QString::from(env!("CARGO_PKG_VERSION")),
            call_active: false,
            call_peer: QString::default(),
            call_video: false,
            call_screen_sharing: false,
            call_state: QString::default(),
            call_muted: false,
            call_video_request: false,
            call_trust: 0,
            call_verified_fp: QString::default(),
            call_verified_device: 0,
            remote_frame: QString::default(),
            local_frame: QString::default(),
            conference_active: false,
            conference_room: QString::default(),
            conference_video: false,
            conference_muted: false,
            conference_camera_on: true,
            conference_screen_sharing: false,
            conference_invite_room: QString::default(),
            conference_invite_from: QString::default(),
            audio_path: QString::default(),
            audio_playing: false,
            audio_pos: 0,
            audio_duration: 0,
        }
    }
}

impl qobject::Backend {
    /// QML entry point — kicks off connection on the core runtime.
    pub fn login(self: Pin<&mut Self>, jid: &QString, password: &QString) {
        let jid = jid.to_string();
        let password = password.to_string();
        if jid.is_empty() {
            return;
        }
        // A handle that lets the background task push state back onto the Qt thread.
        let qt_thread = self.qt_thread();
        crate::session::start(jid, password, qt_thread);
    }

    /// QML entry point — attempt silent re-login from the saved account + sealed password.
    pub fn try_autologin(self: Pin<&mut Self>) {
        crate::session::try_autologin(self.qt_thread());
    }

    /// QML entry point — log out of the current account.
    pub fn logout(self: Pin<&mut Self>) {
        crate::session::logout();
    }

    /// QML entry point — snooze the donation banner for a week.
    pub fn snooze_donation(mut self: Pin<&mut Self>) {
        self.as_mut().set_donation_due(false);
        crate::session::snooze_donation();
    }

    /// QML entry point — permanently remove the default support-room entry from Contacts.
    pub fn dismiss_support_room(mut self: Pin<&mut Self>) {
        self.as_mut().set_support_room_visible(false);
        crate::session::dismiss_support_room();
    }

    /// QML entry point — set + persist the chat-background mode.
    pub fn change_chat_bg_mode(mut self: Pin<&mut Self>, mode: &QString) {
        self.as_mut().set_chat_bg_mode(mode.clone());
        crate::session::set_chat_bg_mode(mode.to_string());
    }

    /// QML entry point — set + persist the custom chat-background image path.
    pub fn change_chat_bg_custom_path(mut self: Pin<&mut Self>, path: &QString) {
        self.as_mut().set_chat_bg_custom_path(path.clone());
        crate::session::set_chat_bg_custom_path(path.to_string());
    }

    /// QML entry point — usable color cameras as a JSON array for the settings picker.
    pub fn camera_list_json(&self) -> QString {
        QString::from(&crate::session::camera_list_json())
    }

    /// QML entry point — set + persist the preferred camera ("" = automatic).
    pub fn change_preferred_camera(mut self: Pin<&mut Self>, path: &QString) {
        self.as_mut().set_preferred_camera(path.clone());
        crate::session::set_preferred_camera(path.to_string());
    }

    /// QML entry point — send a message via the connected core (fire-and-forget; the
    /// stored echo arrives back as `messageStored`).
    pub fn send_message(
        self: Pin<&mut Self>,
        to: &QString,
        body: &QString,
        encrypted: bool,
        reply_to: &QString,
    ) {
        let to = to.to_string();
        let body = body.to_string();
        if to.is_empty() || body.trim().is_empty() {
            return;
        }
        let reply_to = reply_to.to_string();
        let reply_to = if reply_to.is_empty() { None } else { Some(reply_to) };
        crate::session::send_message(to, body, encrypted, reply_to);
    }

    /// QML entry point — toggle a reaction on a message.
    pub fn react(self: Pin<&mut Self>, to: &QString, target: &QString, emoji: &QString) {
        crate::session::react(to.to_string(), target.to_string(), emoji.to_string());
    }

    /// QML entry point — join a MUC room.
    pub fn join_muc(self: Pin<&mut Self>, room: &QString, nick: &QString) {
        crate::session::join_muc(room.to_string(), nick.to_string());
    }

    /// QML entry point — start a MUC private message.
    pub fn start_private(self: Pin<&mut Self>, occupant_jid: &QString) {
        crate::session::start_private(occupant_jid.to_string());
    }

    /// QML entry point — add a roster contact.
    pub fn add_contact(self: Pin<&mut Self>, jid: &QString, name: &QString) {
        crate::session::add_contact(jid.to_string(), name.to_string());
    }

    /// QML entry point — lazily fetch a MUC occupant's avatar.
    pub fn fetch_muc_avatar(self: Pin<&mut Self>, occupant_jid: &QString) {
        crate::session::fetch_muc_avatar(occupant_jid.to_string());
    }

    /// QML entry point — send a sticker image.
    pub fn send_sticker(self: Pin<&mut Self>, to: &QString, path: &QString) {
        crate::session::send_sticker(to.to_string(), path.to_string());
    }

    /// QML entry point — send a file.
    pub fn send_file(self: Pin<&mut Self>, to: &QString, path: &QString) {
        crate::session::send_file(to.to_string(), path.to_string(), String::new());
    }

    /// QML entry point — send a file with a caption (one encrypted message for OMEMO2 chats).
    pub fn send_file_with_caption(
        self: Pin<&mut Self>,
        to: &QString,
        path: &QString,
        caption: &QString,
    ) {
        crate::session::send_file(to.to_string(), path.to_string(), caption.to_string());
    }

    /// QML entry point — share several files in one message (newline-separated paths).
    pub fn send_files(self: Pin<&mut Self>, to: &QString, paths: &QString, caption: &QString) {
        let paths: Vec<String> = paths
            .to_string()
            .split('\n')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        crate::session::send_files(to.to_string(), paths, caption.to_string());
    }

    /// QML entry point — download a shared file to the downloads folder (decrypting `aesgcm://`).
    pub fn download_file(self: Pin<&mut Self>, url: &QString, filename: &QString) {
        crate::session::download_file(url.to_string(), filename.to_string());
    }

    /// QML entry point — fetch a vCard profile.
    pub fn fetch_vcard(self: Pin<&mut Self>, jid: &QString, is_muc: bool) {
        crate::session::fetch_vcard(jid.to_string(), is_muc);
    }

    /// QML entry point — fetch a contact's presence-subscription state.
    pub fn fetch_subscription(self: Pin<&mut Self>, jid: &QString) {
        crate::session::fetch_subscription(jid.to_string());
    }

    /// QML entry point — change a presence subscription.
    pub fn set_subscription(self: Pin<&mut Self>, jid: &QString, action: &QString) {
        crate::session::set_subscription(jid.to_string(), action.to_string());
    }

    /// QML entry point — list available sticker image paths (newline-joined).
    pub fn sticker_files(&self) -> QString {
        QString::from(&crate::session::sticker_files())
    }

    /// QML entry point — the stickers folder (created so the file manager can open it).
    pub fn sticker_dir(&self) -> QString {
        QString::from(&crate::session::sticker_dir_path())
    }

    /// QML entry point — publish a story.
    pub fn publish_story(self: Pin<&mut Self>, path: &QString, title: &QString) {
        crate::session::publish_story(path.to_string(), title.to_string());
    }

    /// QML entry point — fetch stories.
    pub fn fetch_stories(self: Pin<&mut Self>) {
        crate::session::fetch_stories();
    }

    /// QML entry point — retract a story.
    pub fn retract_story(self: Pin<&mut Self>, uuid: &QString) {
        crate::session::retract_story(uuid.to_string());
    }

    // --- Feeds (XEP-0472) ---
    pub fn fetch_feeds(self: Pin<&mut Self>) {
        crate::session::fetch_feeds();
    }
    pub fn fetch_comments(self: Pin<&mut Self>, post_author: &QString, post_id: &QString) {
        crate::session::fetch_comments(post_author.to_string(), post_id.to_string());
    }
    pub fn retract_post(self: Pin<&mut Self>, post_id: &QString) {
        crate::session::retract_post(post_id.to_string());
    }
    pub fn retract_comment(self: Pin<&mut Self>, post_author: &QString, post_id: &QString, comment_id: &QString) {
        crate::session::retract_comment(post_author.to_string(), post_id.to_string(), comment_id.to_string());
    }
    pub fn publish_post(self: Pin<&mut Self>, title: &QString, content: &QString) {
        crate::session::publish_post(title.to_string(), content.to_string());
    }
    pub fn publish_comment(self: Pin<&mut Self>, post_author: &QString, post_id: &QString, content: &QString) {
        crate::session::publish_comment(post_author.to_string(), post_id.to_string(), content.to_string());
    }
    pub fn toggle_like(self: Pin<&mut Self>, post_author: &QString, post_id: &QString) {
        crate::session::toggle_like(post_author.to_string(), post_id.to_string());
    }
    pub fn follow_feed(self: Pin<&mut Self>, jid: &QString) {
        crate::session::follow_feed(jid.to_string());
    }
    pub fn unfollow_feed(self: Pin<&mut Self>, jid: &QString) {
        crate::session::unfollow_feed(jid.to_string());
    }
    pub fn followed_feeds(&self) -> QString {
        QString::from(&crate::session::followed_feeds())
    }

    /// QML entry point — open a shared WebXDC app.
    pub fn open_webxdc(self: Pin<&mut Self>, peer: &QString, thread: &QString, url: &QString) {
        crate::webxdc::open(peer.to_string(), thread.to_string(), url.to_string());
    }

    /// QML entry point — the app window closed.
    pub fn close_webxdc(self: Pin<&mut Self>) {
        crate::webxdc::close();
    }

    /// QML entry point — query a room's OMEMO capability.
    pub fn muc_omemo_capable(&self, room: &QString) -> bool {
        crate::session::muc_omemo_capable(&room.to_string())
    }

    /// QML entry point — remove a conversation from the chats list.
    pub fn delete_chat(self: Pin<&mut Self>, jid: &QString) {
        crate::session::delete_chat(jid.to_string());
    }
    /// QML entry point — leave a group chat.
    pub fn leave_muc(self: Pin<&mut Self>, room: &QString) {
        crate::session::leave_muc(room.to_string());
    }
    /// QML entry point — remove a contact from the roster.
    pub fn remove_contact(self: Pin<&mut Self>, jid: &QString) {
        crate::session::remove_contact(jid.to_string());
    }

    /// QML entry point — set OMEMO2 trust for one of `jid`'s devices.
    pub fn set_trust(self: Pin<&mut Self>, jid: &QString, device_id: i64, trust: i64) {
        crate::session::set_trust(jid.to_string(), device_id, trust);
    }

    /// QML entry point — verify a JID's keys from a scanned/pasted verification link.
    pub fn verify_from_link(self: Pin<&mut Self>, jid: &QString, text: &QString) -> bool {
        crate::session::verify_from_uri(&jid.to_string(), &text.to_string())
    }

    /// QML entry point — encode `text` as a QR code, flattened to `"<size>:<bits>"`.
    pub fn qr_matrix(&self, text: &QString) -> QString {
        QString::from(&crate::qr::matrix(&text.to_string()))
    }

    /// QML entry point — manually verify the active call peer's PQ OMEMO2 key. Marks the key
    /// trust = 3 (verified) and optimistically flips the call indicator to the shield (2).
    pub fn verify_call_key(mut self: Pin<&mut Self>) {
        let jid = self.call_peer.to_string();
        let device = self.call_verified_device;
        if jid.is_empty() || device == 0 {
            return;
        }
        crate::session::set_trust(jid, device, 3);
        self.as_mut().set_call_trust(2);
    }

    /// QML entry point — flip the blind-trust setting.
    pub fn toggle_auto_trust(self: Pin<&mut Self>, value: bool) {
        crate::session::set_auto_trust(value);
    }

    /// QML entry point — reset (wipe + rebuild) our cached OMEMO2 peer identities/sessions.
    pub fn reset_omemo2_identities(self: Pin<&mut Self>) {
        crate::session::reset_omemo2_identities();
    }

    /// QML entry point — LAST RESORT: regenerate our own OMEMO2 identity (fingerprint changes).
    pub fn regenerate_omemo2_identity(self: Pin<&mut Self>) {
        crate::session::regenerate_omemo2_identity();
    }

    /// QML entry point — set our own availability + status message.
    pub fn set_presence(mut self: Pin<&mut Self>, show: &QString, status: &QString) {
        // Mirror immediately so the dialog reflects what was just applied.
        self.as_mut().set_own_show(show.clone());
        self.as_mut().set_own_status(status.clone());
        crate::session::set_presence(show.to_string(), status.to_string());
    }

    /// QML entry point — publish a new own avatar from a local image file.
    pub fn publish_avatar(self: Pin<&mut Self>, path: &QString) {
        let path = path.to_string();
        let path = path.strip_prefix("file://").unwrap_or(&path).to_string();
        crate::session::publish_avatar(path);
    }

    /// QML entry point — publish our nickname.
    pub fn set_nick(mut self: Pin<&mut Self>, nick: &QString) {
        self.as_mut().set_own_nick(nick.clone());
        crate::session::set_nick(nick.to_string());
    }

    /// QML entry point — fetch a published nickname.
    pub fn fetch_nick(self: Pin<&mut Self>, jid: &QString) {
        crate::session::fetch_nick(jid.to_string());
    }

    /// QML entry point — cached avatar path for a JID.
    pub fn avatar_path_for(&self, jid: &QString) -> QString {
        QString::from(&crate::session::avatar_path_for(&jid.to_string()))
    }

    /// QML entry point — sniff a local image file's header for animation (≤256 bytes read).
    /// Avatar paths may carry a `?m=<mtime>` cache-buster — strip it before opening.
    pub fn is_animated_image(&self, path: &QString) -> bool {
        use std::io::Read;
        let path = path.to_string();
        let path = path.split('?').next().unwrap_or("");
        let mut buf = [0u8; 256];
        let Ok(mut f) = std::fs::File::open(path) else { return false };
        let Ok(n) = f.read(&mut buf) else { return false };
        crate::session::animated_image_mime(&buf[..n]).is_some()
    }

    /// QML entry point — ring a peer.
    pub fn place_call(self: Pin<&mut Self>, to: &QString, video: bool) {
        crate::session::place_call(to.to_string(), video);
    }

    pub fn accept_call(self: Pin<&mut Self>) {
        crate::session::accept_call();
    }

    pub fn decline_call(mut self: Pin<&mut Self>) {
        crate::session::decline_call();
        self.as_mut().end_call_locally();
    }

    pub fn hang_up_call(mut self: Pin<&mut Self>) {
        crate::session::cancel_call();
        self.as_mut().end_call_locally();
    }

    /// Tear down the call screen immediately on a *local* hang-up/decline. The core only emits
    /// `Ended` when the *remote* side terminates, so for our own action we close it ourselves
    /// (matches the GTK client). Setting `callActive=false` drives `onCallActiveChanged` in QML.
    fn end_call_locally(mut self: Pin<&mut Self>) {
        self.as_mut().set_call_active(false);
        self.as_mut().set_call_state(QString::from("ended"));
        self.as_mut().set_call_muted(false);
        self.as_mut().set_remote_frame(QString::default());
        self.as_mut().set_local_frame(QString::default());
    }

    pub fn set_call_mute(self: Pin<&mut Self>, muted: bool) {
        crate::session::set_call_mute(muted);
    }

    pub fn set_call_camera(self: Pin<&mut Self>, enabled: bool) {
        crate::session::set_call_camera(enabled);
    }

    pub fn set_call_screen_share(mut self: Pin<&mut Self>, enabled: bool) {
        // Optimistically reflect the button state; the portal picker may still be cancelled, in
        // which case the screen simply never switches (the call keeps its camera/video as-is).
        self.as_mut().set_call_screen_sharing(enabled);
        crate::session::set_call_screen_share(enabled);
    }

    pub fn upgrade_call_to_video(self: Pin<&mut Self>) {
        crate::session::upgrade_call_to_video();
    }

    pub fn accept_video_upgrade(mut self: Pin<&mut Self>) {
        self.as_mut().set_call_video_request(false);
        crate::session::accept_video_upgrade();
    }

    pub fn decline_video_upgrade(mut self: Pin<&mut Self>) {
        self.as_mut().set_call_video_request(false);
        crate::session::decline_video_upgrade();
    }

    // --- group calls (XEP-0272 Muji) ---
    pub fn place_group_call(mut self: Pin<&mut Self>, room: &QString, video: bool) {
        self.as_mut().set_conference_camera_on(true);
        self.as_mut().set_conference_screen_sharing(false);
        crate::session::place_group_call(room.to_string(), video);
    }

    pub fn leave_group_call(self: Pin<&mut Self>) {
        crate::session::leave_group_call();
    }

    pub fn set_conference_mute(mut self: Pin<&mut Self>, muted: bool) {
        self.as_mut().set_conference_muted(muted);
        crate::session::set_conference_mute(muted);
    }

    pub fn set_conference_camera(mut self: Pin<&mut Self>, enabled: bool) {
        self.as_mut().set_conference_camera_on(enabled);
        crate::session::set_conference_camera(enabled);
    }

    pub fn set_conference_screen_share(self: Pin<&mut Self>, enabled: bool) {
        // The authoritative state comes back via Event::ConferenceScreenShare (the portal picker
        // may be cancelled), so don't optimistically flip the property here.
        crate::session::set_conference_screen_share(enabled);
    }

    pub fn join_group_call(mut self: Pin<&mut Self>, video: bool) {
        let room = self.conference_invite_room.to_string();
        self.as_mut().set_conference_invite_room(QString::default());
        self.as_mut().set_conference_invite_from(QString::default());
        self.as_mut().set_conference_camera_on(true);
        self.as_mut().set_conference_screen_sharing(false);
        if !room.is_empty() {
            crate::session::place_group_call(room, video);
        }
    }

    pub fn dismiss_group_call_invite(mut self: Pin<&mut Self>) {
        self.as_mut().set_conference_invite_room(QString::default());
        self.as_mut().set_conference_invite_from(QString::default());
        crate::session::dismiss_group_call_invite();
    }

    // --- voice messages ---
    pub fn start_voice(self: Pin<&mut Self>) -> bool {
        crate::media::start_recording()
    }
    pub fn stop_voice_and_send(self: Pin<&mut Self>, to: &QString) {
        if let Some(path) = crate::media::stop_recording() {
            crate::session::send_file(to.to_string(), path, String::new());
        }
    }
    pub fn cancel_voice(self: Pin<&mut Self>) {
        crate::media::cancel_recording();
    }
    pub fn audio_toggle(self: Pin<&mut Self>, path: &QString) {
        crate::media::toggle(path.to_string(), self.qt_thread());
    }
    pub fn audio_seek(self: Pin<&mut Self>, ms: i64) {
        crate::media::seek(ms);
    }
}
