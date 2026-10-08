//! Core runtime glue: hosts the tokio runtime, owns the shared store, spawns the
//! `mxc-proto` client, and pumps `Event`s back onto the Qt thread.
//!
//! Instead of the GTK app's `glib::spawn_future_local`, results hop back onto the Qt main
//! thread via CXX-Qt's `CxxQtThread::queue` before touching any QObject.
//!
//! (Named `session`, not `core`, to avoid shadowing the `::core` paths the cxx/cxx-qt
//! macros emit.)

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{LazyLock, Mutex, OnceLock};

use cxx_qt::CxxQtThread;
use cxx_qt_lib::QString;
use tokio::runtime::Runtime;
use tokio::sync::OnceCell;

use mxc_proto::{
    spawn, AccountConfig, CallState, CallVideoFrame, Command, ConfParticipant, ConnectionState,
    DeviceKey, Encryption, Event, FeedPost,
};
use mxc_store::Store;

use crate::backend::qobject::Backend;
use crate::calls::qobject::CallLogModel;
use crate::calls::CallEntry;
use crate::conference::ConfPartEntry;
use crate::devices::{DeviceEntry, OWN_KEY};
use crate::feeds::FeedEntry;
use crate::messages::qobject::MessageModel;
use crate::stories::qobject::StoryModel;
use crate::stories::StoryEntry;
use crate::messages::MessageItem;
use crate::model::qobject::ConversationModel;
use crate::model::ConversationItem;
use crate::occupants::OccupantEntry;
use crate::roster::qobject::RosterModel;
use crate::roster::RosterEntry;
use crate::search::qobject::MessageSearchModel;
use crate::search::SearchResult;

/// Process-global multi-thread tokio runtime hosting the core (same role as the GTK
/// app's `runtime.rs`).
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// One shared store, opened lazily and reused by login and the list models.
static STORE: OnceCell<Store> = OnceCell::const_new();

/// Qt-thread handle for the `Backend` QObject, for callers outside the event pump (the
/// WebXDC bridge runs on Chromium's IO thread). Set once when the first session starts.
static BACKEND_QT: std::sync::OnceLock<CxxQtThread<Backend>> = std::sync::OnceLock::new();

/// A clone of the Backend Qt-thread handle (None before the first login).
pub(crate) fn backend_qt() -> Option<CxxQtThread<Backend>> {
    BACKEND_QT.get().cloned()
}

/// Debounced list refresh: avatar/presence floods (e.g. opening a big MUC's member list
/// fetches many avatars) must not emit `conversationsChanged` per event — each emission
/// reloads the conversation+roster models and, with `refresh_open`, the whole open chat.
/// Coalesces emissions into one per 400ms quiet-ish window.
static REFRESH_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static REFRESH_OPEN_TOO: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn schedule_list_refresh(refresh_open: bool) {
    use std::sync::atomic::Ordering;
    if refresh_open {
        REFRESH_OPEN_TOO.store(true, Ordering::Relaxed);
    }
    if REFRESH_PENDING.swap(true, Ordering::Relaxed) {
        return; // an emit is already scheduled; this event rides along
    }
    runtime().spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        REFRESH_PENDING.store(false, Ordering::Relaxed);
        let open_too = REFRESH_OPEN_TOO.swap(false, Ordering::Relaxed);
        if let Some(qt) = backend_qt() {
            let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                backend.as_mut().conversations_changed();
                if open_too {
                    backend.as_mut().refresh_open();
                }
            });
        }
    });
}

/// The connected client's command sender + account id + own bare JID (None when offline).
pub(crate) fn client_info() -> Option<(async_channel::Sender<Command>, i64, String)> {
    let guard = CLIENT.lock().unwrap();
    guard.as_ref().map(|c| (c.commands.clone(), c.account_id, c.jid.clone()))
}

/// The connected client's command sink + account id, set after login so QML (the composer)
/// can send messages without holding the `ClientHandle`.
static CLIENT: Mutex<Option<ClientCtx>> = Mutex::new(None);

struct ClientCtx {
    commands: async_channel::Sender<Command>,
    account_id: i64,
    /// Our own bare JID (for the "own feed" + own-post detection).
    jid: String,
}

/// Per-resource presence (full JID → "online"/"away"/"xa"/"dnd"); a bare JID's shown status
/// is the most-available of its resources (see `best_presence`).
static PRESENCE: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// JIDs we've already asked the server for an avatar, so list reloads don't re-storm fetches.
static AVATAR_REQUESTED: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Image URLs whose download is in-flight, so reloads don't re-fetch the same file.
static IMAGE_REQUESTED: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Per-room OMEMO capability (room bare jid → can-encrypt), from `Event::MucPrivacy`. The
/// chat header gates the encryption toggle on this for MUCs.
static MUC_OMEMO: LazyLock<Mutex<HashMap<String, bool>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether `room` supports OMEMO (private + non-anonymous), as last reported by the server.
pub fn muc_omemo_capable(room: &str) -> bool {
    MUC_OMEMO.lock().unwrap().get(room).copied().unwrap_or(false)
}

// --- 1:1 calls (XEP-0353 JMI + XEP-0166 Jingle) --------------------------------------------

/// The call currently on screen (session id + peer bare JID), so accept/decline/hangup/mute
/// don't need QML to track the ids. Set from `Event::CallUpdate`, cleared when the call ends.
static CURRENT_CALL: LazyLock<Mutex<Option<CallCtx>>> = LazyLock::new(|| Mutex::new(None));

#[derive(Clone)]
struct CallCtx {
    sid: String,
    peer: String,
}

/// Ring `to` (bare JID) for an audio (or audio+video) call.
pub fn place_call(to: String, video: bool) {
    if to.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::PlaceCall {
        account_id: ctx.account_id,
        to,
        video,
    });
}

/// Accept the ringing call.
pub fn accept_call() {
    with_current_call(|ctx, account_id, call| {
        let _ = ctx.commands.try_send(Command::AcceptCall {
            account_id,
            sid: call.sid,
            peer: call.peer,
        });
    });
}

/// Decline the ringing call.
pub fn decline_call() {
    with_current_call(|ctx, account_id, call| {
        let _ = ctx.commands.try_send(Command::DeclineCall {
            account_id,
            sid: call.sid,
            peer: call.peer,
        });
    });
    *CURRENT_CALL.lock().unwrap() = None;
}

/// Cancel an outgoing call / hang up an active one.
pub fn cancel_call() {
    with_current_call(|ctx, account_id, call| {
        let _ = ctx.commands.try_send(Command::CancelCall {
            account_id,
            sid: call.sid,
            peer: call.peer,
        });
    });
    *CURRENT_CALL.lock().unwrap() = None;
}

/// Mute / unmute the microphone on the active call.
pub fn set_call_mute(muted: bool) {
    with_current_call(|ctx, account_id, call| {
        let _ = ctx.commands.try_send(Command::SetCallMute {
            account_id,
            sid: call.sid,
            muted,
        });
    });
}

/// Turn the camera on/off on the active video call.
pub fn set_call_camera(enabled: bool) {
    with_current_call(|ctx, account_id, call| {
        let _ = ctx.commands.try_send(Command::SetCallCamera {
            account_id,
            sid: call.sid,
            enabled,
        });
    });
}

/// Start/stop screen sharing on the active call (the shared screen replaces the camera).
pub fn set_call_screen_share(enabled: bool) {
    with_current_call(|ctx, account_id, call| {
        let _ = ctx.commands.try_send(Command::SetCallScreenShare {
            account_id,
            sid: call.sid,
            enabled,
        });
    });
}

/// Upgrade the active audio call to video.
pub fn upgrade_call_to_video() {
    with_current_call(|ctx, account_id, call| {
        let _ = ctx.commands.try_send(Command::UpgradeCallToVideo {
            account_id,
            sid: call.sid,
        });
    });
}

/// Accept a peer's incoming video-upgrade request.
pub fn accept_video_upgrade() {
    with_current_call(|ctx, account_id, call| {
        let _ = ctx.commands.try_send(Command::AcceptVideoUpgrade {
            account_id,
            sid: call.sid,
        });
    });
}

/// Decline a peer's incoming video-upgrade request.
pub fn decline_video_upgrade() {
    with_current_call(|ctx, account_id, call| {
        let _ = ctx.commands.try_send(Command::DeclineVideoUpgrade {
            account_id,
            sid: call.sid,
        });
    });
}

// --- Muji group calls (XEP-0272) -----------------------------------------------------------

/// The active group call's room JID + its remote participants, mirrored from
/// `Event::ConferenceUpdate` so the conference panel + model can read it. `None` = no call.
static CURRENT_CONFERENCE: LazyLock<Mutex<Option<ConferenceView>>> =
    LazyLock::new(|| Mutex::new(None));

#[derive(Clone, Default)]
struct ConferenceView {
    room: String,
    participants: Vec<ConfPartEntry>,
}

/// Start / join a Muji group call in `room` (we must already be a MUC occupant).
pub fn place_group_call(room: String, video: bool) {
    if room.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::PlaceGroupCall {
        account_id: ctx.account_id,
        room,
        video,
    });
}

/// Leave the active group call.
pub fn leave_group_call() {
    let room = CURRENT_CONFERENCE.lock().unwrap().as_ref().map(|c| c.room.clone());
    let Some(room) = room else { return };
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::LeaveGroupCall { account_id: ctx.account_id, room });
}

/// Mute / unmute our microphone across the whole group call.
pub fn set_conference_mute(muted: bool) {
    let room = CURRENT_CONFERENCE.lock().unwrap().as_ref().map(|c| c.room.clone());
    let Some(room) = room else { return };
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::SetGroupCallMute {
        account_id: ctx.account_id,
        room,
        muted,
    });
}

/// Turn our camera on/off across the whole group video call.
pub fn set_conference_camera(enabled: bool) {
    let room = CURRENT_CONFERENCE.lock().unwrap().as_ref().map(|c| c.room.clone());
    let Some(room) = room else { return };
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::SetGroupCallCamera {
        account_id: ctx.account_id,
        room,
        enabled,
    });
}

/// Start / stop sharing our screen to the group video call (the core runs the portal picker).
pub fn set_conference_screen_share(enabled: bool) {
    let room = CURRENT_CONFERENCE.lock().unwrap().as_ref().map(|c| c.room.clone());
    let Some(room) = room else { return };
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::SetGroupCallScreenShare {
        account_id: ctx.account_id,
        room,
        enabled,
    });
}

/// Dismiss a pending group-call invite (UI-only; the core keeps its one-prompt-per-call state,
/// and will emit a cancellation when the call actually ends).
pub fn dismiss_group_call_invite() {}

/// The active group call's remote participants, for the `ConferenceModel`.
pub fn conference_participants() -> Vec<ConfPartEntry> {
    CURRENT_CONFERENCE
        .lock()
        .unwrap()
        .as_ref()
        .map(|c| c.participants.clone())
        .unwrap_or_default()
}

/// Run `f` with the connected client + the current call, if both exist.
fn with_current_call(f: impl FnOnce(&ClientCtx, i64, CallCtx)) {
    let call = CURRENT_CALL.lock().unwrap().clone();
    let Some(call) = call else { return };
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    f(ctx, ctx.account_id, call);
}

/// Load the account's recent call history and reset the calls model.
pub fn load_calls(jid: String, qt: CxxQtThread<CallLogModel>) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let Ok(account_id) = store.upsert_account(&jid).await else { return };
        let rows = store.recent_calls(account_id, 200).await.unwrap_or_default();
        let items: Vec<CallEntry> = rows.iter().map(CallEntry::from_row).collect();
        let _ = qt.queue(move |model: Pin<&mut CallLogModel>| model.reset(items));
    });
}

// --- Stories (social-feed PEP) -------------------------------------------------------------

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Load non-expired stories (all newest first, or only `contact`'s oldest first) and reset the
/// model; media is fetched + cached lazily.
pub fn load_stories(jid: String, contact: Option<String>, qt: CxxQtThread<StoryModel>) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let Ok(account_id) = store.upsert_account(&jid).await else { return };
        let mut rows = store.recent_stories(account_id, unix_now()).await.unwrap_or_default();
        if let Some(contact) = &contact {
            rows.retain(|s| s.contact.eq_ignore_ascii_case(contact));
            rows.reverse();
        }
        // Keyed by (publisher, id) so a story can never be listed twice.
        let mut seen = HashSet::new();
        rows.retain(|s| seen.insert((s.contact.to_lowercase(), s.uuid.clone())));
        let mut items = Vec::with_capacity(rows.len());
        for s in &rows {
            let cached = story_cache_path(&s.url, &s.r#type);
            let local_path = if cached.is_file() {
                cached.to_string_lossy().into_owned()
            } else {
                // Images are fetched right away; videos (larger) only when the viewer reaches
                // them (`StoryModel::fetchMedia`), as Android streams them on view. A failed
                // download is only retried on request, or every reload would retry it.
                if !s.r#type.starts_with("video/") && !STORY_MEDIA_FAILED.lock().unwrap().contains(&s.url) {
                    prefetch_story_media(s.url.clone(), s.r#type.clone(), mxc_proto::xeps::http_upload::AUTO_DOWNLOAD_LIMIT, &qt);
                }
                String::new()
            };
            request_avatar(&s.contact, false);
            items.push(StoryEntry {
                uuid: s.uuid.clone(),
                contact: s.contact.clone(),
                title: s.title.clone().unwrap_or_default(),
                mime: s.r#type.clone(),
                published: s.published,
                own: s.contact.eq_ignore_ascii_case(&jid),
                local_path,
                avatar_path: avatar_path_for(&s.contact),
                url: s.url.clone(),
                downloading: IMAGE_REQUESTED.lock().unwrap().contains(&s.url),
                failed: STORY_MEDIA_FAILED.lock().unwrap().contains(&s.url),
            });
        }
        let _ = qt.queue(move |model: Pin<&mut StoryModel>| model.reset(items));
    });
}

/// Story media URLs whose last download failed (the viewer offers a retry).
static STORY_MEDIA_FAILED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Where a story's media is cached. Like [`image_cache_path`], but a video whose URL has no
/// usable extension gets one from its type — the cached file is handed to the system player,
/// which can't play a `.img`.
pub(crate) fn story_cache_path(url: &str, mime: &str) -> PathBuf {
    let path = image_cache_path(url);
    let ext = match mime {
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "video/quicktime" => "mov",
        "video/x-matroska" => "mkv",
        "video/3gpp" => "3gp",
        _ => return path,
    };
    if path.extension().is_some_and(|e| e == "img") { path.with_extension(ext) } else { path }
}

/// Download + cache a story's media once (at most `limit` bytes), then reload the story model
/// (also to show a failure).
pub(crate) fn prefetch_story_media(url: String, mime: String, limit: u64, qt: &CxxQtThread<StoryModel>) {
    let path = story_cache_path(&url, &mime);
    if path.is_file() {
        return;
    }
    if !IMAGE_REQUESTED.lock().unwrap().insert(url.clone()) {
        return;
    }
    STORY_MEDIA_FAILED.lock().unwrap().remove(&url);
    let qt = qt.clone();
    runtime().spawn(async move {
        let result = mxc_proto::xeps::http_upload::download_any(&url, limit).await;
        let stored = match result {
            Ok(bytes) => {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                // Written under a temporary name: the player must never get a partial file.
                let tmp = path.with_extension("part");
                std::fs::write(&tmp, &bytes).and_then(|_| std::fs::rename(&tmp, &path)).is_ok()
            }
            Err(e) => {
                tracing::debug!(error = %e, "story media download failed");
                false
            }
        };
        IMAGE_REQUESTED.lock().unwrap().remove(&url);
        if !stored {
            STORY_MEDIA_FAILED.lock().unwrap().insert(url);
        }
        let _ = qt.queue(|model: Pin<&mut StoryModel>| model.reload_self());
    });
}

/// Publish a story (upload `path` with its metadata stripped + publish it to our stories
/// node). Returns whether it was queued (a `PublishDone` event then follows).
pub fn publish_story(path: String, title: String) -> bool {
    if path.is_empty() {
        return false;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return false };
    ctx.commands
        .try_send(Command::PublishStory { account_id: ctx.account_id, path, title })
        .is_ok()
}

/// Fetch stories from ourselves + subscribed contacts (replies via `StoriesUpdated`).
pub fn fetch_stories() {
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::FetchStories { account_id: ctx.account_id });
}

/// Retract one of our own stories.
pub fn retract_story(uuid: String) {
    if uuid.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::RetractStory {
        account_id: ctx.account_id,
        uuid,
    });
}

// --- Feeds (XEP-0472 social feed / microblog) ----------------------------------------------

/// Our own bare JID (set at login) — for the own feed + own-item detection.
static OWN_JID: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(String::new()));

/// Whether `jid` is our own account (bare, case-insensitive). Used to label a 1:1 chat with
/// ourselves as "Note to self". Returns false before login (own JID not yet known).
pub(crate) fn is_own_bare(jid: &str) -> bool {
    let own = OWN_JID.lock().unwrap();
    if own.is_empty() {
        return false;
    }
    let own_bare = own.split('/').next().unwrap_or(&own);
    let jid_bare = jid.split('/').next().unwrap_or(jid);
    jid_bare.eq_ignore_ascii_case(own_bare)
}

/// Display label for a 1:1 chat with our own account.
pub(crate) const NOTE_TO_SELF: &str = "Note to self";

/// Fetched top-level posts per owner bare JID (lower-cased; in-memory). Item ids are only
/// unique per author, so a post is identified by (author, id).
static FEED_POSTS: LazyLock<Mutex<HashMap<String, Vec<FeedPost>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Fetched comments per comments node: (service bare JID lower-cased, node) — the node a post
/// names in its replies link, which needn't be on the author's own service.
type CommentsByNode = HashMap<(String, String), Vec<FeedPost>>;
static FEED_COMMENTS: LazyLock<Mutex<CommentsByNode>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Authors (bare JID, lower-cased) whose feed was found to be open to anyone. Anything else,
/// including not (yet) known, counts as private.
static PUBLIC_FEEDS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn comments_key(service: &str, node: &str) -> (String, String) {
    (service.to_lowercase(), node.to_string())
}

/// Bare JIDs whose feeds we follow (persisted to a text file in the data dir).
static FOLLOWED: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(load_followed()));

/// Per-section "seen up to here" cursors for the nav-rail badges (calls/stories/feeds),
/// persisted as a small key=value file in the data dir so the counts survive restarts.
fn seen_marks_file() -> PathBuf {
    let dir = directories::ProjectDirs::from("de", "monocles", "monocles-chat")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    dir.join("seen_marks.txt")
}

pub(crate) fn seen_mark(key: &str) -> String {
    let prefix = format!("{key}=");
    std::fs::read_to_string(seen_marks_file())
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(&prefix).map(String::from))
        .unwrap_or_default()
}

pub(crate) fn set_seen_mark(key: &str, value: &str) {
    let prefix = format!("{key}=");
    let path = seen_marks_file();
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.starts_with(&prefix))
        .map(String::from)
        .collect();
    lines.push(format!("{prefix}{value}"));
    let _ = std::fs::write(&path, lines.join("\n"));
}

fn followed_file() -> PathBuf {
    let dir = directories::ProjectDirs::from("de", "monocles", "monocles-chat")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    dir.join("followed_feeds.txt")
}

fn load_followed() -> Vec<String> {
    std::fs::read_to_string(followed_file())
        .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect())
        .unwrap_or_default()
}

fn save_followed(list: &[String]) {
    let _ = std::fs::write(followed_file(), list.join("\n"));
}

/// A "like" is a comment whose body is exactly this heart (matches monocles Android).
const HEART: &str = mxc_proto::xeps::microblog::HEART;

/// The cached post `post_id` of `author`.
fn find_post(author: &str, post_id: &str) -> Option<FeedPost> {
    FEED_POSTS
        .lock()
        .unwrap()
        .get(&author.to_lowercase())
        .and_then(|posts| posts.iter().find(|p| p.id == post_id).cloned())
}

/// The comments node (service, node) of `author`'s post `post_id`, if it has one.
fn comments_node_of(author: &str, post_id: &str) -> Option<(String, String)> {
    find_post(author, post_id)
        .filter(|p| !p.comments_jid.is_empty() && !p.comments_node.is_empty())
        .map(|p| (p.comments_jid, p.comments_node))
}

fn is_image(mime: &str) -> bool {
    matches!(mime, "image/jpeg" | "image/png" | "image/gif" | "image/webp")
}

fn to_entry(p: &FeedPost, comment_count: i64, like_count: i64, liked: bool) -> FeedEntry {
    let own = p.author.eq_ignore_ascii_case(&OWN_JID.lock().unwrap());
    // Only cached images are shown inline; anything else is a link to open.
    let attachment_path = if is_image(&p.attachment_type) {
        let cached = image_cache_path(&p.attachment_url);
        if cached.is_file() { cached.to_string_lossy().into_owned() } else { String::new() }
    } else {
        String::new()
    };
    FeedEntry {
        id: p.id.clone(),
        author: p.author.clone(),
        title: p.title.clone(),
        content: p.content.clone(),
        content_html: String::from(&mxc_proto::xeps::atom_text::markdown_to_xhtml_div(&p.content)),
        published: p.published,
        link: p.link.clone(),
        attachment_url: p.attachment_url.clone(),
        attachment_type: p.attachment_type.clone(),
        attachment_path,
        avatar_path: if p.author.is_empty() { String::new() } else { avatar_path_for(&p.author) },
        own,
        can_comment: !p.comments_node.is_empty(),
        public: PUBLIC_FEEDS.lock().unwrap().contains(&p.author.to_lowercase()),
        comment_count,
        like_count,
        liked,
    }
}

/// Merged top-level posts across all fetched feeds, newest first, with reply + like counts
/// (from the comments cache). Likes ("♥" comments) are tallied separately.
pub fn feed_posts(_account_jid: &str) -> Vec<FeedEntry> {
    let own_jid = OWN_JID.lock().unwrap().clone();
    let comments = FEED_COMMENTS.lock().unwrap();
    let map = FEED_POSTS.lock().unwrap();
    let mut seen = HashSet::new();
    let mut items: Vec<FeedEntry> = map
        .values()
        .flat_map(|posts| posts.iter())
        .filter(|p| seen.insert((p.author.to_lowercase(), p.id.clone())))
        .map(|p| {
            let (mut cc, mut lc, mut liked) = (0i64, 0i64, false);
            if let Some(cs) = comments.get(&comments_key(&p.comments_jid, &p.comments_node)) {
                for c in cs {
                    if c.content.trim() == HEART {
                        lc += 1;
                        if c.author.eq_ignore_ascii_case(&own_jid) {
                            liked = true;
                        }
                    } else {
                        cc += 1;
                    }
                }
            }
            to_entry(p, cc, lc, liked)
        })
        .collect();
    items.sort_by_key(|p| std::cmp::Reverse(p.published));
    items
}

/// `author`'s post `post_id`'s comments, oldest first — excluding "♥" likes (those drive the
/// like button).
pub fn feed_comments(author: &str, post_id: &str) -> Vec<FeedEntry> {
    let Some((service, node)) = comments_node_of(author, post_id) else { return Vec::new() };
    FEED_COMMENTS
        .lock()
        .unwrap()
        .get(&comments_key(&service, &node))
        .map(|cs| {
            cs.iter()
                .filter(|c| c.content.trim() != HEART)
                .map(|c| to_entry(c, 0, 0, false))
                .collect()
        })
        .unwrap_or_default()
}

/// Toggle our "♥" like on a post: retract our like comment if present, else publish one.
pub fn toggle_like(post_author: String, post_id: String) {
    let Some((service, node)) = comments_node_of(&post_author, &post_id) else { return };
    let own = OWN_JID.lock().unwrap().clone();
    let my_like = FEED_COMMENTS.lock().unwrap().get(&comments_key(&service, &node)).and_then(|cs| {
        cs.iter()
            .find(|c| c.content.trim() == HEART && c.author.eq_ignore_ascii_case(&own))
            .map(|c| c.id.clone())
    });
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(match my_like {
        Some(comment_id) => Command::RetractComment { account_id: ctx.account_id, service, node, comment_id },
        None => Command::PublishComment { account_id: ctx.account_id, service, node, content: HEART.to_string() },
    });
}

/// Fetch a post's comments (reply arrives as `Event::FeedComments`).
pub fn fetch_comments(post_author: String, post_id: String) {
    let Some((service, node)) = comments_node_of(&post_author, &post_id) else { return };
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::FetchComments { account_id: ctx.account_id, service, node });
}

/// Ask for the comments of each of `posts` that has a comments node.
fn request_comments(posts: &[FeedPost]) {
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        for p in posts.iter().filter(|p| !p.comments_node.is_empty()) {
            let _ = ctx.commands.try_send(Command::FetchComments {
                account_id: ctx.account_id,
                service: p.comments_jid.clone(),
                node: p.comments_node.clone(),
            });
        }
    }
}

/// Download + cache the image attachments of `posts` (and their authors' avatars), then
/// reload the feed.
fn prefetch_feed_media(posts: &[FeedPost], qt: &CxxQtThread<Backend>) {
    for p in posts {
        if !p.author.is_empty() {
            request_avatar(&p.author, false);
        }
        let url = p.attachment_url.clone();
        let lower = url.to_ascii_lowercase();
        if !is_image(&p.attachment_type) || !(lower.starts_with("https://") || lower.starts_with("http://")) {
            continue;
        }
        let path = image_cache_path(&url);
        if path.is_file() || !IMAGE_REQUESTED.lock().unwrap().insert(url.clone()) {
            continue;
        }
        let qt = qt.clone();
        runtime().spawn(async move {
            let result = mxc_proto::xeps::http_upload::download_any(
                &url,
                mxc_proto::xeps::http_upload::AUTO_DOWNLOAD_LIMIT,
            )
            .await;
            IMAGE_REQUESTED.lock().unwrap().remove(&url);
            if let Ok(bytes) = result {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if std::fs::write(&path, &bytes).is_ok() {
                    let _ = qt.queue(|mut backend: Pin<&mut Backend>| backend.as_mut().feeds_changed());
                }
            }
        });
    }
}

/// Fill the feed from the store's cache (authors already fetched this session are kept).
async fn load_cached_feeds(store: &Store, account_id: i64, qt: &CxxQtThread<Backend>) {
    let Ok(rows) = store.feed_posts(account_id).await else { return };
    let mut by_author: HashMap<String, Vec<FeedPost>> = HashMap::new();
    for row in rows {
        by_author.entry(row.author.to_lowercase()).or_default().push(mxc_proto::xeps::microblog::from_row(row));
    }
    let cached: Vec<FeedPost> = by_author.values().flatten().cloned().collect();
    {
        let mut map = FEED_POSTS.lock().unwrap();
        for (author, posts) in by_author {
            map.entry(author).or_insert(posts);
        }
    }
    prefetch_feed_media(&cached, qt);
    let _ = qt.queue(|mut backend: Pin<&mut Backend>| backend.as_mut().feeds_changed());
}

/// Fetch our own feed + every followed feed (replies arrive as `Event::FeedPosts`), and
/// refresh the follow suggestions.
pub fn fetch_feeds() {
    {
        let guard = CLIENT.lock().unwrap();
        let Some(ctx) = guard.as_ref() else { return };
        let mut targets = vec![ctx.jid.clone()];
        targets.extend(FOLLOWED.lock().unwrap().iter().cloned());
        for jid in targets {
            let _ = ctx.commands.try_send(Command::FetchFeed { account_id: ctx.account_id, jid });
        }
    }
    refresh_feed_suggestions();
}

/// Follow suggestions, as on Android: contacts we share presence with both ways (they can see
/// our feed and we theirs) whose feed we don't follow yet. Pushed to `Backend::feedSuggestions`
/// (newline-joined bare JIDs).
fn refresh_feed_suggestions() {
    let Some(account_id) = CLIENT.lock().unwrap().as_ref().map(|c| c.account_id) else { return };
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let Ok(roster) = store.roster(account_id).await else { return };
        let followed = FOLLOWED.lock().unwrap().clone();
        let own = OWN_JID.lock().unwrap().clone();
        let mut suggestions: Vec<String> = roster
            .into_iter()
            .filter(|r| r.subscription == "both")
            .map(|r| r.jid)
            .filter(|j| j.contains('@') && !j.eq_ignore_ascii_case(&own))
            .filter(|j| !followed.iter().any(|f| f.eq_ignore_ascii_case(j)))
            .collect();
        suggestions.sort_by_key(|j| j.to_lowercase());
        let joined = suggestions.join("\n");
        if let Some(qt) = backend_qt() {
            let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                backend.as_mut().set_feed_suggestions(QString::from(&joined));
            });
        }
    });
}

/// Newline-joined followed JIDs (for the QML "following" list).
pub fn followed_feeds() -> String {
    FOLLOWED.lock().unwrap().join("\n")
}

/// Follow a feed (add + persist + fetch it).
pub fn follow_feed(jid: String) {
    let jid = jid.trim().trim_start_matches("xmpp:").split(['/', '?']).next().unwrap_or("").to_string();
    if jid.is_empty() || !jid.contains('@') {
        return;
    }
    {
        let mut list = FOLLOWED.lock().unwrap();
        if list.iter().any(|j| j.eq_ignore_ascii_case(&jid)) {
            return;
        }
        list.push(jid.clone());
        save_followed(&list);
    }
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        let _ = ctx.commands.try_send(Command::FetchFeed { account_id: ctx.account_id, jid });
    }
    refresh_feed_suggestions();
}

/// Unfollow a feed (remove + persist + drop its cached posts).
pub fn unfollow_feed(jid: String) {
    {
        let mut list = FOLLOWED.lock().unwrap();
        list.retain(|j| !j.eq_ignore_ascii_case(&jid));
        save_followed(&list);
    }
    FEED_POSTS.lock().unwrap().remove(&jid.to_lowercase());
    // Drop the cached posts too (posts the contact pushes later still arrive).
    if let Some(account_id) = CLIENT.lock().unwrap().as_ref().map(|c| c.account_id) {
        runtime().spawn(async move {
            if let Ok(store) = store().await {
                let _ = store.replace_feed(account_id, &jid, &[]).await;
            }
        });
    }
    refresh_feed_suggestions();
    if let Some(qt) = backend_qt() {
        let _ = qt.queue(|mut backend: Pin<&mut Backend>| backend.as_mut().feeds_changed());
    }
}

/// Publish a top-level post to our own feed: Markdown `content`, an optional local file to
/// attach (uploaded with its metadata stripped) and an optional related web link.
pub fn publish_post(title: String, content: String, attachment_path: String, link: String) -> bool {
    if title.trim().is_empty() && content.trim().is_empty() && attachment_path.is_empty() {
        return false;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return false };
    ctx.commands
        .try_send(Command::PublishPost {
            account_id: ctx.account_id,
            title,
            content,
            attachment_path,
            attachment: None,
            link,
            edit: None,
        })
        .is_ok()
}

/// Replace our post `post_id` (XEP-0277 edit: same id, original publish time). The attachment
/// is kept unless `attachment_path` names a new file.
pub fn edit_post(post_id: String, title: String, content: String, attachment_path: String, link: String) -> bool {
    let own = OWN_JID.lock().unwrap().clone();
    let Some(post) = find_post(&own, &post_id) else { return false };
    let attachment = (!post.attachment_url.is_empty()).then(|| (post.attachment_url.clone(), post.attachment_type.clone()));
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return false };
    ctx.commands
        .try_send(Command::PublishPost {
            account_id: ctx.account_id,
            title,
            content,
            attachment_path,
            attachment,
            link,
            edit: Some((post_id, post.published)),
        })
        .is_ok()
}

/// `xmpp:` URI of a post (to share it), as Android builds it.
pub fn post_uri(author: &str, post_id: &str) -> String {
    format!("xmpp:{author}?;node={};item={post_id}", mxc_proto::xeps::microblog::NS_MICROBLOG)
}

/// Retract one of our own posts.
pub fn retract_post(post_id: String) {
    if post_id.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::RetractPost { account_id: ctx.account_id, post_id });
}

/// Retract a comment (ours, or any comment on our own post).
pub fn retract_comment(post_author: String, post_id: String, comment_id: String) {
    if comment_id.is_empty() {
        return;
    }
    let Some((service, node)) = comments_node_of(&post_author, &post_id) else { return };
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::RetractComment { account_id: ctx.account_id, service, node, comment_id });
}

/// Publish a comment on a post (XEP-0472 reply).
pub fn publish_comment(post_author: String, post_id: String, content: String) {
    if content.trim().is_empty() {
        return;
    }
    let Some((service, node)) = comments_node_of(&post_author, &post_id) else { return };
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::PublishComment { account_id: ctx.account_id, service, node, content });
}

/// OMEMO2 device-key cache for the trust UI, keyed by a contact's bare JID (or `OWN_KEY`
/// for our own devices). Filled by the event pump from `ContactKeys` / `OwnKeys`; the
/// `DeviceModel` reads it synchronously (see `crate::devices`).
static DEVICE_KEYS: LazyLock<Mutex<HashMap<String, Vec<DeviceEntry>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The cached devices for `jid` (a bare JID, or `OWN_KEY`), empty until the reply lands.
pub fn devices_for(jid: &str) -> Vec<DeviceEntry> {
    DEVICE_KEYS.lock().unwrap().get(jid).cloned().unwrap_or_default()
}

/// Ask the core for a contact's OMEMO2 device keys (reply arrives as `Event::ContactKeys`).
pub fn request_contact_keys(jid: &str) {
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        let _ = ctx.commands.try_send(Command::FetchContactKeys {
            account_id: ctx.account_id,
            jid: jid.to_string(),
        });
    }
}

/// Ask the core for our own profile + OMEMO2 device keys (reply arrives as `Event::OwnKeys`).
pub fn request_own_keys() {
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        let _ = ctx.commands.try_send(Command::FetchOwnKeys { account_id: ctx.account_id });
    }
}

/// Verify `jid`'s keys from a scanned QR code / pasted verification link. Returns false when
/// the text is not a verification URI at all, or is one for a different JID — the caller shows
/// that as an error rather than silently doing nothing. Matching devices are marked manually
/// verified by the core, which then re-emits the key list.
pub fn verify_from_uri(jid: &str, text: &str) -> bool {
    let Some(parsed) = mxc_proto::uri::parse(text) else { return false };
    if !parsed.jid.eq_ignore_ascii_case(jid) || parsed.fingerprints.is_empty() {
        return false;
    }
    let Some((account_id, commands)) =
        CLIENT.lock().unwrap().as_ref().map(|c| (c.account_id, c.commands.clone()))
    else {
        return false;
    };
    let fingerprints = parsed.all_hex();
    let _ = commands.try_send(Command::VerifyOmemoFingerprints {
        account_id,
        jid: parsed.jid,
        fingerprints,
    });
    true
}

/// Set a device's trust (1 = trusted/enabled, 2 = untrusted/disabled, 3 = manually verified).
/// Optimistically updates the cache so the switch sticks; the core re-emits the authoritative
/// list on next fetch.
pub fn set_trust(jid: String, device_id: i64, trust: i64) {
    {
        let mut map = DEVICE_KEYS.lock().unwrap();
        if let Some(list) = map.get_mut(&jid) {
            if let Some(d) = list.iter_mut().find(|d| d.device_id == device_id) {
                d.trust = trust;
            }
        }
    }
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        let _ = ctx.commands.try_send(Command::SetOmemoTrust {
            account_id: ctx.account_id,
            jid,
            device_id,
            trust,
        });
    }
}

/// Map a core `DeviceKey` (a contact's / our other device) into a UI `DeviceEntry`.
fn device_entry(d: &DeviceKey) -> DeviceEntry {
    DeviceEntry {
        device_id: d.device_id,
        fingerprint: d.fingerprint.clone(),
        trust: d.trust,
        active: d.active,
        is_this: false,
    }
}

/// Reset (wipe + rebuild) our cached OMEMO2 peer identities/sessions — the recovery action for
/// stale OMEMO2 state. Our own identity (fingerprint) is preserved. The core replies with a
/// fresh `Event::OwnKeys`, so the key screen refreshes itself.
pub fn reset_omemo2_identities() {
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        let _ = ctx
            .commands
            .try_send(Command::ResetOmemo2Identities { account_id: ctx.account_id });
    }
}

/// LAST RESORT: regenerate our OWN OMEMO2 identity — new key pairs, new device id, new
/// fingerprint — and wipe all peer state. Contacts must verify this device again. The core
/// replies with a fresh `Event::OwnKeys` + a toast.
pub fn regenerate_omemo2_identity() {
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        let _ = ctx
            .commands
            .try_send(Command::RegenerateOmemo2Identity { account_id: ctx.account_id });
    }
}

/// Toggle the app-wide "auto-trust new keys" (blind-trust) setting.
pub fn set_auto_trust(value: bool) {
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        let _ = ctx.commands.try_send(Command::SetAutoTrust {
            account_id: ctx.account_id,
            value,
        });
    }
}

/// Persist a conversation's encryption mode (used by the header lock toggle).
pub fn set_conversation_encryption(conversation_id: i64, encrypted: bool) {
    let mode = if encrypted { "omemo2" } else { "none" };
    runtime().spawn(async move {
        if let Ok(store) = store().await {
            let _ = store.set_conversation_encryption(conversation_id, mode).await;
        }
    });
}

// --- Presence helpers (mirrors the GTK app's window.rs) -------------------------------------

fn show_to_state(show: Option<&str>) -> &'static str {
    match show {
        Some("away") => "away",
        Some("xa") => "xa",
        Some("dnd") => "dnd",
        _ => "online", // None / "chat" / unexpected → online
    }
}

fn presence_rank(state: &str) -> u8 {
    match state {
        "online" => 4,
        "away" => 3,
        "xa" => 2,
        "dnd" => 1,
        _ => 0,
    }
}

/// The most-available presence among `bare`'s resources, or "offline" if none are present.
fn best_presence(map: &HashMap<String, String>, bare: &str) -> &'static str {
    let best = map
        .iter()
        .filter(|(full, _)| full.split('/').next() == Some(bare))
        .map(|(_, state)| state.as_str())
        .max_by_key(|s| presence_rank(s));
    match best {
        Some("away") => "away",
        Some("xa") => "xa",
        Some("dnd") => "dnd",
        Some("online") => "online",
        _ => "offline",
    }
}

/// The shown presence for a bare JID (reads the global map).
fn presence_for(bare: &str) -> String {
    best_presence(&PRESENCE.lock().unwrap(), bare).to_string()
}

// --- Avatar disk cache (shared with the GTK client: same dir + hash) ------------------------

fn avatar_cache_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join(".cache")
        });
    base.join("monocles-chat").join("avatars")
}

/// Avatar cache file for `jid` (contact, room, or `room/nick` occupant - all sender-chosen),
/// named by SHA-256 like the media cache: collision-resistant and stable across Rust releases.
fn avatar_cache_path(jid: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(jid.as_bytes());
    let mut name = String::with_capacity(40);
    for b in &digest[..20] {
        name.push_str(&format!("{b:02x}"));
    }
    avatar_cache_dir().join(name)
}

fn save_avatar_to_disk(jid: &str, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let _ = std::fs::create_dir_all(avatar_cache_dir());
    let _ = std::fs::write(avatar_cache_path(jid), data);
}

/// The cached avatar file path for `jid` (as a string) if present, else "".
pub(crate) fn avatar_path_for(jid: &str) -> String {
    let path = avatar_cache_path(jid);
    let Ok(meta) = std::fs::metadata(&path) else { return String::new() };
    if !meta.is_file() {
        return String::new();
    }
    // Append the mtime as a query: QML Images can then `cache: true` (no reload flash when
    // list models reset) while a republished avatar still busts the cache. QUrl drops the
    // query when resolving the local file, so loading is unaffected.
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}?m={mtime}", path.to_string_lossy())
}

/// Encode a decoded RGBA call frame as a downscaled JPEG `data:` URL for a QML `Image`. The
/// preview is capped (240px local, 480px remote) so per-frame encode + main-thread decode stay
/// cheap; returns `None` for empty/short frames.
fn encode_frame_data_url(frame: &CallVideoFrame) -> Option<String> {
    use base64::Engine;
    use image::{DynamicImage, RgbaImage};

    let expected = (frame.width as usize) * (frame.height as usize) * 4;
    if frame.width == 0 || frame.height == 0 || frame.data.len() < expected {
        return None;
    }
    let img = RgbaImage::from_raw(frame.width, frame.height, frame.data[..expected].to_vec())?;
    let mut dynimg = DynamicImage::ImageRgba8(img);
    let max_w = if frame.local { 240 } else { 480 };
    if frame.width > max_w {
        let h = (frame.height * max_w / frame.width).max(1);
        dynimg = dynimg.resize(max_w, h, image::imageops::FilterType::Triangle);
    }
    let mut buf = std::io::Cursor::new(Vec::new());
    dynimg.write_to(&mut buf, image::ImageFormat::Jpeg).ok()?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(buf.get_ref());
    Some(format!("data:image/jpeg;base64,{b64}"))
}

// --- Inline image / sticker URL cache (shared layout with the GTK client: ~/.cache/monocles-chat/media) ---

/// The file extension to use for a downloaded image URL (from the URL's last path segment).
/// The cache file extension for a media URL: its own extension when that is one of
/// [`SAFE_OPEN_EXTENSIONS`], else "img". The URL is sender-controlled, so nothing else (path or
/// shell characters, very long names, executable types) may reach the file name.
fn url_ext(url: &str) -> String {
    let name = url.rsplit('/').next().unwrap_or("");
    let name = name.split(['?', '#']).next().unwrap_or(name);
    let ext = name.rsplit('.').next().unwrap_or("");
    let ext = ext.to_ascii_lowercase();
    // Only known document/media extensions: cached files are also handed to xdg-open (e.g. the
    // story "Play video" button), so `x.desktop` declared as video must not be cached as such.
    if ext.is_empty() || ext == name.to_ascii_lowercase() || !SAFE_OPEN_EXTENSIONS.contains(&ext.as_str()) {
        "img".to_string()
    } else {
        ext
    }
}

/// File types that may be handed to the system's default application: plain images, audio,
/// video and documents. The sender picks the type, and `xdg-open` on e.g. a `.desktop`, `.jar`,
/// `.exe` (wine) or `.flatpakref` file can run code or start installs.
const SAFE_OPEN_EXTENSIONS: &[&str] = &[
    // images
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "avif", "heic", "heif",
    // audio / video
    "mp3", "m4a", "aac", "ogg", "oga", "opus", "flac", "wav", "mp4", "m4v", "webm", "mkv", "mov", "3gp",
    // documents
    "pdf", "txt", "md", "odt", "ods", "odp", "docx", "xlsx", "pptx", "doc", "xls", "ppt", "csv", "epub",
];

/// The deterministic on-disk cache path a media URL maps to (its existence = "downloaded").
/// Named by SHA-256 of the URL: with a non-cryptographic hash a sender could craft a URL that
/// collides with another one and have its file shown in that one's place (and std's hasher
/// isn't even stable across Rust releases).
pub fn image_cache_path(url: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(url.as_bytes());
    let mut name = String::with_capacity(48);
    for b in &digest[..20] {
        name.push_str(&format!("{b:02x}"));
    }
    let base = avatar_cache_dir();
    let media = base.parent().map(|p| p.join("media")).unwrap_or_else(|| base.join("media"));
    media.join(format!("{name}.{}", url_ext(url)))
}

/// Whether a file the user just downloaded may be opened automatically with the system's
/// default application: only [`SAFE_OPEN_EXTENSIONS`]; anything else is just saved (the toast
/// says where).
fn safe_to_open(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SAFE_OPEN_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

/// Download (+ decrypt, for `aesgcm://`) any not-yet-cached image URLs referenced by `rows`,
/// then reload the model so the freshly-cached images appear. Deduped + runs off-thread.
fn prefetch_images(rows: &[mxc_store::MessageRow], qt: &CxxQtThread<MessageModel>, auto_download: bool) {
    if !auto_download {
        // Public group: don't auto-fetch remote media (avoids leaking our IP to untrusted
        // senders and pulling unwanted content). The user downloads explicitly per file.
        return;
    }
    // One message may share several files (XEP-0447), so fetch every media URL it carries.
    for url in rows.iter().flat_map(crate::messages::row_media_urls) {
        let path = image_cache_path(&url);
        if path.is_file() {
            continue;
        }
        if !IMAGE_REQUESTED.lock().unwrap().insert(url.clone()) {
            continue; // already downloading
        }
        let qt = qt.clone();
        runtime().spawn(async move {
            // Fetched without the user asking: the small automatic-download cap applies.
            let result = mxc_proto::xeps::http_upload::download_any(
                &url,
                mxc_proto::xeps::http_upload::AUTO_DOWNLOAD_LIMIT,
            )
            .await;
            IMAGE_REQUESTED.lock().unwrap().remove(&url);
            if let Ok(bytes) = result {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if std::fs::write(&path, &bytes).is_ok() {
                    // Reload the open conversation so `from_row` now resolves the cached file.
                    let _ = qt.queue(|model: Pin<&mut MessageModel>| model.reload_current());
                }
            }
        });
    }
}

/// On-demand fetch of one media URL into the image cache (a user tapped "Download" in a public
/// group), then reload the open conversation so `from_row` resolves the now-cached file and
/// renders it inline — the same path as `prefetch_images`, but triggered explicitly.
pub fn fetch_media(url: String, qt: CxxQtThread<MessageModel>) {
    if url.is_empty() {
        return;
    }
    let path = image_cache_path(&url);
    if path.is_file() {
        let _ = qt.queue(|model: Pin<&mut MessageModel>| model.reload_current());
        return;
    }
    if !IMAGE_REQUESTED.lock().unwrap().insert(url.clone()) {
        return; // already downloading
    }
    runtime().spawn(async move {
        // The user asked for this one (tapped "Download").
        let result = mxc_proto::xeps::http_upload::download_any(
            &url,
            mxc_proto::xeps::http_upload::MANUAL_DOWNLOAD_LIMIT,
        )
        .await;
        IMAGE_REQUESTED.lock().unwrap().remove(&url);
        if let Ok(bytes) = result {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if std::fs::write(&path, &bytes).is_ok() {
                let _ = qt.queue(|model: Pin<&mut MessageModel>| model.reload_current());
            }
        }
    });
}

/// Ask the server for `jid`'s avatar once (deduped), if connected.
fn request_avatar(jid: &str, is_muc: bool) {
    if !AVATAR_REQUESTED.lock().unwrap().insert(jid.to_string()) {
        return; // already requested
    }
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        let _ = ctx.commands.try_send(Command::FetchAvatar {
            account_id: ctx.account_id,
            jid: jid.to_string(),
            is_muc,
        });
    }
}

pub(crate) fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("mxc-tokio")
            .build()
            .expect("build tokio runtime")
    })
}

/// Cross-platform application data dir (Linux: ~/.local/share/monocles-chat — same path
/// the GTK app uses, so a dev machine shares one DB; macOS/Windows use the native dir).
fn db_path() -> PathBuf {
    let dir = directories::ProjectDirs::from("de", "monocles", "monocles-chat")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    dir.join("monocles.db")
}

/// The shared store, opening it on first use.
pub(crate) async fn store() -> anyhow::Result<&'static Store> {
    STORE
        .get_or_try_init(|| async { Store::open(db_path()).await.map_err(|e| anyhow::anyhow!("{e}")) })
        .await
}

/// Manual login (from the login form): persist the credentials, then connect.
pub fn start(jid: String, password: String, qt: CxxQtThread<Backend>) {
    runtime().spawn(run_session(jid, password, qt));
}

/// Startup auto-login: reconnect the first enabled account whose password is sealed in the
/// secret service (mirrors the GTK client). No-op if there's no such account / no secret.
pub fn try_autologin(qt: CxxQtThread<Backend>) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let Ok(Some(account)) = store.autologin_account().await else { return };
        let secret =
            mxc_store::secrets::retrieve(mxc_store::secrets::kinds::PASSWORD, &account.jid).await;
        let Ok(Some(bytes)) = secret else { return };
        let Ok(password) = String::from_utf8(bytes) else { return };
        run_session(account.jid, password, qt).await;
    });
}

/// Open the store, ensure + persist the account, spawn the core and pump events into the QObject.
/// The password is sealed in the OS secret service (Linux Secret Service / macOS Keychain /
/// Windows Credential Manager, via `mxc-store`) so the next launch can auto-login.
async fn run_session(jid: String, password: String, qt: CxxQtThread<Backend>) {
    // Publish the account JID up front so QML can switch to the shell on auto-login.
    let jid_for_qt = jid.clone();
    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
        backend.as_mut().set_account_jid(QString::from(&jid_for_qt));
    });
    backend_update(&qt, "Opening store…", false);

    let store = match store().await {
        Ok(s) => s,
        Err(e) => return backend_update(&qt, &format!("Store error: {e}"), false),
    };

    let account_id = match store.upsert_account(&jid).await {
        Ok(id) => id,
        Err(e) => return backend_update(&qt, &format!("Account error: {e}"), false),
    };
    let _ = store.set_account_enabled(account_id, true).await;

    // Seal the password for next-launch auto-login (idempotent; references used before move).
    if mxc_store::secrets::store(mxc_store::secrets::kinds::PASSWORD, &jid, password.as_bytes())
        .await
        .is_ok()
    {
        let _ = store.mark_has_secret(account_id, true).await;
    }

    backend_update(&qt, "Connecting…", false);
        *OWN_JID.lock().unwrap() = jid.clone();
        let handle = spawn(
            store.clone(),
            vec![AccountConfig::new(account_id, jid.clone(), password)],
        );
        // Publish the command sink so sends from QML can reach the core.
        *CLIENT.lock().unwrap() = Some(ClientCtx {
            commands: handle.commands.clone(),
            account_id,
            jid,
        });
        let _ = handle.commands.send(Command::Connect { account_id }).await;

        // Show the cached feed right away; the fetches after connecting refresh it.
        load_cached_feeds(&store, account_id, &qt).await;

        // Video-frame pump (separate task so high-rate frames don't share the event loop):
        // encode each frame for the current call to a JPEG data URL and push it to the call
        // screen's remote/local Image.
        let video_rx = handle.video.clone();
        let qt_video = qt.clone();
        runtime().spawn(async move {
            while let Ok(frame) = video_rx.recv().await {
                // A frame belongs either to the 1:1 call on screen or to a Muji group call (where
                // each participant's per-pair session has its own sid).
                let cur_sid = CURRENT_CALL.lock().unwrap().as_ref().map(|c| c.sid.clone());
                let is_conf_sid = !frame.sid.is_empty()
                    && CURRENT_CONFERENCE
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map(|c| c.participants.iter().any(|p| p.sid == frame.sid))
                        .unwrap_or(false);
                if cur_sid.as_deref() == Some(frame.sid.as_str()) {
                    let Some(url) = encode_frame_data_url(&frame) else { continue };
                    let local = frame.local;
                    let _ = qt_video.queue(move |mut backend: Pin<&mut Backend>| {
                        if local {
                            backend.as_mut().set_local_frame(QString::from(&url));
                        } else {
                            backend.as_mut().set_remote_frame(QString::from(&url));
                        }
                    });
                } else if is_conf_sid {
                    let Some(url) = encode_frame_data_url(&frame) else { continue };
                    if frame.local {
                        // Our own camera — a single shared self-preview for the conference.
                        let _ = qt_video.queue(move |mut backend: Pin<&mut Backend>| {
                            backend.as_mut().set_local_frame(QString::from(&url));
                        });
                    } else {
                        // Tag the remote frame with its participant's sid so the right tile updates.
                        let sid = frame.sid.clone();
                        let _ = qt_video.queue(move |mut backend: Pin<&mut Backend>| {
                            backend.as_mut().conference_frame(QString::from(&sid), QString::from(&url));
                        });
                    }
                }
            }
        });

        // Let the WebXDC bridge (called from Chromium's IO thread) queue work onto the Qt
        // thread without holding the event pump's handle.
        let _ = BACKEND_QT.set(qt.clone());

        // Our own bare JID (from the just-stored ClientCtx — `jid` itself was moved into it),
        // for routing own-profile events (nick) below.
        let own_bare = client_info()
            .map(|(_, _, j)| j.split('/').next().unwrap_or(&j).to_string())
            .unwrap_or_default();

        // Donation banner: shown at the bottom of the chats list unless snoozed (one week).
        {
            let qt = qt.clone();
            runtime().spawn(async move {
                let due = match crate::session::store().await {
                    Ok(s) => s
                        .donation_banner_due(chrono::Utc::now().timestamp())
                        .await
                        .unwrap_or(false),
                    Err(_) => false,
                };
                let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                    backend.as_mut().set_donation_due(due);
                });
            });
        }

        // Default monocles support-room entry: shown in Contacts unless the user dismissed it.
        {
            let qt = qt.clone();
            runtime().spawn(async move {
                let visible = match (crate::session::store().await, client_info()) {
                    (Ok(s), Some((_, account_id, _))) => {
                        !s.support_room_dismissed(account_id).await.unwrap_or(false)
                    }
                    _ => true,
                };
                let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                    backend.as_mut().set_support_room_visible(visible);
                });
            });
        }

        // Chat background: apply the saved choice (mode + custom image path).
        {
            let qt = qt.clone();
            runtime().spawn(async move {
                let (mode, path) = match crate::session::store().await {
                    Ok(s) => s
                        .chat_background()
                        .await
                        .unwrap_or_else(|_| ("default".to_string(), String::new())),
                    Err(_) => ("default".to_string(), String::new()),
                };
                let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                    backend.as_mut().set_chat_bg_mode(QString::from(mode.as_str()));
                    backend.as_mut().set_chat_bg_custom_path(QString::from(path.as_str()));
                });
            });
        }

        // Preferred camera: apply the saved choice to the call engine + reflect it in the picker.
        {
            let qt = qt.clone();
            runtime().spawn(async move {
                let path = match crate::session::store().await {
                    Ok(s) => s.preferred_camera().await.unwrap_or_default(),
                    Err(_) => String::new(),
                };
                mxc_media::set_preferred_camera(
                    if path.is_empty() { None } else { Some(path.clone()) },
                );
                let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                    backend.as_mut().set_preferred_camera(QString::from(path.as_str()));
                });
            });
        }

        // Event pump: connection lifecycle → Backend state; message/list changes → signals
        // QML models reload on.
        while let Ok(event) = handle.events.recv().await {
            match event {
                Event::Connection(state) => match state {
                    ConnectionState::Connecting => backend_update(&qt, "Connecting…", false),
                    ConnectionState::Online { full_jid } => {
                        backend_update(&qt, &format!("Online as {full_jid}"), true)
                    }
                    ConnectionState::Disconnected { reason } => {
                        backend_update(&qt, &format!("Disconnected: {reason}"), false)
                    }
                },
                Event::MessageStored { conversation_id, .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().message_stored(conversation_id);
                        backend.as_mut().conversations_changed();
                    });
                }
                Event::FileSaved { path, .. } => {
                    let open = safe_to_open(&path);
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().file_saved(QString::from(&path), open);
                    });
                }
                Event::ConversationsUpdated { .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().conversations_changed();
                    });
                }
                // XEP-0308 correction (ours or the peer's): the core already rewrote the
                // stored row — reload the conversation + list preview.
                Event::MessageEdited { conversation_id, .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().message_stored(conversation_id);
                        backend.as_mut().conversations_changed();
                    });
                }
                // XEP-0424 retraction: the core tombstoned the row (content + metadata +
                // reactions); also drop the media file the old body may have cached.
                Event::MessageRetracted { conversation_id, body, .. } => {
                    if let Some(url) = body.as_deref().and_then(crate::messages::media_url) {
                        let _ = std::fs::remove_file(image_cache_path(&url));
                    }
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().message_stored(conversation_id);
                        backend.as_mut().conversations_changed();
                    });
                }
                Event::Presence { full_jid, show, status, .. } => {
                    let bare = full_jid.split('/').next().unwrap_or(&full_jid).to_string();
                    let mut map = PRESENCE.lock().unwrap();
                    let before = best_presence(&map, &bare);
                    if status.as_deref() == Some("offline") {
                        map.remove(&full_jid);
                    } else {
                        map.insert(full_jid.clone(), show_to_state(show.as_deref()).to_string());
                    }
                    let changed = before != best_presence(&map, &bare);
                    drop(map);
                    // Repaint the lists only when a 1:1 contact's shown status changed (the
                    // lists don't show presence for rooms) — a busy MUC's occupants joining/
                    // leaving otherwise causes constant refresh churn. Known rooms are the
                    // MUC_OMEMO keys (filled on join). Debounced: joining still bursts.
                    let is_room = MUC_OMEMO.lock().unwrap().contains_key(&bare);
                    if changed && !is_room {
                        schedule_list_refresh(false);
                    }
                }
                Event::Avatar { jid, data, .. } => {
                    if !data.is_empty() {
                        save_avatar_to_disk(&jid, &data);
                        schedule_list_refresh(false);
                    }
                }
                // A published nickname (XEP-0172) — ours feeds the profile dialog's field.
                Event::NickUpdated { jid, nick, .. } => {
                    if jid == own_bare {
                        let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                            backend.as_mut().set_own_nick(QString::from(&nick));
                        });
                    }
                }
                // A contact's RFC 6121 subscription state (FetchSubscription reply, or a
                // roster push after a change) → refresh the contact-details toggles.
                Event::Subscription { jid, subscription, ask, .. } => {
                    let ask = ask.unwrap_or_default();
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().subscription_changed(
                            QString::from(&jid),
                            QString::from(&subscription),
                            QString::from(&ask),
                        );
                    });
                }
                // Someone asks to see our presence → QML shows the Allow/Decline prompt.
                Event::SubscriptionRequest { jid, nick, .. } => {
                    let nick = nick.unwrap_or_default();
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend
                            .as_mut()
                            .subscription_request(QString::from(&jid), QString::from(&nick));
                    });
                }
                // WebXDC app-state sync: a stored status update / live realtime packet /
                // selective notification for an app instance (see crate::webxdc).
                Event::WebxdcUpdate { thread, .. } => {
                    crate::webxdc::push_updates(&thread);
                }
                Event::WebxdcRealtime { thread, data_b64, .. } => {
                    crate::webxdc::push_realtime(&thread, &data_b64);
                }
                Event::WebxdcNotify { text, .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().webxdc_notify(QString::from(&text));
                    });
                }
                // Room OMEMO capability discovered (join/disco) → re-gate the lock toggle.
                Event::MucPrivacy { room, omemo_capable, .. } => {
                    MUC_OMEMO.lock().unwrap().insert(room, omemo_capable);
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().muc_privacy_changed();
                    });
                }
                // MUC occupant avatar — cache keyed by the occupant JID (room/nick).
                Event::MucAvatar { room, nick, data, .. } => {
                    if !data.is_empty() {
                        save_avatar_to_disk(&format!("{room}/{nick}"), &data);
                        // Debounced: also refreshes the open MUC (per-message sender avatars).
                        schedule_list_refresh(true);
                    }
                }
                // Delivery receipt / read marker (XEP-0184/0333): the core persisted the new
                // state; refresh the open conversation so its footer updates.
                Event::MessageState { .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().refresh_open();
                    });
                }
                // XEP-0444 reaction tallies changed — update just that message in place (no full
                // reload, so the chat doesn't scroll to the bottom).
                Event::ReactionsUpdated { message_id, tallies, .. } => {
                    let serialized = tallies
                        .iter()
                        .map(|(emoji, count, nicks)| format!("{emoji}\t{count}\t{nicks}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().reactions_updated(message_id, QString::from(&serialized));
                    });
                }
                // 1:1 call lifecycle (JMI/Jingle) → drive the call screen's properties.
                Event::CallUpdate { sid, peer, video, state, .. } => {
                    let state_str = match &state {
                        CallState::Incoming => "incoming",
                        CallState::Outgoing => "outgoing",
                        CallState::Connecting => "connecting",
                        CallState::Active => "active",
                        CallState::Ended { .. } => "ended",
                    };
                    let active = !matches!(state, CallState::Ended { .. });
                    *CURRENT_CALL.lock().unwrap() = active.then(|| CallCtx {
                        sid: sid.clone(),
                        peer: peer.clone(),
                    });
                    let ss = state_str.to_string();
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().set_call_peer(QString::from(&peer));
                        backend.as_mut().set_call_video(video);
                        backend.as_mut().set_call_state(QString::from(&ss));
                        backend.as_mut().set_call_active(active);
                        if !active {
                            backend.as_mut().set_call_muted(false);
                            backend.as_mut().set_call_screen_sharing(false);
                            backend.as_mut().set_call_video_request(false);
                            backend.as_mut().set_call_trust(0);
                            backend.as_mut().set_call_verified_fp(QString::default());
                            backend.as_mut().set_call_verified_device(0);
                            backend.as_mut().set_remote_frame(QString::default());
                            backend.as_mut().set_local_frame(QString::default());
                            // The core just logged the finished call → refresh the Calls list.
                            backend.as_mut().calls_changed();
                        }
                    });
                }
                // Peer asked to upgrade the call to video → raise the consent prompt.
                Event::CallVideoUpgradeRequest { .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().set_call_video_request(true);
                    });
                }
                // Authoritative screen-share state (also corrects an optimistic button if the
                // portal picker was cancelled).
                Event::CallScreenShare { active, .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().set_call_screen_sharing(active);
                    });
                }
                // The call's DTLS was authenticated via PQ OMEMO2 → drive the trust indicator
                // (0 = none, 1 = BTBV-trusted/lock, 2 = manually verified/shield). The indicator
                // is gated on trust so it never over-claims.
                Event::CallVerified { fingerprint, device_id, trust, .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().set_call_trust(trust as i32);
                        backend.as_mut().set_call_verified_fp(QString::from(fingerprint.as_str()));
                        backend.as_mut().set_call_verified_device(device_id);
                    });
                }
                // XEP-0272 Muji: another member started a group call → show a "Join" prompt.
                Event::ConferenceInvite { room, from, .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().set_conference_invite_room(QString::from(&room));
                        backend.as_mut().set_conference_invite_from(QString::from(&from));
                    });
                }
                // The invited call ended → dismiss the prompt.
                Event::ConferenceInviteCancelled { .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().set_conference_invite_room(QString::default());
                        backend.as_mut().set_conference_invite_from(QString::default());
                    });
                }
                // XEP-0272 Muji group-call state → drive the conference panel + participant model.
                Event::ConferenceUpdate { room, active, video, participants, .. } => {
                    let entries: Vec<ConfPartEntry> = participants
                        .into_iter()
                        .map(|p: ConfParticipant| ConfPartEntry {
                            name: p.name,
                            avatar_path: avatar_path_for(&p.jid),
                            jid: p.jid,
                            state: p.state,
                            sid: p.sid,
                        })
                        .collect();
                    // Avatars are fetched lazily by the panel delegates (fetchMucAvatar), like
                    // the occupant list — no event-time fetch storm here.
                    *CURRENT_CONFERENCE.lock().unwrap() = active.then(|| ConferenceView {
                        room: room.clone(),
                        participants: entries,
                    });
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().set_conference_active(active);
                        backend.as_mut().set_conference_room(QString::from(&room));
                        backend.as_mut().set_conference_video(video);
                        if !active {
                            backend.as_mut().set_conference_muted(false);
                            backend.as_mut().set_conference_camera_on(true);
                            backend.as_mut().set_conference_screen_sharing(false);
                            backend.as_mut().set_local_frame(QString::default());
                        }
                        backend.as_mut().conference_changed();
                    });
                }
                // Authoritative group screen-share state (resets the button if the portal picker
                // was cancelled).
                Event::ConferenceScreenShare { active, .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().set_conference_screen_sharing(active);
                    });
                }
                // Stories cache changed (fetched / received / retracted) → reload the feed.
                Event::StoriesUpdated { .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().stories_changed();
                    });
                }
                // vCard4 profile (1:1 contact or MUC room) → cache photo + push fields to QML.
                Event::Vcard { jid, photo, fields, .. } => {
                    let had_photo = !photo.is_empty();
                    if had_photo {
                        save_avatar_to_disk(&jid, &photo);
                    }
                    let serialized = fields
                        .iter()
                        .map(|(label, value)| format!("{label}\t{value}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        if had_photo {
                            backend.as_mut().conversations_changed();
                        }
                        backend.as_mut().vcard_ready(QString::from(&jid), QString::from(&serialized));
                    });
                }
                // A feed's posts arrived (XEP-0472) → cache them, prefetch each post's comments
                // (counts) and image attachment, and reload the Feeds UI.
                Event::FeedPosts { jid, posts, public, .. } => {
                    if public {
                        PUBLIC_FEEDS.lock().unwrap().insert(jid.to_lowercase());
                    } else {
                        PUBLIC_FEEDS.lock().unwrap().remove(&jid.to_lowercase());
                    }
                    request_comments(&posts);
                    prefetch_feed_media(&posts, &qt);
                    FEED_POSTS.lock().unwrap().insert(jid.to_lowercase(), posts);
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().feeds_changed();
                    });
                }
                // A post was published or edited (PEP push) → add or replace it.
                Event::FeedPostReceived { post, .. } => {
                    request_comments(std::slice::from_ref(&post));
                    prefetch_feed_media(std::slice::from_ref(&post), &qt);
                    {
                        let mut map = FEED_POSTS.lock().unwrap();
                        let posts = map.entry(post.author.to_lowercase()).or_default();
                        posts.retain(|p| p.id != post.id);
                        posts.push(post);
                        posts.sort_by_key(|p| std::cmp::Reverse(p.published));
                    }
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().feeds_changed();
                    });
                }
                // A post was retracted by its author.
                Event::FeedPostRetracted { author, post_id, .. } => {
                    let removed = FEED_POSTS
                        .lock()
                        .unwrap()
                        .get_mut(&author.to_lowercase())
                        .map(|posts| {
                            let before = posts.len();
                            posts.retain(|p| p.id != post_id);
                            posts.len() != before
                        })
                        .unwrap_or(false);
                    if removed {
                        let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                            backend.as_mut().feeds_changed();
                        });
                    }
                }
                // A comments node's items arrived → cache by node + reload the open post.
                Event::FeedComments { service, node, comments, .. } => {
                    FEED_COMMENTS.lock().unwrap().insert(comments_key(&service, &node), comments);
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().feeds_changed();
                    });
                }
                // A comments node changed: refetch it if one of our posts points at it (the
                // node name is chosen by whoever creates it, so match service and node).
                Event::FeedCommentsChanged { service, node, .. } => {
                    let known = FEED_POSTS.lock().unwrap().values().flatten().any(|p| {
                        p.comments_node == node && p.comments_jid.eq_ignore_ascii_case(&service)
                    });
                    if known {
                        if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
                            let _ = ctx.commands.try_send(Command::FetchComments {
                                account_id: ctx.account_id,
                                service,
                                node,
                            });
                        }
                    }
                }
                // A Story / post the user started finished uploading + publishing.
                Event::PublishDone { what, error, .. } => {
                    let text = match (what.as_str(), &error) {
                        ("story", None) => "Story published".to_string(),
                        ("story", Some(e)) => format!("Couldn't post story: {e}"),
                        (_, None) => "Post published".to_string(),
                        (_, Some(e)) => format!("Couldn't publish post: {e}"),
                    };
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        let pending = (backend.publishing() - 1).max(0);
                        backend.as_mut().set_publishing(pending);
                        backend.as_mut().toast(QString::from(&text));
                    });
                }
                // OMEMO2 trust UI: a contact's device keys arrived → cache + tell QML to reload
                // the device model showing this JID.
                Event::ContactKeys { jid, devices, .. } => {
                    let items: Vec<DeviceEntry> = devices.iter().map(device_entry).collect();
                    DEVICE_KEYS.lock().unwrap().insert(jid.clone(), items);
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().keys_changed(QString::from(&jid));
                    });
                }
                // Our own profile + device keys: prepend *this* device, then our others.
                Event::OwnKeys {
                    own_device_id,
                    own_fingerprint,
                    verification_uri,
                    devices,
                    auto_trust,
                    presence_show,
                    presence_status,
                    ..
                } => {
                    let mut items = vec![DeviceEntry {
                        device_id: own_device_id,
                        fingerprint: own_fingerprint.clone(),
                        trust: 1,
                        active: true,
                        is_this: true,
                    }];
                    items.extend(devices.iter().map(device_entry));
                    DEVICE_KEYS.lock().unwrap().insert(OWN_KEY.to_string(), items);
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().set_own_fingerprint(QString::from(&own_fingerprint));
                        backend
                            .as_mut()
                            .set_own_verification_uri(QString::from(&verification_uri));
                        backend.as_mut().set_auto_trust(auto_trust);
                        backend.as_mut().set_own_show(QString::from(&presence_show));
                        backend.as_mut().set_own_status(QString::from(&presence_status));
                        backend.as_mut().keys_changed(QString::from(OWN_KEY));
                    });
                }
                // Passive feedback from the core (key verification, OMEMO resets, …).
                Event::Toast { text, .. } => {
                    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
                        backend.as_mut().toast(QString::from(&text));
                    });
                }
                _ => {}
            }
        }
}

/// Send a chat message via the connected core (no-op if not logged in yet). `reply_to` is
/// the XEP-0461 target marker (stanza/origin id), or `None`.
pub fn send_message(to: String, body: String, encrypted: bool, reply_to: Option<String>) {
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let encryption = if encrypted { Encryption::Omemo2 } else { Encryption::None };
    let _ = ctx.commands.try_send(Command::SendMessage {
        account_id: ctx.account_id,
        to,
        body,
        encryption,
        reply_to,
        id: None,
    });
}

/// Publish the image at `path` as our own avatar (XEP-0084). Animated images (GIF / animated
/// WebP) up to 100 KB are published as the RAW file so they stay animated — same rule and
/// size cap as monocles Android. Anything else (or an oversized animation) is decoded,
/// scaled to ≤192px and JPEG-encoded. The reply `Event::Avatar` caches + repaints it.
pub fn publish_avatar(path: String) {
    let Some((commands, account_id, _)) = client_info() else { return };
    runtime().spawn(async move {
        let result =
            tokio::task::spawn_blocking(move || -> anyhow::Result<(Vec<u8>, String, u32, u32)> {
                let raw = std::fs::read(&path)?;
                if let Some(mime) = animated_image_mime(&raw) {
                    if raw.len() <= 100_000 {
                        let (w, h) = image::ImageReader::new(std::io::Cursor::new(&raw))
                            .with_guessed_format()?
                            .into_dimensions()
                            .unwrap_or((0, 0));
                        return Ok((raw, mime.to_string(), w, h));
                    }
                    tracing::info!("avatar: animation over 100 kB — publishing a still instead");
                }
                let img = image::open(&path)?; // GIF/WebP decode to the first frame
                let img = img.thumbnail(192, 192);
                let rgb = image::DynamicImage::ImageRgb8(img.to_rgb8());
                let mut bytes: Vec<u8> = Vec::new();
                rgb.write_to(&mut std::io::Cursor::new(&mut bytes), image::ImageFormat::Jpeg)?;
                Ok((bytes, "image/jpeg".to_string(), rgb.width(), rgb.height()))
            })
            .await;
        match result {
            Ok(Ok((data, mime, width, height))) => {
                let _ = commands
                    .send(Command::PublishAvatar { account_id, data, mime, width, height })
                    .await;
            }
            Ok(Err(e)) => tracing::warn!(error = %e, "avatar: couldn't read/scale image"),
            Err(e) => tracing::warn!(error = %e, "avatar: scale task failed"),
        }
    });
}

/// The mime of an image worth publishing raw to keep its animation: any GIF, or a WebP with
/// an ANIM chunk. (A single-frame GIF published raw is harmless.)
pub(crate) fn animated_image_mime(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if b.len() > 16
        && &b[0..4] == b"RIFF"
        && &b[8..12] == b"WEBP"
        && b[..b.len().min(256)].windows(4).any(|w| w == b"ANIM")
    {
        return Some("image/webp");
    }
    None
}

/// Publish our own nickname (XEP-0172).
pub fn set_nick(nick: String) {
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::SetNick { account_id: ctx.account_id, nick });
}

/// Fetch a published nickname (reply: `Event::NickUpdated` → `ownNick` when it's ours).
pub fn fetch_nick(jid: String) {
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::FetchNick { account_id: ctx.account_id, jid });
}

/// Set + broadcast our own presence (`show` ∈ ""|chat|away|xa|dnd + status message). The core
/// persists it (settings keys presence_show/presence_status) and re-sends it on reconnect.
pub fn set_presence(show: String, status: String) {
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::SetPresence {
        account_id: ctx.account_id,
        show,
        status,
    });
}

/// Log out: shut the core down, forget the sealed password + disable autologin, and clear
/// the Backend's session state so QML returns to the login page (mirrors the GTK logout).
pub fn logout() {
    let Some(ctx) = CLIENT.lock().unwrap().take() else { return };
    let _ = ctx.commands.try_send(Command::Shutdown);
    let jid = ctx.jid.clone();
    let account_id = ctx.account_id;
    runtime().spawn(async move {
        let _ = mxc_store::secrets::delete(mxc_store::secrets::kinds::PASSWORD, &jid).await;
        if let Ok(store) = store().await {
            let _ = store.mark_has_secret(account_id, false).await;
            let _ = store.set_account_enabled(account_id, false).await;
        }
        if let Some(qt) = backend_qt() {
            let _ = qt.queue(|mut backend: Pin<&mut Backend>| {
                backend.as_mut().set_connected(false);
                backend.as_mut().set_status(QString::from("Disconnected"));
                // Emptying the account JID flips QML back to the login page.
                backend.as_mut().set_account_jid(QString::default());
            });
        }
    });
}

/// Permanently dismiss the default support-room entry for the current account.
pub fn dismiss_support_room() {
    let account_id = client_info().map(|(_, a, _)| a);
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let Some(account_id) = account_id else { return };
        let _ = store.dismiss_support_room(account_id).await;
    });
}

/// Persist the chat-background mode ("default" | "none" | "custom").
pub fn set_chat_bg_mode(mode: String) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let _ = store.set_chat_bg_mode(&mode).await;
    });
}

/// Persist the custom chat-background image path.
pub fn set_chat_bg_custom_path(path: String) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let _ = store.set_chat_bg_custom_path(&path).await;
    });
}

/// The camera picker's options as a JSON array `[{"name","path"}, …]` for QML. Runs the
/// GStreamer device monitor synchronously (fast) and lists only usable color cameras (IR /
/// grayscale / metadata nodes are excluded).
pub fn camera_list_json() -> String {
    fn esc(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push(' '),
                c => out.push(c),
            }
        }
        out
    }
    let mut out = String::from("[");
    for (i, (name, path)) in mxc_media::list_cameras().into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{{\"name\":\"{}\",\"path\":\"{}\"}}", esc(&name), esc(&path)));
    }
    out.push(']');
    out
}

/// Persist the preferred camera ("" = automatic) and apply it to the call engine immediately, so
/// the next video call opens the chosen device.
pub fn set_preferred_camera(path: String) {
    mxc_media::set_preferred_camera(if path.is_empty() { None } else { Some(path.clone()) });
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let _ = store.set_preferred_camera(&path).await;
    });
}

/// Snooze the donation banner for a week (shared store key, same as the GTK client).
pub fn snooze_donation() {
    runtime().spawn(async move {
        if let Ok(store) = store().await {
            let _ = store.snooze_donation_banner(chrono::Utc::now().timestamp()).await;
        }
    });
}

/// Add `jid` to the roster (RFC 6121 set + subscribe with pre-approval — the core's
/// AddContact also auto-grants their counter-request, like Android's createContact).
pub fn add_contact(jid: String, name: String) {
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let name = if name.trim().is_empty() { None } else { Some(name.trim().to_string()) };
    let _ = ctx.commands.try_send(Command::AddContact {
        account_id: ctx.account_id,
        jid,
        name,
    });
}

/// Fetch a contact's RFC 6121 subscription state (replies via `subscriptionChanged`).
pub fn fetch_subscription(jid: String) {
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx
        .commands
        .try_send(Command::FetchSubscription { account_id: ctx.account_id, jid });
}

/// RFC 6121 subscription change; `action` ∈ subscribe|unsubscribe|subscribed|unsubscribed
/// (the strings QML passes — mapped onto the proto enum here).
pub fn set_subscription(jid: String, action: String) {
    use mxc_proto::command::Subscription;
    let action = match action.as_str() {
        "subscribe" => Subscription::Subscribe,
        "unsubscribe" => Subscription::Unsubscribe,
        "subscribed" => Subscription::Subscribed,
        "unsubscribed" => Subscription::Unsubscribed,
        _ => return,
    };
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx
        .commands
        .try_send(Command::SetSubscription { account_id: ctx.account_id, jid, action });
}

/// XEP-0424: retract one of our own messages (`target_id` = its origin/stanza id marker).
pub fn retract_message(conversation_id: i64, to: String, target_id: String) {
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::Retract {
        account_id: ctx.account_id,
        conversation_id,
        to,
        target_id,
    });
}

/// XEP-0308: replace one of our own messages' body.
pub fn correct_message(conversation_id: i64, to: String, target_id: String, new_body: String) {
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::Correct {
        account_id: ctx.account_id,
        conversation_id,
        to,
        target_id,
        new_body,
    });
}

/// Build display rows with their XEP-0444 reaction tallies attached (one query for the
/// whole conversation, grouped by message id). Each item's `reactions` is "emoji\tcount"
/// chips joined by '\n'.
async fn build_items(
    store: &Store,
    conversation_id: i64,
    rows: &[mxc_store::MessageRow],
    auto_download: bool,
) -> Vec<MessageItem> {
    let mut items = MessageItem::from_rows(rows, auto_download);
    // Per-message sender avatar for incoming MUC messages (counterpart = room@host/nick).
    for (item, row) in items.iter_mut().zip(rows.iter()) {
        if row.direction == "in" {
            if let Some((room, nick)) = row.counterpart.rsplit_once('/') {
                item.sender_avatar = avatar_path_for(&row.counterpart);
                if item.sender_avatar.is_empty() {
                    request_muc_avatar(room, nick);
                }
            }
        }
    }
    let tallies = store
        .reactions_for_conversation(conversation_id)
        .await
        .unwrap_or_default();
    if tallies.is_empty() {
        return items;
    }
    let mut by_mid: HashMap<i64, String> = HashMap::new();
    for (mid, emoji, count, nicks) in &tallies {
        let chip = format!("{emoji}\t{count}\t{nicks}");
        by_mid
            .entry(*mid)
            .and_modify(|s| {
                s.push('\n');
                s.push_str(&chip);
            })
            .or_insert(chip);
    }
    for item in &mut items {
        // A retracted message is a tombstone: any reactions it gathered stay hidden.
        if item.retracted {
            continue;
        }
        if let Some(s) = by_mid.get(&item.id) {
            item.reactions = s.clone();
        }
    }
    items
}

/// The stickers folder (`<data dir>/stickers`, same as the GTK client). Sub-folders are packs.
/// The stickers folder as a string, created if missing (for the picker's folder button).
pub fn sticker_dir_path() -> String {
    let dir = sticker_dir();
    let _ = std::fs::create_dir_all(&dir);
    dir.to_string_lossy().into_owned()
}

fn sticker_dir() -> PathBuf {
    let dir = directories::ProjectDirs::from("de", "monocles", "monocles-chat")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join("stickers")
}

/// All sticker image files (top level + one level of pack sub-folders), newline-joined absolute
/// paths for QML. Empty if the folder doesn't exist yet.
pub fn sticker_files() -> String {
    fn is_image(p: &std::path::Path) -> bool {
        matches!(
            p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase().as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp"
        )
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    let root = sticker_dir();
    let Ok(entries) = std::fs::read_dir(&root) else { return String::new() };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Ok(pack) = std::fs::read_dir(&path) {
                for e in pack.flatten() {
                    let p = e.path();
                    if p.is_file() && is_image(&p) {
                        paths.push(p);
                    }
                }
            }
        } else if path.is_file() && is_image(&path) {
            paths.push(path);
        }
    }
    paths.sort();
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Send a file (XEP-0363 upload + aesgcm encryption) to `to`.
pub fn send_file(to: String, path: String, caption: String) {
    if to.is_empty() || path.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    // A `.xdc` bundle is a WebXDC app: the core attaches a fresh instance `<thread>` so the
    // participants' status updates sync (matches GTK + Android).
    let cmd = if path.to_ascii_lowercase().ends_with(".xdc") {
        Command::SendWebxdcFile { account_id: ctx.account_id, to, path }
    } else {
        let caption = caption.trim();
        let caption = if caption.is_empty() { None } else { Some(caption.to_string()) };
        Command::SendFile { account_id: ctx.account_id, to, path, caption }
    };
    let _ = ctx.commands.try_send(cmd);
}

/// Share several files in ONE message (XEP-0447). `.xdc` WebXDC apps are sent on their own —
/// each needs its own instance `<thread>`, so they can never be grouped — and one remaining
/// file falls back to the plain single-file path, keeping that wire format unchanged.
pub fn send_files(to: String, paths: Vec<String>, caption: String) {
    if to.is_empty() || paths.is_empty() {
        return;
    }
    let (webxdc, files): (Vec<String>, Vec<String>) =
        paths.into_iter().partition(|p| p.to_ascii_lowercase().ends_with(".xdc"));
    for app in webxdc {
        send_file(to.clone(), app, String::new());
    }
    if files.is_empty() {
        return;
    }
    if files.len() == 1 {
        send_file(to, files.into_iter().next().unwrap_or_default(), caption);
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let caption = caption.trim();
    let caption = if caption.is_empty() { None } else { Some(caption.to_string()) };
    let _ = ctx.commands.try_send(Command::SendFiles {
        account_id: ctx.account_id,
        to,
        paths: files,
        caption,
    });
}

/// Download (+ decrypt, for `aesgcm://`) a shared file to the downloads folder. The core replies
/// with `Event::FileSaved`, which the event loop turns into the `fileSaved` signal for QML.
pub fn download_file(url: String, filename: String) {
    if url.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    // Save under the real file name from the URL; the caller's `filename` may be a display
    // label (e.g. "Image (JPG)" for public-group cards), so it's only a last-resort fallback.
    let from_url = url
        .rsplit('/')
        .next()
        .unwrap_or("")
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    let filename = if !from_url.is_empty() {
        from_url.to_string()
    } else if !filename.trim().is_empty() {
        filename.trim().to_string()
    } else {
        "file".to_string()
    };
    let _ = ctx.commands.try_send(Command::DownloadFile {
        account_id: ctx.account_id,
        url,
        filename,
    });
}

/// Fetch a contact's / room's vCard4 profile (photo + fields). Reply arrives as `Event::Vcard`.
pub fn fetch_vcard(jid: String, is_muc: bool) {
    if jid.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::FetchVcard { account_id: ctx.account_id, jid, is_muc });
}

/// Send the image at `path` as a sticker to `to` (the core picks OMEMO image vs inline BoB).
pub fn send_sticker(to: String, path: String) {
    if to.is_empty() || path.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::SendSticker {
        account_id: ctx.account_id,
        to,
        path,
    });
}

/// Remove a conversation from the chats list (local close; keeps the roster entry).
pub fn delete_chat(jid: String) {
    if jid.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::DeleteChat { account_id: ctx.account_id, jid });
}

/// Leave a group chat (unavailable presence + drop bookmark + remove locally).
pub fn leave_muc(room: String) {
    if room.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::LeaveMuc { account_id: ctx.account_id, room });
}

/// Remove a contact from the roster entirely (cancels subscriptions + drops local data).
pub fn remove_contact(jid: String) {
    if jid.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::RemoveContact { account_id: ctx.account_id, jid });
}

/// Join (or create) a multi-user chat room with the given nick.
pub fn join_muc(room: String, nick: String) {
    if room.is_empty() || nick.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::JoinMuc {
        account_id: ctx.account_id,
        room,
        nick,
        password: None,
    });
}

/// Toggle a reaction (XEP-0444) on a message. The core handles the toggle / full-set wire
/// semantics, so we just send the tapped emoji.
pub fn react(to: String, target_id: String, emoji: String) {
    if to.is_empty() || target_id.is_empty() || emoji.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::React {
        account_id: ctx.account_id,
        to,
        target_id,
        emojis: vec![emoji],
    });
}

/// Load a conversation's most recent `limit` messages and reset the message model.
/// The marker we last sent a XEP-0333 "displayed" for, per conversation — the open chat
/// reloads often (delivery updates, reactions), and the peer should get ONE marker per
/// newest incoming message, not one per repaint.
static LAST_MARKED: LazyLock<Mutex<HashMap<i64, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Viewing a conversation marks it read (the loaders below run exactly when its messages are
/// (re)shown): clears the unread counter locally — the chat-list row + nav badge update via
/// `conversationsChanged` — and sends the read marker for the newest incoming message, like
/// the GTK client does on open / while viewing.
fn mark_displayed(conversation_id: i64, rows: &[mxc_store::MessageRow]) {
    let Some(marker) = rows
        .iter()
        .rev()
        .find(|r| r.direction == "in")
        .and_then(|r| r.origin_id.clone().or_else(|| r.stanza_id.clone()))
    else {
        return;
    };
    {
        let mut marked = LAST_MARKED.lock().unwrap();
        if marked.get(&conversation_id) == Some(&marker) {
            return; // already acknowledged up to here
        }
        marked.insert(conversation_id, marker.clone());
    }
    let Some((commands, account_id, _)) = client_info() else { return };
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        // Clear locally FIRST so the list reload below can't race the core's own clear …
        let _ = store.clear_unread(conversation_id).await;
        // … then send the XEP-0333 marker (the core re-clears harmlessly).
        if let Ok(convs) = store.conversations(account_id).await {
            if let Some(conv) = convs.iter().find(|c| c.id == conversation_id) {
                let _ = commands
                    .send(Command::MarkRead {
                        account_id,
                        conversation_id,
                        to: conv.jid.clone(),
                        stanza_id: marker,
                    })
                    .await;
            }
        }
        if let Some(qt) = backend_qt() {
            let _ = qt.queue(|mut backend: Pin<&mut Backend>| {
                backend.as_mut().conversations_changed();
            });
        }
    });
}

pub fn load_messages(conversation_id: i64, limit: i64, qt: CxxQtThread<MessageModel>) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let rows = store
            .recent_messages(conversation_id, limit)
            .await
            .unwrap_or_default();
        mark_displayed(conversation_id, &rows);
        let auto_download = !store.is_public_group(conversation_id).await.unwrap_or(false);
        prefetch_images(&rows, &qt, auto_download);
        let items = build_items(store, conversation_id, &rows, auto_download).await;
        let _ = qt.queue(move |model: Pin<&mut MessageModel>| {
            model.reset(items);
        });
    });
}

/// Load an older page (a larger window). When the local store has fewer rows than
/// requested, also ask the server for an older MAM page (`Command::LoadHistory`), whose
/// backfilled messages arrive as `MessageStored`.
pub fn load_older(conversation_id: i64, limit: i64, qt: CxxQtThread<MessageModel>) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let rows = store
            .recent_messages(conversation_id, limit)
            .await
            .unwrap_or_default();
        if (rows.len() as i64) < limit {
            if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
                let _ = ctx.commands.try_send(Command::LoadHistory {
                    account_id: ctx.account_id,
                    conversation_id,
                    before: None,
                });
            }
        }
        let auto_download = !store.is_public_group(conversation_id).await.unwrap_or(false);
        prefetch_images(&rows, &qt, auto_download);
        let items = build_items(store, conversation_id, &rows, auto_download).await;
        let _ = qt.queue(move |model: Pin<&mut MessageModel>| {
            model.reset(items);
        });
    });
}

/// Open a conversation with enough recent history loaded to include `message_id`, then emit
/// `jumpReady(marker)` so the view scrolls to it (chats-list search jump-to-message).
pub fn load_messages_around(
    conversation_id: i64,
    message_id: i64,
    marker: String,
    qt: CxxQtThread<MessageModel>,
) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let count = store.count_since(conversation_id, message_id).await.unwrap_or(0);
        // Load the target plus a page of older context; never fewer than the normal first page.
        let limit = (count + crate::messages::INITIAL_LIMIT).max(crate::messages::INITIAL_LIMIT);
        let rows = store.recent_messages(conversation_id, limit).await.unwrap_or_default();
        mark_displayed(conversation_id, &rows);
        let auto_download = !store.is_public_group(conversation_id).await.unwrap_or(false);
        prefetch_images(&rows, &qt, auto_download);
        let items = build_items(store, conversation_id, &rows, auto_download).await;
        let _ = qt.queue(move |mut model: Pin<&mut MessageModel>| {
            model.as_mut().set_open(conversation_id, limit, items);
            model.as_mut().jump_ready(QString::from(marker.as_str()));
        });
    });
}

/// Substring search over the account's message history; resets the search model with the hits.
/// With `scope_jid` empty the search spans all conversations; set to a JID it's scoped to that
/// chat (Signal-style in-conversation search).
pub fn search_messages(
    account_jid: String,
    scope_jid: String,
    query: String,
    qt: CxxQtThread<MessageSearchModel>,
) {
    let query = query.trim().to_string();
    if query.is_empty() {
        let _ = qt.queue(|model: Pin<&mut MessageSearchModel>| model.reset(Vec::new()));
        return;
    }
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let Ok(account_id) = store.upsert_account(&account_jid).await else { return };
        let rows = store
            .search_messages(account_id, &query, &scope_jid, 300)
            .await
            .unwrap_or_default();
        let items: Vec<SearchResult> = rows
            .iter()
            .map(|r| {
                let mut item = SearchResult::from_row(r);
                item.avatar_path = avatar_path_for(&r.conv_jid);
                item
            })
            .collect();
        let _ = qt.queue(move |model: Pin<&mut MessageSearchModel>| {
            model.reset(items);
        });
    });
}

/// Resolve (creating if needed) the 1:1 chat for a contact's bare JID, then open it.
pub fn open_peer(jid: String, qt: CxxQtThread<MessageModel>) {
    open_peer_kind(jid, "chat".to_string(), qt);
}

/// Resolve (creating if needed) the conversation of `kind` for `jid` and open it. `kind` is
/// "chat" for a 1:1 peer or "muc_pm" for a MUC private message.
pub fn open_peer_kind(jid: String, kind: String, qt: CxxQtThread<MessageModel>) {
    let account_id = CLIENT.lock().unwrap().as_ref().map(|c| c.account_id);
    let Some(account_id) = account_id else { return };
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let Ok(conversation_id) = store.conversation_id(account_id, &jid, &kind).await else {
            return;
        };
        let rows = store
            .recent_messages(conversation_id, crate::messages::INITIAL_LIMIT)
            .await
            .unwrap_or_default();
        mark_displayed(conversation_id, &rows);
        let auto_download = !store.is_public_group(conversation_id).await.unwrap_or(false);
        prefetch_images(&rows, &qt, auto_download);
        let items = build_items(store, conversation_id, &rows, auto_download).await;
        let _ = qt.queue(move |model: Pin<&mut MessageModel>| {
            model.set_open(conversation_id, crate::messages::INITIAL_LIMIT, items);
        });
    });
}

/// Current occupants of `room` (bare jid), from the live presence map; also kicks off an
/// avatar fetch for each.
pub fn occupants(room: &str) -> Vec<OccupantEntry> {
    let mut items: Vec<OccupantEntry> = {
        let map = PRESENCE.lock().unwrap();
        map.iter()
            .filter_map(|(full, status)| {
                let (bare, nick) = full.rsplit_once('/')?;
                if bare == room && !nick.is_empty() {
                    Some(OccupantEntry {
                        nick: nick.to_string(),
                        jid: full.clone(),
                        presence: status.clone(),
                        avatar_path: avatar_path_for(full),
                    })
                } else {
                    None
                }
            })
            .collect()
    };
    items.sort_by(|a, b| a.nick.to_lowercase().cmp(&b.nick.to_lowercase()));
    // NOTE: avatars are NOT requested here — a big public room has hundreds of occupants and
    // firing a vCard fetch for each froze the app (event storm). The occupants list's
    // delegates request lazily (only instantiated rows) via `Backend.fetchMucAvatar`.
    items
}

/// Lazily fetch one occupant's avatar (`room@host/nick`), deduped — called per *visible*
/// occupants-list row from QML.
pub fn fetch_muc_avatar(occupant_jid: String) {
    if let Some((room, nick)) = occupant_jid.rsplit_once('/') {
        if !nick.is_empty() {
            request_muc_avatar(room, nick);
        }
    }
}

/// Start (create if needed) a private message with a MUC occupant.
pub fn start_private(occupant_jid: String) {
    if occupant_jid.is_empty() {
        return;
    }
    let guard = CLIENT.lock().unwrap();
    let Some(ctx) = guard.as_ref() else { return };
    let _ = ctx.commands.try_send(Command::StartPrivate {
        account_id: ctx.account_id,
        occupant_jid,
    });
}

/// Ask the server for a MUC occupant's avatar once (deduped, keyed by occupant jid).
fn request_muc_avatar(room: &str, nick: &str) {
    let key = format!("{room}/{nick}");
    if !AVATAR_REQUESTED.lock().unwrap().insert(key) {
        return;
    }
    if let Some(ctx) = CLIENT.lock().unwrap().as_ref() {
        let _ = ctx.commands.try_send(Command::FetchMucAvatar {
            account_id: ctx.account_id,
            room: room.to_string(),
            nick: nick.to_string(),
        });
    }
}

/// Load the account's contacts and reset the roster model.
pub fn load_roster(jid: String, qt: CxxQtThread<RosterModel>) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        let Ok(account_id) = store.upsert_account(&jid).await else { return };
        let roster = store.roster(account_id).await.unwrap_or_default();
        let items: Vec<RosterEntry> = roster
            .iter()
            .map(|r| {
                let mut item = RosterEntry::from_item(r);
                item.presence = presence_for(r.jid.split('/').next().unwrap_or(&r.jid));
                item.avatar_path = avatar_path_for(&r.jid);
                request_avatar(&r.jid, false);
                item
            })
            .collect();
        let _ = qt.queue(move |model: Pin<&mut RosterModel>| {
            model.reset(items);
        });
    });
}

/// Load an account's conversations from the local store and reset the model. Works
/// offline (cached rows), mirroring the GTK app's load-cached-lists behaviour.
pub fn load_conversations(jid: String, qt: CxxQtThread<ConversationModel>) {
    runtime().spawn(async move {
        let Ok(store) = store().await else { return };
        // upsert is idempotent and resolves the account id regardless of login ordering.
        let Ok(account_id) = store.upsert_account(&jid).await else { return };
        let convs = store.conversations(account_id).await.unwrap_or_default();
        let items: Vec<ConversationItem> = convs
            .iter()
            .map(|c| {
                let mut item = ConversationItem::from_conv(c);
                if c.kind == "chat" {
                    item.presence = presence_for(c.jid.split('/').next().unwrap_or(&c.jid));
                }
                item.avatar_path = avatar_path_for(&c.jid);
                request_avatar(&c.jid, c.kind == "muc");
                item
            })
            .collect();

        let _ = qt.queue(move |model: Pin<&mut ConversationModel>| {
            model.reset(items);
        });
    });
}

/// Queue a `Backend` property update onto the Qt thread.
fn backend_update(qt: &CxxQtThread<Backend>, status: &str, connected: bool) {
    let status = status.to_owned();
    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
        backend.as_mut().set_status(QString::from(&status));
        backend.as_mut().set_connected(connected);
    });
}

#[cfg(test)]
mod received_file_tests {
    use super::{image_cache_path, safe_to_open, url_ext};

    #[test]
    fn cache_names_take_only_safe_extensions() {
        assert_eq!(url_ext("https://u.example/a/photo.JPG"), "jpg");
        assert_eq!(url_ext("https://u.example/a/clip.mp4?x=1#y"), "mp4");
        assert_eq!(url_ext("https://u.example/a/x.desktop"), "img");
        assert_eq!(url_ext("https://u.example/a/x.sh"), "img");
        assert_eq!(url_ext("https://u.example/a/noext"), "img");
        assert_eq!(url_ext("aesgcm://u.example/a/f.pdf#abcd"), "pdf");
    }

    #[test]
    fn cache_paths_are_sha256_named_and_distinct() {
        let a = image_cache_path("https://u.example/a.jpg");
        let b = image_cache_path("https://u.example/b.jpg");
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_str().unwrap().to_string();
        assert_eq!(name.len(), 40 + ".jpg".len());
        assert!(name[..40].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn only_documents_and_media_open_automatically() {
        assert!(safe_to_open("/home/u/Downloads/report.PDF"));
        assert!(safe_to_open("/home/u/Downloads/song.ogg"));
        for bad in ["x.desktop", "x.sh", "x.jar", "x.exe", "x.flatpakref", "x.html", "x.AppImage", "noext"] {
            assert!(!safe_to_open(&format!("/home/u/Downloads/{bad}")), "{bad}");
        }
    }
}
