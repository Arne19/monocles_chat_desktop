//! `MessageModel` — a `QAbstractListModel` of the open conversation's messages.
//!
//! `open(conversation_id)` loads history (async, via [`crate::session`]); the chat page
//! calls `reload_current()` when `Backend::messageStored` fires for this conversation.

use std::collections::HashMap;
use std::pin::Pin;

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::{QByteArray, QHash, QHashPair_i32_QByteArray, QModelIndex, QString, QVariant};

use mxc_proto::xeps::bob;
use mxc_store::MessageRow;

/// Messages shown on first open, and how many more each scroll-to-top page adds.
pub const INITIAL_LIMIT: i64 = 40;
const PAGE: i64 = 40;

// Custom roles start at Qt::UserRole (256).
const ROLE_ID: i32 = 256;
const ROLE_BODY: i32 = 257;
const ROLE_OUTGOING: i32 = 258;
const ROLE_TIMESTAMP: i32 = 259;
const ROLE_ENCRYPTED: i32 = 260;
const ROLE_STATE: i32 = 261;
const ROLE_MARKER: i32 = 262;
const ROLE_REPLY_QUOTE: i32 = 263;
const ROLE_REPLY_TO: i32 = 264;
const ROLE_REACTIONS: i32 = 265;
const ROLE_SENDER: i32 = 266;
const ROLE_IMAGE: i32 = 267;
const ROLE_SENDER_AVATAR: i32 = 268;
const ROLE_DAY: i32 = 269;
const ROLE_AUDIO: i32 = 270;
const ROLE_EDITED: i32 = 271;
const ROLE_RETRACTED: i32 = 272;
const ROLE_WEBXDC: i32 = 273;
const ROLE_XDC_THREAD: i32 = 274;
const ROLE_WEBXDC_URL: i32 = 275;
const ROLE_FILE_URL: i32 = 276;
const ROLE_FILE_NAME: i32 = 277;
const ROLE_ATTACHMENTS: i32 = 278;
const ROLE_STANZA_ID: i32 = 279;
const ROLE_BODY_HTML: i32 = 280;
const ROLE_PREVIEW_TEXT: i32 = 281;
const ROLE_PREVIEW_IMAGE: i32 = 282;
const ROLE_REPLY_QUOTE_IMAGE: i32 = 283;

/// One message row, resolved for display.
#[derive(Clone, Default, PartialEq)]
pub struct MessageItem {
    pub id: i64,
    pub body: String,
    pub outgoing: bool,
    pub timestamp: String,
    pub encrypted: bool,
    /// Delivery state for outgoing messages: pending/sent/received/displayed.
    pub state: String,
    /// The id others reference (origin id, else stanza id) — used as a reply target.
    pub marker: String,
    /// Quoted body of the message this one replies to (XEP-0461), if resolvable.
    pub reply_quote: String,
    /// The marker this message replies to (target for jump-to-quote), or empty.
    pub reply_to: String,
    /// Small cached image of the quoted message (a photo or sticker it shares), or empty.
    pub reply_quote_image: String,
    /// This message in one short line, as a reply to it shows it: the text, or for media and
    /// files an icon and a label ("🖼 Photo", "🎤 Voice message", "📎 report.pdf", …).
    pub preview_text: String,
    /// A small image for [`Self::preview_text`]: the cached photo or sticker, or empty.
    pub preview_image: String,
    /// Reaction tallies, serialized as "emoji\tcount" chips joined by '\n' (set in session.rs).
    pub reactions: String,
    /// Sender nick (resource of counterpart) — shown for incoming MUC messages.
    pub sender: String,
    /// Local file path of an inline image (XEP-0231 BoB sticker) when the body is a `cid:`
    /// reference whose bytes are cached on disk; empty for plain messages.
    pub image_path: String,
    /// Cached avatar path of the sender (MUC occupant), for per-message avatars; set in
    /// `session::build_items` from the row's full occupant JID. Empty for 1:1.
    pub sender_avatar: String,
    /// Local calendar day ("YYYY-MM-DD") of the message — drives the date separators.
    pub day: String,
    /// Local file path of a downloaded audio attachment (voice message), or empty.
    pub audio_path: String,
    /// XEP-0308: the body shown is a correction of the original (renders an "edited" tag).
    pub edited: bool,
    /// XEP-0424: the message was retracted (renders as a tombstone).
    pub retracted: bool,
    /// The upload URL of a shared WebXDC `.xdc` app, or empty (renders an "Open app" bubble).
    pub webxdc_url: String,
    /// XEP-7397 thread id — the WebXDC app-instance key carried by `.xdc` messages.
    pub thread: String,
    /// A non-image/non-audio shared file's download URL, or empty (renders a file card with an
    /// "Open" button). The caption, if any, renders in `body` beneath it.
    pub file_url: String,
    /// Display name for `file_url` (the sender's file name, else the URL's last path segment;
    /// a type label in public groups).
    pub file_name: String,
    /// The media type of the single shared file (from the sender's XEP-0447 description), or
    /// empty. A PQ OMEMO2 upload URL has no extension, so this is what says what the file is.
    pub file_mime: String,
    /// The sender's name of the single shared file, to save a download under, or empty.
    pub file_save_name: String,
    /// A message sharing SEVERAL files (XEP-0447): a JSON array of
    /// `{url, name, kind: image|audio|file, path}` — `path` is the local cache copy, empty
    /// until it is downloaded. Empty string for the single-file case, which keeps rendering
    /// through `image_path` / `audio_path` / `file_url` exactly as before.
    pub attachments: String,
    /// The archive-assigned XEP-0359 stanza-id (the room's, in a MUC), or empty — the target
    /// of a XEP-0425 moderation.
    pub stanza_id: String,
    /// XEP-0393 styled `body` as escaped Qt rich text, or empty when nothing is styled (or the
    /// sender sent `<unstyled/>`): then `body` renders as plain text.
    pub body_html: String,
}

/// How a reloaded message list lines up with the shown one: `old[old_start..][..overlap]` are
/// the same messages as `new[new_start..][..overlap]`, and everything else was dropped or added
/// at either end. None if they don't line up like that (another chat, a jump) - then the model
/// is reset.
#[derive(Debug, PartialEq)]
struct Alignment {
    old_start: usize,
    new_start: usize,
    overlap: usize,
}

fn align(old: &[i64], new: &[i64]) -> Option<Alignment> {
    let (&old_first, &new_first) = (old.first()?, new.first()?);
    let (old_start, new_start) = if let Some(p) = new.iter().position(|&id| id == old_first) {
        (0, p)
    } else {
        (old.iter().position(|&id| id == new_first)?, 0)
    };
    let overlap = (old.len() - old_start).min(new.len() - new_start);
    let lines_up = old[old_start..old_start + overlap] == new[new_start..new_start + overlap];
    // The overlap must reach the end of one list: a message vanishing from the middle (e.g.
    // deleted) resets instead.
    let reaches_end = old_start + overlap == old.len() || new_start + overlap == new.len();
    (lines_up && reaches_end && overlap > 0).then_some(Alignment { old_start, new_start, overlap })
}

#[cfg(test)]
mod described_file_tests {
    use super::{file_type_label, row_media_url, webxdc_url, MessageItem, MessageRow};

    /// What monocles Android (and this client) send in a PQ OMEMO2 chat: an `aesgcm://` URL
    /// without extension, its type only in the XEP-0447 description (the attachment column).
    const OPAQUE: &str = "aesgcm://upload.example/slot/0123456789abcdef0123456789abcdef#00ff";

    fn row(attachment: Option<String>, thread: Option<&str>, body: &str) -> MessageRow {
        MessageRow {
            id: 1,
            conversation_id: 1,
            stanza_id: None,
            origin_id: None,
            counterpart: "bob@example.com".into(),
            direction: "in".into(),
            body: Some(body.into()),
            encryption: "omemo2".into(),
            state: "received".into(),
            edited_of: None,
            retracted: false,
            attachment,
            reply_to: None,
            omemo_fingerprint: None,
            timestamp: "2026-11-13T00:00:00Z".into(),
            thread: thread.map(str::to_string),
            moderated: false,
            moderation_reason: None,
            unstyled: false,
        }
    }

    fn described(mime: &str, name: &str) -> Option<String> {
        Some(
            serde_json::json!({
                "url": OPAQUE, "mime": mime,
                "files": [{ "url": OPAQUE, "mime": mime, "name": name }],
            })
            .to_string(),
        )
    }

    #[test]
    fn extensionless_upload_takes_its_type_from_the_description() {
        assert_eq!(row_media_url(&row(described("image/png", "a.png"), None, "")), Some(OPAQUE.into()));
        assert_eq!(row_media_url(&row(described("audio/ogg", "v.oga"), None, "")), Some(OPAQUE.into()));
        assert_eq!(row_media_url(&row(described("application/pdf", "d.pdf"), None, "")), None);
    }

    #[test]
    fn webxdc_is_recognised_by_its_described_type_only() {
        let app = row(described("application/webxdc+zip", "chess.xdc"), Some("t"), "");
        assert_eq!(webxdc_url(&app, ""), Some(OPAQUE.into()));
        // A described file of another type in a thread is not an app, even without extension.
        let pdf = row(described("application/pdf", "d.pdf"), Some("t"), "");
        assert_eq!(webxdc_url(&pdf, ""), None);
        // An undescribed, threaded, extension-less upload keeps the old guess.
        let legacy = row(None, Some("t"), OPAQUE);
        assert_eq!(webxdc_url(&legacy, OPAQUE), Some(OPAQUE.into()));
    }

    /// The described type only makes a file an inline image or audio player for the formats
    /// that can actually be shown (and are fetched automatically for that).
    #[test]
    fn only_renderable_types_become_inline_media() {
        for mime in ["image/svg+xml", "image/heic", "image/tiff", "audio/x-ms-wma", "video/mp4"] {
            assert_eq!(row_media_url(&row(described(mime, "f"), None, "")), None, "{mime}");
        }
        assert_eq!(row_media_url(&row(described("IMAGE/JPEG; x=y", "a"), None, "")), Some(OPAQUE.into()));
        assert_eq!(
            row_media_url(&row(described("audio/ogg; codecs=opus", "v"), None, "")),
            Some(OPAQUE.into())
        );
    }

    /// A generic type says nothing about an app: the threaded, extension-less guess still applies.
    #[test]
    fn generic_type_keeps_the_webxdc_guess() {
        let generic = row(described("application/octet-stream", "x"), Some("t"), "");
        assert_eq!(webxdc_url(&generic, ""), Some(OPAQUE.into()));
        let untyped = row(described("", "x"), Some("t"), "");
        assert_eq!(webxdc_url(&untyped, ""), Some(OPAQUE.into()));
        // Without a thread it is not an app.
        let unthreaded = row(described("application/octet-stream", "x"), None, "");
        assert_eq!(webxdc_url(&unthreaded, ""), None);
    }

    fn preview(m: &MessageRow) -> String {
        MessageItem::from_row(m, true).preview_text
    }

    /// A message without text - a photo, voice message, file or app - still has something to
    /// show when replied to: an icon and a label (or its caption).
    #[test]
    fn media_and_files_preview_by_icon_and_label() {
        assert_eq!(preview(&row(described("image/png", "a.png"), None, "")), "🖼 Photo");
        assert_eq!(preview(&row(described("image/png", "a.png"), None, "at the lake")), "🖼 at the lake");
        assert_eq!(preview(&row(described("audio/ogg", "v.oga"), None, "")), "🎤 Voice message");
        assert_eq!(preview(&row(described("application/pdf", "d.pdf"), None, "")), "📎 d.pdf");
        assert_eq!(
            preview(&row(described("application/webxdc+zip", "chess.xdc"), Some("t"), "")),
            "🧩 chess"
        );
        let two = serde_json::json!({
            "url": OPAQUE, "mime": "image/png",
            "files": [
                { "url": OPAQUE, "mime": "image/png", "name": "a.png" },
                { "url": format!("{OPAQUE}1"), "mime": "application/pdf", "name": "d.pdf" },
            ],
        })
        .to_string();
        assert_eq!(preview(&row(Some(two.clone()), None, "")), "📎 2 files");
        assert_eq!(preview(&row(Some(two), None, "both")), "📎 2 files · both");
        // Text is shown as text; a retracted message as such.
        assert_eq!(preview(&row(None, None, "hello\nthere")), "hello\nthere");
        let mut gone = row(described("image/png", "a.png"), None, "");
        gone.retracted = true;
        assert_eq!(preview(&gone), "(message retracted)");
        // Nothing is cached in the test, so no thumbnail.
        assert_eq!(MessageItem::from_row(&row(described("image/png", "a.png"), None, ""), true).preview_image, "");
    }

    /// A reply quotes the quoted message's preview, not its (empty) text.
    #[test]
    fn reply_to_a_file_quotes_its_preview() {
        let mut photo = row(described("image/jpeg", "p.jpg"), None, "");
        photo.origin_id = Some("m1".into());
        let mut answer = row(None, None, "nice");
        answer.id = 2;
        answer.reply_to = Some("m1".into());
        let items = MessageItem::from_rows(&[photo, answer], true);
        assert_eq!(items[1].reply_quote, "🖼 Photo");
        assert_eq!(items[0].reply_quote, "");
    }

    #[test]
    fn long_previews_are_capped() {
        let long = "x".repeat(500);
        let p = preview(&row(None, None, &long));
        assert_eq!(p.chars().count(), super::PREVIEW_MAX_CHARS + 1);
        assert!(p.ends_with('…'));
    }

    #[test]
    fn label_falls_back_to_the_described_type() {
        assert_eq!(file_type_label(OPAQUE, "application/pdf"), "PDF");
        assert_eq!(file_type_label(OPAQUE, "image/jpeg"), "Image");
        assert_eq!(file_type_label(OPAQUE, ""), "File");
        assert_eq!(file_type_label("https://u.example/a/photo.jpg", "application/pdf"), "Image (JPG)");
    }
}

#[cfg(test)]
mod align_tests {
    use super::{align, Alignment};

    fn a(old_start: usize, new_start: usize, overlap: usize) -> Option<Alignment> {
        Some(Alignment { old_start, new_start, overlap })
    }

    #[test]
    fn appended_dropped_and_prepended_rows_line_up() {
        assert_eq!(align(&[1, 2, 3], &[1, 2, 3]), a(0, 0, 3));
        // New message.
        assert_eq!(align(&[1, 2, 3], &[1, 2, 3, 4]), a(0, 0, 3));
        // Full window: the oldest drops out as a new one arrives.
        assert_eq!(align(&[1, 2, 3], &[2, 3, 4]), a(1, 0, 2));
        // Older page loaded.
        assert_eq!(align(&[3, 4], &[1, 2, 3, 4]), a(0, 2, 2));
        // Window shrank at the end.
        assert_eq!(align(&[1, 2, 3, 4], &[1, 2]), a(0, 0, 2));
    }

    #[test]
    fn anything_else_resets() {
        assert_eq!(align(&[], &[1]), None);
        assert_eq!(align(&[1, 2], &[]), None);
        assert_eq!(align(&[1, 2, 3], &[7, 8, 9]), None);
        // A message removed from the middle.
        assert_eq!(align(&[1, 2, 3, 4], &[1, 3, 4]), None);
        // Reordered.
        assert_eq!(align(&[1, 2, 3], &[1, 3, 2]), None);
    }
}

/// Local calendar day ("YYYY-MM-DD") of an RFC3339 / `datetime('now')` timestamp, for the chat's
/// date separators. Falls back to the date prefix when the string can't be parsed.
fn local_day(ts: &str) -> String {
    use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return dt.with_timezone(&Local).format("%Y-%m-%d").to_string();
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
        return Utc.from_utc_datetime(&ndt).with_timezone(&Local).format("%Y-%m-%d").to_string();
    }
    ts.chars().take(10).collect()
}

/// Whether `body` is a bare inline-sticker reference (a single `cid:` token, no other text).
fn is_sticker_cid(body: &str) -> bool {
    let t = body.trim();
    t.starts_with("cid:") && !t.contains(char::is_whitespace)
}

/// If `body` is a single image URL (`aesgcm://`/`http(s)://` ending in an image extension —
/// how larger / animated stickers and shared images arrive), return it. These need a network
/// fetch + decrypt (handled in `session::prefetch_images`), unlike inline `cid:` stickers.
pub fn image_url(body: &str) -> Option<String> {
    let t = body.trim();
    if t.contains(char::is_whitespace) {
        return None;
    }
    if !(t.starts_with("aesgcm://") || t.starts_with("https://") || t.starts_with("http://")) {
        return None;
    }
    let name = t.rsplit('/').next().unwrap_or("");
    let name = name.split(['?', '#']).next().unwrap_or(name).to_ascii_lowercase();
    let is_image = matches!(
        name.rsplit('.').next().unwrap_or(""),
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp"
    );
    is_image.then(|| t.to_string())
}

/// If `body` is a single audio-file URL (voice messages + shared audio arrive this way), return it.
pub fn audio_url(body: &str) -> Option<String> {
    let t = body.trim();
    if t.contains(char::is_whitespace) {
        return None;
    }
    if !(t.starts_with("aesgcm://") || t.starts_with("https://") || t.starts_with("http://")) {
        return None;
    }
    let name = t.rsplit('/').next().unwrap_or("");
    let name = name.split(['?', '#']).next().unwrap_or(name).to_ascii_lowercase();
    let is_audio = matches!(
        name.rsplit('.').next().unwrap_or(""),
        "oga" | "ogg" | "opus" | "m4a" | "mp3" | "wav" | "aac" | "flac" | "mpeg" | "amr"
    );
    is_audio.then(|| t.to_string())
}

/// Any downloadable media URL (image or audio) — used by the background prefetch.
pub fn media_url(body: &str) -> Option<String> {
    image_url(body).or_else(|| audio_url(body))
}

/// The file URL stored in a message's `attachment` column (captioned files store the URL here
/// and the caption in `body`), if any.
pub fn attachment_url(m: &MessageRow) -> Option<String> {
    let json = m.attachment.as_deref()?;
    serde_json::from_str::<serde_json::Value>(json)
        .ok()?
        .get("url")
        .and_then(|u| u.as_str())
        .map(str::to_string)
}

/// One shared file of a message. A message may carry several (XEP-0447 multi-file sharing, as
/// monocles Android sends it): the wire parser stores them in the `files` array of the
/// `attachment` column, keeping the first one at the top level for single-file callers.
#[derive(Clone)]
pub struct AttachmentFile {
    pub url: String,
    pub name: String,
    pub mime: String,
}

impl AttachmentFile {
    /// How the file renders: inline image, audio player, or a file card.
    pub fn kind(&self) -> &'static str {
        if image_url(&self.url).is_some() {
            "image"
        } else if audio_url(&self.url).is_some() {
            "audio"
        } else {
            renderable_kind(&self.mime).unwrap_or("file")
        }
    }
}

/// How a file of media type `mime` can be shown inline: "image" or "audio" for exactly the
/// formats [`image_url`] / [`audio_url`] accept by extension, else None (a file card). The type
/// is the sender's word, and a single-file message is fetched automatically when it says
/// "image" or "audio" - so `image/svg+xml`, `image/heic`, `audio/x-ms-wma` and the like must not
/// turn into an image or a player that cannot show them.
fn renderable_kind(mime: &str) -> Option<&'static str> {
    let mime = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match mime.as_str() {
        "image/png" | "image/jpeg" | "image/jpg" | "image/gif" | "image/webp" | "image/bmp" => {
            Some("image")
        }
        "audio/ogg" | "audio/opus" | "audio/mp4" | "audio/x-m4a" | "audio/m4a" | "audio/mpeg"
        | "audio/mp3" | "audio/wav" | "audio/x-wav" | "audio/wave" | "audio/aac" | "audio/flac"
        | "audio/x-flac" | "audio/amr" => Some("audio"),
        _ => None,
    }
}

/// Every file in a message's `attachment` column: the `files` array when the sender described
/// several, else the single `{url, mime}` shape.
pub fn attachment_files(m: &MessageRow) -> Vec<AttachmentFile> {
    m.attachment.as_deref().map(attachment_files_json).unwrap_or_default()
}

/// [`attachment_files`] from the raw `attachment` JSON (e.g. what a retraction removed).
pub fn attachment_files_json(json: &str) -> Vec<AttachmentFile> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
    let entries: Vec<&serde_json::Value> = match value.get("files").and_then(|f| f.as_array()) {
        Some(list) => list.iter().collect(),
        None => vec![&value],
    };
    entries
        .into_iter()
        .filter_map(|e| {
            let url = e.get("url").and_then(|u| u.as_str()).unwrap_or("").trim().to_string();
            if url.is_empty() {
                return None;
            }
            let name = e
                .get("name")
                .and_then(|n| n.as_str())
                .map(str::to_string)
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| file_name_of(&url));
            let mime = e.get("mime").and_then(|n| n.as_str()).unwrap_or("").to_string();
            Some(AttachmentFile { url, name, mime })
        })
        .collect()
}

/// The downloadable image/audio URL for a row: the attachment URL for captioned files, else the
/// single-URL body heuristic (legacy / caption-less). Used by rendering and the prefetch.
pub fn row_media_url(m: &MessageRow) -> Option<String> {
    if let Some(file) = attachment_files(m).into_iter().next() {
        // By the described type first: a PQ OMEMO2 upload URL carries no extension.
        return matches!(file.kind(), "image" | "audio").then_some(file.url);
    }
    m.body.as_deref().and_then(media_url)
}

/// Every downloadable media URL of a row — one per shared file. The prefetch uses this so a
/// multi-file message fetches *all* of its images, not just the first.
pub fn row_media_urls(m: &MessageRow) -> Vec<String> {
    let files = attachment_files(m);
    if files.len() > 1 {
        return files
            .into_iter()
            .filter(|f| matches!(f.kind(), "image" | "audio"))
            .map(|f| f.url)
            .collect();
    }
    row_media_url(m).into_iter().collect()
}

/// A caption-less file whose URL is in the body (legacy / OMEMO2 no-caption path), to offer for
/// download (an "Open" button). Restricted to `aesgcm://` — an encrypted upload is unambiguously
/// a shared file, whereas a bare `http(s)` body is a normal link and must stay text. Plaintext
/// file shares carry an OOB element and are handled via the attachment column instead.
/// Image/audio uploads render inline, so they're excluded here.
pub fn other_file_url(s: &str) -> Option<String> {
    let t = s.trim();
    if t.contains(char::is_whitespace) || !t.starts_with("aesgcm://") {
        return None;
    }
    if image_url(t).is_some() || audio_url(t).is_some() {
        return None;
    }
    Some(t.to_string())
}

/// The display file name for a URL: its last path segment (sans query/fragment), or "file".
fn file_name_of(url: &str) -> String {
    let name = url.rsplit('/').next().unwrap_or("");
    let name = name.split(['?', '#']).next().unwrap_or(name);
    if name.is_empty() { "file".to_string() } else { name.to_string() }
}

/// A human file-type label from a URL's extension (e.g. "Image (JPG)", "Video (MP4)", "File"),
/// used to name the download button in public groups where media isn't auto-fetched.
fn file_type_label(url: &str, mime: &str) -> String {
    let name = url.rsplit('/').next().unwrap_or("");
    let name = name.split(['?', '#']).next().unwrap_or(name).to_ascii_lowercase();
    let ext = match name.rsplit_once('.') {
        Some((_, e)) if !e.is_empty() => e.to_string(),
        // No extension (a PQ OMEMO2 upload): label by the described type instead.
        _ => return mime_type_label(mime),
    };
    let kind = match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" => "Image",
        "mp4" | "webm" | "mov" | "mkv" | "avi" | "m4v" => "Video",
        "oga" | "ogg" | "opus" | "m4a" | "mp3" | "wav" | "aac" | "flac" | "amr" | "mpeg" => "Audio",
        "pdf" => "PDF",
        "zip" | "7z" | "rar" | "tar" | "gz" => "Archive",
        "doc" | "docx" | "odt" | "rtf" | "txt" => "Document",
        _ => "File",
    };
    format!("{} ({})", kind, ext.to_uppercase())
}

/// The longest preview line kept (in characters); the QML elides it further to the width.
const PREVIEW_MAX_CHARS: usize = 160;

/// `text` capped to [`PREVIEW_MAX_CHARS`] characters (with "…"). Line breaks are kept - the
/// quote shows up to two lines - but trailing whitespace is not.
fn capped_preview(text: &str) -> String {
    let text = text.trim_end();
    if text.chars().count() <= PREVIEW_MAX_CHARS {
        return text.to_string();
    }
    let mut out: String = text.chars().take(PREVIEW_MAX_CHARS).collect();
    out.push('…');
    out
}

/// A human label for a media type, for a file whose URL has no extension.
fn mime_type_label(mime: &str) -> String {
    let mime = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let label = match mime.as_str() {
        "application/pdf" => "PDF",
        WEBXDC_MIME => "App",
        "application/zip" | "application/x-7z-compressed" | "application/vnd.rar"
        | "application/x-tar" | "application/gzip" => "Archive",
        m if m.starts_with("image/") => "Image",
        m if m.starts_with("video/") => "Video",
        m if m.starts_with("audio/") => "Audio",
        m if m.starts_with("text/") => "Document",
        m if m.starts_with("application/vnd.oasis.opendocument")
            || m.starts_with("application/vnd.openxmlformats-officedocument")
            || m == "application/msword" =>
        {
            "Document"
        }
        _ => "File",
    };
    label.to_string()
}

/// The media type of a WebXDC app archive.
const WEBXDC_MIME: &str = "application/webxdc+zip";

/// If the message is a shared WebXDC app, return its upload URL. Mirrors the GTK client's
/// detection: a single file URL whose name ends `.xdc`, OR an encrypted (`aesgcm://`),
/// **threaded**, extension-less upload — monocles Android names `.xdc` uploads by CID (no
/// extension), but always attaches the instance `<thread>`; normal shared files keep their
/// extension so they aren't misdetected.
pub fn webxdc_url(m: &MessageRow, body: &str) -> Option<String> {
    // A described file (XEP-0447, how monocles Android and this client share an app in a PQ
    // OMEMO2 chat): its type says it, the URL has no extension. A described file of another
    // type is never an app - the extension-less guess below is only for undescribed uploads.
    let files = attachment_files(m);
    if let [file] = files.as_slice() {
        if file.mime.eq_ignore_ascii_case(WEBXDC_MIME)
            || file_name_of(&file.url).to_ascii_lowercase().ends_with(".xdc")
        {
            return Some(file.url.clone());
        }
        let mime = file.mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        if !mime.is_empty() && mime != "application/octet-stream" {
            return None;
        }
        // A generic type (e.g. guessed from an extension-less OOB URL) says nothing: fall back
        // to the guess below, for the attachment's URL as well as the body.
        if let Some(url) = guessed_webxdc_url(m, &file.url) {
            return Some(url);
        }
    } else if !files.is_empty() {
        return None;
    }
    guessed_webxdc_url(m, body)
}

/// The undescribed-upload guess of [`webxdc_url`]: a single URL ending `.xdc`, or a threaded,
/// extension-less `aesgcm://` upload.
fn guessed_webxdc_url(m: &MessageRow, body: &str) -> Option<String> {
    let t = body.trim();
    if t.contains(char::is_whitespace) {
        return None;
    }
    if !(t.starts_with("aesgcm://") || t.starts_with("https://") || t.starts_with("http://")) {
        return None;
    }
    let name = t.rsplit('/').next().unwrap_or("");
    let name = name.split(['?', '#']).next().unwrap_or(name).to_ascii_lowercase();
    if name.ends_with(".xdc") {
        return Some(t.to_string());
    }
    if t.starts_with("aesgcm://") && m.thread.is_some() && !name.contains('.') {
        return Some(t.to_string());
    }
    None
}

impl MessageItem {
    /// `auto_download` is false for public groups: remote media is never fetched automatically;
    /// it renders as a typed download button (see `prefetch_images`, which is also skipped).
    pub fn from_row(m: &MessageRow, auto_download: bool) -> Self {
        let raw = m.body.clone().unwrap_or_default();
        // A captioned file stores the URL in the `attachment` column and the caption in `body`;
        // legacy / caption-less files keep the URL in `body`. Pick the URL to render media from,
        // and the caption to show alongside it.
        let att_url = if m.retracted { None } else { attachment_url(m) };
        let caption = if att_url.is_some() { raw.clone() } else { String::new() };
        let media_src = att_url.clone().unwrap_or_else(|| raw.clone());
        // An inline sticker: the whole body is a single `cid:` reference (XEP-0231 BoB). Resolve
        // it to the on-disk cache; render as an image when present, else a textual placeholder.
        let xdc_url = if m.retracted { None } else { webxdc_url(m, &raw) };
        // A non-image/non-audio shared file is rendered as a card with an "Open" button.
        let mut file_url = String::new();
        let mut file_name = String::new();
        // Several files in one message (XEP-0447): rendered as a tile per file, so the
        // single-file slots below stay empty and `body` keeps just the caption.
        let shared_files = if m.retracted { Vec::new() } else { attachment_files(m) };
        // The one described file of a single-file message: its type decides how it renders
        // (a PQ OMEMO2 upload URL has no extension to go by).
        let single = if shared_files.len() == 1 { shared_files.first().cloned() } else { None };
        let described = |url: &str| single.as_ref().filter(|f| f.url == url);
        let is_image = |url: &str| {
            image_url(url).is_some() || described(url).is_some_and(|f| f.kind() == "image")
        };
        let is_audio = |url: &str| {
            audio_url(url).is_some() || described(url).is_some_and(|f| f.kind() == "audio")
        };
        let mime_of = |url: &str| described(url).map(|f| f.mime.clone()).unwrap_or_default();
        let view = |url: &str| crate::session::media_view_typed(url, &mime_of(url));
        let mut attachments = String::new();
        // The first already-cached photo of a multi-file message, for its preview.
        let mut first_photo = String::new();
        if shared_files.len() > 1 {
            let mut tiles: Vec<serde_json::Value> = Vec::with_capacity(shared_files.len());
            for f in &shared_files {
                let path = crate::session::media_view_typed(&f.url, &f.mime);
                if first_photo.is_empty() && f.kind() == "image" && !path.is_empty() {
                    first_photo = path.clone();
                }
                tiles.push(serde_json::json!({
                    "url": f.url, "name": f.name, "kind": f.kind(), "path": path,
                }));
            }
            attachments = serde_json::to_string(&tiles).unwrap_or_default();
        }
        let (body, image_path, audio_path) = if m.moderated {
            let body = match m.moderation_reason.as_deref() {
                Some(reason) => format!("(removed by a moderator: {reason})"),
                None => "(removed by a moderator)".to_string(),
            };
            (body, String::new(), String::new())
        } else if m.retracted {
            ("(message retracted)".to_string(), String::new(), String::new())
        } else if !attachments.is_empty() {
            // The caption (empty when the files were sent without one) renders under the tiles.
            (raw.clone(), String::new(), String::new())
        } else if xdc_url.is_some() {
            // Rendered as an app card with an Open button (the QML checks the webxdc role).
            (String::new(), String::new(), String::new())
        } else if is_sticker_cid(&raw) {
            match bob::cache_path(raw.trim()).map(|p| crate::session::cache_view(&p)).filter(|p| !p.is_empty()) {
                Some(p) => (String::new(), p, String::new()),
                None => ("🙂 Sticker".to_string(), String::new(), String::new()),
            }
        } else if !auto_download {
            // Public group: never auto-fetch remote media (no IP leak to untrusted senders).
            // Show media inline only once the user has downloaded it (it's in the cache);
            // otherwise a typed download button. The caption, if any, renders beneath it.
            match att_url
                .clone()
                .or_else(|| image_url(&raw))
                .or_else(|| audio_url(&raw))
                .or_else(|| other_file_url(&raw))
            {
                Some(url) => {
                    let is_media = is_image(&url) || is_audio(&url);
                    let cached = if is_media { view(&url) } else { String::new() };
                    if is_image(&url) && !cached.is_empty() {
                        (caption.clone(), cached, String::new())
                    } else if is_audio(&url) && !cached.is_empty() {
                        (caption.clone(), String::new(), cached)
                    } else {
                        // Not downloaded yet (or a non-media file): a typed download button.
                        file_name = file_type_label(&url, &mime_of(&url));
                        file_url = url;
                        (caption.clone(), String::new(), String::new())
                    }
                }
                None => (raw.clone(), String::new(), String::new()),
            }
        } else if let Some(url) = Some(media_src.trim().to_string()).filter(|u| is_image(u)) {
            // A shared image / large or animated sticker sent as an upload URL. Show it once the
            // background fetch has cached it (see session::prefetch_images), else a placeholder.
            // `caption` (empty for caption-less files) renders beneath the image.
            match view(&url) {
                p if !p.is_empty() => (caption.clone(), p, String::new()),
                _ if caption.is_empty() => ("🖼 Loading image…".to_string(), String::new(), String::new()),
                _ => (caption.clone(), String::new(), String::new()),
            }
        } else if let Some(url) = Some(media_src.trim().to_string()).filter(|u| is_audio(u)) {
            // A voice message / shared audio file — rendered as an in-bubble player once cached.
            match view(&url) {
                p if !p.is_empty() => (caption.clone(), String::new(), p),
                _ if caption.is_empty() => ("🎤 Voice message".to_string(), String::new(), String::new()),
                _ => (caption.clone(), String::new(), String::new()),
            }
        } else if let Some(url) = att_url.as_deref() {
            // A captioned non-image/audio file: render a file card (Open button) + the caption.
            file_url = url.to_string();
            file_name = described(url).map(|f| f.name.clone()).unwrap_or_else(|| file_name_of(url));
            (caption.clone(), String::new(), String::new())
        } else if let Some(url) = other_file_url(&raw) {
            // A caption-less file sent the legacy way (URL in the body): same file card.
            file_url = url.clone();
            file_name = file_name_of(&url);
            (String::new(), String::new(), String::new())
        } else {
            (raw.clone(), String::new(), String::new())
        };
        // The message in one short line, for replies to it: media and files by icon + label
        // (a file without caption has no text at all), everything else by its text. Only an
        // image that is already cached is shown - nothing is fetched for a preview.
        let caption_or = |label: &str| {
            if caption.trim().is_empty() { label.to_string() } else { caption.clone() }
        };
        let media = media_src.trim();
        let (preview_text, preview_image) = if m.moderated {
            ("(removed by a moderator)".to_string(), String::new())
        } else if m.retracted {
            ("(message retracted)".to_string(), String::new())
        } else if shared_files.len() > 1 {
            let n = shared_files.len();
            let label = if shared_files.iter().all(|f| f.kind() == "image") {
                format!("🖼 {n} photos")
            } else {
                format!("📎 {n} files")
            };
            let text = if raw.trim().is_empty() { label } else { format!("{label} · {}", raw.trim()) };
            (text, first_photo)
        } else if xdc_url.is_some() {
            let name = single
                .as_ref()
                .map(|f| f.name.trim())
                .filter(|n| !n.is_empty())
                .map(|n| n.strip_suffix(".xdc").unwrap_or(n).to_string())
                .unwrap_or_else(|| "App".to_string());
            (format!("🧩 {name}"), String::new())
        } else if is_sticker_cid(&raw) {
            ("🙂 Sticker".to_string(), image_path.clone())
        } else if is_image(media) {
            (format!("🖼 {}", caption_or("Photo")), image_path.clone())
        } else if is_audio(media) {
            (format!("🎤 {}", caption_or("Voice message")), String::new())
        } else if att_url.is_some() || other_file_url(&raw).is_some() {
            let name = described(media)
                .map(|f| f.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| file_name_of(media));
            (format!("📎 {}", caption_or(&name)), String::new())
        } else {
            (raw.clone(), String::new())
        };
        let preview_text = capped_preview(&preview_text);

        // Only the sender's own text is styled - never our placeholders or tombstones.
        let body_html = if m.retracted || m.moderated {
            String::new()
        } else {
            mxc_proto::xeps::styling::to_html(&body, !m.unstyled).unwrap_or_default()
        };
        Self {
            id: m.id,
            body_html,
            body,
            image_path,
            outgoing: m.direction == "out",
            timestamp: m.timestamp.clone(),
            encrypted: m.encryption == "omemo2",
            state: m.state.clone(),
            marker: m.origin_id.clone().or_else(|| m.stanza_id.clone()).unwrap_or_default(),
            reply_quote: String::new(),
            reply_to: m.reply_to.clone().unwrap_or_default(),
            reply_quote_image: String::new(),
            preview_text,
            preview_image,
            reactions: String::new(),
            sender: match m.counterpart.rsplit_once('/') {
                Some((_, nick)) => nick.to_string(),
                None => String::new(),
            },
            sender_avatar: String::new(),
            day: local_day(&m.timestamp),
            audio_path,
            edited: m.edited_of.is_some(),
            retracted: m.retracted,
            webxdc_url: xdc_url.unwrap_or_default(),
            thread: m.thread.clone().unwrap_or_default(),
            file_mime: single.as_ref().map(|f| f.mime.clone()).unwrap_or_default(),
            file_save_name: single.as_ref().map(|f| f.name.clone()).unwrap_or_default(),
            file_url,
            file_name,
            attachments,
            stanza_id: m.stanza_id.clone().unwrap_or_default(),
        }
    }

    /// Build display rows, resolving each message's reply quote against the loaded page
    /// (XEP-0461 `reply_to` points at another message's stanza/origin id). `auto_download` is
    /// false for public groups (media renders as a typed download button, never auto-fetched).
    pub fn from_rows(rows: &[MessageRow], auto_download: bool) -> Vec<MessageItem> {
        let mut items: Vec<MessageItem> =
            rows.iter().map(|r| MessageItem::from_row(r, auto_download)).collect();
        // A quote shows the quoted message's preview: its text, or for a photo, voice message
        // or file an icon and label (plus the photo, if cached) - such messages have no text.
        let mut by_marker: HashMap<&str, usize> = HashMap::new();
        for (i, r) in rows.iter().enumerate() {
            if let Some(id) = r.stanza_id.as_deref() {
                by_marker.insert(id, i);
            }
            if let Some(id) = r.origin_id.as_deref() {
                by_marker.insert(id, i);
            }
        }
        let quotes: Vec<Option<(String, String)>> = rows
            .iter()
            .map(|r| {
                let target = *by_marker.get(r.reply_to.as_deref()?)?;
                Some((items[target].preview_text.clone(), items[target].preview_image.clone()))
            })
            .collect();
        for (item, quote) in items.iter_mut().zip(quotes) {
            if let Some((text, image)) = quote {
                item.reply_quote = text;
                item.reply_quote_image = image;
            }
        }
        items
    }
}

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!(<QtCore/QAbstractListModel>);
        type QAbstractListModel;

        include!("cxx-qt-lib/qhash.h");
        type QHash_i32_QByteArray = cxx_qt_lib::QHash<cxx_qt_lib::QHashPair_i32_QByteArray>;

        include!("cxx-qt-lib/qvariant.h");
        type QVariant = cxx_qt_lib::QVariant;

        include!("cxx-qt-lib/qmodelindex.h");
        type QModelIndex = cxx_qt_lib::QModelIndex;

        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;

        include!("cxx-qt-lib/qlist.h");
        type QList_i32 = cxx_qt_lib::QList<i32>;
    }

    extern "RustQt" {
        #[qobject]
        #[base = QAbstractListModel]
        #[qml_element]
        type MessageModel = super::MessageModelRust;

        /// Open a conversation and load its recent history.
        #[qinvokable]
        fn open(self: Pin<&mut MessageModel>, conversation_id: i64);

        /// Open `conversation_id`, loading just enough recent history to include
        /// `message_id`, then emit `jumpReady(marker)` so the view scrolls to it. Used by
        /// the chats-list message search to jump to an arbitrary (possibly old) message.
        #[qinvokable]
        #[cxx_name = "openAround"]
        fn open_around(
            self: Pin<&mut MessageModel>,
            conversation_id: i64,
            message_id: i64,
            marker: &QString,
        );

        /// Open (resolving/creating) the 1:1 chat for a contact's bare JID.
        #[qinvokable]
        #[cxx_name = "openPeer"]
        fn open_peer(self: Pin<&mut MessageModel>, jid: &QString);

        /// Open a conversation of a specific kind ("chat" or "muc_pm") for `jid`.
        #[qinvokable]
        #[cxx_name = "openPeerKind"]
        fn open_peer_kind(self: Pin<&mut MessageModel>, jid: &QString, kind: &QString);

        /// Load an older page (scroll-to-top); backfills from the server when local runs out.
        #[qinvokable]
        #[cxx_name = "loadOlder"]
        fn load_older(self: Pin<&mut MessageModel>);

        /// Persist the open conversation's encryption mode (header lock toggle).
        #[qinvokable]
        #[cxx_name = "setEncryption"]
        fn set_encryption(self: Pin<&mut MessageModel>, encrypted: bool);

        /// On a live `messageStored`, reload only if it's the open conversation.
        #[qinvokable]
        #[cxx_name = "noteStored"]
        fn note_stored(self: Pin<&mut MessageModel>, conversation_id: i64);

        /// Reload the currently-open conversation.
        #[qinvokable]
        #[cxx_name = "reloadCurrent"]
        fn reload_current(self: Pin<&mut MessageModel>);

        /// Download a file the user tapped in a public group (where media isn't auto-fetched):
        /// images/audio go into the media cache and re-render inline; other files save to the
        /// downloads folder and open with the system handler.
        #[qinvokable]
        #[cxx_name = "downloadAttachment"]
        fn download_attachment(self: Pin<&mut MessageModel>, url: &QString);

        /// Row index of the message with this marker, or -1 (for jump-to-quoted-message).
        #[qinvokable]
        #[cxx_name = "indexOfMarker"]
        fn index_of_marker(self: &MessageModel, marker: &QString) -> i32;

        /// Update one message's reaction tallies IN PLACE (no model reset → no scroll jump).
        #[qinvokable]
        #[cxx_name = "applyReactions"]
        fn apply_reactions(self: Pin<&mut MessageModel>, message_id: i64, reactions: &QString);

        /// XEP-0424: retract message `target_id` (our own) in the open conversation.
        #[qinvokable]
        fn retract(self: &MessageModel, to: &QString, target_id: &QString);

        /// XEP-0425: ask `room` to retract the message with room stanza-id `stanza_id` (we
        /// must be a moderator). An empty `reason` sends none.
        #[qinvokable]
        fn moderate(self: &MessageModel, room: &QString, stanza_id: &QString, reason: &QString);

        /// XEP-0308: replace message `target_id`'s body in the open conversation.
        #[qinvokable]
        fn correct(self: &MessageModel, to: &QString, target_id: &QString, new_body: &QString);
    }

    extern "RustQt" {
        #[qinvokable]
        #[cxx_override]
        fn data(self: &MessageModel, index: &QModelIndex, role: i32) -> QVariant;

        #[qinvokable]
        #[cxx_override]
        #[rust_name = "row_count"]
        fn rowCount(self: &MessageModel, parent: &QModelIndex) -> i32;

        #[qinvokable]
        #[cxx_override]
        #[rust_name = "role_names"]
        fn roleNames(self: &MessageModel) -> QHash_i32_QByteArray;
    }

    extern "RustQt" {
        /// Emitted once an `openAround` load finishes — `marker` is the message to scroll to.
        #[qsignal]
        #[cxx_name = "jumpReady"]
        fn jump_ready(self: Pin<&mut MessageModel>, marker: QString);

        /// One of our own messages (sent here or from another device) was added at the end of
        /// the open chat - the view scrolls to it, wherever it was scrolled to.
        #[qsignal]
        #[cxx_name = "ownMessageAppended"]
        fn own_message_appended(self: Pin<&mut MessageModel>);
    }

    unsafe extern "RustQt" {
        #[inherit]
        #[rust_name = "begin_reset_model"]
        fn beginResetModel(self: Pin<&mut MessageModel>);
        #[inherit]
        #[rust_name = "end_reset_model"]
        fn endResetModel(self: Pin<&mut MessageModel>);
        // For targeted single-row updates (reactions) without a full reset.
        #[inherit]
        fn index(self: &MessageModel, row: i32, column: i32, parent: &QModelIndex) -> QModelIndex;
        #[inherit]
        #[rust_name = "data_changed"]
        fn dataChanged(
            self: Pin<&mut MessageModel>,
            top_left: &QModelIndex,
            bottom_right: &QModelIndex,
            roles: &QList_i32,
        );
        // Row insertions/removals, so new and dropped messages don't reset the view.
        #[inherit]
        #[rust_name = "begin_insert_rows"]
        fn beginInsertRows(self: Pin<&mut MessageModel>, parent: &QModelIndex, first: i32, last: i32);
        #[inherit]
        #[rust_name = "end_insert_rows"]
        fn endInsertRows(self: Pin<&mut MessageModel>);
        #[inherit]
        #[rust_name = "begin_remove_rows"]
        fn beginRemoveRows(self: Pin<&mut MessageModel>, parent: &QModelIndex, first: i32, last: i32);
        #[inherit]
        #[rust_name = "end_remove_rows"]
        fn endRemoveRows(self: Pin<&mut MessageModel>);
    }

    impl cxx_qt::Threading for MessageModel {}
}

/// Backing data for the `MessageModel` QObject.
#[derive(Default)]
pub struct MessageModelRust {
    items: Vec<MessageItem>,
    conversation_id: i64,
    /// How many recent messages are currently loaded (grows as the user pages up).
    limit: i64,
}

impl MessageModelRust {
    /// How the sender described the file at `url` among the loaded messages: its kind (image,
    /// audio, file) and its name. None when no loaded message describes it.
    fn described_file(&self, url: &str) -> Option<(String, String)> {
        for item in &self.items {
            if item.file_url == url && !item.file_mime.is_empty() {
                let file = AttachmentFile {
                    url: url.to_string(),
                    name: item.file_save_name.clone(),
                    mime: item.file_mime.clone(),
                };
                return Some((file.kind().to_string(), item.file_save_name.clone()));
            }
            if item.attachments.is_empty() {
                continue;
            }
            let Ok(tiles) = serde_json::from_str::<Vec<serde_json::Value>>(&item.attachments) else {
                continue;
            };
            for tile in tiles {
                if tile.get("url").and_then(|u| u.as_str()) == Some(url) {
                    let text = |key: &str| {
                        tile.get(key).and_then(|v| v.as_str()).unwrap_or_default().to_string()
                    };
                    return Some((text("kind"), text("name")));
                }
            }
        }
        None
    }
}

impl qobject::MessageModel {
    pub fn open(mut self: Pin<&mut Self>, conversation_id: i64) {
        self.as_mut().rust_mut().conversation_id = conversation_id;
        self.as_mut().rust_mut().limit = INITIAL_LIMIT;
        crate::session::load_messages(conversation_id, INITIAL_LIMIT, self.qt_thread());
    }

    pub fn open_around(mut self: Pin<&mut Self>, conversation_id: i64, message_id: i64, marker: &QString) {
        self.as_mut().rust_mut().conversation_id = conversation_id;
        crate::session::load_messages_around(
            conversation_id,
            message_id,
            marker.to_string(),
            self.qt_thread(),
        );
    }

    pub fn reload_current(self: Pin<&mut Self>) {
        let cid = self.conversation_id;
        let limit = self.limit.max(INITIAL_LIMIT);
        if cid > 0 {
            crate::session::load_messages(cid, limit, self.qt_thread());
        }
    }

    pub fn download_attachment(self: Pin<&mut Self>, url: &QString) {
        let url = url.to_string();
        // What the sender described for this URL (a PQ OMEMO2 upload URL has no extension).
        let (kind, name) = self.rust().described_file(&url).unwrap_or_default();
        if image_url(&url).is_some() || audio_url(&url).is_some() || matches!(kind.as_str(), "image" | "audio") {
            // Media: fetch into the cache and reload so it renders inline in the bubble.
            crate::session::fetch_media(url, self.qt_thread());
        } else {
            // Other files: save to the downloads folder and open with the system handler.
            crate::session::download_file(url, name);
        }
    }

    /// Grow the window and load one more page of older messages.
    pub fn load_older(mut self: Pin<&mut Self>) {
        let cid = self.conversation_id;
        if cid <= 0 {
            return;
        }
        let new_limit = self.limit.max(INITIAL_LIMIT) + PAGE;
        self.as_mut().rust_mut().limit = new_limit;
        crate::session::load_older(cid, new_limit, self.qt_thread());
    }

    pub fn open_peer(self: Pin<&mut Self>, jid: &QString) {
        crate::session::open_peer(jid.to_string(), self.qt_thread());
    }

    pub fn open_peer_kind(self: Pin<&mut Self>, jid: &QString, kind: &QString) {
        crate::session::open_peer_kind(jid.to_string(), kind.to_string(), self.qt_thread());
    }

    pub fn set_encryption(self: Pin<&mut Self>, encrypted: bool) {
        let cid = self.conversation_id;
        if cid > 0 {
            crate::session::set_conversation_encryption(cid, encrypted);
        }
    }

    pub fn note_stored(self: Pin<&mut Self>, conversation_id: i64) {
        if self.conversation_id == conversation_id {
            self.reload_current();
        }
    }

    /// Update one message's reactions string in place + emit dataChanged for just that row, so
    /// the view repaints without a model reset (which would scroll the list to the bottom).
    pub fn apply_reactions(mut self: Pin<&mut Self>, message_id: i64, reactions: &QString) {
        let reactions = reactions.to_string();
        let Some(row) = self.items.iter().position(|i| i.id == message_id) else {
            return;
        };
        // Tombstones show no reactions, even if a peer reacts after the retraction.
        if self.items[row].retracted {
            return;
        }
        self.as_mut().rust_mut().items[row].reactions = reactions;
        let parent = QModelIndex::default();
        let idx = self.as_ref().index(row as i32, 0, &parent);
        self.as_mut().data_changed(&idx, &idx, &cxx_qt_lib::QList::<i32>::default());
    }

    /// Ask the peer(s) to delete one of our messages (XEP-0424); the core tombstones our copy
    /// and replies with `MessageRetracted`, which reloads this conversation.
    pub fn retract(&self, to: &QString, target_id: &QString) {
        if self.conversation_id > 0 {
            crate::session::retract_message(self.conversation_id, to.to_string(), target_id.to_string());
        }
    }

    /// Ask the room to moderate (XEP-0425) a message; the room's broadcast tombstones it for
    /// everyone and comes back as `MessageRetracted`, which reloads this conversation.
    pub fn moderate(&self, room: &QString, stanza_id: &QString, reason: &QString) {
        let stanza_id = stanza_id.to_string();
        if stanza_id.is_empty() {
            return;
        }
        let reason = reason.to_string().trim().to_string();
        crate::session::moderate_message(room.to_string(), stanza_id, Some(reason).filter(|r| !r.is_empty()));
    }

    /// Send a XEP-0308 correction for one of our messages; the core updates the stored row
    /// and replies with `MessageEdited`, which reloads this conversation.
    pub fn correct(&self, to: &QString, target_id: &QString, new_body: &QString) {
        if self.conversation_id > 0 {
            crate::session::correct_message(
                self.conversation_id,
                to.to_string(),
                target_id.to_string(),
                new_body.to_string(),
            );
        }
    }

    /// Set the open conversation id + window and replace its rows in one model reset (used
    /// by `open_peer`, where the id is resolved asynchronously).
    pub fn set_open(mut self: Pin<&mut Self>, conversation_id: i64, limit: i64, items: Vec<MessageItem>) {
        self.as_mut().rust_mut().conversation_id = conversation_id;
        self.as_mut().rust_mut().limit = limit;
        self.as_mut().begin_reset_model();
        self.as_mut().rust_mut().items = items;
        self.as_mut().end_reset_model();
    }

    /// Replace all rows (called from the core runtime via the Qt thread queue). The open chat
    /// reloads often (new and sent messages, delivery ticks, avatars, corrections, paging), and a
    /// full model reset throws the view to the top before it is scrolled back - the chat visibly
    /// jumped. So whenever the new rows are the old ones with messages dropped/added at either
    /// end (see [`align`]), they are applied as row removals/insertions plus `dataChanged` for
    /// the rows that changed; only anything else resets.
    pub fn reset(mut self: Pin<&mut Self>, items: Vec<MessageItem>) {
        let old_ids: Vec<i64> = self.items.iter().map(|i| i.id).collect();
        let new_ids: Vec<i64> = items.iter().map(|i| i.id).collect();
        let Some(a) = align(&old_ids, &new_ids) else {
            self.as_mut().begin_reset_model();
            self.as_mut().rust_mut().items = items;
            self.as_mut().end_reset_model();
            return;
        };
        let parent = QModelIndex::default();
        // 1. Drop old rows before and after the overlap.
        if a.old_start > 0 {
            self.as_mut().begin_remove_rows(&parent, 0, a.old_start as i32 - 1);
            self.as_mut().rust_mut().items.drain(..a.old_start);
            self.as_mut().end_remove_rows();
        }
        let len = self.items.len();
        if len > a.overlap {
            self.as_mut().begin_remove_rows(&parent, a.overlap as i32, len as i32 - 1);
            self.as_mut().rust_mut().items.truncate(a.overlap);
            self.as_mut().end_remove_rows();
        }
        // 2. Update the overlapping rows that changed (now at 0..overlap).
        let changed: Vec<usize> = (0..a.overlap)
            .filter(|&i| self.items[i] != items[a.new_start + i])
            .collect();
        for &i in &changed {
            self.as_mut().rust_mut().items[i] = items[a.new_start + i].clone();
        }
        for i in changed {
            let idx = self.as_ref().index(i as i32, 0, &parent);
            self.as_mut().data_changed(&idx, &idx, &cxx_qt_lib::QList::<i32>::default());
        }
        // 3. Insert new rows before (an older page) and after (new messages) the overlap.
        if a.new_start > 0 {
            self.as_mut().begin_insert_rows(&parent, 0, a.new_start as i32 - 1);
            let mut front = items[..a.new_start].to_vec();
            front.append(&mut self.as_mut().rust_mut().items);
            self.as_mut().rust_mut().items = front;
            self.as_mut().end_insert_rows();
        }
        let have = self.items.len();
        if items.len() > have {
            let own_appended = items[have..].iter().any(|m| m.outgoing);
            self.as_mut().begin_insert_rows(&parent, have as i32, items.len() as i32 - 1);
            self.as_mut().rust_mut().items.extend_from_slice(&items[have..]);
            self.as_mut().end_insert_rows();
            if own_appended {
                self.as_mut().own_message_appended();
            }
        }
    }

    fn data(&self, index: &QModelIndex, role: i32) -> QVariant {
        let Some(item) = self.items.get(index.row() as usize) else {
            return QVariant::default();
        };
        match role {
            ROLE_ID => QVariant::from(&item.id),
            ROLE_BODY => QVariant::from(&QString::from(item.body.as_str())),
            ROLE_OUTGOING => QVariant::from(&item.outgoing),
            ROLE_TIMESTAMP => QVariant::from(&QString::from(item.timestamp.as_str())),
            ROLE_ENCRYPTED => QVariant::from(&item.encrypted),
            ROLE_STATE => QVariant::from(&QString::from(item.state.as_str())),
            ROLE_MARKER => QVariant::from(&QString::from(item.marker.as_str())),
            ROLE_REPLY_QUOTE => QVariant::from(&QString::from(item.reply_quote.as_str())),
            ROLE_REPLY_TO => QVariant::from(&QString::from(item.reply_to.as_str())),
            ROLE_REACTIONS => QVariant::from(&QString::from(item.reactions.as_str())),
            ROLE_SENDER => QVariant::from(&QString::from(item.sender.as_str())),
            ROLE_IMAGE => QVariant::from(&QString::from(item.image_path.as_str())),
            ROLE_SENDER_AVATAR => QVariant::from(&QString::from(item.sender_avatar.as_str())),
            ROLE_DAY => QVariant::from(&QString::from(item.day.as_str())),
            ROLE_AUDIO => QVariant::from(&QString::from(item.audio_path.as_str())),
            ROLE_EDITED => QVariant::from(&item.edited),
            ROLE_RETRACTED => QVariant::from(&item.retracted),
            ROLE_WEBXDC => QVariant::from(&!item.webxdc_url.is_empty()),
            ROLE_XDC_THREAD => QVariant::from(&QString::from(item.thread.as_str())),
            ROLE_WEBXDC_URL => QVariant::from(&QString::from(item.webxdc_url.as_str())),
            ROLE_FILE_URL => QVariant::from(&QString::from(item.file_url.as_str())),
            ROLE_FILE_NAME => QVariant::from(&QString::from(item.file_name.as_str())),
            ROLE_ATTACHMENTS => QVariant::from(&QString::from(item.attachments.as_str())),
            ROLE_STANZA_ID => QVariant::from(&QString::from(item.stanza_id.as_str())),
            ROLE_BODY_HTML => QVariant::from(&QString::from(item.body_html.as_str())),
            ROLE_PREVIEW_TEXT => QVariant::from(&QString::from(item.preview_text.as_str())),
            ROLE_PREVIEW_IMAGE => QVariant::from(&QString::from(item.preview_image.as_str())),
            ROLE_REPLY_QUOTE_IMAGE => QVariant::from(&QString::from(item.reply_quote_image.as_str())),
            _ => QVariant::default(),
        }
    }

    fn row_count(&self, _parent: &QModelIndex) -> i32 {
        self.items.len() as i32
    }

    fn index_of_marker(&self, marker: &QString) -> i32 {
        let marker = marker.to_string();
        if marker.is_empty() {
            return -1;
        }
        self.items
            .iter()
            .position(|item| item.marker == marker)
            .map(|i| i as i32)
            .unwrap_or(-1)
    }

    fn role_names(&self) -> QHash<QHashPair_i32_QByteArray> {
        let mut roles = QHash::<QHashPair_i32_QByteArray>::default();
        roles.insert(ROLE_ID, QByteArray::from("messageId"));
        roles.insert(ROLE_BODY, QByteArray::from("body"));
        roles.insert(ROLE_OUTGOING, QByteArray::from("outgoing"));
        roles.insert(ROLE_TIMESTAMP, QByteArray::from("timestamp"));
        roles.insert(ROLE_ENCRYPTED, QByteArray::from("encrypted"));
        roles.insert(ROLE_STATE, QByteArray::from("state"));
        roles.insert(ROLE_MARKER, QByteArray::from("marker"));
        roles.insert(ROLE_REPLY_QUOTE, QByteArray::from("replyQuote"));
        roles.insert(ROLE_REPLY_TO, QByteArray::from("replyTo"));
        roles.insert(ROLE_REACTIONS, QByteArray::from("reactions"));
        roles.insert(ROLE_SENDER, QByteArray::from("sender"));
        roles.insert(ROLE_IMAGE, QByteArray::from("imagePath"));
        roles.insert(ROLE_SENDER_AVATAR, QByteArray::from("senderAvatar"));
        roles.insert(ROLE_DAY, QByteArray::from("day"));
        roles.insert(ROLE_AUDIO, QByteArray::from("audioPath"));
        roles.insert(ROLE_EDITED, QByteArray::from("edited"));
        roles.insert(ROLE_RETRACTED, QByteArray::from("retracted"));
        roles.insert(ROLE_WEBXDC, QByteArray::from("webxdc"));
        roles.insert(ROLE_XDC_THREAD, QByteArray::from("xdcThread"));
        roles.insert(ROLE_WEBXDC_URL, QByteArray::from("webxdcUrl"));
        roles.insert(ROLE_FILE_URL, QByteArray::from("fileUrl"));
        roles.insert(ROLE_FILE_NAME, QByteArray::from("fileName"));
        roles.insert(ROLE_ATTACHMENTS, QByteArray::from("attachments"));
        roles.insert(ROLE_STANZA_ID, QByteArray::from("stanzaId"));
        roles.insert(ROLE_BODY_HTML, QByteArray::from("bodyHtml"));
        roles.insert(ROLE_PREVIEW_TEXT, QByteArray::from("previewText"));
        roles.insert(ROLE_PREVIEW_IMAGE, QByteArray::from("previewImage"));
        roles.insert(ROLE_REPLY_QUOTE_IMAGE, QByteArray::from("replyQuoteImage"));
        roles
    }
}
