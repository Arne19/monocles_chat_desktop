//! Location previews for `geo:` messages, rendered on this machine from map tiles
//! ([`mxc_proto::map_tiles`]) and kept **in memory only** as `data:` URLs: unlike media
//! ([`crate::session::media_view`]) nothing is written to disk, where a stored map would show
//! where a contact shared their location. Same opt-in and tile-server choice as Android.

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

use cxx_qt::CxxQtThread;
use mxc_proto::map_tiles;

use crate::messages::qobject::MessageModel;

/// Setting: show map previews (flag, off by default: tiles reveal the area to the tile server).
pub const SETTING_SHOW_MAPS: &str = "show_maps_inside";
/// Setting: custom tile URL template; empty or invalid = OpenStreetMap.
pub const SETTING_TILE_SERVER_URL: &str = "map_tile_server_url";

/// Previews kept in memory (a few MB of JPEG at most).
const CACHE_ENTRIES: usize = 64;
/// After a failed render, no new attempt for this long (no request storm on every reload).
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(60);
/// A moving live share switches its map at most this often (as on Android): updates come every
/// few seconds, and each new map costs 4-9 tile requests.
const LIVE_REFRESH: Duration = Duration::from_secs(60);

struct Settings {
    enabled: bool,
    template: String,
}

static SETTINGS: LazyLock<RwLock<Settings>> = LazyLock::new(|| {
    RwLock::new(Settings { enabled: false, template: map_tiles::OSM_TEMPLATE.to_string() })
});

/// (latitude·10⁷, longitude·10⁷, template): one preview per place and tile server.
type Key = (i64, i64, String);

#[derive(Default)]
struct Cache {
    previews: HashMap<Key, String>,
    order: VecDeque<Key>,
}

static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(Cache::default()));
static REQUESTED: LazyLock<Mutex<HashSet<Key>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static FAILED: LazyLock<Mutex<HashMap<Key, Instant>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// A position on a live share's map, and since when it is shown.
type Shown = (f64, f64, Instant);

/// Per live share (by message id): the position its map currently shows.
static LIVE_SHOWN: LazyLock<Mutex<HashMap<i64, Shown>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Per live share: the last map it showed, kept on screen while the next one renders.
static LIVE_LAST_READY: LazyLock<Mutex<HashMap<i64, (String, String)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// What a message shows for its location.
#[derive(Debug, PartialEq)]
pub enum Preview {
    /// Not a location, or previews are off: the body renders as text.
    None,
    /// A location whose preview is being rendered (or failed): a "📍 Location" label.
    Pending,
    /// The rendered map (`data:` URL) and its credit line.
    Ready { data_url: String, attribution: String },
}

fn key(lat: f64, lon: f64, template: &str) -> Key {
    ((lat * 1e7).round() as i64, (lon * 1e7).round() as i64, template.to_string())
}

/// The preview state of a message `body` (only bodies that are exactly one `geo:` URI).
pub fn preview(body: &str) -> Preview {
    match map_tiles::parse_geo(body) {
        Some((lat, lon)) => preview_at(None, lat, lon),
        None => Preview::None,
    }
}

/// The preview state of a location at `lat`/`lon`. For a live share (`live` = its message id),
/// the previous map stays while the one for the new position renders.
pub fn preview_at(live: Option<i64>, lat: f64, lon: f64) -> Preview {
    let settings = SETTINGS.read().unwrap();
    if !settings.enabled {
        return Preview::None;
    }
    let attribution = map_tiles::attribution(&settings.template);
    let key = key(lat, lon, &settings.template);
    let cached = CACHE.lock().unwrap().previews.get(&key).cloned();
    match (cached, live) {
        (Some(data_url), Some(id)) => {
            LIVE_LAST_READY.lock().unwrap().insert(id, (data_url.clone(), attribution.clone()));
            Preview::Ready { data_url, attribution }
        }
        (Some(data_url), None) => Preview::Ready { data_url, attribution },
        (None, Some(id)) => match LIVE_LAST_READY.lock().unwrap().get(&id) {
            // the same tile server's map of a moment ago
            Some((data_url, shown_attribution)) if *shown_attribution == attribution => {
                Preview::Ready { data_url: data_url.clone(), attribution }
            }
            _ => Preview::Pending,
        },
        (None, None) => Preview::Pending,
    }
}

/// The position a live share's map shows for its newest position `lat`/`lon`: the newest one,
/// but switched at most every [`LIVE_REFRESH`].
pub fn displayed_point(message_id: i64, lat: f64, lon: f64) -> (f64, f64) {
    let mut shown = LIVE_SHOWN.lock().unwrap();
    match shown.get(&message_id) {
        Some(&(slat, slon, since)) if (slat, slon) == (lat, lon) || since.elapsed() < LIVE_REFRESH => (slat, slon),
        _ => {
            shown.insert(message_id, (lat, lon, Instant::now()));
            (lat, lon)
        }
    }
}

/// The position to show for `row`: a live share's (throttled) newest one, else its `geo:` body.
pub fn point_of(
    row: &mxc_store::MessageRow,
    live: &HashMap<i64, mxc_store::live_locations::LiveLocation>,
) -> Option<(f64, f64)> {
    match live.get(&row.id).and_then(|l| l.last) {
        Some((lat, lon)) => Some(displayed_point(row.id, lat, lon)),
        None => row.body.as_deref().and_then(map_tiles::parse_geo),
    }
}

/// Applies the stored settings (at startup).
pub async fn load(store: &mxc_store::Store) {
    let enabled = matches!(store.setting(SETTING_SHOW_MAPS).await.ok().flatten().as_deref(), Some("1"));
    let custom = store.setting(SETTING_TILE_SERVER_URL).await.ok().flatten();
    let mut settings = SETTINGS.write().unwrap();
    settings.enabled = enabled;
    settings.template = map_tiles::effective_template(custom.as_deref());
}

/// Whether previews are on, and the custom template as stored ("" for OpenStreetMap).
pub fn current() -> (bool, String) {
    let settings = SETTINGS.read().unwrap();
    let custom = if settings.template == map_tiles::OSM_TEMPLATE {
        String::new()
    } else {
        settings.template.clone()
    };
    (settings.enabled, custom)
}

pub fn set_enabled(enabled: bool) {
    SETTINGS.write().unwrap().enabled = enabled;
    if !enabled {
        // nothing of the previews stays around once they are switched off
        *CACHE.lock().unwrap() = Cache::default();
        LIVE_LAST_READY.lock().unwrap().clear();
    }
}

/// Sets the custom template ("" = OpenStreetMap); false if it is not valid.
pub fn set_template(input: &str) -> bool {
    let input = input.trim();
    if !input.is_empty() && !map_tiles::is_valid_template(input) {
        return false;
    }
    SETTINGS.write().unwrap().template = map_tiles::effective_template(Some(input));
    // previews of the old server are no longer shown; free them
    *CACHE.lock().unwrap() = Cache::default();
    LIVE_LAST_READY.lock().unwrap().clear();
    FAILED.lock().unwrap().clear();
    true
}

/// Renders the missing previews of `rows` (live shares at their shown position, see
/// [`point_of`]) in the background, then reloads the open conversation so [`preview_at`] finds
/// them.
pub fn prefetch(
    rows: &[mxc_store::MessageRow],
    live: &HashMap<i64, mxc_store::live_locations::LiveLocation>,
    qt: &CxxQtThread<MessageModel>,
) {
    let template = {
        let settings = SETTINGS.read().unwrap();
        if !settings.enabled {
            return;
        }
        settings.template.clone()
    };
    for row in rows {
        if row.retracted || row.moderated {
            continue;
        }
        // only bodies that are a location; a live share then shows its newest position
        if row.body.as_deref().and_then(map_tiles::parse_geo).is_none() {
            continue;
        }
        let Some((lat, lon)) = point_of(row, live) else { continue };
        let key = key(lat, lon, &template);
        if CACHE.lock().unwrap().previews.contains_key(&key) {
            continue;
        }
        if FAILED.lock().unwrap().get(&key).is_some_and(|t| t.elapsed() < RETRY_AFTER_FAILURE) {
            continue;
        }
        if !REQUESTED.lock().unwrap().insert(key.clone()) {
            continue; // already rendering
        }
        let qt = qt.clone();
        let template = template.clone();
        crate::session::runtime().spawn(async move {
            let rendered = map_tiles::render(lat, lon, &template).await.and_then(|image| encode(&image));
            REQUESTED.lock().unwrap().remove(&key);
            match rendered {
                Ok(data_url) => {
                    // switched off or to another server meanwhile: drop it
                    {
                        let settings = SETTINGS.read().unwrap();
                        if !settings.enabled || settings.template != template {
                            return;
                        }
                    }
                    insert(key, data_url);
                    let _ = qt.queue(|model: Pin<&mut MessageModel>| model.reload_current());
                }
                Err(e) => {
                    // no coordinates or URLs in the log
                    tracing::debug!(error = %e, "map preview failed");
                    FAILED.lock().unwrap().insert(key, Instant::now());
                }
            }
        });
    }
}

fn insert(key: Key, data_url: String) {
    let mut cache = CACHE.lock().unwrap();
    if cache.previews.insert(key.clone(), data_url).is_none() {
        cache.order.push_back(key);
    }
    while cache.order.len() > CACHE_ENTRIES {
        if let Some(old) = cache.order.pop_front() {
            cache.previews.remove(&old);
        }
    }
}

/// JPEG `data:` URL of a rendered map (much smaller than PNG for map imagery).
fn encode(map: &image::RgbaImage) -> anyhow::Result<String> {
    use base64::Engine;
    let rgb = image::DynamicImage::ImageRgba8(map.clone()).to_rgb8();
    let mut jpeg = Vec::with_capacity(96 * 1024);
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 85).encode_image(&rgb)?;
    Ok(format!("data:image/jpeg;base64,{}", base64::engine::general_purpose::STANDARD.encode(&jpeg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geo_row(body: &str) -> mxc_store::MessageRow {
        mxc_store::MessageRow {
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
            attachment: None,
            reply_to: None,
            omemo_fingerprint: None,
            timestamp: "2026-11-13T00:00:00Z".into(),
            thread: None,
            moderated: false,
            moderation_reason: None,
            unstyled: false,
        }
    }

    /// One test for all of it: the settings are process-wide.
    #[test]
    fn only_locations_with_previews_on_get_one() {
        use crate::messages::MessageItem;
        let body = "geo:52.52,13.405;u=10";
        // off by default: the text stays
        let item = MessageItem::from_row(&geo_row(body), true);
        assert_eq!((item.body.as_str(), item.geo_uri.as_str(), item.map_preview.as_str()), (body, "", ""));
        SETTINGS.write().unwrap().enabled = true;
        let item = MessageItem::from_row(&geo_row(body), true);
        assert_eq!(item.body, "📍 Location");
        assert_eq!(item.geo_uri, "geo:52.52,13.405");
        assert_eq!(item.preview_text, "📍 Location");
        // not a location: unchanged
        assert_eq!(MessageItem::from_row(&geo_row("geo:52.52,13.405 here"), true).geo_uri, "");
        insert(key(52.52, 13.405, map_tiles::OSM_TEMPLATE), "data:image/jpeg;base64,AA==".into());
        let item = MessageItem::from_row(&geo_row(body), true);
        assert_eq!(item.body, "");
        assert_eq!(item.map_preview, "data:image/jpeg;base64,AA==");
        assert_eq!(item.preview_image, "data:image/jpeg;base64,AA==");
        assert_eq!(item.map_attribution, "© OpenStreetMap");
        // a retracted location shows the tombstone, no map
        let mut gone = geo_row(body);
        gone.retracted = true;
        assert_eq!(MessageItem::from_row(&gone, true).map_preview, "");
        // a live share: active, its newest position (throttled), the old map while the new renders
        let mut share = mxc_store::live_locations::LiveLocation { expires: 2_000, last: None, stopped: false };
        let mut live = HashMap::new();
        let row = geo_row(body);
        live.insert(row.id, share.clone());
        let mut item = MessageItem::from_row(&row, true);
        item.apply_live_location(&row, &share, &live, 1_000);
        assert_eq!((item.live_state.as_str(), item.live_expires_ms), ("active", 2_000_000));
        assert_eq!(item.map_preview, "data:image/jpeg;base64,AA==", "start position, cached");
        share.last = Some((48.1, 11.5));
        live.insert(row.id, share.clone());
        let mut item = MessageItem::from_row(&row, true);
        item.apply_live_location(&row, &share, &live, 1_000);
        assert_eq!(item.geo_uri, "geo:48.1,11.5");
        assert_eq!(item.map_preview, "data:image/jpeg;base64,AA==", "previous map until the new one is ready");
        assert_eq!(item.preview_text, "📍 Live location");
        // within a minute the shown position stays
        assert_eq!(displayed_point(row.id, 40.0, 10.0), (48.1, 11.5));
        // ended (stopped or expired)
        share.stopped = true;
        let mut item = MessageItem::from_row(&row, true);
        item.apply_live_location(&row, &share, &live, 1_000);
        assert_eq!((item.live_state.as_str(), item.live_expires_ms), ("ended", 0));
        *CACHE.lock().unwrap() = Cache::default();
        LIVE_LAST_READY.lock().unwrap().clear();
        let mut item = MessageItem::from_row(&row, true);
        item.apply_live_location(&row, &share, &live, 3_000);
        assert_eq!(item.body, "📍 Live location ended");
        SETTINGS.write().unwrap().enabled = false;
        // previews off: the text stays, the state is still known
        let mut item = MessageItem::from_row(&row, true);
        item.apply_live_location(&row, &share, &live, 1_000);
        assert_eq!((item.body.as_str(), item.live_state.as_str()), (body, "ended"));

        // off by default
        assert_eq!(preview("geo:52.52,13.405"), Preview::None);
        SETTINGS.write().unwrap().enabled = true;
        assert_eq!(preview("hello"), Preview::None);
        assert_eq!(preview("geo:52.52,13.405"), Preview::Pending);
        insert(key(52.52, 13.405, map_tiles::OSM_TEMPLATE), "data:image/jpeg;base64,AA==".into());
        assert_eq!(
            preview("geo:52.52,13.405"),
            Preview::Ready {
                data_url: "data:image/jpeg;base64,AA==".into(),
                attribution: "© OpenStreetMap".into()
            }
        );
        // a new server: previews of the old one are gone, invalid templates refused
        assert!(!set_template("http://x.example/{z}/{x}/{y}.png"));
        assert!(set_template("https://t.example/{z}/{x}/{y}.png"));
        assert_eq!(preview("geo:52.52,13.405"), Preview::Pending);
        assert_eq!(current(), (true, "https://t.example/{z}/{x}/{y}.png".to_string()));
        assert!(set_template(""));
        set_enabled(false);
        assert_eq!(preview("geo:52.52,13.405"), Preview::None);
        assert_eq!(current(), (false, String::new()));
    }

    #[test]
    fn encodes_a_jpeg_data_url() {
        let url = encode(&image::RgbaImage::from_pixel(8, 8, image::Rgba([1, 2, 3, 255]))).unwrap();
        assert!(url.starts_with("data:image/jpeg;base64,/9j/"));
    }
}
