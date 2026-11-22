//! Location previews rendered on this machine from map tiles, as on Android
//! (`MapPreview`/`MapPreviewLoader`/`MapTiles`): no static-map server is involved. The z15 tiles
//! around a shared `geo:` location are fetched from the chosen tile server (OpenStreetMap or a
//! user-set XYZ URL template) and stitched into one 512×512 image, in memory only: a stored map
//! would show on disk where a contact shared their location. The pin and the credit line are
//! drawn by the UI on top.
//!
//! Like everywhere in this client, `.onion`/`.i2p` hosts are refused (no Tor/I2P here, and such
//! names must never reach a DNS server), and redirects stay on https.

use std::sync::OnceLock;

/// Zoom level of the preview (about 1.2 km per tile).
pub const ZOOM: u32 = 15;
/// Edge length of one tile cell, in pixels.
pub const TILE_SIZE: u32 = 256;
/// Edge length of the rendered preview, in pixels.
pub const SIZE: u32 = 512;
/// The default tile server.
pub const OSM_TEMPLATE: &str = "https://tile.openstreetmap.org/{z}/{x}/{y}.png";

/// Web Mercator is undefined beyond this latitude; tile servers have no tiles there.
const MAX_LATITUDE: f64 = 85.051_128_78;
const MAX_TEMPLATE_LENGTH: usize = 2048;
/// A PNG tile is ~10–60 KB (@2x a few times that); anything much bigger is not a tile.
const MAX_TILE_BYTES: usize = 1024 * 1024;
/// Background of cells without a tile (beyond the poles, or a 404 from a partial server).
const BLANK: image::Rgba<u8> = image::Rgba([0xe0, 0xe0, 0xe0, 0xff]);

// ---- geo: URIs ----

/// The coordinates of a message body that is exactly one `geo:` URI (RFC 5870, the same grammar
/// Android's `GeoHelper.GEO_URI` accepts), or `None`.
pub fn parse_geo(body: &str) -> Option<(f64, f64)> {
    let s = body.trim();
    let rest = strip_prefix_ignore_case(s, "geo:")?;
    let (lat, rest) = take_number(rest, true)?;
    let rest = rest.strip_prefix(',')?;
    let (lon, mut rest) = take_number(rest, true)?;
    // optional altitude
    if let Some(r) = rest.strip_prefix(',') {
        rest = take_number(r, true)?.1;
    }
    // ;crs=…, ;u=…, then any ;key=value parameters, in that order (as the Android regex)
    if let Some(r) = strip_prefix_ignore_case(rest, ";crs=") {
        rest = take_while1(r, |c| c.is_ascii_alphanumeric() || c == '_' || c == '-')?;
    }
    if let Some(r) = strip_prefix_ignore_case(rest, ";u=") {
        rest = take_number(r, false)?.1;
    }
    while let Some(r) = rest.strip_prefix(';') {
        let r = take_while1(r, |c| c.is_ascii_alphanumeric() || c == '_' || c == '-')?;
        let r = r.strip_prefix('=')?;
        rest = take_param_value(r)?;
    }
    if let Some(r) = strip_prefix_ignore_case(rest, "?z=") {
        rest = take_while1(r, |c| c.is_ascii_digit())?;
    }
    if !rest.is_empty() {
        return None;
    }
    let lat: f64 = lat.parse().ok()?;
    let lon: f64 = lon.parse().ok()?;
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)).then_some((lat, lon))
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

/// `-?\d+(\.\d+)?` (sign only if `signed`): the number and the rest.
fn take_number(s: &str, signed: bool) -> Option<(&str, &str)> {
    let mut end = 0;
    let bytes = s.as_bytes();
    if signed && bytes.first() == Some(&b'-') {
        end = 1;
    }
    let digits = bytes[end..].iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    end += digits;
    if bytes.get(end) == Some(&b'.') {
        let fraction = bytes[end + 1..].iter().take_while(|b| b.is_ascii_digit()).count();
        if fraction == 0 {
            return None;
        }
        end += 1 + fraction;
    }
    Some((&s[..end], &s[end..]))
}

fn take_while1(s: &str, accept: impl Fn(char) -> bool) -> Option<&str> {
    let end = s.find(|c: char| !accept(c)).unwrap_or(s.len());
    (end > 0).then(|| &s[end..])
}

/// A parameter value: unreserved characters or `%XX` escapes, at least one.
fn take_param_value(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            i += 1;
        } else if b == b'%'
            && bytes.get(i + 1).is_some_and(|c| c.is_ascii_hexdigit())
            && bytes.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit())
        {
            i += 3;
        } else {
            break;
        }
    }
    (i > 0).then(|| &s[i..])
}

// ---- tile math ----

/// Global pixel coordinates of `lat`/`lon` at `zoom` (Web Mercator, 256 px tiles).
pub fn to_pixel(lat: f64, lon: f64, zoom: u32) -> (f64, f64) {
    let world = f64::from(TILE_SIZE) * f64::from(1u32 << zoom);
    let lat = lat.clamp(-MAX_LATITUDE, MAX_LATITUDE);
    let x = (lon + 180.0) / 360.0 * world;
    let sin = lat.to_radians().sin();
    let y = (0.5 - ((1.0 + sin) / (1.0 - sin)).ln() / (4.0 * std::f64::consts::PI)) * world;
    (x, y)
}

/// Tile column `x` wrapped around the antimeridian.
pub fn wrap_x(x: i64, zoom: u32) -> u32 {
    let n = 1i64 << zoom;
    x.rem_euclid(n) as u32
}

/// Whether tile row `y` exists at `zoom` (no wrapping north/south).
pub fn valid_y(y: i64, zoom: u32) -> bool {
    (0..(1i64 << zoom)).contains(&y)
}

// ---- tile server ----

/// The URL of one tile. Only integers are inserted into the template.
pub fn tile_url(template: &str, zoom: u32, x: u32, y: u32) -> String {
    template
        .replace("{z}", &zoom.to_string())
        .replace("{x}", &x.to_string())
        .replace("{y}", &y.to_string())
}

/// Whether `input` is an acceptable custom tile URL template: https, exactly one each of `{z}`,
/// `{x}`, `{y}`, no other braces, no credentials, no whitespace, placeholders not in the host or
/// port, and no `.onion`/`.i2p` host (this client can't reach them).
pub fn is_valid_template(input: &str) -> bool {
    let template = input.trim();
    if template.is_empty() || template.len() > MAX_TEMPLATE_LENGTH {
        return false;
    }
    if template.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    for placeholder in ["{z}", "{x}", "{y}"] {
        if template.matches(placeholder).count() != 1 {
            return false;
        }
    }
    let rest = template.replace("{z}", "").replace("{x}", "").replace("{y}", "");
    if rest.contains('{') || rest.contains('}') {
        return false;
    }
    let (Ok(url), Ok(other)) = (
        url::Url::parse(&tile_url(template, 0, 0, 0)),
        url::Url::parse(&tile_url(template, 1, 1, 1)),
    ) else {
        return false;
    };
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    // the tile coordinates must not pick the server (one server, not one per tile)
    if url.host() != other.host() || url.port() != other.port() {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(host)) => !crate::hidden::is_hidden_service_host(host),
        Some(_) => true,
        None => false,
    }
}

/// The template in effect for a stored setting value: the custom one if valid, else OSM.
pub fn effective_template(setting: Option<&str>) -> String {
    match setting.map(str::trim) {
        Some(custom) if is_valid_template(custom) => custom.to_string(),
        _ => OSM_TEMPLATE.to_string(),
    }
}

/// The credit line to show on a map from `template`: OSM's for OSM, else the tile host (the data
/// is not necessarily OSM's).
pub fn attribution(template: &str) -> String {
    if template == OSM_TEMPLATE {
        return "© OpenStreetMap".to_string();
    }
    let host = url::Url::parse(&tile_url(template, 0, 0, 0))
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string());
    format!("Map: {host}")
}

// ---- rendering ----

/// The client for tile downloads: the system's roots, bounded timeouts, and redirects that stay
/// on https and never go to a hidden-service name. The server is the user's choice, so a
/// self-hosted tile server on the LAN is allowed (unlike sender-chosen file URLs).
fn tile_client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        let builder = reqwest::Client::builder();
        let builder = match crate::tls_roots::http_roots() {
            Some(roots) => builder.tls_certs_only(roots),
            None => builder,
        };
        builder
            // tile servers' usage policies (OSM's among them) require an identifying user agent
            .user_agent(concat!("monocles-chat-desktop/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(20))
            .read_timeout(std::time::Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let hidden = matches!(
                    attempt.url().host(),
                    Some(url::Host::Domain(h)) if crate::hidden::is_hidden_service_host(h)
                );
                if attempt.previous().len() >= 5 {
                    attempt.error("too many redirects")
                } else if attempt.url().scheme() != "https" || hidden {
                    // http would send the tile coordinates (the location) in cleartext
                    attempt.error("refusing redirect to a non-https or hidden-service address")
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .expect("reqwest client")
    })
}

/// Fetches one tile; `Ok(None)` for a 404 (servers with partial coverage).
async fn fetch_tile(url: String) -> anyhow::Result<Option<image::RgbaImage>> {
    let mut response = tile_client().get(&url).send().await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        anyhow::bail!("tile server returned {}", response.status().as_u16());
    }
    if response.content_length().is_some_and(|n| n > MAX_TILE_BYTES as u64) {
        anyhow::bail!("tile too large");
    }
    let mut bytes = Vec::with_capacity(64 * 1024);
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_TILE_BYTES {
            anyhow::bail!("tile too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Some(decode_tile(&bytes)?))
}

/// Decodes a tile from untrusted bytes: only square 256 or 512 px images (512 = @2x, scaled
/// into the 256 px cell); the size is checked before the pixels are decoded.
fn decode_tile(bytes: &[u8]) -> anyhow::Result<image::RgbaImage> {
    let reader = image::ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format()?;
    let format = reader.format().ok_or_else(|| anyhow::anyhow!("unknown tile format"))?;
    if !matches!(format, image::ImageFormat::Png | image::ImageFormat::Jpeg | image::ImageFormat::WebP) {
        anyhow::bail!("unexpected tile format");
    }
    let (w, h) = reader.into_dimensions()?;
    if w != h || (w != TILE_SIZE && w != 2 * TILE_SIZE) {
        anyhow::bail!("unexpected tile dimensions");
    }
    let tile = image::load_from_memory_with_format(bytes, format)?.to_rgba8();
    Ok(if tile.width() == TILE_SIZE {
        tile
    } else {
        image::imageops::resize(&tile, TILE_SIZE, TILE_SIZE, image::imageops::FilterType::Triangle)
    })
}

/// One cell of the preview window: its column and row, and the tile `(x, y)` it shows (none
/// for rows beyond the poles).
type Cell = (u32, u32, Option<(u32, u32)>);

/// The cells of the preview window, plus the offset of the window inside the first cell.
fn layout(lat: f64, lon: f64) -> (Vec<Cell>, (i64, i64)) {
    let (cx, cy) = to_pixel(lat, lon, ZOOM);
    let half = i64::from(SIZE / 2);
    let left = cx.floor() as i64 - half;
    let top = cy.floor() as i64 - half;
    let tile = i64::from(TILE_SIZE);
    let (first_x, first_y) = (left.div_euclid(tile), top.div_euclid(tile));
    let last_x = (left + i64::from(SIZE) - 1).div_euclid(tile);
    let last_y = (top + i64::from(SIZE) - 1).div_euclid(tile);
    let mut cells = Vec::new();
    for (row, y) in (first_y..=last_y).enumerate() {
        for (column, x) in (first_x..=last_x).enumerate() {
            let source = valid_y(y, ZOOM).then(|| (wrap_x(x, ZOOM), y as u32));
            cells.push((column as u32, row as u32, source));
        }
    }
    (cells, (left - first_x * tile, top - first_y * tile))
}

/// Renders the map around `lat`/`lon` from `template` (validated by the caller, see
/// [`effective_template`]): 512×512 px with the location at the centre pixel. Fails if any tile
/// but a 404 fails.
pub async fn render(lat: f64, lon: f64, template: &str) -> anyhow::Result<image::RgbaImage> {
    let (cells, (offset_x, offset_y)) = layout(lat, lon);
    let fetches = cells.iter().map(|&(_, _, source)| {
        let url = source.map(|(x, y)| tile_url(template, ZOOM, x, y));
        async move {
            match url {
                Some(url) => fetch_tile(url).await,
                None => Ok(None),
            }
        }
    });
    let tiles = futures::future::join_all(fetches).await;
    let mut canvas = image::RgbaImage::from_pixel(SIZE, SIZE, BLANK);
    for (&(column, row, _), tile) in cells.iter().zip(tiles) {
        let Some(tile) = tile? else { continue };
        let x = i64::from(column * TILE_SIZE) - offset_x;
        let y = i64::from(row * TILE_SIZE) - offset_y;
        image::imageops::overlay(&mut canvas, &tile, x, y);
    }
    Ok(canvas)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORLD: f64 = TILE_SIZE as f64 * (1u32 << ZOOM) as f64;

    #[test]
    fn known_point_maps_to_known_tile() {
        // Berlin, slippy-map reference: z15 tile 17604/10746 (same values as Android's test)
        let (x, y) = to_pixel(52.52, 13.405, ZOOM);
        assert_eq!((x / 256.0) as u32, 17604);
        assert_eq!((y / 256.0) as u32, 10746);
        assert!((x - 17604.152_888_888_89 * 256.0).abs() < 1e-3);
        assert!((y - 10746.434_709_360_34 * 256.0).abs() < 1e-3);
    }

    #[test]
    fn origin_is_world_centre_and_poles_clamp() {
        let (x, y) = to_pixel(0.0, 0.0, ZOOM);
        assert!((x - WORLD / 2.0).abs() < 1e-6 && (y - WORLD / 2.0).abs() < 1e-6);
        assert!(to_pixel(90.0, 0.0, ZOOM).1.abs() < 1e-3);
        assert!((to_pixel(-90.0, 0.0, ZOOM).1 - WORLD).abs() < 1e-3);
        assert!(to_pixel(0.0, -180.0, ZOOM).0.abs() < 1e-6);
        assert!((to_pixel(0.0, 180.0, ZOOM).0 - WORLD).abs() < 1e-6);
    }

    #[test]
    fn tiles_wrap_east_west_but_not_north_south() {
        let n = 1i64 << ZOOM;
        assert_eq!(wrap_x(-1, ZOOM), (n - 1) as u32);
        assert_eq!(wrap_x(n, ZOOM), 0);
        assert_eq!(wrap_x(5, ZOOM), 5);
        assert!(!valid_y(-1, ZOOM) && !valid_y(n, ZOOM) && valid_y(0, ZOOM));
    }

    #[test]
    fn layout_centres_the_location() {
        let (cells, (ox, oy)) = layout(52.52, 13.405);
        assert!((4..=9).contains(&cells.len()));
        // the centre pixel of the canvas is the location's pixel
        let (cx, cy) = to_pixel(52.52, 13.405, ZOOM);
        let (first_col_x, first_row_y) = (cells[0].2.unwrap().0 as i64, cells[0].2.unwrap().1 as i64);
        assert_eq!(first_col_x * 256 + ox + 256, cx.floor() as i64);
        assert_eq!(first_row_y * 256 + oy + 256, cy.floor() as i64);
        // near the north pole the top rows have no tile
        let (polar, _) = layout(89.0, 0.0);
        assert!(polar.iter().any(|c| c.2.is_none()));
    }

    #[test]
    fn accepts_xyz_templates() {
        assert!(is_valid_template(OSM_TEMPLATE));
        assert!(is_valid_template("https://a.example/{z}/{x}/{y}.png"));
        assert!(is_valid_template("https://a.example/t?z={z}&x={x}&y={y}&key=K"));
        assert!(is_valid_template("  https://a.example/{z}/{x}/{y}@2x.png "));
        assert!(is_valid_template("https://192.168.1.5:8080/{z}/{x}/{y}.png"));
    }

    #[test]
    fn rejects_bad_templates() {
        for bad in [
            "",
            "garbage",
            "http://a.example/{z}/{x}/{y}.png",
            "ftp://a.example/{z}/{x}/{y}.png",
            "https://a.example/{z}/{x}.png",
            "https://a.example/{z}/{x}/{y}/{y}.png",
            "https://{s}.a.example/{z}/{x}/{y}.png",
            "https://u:p@a.example/{z}/{x}/{y}.png",
            "https://a.example/{z}/{x} /{y}.png",
            "https://{z}{x}{y}.example/a.png",
            "https://a.example:{z}/{x}/{y}.png",
            // no Tor/I2P in this client
            "https://abcdef.onion/{z}/{x}/{y}.png",
            "http://abcdef.onion/{z}/{x}/{y}.png",
            "https://tiles.i2p/{z}/{x}/{y}.png",
        ] {
            assert!(!is_valid_template(bad), "{bad}");
        }
    }

    #[test]
    fn effective_template_falls_back_to_osm() {
        assert_eq!(effective_template(None), OSM_TEMPLATE);
        assert_eq!(effective_template(Some("")), OSM_TEMPLATE);
        assert_eq!(effective_template(Some("http://x/{z}/{x}/{y}")), OSM_TEMPLATE);
        assert_eq!(
            effective_template(Some(" https://a.example/{z}/{x}/{y}.png ")),
            "https://a.example/{z}/{x}/{y}.png"
        );
    }

    #[test]
    fn builds_urls_and_attribution() {
        assert_eq!(
            tile_url(OSM_TEMPLATE, 15, 17604, 10746),
            "https://tile.openstreetmap.org/15/17604/10746.png"
        );
        assert_eq!(attribution(OSM_TEMPLATE), "© OpenStreetMap");
        assert_eq!(attribution("https://tiles.example.org/{z}/{x}/{y}.png"), "Map: tiles.example.org");
    }

    #[test]
    fn parses_geo_uris() {
        assert_eq!(parse_geo("geo:52.52,13.405"), Some((52.52, 13.405)));
        assert_eq!(parse_geo("  GEO:-33.9,18.4  "), Some((-33.9, 18.4)));
        assert_eq!(parse_geo("geo:1,2,30.5;crs=wgs84;u=12.5"), Some((1.0, 2.0)));
        assert_eq!(parse_geo("geo:1,2;u=35;name=Caf%C3%A9_(old)"), Some((1.0, 2.0)));
        assert_eq!(parse_geo("geo:1,2?z=15"), Some((1.0, 2.0)));
        for bad in [
            "geo:",
            "geo:1",
            "geo:1,",
            "geo:91,0",
            "geo:0,181",
            "geo:1.,2",
            "geo:1,2 see you there",
            "meet me at geo:1,2",
            "geo:1,2;u=",
            "geo:1,2;x=%zz",
            "geo:1,2?q=cafe",
        ] {
            assert_eq!(parse_geo(bad), None, "{bad}");
        }
    }

    /// Against the real OpenStreetMap tile server: `cargo test -p mxc-proto map_tiles -- --ignored`.
    #[tokio::test]
    #[ignore = "network"]
    async fn renders_from_openstreetmap() {
        let map = render(52.52, 13.405, OSM_TEMPLATE).await.unwrap();
        assert_eq!(map.dimensions(), (SIZE, SIZE));
        // real map content, not just the blank background
        assert!(map.pixels().any(|p| *p != BLANK));
    }

    #[test]
    fn decode_rejects_non_tiles() {
        let mut png = Vec::new();
        image::RgbaImage::new(100, 100)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert!(decode_tile(&png).is_err());
        let mut tile = Vec::new();
        image::RgbaImage::new(512, 512)
            .write_to(&mut std::io::Cursor::new(&mut tile), image::ImageFormat::Png)
            .unwrap();
        assert_eq!(decode_tile(&tile).unwrap().dimensions(), (256, 256));
        assert!(decode_tile(b"not an image").is_err());
    }
}
