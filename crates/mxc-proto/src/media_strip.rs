//! Metadata-free copies of media published to Stories and Feeds, ported from monocles chat
//! for Android's `MediaMetadataStripper`.
//!
//! Story and post media is uploaded unencrypted and readable by every contact, so no
//! identifying metadata may leave the machine: GPS position, device, owner, capture time,
//! embedded thumbnails/previews, XMP/IPTC, appended trailers. Nothing is re-encoded:
//!
//! - JPEG: drops every APPn/COM segment except JFIF (without thumbnail), the ICC profile and
//!   the Adobe color transform marker, and anything after EOI (motion-photo videos, vendor
//!   trailers). The EXIF orientation is carried over in a minimal EXIF block.
//! - PNG: keeps only rendering-relevant chunks (no tEXt/zTXt/iTXt/eXIf/tIME…).
//! - WebP: drops the EXIF and XMP chunks.
//! - GIF: drops comments and application extensions other than the loop control.
//! - MP4/MOV/3GP: `udta`/`meta`/XMP `uuid` boxes and non-audio/video tracks are overwritten
//!   with `free` boxes of the same size (so every sample offset stays valid), the samples of
//!   those tracks are zeroed, and the creation/modification times are cleared. (Android
//!   remuxes instead; there is no platform muxer here.)
//! - WebM/Matroska: `Tags`, `Attachments` and the identifying `Info` children are overwritten
//!   with `Void` elements of the same size.
//!
//! Anything else that is an image or video is refused rather than published as-is.

use anyhow::{bail, ensure, Context};

/// Larger inputs are refused (as on Android for images; videos are read whole here too).
const MAX_SIZE: usize = 512 * 1024 * 1024;

/// Whether `mime` is a type [`strip`] can clean.
pub fn can_strip(mime: &str) -> bool {
    matches!(
        mime,
        "image/jpeg"
            | "image/png"
            | "image/webp"
            | "image/gif"
            | "video/mp4"
            | "video/quicktime"
            | "video/3gpp"
            | "video/webm"
            | "video/x-matroska"
    )
}

/// The media type of `data` from its magic bytes, for the formats handled here.
pub fn sniff(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if data.starts_with(PNG_SIGNATURE) {
        Some("image/png")
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Some("image/webp")
    } else if data.len() >= 12 && &data[4..8] == b"ftyp" {
        Some(match &data[8..12] {
            b"qt  " => "video/quicktime",
            b if b.starts_with(b"3g") => "video/3gpp",
            _ => "video/mp4",
        })
    } else if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        // EBML DocType "webm" sits in the header; anything else is plain Matroska.
        let head = &data[..data.len().min(64)];
        Some(if head.windows(4).any(|w| w == b"webm") { "video/webm" } else { "video/x-matroska" })
    } else {
        None
    }
}

/// Prepares a file for a public broadcast (Story / feed post): returns the bytes to upload and
/// their type. Images and videos are stripped of metadata, or refused if that isn't possible;
/// other files go out as they are. The type comes from the content where it can be recognised,
/// else from `fallback_mime` (the file name's).
pub fn prepare_for_broadcast(data: Vec<u8>, fallback_mime: &str) -> anyhow::Result<(Vec<u8>, String)> {
    let mime = sniff(&data).unwrap_or(fallback_mime);
    if can_strip(mime) {
        let stripped = strip(&data, mime)
            .context("Could not remove location and device data from this file. It was not published")?;
        Ok((stripped, mime.to_string()))
    } else if mime.starts_with("image/") || mime.starts_with("video/") {
        // A media format we can't clean; it may carry location or device data.
        bail!("Can't remove location and device data from {mime} files. It was not published")
    } else {
        Ok((data, mime.to_string()))
    }
}

/// A metadata-free copy of `data` (of type `mime`). Errors if it can't be parsed — the caller
/// must then not publish the file.
pub fn strip(data: &[u8], mime: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(data.len() <= MAX_SIZE, "file too large to strip");
    match mime {
        "image/jpeg" => strip_jpeg(data, read_orientation(data)),
        "image/png" => strip_png(data),
        "image/webp" => strip_webp(data),
        "image/gif" => strip_gif(data),
        "video/mp4" | "video/quicktime" | "video/3gpp" => strip_mp4(data),
        "video/webm" | "video/x-matroska" => strip_matroska(data),
        _ => bail!("unsupported type {mime}"),
    }
}

/// Bytes, or an error if `data[from..from + len]` is out of range.
fn slice(data: &[u8], from: usize, len: usize) -> anyhow::Result<&[u8]> {
    data.get(from..from.checked_add(len).context("overflow")?).context("truncated file")
}

fn u16_be(d: &[u8], p: usize) -> anyhow::Result<u16> {
    Ok(u16::from_be_bytes(slice(d, p, 2)?.try_into()?))
}

fn u32_be(d: &[u8], p: usize) -> anyhow::Result<u32> {
    Ok(u32::from_be_bytes(slice(d, p, 4)?.try_into()?))
}

fn u64_be(d: &[u8], p: usize) -> anyhow::Result<u64> {
    Ok(u64::from_be_bytes(slice(d, p, 8)?.try_into()?))
}

fn u32_le(d: &[u8], p: usize) -> anyhow::Result<u32> {
    Ok(u32::from_le_bytes(slice(d, p, 4)?.try_into()?))
}

// ------------------------------------------------------------------------------------- JPEG

/// The EXIF orientation (1–8), or 1 if there is none.
fn read_orientation(jpeg: &[u8]) -> u16 {
    fn find(jpeg: &[u8]) -> anyhow::Result<u16> {
        let mut pos = 2;
        while pos + 4 <= jpeg.len() && jpeg[pos] == 0xFF {
            let marker = jpeg[pos + 1];
            if marker == 0xDA || marker == 0xD9 {
                break;
            }
            let len = u16_be(jpeg, pos + 2)? as usize;
            let payload = slice(jpeg, pos + 4, len.saturating_sub(2))?;
            if marker == 0xE1 && payload.starts_with(b"Exif\0\0") {
                return tiff_orientation(&payload[6..]);
            }
            pos += 2 + len;
        }
        Ok(1)
    }
    find(jpeg).unwrap_or(1)
}

fn tiff_orientation(tiff: &[u8]) -> anyhow::Result<u16> {
    let le = match slice(tiff, 0, 2)? {
        b"II" => true,
        b"MM" => false,
        _ => bail!("bad TIFF header"),
    };
    let r16 = |p: usize| -> anyhow::Result<u16> {
        let b: [u8; 2] = slice(tiff, p, 2)?.try_into()?;
        Ok(if le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) })
    };
    let r32 = |p: usize| -> anyhow::Result<u32> {
        let b: [u8; 4] = slice(tiff, p, 4)?.try_into()?;
        Ok(if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
    };
    let ifd = r32(4)? as usize;
    let entries = r16(ifd)? as usize;
    for i in 0..entries {
        let e = ifd + 2 + i * 12;
        // Orientation, type SHORT: the value sits in the first two bytes of the value field.
        if r16(e)? == 0x0112 && r16(e + 2)? == 3 {
            return r16(e + 8);
        }
    }
    Ok(1)
}

fn strip_jpeg(input: &[u8], orientation: u16) -> anyhow::Result<Vec<u8>> {
    ensure!(input.len() >= 4 && input[0] == 0xFF && input[1] == 0xD8, "not a JPEG");
    let write_orientation = (2..=8).contains(&orientation);
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&[0xFF, 0xD8]);
    if write_orientation {
        // An APP1 EXIF block holding nothing but IFD0 with the orientation tag.
        out.extend_from_slice(&[
            0xFF, 0xE1, 0x00, 0x22, b'E', b'x', b'i', b'f', 0, 0, b'M', b'M', 0x00, 0x2A, 0, 0, 0,
            0x08, 0x00, 0x01, 0x01, 0x12, 0x00, 0x03, 0, 0, 0, 0x01, 0x00, orientation as u8, 0,
            0, 0, 0, 0, 0,
        ]);
    }
    let mut pos = 2;
    loop {
        // Find the next marker, skipping fill bytes.
        ensure!(pos < input.len() && input[pos] == 0xFF, "JPEG marker expected");
        while pos < input.len() && input[pos] == 0xFF {
            pos += 1;
        }
        ensure!(pos < input.len(), "truncated JPEG");
        let marker = input[pos];
        pos += 1;
        if marker == 0xD9 {
            // EOI: drop whatever trails the image.
            out.extend_from_slice(&[0xFF, 0xD9]);
            return Ok(out);
        }
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            out.extend_from_slice(&[0xFF, marker]);
            continue;
        }
        let length = u16_be(input, pos)? as usize;
        ensure!(length >= 2 && pos + length <= input.len(), "invalid JPEG segment length");
        let payload = &input[pos + 2..pos + length];
        if keep_jpeg_segment(marker, payload, write_orientation) {
            out.extend_from_slice(&[0xFF, marker]);
            out.extend_from_slice(&input[pos..pos + length]);
        }
        pos += length;
        if marker == 0xDA {
            // SOS: copy the entropy-coded data up to the next real marker.
            let start = pos;
            while pos + 1 < input.len() {
                if input[pos] == 0xFF {
                    let next = input[pos + 1];
                    if next == 0x00 || (0xD0..=0xD7).contains(&next) || next == 0xFF {
                        pos += if next == 0xFF { 1 } else { 2 };
                        continue;
                    }
                    break;
                }
                pos += 1;
            }
            ensure!(pos + 1 < input.len(), "JPEG without EOI");
            out.extend_from_slice(&input[start..pos]);
        }
    }
}

fn keep_jpeg_segment(marker: u8, payload: &[u8], exif_written: bool) -> bool {
    match marker {
        // JFIF without a thumbnail. Dropped when we wrote an EXIF block, which must come first.
        0xE0 => {
            !exif_written
                && payload.starts_with(b"JFIF\0")
                && payload.len() >= 14
                && payload[12] == 0
                && payload[13] == 0
        }
        0xE2 => payload.starts_with(b"ICC_PROFILE\0"),
        0xEE => payload.starts_with(b"Adobe"),
        // Other APPn (EXIF, XMP, MPF, IPTC/Photoshop, vendor data) and comments.
        m => !((0xE0..=0xEF).contains(&m) || m == 0xFE),
    }
}

// -------------------------------------------------------------------------------------- PNG

const PNG_SIGNATURE: &[u8] = &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];

const PNG_ANCILLARY_KEPT: &[&[u8; 4]] = &[
    b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"cICP", b"mDCv", b"cLLi", b"bKGD",
    b"hIST", b"pHYs", b"sPLT", b"acTL", b"fcTL", b"fdAT",
];

fn strip_png(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(input.starts_with(PNG_SIGNATURE), "not a PNG");
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(PNG_SIGNATURE);
    let mut pos = PNG_SIGNATURE.len();
    while pos + 12 <= input.len() {
        let length = u32_be(input, pos)? as usize;
        ensure!(length <= input.len() - pos - 12, "invalid PNG chunk length");
        let kind: &[u8; 4] = input[pos + 4..pos + 8].try_into()?;
        let size = length + 12;
        // Critical chunks have an upper-case first letter.
        if kind[0].is_ascii_uppercase() || PNG_ANCILLARY_KEPT.contains(&kind) {
            out.extend_from_slice(&input[pos..pos + size]);
        }
        pos += size;
        if kind == b"IEND" {
            return Ok(out);
        }
    }
    bail!("PNG without IEND")
}

// ------------------------------------------------------------------------------------- WebP

fn strip_webp(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(input.len() >= 12 && &input[0..4] == b"RIFF" && &input[8..12] == b"WEBP", "not a WebP");
    let riff_end = input.len().min(8 + u32_le(input, 4)? as usize);
    let mut body = Vec::with_capacity(input.len());
    let mut pos = 12;
    while pos + 8 <= riff_end {
        let fourcc = &input[pos..pos + 4];
        let size = u32_le(input, pos + 4)? as usize;
        let padded = size + (size & 1);
        ensure!(padded <= riff_end - pos - 8, "invalid WebP chunk size");
        let total = 8 + padded;
        if fourcc != b"EXIF" && fourcc != b"XMP " {
            let start = body.len();
            body.extend_from_slice(&input[pos..pos + total]);
            if fourcc == b"VP8X" && size >= 1 {
                // Clear the "has EXIF" (0x08) and "has XMP" (0x04) flags.
                body[start + 8] &= !0x0C;
            }
        }
        pos += total;
    }
    let mut out = Vec::with_capacity(body.len() + 12);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(body.len() as u32 + 4).to_le_bytes());
    out.extend_from_slice(b"WEBP");
    out.extend_from_slice(&body);
    Ok(out)
}

// -------------------------------------------------------------------------------------- GIF

fn strip_gif(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(
        input.len() >= 13 && (input.starts_with(b"GIF87a") || input.starts_with(b"GIF89a")),
        "not a GIF"
    );
    let mut out = Vec::with_capacity(input.len());
    let mut pos = 13;
    let lsd_flags = input[10];
    if lsd_flags & 0x80 != 0 {
        pos += 3 * (1 << ((lsd_flags & 0x07) + 1));
    }
    ensure!(pos <= input.len(), "truncated GIF");
    out.extend_from_slice(&input[..pos]);
    while pos < input.len() {
        match input[pos] {
            // Trailer.
            0x3B => {
                out.push(0x3B);
                return Ok(out);
            }
            // Image descriptor.
            0x2C => {
                ensure!(pos + 10 <= input.len(), "truncated GIF image");
                let mut p = pos + 10;
                let flags = input[pos + 9];
                if flags & 0x80 != 0 {
                    p += 3 * (1 << ((flags & 0x07) + 1));
                }
                p += 1; // LZW minimum code size
                p = skip_sub_blocks(input, p)?;
                out.extend_from_slice(&input[pos..p]);
                pos = p;
            }
            // Extension.
            0x21 => {
                ensure!(pos + 2 <= input.len(), "truncated GIF extension");
                let label = input[pos + 1];
                let end = skip_sub_blocks(input, pos + 2)?;
                let data = &input[pos + 2..end];
                let keep = match label {
                    // Graphic control, plain text.
                    0xF9 | 0x01 => true,
                    // Application: keep only the loop count.
                    0xFF => data.starts_with(b"\x0bNETSCAPE2.0") || data.starts_with(b"\x0bANIMEXTS1.0"),
                    // Comment (0xFE) and unknown extensions.
                    _ => false,
                };
                if keep {
                    out.extend_from_slice(&input[pos..end]);
                }
                pos = end;
            }
            b => bail!("unexpected GIF block {b}"),
        }
    }
    bail!("GIF without trailer")
}

fn skip_sub_blocks(input: &[u8], mut pos: usize) -> anyhow::Result<usize> {
    loop {
        ensure!(pos < input.len(), "truncated GIF sub-blocks");
        let size = input[pos] as usize;
        pos += 1 + size;
        if size == 0 {
            return Ok(pos);
        }
    }
}

// ----------------------------------------------------------------------- MP4 / QuickTime

/// One ISO-BMFF box: `start..end` spans the whole box, `body` is where its payload begins.
struct Mp4Box {
    kind: [u8; 4],
    start: usize,
    body: usize,
    end: usize,
}

/// The boxes laid out in `data[from..to]`.
fn mp4_boxes(data: &[u8], from: usize, to: usize) -> anyhow::Result<Vec<Mp4Box>> {
    let mut boxes = Vec::new();
    let mut pos = from;
    while pos + 8 <= to {
        let size32 = u32_be(data, pos)? as u64;
        let kind: [u8; 4] = data[pos + 4..pos + 8].try_into()?;
        let (size, header) = match size32 {
            0 => ((to - pos) as u64, 8),
            1 => (u64_be(data, pos + 8)?, 16),
            n => (n, 8),
        };
        ensure!(size >= header as u64 && size <= (to - pos) as u64, "invalid MP4 box size");
        let end = pos + size as usize;
        boxes.push(Mp4Box { kind, start: pos, body: pos + header, end });
        pos = end;
    }
    ensure!(pos == to || to - pos < 8, "trailing garbage in MP4 container");
    Ok(boxes)
}

/// Overwrites `data[b.start..b.end]` with a `free` box of the same size.
fn mp4_blank(data: &mut [u8], b: &Mp4Box) {
    data[b.start + 4..b.start + 8].copy_from_slice(b"free");
    data[b.body..b.end].fill(0);
}

/// Clears the creation/modification time of a `mvhd`/`tkhd`/`mdhd` full box.
fn mp4_clear_times(data: &mut [u8], b: &Mp4Box) -> anyhow::Result<()> {
    let version = *data.get(b.body).context("truncated MP4 header box")?;
    let len = if version == 1 { 16 } else { 8 };
    ensure!(b.body + 4 + len <= b.end, "truncated MP4 header box");
    data[b.body + 4..b.body + 4 + len].fill(0);
    Ok(())
}

/// Boxes that carry user data / metadata rather than media.
fn mp4_is_metadata(kind: &[u8; 4]) -> bool {
    matches!(kind, b"udta" | b"meta" | b"uuid" | b"XMP_" | b"ilst")
}

fn strip_mp4(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut data = input.to_vec();
    let top = mp4_boxes(input, 0, input.len())?;
    ensure!(top.iter().any(|b| &b.kind == b"moov"), "not an MP4 file");
    for b in &top {
        if mp4_is_metadata(&b.kind) {
            mp4_blank(&mut data, b);
        } else if &b.kind == b"moov" {
            strip_moov(input, &mut data, b)?;
        }
    }
    Ok(data)
}

fn strip_moov(input: &[u8], data: &mut [u8], moov: &Mp4Box) -> anyhow::Result<()> {
    let mut media_tracks = 0;
    for b in mp4_boxes(input, moov.body, moov.end)? {
        match &b.kind {
            b"mvhd" => mp4_clear_times(data, &b)?,
            b"trak" => {
                if strip_trak(input, data, &b)? {
                    media_tracks += 1;
                } else {
                    // A metadata/timed-text/location track: its samples are zeroed in the
                    // media data and its description is dropped.
                    mp4_blank(data, &b);
                }
            }
            kind if mp4_is_metadata(kind) => mp4_blank(data, &b),
            _ => {}
        }
    }
    ensure!(media_tracks > 0, "no audio or video tracks");
    Ok(())
}

/// Cleans one `trak`. Returns whether it is an audio/video track (to keep); for any other
/// track its samples have been zeroed and the caller blanks the box.
fn strip_trak(input: &[u8], data: &mut [u8], trak: &Mp4Box) -> anyhow::Result<bool> {
    let children = mp4_boxes(input, trak.body, trak.end)?;
    let mdia = children.iter().find(|b| &b.kind == b"mdia").context("track without mdia")?;
    let mdia_children = mp4_boxes(input, mdia.body, mdia.end)?;
    let handler = mdia_children
        .iter()
        .find(|b| &b.kind == b"hdlr")
        .map(|h| slice(input, h.body + 8, 4).map(|s| <[u8; 4]>::try_from(s).unwrap_or_default()))
        .transpose()?
        .unwrap_or_default();
    let media = matches!(&handler, b"vide" | b"soun");
    if !media {
        zero_track_samples(input, data, &mdia_children)?;
        return Ok(false);
    }
    for b in &children {
        match &b.kind {
            b"tkhd" => mp4_clear_times(data, b)?,
            kind if mp4_is_metadata(kind) => mp4_blank(data, b),
            _ => {}
        }
    }
    for b in &mdia_children {
        match &b.kind {
            b"mdhd" => mp4_clear_times(data, b)?,
            kind if mp4_is_metadata(kind) => mp4_blank(data, b),
            _ => {}
        }
    }
    Ok(true)
}

/// Zeroes the sample data of a track, located through its sample table.
fn zero_track_samples(input: &[u8], data: &mut [u8], mdia_children: &[Mp4Box]) -> anyhow::Result<()> {
    let Some(minf) = mdia_children.iter().find(|b| &b.kind == b"minf") else { return Ok(()) };
    let Some(stbl) = mp4_boxes(input, minf.body, minf.end)?.into_iter().find(|b| &b.kind == b"stbl") else {
        return Ok(());
    };
    let tables = mp4_boxes(input, stbl.body, stbl.end)?;
    let find = |k: &[u8; 4]| tables.iter().find(|b| &b.kind == k);

    // Chunk offsets.
    let mut chunks: Vec<u64> = Vec::new();
    if let Some(b) = find(b"stco") {
        let n = u32_be(input, b.body + 4)? as usize;
        for i in 0..n {
            chunks.push(u32_be(input, b.body + 8 + i * 4)? as u64);
        }
    } else if let Some(b) = find(b"co64") {
        let n = u32_be(input, b.body + 4)? as usize;
        for i in 0..n {
            chunks.push(u64_be(input, b.body + 8 + i * 8)?);
        }
    }
    if chunks.is_empty() {
        return Ok(());
    }
    // Sample sizes.
    let stsz = find(b"stsz").context("track without stsz")?;
    let fixed = u32_be(input, stsz.body + 4)? as u64;
    let count = u32_be(input, stsz.body + 8)? as usize;
    let size_of = |i: usize| -> anyhow::Result<u64> {
        if fixed != 0 { Ok(fixed) } else { Ok(u32_be(input, stsz.body + 12 + i * 4)? as u64) }
    };
    // Samples per chunk: runs of (first chunk (1-based), samples per chunk).
    let stsc = find(b"stsc").context("track without stsc")?;
    let runs_n = u32_be(input, stsc.body + 4)? as usize;
    let mut runs = Vec::with_capacity(runs_n);
    for i in 0..runs_n {
        let e = stsc.body + 8 + i * 12;
        runs.push((u32_be(input, e)? as usize, u32_be(input, e + 4)? as usize));
    }
    let mut sample = 0;
    for (ci, &offset) in chunks.iter().enumerate() {
        let per_chunk = runs.iter().rev().find(|(first, _)| *first <= ci + 1).map(|r| r.1).unwrap_or(0);
        let mut pos = offset as usize;
        for _ in 0..per_chunk {
            if sample >= count {
                break;
            }
            let len = size_of(sample)? as usize;
            let end = pos.checked_add(len).context("overflow")?;
            ensure!(end <= data.len(), "sample outside the file");
            data[pos..end].fill(0);
            pos = end;
            sample += 1;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------- WebM / Matroska

const EBML_HEADER: u32 = 0x1A45_DFA3;
const MKV_SEGMENT: u32 = 0x1853_8067;
const MKV_CLUSTER: u32 = 0x1F43_B675;
const MKV_INFO: u32 = 0x1549_A966;
const MKV_TAGS: u32 = 0x1254_C367;
const MKV_ATTACHMENTS: u32 = 0x1941_A469;
/// Level-1 children of a Segment (end an unknown-size Cluster).
const MKV_LEVEL1: &[u32] =
    &[0x114D_9B74, MKV_INFO, 0x1654_AE6B, 0x1C53_BB6B, MKV_ATTACHMENTS, 0x1043_A770, MKV_TAGS, MKV_CLUSTER];
/// Info children that identify the author or time: DateUTC, Title, MuxingApp, WritingApp.
const MKV_INFO_IDENTIFYING: &[u32] = &[0x4461, 0x7BA9, 0x4D80, 0x5741];

/// Reads an EBML element header at `pos`: (id, payload start, payload size or None if unknown).
fn ebml_header(d: &[u8], pos: usize) -> anyhow::Result<(u32, usize, Option<usize>)> {
    let first = *d.get(pos).context("truncated EBML")?;
    let id_len = first.leading_zeros() as usize + 1;
    ensure!(id_len <= 4, "invalid EBML id");
    let mut id = 0u32;
    for &b in slice(d, pos, id_len)? {
        id = (id << 8) | b as u32;
    }
    let p = pos + id_len;
    let first = *d.get(p).context("truncated EBML")?;
    let size_len = first.leading_zeros() as usize + 1;
    ensure!(size_len <= 8, "invalid EBML size");
    let bytes = slice(d, p, size_len)?;
    let mut size = (bytes[0] as u64) & (0xFF >> size_len);
    let mut all_ones = size == (0xFF >> size_len) as u64;
    for &b in &bytes[1..] {
        size = (size << 8) | b as u64;
        all_ones &= b == 0xFF;
    }
    let body = p + size_len;
    if all_ones {
        return Ok((id, body, None));
    }
    let size = usize::try_from(size)?;
    ensure!(body.checked_add(size).is_some_and(|e| e <= d.len()), "EBML element past the end");
    Ok((id, body, Some(size)))
}

/// Overwrites `data[start..end]` with a single `Void` element of the same size.
fn ebml_void(data: &mut [u8], start: usize, end: usize) {
    let total = end - start;
    // Width of the size field: one byte when the payload fits, else eight.
    let width = if total.saturating_sub(2) <= 126 { 1 } else { 8 };
    data[start..end].fill(0);
    data[start] = 0xEC;
    let payload = (total - 1 - width) as u64;
    if width == 1 {
        data[start + 1] = 0x80 | payload as u8;
    } else {
        data[start + 1] = 0x01;
        data[start + 2..start + 9].copy_from_slice(&payload.to_be_bytes()[1..]);
    }
}

fn strip_matroska(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut data = input.to_vec();
    let (id, body, size) = ebml_header(input, 0)?;
    ensure!(id == EBML_HEADER, "not a Matroska file");
    let mut pos = body + size.context("unknown-size EBML header")?;
    let mut segments = 0;
    while pos < input.len() {
        let (id, body, size) = ebml_header(input, pos)?;
        let end = size.map_or(input.len(), |s| body + s);
        if id == MKV_SEGMENT {
            strip_segment(input, &mut data, body, end)?;
            segments += 1;
        }
        pos = end;
    }
    ensure!(segments > 0, "Matroska file without segment");
    Ok(data)
}

fn strip_segment(input: &[u8], data: &mut [u8], from: usize, to: usize) -> anyhow::Result<()> {
    let mut pos = from;
    while pos < to {
        let (id, body, size) = ebml_header(input, pos)?;
        let end = match size {
            Some(s) => body + s,
            // Only a Cluster may have an unknown size in practice: it ends at the next
            // level-1 element.
            None if id == MKV_CLUSTER => {
                let mut p = body;
                while p < to {
                    let (child, child_body, child_size) = ebml_header(input, p)?;
                    if MKV_LEVEL1.contains(&child) {
                        break;
                    }
                    p = child_body + child_size.context("unknown-size cluster child")?;
                }
                p
            }
            None => bail!("unknown-size Matroska element"),
        };
        match id {
            MKV_TAGS | MKV_ATTACHMENTS => ebml_void(data, pos, end),
            MKV_INFO => {
                let mut p = body;
                while p < end {
                    let (child, child_body, child_size) = ebml_header(input, p)?;
                    let child_end = child_body + child_size.context("unknown-size Info child")?;
                    if MKV_INFO_IDENTIFYING.contains(&child) {
                        ebml_void(data, p, child_end);
                    }
                    p = child_end;
                }
            }
            _ => {}
        }
        pos = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg_with_exif(orientation: u8) -> Vec<u8> {
        let mut j = vec![0xFF, 0xD8];
        // APP1 EXIF: orientation + a fake GPS marker string that must disappear.
        let mut exif = b"Exif\0\0MM\x00\x2A\x00\x00\x00\x08\x00\x01\x01\x12\x00\x03\x00\x00\x00\x01".to_vec();
        exif.extend_from_slice(&[0x00, orientation, 0, 0, 0, 0, 0, 0]);
        exif.extend_from_slice(b"GPS-SECRET");
        j.extend_from_slice(&[0xFF, 0xE1]);
        j.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
        j.extend_from_slice(&exif);
        // COM segment.
        j.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x08]);
        j.extend_from_slice(b"Pixel");
        j.push(0);
        // DQT (kept), SOS + entropy data, EOI, trailer.
        j.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x00, 0x01]);
        j.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x03, 0x01, 0x12, 0xFF, 0x00, 0x34]);
        j.extend_from_slice(&[0xFF, 0xD9]);
        j.extend_from_slice(b"MOTION-PHOTO-TRAILER");
        j
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn jpeg_loses_metadata_but_keeps_orientation_and_image() {
        let input = jpeg_with_exif(6);
        assert_eq!(read_orientation(&input), 6);
        let out = strip(&input, "image/jpeg").unwrap();
        assert!(!contains(&out, b"GPS-SECRET"));
        assert!(!contains(&out, b"Pixel"));
        assert!(!contains(&out, b"MOTION"));
        assert!(contains(&out, &[0xFF, 0xDB, 0x00, 0x04, 0x00, 0x01]));
        assert!(contains(&out, &[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD9]));
        assert_eq!(read_orientation(&out), 6);
        assert!(out.ends_with(&[0xFF, 0xD9]));
    }

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut c = (data.len() as u32).to_be_bytes().to_vec();
        c.extend_from_slice(kind);
        c.extend_from_slice(data);
        c.extend_from_slice(&[0, 0, 0, 0]); // CRC isn't checked here
        c
    }

    #[test]
    fn png_keeps_only_rendering_chunks() {
        let mut p = PNG_SIGNATURE.to_vec();
        p.extend(png_chunk(b"IHDR", &[0; 13]));
        p.extend(png_chunk(b"tEXt", b"Author\0me"));
        p.extend(png_chunk(b"eXIf", b"GPS"));
        p.extend(png_chunk(b"gAMA", &[0, 0, 0, 1]));
        p.extend(png_chunk(b"IDAT", &[1, 2, 3]));
        p.extend(png_chunk(b"IEND", &[]));
        let out = strip(&p, "image/png").unwrap();
        assert!(!contains(&out, b"tEXt") && !contains(&out, b"eXIf"));
        assert!(contains(&out, b"gAMA") && contains(&out, b"IDAT") && contains(&out, b"IEND"));
    }

    #[test]
    fn webp_drops_exif_and_xmp() {
        let mut body = Vec::new();
        body.extend_from_slice(b"VP8X");
        body.extend_from_slice(&10u32.to_le_bytes());
        body.extend_from_slice(&[0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(b"EXIF");
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(b"GPS\0");
        body.extend_from_slice(b"VP8 ");
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&[7, 7]);
        let mut w = b"RIFF".to_vec();
        w.extend_from_slice(&(body.len() as u32 + 4).to_le_bytes());
        w.extend_from_slice(b"WEBP");
        w.extend_from_slice(&body);
        let out = strip(&w, "image/webp").unwrap();
        assert!(!contains(&out, b"EXIF") && !contains(&out, b"GPS"));
        assert_eq!(out[20] & 0x0C, 0);
        assert_eq!(u32_le(&out, 4).unwrap() as usize, out.len() - 8);
    }

    #[test]
    fn gif_drops_comments_keeps_loop() {
        let mut g = b"GIF89a".to_vec();
        g.extend_from_slice(&[1, 0, 1, 0, 0x00, 0, 0]); // no global color table
        g.extend_from_slice(b"\x21\xFF\x0bNETSCAPE2.0\x03\x01\x00\x00\x00");
        g.extend_from_slice(b"\x21\xFE\x06secret\x00");
        g.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0x00, 0x02, 0x01, 0x44, 0x00]);
        g.push(0x3B);
        let out = strip(&g, "image/gif").unwrap();
        assert!(!contains(&out, b"secret"));
        assert!(contains(&out, b"NETSCAPE2.0"));
        assert_eq!(*out.last().unwrap(), 0x3B);
    }

    fn mp4_box(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(kind);
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn mp4_blanks_user_data_and_metadata_tracks() {
        let hdlr = |h: &[u8; 4]| {
            let mut p = vec![0; 8];
            p.extend_from_slice(h);
            p.extend_from_slice(&[0; 12]);
            mp4_box(b"hdlr", &p)
        };
        let mdhd = mp4_box(b"mdhd", &[0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0]);
        let video = mp4_box(b"trak", &[mp4_box(b"mdia", &[mdhd.clone(), hdlr(b"vide")].concat())].concat());
        // A metadata track whose single 4-byte sample lives at offset `meta_at` in the mdat.
        let mdat_payload = b"VIDEOGPS!";
        let ftyp = mp4_box(b"ftyp", b"isom");
        let mdat = mp4_box(b"mdat", mdat_payload);
        let meta_at = (ftyp.len() + 8 + 5) as u32;
        let stbl = mp4_box(
            b"stbl",
            &[
                mp4_box(b"stsz", &[&[0u8; 4][..], &4u32.to_be_bytes(), &1u32.to_be_bytes()].concat()),
                mp4_box(b"stsc", &[&[0u8; 4][..], &1u32.to_be_bytes(), &1u32.to_be_bytes(), &1u32.to_be_bytes(), &1u32.to_be_bytes()].concat()),
                mp4_box(b"stco", &[&[0u8; 4][..], &1u32.to_be_bytes(), &meta_at.to_be_bytes()].concat()),
            ]
            .concat(),
        );
        let meta_trak = mp4_box(
            b"trak",
            &[mp4_box(b"mdia", &[hdlr(b"meta"), mp4_box(b"minf", &stbl)].concat())].concat(),
        );
        let udta = mp4_box(b"udta", b"\xa9xyz+52.5+013.4/");
        let moov = mp4_box(b"moov", &[video, meta_trak, udta].concat());
        let file = [ftyp, mdat, moov].concat();

        let out = strip(&file, "video/mp4").unwrap();
        assert_eq!(out.len(), file.len());
        assert!(!contains(&out, b"+52.5+013.4"));
        assert!(!contains(&out, b"GPS!"));
        assert!(contains(&out, b"VIDEO"));
        assert!(!contains(&out, &[1, 2, 3, 4, 5, 6, 7, 8]));
        assert!(contains(&out, b"vide"));
    }

    #[test]
    fn matroska_voids_tags() {
        let el = |id: &[u8], payload: &[u8]| {
            let mut e = id.to_vec();
            e.push(0x80 | payload.len() as u8);
            e.extend_from_slice(payload);
            e
        };
        let header = el(&[0x1A, 0x45, 0xDF, 0xA3], &el(&[0x42, 0x82], b"webm"));
        let info = el(&[0x15, 0x49, 0xA9, 0x66], &[el(&[0x2A, 0xD7, 0xB1], &[0x0F, 0x42, 0x40]), el(&[0x57, 0x41], b"Phone 9")].concat());
        let tags = el(&[0x12, 0x54, 0xC3, 0x67], b"LOCATION=+52+13");
        let cluster = el(&[0x1F, 0x43, 0xB6, 0x75], &el(&[0xE7], &[0]));
        let segment = el(&[0x18, 0x53, 0x80, 0x67], &[info, cluster, tags].concat());
        let file = [header, segment].concat();
        let out = strip(&file, "video/webm").unwrap();
        assert_eq!(out.len(), file.len());
        assert!(!contains(&out, b"LOCATION") && !contains(&out, b"Phone 9"));
        assert!(contains(&out, &[0x2A, 0xD7, 0xB1]));
        // Still a valid element stream.
        strip(&out, "video/webm").unwrap();
    }

    #[test]
    fn unsupported_and_broken_input_is_refused() {
        assert!(strip(b"not an image", "image/jpeg").is_err());
        assert!(strip(b"x", "image/heic").is_err());
        assert!(!can_strip("image/heic"));
    }
}
