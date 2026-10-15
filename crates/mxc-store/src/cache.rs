//! Encryption at rest for the on-disk media caches (avatars, chat media, story media, stickers,
//! WebXDC bundles).
//!
//! Every cache file is sealed with AES-256-GCM under a random key kept in the secret service,
//! like the database key, with the file name as associated data so a sealed file can't be
//! passed off as a different cache entry. Format: `MAGIC | nonce (12) | ciphertext + tag`.
//! Cache file names carry no extension, so they don't give away the media type either; the
//! type is only applied to the decrypted view copy.
//!
//! Consumers that need a real file (QML images, the GStreamer player, the system video player,
//! the WebXDC web view) get a decrypted copy from [`view`]. Those copies live in a per-process
//! *view* directory under `$XDG_RUNTIME_DIR` (a RAM-backed tmpfs on Linux), or the user's temp
//! dir where there is none. It is created owner-only, removed by [`wipe_views`] at exit, and
//! any left behind by a crashed run are removed on the next start.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::{secrets, StoreError, DB_KEY_ACCOUNT};

const MAGIC: &[u8; 8] = b"MXCENC1\0";
const NONCE_LEN: usize = 12;
/// Prefix of the per-process view directories (`<prefix><pid>-<random>`).
const VIEW_PREFIX: &str = "monocles-chat-view-";

static KEY: OnceLock<Aes256Gcm> = OnceLock::new();
static VIEW_ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Load the cache key from the secret service (creating it on first use). Until this ran,
/// nothing can be written to or read from the cache.
pub async fn init() -> crate::Result<()> {
    if KEY.get().is_some() {
        return Ok(());
    }
    let hex_key = match secrets::retrieve(secrets::kinds::CACHE_KEY, DB_KEY_ACCOUNT).await? {
        Some(bytes) => String::from_utf8(bytes).map_err(|e| StoreError::Secret(e.to_string()))?,
        None => {
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            let hex_key = hex::encode(key);
            secrets::store(secrets::kinds::CACHE_KEY, DB_KEY_ACCOUNT, hex_key.as_bytes()).await?;
            hex_key
        }
    };
    let key = hex::decode(hex_key.trim()).map_err(|e| StoreError::Secret(e.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| StoreError::Secret(e.to_string()))?;
    let _ = KEY.set(cipher);
    Ok(())
}

fn key() -> io::Result<&'static Aes256Gcm> {
    KEY.get().ok_or_else(|| io::Error::other("cache key not loaded"))
}

/// The associated data binding a sealed file to its cache entry: its file name.
fn aad(path: &Path) -> Vec<u8> {
    path.file_name().map(|n| n.as_encoded_bytes().to_vec()).unwrap_or_default()
}

fn seal(path: &Path, plain: &[u8]) -> io::Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let aad = aad(path);
    let ct = key()?
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: &aad })
        .map_err(|_| io::Error::other("cache encryption failed"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_sealed(path: &Path, sealed: &[u8]) -> io::Result<Vec<u8>> {
    let body = &sealed[MAGIC.len()..];
    if body.len() < NONCE_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated cache file"));
    }
    let (nonce, ct) = body.split_at(NONCE_LEN);
    let aad = aad(path);
    key()?
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cache file failed authentication"))
}

/// A sibling name for writing `path` atomically.
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp-{:016x}", rand::rng().next_u64()));
    path.with_file_name(name)
}

/// Write `bytes` to a new owner-only file at `path`, via a temporary name so readers never see
/// a partial file.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = tmp_sibling(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let result = opts.open(&tmp).and_then(|mut f| f.write_all(bytes)).and_then(|_| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Encrypt `plain` into the cache file at `path` (replacing it, and dropping its view copy).
pub fn write(path: &Path, plain: &[u8]) -> io::Result<()> {
    let sealed = seal(path, plain)?;
    write_private(path, &sealed)?;
    drop_view(path);
    Ok(())
}

/// Decrypt the cache file at `path`. A file that isn't sealed yet (written by an older build)
/// is sealed in place and returned as is.
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    if data.starts_with(MAGIC) {
        return open_sealed(path, &data);
    }
    write(path, &data)?;
    Ok(data)
}

/// Delete the cache file at `path` and its view copy.
pub fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
    drop_view(path);
}

/// Seal every not-yet-sealed file under `dir` (recursively) in place, and remove leftover
/// temporary files. For migrating caches written by older builds; a no-op once done.
pub fn seal_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        let path = entry.path();
        if ft.is_dir() {
            seal_dir(&path);
        } else if ft.is_file() {
            if path.file_name().is_some_and(|n| n.to_string_lossy().contains(".tmp-")) {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            let mut head = [0u8; MAGIC.len()];
            let sealed = std::fs::File::open(&path)
                .and_then(|mut f| io::Read::read_exact(&mut f, &mut head))
                .is_ok_and(|_| &head == MAGIC);
            if !sealed {
                if let Ok(data) = std::fs::read(&path) {
                    if write(&path, &data).is_err() {
                        tracing::warn!(path = %path.display(), "couldn't seal cache file");
                    }
                }
            }
        }
    }
}

/// Rename every file under `dir` (not recursive) that still has an extension, as older builds
/// named media cache files, to its name without one. The name is bound into the encryption, so
/// each is decrypted under its old name and sealed again under the new one; one that doesn't
/// decrypt is dropped.
pub fn strip_extensions(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if !entry.file_type().is_ok_and(|t| t.is_file()) || path.extension().is_none() {
            continue;
        }
        if path.file_name().is_some_and(|n| n.to_string_lossy().contains(".tmp-")) {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let target = path.with_extension("");
        if !target.exists() {
            let Ok(data) = std::fs::read(&path) else { continue };
            let plain = if data.starts_with(MAGIC) { open_sealed(&path, &data) } else { Ok(data) };
            match plain {
                Ok(plain) => {
                    if let Err(e) = write(&target, &plain) {
                        tracing::warn!(error = %e, path = %path.display(), "couldn't rename cache file");
                        continue; // keep it; retried next start
                    }
                }
                Err(e) if e.kind() != io::ErrorKind::InvalidData => continue,
                Err(_) => tracing::warn!(path = %path.display(), "dropping undecryptable cache file"),
            }
        }
        remove(&path);
    }
}

// --- decrypted view copies ------------------------------------------------------------------

/// This process's view directory (created on first use), or `None` if it couldn't be made.
fn view_root() -> Option<&'static Path> {
    VIEW_ROOT.get_or_init(create_view_root).as_deref()
}

fn create_view_root() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty() && p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("{VIEW_PREFIX}{}-{:016x}", std::process::id(), rand::rng().next_u64()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    // Not recursive: fails (rather than reusing it) if the name exists, e.g. a planted symlink.
    if let Err(e) = builder.create(&dir) {
        tracing::warn!(error = %e, "couldn't create the media view directory");
        return None;
    }
    sweep_stale_views(&base, &dir);
    Some(dir)
}

/// Remove view directories of earlier runs that didn't exit cleanly (only our own, and on
/// Linux only those whose process is gone).
fn sweep_stale_views(base: &Path, ours: &Path) {
    #[cfg(unix)]
    let our_uid = {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(ours) {
            Ok(m) => m.uid(),
            Err(_) => return,
        }
    };
    let Ok(entries) = std::fs::read_dir(base) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path == ours {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(VIEW_PREFIX) else { continue };
        // Never follow a symlink out of the base dir.
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if !meta.is_dir() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != our_uid {
                continue;
            }
        }
        if cfg!(target_os = "linux") {
            let pid = rest.split('-').next().unwrap_or("");
            if !pid.is_empty() && Path::new("/proc").join(pid).exists() {
                continue; // another running instance
            }
        }
        let _ = std::fs::remove_dir_all(&path);
    }
}

/// A private subdirectory `name` of the view directory (created if needed), for plaintext that
/// has to exist as files only while the app runs (an extracted WebXDC app, a voice recording).
pub fn view_subdir(name: &str) -> Option<PathBuf> {
    let dir = view_root()?.join(name);
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(&dir).ok()?;
    Some(dir)
}

/// The directory holding the view copies of cache file `path`: named by a hash of the path.
fn view_dir_of(path: &Path) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(path.as_os_str().as_encoded_bytes());
    Some(view_root()?.join(hex::encode(&digest[..20])))
}

fn drop_view(path: &Path) {
    if VIEW_ROOT.get().is_none() {
        return; // no view made yet
    }
    if let Some(dir) = view_dir_of(path) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A decrypted copy of the cache file at `path`, for handing to whatever needs a real file;
/// `None` if it isn't cached. `ext` becomes the copy's extension (players pick the format by
/// it; only pass a safe one). A file that fails to decrypt (corrupt or tampered with) is
/// deleted, so it gets fetched again.
pub fn view(path: &Path, ext: Option<&str>) -> Option<PathBuf> {
    if !path.is_file() {
        return None;
    }
    let dir = view_dir_of(path)?;
    let v = match ext.filter(|e| !e.is_empty() && e.chars().all(|c| c.is_ascii_alphanumeric())) {
        Some(ext) => dir.join(format!("media.{ext}")),
        None => dir.join("media"),
    };
    if v.is_file() {
        return Some(v);
    }
    let plain = match read(path) {
        Ok(p) => p,
        Err(e) => {
            if e.kind() == io::ErrorKind::InvalidData {
                tracing::warn!(path = %path.display(), "dropping undecryptable cache file");
                remove(path);
            }
            return None;
        }
    };
    write_private(&v, &plain).ok()?;
    Some(v)
}

/// Remove this process's view directory (at exit).
pub fn wipe_views() {
    if let Some(Some(dir)) = VIEW_ROOT.get() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() {
        let _ = KEY.set(Aes256Gcm::new_from_slice(&[7u8; 32]).unwrap());
    }

    #[test]
    fn round_trip_is_encrypted_and_bound_to_the_name() {
        test_key();
        let dir = std::env::temp_dir().join(format!("mxc-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = dir.join("a");
        let plain = b"secret picture bytes";
        write(&a, plain).unwrap();

        let raw = std::fs::read(&a).unwrap();
        assert!(raw.starts_with(MAGIC));
        assert!(!raw.windows(6).any(|w| w == b"secret"), "plaintext on disk");
        assert_eq!(read(&a).unwrap(), plain);

        // Moved to another entry's name: fails authentication.
        let b = dir.join("b");
        std::fs::copy(&a, &b).unwrap();
        assert_eq!(read(&b).unwrap_err().kind(), io::ErrorKind::InvalidData);

        // A legacy plaintext file is sealed in place on first read.
        let legacy = dir.join("legacy");
        std::fs::write(&legacy, b"old secret").unwrap();
        assert_eq!(read(&legacy).unwrap(), b"old secret");
        assert!(std::fs::read(&legacy).unwrap().starts_with(MAGIC));

        // The view copy is plaintext, outside the cache dir, and dropped on rewrite.
        let v = view(&a, Some("png")).unwrap();
        assert!(!v.starts_with(&dir));
        assert_eq!(v.extension().unwrap(), "png");
        assert_eq!(std::fs::read(&v).unwrap(), plain);
        assert!(view(&a, Some("../x")).unwrap().extension().is_none(), "unsafe ext ignored");
        write(&a, b"new").unwrap();
        assert!(!v.exists());
        assert_eq!(std::fs::read(view(&a, Some("png")).unwrap()).unwrap(), b"new");

        // An undecryptable file is dropped (so it's fetched again).
        assert!(view(&b, None).is_none());
        assert!(!b.exists());

        // Older builds' names with an extension: re-sealed under the bare name.
        let m = dir.join("media");
        write(&m.join("c.jpg"), b"sealed jpg").unwrap();
        std::fs::write(m.join("d.mp4"), b"plain mp4").unwrap();
        strip_extensions(&m);
        assert!(!m.join("c.jpg").exists() && !m.join("d.mp4").exists());
        assert_eq!(read(&m.join("c")).unwrap(), b"sealed jpg");
        assert_eq!(read(&m.join("d")).unwrap(), b"plain mp4");
        assert!(std::fs::read(m.join("d")).unwrap().starts_with(MAGIC));

        wipe_views();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
