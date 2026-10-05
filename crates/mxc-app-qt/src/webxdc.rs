//! WebXDC app runner (Qt side): runs a `.xdc` mini-app in a QtWebEngine view and bridges its
//! JS API (`window.webxdc`) to the chat — status updates + realtime sync to the peers, exactly
//! like monocles Android and the GTK client.
//!
//! The `.xdc` (a zip) is extracted to a cache dir and served over a private `webxdc://` URI
//! scheme implemented by the C++ shim (`cpp/webxdc_shim.cpp` — QtWebEngine's scheme handler and
//! `QtWebEngineQuick::initialize` have no Rust bindings). `webxdc.js` (served at `/webxdc.js`)
//! defines the JS API; the app talks back by `fetch()`-POSTing JSON to `/__bridge__` on its origin,
//! which the shim forwards to [`bridge_message`] (on a Chromium IO thread). Outgoing
//! `sendUpdate`/realtime become `Command::SendWebxdc{Update,Realtime}`; incoming updates (from
//! the session event pump) are pushed back into the view via Backend signals → `runJavaScript`.

use std::os::raw::c_char;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;

use cxx_qt_lib::QString;
use mxc_proto::Command;

use crate::backend::qobject::Backend;
use crate::session;

extern "C" {
    /// Register the `webxdc://` scheme + WebEngine GL sharing. MUST run before QGuiApplication.
    fn mxc_webxdc_pre_app_init();
    /// Point the scheme handler at an extracted app dir + its generated webxdc.js, served only
    /// on `webxdc://<host>/` (installs the handler + offline interceptor on the default profile
    /// on first use). Must run on the Qt thread.
    fn mxc_webxdc_install(root: *const c_char, js: *const c_char, host: *const c_char);
}

/// Called by the C++ scheme handler with each JSON message the app POSTs to `/__bridge__`.
#[no_mangle]
pub extern "C" fn mxc_webxdc_bridge_message(ptr: *const c_char, len: usize) {
    if ptr.is_null() {
        return;
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    if let Ok(s) = std::str::from_utf8(bytes) {
        bridge_message(s);
    }
}

pub fn pre_app_init() {
    unsafe { mxc_webxdc_pre_app_init() }
}

fn install(root: &str, js: &str, host: &str) {
    let (Ok(root), Ok(js), Ok(host)) =
        (std::ffi::CString::new(root), std::ffi::CString::new(js), std::ffi::CString::new(host))
    else {
        return;
    };
    unsafe { mxc_webxdc_install(root.as_ptr(), js.as_ptr(), host.as_ptr()) }
}

/// The private origin host of app instance `thread`: `x` + 128 bits of SHA-256. Every instance
/// gets its own origin, so apps can't read each other's localStorage/IndexedDB (they all used
/// to share `webxdc://app`). A cryptographic hash because the thread id is chosen by whoever
/// sent the app - with a weak hash one could pick an id that collides with a victim app's
/// host and share its storage.
pub fn instance_host(thread: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(thread.as_bytes());
    let mut host = String::with_capacity(33);
    host.push('x');
    for b in &digest[..16] {
        host.push_str(&format!("{b:02x}"));
    }
    host
}

/// The single live app instance (like the GTK client: one app window at a time).
struct Live {
    thread: String,
    peer: String,
    /// Highest update serial already pushed into the running app.
    last_serial: i64,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);

/// Open the `.xdc` app shared in chat `peer` with instance id `thread` at upload URL `url`:
/// download (cached), extract, point the scheme handler at it, then signal QML to create the
/// WebEngine window (`webxdcReady`).
pub fn open(peer: String, thread: String, url: String) {
    if thread.is_empty() || url.is_empty() {
        return;
    }
    session::runtime().spawn(async move {
        let path = session::image_cache_path(&url);
        if !path.is_file() {
            match mxc_proto::xeps::http_upload::download_any(&url).await {
                Ok(bytes) => {
                    if let Some(dir) = path.parent() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    if let Err(e) = std::fs::write(&path, &bytes) {
                        tracing::warn!(error = %e, "webxdc: cache write failed");
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, %url, "webxdc: download failed");
                    return;
                }
            }
        }
        let dir = match extract_xdc(&path, &thread) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "webxdc: couldn't extract app");
                return;
            }
        };
        let Some((_, _, jid)) = session::client_info() else { return };
        let self_addr = format!("xmpp:{}", urlencode(&jid));
        let self_name = jid.split('@').next().unwrap_or(&jid).to_string();
        let js = webxdc_js(&self_addr, &self_name);

        *LIVE.lock().unwrap() = Some(Live { thread: thread.clone(), peer, last_serial: 0 });

        let Some(qt) = session::backend_qt() else { return };
        let dir_s = dir.to_string_lossy().into_owned();
        let host = instance_host(&thread);
        let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
            install(&dir_s, &js, &host); // scheme-handler setup needs the Qt thread
            backend.as_mut().webxdc_ready(QString::from(&thread), QString::from(&host));
        });
    });
}

/// Drop the live instance (the QML app window closed).
pub fn close() {
    *LIVE.lock().unwrap() = None;
}

/// Push every stored update past the live view's cursor into the running app
/// (`webxdcUpdates` signal → QML `runJavaScript("__webxdcPushUpdates([...])")`).
pub fn push_updates(thread: &str) {
    let from_serial = {
        let live = LIVE.lock().unwrap();
        let Some(live) = live.as_ref() else { return };
        if live.thread != thread {
            return;
        }
        live.last_serial
    };
    let Some((_, account_id, _)) = session::client_info() else { return };
    let thread = thread.to_string();
    session::runtime().spawn(async move {
        let Ok(store) = session::store().await else { return };
        let rows = store
            .webxdc_updates_since(account_id, &thread, from_serial)
            .await
            .unwrap_or_default();
        if rows.is_empty() {
            return;
        }
        // Every update after the cursor, serial-ordered → the last row's serial IS the max.
        let max = rows.last().map(|r| r.serial).unwrap_or(0);
        let items: Vec<String> = rows
            .iter()
            .map(|r| {
                mxc_proto::xeps::webxdc::update_json(
                    r.serial,
                    max,
                    r.sender.as_deref(),
                    r.info.as_deref(),
                    r.document.as_deref(),
                    r.summary.as_deref(),
                    r.payload.as_deref(),
                )
            })
            .collect();
        {
            let mut live = LIVE.lock().unwrap();
            match live.as_mut() {
                Some(l) if l.thread == thread => l.last_serial = l.last_serial.max(max),
                _ => return, // window closed / different app while we queried
            }
        }
        let Some(qt) = session::backend_qt() else { return };
        let joined = items.join(",");
        let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
            backend
                .as_mut()
                .webxdc_updates(QString::from(&thread), QString::from(&joined));
        });
    });
}

/// Push realtime data (base64) into the running app.
pub fn push_realtime(thread: &str, data_b64: &str) {
    {
        let live = LIVE.lock().unwrap();
        match live.as_ref() {
            Some(l) if l.thread == thread => {}
            _ => return,
        }
    }
    let Some(qt) = session::backend_qt() else { return };
    // The b64 lands inside a single-quoted JS string literal — strip anything that could escape.
    let safe: String = data_b64.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')).collect();
    let thread = thread.to_string();
    let _ = qt.queue(move |mut backend: Pin<&mut Backend>| {
        backend
            .as_mut()
            .webxdc_realtime(QString::from(&thread), QString::from(&safe));
    });
}

/// Handle one JSON message POSTed by the app to `/__bridge__` (Chromium IO thread).
fn bridge_message(msg: &str) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(msg) else { return };
    let prop = |name: &str| -> Option<String> {
        v.get(name).and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(String::from)
    };
    let (peer, thread) = {
        let live = LIVE.lock().unwrap();
        let Some(live) = live.as_ref() else { return };
        (live.peer.clone(), live.thread.clone())
    };
    let Some((commands, account_id, _)) = session::client_info() else { return };
    let kind = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
    tracing::debug!(kind = %kind, "webxdc bridge message");
    match kind {
        "requestUpdates" => {
            // Reset the cursor to the requested serial, then push from there.
            let serial = v.get("serial").and_then(|x| x.as_i64()).unwrap_or(0);
            if let Some(live) = LIVE.lock().unwrap().as_mut() {
                live.last_serial = serial;
            }
            push_updates(&thread);
        }
        "sendUpdate" => {
            let _ = commands.try_send(Command::SendWebxdcUpdate {
                account_id,
                to: peer,
                thread,
                payload: prop("payload"),
                info: prop("info"),
                document: prop("document"),
                summary: prop("summary"),
                notify: prop("notify"),
            });
        }
        "realtime" => {
            if let Some(data) = prop("data") {
                let _ = commands.try_send(Command::SendWebxdcRealtime {
                    account_id,
                    to: peer,
                    thread,
                    data_b64: data,
                });
            }
        }
        "sendToChat" => {
            // Forward a file and/or text from the app into the chat.
            if let Some((b64, name)) = prop("base64").zip(prop("name")) {
                if let Some(bytes) = mxc_proto::xeps::webxdc::b64_decode(&b64) {
                    let safe: String = name
                        .chars()
                        .map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
                        .collect();
                    let dir = webxdc_cache_dir().join("out");
                    let _ = std::fs::create_dir_all(&dir);
                    let out = dir.join(format!("{:08x}-{safe}", hash_str(&b64) as u32));
                    if std::fs::write(&out, &bytes).is_ok() {
                        let path = out.to_string_lossy().into_owned();
                        let cmd = if safe.to_ascii_lowercase().ends_with(".xdc") {
                            Command::SendWebxdcFile { account_id, to: peer.clone(), path }
                        } else {
                            Command::SendFile { account_id, to: peer.clone(), path, caption: None }
                        };
                        let _ = commands.try_send(cmd);
                    }
                }
            }
            if let Some(text) = prop("text") {
                let _ = commands.try_send(Command::SendMessage {
                    account_id,
                    to: peer,
                    body: text,
                    encryption: mxc_proto::Encryption::None,
                    reply_to: None,
                    id: None,
                });
            }
        }
        _ => {}
    }
}

fn hash_str(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn webxdc_cache_dir() -> PathBuf {
    directories::ProjectDirs::from("de", "monocles", "monocles-chat")
        .map(|d| d.cache_dir().join("webxdc"))
        .unwrap_or_else(|| PathBuf::from("/tmp/monocles-webxdc"))
}

/// Extract a `.xdc` zip into a private cache dir keyed by its instance thread. Reuses a previous
/// extraction when the source file is unchanged (fingerprint = size+mtime in a marker file) —
/// an instance's app file is immutable, so re-unzipping every open is a visible stall.
fn extract_xdc(xdc_path: &std::path::Path, thread: &str) -> anyhow::Result<PathBuf> {
    let safe: String = thread.chars().filter(|c| c.is_alphanumeric() || *c == '-').collect();
    let dir = webxdc_cache_dir().join(safe);

    let marker = dir.join(".xdc-src");
    let fingerprint = std::fs::metadata(xdc_path).ok().map(|m| {
        let mtime = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("{}:{}", m.len(), mtime)
    });
    if let Some(fp) = &fingerprint {
        if dir.join("index.html").exists()
            && std::fs::read_to_string(&marker).ok().as_deref() == Some(fp.as_str())
        {
            return Ok(dir);
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let file = std::fs::File::open(xdc_path)?;
    let mut zip = zip::ZipArchive::new(file)?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let Some(rel) = entry.enclosed_name() else { continue };
        let out = dir.join(&rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::File::create(&out)?;
        std::io::copy(&mut entry, &mut f)?;
    }
    if let Some(fp) = &fingerprint {
        let _ = std::fs::write(&marker, fp);
    }
    Ok(dir)
}

/// Percent-encode a JID for the `xmpp:` selfAddr (keeping `@ / +` like Android's `Uri.encode`).
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'@' | b'/' | b'+' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The injected `window.webxdc` API. Same push-based design as the GTK client's, but the
/// app→host channel is a `fetch()` POST to `/__bridge__` on our private scheme (QtWebEngine
/// has no script-message handler reachable from QML/Rust).
fn webxdc_js(self_addr: &str, self_name: &str) -> String {
    let addr = mxc_proto::xeps::webxdc::json_quote(self_addr);
    let name = mxc_proto::xeps::webxdc::json_quote(self_name);
    format!(
        r#"
window.webxdc = (() => {{
  let update_listener = () => {{}};
  let realtime_listener = null;
  let last_serial = 0;
  let setUpdateListenerPromise = null;
  const post = (m) => fetch("/__bridge__", {{ method: "POST", headers: {{ "Content-Type": "application/json" }}, body: JSON.stringify(m) }}).catch((e) => console.error("webxdc bridge", e));
  window.__webxdcPushUpdates = (updates) => {{
    updates.forEach((u) => {{ try {{ update_listener(u); }} catch (e) {{ console.error(e); }} last_serial = u.serial; }});
    if (setUpdateListenerPromise) {{ setUpdateListenerPromise(); setUpdateListenerPromise = null; }}
  }};
  window.__webxdcRealtimeData = (b64) => {{
    if (!realtime_listener) return;
    realtime_listener(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
  }};
  return {{
    selfAddr: {addr},
    selfName: {name},
    setUpdateListener: (cb, serial) => {{
      last_serial = (typeof serial === "undefined") ? 0 : parseInt(serial);
      update_listener = cb;
      const p = new Promise((res) => {{ setUpdateListenerPromise = res; }});
      post({{ type: "requestUpdates", serial: last_serial }});
      return p;
    }},
    sendUpdate: (update, descr) => {{
      post({{
        type: "sendUpdate",
        payload: (update.payload === undefined ? "" : JSON.stringify(update.payload)),
        info: (update.info || ""),
        document: (update.document || ""),
        summary: (update.summary || ""),
        notify: (update.notify ? JSON.stringify(update.notify) : "")
      }});
    }},
    joinRealtimeChannel: () => ({{
      leave: () => {{}},
      send: (data) => {{
        if (!(data instanceof Uint8Array)) throw new Error("realtime data must be a Uint8Array");
        let s = ""; data.forEach((b) => s += String.fromCharCode(b));
        post({{ type: "realtime", data: btoa(s) }});
      }},
      setListener: (l) => {{ realtime_listener = l; }}
    }}),
    sendToChat: async (message) => {{
      if (!message || (!message.file && !message.text)) return Promise.reject("sendToChat() error: file or text missing");
      const blobToBase64 = (file) => new Promise((resolve, reject) => {{
        const dataStart = ";base64,";
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => {{ const d = reader.result; resolve(d.slice(d.indexOf(dataStart) + dataStart.length)); }};
        reader.onerror = () => reject(reader.error);
      }});
      const data = {{ type: "sendToChat" }};
      if (message.text) data.text = message.text;
      if (message.file) {{
        if (!message.file.name) return Promise.reject("sendToChat() error: file name missing");
        let b64;
        if (message.file.blob instanceof Blob) b64 = await blobToBase64(message.file.blob);
        else if (typeof message.file.base64 === "string") b64 = message.file.base64;
        else if (typeof message.file.plainText === "string") b64 = await blobToBase64(new Blob([message.file.plainText]));
        else return Promise.reject("sendToChat() error: none of blob, base64 or plainText set correctly");
        data.base64 = b64;
        data.name = message.file.name;
      }}
      post(data);
    }},
    importFiles: (filters) => {{
      const el = document.createElement("input");
      el.type = "file";
      el.accept = [...(filters.extensions || []), ...(filters.mimeTypes || [])].join(",");
      el.multiple = filters.multiple || false;
      const p = new Promise((resolve) => {{ el.onchange = () => {{ const fs = Array.from(el.files || []); document.body.removeChild(el); resolve(fs); }}; }});
      el.style.display = "none";
      document.body.appendChild(el);
      el.click();
      return p;
    }}
  }};
}})();
"#
    )
}

#[cfg(test)]
mod tests {
    use super::instance_host;

    #[test]
    fn instance_hosts_are_distinct_valid_labels() {
        let a = instance_host("thread-a");
        let b = instance_host("thread-b");
        assert_ne!(a, b);
        assert_eq!(a, instance_host("thread-a"));
        assert_eq!(a.len(), 33);
        assert!(a.starts_with('x'));
        assert!(a[1..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
