//! PQ OMEMO2 orchestration (Stages C/D): PEP device-list/bundle publish+fetch, session
//! establishment, and `<encrypted>` stanza build/parse. The crypto lives in `mxc-omemo`;
//! this module is the XMPP glue.
//!
//! Per-account [`OmemoStores`] (with the identity key loaded from the secret service) are
//! cached process-globally and populated by [`ensure_initialized`] at bootstrap.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_channel::Sender;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use minidom::Element;

use tracing::{debug, info, warn};

use mxc_omemo::bundle::Bundle;
use mxc_omemo::sce::Envelope;
use mxc_omemo::session::{self, DeviceAddr, EncryptedMessage, WrappedKey};
use mxc_omemo::store::OmemoStores;
use mxc_store::{secrets, Store};

use crate::client::{AccountConfig, Writer};
use crate::event::Event;
use crate::xeps::pep;
use crate::xeps::roster::new_id;

// PQ-OMEMO2 (proto-XEP OMEMO-PQXDH). Deliberately NOT urn:xmpp:omemo:2: this stack is
// wire-incompatible with XEP-0384 v0.9 (AES-256-GCM payload scheme, mandatory PQXDH v4
// handshake, mandatory hybrid PQ identity), so sharing the standard namespace would make
// genuine XEP-0384 clients fetch our bundles, burn prekeys and hard-fail undebuggably.
// Under a distinct namespace the two ecosystems simply ignore each other.
// MUST stay in lockstep with the Android client (Namespace.OMEMO2).
pub const NS_OMEMO2: &str = "urn:monocles:omemo-pq:1";
pub const NODE_DEVICES: &str = "urn:monocles:omemo-pq:1:devices";
pub const NODE_BUNDLES: &str = "urn:monocles:omemo-pq:1:bundles";
const NS_EME: &str = "urn:xmpp:eme:0";
const NS_CLIENT: &str = "jabber:client";
const NS_HINTS: &str = "urn:xmpp:hints";

const PREKEY_COUNT: u32 = 100;
const SIGNED_PREKEY_ID: u32 = 1;
const KEM_SIGNED_ID: u32 = 1;
const FIRST_PREKEY_ID: u32 = 100;
/// Replenish one-time pre-keys once the available count drops below this (proto-XEP §4.5).
const PREKEY_LOW_WATER: u32 = 50;

/// What `decrypt_message` recovers.
pub struct Decrypted {
    /// The SCE envelope XML bytes (to be parsed + binding-checked by the caller).
    pub envelope: Vec<u8>,
    pub sender_device: u32,
    pub fingerprint: String,
    /// True if this was a key-exchange (PreKey) message — it consumed a one-time pre-key,
    /// so the caller should replenish + republish the bundle.
    pub was_kex: bool,
    /// True if this was a key-transport message (a `<header>` with no `<payload>`): the session
    /// was (re)established as a side effect, but there is no content to display.
    pub key_transport: bool,
    /// True if this message's Double Ratchet counter reached the XEP-0384 heartbeat threshold and
    /// we have not yet heartbeated for its ratchet key: the caller should send a heartbeat back to
    /// `sender_device` (see [`send_heartbeat`]) to force a DH-ratchet step.
    pub heartbeat_due: bool,
}

// --- per-account store cache ------------------------------------------------

fn cache() -> &'static Mutex<HashMap<i64, OmemoStores>> {
    static C: OnceLock<Mutex<HashMap<i64, OmemoStores>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached(account_id: i64) -> Option<OmemoStores> {
    cache().lock().unwrap().get(&account_id).cloned()
}

// --- session-establishment failure cache ------------------------------------
//
// Without this, `sessions_for` re-fetches (over PEP) and re-attempts establishment for every
// device that has no session on *every* outgoing message. Since the hybrid post-quantum
// identity is mandatory, any device whose published bundle predates it fails deterministically
// and would otherwise be retried on each send — a burst of round-trips that delays (or, when it
// leaves no usable device, blocks) the message. We mirror the Android client's `fetchStatusMap`
// (`AxolotlService`), which marks such a device `FetchStatus.ERROR` and stops re-fetching it
// until its device list republishes. This is a pure availability/freshness optimization: it only
// suppresses *re-attempts*, never sends anything unencrypted/downgraded, and never touches
// signature verification, the TOFU pin, or trust.

/// How long a device whose session could not be established is skipped before we try its bundle
/// again. (Android keeps the error until the device list republishes; we additionally cap it with
/// this TTL so a re-keyed device recovers on its own.)
const ESTABLISH_RETRY_BACKOFF: Duration = Duration::from_secs(600);

type FailKey = (i64, String, u32);

fn establish_failures() -> &'static Mutex<HashMap<FailKey, Instant>> {
    static C: OnceLock<Mutex<HashMap<FailKey, Instant>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether we failed to establish a session with this device within the back-off window (so the
/// caller should skip the bundle re-fetch this round). Expired entries are evicted on read.
fn recently_failed(account_id: i64, jid: &str, device: u32) -> bool {
    let mut m = establish_failures().lock().unwrap();
    let key = (account_id, jid.to_string(), device);
    match m.get(&key) {
        Some(t) if t.elapsed() < ESTABLISH_RETRY_BACKOFF => true,
        Some(_) => {
            m.remove(&key);
            false
        }
        None => false,
    }
}

fn note_establish_failure(account_id: i64, jid: &str, device: u32) {
    establish_failures()
        .lock()
        .unwrap()
        .insert((account_id, jid.to_string(), device), Instant::now());
}

fn note_establish_success(account_id: i64, jid: &str, device: u32) {
    establish_failures().lock().unwrap().remove(&(account_id, jid.to_string(), device));
}

/// Last device list we saw per (account, JID), so a *change* can clear that JID's failure
/// entries — matching Android's `clearErrorsInFetchStatusMap` on a device-list update, so a
/// newly added or rotated device is retried at once instead of waiting out the back-off.
fn device_list_seen() -> &'static Mutex<HashMap<(i64, String), Vec<u32>>> {
    static C: OnceLock<Mutex<HashMap<(i64, String), Vec<u32>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record the device list just fetched for `jid`; if it differs from last time, drop that JID's
/// establish-failure entries so the changed set is re-evaluated immediately.
fn refresh_device_list(account_id: i64, jid: &str, devices: &[u32]) {
    let mut sorted = devices.to_vec();
    sorted.sort_unstable();
    let key = (account_id, jid.to_string());
    let changed = {
        let mut seen = device_list_seen().lock().unwrap();
        let changed = seen.get(&key).map(|prev| prev != &sorted).unwrap_or(true);
        seen.insert(key, sorted);
        changed
    };
    if changed {
        establish_failures()
            .lock()
            .unwrap()
            .retain(|(a, j, _), _| !(*a == account_id && j == jid));
    }
}

/// Forget all in-memory OMEMO2 establishment-failure and device-list snapshots for an account.
/// Paired with [`mxc_store::Store::reset_omemo2_peer_state`] by the "reset OMEMO2 identities"
/// action so peers are re-fetched and re-established immediately instead of waiting out the
/// failure back-off.
pub fn forget_caches(account_id: i64) {
    establish_failures().lock().unwrap().retain(|(a, _, _), _| *a != account_id);
    device_list_seen().lock().unwrap().retain(|(a, _), _| *a != account_id);
    heartbeat_sent().lock().unwrap().retain(|(a, _, _), _| *a != account_id);
}

/// Drop the cached in-memory [`OmemoStores`] for an account, so the next OMEMO2 operation
/// reloads the identity from disk — or, after [`regenerate_own_identity`] wiped it, generates
/// a brand-new one. Without this, the old identity key pair would keep being used from memory.
pub fn forget_stores(account_id: i64) {
    cache().lock().unwrap().remove(&account_id);
}

/// Drop the establish-failure cache entries for a single peer, so the next outgoing message
/// re-fetches their bundle and rebuilds the session immediately instead of waiting out the
/// back-off. Called when we receive a message from them we cannot decrypt (e.g. a stale session
/// after a one-sided OMEMO2 reset) — the standard self-healing trigger.
pub fn forget_jid_failures(account_id: i64, jid: &str) {
    establish_failures()
        .lock()
        .unwrap()
        .retain(|(a, j, _), _| !(*a == account_id && j == jid));
}

/// Rate-limit window for [`heal_session`] per device, to avoid heal storms / handshake ping-pong.
const HEAL_COOLDOWN: Duration = Duration::from_secs(300);

fn heal_attempts() -> &'static Mutex<HashMap<FailKey, Instant>> {
    static C: OnceLock<Mutex<HashMap<FailKey, Instant>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether we may heal this device now (and record the attempt). At most one per `HEAL_COOLDOWN`.
fn may_heal(account_id: i64, jid: &str, device: u32) -> bool {
    let mut m = heal_attempts().lock().unwrap();
    let key = (account_id, jid.to_string(), device);
    match m.get(&key) {
        Some(t) if t.elapsed() < HEAL_COOLDOWN => false,
        _ => {
            m.insert(key, Instant::now());
            true
        }
    }
}

/// Devices we already attempted a background pq_ik pin reconciliation for this app run (see
/// [`reconcile_pq_pin_if_missing`]) — at most one bundle fetch per device per run, whether or
/// not it succeeds, so a peer that never publishes a usable bundle cannot cause fetch loops.
fn pq_pin_reconcile_attempts() -> &'static Mutex<HashSet<FailKey>> {
    static C: OnceLock<Mutex<HashSet<FailKey>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashSet::new()))
}

// --- user notices -----------------------------------------------------------

/// Per-account UI event channel, registered at OMEMO bootstrap. The places that detect a
/// post-quantum identity change (session building on send, heal, pin reconciliation) are deep in
/// call chains that carry no event sender; this lets them still reach the user.
fn event_sinks() -> &'static Mutex<HashMap<i64, Sender<Event>>> {
    static C: OnceLock<Mutex<HashMap<i64, Sender<Event>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_event_sink(account_id: i64, events: &Sender<Event>) {
    event_sinks().lock().unwrap().insert(account_id, events.clone());
}

/// (account, JID, pin key) whose post-quantum identity change the user was already told about.
fn pq_identity_change_notified() -> &'static Mutex<HashSet<(i64, String, String)>> {
    static C: OnceLock<Mutex<HashSet<(i64, String, String)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Tell the user — once per device per app run — that a contact's post-quantum identity changed
/// and is refused until re-verified (proto-XEP §4.9.2). Refusing is the security rule; telling
/// the user is what keeps a legitimate change (e.g. a restore from a backup without the PQ key)
/// from silently cutting the contact off. Mirrors Android's `notifyOmemo2PqIdentityChanged`.
fn notify_pq_identity_changed(account_id: i64, jid: &str, fp_key: &str) {
    if !pq_identity_change_notified().lock().unwrap().insert((
        account_id,
        jid.to_string(),
        fp_key.to_string(),
    )) {
        return;
    }
    warn!(%jid, "omemo: post-quantum identity CHANGED — refused until re-verified");
    let sink = event_sinks().lock().unwrap().get(&account_id).cloned();
    if let Some(events) = sink {
        let _ = events.try_send(Event::Toast {
            text: format!(
                "The post-quantum identity of {jid} changed. New PQ OMEMO2 sessions with that \
                 device are blocked until you verify it again by scanning their QR code."
            ),
            important: true,
        });
    }
}

/// Forget an earlier notice once the user re-verified the device, so a later change is reported.
fn clear_pq_identity_notice(account_id: i64, jid: &str, fp_key: &str) {
    pq_identity_change_notified().lock().unwrap().remove(&(
        account_id,
        jid.to_string(),
        fp_key.to_string(),
    ));
}

/// If `err` is a refused post-quantum identity change, tell the user.
fn notice_if_pq_identity_changed(account_id: i64, jid: &str, err: &mxc_omemo::OmemoError) {
    if let mxc_omemo::OmemoError::PqIdentityChanged(fp_key) = err {
        notify_pq_identity_changed(account_id, jid, fp_key);
    }
}

/// XEP-0384 heartbeat threshold: the first message received for a given ratchet key whose Double
/// Ratchet counter reaches this value MUST be answered with a heartbeat (an empty OMEMO message),
/// forcing a DH-ratchet step so the peer's next chain restarts at 0.
const HEARTBEAT_COUNTER_THRESHOLD: u32 = 53;

/// The sender ratchet key we last sent a heartbeat for, per peer device. Lets us honour the spec's
/// "the *first* message for a given ratchet key" wording: we heartbeat once per receiving chain, so
/// a burst of in-flight messages already past the threshold can't cause a heartbeat storm.
fn heartbeat_sent() -> &'static Mutex<HashMap<FailKey, Vec<u8>>> {
    static C: OnceLock<Mutex<HashMap<FailKey, Vec<u8>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether a heartbeat is due for this peer device given a freshly-received message's
/// `(counter, ratchet_key)`: true only when the counter is at/over the threshold AND we have not
/// already heartbeated for this exact ratchet key. Records the ratchet key on a `true` result so
/// the next message in the same chain is a no-op.
fn heartbeat_due(account_id: i64, jid: &str, device: u32, counter: u32, ratchet_key: &[u8]) -> bool {
    if counter < HEARTBEAT_COUNTER_THRESHOLD {
        return false;
    }
    let mut m = heartbeat_sent().lock().unwrap();
    let key = (account_id, jid.to_string(), device);
    if m.get(&key).map(|prev| prev.as_slice() == ratchet_key).unwrap_or(false) {
        return false;
    }
    m.insert(key, ratchet_key.to_vec());
    true
}

/// Load (or first-time create) this account's OMEMO identity + stores.
/// Returns `(stores, freshly_created)`.
async fn load_or_create(store: &Store, cfg: &AccountConfig) -> anyhow::Result<(OmemoStores, bool)> {
    if let Some(s) = cached(cfg.account_id) {
        return Ok((s, false));
    }
    let dev = store.omemo_own_device_id(cfg.account_id).await?;
    let id_bytes = secrets::retrieve(secrets::kinds::OMEMO_IDENTITY, &cfg.jid).await?;
    let pq_bytes = secrets::retrieve(secrets::kinds::OMEMO_PQ_IDENTITY, &cfg.jid).await?;

    let (stores, fresh) = match (dev, id_bytes) {
        (Some(dev), Some(bytes)) => {
            // Existing classical OMEMO2 identity. Add a post-quantum half if this install
            // predates the hybrid identity — the classical identity (and its fingerprint)
            // is untouched, so no re-verification is needed; the bundle simply gains a
            // <pq-ik> on the next republish.
            let pq_bytes = match pq_bytes {
                Some(p) => p,
                None => {
                    let p = session::new_pq_identity_bytes();
                    secrets::store(secrets::kinds::OMEMO_PQ_IDENTITY, &cfg.jid, &p).await?;
                    p
                }
            };
            let s = session::stores_from_identity(
                store.clone(),
                cfg.account_id,
                &bytes,
                &pq_bytes,
                dev as u32,
            )
            .map_err(|e| anyhow::anyhow!("load omemo identity: {e}"))?;
            store
                .set_omemo_own_pq_identity_pub(cfg.account_id, &s.pq_identity_public_bytes())
                .await?;
            (s, false)
        }
        _ => {
            let (identity_bytes, pq_identity_bytes, device_id) = session::new_identity_bytes();
            secrets::store(secrets::kinds::OMEMO_IDENTITY, &cfg.jid, &identity_bytes).await?;
            secrets::store(secrets::kinds::OMEMO_PQ_IDENTITY, &cfg.jid, &pq_identity_bytes).await?;
            let s = session::stores_from_identity(
                store.clone(),
                cfg.account_id,
                &identity_bytes,
                &pq_identity_bytes,
                device_id,
            )
            .map_err(|e| anyhow::anyhow!("create omemo identity: {e}"))?;
            store
                .set_omemo_own_identity(cfg.account_id, device_id as i64, &s.identity_public_bytes(), true)
                .await?;
            store
                .set_omemo_own_pq_identity_pub(cfg.account_id, &s.pq_identity_public_bytes())
                .await?;
            store.set_omemo_device_id(cfg.account_id, device_id as i64).await?;
            (s, true)
        }
    };
    cache().lock().unwrap().insert(cfg.account_id, stores.clone());
    Ok((stores, fresh))
}

async fn stores(store: &Store, cfg: &AccountConfig) -> anyhow::Result<OmemoStores> {
    Ok(load_or_create(store, cfg).await?.0)
}

/// Our own OMEMO2 device id (registration id), advertised in JMI for OMEMO-verified calls.
pub async fn own_device_id(store: &Store, cfg: &AccountConfig) -> anyhow::Result<u32> {
    Ok(stores(store, cfg).await?.registration_id())
}

// --- bootstrap --------------------------------------------------------------

/// Ensure our identity exists, our bundle is published, and our device id is in the
/// device list. Called from bootstrap (best-effort).
pub async fn ensure_initialized(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
) -> anyhow::Result<()> {
    register_event_sink(cfg.account_id, events);
    let device_id = maintain_and_republish(w, store, cfg).await?;
    // A device id retired by an identity regeneration whose list update failed is removed now.
    let retired = retired_device(store, cfg.account_id).await.filter(|old| *old != device_id);
    publish_device_list_replacing(w, cfg, device_id, retired).await?;
    if retired.is_some() {
        set_retired_device(store, cfg.account_id, None).await?;
    }
    Ok(())
}

/// The setting under which a device id retired by [`regenerate_own_identity`] waits to be
/// removed from our device list (per account; the settings table is app-wide).
fn retired_device_key(account_id: i64) -> String {
    format!("omemo2_retired_device_id:{account_id}")
}

async fn retired_device(store: &Store, account_id: i64) -> Option<u32> {
    store.setting(&retired_device_key(account_id)).await.ok().flatten().and_then(|v| v.parse().ok())
}

/// Record (`Some`) or clear (`None`, an empty value) the retired device id.
async fn set_retired_device(store: &Store, account_id: i64, device: Option<u32>) -> anyhow::Result<()> {
    let value = device.map(|d| d.to_string()).unwrap_or_default();
    store.set_setting(&retired_device_key(account_id), &value).await?;
    Ok(())
}

/// LAST-RESORT full identity regeneration (the desktop counterpart of Android's
/// "Delete OMEMO identities"): wipe our own hybrid identity — classical + ML-DSA-87 key
/// pairs, device id, every pre-key — plus all peer state, then generate and publish a
/// brand-new identity. This device gets a NEW fingerprint; contacts MUST verify it again.
///
/// Order matters: capture the old device id first (to retract its bundle and prune it from
/// the PEP device list), wipe disk state, delete the private-key secrets, drop the in-memory
/// stores (else the old key pair would keep being used from cache), and only then
/// re-initialize — `load_or_create` sees no own-identity row and mints a fresh identity.
pub async fn regenerate_own_identity(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
) -> anyhow::Result<()> {
    let old_device = store
        .omemo_own_device_id(cfg.account_id)
        .await?
        .map(|d| d as u32);
    warn!(account = cfg.account_id, old_device, "omemo: REGENERATING own identity (last resort)");
    // Remember the old id before anything is wiped: if the device-list update at the end fails
    // (e.g. the read times out), the next bootstrap still removes it (see ensure_initialized),
    // instead of leaving a device advertised whose bundle is gone.
    if old_device.is_some() {
        set_retired_device(store, cfg.account_id, old_device).await?;
    }
    store.reset_omemo2_own_state(cfg.account_id).await?;
    store.reset_omemo2_peer_state(cfg.account_id).await?;
    // Belt and braces: load_or_create would overwrite these anyway once the own-identity row
    // is gone, but a possibly compromised private key should not linger in the keyring for
    // even a moment longer than necessary.
    let _ = secrets::delete(secrets::kinds::OMEMO_IDENTITY, &cfg.jid).await;
    let _ = secrets::delete(secrets::kinds::OMEMO_PQ_IDENTITY, &cfg.jid).await;
    forget_stores(cfg.account_id);
    forget_caches(cfg.account_id);
    // Retract the old bundle so peers can no longer fetch the retired (possibly compromised)
    // key material. Best-effort: the node item may already be gone.
    if let Some(old) = old_device {
        let _ = pep::retract(w, NODE_BUNDLES, &old.to_string()).await;
    }
    // Mint + publish the new identity, and swap the old device id for the new one in the
    // device list (other devices on the account are preserved).
    let device_id = maintain_and_republish(w, store, cfg).await?;
    publish_device_list_replacing(w, cfg, device_id, old_device).await?;
    set_retired_device(store, cfg.account_id, None).await?;
    Ok(())
}

/// (Re)build the bundle from the keys we currently hold — generating the initial set on
/// first use, and topping up one-time pre-keys when low — then publish it. Keeps the
/// advertised bundle in sync with what's actually usable. Returns our device id.
pub async fn maintain_and_republish(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
) -> anyhow::Result<u32> {
    let stores = stores(store, cfg).await?;
    let device_id = stores.registration_id();
    let bundle = session::maintain_bundle(
        &stores,
        SIGNED_PREKEY_ID,
        KEM_SIGNED_ID,
        FIRST_PREKEY_ID,
        PREKEY_COUNT,
        PREKEY_LOW_WATER,
    )
    .await
    .map_err(|e| anyhow::anyhow!("maintain bundle: {e}"))?;
    debug!(
        device_id,
        has_pq_identity = bundle.has_pq_identity(),
        pq_ik_len = bundle.pq_ik.len(),
        ec_prekeys = bundle.prekeys.len(),
        "omemo: (re)publishing own bundle"
    );
    store.set_omemo_bundle_xml(cfg.account_id, &bundle.to_xml()).await?;
    publish_bundle(w, device_id, &bundle).await?;
    Ok(device_id)
}

async fn publish_bundle(w: &Writer, device_id: u32, bundle: &Bundle) -> anyhow::Result<()> {
    publish_bundle_xml(w, device_id, &bundle.to_xml()).await
}

async fn publish_bundle_xml(w: &Writer, device_id: u32, xml: &str) -> anyhow::Result<()> {
    let payload: Element = xml.parse().map_err(|e| anyhow::anyhow!("serialize bundle: {e}"))?;
    pep::publish(
        w,
        NODE_BUNDLES,
        Some(&device_id.to_string()),
        payload,
        Some(pep::publish_options("open")),
    )
    .await?;
    Ok(())
}

/// A device list as far as it can be known: the list we read, empty if the node doesn't exist
/// (`item-not-found` - nothing published, so no devices), or an error for any other failure,
/// where the real list is unknown. A read-modify-write publish must not go ahead on that error:
/// it would overwrite the real list with one built from nothing.
fn existing_device_list(read: anyhow::Result<Vec<u32>>) -> anyhow::Result<Vec<u32>> {
    match read {
        Ok(ids) => Ok(ids),
        Err(e) if e.to_string().contains("item-not-found") => Ok(Vec::new()),
        Err(e) => Err(anyhow::anyhow!("reading the device list failed: {e}")),
    }
}

async fn publish_device_list(w: &Writer, cfg: &AccountConfig, device_id: u32) -> anyhow::Result<()> {
    publish_device_list_replacing(w, cfg, device_id, None).await
}

/// Publish our account's OMEMO2 device list containing `device_id`, optionally dropping
/// `remove` (our previous device id after an identity regeneration — its bundle is gone, so
/// leaving it advertised would make peers try, and fail, to encrypt to it). Other devices'
/// ids are preserved.
///
/// The current list is read first and only a node that doesn't exist yet (`item-not-found`)
/// counts as empty. Any other failure (timeout, server error) aborts without publishing: a list
/// built from a failed read would hold only our device and drop every other live one, and
/// peers would stop encrypting to them. Callers treat the error as "retry later" (bootstrap
/// logs it; our own device-list notification re-announces).
async fn publish_device_list_replacing(
    w: &Writer,
    cfg: &AccountConfig,
    device_id: u32,
    remove: Option<u32>,
) -> anyhow::Result<()> {
    let mut ids = existing_device_list(fetch_device_list(w, cfg.bare()).await)
        .map_err(|e| anyhow::anyhow!("not publishing our device list: {e}"))?;
    if at_device_cap(&ids) {
        // Possibly truncated by the parser: publishing it would drop every device past the cap.
        anyhow::bail!("not publishing our device list: it is at the {MAX_DEVICES_PER_JID}-device cap");
    }
    if let Some(old) = remove {
        ids.retain(|id| *id != old);
    }
    if !ids.contains(&device_id) {
        ids.push(device_id);
    }
    let mut devices = Element::builder("devices", NS_OMEMO2);
    for id in &ids {
        devices = devices.append(Element::builder("device", NS_OMEMO2).attr(crate::ncname("id"), id.to_string()).build());
    }
    pep::publish(w, NODE_DEVICES, Some("current"), devices.build(), Some(pep::publish_options("open")))
        .await?;
    Ok(())
}

// --- fetch ------------------------------------------------------------------

/// Most devices we accept from one JID's published OMEMO2 device list.
///
/// Every accepted id costs an outbound bundle fetch (see [`sessions_for`]) plus a stored session
/// and a cached failure entry, and nothing else bounds the list — the XML reader limits nesting
/// depth, not child count — so a hostile PEP node could turn one device-list fetch into tens of
/// thousands of IQ round-trips. Far above any plausible real account; the key UI is unusable long
/// before it. Matches monocles Android's `AxolotlService.MAX_DEVICES_PER_JID`.
pub const MAX_DEVICES_PER_JID: usize = 128;

/// Most wrapped keys we will try to unwrap for **our own device** out of one message header.
///
/// A header legitimately carries one `<key rid='us'>`; two is the known benign case (a sender
/// that rebuilt the session mid-send and attached both the old and the new wrap). Nothing in the
/// format forbids more, and each one costs a full trial ratchet decryption, so an unbounded list
/// turns a single stanza into as much CPU as the sender cares to ask for. Eight leaves generous
/// room above every legitimate case while bounding the work per stanza.
///
/// The cap is on *attempts*, not on trust: the wraps past it are ignored, exactly as if the
/// sender had not sent them.
pub const MAX_KEY_CANDIDATES: usize = 8;

async fn fetch_device_list(w: &Writer, jid: &str) -> anyhow::Result<Vec<u32>> {
    let reply = pep::items(w, Some(jid), NODE_DEVICES, Some(1)).await?;
    let mut out = Vec::new();
    for (_, payload) in pep::extract_items(&reply) {
        if payload.name() == "devices" {
            parse_devices(jid, &payload, &mut out);
        }
    }
    Ok(out)
}

/// Whether a device list we parsed may have been cut off at [`MAX_DEVICES_PER_JID`]. Then a
/// device "missing" from it may just sit past the cap, and a list rebuilt from it would drop
/// every device beyond the cap, so it must not drive a re-announce or a publish.
fn at_device_cap(devices: &[u32]) -> bool {
    devices.len() >= MAX_DEVICES_PER_JID
}

/// Append the device ids of a `<devices>` payload to `out`, up to [`MAX_DEVICES_PER_JID`] in
/// total. Shared by fetches and live notifications, so both obey the same cap.
fn parse_devices(jid: &str, payload: &Element, out: &mut Vec<u32>) {
    for d in payload.children().filter(|c| c.name() == "device") {
        if out.len() >= MAX_DEVICES_PER_JID {
            warn!(%jid, cap = MAX_DEVICES_PER_JID,
                "omemo: device list exceeds the cap — ignoring the rest");
            break;
        }
        if let Some(id) = d.attr("id").and_then(|s| s.parse::<u32>().ok()) {
            out.push(id);
        }
    }
}

// --- live device-list notifications -----------------------------------------

const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";

/// Base cooldown between two re-announcements of our own device triggered by notifications.
/// It doubles with every re-announce that follows soon after the previous one - another client
/// keeps removing us, e.g. Android's OMEMO auto-expiry (on by default) pruning a long-idle
/// device - up to [`OWN_REANNOUNCE_COOLDOWN_MAX`], and drops back to the base after a quiet
/// period. A fight then costs a few publishes a day instead of one a minute.
const OWN_REANNOUNCE_COOLDOWN: Duration = Duration::from_secs(60);
const OWN_REANNOUNCE_COOLDOWN_MAX: Duration = Duration::from_secs(6 * 60 * 60);
/// The streak at which the fight is reported (once per streak).
const OWN_REANNOUNCE_WARN_STREAK: u32 = 3;

/// The last re-announce of an account and how many came in quick succession before it.
#[derive(Debug, Clone, Copy)]
struct Reannounced {
    at: Instant,
    streak: u32,
}

fn own_reannounced() -> &'static Mutex<HashMap<i64, Reannounced>> {
    static C: OnceLock<Mutex<HashMap<i64, Reannounced>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The cooldown after a re-announce with the given streak: base · 2^streak, capped.
fn reannounce_cooldown(streak: u32) -> Duration {
    1u32.checked_shl(streak)
        .and_then(|factor| OWN_REANNOUNCE_COOLDOWN.checked_mul(factor))
        .map_or(OWN_REANNOUNCE_COOLDOWN_MAX, |d| d.min(OWN_REANNOUNCE_COOLDOWN_MAX))
}

/// Whether we may re-announce our own device now (and record the attempt).
fn may_reannounce_own_device(account_id: i64) -> bool {
    let mut m = own_reannounced().lock().unwrap();
    let streak = match m.get(&account_id) {
        Some(last) => {
            let cooldown = reannounce_cooldown(last.streak);
            let elapsed = last.at.elapsed();
            if elapsed < cooldown {
                return false;
            }
            // Soon after the previous one: someone keeps removing us, so back off further.
            if elapsed > cooldown.saturating_mul(2) { 0 } else { last.streak.saturating_add(1) }
        }
        None => 0,
    };
    if streak == OWN_REANNOUNCE_WARN_STREAK {
        warn!(
            account_id,
            next_cooldown_secs = reannounce_cooldown(streak).as_secs(),
            "omemo: another client keeps removing this device from our OMEMO device list \
             (OMEMO auto-expiry?); backing off"
        );
    }
    m.insert(account_id, Reannounced { at: Instant::now(), streak });
    true
}

/// How long until the account's re-announce cooldown is over (zero if it already is).
fn reannounce_cooldown_left(account_id: i64) -> Duration {
    own_reannounced()
        .lock()
        .unwrap()
        .get(&account_id)
        .map(|last| reannounce_cooldown(last.streak).saturating_sub(last.at.elapsed()))
        .unwrap_or_default()
}

/// Accounts with a deferred re-announce waiting for the cooldown to end (at most one each).
fn reannounce_scheduled() -> &'static Mutex<HashSet<i64>> {
    static C: OnceLock<Mutex<HashSet<i64>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Clears an account's [`reannounce_scheduled`] entry when dropped.
struct ScheduledGuard(i64);

impl Drop for ScheduledGuard {
    fn drop(&mut self) {
        reannounce_scheduled().lock().unwrap().remove(&self.0);
    }
}

/// Our device was dropped from our own list while the re-announce cooldown was running: try
/// again once it is over, instead of staying unannounced until the next notification or login
/// (peers don't encrypt to a device missing from the list, so messages to it would be lost).
///
/// At most one retry is pending per account. When it fires it reads the list afresh - another
/// client, or an earlier notification, may have put us back meanwhile - and only re-announces
/// if we are still missing, through the same re-fetching [`publish_device_list`] path. A failed
/// read changes nothing. The task lives on the connection's runtime, so it ends with it.
fn schedule_own_reannounce(w: Writer, cfg: AccountConfig, device: u32) {
    let account_id = cfg.account_id;
    if !reannounce_scheduled().lock().unwrap().insert(account_id) {
        return; // a retry is already waiting
    }
    // Owned by the task: if its runtime drops it mid-sleep (a reconnect), the entry is still
    // cleared, so a later removal can schedule a new retry.
    let scheduled = ScheduledGuard(account_id);
    let wait = reannounce_cooldown_left(account_id);
    tokio::task::spawn_local(async move {
        tokio::time::sleep(wait).await;
        drop(scheduled);
        match existing_device_list(fetch_device_list(&w, cfg.bare()).await) {
            Ok(devices) if devices.contains(&device) => {
                debug!(device, "omemo: our device is back in our device list; no re-announce needed");
            }
            Ok(devices) if at_device_cap(&devices) => {
                warn!(cap = MAX_DEVICES_PER_JID, "omemo: our device list is at the device cap; not re-announcing from it");
            }
            Ok(_) => {
                if may_reannounce_own_device(account_id) {
                    info!(device, "omemo: our device is still missing after the cooldown; re-announcing it");
                    if let Err(e) = publish_device_list(&w, &cfg, device).await {
                        warn!(error = %e, "omemo: re-announcing our device");
                    }
                } else {
                    // Another re-announce just happened (and its own notification will tell).
                    debug!(device, "omemo: re-announce already done meanwhile");
                }
            }
            Err(e) => warn!(error = %e, "omemo: could not read our device list for the deferred re-announce"),
        }
    });
}

/// Whether a `pubsub#event` deletes or purges the device-list node. That is definitive (no
/// devices published any more), unlike an `<items>` notification without payload.
fn device_list_cleared(event: &Element) -> bool {
    ["delete", "purge"]
        .iter()
        .any(|action| event.get_child(action, NS_PUBSUB_EVENT).is_some_and(|el| el.attr("node") == Some(NODE_DEVICES)))
}

/// The device ids carried by a device-list notification's `<items>`: `Some` with the ids of
/// the (last) published `<devices>` payload, `None` if no item carries one (a notification
/// without payload, or a retraction) - the caller then asks the node itself.
fn devices_in_notification(jid: &str, items: &Element) -> Option<Vec<u32>> {
    let payload = items
        .children()
        .filter(|c| c.name() == "item")
        .filter_map(|item| item.get_child("devices", NS_OMEMO2))
        .last()?;
    let mut out = Vec::new();
    parse_devices(jid, payload, &mut out);
    Some(out)
}

/// Handle a PEP notification for an OMEMO2 device list (`+notify` on [`NODE_DEVICES`]).
/// Returns true if it was one (and thus consumed).
///
/// What it does - and deliberately doesn't:
/// * clears the JID's establish-failure back-off when its list changed, so a new device is
///   tried on the very next send (encryption itself still re-fetches the list every time);
/// * marks the JID's known devices active/inactive for the key screens and refreshes them;
/// * for our own account: if our device is missing from the list, re-announces it through
///   the re-fetching [`publish_device_list`] path (never a locally held list, and never removing
///   anyone - see the device-list pruning rules), rate-limited by [`OWN_REANNOUNCE_COOLDOWN`];
///   a removal during the cooldown is retried when it ends ([`schedule_own_reannounce`]).
///
/// Nothing is deleted and no trust changes, so a forged or transient list can at worst grey
/// devices out until the next one. Only bare-JID senders count (see
/// [`super::origin::pubsub_event_origin`]).
pub async fn handle_device_list_event(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    msg: &Element,
) -> bool {
    let Some(event) = msg.get_child("event", NS_PUBSUB_EVENT) else {
        return false;
    };
    let items = event.get_child("items", NS_PUBSUB_EVENT).filter(|i| i.attr("node") == Some(NODE_DEVICES));
    let cleared = device_list_cleared(event);
    if items.is_none() && !cleared {
        return false;
    }
    let Some(jid) = super::origin::pubsub_event_origin(msg.attr("from"), cfg.bare()) else {
        debug!(from = ?msg.attr("from"), "omemo: ignoring device-list event from a non-bare JID");
        return true;
    };
    let own = jid.eq_ignore_ascii_case(cfg.bare());
    let jid = if own { cfg.bare().to_string() } else { jid };

    let carried = match items {
        Some(items) => devices_in_notification(&jid, items),
        // The node was deleted or purged: no devices (for us, re-announced below).
        None => Some(Vec::new()),
    };
    let devices = match carried {
        Some(devices) => devices,
        None => match existing_device_list(fetch_device_list(w, &jid).await) {
            Ok(devices) => devices,
            Err(e) => {
                // Can't tell what the list is now: change nothing rather than guess.
                debug!(%jid, error = %e, "omemo: device-list notification without payload; fetch failed");
                return true;
            }
        },
    };
    debug!(%jid, ?devices, "omemo: device-list notification");
    refresh_device_list(cfg.account_id, &jid, &devices);

    let own_device = if own {
        store.omemo_own_device_id(cfg.account_id).await.ok().flatten().and_then(|d| u32::try_from(d).ok())
    } else {
        None
    };
    let changed = store
        .set_omemo_devices_active(cfg.account_id, &jid, &devices, own_device)
        .await
        .unwrap_or_else(|e| {
            warn!(%jid, error = %e, "omemo: updating device activity");
            false
        });

    if own {
        if at_device_cap(&devices) && own_device.is_some_and(|d| !devices.contains(&d)) {
            warn!(cap = MAX_DEVICES_PER_JID, "omemo: our device list is at the device cap; not re-announcing from it");
        } else if let Some(device) = own_device.filter(|d| !devices.contains(d)) {
            if may_reannounce_own_device(cfg.account_id) {
                info!(device, "omemo: our device is missing from our device list; re-announcing it");
                if let Err(e) = publish_device_list(w, cfg, device).await {
                    warn!(error = %e, "omemo: re-announcing our device");
                }
            } else {
                debug!(device, "omemo: our device is missing from our device list; retrying after the cooldown");
                schedule_own_reannounce(w.clone(), cfg.clone(), device);
            }
        }
        if changed {
            let _ = crate::client::send_own_keys(store, events, cfg, cfg.account_id).await;
        }
    } else if changed {
        let _ = crate::client::send_contact_keys(store, events, cfg.account_id, jid).await;
    }
    true
}

async fn fetch_bundle(w: &Writer, jid: &str, device: u32) -> anyhow::Result<Bundle> {
    let reply = pep::item(w, Some(jid), NODE_BUNDLES, &device.to_string()).await?;
    let (_, payload) = pep::extract_items(&reply)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no bundle for {jid}/{device}"))?;
    Bundle::from_xml(&String::from(&payload)).map_err(|e| anyhow::anyhow!("parse bundle: {e}"))
}

/// Fetch `jid`'s device list and ensure a session exists for each device, returning the
/// addresses we can encrypt to. Devices whose bundle can't be fetched are skipped.
async fn sessions_for(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    stores: &OmemoStores,
    jid: &str,
    our_device: u32,
) -> anyhow::Result<Vec<DeviceAddr>> {
    let devices = fetch_device_list(w, jid).await.unwrap_or_default();
    // Clear stale failure entries for this JID if its device list changed (Android parity).
    refresh_device_list(cfg.account_id, jid, &devices);
    let mut out = Vec::new();
    for dev in devices {
        if jid == cfg.bare() && dev == our_device {
            continue; // never encrypt to ourselves
        }
        let addr = DeviceAddr { jid: jid.to_string(), device_id: dev };
        let has_session = store
            .load_omemo_session(cfg.account_id, jid, dev as i64)
            .await?
            .is_some();
        if !has_session {
            // Skip a device whose session establishment recently failed (e.g. its published
            // bundle has no post-quantum identity, or no bundle at all), so we don't re-fetch
            // it on every send.
            if recently_failed(cfg.account_id, jid, dev) {
                debug!(%jid, dev, "omemo: skipping device (recent establish failure cached)");
                continue;
            }
            match fetch_bundle(w, jid, dev).await {
                Ok(bundle) => {
                    match session::establish_session(stores, cfg.bare(), our_device, &addr, &bundle)
                        .await
                    {
                        Ok(()) => {
                            debug!(%jid, dev, "omemo: session established");
                            note_establish_success(cfg.account_id, jid, dev);
                        }
                        Err(e) => {
                            warn!(%jid, dev, error = %e, "omemo: session establishment failed");
                            notice_if_pq_identity_changed(cfg.account_id, jid, &e);
                            note_establish_failure(cfg.account_id, jid, dev);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    warn!(%jid, dev, error = %e, "omemo: bundle fetch/parse failed");
                    note_establish_failure(cfg.account_id, jid, dev);
                    continue;
                }
            }
        }
        // Only encrypt to *trusted* devices: trust == 1 (BTBV-trusted) or trust == 3 (manually
        // verified). Establishing the session above saved the identity with its initial trust
        // (1 if "auto-trust new keys" is on, else 0 = undecided); undecided (0) / untrusted (2)
        // devices are skipped until the user enables them.
        let trusted = store
            .omemo_identity(cfg.account_id, jid, dev as i64)
            .await?
            .map(|id| id.trust == 1 || id.trust == 3)
            .unwrap_or(false);
        if trusted {
            out.push(addr);
        } else {
            debug!(%jid, dev, "omemo: device has a session but is not trusted — not encrypting to it");
        }
    }
    debug!(%jid, usable_devices = out.len(), "omemo: sessions_for done");
    Ok(out)
}

// --- encrypt / decrypt ------------------------------------------------------

/// Encrypt an SCE envelope for `to_bare` (+ our own other devices) and return the
/// `<encrypted>` element ready to attach to a message.
pub async fn encrypt_for(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    to_bare: &str,
    envelope_xml: &[u8],
) -> anyhow::Result<Element> {
    // 1:1: the single recipient is also the payload context-binding recipient (§5.4.2).
    encrypt_for_recipients(w, store, cfg, &[to_bare.to_string()], Some(to_bare), envelope_xml).await
}

/// Encrypt an SCE envelope for every bare JID in `recipients` (+ our own other devices) and
/// return the `<encrypted>` element. Used both for 1:1 (a single recipient) and for an
/// encrypted MUC (one entry per room member's real bare JID — see `muc_member_jids`). Devices
/// whose bundle can't be fetched, or that aren't trusted, are skipped; if that leaves no
/// recipient at all the call fails so we never send an undeliverable ciphertext.
///
/// `binding_to` is the single recipient bare JID bound into the payload's context binding
/// (§5.4.2) — the counterpart for a 1:1 or the room JID for a MUC (i.e. the SCE `<to>`), or
/// `None` when it can't be canonicalised (a MUC private message), matching the receiver.
pub async fn encrypt_for_recipients(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    recipients: &[String],
    binding_to: Option<&str>,
    envelope_xml: &[u8],
) -> anyhow::Result<Element> {
    let stores = stores(store, cfg).await?;
    let our_device = stores.registration_id();

    let mut addrs = Vec::new();
    for jid in recipients {
        // Our own bare JID is handled once below (sessions_for skips our sending device).
        if jid.eq_ignore_ascii_case(cfg.bare()) {
            continue;
        }
        addrs.extend(sessions_for(w, store, cfg, &stores, jid, our_device).await?);
    }
    // Devices of the actual recipient(s), counted BEFORE our own are added: the check below has
    // to be "did we wrap for anyone we are writing to", not "did we wrap for anyone at all"
    // (proto-XEP §4.6.9). sessions_for() drops untrusted and unreachable devices, so a peer whose
    // devices are all untrusted contributes nothing — and with another device of our own in the
    // list the send would still have gone out, readable by us alone, and been reported as sent
    // while the peer saw a "not encrypted for this device" placeholder.
    let recipient_devices = addrs.len();
    // Always also encrypt to our own other devices so they (and carbons) can decrypt.
    addrs.extend(sessions_for(w, store, cfg, &stores, cfg.bare(), our_device).await?);

    // Note-to-self parity with Android (`acceptEmpty` for `isSelf()` chats): when the only
    // recipient is our own account, permit an *empty* recipient set so a single-device self-note
    // still sends. The payload is still sealed; the `<header>` just carries no `<key>` until we
    // own another device (later self-notes then wrap to it normally). For any other recipient we
    // keep refusing to emit ciphertext that nobody can read.
    let note_to_self =
        !recipients.is_empty() && recipients.iter().all(|j| j.eq_ignore_ascii_case(cfg.bare()));
    if recipient_devices == 0 && !note_to_self {
        anyhow::bail!("no trusted OMEMO2 device for the recipient(s)");
    }

    let enc = session::encrypt(&stores, cfg.bare(), our_device, &addrs, binding_to, envelope_xml)
        .await
        .map_err(|e| anyhow::anyhow!("omemo encrypt: {e}"))?;
    Ok(build_encrypted(&enc, our_device))
}

/// Build the OMEMO2 `<header sid><keys jid><key rid kex>…` element (the wrapped per-device keys).
fn build_header(enc: &EncryptedMessage, sender_device: u32) -> Element {
    let mut by_jid: BTreeMap<&str, Vec<&WrappedKey>> = BTreeMap::new();
    for k in &enc.keys {
        by_jid.entry(k.jid.as_str()).or_default().push(k);
    }

    let mut header = Element::builder("header", NS_OMEMO2).attr(crate::ncname("sid"), sender_device.to_string());
    // Handshake authentication (proto-XEP §4.9.7): session::encrypt signs it whenever a key is a
    // pre-key message, so it is present exactly when a receiver will require it.
    if let Some(auth) = &enc.pq_auth {
        header = header.append(
            Element::builder("pq-auth", NS_OMEMO2)
                .append(
                    Element::builder("pq-ik", NS_OMEMO2)
                        .attr(crate::ncname("type"), "ML-DSA-87")
                        .append(B64.encode(&auth.pq_ik))
                        .build(),
                )
                .append(Element::builder("pq-sig", NS_OMEMO2).append(B64.encode(&auth.pq_sig)).build())
                .append(Element::builder("ik-sig", NS_OMEMO2).append(B64.encode(&auth.ik_sig)).build())
                .build(),
        );
    }
    for (jid, ks) in by_jid {
        let mut keys_el = Element::builder("keys", NS_OMEMO2).attr(crate::ncname("jid"), jid);
        for k in ks {
            let mut key_el = Element::builder("key", NS_OMEMO2).attr(crate::ncname("rid"), k.device_id.to_string());
            if k.kex {
                key_el = key_el.attr(crate::ncname("kex"), "true");
            }
            keys_el = keys_el.append(key_el.append(B64.encode(&k.data)).build());
        }
        header = header.append(keys_el.build());
    }
    header.build()
}

/// Build the full `<encrypted xmlns='urn:monocles:omemo-pq:1'>` element (header + `<payload>` +
/// `<commit>`). The `<commit>` is the single shared key commitment (proto-XEP §5.5) that makes the
/// AEAD key-committing; receivers verify it before opening the payload.
fn build_encrypted(enc: &EncryptedMessage, sender_device: u32) -> Element {
    Element::builder("encrypted", NS_OMEMO2)
        .append(build_header(enc, sender_device))
        .append(Element::builder("payload", NS_OMEMO2).append(B64.encode(&enc.payload)).build())
        .append(Element::builder("commit", NS_OMEMO2).append(B64.encode(enc.commit)).build())
        .build()
}

/// Encrypt an **empty SCE envelope** (no body, no metadata) to `addr` and build the OMEMO2
/// `<encrypted>` element *with* a `<payload>`. Used for both session heals and XEP-0384
/// heartbeats.
///
/// We deliberately send a payload-bearing empty message rather than a header-only (`<payload>`-less)
/// one: the Android reference client drops any OMEMO2 stanza that carries no `<payload>`
/// (`MessageParser` returns early on `!hasPayload()`), so a header-only message would never reach
/// its ratchet — the heal/heartbeat would be a silent no-op against an Android peer. The decrypted
/// envelope is empty (no `<body>`), so receivers process the key/ratchet but create no visible
/// message. The envelope still carries the §4.6.1 `<from>`/`<to>` binding.
async fn build_empty_omemo2(
    stores: &OmemoStores,
    cfg: &AccountConfig,
    our_device: u32,
    peer_bare: &str,
    addr: DeviceAddr,
) -> anyhow::Result<Element> {
    let env =
        Envelope::with_content("", cfg.bare(), peer_bare, Some(crate::xeps::rfc3339_now()));
    let enc = session::encrypt(
        stores,
        cfg.bare(),
        our_device,
        &[addr],
        Some(peer_bare),
        env.to_xml().as_bytes(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("omemo empty-message encrypt: {e}"))?;
    Ok(build_encrypted(&enc, our_device))
}

/// EME hint to attach alongside an `<encrypted>` element.
pub fn eme_hint() -> Element {
    Element::builder("encryption", NS_EME)
        .attr(crate::ncname("name"), "PQ-OMEMO2")
        .attr(crate::ncname("namespace"), NS_OMEMO2)
        .build()
}

/// Recover a broken/stale inbound session with a peer device: (re)establish a fresh outbound
/// session from its published bundle and send it an **empty OMEMO2 message** (an empty SCE
/// envelope, `<payload>` present — see [`build_empty_omemo2`]), so the peer adopts the new session
/// and its next message decrypts — even if we never send it a normal message ourselves. Mirrors the
/// Android client's `completeOmemo2Session`. Called best-effort when an inbound message fails to
/// decrypt.
///
/// Security: this never weakens messaging. The re-established identity is authenticated by the
/// bundle's ML-DSA-87 signature and TOFU-pinned inside `establish_session` (no downgrade, mandatory
/// PQ identity still enforced); we only re-handshake to a **trusted** device (trust 1 or 3), so a
/// blind-trust-off user is never silently re-paired to an unverified key; the message carries **no
/// plaintext**; and it is rate-limited per device to prevent heal storms.
pub async fn heal_session(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    sender_bare: &str,
    sender_device: u32,
) -> anyhow::Result<()> {
    if !may_heal(cfg.account_id, sender_bare, sender_device) {
        return Ok(());
    }
    let stores = stores(store, cfg).await?;
    let our_device = stores.registration_id();
    if sender_bare == cfg.bare() && sender_device == our_device {
        return Ok(()); // never heal toward ourselves
    }
    let addr = DeviceAddr { jid: sender_bare.to_string(), device_id: sender_device };

    // Re-fetch the bundle and (re)establish a fresh outbound session (libsignal archives the old).
    forget_jid_failures(cfg.account_id, sender_bare);
    let bundle = match fetch_bundle(w, sender_bare, sender_device).await {
        Ok(b) => b,
        Err(e) => {
            warn!(%sender_bare, sender_device, error = %e, "omemo: heal — no bundle, cannot re-establish");
            note_establish_failure(cfg.account_id, sender_bare, sender_device);
            return Ok(());
        }
    };
    if let Err(e) =
        session::establish_session(&stores, cfg.bare(), our_device, &addr, &bundle).await
    {
        warn!(%sender_bare, sender_device, error = %e, "omemo: heal — re-establish failed");
        notice_if_pq_identity_changed(cfg.account_id, sender_bare, &e);
        note_establish_failure(cfg.account_id, sender_bare, sender_device);
        return Ok(());
    }

    // Respect trust: only re-handshake to a device we actually encrypt to.
    let trusted = store
        .omemo_identity(cfg.account_id, sender_bare, sender_device as i64)
        .await?
        .map(|id| id.trust == 1 || id.trust == 3)
        .unwrap_or(false);
    if !trusted {
        debug!(%sender_bare, sender_device, "omemo: heal — device not trusted, not sending empty message");
        return Ok(());
    }

    // Encrypt an empty SCE envelope to just this device (a `<key kex>` + `<payload>`); decrypting
    // it re-establishes/advances the peer's session, with no visible message.
    let enc_el = build_empty_omemo2(&stores, cfg, our_device, sender_bare, addr).await?;
    let msg = Element::builder("message", NS_CLIENT)
        .attr(crate::ncname("to"), sender_bare)
        .attr(crate::ncname("type"), "chat")
        .attr(crate::ncname("id"), new_id("heal"))
        .append(enc_el)
        .append(eme_hint())
        .append(Element::builder("no-store", NS_HINTS).build())
        .build();
    w.send(msg)?;
    info!(%sender_bare, sender_device, "omemo: sent empty OMEMO2 message to heal broken session");
    Ok(())
}

/// Outcome of [`verify_hybrid_fingerprint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridCheck {
    /// The post-quantum identity matches the scanned hybrid fingerprint (and is pinned).
    Verified,
    /// It does not: the published identity differs from the scanned one, or the bundle was
    /// refused (wrong classical key, bad signature). Possibly an active attack.
    Mismatch,
    /// The device's bundle could not be fetched; nothing was decided.
    Unavailable,
}

/// Out-of-band verification of a device's hybrid fingerprint (a scanned `omemo-pq-hfp-`,
/// proto-XEP §10.1). `identity_key` is the device's serialized classical key. Returns true when
/// its post-quantum identity matches `hybrid`: either the pinned one already does, or the
/// device's bundle — both v4 signatures verified — carries one that does, which is then
/// (re-)pinned. This is the only path allowed to replace a pin, because the user authenticated
/// it out of band. Anything but [`HybridCheck::Verified`] means the caller MUST NOT mark the key
/// verified, and SHOULD say why: a mismatch may be an active attack.
pub async fn verify_hybrid_fingerprint(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    jid: &str,
    device_id: u32,
    identity_key: &[u8],
    hybrid: &str,
) -> anyhow::Result<HybridCheck> {
    let pin_key = mxc_omemo::pq_pin_key(identity_key);
    if let Some(pinned) = store.get_pinned_omemo2_pq_identity(cfg.account_id, jid, &pin_key).await? {
        if mxc_omemo::hybrid_fingerprint(identity_key, &pinned) == hybrid {
            return Ok(HybridCheck::Verified);
        }
    }
    let bundle = match fetch_bundle(w, jid, device_id).await {
        Ok(b) => b,
        Err(e) => {
            warn!(%jid, device_id, error = %e, "omemo: hybrid verification — bundle fetch failed");
            return Ok(HybridCheck::Unavailable);
        }
    };
    let pq_ik = match session::verified_bundle_pq_identity(&bundle, identity_key) {
        Ok(pq) => pq,
        Err(e) => {
            warn!(%jid, device_id, error = %e, "omemo: hybrid verification — bundle refused");
            return Ok(HybridCheck::Mismatch);
        }
    };
    if mxc_omemo::hybrid_fingerprint(identity_key, &pq_ik) != hybrid {
        warn!(%jid, device_id,
            "omemo: hybrid verification FAILED — the published PQ identity does not match the scanned fingerprint");
        return Ok(HybridCheck::Mismatch);
    }
    store.pin_omemo2_pq_identity(cfg.account_id, jid, &pin_key, &pq_ik).await?;
    clear_pq_identity_notice(cfg.account_id, jid, &pin_key);
    info!(%jid, device_id, "omemo: verified hybrid fingerprint and pinned its PQ identity");
    Ok(HybridCheck::Verified)
}

/// Background pq_ik pin reconciliation (mirror of the Android client). A peer's post-quantum
/// identity is normally pinned when WE establish the session from its fetched bundle
/// ([`session::establish_session`]). When the PEER initiated the session, the inbound PQXDH key
/// exchange never delivers its `<pq-ik>` (it only travels in the published bundle), so no pin is
/// ever written and [`sessions_for`] never fetches the bundle again once a session exists — the
/// device then shows its classical instead of hybrid fingerprint indefinitely. Called
/// best-effort after every successful inbound OMEMO2 decrypt: if no pq_ik is pinned for the
/// sender's classical identity yet, fetch its bundle once (per device, per app run), verify it,
/// and pin ([`session::reconcile_pq_pin`] — same ML-DSA-87 transcript verification as an
/// outbound establish, bundle identity must match the known one, and an existing pin is never
/// overwritten).
pub async fn reconcile_pq_pin_if_missing(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    sender_bare: &str,
    sender_device: u32,
) -> anyhow::Result<()> {
    let stores = stores(store, cfg).await?;
    if sender_bare == cfg.bare() && sender_device == stores.registration_id() {
        return Ok(()); // never reconcile toward ourselves
    }
    // At most one attempt per device per app run, whether or not it succeeds.
    {
        let mut m = pq_pin_reconcile_attempts().lock().unwrap();
        if !m.insert((cfg.account_id, sender_bare.to_string(), sender_device)) {
            return Ok(());
        }
    }
    // The sender's classical identity key, as saved by the (inbound) session establishment.
    let Some(rec) = store
        .omemo_identity(cfg.account_id, sender_bare, sender_device as i64)
        .await?
    else {
        return Ok(());
    };
    let pin_key = mxc_omemo::pq_pin_key(&rec.identity_key);
    if store
        .get_pinned_omemo2_pq_identity(cfg.account_id, sender_bare, &pin_key)
        .await?
        .is_some()
    {
        return Ok(()); // already pinned
    }
    debug!(%sender_bare, sender_device, "omemo: no pq_ik pinned — fetching bundle to reconcile");
    let bundle = match fetch_bundle(w, sender_bare, sender_device).await {
        Ok(b) => b,
        Err(e) => {
            warn!(%sender_bare, sender_device, error = %e,
                "omemo: pq pin reconciliation — bundle fetch failed");
            return Ok(());
        }
    };
    let addr = DeviceAddr { jid: sender_bare.to_string(), device_id: sender_device };
    match session::reconcile_pq_pin(&stores, &addr, &bundle, &rec.identity_key).await {
        Ok(true) => {
            info!(%sender_bare, sender_device, "omemo: pq pin reconciliation — pinned PQ identity");
        }
        Ok(false) => {}
        Err(e) => {
            warn!(%sender_bare, sender_device, error = %e,
                "omemo: pq pin reconciliation — refused, not pinning");
            notice_if_pq_identity_changed(cfg.account_id, sender_bare, &e);
        }
    }
    Ok(())
}

/// Send an XEP-0384 **heartbeat**: an empty OMEMO2 message to `sender_device` over the *existing*
/// session (we just decrypted one of its messages, so a session is already established — unlike
/// [`heal_session`], we never re-fetch a bundle). Encrypting empty content advances our sending
/// chain and carries a fresh ratchet key, so when the peer receives it they perform a DH-ratchet
/// step and their next chain restarts at counter 0. Called when an inbound message's counter
/// reaches the heartbeat threshold (see [`heartbeat_due`]).
///
/// Security: identical envelope to a heal — an **empty SCE envelope** (no body, no metadata), sent
/// **only to a trusted device** (trust 1 or 3), and at most once per receiving ratchet key. It
/// strictly improves the ratchet's post-compromise security in one-directional conversations and
/// never downgrades or re-pairs anything.
pub async fn send_heartbeat(
    w: &Writer,
    store: &Store,
    cfg: &AccountConfig,
    sender_bare: &str,
    sender_device: u32,
) -> anyhow::Result<()> {
    let stores = stores(store, cfg).await?;
    let our_device = stores.registration_id();
    if sender_bare == cfg.bare() && sender_device == our_device {
        return Ok(()); // never heartbeat toward ourselves
    }
    // Only emit an (encrypted, empty) message to a device we actually trust to encrypt to.
    let trusted = store
        .omemo_identity(cfg.account_id, sender_bare, sender_device as i64)
        .await?
        .map(|id| id.trust == 1 || id.trust == 3)
        .unwrap_or(false);
    if !trusted {
        debug!(%sender_bare, sender_device, "omemo: heartbeat — device not trusted, skipping");
        return Ok(());
    }
    let addr = DeviceAddr { jid: sender_bare.to_string(), device_id: sender_device };
    let enc_el = build_empty_omemo2(&stores, cfg, our_device, sender_bare, addr).await?;
    let msg = Element::builder("message", NS_CLIENT)
        .attr(crate::ncname("to"), sender_bare)
        .attr(crate::ncname("type"), "chat")
        .attr(crate::ncname("id"), new_id("hb"))
        .append(enc_el)
        .append(eme_hint())
        .append(Element::builder("no-store", NS_HINTS).build())
        .build();
    w.send(msg)?;
    info!(%sender_bare, sender_device, "omemo: sent XEP-0384 heartbeat (ratchet counter ≥ threshold)");
    Ok(())
}

/// Does a `<keys jid='…'>` block address us?
///
/// A plain `==` against our bare JID was too strict: XMPP localparts and domains are both
/// case-insensitive (PRECIS UsernameCaseMapped / IDNA), so a peer writing `Alice@Example.com`
/// addresses the same account — and Android accepts it, since it compares parsed bare JIDs. The
/// desktop dropped the message with "no key for our device" instead. Being lenient here is not a
/// loosening: the value is compared against *our own* JID, and case-folding is what the JID
/// equality rules already require. ASCII case folding (rather than full PRECIS) matches how the
/// rest of this crate compares JIDs, including `Envelope::verify_binding`.
/// The wrapped keys in `header` that are addressed to our own device, at most
/// [`MAX_KEY_CANDIDATES`] of them, as `(wrapped_key, is_kex)` — plus whether the list was
/// truncated by the cap.
///
/// Only the `<keys>` block bearing OUR bare JID is read (XEP-0420 §4.6.4): a sender must not be
/// able to smuggle a key for our device in under another user's block. Undecodable base64 is
/// skipped rather than fatal, so one bad entry cannot suppress a good one beside it.
fn select_key_candidates(
    header: &Element,
    our_bare: &str,
    our_device: u32,
) -> (Vec<(Vec<u8>, bool)>, bool) {
    let our_rid = our_device.to_string();
    let mut candidates: Vec<(Vec<u8>, bool)> = header
        .children()
        .filter(|c| c.name() == "keys" && keys_block_is_ours(c.attr("jid"), our_bare))
        .flat_map(|keys| keys.children().filter(|c| c.name() == "key"))
        .filter(|k| k.attr("rid") == Some(our_rid.as_str()))
        .filter_map(|k| {
            B64.decode(k.text().trim()).ok().map(|w| (w, k.attr("kex") == Some("true")))
        })
        // One past the cap, so a truncation can be told from an exactly-full list.
        .take(MAX_KEY_CANDIDATES + 1)
        .collect();
    let truncated = candidates.len() > MAX_KEY_CANDIDATES;
    if truncated {
        candidates.truncate(MAX_KEY_CANDIDATES);
    }
    (candidates, truncated)
}

/// Every `<key kex='true'>` in `header`, across all `<keys>` blocks, as the handshake transcript
/// covers them (proto-XEP §4.9.7). Entries that do not parse are skipped, as the Android parser
/// skips them, so both clients recompute the transcript over the same set.
fn header_kex_entries(header: &Element) -> Vec<session::KexEntry> {
    let mut entries = Vec::new();
    for keys in header.children().filter(|c| c.name() == "keys") {
        let Some(jid) = keys.attr("jid") else { continue };
        let bare = jid.split('/').next().unwrap_or(jid);
        for key in keys.children().filter(|c| c.name() == "key" && c.attr("kex") == Some("true")) {
            let (Some(rid), Ok(data)) = (
                key.attr("rid").and_then(|r| r.parse::<u32>().ok()),
                B64.decode(key.text().trim()),
            ) else {
                continue;
            };
            entries.push(session::KexEntry { jid: bare.to_string(), device_id: rid, data });
        }
    }
    entries
}

/// Parse `<pq-auth>`, or `None` when it is absent or malformed (never an error: a message
/// without it is refused by [`session::verify_pq_auth`] if, and only if, it needs it).
fn parse_pq_auth(header: &Element) -> Option<session::PqAuth> {
    let auth = header.get_child("pq-auth", NS_OMEMO2)?;
    let pq_ik_el = auth.get_child("pq-ik", NS_OMEMO2)?;
    if pq_ik_el.attr("type").is_some_and(|t| t != "ML-DSA-87") {
        warn!("omemo: refusing <pq-auth> with an unsupported type");
        return None;
    }
    let field = |name: &str| -> Option<Vec<u8>> {
        B64.decode(auth.get_child(name, NS_OMEMO2)?.text().trim()).ok()
    };
    Some(session::PqAuth {
        pq_ik: B64.decode(pq_ik_el.text().trim()).ok()?,
        pq_sig: field("pq-sig")?,
        ik_sig: field("ik-sig")?,
    })
}

fn keys_block_is_ours(jid_attr: Option<&str>, our_bare: &str) -> bool {
    let Some(jid) = jid_attr else { return false };
    let bare = jid.split('/').next().unwrap_or(jid);
    bare.eq_ignore_ascii_case(our_bare)
}

/// Decrypt an incoming `<encrypted>` element addressed to us from `sender_bare`.
///
/// `expected_to` is the recipient bare JID the sender is expected to have bound into the payload
/// context (§5.4.2) — our own bare JID for an incoming 1:1, the counterpart for a carbon of our
/// own send, the room JID for a MUC, `None` for a MUC private message. It must match the value
/// later checked against the SCE `<to>`; GCM decryption fails otherwise.
pub async fn decrypt_message(
    store: &Store,
    cfg: &AccountConfig,
    events: &Sender<Event>,
    encrypted: &Element,
    sender_bare: &str,
    expected_to: Option<&str>,
) -> anyhow::Result<Decrypted> {
    let header = encrypted
        .get_child("header", NS_OMEMO2)
        .ok_or_else(|| anyhow::anyhow!("omemo: no <header>"))?;
    let sender_device: u32 = header
        .attr("sid")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("omemo: bad sid"))?;
    // A missing `<payload>` is a key-transport message (used to re-sync a broken session): we
    // still process the wrapped key (which (re)establishes the session) but there is no content.
    let is_key_transport = encrypted.get_child("payload", NS_OMEMO2).is_none();
    let payload = match encrypted.get_child("payload", NS_OMEMO2) {
        Some(p) => B64.decode(p.text().trim())?,
        None => Vec::new(),
    };
    // Single shared key commitment (proto-XEP §5.5); verified against the unwrapped key inside
    // session::decrypt. Absent on a key-transport message (no payload); required with a payload.
    let commit = encrypted
        .get_child("commit", NS_OMEMO2)
        .map(|c| B64.decode(c.text().trim()))
        .transpose()?;

    let stores = stores(store, cfg).await?;
    let our_device = stores.registration_id();

    // Only consider the <keys> block addressed to us (XEP-0420 §4.6.4) — a sender must not be
    // able to smuggle a key for our device in under another user's block.
    let (candidates, truncated) = select_key_candidates(header, cfg.bare(), our_device);
    if truncated {
        warn!(%sender_bare, sender_device, cap = MAX_KEY_CANDIDATES,
            "omemo: header carries more wrapped keys for our device than the cap — ignoring the rest");
    }
    if candidates.is_empty() {
        anyhow::bail!("omemo: no key for our device {our_device}");
    }

    let from = DeviceAddr { jid: sender_bare.to_string(), device_id: sender_device };
    // Post-quantum handshake authentication, BEFORE any candidate reaches libsignal: once it has
    // processed a pre-key message the session is stored, and later messages on it would decrypt
    // with no further check (proto-XEP §4.9.7).
    let handshake = session::verify_pq_auth(
        &stores,
        &from,
        &candidates,
        &header_kex_entries(header),
        parse_pq_auth(header).as_ref(),
    )
    .await
    .map_err(|e| {
        notice_if_pq_identity_changed(cfg.account_id, sender_bare, &e);
        anyhow::anyhow!("omemo decrypt: {e}")
    })?;
    // A header may legitimately carry more than one wrap for us — e.g. a sender that rebuilt the
    // session mid-send and attached both the old and the new one. Try each and keep the first
    // that opens (mirrors Android's processReceiving, which walks its candidate list the same
    // way).
    //
    // Retry only past a *wrapped-key* failure. `session::decrypt` advances and stores the ratchet
    // before it touches the payload, so a payload-layer failure — `OmemoError::Aead`: key
    // commitment mismatch, GCM tag mismatch, bad key length — means the key unwrapped fine and
    // the ciphertext beside it did not verify. That is a tampering signal, not the wrong wrap,
    // and it is final: continuing would spend another ratchet step per attempt on one stanza,
    // handing an attacker extra bites at the session for free.
    let mut opened = None;
    let mut last_err = None;
    for (candidate, candidate_kex) in candidates {
        match session::decrypt(
            &stores,
            cfg.bare(),
            our_device,
            &from,
            expected_to,
            &candidate,
            candidate_kex,
            &payload,
            commit.as_deref(),
        )
        .await
        {
            Ok(env) => {
                opened = Some((env, candidate, candidate_kex));
                break;
            }
            Err(e @ mxc_omemo::OmemoError::Aead(_)) => {
                last_err = Some(e);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let (envelope, wrapped, kex) = match opened {
        Some(v) => v,
        None => {
            let e = last_err.expect("non-empty candidate list always records an error");
            return Err(anyhow::anyhow!("omemo decrypt: {e}"));
        }
    };
    // The pin was written inside verify_pq_auth, before libsignal saw the message.
    if handshake.as_ref().is_some_and(|h| h.newly_pinned) {
        debug!(%sender_bare, sender_device, "omemo: pinned PQ identity from an authenticated handshake");
    }

    // XEP-0384 heartbeat: if this whisper's ratchet counter reached the threshold (a long
    // one-directional chain), flag a heartbeat so the caller forces a DH-ratchet step — restoring
    // break-in recovery and bounding skipped-key storage. Once per ratchet key; kex/key-transport
    // messages never qualify (fresh chain / no counter).
    let heartbeat_due = session::whisper_ratchet_counter(&wrapped, kex)
        .map(|(counter, ratchet_key)| {
            self::heartbeat_due(cfg.account_id, sender_bare, sender_device, counter, &ratchet_key)
        })
        .unwrap_or(false);

    // Fingerprint + TOFU prompt for the sending device.
    let fingerprint = match store
        .omemo_identity(cfg.account_id, sender_bare, sender_device as i64)
        .await?
    {
        Some(rec) => mxc_omemo::fingerprint(&rec.identity_key),
        None => String::new(),
    };
    let _ = events
        .send(Event::OmemoDeviceSeen {
            account_id: cfg.account_id,
            jid: sender_bare.to_string(),
            device_id: sender_device as i64,
            fingerprint: fingerprint.clone(),
        })
        .await;

    Ok(Decrypted {
        envelope,
        sender_device,
        fingerprint,
        was_kex: kex,
        key_transport: is_key_transport,
        heartbeat_due,
    })
}

#[cfg(test)]
mod device_list_event_tests {
    use super::{devices_in_notification, may_reannounce_own_device, MAX_DEVICES_PER_JID, NODE_DEVICES, NS_OMEMO2};
    use minidom::Element;

    fn items(inner: &str) -> Element {
        format!("<items xmlns='http://jabber.org/protocol/pubsub#event' node='{NODE_DEVICES}'>{inner}</items>")
            .parse()
            .unwrap()
    }

    #[test]
    fn published_list_is_parsed() {
        let el = items(&format!(
            "<item id='current'><devices xmlns='{NS_OMEMO2}'><device id='7'/><device id='42'/><device id='x'/></devices></item>"
        ));
        assert_eq!(devices_in_notification("a@b", &el), Some(vec![7, 42]));
        // A published but empty list is a real (empty) list, not "unknown".
        let empty = items(&format!("<item id='current'><devices xmlns='{NS_OMEMO2}'/></item>"));
        assert_eq!(devices_in_notification("a@b", &empty), Some(vec![]));
    }

    #[test]
    fn no_payload_or_retraction_means_ask_the_node() {
        assert_eq!(devices_in_notification("a@b", &items("<item id='current'/>")), None);
        assert_eq!(devices_in_notification("a@b", &items("<retract id='current'/>")), None);
        // A payload in another namespace (e.g. legacy OMEMO) is not ours to read.
        let legacy = items("<item id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='1'/></devices></item>");
        assert_eq!(devices_in_notification("a@b", &legacy), None);
    }

    #[test]
    fn deleting_or_purging_the_node_counts_as_cleared() {
        use super::device_list_cleared;
        let event = |inner: &str| -> Element {
            format!("<event xmlns='http://jabber.org/protocol/pubsub#event'>{inner}</event>").parse().unwrap()
        };
        assert!(device_list_cleared(&event(&format!("<delete node='{NODE_DEVICES}'/>"))));
        assert!(device_list_cleared(&event(&format!("<purge node='{NODE_DEVICES}'/>"))));
        // Another node, or an ordinary items notification, is not.
        assert!(!device_list_cleared(&event("<delete node='urn:xmpp:bookmarks:1'/>")));
        assert!(!device_list_cleared(&event(&format!("<items node='{NODE_DEVICES}'/>"))));
    }

    #[test]
    fn notification_obeys_the_device_cap() {
        let many: String = (0..MAX_DEVICES_PER_JID as u32 + 50).map(|i| format!("<device id='{i}'/>")).collect();
        let el = items(&format!("<item id='current'><devices xmlns='{NS_OMEMO2}'>{many}</devices></item>"));
        assert_eq!(devices_in_notification("a@b", &el).unwrap().len(), MAX_DEVICES_PER_JID);
    }

    #[test]
    fn own_reannounce_is_rate_limited() {
        let account = -4242; // an id no other test uses
        assert!(may_reannounce_own_device(account));
        assert!(!may_reannounce_own_device(account));
    }

    #[test]
    fn reannounce_cooldown_doubles_and_is_capped() {
        use super::{reannounce_cooldown, OWN_REANNOUNCE_COOLDOWN, OWN_REANNOUNCE_COOLDOWN_MAX};
        assert_eq!(reannounce_cooldown(0), OWN_REANNOUNCE_COOLDOWN);
        assert_eq!(reannounce_cooldown(1), OWN_REANNOUNCE_COOLDOWN * 2);
        assert_eq!(reannounce_cooldown(3), OWN_REANNOUNCE_COOLDOWN * 8);
        assert_eq!(reannounce_cooldown(20), OWN_REANNOUNCE_COOLDOWN_MAX);
        assert_eq!(reannounce_cooldown(u32::MAX), OWN_REANNOUNCE_COOLDOWN_MAX);
    }

    /// Removed again soon after re-announcing: back off further. After a quiet period: reset.
    #[test]
    fn repeated_removals_back_off_and_quiet_periods_reset() {
        use super::{own_reannounced, reannounce_cooldown_left, Reannounced, OWN_REANNOUNCE_COOLDOWN};
        use std::time::{Duration, Instant};
        let account = -4343;
        let set = |ago: Duration, streak: u32| {
            own_reannounced().lock().unwrap().insert(account, Reannounced { at: Instant::now() - ago, streak });
        };
        let streak = || own_reannounced().lock().unwrap()[&account].streak;

        // Just past the 60 s cooldown: a fight, so the next cooldown is 120 s.
        set(OWN_REANNOUNCE_COOLDOWN + Duration::from_secs(1), 0);
        assert!(may_reannounce_own_device(account));
        assert_eq!(streak(), 1);
        assert!(reannounce_cooldown_left(account) > OWN_REANNOUNCE_COOLDOWN);
        assert!(!may_reannounce_own_device(account), "still cooling down");

        // Long after a streak-3 re-announce (8 min cooldown): calm again, back to the base.
        set(Duration::from_secs(60 * 60), 3);
        assert!(may_reannounce_own_device(account));
        assert_eq!(streak(), 0);
    }

    /// A deferred retry whose runtime is dropped mid-sleep (reconnect) must not block later ones.
    #[tokio::test]
    async fn cancelled_retry_does_not_wedge_scheduling() {
        use super::{own_reannounced, reannounce_scheduled, schedule_own_reannounce, Reannounced};
        use crate::client::{AccountConfig, Writer};
        use std::time::Instant;
        let account = -7004;
        own_reannounced().lock().unwrap().insert(account, Reannounced { at: Instant::now(), streak: 0 });
        let (w, _rx) = Writer::for_tests();
        let cfg = AccountConfig::new(account, "me@example.org".into(), String::new());
        let local = tokio::task::LocalSet::new();
        local.run_until(async { schedule_own_reannounce(w, cfg, 77) }).await;
        assert!(reannounce_scheduled().lock().unwrap().contains(&account), "retry pending while sleeping");
        drop(local); // the connection's runtime goes away with the task still sleeping
        assert!(!reannounce_scheduled().lock().unwrap().contains(&account), "the guard cleared the entry");
    }

    mod deferred {
        use super::super::{
            own_reannounced, schedule_own_reannounce, Reannounced, NODE_DEVICES, NS_OMEMO2,
            OWN_REANNOUNCE_COOLDOWN,
        };
        use crate::client::{AccountConfig, Writer};
        use crate::xeps::iq;
        use minidom::Element;
        use std::time::{Duration, Instant};
        use tokio::sync::mpsc::UnboundedReceiver;

        const ME: &str = "me@example.org";
        const OURS: u32 = 77;

        async fn next(rx: &mut UnboundedReceiver<Element>) -> Element {
            tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("a stanza").expect("open")
        }

        fn devices_reply(get: &Element, ids: &[u32]) -> Element {
            let devices: String = ids.iter().map(|d| format!("<device id='{d}'/>")).collect();
            format!(
                "<iq xmlns='jabber:client' type='result' id='{}' from='{ME}'>\
                 <pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='{NODE_DEVICES}'>\
                 <item id='current'><devices xmlns='{NS_OMEMO2}'>{devices}</devices></item>\
                 </items></pubsub></iq>",
                get.attr("id").unwrap()
            )
            .parse()
            .unwrap()
        }

        fn result_for(iq: &Element) -> Element {
            format!("<iq xmlns='jabber:client' type='result' id='{}' from='{ME}'/>", iq.attr("id").unwrap())
                .parse()
                .unwrap()
        }

        fn error_reply(iq: &Element, condition: &str) -> Element {
            format!(
                "<iq xmlns='jabber:client' type='error' id='{}' from='{ME}'><error type='cancel'>\
                 <{condition} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
                iq.attr("id").unwrap()
            )
            .parse()
            .unwrap()
        }

        #[test]
        fn only_a_missing_node_counts_as_an_empty_list() {
            use super::super::existing_device_list;
            assert_eq!(existing_device_list(Ok(vec![5, 7])).unwrap(), vec![5, 7]);
            assert!(existing_device_list(Err(anyhow::anyhow!("iq x error: item-not-found"))).unwrap().is_empty());
            let timeout = existing_device_list(Err(anyhow::anyhow!("iq x timed out"))).unwrap_err();
            assert!(timeout.to_string().contains("timed out"), "{timeout}");
            assert!(existing_device_list(Err(anyhow::anyhow!("iq x error: service-unavailable"))).is_err());
        }

        /// Publishing reads the node first: a failed read publishes nothing; a node that does
        /// not exist yet is published with just our device.
        #[tokio::test]
        async fn publish_never_builds_a_list_from_a_failed_read() {
            use super::super::publish_device_list;
            let cfg = AccountConfig::new(-7003, ME.into(), String::new());

            let (w, mut rx) = Writer::for_tests();
            let publishing = {
                let (w, cfg) = (w.clone(), cfg.clone());
                tokio::spawn(async move { publish_device_list(&w, &cfg, OURS).await })
            };
            drop(w);
            let get = next(&mut rx).await;
            assert!(iq::try_resolve(&error_reply(&get, "service-unavailable"), ME));
            assert!(publishing.await.unwrap().is_err(), "a failed read must abort");
            assert!(rx.recv().await.is_none(), "nothing may be published after a failed read");

            let (w, mut rx) = Writer::for_tests();
            let publishing = {
                let (w, cfg) = (w.clone(), cfg.clone());
                tokio::spawn(async move { publish_device_list(&w, &cfg, OURS).await })
            };
            drop(w);
            let get = next(&mut rx).await;
            assert!(iq::try_resolve(&error_reply(&get, "item-not-found"), ME));
            let publish = next(&mut rx).await;
            assert_eq!(publish.attr("type"), Some("set"));
            let xml = String::from(&publish);
            assert!(xml.contains(&format!("id=\"{OURS}\"")) || xml.contains(&format!("id='{OURS}'")), "{xml}");
            assert!(iq::try_resolve(&result_for(&publish), ME));
            assert!(publishing.await.unwrap().is_ok());
        }

        /// A list read at the device cap may be truncated: rewriting it would drop every device
        /// past the cap, so the publish is refused.
        #[tokio::test]
        async fn publish_refuses_a_list_at_the_device_cap() {
            use super::super::{publish_device_list, MAX_DEVICES_PER_JID};
            let cfg = AccountConfig::new(-7005, ME.into(), String::new());
            let (w, mut rx) = Writer::for_tests();
            let publishing = {
                let (w, cfg) = (w.clone(), cfg.clone());
                tokio::spawn(async move { publish_device_list(&w, &cfg, OURS).await })
            };
            drop(w);
            let get = next(&mut rx).await;
            let full: Vec<u32> = (1000..1000 + MAX_DEVICES_PER_JID as u32).collect();
            assert!(iq::try_resolve(&devices_reply(&get, &full), ME));
            let err = publishing.await.unwrap().unwrap_err();
            assert!(err.to_string().contains("cap"), "{err}");
            assert!(rx.recv().await.is_none(), "nothing may be published");
        }

        /// Start `account` with only ~50 ms of re-announce cooldown left and schedule twice.
        fn schedule(account: i64) -> UnboundedReceiver<Element> {
            let (w, rx) = Writer::for_tests();
            let cfg = AccountConfig::new(account, ME.into(), String::new());
            let almost_over = OWN_REANNOUNCE_COOLDOWN - Duration::from_millis(50);
            own_reannounced().lock().unwrap().insert(account, Reannounced { at: Instant::now() - almost_over, streak: 0 });
            schedule_own_reannounce(w.clone(), cfg.clone(), OURS);
            schedule_own_reannounce(w, cfg, OURS); // already pending: must not add a second retry
            rx
        }

        #[tokio::test]
        async fn retry_rechecks_the_list_and_publishes_only_if_still_missing() {
            tokio::task::LocalSet::new()
                .run_until(async {
                    // Back in the list by the time the cooldown ends: read once, publish nothing.
                    let mut rx = schedule(-7001);
                    let get = next(&mut rx).await;
                    assert_eq!(get.attr("type"), Some("get"));
                    assert!(iq::try_resolve(&devices_reply(&get, &[5, OURS]), ME));
                    // Nothing else may be sent: either silence, or the channel closing because the
                    // (single) retry task finished and dropped its writer.
                    let more = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
                    assert!(!matches!(more, Ok(Some(_))), "no publish and no second (duplicate) retry: {more:?}");

                    // Still missing: re-announce through the re-fetching publish, keeping the
                    // other device and adding ours.
                    let mut rx = schedule(-7002);
                    let get = next(&mut rx).await;
                    assert!(iq::try_resolve(&devices_reply(&get, &[5]), ME));
                    let refetch = next(&mut rx).await; // publish_device_list reads the node again
                    assert_eq!(refetch.attr("type"), Some("get"));
                    assert!(iq::try_resolve(&devices_reply(&refetch, &[5]), ME));
                    let publish = next(&mut rx).await;
                    assert_eq!(publish.attr("type"), Some("set"));
                    let xml = String::from(&publish);
                    assert!(xml.contains("id=\"5\"") || xml.contains("id='5'"), "{xml}");
                    assert!(xml.contains(&format!("id=\"{OURS}\"")) || xml.contains(&format!("id='{OURS}'")), "{xml}");
                    assert!(iq::try_resolve(&result_for(&publish), ME));
                })
                .await;
        }
    }
}

#[cfg(test)]
mod keys_block_tests {
    use super::keys_block_is_ours;

    /// XMPP JID equality folds case in both the localpart and the domain, and Android compares
    /// parsed bare JIDs — so a peer writing `Alice@Example.com` addresses us. The desktop used
    /// `==` and dropped those messages with "no key for our device".
    #[test]
    fn case_and_resource_are_ignored() {
        assert!(keys_block_is_ours(Some("alice@example.com"), "alice@example.com"));
        assert!(keys_block_is_ours(Some("Alice@Example.COM"), "alice@example.com"));
        assert!(keys_block_is_ours(Some("alice@example.com/phone"), "alice@example.com"));
    }

    /// The block still has to be *ours*: this check is what stops a sender stuffing a key for
    /// our device in under another user's `<keys>` block (XEP-0420 §4.6.4).
    #[test]
    fn another_jid_is_still_refused() {
        assert!(!keys_block_is_ours(Some("mallory@example.com"), "alice@example.com"));
        assert!(!keys_block_is_ours(Some("alice@evil.test"), "alice@example.com"));
        assert!(!keys_block_is_ours(Some(""), "alice@example.com"));
        assert!(!keys_block_is_ours(None, "alice@example.com"));
    }
}

#[cfg(test)]
mod key_candidate_tests {
    use super::{select_key_candidates, MAX_KEY_CANDIDATES, NS_OMEMO2};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use minidom::Element;

    const US: &str = "alice@example.com";
    const OUR_RID: u32 = 42;

    /// A `<header>` whose `<keys jid=…>` block holds `n` wraps for our device, plus the noise a
    /// real header carries: another recipient's block, and a key for a different device of ours.
    fn header_with(jid: &str, n: usize) -> Element {
        let mut keys = Element::builder("keys", NS_OMEMO2).attr(crate::ncname("jid"), jid);
        for i in 0..n {
            keys = keys.append(
                Element::builder("key", NS_OMEMO2)
                    .attr(crate::ncname("rid"), OUR_RID.to_string())
                    .append(B64.encode([i as u8; 16]))
                    .build(),
            );
        }
        keys = keys.append(
            Element::builder("key", NS_OMEMO2)
                .attr(crate::ncname("rid"), "99")
                .append(B64.encode([0xEEu8; 16]))
                .build(),
        );
        Element::builder("header", NS_OMEMO2)
            .attr(crate::ncname("sid"), "7")
            .append(keys.build())
            .append(
                Element::builder("keys", NS_OMEMO2)
                    .attr(crate::ncname("jid"), "bob@example.com")
                    .append(
                        Element::builder("key", NS_OMEMO2)
                            .attr(crate::ncname("rid"), OUR_RID.to_string())
                            .append(B64.encode([0xFFu8; 16]))
                            .build(),
                    )
                    .build(),
            )
            .build()
    }

    /// The ordinary cases are untouched: one wrap, or the benign two a sender that rebuilt the
    /// session mid-send attaches. Only our own block and our own rid are read.
    #[test]
    fn legitimate_headers_pass_through() {
        for n in 1..=2 {
            let (c, truncated) = select_key_candidates(&header_with(US, n), US, OUR_RID);
            assert_eq!(c.len(), n);
            assert!(!truncated);
            assert_eq!(c[0].0, vec![0u8; 16], "our own block's first wrap");
        }
        // Nothing addressed to us at all.
        let (c, truncated) = select_key_candidates(&header_with("bob@example.com", 3), US, OUR_RID);
        assert!(c.is_empty(), "another JID's block is never read");
        assert!(!truncated);
    }

    /// Each wrap costs a full trial ratchet decryption, so a header stuffed with them must not
    /// buy the sender unbounded work. Past the cap the rest are ignored, and the caller is told.
    #[test]
    fn candidates_are_capped() {
        let (c, truncated) =
            select_key_candidates(&header_with(US, MAX_KEY_CANDIDATES * 100), US, OUR_RID);
        assert_eq!(c.len(), MAX_KEY_CANDIDATES);
        assert!(truncated);

        // Exactly full is NOT a truncation — the boundary the `take(cap + 1)` exists to get right.
        let (c, truncated) = select_key_candidates(&header_with(US, MAX_KEY_CANDIDATES), US, OUR_RID);
        assert_eq!(c.len(), MAX_KEY_CANDIDATES);
        assert!(!truncated);
    }

    /// One undecodable wrap must not suppress a good one beside it, and must not consume a slot.
    #[test]
    fn undecodable_wraps_are_skipped() {
        let header = Element::builder("header", NS_OMEMO2)
            .attr(crate::ncname("sid"), "7")
            .append(
                Element::builder("keys", NS_OMEMO2)
                    .attr(crate::ncname("jid"), US)
                    .append(
                        Element::builder("key", NS_OMEMO2)
                            .attr(crate::ncname("rid"), OUR_RID.to_string())
                            .append("!!!not base64!!!")
                            .build(),
                    )
                    .append(
                        Element::builder("key", NS_OMEMO2)
                            .attr(crate::ncname("rid"), OUR_RID.to_string())
                            .attr(crate::ncname("kex"), "true")
                            .append(B64.encode([0xABu8; 16]))
                            .build(),
                    )
                    .build(),
            )
            .build();
        let (c, truncated) = select_key_candidates(&header, US, OUR_RID);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], (vec![0xABu8; 16], true), "the kex flag survives");
        assert!(!truncated);
    }
}
