//! PQXDH session establishment + message encrypt/decrypt.
//!
//! Thin layer over libsignal v0.94.1: we never re-implement crypto. Flow per proto-XEP
//! §4.4. The OMEMO2 content key (32-byte AES-256-GCM key) is generated per message,
//! GCM-encrypts the SCE plaintext, and the 48-byte `key||tag` material is wrapped per
//! recipient device via the libsignal ratchet (`message_encrypt`) → the `<key>` elements.
//! The first message to a device is a `PreKeySignalMessage` (`kex=true`) carrying the
//! ML-KEM ciphertext from PQXDH; subsequent ones are plain `SignalMessage`s and the SPQR
//! braid runs unmodified inside libsignal.

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update};
use sha3::{CShake256, CShake256Core};
use zeroize::Zeroize;
use libsignal_protocol::{
    kem, message_decrypt_prekey, message_decrypt_signal, message_encrypt, pq_bundle_transcript, pq_bundle_verify,
    pq_kem_binding, pq_kex_auth_transcript, pq_kex_auth_verify, process_prekey_bundle, KexAuthEntry, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KeyPair,
    KyberPreKeyId, KyberPreKeyRecord, PqIdentityKey, PqIdentityKeyPair, PqSignature, PreKeyBundle,
    PreKeyId, PreKeyRecord, PreKeySignalMessage, PublicKey, SignalMessage, SignedPreKeyId,
    SignedPreKeyRecord, Timestamp,
};
use rand::RngCore;

use crate::bundle::{Bundle, KemPreKey};
use crate::store::{protocol_address, OmemoStores};
use crate::{OmemoError, Result};

/// OMEMO2 message key length (wrapped per device); the KMAC256 key.
const MSG_KEY_LEN: usize = 32;
/// AES-256-GCM IV/nonce length (bytes).
const IV_LEN: usize = 12;
/// AES-256-GCM authentication tag length (bytes), appended to the ciphertext by GCM.
const TAG_LEN: usize = 16;
/// Payload KDF output: 32-byte AES-256 key || 12-byte IV (must match monocles Android exactly).
const KDF_OUTPUT_LEN: usize = MSG_KEY_LEN + IV_LEN;
/// Both the payload key/IV and the key commitment are KMAC256 keyed by the message key, separated
/// only by these customization strings (must match monocles Android exactly).
///
/// One primitive rather than two: v2 used an unkeyed SHA3-512 commitment alongside an
/// HKDF-SHA-256 payload KDF, so their independence rested on Keccak and SHA-2 not correlating.
/// Under KMAC they are two customization strings of the same PRF, which cSHAKE encodes
/// unambiguously — a single-assumption argument, and it retires the hand-rolled length-prefixing
/// v2 needed. Keying by the message key also upgrades hiding from one-wayness of an unkeyed hash
/// to PRF security. Binding is unchanged at 256-bit: KMAC absorbs the encoded key as ordinary
/// sponge input, so a key-collision is a sponge collision.
const PAYLOAD_CUSTOMIZATION: &[u8] = b"monocles:omemo2:payload:v3";
const COMMIT_CUSTOMIZATION: &[u8] = b"monocles:omemo2:key-commitment:v3";
/// Key-commitment length. AES-256-GCM is not a committing AEAD, so a ciphertext can be opened
/// under two different keys (the "invisible salamander"). We publish a single shared commitment to
/// the message key next to the payload; receivers recompute it from their unwrapped key and reject
/// on mismatch, making the scheme key-committing and defeating both salamander collisions and
/// malicious-sender equivocation. 64 bytes gives 256-bit binding, matching the category-5 PQ
/// primitives around it.
const COMMIT_LEN: usize = 64;

/// Identifies a remote OMEMO2 device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAddr {
    pub jid: String,
    pub device_id: u32,
}

/// One recipient device's wrapped content key.
#[derive(Debug, Clone)]
pub struct WrappedKey {
    pub jid: String,
    pub device_id: u32,
    /// Serialized libsignal ciphertext (PreKeySignalMessage or SignalMessage).
    pub data: Vec<u8>,
    /// True if this is a key-exchange (PreKey) message — `<key kex='true'>`.
    pub kex: bool,
}

/// Result of encrypting one plaintext for a set of recipient devices.
///
/// `payload` is `AES-256-GCM(ciphertext) || tag[16]`. There is no separate IV on the wire —
/// the key and IV are HKDF-derived from the per-message key (which travels wrapped inside each
/// `<key>`) using the context-binding string as the HKDF salt; that same binding is the GCM AAD.
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub payload: Vec<u8>,
    pub keys: Vec<WrappedKey>,
    /// Key commitment over the message key (see `COMMIT_INFO`), published as a single shared
    /// `<commit>` element so a ciphertext binds to exactly one message key.
    pub commit: [u8; COMMIT_LEN],
    /// `<pq-auth>`: present whenever `keys` contains a pre-key message (proto-XEP §4.9.7).
    pub pq_auth: Option<PqAuth>,
}

/// The content of a `<pq-auth>` element: the sender's ML-DSA-87 identity key and its signature
/// over the handshake transcript, plus the classical identity key's signature over the same
/// transcript (proto-XEP §4.9.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqAuth {
    pub pq_ik: Vec<u8>,
    pub pq_sig: Vec<u8>,
    pub ik_sig: Vec<u8>,
}

/// One `<key kex='true'>` of a stanza, as the handshake transcript covers it: the `<keys jid>`
/// it sits under, its `rid`, and the serialized `PreKeySignalMessage`.
#[derive(Debug, Clone)]
pub struct KexEntry {
    pub jid: String,
    pub device_id: u32,
    pub data: Vec<u8>,
}

/// A pre-key message whose `<pq-auth>` verified; see [`verify_pq_auth`].
#[derive(Debug, Clone)]
pub struct VerifiedHandshake {
    pub fp_key: String,
    pub pq_ik: Vec<u8>,
    /// True when this handshake wrote the pin (first contact).
    pub newly_pinned: bool,
}

fn kex_auth_transcript(
    sender_jid: &str,
    sender_device: u32,
    ik: &IdentityKey,
    pq_ik: &PqIdentityKey,
    entries: &[KexEntry],
) -> Vec<u8> {
    let entries: Vec<KexAuthEntry<'_>> = entries
        .iter()
        .map(|e| KexAuthEntry {
            recipient_jid: &e.jid,
            recipient_device_id: e.device_id,
            prekey_message: &e.data,
        })
        .collect();
    pq_kex_auth_transcript(sender_jid, sender_device, ik, pq_ik, &entries)
}

/// Sign `<pq-auth>` for an outgoing message, or `None` when it carries no pre-key message.
///
/// The ML-DSA-87 signature post-quantum authenticates the handshake: a quantum adversary who
/// recovers our classical identity key can still not open a session in our name with anyone who
/// pinned our post-quantum identity. The classical signature binds that post-quantum key to our
/// classical identity, so nobody without our classical private key can replace it with their own.
fn sign_pq_auth(
    stores: &OmemoStores,
    our_jid: &str,
    our_device: u32,
    keys: &[WrappedKey],
) -> Result<Option<PqAuth>> {
    let entries: Vec<KexEntry> = keys
        .iter()
        .filter(|k| k.kex)
        .map(|k| KexEntry { jid: k.jid.clone(), device_id: k.device_id, data: k.data.clone() })
        .collect();
    if entries.is_empty() {
        return Ok(None);
    }
    let mut rng = rand::rng();
    let pq = stores.pq_identity();
    let pq_pub = pq.public_key();
    let transcript = kex_auth_transcript(
        our_jid,
        our_device,
        stores.identity().identity_key(),
        &pq_pub,
        &entries,
    );
    let pq_sig = pq.sign(&transcript, &mut rng).map_err(|e| OmemoError::Signal(e.to_string()))?;
    let ik_sig = stores
        .identity()
        .private_key()
        .calculate_signature(&transcript, &mut rng)
        .map_err(|e| OmemoError::Signal(e.to_string()))?;
    Ok(Some(PqAuth {
        pq_ik: pq_pub.serialize().to_vec(),
        pq_sig: pq_sig.serialize().to_vec(),
        ik_sig: ik_sig.to_vec(),
    }))
}

/// Post-quantum authentication of an incoming pre-key message (proto-XEP §4.9.7). MUST run
/// before the message is handed to libsignal: once it has processed a pre-key message the new
/// session is stored, and the sender's later (non-pre-key) messages would decrypt with no
/// further post-quantum check.
///
/// `candidates` are the wraps for our device that will be tried; `header_kex` every
/// `<key kex='true'>` in the header (all recipients — the signature covers them all). Returns
/// `None` when no candidate is a pre-key message: an established session was authenticated when
/// it was built. Otherwise `<pq-auth>` must be present, both signatures must verify, and its
/// post-quantum key must match the one pinned for the sender's (JID, classical identity).
pub async fn verify_pq_auth(
    stores: &OmemoStores,
    from: &DeviceAddr,
    candidates: &[(Vec<u8>, bool)],
    header_kex: &[KexEntry],
    auth: Option<&PqAuth>,
) -> Result<Option<VerifiedHandshake>> {
    let mut sender_ik: Option<IdentityKey> = None;
    for (data, kex) in candidates {
        if !*kex {
            continue;
        }
        // A malformed candidate is skipped, not fatal: libsignal cannot process it either (it
        // fails to parse there too, before any state changes), and a well-formed sibling — e.g.
        // the second wrap of a sender that rebuilt the session mid-send — must stay usable.
        let Ok(msg) = PreKeySignalMessage::try_from(data.as_slice()) else {
            tracing::warn!("omemo: skipping malformed pre-key message candidate");
            continue;
        };
        let ik = *msg.identity_key();
        if sender_ik.is_some_and(|known| known != ik) {
            return Err(OmemoError::HandshakeAuth(
                "pre-key messages for this device name different identity keys".into(),
            ));
        }
        sender_ik = Some(ik);
    }
    let Some(ik) = sender_ik else { return Ok(None) };
    let auth = auth.ok_or_else(|| {
        OmemoError::HandshakeAuth(
            "pre-key message without a valid <pq-auth> — the sender's client predates handshake \
             authentication and must be updated"
                .into(),
        )
    })?;
    // The one shared verification routine (libsignal `pq_kex_auth_verify`, also behind
    // Android's `PqAuth.verify`): lengths, both signatures, no short-circuit.
    let entries: Vec<KexAuthEntry<'_>> = header_kex
        .iter()
        .map(|e| KexAuthEntry {
            recipient_jid: &e.jid,
            recipient_device_id: e.device_id,
            prekey_message: &e.data,
        })
        .collect();
    if !pq_kex_auth_verify(
        &from.jid,
        from.device_id,
        &ik,
        &auth.pq_ik,
        &auth.pq_sig,
        &auth.ik_sig,
        &entries,
    ) {
        return Err(OmemoError::HandshakeAuth("invalid <pq-auth> signature".into()));
    }
    // Pin NOW, before libsignal stores the session: if the payload later fails to open, the
    // session still exists, and it must not exist without its pin. Safe on first contact
    // because the classical key signed this PQ key (`<ik-sig>`). The write is atomic, so a
    // concurrent pin is never overwritten; a different existing pin refuses the handshake.
    let fp_key = crate::pq_pin_key(&ik.serialize());
    let existing = stores
        .store
        .get_pinned_omemo2_pq_identity(stores.account_id, &from.jid, &fp_key)
        .await?;
    let newly_pinned = existing.is_none();
    let pinned = match existing {
        Some(p) => p,
        None => {
            stores
                .store
                .pin_omemo2_pq_identity_if_absent(stores.account_id, &from.jid, &fp_key, &auth.pq_ik)
                .await?
        }
    };
    if pinned != auth.pq_ik {
        return Err(OmemoError::PqIdentityChanged(fp_key));
    }
    Ok(Some(VerifiedHandshake { fp_key, pq_ik: auth.pq_ik.clone(), newly_pinned }))
}

/// Context-binding string used as BOTH the HKDF salt and the AES-GCM AAD (proto-XEP §5.4.2):
/// `"OMEMO2" || 0x00 || SENDER_BARE || 0x00 || RECIPIENT_BARE || 0x00 || u32_be(SOURCE_DEVICE_ID)`.
/// It binds the ciphertext to the message context (sender/recipient/device), defeating
/// re-routing / device-transpose attacks at the symmetric layer. A missing recipient
/// (`to == None`, e.g. a metadata-only SCE with no `<to>`) is bound as an empty segment. JIDs are
/// bare-normalised to match monocles Android's `Jid.asBareJid()`. Byte-identical to Android's
/// `XmppOmemo2Message.computeContextBinding`.
fn compute_context_binding(from: &str, to: Option<&str>, sid: u32) -> Vec<u8> {
    fn bare(jid: &str) -> &str {
        jid.split('/').next().unwrap_or(jid)
    }
    let from_bytes = bare(from).as_bytes();
    let to_bytes = to.map(bare).unwrap_or("").as_bytes();
    let prefix = b"OMEMO2";
    let mut buf = Vec::with_capacity(prefix.len() + 1 + from_bytes.len() + 1 + to_bytes.len() + 1 + 4);
    buf.extend_from_slice(prefix);
    buf.push(0);
    buf.extend_from_slice(from_bytes);
    buf.push(0);
    buf.extend_from_slice(to_bytes);
    buf.push(0);
    buf.extend_from_slice(&sid.to_be_bytes());
    buf
}

/// OMEMO2 payload seal: HKDF(message_key, salt=binding) → key||iv, AES-256-GCM encrypt with the
/// binding as AAD. Mirrors monocles Android `XmppOmemo2Message.encrypt`.
fn omemo2_seal(
    message_key: &[u8],
    plaintext: &[u8],
    from: &str,
    to: Option<&str>,
    sid: u32,
) -> Result<Vec<u8>> {
    let binding = compute_context_binding(from, to, sid);
    let (mut enc_key, iv) = derive_payload_keys(message_key, &binding)?;
    let cipher =
        Aes256Gcm::new_from_slice(&enc_key).map_err(|e| OmemoError::Aead(e.to_string()))?;
    enc_key.zeroize(); // the cipher copied the key; wipe our copy
    cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad: &binding })
        .map_err(|e| OmemoError::Aead(e.to_string()))
}

/// NIST SP 800-185 §2.3.1 `left_encode`: the byte length of `value`, then `value` big-endian.
fn left_encode(value: u64, out: &mut Vec<u8>) {
    let bytes = value.to_be_bytes();
    // Index of the first significant byte; a zero value still encodes as one 0x00 byte.
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    out.push((8 - first) as u8);
    out.extend_from_slice(&bytes[first..]);
}

/// NIST SP 800-185 §2.3.1 `right_encode`: `value` big-endian, then its byte length.
fn right_encode(value: u64, out: &mut Vec<u8>) {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    out.extend_from_slice(&bytes[first..]);
    out.push((8 - first) as u8);
}

/// NIST SP 800-185 §2.3.2 `encode_string`: the *bit* length of `s`, then `s`.
fn encode_string(s: &[u8], out: &mut Vec<u8>) {
    left_encode((s.len() as u64) * 8, out);
    out.extend_from_slice(s);
}

/// NIST SP 800-185 §2.3.3 `bytepad(X, w)`: `left_encode(w) || X`, zero-padded to a multiple of `w`.
///
/// The output length is computed up front and allocated exactly. That matters here because `X`
/// wraps the message key: a `Vec` that grew would leave a copy of it in a freed buffer that the
/// caller's `zeroize` could never reach.
fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(9);
    left_encode(w as u64, &mut prefix);
    let padded_len = (prefix.len() + x.len()).div_ceil(w) * w;
    let mut z = Vec::with_capacity(padded_len);
    z.extend_from_slice(&prefix);
    z.extend_from_slice(x);
    z.resize(padded_len, 0);
    z
}

/// Keccak rate of cSHAKE256 in bytes — the `w` KMAC256 pads its encoded key to.
const KMAC256_RATE: usize = 136;

/// KMAC256 (NIST SP 800-185 §4): a keyed, variable-output PRF over cSHAKE256.
///
/// `KMAC256(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L),
/// L, "KMAC", S)`. `CShake256::new_with_function_name` supplies the `"KMAC"` function name and the
/// customization-string prefix, so only the three SP 800-185 encodings above are ours.
///
/// This MUST agree byte-for-byte with BouncyCastle's `org.bouncycastle.crypto.macs.KMAC` on the
/// Android side. Both are pinned to NIST's own published sample vectors (see
/// `kmac256_nist_sp800_185_vectors`) rather than merely to each other, so a divergence in these
/// hand-written encodings cannot pass unnoticed.
fn kmac256(key: &[u8], data: &[u8], customization: &[u8], out: &mut [u8]) {
    // Both buffers below hold the caller's key, so both are bound to locals rather than passed as
    // temporaries — a temporary would be dropped un-zeroized and leave the message key in freed
    // heap memory. Neither reallocates either (see `bytepad`; `encode_string` appends at most a
    // 9-byte prefix to `key`), so there is no grown-out-of buffer to miss.
    let mut encoded_key = Vec::with_capacity(key.len() + 9);
    encode_string(key, &mut encoded_key);
    let mut padded_key = bytepad(&encoded_key, KMAC256_RATE);
    encoded_key.zeroize();

    let mut h: CShake256 =
        CoreWrapper::from_core(CShake256Core::new_with_function_name(b"KMAC", customization));
    h.update(&padded_key);
    h.update(data);

    let mut tail = Vec::with_capacity(9);
    right_encode((out.len() as u64) * 8, &mut tail);
    h.update(&tail);

    h.finalize_xof_into(out);
    padded_key.zeroize();
    // The sponge inside `h` also absorbed the key and is not zeroized on drop — `CShake256` does
    // not implement `Zeroize`. That leaves a permuted Keccak state rather than the key itself
    // (`padded_key` is an exact multiple of the rate, so no verbatim tail bytes sit in the
    // buffer), but it is a library limitation worth naming rather than implying a full wipe.
}

/// Key commitment: `KMAC256(key = MK, data = binding, L = 512, S = COMMIT_CUSTOMIZATION)`.
///
/// A single shared value that binds the ciphertext to exactly one message key, making the AEAD
/// key-committing. Keyed by `MK` itself, so hiding follows from KMAC's PRF security rather than
/// from one-wayness of an unkeyed hash; binding is preserved because KMAC absorbs the encoded key
/// as ordinary sponge input, making a key-collision a sponge collision (256-bit at this output
/// length). Independent of the payload key/IV (`derive_payload_keys`) by customization string
/// alone — one primitive, not two families. Byte-identical to Android's
/// `XmppOmemo2Message.keyCommitment`.
fn omemo2_key_commitment(message_key: &[u8], binding: &[u8]) -> Result<[u8; COMMIT_LEN]> {
    let mut out = [0u8; COMMIT_LEN];
    kmac256(message_key, binding, COMMIT_CUSTOMIZATION, &mut out);
    Ok(out)
}

/// Constant-time equality for the (public, fixed-length) key-commitment digests.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// OMEMO2 payload open: verify the key commitment, then HKDF(message_key, salt=binding) → key||iv
/// and AES-256-GCM decrypt with the binding as AAD (which authenticates the from/to/sid context).
/// Fails if the commitment is missing/mismatched or the tag is invalid.
fn omemo2_open(
    message_key: &[u8],
    payload: &[u8],
    from: &str,
    to: Option<&str>,
    sid: u32,
    commit: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if payload.len() < TAG_LEN {
        return Err(OmemoError::Aead("payload shorter than GCM tag".into()));
    }
    let binding = compute_context_binding(from, to, sid);
    // Key-commitment check BEFORE using the key: recompute from the unwrapped message key and
    // require equality with the sender's single published <commit>. This makes the AEAD
    // key-committing — a ciphertext opens under exactly one message key — closing invisible-
    // salamander collisions and malicious-sender equivocation. Fail closed if it is absent.
    let expected = omemo2_key_commitment(message_key, &binding)?;
    match commit {
        Some(c) if ct_eq(c, &expected) => {}
        _ => return Err(OmemoError::Aead("OMEMO2 key commitment missing or mismatched".into())),
    }
    let (mut enc_key, iv) = derive_payload_keys(message_key, &binding)?;
    let cipher =
        Aes256Gcm::new_from_slice(&enc_key).map_err(|e| OmemoError::Aead(e.to_string()))?;
    enc_key.zeroize(); // the cipher copied the key; wipe our copy
    cipher
        .decrypt(Nonce::from_slice(&iv), Payload { msg: payload, aad: &binding })
        .map_err(|_| OmemoError::Aead("OMEMO2 GCM authentication failed".into()))
}

/// `KMAC256(key=message_key, data=binding, L=352, S=PAYLOAD_CUSTOMIZATION)` → (encKey[32], iv[12]).
///
/// Same primitive and key as the commitment, separated only by the customization string, so their
/// independence rests on KMAC being a PRF rather than on two unrelated hash families not
/// correlating. Must match Android's `XmppOmemo2Message` payload derivation exactly.
fn derive_payload_keys(message_key: &[u8], binding: &[u8]) -> Result<([u8; 32], [u8; IV_LEN])> {
    let mut okm = [0u8; KDF_OUTPUT_LEN];
    kmac256(message_key, binding, PAYLOAD_CUSTOMIZATION, &mut okm);
    let mut enc = [0u8; 32];
    let mut iv = [0u8; IV_LEN];
    enc.copy_from_slice(&okm[0..MSG_KEY_LEN]);
    iv.copy_from_slice(&okm[MSG_KEY_LEN..KDF_OUTPUT_LEN]);
    okm.zeroize(); // wipe the combined key+iv material
    Ok((enc, iv))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Generate a fresh long-term hybrid identity — a classical Curve25519/Ed25519
/// [`IdentityKeyPair`] plus a post-quantum ML-DSA-87 [`PqIdentityKeyPair`] — and a random
/// non-zero device/registration id.
pub fn generate_identity() -> (IdentityKeyPair, PqIdentityKeyPair, u32) {
    let mut rng = rand::rng();
    let identity = IdentityKeyPair::generate(&mut rng);
    let pq_identity = PqIdentityKeyPair::generate(&mut rng);
    // OMEMO device ids are positive 31-bit integers.
    let device_id = (rng.next_u32() & 0x7fff_ffff).max(1);
    (identity, pq_identity, device_id)
}

/// Generate a fresh post-quantum (ML-DSA-87) identity key pair, serialized. Used to
/// upgrade an existing classical-only OMEMO2 install in place (the classical identity and
/// its fingerprint are unchanged, so no re-verification is needed).
pub fn new_pq_identity_bytes() -> Vec<u8> {
    let mut rng = rand::rng();
    PqIdentityKeyPair::generate(&mut rng).serialize().to_vec()
}

/// Generate a new hybrid identity, returning (serialized classical identity-key-pair bytes,
/// serialized ML-DSA-87 identity-key-pair bytes, device id). Both secret blobs are sealed in
/// the secret service by the caller; the device id goes in the DB. Keeps libsignal types out
/// of `mxc-proto`.
pub fn new_identity_bytes() -> (Vec<u8>, Vec<u8>, u32) {
    let (identity, pq_identity, device_id) = generate_identity();
    (identity.serialize().to_vec(), pq_identity.serialize().to_vec(), device_id)
}

/// Reconstruct an [`OmemoStores`] from a serialized classical + post-quantum identity key
/// pair and device id.
pub fn stores_from_identity(
    store: mxc_store::Store,
    account_id: i64,
    identity_bytes: &[u8],
    pq_identity_bytes: &[u8],
    device_id: u32,
) -> Result<OmemoStores> {
    let identity = IdentityKeyPair::try_from(identity_bytes)?;
    let pq_identity = PqIdentityKeyPair::deserialize(pq_identity_bytes)?;
    Ok(OmemoStores::new(store, account_id, identity, device_id, pq_identity))
}

/// Sign the monocles hybrid-identity transcript (v4) binding the device's post-quantum
/// identity key to its classical identity key, EC signed pre-key, and — via the KEM binding
/// digest — every ML-KEM pre-key in the bundle (kem-spk + all one-time kem-pk), proto-XEP
/// §4.9.1. It is signed by BOTH identity keys: the ML-DSA-87 signature stops a quantum
/// adversary substituting any of it, the classical one stops anyone without our classical
/// private key attaching a pq_ik of their own. Returns `(pq_ik, pq_sig, ik_sig)`. The
/// transcript and binding are computed by libsignal's [`pq_bundle_transcript`] /
/// [`pq_kem_binding`] so they are byte-identical to what a verifier (incl. the Android
/// client) recomputes and checks.
fn sign_bundle_pq(
    stores: &OmemoStores,
    signed_prekey_id: u32,
    signed_pre_key_public: &PublicKey,
    kem_spk_id: u32,
    kem_spk_public: &[u8],
    kem_one_time: &[(u32, &[u8])],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut rng = rand::rng();
    let pq = stores.pq_identity();
    let pq_pub = pq.public_key();
    let one_time: Vec<(KyberPreKeyId, &[u8])> = kem_one_time
        .iter()
        .map(|(id, k)| (KyberPreKeyId::from(*id), *k))
        .collect();
    let kem_binding = pq_kem_binding(KyberPreKeyId::from(kem_spk_id), kem_spk_public, &one_time);
    let transcript = pq_bundle_transcript(
        stores.identity().identity_key(),
        &pq_pub,
        SignedPreKeyId::from(signed_prekey_id),
        signed_pre_key_public,
        &kem_binding,
    );
    let sig = pq.sign(&transcript, &mut rng).map_err(|e| OmemoError::Signal(e.to_string()))?;
    let ik_sig = stores
        .identity()
        .private_key()
        .calculate_signature(&transcript, &mut rng)
        .map_err(|e| OmemoError::Signal(e.to_string()))?
        .to_vec();
    Ok((pq_pub.serialize().to_vec(), sig.serialize().to_vec(), ik_sig))
}

/// Generate one signed pre-key (EC), one last-resort signed KEM pre-key, plus `count`
/// one-time EC pre-keys and `count` one-time KEM pre-keys; store them all and return the
/// publishable [`Bundle`] (proto-XEP §4.3).
pub async fn generate_and_store_prekeys(
    stores: &OmemoStores,
    signed_prekey_id: u32,
    kem_signed_id: u32,
    first_prekey_id: u32,
    count: u32,
) -> Result<Bundle> {
    let mut rng = rand::rng();
    let acc = stores.account_id;
    let ik_priv = stores.identity().private_key();

    // EC one-time pre-keys.
    let mut prekeys = Vec::new();
    for i in 0..count {
        let id = first_prekey_id + i;
        let kp = KeyPair::generate(&mut rng);
        let rec = PreKeyRecord::new(PreKeyId::from(id), &kp);
        stores.store.store_prekey(acc, id as i64, &rec.serialize()?).await?;
        prekeys.push((id, ec_raw(&kp.public_key.serialize())));
    }

    // Signed EC pre-key.
    let spk_kp = KeyPair::generate(&mut rng);
    let spk_pub = spk_kp.public_key.serialize();
    let spk_sig = ik_priv
        .calculate_signature(&spk_pub, &mut rng)
        .map_err(|e| OmemoError::Signal(e.to_string()))?
        .to_vec();
    let spk_rec = SignedPreKeyRecord::new(
        SignedPreKeyId::from(signed_prekey_id),
        Timestamp::from_epoch_millis(now_ms()),
        &spk_kp,
        &spk_sig,
    );
    stores
        .store
        .store_signed_prekey(acc, signed_prekey_id as i64, &spk_rec.serialize()?)
        .await?;

    // Last-resort signed KEM pre-key (kem-spk).
    let kem_spk_rec =
        KyberPreKeyRecord::generate(kem::KeyType::MLKEM1024, KyberPreKeyId::from(kem_signed_id), ik_priv)?;
    stores
        .store
        .store_kyber_prekey(acc, kem_signed_id as i64, &kem_spk_rec.serialize()?, true)
        .await?;
    let kem_spk = kem_spk_rec.public_key()?.serialize().to_vec();
    let kem_spk_sig = kem_spk_rec.signature()?;

    // One-time KEM pre-keys (kem-prekeys).
    let mut kem_prekeys = Vec::new();
    for i in 0..count {
        let id = kem_signed_id + 1 + i;
        let rec =
            KyberPreKeyRecord::generate(kem::KeyType::MLKEM1024, KyberPreKeyId::from(id), ik_priv)?;
        stores.store.store_kyber_prekey(acc, id as i64, &rec.serialize()?, false).await?;
        kem_prekeys.push(KemPreKey {
            id,
            key: rec.public_key()?.serialize().to_vec(),
            sig: rec.signature()?,
        });
    }

    let kem_ot: Vec<(u32, &[u8])> =
        kem_prekeys.iter().map(|k| (k.id, k.key.as_slice())).collect();
    let (pq_ik, pq_sig, ik_sig) = sign_bundle_pq(
        stores,
        signed_prekey_id,
        &spk_kp.public_key,
        kem_signed_id,
        &kem_spk,
        &kem_ot,
    )?;

    Ok(Bundle {
        spk_id: signed_prekey_id,
        spk: ec_raw(&spk_pub),
        spk_sig,
        ik: ec_raw(&stores.identity().identity_key().public_key().serialize()),
        prekeys,
        kem_spk_id: kem_signed_id,
        kem_spk,
        kem_spk_sig,
        kem_prekeys,
        pq_ik,
        pq_sig,
        ik_sig,
    })
}

/// Maintain the published bundle (proto-XEP §4.5): on first use generate the full key set;
/// otherwise top up one-time EC/KEM pre-keys when stock falls below `low_water` and rebuild
/// the bundle from the keys we currently hold (so we never advertise a consumed pre-key).
pub async fn maintain_bundle(
    stores: &OmemoStores,
    signed_prekey_id: u32,
    kem_signed_id: u32,
    first_prekey_id: u32,
    target: u32,
    low_water: u32,
) -> Result<Bundle> {
    let fresh = stores
        .store
        .load_signed_prekey(stores.account_id, signed_prekey_id as i64)
        .await?
        .is_none();
    if fresh {
        return generate_and_store_prekeys(stores, signed_prekey_id, kem_signed_id, first_prekey_id, target)
            .await;
    }
    // Upgrade path: discard retained Round-3 Kyber prekeys first, so `replenish` sees the real
    // ML-KEM count and `rotate_last_resort_if_due` does not keep a Round-3 signed prekey.
    purge_non_ml_kem_prekeys(stores).await?;
    replenish(stores, target, low_water).await?;
    rotate_last_resort_if_due(stores).await?;
    // The EC signed pre-key rotates on the same schedule as the KEM one; publish whichever id
    // that leaves current (the caller's `signed_prekey_id` is only the id of the very first).
    let current_spk_id = rotate_signed_prekey_if_due(stores, signed_prekey_id).await?;
    prune_stale_kyber_prekeys(stores).await?;
    rebuild_bundle(stores, current_spk_id).await
}

/// Delete stored KEM prekeys that are not FIPS 203 ML-KEM-1024.
///
/// PQ-OMEMO2 moved from Round-3 CRYSTALS-Kyber-1024 to ML-KEM-1024 (proto-XEP §5.1.1), but both
/// the last-resort key and the one-time pool are deliberately *retained* across publishes — the
/// signed prekey until it ages out of its rotation window, the one-time keys until consumed.
/// Without this purge an upgraded client would keep republishing its old Round-3 keys: every peer
/// would reject the bundle, and the one-time pool would never refill because its count already
/// sits at the target, so nothing would trigger regeneration.
///
/// Deleting rather than skipping is deliberate — the row count is what `replenish` keys off.
/// Losing the old private keys costs nothing: they can only open Round-3 sessions, which this
/// profile's transcript and payload changes already invalidated. Idempotent.
async fn purge_non_ml_kem_prekeys(stores: &OmemoStores) -> Result<()> {
    let acc = stores.account_id;
    let mut purged = 0usize;
    for (id, bytes, _is_last_resort, _used) in stores.store.all_kyber_prekeys(acc).await? {
        let is_ml_kem = KyberPreKeyRecord::deserialize(&bytes)
            .ok()
            .and_then(|rec| rec.public_key().ok())
            .map(|pk| crate::bundle::is_ml_kem_1024(&pk.serialize()))
            .unwrap_or(false); // an unreadable row is stale too — it cannot be published either
        if !is_ml_kem {
            stores.store.delete_kyber_prekey(acc, id).await?;
            purged += 1;
        }
    }
    if purged > 0 {
        tracing::info!(
            purged,
            "discarded KEM prekeys that were not ML-KEM-1024; they will be regenerated"
        );
    }
    Ok(())
}

/// Rotate the signed (last-resort) KEM prekey after this age (proto-XEP §4.5.1 allows
/// 7–90 days; 30 keeps last-resort exposure short without churning the bundle). Matches
/// Android's `KEM_SPK_ROTATION_MS`.
const KEM_SPK_ROTATION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Rotate the EC signed pre-key on the same schedule (proto-XEP §4.5.1). The two are the
/// classical and post-quantum halves of the same handshake: a signed pre-key that stays
/// published for years widens the window in which its compromise unlocks every session
/// established against it. Matches Android's `SIGNED_PREKEY_ROTATION_MS`.
const SIGNED_PREKEY_ROTATION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Delete consumed / superseded KEM prekeys older than this: any in-flight
/// PreKeySignalMessage still referencing them is long dead, and keeping them only grows
/// the at-rest secret-key store. Matches Android's `KEM_PREKEY_MAX_AGE_MS`.
const KEM_PREKEY_MAX_AGE_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// Generate and store a NEW last-resort KEM prekey (next free id) once the current one has
/// aged past [`KEM_SPK_ROTATION_MS`]. The superseded one stays in the store for the
/// [`KEM_PREKEY_MAX_AGE_MS`] grace period so in-flight session initiations against a
/// previously fetched bundle still decrypt; `rebuild_bundle` publishes only the newest.
async fn rotate_last_resort_if_due(stores: &OmemoStores) -> Result<()> {
    let acc = stores.account_id;
    let Some((_, bytes)) = stores.store.last_resort_kyber(acc).await? else {
        return Ok(()); // fresh path creates it; nothing to rotate
    };
    let rec = KyberPreKeyRecord::deserialize(&bytes)?;
    let age = now_ms().saturating_sub(rec.timestamp()?.epoch_millis());
    if age <= KEM_SPK_ROTATION_MS {
        return Ok(());
    }
    let next = stores.store.max_kyber_prekey_id(acc).await? as u32 + 1;
    let ik_priv = stores.identity().private_key();
    let new_rec =
        KyberPreKeyRecord::generate(kem::KeyType::MLKEM1024, KyberPreKeyId::from(next), ik_priv)?;
    stores.store.store_kyber_prekey(acc, next as i64, &new_rec.serialize()?, true).await?;
    Ok(())
}

/// Generate and store a NEW EC signed pre-key (next free id) once the current one has aged past
/// [`SIGNED_PREKEY_ROTATION_MS`], and return the id to publish.
///
/// The superseded record is deliberately KEPT under its old id: peers that fetched the previous
/// bundle cite that id in their PreKeySignalMessage, and the store resolves it by id — reusing
/// the id for new key material instead would break every handshake already in flight against it.
async fn rotate_signed_prekey_if_due(stores: &OmemoStores, fallback_id: u32) -> Result<u32> {
    let acc = stores.account_id;
    let Some((current_id, bytes)) = stores.store.newest_signed_prekey(acc).await? else {
        return Ok(fallback_id); // fresh path creates it; nothing to rotate
    };
    let rec = SignedPreKeyRecord::deserialize(&bytes)?;
    let age = now_ms().saturating_sub(rec.timestamp()?.epoch_millis());
    if age <= SIGNED_PREKEY_ROTATION_MS {
        return Ok(current_id as u32);
    }

    let next = current_id as u32 + 1;
    let mut rng = rand::rng();
    let ik_priv = stores.identity().private_key();
    let kp = KeyPair::generate(&mut rng);
    let pub_bytes = kp.public_key.serialize();
    let sig = ik_priv
        .calculate_signature(&pub_bytes, &mut rng)
        .map_err(|e| OmemoError::Signal(e.to_string()))?
        .to_vec();
    let new_rec = SignedPreKeyRecord::new(
        SignedPreKeyId::from(next),
        Timestamp::from_epoch_millis(now_ms()),
        &kp,
        &sig,
    );
    stores.store.store_signed_prekey(acc, next as i64, &new_rec.serialize()?).await?;
    Ok(next)
}

/// Delete KEM prekeys that can no longer serve any purpose: consumed one-time keys and
/// superseded last-resort keys older than [`KEM_PREKEY_MAX_AGE_MS`]. Unconsumed one-time
/// keys are never pruned — they are still part of the published bundle.
async fn prune_stale_kyber_prekeys(stores: &OmemoStores) -> Result<()> {
    let acc = stores.account_id;
    let cutoff = now_ms().saturating_sub(KEM_PREKEY_MAX_AGE_MS);
    let current_last_resort = stores.store.last_resort_kyber(acc).await?.map(|(id, _)| id);
    for (id, bytes, is_last_resort, used) in stores.store.all_kyber_prekeys(acc).await? {
        if Some(id) == current_last_resort {
            continue;
        }
        // prunable: consumed one-time keys, and superseded (non-current) last-resorts
        if !used && !is_last_resort {
            continue;
        }
        let Ok(rec) = KyberPreKeyRecord::deserialize(&bytes) else { continue };
        let ts = rec.timestamp().map(|t| t.epoch_millis()).unwrap_or(0);
        if ts < cutoff {
            stores.store.delete_kyber_prekey(acc, id).await?;
        }
    }
    // With the superseded keys gone, drop the last-resort replay records that named them: they
    // are unreachable (the replay now fails at key lookup) and that table is otherwise
    // append-only and remotely growable — one row per handshake anyone on the network initiates
    // against our last-resort key.
    let orphaned = stores.store.prune_orphaned_kyber_last_resort_sessions(acc).await?;
    if orphaned > 0 {
        tracing::info!(orphaned, "omemo: pruned last-resort replay records for deleted KEM prekeys");
    }
    Ok(())
}

/// Generate fresh one-time EC/KEM pre-keys to bring each set back up to `target` when it
/// has dropped below `low_water`. New ids continue past the current maximum.
async fn replenish(stores: &OmemoStores, target: u32, low_water: u32) -> Result<()> {
    let acc = stores.account_id;
    let mut rng = rand::rng();
    let ik_priv = stores.identity().private_key();

    let ec_count = stores.store.count_prekeys(acc).await? as u32;
    if ec_count < low_water {
        let mut next = stores.store.max_prekey_id(acc).await? as u32 + 1;
        for _ in ec_count..target {
            let kp = KeyPair::generate(&mut rng);
            let rec = PreKeyRecord::new(PreKeyId::from(next), &kp);
            stores.store.store_prekey(acc, next as i64, &rec.serialize()?).await?;
            next += 1;
        }
    }

    let kem_count = stores.store.available_kyber_prekeys(acc).await?.len() as u32;
    if kem_count < low_water {
        let mut next = stores.store.max_kyber_prekey_id(acc).await? as u32 + 1;
        for _ in kem_count..target {
            let rec =
                KyberPreKeyRecord::generate(kem::KeyType::MLKEM1024, KyberPreKeyId::from(next), ik_priv)?;
            stores.store.store_kyber_prekey(acc, next as i64, &rec.serialize()?, false).await?;
            next += 1;
        }
    }
    Ok(())
}

/// Build a publishable [`Bundle`] from the keys currently in the store (signed pre-key,
/// last-resort KEM pre-key, and all available one-time EC/KEM pre-keys).
async fn rebuild_bundle(stores: &OmemoStores, signed_prekey_id: u32) -> Result<Bundle> {
    let acc = stores.account_id;

    let spk_bytes = stores
        .store
        .load_signed_prekey(acc, signed_prekey_id as i64)
        .await?
        .ok_or_else(|| OmemoError::Signal("missing signed prekey".into()))?;
    let spk_rec = SignedPreKeyRecord::deserialize(&spk_bytes)?;

    let (kem_id, kem_bytes) = stores
        .store
        .last_resort_kyber(acc)
        .await?
        .ok_or_else(|| OmemoError::Signal("missing last-resort kyber prekey".into()))?;
    let kem_rec = KyberPreKeyRecord::deserialize(&kem_bytes)?;

    let mut prekeys = Vec::new();
    for (id, bytes) in stores.store.list_prekeys(acc).await? {
        let rec = PreKeyRecord::deserialize(&bytes)?;
        prekeys.push((id as u32, ec_raw(&rec.public_key()?.serialize())));
    }

    let mut kem_prekeys = Vec::new();
    for (id, bytes) in stores.store.available_kyber_prekeys(acc).await? {
        let rec = KyberPreKeyRecord::deserialize(&bytes)?;
        kem_prekeys.push(KemPreKey {
            id: id as u32,
            key: rec.public_key()?.serialize().to_vec(),
            sig: rec.signature()?,
        });
    }

    let spk_id = u32::from(spk_rec.id()?);
    let kem_spk_public = kem_rec.public_key()?.serialize().to_vec();
    let kem_ot: Vec<(u32, &[u8])> =
        kem_prekeys.iter().map(|k| (k.id, k.key.as_slice())).collect();
    let (pq_ik, pq_sig, ik_sig) = sign_bundle_pq(
        stores,
        spk_id,
        &spk_rec.public_key()?,
        kem_id as u32,
        &kem_spk_public,
        &kem_ot,
    )?;

    Ok(Bundle {
        spk_id,
        spk: ec_raw(&spk_rec.public_key()?.serialize()),
        spk_sig: spk_rec.signature()?,
        ik: ec_raw(&stores.identity().identity_key().public_key().serialize()),
        prekeys,
        kem_spk_id: kem_id as u32,
        kem_spk: kem_rec.public_key()?.serialize().to_vec(),
        kem_spk_sig: kem_rec.signature()?,
        kem_prekeys,
        pq_ik,
        pq_sig,
        ik_sig,
    })
}

/// Establish an outbound PQXDH session toward `remote` from their published [`Bundle`].
///
/// Picks a one-time `<kem-pk>` if available, else the last-resort `<kem-spk>`, and a
/// random one-time EC `<pk>`. libsignal's `process_prekey_bundle` verifies the bundle
/// signatures against the bundle's identity key and runs PQXDH (X3DH + ML-KEM encaps).
pub async fn establish_session(
    stores: &OmemoStores,
    our_jid: &str,
    our_device: u32,
    remote: &DeviceAddr,
    bundle: &Bundle,
) -> Result<()> {
    if !bundle.supports_pqxdh() {
        return Err(OmemoError::NoPqxdh);
    }
    // The monocles hybrid post-quantum identity is mandatory — never downgrade.
    if !bundle.has_pq_identity() {
        return Err(OmemoError::NoPqIdentity);
    }

    let ik = IdentityKey::decode(&ec_djb(&bundle.ik))?;
    let pq_identity_key = PqIdentityKey::deserialize(&bundle.pq_ik)?;
    let pq_signature = PqSignature::deserialize(&bundle.pq_sig)?;

    // TOFU-pin the post-quantum identity, keyed to (owning JID, classical identity key). A
    // *different* `<pq-ik>` for an identity we have already pinned is ALWAYS refused — also
    // when the classical fingerprint is user-verified (proto-XEP §4.9.2). Earlier builds
    // accepted and re-pinned it in that case, to blunt a pin-poisoning DoS; but a quantum
    // adversary who recovers the classical key could then present a pq_ik of its own and have
    // it accepted precisely because the contact was verified. That DoS is gone: pins are scoped
    // to `remote.jid`, and the v4 transcript is signed by the classical key too, so nobody
    // without that private key can attach a pq_ik to it. The only way to replace a pin is an
    // out-of-band verification of the new hybrid fingerprint (`omemo-pq-hfp-`).
    let fp_key = crate::pq_pin_key(&ik.serialize());
    let pinned = stores
        .store
        .get_pinned_omemo2_pq_identity(stores.account_id, &remote.jid, &fp_key)
        .await?;
    if let Some(pinned) = &pinned {
        if pinned.as_slice() != bundle.pq_ik.as_slice() {
            return Err(OmemoError::PqIdentityChanged(fp_key));
        }
    }
    // Verify both transcript signatures and pin BEFORE process_prekey_bundle: it stores the
    // session, which must never exist against a PQ identity other than the pinned one. Pinning
    // first (atomically) means a concurrent pin of a different key refuses the build before any
    // session is stored; process_prekey_bundle then checks the same signatures again.
    verified_bundle_pq_identity(bundle, &ik.serialize())?;
    let now_pinned = stores
        .store
        .pin_omemo2_pq_identity_if_absent(stores.account_id, &remote.jid, &fp_key, &bundle.pq_ik)
        .await?;
    if now_pinned != bundle.pq_ik {
        return Err(OmemoError::PqIdentityChanged(fp_key));
    }

    // Choose a one-time EC prekey.
    let ec = bundle.prekeys.first().ok_or_else(|| {
        OmemoError::BundleParse("bundle has no one-time EC prekeys".into())
    })?;
    let ec_pub = dec_pub(&ec.1)?;

    // Choose a KEM prekey: one-time if present, else last-resort signed kem-spk.
    let (kem_id, kem_pub_bytes, _kem_sig) = match bundle.kem_prekeys.first() {
        Some(kp) => (kp.id, &kp.key, &kp.sig),
        None => (bundle.kem_spk_id, &bundle.kem_spk, &bundle.kem_spk_sig),
    };
    let kem_pub = kem::PublicKey::deserialize(kem_pub_bytes)?;

    // Recompute the KEM binding over ALL of the fetched bundle's ML-KEM pre-keys
    // (kem-spk + every one-time kem-pk). `with_pq_identity` makes
    // process_prekey_bundle (below) verify both signatures over the v4 transcript —
    // which covers this binding — so a substituted KEM pre-key (the harvest-and-forge
    // vector) or a foreign pq_ik aborts here.
    let kem_ot: Vec<(KyberPreKeyId, &[u8])> = bundle
        .kem_prekeys
        .iter()
        .map(|k| (KyberPreKeyId::from(k.id), k.key.as_slice()))
        .collect();
    let kem_binding = pq_kem_binding(
        KyberPreKeyId::from(bundle.kem_spk_id),
        &bundle.kem_spk,
        &kem_ot,
    );
    let pre_bundle = PreKeyBundle::new(
        remote.device_id, // OMEMO uses the device id as the registration id
        device_id(remote.device_id)?,
        Some((PreKeyId::from(ec.0), ec_pub)),
        SignedPreKeyId::from(bundle.spk_id),
        dec_pub(&bundle.spk)?,
        bundle.spk_sig.clone(),
        KyberPreKeyId::from(kem_id),
        kem_pub,
        _kem_sig.clone(),
        ik,
    )?
    .with_pq_identity(
        pq_identity_key,
        pq_signature,
        bundle.ik_sig.clone(),
        kem_binding.to_vec(),
    );

    let remote_addr = protocol_address(&remote.jid, remote.device_id)?;
    let local_addr = protocol_address(our_jid, our_device)?;
    let mut sess = stores.session_store();
    let mut ids = stores.identity_store();
    let mut rng = rand::rng();

    process_prekey_bundle(
        &remote_addr,
        &local_addr,
        &mut sess,
        &mut ids,
        &pre_bundle,
        SystemTime::now(),
        &mut rng,
    )
    .await?;
    // The PQ identity was verified and pinned above, before the session was stored.
    Ok(())
}

/// The post-quantum identity a fetched [`Bundle`] authenticates for the classical identity
/// `known_ik` (serialized, 33 bytes): the bundle must carry exactly that classical key, and both
/// signatures over its v4 transcript must verify ([`pq_bundle_verify`], the check
/// `process_prekey_bundle` makes). Returns the 2592-byte ML-DSA-87 key.
pub fn verified_bundle_pq_identity(bundle: &Bundle, known_ik: &[u8]) -> Result<Vec<u8>> {
    if !bundle.has_pq_identity() {
        return Err(OmemoError::NoPqIdentity);
    }
    let ik = IdentityKey::decode(&ec_djb(&bundle.ik))?;
    if ik.serialize().as_ref() != known_ik {
        return Err(OmemoError::BundleParse(
            "bundle carries a different classical identity key".into(),
        ));
    }
    let pq_identity_key = PqIdentityKey::deserialize(&bundle.pq_ik)?;
    let pq_signature = PqSignature::deserialize(&bundle.pq_sig)?;
    let kem_ot: Vec<(KyberPreKeyId, &[u8])> = bundle
        .kem_prekeys
        .iter()
        .map(|k| (KyberPreKeyId::from(k.id), k.key.as_slice()))
        .collect();
    let kem_binding = pq_kem_binding(
        KyberPreKeyId::from(bundle.kem_spk_id),
        &bundle.kem_spk,
        &kem_ot,
    );
    if !pq_bundle_verify(
        &ik,
        &pq_identity_key,
        &pq_signature,
        &bundle.ik_sig,
        SignedPreKeyId::from(bundle.spk_id),
        &dec_pub(&bundle.spk)?,
        &kem_binding,
    ) {
        return Err(OmemoError::BadSignature("pq bundle transcript"));
    }
    Ok(bundle.pq_ik.clone())
}

/// Verify a fetched [`Bundle`]'s post-quantum identity and **pin-fill** it for a peer whose
/// classical identity we already know but whose pq_ik was never pinned — the state left behind
/// when the PEER initiated the session: an inbound PQXDH key exchange carries the initiator's
/// classical identity key but not its `<pq-ik>`, which only travels in the published bundle.
/// Without the pin the device keeps displaying its classical instead of hybrid fingerprint.
/// Mirrors the Android client's `reconcileOmemo2PqPinIfMissing`.
///
/// Security: strictly a TOFU pin-fill, never a re-pin — an existing pin is NEVER overwritten
/// here (a changed pq_ik remains a refused identity change). Before pinning, the bundle must
/// (a) carry exactly the classical identity key we already hold for this device (`known_ik`,
/// the serialized key from our identity store), so a malicious or compromised PEP node cannot
/// poison the pin of a known identity, and (b) carry valid ML-DSA-87 AND classical signatures
/// over the v4 transcript (ik, pq_ik, EC signed pre-key, KEM binding) — the same
/// [`pq_bundle_verify`] check `process_prekey_bundle` performs during [`establish_session`].
///
/// Returns `Ok(true)` when a pin was written, `Ok(false)` when the same key was already pinned,
/// and [`OmemoError::PqIdentityChanged`] when a *different* one is (the pin is kept).
pub async fn reconcile_pq_pin(
    stores: &OmemoStores,
    remote: &DeviceAddr,
    bundle: &Bundle,
    known_ik: &[u8],
) -> Result<bool> {
    // (a) the bundle must belong to the classical identity we already know, and (b) both
    // signatures over its v4 transcript must verify.
    verified_bundle_pq_identity(bundle, known_ik).map_err(|e| match e {
        OmemoError::BadSignature(_) => {
            OmemoError::BadSignature("pq bundle transcript (pin reconciliation)")
        }
        other => other,
    })?;

    // Pin-fill only, and NEVER overwrite an existing pin (a concurrent establish_session or
    // inbound handshake may have pinned already). The read tells "already pinned" apart from
    // "pinned now"; the write itself is atomic, so a race between the two cannot overwrite.
    let fp_key = crate::pq_pin_key(known_ik);
    let existing = stores
        .store
        .get_pinned_omemo2_pq_identity(stores.account_id, &remote.jid, &fp_key)
        .await?;
    let newly_pinned = existing.is_none();
    let pinned = match existing {
        Some(pinned) => pinned,
        None => {
            stores
                .store
                .pin_omemo2_pq_identity_if_absent(stores.account_id, &remote.jid, &fp_key, &bundle.pq_ik)
                .await?
        }
    };
    if pinned != bundle.pq_ik {
        // The existing pin stands; the mismatch is an identity change the caller reports.
        return Err(OmemoError::PqIdentityChanged(fp_key));
    }
    Ok(newly_pinned)
}

/// Encrypt `plaintext` (an SCE envelope) for all `recipients` that already have a session.
///
/// `to_bare` is the conversation recipient bare JID that goes into the payload's context binding
/// (proto-XEP §5.4.2) — for a 1:1 the counterpart, for a MUC the room JID, matching the SCE
/// `<to>`. `None` binds an empty recipient segment (metadata-only stanzas without a `<to>`).
pub async fn encrypt(
    stores: &OmemoStores,
    our_jid: &str,
    our_device: u32,
    recipients: &[DeviceAddr],
    to_bare: Option<&str>,
    plaintext: &[u8],
) -> Result<EncryptedMessage> {
    let mut rng = rand::rng();

    // Fresh 32-byte message key; seal the SCE plaintext (AES-256-GCM, HKDF-derived key+IV, with
    // the from/to/sid context binding as HKDF salt + GCM AAD).
    let mut message_key = [0u8; MSG_KEY_LEN];
    rng.fill_bytes(&mut message_key);
    let payload = omemo2_seal(&message_key, plaintext, our_jid, to_bare, our_device)?;
    // Publish the key commitment alongside the payload (same message key + context binding).
    let commit = omemo2_key_commitment(
        &message_key,
        &compute_context_binding(our_jid, to_bare, our_device),
    )?;

    // Wrap the message key per recipient device through the libsignal ratchet.
    let local_addr = protocol_address(our_jid, our_device)?;
    let mut keys = Vec::new();
    for r in recipients {
        let remote_addr = protocol_address(&r.jid, r.device_id)?;
        let mut sess = stores.session_store();
        let mut ids = stores.identity_store();
        let ct = message_encrypt(
            &message_key,
            &remote_addr,
            &local_addr,
            &mut sess,
            &mut ids,
            SystemTime::now(),
            &mut rng,
        )
        .await?;
        use libsignal_protocol::CiphertextMessageType;
        let kex = ct.message_type() == CiphertextMessageType::PreKey;
        keys.push(WrappedKey {
            jid: r.jid.clone(),
            device_id: r.device_id,
            data: ct.serialize().to_vec(),
            kex,
        });
    }
    // All per-device wraps done — the raw message key must not linger in the heap
    // (mirrors Android's XmppOmemo2Message.wipeMessageKey).
    message_key.zeroize();

    let pq_auth = sign_pq_auth(stores, our_jid, our_device, &keys)?;
    Ok(EncryptedMessage { payload, keys, commit, pq_auth })
}

/// Decrypt one wrapped key + payload addressed to us. Returns the SCE plaintext.
///
/// `expected_to` is the recipient bare JID the sender is expected to have bound into the payload
/// (proto-XEP §5.4.2): our own bare JID for an incoming 1:1, the counterpart for a carbon of our
/// own send, the room JID for a MUC, or `None` when it can't be determined (bound as empty). GCM
/// decryption fails if the recomputed binding — sender bare JID (`from.jid`), `expected_to`, and
/// the sender's device id (`from.device_id`) — does not match what the sender used.
pub async fn decrypt(
    stores: &OmemoStores,
    our_jid: &str,
    our_device: u32,
    from: &DeviceAddr,
    expected_to: Option<&str>,
    wrapped_key: &[u8],
    is_kex: bool,
    payload: &[u8],
    commit: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let remote_addr = protocol_address(&from.jid, from.device_id)?;
    let local_addr = protocol_address(our_jid, our_device)?;
    let mut sess = stores.session_store();
    let mut ids = stores.identity_store();
    let mut rng = rand::rng();

    let message_key = if is_kex {
        let msg = PreKeySignalMessage::try_from(wrapped_key)?;
        let mut pre = stores.pre_key_store();
        let signed = stores.signed_pre_key_store();
        let mut kyber = stores.kyber_pre_key_store();
        message_decrypt_prekey(
            &msg, &remote_addr, &local_addr, &mut sess, &mut ids, &mut pre, &signed, &mut kyber,
            &mut rng,
        )
        .await?
    } else {
        let msg = SignalMessage::try_from(wrapped_key)?;
        message_decrypt_signal(&msg, &remote_addr, &local_addr, &mut sess, &mut ids, &mut rng).await?
    };

    let mut message_key = message_key;
    if message_key.len() != MSG_KEY_LEN {
        message_key.zeroize();
        return Err(OmemoError::Aead(format!(
            "OMEMO2 message key must be {MSG_KEY_LEN} bytes",
        )));
    }
    // A key-transport message carries no `<payload>`: decrypting the wrapped key above already
    // (re)established/advanced the libsignal session — which is the whole point of a heal — so
    // there is nothing to open. Return empty content; the caller treats it as a no-op message.
    if payload.is_empty() {
        message_key.zeroize();
        return Ok(Vec::new());
    }
    let out = omemo2_open(&message_key, payload, &from.jid, expected_to, from.device_id, commit);
    // Single-use unwrapped key — zero it as soon as the payload is open (Android parity).
    message_key.zeroize();
    out
}

/// For a non-kex whisper message, return its Double Ratchet message `(counter,
/// sender_ratchet_key)`. A `PreKeySignalMessage` (kex) starts a fresh chain at counter 0, so it
/// never needs a heartbeat and returns `None`. Used to implement XEP-0384's rule that the first
/// message received for a given ratchet key with counter ≥ 53 MUST be answered with a heartbeat,
/// forcing a DH-ratchet step so the chain (and skipped-key storage) restarts from 0.
pub fn whisper_ratchet_counter(wrapped_key: &[u8], is_kex: bool) -> Option<(u32, Vec<u8>)> {
    if is_kex {
        return None;
    }
    let msg = SignalMessage::try_from(wrapped_key).ok()?;
    Some((msg.counter(), msg.sender_ratchet_key().serialize().to_vec()))
}

fn device_id(id: u32) -> Result<libsignal_protocol::DeviceId> {
    libsignal_protocol::DeviceId::try_from(id)
        .map_err(|_| OmemoError::Signal("zero device id".into()))
}

/// Decode a curve public key (its `CurveError` doesn't convert into `OmemoError`).
/// Accepts both raw 32-byte (OMEMO2 wire / Android) and 33-byte DJB-prefixed forms.
fn dec_pub(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::try_from(ec_djb(bytes).as_slice()).map_err(|e| OmemoError::Signal(e.to_string()))
}

/// Ensure an EC public key is in libsignal's 33-byte DJB form (`0x05` ‖ 32 bytes).
/// OMEMO2 publishes raw 32-byte Curve25519 keys (no type prefix); libsignal needs the
/// prefix.
fn ec_djb(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 32 {
        let mut v = Vec::with_capacity(33);
        v.push(0x05);
        v.extend_from_slice(bytes);
        v
    } else {
        bytes.to_vec()
    }
}

/// Strip libsignal's `0x05` type prefix → the raw 32-byte form OMEMO2 publishes on the
/// wire (so Android/the spec can read our bundle).
fn ec_raw(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 33 && bytes[0] == 0x05 {
        bytes[1..].to_vec()
    } else {
        bytes.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mxc_store::Store;

    async fn party(jid: &str) -> (OmemoStores, u32) {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account(jid).await.unwrap();
        let (identity, pq_identity, device) = generate_identity();
        (OmemoStores::new(store, acc, identity, device, pq_identity), device)
    }

    #[test]
    fn context_binding_layout() {
        // Byte-identical to monocles Android's XmppOmemo2Message.computeContextBinding:
        // "OMEMO2" \0 SENDER_BARE \0 RECIPIENT_BARE \0 u32_be(sid). JIDs are bare-normalised.
        let b = compute_context_binding("alice@example.com/desktop", Some("bob@example.com"), 0x0102_0304);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"OMEMO2\0alice@example.com\0bob@example.com\0");
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(b, expected);

        // A missing recipient (metadata-only SCE without a <to>) is bound as an empty segment.
        assert_eq!(
            compute_context_binding("a@x", None, 1),
            b"OMEMO2\0a@x\0\0\0\0\0\x01"
        );
    }

    /// Retained Round-3 Kyber prekeys from before the ML-KEM switch must be discarded on the
    /// next maintenance pass, not republished.
    ///
    /// This is the upgrade case, and it is the one every other test misses: they all start from
    /// an empty store and therefore always generate ML-KEM. A real device carries its old keys
    /// forward — the last-resort key until it ages out of a 30-day window, the one-time pool
    /// until consumed — so without the purge it would keep publishing a bundle that every peer
    /// (and its own reconciliation) rejects, with the pool never refilling because its count
    /// already sits at target.
    #[tokio::test]
    async fn retained_kyber_prekeys_are_replaced_on_upgrade() {
        let (alice, _dev) = party("alice@example.com").await;
        let acc = alice.account_id;
        let ik_priv = alice.identity().private_key();

        // Simulate a pre-upgrade store: a Round-3 last-resort key plus a full one-time pool.
        let last_resort =
            KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, KyberPreKeyId::from(1u32), ik_priv)
                .unwrap();
        alice.store
            .store_kyber_prekey(acc, 1, &last_resort.serialize().unwrap(), true)
            .await
            .unwrap();
        for id in 2..=3u32 {
            let rec =
                KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, KyberPreKeyId::from(id), ik_priv)
                    .unwrap();
            alice.store
                .store_kyber_prekey(acc, id as i64, &rec.serialize().unwrap(), false)
                .await
                .unwrap();
        }
        // A signed pre-key, so `maintain_bundle` takes the upgrade path rather than the fresh one.
        let bundle = generate_and_store_prekeys(&alice, 1, 100, 200, 2).await.unwrap();
        assert!(!bundle.kem_spk.is_empty());

        let bundle = maintain_bundle(&alice, 1, 100, 200, 2, 2).await.unwrap();

        assert_eq!(
            bundle.kem_spk[0], 0x0A,
            "the retained Round-3 last-resort key must have been rotated out"
        );
        for pk in &bundle.kem_prekeys {
            assert_eq!(pk.key[0], 0x0A, "no Round-3 one-time key may survive into the bundle");
        }
        // And they must be gone from the store, not merely skipped — the row count is what
        // drives the replenish decision.
        for (_, bytes, _, _) in alice.store.all_kyber_prekeys(acc).await.unwrap() {
            let rec = KyberPreKeyRecord::deserialize(&bytes).unwrap();
            assert_eq!(rec.public_key().unwrap().serialize()[0], 0x0A);
        }
    }

    /// The KEM must be **FIPS 203 ML-KEM-1024**, not Round-3 CRYSTALS-Kyber-1024.
    ///
    /// libsignal exposes both under confusingly similar names — `KeyType::Kyber1024` is Round 3
    /// and `KeyType::MLKEM1024` is FIPS 203 — with identical key and ciphertext sizes, so nothing
    /// about the shape of a bundle reveals which one is in use. They are not interoperable (Round
    /// 3 folds `H(ct)` into the shared secret; FIPS 203 does not), and this profile specifies
    /// FIPS 203. The serialized type byte is the only observable difference, so pin it: 0x0A for
    /// ML-KEM-1024, 0x08 for Kyber-1024. This project shipped the wrong one for months precisely
    /// because no test asserted it.
    #[tokio::test]
    async fn kem_prekeys_are_fips203_ml_kem_1024() {
        let (alice, _dev) = party("alice@example.com").await;
        let bundle = generate_and_store_prekeys(&alice, 1, 1000, 100, 2).await.unwrap();

        // Keys go on the wire in libsignal's serialized form: type byte then raw key.
        assert_eq!(
            bundle.kem_spk[0], 0x0A,
            "<kem-spk> must be ML-KEM-1024 (0x0A), not Kyber-1024 (0x08)"
        );
        assert_eq!(
            bundle.kem_spk.len(),
            1 + 1568,
            "ML-KEM-1024 public key is 1568 bytes plus the type byte"
        );

        assert!(!bundle.kem_prekeys.is_empty());
        for pk in &bundle.kem_prekeys {
            assert_eq!(
                pk.key[0], 0x0A,
                "every <kem-pk> must be ML-KEM-1024 (0x0A), not Kyber-1024 (0x08)"
            );
        }
    }

    #[tokio::test]
    async fn pqxdh_session_round_trip() {
        // Bob publishes a PQ bundle.
        let (bob, bob_dev) = party("bob@example.com").await;
        let bob_bundle = generate_and_store_prekeys(&bob, 1, 1000, 100, 5).await.unwrap();
        assert!(bob_bundle.supports_pqxdh());
        // libsignal's kem::PublicKey::serialize() prepends a 1-byte key-type tag (0x08
        // for ML-KEM-1024), so the on-the-wire length is 1568 + 1 (same as Android).
        assert_eq!(bob_bundle.kem_spk.len(), crate::ML_KEM_1024_PUBKEY_LEN + 1);

        // Alice processes Bob's bundle (PQXDH) and encrypts a message.
        let (alice, alice_dev) = party("alice@example.com").await;
        let bob_addr = DeviceAddr { jid: "bob@example.com".into(), device_id: bob_dev };
        establish_session(&alice, "alice@example.com", alice_dev, &bob_addr, &bob_bundle)
            .await
            .unwrap();

        let enc = encrypt(
            &alice,
            "alice@example.com",
            alice_dev,
            &[bob_addr],
            Some("bob@example.com"),
            b"hello pq world",
        )
        .await
        .unwrap();
        assert_eq!(enc.keys.len(), 1);
        // First message MUST be a key-exchange (PreKey) carrying the ML-KEM ciphertext.
        assert!(enc.keys[0].kex);

        // Bob decrypts. The payload context binding (§5.4.2) recomputed from (from=alice,
        // to=bob, sid=alice_dev) must match what Alice sealed with, or GCM auth fails.
        let wk = &enc.keys[0];
        let alice_addr = DeviceAddr { jid: "alice@example.com".into(), device_id: alice_dev };
        let pt = decrypt(
            &bob,
            "bob@example.com",
            bob_dev,
            &alice_addr,
            Some("bob@example.com"),
            &wk.data,
            wk.kex,
            &enc.payload,
            Some(&enc.commit),
        )
        .await
        .unwrap();
        assert_eq!(pt, b"hello pq world");
    }

    /// Pin-fill never overwrites: the first pin for (JID, IK) stands, a later different key is
    /// reported back instead of written, and only the explicit replace (hybrid-fingerprint scan)
    /// changes it.
    #[tokio::test]
    async fn pin_if_absent_never_overwrites() {
        let (bob, _) = party("bob@example.com").await;
        let (acc, jid, fp) = (bob.account_id, "alice@example.com", "05aa");
        let first = bob.store.pin_omemo2_pq_identity_if_absent(acc, jid, fp, &[1u8; 4]).await.unwrap();
        assert_eq!(first, vec![1u8; 4]);
        let second = bob.store.pin_omemo2_pq_identity_if_absent(acc, jid, fp, &[2u8; 4]).await.unwrap();
        assert_eq!(second, vec![1u8; 4], "an existing pin must win");
        // The same pin for another JID is independent (pins are JID-scoped).
        let other = bob
            .store
            .pin_omemo2_pq_identity_if_absent(acc, "mallory@example.com", fp, &[3u8; 4])
            .await
            .unwrap();
        assert_eq!(other, vec![3u8; 4]);
        bob.store.pin_omemo2_pq_identity(acc, jid, fp, &[2u8; 4]).await.unwrap();
        assert_eq!(
            bob.store.get_pinned_omemo2_pq_identity(acc, jid, fp).await.unwrap(),
            Some(vec![2u8; 4]),
            "the explicit replace (hfp scan) does change it"
        );
    }

    /// `<pq-auth>` (proto-XEP §4.9.7): a pre-key message is accepted only with a valid handshake
    /// signature by BOTH of the sender's identity keys, and only under the PQ identity pinned for
    /// it. Runs the real verification against a real PQXDH pre-key message.
    #[tokio::test]
    async fn pq_auth_authenticates_the_handshake() {
        let (bob, bob_dev) = party("bob@example.com").await;
        let bob_bundle = generate_and_store_prekeys(&bob, 1, 1000, 100, 5).await.unwrap();
        let (alice, alice_dev) = party("alice@example.com").await;
        let bob_addr = DeviceAddr { jid: "bob@example.com".into(), device_id: bob_dev };
        establish_session(&alice, "alice@example.com", alice_dev, &bob_addr, &bob_bundle)
            .await
            .unwrap();
        let enc = encrypt(&alice, "alice@example.com", alice_dev, &[bob_addr], Some("bob@example.com"), b"hi")
            .await
            .unwrap();
        assert!(enc.keys[0].kex);
        let auth = enc.pq_auth.clone().expect("a pre-key message carries <pq-auth>");
        let wk = &enc.keys[0];
        let candidates = vec![(wk.data.clone(), true)];
        let entries =
            vec![KexEntry { jid: "BOB@example.com".into(), device_id: bob_dev, data: wk.data.clone() }];
        let alice_addr = DeviceAddr { jid: "alice@example.com".into(), device_id: alice_dev };

        // Valid: verifies (JID case does not matter), and — first contact — pins right away,
        // before any decryption.
        let ok = verify_pq_auth(&bob, &alice_addr, &candidates, &entries, Some(&auth))
            .await
            .expect("valid <pq-auth>")
            .expect("a pre-key message is authenticated");
        assert!(ok.newly_pinned);
        assert_eq!(ok.pq_ik, alice.pq_identity().public_key().serialize().to_vec());
        assert_eq!(
            bob.store
                .get_pinned_omemo2_pq_identity(bob.account_id, "alice@example.com", &ok.fp_key)
                .await
                .unwrap(),
            Some(ok.pq_ik.clone()),
            "the pin is written at verification, not after the payload opens"
        );
        // Verifying again finds the same pin: not newly pinned, still accepted.
        let again = verify_pq_auth(&bob, &alice_addr, &candidates, &entries, Some(&auth))
            .await
            .unwrap()
            .unwrap();
        assert!(!again.newly_pinned);

        // Missing: refused.
        assert!(matches!(
            verify_pq_auth(&bob, &alice_addr, &candidates, &entries, None).await,
            Err(OmemoError::HandshakeAuth(_))
        ));

        // A planted PQ key with its own valid ML-DSA signature, but Alice's classical signature
        // replayed from the genuine <pq-auth>: refused, because IK never signed that transcript.
        let mallory_pq = PqIdentityKeyPair::generate(&mut rand::rng());
        let transcript = kex_auth_transcript(
            "alice@example.com",
            alice_dev,
            alice.identity().identity_key(),
            &mallory_pq.public_key(),
            &entries,
        );
        let planted = PqAuth {
            pq_ik: mallory_pq.public_key().serialize().to_vec(),
            pq_sig: mallory_pq.sign(&transcript, &mut rand::rng()).unwrap().serialize().to_vec(),
            ik_sig: auth.ik_sig.clone(),
        };
        assert!(matches!(
            verify_pq_auth(&bob, &alice_addr, &candidates, &entries, Some(&planted)).await,
            Err(OmemoError::HandshakeAuth(_))
        ));

        // The signature covers every pre-key message of the stanza: dropping or adding one fails.
        let mut extra = entries.clone();
        extra.push(KexEntry { jid: "carol@example.com".into(), device_id: 5, data: vec![1, 2, 3] });
        assert!(verify_pq_auth(&bob, &alice_addr, &candidates, &extra, Some(&auth)).await.is_err());

        // Attributed to another sender: fails.
        let mallory_addr = DeviceAddr { jid: "mallory@example.com".into(), device_id: alice_dev };
        assert!(verify_pq_auth(&bob, &mallory_addr, &candidates, &entries, Some(&auth)).await.is_err());

        // A different PQ identity already pinned for Alice: an identity change, refused.
        let other = PqIdentityKeyPair::generate(&mut rand::rng());
        bob.store
            .pin_omemo2_pq_identity(bob.account_id, "alice@example.com", &ok.fp_key, &other.public_key().serialize())
            .await
            .unwrap();
        assert!(matches!(
            verify_pq_auth(&bob, &alice_addr, &candidates, &entries, Some(&auth)).await,
            Err(OmemoError::PqIdentityChanged(_))
        ));

        // A whisper (non-pre-key) candidate needs no <pq-auth>.
        assert!(verify_pq_auth(&bob, &alice_addr, &[(wk.data.clone(), false)], &[], None)
            .await
            .unwrap()
            .is_none());
    }

    /// The key commitment makes the AEAD key-committing: a payload opens only under the one
    /// message key whose commitment matches the single published `<commit>`. A missing, tampered,
    /// or different-key commitment MUST be rejected — this is the invisible-salamander /
    /// malicious-sender-equivocation defence. Exercised at the symmetric layer so it does not
    /// depend on ratchet state.
    #[test]
    fn key_commitment_is_enforced() {
        let message_key = [7u8; MSG_KEY_LEN];
        let (from, to, sid) = ("alice@example.com", Some("bob@example.com"), 42u32);
        let payload = omemo2_seal(&message_key, b"committed message", from, to, sid).unwrap();
        let binding = compute_context_binding(from, to, sid);
        let commit = omemo2_key_commitment(&message_key, &binding).unwrap();

        // Correct commitment → opens.
        let pt = omemo2_open(&message_key, &payload, from, to, sid, Some(&commit)).unwrap();
        assert_eq!(pt, b"committed message");
        // Missing commitment → reject (fail closed).
        assert!(omemo2_open(&message_key, &payload, from, to, sid, None).is_err());
        // Tampered commitment → reject.
        let mut bad = commit;
        bad[0] ^= 0xFF;
        assert!(omemo2_open(&message_key, &payload, from, to, sid, Some(&bad)).is_err());
        // Equivocation defence: a *different* key's commitment must not open this payload — the
        // ciphertext is bound to exactly one message key.
        let other_commit = omemo2_key_commitment(&[9u8; MSG_KEY_LEN], &binding).unwrap();
        assert!(omemo2_open(&message_key, &payload, from, to, sid, Some(&other_commit)).is_err());
    }

    /// NIST SP 800-185 KMAC256 sample vectors #4, #5 and #6.
    ///
    /// These pin our hand-written `left_encode`/`right_encode`/`bytepad`/`encode_string` to the
    /// standard itself, not merely to the Android side. That matters: the Android client uses
    /// BouncyCastle's `KMAC`, a separate implementation, and the two must agree byte-for-byte or
    /// no cross-client message decrypts. Anchoring both to NIST rather than to each other means a
    /// shared misreading of the spec cannot cancel out.
    #[test]
    fn kmac256_nist_sp800_185_vectors() {
        let key: Vec<u8> = (0x40u8..=0x5F).collect();
        let tagged = b"My Tagged Application";

        let mut out = [0u8; 64];
        kmac256(&key, &[0x00, 0x01, 0x02, 0x03], tagged, &mut out);
        assert_eq!(
            hex::encode(out),
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7\
             f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
            "SP 800-185 KMAC256 sample #4"
        );

        let data: Vec<u8> = (0x00u8..=0xC7).collect();
        kmac256(&key, &data, b"", &mut out);
        assert_eq!(
            hex::encode(out),
            "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691\
             589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
            "SP 800-185 KMAC256 sample #5"
        );

        kmac256(&key, &data, tagged, &mut out);
        assert_eq!(
            hex::encode(out),
            "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9\
             70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965",
            "SP 800-185 KMAC256 sample #6"
        );
    }

    /// The payload key/IV derivation must match Android's byte-for-byte too — it is the other
    /// KMAC256 customization string, and a mismatch means every message fails its GCM tag.
    #[test]
    fn payload_keys_known_answer() {
        let binding = compute_context_binding("alice@example.com", Some("bob@example.com"), 42);
        let (enc, iv) = derive_payload_keys(&[7u8; MSG_KEY_LEN], &binding).unwrap();
        assert_eq!(
            hex::encode(enc),
            "91d133b399016d8ed75e9e585ecdcd7ffb1c95b9b364e188784ccbab610d97e7"
        );
        assert_eq!(hex::encode(iv), "058b5c01dd3d1eac0e564269");
    }

    /// Known-answer test locking the commitment to monocles Android's
    /// `XmppOmemo2Message.keyCommitment` and to the vector documented in the proto-XEP §5.5.
    /// Both clients publish this value in `<commit>`, so if it changes here it must change
    /// there in lockstep or every cross-client message is rejected as a commitment mismatch.
    #[test]
    fn key_commitment_known_answer() {
        let binding = compute_context_binding("alice@example.com", Some("bob@example.com"), 42);
        let commit = omemo2_key_commitment(&[7u8; MSG_KEY_LEN], &binding).unwrap();
        assert_eq!(
            hex::encode(commit),
            "e04e685382db88563a43d2a5d55218bf917b5b57989b377636d88cf7f479bfc5\
             31b5a1a87a4eeef2909d8510a27f0b83e9f183361686ad5a3b00194794bde224"
        );
    }

    #[tokio::test]
    async fn tampered_kem_prekey_fails_pq_verification() {
        // Bob publishes a PQ bundle with several one-time KEM prekeys.
        let (bob, _bob_dev) = party("bob@example.com").await;
        let bob_bundle = generate_and_store_prekeys(&bob, 1, 1000, 100, 5).await.unwrap();
        assert!(bob_bundle.kem_prekeys.len() >= 2);

        // An attacker substitutes a one-time KEM key that Alice will NOT select
        // (she picks kem_prekeys[0]); only the transcript's KEM manifest — which binds
        // the entire published KEM set, not just the selected key — catches this.
        let mut tampered = bob_bundle.clone();
        tampered.kem_prekeys[1].key[0] ^= 0xFF;

        let (alice, alice_dev) = party("alice@example.com").await;
        let bob_addr = DeviceAddr { jid: "bob@example.com".into(), device_id: _bob_dev };
        let result =
            establish_session(&alice, "alice@example.com", alice_dev, &bob_addr, &tampered).await;
        assert!(
            result.is_err(),
            "a substituted (non-selected) one-time KEM prekey must fail PQ bundle verification"
        );
    }

    /// Pin-fill reconciliation for peer-initiated sessions: pins only a bundle whose classical
    /// identity matches the known one AND whose ML-DSA-87 transcript signature verifies, and
    /// never overwrites an existing pin.
    #[tokio::test]
    async fn pq_pin_reconciliation() {
        // Bob publishes a bundle. Alice knows Bob's classical identity key (the state an
        // inbound PQXDH kex from Bob leaves behind) but has no pq pin for it.
        let (bob, bob_dev) = party("bob@example.com").await;
        let bob_bundle = generate_and_store_prekeys(&bob, 1, 1000, 100, 2).await.unwrap();
        let (alice, _alice_dev) = party("alice@example.com").await;
        let bob_addr = DeviceAddr { jid: "bob@example.com".into(), device_id: bob_dev };
        let known_ik = IdentityKey::decode(&ec_djb(&bob_bundle.ik))
            .unwrap()
            .serialize()
            .to_vec();
        let pin_key = crate::pq_pin_key(&known_ik);

        // A bundle carrying a DIFFERENT classical identity than the known one is refused
        // (PEP pin-poisoning defence).
        let (other_identity, _, _) = generate_identity();
        let other_ik = other_identity.identity_key().serialize().to_vec();
        assert!(
            reconcile_pq_pin(&alice, &bob_addr, &bob_bundle, &other_ik).await.is_err(),
            "mismatched classical identity must be refused"
        );

        // A tampered ML-DSA-87 signature is refused.
        let mut bad_sig = bob_bundle.clone();
        bad_sig.pq_sig[0] ^= 0xFF;
        assert!(
            reconcile_pq_pin(&alice, &bob_addr, &bad_sig, &known_ik).await.is_err(),
            "tampered pq_sig must be refused"
        );
        // A substituted pq_ik is refused (transcript/signature no longer match).
        let mut bad_ik = bob_bundle.clone();
        bad_ik.pq_ik[0] ^= 0xFF;
        assert!(
            reconcile_pq_pin(&alice, &bob_addr, &bad_ik, &known_ik).await.is_err(),
            "substituted pq_ik must be refused"
        );
        // Nothing was pinned by the refused attempts.
        assert!(alice
            .store
            .get_pinned_omemo2_pq_identity(alice.account_id, &bob_addr.jid, &pin_key)
            .await
            .unwrap()
            .is_none());

        // The genuine bundle pins.
        assert!(reconcile_pq_pin(&alice, &bob_addr, &bob_bundle, &known_ik).await.unwrap());
        assert_eq!(
            alice
                .store
                .get_pinned_omemo2_pq_identity(alice.account_id, &bob_addr.jid, &pin_key)
                .await
                .unwrap()
                .unwrap(),
            bob_bundle.pq_ik
        );
        // A second reconciliation is a no-op (already pinned).
        assert!(!reconcile_pq_pin(&alice, &bob_addr, &bob_bundle, &known_ik).await.unwrap());

        // An existing pin is NEVER overwritten, even by a bundle that verifies: pre-pin a
        // different value and check it survives.
        let sentinel = vec![0xAAu8; 4];
        alice
            .store
            .pin_omemo2_pq_identity(alice.account_id, &bob_addr.jid, &pin_key, &sentinel)
            .await
            .unwrap();
        assert!(matches!(
            reconcile_pq_pin(&alice, &bob_addr, &bob_bundle, &known_ik).await,
            Err(OmemoError::PqIdentityChanged(_))
        ));
        assert_eq!(
            alice
                .store
                .get_pinned_omemo2_pq_identity(alice.account_id, &bob_addr.jid, &pin_key)
                .await
                .unwrap()
                .unwrap(),
            sentinel,
            "an existing pin must never be overwritten by reconciliation"
        );

        // …and that pin belongs to bob@example.com alone. A classical `<ik>` is published in
        // PEP, so any peer can republish someone else's; if the pin were keyed on the
        // fingerprint alone, mallory's pin would be read back for bob and every later session
        // with the real bob would be refused as a changed pq_ik. Scoping on the JID is what
        // keeps that DoS from crossing accounts.
        assert!(
            alice
                .store
                .get_pinned_omemo2_pq_identity(alice.account_id, "mallory@example.com", &pin_key)
                .await
                .unwrap()
                .is_none(),
            "a pin must not be visible under a JID that did not write it"
        );
        let mallory_addr =
            DeviceAddr { jid: "mallory@example.com".into(), device_id: bob_dev };
        alice
            .store
            .pin_omemo2_pq_identity(
                alice.account_id,
                &mallory_addr.jid,
                &pin_key,
                &[0xBBu8; 4],
            )
            .await
            .unwrap();
        assert_eq!(
            alice
                .store
                .get_pinned_omemo2_pq_identity(alice.account_id, &bob_addr.jid, &pin_key)
                .await
                .unwrap()
                .unwrap(),
            sentinel,
            "a pin written under another JID must not overwrite bob's"
        );
    }

    /// A peer device whose identity key is REPLACED must lose its trust: the user verified (or
    /// blind-trusted) the key that was there before and has said nothing about this one. The
    /// rebuild itself is allowed — refusing at the libsignal layer would strand a peer who
    /// legitimately reinstalled — but the new key lands undecided, which every encryption path
    /// skips. Mirrors monocles Android's `SQLiteAxolotlStore.saveIdentity`.
    #[tokio::test]
    async fn replaced_identity_key_loses_trust() {
        use libsignal_protocol::{Direction, IdentityKeyStore};

        let (alice, _) = party("alice@example.com").await;
        let jid = "bob@example.com";
        let dev = 7u32;
        let addr = protocol_address(jid, dev).unwrap();

        let (first, _, _) = generate_identity();
        let (second, _, _) = generate_identity();
        let mut ids = alice.identity_store();

        // First contact: TOFU. The dev store defaults to auto-trust, so bob lands trusted (1).
        assert!(ids
            .is_trusted_identity(&addr, first.identity_key(), Direction::Sending)
            .await
            .unwrap());
        ids.save_identity(&addr, first.identity_key()).await.unwrap();
        // Promote to manually verified — the strongest state, and the one that must not carry.
        alice.store.set_omemo_trust(alice.account_id, jid, dev as i64, 3).await.unwrap();

        // A different key on the same (jid, device) is still accepted by libsignal, so the
        // ratchet can be rebuilt…
        assert!(
            ids.is_trusted_identity(&addr, second.identity_key(), Direction::Sending)
                .await
                .unwrap(),
            "a replaced key must not hard-fail inside libsignal"
        );
        ids.save_identity(&addr, second.identity_key()).await.unwrap();

        // …but the verification does NOT transfer to it.
        let rec = alice
            .store
            .omemo_identity(alice.account_id, jid, dev as i64)
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(rec.identity_key, second.identity_key().serialize().to_vec());
        assert_eq!(rec.trust, 0, "a replaced identity key must be undecided, never inherited");

        // Re-saving the SAME key is not a replacement and leaves a decision alone.
        alice.store.set_omemo_trust(alice.account_id, jid, dev as i64, 3).await.unwrap();
        ids.save_identity(&addr, second.identity_key()).await.unwrap();
        assert_eq!(
            alice
                .store
                .omemo_identity(alice.account_id, jid, dev as i64)
                .await
                .unwrap()
                .unwrap()
                .trust,
            3,
            "an unchanged key keeps its trust"
        );
    }
}
