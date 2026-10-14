//! `mxc-omemo` — PQ OMEMO2 (`urn:monocles:omemo-pq:1`, PQXDH + SPQR) for monocles chat desktop.
//!
//! This crate is the headline feature. It is built directly on **`libsignal-protocol`
//! v0.94.1** — the exact same Rust crate the monocles Android app compiles — so PQXDH
//! (X3DH + ML-KEM-1024 encapsulation) and the SPQR triple-ratchet braid produce
//! byte-identical output and interoperate at the wire level.
//!
//! Responsibilities:
//! - [`bundle`]  build/parse the PQ-extended OMEMO2 bundle (`<kem-spk>/<kem-spks>/
//!   <kem-prekeys>`), per the proto-XEP §4.3.
//! - [`store`]   implement libsignal's store traits (`IdentityKeyStore`, `SessionStore`,
//!   `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`) over `mxc-store`.
//! - [`session`] session init (PQXDH via `SessionBuilder::process`) + encrypt/decrypt;
//!   the SPQR braid runs unmodified inside libsignal's ongoing-session ratchet.
//! - [`sce`]     XEP-0420 Stanza Content Encryption envelope wrap/unwrap.
//!
//! The orchestration of PEP publish/fetch lives in `mxc-proto`; this crate is pure
//! crypto + persistence and never touches the network.

pub mod bundle;
pub mod sce;
pub mod session;
pub mod store;

#[derive(Debug, thiserror::Error)]
pub enum OmemoError {
    #[error("bundle parse: {0}")]
    BundleParse(String),
    #[error("base64: {0}")]
    Base64(String),
    #[error("signature verification failed for {0}")]
    BadSignature(&'static str),
    #[error("peer does not support PQXDH (no <kem-spk> in bundle)")]
    NoPqxdh,
    #[error("peer does not advertise a post-quantum hybrid identity (no <pq-ik> in bundle)")]
    NoPqIdentity,
    #[error("post-quantum identity for {0} changed — refused; re-verify the contact's hybrid fingerprint")]
    PqIdentityChanged(String),
    #[error("handshake authentication (<pq-auth>) failed: {0}")]
    HandshakeAuth(String),
    #[error("store: {0}")]
    Store(#[from] mxc_store::StoreError),
    #[error("libsignal: {0}")]
    Signal(String),
    #[error("aead: {0}")]
    Aead(String),
}

impl From<libsignal_protocol::SignalProtocolError> for OmemoError {
    fn from(e: libsignal_protocol::SignalProtocolError) -> Self {
        OmemoError::Signal(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, OmemoError>;

/// ML-KEM-1024 public key length in bytes (per FIPS-203 / proto-XEP §4.3.1).
pub const ML_KEM_1024_PUBKEY_LEN: usize = 1568;
/// Curve25519 public key length (IK, SPK, EC prekeys).
pub const CURVE25519_PUBKEY_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;
/// ML-DSA-87 (FIPS-204) public (verification) key length, in bytes — the post-quantum
/// half of the monocles hybrid identity (`<pq-ik>`).
pub const ML_DSA_87_PUBKEY_LEN: usize = 2592;
/// ML-DSA-87 signature length, in bytes (`<pq-sig>`).
pub const ML_DSA_87_SIG_LEN: usize = 4627;

/// Domain-separation label for the monocles PQ-OMEMO2 hybrid fingerprint. MUST match the
/// Android client (`CryptoHelper.HYBRID_OMEMO2_FP_LABEL`) byte-for-byte.
const HYBRID_FP_LABEL: &[u8] = b"monocles:omemo2:ik:v2";

/// The user-verifiable fingerprint of a monocles PQ-OMEMO2 *hybrid* identity:
/// `SHA3-512(label || u32_be(len(IK)) || IK || u32_be(len(PQ-IK)) || PQ-IK)`, lowercase hex.
/// Because it commits to BOTH the classical and the post-quantum identity key, comparing it
/// out-of-band authenticates the post-quantum key too — the binding that defeats a quantum
/// adversary who could forge the classical Ed25519 signature.
///
/// SHA3-512 rather than SHA-256 because this is the one value a *user* checks, and the
/// adversary here controls both sides of the comparison: a malicious contact who finds two
/// identities sharing a fingerprint gets one the victim verified and one they did not. That
/// is a chosen-collision setting, so the 128-bit birthday bound of a 32-byte digest was the
/// relevant strength; 64 bytes makes it 256-bit, matching the rest of the profile. Changing
/// it un-verifies nobody — trust is keyed on the classical fingerprint, this is display-only.
///
/// `identity_key` MUST be the libsignal-serialized (33-byte `0x05`-prefixed) classical
/// identity key and `pq_identity_key` the 2592-byte ML-DSA-87 verification key, matching
/// exactly what the Android client hashes, so the displayed strings are interoperable.
pub fn hybrid_fingerprint(identity_key: &[u8], pq_identity_key: &[u8]) -> String {
    use sha3::{Digest, Sha3_512};
    let mut h = Sha3_512::new();
    h.update(HYBRID_FP_LABEL);
    h.update((identity_key.len() as u32).to_be_bytes());
    h.update(identity_key);
    h.update((pq_identity_key.len() as u32).to_be_bytes());
    h.update(pq_identity_key);
    hex::encode(h.finalize())
}

/// [`hybrid_fingerprint`] grouped in blocks of 8 for display, matching the classical
/// [`fingerprint`] layout and the Android client's `prettifyFingerprint`, so the two clients
/// render the same string for out-of-band comparison.
pub fn hybrid_fingerprint_display(identity_key: &[u8], pq_identity_key: &[u8]) -> String {
    let hex = hybrid_fingerprint(identity_key, pq_identity_key);
    hex.as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The lookup key under which a device's post-quantum identity is pinned: lowercase hex of
/// its serialized (33-byte) classical identity key. The single source of truth shared by the
/// pin-write (session establishment) and pin-read (fingerprint display) paths.
pub fn pq_pin_key(identity_key_serialized: &[u8]) -> String {
    hex::encode(identity_key_serialized)
}

/// The OMEMO fingerprint of an identity key, formatted like monocles/Conversations: the
/// lowercase hex of the 32-byte Curve25519 public key (libsignal's `0x05` type prefix
/// stripped), grouped in blocks of 8. This is the raw key hex — NOT a hash — so it matches
/// what other XMPP clients display for verification.
pub fn fingerprint(identity_key_bytes: &[u8]) -> String {
    let key = if identity_key_bytes.len() == 33 && identity_key_bytes[0] == 0x05 {
        &identity_key_bytes[1..]
    } else {
        identity_key_bytes
    };
    let hex = hex::encode(key);
    hex.as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    /// Known-answer test locking the hybrid fingerprint to monocles Android's
    /// `CryptoHelper.hybridOmemo2Fingerprint` and to the vector in the proto-XEP §4.9.3.
    /// This is the string a user compares out of band, so a divergence between the two
    /// clients would look to them exactly like a failed verification.
    #[test]
    fn hybrid_fingerprint_known_answer() {
        let mut ik = vec![0x05u8];
        ik.extend_from_slice(&[0x11u8; 32]);
        let pq_ik = [0x22u8; ML_DSA_87_PUBKEY_LEN];
        assert_eq!(
            hybrid_fingerprint(&ik, &pq_ik),
            "6b6ea370b7cbc0078f992487b235ab384a7f272b232e508a2d27da9b42f1def7\
             f2def0daffbdfd91a33065c1e383473a1eacce6e5709833d286c5e399e19c77a"
        );
    }

    /// The fingerprint must commit to the post-quantum half, not just the classical key —
    /// that binding is the entire reason it exists (§4.9.3).
    #[test]
    fn hybrid_fingerprint_commits_to_pq_key() {
        let mut ik = vec![0x05u8];
        ik.extend_from_slice(&[0x11u8; 32]);
        let a = hybrid_fingerprint(&ik, &[0x22u8; ML_DSA_87_PUBKEY_LEN]);
        let b = hybrid_fingerprint(&ik, &[0x23u8; ML_DSA_87_PUBKEY_LEN]);
        assert_eq!(a.len(), 128, "SHA3-512 renders as 128 hex characters");
        assert_ne!(a, b);
    }
}
