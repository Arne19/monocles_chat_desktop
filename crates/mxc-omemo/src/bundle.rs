//! PQ OMEMO2 bundle (`<bundle xmlns='urn:monocles:omemo-pq:1'>`) build + parse.
//!
//! Layout (proto-XEP §4.3): classic `<spk>/<spks>/<ik>/<prekeys>` plus the PQXDH
//! additions `<kem-spk>/<kem-spks>` (long-lived, last-resort, ML-KEM-1024) and
//! `<kem-prekeys><kem-pk id sig>` (one-time). All key/signature payloads are base64.
//!
//! Signature semantics enforced elsewhere (verified against the peer `<ik>` in
//! [`crate::session`]); this module only does structural (de)serialization, which is
//! why it is fully unit-testable without libsignal.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::{OmemoError, Result};

// Must match mxc-proto's NS_OMEMO2 and the Android client's Namespace.OMEMO2 —
// this profile's own namespace, deliberately distinct from XEP-0384's
// urn:xmpp:omemo:2 (the stacks are wire-incompatible; see proto-XEP §1.2).
pub const NS_OMEMO2: &str = "urn:monocles:omemo-pq:1";

/// Diagnostic `rev` attribute on our `<bundle>`: the bundle transcript version. It lets a peer
/// on an older version report "update the client" instead of an opaque signature failure; it is
/// unsigned and MUST NOT select behaviour (proto-XEP §4.3.1).
pub const BUNDLE_REVISION: &str = "4";

/// The algorithm this namespace version fixes for `<pq-ik>` (proto-XEP §4.9.1.1).
const PQ_IDENTITY_ALGORITHM: &str = "ML-DSA-87";
/// The algorithm this namespace version fixes for `<kem-spk>`/`<kem-pk>`.
const PQ_KEM_ALGORITHM: &str = "ML-KEM-1024";

/// libsignal's algorithm tag for ML-KEM-1024, the first byte of a serialized KEM public key.
/// Round-3 CRYSTALS-Kyber-1024 is `0x08`; the tag is the only thing distinguishing them on the
/// wire, since key and ciphertext sizes are identical (proto-XEP §5.1.1).
const ML_KEM_1024_TAG: u8 = 0x0A;

/// True iff `serialized_key` is a FIPS 203 ML-KEM-1024 public key in libsignal's wire form.
pub(crate) fn is_ml_kem_1024(serialized_key: &[u8]) -> bool {
    serialized_key.first() == Some(&ML_KEM_1024_TAG)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemPreKey {
    pub id: u32,
    /// ML-KEM-1024 public key in libsignal wire form: 0x0A tag then 1568 key bytes.
    pub key: Vec<u8>,
    /// Ed25519 signature over `key` by the identity key (64 bytes).
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub spk_id: u32,
    pub spk: Vec<u8>,
    pub spk_sig: Vec<u8>,
    pub ik: Vec<u8>,
    /// Classic EC one-time prekeys: (id, pubkey).
    pub prekeys: Vec<(u32, Vec<u8>)>,
    // --- PQXDH ---
    pub kem_spk_id: u32,
    pub kem_spk: Vec<u8>,
    pub kem_spk_sig: Vec<u8>,
    pub kem_prekeys: Vec<KemPreKey>,
    // --- monocles hybrid post-quantum identity (proto-XEP §4.9) ---
    /// ML-DSA-87 public identity key (2592 bytes) — the post-quantum half of the device's
    /// hybrid identity. Empty only on a (rejected) legacy bundle.
    pub pq_ik: Vec<u8>,
    /// ML-DSA-87 signature (4627 bytes) over the v4 bundle transcript
    /// `pq_bundle_transcript(ik, pq_ik, spk_id, spk, kem_binding)`, where
    /// `kem_binding` covers the kem-spk and all one-time kem-pk (proto-XEP §4.9.1).
    pub pq_sig: Vec<u8>,
    /// XEdDSA signature (64 bytes) by the classical identity key over the same v4 transcript.
    /// Without it, anyone able to serve bundles could attach a PQ identity of their own to a
    /// device's genuine classical material (proto-XEP §4.9.1).
    pub ik_sig: Vec<u8>,
}

impl Bundle {
    /// Whether this bundle advertises PQXDH support (has a signed KEM prekey).
    pub fn supports_pqxdh(&self) -> bool {
        !self.kem_spk.is_empty()
    }

    /// Whether this bundle carries the monocles hybrid post-quantum identity, signed by both
    /// identity keys.
    pub fn has_pq_identity(&self) -> bool {
        !self.pq_ik.is_empty() && !self.pq_sig.is_empty() && !self.ik_sig.is_empty()
    }

    /// Serialize to the compact `<bundle>` XML form for PEP publish.
    pub fn to_xml(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("<bundle xmlns='{NS_OMEMO2}' rev='{BUNDLE_REVISION}'>"));
        s.push_str(&format!("<spk id='{}'>{}</spk>", self.spk_id, B64.encode(&self.spk)));
        s.push_str(&format!("<spks>{}</spks>", B64.encode(&self.spk_sig)));
        s.push_str(&format!("<ik>{}</ik>", B64.encode(&self.ik)));
        s.push_str("<prekeys>");
        for (id, pk) in &self.prekeys {
            s.push_str(&format!("<pk id='{}'>{}</pk>", id, B64.encode(pk)));
        }
        s.push_str("</prekeys>");
        // PQXDH
        s.push_str(&format!("<kem-spk id='{}'>{}</kem-spk>", self.kem_spk_id, B64.encode(&self.kem_spk)));
        s.push_str(&format!("<kem-spks>{}</kem-spks>", B64.encode(&self.kem_spk_sig)));
        s.push_str("<kem-prekeys>");
        for kp in &self.kem_prekeys {
            s.push_str(&format!(
                "<kem-pk id='{}' sig='{}'>{}</kem-pk>",
                kp.id,
                B64.encode(&kp.sig),
                B64.encode(&kp.key),
            ));
        }
        s.push_str("</kem-prekeys>");
        // monocles hybrid post-quantum identity (ML-DSA-87).
        if self.has_pq_identity() {
            s.push_str(&format!("<pq-ik type='ML-DSA-87'>{}</pq-ik>", B64.encode(&self.pq_ik)));
            s.push_str(&format!("<pq-sig>{}</pq-sig>", B64.encode(&self.pq_sig)));
            s.push_str(&format!("<ik-sig>{}</ik-sig>", B64.encode(&self.ik_sig)));
        }
        s.push_str("</bundle>");
        s
    }

    /// Parse a `<bundle>` element body (as received from a PEP fetch).
    ///
    /// A PQXDH-capable client receiving a bundle without `<kem-spk>` returns
    /// [`OmemoError::NoPqxdh`] (proto-XEP §4.3.2: MUST refuse, do not downgrade).
    pub fn from_xml(xml: &str) -> Result<Self> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut b = Bundle {
            spk_id: 0,
            spk: vec![],
            spk_sig: vec![],
            ik: vec![],
            prekeys: vec![],
            kem_spk_id: 0,
            kem_spk: vec![],
            kem_spk_sig: vec![],
            kem_prekeys: vec![],
            pq_ik: vec![],
            pq_sig: vec![],
            ik_sig: vec![],
        };

        // current element context
        let mut cur: Vec<u8> = Vec::new();
        let mut cur_id: Option<u32> = None;
        let mut cur_sig: Option<Vec<u8>> = None;
        let mut rev: Option<String> = None;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Err(e) => return Err(OmemoError::BundleParse(e.to_string())),
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) => {
                    cur = e.name().as_ref().to_vec();
                    cur_id = attr_u32(&e, b"id");
                    cur_sig = attr_b64(&e, b"sig")?;
                    let cur_type = attr_str(&e, b"type");
                    if cur.as_slice() == b"bundle" {
                        rev = attr_str(&e, b"rev");
                    }
                    // The `type` attribute is decorative in this namespace version: absent or
                    // naming the fixed algorithm is fine, anything else is refused rather than
                    // parsed as the fixed algorithm anyway. It sits outside the signature, so
                    // reinterpreting it would be exactly the downgrade the transcript's algorithm
                    // binding exists to prevent (proto-XEP §4.9.1.1).
                    let fixed = match cur.as_slice() {
                        b"pq-ik" => Some(PQ_IDENTITY_ALGORITHM),
                        b"kem-spk" | b"kem-pk" => Some(PQ_KEM_ALGORITHM),
                        _ => None,
                    };
                    if let (Some(fixed), Some(ty)) = (fixed, cur_type.as_deref()) {
                        if ty != fixed {
                            return Err(OmemoError::BundleParse(format!(
                                "<{}> with unsupported type='{ty}' (this version implements {fixed} only)",
                                String::from_utf8_lossy(&cur)
                            )));
                        }
                    }
                }
                Ok(Event::Empty(e)) => {
                    // an empty <pk/> shouldn't occur, but handle gracefully
                    let _ = (attr_u32(&e, b"id"), e);
                }
                Ok(Event::Text(t)) => {
                    // quick-xml 0.40 split BytesText::unescape() into byte-decode + entity
                    // unescape (the latter now the free fn quick_xml::escape::unescape).
                    let decoded =
                        t.decode().map_err(|e| OmemoError::BundleParse(e.to_string()))?;
                    let txt = quick_xml::escape::unescape(&decoded)
                        .map_err(|e| OmemoError::BundleParse(e.to_string()))?;
                    let raw = decode_b64(txt.trim())?;
                    match cur.as_slice() {
                        b"spk" => {
                            b.spk = raw;
                            b.spk_id = cur_id.unwrap_or(0);
                        }
                        b"spks" => b.spk_sig = raw,
                        b"ik" => b.ik = raw,
                        b"pk" => b.prekeys.push((cur_id.unwrap_or(0), raw)),
                        b"kem-spk" => {
                            b.kem_spk = raw;
                            b.kem_spk_id = cur_id.unwrap_or(0);
                        }
                        b"kem-spks" => b.kem_spk_sig = raw,
                        // A `<kem-pk>` that is not ML-KEM-1024 is dropped rather than collected;
                        // the recomputed KEM binding then disagrees with the signed one and the
                        // whole bundle is refused (see `is_ml_kem_1024`).
                        b"kem-pk" if is_ml_kem_1024(&raw) => b.kem_prekeys.push(KemPreKey {
                            id: cur_id.unwrap_or(0),
                            key: raw,
                            sig: cur_sig.clone().unwrap_or_default(),
                        }),
                        b"pq-ik" => b.pq_ik = raw,
                        b"pq-sig" => b.pq_sig = raw,
                        b"ik-sig" => b.ik_sig = raw,
                        _ => {}
                    }
                }
                _ => {}
            }
            buf.clear();
        }

        if b.ik.is_empty() || b.spk.is_empty() {
            return Err(OmemoError::BundleParse("missing <ik> or <spk>".into()));
        }
        if !b.supports_pqxdh() {
            return Err(OmemoError::NoPqxdh);
        }
        // Reject anything that is not FIPS 203 ML-KEM-1024 (proto-XEP §5.1.1). Round-3
        // CRYSTALS-Kyber-1024 has identical key and ciphertext sizes and deserializes fine —
        // libsignal still supports it — but derives a different shared secret. Without this a
        // peer publishing Round-3 keys would pass signature verification (both sides hash the
        // same bytes) and we would silently complete PQXDH on the superseded, non-standard
        // algorithm while the signed transcript asserts ML-KEM-1024.
        if !is_ml_kem_1024(&b.kem_spk) {
            return Err(OmemoError::BundleParse(
                "<kem-spk> is not ML-KEM-1024 (FIPS 203); refusing to downgrade".into(),
            ));
        }
        // The monocles hybrid post-quantum identity is mandatory — a bundle without a
        // valid `<pq-ik>`/`<pq-sig>`/`<ik-sig>` is refused, never downgraded (proto-XEP §4.9).
        if !b.pq_ik.is_empty() && !b.pq_sig.is_empty() && b.ik_sig.is_empty() {
            tracing::warn!(
                rev = rev.as_deref().unwrap_or("none"),
                "OMEMO2 bundle has no <ik-sig>: the peer's client predates bundle transcript v4 \
                 and must be updated"
            );
        }
        if !b.has_pq_identity() {
            return Err(OmemoError::NoPqIdentity);
        }
        Ok(b)
    }
}

fn attr_u32(e: &quick_xml::events::BytesStart, key: &[u8]) -> Option<u32> {
    e.attributes().flatten().find(|a| a.key.as_ref() == key).and_then(|a| {
        std::str::from_utf8(&a.value).ok().and_then(|s| s.parse().ok())
    })
}

fn attr_str(e: &quick_xml::events::BytesStart, key: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .and_then(|a| std::str::from_utf8(&a.value).ok().map(str::to_owned))
}

fn attr_b64(e: &quick_xml::events::BytesStart, key: &[u8]) -> Result<Option<Vec<u8>>> {
    for a in e.attributes().flatten() {
        if a.key.as_ref() == key {
            let s = std::str::from_utf8(&a.value).map_err(|e| OmemoError::BundleParse(e.to_string()))?;
            return Ok(Some(decode_b64(s)?));
        }
    }
    Ok(None)
}

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s.trim()).map_err(|e| OmemoError::Base64(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A KEM public key in libsignal wire form: the ML-KEM-1024 tag then 1568 key bytes. The
    /// tag matters — `Bundle::from_xml` refuses anything that is not ML-KEM-1024 (§5.1.1).
    fn ml_kem_key(fill: u8) -> Vec<u8> {
        let mut key = vec![super::ML_KEM_1024_TAG];
        key.extend(std::iter::repeat_n(fill, super::super::ML_KEM_1024_PUBKEY_LEN));
        key
    }

    fn sample() -> Bundle {
        Bundle {
            spk_id: 42,
            spk: vec![1u8; super::super::CURVE25519_PUBKEY_LEN],
            spk_sig: vec![2u8; super::super::ED25519_SIG_LEN],
            ik: vec![3u8; super::super::CURVE25519_PUBKEY_LEN],
            prekeys: vec![(100, vec![4u8; 32]), (101, vec![5u8; 32])],
            kem_spk_id: 1,
            kem_spk: ml_kem_key(6),
            kem_spk_sig: vec![7u8; super::super::ED25519_SIG_LEN],
            kem_prekeys: vec![
                KemPreKey { id: 200, key: ml_kem_key(8), sig: vec![9u8; 64] },
                KemPreKey { id: 201, key: ml_kem_key(10), sig: vec![11u8; 64] },
            ],
            pq_ik: vec![12u8; super::super::ML_DSA_87_PUBKEY_LEN],
            pq_sig: vec![13u8; super::super::ML_DSA_87_SIG_LEN],
            ik_sig: vec![14u8; super::super::ED25519_SIG_LEN],
        }
    }

    /// A bundle whose KEM keys are Round-3 CRYSTALS-Kyber-1024 (tag 0x08) must be refused, not
    /// silently downgraded onto the superseded algorithm. Same sizes, same parse, different
    /// shared secret — the tag is the only tell (§5.1.1).
    #[test]
    fn kyber_1024_bundle_is_refused() {
        let mut b = sample();
        b.kem_spk[0] = 0x08;
        assert!(matches!(
            Bundle::from_xml(&b.to_xml()),
            Err(OmemoError::BundleParse(_))
        ));

        // A Kyber-tagged one-time key is dropped rather than collected, so the recomputed KEM
        // binding no longer matches the signed one and session establishment fails downstream.
        let mut c = sample();
        c.kem_prekeys[0].key[0] = 0x08;
        let parsed = Bundle::from_xml(&c.to_xml()).expect("kem-spk is still valid");
        assert_eq!(parsed.kem_prekeys.len(), 1, "the Kyber-tagged <kem-pk> must be dropped");
        assert_eq!(parsed.kem_prekeys[0].id, 201);
    }

    #[test]
    fn bundle_xml_round_trip() {
        let b = sample();
        let xml = b.to_xml();
        let parsed = Bundle::from_xml(&xml).expect("parse");
        assert_eq!(b, parsed);
        // ML-KEM key length preserved exactly: 0x0A tag plus 1568 key bytes.
        assert_eq!(parsed.kem_spk.len(), 1 + super::super::ML_KEM_1024_PUBKEY_LEN);
        assert_eq!(parsed.kem_prekeys[0].key.len(), 1 + super::super::ML_KEM_1024_PUBKEY_LEN);
        // Hybrid PQ identity round-trips at full length (ML-DSA-87: 2592 / 4627 bytes).
        assert_eq!(parsed.pq_ik.len(), super::super::ML_DSA_87_PUBKEY_LEN);
        assert_eq!(parsed.pq_sig.len(), super::super::ML_DSA_87_SIG_LEN);
    }

    #[test]
    fn bundle_without_pq_identity_is_rejected() {
        let mut b = sample();
        b.pq_ik.clear();
        b.pq_sig.clear();
        // A PQXDH-capable bundle that omits the hybrid identity must be refused, not downgraded.
        let xml = b.to_xml();
        assert!(matches!(Bundle::from_xml(&xml), Err(OmemoError::NoPqIdentity)));
    }

    /// A pre-v4 bundle, signed by the post-quantum key only, is refused (proto-XEP §4.9.1).
    #[test]
    fn bundle_without_ik_signature_is_rejected() {
        let mut b = sample();
        b.ik_sig.clear();
        let xml = b.to_xml();
        assert!(!xml.contains("<ik-sig>"));
        // to_xml omits the whole PQ identity when it is incomplete; build the v3 shape by hand.
        let v3 = xml.replace(
            "</kem-prekeys>",
            &format!(
                "</kem-prekeys><pq-ik type='ML-DSA-87'>{}</pq-ik><pq-sig>{}</pq-sig>",
                B64.encode(&b.pq_ik),
                B64.encode(&b.pq_sig)
            ),
        );
        assert!(matches!(Bundle::from_xml(&v3), Err(OmemoError::NoPqIdentity)));
    }

    #[test]
    fn bundle_carries_its_revision() {
        assert!(sample().to_xml().starts_with(&format!(
            "<bundle xmlns='{NS_OMEMO2}' rev='{BUNDLE_REVISION}'>"
        )));
    }

    /// `type` is outside the signature: absent or the fixed algorithm is fine, anything else is
    /// refused rather than reinterpreted (proto-XEP §4.9.1.1).
    #[test]
    fn unknown_type_attribute_is_refused() {
        let xml = sample().to_xml();
        assert!(Bundle::from_xml(&xml.replace("type='ML-DSA-87'", "")).is_ok());
        assert!(matches!(
            Bundle::from_xml(&xml.replace("type='ML-DSA-87'", "type='SLH-DSA'")),
            Err(OmemoError::BundleParse(_))
        ));
        assert!(matches!(
            Bundle::from_xml(&xml.replace("<kem-spk id=", "<kem-spk type='Kyber1024' id=")),
            Err(OmemoError::BundleParse(_))
        ));
        assert!(matches!(
            Bundle::from_xml(&xml.replacen("<kem-pk id=", "<kem-pk type='X' id=", 1)),
            Err(OmemoError::BundleParse(_))
        ));
        assert!(Bundle::from_xml(&xml.replace("<kem-spk id=", "<kem-spk type='ML-KEM-1024' id="))
            .is_ok());
    }

    #[test]
    fn bundle_without_kem_is_rejected() {
        let mut b = sample();
        b.kem_spk.clear();
        b.kem_prekeys.clear();
        // serialize a non-PQXDH bundle by hand (omit kem-spk)
        let xml = format!(
            "<bundle xmlns='{NS_OMEMO2}'><spk id='1'>{}</spk><spks>{}</spks><ik>{}</ik><prekeys></prekeys></bundle>",
            B64.encode(&b.spk), B64.encode(&b.spk_sig), B64.encode(&b.ik)
        );
        assert!(matches!(Bundle::from_xml(&xml), Err(OmemoError::NoPqxdh)));
    }
}
