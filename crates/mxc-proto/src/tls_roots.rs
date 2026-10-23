//! Root certificates we trust for TLS, minus a blocklist.
//!
//! Some roots that ship in the Mozilla bundle and in OS stores are refused anyway: the
//! eMudhra / emSign roots (Conversations 9233a441e, monocles Android
//! `TrustManagers.BLOCKED_ROOT_SHA256`). They are matched by SHA-256 of the root certificate's
//! DER, so the source has to give us DER (webpki-roots only carries trust anchors, hence
//! webpki-root-certs for the XMPP side).

use std::sync::{Arc, OnceLock};

use sha2::{Digest, Sha256};

/// SHA-256 (lowercase hex) of every refused root certificate.
const BLOCKED_ROOT_SHA256: &[&str] = &[
    // https://emudhra.we-have-a-problem.com/roots.json
    "7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d",
    "f2edaaff3d9b701fb4d14c9f285f8c0bad90fc3bcc1fa07d47f4718edaba34a5",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
    // the other emSign Root CAs
    "40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367",
    "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f",
    "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3",
];

/// Whether `der` (a whole certificate) is one of the refused roots.
pub fn is_blocked(der: &[u8]) -> bool {
    let digest = hex::encode(Sha256::digest(der));
    BLOCKED_ROOT_SHA256.contains(&digest.as_str())
}

/// The roots for the XMPP connection's PKIX check: the Mozilla bundle without the blocked
/// roots. Built once.
pub fn xmpp_roots() -> Arc<rustls::RootCertStore> {
    static ROOTS: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                if is_blocked(der.as_ref()) {
                    tracing::debug!("not trusting blocked root CA");
                    continue;
                }
                if let Err(e) = roots.add(der.clone()) {
                    tracing::warn!(error = %e, "skipping unparsable bundled root");
                }
            }
            Arc::new(roots)
        })
        .clone()
}

/// The roots for HTTP (uploads, downloads): the operating system's store, as reqwest used
/// before through the platform verifier, without the blocked roots. `None` if the store can't
/// be read or is empty; the caller then keeps reqwest's default (the unfiltered platform
/// verifier) rather than leaving the app without working HTTPS.
pub fn http_roots() -> Option<Vec<reqwest::Certificate>> {
    let loaded = rustls_native_certs::load_native_certs();
    for e in &loaded.errors {
        tracing::warn!(error = %e, "loading a system root certificate");
    }
    let certs: Vec<reqwest::Certificate> = loaded
        .certs
        .iter()
        .filter(|der| !is_blocked(der.as_ref()))
        .filter_map(|der| reqwest::Certificate::from_der(der.as_ref()).ok())
        .collect();
    if certs.is_empty() {
        tracing::warn!("no usable system root certificates; using the platform default");
        return None;
    }
    Some(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_entries_are_sha256_hex() {
        for h in BLOCKED_ROOT_SHA256 {
            assert_eq!(h.len(), 64);
            assert!(h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        }
    }

    #[test]
    fn ordinary_roots_are_not_blocked() {
        let total = webpki_root_certs::TLS_SERVER_ROOT_CERTS.len();
        let blocked = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .filter(|der| is_blocked(der.as_ref()))
            .count();
        // the Mozilla bundle carries some of the emSign roots, but nowhere near all roots
        assert!(blocked < BLOCKED_ROOT_SHA256.len() + 1);
        assert!(total - blocked > 100);
        assert_eq!(xmpp_roots().len(), total - blocked);
    }
}
