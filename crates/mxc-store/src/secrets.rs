//! OS-keychain storage for passwords and the OMEMO identity private keys. Nothing
//! sensitive lands in SQLite.
//!
//! The backend is platform-specific (selected at compile time):
//! - **Linux**: the freedesktop Secret Service (GNOME Keyring / KWallet) via `oo7`.
//! - **macOS / Windows**: the OS keychain (Keychain Services / Credential Manager) via
//!   the `keyring` crate.
//!
//! Both backends present the same async API and namespace entries by `app` / `kind` /
//! `account`, so the keychain UI shows sensible per-account entries.

use crate::StoreError;

const APP_ID: &str = "de.monocles.chat";

#[cfg(target_os = "linux")]
pub use secret_service::{delete, retrieve, store};

#[cfg(not(target_os = "linux"))]
pub use keychain::{delete, retrieve, store};

/// Linux backend: freedesktop Secret Service over D-Bus via `oo7`.
#[cfg(target_os = "linux")]
mod secret_service {
    use super::{StoreError, APP_ID};
    use std::collections::HashMap;

    fn attrs<'a>(kind: &'a str, account: &'a str) -> HashMap<&'a str, &'a str> {
        let mut m = HashMap::new();
        m.insert("app", APP_ID);
        m.insert("kind", kind);
        m.insert("account", account);
        m
    }

    /// Connect to the Secret Service and unlock the default collection.
    ///
    /// oo7 0.6 no longer unlocks the collection inside `create_item`/`secret`/`delete`, so a
    /// locked GNOME-Keyring/KWallet collection fails with `org.freedesktop.Secret.Error.IsLocked`
    /// (notably on the login write path). Unlocking up front fixes that; it is a no-op when the
    /// collection is already unlocked and may prompt the desktop keyring agent once per session.
    async fn unlocked_keyring() -> Result<oo7::Keyring, StoreError> {
        let keyring = oo7::Keyring::new()
            .await
            .map_err(|e| StoreError::Secret(e.to_string()))?;
        keyring
            .unlock()
            .await
            .map_err(|e| StoreError::Secret(e.to_string()))?;
        Ok(keyring)
    }

    /// Store a secret value (password, sealed identity-key blob) for an account.
    pub async fn store(kind: &str, account_jid: &str, value: &[u8]) -> Result<(), StoreError> {
        let keyring = unlocked_keyring().await?;
        keyring
            .create_item(
                &format!("monocles chat {kind} ({account_jid})"),
                &attrs(kind, account_jid),
                value,
                true, // replace existing
            )
            .await
            .map_err(|e| StoreError::Secret(e.to_string()))?;
        Ok(())
    }

    /// Retrieve the first matching secret, if any.
    pub async fn retrieve(kind: &str, account_jid: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let keyring = unlocked_keyring().await?;
        let items = keyring
            .search_items(&attrs(kind, account_jid))
            .await
            .map_err(|e| StoreError::Secret(e.to_string()))?;
        match items.into_iter().next() {
            Some(item) => {
                let secret = item
                    .secret()
                    .await
                    .map_err(|e| StoreError::Secret(e.to_string()))?;
                Ok(Some(secret.to_vec()))
            }
            None => Ok(None),
        }
    }

    pub async fn delete(kind: &str, account_jid: &str) -> Result<(), StoreError> {
        let keyring = unlocked_keyring().await?;
        keyring
            .delete(&attrs(kind, account_jid))
            .await
            .map_err(|e| StoreError::Secret(e.to_string()))?;
        Ok(())
    }
}

/// macOS / Windows backend: the OS keychain via the `keyring` crate.
///
/// The keychain keys entries on `(service, account)`. We fold our `kind` into the service
/// name (`de.monocles.chat.<kind>`) so each kind is its own entry, and keep the JID as the
/// account — mirroring the `{ app, kind, account }` namespacing of the Linux backend. The
/// `keyring` API is blocking, so each call runs on a `spawn_blocking` thread to avoid
/// stalling the tokio runtime.
#[cfg(not(target_os = "linux"))]
mod keychain {
    use super::{StoreError, APP_ID};

    fn entry(kind: &str, account_jid: &str) -> Result<keyring::Entry, StoreError> {
        let service = format!("{APP_ID}.{kind}");
        keyring::Entry::new(&service, account_jid).map_err(|e| StoreError::Secret(e.to_string()))
    }

    /// Store a secret value (password, sealed identity-key blob) for an account.
    pub async fn store(kind: &str, account_jid: &str, value: &[u8]) -> Result<(), StoreError> {
        let (kind, account, value) = (kind.to_owned(), account_jid.to_owned(), value.to_vec());
        tokio::task::spawn_blocking(move || {
            entry(&kind, &account)?
                .set_secret(&value)
                .map_err(|e| StoreError::Secret(e.to_string()))
        })
        .await
        .map_err(|e| StoreError::Secret(e.to_string()))?
    }

    /// Retrieve the matching secret, if any.
    pub async fn retrieve(kind: &str, account_jid: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let (kind, account) = (kind.to_owned(), account_jid.to_owned());
        tokio::task::spawn_blocking(move || match entry(&kind, &account)?.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StoreError::Secret(e.to_string())),
        })
        .await
        .map_err(|e| StoreError::Secret(e.to_string()))?
    }

    pub async fn delete(kind: &str, account_jid: &str) -> Result<(), StoreError> {
        let (kind, account) = (kind.to_owned(), account_jid.to_owned());
        tokio::task::spawn_blocking(move || match entry(&kind, &account)?.delete_credential() {
            // Deleting a non-existent entry is a no-op, matching the Linux backend.
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(StoreError::Secret(e.to_string())),
        })
        .await
        .map_err(|e| StoreError::Secret(e.to_string()))?
    }
}

pub mod kinds {
    pub const PASSWORD: &str = "xmpp-password";
    /// libsignal `IdentityKeyPair::serialize()` bytes for the account's OMEMO2 identity.
    pub const OMEMO_IDENTITY: &str = "omemo2-identity";
    /// `PqIdentityKeyPair::serialize()` bytes (ML-DSA-87 signing+verification key) for the
    /// account's post-quantum half of the OMEMO2 hybrid identity.
    pub const OMEMO_PQ_IDENTITY: &str = "omemo2-pq-identity";
    /// Hex-encoded 32-byte SQLCipher key for the local database (not account-specific).
    pub const DB_KEY: &str = "db-key";
    /// Hex-encoded 32-byte AES-256-GCM key for the on-disk media caches (see `cache`).
    pub const CACHE_KEY: &str = "cache-key";
}
