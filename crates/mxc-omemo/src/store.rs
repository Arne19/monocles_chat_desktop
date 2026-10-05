//! libsignal store-trait implementations over `mxc-store`.
//!
//! libsignal's session functions take the five stores as *separate* `&mut dyn` refs
//! (e.g. `message_decrypt_prekey` wants session + identity + pre-key + signed + kyber at
//! once), so they cannot all be `&mut` views of one object. We therefore split into five
//! small structs that each hold a clone of the `Arc`-backed [`Store`] (same SQLite, so
//! they stay consistent). [`OmemoStores`] is a holder that vends them.
//!
//! The traits are `#[async_trait(?Send)]`, so we await `mxc-store` directly. Records are
//! libsignal's own `*::serialize()` bytes stored verbatim → identical on-disk format to
//! Android. The identity key pair + local registration (device) id are cached in the
//! identity store (loaded once from the secret service / accounts row).

use std::sync::Arc;

use async_trait::async_trait;

use libsignal_protocol::{
    DeviceId, Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PqIdentityKeyPair,
    PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};

use mxc_store::Store;

pub const TRUST_UNDECIDED: i64 = 0;
pub const TRUST_TRUSTED: i64 = 1;
pub const TRUST_UNTRUSTED: i64 = 2;

type R<T> = Result<T, SignalProtocolError>;

fn err<E: std::fmt::Display>(e: E) -> SignalProtocolError {
    SignalProtocolError::InvalidState("mxc-omemo store", e.to_string())
}

fn parts(address: &ProtocolAddress) -> (String, i64) {
    (address.name().to_string(), u32::from(address.device_id()) as i64)
}

/// Holder that vends the five per-account store views.
#[derive(Clone)]
pub struct OmemoStores {
    pub store: Store,
    pub account_id: i64,
    identity: IdentityKeyPair,
    registration_id: u32,
    /// Post-quantum (ML-DSA-87) half of the hybrid identity. `Arc` because
    /// `PqIdentityKeyPair` is not `Copy`/`Clone` and `OmemoStores` is cloned per store view.
    pq_identity: Arc<PqIdentityKeyPair>,
}

impl OmemoStores {
    pub fn new(
        store: Store,
        account_id: i64,
        identity: IdentityKeyPair,
        registration_id: u32,
        pq_identity: PqIdentityKeyPair,
    ) -> Self {
        Self {
            store,
            account_id,
            identity,
            registration_id,
            pq_identity: Arc::new(pq_identity),
        }
    }
    pub fn identity(&self) -> &IdentityKeyPair {
        &self.identity
    }
    /// The post-quantum (ML-DSA-87) identity key pair.
    pub fn pq_identity(&self) -> &PqIdentityKeyPair {
        &self.pq_identity
    }
    pub fn registration_id(&self) -> u32 {
        self.registration_id
    }
    /// Serialized public identity key (for the DB row + fingerprint display).
    pub fn identity_public_bytes(&self) -> Vec<u8> {
        self.identity.identity_key().public_key().serialize().to_vec()
    }
    /// Serialized public ML-DSA-87 identity key (for the DB row + hybrid fingerprint display).
    pub fn pq_identity_public_bytes(&self) -> Vec<u8> {
        self.pq_identity.public_key().serialize().to_vec()
    }

    pub fn identity_store(&self) -> IdentityStore {
        IdentityStore {
            store: self.store.clone(),
            account_id: self.account_id,
            identity: self.identity,
            registration_id: self.registration_id,
        }
    }
    pub fn session_store(&self) -> SessionStoreImpl {
        SessionStoreImpl { store: self.store.clone(), account_id: self.account_id }
    }
    pub fn pre_key_store(&self) -> PreKeyStoreImpl {
        PreKeyStoreImpl { store: self.store.clone(), account_id: self.account_id }
    }
    pub fn signed_pre_key_store(&self) -> SignedPreKeyStoreImpl {
        SignedPreKeyStoreImpl { store: self.store.clone(), account_id: self.account_id }
    }
    pub fn kyber_pre_key_store(&self) -> KyberPreKeyStoreImpl {
        KyberPreKeyStoreImpl { store: self.store.clone(), account_id: self.account_id }
    }
}

// ---- IdentityKeyStore -----------------------------------------------------

pub struct IdentityStore {
    store: Store,
    account_id: i64,
    identity: IdentityKeyPair,
    registration_id: u32,
}

#[async_trait(?Send)]
impl IdentityKeyStore for IdentityStore {
    async fn get_identity_key_pair(&self) -> R<IdentityKeyPair> {
        Ok(self.identity)
    }
    async fn get_local_registration_id(&self) -> R<u32> {
        Ok(self.registration_id)
    }
    async fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> R<IdentityChange> {
        let (jid, dev) = parts(address);
        let serialized = identity.serialize();
        let existed = self.store.omemo_identity(self.account_id, &jid, dev).await.map_err(err)?;
        let replaced = matches!(&existed, Some(old) if old.identity_key.as_slice() != &serialized[..]);
        // `save_omemo_identity` resets a replaced key's trust to undecided; log it, because
        // from here on that device is skipped by every encryption path until the user acts.
        if replaced {
            tracing::warn!(
                %jid,
                device_id = dev,
                "omemo: identity key REPLACED — trust reset to undecided, awaiting verification"
            );
        }
        self.store
            .save_omemo_identity(self.account_id, &jid, dev, &serialized)
            .await
            .map_err(err)?;
        if replaced {
            Ok(IdentityChange::ReplacedExisting)
        } else {
            Ok(IdentityChange::NewOrUnchanged)
        }
    }
    /// Whether libsignal may build/advance a ratchet toward this identity. This is NOT the
    /// application's trust decision — that lives in `omemo_identities.trust` and is enforced by
    /// `mxc-proto` (only trust 1 or 3 is ever encrypted to).
    ///
    /// A **replaced** identity key is accepted here on purpose. Refusing it would abort inside
    /// libsignal, leaving a peer who legitimately reinstalled on the same device id permanently
    /// unreachable with no recovery short of wiping all peer state. Instead the rebuild
    /// proceeds and [`Self::save_identity`] files the new key as undecided, so the app-level
    /// gate blocks it and the user is asked. Same split as monocles Android's
    /// `SQLiteAxolotlStore` (`isTrustedIdentity` → true; trust enforced in `AxolotlService`).
    ///
    /// An *explicitly untrusted* row still blocks its own key: that is a standing user decision
    /// about this device, not an unanswered question.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> R<bool> {
        let (jid, dev) = parts(address);
        match self.store.omemo_identity(self.account_id, &jid, dev).await.map_err(err)? {
            None => Ok(true), // TOFU: accept new device (surfaced to UI for verification)
            Some(rec) if rec.identity_key.as_slice() != &identity.serialize()[..] => Ok(true),
            Some(rec) => Ok(rec.trust != TRUST_UNTRUSTED),
        }
    }
    async fn get_identity(&self, address: &ProtocolAddress) -> R<Option<IdentityKey>> {
        let (jid, dev) = parts(address);
        match self.store.omemo_identity(self.account_id, &jid, dev).await.map_err(err)? {
            Some(rec) => Ok(Some(IdentityKey::decode(&rec.identity_key)?)),
            None => Ok(None),
        }
    }
}

// ---- PreKeyStore ----------------------------------------------------------

pub struct PreKeyStoreImpl {
    store: Store,
    account_id: i64,
}

#[async_trait(?Send)]
impl PreKeyStore for PreKeyStoreImpl {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> R<PreKeyRecord> {
        match self.store.load_prekey(self.account_id, u32::from(prekey_id) as i64).await.map_err(err)? {
            Some(b) => PreKeyRecord::deserialize(&b),
            None => Err(SignalProtocolError::InvalidPreKeyId),
        }
    }
    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> R<()> {
        self.store
            .store_prekey(self.account_id, u32::from(prekey_id) as i64, &record.serialize()?)
            .await
            .map_err(err)
    }
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> R<()> {
        self.store.remove_prekey(self.account_id, u32::from(prekey_id) as i64).await.map_err(err)
    }
}

// ---- SignedPreKeyStore ----------------------------------------------------

pub struct SignedPreKeyStoreImpl {
    store: Store,
    account_id: i64,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SignedPreKeyStoreImpl {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> R<SignedPreKeyRecord> {
        match self.store.load_signed_prekey(self.account_id, u32::from(id) as i64).await.map_err(err)? {
            Some(b) => SignedPreKeyRecord::deserialize(&b),
            None => Err(SignalProtocolError::InvalidSignedPreKeyId),
        }
    }
    async fn save_signed_pre_key(&mut self, id: SignedPreKeyId, record: &SignedPreKeyRecord) -> R<()> {
        self.store
            .store_signed_prekey(self.account_id, u32::from(id) as i64, &record.serialize()?)
            .await
            .map_err(err)
    }
}

// ---- KyberPreKeyStore -----------------------------------------------------

pub struct KyberPreKeyStoreImpl {
    store: Store,
    account_id: i64,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KyberPreKeyStoreImpl {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> R<KyberPreKeyRecord> {
        match self
            .store
            .load_kyber_prekey_meta(self.account_id, u32::from(id) as i64)
            .await
            .map_err(err)?
        {
            // A consumed one-time KEM pre-key MUST NOT decrypt again: serving it would
            // let a replayed PreKeySignalMessage re-run the handshake (Android deletes
            // the record on use; we keep the row for bookkeeping but refuse to load it).
            // Last-resort keys stay loadable — their replay protection is the
            // per-initiation tuple tracker in mark_kyber_pre_key_used below.
            Some((_, true, false)) => Err(SignalProtocolError::InvalidKyberPreKeyId),
            Some((b, _, _)) => KyberPreKeyRecord::deserialize(&b),
            None => Err(SignalProtocolError::InvalidKyberPreKeyId),
        }
    }
    async fn save_kyber_pre_key(&mut self, id: KyberPreKeyId, record: &KyberPreKeyRecord) -> R<()> {
        self.store
            .store_kyber_prekey(self.account_id, u32::from(id) as i64, &record.serialize()?, false)
            .await
            .map_err(err)
    }
    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> R<()> {
        let kyber_id = u32::from(id) as i64;
        let is_last_resort = self
            .store
            .load_kyber_prekey_meta(self.account_id, kyber_id)
            .await
            .map_err(err)?
            .map(|(_, _, lr)| lr)
            .unwrap_or(false);
        if is_last_resort {
            // proto-XEP §6.4: the last-resort key is reused across sessions, so track the
            // (kemId, spkId, baseKey) tuple of each initiation and reject duplicates —
            // otherwise a malicious server could replay a captured PreKeySignalMessage.
            // Mirrors Android's kyber_last_resort_sessions / ReusedBaseKeyException.
            let spk_id = u32::from(ec_prekey_id) as i64;
            let base = base_key.serialize();
            if self
                .store
                .kyber_last_resort_session_seen(self.account_id, kyber_id, spk_id, &base)
                .await
                .map_err(err)?
            {
                return Err(SignalProtocolError::InvalidMessage(
                    libsignal_protocol::CiphertextMessageType::PreKey,
                    "kyber last-resort prekey replayed".to_owned(),
                ));
            }
            self.store
                .record_kyber_last_resort_session(self.account_id, kyber_id, spk_id, &base)
                .await
                .map_err(err)
        } else {
            // One-time key: single use. get_kyber_pre_key refuses used records.
            self.store.mark_kyber_prekey_used(self.account_id, kyber_id).await.map_err(err)
        }
    }
}

// ---- SessionStore ---------------------------------------------------------

pub struct SessionStoreImpl {
    store: Store,
    account_id: i64,
}

#[async_trait(?Send)]
impl SessionStore for SessionStoreImpl {
    async fn load_session(&self, address: &ProtocolAddress) -> R<Option<SessionRecord>> {
        let (jid, dev) = parts(address);
        match self.store.load_omemo_session(self.account_id, &jid, dev).await.map_err(err)? {
            Some(b) => Ok(Some(SessionRecord::deserialize(&b)?)),
            None => Ok(None),
        }
    }
    async fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> R<()> {
        let (jid, dev) = parts(address);
        self.store
            .store_omemo_session(self.account_id, &jid, dev, &record.serialize()?)
            .await
            .map_err(err)
    }
}

/// Build a `ProtocolAddress` from our (bare jid, device id) keying.
pub fn protocol_address(jid: &str, device_id: u32) -> R<ProtocolAddress> {
    let dev = DeviceId::try_from(device_id)
        .map_err(|_| SignalProtocolError::InvalidState("device_id", "zero device id".into()))?;
    Ok(ProtocolAddress::new(jid.to_string(), dev))
}
