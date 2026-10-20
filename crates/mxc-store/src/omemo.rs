//! Raw blob CRUD for the PQ OMEMO2 key stores.
//!
//! These are intentionally dumb: they store/return libsignal-serialized record bytes
//! keyed by XMPP addressing. The libsignal store-trait impls (`IdentityKeyStore`,
//! `SessionStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`) live in the
//! `mxc-omemo` crate and call through to these.

use crate::{Result, Store};

#[derive(Debug, Clone)]
pub struct OmemoIdentity {
    pub device_id: i64,
    pub identity_key: Vec<u8>,
    /// 0 = undecided, 1 = trusted (BTBV), 2 = untrusted, 3 = verified (manually, via fingerprint
    /// comparison). Both 1 and 3 are encryption-eligible; only 3 lights the call "shield".
    pub trust: i64,
    pub active: bool,
}

impl Store {
    // ---- app settings ----------------------------------------------------

    /// Whether newly-seen OMEMO devices are automatically trusted (blind-trust). Default on.
    pub async fn auto_trust_new_keys(&self) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT value as "value!: String" FROM settings WHERE key = 'auto_trust_new_keys'"#
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.value != "0").unwrap_or(true))
    }

    pub async fn set_auto_trust_new_keys(&self, on: bool) -> Result<()> {
        let v = if on { "1" } else { "0" };
        sqlx::query!(
            r#"INSERT INTO settings (key, value) VALUES ('auto_trust_new_keys', ?1)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            v
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- own identity ----------------------------------------------------

    pub async fn omemo_own_device_id(&self, account_id: i64) -> Result<Option<i64>> {
        let rec = sqlx::query!(
            r#"SELECT device_id as "device_id!: i64" FROM omemo_own_identity WHERE account_id = ?1"#,
            account_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(rec.map(|r| r.device_id))
    }

    /// Our own public identity key bytes (for displaying this device's fingerprint).
    pub async fn omemo_own_identity_pub(&self, account_id: i64) -> Result<Option<Vec<u8>>> {
        let rec = sqlx::query!(
            r#"SELECT identity_pub as "identity_pub!: Vec<u8>" FROM omemo_own_identity WHERE account_id = ?1"#,
            account_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(rec.map(|r| r.identity_pub))
    }

    pub async fn set_omemo_own_identity(
        &self,
        account_id: i64,
        device_id: i64,
        identity_pub: &[u8],
        has_private: bool,
    ) -> Result<()> {
        let hp = has_private as i64;
        sqlx::query!(
            r#"INSERT INTO omemo_own_identity (account_id, device_id, identity_pub, has_private)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(account_id) DO UPDATE SET
                 device_id = excluded.device_id,
                 identity_pub = excluded.identity_pub,
                 has_private = excluded.has_private"#,
            account_id, device_id, identity_pub, hp,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Our own public ML-DSA-87 identity key (for displaying this device's hybrid fingerprint).
    pub async fn omemo_own_pq_identity_pub(&self, account_id: i64) -> Result<Option<Vec<u8>>> {
        let rec = sqlx::query!(
            r#"SELECT pq_identity_pub as "pq_identity_pub: Vec<u8>" FROM omemo_own_identity WHERE account_id = ?1"#,
            account_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(rec.and_then(|r| r.pq_identity_pub))
    }

    /// Store our own public ML-DSA-87 identity key.
    pub async fn set_omemo_own_pq_identity_pub(&self, account_id: i64, pq_identity_pub: &[u8]) -> Result<()> {
        sqlx::query!(
            "UPDATE omemo_own_identity SET pq_identity_pub = ?1 WHERE account_id = ?2",
            pq_identity_pub,
            account_id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- post-quantum identity pins (hybrid identity) -------------------

    /// The post-quantum (ML-DSA-87) identity key `jid` has pinned for its classical
    /// `fingerprint` (hex of its serialized classical IdentityKey), if any.
    ///
    /// `jid` is not decoration. A classical identity key is published in PEP for anyone to
    /// read, so a pin keyed on the fingerprint alone let one JID poison another's: publish
    /// someone else's `<ik>` beside your own `<pq-ik>`, get pinned on first contact, and every
    /// later session with the real owner is refused as a changed pq_ik. Trust and the pin both
    /// belong to a (JID, key) pair, never to a key on its own.
    pub async fn get_pinned_omemo2_pq_identity(
        &self,
        account_id: i64,
        jid: &str,
        fingerprint: &str,
    ) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query!(
            r#"SELECT pq_identity_key as "pq_identity_key!: Vec<u8>"
               FROM omemo_pq_identities
               WHERE account_id = ?1 AND address_jid = ?2 AND fingerprint = ?3"#,
            account_id, jid, fingerprint,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.pq_identity_key))
    }

    /// Pin `jid`'s post-quantum identity to its classical `fingerprint`, REPLACING any existing
    /// pin. Only for an out-of-band verification of the hybrid fingerprint — the one input
    /// allowed to replace a pin (proto-XEP §10.1); every other path uses
    /// [`Self::pin_omemo2_pq_identity_if_absent`]. See
    /// [`Self::get_pinned_omemo2_pq_identity`] for why the pin is scoped to `jid`.
    pub async fn pin_omemo2_pq_identity(
        &self,
        account_id: i64,
        jid: &str,
        fingerprint: &str,
        pq_identity_key: &[u8],
    ) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO omemo_pq_identities (account_id, address_jid, fingerprint, pq_identity_key)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(account_id, address_jid, fingerprint)
               DO UPDATE SET pq_identity_key = excluded.pq_identity_key"#,
            account_id, jid, fingerprint, pq_identity_key,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Pin `jid`'s post-quantum identity only if nothing is pinned yet for (`jid`,
    /// `fingerprint`). One `INSERT … ON CONFLICT DO NOTHING` against the primary key, so two
    /// tasks racing to pin can never overwrite each other (mirrors Android's
    /// `pinOmemo2PqIdentityIfAbsent`).
    ///
    /// Returns the key pinned afterwards: `pq_identity_key` when it was inserted (or already
    /// was the pin), otherwise the different key that was already there.
    pub async fn pin_omemo2_pq_identity_if_absent(
        &self,
        account_id: i64,
        jid: &str,
        fingerprint: &str,
        pq_identity_key: &[u8],
    ) -> Result<Vec<u8>> {
        sqlx::query!(
            r#"INSERT INTO omemo_pq_identities (account_id, address_jid, fingerprint, pq_identity_key)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(account_id, address_jid, fingerprint) DO NOTHING"#,
            account_id, jid, fingerprint, pq_identity_key,
        )
        .execute(self.pool())
        .await?;
        Ok(self
            .get_pinned_omemo2_pq_identity(account_id, jid, fingerprint)
            .await?
            .unwrap_or_else(|| pq_identity_key.to_vec()))
    }

    /// Wipe all locally cached OMEMO2 **peer** state for an account — ongoing sessions, peer
    /// identity keys (and their trust), pinned post-quantum identities, and cached device lists
    /// — so they are re-fetched and rebuilt from scratch on the next exchange. Our OWN identity,
    /// device id, pre-keys and published bundle are left intact, so our fingerprint is unchanged
    /// and contacts do not need to re-verify us. The recovery action for stale OMEMO2 state.
    pub async fn reset_omemo2_peer_state(&self, account_id: i64) -> Result<()> {
        sqlx::query!("DELETE FROM omemo_sessions WHERE account_id = ?1", account_id)
            .execute(self.pool())
            .await?;
        sqlx::query!("DELETE FROM omemo_identities WHERE account_id = ?1", account_id)
            .execute(self.pool())
            .await?;
        sqlx::query!("DELETE FROM omemo_pq_identities WHERE account_id = ?1", account_id)
            .execute(self.pool())
            .await?;
        sqlx::query!("DELETE FROM omemo_device_lists WHERE account_id = ?1", account_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Wipe our OWN OMEMO2 identity + key material for an account — the own-identity row
    /// (device id, classical + ML-DSA-87 public keys, cached bundle XML) and every pre-key
    /// table (EC one-time, EC signed, Kyber, and the Kyber last-resort replay records).
    ///
    /// This is one half of the LAST-RESORT identity regeneration (the other half is
    /// [`Self::reset_omemo2_peer_state`]): with the own-identity row gone, the next OMEMO2
    /// initialization generates a brand-new device id + hybrid identity, so this device gets a
    /// new fingerprint and contacts MUST verify it again. The caller must also delete the
    /// private-key secrets and drop any in-memory stores cache.
    pub async fn reset_omemo2_own_state(&self, account_id: i64) -> Result<()> {
        sqlx::query!("DELETE FROM omemo_own_identity WHERE account_id = ?1", account_id)
            .execute(self.pool())
            .await?;
        sqlx::query!("DELETE FROM omemo_prekeys WHERE account_id = ?1", account_id)
            .execute(self.pool())
            .await?;
        sqlx::query!("DELETE FROM omemo_signed_prekeys WHERE account_id = ?1", account_id)
            .execute(self.pool())
            .await?;
        sqlx::query!("DELETE FROM omemo_kyber_prekeys WHERE account_id = ?1", account_id)
            .execute(self.pool())
            .await?;
        sqlx::query!("DELETE FROM omemo_kyber_last_resort_sessions WHERE account_id = ?1", account_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Cache the published OMEMO2 `<bundle>` XML so we can re-publish it verbatim.
    pub async fn set_omemo_bundle_xml(&self, account_id: i64, xml: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE omemo_own_identity SET bundle_xml = ?1 WHERE account_id = ?2",
            xml,
            account_id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// The cached published bundle XML, if we've generated one.
    pub async fn omemo_bundle_xml(&self, account_id: i64) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT bundle_xml as "bundle_xml: String" FROM omemo_own_identity WHERE account_id = ?1"#,
            account_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.and_then(|r| r.bundle_xml))
    }

    // ---- remote identities / trust --------------------------------------

    pub async fn save_omemo_identity(
        &self,
        account_id: i64,
        jid: &str,
        device_id: i64,
        identity_key: &[u8],
    ) -> Result<()> {
        // A *new* device starts trusted (1) when "auto-trust new keys" is on, else undecided
        // (0). An existing device whose key is UNCHANGED keeps whatever trust it had.
        //
        // A REPLACED key is reset to undecided (0), never carried over. Trust belongs to a
        // (JID, key) pair, not to a device slot: the user verified — or blind-trusted — the key
        // that was there before, and has said nothing about this one. Blind-trust-before-
        // verification agrees to accept a *new device*, which is not the same event; a
        // malicious server can force a rebuild at will (break the session, we re-fetch the
        // bundle), so carrying the old verdict across would let it swap the identity silently.
        // The encryption paths gate on trust 1 or 3, so an undecided device is skipped until
        // the user decides. Mirrors monocles Android's `SQLiteAxolotlStore.saveIdentity`.
        let new_trust: i64 = if self.auto_trust_new_keys().await? { 1 } else { 0 };
        sqlx::query!(
            r#"INSERT INTO omemo_identities (account_id, address_jid, device_id, identity_key, trust)
               VALUES (?1, ?2, ?3, ?4, ?5)
               ON CONFLICT(account_id, address_jid, device_id) DO UPDATE SET
                 identity_key = excluded.identity_key,
                 active = 1,
                 trust = CASE
                     WHEN omemo_identities.identity_key = excluded.identity_key
                     THEN omemo_identities.trust
                     ELSE 0
                 END"#,
            account_id, jid, device_id, identity_key, new_trust,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn omemo_identity(
        &self,
        account_id: i64,
        jid: &str,
        device_id: i64,
    ) -> Result<Option<OmemoIdentity>> {
        let row = sqlx::query!(
            r#"SELECT device_id as "device_id!: i64",
                      identity_key as "identity_key!: Vec<u8>",
                      trust as "trust!: i64",
                      active as "active!: bool"
               FROM omemo_identities
               WHERE account_id = ?1 AND address_jid = ?2 AND device_id = ?3"#,
            account_id, jid, device_id,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| OmemoIdentity {
            device_id: r.device_id,
            identity_key: r.identity_key,
            trust: r.trust,
            active: r.active,
        }))
    }

    /// All known OMEMO identities for `jid` (e.g. our own bare JID = our other devices), for
    /// the key-management UI. Newest-seen first.
    pub async fn list_omemo_identities(&self, account_id: i64, jid: &str) -> Result<Vec<OmemoIdentity>> {
        let rows = sqlx::query!(
            r#"SELECT device_id as "device_id!: i64",
                      identity_key as "identity_key!: Vec<u8>",
                      trust as "trust!: i64",
                      active as "active!: bool"
               FROM omemo_identities
               WHERE account_id = ?1 AND address_jid = ?2
               ORDER BY seen_at DESC"#,
            account_id, jid,
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| OmemoIdentity {
                device_id: r.device_id,
                identity_key: r.identity_key,
                trust: r.trust,
                active: r.active,
            })
            .collect())
    }

    pub async fn set_omemo_trust(
        &self,
        account_id: i64,
        jid: &str,
        device_id: i64,
        trust: i64,
    ) -> Result<()> {
        sqlx::query!(
            r#"UPDATE omemo_identities SET trust = ?4
               WHERE account_id = ?1 AND address_jid = ?2 AND device_id = ?3"#,
            account_id, jid, device_id, trust,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- sessions --------------------------------------------------------

    pub async fn load_omemo_session(
        &self,
        account_id: i64,
        jid: &str,
        device_id: i64,
    ) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query!(
            r#"SELECT record as "record!: Vec<u8>" FROM omemo_sessions
               WHERE account_id = ?1 AND address_jid = ?2 AND device_id = ?3"#,
            account_id, jid, device_id,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.record))
    }

    pub async fn store_omemo_session(
        &self,
        account_id: i64,
        jid: &str,
        device_id: i64,
        record: &[u8],
    ) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO omemo_sessions (account_id, address_jid, device_id, record)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(account_id, address_jid, device_id)
               DO UPDATE SET record = excluded.record"#,
            account_id, jid, device_id, record,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- EC pre-keys -----------------------------------------------------

    pub async fn load_prekey(&self, account_id: i64, prekey_id: i64) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query!(
            r#"SELECT record as "record!: Vec<u8>" FROM omemo_prekeys
               WHERE account_id = ?1 AND prekey_id = ?2"#,
            account_id, prekey_id,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.record))
    }

    pub async fn store_prekey(&self, account_id: i64, prekey_id: i64, record: &[u8]) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO omemo_prekeys (account_id, prekey_id, record) VALUES (?1, ?2, ?3)
               ON CONFLICT(account_id, prekey_id) DO UPDATE SET record = excluded.record"#,
            account_id, prekey_id, record,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn remove_prekey(&self, account_id: i64, prekey_id: i64) -> Result<()> {
        sqlx::query!(
            "DELETE FROM omemo_prekeys WHERE account_id = ?1 AND prekey_id = ?2",
            account_id, prekey_id,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn count_prekeys(&self, account_id: i64) -> Result<i64> {
        let rec = sqlx::query!(
            r#"SELECT COUNT(*) as "n!: i64" FROM omemo_prekeys WHERE account_id = ?1"#,
            account_id
        )
        .fetch_one(self.pool())
        .await?;
        Ok(rec.n)
    }

    /// All stored EC one-time pre-keys as (id, record bytes) — for rebuilding the bundle.
    pub async fn list_prekeys(&self, account_id: i64) -> Result<Vec<(i64, Vec<u8>)>> {
        let rows = sqlx::query!(
            r#"SELECT prekey_id as "id!: i64", record as "record!: Vec<u8>"
               FROM omemo_prekeys WHERE account_id = ?1 ORDER BY prekey_id"#,
            account_id
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|r| (r.id, r.record)).collect())
    }

    pub async fn max_prekey_id(&self, account_id: i64) -> Result<i64> {
        let rec = sqlx::query!(
            r#"SELECT COALESCE(MAX(prekey_id), 0) as "m!: i64" FROM omemo_prekeys WHERE account_id = ?1"#,
            account_id
        )
        .fetch_one(self.pool())
        .await?;
        Ok(rec.m)
    }

    // ---- signed pre-keys -------------------------------------------------

    pub async fn load_signed_prekey(&self, account_id: i64, id: i64) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query!(
            r#"SELECT record as "record!: Vec<u8>" FROM omemo_signed_prekeys
               WHERE account_id = ?1 AND signed_prekey_id = ?2"#,
            account_id, id,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.record))
    }

    /// The newest signed pre-key (highest id — ids only ever increase, so that is also the most
    /// recently generated one) together with its record. Superseded signed pre-keys stay in the
    /// table on rotation, so a handshake in flight against a previously published bundle can
    /// still resolve the id it cites.
    pub async fn newest_signed_prekey(&self, account_id: i64) -> Result<Option<(i64, Vec<u8>)>> {
        let row = sqlx::query!(
            r#"SELECT signed_prekey_id as "id!: i64", record as "record!: Vec<u8>"
               FROM omemo_signed_prekeys WHERE account_id = ?1
               ORDER BY signed_prekey_id DESC LIMIT 1"#,
            account_id,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| (r.id, r.record)))
    }

    pub async fn store_signed_prekey(&self, account_id: i64, id: i64, record: &[u8]) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO omemo_signed_prekeys (account_id, signed_prekey_id, record)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(account_id, signed_prekey_id) DO UPDATE SET record = excluded.record"#,
            account_id, id, record,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- KEM (kyber) pre-keys -------------------------------------------

    pub async fn load_kyber_prekey(&self, account_id: i64, id: i64) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query!(
            r#"SELECT record as "record!: Vec<u8>" FROM omemo_kyber_prekeys
               WHERE account_id = ?1 AND kyber_prekey_id = ?2"#,
            account_id, id,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.record))
    }

    pub async fn store_kyber_prekey(
        &self,
        account_id: i64,
        id: i64,
        record: &[u8],
        is_last_resort: bool,
    ) -> Result<()> {
        let lr = is_last_resort as i64;
        sqlx::query!(
            r#"INSERT INTO omemo_kyber_prekeys (account_id, kyber_prekey_id, record, is_last_resort)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(account_id, kyber_prekey_id)
               DO UPDATE SET record = excluded.record, is_last_resort = excluded.is_last_resort"#,
            account_id, id, record, lr,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Last-resort replay guard: mark a one-time KEM prekey used (non-last-resort ones
    /// are then deleted by the OMEMO layer; last-resort ones are kept but flagged).
    pub async fn mark_kyber_prekey_used(&self, account_id: i64, id: i64) -> Result<()> {
        sqlx::query!(
            r#"UPDATE omemo_kyber_prekeys SET used = 1
               WHERE account_id = ?1 AND kyber_prekey_id = ?2"#,
            account_id, id,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Available (unused, non-last-resort) one-time KEM pre-keys as (id, record bytes).
    pub async fn available_kyber_prekeys(&self, account_id: i64) -> Result<Vec<(i64, Vec<u8>)>> {
        let rows = sqlx::query!(
            r#"SELECT kyber_prekey_id as "id!: i64", record as "record!: Vec<u8>"
               FROM omemo_kyber_prekeys
               WHERE account_id = ?1 AND used = 0 AND is_last_resort = 0
               ORDER BY kyber_prekey_id"#,
            account_id
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|r| (r.id, r.record)).collect())
    }

    /// The CURRENT last-resort signed KEM pre-key (id, record bytes), if present.
    /// Newest id wins: rotation (proto-XEP §4.5.1) stores a fresh last-resort under the
    /// next free id while superseded ones remain decryptable for a grace period.
    pub async fn last_resort_kyber(&self, account_id: i64) -> Result<Option<(i64, Vec<u8>)>> {
        let row = sqlx::query!(
            r#"SELECT kyber_prekey_id as "id!: i64", record as "record!: Vec<u8>"
               FROM omemo_kyber_prekeys
               WHERE account_id = ?1 AND is_last_resort = 1
               ORDER BY kyber_prekey_id DESC LIMIT 1"#,
            account_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| (r.id, r.record)))
    }

    /// Every KEM pre-key row: (id, record, is_last_resort, used). For pruning.
    pub async fn all_kyber_prekeys(
        &self,
        account_id: i64,
    ) -> Result<Vec<(i64, Vec<u8>, bool, bool)>> {
        let rows = sqlx::query!(
            r#"SELECT kyber_prekey_id as "id!: i64", record as "record!: Vec<u8>",
                      is_last_resort as "is_last_resort!: bool", used as "used!: bool"
               FROM omemo_kyber_prekeys WHERE account_id = ?1"#,
            account_id
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|r| (r.id, r.record, r.is_last_resort, r.used)).collect())
    }

    pub async fn delete_kyber_prekey(&self, account_id: i64, id: i64) -> Result<()> {
        sqlx::query!(
            r#"DELETE FROM omemo_kyber_prekeys
               WHERE account_id = ?1 AND kyber_prekey_id = ?2"#,
            account_id,
            id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// A KEM pre-key row with its flags: (record, used, is_last_resort).
    pub async fn load_kyber_prekey_meta(
        &self,
        account_id: i64,
        id: i64,
    ) -> Result<Option<(Vec<u8>, bool, bool)>> {
        let row = sqlx::query!(
            r#"SELECT record as "record!: Vec<u8>", used as "used!: bool",
                      is_last_resort as "is_last_resort!: bool"
               FROM omemo_kyber_prekeys
               WHERE account_id = ?1 AND kyber_prekey_id = ?2"#,
            account_id,
            id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| (r.record, r.used, r.is_last_resort)))
    }

    /// Whether the (kyber_prekey_id, signed_prekey_id, base_key) tuple of a last-resort
    /// session initiation was seen before (proto-XEP §6.4 replay tracking).
    pub async fn kyber_last_resort_session_seen(
        &self,
        account_id: i64,
        kyber_prekey_id: i64,
        signed_prekey_id: i64,
        base_key: &[u8],
    ) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT 1 as "one!: i64" FROM omemo_kyber_last_resort_sessions
               WHERE account_id = ?1 AND kyber_prekey_id = ?2
                 AND signed_prekey_id = ?3 AND base_key = ?4"#,
            account_id,
            kyber_prekey_id,
            signed_prekey_id,
            base_key
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.is_some())
    }

    /// Delete replay-tracking rows whose KEM prekey no longer exists, returning the row count.
    ///
    /// [`Self::record_kyber_last_resort_session`] is append-only, and it is the one write in the
    /// OMEMO2 path an unauthenticated remote party can trigger: bundles are public, so anyone who
    /// can send us a stanza can initiate a handshake against our last-resort key and add a row.
    /// Nothing removed them, so the table grew for the lifetime of the account.
    ///
    /// A row only defends anything while the key it names is still loadable. Once
    /// `prune_stale_kyber_prekeys` has deleted a superseded last-resort key, a replay against it
    /// fails at key lookup and never reaches the tuple check — so those rows can go. Keyed on the
    /// prekey's continued existence rather than on age, so a key retained past any timeout keeps
    /// its tuples.
    pub async fn prune_orphaned_kyber_last_resort_sessions(&self, account_id: i64) -> Result<u64> {
        let res = sqlx::query!(
            r#"DELETE FROM omemo_kyber_last_resort_sessions
               WHERE account_id = ?1 AND kyber_prekey_id NOT IN
                     (SELECT kyber_prekey_id FROM omemo_kyber_prekeys WHERE account_id = ?1)"#,
            account_id
        )
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected())
    }

    /// Record a last-resort session-initiation tuple (see [`Self::kyber_last_resort_session_seen`]).
    pub async fn record_kyber_last_resort_session(
        &self,
        account_id: i64,
        kyber_prekey_id: i64,
        signed_prekey_id: i64,
        base_key: &[u8],
    ) -> Result<()> {
        sqlx::query!(
            r#"INSERT OR IGNORE INTO omemo_kyber_last_resort_sessions
               (account_id, kyber_prekey_id, signed_prekey_id, base_key)
               VALUES (?1, ?2, ?3, ?4)"#,
            account_id,
            kyber_prekey_id,
            signed_prekey_id,
            base_key
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn max_kyber_prekey_id(&self, account_id: i64) -> Result<i64> {
        let rec = sqlx::query!(
            r#"SELECT COALESCE(MAX(kyber_prekey_id), 0) as "m!: i64"
               FROM omemo_kyber_prekeys WHERE account_id = ?1"#,
            account_id
        )
        .fetch_one(self.pool())
        .await?;
        Ok(rec.m)
    }

    pub async fn kyber_prekey_used(&self, account_id: i64, id: i64) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT used as "used!: bool" FROM omemo_kyber_prekeys
               WHERE account_id = ?1 AND kyber_prekey_id = ?2"#,
            account_id, id,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.used).unwrap_or(false))
    }

    // ---- device lists ----------------------------------------------------

    /// Mark which of `jid`'s known OMEMO2 devices are in its current published device list:
    /// listed → active, unlisted → inactive. `keep` (our own device, for our own JID) stays
    /// active whatever the list says. This is display state for the key screens only: no row is
    /// deleted, trust is untouched, and nothing is published - a transient or hostile list can
    /// at worst grey a device out until the next one. Returns whether any row changed.
    pub async fn set_omemo_devices_active(
        &self,
        account_id: i64,
        jid: &str,
        listed: &[u32],
        keep: Option<u32>,
    ) -> Result<bool> {
        // The ids travel as one bound JSON array (built from integers only), so the SQL stays
        // static. -1 is never a device id (they are u32), so "no device to keep" matches none.
        let ids = listed.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        let ids = format!("[{ids}]");
        let keep = keep.map(i64::from).unwrap_or(-1);
        let result = sqlx::query(
            "UPDATE omemo_identities
             SET active = (device_id IN (SELECT value FROM json_each(?1)) OR device_id = ?2)
             WHERE account_id = ?3 AND address_jid = ?4 COLLATE NOCASE
               AND active <> (device_id IN (SELECT value FROM json_each(?1)) OR device_id = ?2)",
        )
        .bind(ids)
        .bind(keep)
        .bind(account_id)
        .bind(jid)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn cache_device_list(
        &self,
        account_id: i64,
        jid: &str,
        device_ids_json: &str,
    ) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO omemo_device_lists (account_id, address_jid, device_ids, fetched_at)
               VALUES (?1, ?2, ?3, datetime('now'))
               ON CONFLICT(account_id, address_jid)
               DO UPDATE SET device_ids = excluded.device_ids, fetched_at = excluded.fetched_at"#,
            account_id, jid, device_ids_json,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod last_resort_prune_tests {
    use crate::Store;

    /// A published device list only flips the display flag: unlisted devices go inactive,
    /// re-listed ones active again, our own device never goes inactive, trust is untouched.
    #[tokio::test]
    async fn device_list_sets_the_active_flag_only() {
        let store = Store::open_in_memory().await.expect("open");
        let acc = store.upsert_account("me@example.org").await.expect("account");
        let peer = "friend@example.net";
        for dev in [1, 2, 3] {
            store.save_omemo_identity(acc, peer, dev, &[dev as u8; 33]).await.unwrap();
        }
        let active = |s: Store| async move {
            let mut a: Vec<(i64, bool)> =
                s.list_omemo_identities(acc, peer).await.unwrap().into_iter().map(|i| (i.device_id, i.active)).collect();
            a.sort();
            a
        };
        let trust_before: Vec<i64> =
            store.list_omemo_identities(acc, peer).await.unwrap().into_iter().map(|i| i.trust).collect();

        assert!(store.set_omemo_devices_active(acc, peer, &[1, 3], None).await.unwrap());
        assert_eq!(active(store.clone()).await, vec![(1, true), (2, false), (3, true)]);
        // Same list again: nothing to change.
        assert!(!store.set_omemo_devices_active(acc, peer, &[1, 3], None).await.unwrap());
        // Case-insensitive JID match, and re-listing reactivates.
        assert!(store.set_omemo_devices_active(acc, "Friend@Example.net", &[2], None).await.unwrap());
        assert_eq!(active(store.clone()).await, vec![(1, false), (2, true), (3, false)]);
        // An empty list (valid SQL) greys everything out except the kept device.
        assert!(store.set_omemo_devices_active(acc, peer, &[], Some(3)).await.unwrap());
        assert_eq!(active(store.clone()).await, vec![(1, false), (2, false), (3, true)]);

        let trust_after: Vec<i64> =
            store.list_omemo_identities(acc, peer).await.unwrap().into_iter().map(|i| i.trust).collect();
        assert_eq!(trust_before, trust_after);
        assert_eq!(store.list_omemo_identities(acc, peer).await.unwrap().len(), 3, "nothing is deleted");
    }

    /// The replay-tracking table is append-only and is the one OMEMO2 write an unauthenticated
    /// peer can trigger, so it has to shed rows once the key they name is gone — but not before,
    /// or a live last-resort key would lose its replay defence.
    #[tokio::test]
    async fn prunes_only_rows_whose_prekey_is_gone() {
        let store = Store::open_in_memory().await.expect("open");
        let acc = store.upsert_account("arne@monocles.eu").await.expect("account");

        // Two last-resort keys, each with a recorded initiation; then one key is retired.
        store.store_kyber_prekey(acc, 7, b"record-7", true).await.unwrap();
        store.store_kyber_prekey(acc, 8, b"record-8", true).await.unwrap();
        store.record_kyber_last_resort_session(acc, 7, 1, b"base-a").await.unwrap();
        store.record_kyber_last_resort_session(acc, 7, 1, b"base-b").await.unwrap();
        store.record_kyber_last_resort_session(acc, 8, 1, b"base-c").await.unwrap();

        // Nothing to prune while both keys exist.
        assert_eq!(store.prune_orphaned_kyber_last_resort_sessions(acc).await.unwrap(), 0);

        store.delete_kyber_prekey(acc, 7).await.unwrap();
        assert_eq!(store.prune_orphaned_kyber_last_resort_sessions(acc).await.unwrap(), 2);

        // The surviving key keeps its tuple — a replay against it must still be caught.
        assert!(store.kyber_last_resort_session_seen(acc, 8, 1, b"base-c").await.unwrap());
        assert!(!store.kyber_last_resort_session_seen(acc, 7, 1, b"base-a").await.unwrap());
        // Idempotent.
        assert_eq!(store.prune_orphaned_kyber_last_resort_sessions(acc).await.unwrap(), 0);
    }
}
