//! Account rows.

use crate::{Result, Store};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Account {
    pub id: i64,
    pub jid: String,
    pub has_secret: bool,
    pub resource: Option<String>,
    pub enabled: bool,
    pub omemo_device_id: Option<i64>,
    pub display_name: Option<String>,
}

impl Store {
    /// Insert the account if new, returning its id. Idempotent on bare JID.
    pub async fn upsert_account(&self, jid: &str) -> Result<i64> {
        let rec = sqlx::query!(
            r#"
            INSERT INTO accounts (jid) VALUES (?1)
            ON CONFLICT(jid) DO UPDATE SET jid = jid
            RETURNING id as "id!: i64"
            "#,
            jid
        )
        .fetch_one(self.pool())
        .await?;
        Ok(rec.id)
    }

    pub async fn account_by_jid(&self, jid: &str) -> Result<Option<Account>> {
        let acc = sqlx::query_as::<_, Account>(
            r#"SELECT id, jid, has_secret, resource, enabled, omemo_device_id, display_name
               FROM accounts WHERE jid = ?1"#,
        )
        .bind(jid)
        .fetch_optional(self.pool())
        .await?;
        Ok(acc)
    }

    pub async fn enabled_accounts(&self) -> Result<Vec<Account>> {
        let rows = sqlx::query_as::<_, Account>(
            r#"SELECT id, jid, has_secret, resource, enabled, omemo_device_id, display_name
               FROM accounts WHERE enabled = 1 ORDER BY id"#,
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Record the OMEMO2 device id assigned to this account.
    pub async fn set_omemo_device_id(&self, account_id: i64, device_id: i64) -> Result<()> {
        sqlx::query!(
            "UPDATE accounts SET omemo_device_id = ?1 WHERE id = ?2",
            device_id,
            account_id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn mark_has_secret(&self, account_id: i64, has: bool) -> Result<()> {
        let v = has as i64;
        sqlx::query!("UPDATE accounts SET has_secret = ?1 WHERE id = ?2", v, account_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn set_account_enabled(&self, account_id: i64, enabled: bool) -> Result<()> {
        let v = enabled as i64;
        sqlx::query!("UPDATE accounts SET enabled = ?1 WHERE id = ?2", v, account_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// XEP-0474: priority of the strongest SASL mechanism used for the account so far (-1: none).
    pub async fn sasl_pin(&self, account_id: i64) -> Result<i32> {
        let pin: Option<i64> = sqlx::query_scalar("SELECT sasl_pin FROM accounts WHERE id = ?1")
            .bind(account_id)
            .fetch_optional(self.pool())
            .await?;
        Ok(pin.unwrap_or(-1) as i32)
    }

    /// Record the SASL pin; `-1` resets it (when the user re-enters the password).
    pub async fn set_sasl_pin(&self, account_id: i64, pin: i32) -> Result<()> {
        sqlx::query("UPDATE accounts SET sasl_pin = ?1 WHERE id = ?2")
            .bind(pin as i64)
            .bind(account_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// The first enabled account that has a stored secret (for auto-login on startup).
    pub async fn autologin_account(&self) -> Result<Option<Account>> {
        let acc = sqlx::query_as::<_, Account>(
            r#"SELECT id, jid, has_secret, resource, enabled, omemo_device_id, display_name
               FROM accounts WHERE enabled = 1 AND has_secret = 1 ORDER BY id LIMIT 1"#,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(acc)
    }
}
