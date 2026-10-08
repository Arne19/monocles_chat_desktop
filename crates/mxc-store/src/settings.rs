//! Misc. app-wide key/value settings (the `settings` table), beyond the OMEMO ones in
//! [`crate::omemo`].

use crate::Store;
use anyhow::Result;

/// How long "Not now" hides the donation banner before it's shown again.
pub const DONATION_SNOOZE_SECS: i64 = 7 * 24 * 60 * 60; // one week

impl Store {
    /// Whether the donation banner should be shown now: true unless the user dismissed it
    /// within the last [`DONATION_SNOOZE_SECS`].
    pub async fn donation_banner_due(&self, now: i64) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT value as "value!: String" FROM settings WHERE key = 'donation_snooze_until'"#
        )
        .fetch_optional(self.pool())
        .await?;
        let snooze_until = row.and_then(|r| r.value.parse::<i64>().ok()).unwrap_or(0);
        Ok(now >= snooze_until)
    }

    /// Dismiss the donation banner ("Not now"): hide it until `now + DONATION_SNOOZE_SECS`.
    pub async fn snooze_donation_banner(&self, now: i64) -> Result<()> {
        let until = (now + DONATION_SNOOZE_SECS).to_string();
        sqlx::query!(
            r#"INSERT INTO settings (key, value) VALUES ('donation_snooze_until', ?1)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            until
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- one-shot flags (e.g. migrations done once per account) ----

    /// Whether the flag `key` has been set.
    pub async fn flag(&self, key: &str) -> Result<bool> {
        let row = sqlx::query_as::<_, (String,)>("SELECT value FROM settings WHERE key = ?1")
            .bind(key)
            .fetch_optional(self.pool())
            .await?;
        Ok(row.is_some_and(|(v,)| v == "1"))
    }

    /// Set the flag `key`.
    pub async fn set_flag(&self, key: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?1, '1') ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- default monocles support-room entry (Contacts tab) ----

    /// Whether the user removed the default support-room entry (per account).
    pub async fn support_room_dismissed(&self, account_id: i64) -> Result<bool> {
        let key = format!("support_room_dismissed:{account_id}");
        let row = sqlx::query!(
            r#"SELECT value as "value!: String" FROM settings WHERE key = ?1"#,
            key
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.value == "1").unwrap_or(false))
    }

    /// Permanently remove the default support-room entry (per account).
    pub async fn dismiss_support_room(&self, account_id: i64) -> Result<()> {
        let key = format!("support_room_dismissed:{account_id}");
        sqlx::query!(
            r#"INSERT INTO settings (key, value) VALUES (?1, '1')
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            key
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- chat background (app-wide UI preference) ----

    /// The chat-background preference: `(mode, custom_path)`. `mode` is "default" (the bundled
    /// monocles doodle tile), "none", or "custom"; `custom_path` is the chosen image for the
    /// "custom" mode. Defaults to the bundled background.
    pub async fn chat_background(&self) -> Result<(String, String)> {
        let mode = sqlx::query!(
            r#"SELECT value as "value!: String" FROM settings WHERE key = 'chat_bg_mode'"#
        )
        .fetch_optional(self.pool())
        .await?
        .map(|r| r.value)
        .unwrap_or_else(|| "default".to_string());
        let path = sqlx::query!(
            r#"SELECT value as "value!: String" FROM settings WHERE key = 'chat_bg_custom_path'"#
        )
        .fetch_optional(self.pool())
        .await?
        .map(|r| r.value)
        .unwrap_or_default();
        Ok((mode, path))
    }

    /// Persist the chat-background mode ("default" | "none" | "custom").
    pub async fn set_chat_bg_mode(&self, mode: &str) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO settings (key, value) VALUES ('chat_bg_mode', ?1)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            mode
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Persist the custom chat-background image path (used in "custom" mode).
    pub async fn set_chat_bg_custom_path(&self, path: &str) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO settings (key, value) VALUES ('chat_bg_custom_path', ?1)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            path
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- preferred camera (app-wide call setting) ----

    /// The user's preferred camera device path for video calls, or "" for automatic selection.
    pub async fn preferred_camera(&self) -> Result<String> {
        let row = sqlx::query!(
            r#"SELECT value as "value!: String" FROM settings WHERE key = 'preferred_camera'"#
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.value).unwrap_or_default())
    }

    /// Persist the preferred camera device path ("" = automatic).
    pub async fn set_preferred_camera(&self, path: &str) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO settings (key, value) VALUES ('preferred_camera', ?1)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            path
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- our own presence (XEP-0107-ish): availability `<show>` + `<status>` message ----

    /// Our last chosen presence: `(show, status)`. `show` is the RFC 6121 value ("" = online/
    /// available, else "chat"/"away"/"xa"/"dnd"); `status` is the free-text message. Restored
    /// and re-sent on connect.
    pub async fn own_presence(&self) -> Result<(String, String)> {
        let show = sqlx::query!(
            r#"SELECT value as "value!: String" FROM settings WHERE key = 'presence_show'"#
        )
        .fetch_optional(self.pool())
        .await?
        .map(|r| r.value)
        .unwrap_or_default();
        let status = sqlx::query!(
            r#"SELECT value as "value!: String" FROM settings WHERE key = 'presence_status'"#
        )
        .fetch_optional(self.pool())
        .await?
        .map(|r| r.value)
        .unwrap_or_default();
        Ok((show, status))
    }

    /// Persist our chosen presence (`show` "" = online).
    pub async fn set_own_presence(&self, show: &str, status: &str) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO settings (key, value) VALUES ('presence_show', ?1)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            show
        )
        .execute(self.pool())
        .await?;
        sqlx::query!(
            r#"INSERT INTO settings (key, value) VALUES ('presence_status', ?1)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            status
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- presence subscription pre-approval (RFC 6121 §3.4, mirrors Android's
    //      Contact.Options.PREEMPTIVE_GRANT) ---------------------------------------------

    /// Remember that we want to grant `jid` our presence: when their `subscribe` arrives (now
    /// or later) it's auto-approved, instead of a bare `subscribed` being a server no-op.
    pub async fn set_presence_preapproval(&self, account_id: i64, jid: &str) -> Result<()> {
        let key = format!("preapprove:{account_id}:{jid}");
        sqlx::query!(
            r#"INSERT INTO settings (key, value) VALUES (?1, '1')
               ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
            key
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Consume a pending pre-approval for `jid` (returns whether one existed, and clears it).
    pub async fn take_presence_preapproval(&self, account_id: i64, jid: &str) -> Result<bool> {
        let key = format!("preapprove:{account_id}:{jid}");
        let res = sqlx::query!("DELETE FROM settings WHERE key = ?1", key)
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Drop any pre-approval for `jid` (e.g. when revoking presence).
    pub async fn clear_presence_preapproval(&self, account_id: i64, jid: &str) -> Result<()> {
        let key = format!("preapprove:{account_id}:{jid}");
        sqlx::query!("DELETE FROM settings WHERE key = ?1", key)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}
