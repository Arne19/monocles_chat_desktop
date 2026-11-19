//! Disappearing messages: the per-chat timer, the per-message timer and expiry.
//!
//! The model is monocles Android's. A chat has a timer setting (seconds, 0 = off). Every
//! message carries the timer its sender stamped on it; the countdown starts when the message
//! is sent (ours) or read (theirs), and when it runs out the message is deleted here.

use crate::{Result, Store};

/// Selectable durations in seconds - the same list as monocles Android.
pub const DURATIONS: [i64; 10] = [30, 60, 300, 1800, 3600, 21600, 43200, 86400, 604800, 2592000];

/// Upper bound for a timer taken from the wire (one year); anything else is ignored.
pub const MAX_TIMER: i64 = 365 * 24 * 3600;

/// How long the ids of expired messages are remembered.
const REMEMBER_EXPIRED_SECS: i64 = 90 * 24 * 3600;

/// A message that expired and was deleted; what it held, for dropping cached media.
#[derive(Debug, Clone)]
pub struct Expired {
    pub account_id: i64,
    pub conversation_id: i64,
    pub message_id: i64,
    pub body: Option<String>,
    pub attachment: Option<String>,
}

/// A timer value from the wire, or `None` if it is not a usable one. 0 means "off".
pub fn sane_timer(value: i64) -> Option<i64> {
    (0..=MAX_TIMER).contains(&value).then_some(value)
}

impl Store {
    /// The chat's disappearing-message timer in seconds (0 = off).
    pub async fn conversation_ephemeral_timer(&self, conversation_id: i64) -> Result<i64> {
        let timer: Option<i64> =
            sqlx::query_scalar("SELECT ephemeral_timer FROM conversations WHERE id = ?1")
                .bind(conversation_id)
                .fetch_optional(self.pool())
                .await?;
        Ok(timer.unwrap_or(0))
    }

    /// [`Self::conversation_ephemeral_timer`] for the chat with `jid` (0 if there is none).
    pub async fn conversation_ephemeral_timer_by_jid(&self, account_id: i64, jid: &str) -> Result<i64> {
        let timer: Option<i64> = sqlx::query_scalar(
            "SELECT ephemeral_timer FROM conversations WHERE account_id = ?1 AND jid = ?2",
        )
        .bind(account_id)
        .bind(jid)
        .fetch_optional(self.pool())
        .await?;
        Ok(timer.unwrap_or(0))
    }

    /// A timer change that arrived from the network, as of `at` (unix seconds, from the stanza),
    /// with `now` the local clock. A change older than the last one applied is ignored - that is
    /// one met while paging back through history.
    ///
    /// `at` is somebody else's clock (the sender's or the server's), so it is never taken to lie
    /// in the future: a stamp ahead of ours would otherwise outrank every later change, the
    /// user's own included, and a contact could freeze our setting with a forged `<delay/>`. A
    /// future value already stored (written before this rule) counts as `now` for the same
    /// reason. Returns whether the timer value changed.
    pub async fn set_conversation_ephemeral_timer(
        &self,
        conversation_id: i64,
        seconds: i64,
        at: i64,
        now: i64,
    ) -> Result<bool> {
        let seconds = sane_timer(seconds).unwrap_or(0);
        let at = at.min(now);
        let before = self.conversation_ephemeral_timer(conversation_id).await?;
        let done = sqlx::query(
            r#"UPDATE conversations SET ephemeral_timer = ?2, ephemeral_changed_at = ?3
               WHERE id = ?1 AND MIN(ephemeral_changed_at, ?4) <= ?3"#,
        )
        .bind(conversation_id)
        .bind(seconds)
        .bind(at)
        .bind(now)
        .execute(self.pool())
        .await?;
        Ok(done.rows_affected() > 0 && before != seconds)
    }

    /// The user changed the chat's timer here, at `now`. Always applied: the user's own choice
    /// is never outranked by an earlier stamp. Returns whether the timer value changed.
    pub async fn set_conversation_ephemeral_timer_local(
        &self,
        conversation_id: i64,
        seconds: i64,
        now: i64,
    ) -> Result<bool> {
        let seconds = sane_timer(seconds).unwrap_or(0);
        let before = self.conversation_ephemeral_timer(conversation_id).await?;
        sqlx::query(
            "UPDATE conversations SET ephemeral_timer = ?2, ephemeral_changed_at = ?3 WHERE id = ?1",
        )
        .bind(conversation_id)
        .bind(seconds)
        .bind(now)
        .execute(self.pool())
        .await?;
        Ok(before != seconds)
    }

    /// Record the timer a message carries and, if its countdown already runs, when it ends.
    pub async fn set_message_ephemeral(&self, message_id: i64, timer: i64, expire_at: Option<i64>) -> Result<()> {
        sqlx::query("UPDATE messages SET ephemeral_timer = ?2, expire_at = ?3 WHERE id = ?1")
            .bind(message_id)
            .bind(timer)
            .bind(expire_at)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// [`Self::set_message_ephemeral`] for a message known by the id we sent it under.
    pub async fn set_message_ephemeral_by_origin(
        &self,
        conversation_id: i64,
        origin_id: &str,
        timer: i64,
        expire_at: Option<i64>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE messages SET ephemeral_timer = ?3, expire_at = ?4 WHERE conversation_id = ?1 AND origin_id = ?2",
        )
        .bind(conversation_id)
        .bind(origin_id)
        .bind(timer)
        .bind(expire_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// The chat was read: start the countdown of its incoming timed messages. Returns how many.
    pub async fn start_expiry_on_read(&self, conversation_id: i64, now: i64) -> Result<u64> {
        let done = sqlx::query(
            r#"UPDATE messages SET expire_at = ?2 + ephemeral_timer
               WHERE conversation_id = ?1 AND direction = 'in'
                 AND ephemeral_timer > 0 AND expire_at IS NULL"#,
        )
        .bind(conversation_id)
        .bind(now)
        .execute(self.pool())
        .await?;
        Ok(done.rows_affected())
    }

    /// When the next message is due, if any countdown is running.
    pub async fn next_expiry(&self) -> Result<Option<i64>> {
        let next: Option<Option<i64>> =
            sqlx::query_scalar("SELECT MIN(expire_at) FROM messages WHERE expire_at IS NOT NULL")
                .fetch_optional(self.pool())
                .await?;
        Ok(next.flatten())
    }

    /// Delete every message whose countdown has run out and return what they held. Their ids
    /// are remembered so that a second copy of the same message is not stored again.
    pub async fn take_expired(&self, now: i64) -> Result<Vec<Expired>> {
        // (id, conversation, account, body, attachment, origin id, stanza id, remote id)
        type Due = (i64, i64, i64, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>);
        let due: Vec<Due> = sqlx::query_as(
            r#"SELECT m.id, m.conversation_id, c.account_id, m.body, m.attachment,
                      m.origin_id, m.stanza_id, m.remote_id
               FROM messages m JOIN conversations c ON c.id = m.conversation_id
               WHERE m.expire_at IS NOT NULL AND m.expire_at <= ?1"#,
        )
        .bind(now)
        .fetch_all(self.pool())
        .await?;
        let mut expired = Vec::with_capacity(due.len());
        for (id, conversation_id, account_id, body, attachment, origin, stanza, remote) in due {
            for marker in [origin, stanza, remote].into_iter().flatten() {
                sqlx::query(
                    "INSERT OR REPLACE INTO expired_messages (conversation_id, marker, expired_at) VALUES (?1, ?2, ?3)",
                )
                .bind(conversation_id)
                .bind(marker)
                .bind(now)
                .execute(self.pool())
                .await?;
            }
            // reactions and message_versions go with the row (ON DELETE CASCADE)
            sqlx::query("DELETE FROM messages WHERE id = ?1").bind(id).execute(self.pool()).await?;
            expired.push(Expired { account_id, conversation_id, message_id: id, body, attachment });
        }
        sqlx::query("DELETE FROM expired_messages WHERE expired_at < ?1")
            .bind(now - REMEMBER_EXPIRED_SECS)
            .execute(self.pool())
            .await?;
        Ok(expired)
    }

    /// Whether a message with one of these ids already expired in this chat.
    pub async fn was_expired(&self, conversation_id: i64, markers: &[&str]) -> Result<bool> {
        for marker in markers {
            let hit: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM expired_messages WHERE conversation_id = ?1 AND marker = ?2 LIMIT 1",
            )
            .bind(conversation_id)
            .bind(marker)
            .fetch_optional(self.pool())
            .await?;
            if hit.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::sane_timer;
    use crate::{Direction, NewMessage, Store};

    fn msg(conv: i64, origin: &str, dir: Direction) -> NewMessage {
        NewMessage {
            conversation_id: conv,
            stanza_id: None,
            origin_id: Some(origin.into()),
            counterpart: "bob@example.org".into(),
            direction: dir,
            body: Some("hello".into()),
            encryption: "omemo2".into(),
            reply_to: None,
            omemo_fingerprint: None,
            attachment: None,
            occupant_id: None,
            timestamp: "2026-11-11T00:00:00Z".into(),
            thread: None,
            unstyled: false,
            ephemeral_timer: 0,
        }
    }

    #[test]
    fn only_usable_timers_are_taken_from_the_wire() {
        assert_eq!(sane_timer(0), Some(0));
        assert_eq!(sane_timer(3600), Some(3600));
        assert_eq!(sane_timer(-1), None);
        assert_eq!(sane_timer(i64::MAX), None);
    }

    #[tokio::test]
    async fn chat_timer_roundtrip() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let conv = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 0);
        assert!(store.set_conversation_ephemeral_timer(conv, 3600, 100, 10_000).await.unwrap());
        assert!(!store.set_conversation_ephemeral_timer(conv, 3600, 101, 10_000).await.unwrap(), "unchanged");
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 3600);
        assert_eq!(store.conversation_ephemeral_timer_by_jid(acc, "bob@example.org").await.unwrap(), 3600);
        assert_eq!(store.conversation_ephemeral_timer_by_jid(acc, "nobody@example.org").await.unwrap(), 0);
        assert!(store.set_conversation_ephemeral_timer(conv, -5, 102, 10_000).await.unwrap(), "nonsense turns it off");
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn an_older_change_does_not_override_a_newer_one() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let conv = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        assert!(store.set_conversation_ephemeral_timer(conv, 60, 2_000, 10_000).await.unwrap());
        // met later while paging back through the archive
        assert!(!store.set_conversation_ephemeral_timer(conv, 0, 1_000, 10_000).await.unwrap());
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 60);
        assert!(store.set_conversation_ephemeral_timer(conv, 0, 3_000, 10_000).await.unwrap());
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_future_stamp_does_not_freeze_the_timer() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let conv = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        // a change stamped far ahead of our clock (skew, or a forged <delay/>) counts as "now"
        assert!(store.set_conversation_ephemeral_timer(conv, 60, 9_999_999, 1_000).await.unwrap());
        // so a genuine later one still applies
        assert!(store.set_conversation_ephemeral_timer(conv, 0, 1_001, 1_001).await.unwrap());
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 0);
        // and an older one is still ignored
        assert!(!store.set_conversation_ephemeral_timer(conv, 300, 900, 1_002).await.unwrap());
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_future_stamp_stored_before_the_fix_is_healed() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let conv = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        sqlx::query("UPDATE conversations SET ephemeral_timer = 60, ephemeral_changed_at = 9999999 WHERE id = ?1")
            .bind(conv)
            .execute(store.pool())
            .await
            .unwrap();
        assert!(store.set_conversation_ephemeral_timer(conv, 0, 1_000, 1_000).await.unwrap());
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn the_users_own_change_always_applies() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let conv = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        assert!(store.set_conversation_ephemeral_timer(conv, 60, 5_000, 5_000).await.unwrap());
        // our clock behind the stamp of the last incoming change: the user still wins
        assert!(store.set_conversation_ephemeral_timer_local(conv, 0, 4_000).await.unwrap());
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 0);
        // the same value again: applied, reported as unchanged
        assert!(!store.set_conversation_ephemeral_timer_local(conv, 0, 4_001).await.unwrap());
        // a later incoming change is ordered after the local one
        assert!(store.set_conversation_ephemeral_timer(conv, 300, 4_002, 4_002).await.unwrap());
        assert_eq!(store.conversation_ephemeral_timer(conv).await.unwrap(), 300);
    }

    #[tokio::test]
    async fn incoming_counts_down_from_reading_and_outgoing_from_sending() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let conv = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        let theirs = store.insert_message(&msg(conv, "in-1", Direction::In)).await.unwrap().unwrap();
        let ours = store.insert_message(&msg(conv, "out-1", Direction::Out)).await.unwrap().unwrap();
        let plain = store.insert_message(&msg(conv, "in-2", Direction::In)).await.unwrap().unwrap();
        store.set_message_ephemeral(theirs, 60, None).await.unwrap();
        store.set_message_ephemeral(ours, 60, Some(1_060)).await.unwrap();

        // unread: only our own message has a running countdown
        assert_eq!(store.next_expiry().await.unwrap(), Some(1_060));
        assert!(store.take_expired(1_059).await.unwrap().is_empty());
        let gone = store.take_expired(1_060).await.unwrap();
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].message_id, ours);
        assert_eq!(gone[0].account_id, acc);
        assert_eq!(gone[0].body.as_deref(), Some("hello"));

        // reading starts theirs; the untimed message is never touched
        assert_eq!(store.start_expiry_on_read(conv, 2_000).await.unwrap(), 1);
        assert_eq!(store.start_expiry_on_read(conv, 5_000).await.unwrap(), 0, "starts once");
        assert_eq!(store.next_expiry().await.unwrap(), Some(2_060));
        assert_eq!(store.take_expired(2_060).await.unwrap().len(), 1);
        assert_eq!(store.next_expiry().await.unwrap(), None);
        assert!(store.message_by_marker(conv, "in-2").await.unwrap().is_some());
        let _ = plain;
    }

    #[tokio::test]
    async fn an_expired_message_does_not_come_back() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let conv = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        let id = store.insert_message(&msg(conv, "in-1", Direction::In)).await.unwrap().unwrap();
        store.set_message_ephemeral(id, 60, Some(100)).await.unwrap();
        store.take_expired(100).await.unwrap();
        assert!(store.was_expired(conv, &["in-1"]).await.unwrap());
        assert!(!store.was_expired(conv, &["other"]).await.unwrap());
        // the same message delivered again (archive, carbon) is not stored
        assert!(store.insert_message(&msg(conv, "in-1", Direction::In)).await.unwrap().is_none());
        // a different one is
        assert!(store.insert_message(&msg(conv, "in-2", Direction::In)).await.unwrap().is_some());
    }
}
