//! Pinned messages: local only, as on monocles Android (nothing goes over the wire).
//!
//! A pin references the message row and holds no copy of its content, so the pin bar always
//! shows the message as it is now, and a pin cannot outlive its message: when the row goes
//! (expired, conversation removed, history cleared) the pin goes with it (`ON DELETE CASCADE`),
//! and a retraction or moderation, which keep a tombstone row, drop it explicitly.

use crate::messages::MessageRow;
use crate::{Result, Store};

impl Store {
    /// Pin `message_id` of `conversation_id` as of `at` (unix seconds). Pinning it again only
    /// brings it to the front. Refused (`false`) for a message of another conversation, a
    /// retracted one, or one whose disappearing-message time is up.
    pub async fn pin_message(&self, conversation_id: i64, message_id: i64, at: i64) -> Result<bool> {
        let done = sqlx::query(
            r#"INSERT INTO pinned_messages (message_id, conversation_id, pinned_at)
               SELECT id, conversation_id, ?3 FROM messages
               WHERE id = ?1 AND conversation_id = ?2 AND retracted = 0
                     AND (expire_at IS NULL OR expire_at > ?3)
               ON CONFLICT(message_id) DO UPDATE SET pinned_at = excluded.pinned_at"#,
        )
        .bind(message_id)
        .bind(conversation_id)
        .bind(at)
        .execute(self.pool())
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Remove the pin of `message_id`, if it has one. Returns whether there was one.
    pub async fn unpin_message(&self, message_id: i64) -> Result<bool> {
        self.drop_pin(message_id).await
    }

    pub(crate) async fn drop_pin(&self, message_id: i64) -> Result<bool> {
        let done = sqlx::query("DELETE FROM pinned_messages WHERE message_id = ?1")
            .bind(message_id)
            .execute(self.pool())
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// The pinned messages of a conversation, the most recently pinned first, as they are now.
    /// A message whose disappearing-message time is up is left out already, before the expiry
    /// tick deletes it (and its pin with it).
    pub async fn pinned_messages(&self, conversation_id: i64, now: i64) -> Result<Vec<MessageRow>> {
        Ok(sqlx::query_as::<_, MessageRow>(
            r#"SELECT m.id, m.conversation_id, m.stanza_id, m.origin_id, m.counterpart, m.direction,
                      m.body, m.encryption, m.state, m.edited_of, m.retracted, m.attachment,
                      m.reply_to, m.omemo_fingerprint, m.timestamp, m.thread, m.moderated,
                      m.moderation_reason, m.unstyled
               FROM pinned_messages p JOIN messages m ON m.id = p.message_id
               WHERE p.conversation_id = ?1 AND m.retracted = 0
                     AND (m.expire_at IS NULL OR m.expire_at > ?2)
               ORDER BY p.pinned_at DESC, p.rowid DESC"#,
        )
        .bind(conversation_id)
        .bind(now)
        .fetch_all(self.pool())
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Direction, NewMessage, Store};

    fn msg(conv: i64, origin: &str, body: &str) -> NewMessage {
        NewMessage {
            conversation_id: conv,
            stanza_id: None,
            origin_id: Some(origin.into()),
            counterpart: "bob@example.org".into(),
            direction: Direction::Out,
            body: Some(body.into()),
            encryption: "omemo2".into(),
            reply_to: None,
            omemo_fingerprint: None,
            attachment: None,
            occupant_id: None,
            timestamp: "2026-11-18T00:00:00Z".into(),
            thread: None,
            unstyled: false,
            ephemeral_timer: 0,
        }
    }

    async fn setup() -> (Store, i64, i64) {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let conv = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        (store, acc, conv)
    }

    fn bodies(rows: &[crate::messages::MessageRow]) -> Vec<String> {
        rows.iter().map(|r| r.body.clone().unwrap_or_default()).collect()
    }

    #[tokio::test]
    async fn pin_list_unpin_newest_first() {
        let (store, _, conv) = setup().await;
        let a = store.insert_message(&msg(conv, "a", "first")).await.unwrap().unwrap();
        let b = store.insert_message(&msg(conv, "b", "second")).await.unwrap().unwrap();
        assert!(store.pin_message(conv, a, 100).await.unwrap());
        assert!(store.pin_message(conv, b, 200).await.unwrap());
        assert_eq!(bodies(&store.pinned_messages(conv, 300).await.unwrap()), ["second", "first"]);
        // pinning again brings it to the front
        assert!(store.pin_message(conv, a, 400).await.unwrap());
        assert_eq!(bodies(&store.pinned_messages(conv, 500).await.unwrap()), ["first", "second"]);
        assert!(store.unpin_message(a).await.unwrap());
        assert!(!store.unpin_message(a).await.unwrap(), "only once");
        assert_eq!(bodies(&store.pinned_messages(conv, 500).await.unwrap()), ["second"]);
    }

    #[tokio::test]
    async fn a_pin_shows_the_message_as_it_is_now() {
        let (store, _, conv) = setup().await;
        let a = store.insert_message(&msg(conv, "a", "typo")).await.unwrap().unwrap();
        store.pin_message(conv, a, 100).await.unwrap();
        store.correct_message(a, "a", "fixed", "omemo2", None).await.unwrap();
        assert_eq!(bodies(&store.pinned_messages(conv, 200).await.unwrap()), ["fixed"]);
    }

    #[tokio::test]
    async fn a_retracted_message_loses_its_pin() {
        let (store, _, conv) = setup().await;
        let a = store.insert_message(&msg(conv, "a", "oops")).await.unwrap().unwrap();
        store.pin_message(conv, a, 100).await.unwrap();
        assert!(store.retract_message(conv, "a").await.unwrap().is_some());
        assert!(store.pinned_messages(conv, 200).await.unwrap().is_empty());
        assert!(!store.unpin_message(a).await.unwrap(), "the pin row itself is gone");
        assert!(!store.pin_message(conv, a, 300).await.unwrap(), "a tombstone cannot be pinned");
    }

    #[tokio::test]
    async fn a_disappearing_message_takes_its_pin_along() {
        let (store, _, conv) = setup().await;
        let a = store.insert_message(&msg(conv, "a", "soon gone")).await.unwrap().unwrap();
        store.set_message_ephemeral(a, 60, Some(1_060)).await.unwrap();
        store.pin_message(conv, a, 1_000).await.unwrap();
        assert_eq!(store.pinned_messages(conv, 1_059).await.unwrap().len(), 1);
        // time is up: hidden at once, before the expiry tick deletes the row
        assert!(store.pinned_messages(conv, 1_060).await.unwrap().is_empty());
        store.take_expired(1_060).await.unwrap();
        assert!(!store.unpin_message(a).await.unwrap(), "deleted with the message");
        assert!(!store.pin_message(conv, a, 900).await.unwrap(), "the message is gone");
    }

    #[tokio::test]
    async fn an_expired_message_cannot_be_pinned() {
        let (store, _, conv) = setup().await;
        let a = store.insert_message(&msg(conv, "a", "gone")).await.unwrap().unwrap();
        store.set_message_ephemeral(a, 60, Some(1_060)).await.unwrap();
        assert!(!store.pin_message(conv, a, 1_060).await.unwrap());
    }

    #[tokio::test]
    async fn removing_the_conversation_removes_its_pins() {
        let (store, acc, conv) = setup().await;
        let a = store.insert_message(&msg(conv, "a", "hello")).await.unwrap().unwrap();
        store.pin_message(conv, a, 100).await.unwrap();
        store.delete_conversation(acc, "bob@example.org").await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pinned_messages")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn only_a_message_of_the_conversation_can_be_pinned_there() {
        let (store, acc, conv) = setup().await;
        let other = store.conversation_id(acc, "carol@example.org", "chat").await.unwrap();
        let a = store.insert_message(&msg(other, "a", "elsewhere")).await.unwrap().unwrap();
        assert!(!store.pin_message(conv, a, 100).await.unwrap());
        assert!(store.pinned_messages(conv, 200).await.unwrap().is_empty());
    }
}
