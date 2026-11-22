//! Live locations shared from monocles Android (`urn:xmpp:live-location:0`): which `geo:`
//! message is a live share, its newest position and whether it still runs. Like everything in
//! the store, encrypted at rest (SQLCipher).

use std::collections::HashMap;

use crate::{Result, Store};

/// The state of one live share, by its starting message.
#[derive(Debug, Clone, PartialEq)]
pub struct LiveLocation {
    /// Unix seconds when the share ends on its own.
    pub expires: i64,
    /// The newest position, once an update came.
    pub last: Option<(f64, f64)>,
    /// The sender ended it.
    pub stopped: bool,
}

impl LiveLocation {
    /// Still running at `now` (unix seconds).
    pub fn active(&self, now: i64) -> bool {
        !self.stopped && now < self.expires
    }
}

impl Store {
    /// Records that `message_id` starts live session `session_id` of `sender` (bare JID),
    /// running until `expires`. A session id the conversation already knows is refused: the
    /// first message owns it.
    pub async fn start_live_location(
        &self,
        message_id: i64,
        conversation_id: i64,
        session_id: &str,
        sender: &str,
        expires: i64,
    ) -> Result<bool> {
        let done = sqlx::query(
            r#"INSERT INTO live_locations (message_id, conversation_id, session_id, sender, expires)
               SELECT ?1, ?2, ?3, ?4, ?5
               WHERE NOT EXISTS (SELECT 1 FROM live_locations
                                 WHERE conversation_id = ?2 AND session_id = ?3)
               ON CONFLICT(message_id) DO NOTHING"#,
        )
        .bind(message_id)
        .bind(conversation_id)
        .bind(session_id)
        .bind(sender.to_ascii_lowercase())
        .bind(expires)
        .execute(self.pool())
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Moves session `session_id` of `sender` in `conversation_id` to `lat`/`lon`, if it is
    /// still running at `now`. Returns its message. Anyone else's update changes nothing.
    pub async fn update_live_location(
        &self,
        conversation_id: i64,
        session_id: &str,
        sender: &str,
        lat: f64,
        lon: f64,
        now: i64,
    ) -> Result<Option<i64>> {
        Ok(sqlx::query_scalar::<_, i64>(
            r#"UPDATE live_locations SET last_lat = ?4, last_lon = ?5
               WHERE conversation_id = ?1 AND session_id = ?2 AND sender = ?3
                     AND stopped = 0 AND expires > ?6
               RETURNING message_id"#,
        )
        .bind(conversation_id)
        .bind(session_id)
        .bind(sender.to_ascii_lowercase())
        .bind(lat)
        .bind(lon)
        .bind(now)
        .fetch_optional(self.pool())
        .await?)
    }

    /// Ends session `session_id` of `sender` in `conversation_id`. Returns its message.
    pub async fn stop_live_location(
        &self,
        conversation_id: i64,
        session_id: &str,
        sender: &str,
    ) -> Result<Option<i64>> {
        Ok(sqlx::query_scalar::<_, i64>(
            r#"UPDATE live_locations SET stopped = 1
               WHERE conversation_id = ?1 AND session_id = ?2 AND sender = ?3 AND stopped = 0
               RETURNING message_id"#,
        )
        .bind(conversation_id)
        .bind(session_id)
        .bind(sender.to_ascii_lowercase())
        .fetch_optional(self.pool())
        .await?)
    }

    /// The live shares of a conversation, by their starting message.
    pub async fn live_locations(&self, conversation_id: i64) -> Result<HashMap<i64, LiveLocation>> {
        let rows = sqlx::query_as::<_, (i64, i64, Option<f64>, Option<f64>, bool)>(
            r#"SELECT message_id, expires, last_lat, last_lon, stopped
               FROM live_locations WHERE conversation_id = ?1"#,
        )
        .bind(conversation_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, expires, lat, lon, stopped)| {
                let last = lat.zip(lon);
                (id, LiveLocation { expires, last, stopped })
            })
            .collect())
    }

    pub(crate) async fn drop_live_location(&self, message_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM live_locations WHERE message_id = ?1")
            .bind(message_id)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Direction, NewMessage, Store};

    fn msg(conv: i64, origin: &str) -> NewMessage {
        NewMessage {
            conversation_id: conv,
            stanza_id: None,
            origin_id: Some(origin.into()),
            counterpart: "bob@example.org".into(),
            direction: Direction::In,
            body: Some("geo:52.52,13.405".into()),
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
        let (store, _, conv, mid) = setup_with_account().await;
        (store, conv, mid)
    }

    async fn setup_with_account() -> (Store, i64, i64, i64) {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let conv = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        let mid = store.insert_message(&msg(conv, "a")).await.unwrap().unwrap();
        assert!(store.start_live_location(mid, conv, "s1", "Bob@Example.org", 1000).await.unwrap());
        (store, acc, conv, mid)
    }

    #[tokio::test]
    async fn only_the_sender_moves_and_ends_a_share() {
        let (store, conv, mid) = setup().await;
        let live = &store.live_locations(conv).await.unwrap()[&mid];
        assert!(live.active(999) && !live.active(1000));
        assert_eq!(live.last, None);
        // someone else, another session, another conversation: nothing happens
        assert_eq!(store.update_live_location(conv, "s1", "eve@example.org", 1.0, 2.0, 10).await.unwrap(), None);
        assert_eq!(store.update_live_location(conv, "s2", "bob@example.org", 1.0, 2.0, 10).await.unwrap(), None);
        assert_eq!(store.update_live_location(conv + 1, "s1", "bob@example.org", 1.0, 2.0, 10).await.unwrap(), None);
        assert_eq!(store.stop_live_location(conv, "s1", "eve@example.org").await.unwrap(), None);
        // the sender (any case)
        assert_eq!(store.update_live_location(conv, "s1", "BOB@example.org", 1.0, 2.0, 10).await.unwrap(), Some(mid));
        assert_eq!(store.live_locations(conv).await.unwrap()[&mid].last, Some((1.0, 2.0)));
        // no update after the expiry
        assert_eq!(store.update_live_location(conv, "s1", "bob@example.org", 3.0, 4.0, 1000).await.unwrap(), None);
        assert_eq!(store.stop_live_location(conv, "s1", "bob@example.org").await.unwrap(), Some(mid));
        assert!(store.live_locations(conv).await.unwrap()[&mid].stopped);
        // stopped: no more updates, no second stop
        assert_eq!(store.update_live_location(conv, "s1", "bob@example.org", 3.0, 4.0, 20).await.unwrap(), None);
        assert_eq!(store.stop_live_location(conv, "s1", "bob@example.org").await.unwrap(), None);
    }

    #[tokio::test]
    async fn the_first_message_owns_a_session() {
        let (store, conv, _) = setup().await;
        let other = store.insert_message(&msg(conv, "b")).await.unwrap().unwrap();
        assert!(!store.start_live_location(other, conv, "s1", "bob@example.org", 5000).await.unwrap());
    }

    #[tokio::test]
    async fn a_share_goes_with_its_message() {
        let (store, conv, mid) = setup().await;
        store.retract_message_id(mid).await.unwrap();
        assert!(store.live_locations(conv).await.unwrap().is_empty());
        let (store, conv, mid) = setup().await;
        store.moderate_message_id(mid, None).await.unwrap();
        assert!(store.live_locations(conv).await.unwrap().is_empty());
        let (store, acc, conv, _) = setup_with_account().await;
        store.delete_conversation(acc, "bob@example.org").await.unwrap();
        assert!(store.live_locations(conv).await.unwrap().is_empty());
    }
}
