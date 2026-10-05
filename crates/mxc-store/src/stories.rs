//! Social-feed Stories: ephemeral 24h media posts from contacts, cached locally.

use crate::{Result, Store};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoryRow {
    pub uuid: String,
    /// Publisher bare JID.
    pub contact: String,
    pub url: String,
    pub r#type: String,
    pub title: Option<String>,
    /// Unix seconds.
    pub published: i64,
}

/// 24 hours, matching the server-side `pubsub#item_expire`.
const STORY_TTL_SECS: i64 = 86_400;

impl Store {
    /// Upsert a story (dedup on its uuid). Story ids are chosen by the publisher and the table
    /// is keyed by them alone, so an existing row is only updated by the same publisher on the
    /// same account - otherwise anyone could reuse a contact's story id to replace its media
    /// while it still shows as that contact's story.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_story(
        &self,
        account_id: i64,
        uuid: &str,
        contact: &str,
        url: &str,
        type_: &str,
        title: Option<&str>,
        published: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO stories (uuid, account_id, contact, url, type, title, published)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
               ON CONFLICT(uuid) DO UPDATE SET
                 url = excluded.url, type = excluded.type, title = excluded.title,
                 published = excluded.published
               WHERE stories.account_id = excluded.account_id
                 AND stories.contact = excluded.contact COLLATE NOCASE"#,
        )
        .bind(uuid)
        .bind(account_id)
        .bind(contact)
        .bind(url)
        .bind(type_)
        .bind(title)
        .bind(published)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// All non-expired stories, newest first.
    pub async fn recent_stories(&self, account_id: i64, now: i64) -> Result<Vec<StoryRow>> {
        let cutoff = now - STORY_TTL_SECS;
        let rows = sqlx::query_as::<_, StoryRow>(
            r#"SELECT uuid, contact, url, type, title, published
               FROM stories WHERE account_id = ?1 AND published >= ?2
               ORDER BY published DESC"#,
        )
        .bind(account_id)
        .bind(cutoff)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Drop expired stories (older than 24h).
    pub async fn expire_stories(&self, now: i64) -> Result<()> {
        let cutoff = now - STORY_TTL_SECS;
        sqlx::query!("DELETE FROM stories WHERE published < ?1", cutoff)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Remove one story (e.g. on retract) - only if `contact` (bare JID) published it on this
    /// account: a retraction is only valid from the story's own publisher.
    pub async fn delete_story(&self, account_id: i64, contact: &str, uuid: &str) -> Result<()> {
        sqlx::query("DELETE FROM stories WHERE uuid = ?1 AND account_id = ?2 AND contact = ?3 COLLATE NOCASE")
            .bind(uuid)
            .bind(account_id)
            .bind(contact)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Store;

    #[tokio::test]
    async fn stories_are_owned_by_their_publisher() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let now = 1_000_000;
        store.upsert_story(acc, "s1", "alice@example.org", "https://a/1", "image/jpeg", None, now).await.unwrap();
        // Mallory reuses Alice's story id: neither replaced nor deleted.
        store.upsert_story(acc, "s1", "mallory@evil.org", "https://evil/x", "image/jpeg", None, now).await.unwrap();
        store.delete_story(acc, "mallory@evil.org", "s1").await.unwrap();
        let rows = store.recent_stories(acc, now).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].contact, "alice@example.org");
        assert_eq!(rows[0].url, "https://a/1");
        // Alice herself can update and retract it.
        store.upsert_story(acc, "s1", "alice@example.org", "https://a/2", "image/jpeg", None, now).await.unwrap();
        assert_eq!(store.recent_stories(acc, now).await.unwrap()[0].url, "https://a/2");
        store.delete_story(acc, "alice@example.org", "s1").await.unwrap();
        assert!(store.recent_stories(acc, now).await.unwrap().is_empty());
    }
}
