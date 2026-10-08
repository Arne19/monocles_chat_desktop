//! Social-feed posts (XEP-0472 microblog), cached per account and author.

use crate::{Result, Store};

#[derive(Debug, Clone, Default, PartialEq, sqlx::FromRow)]
pub struct FeedPostRow {
    /// Author bare JID.
    pub author: String,
    pub id: String,
    pub title: String,
    pub content: String,
    /// Unix seconds.
    pub published: i64,
    pub link: String,
    pub attachment_url: String,
    pub attachment_type: String,
    pub comments_jid: String,
    pub comments_node: String,
}

fn upsert_query(account_id: i64, post: &FeedPostRow) -> sqlx::query::Query<'_, sqlx::Sqlite, sqlx::sqlite::SqliteArguments> {
    sqlx::query(
        r#"INSERT OR REPLACE INTO feed_posts (account_id, author, id, title, content, published,
             link, attachment_url, attachment_type, comments_jid, comments_node)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
    )
    .bind(account_id)
    .bind(&post.author)
    .bind(&post.id)
    .bind(&post.title)
    .bind(&post.content)
    .bind(post.published)
    .bind(&post.link)
    .bind(&post.attachment_url)
    .bind(&post.attachment_type)
    .bind(&post.comments_jid)
    .bind(&post.comments_node)
}

impl Store {
    /// Add or replace (an edit of) one post. Keyed by (author, id): an author can only replace
    /// their own posts.
    pub async fn upsert_feed_post(&self, account_id: i64, post: &FeedPostRow) -> Result<()> {
        upsert_query(account_id, post).execute(self.pool()).await?;
        Ok(())
    }

    /// Replace everything cached of `author` with `posts` (a fresh listing of their feed): posts
    /// deleted while we missed the retraction disappear too.
    pub async fn replace_feed(&self, account_id: i64, author: &str, posts: &[FeedPostRow]) -> Result<()> {
        let mut tx = self.pool().begin().await?;
        sqlx::query("DELETE FROM feed_posts WHERE account_id = ?1 AND author = ?2")
            .bind(account_id)
            .bind(author)
            .execute(&mut *tx)
            .await?;
        for post in posts.iter().filter(|p| p.author.eq_ignore_ascii_case(author)) {
            upsert_query(account_id, post).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Remove `author`'s post `id` (a retraction is only valid from the post's author).
    pub async fn delete_feed_post(&self, account_id: i64, author: &str, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM feed_posts WHERE account_id = ?1 AND author = ?2 AND id = ?3")
            .bind(account_id)
            .bind(author)
            .bind(id)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// All cached posts of the account, newest first.
    pub async fn feed_posts(&self, account_id: i64) -> Result<Vec<FeedPostRow>> {
        Ok(sqlx::query_as::<_, FeedPostRow>(
            r#"SELECT author, id, title, content, published, link, attachment_url, attachment_type,
                      comments_jid, comments_node
               FROM feed_posts WHERE account_id = ?1 ORDER BY published DESC"#,
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::FeedPostRow;
    use crate::Store;

    fn post(author: &str, id: &str, title: &str) -> FeedPostRow {
        FeedPostRow { author: author.into(), id: id.into(), title: title.into(), published: 1, ..Default::default() }
    }

    #[tokio::test]
    async fn posts_are_keyed_by_author_and_id() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        store.upsert_feed_post(acc, &post("alice@a.org", "hello", "A")).await.unwrap();
        // Same id by someone else is a different post; it can't replace or delete Alice's.
        store.upsert_feed_post(acc, &post("bob@b.org", "hello", "B")).await.unwrap();
        store.delete_feed_post(acc, "bob@b.org", "hello").await.unwrap();
        let rows = store.feed_posts(acc).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, "A");
        // An edit by Alice replaces it.
        store.upsert_feed_post(acc, &post("Alice@a.org", "hello", "A2")).await.unwrap();
        assert_eq!(store.feed_posts(acc).await.unwrap()[0].title, "A2");
        // A fresh listing replaces all of her posts, and only hers.
        store.upsert_feed_post(acc, &post("bob@b.org", "x", "B")).await.unwrap();
        store.replace_feed(acc, "alice@a.org", &[post("alice@a.org", "new", "N")]).await.unwrap();
        let mut ids: Vec<String> = store.feed_posts(acc).await.unwrap().into_iter().map(|r| r.id).collect();
        ids.sort();
        assert_eq!(ids, vec!["new", "x"]);
    }
}
