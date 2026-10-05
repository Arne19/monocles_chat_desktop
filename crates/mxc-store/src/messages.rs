//! Conversations + message rows.

use crate::{Result, Store};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MessageRow {
    pub id: i64,
    pub conversation_id: i64,
    pub stanza_id: Option<String>,
    pub origin_id: Option<String>,
    pub counterpart: String,
    pub direction: String,
    pub body: Option<String>,
    pub encryption: String,
    pub state: String,
    pub edited_of: Option<String>,
    pub retracted: bool,
    pub attachment: Option<String>,
    pub reply_to: Option<String>,
    pub omemo_fingerprint: Option<String>,
    pub timestamp: String,
    /// XEP-7397 thread id — set for WebXDC `.xdc` app messages (the instance key).
    pub thread: Option<String>,
}

/// One full-text search hit: a message joined with its conversation, for the chats-list
/// message search. Columns are aliased in `search_messages` to match these field names.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MessageSearchRow {
    pub message_id: i64,
    pub conversation_id: i64,
    pub conv_jid: String,
    pub conv_kind: String,
    pub conv_name: Option<String>,
    pub conv_encryption: String,
    /// The id others reference (origin id, else stanza id) — the jump-to target.
    pub marker: Option<String>,
    pub body: Option<String>,
    pub direction: String,
    pub counterpart: String,
    pub timestamp: String,
}

/// An outgoing message queued while offline, to be sent by the outbox on reconnect.
#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub origin_id: String,
    /// Recipient (bare JID for 1:1, full occupant JID for a MUC private message).
    pub to: String,
    pub body: String,
    pub encryption: String,
    pub reply_to: Option<String>,
}

/// A message about to be persisted.
#[derive(Debug, Clone)]
pub struct NewMessage {
    pub conversation_id: i64,
    pub stanza_id: Option<String>,
    pub origin_id: Option<String>,
    pub counterpart: String,
    pub direction: Direction,
    pub body: Option<String>,
    pub encryption: String,
    pub reply_to: Option<String>,
    pub omemo_fingerprint: Option<String>,
    /// XEP-0066/0363 attachment metadata (JSON: `{"url":…,"mime":…}`). Set for file messages
    /// that carry a caption — the caption lives in `body`, the file URL here — so the file is
    /// rendered separately from the caption text. `None` for plain text / caption-less files.
    pub attachment: Option<String>,
    /// XEP-0421 occupant id (MUC messages only), for reaction attribution.
    pub occupant_id: Option<String>,
    /// RFC3339 / `datetime('now')`-compatible timestamp (delay-corrected).
    pub timestamp: String,
    /// XEP-7397 thread id — set for WebXDC `.xdc` app messages (the instance key).
    pub thread: Option<String>,
}

impl Store {
    /// Find or create a conversation row for (account, jid).
    pub async fn conversation_id(
        &self,
        account_id: i64,
        jid: &str,
        kind: &str,
    ) -> Result<i64> {
        // PQ OMEMO2 is on by default for new 1:1 chats; MUCs start plaintext (group OMEMO
        // would need per-member device lists, not yet wired). Existing rows keep their
        // mode (the ON CONFLICT clause is a no-op update).
        // Group chats + MUC private messages aren't OMEMO-encrypted to a real JID; 1:1 is.
        let default_encryption = if kind == "chat" { "omemo2" } else { "none" };
        // Group chats default to mentions-only; 1:1 chats and MUC PMs notify for all.
        let default_notify = if kind == "muc" { "mentioned" } else { "all" };
        let rec = sqlx::query!(
            r#"
            INSERT INTO conversations (account_id, jid, kind, encryption, notify) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(account_id, jid) DO UPDATE SET jid = jid
            RETURNING id as "id!: i64"
            "#,
            account_id,
            jid,
            kind,
            default_encryption,
            default_notify
        )
        .fetch_one(self.pool())
        .await?;
        Ok(rec.id)
    }

    /// Insert a message, deduplicating on (stanza_id|origin_id) within the conversation.
    /// Returns the row id, or `None` if it was a duplicate that we skipped.
    pub async fn insert_message(&self, msg: &NewMessage) -> Result<Option<i64>> {
        // Serialize the dedup-check + insert so two concurrent deliveries of the same message
        // (e.g. live groupchat + MAM catch-up) can't both miss the dedup and double-insert.
        let _guard = self.insert_lock.lock().await;
        // Dedup: a matching origin-id or stanza-id in the same conversation means we've
        // already stored this (e.g. carbon + MAM, or our own echo).
        if msg.stanza_id.is_some() || msg.origin_id.is_some() {
            let existing = sqlx::query!(
                r#"SELECT id as "id!: i64" FROM messages
                   WHERE conversation_id = ?1
                     AND ((stanza_id IS NOT NULL AND stanza_id = ?2)
                       OR (origin_id IS NOT NULL AND origin_id = ?3))
                   LIMIT 1"#,
                msg.conversation_id,
                msg.stanza_id,
                msg.origin_id,
            )
            .fetch_optional(self.pool())
            .await?;
            if let Some(row) = existing {
                // Already stored (e.g. our own message now reflected by the MUC). Backfill any
                // ids we didn't have at first sight — crucially the room-assigned stanza-id and
                // our occupant-id — so reactions, which reference the stanza-id, can match it.
                sqlx::query!(
                    r#"UPDATE messages
                       SET stanza_id = COALESCE(stanza_id, ?2),
                           occupant_id = COALESCE(occupant_id, ?3)
                       WHERE id = ?1"#,
                    row.id,
                    msg.stanza_id,
                    msg.occupant_id,
                )
                .execute(self.pool())
                .await?;
                return Ok(None);
            }
        }

        let dir = msg.direction.as_str();
        let rec = sqlx::query!(
            r#"
            INSERT INTO messages
              (conversation_id, stanza_id, origin_id, counterpart, direction, body,
               encryption, reply_to, omemo_fingerprint, occupant_id, timestamp, thread)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            RETURNING id as "id!: i64"
            "#,
            msg.conversation_id,
            msg.stanza_id,
            msg.origin_id,
            msg.counterpart,
            dir,
            msg.body,
            msg.encryption,
            msg.reply_to,
            msg.omemo_fingerprint,
            msg.occupant_id,
            msg.timestamp,
            msg.thread,
        )
        .fetch_one(self.pool())
        .await?;

        sqlx::query!(
            "UPDATE conversations SET last_active = ?1 WHERE id = ?2",
            msg.timestamp,
            msg.conversation_id
        )
        .execute(self.pool())
        .await?;

        Ok(Some(rec.id))
    }

    /// Newest-last page of messages for a conversation.
    pub async fn recent_messages(
        &self,
        conversation_id: i64,
        limit: i64,
    ) -> Result<Vec<MessageRow>> {
        let mut rows = sqlx::query_as::<_, MessageRow>(
            r#"SELECT id, conversation_id, stanza_id, origin_id, counterpart, direction,
                      body, encryption, state, edited_of, retracted, attachment, reply_to,
                      omemo_fingerprint, timestamp, thread
               FROM messages WHERE conversation_id = ?1
               ORDER BY timestamp DESC, id DESC LIMIT ?2"#,
        )
        .bind(conversation_id)
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        rows.reverse();
        Ok(rows)
    }

    /// Full-text (substring) search over message bodies, newest first. Used by the chats-list
    /// message search. With `scope_jid` empty it spans all of the account's conversations; set
    /// to a conversation's JID it searches just that chat (the Signal-style scoped search). The
    /// query is a literal substring — `%`, `_` and `\` are escaped so they can't act as
    /// LIKE wildcards.
    pub async fn search_messages(
        &self,
        account_id: i64,
        query: &str,
        scope_jid: &str,
        limit: i64,
    ) -> Result<Vec<MessageSearchRow>> {
        let escaped = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        let rows = sqlx::query_as::<_, MessageSearchRow>(
            r#"SELECT m.id AS message_id, m.conversation_id AS conversation_id,
                      c.jid AS conv_jid, c.kind AS conv_kind, c.name AS conv_name,
                      c.encryption AS conv_encryption,
                      COALESCE(m.origin_id, m.stanza_id) AS marker,
                      m.body AS body, m.direction AS direction,
                      m.counterpart AS counterpart, m.timestamp AS timestamp
               FROM messages m
               JOIN conversations c ON c.id = m.conversation_id
               WHERE c.account_id = ?1 AND c.archived = 0 AND m.retracted = 0
                     AND m.body IS NOT NULL AND m.body LIKE ?2 ESCAPE '\'
                     AND (?4 = '' OR c.jid = ?4)
               ORDER BY m.timestamp DESC, m.id DESC
               LIMIT ?3"#,
        )
        .bind(account_id)
        .bind(pattern)
        .bind(limit)
        .bind(scope_jid)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// How many messages in `conversation_id` are at least as recent as `message_id`
    /// (the message itself plus everything newer). Lets the chat view load exactly enough
    /// recent history with `recent_messages` to include a given (possibly old) message.
    pub async fn count_since(&self, conversation_id: i64, message_id: i64) -> Result<i64> {
        let rec = sqlx::query!(
            r#"SELECT COUNT(*) AS "n!: i64"
               FROM messages m
               JOIN messages t ON t.id = ?2
               WHERE m.conversation_id = ?1
                     AND (m.timestamp > t.timestamp
                          OR (m.timestamp = t.timestamp AND m.id >= t.id))"#,
            conversation_id,
            message_id,
        )
        .fetch_one(self.pool())
        .await?;
        Ok(rec.n)
    }

    /// Backfill the room-assigned stanza-id (and occupant-id) onto an already-stored message,
    /// matched by its origin-id within the conversation. Used when our own encrypted MUC message
    /// is reflected by the room — we can't decrypt the echo, but still want its stanza-id so
    /// reactions to our own messages resolve. No-op if the row isn't found.
    pub async fn backfill_stanza_id(
        &self,
        conversation_id: i64,
        origin_id: &str,
        stanza_id: &str,
        occupant_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            r#"UPDATE messages
               SET stanza_id = COALESCE(stanza_id, ?3),
                   occupant_id = COALESCE(occupant_id, ?4)
               WHERE conversation_id = ?1 AND origin_id = ?2"#,
            conversation_id,
            origin_id,
            stanza_id,
            occupant_id,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Update delivery state by stanza/origin id (receipts XEP-0184, markers XEP-0333).
    pub async fn set_message_state(&self, marker_id: &str, state: &str) -> Result<()> {
        sqlx::query!(
            r#"UPDATE messages SET state = ?1
               WHERE stanza_id = ?2 OR origin_id = ?2"#,
            state,
            marker_id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Outgoing messages queued while offline (state = 'pending'), oldest first, for the outbox
    /// to flush on reconnect. Carries everything needed to rebuild + send the stanza.
    pub async fn pending_messages(&self, account_id: i64) -> Result<Vec<PendingMessage>> {
        let rows = sqlx::query!(
            r#"SELECT m.origin_id as "origin_id!: String",
                      m.counterpart as "to!: String",
                      m.body as "body!: String",
                      m.encryption as "encryption!: String",
                      m.reply_to as "reply_to: String"
               FROM messages m
               JOIN conversations c ON c.id = m.conversation_id
               WHERE c.account_id = ?1 AND m.direction = 'out' AND m.state = 'pending'
                     AND m.origin_id IS NOT NULL AND m.body IS NOT NULL
               ORDER BY m.id"#,
            account_id
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PendingMessage {
                origin_id: r.origin_id,
                to: r.to,
                body: r.body,
                encryption: r.encryption,
                reply_to: r.reply_to,
            })
            .collect())
    }

    /// Persist an outgoing message as `pending` (composed locally, not yet sent) and return the
    /// stored row. Used by the UI to render + queue a send without waiting on the network/core:
    /// the row shows immediately ("sending…") and the outbox flushes it on (re)connect. Keyed
    /// by `origin_id`, so a later core/echo insert with the same id dedups instead of duplicating.
    pub async fn queue_outgoing(
        &self,
        conversation_id: i64,
        to: &str,
        body: &str,
        encryption: &str,
        reply_to: Option<&str>,
        origin_id: &str,
        timestamp: &str,
    ) -> Result<Option<MessageRow>> {
        let msg = NewMessage {
            conversation_id,
            stanza_id: None,
            origin_id: Some(origin_id.to_string()),
            counterpart: to.to_string(),
            direction: Direction::Out,
            body: Some(body.to_string()),
            encryption: encryption.to_string(),
            reply_to: reply_to.map(str::to_string),
            omemo_fingerprint: None,
            attachment: None,
            occupant_id: None,
            timestamp: timestamp.to_string(),
            thread: None,
        };
        // Dedup-aware: if this id already exists (e.g. a retry), don't double-insert.
        if self.insert_message(&msg).await?.is_none() {
            return self.message_by_marker(conversation_id, origin_id).await;
        }
        self.set_message_state(origin_id, "pending").await?;
        self.message_by_marker(conversation_id, origin_id).await
    }

    /// Look up a stored message by either its origin-id or server stanza-id within a
    /// conversation. Used to target corrections/retractions/reactions.
    pub async fn message_by_marker(
        &self,
        conversation_id: i64,
        marker_id: &str,
    ) -> Result<Option<MessageRow>> {
        let row = sqlx::query_as::<_, MessageRow>(
            r#"SELECT id, conversation_id, stanza_id, origin_id, counterpart, direction,
                      body, encryption, state, edited_of, retracted, attachment, reply_to,
                      omemo_fingerprint, timestamp, thread
               FROM messages
               WHERE conversation_id = ?1 AND (origin_id = ?2 OR stanza_id = ?2)
               ORDER BY id DESC LIMIT 1"#,
        )
        .bind(conversation_id)
        .bind(marker_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    /// XEP-0308: replace the body of the message targeted by `target_marker`, recording
    /// the edit pointer. No sender check — only for edits *we* make locally; incoming
    /// corrections go through [`Self::find_from_sender`] + [`Self::correct_message`].
    /// Returns the edited row id if found.
    pub async fn apply_correction(
        &self,
        conversation_id: i64,
        target_marker: &str,
        new_body: &str,
    ) -> Result<Option<i64>> {
        let Some(orig) = self.message_by_marker(conversation_id, target_marker).await? else {
            return Ok(None);
        };
        sqlx::query!(
            r#"UPDATE messages SET body = ?1, edited_of = ?2 WHERE id = ?3"#,
            new_body,
            target_marker,
            orig.id,
        )
        .execute(self.pool())
        .await?;
        Ok(Some(orig.id))
    }

    /// XEP-0424: tombstone the targeted message — per spec the content AND its metadata go
    /// (body, attachment, correction/reply links, fingerprint, reactions); only a minimal
    /// stub row remains. Returns the message id and the body it had, so callers can also
    /// drop any media-cache file downloaded for it. No sender check — only for retractions
    /// *we* make locally; incoming ones go through [`Self::find_from_sender`] +
    /// [`Self::retract_message_id`].
    pub async fn retract_message(
        &self,
        conversation_id: i64,
        target_marker: &str,
    ) -> Result<Option<(i64, Option<String>)>> {
        let Some(orig) = self.message_by_marker(conversation_id, target_marker).await? else {
            return Ok(None);
        };
        sqlx::query!(
            r#"UPDATE messages SET retracted = 1, body = NULL, attachment = NULL,
               edited_of = NULL, reply_to = NULL, omemo_fingerprint = NULL WHERE id = ?1"#,
            orig.id,
        )
        .execute(self.pool())
        .await?;
        sqlx::query!("DELETE FROM reactions WHERE message_id = ?1", orig.id)
            .execute(self.pool())
            .await?;
        Ok(Some((orig.id, orig.body)))
    }

    /// The newest non-retracted message in `conversation_id` with marker `marker_id` that was
    /// sent by the same party as an incoming correction/retraction: same `direction`, and — when
    /// `occupant_id` is given (MUC) — the same XEP-0421 occupant id. This is the authorization
    /// for XEP-0308/0424: only the original sender may edit or retract a message (Conversations'
    /// `findMessageWithUuidOrRemoteId` filter).
    ///
    /// With `fingerprint = Some(fp)` (corrections), a message received under an OMEMO fingerprint
    /// additionally only matches an edit made under that *same* fingerprint (`fp` = `None` for a
    /// plaintext edit matches only unencrypted originals) — monocles Android's
    /// `fingerprintsMatch`: otherwise the peer's server could forge a plaintext correction that
    /// rewrites an encrypted message. Retractions use the same rule; only a XEP-0425 moderation
    /// (from the room itself, via [`Self::find_by_stanza_id`]) is exempt.
    pub async fn find_from_sender(
        &self,
        conversation_id: i64,
        marker_id: &str,
        direction: &str,
        occupant_id: Option<&str>,
        fingerprint: Option<Option<&str>>,
    ) -> Result<Option<i64>> {
        let (check_fp, fp) = match fingerprint {
            Some(fp) => (1i64, fp),
            None => (0i64, None),
        };
        let id: Option<i64> = sqlx::query_scalar(
            r#"SELECT id FROM messages
               WHERE conversation_id = ?1 AND (origin_id = ?2 OR stanza_id = ?2)
                     AND direction = ?3 AND (?4 IS NULL OR occupant_id = ?4)
                     AND retracted = 0
                     AND (?5 = 0 OR omemo_fingerprint IS NULL OR omemo_fingerprint = ?6)
               ORDER BY id DESC LIMIT 1"#,
        )
        .bind(conversation_id)
        .bind(marker_id)
        .bind(direction)
        .bind(occupant_id)
        .bind(check_fp)
        .bind(fp)
        .fetch_optional(self.pool())
        .await?;
        Ok(id)
    }

    /// The newest non-retracted message in `conversation_id` with archive id `stanza_id` (a
    /// XEP-0425 moderation from the room references the room-assigned stanza-id only).
    pub async fn find_by_stanza_id(&self, conversation_id: i64, stanza_id: &str) -> Result<Option<i64>> {
        let id: Option<i64> = sqlx::query_scalar(
            r#"SELECT id FROM messages
               WHERE conversation_id = ?1 AND stanza_id = ?2 AND retracted = 0
               ORDER BY id DESC LIMIT 1"#,
        )
        .bind(conversation_id)
        .bind(stanza_id)
        .fetch_optional(self.pool())
        .await?;
        Ok(id)
    }

    /// XEP-0308: replace the body of message `message_id` (already authorized by the caller
    /// via [`Self::find_from_sender`]). The row takes the *correction's* encryption and
    /// fingerprint, so a plaintext correction of an encrypted message can't keep the lock.
    pub async fn correct_message(
        &self,
        message_id: i64,
        target_marker: &str,
        new_body: &str,
        encryption: &str,
        fingerprint: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"UPDATE messages SET body = ?1, edited_of = ?2, encryption = ?3, omemo_fingerprint = ?4
               WHERE id = ?5"#,
        )
        .bind(new_body)
        .bind(target_marker)
        .bind(encryption)
        .bind(fingerprint)
        .bind(message_id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// XEP-0424 tombstone of message `message_id` (already authorized by the caller); same
    /// effect as [`Self::retract_message`]. Returns the body it had.
    pub async fn retract_message_id(&self, message_id: i64) -> Result<Option<String>> {
        let body: Option<Option<String>> = sqlx::query_scalar("SELECT body FROM messages WHERE id = ?1")
            .bind(message_id)
            .fetch_optional(self.pool())
            .await?;
        sqlx::query(
            r#"UPDATE messages SET retracted = 1, body = NULL, attachment = NULL,
               edited_of = NULL, reply_to = NULL, omemo_fingerprint = NULL WHERE id = ?1"#,
        )
        .bind(message_id)
        .execute(self.pool())
        .await?;
        sqlx::query("DELETE FROM reactions WHERE message_id = ?1")
            .bind(message_id)
            .execute(self.pool())
            .await?;
        Ok(body.flatten())
    }

    /// XEP-0184/0333 from the counterpart: advance the delivery state of one of *our* messages
    /// in `conversation_id` (never another conversation's, never an incoming one), and never
    /// downgrade `displayed` back to `received`. Returns whether a row changed.
    pub async fn mark_outgoing_state(
        &self,
        conversation_id: i64,
        marker_id: &str,
        state: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            r#"UPDATE messages SET state = ?1
               WHERE conversation_id = ?2 AND direction = 'out'
                     AND (stanza_id = ?3 OR origin_id = ?3)
                     AND NOT (?1 = 'received' AND state = 'displayed')"#,
        )
        .bind(state)
        .bind(conversation_id)
        .bind(marker_id)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Attach XEP-0066/0363 media metadata JSON to a message.
    pub async fn set_attachment(&self, message_id: i64, attachment_json: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE messages SET attachment = ?1 WHERE id = ?2",
            attachment_json,
            message_id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    // ---- reactions (XEP-0444) -------------------------------------------

    /// Replace a reactor's full reaction set for a message (XEP-0444 replace-semantics:
    /// the reactor's previous reactions are dropped and replaced with `emojis`).
    pub async fn set_reactions(
        &self,
        message_id: i64,
        reactor: &str,
        reactor_nick: Option<&str>,
        emojis: &[String],
    ) -> Result<()> {
        let mut tx = self.pool().begin().await?;
        sqlx::query!(
            "DELETE FROM reactions WHERE message_id = ?1 AND reactor = ?2",
            message_id,
            reactor
        )
        .execute(&mut *tx)
        .await?;
        for e in emojis {
            sqlx::query!(
                "INSERT OR IGNORE INTO reactions (message_id, reactor, emoji, reactor_nick)
                 VALUES (?1, ?2, ?3, ?4)",
                message_id,
                reactor,
                e,
                reactor_nick
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// A single reactor's current emojis for a message (for toggle logic).
    pub async fn reactions_of(&self, message_id: i64, reactor: &str) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"SELECT emoji as "emoji!: String" FROM reactions
               WHERE message_id = ?1 AND reactor = ?2"#,
            message_id,
            reactor
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|r| r.emoji).collect())
    }

    /// (emoji, count, reactor-names) tallies for a message, most-used first. The names are a
    /// comma-separated list of who reacted with that emoji (for the UI tooltip).
    pub async fn reactions(&self, message_id: i64) -> Result<Vec<(String, i64, String)>> {
        let rows = sqlx::query!(
            r#"SELECT emoji as "emoji!: String", COUNT(*) as "n!: i64",
                      COALESCE(GROUP_CONCAT(reactor_nick, ', '), '') as "nicks!: String"
               FROM reactions WHERE message_id = ?1
               GROUP BY emoji ORDER BY COUNT(*) DESC, emoji"#,
            message_id
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|r| (r.emoji, r.n, r.nicks)).collect())
    }

    /// All reaction tallies for every message in a conversation, in ONE query (avoids an
    /// N+1 of per-message [`reactions`] calls when opening a chat). Returns flat rows
    /// `(message_id, emoji, count, nicks)` ordered by message id then most-used emoji first,
    /// so the caller can group them sequentially.
    pub async fn reactions_for_conversation(
        &self,
        conversation_id: i64,
    ) -> Result<Vec<(i64, String, i64, String)>> {
        let rows = sqlx::query!(
            r#"SELECT r.message_id as "mid!: i64", r.emoji as "emoji!: String",
                      COUNT(*) as "n!: i64",
                      COALESCE(GROUP_CONCAT(r.reactor_nick, ', '), '') as "nicks!: String"
               FROM reactions r
               JOIN messages m ON m.id = r.message_id
               WHERE m.conversation_id = ?1
               GROUP BY r.message_id, r.emoji
               ORDER BY r.message_id, COUNT(*) DESC, r.emoji"#,
            conversation_id
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|r| (r.mid, r.emoji, r.n, r.nicks)).collect())
    }

    // ---- conversation list / unread ------------------------------------

    pub async fn conversations(&self, account_id: i64) -> Result<Vec<Conversation>> {
        let rows = sqlx::query_as::<_, Conversation>(
            r#"SELECT id, jid, kind, name, encryption, unread, last_active, muc_autojoin, notify
               FROM conversations
               WHERE account_id = ?1 AND archived = 0
               ORDER BY last_active DESC NULLS LAST, COALESCE(name, jid)"#,
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    pub async fn bump_unread(&self, conversation_id: i64) -> Result<()> {
        sqlx::query!(
            "UPDATE conversations SET unread = unread + 1 WHERE id = ?1",
            conversation_id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn clear_unread(&self, conversation_id: i64) -> Result<()> {
        sqlx::query!(
            "UPDATE conversations SET unread = 0 WHERE id = ?1",
            conversation_id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Set a conversation's notification mode ('all'|'mentioned'|'mentions_replies'|'none').
    pub async fn set_notify_mode(&self, account_id: i64, jid: &str, mode: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE conversations SET notify = ?3 WHERE account_id = ?1 AND jid = ?2",
            account_id,
            jid,
            mode
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn set_conversation_encryption(
        &self,
        conversation_id: i64,
        encryption: &str,
    ) -> Result<()> {
        sqlx::query!(
            "UPDATE conversations SET encryption = ?1 WHERE id = ?2",
            encryption,
            conversation_id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Configure a MUC conversation row (nick + autojoin), creating it if needed.
    pub async fn upsert_muc(
        &self,
        account_id: i64,
        room_jid: &str,
        name: Option<&str>,
        nick: Option<&str>,
        autojoin: bool,
    ) -> Result<i64> {
        let aj = autojoin as i64;
        // New group chats default to mentions-only ('mentioned'), like monocles Android; an
        // existing row keeps whatever notify mode the user set (ON CONFLICT leaves it alone).
        let rec = sqlx::query!(
            r#"INSERT INTO conversations (account_id, jid, kind, name, muc_nick, muc_autojoin, notify)
               VALUES (?1, ?2, 'muc', ?3, ?4, ?5, 'mentioned')
               ON CONFLICT(account_id, jid) DO UPDATE SET
                 kind = 'muc', name = COALESCE(excluded.name, conversations.name),
                 muc_nick = COALESCE(excluded.muc_nick, conversations.muc_nick),
                 muc_autojoin = excluded.muc_autojoin
               RETURNING id as "id!: i64""#,
            account_id, room_jid, name, nick, aj,
        )
        .fetch_one(self.pool())
        .await?;
        Ok(rec.id)
    }

    pub async fn autojoin_mucs(&self, account_id: i64) -> Result<Vec<Conversation>> {
        let rows = sqlx::query_as::<_, Conversation>(
            r#"SELECT id, jid, kind, name, encryption, unread, last_active, muc_autojoin, notify
               FROM conversations WHERE account_id = ?1 AND kind = 'muc' AND muc_autojoin = 1"#,
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }

    /// Encryption mode ('none'|'omemo2') for (account, jid), if the conversation exists.
    pub async fn conversation_encryption(&self, account_id: i64, jid: &str) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT encryption as "encryption!: String" FROM conversations
               WHERE account_id = ?1 AND jid = ?2"#,
            account_id, jid
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.encryption))
    }

    /// The kind ('chat'|'muc') of an existing conversation for (account, jid), if any.
    pub async fn conversation_kind(&self, account_id: i64, jid: &str) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT kind as "kind!: String" FROM conversations
               WHERE account_id = ?1 AND jid = ?2"#,
            account_id, jid
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.kind))
    }

    /// Our own XEP-0421 occupant id in a MUC, if we've learned it yet.
    pub async fn muc_self_occupant(&self, conversation_id: i64) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT muc_self_occupant_id as "occ?: String" FROM conversations WHERE id = ?1"#,
            conversation_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.and_then(|r| r.occ))
    }

    /// Record our own occupant id for a MUC (idempotent).
    pub async fn set_muc_self_occupant(&self, conversation_id: i64, occupant_id: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE conversations SET muc_self_occupant_id = ?1 WHERE id = ?2",
            occupant_id,
            conversation_id
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Delete a conversation and its messages/reactions (FK `ON DELETE CASCADE`).
    pub async fn delete_conversation(&self, account_id: i64, jid: &str) -> Result<()> {
        sqlx::query!(
            "DELETE FROM conversations WHERE account_id = ?1 AND jid = ?2",
            account_id,
            jid
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Our stored nick for a MUC by its room JID (for the leave presence).
    pub async fn muc_nick_by_jid(&self, account_id: i64, jid: &str) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT muc_nick as "nick?: String" FROM conversations
               WHERE account_id = ?1 AND jid = ?2"#,
            account_id,
            jid
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.and_then(|r| r.nick))
    }

    /// Stored password for a protected MUC (by conversation id), if any.
    pub async fn muc_password(&self, conversation_id: i64) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT muc_password as "pw?: String" FROM conversations WHERE id = ?1"#,
            conversation_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.and_then(|r| r.pw))
    }

    /// Persist a MUC password (for re-joining on autojoin/restart).
    pub async fn set_muc_password(&self, account_id: i64, jid: &str, password: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE conversations SET muc_password = ?3 WHERE account_id = ?1 AND jid = ?2",
            account_id,
            jid,
            password
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// The room's current subject/topic (XEP-0045 §8.1), if we've seen a subject message.
    pub async fn muc_subject(&self, conversation_id: i64) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT muc_subject as "subject?: String" FROM conversations WHERE id = ?1"#,
            conversation_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.and_then(|r| r.subject))
    }

    /// Persist the room's current subject/topic.
    pub async fn set_muc_subject(&self, conversation_id: i64, subject: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE conversations SET muc_subject = ?2 WHERE id = ?1",
            conversation_id,
            subject
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Our own nickname in a MUC conversation (the resource we joined with), if known.
    pub async fn muc_nick(&self, conversation_id: i64) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT muc_nick as "muc_nick?: String" FROM conversations WHERE id = ?1"#,
            conversation_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.and_then(|r| r.muc_nick))
    }

    /// Whether a conversation is a **public group**: a MUC that is not both members-only and
    /// non-anonymous (the negation of monocles' `isPrivateAndNonAnonymous`). Used to decide
    /// auto-download policy — remote files from public rooms are not fetched automatically.
    pub async fn is_public_group(&self, conversation_id: i64) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT kind as "kind!: String",
                      muc_members_only as "members_only!: i64",
                      muc_non_anonymous as "non_anonymous!: i64"
               FROM conversations WHERE id = ?1"#,
            conversation_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(match row {
            Some(r) => r.kind == "muc" && !(r.members_only != 0 && r.non_anonymous != 0),
            None => false,
        })
    }

    // ---- Encrypted-MUC support (room privacy features + occupant real JIDs) ----

    /// Cache a room's two privacy features (from disco#info). Together they decide whether
    /// OMEMO is possible in the room (members-only + non-anonymous → real JIDs are known).
    pub async fn set_muc_features(
        &self,
        conversation_id: i64,
        members_only: bool,
        non_anonymous: bool,
    ) -> Result<()> {
        let mo = members_only as i64;
        let na = non_anonymous as i64;
        sqlx::query!(
            "UPDATE conversations SET muc_members_only = ?2, muc_non_anonymous = ?3 WHERE id = ?1",
            conversation_id,
            mo,
            na,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// A room's `(members_only, non_anonymous)` features. OMEMO is offered only when both hold.
    pub async fn muc_features(&self, conversation_id: i64) -> Result<(bool, bool)> {
        let row = sqlx::query!(
            r#"SELECT muc_members_only as "mo!: i64", muc_non_anonymous as "na!: i64"
               FROM conversations WHERE id = ?1"#,
            conversation_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| (r.mo != 0, r.na != 0)).unwrap_or((false, false)))
    }

    /// Whether a room supports OMEMO (private + non-anonymous), by its bare JID.
    pub async fn muc_omemo_capable(&self, account_id: i64, room: &str) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT muc_members_only as "mo!: i64", muc_non_anonymous as "na!: i64"
               FROM conversations WHERE account_id = ?1 AND jid = ?2 AND kind = 'muc'"#,
            account_id, room
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.mo != 0 && r.na != 0).unwrap_or(false))
    }

    /// Record/refresh a room occupant (from MUC presence or an affiliation-list query).
    /// `real_jid` is the occupant's real bare JID (only present in non-anonymous rooms).
    pub async fn upsert_muc_occupant(
        &self,
        conversation_id: i64,
        nick: &str,
        real_jid: Option<&str>,
        affiliation: Option<&str>,
    ) -> Result<()> {
        // COALESCE keeps a previously-learned real JID/affiliation if a later presence omits it.
        sqlx::query!(
            r#"INSERT INTO muc_occupants (conversation_id, nick, real_jid, affiliation)
               VALUES (?1, ?2, ?3, ?4)
               ON CONFLICT(conversation_id, nick) DO UPDATE SET
                 real_jid = COALESCE(excluded.real_jid, muc_occupants.real_jid),
                 affiliation = COALESCE(excluded.affiliation, muc_occupants.affiliation)"#,
            conversation_id,
            nick,
            real_jid,
            affiliation,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Drop an occupant (left the room — unavailable presence).
    pub async fn remove_muc_occupant(&self, conversation_id: i64, nick: &str) -> Result<()> {
        sqlx::query!(
            "DELETE FROM muc_occupants WHERE conversation_id = ?1 AND nick = ?2",
            conversation_id,
            nick,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Resolve an occupant nick to their real bare JID (for decrypting a groupchat OMEMO message).
    pub async fn muc_occupant_real_jid(
        &self,
        conversation_id: i64,
        nick: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT real_jid as "real_jid?: String"
               FROM muc_occupants WHERE conversation_id = ?1 AND nick = ?2"#,
            conversation_id,
            nick,
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.and_then(|r| r.real_jid))
    }

    /// Distinct real bare JIDs of the room's members (affiliation owner/admin/member), excluding
    /// our own — the OMEMO crypto targets for a group message (matches Android's getCryptoTargets).
    pub async fn muc_member_jids(
        &self,
        conversation_id: i64,
        own_bare: &str,
    ) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"SELECT DISTINCT real_jid as "real_jid!: String"
               FROM muc_occupants
               WHERE conversation_id = ?1
                 AND real_jid IS NOT NULL
                 AND affiliation IN ('owner', 'admin', 'member')"#,
            conversation_id,
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.real_jid)
            .filter(|j| !j.eq_ignore_ascii_case(own_bare))
            .collect())
    }

    /// Encryption mode ('none'|'omemo2') for a conversation id.
    pub async fn conversation_encryption_by_id(&self, conversation_id: i64) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT encryption as "encryption!: String" FROM conversations WHERE id = ?1"#,
            conversation_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| r.encryption))
    }

    /// (jid, kind) for a conversation id.
    pub async fn conversation_target(&self, conversation_id: i64) -> Result<Option<(String, String)>> {
        let row = sqlx::query!(
            r#"SELECT jid as "jid!: String", kind as "kind!: String"
               FROM conversations WHERE id = ?1"#,
            conversation_id
        )
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(|r| (r.jid, r.kind)))
    }

    // ---- MAM cursors (XEP-0313) -----------------------------------------

    pub async fn mam_cursor(&self, account_id: i64, archive: &str) -> Result<Option<MamCursor>> {
        let row = sqlx::query_as::<_, MamCursor>(
            r#"SELECT first_id, last_id, complete FROM mam_cursors
               WHERE account_id = ?1 AND archive = ?2"#,
        )
        .bind(account_id)
        .bind(archive)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn set_mam_cursor(
        &self,
        account_id: i64,
        archive: &str,
        first_id: Option<&str>,
        last_id: Option<&str>,
        complete: bool,
    ) -> Result<()> {
        let c = complete as i64;
        sqlx::query!(
            r#"INSERT INTO mam_cursors (account_id, archive, first_id, last_id, complete)
               VALUES (?1, ?2, ?3, ?4, ?5)
               ON CONFLICT(account_id, archive) DO UPDATE SET
                 first_id = COALESCE(excluded.first_id, mam_cursors.first_id),
                 last_id  = COALESCE(excluded.last_id,  mam_cursors.last_id),
                 complete = excluded.complete"#,
            account_id, archive, first_id, last_id, c,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Conversation {
    pub id: i64,
    pub jid: String,
    pub kind: String,
    pub name: Option<String>,
    pub encryption: String,
    pub unread: i64,
    pub last_active: Option<String>,
    pub muc_autojoin: bool,
    /// Notification mode: 'all' | 'mentioned' | 'mentions_replies' | 'none'.
    pub notify: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MamCursor {
    pub first_id: Option<String>,
    pub last_id: Option<String>,
    pub complete: bool,
}

#[cfg(test)]
mod sender_auth_tests {
    use crate::{Direction, NewMessage, Store};

    fn msg(conv: i64, origin: &str, dir: Direction, occ: Option<&str>) -> NewMessage {
        NewMessage {
            conversation_id: conv,
            stanza_id: None,
            origin_id: Some(origin.into()),
            counterpart: "x@y".into(),
            direction: dir,
            body: Some("hello".into()),
            encryption: "omemo2".into(),
            reply_to: None,
            omemo_fingerprint: Some("fp".into()),
            attachment: None,
            occupant_id: occ.map(str::to_string),
            timestamp: "2026-10-04T00:00:00Z".into(),
            thread: None,
        }
    }

    #[tokio::test]
    async fn corrections_and_retractions_only_match_the_sender() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let room = store.conversation_id(acc, "room@muc.example.org", "muc").await.unwrap();
        let other = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        let mine = store.insert_message(&msg(room, "m1", Direction::Out, Some("occ-me"))).await.unwrap().unwrap();
        let alice = store.insert_message(&msg(room, "a1", Direction::In, Some("occ-alice"))).await.unwrap().unwrap();

        // Mallory (another occupant) can target neither Alice's nor our message.
        assert_eq!(store.find_from_sender(room, "a1", "in", Some("occ-mallory"), None).await.unwrap(), None);
        assert_eq!(store.find_from_sender(room, "m1", "in", Some("occ-mallory"), None).await.unwrap(), None);
        // Alice can target hers, we can target ours.
        assert_eq!(store.find_from_sender(room, "a1", "in", Some("occ-alice"), None).await.unwrap(), Some(alice));
        assert_eq!(store.find_from_sender(room, "m1", "out", None, None).await.unwrap(), Some(mine));
        // Other conversations never match.
        assert_eq!(store.find_from_sender(other, "a1", "in", None, None).await.unwrap(), None);

        // An encrypted original can only be corrected under its own fingerprint.
        assert_eq!(store.find_from_sender(room, "a1", "in", Some("occ-alice"), Some(None)).await.unwrap(), None);
        assert_eq!(store.find_from_sender(room, "a1", "in", Some("occ-alice"), Some(Some("other"))).await.unwrap(), None);
        assert_eq!(store.find_from_sender(room, "a1", "in", Some("occ-alice"), Some(Some("fp"))).await.unwrap(), Some(alice));

        // Applying a correction takes over its encryption state.
        store.correct_message(alice, "a1", "edited", "none", None).await.unwrap();
        let row = store.message_by_marker(room, "a1").await.unwrap().unwrap();
        assert_eq!(row.body.as_deref(), Some("edited"));
        assert_eq!(row.encryption, "none");
        assert_eq!(row.omemo_fingerprint, None);

        // A plaintext retraction can't delete an encrypted message (fresh one: a2).
        let a2 = store.insert_message(&msg(room, "a2", Direction::In, Some("occ-alice"))).await.unwrap().unwrap();
        assert_eq!(store.find_from_sender(room, "a2", "in", Some("occ-alice"), Some(None)).await.unwrap(), None);
        assert_eq!(store.find_from_sender(room, "a2", "in", Some("occ-alice"), Some(Some("fp"))).await.unwrap(), Some(a2));

        // Retracted messages can't be targeted again.
        assert_eq!(store.retract_message_id(alice).await.unwrap().as_deref(), Some("edited"));
        assert_eq!(store.find_from_sender(room, "a1", "in", Some("occ-alice"), None).await.unwrap(), None);
    }

    #[tokio::test]
    async fn receipts_only_touch_our_messages_in_that_conversation() {
        let store = Store::open_in_memory().await.unwrap();
        let acc = store.upsert_account("me@example.org").await.unwrap();
        let bob = store.conversation_id(acc, "bob@example.org", "chat").await.unwrap();
        let eve = store.conversation_id(acc, "eve@example.org", "chat").await.unwrap();
        store.insert_message(&msg(bob, "out1", Direction::Out, None)).await.unwrap();
        store.insert_message(&msg(bob, "in1", Direction::In, None)).await.unwrap();

        assert!(!store.mark_outgoing_state(eve, "out1", "displayed").await.unwrap());
        assert!(!store.mark_outgoing_state(bob, "in1", "displayed").await.unwrap());
        assert!(store.mark_outgoing_state(bob, "out1", "displayed").await.unwrap());
        // No downgrade from displayed to received.
        assert!(!store.mark_outgoing_state(bob, "out1", "received").await.unwrap());
    }
}
