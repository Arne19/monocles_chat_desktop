-- XEP-0425 message moderation: a tombstone removed by a room moderator (rather than retracted
-- by its sender) and the moderator's optional reason, shown in place of the body.
ALTER TABLE messages ADD COLUMN moderated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN moderation_reason TEXT;

-- Moderations that arrived before the message they remove (e.g. paging back through a room
-- archive that keeps the original): the target is dropped when it shows up later.
CREATE TABLE IF NOT EXISTS pending_moderations (
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    stanza_id       TEXT    NOT NULL,
    PRIMARY KEY (conversation_id, stanza_id)
);
