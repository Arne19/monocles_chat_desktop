-- Disappearing messages (urn:xmpp:ephemeral:0, as monocles Android).

-- The chat's setting: seconds, 0 = off. New messages we send carry it.
ALTER TABLE conversations ADD COLUMN ephemeral_timer INTEGER NOT NULL DEFAULT 0;
-- When (unix seconds, as stamped on the stanza) the setting last changed: a change that is
-- older than this - one met while paging back through history - is not applied.
ALTER TABLE conversations ADD COLUMN ephemeral_changed_at INTEGER NOT NULL DEFAULT 0;

-- Each message keeps the timer its sender stamped on it. `expire_at` (unix seconds) is set when
-- the countdown starts: at sending time for our own messages, when read for incoming ones.
ALTER TABLE messages ADD COLUMN ephemeral_timer INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN expire_at INTEGER;
CREATE INDEX IF NOT EXISTS idx_messages_expire_at ON messages (expire_at) WHERE expire_at IS NOT NULL;

-- Ids of messages that expired and were deleted. A copy that reaches us again (an archive that
-- kept it despite the no-permanent-store hint, a late carbon) must not bring the message back.
CREATE TABLE IF NOT EXISTS expired_messages (
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    marker          TEXT    NOT NULL,
    expired_at      INTEGER NOT NULL,
    PRIMARY KEY (conversation_id, marker)
);
