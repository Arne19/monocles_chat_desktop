-- Pinned messages (local only, as on monocles Android: nothing is sent over the wire).
-- A pin is a reference to the message row, never a copy of its content: the pin bar shows the
-- message as it is now (an edit shows its new text), and when the message goes - it expired,
-- the conversation was removed or its history cleared - its pin goes with it (ON DELETE
-- CASCADE). Retraction and moderation keep a tombstone row, so they drop the pin themselves.
CREATE TABLE IF NOT EXISTS pinned_messages (
    message_id      INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    pinned_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pinned_conv ON pinned_messages(conversation_id, pinned_at DESC);
