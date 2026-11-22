-- Live locations received from monocles Android (urn:xmpp:live-location:0). The share starts
-- with a normal `geo:` message carrying <live-location id expires/>; this row ties that message
-- to its session. Later OMEMO2-only updates move `last_lat`/`last_lon`, a stop or the expiry
-- ends it. Only the original sender (`sender`, the crypto sender's bare JID) can move or end
-- it. The row goes with its message (ON DELETE CASCADE: expiry, history clear, conversation
-- removal); a retraction or moderation, which keep a tombstone, drops it explicitly.
CREATE TABLE IF NOT EXISTS live_locations (
    message_id      INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    session_id      TEXT NOT NULL,
    sender          TEXT NOT NULL,
    expires         INTEGER NOT NULL,
    last_lat        REAL,
    last_lon        REAL,
    stopped         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_live_locations_session ON live_locations(conversation_id, session_id);
