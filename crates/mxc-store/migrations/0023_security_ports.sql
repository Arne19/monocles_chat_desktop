-- Security fixes ported from monocles Android (2026-10).

-- Room stanza-ids of the corrections a message received (XEP-0308). A correction rewrites the
-- original row, but in the room archive it is its own message with its own stanza-id: a
-- moderation has to remove those too, or the edited text stays visible to everyone else
-- (Conversations 13063fbf4). Also lets a moderation that names a correction's id find the row.
CREATE TABLE IF NOT EXISTS message_versions (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    stanza_id  TEXT    NOT NULL,
    PRIMARY KEY (message_id, stanza_id)
);
CREATE INDEX IF NOT EXISTS idx_message_versions_stanza_id ON message_versions (stanza_id);

-- A conversation created by an incoming stanza stays hidden until it holds a message, so a
-- bodyless stanza (receipt, chat state, ...) from anyone can't put an empty chat in the list.
ALTER TABLE conversations ADD COLUMN pending INTEGER NOT NULL DEFAULT 0;

-- Offline room members used to be keyed by nick = their real bare JID, so an occupant could
-- join with the nick "alice@example.org" and land on Alice's row (swapping her real JID out of
-- the OMEMO targets, or deleting it when leaving). Their rows now use a key no real nick can
-- have: a control character is not allowed in an XMPP resourcepart.
UPDATE muc_occupants SET nick = char(1) || 'member:' || real_jid
WHERE real_jid IS NOT NULL AND nick = real_jid;
