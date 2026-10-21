-- XEP-0424 retractions that arrived before the message they remove (e.g. paging back through
-- an archive, where the retraction is on a newer page than its target): the target is
-- tombstoned when it shows up later. Carries the same sender binding as a live retraction
-- (direction, XEP-0421 occupant id, OMEMO fingerprint) so it can't hit anyone else's message.
-- Bounded per conversation (see Store::add_pending_retraction): retractions of ids that never
-- arrive cost the sender nothing.
CREATE TABLE IF NOT EXISTS pending_retractions (
    conversation_id   INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    target_id         TEXT    NOT NULL,
    direction         TEXT    NOT NULL,
    occupant_id       TEXT,
    omemo_fingerprint TEXT,
    -- Made (encrypted) by one of our own trusted devices on our own message: it removes that
    -- message whichever of our devices' fingerprints the message carries.
    any_own_device    INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (conversation_id, target_id, direction)
);

-- The sender's stanza `id` when it differs from the XEP-0359 origin-id (or there is none):
-- monocles Android and Conversations address corrections/retractions to it, and Android sends
-- no origin-id on a MUC private message. Only used to find an edit's target - never for
-- duplicate suppression, since stanza ids need not be unique.
ALTER TABLE messages ADD COLUMN remote_id TEXT;

-- Our own room messages sent from another of our devices used to be stored as incoming (they
-- come back from our nick). They are ours: store them as outgoing, so they can be edited and
-- retracted here. Only by the room-assigned occupant id (per real user, refreshed from our own
-- presence on every join) - never by nick, which someone else may have held.
UPDATE messages
SET direction = 'out', state = CASE WHEN state = 'queued' THEN 'sent' ELSE state END
WHERE direction = 'in'
  AND occupant_id IS NOT NULL
  AND occupant_id = (
      SELECT c.muc_self_occupant_id FROM conversations c
      WHERE c.id = messages.conversation_id AND c.kind = 'muc'
  );
