-- A pending retraction is kept per sender, not just per retracted id: with one slot per id and
-- direction, another occupant's retraction of the same id (which fails the sender check later)
-- could take the slot and so keep the real author's retraction from ever applying. Retractions
-- from the same sender still merge (INSERT OR IGNORE against the unique index).
CREATE TABLE pending_retractions_new (
    conversation_id   INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    target_id         TEXT    NOT NULL,
    direction         TEXT    NOT NULL,
    occupant_id       TEXT,
    omemo_fingerprint TEXT,
    any_own_device    INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO pending_retractions_new
    (conversation_id, target_id, direction, occupant_id, omemo_fingerprint, any_own_device, created_at)
SELECT conversation_id, target_id, direction, occupant_id, omemo_fingerprint, any_own_device, created_at
FROM pending_retractions;

DROP TABLE pending_retractions;
ALTER TABLE pending_retractions_new RENAME TO pending_retractions;

CREATE UNIQUE INDEX pending_retractions_sender ON pending_retractions (
    conversation_id, target_id, direction,
    IFNULL(occupant_id, ''), IFNULL(omemo_fingerprint, ''), any_own_device
);
