-- Mark group-call (XEP-0272 Muji) rows explicitly. Before, a row counted as a group call only
-- while a group conversation with that JID still existed, so after leaving the group its calls
-- turned into 1:1 calls "with the room" (opening a 1:1 chat with it, calling it back 1:1).
ALTER TABLE call_log ADD COLUMN is_group INTEGER NOT NULL DEFAULT 0;

-- Existing rows: the groups we are still in. Rows of groups already left can't be recovered.
UPDATE call_log SET is_group = 1
WHERE EXISTS (
    SELECT 1 FROM conversations c
    WHERE c.account_id = call_log.account_id
      AND c.kind = 'muc'
      AND c.jid = call_log.peer COLLATE NOCASE
);
