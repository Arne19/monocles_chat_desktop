-- Social feed (XEP-0472 / XEP-0277) posts: a cache of the followed feeds and of pushed posts,
-- so the Feeds view isn't empty until the servers answered. Item ids are chosen by each
-- publisher, so they are only unique per author. `published` is unix seconds.
CREATE TABLE feed_posts (
    account_id      INTEGER NOT NULL,
    author          TEXT    NOT NULL COLLATE NOCASE,   -- bare JID (verified publisher)
    id              TEXT    NOT NULL,                  -- PubSub item id
    title           TEXT    NOT NULL DEFAULT '',
    content         TEXT    NOT NULL DEFAULT '',       -- Markdown
    published       INTEGER NOT NULL,
    link            TEXT    NOT NULL DEFAULT '',
    attachment_url  TEXT    NOT NULL DEFAULT '',
    attachment_type TEXT    NOT NULL DEFAULT '',
    comments_jid    TEXT    NOT NULL DEFAULT '',
    comments_node   TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (account_id, author, id)
);
