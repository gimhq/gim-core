-- Gives hubs the url_shared column of 0004_hubs.sql on databases created
-- before 0004 gained it (0004 was edited in place after it had shipped).
-- Rebuilds the table rather than adding the column, so the result is the
-- exact table 0004 creates today. The runner skips this migration when hubs
-- already has url_shared (databases created by the edited 0004).

ALTER TABLE hubs RENAME TO hubs_before_0007;

CREATE TABLE hubs (
    hub_id TEXT PRIMARY KEY NOT NULL,
    url TEXT,
    url_shared INTEGER NOT NULL DEFAULT 0 CHECK (url_shared IN (0, 1)),
    priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 255),
    verified_root_pubkey BLOB,
    last_seen_ms INTEGER,
    state TEXT NOT NULL CHECK (state IN ('unverified', 'verified', 'removed'))
);

INSERT INTO hubs (hub_id, url, priority, verified_root_pubkey, last_seen_ms, state)
SELECT hub_id, url, priority, verified_root_pubkey, last_seen_ms, state
FROM hubs_before_0007;

DROP TABLE hubs_before_0007;
