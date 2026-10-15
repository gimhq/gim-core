-- This device's pending leave of a group (its Remove proposal for its own
-- leaf), kept while the chat is leaving. `data` is CBOR (rows.rs).

CREATE TABLE pending_leaves (
    group_id TEXT PRIMARY KEY NOT NULL,
    data BLOB NOT NULL
);
