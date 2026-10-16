-- The hubs of the own user's hosting record known to this device: the
-- client API URL learned for each hub_id, the root key that URL proved,
-- and whether the hub is still listed.

CREATE TABLE hubs (
    hub_id TEXT PRIMARY KEY NOT NULL,
    url TEXT,
    priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 255),
    verified_root_pubkey BLOB,
    last_seen_ms INTEGER,
    state TEXT NOT NULL CHECK (state IN ('unverified', 'verified', 'removed'))
);
