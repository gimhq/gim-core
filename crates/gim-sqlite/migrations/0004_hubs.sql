-- The hubs of the own user's hosting record known to this device: the
-- client API URL learned for each hub_id, the root key that URL proved,
-- and whether the hub is still listed. url_shared: the URL came from another
-- own device (self group) and is never contacted (no URL-bound hub proof
-- yet); only a URL set on this device is used.

CREATE TABLE hubs (
    hub_id TEXT PRIMARY KEY NOT NULL,
    url TEXT,
    url_shared INTEGER NOT NULL DEFAULT 0 CHECK (url_shared IN (0, 1)),
    priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 255),
    verified_root_pubkey BLOB,
    last_seen_ms INTEGER,
    state TEXT NOT NULL CHECK (state IN ('unverified', 'verified', 'removed'))
);
