-- M2 schema v1. M1 databases (plaintext, migrations 0001-0004) are not
-- migrated: SqliteStore resets them (see src/lib.rs).

-- gim-base state rows. Columns hold what is queried or ordered on; the rest
-- of a row is a CBOR `data` blob (see src/rows.rs). No foreign keys to
-- `chats`: messages may be parked before their chat exists, and
-- `remove_chat` deletes dependent rows explicitly.

CREATE TABLE chats (
    group_id TEXT PRIMARY KEY NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX chats_updated_at ON chats (updated_at_ms DESC, group_id);

CREATE TABLE messages (
    message_id TEXT PRIMARY KEY NOT NULL,
    group_id TEXT NOT NULL,
    -- NULL until an own message was accepted by the server.
    seq INTEGER,
    sent_at_ms INTEGER NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX messages_group_seq ON messages (group_id, seq);
CREATE INDEX messages_group_sent_at ON messages (group_id, sent_at_ms);

CREATE TABLE outbox (
    message_id TEXT PRIMARY KEY NOT NULL,
    group_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'failed')),
    next_attempt_at_ms INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX outbox_due ON outbox (state, next_attempt_at_ms);
CREATE INDEX outbox_created_at ON outbox (created_at_ms, message_id);
CREATE INDEX outbox_group ON outbox (group_id);

CREATE TABLE group_cursors (
    group_id TEXT PRIMARY KEY NOT NULL,
    contiguous_seq INTEGER NOT NULL,
    -- CBOR array of applied seqs above `contiguous_seq`.
    ahead BLOB NOT NULL
);

CREATE TABLE parked_messages (
    group_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (group_id, seq)
);

CREATE TABLE media_cache (
    blob_id TEXT PRIMARY KEY NOT NULL,
    local_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    last_access_ms INTEGER NOT NULL
);
CREATE INDEX media_cache_last_access ON media_cache (last_access_ms, blob_id);

CREATE TABLE users (
    user_id TEXT PRIMARY KEY NOT NULL,
    handle TEXT NOT NULL,
    display_name TEXT NOT NULL
);

CREATE TABLE sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    global_cursor INTEGER NOT NULL
);

-- gim-crypto CryptoStore rows besides the OpenMLS storage provider tables,
-- which openmls_sqlite_storage creates with its own migrations.

CREATE TABLE crypto_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    signature_private_key BLOB NOT NULL,
    signature_public_key BLOB NOT NULL,
    -- Encoded gim MLS credential.
    credential BLOB NOT NULL
);

CREATE TABLE crypto_groups (
    group_id TEXT PRIMARY KEY NOT NULL
);

-- Own commits whose outcome is not settled yet (one per group), and
-- devices that left a group (or were revoked) but may still be in its MLS
-- tree.

CREATE TABLE pending_commits (
    group_id TEXT PRIMARY KEY NOT NULL,
    data BLOB NOT NULL
);

CREATE TABLE departed_members (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id, device_id)
);

-- Latest known signed DeviceList (gim-identity CBOR) of each user.

CREATE TABLE device_lists (
    user_id TEXT PRIMARY KEY NOT NULL,
    data BLOB NOT NULL
);

-- Self groups (MLS groups of the own user's devices), in the order they
-- were recorded; the last one is current. Their chats are hidden from the
-- chat list.

CREATE TABLE self_groups (
    n INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT NOT NULL UNIQUE
);

-- Users joining or leaving a chat, one row per (group, seq, user), recorded
-- when the commit or Welcome that did it is applied.

CREATE TABLE membership_events (
    group_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    user_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('added', 'removed', 'left')),
    at_ms INTEGER NOT NULL,
    PRIMARY KEY (group_id, seq, user_id)
);
