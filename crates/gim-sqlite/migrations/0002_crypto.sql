-- gim-crypto CryptoStore rows besides the OpenMLS storage provider tables,
-- which openmls_sqlite_storage creates with its own migrations.

CREATE TABLE crypto_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    signature_private_key BLOB NOT NULL,
    signature_public_key BLOB NOT NULL
);

CREATE TABLE crypto_groups (
    group_id TEXT PRIMARY KEY NOT NULL
);
