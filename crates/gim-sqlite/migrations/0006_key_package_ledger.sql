-- The KeyPackage ledger (multi-homing): every KeyPackage this device
-- generated, by its MLS KeyPackageRef, and the one hub it is uploaded to.
-- Rows are never deleted, so a kp_ref is never uploaded to another hub.

CREATE TABLE key_package_ledger (
    kp_ref BLOB PRIMARY KEY NOT NULL,
    hub_id TEXT NOT NULL,
    last_resort INTEGER NOT NULL CHECK (last_resort IN (0, 1)),
    created_at_ms INTEGER NOT NULL
);
