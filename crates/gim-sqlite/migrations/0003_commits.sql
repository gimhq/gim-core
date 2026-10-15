-- Own commits whose outcome or follow-up is not settled yet (one per
-- group), and devices that left a group's fan-out list but may still be in
-- its MLS tree.

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
