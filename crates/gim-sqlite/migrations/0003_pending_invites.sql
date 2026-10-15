-- Users added to a chat whose hub was unreachable when their KeyPackages
-- were claimed; claimed again until the invite expires a TTL after
-- `created_at_ms`.

CREATE TABLE pending_invites (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    next_retry_at_ms INTEGER NOT NULL,
    attempts INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
);
