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
