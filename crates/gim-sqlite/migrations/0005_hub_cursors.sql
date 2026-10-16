-- The event cursor of this device on each listed hub other than the home
-- hub (multi-homing; the home hub keeps sync_state.global_cursor). Event
-- ids differ between hubs, so each hub is followed from its own cursor.

CREATE TABLE hub_cursors (
    hub_id TEXT PRIMARY KEY NOT NULL,
    cursor INTEGER NOT NULL
);
