//! Embedded, forward-only schema migrations. The schema version is
//! `PRAGMA user_version`: migration `i` (0-based) moves it from `i` to
//! `i + 1`. Never edit a released migration; append a new one.
//!
//! M2 restarted the history (D5): M1 databases are reset, not migrated.

use gim_base::StoreError;
use rusqlite::{Connection, TransactionBehavior};

const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_schema.sql"),
    include_str!("../migrations/0002_pending_leaves.sql"),
    include_str!("../migrations/0003_pending_invites.sql"),
];

/// Schema version written by this build.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// `PRAGMA application_id` of a gim database ("GIM2").
pub const APPLICATION_ID: i32 = 0x4749_4D32;

pub(crate) fn schema_version(conn: &Connection) -> Result<u32, StoreError> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(StoreError::new)
}

pub(crate) fn application_id(conn: &Connection) -> Result<i32, StoreError> {
    conn.pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(StoreError::new)
}

/// Migrates to [`SCHEMA_VERSION`] in one transaction and stamps
/// [`APPLICATION_ID`].
pub(crate) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let txn = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(StoreError::new)?;
    let current = schema_version(&txn)?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::new(format!(
            "database schema v{current} is newer than this build (v{SCHEMA_VERSION})"
        )));
    }
    for sql in &MIGRATIONS[current as usize..] {
        txn.execute_batch(sql).map_err(StoreError::new)?;
    }
    txn.pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(StoreError::new)?;
    txn.pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(StoreError::new)?;
    txn.commit().map_err(StoreError::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        let names = stmt.query_map([], |row| row.get(0)).unwrap();
        names.collect::<Result<_, _>>().unwrap()
    }

    #[test]
    fn migrates_from_empty_to_latest() {
        let mut conn = Connection::open_in_memory().unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 0);
        assert_eq!(application_id(&conn).unwrap(), 0);
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        assert_eq!(application_id(&conn).unwrap(), APPLICATION_ID);
        let tables = tables(&conn);
        for table in [
            "chats",
            "messages",
            "outbox",
            "crypto_identity",
            "crypto_groups",
            "pending_commits",
            "pending_leaves",
            "pending_invites",
            "departed_members",
            "device_lists",
            "membership_events",
        ] {
            assert!(tables.iter().any(|t| t == table), "{table} in {tables:?}");
        }
        // Idempotent at the latest version.
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn migrates_a_v1_database_keeping_its_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute(
            "INSERT INTO pending_commits (group_id, data) VALUES ('crew', x'00')",
            [],
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        assert!(tables(&conn).iter().any(|t| t == "pending_leaves"));
        assert!(tables(&conn).iter().any(|t| t == "pending_invites"));
        let kept: i64 = conn
            .query_row("SELECT COUNT(*) FROM pending_commits", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, 1);
    }

    #[test]
    fn migrates_a_v2_database_keeping_its_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        conn.execute_batch(MIGRATIONS[1]).unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        conn.execute(
            "INSERT INTO pending_leaves (group_id, data) VALUES ('crew', x'01')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pending_commits (group_id, data) VALUES ('crew', x'00')",
            [],
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        assert!(tables(&conn).iter().any(|t| t == "pending_invites"));
        for table in ["pending_leaves", "pending_commits"] {
            let kept: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(kept, 1, "{table}");
        }
    }

    #[test]
    fn membership_kind_is_checked() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO membership_events (group_id, seq, user_id, actor, kind, at_ms) \
             VALUES ('crew', 2, 'bob', 'alice', 'added', 7)",
            [],
        )
        .unwrap();
        let bad_kind = conn.execute(
            "INSERT INTO membership_events (group_id, seq, user_id, actor, kind, at_ms) \
             VALUES ('crew', 3, 'bob', 'alice', 'joined', 7)",
            [],
        );
        assert!(bad_kind.is_err());
    }

    #[test]
    fn refuses_newer_schema() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let err = migrate(&mut conn).unwrap_err();
        assert!(err.0.contains("newer"), "{err}");
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION + 1);
    }
}
