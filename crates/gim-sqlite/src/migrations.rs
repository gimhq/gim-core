//! Embedded, forward-only schema migrations. The schema version is
//! `PRAGMA user_version`: migration `i` (0-based) moves it from `i` to
//! `i + 1`. Never edit a released migration; append a new one.

use gim_base::StoreError;
use rusqlite::{Connection, TransactionBehavior};

const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_state.sql"),
    include_str!("../migrations/0002_crypto.sql"),
];

/// Schema version written by this build.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

pub(crate) fn schema_version(conn: &Connection) -> Result<u32, StoreError> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(StoreError::new)
}

/// Migrates to [`SCHEMA_VERSION`] in one transaction.
pub(crate) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    migrate_to(conn, SCHEMA_VERSION)
}

fn migrate_to(conn: &mut Connection, target: u32) -> Result<(), StoreError> {
    let txn = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(StoreError::new)?;
    let current = schema_version(&txn)?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::new(format!(
            "database schema v{current} is newer than this build (v{SCHEMA_VERSION})"
        )));
    }
    for sql in &MIGRATIONS[current as usize..target as usize] {
        txn.execute_batch(sql).map_err(StoreError::new)?;
    }
    txn.pragma_update(None, "user_version", target)
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
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        let tables = tables(&conn);
        for table in ["chats", "messages", "outbox", "crypto_identity"] {
            assert!(tables.iter().any(|t| t == table), "{table} in {tables:?}");
        }
        // Idempotent at the latest version.
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn migrates_from_v1_keeping_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate_to(&mut conn, 1).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 1);
        assert!(!tables(&conn).iter().any(|t| t == "crypto_identity"));
        conn.execute(
            "INSERT INTO chats (group_id, updated_at_ms, data) VALUES ('crew', 7, x'00')",
            [],
        )
        .unwrap();

        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        assert!(tables(&conn).iter().any(|t| t == "crypto_identity"));
        let updated: u64 = conn
            .query_row(
                "SELECT updated_at_ms FROM chats WHERE group_id = 'crew'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(updated, 7);
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
