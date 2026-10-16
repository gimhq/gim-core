//! Upgrades of databases built by released (core main) migration sets: each
//! must open with the current code, keep its rows, and end with exactly the
//! schema of a fresh database.

mod common;

use std::path::Path;

use common::key;
use gim_base::model::{HubRecord, HubState, KeyPackageRecord};
use gim_base::{StateReader, StateStore, StoreTxn};
use gim_sqlite::{SqliteStore, APPLICATION_ID, DATABASE_FILE_NAME, SCHEMA_VERSION};
use rusqlite::Connection;

/// The migrations as they were at d5ead6d (C4a), before 0004_hubs.sql was
/// edited in place. 0001-0003 are also the sets of b577edb (0001 only),
/// c313304 and 7077421 (0001-0003): their files are identical.
const D5EAD6D: &[&str] = &[
    include_str!("fixtures/migrations-d5ead6d/0001_schema.sql"),
    include_str!("fixtures/migrations-d5ead6d/0002_pending_leaves.sql"),
    include_str!("fixtures/migrations-d5ead6d/0003_pending_invites.sql"),
    include_str!("fixtures/migrations-d5ead6d/0004_hubs.sql"),
];

/// The migrations of 50f7915 (C4b): 0001-0006 with the edited 0004.
const C4B: &[&str] = &[
    include_str!("../migrations/0001_schema.sql"),
    include_str!("../migrations/0002_pending_leaves.sql"),
    include_str!("../migrations/0003_pending_invites.sql"),
    include_str!("../migrations/0004_hubs.sql"),
    include_str!("../migrations/0005_hub_cursors.sql"),
    include_str!("../migrations/0006_key_package_ledger.sql"),
];

/// Every database a released build can leave behind.
fn releases() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("b577edb v1", D5EAD6D[..1].to_vec()),
        ("7077421 v3", D5EAD6D[..3].to_vec()),
        ("d5ead6d v4", D5EAD6D.to_vec()),
        // A d5ead6d database opened by 50f7915: 0005 and 0006 ran, but
        // hubs never got url_shared.
        (
            "d5ead6d v4 upgraded by 50f7915 to v6",
            [D5EAD6D, &C4B[4..]].concat(),
        ),
        ("50f7915 v6", C4B.to_vec()),
    ]
}

/// A raw connection keyed like [`key`], as the store keys it.
fn raw_keyed(dir: &Path) -> Connection {
    let conn = Connection::open(dir.join(DATABASE_FILE_NAME)).unwrap();
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", "07".repeat(32)))
        .unwrap();
    conn
}

/// Builds the database a release with `migrations` writes, holding one hub
/// row once the hubs table exists.
fn build_release(dir: &Path, migrations: &[&str]) {
    let conn = raw_keyed(dir);
    for sql in migrations {
        conn.execute_batch(sql).unwrap();
    }
    conn.pragma_update(None, "user_version", migrations.len())
        .unwrap();
    conn.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    if migrations.len() >= 4 {
        conn.execute(
            "INSERT INTO hubs (hub_id, url, priority, state) \
             VALUES ('h0', 'https://h0.example', 0, 'verified')",
            [],
        )
        .unwrap();
    }
}

#[derive(Debug, PartialEq)]
struct Schema {
    user_version: u32,
    application_id: i32,
    /// `(type, name, tbl_name, sql)`, by type and name.
    objects: Vec<(String, String, String, Option<String>)>,
    /// `pragma table_info` of each table, by table name.
    columns: Vec<(String, Vec<String>)>,
}

fn schema(dir: &Path) -> Schema {
    let conn = raw_keyed(dir);
    let mut stmt = conn
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
        .unwrap();
    let objects: Vec<(String, String, String, Option<String>)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let columns = objects
        .iter()
        .filter(|(kind, ..)| kind == "table")
        .map(|(_, table, ..)| {
            let mut stmt = conn
                .prepare(
                    "SELECT cid, name, type, \"notnull\", dflt_value, pk \
                     FROM pragma_table_info(?1) ORDER BY cid",
                )
                .unwrap();
            let info = stmt
                .query_map([table], |row| {
                    Ok(format!(
                        "{}|{}|{}|{}|{:?}|{}",
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            (table.clone(), info)
        })
        .collect();
    Schema {
        user_version: conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap(),
        application_id: conn
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap(),
        objects,
        columns,
    }
}

fn fresh_schema() -> Schema {
    let dir = tempfile::tempdir().unwrap();
    drop(SqliteStore::open(dir.path(), &key()).unwrap());
    schema(dir.path())
}

fn hub(hub_id: &str, url_shared: bool) -> HubRecord {
    HubRecord {
        hub_id: hub_id.into(),
        url: Some(format!("https://{hub_id}.example")),
        url_shared,
        priority: 1,
        verified_root_pubkey: Some(vec![7; 32]),
        last_seen_ms: Some(5),
        state: HubState::Unverified,
    }
}

#[test]
fn released_databases_upgrade_to_the_fresh_schema() {
    let fresh = fresh_schema();
    assert_eq!(fresh.user_version, SCHEMA_VERSION);
    for (release, migrations) in releases() {
        let dir = tempfile::tempdir().unwrap();
        build_release(dir.path(), &migrations);
        drop(SqliteStore::open(dir.path(), &key()).unwrap());
        assert_eq!(schema(dir.path()), fresh, "{release}");
    }
}

#[test]
fn released_databases_read_and_write_hubs_cursors_and_key_packages() {
    for (release, migrations) in releases() {
        let dir = tempfile::tempdir().unwrap();
        build_release(dir.path(), &migrations);
        let store = SqliteStore::open(dir.path(), &key()).unwrap();

        // The hub row written by the release survives, not shared.
        let kept: Vec<HubRecord> = store.hubs().unwrap();
        if migrations.len() >= 4 {
            assert_eq!(kept.len(), 1, "{release}");
            assert_eq!(kept[0].hub_id, "h0", "{release}");
            assert_eq!(kept[0].url.as_deref(), Some("https://h0.example"));
            assert!(!kept[0].url_shared, "{release}");
            assert_eq!(kept[0].state, HubState::Verified, "{release}");
        } else {
            assert!(kept.is_empty(), "{release}");
        }

        let (local, shared) = (hub("ha", false), hub("hb", true));
        let record = KeyPackageRecord {
            kp_ref: vec![1, 2],
            hub_id: "hb".into(),
            last_resort: true,
            created_at_ms: 9,
        };
        store
            .transaction(|txn| {
                txn.upsert_hub(&local)?;
                txn.upsert_hub(&shared)?;
                txn.set_hub_cursor("hb", 17)?;
                txn.add_key_package_record(&record)?;
                Ok(())
            })
            .unwrap_or_else(|err| panic!("{release}: {err:?}"));
        drop(store);

        let store = SqliteStore::open(dir.path(), &key()).unwrap();
        let hubs = store.hubs().unwrap();
        assert!(hubs.contains(&local), "{release}: {hubs:?}");
        assert!(hubs.contains(&shared), "{release}: {hubs:?}");
        assert_eq!(store.hub_cursor("hb").unwrap(), Some(17), "{release}");
        assert_eq!(store.key_package_records().unwrap(), [record], "{release}");
    }
}
