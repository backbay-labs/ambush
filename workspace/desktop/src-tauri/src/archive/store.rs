//! Local SQLite archive store for saved relay messages.
//!
//! Three tables:
//! - `archived_events`       — one raw event row per (identity, relay, event_id)
//! - `archived_event_scopes` — N scope membership rows per raw event (many-to-many)
//! - `save_subscriptions`    — which scopes the user has subscribed to save
//!
//! WAL + `busy_timeout=5000` matches `managed_agents/retention.rs`.
//! Raw event rows are GC'd when their last scope row is deleted.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

// ── Schema ─────────────────────────────────────────────────────────────────

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS archived_events (
    identity_pubkey TEXT NOT NULL,
    relay_url       TEXT NOT NULL,
    id              TEXT NOT NULL,
    kind            INTEGER NOT NULL,
    pubkey          TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    raw_json        TEXT NOT NULL,
    archived_at     INTEGER NOT NULL,
    PRIMARY KEY (identity_pubkey, relay_url, id)
);

CREATE TABLE IF NOT EXISTS archived_event_scopes (
    identity_pubkey TEXT NOT NULL,
    relay_url       TEXT NOT NULL,
    id              TEXT NOT NULL,
    scope_type      TEXT NOT NULL,
    scope_value     TEXT NOT NULL,
    archived_at     INTEGER NOT NULL,
    PRIMARY KEY (identity_pubkey, relay_url, id, scope_type, scope_value)
);

CREATE TABLE IF NOT EXISTS save_subscriptions (
    identity_pubkey TEXT NOT NULL,
    relay_url       TEXT NOT NULL,
    scope_type      TEXT NOT NULL,
    scope_value     TEXT NOT NULL,
    kinds           TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (identity_pubkey, relay_url, scope_type, scope_value)
);
";

// ── Open / init ─────────────────────────────────────────────────────────────

/// Open (or create) the archive database at the given path.
///
/// Applies WAL journaling and `busy_timeout=5000` on every connection,
/// matching `managed_agents/retention.rs`. Creates all three tables if they
/// don't already exist.
pub fn open_archive_db(path: &Path) -> Result<Connection, String> {
    // Ensure the parent directory exists so `Connection::open` doesn't fail.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create archive dir: {e}"))?;
    }

    let conn = Connection::open(path).map_err(|e| format!("failed to open archive db: {e}"))?;

    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| format!("failed to set WAL mode: {e}"))?;
    conn.pragma_update(None, "busy_timeout", 5000)
        .map_err(|e| format!("failed to set busy_timeout: {e}"))?;

    conn.execute_batch(SCHEMA)
        .map_err(|e| format!("failed to initialize archive schema: {e}"))?;

    Ok(conn)
}

// ── Save subscriptions ──────────────────────────────────────────────────────

/// A save subscription row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SaveSubscription {
    pub identity_pubkey: String,
    pub relay_url: String,
    pub scope_type: String,
    pub scope_value: String,
    /// JSON-encoded integer array, e.g. `[1,6,39000]`.
    pub kinds: String,
    pub created_at: i64,
}

/// Insert or replace a save subscription. `kinds` must be a JSON int array.
pub fn upsert_save_subscription(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
    scope_type: &str,
    scope_value: &str,
    kinds_json: &str,
    now: i64,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO save_subscriptions
             (identity_pubkey, relay_url, scope_type, scope_value, kinds, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (identity_pubkey, relay_url, scope_type, scope_value)
         DO UPDATE SET kinds = excluded.kinds",
        params![
            identity_pubkey,
            relay_url,
            scope_type,
            scope_value,
            kinds_json,
            now
        ],
    )
    .map_err(|e| format!("failed to upsert save subscription: {e}"))?;
    Ok(())
}

/// List all save subscriptions for the given identity + relay.
pub fn list_save_subscriptions(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
) -> Result<Vec<SaveSubscription>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT identity_pubkey, relay_url, scope_type, scope_value, kinds, created_at
             FROM save_subscriptions
             WHERE identity_pubkey = ?1 AND relay_url = ?2
             ORDER BY created_at ASC",
        )
        .map_err(|e| format!("prepare list_save_subscriptions: {e}"))?;

    let rows = stmt
        .query_map(params![identity_pubkey, relay_url], |row| {
            Ok(SaveSubscription {
                identity_pubkey: row.get(0)?,
                relay_url: row.get(1)?,
                scope_type: row.get(2)?,
                scope_value: row.get(3)?,
                kinds: row.get(4)?,
                created_at: row.get(5)?,
            })
        })
        .map_err(|e| format!("query list_save_subscriptions: {e}"))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read list_save_subscriptions row: {e}"))
}

/// Delete a save subscription. Does NOT purge archived event data (retention
/// is decoupled in v1). Returns `true` if a row was deleted.
pub fn delete_save_subscription(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
    scope_type: &str,
    scope_value: &str,
) -> Result<bool, String> {
    let affected = conn
        .execute(
            "DELETE FROM save_subscriptions
             WHERE identity_pubkey = ?1
               AND relay_url       = ?2
               AND scope_type      = ?3
               AND scope_value     = ?4",
            params![identity_pubkey, relay_url, scope_type, scope_value],
        )
        .map_err(|e| format!("failed to delete save subscription: {e}"))?;
    Ok(affected > 0)
}

/// Return true if a matching save subscription exists for the given scope.
#[allow(dead_code)]
pub fn has_save_subscription(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
    scope_type: &str,
    scope_value: &str,
) -> Result<bool, String> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM save_subscriptions
             WHERE identity_pubkey = ?1
               AND relay_url       = ?2
               AND scope_type      = ?3
               AND scope_value     = ?4",
            params![identity_pubkey, relay_url, scope_type, scope_value],
            |row| row.get(0),
        )
        .map_err(|e| format!("failed to check save subscription: {e}"))?;
    Ok(count > 0)
}

/// Atomically merge `new_kind` into the `owner_p` save subscription for the
/// given identity + relay + scope_value.
///
/// Reads the current `kinds` array, unions in `new_kind`, and writes back —
/// all inside a single `BEGIN IMMEDIATE` SQLite transaction.  `IMMEDIATE`
/// acquires the write lock at `BEGIN` (before the `SELECT`), so a second
/// concurrent caller blocks on `busy_timeout` (5000 ms, set by
/// `open_archive_db`) and then reads the first caller's committed row.  This
/// guarantees the union is complete; a `DEFERRED` transaction would let two
/// concurrent callers both read the empty snapshot and produce a
/// `BUSY_SNAPSHOT` failure on the losing writer.
///
/// If no row exists yet it is created with `[new_kind]`. `now` is used as
/// `created_at` only on insert (the conflict clause never updates it).
pub fn merge_owner_p_kinds(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
    scope_value: &str,
    new_kind: u32,
    now: i64,
) -> Result<(), String> {
    // BEGIN IMMEDIATE takes the write lock before the SELECT so concurrent
    // callers serialize here rather than racing to a BUSY_SNAPSHOT error.
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("merge_owner_p_kinds begin immediate: {e}"))?;

    let result = (|| -> Result<(), String> {
        // Read the current kinds, if any.
        let existing_json: Option<String> = conn
            .query_row(
                "SELECT kinds FROM save_subscriptions
                 WHERE identity_pubkey = ?1
                   AND relay_url       = ?2
                   AND scope_type      = 'owner_p'
                   AND scope_value     = ?3",
                params![identity_pubkey, relay_url, scope_value],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| format!("merge_owner_p_kinds read: {e}"))?;

        // Parse, union, re-serialize.
        let mut kinds: Vec<u32> = match existing_json {
            Some(ref json) => serde_json::from_str(json).unwrap_or_default(),
            None => vec![],
        };
        if !kinds.contains(&new_kind) {
            kinds.push(new_kind);
        }
        let kinds_json = serde_json::to_string(&kinds)
            .map_err(|e| format!("merge_owner_p_kinds serialize: {e}"))?;

        // Upsert — INSERT on first call, UPDATE kinds on subsequent.
        conn.execute(
            "INSERT INTO save_subscriptions
                 (identity_pubkey, relay_url, scope_type, scope_value, kinds, created_at)
             VALUES (?1, ?2, 'owner_p', ?3, ?4, ?5)
             ON CONFLICT (identity_pubkey, relay_url, scope_type, scope_value)
             DO UPDATE SET kinds = excluded.kinds",
            params![identity_pubkey, relay_url, scope_value, kinds_json, now],
        )
        .map_err(|e| format!("merge_owner_p_kinds upsert: {e}"))?;

        Ok(())
    })();

    if result.is_ok() {
        conn.execute_batch("COMMIT")
            .map_err(|e| format!("merge_owner_p_kinds commit: {e}"))?;
    } else {
        // Best-effort rollback; ignore the rollback error to surface the
        // original error to the caller.
        let _ = conn.execute_batch("ROLLBACK");
    }

    result
}

/// Return the `kinds` JSON string for a matching save subscription, or `None`
/// if no subscription exists.
pub fn get_subscription_kinds(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
    scope_type: &str,
    scope_value: &str,
) -> Result<Option<String>, String> {
    let result = conn
        .query_row(
            "SELECT kinds FROM save_subscriptions
             WHERE identity_pubkey = ?1
               AND relay_url       = ?2
               AND scope_type      = ?3
               AND scope_value     = ?4",
            params![identity_pubkey, relay_url, scope_type, scope_value],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| format!("failed to fetch subscription kinds: {e}"))?;
    Ok(result)
}

// ── Archived events ─────────────────────────────────────────────────────────

/// Upsert an event row (idempotent on the PK).
///
/// Does nothing if the event is already archived (same identity/relay/id).
pub fn upsert_archived_event(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
    event_id: &str,
    kind: i64,
    pubkey: &str,
    created_at: i64,
    raw_json: &str,
    archived_at: i64,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO archived_events
             (identity_pubkey, relay_url, id, kind, pubkey, created_at, raw_json, archived_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT (identity_pubkey, relay_url, id) DO NOTHING",
        params![
            identity_pubkey,
            relay_url,
            event_id,
            kind,
            pubkey,
            created_at,
            raw_json,
            archived_at
        ],
    )
    .map_err(|e| format!("failed to upsert archived event: {e}"))?;
    Ok(())
}

/// Upsert a scope membership row for an event.
///
/// Idempotent: if the (identity, relay, id, scope_type, scope_value) PK already
/// exists the row is left unchanged.
pub fn upsert_event_scope(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
    event_id: &str,
    scope_type: &str,
    scope_value: &str,
    archived_at: i64,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO archived_event_scopes
             (identity_pubkey, relay_url, id, scope_type, scope_value, archived_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (identity_pubkey, relay_url, id, scope_type, scope_value) DO NOTHING",
        params![
            identity_pubkey,
            relay_url,
            event_id,
            scope_type,
            scope_value,
            archived_at
        ],
    )
    .map_err(|e| format!("failed to upsert event scope: {e}"))?;
    Ok(())
}

/// Read a paginated page of archived events for a given scope.
///
/// Returns the `raw_json` of matching events in newest-first order
/// (`ORDER BY created_at DESC, id DESC`). The optional compound cursor
/// `(before_created_at, before_id)` implements keyset pagination: both fields
/// must be `Some` together to activate the cursor (passing one `Some` and one
/// `None` is a logic error at the call site — the store treats mixed `Some`/
/// `None` as no cursor). The predicate mirrors the sort order exactly:
/// `(created_at < before_created_at) OR (created_at = before_created_at AND
/// id < before_id)`. Pass `None`/`None` to start at the newest end.
///
/// A scalar `created_at`-only cursor would skip same-second siblings at a page
/// boundary because rows are ordered by `(created_at DESC, id DESC)` — two
/// rows with equal `created_at` on different pages would both be excluded by
/// `created_at < before`. The compound cursor avoids this.
///
/// An optional `kinds` slice filters by event kind; `None` admits all kinds.
///
/// Returns at most `limit` rows (caller is responsible for a sane default).
pub fn read_archived_events(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
    scope_type: &str,
    scope_value: &str,
    kinds: Option<&[i64]>,
    before_created_at: Option<i64>,
    before_id: Option<&str>,
    limit: i64,
) -> Result<Vec<String>, String> {
    // Build clauses and positional params together so slot numbers are always
    // contiguous (rusqlite rejects gaps like ?4 then ?6 with no ?5 in between).
    //
    // Fixed params: identity_pubkey, relay_url, scope_type, scope_value = ?1–?4.
    // Optional params appended in declaration order, limit always last.

    let mut next_slot: usize = 5;
    let mut extra_clauses = String::new();
    let mut kinds_json: Option<String> = None;
    let mut before_at_val: Option<i64> = None;
    let mut before_id_val: Option<String> = None;

    if let Some(ks) = kinds {
        kinds_json = Some(serde_json::to_string(ks).unwrap_or_else(|_| "[]".to_string()));
        extra_clauses.push_str(&format!(
            " AND ae.kind IN (SELECT value FROM json_each(?{next_slot}))"
        ));
        next_slot += 1;
    }
    // Compound cursor: both fields must be Some to activate.  The predicate
    // mirrors ORDER BY (created_at DESC, id DESC) exactly so no same-second
    // sibling is skipped at a page boundary.
    if let (Some(bat), Some(bid)) = (before_created_at, before_id) {
        before_at_val = Some(bat);
        before_id_val = Some(bid.to_owned());
        extra_clauses.push_str(&format!(
            " AND (ae.created_at < ?{next_slot} \
              OR (ae.created_at = ?{next_slot} AND ae.id < ?{}))",
            next_slot + 1,
        ));
        next_slot += 2;
    }
    let limit_slot = next_slot;

    let sql = format!(
        "SELECT ae.raw_json \
         FROM archived_events ae \
         INNER JOIN archived_event_scopes aes \
             ON aes.identity_pubkey = ae.identity_pubkey \
            AND aes.relay_url       = ae.relay_url \
            AND aes.id              = ae.id \
         WHERE ae.identity_pubkey = ?1 \
           AND ae.relay_url       = ?2 \
           AND aes.scope_type     = ?3 \
           AND aes.scope_value    = ?4\
         {extra_clauses}\
         ORDER BY ae.created_at DESC, ae.id DESC \
         LIMIT ?{limit_slot}",
    );

    // Build the param list dynamically to match the generated SQL.
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(identity_pubkey.to_owned()),
        Box::new(relay_url.to_owned()),
        Box::new(scope_type.to_owned()),
        Box::new(scope_value.to_owned()),
    ];
    if let Some(kj) = kinds_json {
        params.push(Box::new(kj));
    }
    if let (Some(bat), Some(bid)) = (before_at_val, before_id_val) {
        // Both slots use the same created_at value (the OR predicate references
        // it twice); the id slot follows.
        params.push(Box::new(bat));
        params.push(Box::new(bid));
    }
    params.push(Box::new(limit));

    let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("prepare read_archived_events: {e}"))?;

    let rows = stmt
        .query_map(param_refs.as_slice(), |row| row.get::<_, String>(0))
        .map_err(|e| format!("query read_archived_events: {e}"))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read read_archived_events row: {e}"))
}

/// GC: delete orphaned event rows whose last scope row was just removed.
///
/// Called after any batch deletion of scope rows. Uses a LEFT JOIN so only
/// events with zero remaining scope rows are deleted.
#[allow(dead_code)] // Used by P4 purge commands; not yet wired to a Tauri command.
pub fn gc_orphaned_events(
    conn: &Connection,
    identity_pubkey: &str,
    relay_url: &str,
) -> Result<usize, String> {
    let affected = conn
        .execute(
            "DELETE FROM archived_events
             WHERE identity_pubkey = ?1
               AND relay_url       = ?2
               AND id NOT IN (
                   SELECT id FROM archived_event_scopes
                   WHERE identity_pubkey = ?1
                     AND relay_url       = ?2
               )",
            params![identity_pubkey, relay_url],
        )
        .map_err(|e| format!("failed to gc orphaned events: {e}"))?;
    Ok(affected)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn in_memory() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "busy_timeout", 5000).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn
    }

    // ── Schema init ──────────────────────────────────────────────────────────

    #[test]
    fn test_schema_init_creates_all_tables() {
        let conn = in_memory();
        // Verify all three tables exist by inserting a row in each.
        conn.execute(
            "INSERT INTO save_subscriptions VALUES ('pk','relay','channel_h','abc','[1]',0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO archived_events VALUES ('pk','relay','id1',1,'author',0,'{}',0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO archived_event_scopes VALUES ('pk','relay','id1','channel_h','abc',0)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn test_schema_init_is_idempotent() {
        // Running SCHEMA twice must not error.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute_batch(SCHEMA).unwrap();
    }

    // ── Save subscriptions ───────────────────────────────────────────────────

    #[test]
    fn test_upsert_save_subscription_inserts_and_updates_kinds() {
        let conn = in_memory();
        upsert_save_subscription(&conn, "pk", "wss://r", "channel_h", "abc", "[1]", 1).unwrap();
        let subs = list_save_subscriptions(&conn, "pk", "wss://r").unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].kinds, "[1]");

        // Update kinds.
        upsert_save_subscription(&conn, "pk", "wss://r", "channel_h", "abc", "[1,6]", 2).unwrap();
        let subs = list_save_subscriptions(&conn, "pk", "wss://r").unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].kinds, "[1,6]");
    }

    #[test]
    fn test_list_save_subscriptions_scoped_to_identity_and_relay() {
        let conn = in_memory();
        upsert_save_subscription(&conn, "pk1", "wss://r1", "channel_h", "a", "[1]", 1).unwrap();
        upsert_save_subscription(&conn, "pk2", "wss://r1", "channel_h", "b", "[1]", 2).unwrap();
        upsert_save_subscription(&conn, "pk1", "wss://r2", "channel_h", "c", "[1]", 3).unwrap();

        let subs = list_save_subscriptions(&conn, "pk1", "wss://r1").unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].scope_value, "a");
    }

    #[test]
    fn test_delete_save_subscription_removes_row() {
        let conn = in_memory();
        upsert_save_subscription(&conn, "pk", "wss://r", "channel_h", "abc", "[1]", 1).unwrap();
        let deleted = delete_save_subscription(&conn, "pk", "wss://r", "channel_h", "abc").unwrap();
        assert!(deleted);
        let subs = list_save_subscriptions(&conn, "pk", "wss://r").unwrap();
        assert!(subs.is_empty());
    }

    #[test]
    fn test_delete_save_subscription_returns_false_when_not_found() {
        let conn = in_memory();
        let deleted =
            delete_save_subscription(&conn, "pk", "wss://r", "channel_h", "nope").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_has_save_subscription_true_and_false() {
        let conn = in_memory();
        upsert_save_subscription(&conn, "pk", "wss://r", "owner_p", "mypk", "[24200]", 1).unwrap();
        assert!(has_save_subscription(&conn, "pk", "wss://r", "owner_p", "mypk").unwrap());
        assert!(!has_save_subscription(&conn, "pk", "wss://r", "owner_p", "other").unwrap());
    }

    // ── merge_owner_p_kinds ──────────────────────────────────────────────────

    #[test]
    fn test_merge_owner_p_kinds_creates_row_when_none_exists() {
        let conn = in_memory();
        merge_owner_p_kinds(&conn, "pk", "wss://r", "mypk", 24200, 1).unwrap();
        let subs = list_save_subscriptions(&conn, "pk", "wss://r").unwrap();
        assert_eq!(subs.len(), 1);
        let kinds: Vec<u32> = serde_json::from_str(&subs[0].kinds).unwrap();
        assert_eq!(kinds, [24200]);
    }

    #[test]
    fn test_merge_owner_p_kinds_adds_new_kind_to_existing_row() {
        let conn = in_memory();
        // Seed with 24200 first.
        merge_owner_p_kinds(&conn, "pk", "wss://r", "mypk", 24200, 1).unwrap();
        // Now merge 44200 in — must produce [24200, 44200].
        merge_owner_p_kinds(&conn, "pk", "wss://r", "mypk", 44200, 2).unwrap();
        let subs = list_save_subscriptions(&conn, "pk", "wss://r").unwrap();
        assert_eq!(subs.len(), 1);
        let kinds: Vec<u32> = serde_json::from_str(&subs[0].kinds).unwrap();
        assert!(kinds.contains(&24200), "must still contain 24200");
        assert!(kinds.contains(&44200), "must now contain 44200");
        assert_eq!(kinds.len(), 2, "no duplicates");
    }

    #[test]
    fn test_merge_owner_p_kinds_idempotent_on_existing_kind() {
        let conn = in_memory();
        merge_owner_p_kinds(&conn, "pk", "wss://r", "mypk", 44200, 1).unwrap();
        merge_owner_p_kinds(&conn, "pk", "wss://r", "mypk", 44200, 2).unwrap();
        let subs = list_save_subscriptions(&conn, "pk", "wss://r").unwrap();
        let kinds: Vec<u32> = serde_json::from_str(&subs[0].kinds).unwrap();
        assert_eq!(kinds, [44200], "no duplicates after idempotent call");
    }

    /// Two-connection WAL regression test for the BEGIN IMMEDIATE fix.
    ///
    /// Opens TWO separate connections to the same WAL file (mirroring the
    /// real scenario where the observer-archive seed hook and the
    /// metric-archive seed hook each open their own connection via
    /// `open_archive_db`).  Both threads call `merge_owner_p_kinds`
    /// concurrently from an empty row.  With `BEGIN IMMEDIATE` the losing
    /// thread blocks on `busy_timeout` until the winner commits, then
    /// reads the committed row and merges its kind in.  Both calls must
    /// resolve `Ok` and the final row must contain exactly `[24200, 44200]`.
    ///
    /// A `DEFERRED` transaction would produce `SQLITE_BUSY_SNAPSHOT` on the
    /// loser (not retried by busy_timeout), causing one kind to be silently
    /// dropped.  This test fails in <10 ms if the IMMEDIATE guard is removed.
    #[test]
    fn test_merge_owner_p_kinds_two_conn_wal_both_kinds_survive() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use tempfile::NamedTempFile;

        // A real file DB is required for WAL mode (in-memory dbs don't support
        // shared-cache WAL across multiple connections in the same process).
        let db_file = NamedTempFile::new().unwrap();
        let db_path = db_file.path().to_path_buf();

        // Initialise schema on the file DB via conn-A so both threads see it.
        let init_conn = open_archive_db(&db_path).unwrap();
        drop(init_conn);

        // Barrier ensures both threads are inside `merge_owner_p_kinds` before
        // either one issues `BEGIN IMMEDIATE`, maximising the race window.
        let barrier = Arc::new(Barrier::new(2));

        let path_a = db_path.clone();
        let path_b = db_path.clone();
        let bar_a = Arc::clone(&barrier);
        let bar_b = Arc::clone(&barrier);

        let handle_observer = thread::spawn(move || {
            let conn = open_archive_db(&path_a).unwrap();
            bar_a.wait(); // sync: both threads ready
            merge_owner_p_kinds(&conn, "pk", "wss://r", "mypk", 24200, 1)
        });

        let handle_metric = thread::spawn(move || {
            let conn = open_archive_db(&path_b).unwrap();
            bar_b.wait(); // sync: both threads ready
            merge_owner_p_kinds(&conn, "pk", "wss://r", "mypk", 44200, 2)
        });

        let res_observer = handle_observer.join().expect("observer thread panicked");
        let res_metric = handle_metric.join().expect("metric thread panicked");

        assert!(
            res_observer.is_ok(),
            "observer seed must succeed: {:?}",
            res_observer
        );
        assert!(
            res_metric.is_ok(),
            "metric seed must succeed: {:?}",
            res_metric
        );

        // Verify the final row contains both kinds.
        let verify_conn = open_archive_db(&db_path).unwrap();
        let subs = list_save_subscriptions(&verify_conn, "pk", "wss://r").unwrap();
        assert_eq!(subs.len(), 1, "exactly one owner_p row");
        let kinds: Vec<u32> = serde_json::from_str(&subs[0].kinds).unwrap();
        assert!(
            kinds.contains(&24200),
            "observer kind 24200 must survive concurrent metric seed; got {:?}",
            kinds
        );
        assert!(
            kinds.contains(&44200),
            "metric kind 44200 must be present after concurrent seed; got {:?}",
            kinds
        );
        assert_eq!(
            kinds.len(),
            2,
            "exactly two kinds, no duplicates; got {:?}",
            kinds
        );
    }

    // ── Archived events ──────────────────────────────────────────────────────

    #[test]
    fn test_upsert_archived_event_is_idempotent() {
        let conn = in_memory();
        upsert_archived_event(&conn, "pk", "wss://r", "id1", 1, "author", 100, "{}", 200).unwrap();
        // Second call must not error or duplicate.
        upsert_archived_event(&conn, "pk", "wss://r", "id1", 1, "author", 100, "{}", 201).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM archived_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    // ── Many-to-many scope rows ──────────────────────────────────────────────

    #[test]
    fn test_one_event_gets_multiple_scope_rows() {
        let conn = in_memory();
        upsert_archived_event(&conn, "pk", "wss://r", "id1", 1, "author", 100, "{}", 200).unwrap();
        upsert_event_scope(&conn, "pk", "wss://r", "id1", "channel_h", "chan1", 200).unwrap();
        upsert_event_scope(&conn, "pk", "wss://r", "id1", "referenced_e", "evref", 200).unwrap();
        // Idempotent second insert.
        upsert_event_scope(&conn, "pk", "wss://r", "id1", "channel_h", "chan1", 201).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM archived_event_scopes WHERE id = 'id1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    // ── GC ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_gc_removes_event_when_last_scope_deleted() {
        let conn = in_memory();
        upsert_archived_event(&conn, "pk", "wss://r", "id1", 1, "author", 100, "{}", 200).unwrap();
        upsert_event_scope(&conn, "pk", "wss://r", "id1", "channel_h", "c1", 200).unwrap();
        // Delete the only scope row manually.
        conn.execute("DELETE FROM archived_event_scopes WHERE id = 'id1'", [])
            .unwrap();
        let removed = gc_orphaned_events(&conn, "pk", "wss://r").unwrap();
        assert_eq!(removed, 1);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM archived_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_gc_leaves_event_with_remaining_scope() {
        let conn = in_memory();
        upsert_archived_event(&conn, "pk", "wss://r", "id1", 1, "author", 100, "{}", 200).unwrap();
        upsert_event_scope(&conn, "pk", "wss://r", "id1", "channel_h", "c1", 200).unwrap();
        upsert_event_scope(&conn, "pk", "wss://r", "id1", "referenced_e", "ref", 200).unwrap();
        // Delete only one scope row.
        conn.execute(
            "DELETE FROM archived_event_scopes WHERE scope_type = 'referenced_e'",
            [],
        )
        .unwrap();
        let removed = gc_orphaned_events(&conn, "pk", "wss://r").unwrap();
        assert_eq!(removed, 0);
    }

    // ── read_archived_events ─────────────────────────────────────────────────

    fn seed_events(conn: &Connection) {
        // Three events in scope "channel_h/chan1" for identity "pk"/"wss://r".
        // created_at: 300 (newest), 200, 100 (oldest).
        for (id, kind, created_at, raw) in &[
            ("e1", 9i64, 300i64, r#"{"id":"e1","created_at":300}"#),
            ("e2", 9i64, 200i64, r#"{"id":"e2","created_at":200}"#),
            ("e3", 42i64, 100i64, r#"{"id":"e3","created_at":100}"#),
        ] {
            upsert_archived_event(
                conn,
                "pk",
                "wss://r",
                id,
                *kind,
                "author",
                *created_at,
                raw,
                999,
            )
            .unwrap();
            upsert_event_scope(conn, "pk", "wss://r", id, "channel_h", "chan1", 999).unwrap();
        }
        // One event in a different scope — must never appear in chan1 results.
        upsert_archived_event(
            conn,
            "pk",
            "wss://r",
            "e4",
            9,
            "author",
            250,
            r#"{"id":"e4"}"#,
            999,
        )
        .unwrap();
        upsert_event_scope(conn, "pk", "wss://r", "e4", "channel_h", "chan2", 999).unwrap();
    }

    #[test]
    fn test_read_archived_events_returns_newest_first() {
        let conn = in_memory();
        seed_events(&conn);
        let rows = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan1",
            None,
            None,
            None,
            10,
        )
        .unwrap();
        assert_eq!(rows.len(), 3);
        // Newest first: e1 (300), e2 (200), e3 (100).
        let ids: Vec<&str> = rows
            .iter()
            .map(|r| {
                if r.contains("\"e1\"") {
                    "e1"
                } else if r.contains("\"e2\"") {
                    "e2"
                } else {
                    "e3"
                }
            })
            .collect();
        assert_eq!(ids, ["e1", "e2", "e3"]);
    }

    #[test]
    fn test_read_archived_events_keyset_cursor_excludes_at_boundary() {
        let conn = in_memory();
        seed_events(&conn);
        // Compound cursor at e1 (created_at=300, id="e1"): excludes e1 itself,
        // returns e2 and e3.
        let rows = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan1",
            None,
            Some(300),
            Some("e1"),
            10,
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| !r.contains("\"e1\"")));
    }

    #[test]
    fn test_read_archived_events_keyset_cursor_advances_correctly() {
        let conn = in_memory();
        seed_events(&conn);
        // Page 1: before=None/None, limit=2 → e1, e2.
        let page1 = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan1",
            None,
            None,
            None,
            2,
        )
        .unwrap();
        assert_eq!(page1.len(), 2);
        // Page 2: compound cursor at e2 (created_at=200, id="e2") → e3 only.
        let page2 = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan1",
            None,
            Some(200),
            Some("e2"),
            2,
        )
        .unwrap();
        assert_eq!(page2.len(), 1);
        assert!(page2[0].contains("\"e3\""));
        // No overlap between pages.
        assert!(page1.iter().all(|r| !r.contains("\"e3\"")));
    }

    #[test]
    fn test_read_archived_events_kind_filter() {
        let conn = in_memory();
        seed_events(&conn);
        // Only kind 9 (e1 and e2); e3 is kind 42.
        let rows = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan1",
            Some(&[9]),
            None,
            None,
            10,
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| !r.contains("\"e3\"")));
    }

    #[test]
    fn test_read_archived_events_scope_isolation() {
        let conn = in_memory();
        seed_events(&conn);
        // chan2 has only e4; chan1 results must not include e4.
        let chan1 = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan1",
            None,
            None,
            None,
            10,
        )
        .unwrap();
        assert!(chan1.iter().all(|r| !r.contains("\"e4\"")));

        let chan2 = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan2",
            None,
            None,
            None,
            10,
        )
        .unwrap();
        assert_eq!(chan2.len(), 1);
        assert!(chan2[0].contains("\"e4\""));
    }

    #[test]
    fn test_read_archived_events_identity_isolation() {
        let conn = in_memory();
        seed_events(&conn);
        // Different identity — must see no rows.
        let rows = read_archived_events(
            &conn,
            "pk2",
            "wss://r",
            "channel_h",
            "chan1",
            None,
            None,
            None,
            10,
        )
        .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn test_read_archived_events_relay_isolation() {
        let conn = in_memory();
        seed_events(&conn);
        // Different relay — must see no rows.
        let rows = read_archived_events(
            &conn,
            "pk",
            "wss://other",
            "channel_h",
            "chan1",
            None,
            None,
            None,
            10,
        )
        .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn test_read_archived_events_empty_result() {
        let conn = in_memory();
        let rows = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "nope",
            None,
            None,
            None,
            10,
        )
        .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn test_read_archived_events_limit_respected() {
        let conn = in_memory();
        seed_events(&conn);
        let rows = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan1",
            None,
            None,
            None,
            1,
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        // Must be the newest (e1, created_at=300).
        assert!(rows[0].contains("\"e1\""));
    }

    #[test]
    fn test_read_archived_events_no_duplicates_across_pages() {
        let conn = in_memory();
        seed_events(&conn);
        let page1 = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan1",
            None,
            None,
            None,
            2,
        )
        .unwrap();
        // Compound cursor at e2 (the oldest in page1: created_at=200, id="e2").
        let page2 = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "chan1",
            None,
            Some(200),
            Some("e2"),
            2,
        )
        .unwrap();
        // All event ids across both pages are unique.
        let all: Vec<_> = page1.iter().chain(page2.iter()).collect();
        assert_eq!(all.len(), 3); // 2 + 1 = 3 total, no duplication.
    }

    /// Regression for the scalar-cursor same-second skip defect (Thufir IMPORTANT).
    ///
    /// The writer stores `created_at` in whole seconds, so two events can share
    /// the same timestamp.  The sort order is `(created_at DESC, id DESC)`, so
    /// a page split exactly at a same-second boundary leaves one sibling on each
    /// side.  With only `created_at < before` the second-page sibling would be
    /// permanently excluded.  The compound `(created_at < ?) OR (created_at = ?
    /// AND id < ?)` predicate mirrors the sort key exactly and avoids the skip.
    #[test]
    fn test_read_archived_events_same_second_cursor_no_skip() {
        let conn = in_memory();
        // Two events share created_at=1000. Sort order: "z" (id "z") > "a" (id "a"),
        // so ORDER BY created_at DESC, id DESC yields: ("z", 1000) first, ("a", 1000) second.
        // A third event has created_at=500.
        for (id, kind, created_at, raw) in &[
            ("z", 9i64, 1000i64, r#"{"id":"z","created_at":1000}"#),
            ("a", 9i64, 1000i64, r#"{"id":"a","created_at":1000}"#),
            ("old", 9i64, 500i64, r#"{"id":"old","created_at":500}"#),
        ] {
            upsert_archived_event(
                &conn,
                "pk",
                "wss://r",
                id,
                *kind,
                "author",
                *created_at,
                raw,
                999,
            )
            .unwrap();
            upsert_event_scope(&conn, "pk", "wss://r", id, "channel_h", "same_sec", 999).unwrap();
        }

        // Page 1: limit=1 → should return ("z", 1000) only (newest by compound sort).
        let page1 = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "same_sec",
            None,
            None,
            None,
            1,
        )
        .unwrap();
        assert_eq!(page1.len(), 1);
        assert!(page1[0].contains("\"z\""), "page1 must be the 'z' row");

        // Page 2: compound cursor at ("z", 1000).
        // With a scalar cursor (created_at < 1000), row "a" would be SKIPPED.
        // With the compound cursor, "a" must appear on page 2.
        let page2 = read_archived_events(
            &conn,
            "pk",
            "wss://r",
            "channel_h",
            "same_sec",
            None,
            Some(1000),
            Some("z"),
            2,
        )
        .unwrap();
        // Must contain "a" (same-second sibling) and "old" (strictly older).
        assert_eq!(page2.len(), 2, "page2 must return both remaining rows");
        assert!(
            page2.iter().any(|r| r.contains("\"a\"")),
            "same-second sibling 'a' must not be skipped"
        );
        assert!(
            page2.iter().any(|r| r.contains("\"old\"")),
            "'old' row must appear on page2"
        );
        // No overlap with page1.
        assert!(page2.iter().all(|r| !r.contains("\"z\"")));
    }
}
