//! Calendar feed tokens — Phase 24.3.
//!
//! A feed is a bearer credential of its own kind: 32 random bytes, shown once,
//! stored here only as a SHA-256 hash — the same shape `users::create_user_token`
//! already uses for API tokens, for the same reason. `GET /ics/{token}.ics`
//! looks a presented token up by its hash and never needs the plaintext again.
//!
//! `user_id = NULL` means the feed belongs to the vault owner and is built from
//! **every** entry, unfiltered. A non-null `user_id` means the feed must be
//! re-filtered through `filter_vault_for_user` on **every fetch**, not once at
//! creation — a permission revoked after the feed was minted has to shrink it,
//! or the feed outlives the access it was issued under.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Creates the table if absent. Called from [`crate::init_schema`].
pub fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ics_feeds (
             id              TEXT PRIMARY KEY,
             user_id         TEXT,
             token_hash      TEXT NOT NULL UNIQUE,
             name            TEXT NOT NULL,
             kinds           TEXT NOT NULL,
             scope           TEXT NOT NULL DEFAULT '',
             created_at      TEXT NOT NULL,
             last_fetched_at TEXT,
             revoked_at      TEXT
         );
         CREATE INDEX IF NOT EXISTS ics_feeds_token ON ics_feeds(token_hash);",
    )
    .map_err(|e| e.to_string())
}

#[derive(Clone, Serialize)]
pub struct FeedRecord {
    pub id: String,
    pub user_id: Option<String>,
    pub name: String,
    /// `created` / `expires` / `rotation`, comma-joined.
    pub kinds: String,
    /// Comma-joined opt-in flags. Only meaningful value today: `account_names`
    /// — off by default, because an account name is often an email address and
    /// the design's rule is that a feed says nothing beyond names and dates
    /// unless the person creating it asks for more.
    pub scope: String,
    pub created_at: String,
    pub last_fetched_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl FeedRecord {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn include_account_names(&self) -> bool {
        self.scope.split(',').any(|s| s == "account_names")
    }

    pub fn kind_list(&self) -> Vec<String> {
        self.kinds
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }
}

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<FeedRecord> {
    Ok(FeedRecord {
        id: row.get(0)?,
        user_id: row.get(1)?,
        name: row.get(2)?,
        kinds: row.get(3)?,
        scope: row.get(4)?,
        created_at: row.get(5)?,
        last_fetched_at: row.get(6)?,
        revoked_at: row.get(7)?,
    })
}

const COLS: &str = "id, user_id, name, kinds, scope, created_at, last_fetched_at, revoked_at";

/// Mints a feed. Returns the record and the plaintext token — the **only** time
/// the plaintext exists outside the requester's own response.
pub fn create_feed(
    conn: &Connection,
    user_id: Option<&str>,
    name: &str,
    kinds: &[String],
    include_account_names: bool,
) -> Result<(FeedRecord, String), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let token_hash = sha256_hex(&token);
    let id = crate::new_uuid();
    let created_at = crate::iso_now();
    let kinds_joined = kinds.join(",");
    let scope = if include_account_names {
        "account_names".to_string()
    } else {
        String::new()
    };
    conn.execute(
        "INSERT INTO ics_feeds (id, user_id, token_hash, name, kinds, scope, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            user_id,
            token_hash,
            name,
            kinds_joined,
            scope,
            created_at
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok((
        FeedRecord {
            id,
            user_id: user_id.map(str::to_string),
            name: name.to_string(),
            kinds: kinds_joined,
            scope,
            created_at,
            last_fetched_at: None,
            revoked_at: None,
        },
        token,
    ))
}

/// Feeds visible to the caller: every feed for the owner, only the caller's own
/// otherwise.
pub fn list_feeds(
    conn: &Connection,
    is_owner: bool,
    user_id: &str,
) -> Result<Vec<FeedRecord>, String> {
    let sql = format!(
        "SELECT {COLS} FROM ics_feeds {} ORDER BY created_at DESC",
        if is_owner { "" } else { "WHERE user_id = ?1" }
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = if is_owner {
        stmt.query_map([], row_to_record)
    } else {
        stmt.query_map(params![user_id], row_to_record)
    }
    .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

/// Revokes a feed. An owner may revoke any feed; a sub-user only their own —
/// enforced here rather than trusted to the caller, since this is the one
/// place that decides whether a URL someone thought they killed still works.
pub fn revoke_feed(
    conn: &Connection,
    feed_id: &str,
    actor_user_id: &str,
    is_owner: bool,
) -> Result<bool, String> {
    let n = if is_owner {
        conn.execute(
            "UPDATE ics_feeds SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
            params![crate::iso_now(), feed_id],
        )
    } else {
        conn.execute(
            "UPDATE ics_feeds SET revoked_at = ?1 \
             WHERE id = ?2 AND user_id = ?3 AND revoked_at IS NULL",
            params![crate::iso_now(), feed_id, actor_user_id],
        )
    }
    .map_err(|e| e.to_string())?;
    Ok(n > 0)
}

/// Looks a presented token up by its hash. Revoked feeds are excluded here
/// rather than filtered by the caller, so a revoked token can never be reached
/// by forgetting one check site.
pub fn find_active_feed_by_token(
    conn: &Connection,
    raw_token: &str,
) -> Result<Option<FeedRecord>, String> {
    let hash = sha256_hex(raw_token);
    conn.query_row(
        &format!("SELECT {COLS} FROM ics_feeds WHERE token_hash = ?1 AND revoked_at IS NULL"),
        params![hash],
        row_to_record,
    )
    .optional()
    .map_err(|e| e.to_string())
}

/// Stamps the last-fetch time. Deliberately not an audited write — a calendar
/// client polling hourly would grow the hash-chained audit log without bound,
/// the same reason vault reads stopped being audited.
pub fn touch_feed(conn: &Connection, feed_id: &str) -> Result<(), String> {
    conn.execute(
        "UPDATE ics_feeds SET last_fetched_at = ?1 WHERE id = ?2",
        params![crate::iso_now(), feed_id],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn a_revoked_feed_is_not_found_by_its_token() {
        let conn = mem();
        let (feed, token) =
            create_feed(&conn, None, "Everything", &["expires".to_string()], false).unwrap();
        assert!(find_active_feed_by_token(&conn, &token).unwrap().is_some());
        assert!(revoke_feed(&conn, &feed.id, "owner", true).unwrap());
        assert!(find_active_feed_by_token(&conn, &token).unwrap().is_none());
    }

    #[test]
    fn a_sub_user_cannot_revoke_someone_elses_feed() {
        let conn = mem();
        let (feed, _) = create_feed(
            &conn,
            Some("alice"),
            "Alice's feed",
            &["expires".to_string()],
            false,
        )
        .unwrap();
        assert!(!revoke_feed(&conn, &feed.id, "bob", false).unwrap());
        assert!(revoke_feed(&conn, &feed.id, "alice", false).unwrap());
    }

    #[test]
    fn account_names_are_opt_in() {
        let conn = mem();
        let (feed, _) = create_feed(&conn, None, "X", &["expires".to_string()], false).unwrap();
        assert!(!feed.include_account_names());
        let (feed2, _) = create_feed(&conn, None, "Y", &["expires".to_string()], true).unwrap();
        assert!(feed2.include_account_names());
    }

    #[test]
    fn an_unknown_token_finds_nothing() {
        let conn = mem();
        assert!(find_active_feed_by_token(&conn, "not-a-real-token")
            .unwrap()
            .is_none());
    }
}
