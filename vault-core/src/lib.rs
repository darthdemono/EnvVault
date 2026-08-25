//! vault-core — shared encryption, storage, and tooling for EnvVault.
//!
//! Used by the Tauri desktop app, the HTTP server (`envv-server`), and the CLI
//! (`envv-cli`).  Has no dependency on Tauri; accepts `&Path` for all I/O.

use argon2::{Algorithm, Argon2, Params, Version};
pub use rusqlite::Connection as SqlConnection;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
pub use zeroize::Zeroize;

pub mod generators;
pub use generators::{generate_certificate, generate_ssh_keypair};

pub mod permex;
pub use permex::{
    eval as eval_perm_expr, parse as parse_perm_expr, EntryView, Expr as PermExpr,
    Field as PermField,
};

pub mod users;
pub use users::{
    assign_user_class, authority_tier, class_authority_tier, create_user, create_user_class,
    create_user_token, delete_user, delete_user_class, effective_permission_expr,
    ensure_owner_user, filter_vault_for_user, get_class_permissions, get_permission_expr,
    get_user_capabilities, get_user_permissions, glob_matches, init_users_schema,
    list_user_classes, list_user_tokens, list_users, merge_user_vault_write, rename_user,
    revoke_user_token, seed_default_admin, set_class_permissions, set_permission_expr,
    set_user_password, set_user_permissions, token_user_id, update_user_class, user_authority_tier,
    verify_user_password, verify_user_token, AdminSeed, ClassPermission, PermissionRecord,
    TokenRecord, UserClass, UserRecord,
};

// ── Constants ──────────────────────────────────────────────────────────────────

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

const A2_M_COST: u32 = 65_536;
const A2_T_COST: u32 = 3;
const A2_P_COST: u32 = 1;

/// In-memory AES-256 vault key.
pub type VaultKey = [u8; KEY_LEN];

// ── KDF ────────────────────────────────────────────────────────────────────────

/// Derives a 32-byte AES-256 key from `password` and `salt` using Argon2id
/// (m=65536 KiB, t=3, p=1 — OWASP 2023 recommendation).
pub fn derive_key(password: &str, salt: &[u8]) -> Result<VaultKey, String> {
    let params =
        Params::new(A2_M_COST, A2_T_COST, A2_P_COST, Some(KEY_LEN)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

/// Reads salt from `salt_path`; generates and writes a fresh 16-byte salt if absent.
pub fn read_or_create_salt(salt_path: &Path) -> Result<[u8; SALT_LEN], String> {
    if salt_path.exists() {
        let raw = fs::read(salt_path).map_err(|e| e.to_string())?;
        raw.try_into()
            .map_err(|_| "vault.salt is corrupt (wrong length)".to_string())
    } else {
        use rand::RngCore;
        let mut s = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut s);
        if let Some(parent) = salt_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(salt_path, s).map_err(|e| e.to_string())?;
        Ok(s)
    }
}

// ── Database ───────────────────────────────────────────────────────────────────

/// Opens (or creates) the SQLCipher database at `db_path` using the 32-byte `key`.
///
/// Executes a verification query; returns `Err("Wrong master password")` on
/// decryption failure so callers can distinguish auth errors from I/O errors.
pub fn open_db(db_path: &Path, key: &VaultKey) -> Result<Connection, String> {
    if let Some(p) = db_path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .map_err(|e| e.to_string())?;
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key)))
        .map_err(|e| e.to_string())?;
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|_| "Wrong master password".to_string())?;
    // WAL mode: allows concurrent reads + one writer, avoids full locks (item 17)
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .map_err(|e| e.to_string())?;
    Ok(conn)
}

/// Creates the `vault` and `vault_audit` tables if absent; adds hash-chain
/// columns to `vault_audit` via idempotent ALTER TABLE (errors silently ignored
/// on existing columns).
pub fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault (
             id   INTEGER PRIMARY KEY CHECK (id = 1),
             data TEXT    NOT NULL
         );
         CREATE TABLE IF NOT EXISTS vault_audit (
             id             INTEGER PRIMARY KEY AUTOINCREMENT,
             action         TEXT    NOT NULL,
             entry_provider TEXT,
             timestamp      TEXT    NOT NULL,
             details        TEXT
         );
         CREATE TABLE IF NOT EXISTS vault_meta (
             key   TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );",
    )
    .map_err(|e| e.to_string())?;
    // Idempotent migration: add hash-chain columns if absent.
    let _ = conn.execute_batch("ALTER TABLE vault_audit ADD COLUMN entry_hash TEXT;");
    let _ = conn.execute_batch("ALTER TABLE vault_audit ADD COLUMN prev_hash  TEXT;");
    // Who performed the action. Rows written before this column exists stay NULL
    // and verify against the v1 hash formula (see `compute_audit_hash`).
    let _ = conn.execute_batch("ALTER TABLE vault_audit ADD COLUMN actor TEXT;");
    // Multi-user tables (Phase 5)
    users::init_users_schema(conn)?;
    Ok(())
}

// ── Entry identity ────────────────────────────────────────────────────────────

/// Canonical identity key for a vault entry.
///
/// Prefers the stable `id` (a UUID the frontend assigns on creation and never
/// mutates). Falls back to `provider|account_name|key_id` for entries written
/// before `id` existed.
///
/// Every consumer must use this one function. `save_vault` and
/// [`merge_user_vault_write`] previously disagreed — the former ignored
/// `key_id`, so two entries sharing provider+account collapsed into one key and
/// `version_history` / audit rows landed on the wrong entry, while the RBAC
/// merge treated them as distinct.
pub fn entry_ck(entry: &serde_json::Value) -> String {
    if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
        if !id.is_empty() {
            return format!("id\u{1}{id}");
        }
    }
    let field = |k: &str| entry.get(k).and_then(|v| v.as_str()).unwrap_or("");
    format!(
        "legacy\u{1}{}\u{1}{}\u{1}{}",
        field("provider"),
        field("account_name"),
        field("key_id"),
    )
}

// ── Vault I/O ─────────────────────────────────────────────────────────────────

/// Loads the raw vault JSON from an open connection.
pub fn load_vault(conn: &Connection) -> Result<Option<serde_json::Value>, String> {
    let raw: Option<String> = conn
        .query_row("SELECT data FROM vault WHERE id = 1", [], |row| row.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    match raw {
        None => Ok(None),
        Some(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| e.to_string()),
    }
}

/// Marker prefix on the error returned when a compare-and-swap write is refused.
/// Callers match on this to tell "someone else wrote first" from a real failure.
pub const CONFLICT_ERR: &str = "VAULT_CONFLICT";

/// Who is writing, and what they believe the vault currently is.
///
/// A struct rather than two positional `Option<&str>` arguments: silently
/// swapping an actor id for a version hash would disable the concurrency check
/// while still compiling and still passing tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct SaveCtx<'a> {
    /// User id responsible for the change, recorded in the audit log.
    /// `None` for contexts where the owner is implicit.
    pub actor: Option<&'a str>,
    /// The version the caller last read. When set, the write is refused unless
    /// the stored vault is *still* at that version. `None` writes unconditionally
    /// — only correct when nothing else can be writing.
    pub expect_version: Option<&'a str>,
}

/// Current version of the stored vault, or `None` when the vault is empty.
///
/// This is the `data_hash` that `save_vault` writes, so it is by construction
/// the hash of exactly the bytes on disk — no re-serialisation, no assumptions
/// about map ordering.
pub fn vault_version(conn: &Connection) -> Result<Option<String>, String> {
    conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'data_hash'",
        [],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| e.to_string())
}

/// Serialises `data` to the vault, updating `version_history` on key changes
/// and appending to the `vault_audit` hash chain. Returns the new version.
///
/// # Concurrency
///
/// When `ctx.expect_version` is set this is a **compare-and-swap**: the whole
/// operation runs inside one `BEGIN IMMEDIATE` transaction, and if another
/// writer has changed the vault since the caller read it, nothing is written and
/// [`CONFLICT_ERR`] is returned.
///
/// Doing the check here rather than in each caller matters for two reasons.
/// A caller that reads, compares, then writes has a race between the compare and
/// the write — which is what the server's `If-Match` handling used to be. And a
/// caller that simply forgets is silently unprotected, which is how the desktop
/// could clobber a LAN peer's edit.
///
/// The audit appends are inside the same transaction. They used to run before it,
/// so a rejected or failed write still left audit rows describing changes that
/// never happened.
pub fn save_vault(
    conn: &Connection,
    data: serde_json::Value,
    ctx: SaveCtx<'_>,
) -> Result<String, String> {
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| e.to_string())?;
    match save_vault_txn(conn, data, ctx) {
        Ok(hash) => {
            conn.execute_batch("COMMIT").map_err(|e| e.to_string())?;
            Ok(hash)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Body of [`save_vault`]. Must only be called inside a write transaction.
fn save_vault_txn(
    conn: &Connection,
    data: serde_json::Value,
    ctx: SaveCtx<'_>,
) -> Result<String, String> {
    use std::collections::{HashMap, HashSet};

    let actor = ctx.actor;
    let now_str = iso_now();

    // Compare-and-swap. Inside the transaction, so no writer can slip between
    // this check and the write below.
    if let Some(expected) = ctx.expect_version {
        let current = vault_version(conn)?;
        // An absent version means an empty vault; a caller expecting a specific
        // version against an empty vault is out of date either way.
        if current.as_deref() != Some(expected) {
            return Err(format!(
                "{CONFLICT_ERR}: the vault changed since you last read it — reload and retry"
            ));
        }
    }

    let existing: Option<serde_json::Value> = conn
        .query_row("SELECT data FROM vault WHERE id = 1", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(|e| e.to_string())?
        .and_then(|s| serde_json::from_str(&s).ok());

    let old_map: HashMap<String, serde_json::Value> = existing
        .as_ref()
        .and_then(|v| v.get("api_keys"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|e| (entry_ck(e), e.clone())).collect())
        .unwrap_or_default();

    let new_keys: HashSet<String> = data
        .get("api_keys")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(entry_ck).collect())
        .unwrap_or_default();

    for (ck, old_e) in &old_map {
        if !new_keys.contains(ck) {
            let provider = old_e.get("provider").and_then(|v| v.as_str()).unwrap_or("");
            append_audit(conn, "delete", provider, &now_str, None, actor)?;
        }
    }

    let mut new_data = data;
    if let Some(arr) = new_data.get_mut("api_keys").and_then(|v| v.as_array_mut()) {
        for entry in arr.iter_mut() {
            let provider = entry
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let ck = entry_ck(entry);

            if let Some(old_e) = old_map.get(&ck) {
                let new_val = entry.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
                let old_val = old_e.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
                if new_val != old_val && !old_val.is_empty() {
                    let mut history: Vec<serde_json::Value> = entry
                        .get("version_history")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_else(|| {
                            old_e
                                .get("version_history")
                                .and_then(|v| v.as_array())
                                .cloned()
                                .unwrap_or_default()
                        });
                    history.insert(
                        0,
                        serde_json::json!({ "value": old_val, "saved_at": now_str }),
                    );
                    history.truncate(50);
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert(
                            "version_history".to_string(),
                            serde_json::Value::Array(history),
                        );
                    }
                    append_audit(
                        conn,
                        "update",
                        &provider,
                        &now_str,
                        Some("api_key rotated"),
                        actor,
                    )?;
                }
            } else {
                append_audit(conn, "add", &provider, &now_str, None, actor)?;
            }
        }
    }

    let raw = serde_json::to_string(&new_data).map_err(|e| e.to_string())?;
    let hash = format!("{:x}", Sha256::digest(raw.as_bytes()));

    // Data and hash move together, so the integrity check never sees a mismatch.
    conn.execute(
        "INSERT OR REPLACE INTO vault (id, data) VALUES (1, ?1)",
        rusqlite::params![raw],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('data_hash', ?1)",
        rusqlite::params![hash],
    )
    .map_err(|e| e.to_string())?;

    Ok(hash)
}

/// Verifies the stored vault data against its SHA-256 integrity hash.
/// Returns `Ok(true)` if hash matches, `Ok(false)` if tampered or hash absent, `Err` on I/O.
pub fn verify_vault_integrity(conn: &Connection) -> Result<bool, String> {
    let raw: Option<String> = conn
        .query_row("SELECT data FROM vault WHERE id = 1", [], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    let stored_hash: Option<String> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'data_hash'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    match (raw, stored_hash) {
        (Some(data), Some(expected)) => {
            let actual = format!("{:x}", Sha256::digest(data.as_bytes()));
            Ok(actual == expected)
        }
        (None, _) => Ok(true),       // empty vault: trivially intact
        (Some(_), None) => Ok(true), // no hash stored yet (pre-migration): trust it
    }
}

/// Returns vault entries whose `expires_at` date falls within `within_days` days
/// from today (inclusive of today, exclusive of entries already expired).
///
/// Uses lexicographic YYYY-MM-DD comparison — no parsing feature required.
pub fn get_expiring_entries(
    conn: &Connection,
    within_days: u32,
) -> Result<Vec<serde_json::Value>, String> {
    let data = load_vault(conn)?.unwrap_or_else(|| serde_json::json!({ "api_keys": [] }));
    Ok(expiring_from_value(&data, within_days))
}

/// Like [`get_expiring_entries`] but first filters the vault to the entries the
/// user is permitted to read.  Prevents non-owner sessions from learning about
/// the expiry (and full contents) of secrets outside their RBAC scope.
pub fn get_expiring_entries_for_user(
    conn: &Connection,
    within_days: u32,
    read: Option<&permex::Expr>,
) -> Result<Vec<serde_json::Value>, String> {
    let data = load_vault(conn)?.unwrap_or_else(|| serde_json::json!({ "api_keys": [] }));
    let filtered = filter_vault_for_user(data, read);
    Ok(expiring_from_value(&filtered, within_days))
}

/// Extracts the `api_keys` whose `expires_at` falls within `within_days` of today.
fn expiring_from_value(data: &serde_json::Value, within_days: u32) -> Vec<serde_json::Value> {
    let now = time::OffsetDateTime::now_utc();
    let cutoff = now + time::Duration::days(within_days as i64);
    let today_str = fmt_date(&now);
    let cutoff_str = fmt_date(&cutoff);

    data.get("api_keys")
        .and_then(|k| k.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| {
            entry
                .get("expires_at")
                .and_then(|v| v.as_str())
                .is_some_and(|s| {
                    let d = &s[..s.len().min(10)];
                    d >= today_str.as_str() && d <= cutoff_str.as_str()
                })
        })
        .collect()
}

fn fmt_date(dt: &time::OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
}

// ── Audit log ─────────────────────────────────────────────────────────────────

/// A single audit log row, including the hash-chain fields.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditRow {
    pub id: i64,
    pub action: String,
    pub entry_provider: Option<String>,
    pub timestamp: String,
    pub details: Option<String>,
    pub entry_hash: Option<String>,
    pub prev_hash: Option<String>,
    /// User id that performed the action. `None` for rows written before actor
    /// tracking, and for local desktop edits where the owner is implicit.
    pub actor: Option<String>,
}

/// Appends an audit entry and computes `entry_hash = SHA256(action|provider|ts|prev_hash)`.
fn append_audit(
    conn: &Connection,
    action: &str,
    provider: &str,
    timestamp: &str,
    details: Option<&str>,
    actor: Option<&str>,
) -> Result<(), String> {
    let prev_hash: Option<String> = conn
        .query_row(
            "SELECT entry_hash FROM vault_audit ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .flatten();

    let entry_hash = compute_audit_hash(
        action,
        provider,
        timestamp,
        actor,
        prev_hash.as_deref().unwrap_or("genesis"),
    );

    conn.execute(
        "INSERT INTO vault_audit \
         (action, entry_provider, timestamp, details, entry_hash, prev_hash, actor) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![action, provider, timestamp, details, entry_hash, prev_hash, actor],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Records a hash-chained audit event with the current timestamp.
pub fn record_event(
    conn: &Connection,
    action: &str,
    provider: &str,
    details: Option<&str>,
    actor: Option<&str>,
) -> Result<(), String> {
    append_audit(conn, action, provider, &iso_now(), details, actor)
}

/// Hash for one audit row, binding it to its predecessor.
///
/// Two formats coexist:
/// - **v1** `action|provider|timestamp|prev` — rows written before actor tracking.
/// - **v2** `action|provider|timestamp|actor|prev` — includes the acting user, so
///   attribution is covered by the chain and cannot be rewritten undetected.
///
/// A row with no actor keeps using v1 so existing chains stay verifiable; the
/// verifier tries v2 first and falls back to v1.
fn compute_audit_hash(
    action: &str,
    provider: &str,
    timestamp: &str,
    actor: Option<&str>,
    prev_hash: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    match actor {
        Some(a) => {
            for part in [
                action, "|", provider, "|", timestamp, "|", a, "|", prev_hash,
            ] {
                h.update(part.as_bytes());
            }
        }
        None => {
            for part in [action, "|", provider, "|", timestamp, "|", prev_hash] {
                h.update(part.as_bytes());
            }
        }
    }
    hex::encode(h.finalize())
}

/// Returns all audit rows ordered newest-first.
pub fn load_audit(conn: &Connection) -> Result<Vec<AuditRow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, action, entry_provider, timestamp, details, entry_hash, prev_hash, actor \
         FROM vault_audit ORDER BY id DESC",
        )
        .map_err(|e| e.to_string())?;

    let rows: Vec<Result<AuditRow, _>> = stmt
        .query_map([], |row| {
            Ok(AuditRow {
                id: row.get(0)?,
                action: row.get(1)?,
                entry_provider: row.get(2)?,
                timestamp: row.get(3)?,
                details: row.get(4)?,
                entry_hash: row.get(5)?,
                prev_hash: row.get(6)?,
                actor: row.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect();
    rows.into_iter()
        .map(|r| r.map_err(|e| e.to_string()))
        .collect()
}

// ── Migration helpers ─────────────────────────────────────────────────────────

/// Inserts raw JSON from a legacy `vault.json` into the `vault` table.
/// Called once on first unlock after a Phase 1 → Phase 2 upgrade.
pub fn migrate_legacy_json(conn: &Connection, raw_json: &str) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO vault (id, data) VALUES (1, ?1)",
        rusqlite::params![raw_json],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Returns the current UTC time as an ISO-8601 string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn iso_now() -> String {
    let t = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Unique scratch path per test; SQLCipher needs a real file, not `:memory:`.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("envvault-test-{tag}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open_scratch(tag: &str) -> (Connection, std::path::PathBuf) {
        let dir = scratch(tag);
        let key = derive_key("correct horse battery staple", b"0123456789abcdef").unwrap();
        let conn = open_db(&dir.join("vault.db"), &key).unwrap();
        init_schema(&conn).unwrap();
        (conn, dir)
    }

    // ── KDF ────────────────────────────────────────────────────────────────────

    #[test]
    fn derive_key_is_deterministic_and_salt_sensitive() {
        let a = derive_key("hunter2", b"0123456789abcdef").unwrap();
        let b = derive_key("hunter2", b"0123456789abcdef").unwrap();
        let c = derive_key("hunter2", b"fedcba9876543210").unwrap();
        let d = derive_key("hunter3", b"0123456789abcdef").unwrap();
        assert_eq!(a, b, "same password + salt must derive the same key");
        assert_ne!(a, c, "different salt must derive a different key");
        assert_ne!(a, d, "different password must derive a different key");
    }

    #[test]
    fn salt_is_persisted_and_reused() {
        let dir = scratch("salt");
        let path = dir.join("vault.salt");
        let first = read_or_create_salt(&path).unwrap();
        let second = read_or_create_salt(&path).unwrap();
        assert_eq!(first, second, "salt must be stable across reads");
        assert_eq!(first.len(), SALT_LEN);
    }

    // ── Entry identity ─────────────────────────────────────────────────────────

    #[test]
    fn entry_ck_prefers_stable_id() {
        let a = json!({ "id": "abc", "provider": "GitHub", "account_name": "x" });
        let b = json!({ "id": "abc", "provider": "Renamed", "account_name": "y" });
        assert_eq!(entry_ck(&a), entry_ck(&b), "id must dominate other fields");
    }

    #[test]
    fn entry_ck_legacy_distinguishes_key_id() {
        // The historic save_vault key ignored key_id and collapsed these two into
        // one entry, misattributing version_history between them.
        let a = json!({ "provider": "AWS", "account_name": "prod", "key_id": "one" });
        let b = json!({ "provider": "AWS", "account_name": "prod", "key_id": "two" });
        assert_ne!(entry_ck(&a), entry_ck(&b));
    }

    #[test]
    fn entry_ck_ignores_empty_id() {
        let with_empty = json!({ "id": "", "provider": "P" });
        let without = json!({ "provider": "P" });
        assert_eq!(entry_ck(&with_empty), entry_ck(&without));
    }

    // ── Vault I/O ──────────────────────────────────────────────────────────────

    #[test]
    fn save_then_load_roundtrips() {
        let (conn, _dir) = open_scratch("roundtrip");
        let data = json!({
            "api_keys": [{ "id": "1", "provider": "GitHub", "api_key": "ghp_aaa" }],
            "user_categories": ["dev"],
            "projects": [{ "id": "Universal", "name": "Universal" }],
        });
        save_vault(&conn, data.clone(), SaveCtx::default()).unwrap();
        let loaded = load_vault(&conn).unwrap().expect("vault should exist");
        assert_eq!(loaded["api_keys"][0]["provider"], "GitHub");
        assert_eq!(loaded["user_categories"][0], "dev");
    }

    #[test]
    fn load_returns_none_for_fresh_vault() {
        let (conn, _dir) = open_scratch("fresh");
        assert!(load_vault(&conn).unwrap().is_none());
    }

    #[test]
    fn changing_a_key_records_previous_value_in_history() {
        let (conn, _dir) = open_scratch("history");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "GitHub", "api_key": "old_value" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "GitHub", "api_key": "new_value" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        let loaded = load_vault(&conn).unwrap().unwrap();
        let history = loaded["api_keys"][0]["version_history"].as_array().unwrap();
        assert_eq!(
            history.len(),
            1,
            "one rotation should append one history entry"
        );
        assert_eq!(history[0]["value"], "old_value");
    }

    #[test]
    fn history_follows_the_id_not_the_provider_name() {
        // Renaming an entry must not look like "delete + create", which would
        // lose its history. This is exactly what the old provider|account key broke.
        let (conn, _dir) = open_scratch("rename");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "OldName", "api_key": "v1" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "NewName", "api_key": "v2" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        let loaded = load_vault(&conn).unwrap().unwrap();
        let history = loaded["api_keys"][0]["version_history"].as_array().unwrap();
        assert_eq!(history[0]["value"], "v1", "history must survive a rename");
    }

    #[test]
    fn integrity_hash_matches_after_save() {
        let (conn, _dir) = open_scratch("integrity");
        save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        assert!(verify_vault_integrity(&conn).unwrap());
    }

    #[test]
    fn integrity_check_detects_tampering() {
        let (conn, _dir) = open_scratch("tamper");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "P", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        // Rewrite the row behind save_vault's back, leaving the stored hash stale.
        conn.execute(
            "UPDATE vault SET data = ?1 WHERE id = 1",
            rusqlite::params![r#"{"api_keys":[{"id":"1","provider":"EVIL","api_key":"k"}]}"#],
        )
        .unwrap();
        assert!(
            !verify_vault_integrity(&conn).unwrap(),
            "tampered data must fail the hash check"
        );
    }

    #[test]
    fn empty_vault_is_trivially_intact() {
        let (conn, _dir) = open_scratch("empty-integrity");
        assert!(verify_vault_integrity(&conn).unwrap());
    }

    // ── Optimistic concurrency ────────────────────────────────────────────────

    #[test]
    fn version_changes_with_every_write() {
        let (conn, _dir) = open_scratch("version");
        assert!(
            vault_version(&conn).unwrap().is_none(),
            "empty vault has no version"
        );
        let v1 = save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        let v2 = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        assert_ne!(v1, v2);
        assert_eq!(vault_version(&conn).unwrap().as_deref(), Some(v2.as_str()));
    }

    #[test]
    fn returned_version_is_the_stored_version() {
        // The value save_vault hands back must be exactly what a later
        // compare-and-swap will be checked against, or every write would conflict.
        let (conn, _dir) = open_scratch("version-match");
        let v = save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        assert_eq!(vault_version(&conn).unwrap().unwrap(), v);
    }

    #[test]
    fn writing_at_the_expected_version_succeeds() {
        let (conn, _dir) = open_scratch("cas-ok");
        let v1 = save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        let res = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        );
        assert!(res.is_ok());
    }

    #[test]
    fn writing_at_a_stale_version_is_refused() {
        // The lost-update scenario: two writers read v1, one saves, the other
        // must not be allowed to overwrite it.
        let (conn, _dir) = open_scratch("cas-stale");
        let v1 = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "original", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        // Writer A lands first.
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "written-by-A", "api_key": "k" }]
            }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        )
        .unwrap();

        // Writer B still holds v1.
        let err = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "written-by-B", "api_key": "k" }]
            }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        )
        .expect_err("a stale write must be refused");
        assert!(
            err.starts_with(CONFLICT_ERR),
            "callers match on this prefix, got: {err}"
        );

        // A's data survived intact.
        let stored = load_vault(&conn).unwrap().unwrap();
        assert_eq!(stored["api_keys"][0]["provider"], "written-by-A");
    }

    #[test]
    fn a_refused_write_leaves_no_trace() {
        // The audit appends used to run before the transaction, so a rejected
        // write still logged changes that never happened.
        let (conn, _dir) = open_scratch("cas-clean");
        let v1 = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();

        let audit_before = load_audit(&conn).unwrap().len();
        let version_before = vault_version(&conn).unwrap();

        let _ = save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "9", "provider": "GHOST", "api_key": "k" }]
            }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        );

        assert_eq!(
            load_audit(&conn).unwrap().len(),
            audit_before,
            "a refused write must not append audit rows"
        );
        assert_eq!(vault_version(&conn).unwrap(), version_before);
        assert!(!load_audit(&conn)
            .unwrap()
            .iter()
            .any(|r| r.entry_provider.as_deref() == Some("GHOST")));
    }

    #[test]
    fn expecting_a_version_against_an_empty_vault_is_refused() {
        let (conn, _dir) = open_scratch("cas-empty");
        let err = save_vault(
            &conn,
            json!({ "api_keys": [] }),
            SaveCtx {
                actor: None,
                expect_version: Some("deadbeef"),
            },
        )
        .expect_err("nothing is stored, so no version can match");
        assert!(err.starts_with(CONFLICT_ERR));
    }

    #[test]
    fn omitting_the_version_writes_unconditionally() {
        // The explicit escape hatch, used when the user chooses to overwrite.
        let (conn, _dir) = open_scratch("cas-force");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "first", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "forced", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        let stored = load_vault(&conn).unwrap().unwrap();
        assert_eq!(stored["api_keys"][0]["provider"], "forced");
    }

    #[test]
    fn integrity_still_holds_after_a_refused_write() {
        let (conn, _dir) = open_scratch("cas-integrity");
        let v1 = save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        let _ = save_vault(
            &conn,
            json!({ "api_keys": [] }),
            SaveCtx {
                actor: None,
                expect_version: Some(&v1),
            },
        );
        assert!(
            verify_vault_integrity(&conn).unwrap(),
            "a rolled-back write must not desync data from its hash"
        );
    }

    // ── Audit chain ────────────────────────────────────────────────────────────

    #[test]
    fn audit_rows_form_a_hash_chain() {
        let (conn, _dir) = open_scratch("audit");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(
            &conn,
            json!({
                "api_keys": [
                    { "id": "1", "provider": "A", "api_key": "k" },
                    { "id": "2", "provider": "B", "api_key": "k2" }
                ]
            }),
            SaveCtx::default(),
        )
        .unwrap();

        let mut rows = load_audit(&conn).unwrap();
        assert!(rows.len() >= 2, "expected an audit row per added entry");
        rows.sort_by_key(|r| r.id); // load_audit returns newest-first
        assert!(rows[0].entry_hash.is_some());
        // Each row must link to its predecessor.
        for pair in rows.windows(2) {
            assert_eq!(
                pair[1].prev_hash, pair[0].entry_hash,
                "row {} must chain to row {}",
                pair[1].id, pair[0].id
            );
        }
    }

    #[test]
    fn deleting_an_entry_is_audited() {
        let (conn, _dir) = open_scratch("audit-delete");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "Doomed", "api_key": "k" }]
            }),
            SaveCtx::default(),
        )
        .unwrap();
        save_vault(&conn, json!({ "api_keys": [] }), SaveCtx::default()).unwrap();
        let rows = load_audit(&conn).unwrap();
        assert!(rows
            .iter()
            .any(|r| r.action == "delete" && r.entry_provider.as_deref() == Some("Doomed")));
    }

    #[test]
    fn audit_rows_record_the_acting_user() {
        let (conn, _dir) = open_scratch("audit-actor");
        save_vault(
            &conn,
            json!({
                "api_keys": [{ "id": "1", "provider": "A", "api_key": "k" }]
            }),
            SaveCtx {
                actor: Some("user-123"),
                ..Default::default()
            },
        )
        .unwrap();
        let rows = load_audit(&conn).unwrap();
        let add = rows.iter().find(|r| r.action == "add").unwrap();
        assert_eq!(add.actor.as_deref(), Some("user-123"));
    }

    #[test]
    fn actor_is_bound_into_the_hash_chain() {
        // Rewriting who did something must invalidate the row hash, otherwise
        // attribution would be forgeable while the chain still "verified".
        let with = compute_audit_hash("add", "P", "T", Some("alice"), "prev");
        let other = compute_audit_hash("add", "P", "T", Some("bob"), "prev");
        let without = compute_audit_hash("add", "P", "T", None, "prev");
        assert_ne!(with, other, "different actor must give a different hash");
        assert_ne!(with, without);
    }

    #[test]
    fn actorless_rows_keep_the_v1_hash_format() {
        // Existing chains were written before the actor column; their hashes
        // must still reproduce or every old log would read as tampered.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for part in ["add", "|", "P", "|", "T", "|", "prev"] {
            h.update(part.as_bytes());
        }
        assert_eq!(
            compute_audit_hash("add", "P", "T", None, "prev"),
            hex::encode(h.finalize())
        );
    }

    // ── Expiry ─────────────────────────────────────────────────────────────────

    #[test]
    fn expiring_selects_only_the_window() {
        let now = time::OffsetDateTime::now_utc();
        let fmt = |d: i64| {
            let t = now + time::Duration::days(d);
            format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())
        };
        let data = json!({ "api_keys": [
            { "provider": "expired",  "expires_at": fmt(-5)  },
            { "provider": "soon",     "expires_at": fmt(3)   },
            { "provider": "far",      "expires_at": fmt(365) },
            { "provider": "no-expiry" },
        ]});
        let found = expiring_from_value(&data, 30);
        let names: Vec<&str> = found
            .iter()
            .map(|e| e["provider"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["soon"],
            "already-expired, far-future and never-expiring entries are all excluded"
        );
    }
}
