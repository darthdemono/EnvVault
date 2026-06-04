//! vault-core — shared encryption, storage, and tooling for API Vault.
//!
//! Used by the Tauri desktop app, the HTTP server (`apiv-server`), and the CLI
//! (`apiv-cli`).  Has no dependency on Tauri; accepts `&Path` for all I/O.

use std::fs;
use std::path::Path;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use argon2::{Argon2, Algorithm, Version, Params};
pub use zeroize::Zeroize;

pub mod generators;
pub use generators::{generate_certificate, generate_ssh_keypair};

// ── Constants ──────────────────────────────────────────────────────────────────

pub const SALT_LEN: usize = 16;
pub const KEY_LEN:  usize = 32;

const A2_M_COST: u32 = 65_536;
const A2_T_COST: u32 = 3;
const A2_P_COST: u32 = 1;

/// In-memory AES-256 vault key.
pub type VaultKey = [u8; KEY_LEN];

// ── KDF ────────────────────────────────────────────────────────────────────────

/// Derives a 32-byte AES-256 key from `password` and `salt` using Argon2id
/// (m=65536 KiB, t=3, p=1 — OWASP 2023 recommendation).
pub fn derive_key(password: &str, salt: &[u8]) -> Result<VaultKey, String> {
    let params = Params::new(A2_M_COST, A2_T_COST, A2_P_COST, Some(KEY_LEN))
        .map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

/// Reads salt from `salt_path`; generates and writes a fresh 16-byte salt if absent.
pub fn read_or_create_salt(salt_path: &Path) -> Result<[u8; SALT_LEN], String> {
    if salt_path.exists() {
        let raw = fs::read(salt_path).map_err(|e| e.to_string())?;
        raw.try_into().map_err(|_| "vault.salt is corrupt (wrong length)".to_string())
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
    ).map_err(|e| e.to_string())?;
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key)))
        .map_err(|e| e.to_string())?;
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|_| "Wrong master password".to_string())?;
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
         );"
    ).map_err(|e| e.to_string())?;
    // Idempotent migration: add hash-chain columns if absent.
    let _ = conn.execute_batch("ALTER TABLE vault_audit ADD COLUMN entry_hash TEXT;");
    let _ = conn.execute_batch("ALTER TABLE vault_audit ADD COLUMN prev_hash  TEXT;");
    Ok(())
}

// ── Vault I/O ─────────────────────────────────────────────────────────────────

/// Loads the raw vault JSON from an open connection.
pub fn load_vault(conn: &Connection) -> Result<Option<serde_json::Value>, String> {
    let raw: Option<String> = conn
        .query_row("SELECT data FROM vault WHERE id = 1", [], |row| row.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    match raw {
        None    => Ok(None),
        Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| e.to_string()),
    }
}

/// Serialises `data` to the vault, updating `version_history` on key changes
/// and appending to the `vault_audit` hash chain.
pub fn save_vault(conn: &Connection, data: serde_json::Value) -> Result<(), String> {
    use std::collections::{HashMap, HashSet};

    let now_str = iso_now();

    let existing: Option<serde_json::Value> = conn
        .query_row(
            "SELECT data FROM vault WHERE id = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .and_then(|s| serde_json::from_str(&s).ok());

    let old_map: HashMap<String, serde_json::Value> = existing
        .as_ref()
        .and_then(|v| v.get("api_keys"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|e| {
            let p = e.get("provider")?.as_str()?.to_string();
            let a = e.get("account_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            Some((format!("{}|{}", p, a), e.clone()))
        }).collect())
        .unwrap_or_default();

    let new_keys: HashSet<String> = data
        .get("api_keys")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|e| {
            let p = e.get("provider")?.as_str()?.to_string();
            let a = e.get("account_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            Some(format!("{}|{}", p, a))
        }).collect())
        .unwrap_or_default();

    for (ck, old_e) in &old_map {
        if !new_keys.contains(ck) {
            let provider = old_e.get("provider").and_then(|v| v.as_str()).unwrap_or("");
            append_audit(conn, "delete", provider, &now_str, None)?;
        }
    }

    let mut new_data = data;
    if let Some(arr) = new_data.get_mut("api_keys").and_then(|v| v.as_array_mut()) {
        for entry in arr.iter_mut() {
            let provider = entry.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let account  = entry.get("account_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let ck       = format!("{}|{}", provider, account);

            if let Some(old_e) = old_map.get(&ck) {
                let new_val = entry.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
                let old_val = old_e.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
                if new_val != old_val && !old_val.is_empty() {
                    let mut history: Vec<serde_json::Value> = entry
                        .get("version_history").and_then(|v| v.as_array()).cloned()
                        .unwrap_or_else(|| old_e.get("version_history")
                            .and_then(|v| v.as_array()).cloned().unwrap_or_default());
                    history.insert(0, serde_json::json!({ "value": old_val, "saved_at": now_str }));
                    history.truncate(50);
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert("version_history".to_string(), serde_json::Value::Array(history));
                    }
                    append_audit(conn, "update", &provider, &now_str, Some("api_key rotated"))?;
                }
            } else {
                append_audit(conn, "add", &provider, &now_str, None)?;
            }
        }
    }

    let raw = serde_json::to_string(&new_data).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO vault (id, data) VALUES (1, ?1)",
        rusqlite::params![raw],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

/// Returns vault entries whose `expires_at` date falls within `within_days` days
/// from today (inclusive of today, exclusive of entries already expired).
///
/// Uses lexicographic YYYY-MM-DD comparison — no parsing feature required.
pub fn get_expiring_entries(conn: &Connection, within_days: u32) -> Result<Vec<serde_json::Value>, String> {
    let data = load_vault(conn)?;
    let now    = time::OffsetDateTime::now_utc();
    let cutoff = now + time::Duration::days(within_days as i64);
    let today_str  = fmt_date(&now);
    let cutoff_str = fmt_date(&cutoff);

    let result = data
        .and_then(|v| v.get("api_keys").and_then(|k| k.as_array()).cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| {
            entry.get("expires_at").and_then(|v| v.as_str()).map_or(false, |s| {
                let d = &s[..s.len().min(10)];
                d >= today_str.as_str() && d <= cutoff_str.as_str()
            })
        })
        .collect();
    Ok(result)
}

fn fmt_date(dt: &time::OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day())
}

// ── Audit log ─────────────────────────────────────────────────────────────────

/// A single audit log row, including the hash-chain fields.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditRow {
    pub id:             i64,
    pub action:         String,
    pub entry_provider: Option<String>,
    pub timestamp:      String,
    pub details:        Option<String>,
    pub entry_hash:     Option<String>,
    pub prev_hash:      Option<String>,
}

/// Appends an audit entry and computes `entry_hash = SHA256(action|provider|ts|prev_hash)`.
fn append_audit(
    conn:      &Connection,
    action:    &str,
    provider:  &str,
    timestamp: &str,
    details:   Option<&str>,
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
        action, provider, timestamp,
        prev_hash.as_deref().unwrap_or("genesis"),
    );

    conn.execute(
        "INSERT INTO vault_audit \
         (action, entry_provider, timestamp, details, entry_hash, prev_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![action, provider, timestamp, details, entry_hash, prev_hash],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

fn compute_audit_hash(action: &str, provider: &str, timestamp: &str, prev_hash: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    for part in [action, "|", provider, "|", timestamp, "|", prev_hash] {
        h.update(part.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Returns all audit rows ordered newest-first.
pub fn load_audit(conn: &Connection) -> Result<Vec<AuditRow>, String> {
    let mut stmt = conn.prepare(
        "SELECT id, action, entry_provider, timestamp, details, entry_hash, prev_hash \
         FROM vault_audit ORDER BY id DESC"
    ).map_err(|e| e.to_string())?;

    let rows: Vec<Result<AuditRow, _>> = stmt.query_map([], |row| Ok(AuditRow {
        id:             row.get(0)?,
        action:         row.get(1)?,
        entry_provider: row.get(2)?,
        timestamp:      row.get(3)?,
        details:        row.get(4)?,
        entry_hash:     row.get(5)?,
        prev_hash:      row.get(6)?,
    }))
    .map_err(|e| e.to_string())?
    .collect();
    rows.into_iter().map(|r| r.map_err(|e| e.to_string())).collect()
}

// ── Migration helpers ─────────────────────────────────────────────────────────

/// Inserts raw JSON from a legacy `vault.json` into the `vault` table.
/// Called once on first unlock after a Phase 1 → Phase 2 upgrade.
pub fn migrate_legacy_json(conn: &Connection, raw_json: &str) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO vault (id, data) VALUES (1, ?1)",
        rusqlite::params![raw_json],
    ).map(|_| ()).map_err(|e| e.to_string())
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Returns the current UTC time as an ISO-8601 string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn iso_now() -> String {
    let t = time::OffsetDateTime::now_utc();
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(), t.month() as u8, t.day(),
        t.hour(), t.minute(), t.second())
}
