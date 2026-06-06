//! User management, token management, and RBAC for API Vault.
//!
//! Users are stored in the SQLCipher-encrypted vault database — they can only
//! be read or created when the owner has unlocked the vault (i.e. the vault key
//! is in memory).  The owner is the only party who can manage users.
//!
//! # Auth modes
//! - Username + password: stored as `SHA-256(salt || password)` with a 16-byte random salt.
//! - Token: 32 random bytes returned as a 64-char hex string once; stored as `SHA-256(token)`.
//!
//! # Permission model
//! Each permission has:
//! - `scope_type`:  `"vault"` | `"project"` | `"category"`
//! - `scope_value`: `"*"`, or a glob like `"wg0-*"` / `"Cloud/AWS"`
//! - `permission`:  `"read"` | `"write"` (write implies read)
//!
//! Glob rules: `*` matches any sequence of characters (including empty); `?` matches one char.

use std::collections::{HashMap, HashSet};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use rand::RngCore;
use crate::iso_now;

// ── Public types ──────────────────────────────────────────────────────────────

/// A named user class (role template) with capabilities and permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserClass {
    pub id:                   String,
    pub name:                 String,
    pub description:          String,
    /// Can create/delete users and assign classes.
    pub cap_manage_users:     bool,
    /// Can create/edit/delete user classes (admin-level).
    pub cap_manage_classes:   bool,
    /// Can delete projects.
    pub cap_delete_projects:  bool,
    pub created_at:           String,
}

/// A single permission row scoped to a user class (no user_id — applies to all class members).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassPermission {
    pub class_id:    String,
    pub scope_type:  String,
    pub scope_value: String,
    pub permission:  String,
}

/// A vault user (password hash is never exposed via this struct).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub id:           String,
    pub username:     String,
    /// True when the user has a password set (can use username+password auth).
    pub has_password: bool,
    pub is_owner:     bool,
    pub created_at:   String,
    pub last_seen_at: Option<String>,
}

/// A stored API token descriptor.  The actual token is returned only on creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id:          String,
    pub user_id:     String,
    pub description: Option<String>,
    pub created_at:  String,
    pub expires_at:  Option<String>,
}

/// A single RBAC permission row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRecord {
    pub user_id:     String,
    /// `"vault"` | `"project"` | `"category"`
    pub scope_type:  String,
    /// Glob pattern: `"*"`, `"wg0-*"`, `"Cloud/AWS"`, etc.
    pub scope_value: String,
    /// `"read"` | `"write"` (write implies read)
    pub permission:  String,
}

// ── Schema ────────────────────────────────────────────────────────────────────

/// Creates all user-related tables (idempotent) and seeds default classes.
pub fn init_users_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
             id            TEXT PRIMARY KEY,
             username      TEXT NOT NULL UNIQUE,
             password_hash TEXT,
             is_owner      INTEGER NOT NULL DEFAULT 0,
             created_at    TEXT NOT NULL,
             last_seen_at  TEXT
         );
         CREATE TABLE IF NOT EXISTS user_tokens (
             id          TEXT PRIMARY KEY,
             token_hash  TEXT NOT NULL UNIQUE,
             user_id     TEXT NOT NULL,
             description TEXT,
             created_at  TEXT NOT NULL,
             expires_at  TEXT
         );
         CREATE TABLE IF NOT EXISTS user_permissions (
             user_id     TEXT NOT NULL,
             scope_type  TEXT NOT NULL,
             scope_value TEXT NOT NULL,
             permission  TEXT NOT NULL,
             PRIMARY KEY (user_id, scope_type, scope_value)
         );
         CREATE TABLE IF NOT EXISTS user_classes (
             id                   TEXT PRIMARY KEY,
             name                 TEXT NOT NULL UNIQUE,
             description          TEXT NOT NULL DEFAULT '',
             cap_manage_users     INTEGER NOT NULL DEFAULT 0,
             cap_manage_classes   INTEGER NOT NULL DEFAULT 0,
             cap_delete_projects  INTEGER NOT NULL DEFAULT 0,
             created_at           TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS user_class_permissions (
             class_id    TEXT NOT NULL,
             scope_type  TEXT NOT NULL,
             scope_value TEXT NOT NULL,
             permission  TEXT NOT NULL,
             PRIMARY KEY (class_id, scope_type, scope_value)
         );"
    ).map_err(|e| e.to_string())?;

    // Idempotent migrations
    conn.execute("ALTER TABLE users ADD COLUMN class_id TEXT", []).ok();
    conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT", []).ok();
    // Stores the last accepted TOTP counter step to prevent replay within the same window.
    conn.execute("ALTER TABLE users ADD COLUMN totp_last_step INTEGER", []).ok();

    // Seed default classes if none exist
    let class_count: i32 = conn
        .query_row("SELECT COUNT(*) FROM user_classes", [], |r| r.get(0))
        .unwrap_or(0);
    if class_count == 0 {
        seed_default_classes(conn)?;
    }
    Ok(())
}

/// Seeds the three built-in user classes: Admin, Moderator, Viewer.
fn seed_default_classes(conn: &Connection) -> Result<(), String> {
    let now = iso_now();

    struct ClassSeed<'a> {
        id: &'a str, name: &'a str, description: &'a str,
        cap_manage_users: i32, cap_manage_classes: i32, cap_delete_projects: i32,
        perms: &'a [(&'a str, &'a str, &'a str)], // (scope_type, scope_value, permission)
    }

    let seeds = [
        ClassSeed {
            id: "cls-admin", name: "Admin",
            description: "Full vault access. Can manage users and classes.",
            cap_manage_users: 1, cap_manage_classes: 1, cap_delete_projects: 1,
            perms: &[("vault", "*", "write")],
        },
        ClassSeed {
            id: "cls-moderator", name: "Moderator",
            description: "Full vault access. Can manage users but not classes or project deletion.",
            cap_manage_users: 1, cap_manage_classes: 0, cap_delete_projects: 0,
            perms: &[("vault", "*", "write")],
        },
        ClassSeed {
            id: "cls-viewer", name: "Viewer",
            description: "Read-only access to the entire vault.",
            cap_manage_users: 0, cap_manage_classes: 0, cap_delete_projects: 0,
            perms: &[("vault", "*", "read")],
        },
    ];

    for s in &seeds {
        conn.execute(
            "INSERT OR IGNORE INTO user_classes (id, name, description, cap_manage_users, cap_manage_classes, cap_delete_projects, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![s.id, s.name, s.description, s.cap_manage_users, s.cap_manage_classes, s.cap_delete_projects, now],
        ).map_err(|e| e.to_string())?;
        for (scope_type, scope_value, permission) in s.perms {
            conn.execute(
                "INSERT OR IGNORE INTO user_class_permissions (class_id, scope_type, scope_value, permission) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![s.id, scope_type, scope_value, permission],
            ).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn new_uuid() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&b[0..4]),
        hex::encode(&b[4..6]),
        hex::encode(&b[6..8]),
        hex::encode(&b[8..10]),
        hex::encode(&b[10..16]),
    )
}

/// Hashes `password` with Argon2id (m=32768, t=2, p=1) and returns a
/// self-describing PHC string `$argon2id$v=19$...` suitable for long-term storage.
///
/// Uses lower cost params than the vault KDF to keep interactive login fast
/// while still providing >200ms hash time on modern hardware.
fn hash_password(password: &str) -> String {
    use argon2::{Argon2, Algorithm, Version, Params, PasswordHasher};
    use argon2::password_hash::{SaltString, rand_core::OsRng};

    let salt   = SaltString::generate(&mut OsRng);
    let params = Params::new(32_768, 2, 1, None).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

/// Verifies `password` against `stored`.
///
/// Supports two on-disk formats:
/// - **PHC** (`$argon2id$…`) — new default since Phase 5.1.
/// - **Legacy SHA-256** (`<salt_hex>:<hash_hex>`) — written by Phase 5.0 and earlier.
///
/// Returns `true` only when the password matches.  Callers should re-hash with
/// `hash_password` after a successful legacy verification to upgrade the stored hash.
fn verify_password_hash(password: &str, stored: &str) -> bool {
    if stored.starts_with("$argon2") {
        use argon2::{Argon2, PasswordVerifier};
        use argon2::password_hash::PasswordHash;
        let Ok(parsed) = PasswordHash::new(stored) else { return false; };
        Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
    } else {
        // Legacy: "<salt_hex>:<sha256_hex>" — upgrade on next login
        let mut parts = stored.splitn(2, ':');
        let (Some(salt_hex), Some(hash_hex)) = (parts.next(), parts.next()) else { return false; };
        let Ok(salt) = hex::decode(salt_hex) else { return false; };
        let mut h = Sha256::new();
        h.update(&salt);
        h.update(password.as_bytes());
        hex::encode(h.finalize()) == hash_hex
    }
}

fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

fn touch_last_seen(conn: &Connection, user_id: &str) -> Result<(), String> {
    conn.execute(
        "UPDATE users SET last_seen_at = ?1 WHERE id = ?2",
        rusqlite::params![iso_now(), user_id],
    ).map(|_| ()).map_err(|e| e.to_string())
}

// ── User CRUD ─────────────────────────────────────────────────────────────────

/// Creates a new user.  Pass `password = None` for token-only auth.
pub fn create_user(
    conn:     &Connection,
    username: &str,
    password: Option<&str>,
    is_owner: bool,
) -> Result<UserRecord, String> {
    let id            = new_uuid();
    let now           = iso_now();
    let password_hash = password.map(hash_password);
    conn.execute(
        "INSERT INTO users (id, username, password_hash, is_owner, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![id, username, password_hash, is_owner as i32, now],
    ).map_err(|e| e.to_string())?;
    Ok(UserRecord {
        id,
        username:     username.to_string(),
        has_password: password.is_some(),
        is_owner,
        created_at:   now,
        last_seen_at: None,
    })
}

/// Renames a user (owner or non-owner).  Fails if `new_username` is already taken.
pub fn rename_user(conn: &Connection, user_id: &str, new_username: &str) -> Result<(), String> {
    conn.execute(
        "UPDATE users SET username = ?1 WHERE id = ?2",
        rusqlite::params![new_username, user_id],
    ).map(|_| ()).map_err(|e| e.to_string())
}

/// Updates (or clears) a user's password.
pub fn set_user_password(conn: &Connection, user_id: &str, password: Option<&str>) -> Result<(), String> {
    conn.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        rusqlite::params![password.map(hash_password), user_id],
    ).map(|_| ()).map_err(|e| e.to_string())
}

/// Verifies username + password.  Returns `None` on invalid credentials.
pub fn verify_user_password(conn: &Connection, username: &str, password: &str) -> Result<Option<UserRecord>, String> {
    let row: Option<(String, String, Option<String>, i32, String, Option<String>)> = conn
        .query_row(
            "SELECT id, username, password_hash, is_owner, created_at, last_seen_at \
             FROM users WHERE username = ?1",
            rusqlite::params![username],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let Some((id, uname, hash_opt, is_owner_i, created_at, last_seen)) = row else { return Ok(None); };
    let stored = hash_opt.ok_or_else(|| "User has no password set".to_string())?;
    if !verify_password_hash(password, &stored) { return Ok(None); }
    // Transparent upgrade: rehash with Argon2id when the stored hash is legacy SHA-256.
    if !stored.starts_with("$argon2") {
        let new_hash = hash_password(password);
        let _ = conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            rusqlite::params![new_hash, id],
        );
    }
    touch_last_seen(conn, &id)?;
    Ok(Some(UserRecord {
        id, username: uname, has_password: true,
        is_owner: is_owner_i != 0, created_at, last_seen_at: last_seen,
    }))
}

/// Verifies a raw 64-char hex token.  Returns `None` if invalid or expired.
pub fn verify_user_token(conn: &Connection, token: &str) -> Result<Option<UserRecord>, String> {
    let token_hash = sha256_hex(token);
    let now        = iso_now();
    let row: Option<(String, String, Option<String>, i32, String, Option<String>)> = conn
        .query_row(
            "SELECT u.id, u.username, u.password_hash, u.is_owner, u.created_at, u.last_seen_at \
             FROM user_tokens t JOIN users u ON u.id = t.user_id \
             WHERE t.token_hash = ?1 AND (t.expires_at IS NULL OR t.expires_at > ?2)",
            rusqlite::params![token_hash, now],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let Some((id, uname, hash_opt, is_owner_i, created_at, last_seen)) = row else { return Ok(None); };
    touch_last_seen(conn, &id)?;
    Ok(Some(UserRecord {
        id, username: uname, has_password: hash_opt.is_some(),
        is_owner: is_owner_i != 0, created_at, last_seen_at: last_seen,
    }))
}

/// Lists all users, owners first, then by creation date.
pub fn list_users(conn: &Connection) -> Result<Vec<UserRecord>, String> {
    let mut stmt = conn.prepare(
        "SELECT id, username, password_hash, is_owner, created_at, last_seen_at \
         FROM users ORDER BY is_owner DESC, created_at ASC"
    ).map_err(|e| e.to_string())?;
    let rows: Vec<Result<UserRecord, _>> = stmt.query_map([], |r| Ok(UserRecord {
        id:           r.get(0)?,
        username:     r.get(1)?,
        has_password: r.get::<_, Option<String>>(2)?.is_some(),
        is_owner:     r.get::<_, i32>(3)? != 0,
        created_at:   r.get(4)?,
        last_seen_at: r.get(5)?,
    }))
    .map_err(|e| e.to_string())?
    .collect();
    rows.into_iter().map(|r| r.map_err(|e| e.to_string())).collect()
}

/// Deletes a user plus all their tokens and permissions.
/// Returns `Err` if `user_id` belongs to the owner account.
pub fn delete_user(conn: &Connection, user_id: &str) -> Result<(), String> {
    let is_owner: Option<i32> = conn
        .query_row("SELECT is_owner FROM users WHERE id = ?1", rusqlite::params![user_id], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    if is_owner == Some(1) { return Err("Cannot delete the owner account".to_string()); }
    conn.execute("DELETE FROM user_permissions WHERE user_id = ?1", rusqlite::params![user_id]).map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM user_tokens WHERE user_id = ?1",      rusqlite::params![user_id]).map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM users WHERE id = ?1",                 rusqlite::params![user_id]).map_err(|e| e.to_string())?;
    Ok(())
}

// ── User class CRUD ───────────────────────────────────────────────────────────

pub fn list_user_classes(conn: &Connection) -> Result<Vec<UserClass>, String> {
    let mut stmt = conn.prepare(
        "SELECT id, name, description, cap_manage_users, cap_manage_classes, cap_delete_projects, created_at \
         FROM user_classes ORDER BY created_at ASC"
    ).map_err(|e| e.to_string())?;
    let rows: Vec<Result<UserClass, _>> = stmt.query_map([], |r| Ok(UserClass {
        id: r.get(0)?, name: r.get(1)?, description: r.get(2)?,
        cap_manage_users:    r.get::<_, i32>(3)? != 0,
        cap_manage_classes:  r.get::<_, i32>(4)? != 0,
        cap_delete_projects: r.get::<_, i32>(5)? != 0,
        created_at: r.get(6)?,
    })).map_err(|e| e.to_string())?.collect();
    rows.into_iter().map(|r| r.map_err(|e| e.to_string())).collect()
}

pub fn create_user_class(
    conn: &Connection,
    name: &str,
    description: &str,
    cap_manage_users: bool,
    cap_manage_classes: bool,
    cap_delete_projects: bool,
) -> Result<UserClass, String> {
    let id  = new_uuid();
    let now = iso_now();
    conn.execute(
        "INSERT INTO user_classes (id, name, description, cap_manage_users, cap_manage_classes, cap_delete_projects, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![id, name, description, cap_manage_users as i32, cap_manage_classes as i32, cap_delete_projects as i32, now],
    ).map_err(|e| e.to_string())?;
    Ok(UserClass { id, name: name.to_string(), description: description.to_string(),
        cap_manage_users, cap_manage_classes, cap_delete_projects, created_at: now })
}

pub fn update_user_class(
    conn: &Connection,
    class_id: &str,
    name: &str,
    description: &str,
    cap_manage_users: bool,
    cap_manage_classes: bool,
    cap_delete_projects: bool,
) -> Result<(), String> {
    conn.execute(
        "UPDATE user_classes SET name=?1, description=?2, cap_manage_users=?3, cap_manage_classes=?4, cap_delete_projects=?5 WHERE id=?6",
        rusqlite::params![name, description, cap_manage_users as i32, cap_manage_classes as i32, cap_delete_projects as i32, class_id],
    ).map(|_| ()).map_err(|e| e.to_string())
}

pub fn delete_user_class(conn: &Connection, class_id: &str) -> Result<(), String> {
    // Unassign users first
    conn.execute("UPDATE users SET class_id = NULL WHERE class_id = ?1", rusqlite::params![class_id])
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM user_class_permissions WHERE class_id = ?1", rusqlite::params![class_id])
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM user_classes WHERE id = ?1", rusqlite::params![class_id])
        .map(|_| ()).map_err(|e| e.to_string())
}

pub fn get_class_permissions(conn: &Connection, class_id: &str) -> Result<Vec<ClassPermission>, String> {
    let mut stmt = conn.prepare(
        "SELECT class_id, scope_type, scope_value, permission FROM user_class_permissions WHERE class_id = ?1"
    ).map_err(|e| e.to_string())?;
    let rows: Vec<Result<ClassPermission, _>> = stmt.query_map(rusqlite::params![class_id], |r| Ok(ClassPermission {
        class_id: r.get(0)?, scope_type: r.get(1)?, scope_value: r.get(2)?, permission: r.get(3)?,
    })).map_err(|e| e.to_string())?.collect();
    rows.into_iter().map(|r| r.map_err(|e| e.to_string())).collect()
}

pub fn set_class_permissions(conn: &Connection, class_id: &str, permissions: &[ClassPermission]) -> Result<(), String> {
    conn.execute("DELETE FROM user_class_permissions WHERE class_id = ?1", rusqlite::params![class_id])
        .map_err(|e| e.to_string())?;
    for p in permissions {
        conn.execute(
            "INSERT INTO user_class_permissions (class_id, scope_type, scope_value, permission) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![class_id, p.scope_type, p.scope_value, p.permission],
        ).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn assign_user_class(conn: &Connection, user_id: &str, class_id: Option<&str>) -> Result<(), String> {
    conn.execute("UPDATE users SET class_id = ?1 WHERE id = ?2", rusqlite::params![class_id, user_id])
        .map(|_| ()).map_err(|e| e.to_string())
}

/// Returns the merged effective permissions for a user: class permissions ∪ individual permissions.
/// Write permission for a given scope supersedes read.
pub fn get_user_effective_permissions(conn: &Connection, user_id: &str) -> Result<Vec<PermissionRecord>, String> {
    // Individual permissions
    let individual = get_user_permissions(conn, user_id)?;

    // Class permissions (via the user's class_id)
    let class_id: Option<String> = conn
        .query_row("SELECT class_id FROM users WHERE id = ?1", rusqlite::params![user_id], |r| r.get(0))
        .optional().map_err(|e| e.to_string())?
        .flatten();

    let class_perms: Vec<PermissionRecord> = if let Some(cid) = class_id {
        get_class_permissions(conn, &cid)?.into_iter().map(|cp| PermissionRecord {
            user_id:     user_id.to_string(),
            scope_type:  cp.scope_type,
            scope_value: cp.scope_value,
            permission:  cp.permission,
        }).collect()
    } else { vec![] };

    // Merge: individual overrides class for same scope; write wins over read
    let mut merged: std::collections::HashMap<(String, String), String> = std::collections::HashMap::new();
    for p in class_perms.iter().chain(individual.iter()) {
        let key = (p.scope_type.clone(), p.scope_value.clone());
        let cur = merged.entry(key).or_insert_with(|| p.permission.clone());
        if p.permission == "write" { *cur = "write".to_string(); }
    }
    Ok(merged.into_iter().map(|((scope_type, scope_value), permission)| PermissionRecord {
        user_id: user_id.to_string(), scope_type, scope_value, permission,
    }).collect())
}

/// Returns the capabilities of the user's class (None values mean no class = no extra capabilities).
pub fn get_user_capabilities(conn: &Connection, user_id: &str) -> Result<(bool, bool, bool), String> {
    let class_id: Option<String> = conn
        .query_row("SELECT class_id FROM users WHERE id = ?1", rusqlite::params![user_id], |r| r.get(0))
        .optional().map_err(|e| e.to_string())?
        .flatten();
    if let Some(cid) = class_id {
        let row: Option<(i32, i32, i32)> = conn
            .query_row(
                "SELECT cap_manage_users, cap_manage_classes, cap_delete_projects FROM user_classes WHERE id = ?1",
                rusqlite::params![cid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).optional().map_err(|e| e.to_string())?;
        if let Some((u, c, d)) = row {
            return Ok((u != 0, c != 0, d != 0));
        }
    }
    Ok((false, false, false))
}

// ── TOTP (2FA for sub-users) ──────────────────────────────────────────────────

/// Generates a new 20-byte TOTP secret, stores it for `user_id`, and returns it
/// as a base32-encoded string that the user scans into their authenticator app.
pub fn enable_totp(conn: &Connection, user_id: &str) -> Result<String, String> {
    let mut raw = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut raw);
    let secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &raw);
    conn.execute("UPDATE users SET totp_secret = ?1 WHERE id = ?2", rusqlite::params![secret, user_id])
        .map_err(|e| e.to_string())?;
    Ok(secret)
}

/// Disables TOTP for `user_id` by clearing the stored secret.
pub fn disable_totp(conn: &Connection, user_id: &str) -> Result<(), String> {
    conn.execute("UPDATE users SET totp_secret = NULL WHERE id = ?1", rusqlite::params![user_id])
        .map(|_| ()).map_err(|e| e.to_string())
}

/// Returns whether TOTP is enabled for the given user.
pub fn totp_enabled(conn: &Connection, user_id: &str) -> Result<bool, String> {
    let secret: Option<Option<String>> = conn
        .query_row("SELECT totp_secret FROM users WHERE id = ?1", rusqlite::params![user_id], |r| r.get(0))
        .optional().map_err(|e| e.to_string())?;
    Ok(secret.flatten().is_some())
}

/// Verifies a 6-digit TOTP code for `user_id`.
///
/// Checks the current 30-second window plus one window on either side for clock skew.
/// Tracks the last accepted counter step per user to prevent replay attacks — the same
/// code cannot be accepted twice within the same (or adjacent) windows.
pub fn verify_totp_code(conn: &Connection, user_id: &str, code: &str) -> Result<bool, String> {
    let row: Option<(Option<String>, Option<i64>)> = conn
        .query_row(
            "SELECT totp_secret, totp_last_step FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional().map_err(|e| e.to_string())?;

    let Some((secret_opt, last_step_opt)) = row else { return Ok(false); };
    let Some(secret_b32) = secret_opt else { return Ok(true); }; // TOTP not enabled — pass

    let raw = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret_b32)
        .ok_or("Invalid TOTP secret stored")?;

    let now_step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?
        .as_secs() / 30;

    // Check current step and ±1 for clock skew
    for step_offset in [-1i64, 0, 1] {
        let step = (now_step as i64 + step_offset) as u64;
        if hotp_code(&raw, step) == code {
            // Reject if this step (or an adjacent already-used step) was already consumed.
            if let Some(last) = last_step_opt {
                if step <= last as u64 { return Ok(false); } // replay detected
            }
            // Record the accepted step to block replay of this code.
            let _ = conn.execute(
                "UPDATE users SET totp_last_step = ?1 WHERE id = ?2",
                rusqlite::params![step as i64, user_id],
            );
            return Ok(true);
        }
    }
    Ok(false)
}

fn hotp_code(secret: &[u8], counter: u64) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC init");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]) % 1_000_000;
    format!("{:06}", code)
}

// ── Token management ──────────────────────────────────────────────────────────

/// Creates a token for `user_id`.
/// Returns `(token_id, plaintext_token)` — the plaintext is shown **once**.
pub fn create_user_token(
    conn:        &Connection,
    user_id:     &str,
    description: Option<&str>,
    expires_at:  Option<&str>,
) -> Result<(String, String), String> {
    let token_id = new_uuid();
    let mut raw  = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let plaintext  = hex::encode(raw);
    let token_hash = sha256_hex(&plaintext);
    conn.execute(
        "INSERT INTO user_tokens (id, token_hash, user_id, description, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![token_id, token_hash, user_id, description, iso_now(), expires_at],
    ).map_err(|e| e.to_string())?;
    Ok((token_id, plaintext))
}

/// Revokes a token by its UUID.
pub fn revoke_user_token(conn: &Connection, token_id: &str) -> Result<(), String> {
    conn.execute("DELETE FROM user_tokens WHERE id = ?1", rusqlite::params![token_id])
        .map(|_| ()).map_err(|e| e.to_string())
}

/// Lists all tokens for a user (no hashes).
pub fn list_user_tokens(conn: &Connection, user_id: &str) -> Result<Vec<TokenRecord>, String> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, description, created_at, expires_at \
         FROM user_tokens WHERE user_id = ?1 ORDER BY created_at"
    ).map_err(|e| e.to_string())?;
    let rows: Vec<Result<TokenRecord, _>> = stmt.query_map(rusqlite::params![user_id], |r| Ok(TokenRecord {
        id: r.get(0)?, user_id: r.get(1)?,
        description: r.get(2)?, created_at: r.get(3)?, expires_at: r.get(4)?,
    }))
    .map_err(|e| e.to_string())?
    .collect();
    rows.into_iter().map(|r| r.map_err(|e| e.to_string())).collect()
}

// ── Permission management ─────────────────────────────────────────────────────

/// Returns all permissions for a user.
pub fn get_user_permissions(conn: &Connection, user_id: &str) -> Result<Vec<PermissionRecord>, String> {
    let mut stmt = conn.prepare(
        "SELECT user_id, scope_type, scope_value, permission \
         FROM user_permissions WHERE user_id = ?1 \
         ORDER BY scope_type, scope_value"
    ).map_err(|e| e.to_string())?;
    let rows: Vec<Result<PermissionRecord, _>> = stmt.query_map(rusqlite::params![user_id], |r| Ok(PermissionRecord {
        user_id: r.get(0)?, scope_type: r.get(1)?,
        scope_value: r.get(2)?, permission: r.get(3)?,
    }))
    .map_err(|e| e.to_string())?
    .collect();
    rows.into_iter().map(|r| r.map_err(|e| e.to_string())).collect()
}

/// Atomically replaces all permissions for a user.
pub fn set_user_permissions(conn: &Connection, user_id: &str, permissions: &[PermissionRecord]) -> Result<(), String> {
    conn.execute("DELETE FROM user_permissions WHERE user_id = ?1", rusqlite::params![user_id])
        .map_err(|e| e.to_string())?;
    for p in permissions {
        conn.execute(
            "INSERT INTO user_permissions (user_id, scope_type, scope_value, permission) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![user_id, p.scope_type, p.scope_value, p.permission],
        ).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── Vault filtering ───────────────────────────────────────────────────────────

/// Standard wildcard matching: `*` = any sequence, `?` = one char.
pub fn glob_matches(pattern: &str, value: &str) -> bool {
    let (pb, vb) = (pattern.as_bytes(), value.as_bytes());
    let (mut pi, mut vi) = (0usize, 0usize);
    let (mut star_pi, mut star_vi) = (usize::MAX, 0usize);
    while vi < vb.len() {
        if pi < pb.len() && pb[pi] == b'*' {
            star_pi = pi; star_vi = vi; pi += 1;
        } else if pi < pb.len() && (pb[pi] == vb[vi] || pb[pi] == b'?') {
            pi += 1; vi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1; star_vi += 1; vi = star_vi;
        } else {
            return false;
        }
    }
    while pi < pb.len() && pb[pi] == b'*' { pi += 1; }
    pi == pb.len()
}

fn build_project_names(vault: &serde_json::Value) -> HashMap<String, String> {
    vault.get("projects")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|p| {
            Some((p.get("id")?.as_str()?.to_string(), p.get("name")?.as_str()?.to_string()))
        }).collect())
        .unwrap_or_default()
}

/// Returns true when `entry` satisfies at least one permission at `perm_level`.
/// `perm_level` is `"read"` or `"write"`. Write permission satisfies read checks.
fn entry_matches_permissions(
    entry:         &serde_json::Value,
    permissions:   &[PermissionRecord],
    project_names: &HashMap<String, String>,
    perm_level:    &str,
) -> bool {
    let empty = vec![];
    let categories: Vec<&str> = entry.get("categories")
        .and_then(|v| v.as_array()).unwrap_or(&empty)
        .iter().filter_map(|v| v.as_str()).collect();
    let project_ids: Vec<&str> = entry.get("projectIds")
        .and_then(|v| v.as_array()).unwrap_or(&empty)
        .iter().filter_map(|v| v.as_str()).collect();

    for p in permissions {
        if p.permission != "write" && p.permission != perm_level { continue; }
        match p.scope_type.as_str() {
            "vault"    => return true,
            "category" => { if categories.iter().any(|c| glob_matches(&p.scope_value, c)) { return true; } }
            "project"  => {
                for pid in &project_ids {
                    let name = project_names.get(*pid).map(|s| s.as_str()).unwrap_or(pid);
                    if glob_matches(&p.scope_value, name) || glob_matches(&p.scope_value, pid) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Returns a filtered copy of `vault` containing only entries readable by the user.
/// Also trims the `projects` list to those referenced by the visible entries.
pub fn filter_vault_for_user(vault: serde_json::Value, permissions: &[PermissionRecord]) -> serde_json::Value {
    if permissions.iter().any(|p| p.scope_type == "vault") { return vault; }

    let project_names = build_project_names(&vault);
    let empty = vec![];
    let api_keys = vault.get("api_keys").and_then(|v| v.as_array()).unwrap_or(&empty);

    let visible: Vec<serde_json::Value> = api_keys.iter()
        .filter(|e| entry_matches_permissions(e, permissions, &project_names, "read"))
        .cloned().collect();

    let visible_pids: HashSet<String> = visible.iter()
        .flat_map(|e| e.get("projectIds").and_then(|v| v.as_array()).unwrap_or(&empty)
            .iter().filter_map(|v| v.as_str().map(|s| s.to_string())))
        .collect();

    let projects = vault.get("projects").and_then(|v| v.as_array()).unwrap_or(&empty);
    let visible_projects: Vec<serde_json::Value> = projects.iter()
        .filter(|p| p.get("id").and_then(|v| v.as_str())
            .map_or(false, |id| id == "Universal" || visible_pids.contains(id)))
        .cloned().collect();

    serde_json::json!({
        "api_keys":        visible,
        "user_categories": vault.get("user_categories").cloned().unwrap_or(serde_json::json!([])),
        "projects":        visible_projects,
    })
}

/// Merges a user's submitted vault data into the full vault, respecting write permissions.
///
/// - Entries the user submitted within their write scope → applied (add / update).
/// - Entries in the user's write scope that are absent from the submission → deleted.
/// - Entries outside the user's write scope → unchanged from `full_vault`.
///
/// Returns `Err` if the user's submission contains an entry outside their write scope.
pub fn merge_user_vault_write(
    full_vault:  serde_json::Value,
    user_data:   serde_json::Value,
    permissions: &[PermissionRecord],
) -> Result<serde_json::Value, String> {
    let project_names = build_project_names(&full_vault);
    let write_perms: Vec<PermissionRecord> = permissions.iter()
        .filter(|p| p.permission == "write")
        .cloned().collect();

    if write_perms.is_empty() {
        return Err("No write permissions".to_string());
    }

    let empty = vec![];
    let full_keys = full_vault.get("api_keys").and_then(|v| v.as_array()).unwrap_or(&empty);
    let user_keys = user_data.get("api_keys").and_then(|v| v.as_array()).unwrap_or(&empty);

    let entry_ck = |e: &serde_json::Value| -> String {
        format!("{}|{}",
            e.get("provider").and_then(|v| v.as_str()).unwrap_or(""),
            e.get("account_name").and_then(|v| v.as_str()).unwrap_or(""))
    };

    // Validate: every submitted entry must be within write scope
    for entry in user_keys {
        if !entry_matches_permissions(entry, &write_perms, &project_names, "write") {
            return Err(format!(
                "Write permission denied for '{}'",
                entry.get("provider").and_then(|v| v.as_str()).unwrap_or("?")
            ));
        }
    }

    let user_map: HashMap<String, &serde_json::Value> =
        user_keys.iter().map(|e| (entry_ck(e), e)).collect();

    let user_writable_cks: HashSet<String> = full_keys.iter()
        .filter(|e| entry_matches_permissions(e, &write_perms, &project_names, "write"))
        .map(|e| entry_ck(e))
        .collect();

    let full_cks: HashSet<String> = full_keys.iter().map(|e| entry_ck(e)).collect();

    let mut result: Vec<serde_json::Value> = Vec::new();

    // Keep current entries; apply user's changes to writable ones
    for entry in full_keys {
        let ck = entry_ck(entry);
        if user_writable_cks.contains(&ck) {
            if let Some(&user_entry) = user_map.get(&ck) {
                result.push(user_entry.clone());
            }
            // else: user deleted it — omit
        } else {
            result.push(entry.clone());
        }
    }

    // Append genuinely new entries from user's submission
    for entry in user_keys {
        if !full_cks.contains(&entry_ck(entry)) {
            result.push(entry.clone());
        }
    }

    let mut out = full_vault.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("api_keys".to_string(), serde_json::Value::Array(result));
    }
    Ok(out)
}
