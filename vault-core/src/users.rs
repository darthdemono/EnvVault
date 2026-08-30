//! User management, token management, and RBAC for EnvVault.
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

use crate::iso_now;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// One `(scope_type, scope_value)` pair from the `user_permissions` table.
///
/// Named because it appears three deep inside `PermissionsBySubject` below, and
/// clippy's `type_complexity` is right that the nested form is unreadable.
type Scope = (String, String);

/// `subject id -> (read scopes, write scopes)`.
///
/// A write scope also grants read, so the read vector is the superset; see
/// `load_all_permissions`, which pushes into both.
type PermissionsBySubject = HashMap<String, (Vec<Scope>, Vec<Scope>)>;

/// The `users` columns every lookup selects, in `SELECT` order:
/// `id, username, password_hash, is_owner, created_at, last_seen_at`.
///
/// `password_hash` and `last_seen_at` are nullable — a user created by an
/// administrator has no hash until first login, and has never been seen.
type UserRow = (String, String, Option<String>, i32, String, Option<String>);

// ── Public types ──────────────────────────────────────────────────────────────

/// A named user class (role template) with capabilities and permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserClass {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Can create/delete users and assign classes.
    pub cap_manage_users: bool,
    /// Can create/edit/delete user classes (admin-level).
    pub cap_manage_classes: bool,
    /// Can delete projects.
    pub cap_delete_projects: bool,
    pub created_at: String,
}

/// A single permission row scoped to a user class (no user_id — applies to all class members).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassPermission {
    pub class_id: String,
    pub scope_type: String,
    pub scope_value: String,
    pub permission: String,
}

/// A vault user (password hash is never exposed via this struct).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    /// True when the user has a password set (can use username+password auth).
    pub has_password: bool,
    pub is_owner: bool,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

/// A stored API token descriptor.  The actual token is returned only on creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    pub user_id: String,
    pub description: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// A single RBAC permission row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRecord {
    pub user_id: String,
    /// `"vault"` | `"project"` | `"category"`
    pub scope_type: String,
    /// Glob pattern: `"*"`, `"wg0-*"`, `"Cloud/AWS"`, etc.
    pub scope_value: String,
    /// `"read"` | `"write"` (write implies read)
    pub permission: String,
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
         );
         CREATE TABLE IF NOT EXISTS permission_expressions (
             subject_kind TEXT NOT NULL,   -- 'user' | 'class'
             subject_id   TEXT NOT NULL,
             permission   TEXT NOT NULL,   -- 'read' | 'write'
             expression   TEXT NOT NULL,
             PRIMARY KEY (subject_kind, subject_id, permission)
         );",
    )
    .map_err(|e| e.to_string())?;

    // Idempotent migrations
    conn.execute("ALTER TABLE users ADD COLUMN class_id TEXT", [])
        .ok();
    // Strict write scoping. Defaults to 0 — existing users keep the behaviour
    // they had, because a migration that silently tightened permissions would
    // break running deployments in a way nobody could attribute to an upgrade.
    conn.execute(
        "ALTER TABLE users ADD COLUMN strict_write INTEGER NOT NULL DEFAULT 0",
        [],
    )
    .ok();
    conn.execute(
        "ALTER TABLE user_classes ADD COLUMN strict_write INTEGER NOT NULL DEFAULT 0",
        [],
    )
    .ok();

    // Seed default classes if none exist
    let class_count: i32 = conn
        .query_row("SELECT COUNT(*) FROM user_classes", [], |r| r.get(0))
        .unwrap_or(0);
    if class_count == 0 {
        seed_default_classes(conn)?;
    }

    // Must run *after* seeding: on a fresh database the seeded class permission
    // rows are themselves what gets compiled into expressions. Run before, and
    // the built-in Admin/Moderator/Viewer classes would end up with no rules at
    // all — silently denying everything.
    migrate_rows_to_expressions(conn)?;
    Ok(())
}

// ── Permission expressions ────────────────────────────────────────────────────

/// One-time compilation of the legacy `(scope_type, scope_value, permission)`
/// rows into equivalent expressions.
///
/// Legacy rows always meant "any of these matches", so they compile to an OR
/// chain — which reproduces the old read behaviour exactly. Guarded by a marker
/// in `vault_meta` rather than by "is the table empty", so deliberately clearing
/// every expression does not resurrect the old rules on the next start.
fn migrate_rows_to_expressions(conn: &Connection) -> Result<(), String> {
    let done: Option<String> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'perm_expr_migrated'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if done.is_some() {
        return Ok(());
    }

    for (kind, table, id_col) in [
        ("user", "user_permissions", "user_id"),
        ("class", "user_class_permissions", "class_id"),
    ] {
        let sql = format!("SELECT {id_col}, scope_type, scope_value, permission FROM {table}");
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows: Vec<(String, String, String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .collect();

        // subject -> (read scopes, write scopes). Write also grants read.
        let mut by_subject: PermissionsBySubject = HashMap::new();
        for (sid, scope_type, scope_value, permission) in rows {
            let e = by_subject.entry(sid).or_default();
            e.0.push((scope_type.clone(), scope_value.clone()));
            if permission == "write" {
                e.1.push((scope_type, scope_value));
            }
        }

        for (sid, (read_scopes, write_scopes)) in by_subject {
            for (perm, scopes) in [("read", read_scopes), ("write", write_scopes)] {
                let refs: Vec<(&str, &str)> = scopes
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect();
                if let Some(expr) = crate::permex::compile_scopes(refs) {
                    conn.execute(
                        "INSERT OR REPLACE INTO permission_expressions \
                         (subject_kind, subject_id, permission, expression) VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![kind, sid, perm, expr.to_string()],
                    ).map_err(|e| e.to_string())?;
                }
            }
        }
    }

    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('perm_expr_migrated', ?1)",
        rusqlite::params![iso_now()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Reads a stored expression for a subject, if any.
pub fn get_permission_expr(
    conn: &Connection,
    subject_kind: &str,
    subject_id: &str,
    permission: &str,
) -> Result<Option<String>, String> {
    conn.query_row(
        "SELECT expression FROM permission_expressions \
         WHERE subject_kind = ?1 AND subject_id = ?2 AND permission = ?3",
        rusqlite::params![subject_kind, subject_id, permission],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| e.to_string())
}

/// Stores an expression, or clears it when `expression` is empty/blank.
///
/// Validates by parsing first: an unparseable expression denies everything at
/// evaluation time, so letting one be saved would silently lock a user out.
pub fn set_permission_expr(
    conn: &Connection,
    subject_kind: &str,
    subject_id: &str,
    permission: &str,
    expression: &str,
) -> Result<(), String> {
    if !matches!(subject_kind, "user" | "class") {
        return Err(format!("unknown subject kind '{subject_kind}'"));
    }
    if !matches!(permission, "read" | "write") {
        return Err(format!("unknown permission '{permission}'"));
    }
    if expression.trim().is_empty() {
        conn.execute(
            "DELETE FROM permission_expressions \
             WHERE subject_kind = ?1 AND subject_id = ?2 AND permission = ?3",
            rusqlite::params![subject_kind, subject_id, permission],
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }
    let parsed = crate::permex::parse(expression)?;
    conn.execute(
        "INSERT OR REPLACE INTO permission_expressions \
         (subject_kind, subject_id, permission, expression) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![subject_kind, subject_id, permission, parsed.to_string()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Whether writes for this user must satisfy **every** scope rather than any.
///
/// True when the user *or* their class has it set. The OR is deliberate and is
/// the fail-closed direction: a class that exists to constrain a group must not
/// be looser than the group, and an individual asked to be strict must not be
/// relaxed by their class.
pub fn strict_write_for(conn: &Connection, user_id: &str) -> Result<bool, String> {
    let user: i64 = conn
        .query_row(
            "SELECT COALESCE(strict_write, 0) FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .unwrap_or(0);
    if user != 0 {
        return Ok(true);
    }
    let class: i64 = conn
        .query_row(
            "SELECT COALESCE(c.strict_write, 0) FROM users u \
             JOIN user_classes c ON c.id = u.class_id WHERE u.id = ?1",
            rusqlite::params![user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .unwrap_or(0);
    Ok(class != 0)
}

/// Turn strict write scoping on or off for a user or a class.
pub fn set_strict_write(
    conn: &Connection,
    subject_kind: &str,
    subject_id: &str,
    strict: bool,
) -> Result<(), String> {
    let table = match subject_kind {
        "user" => "users",
        "class" => "user_classes",
        other => return Err(format!("unknown subject kind '{other}'")),
    };
    let n = conn
        .execute(
            &format!("UPDATE {table} SET strict_write = ?1 WHERE id = ?2"),
            rusqlite::params![i64::from(strict), subject_id],
        )
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err(format!("No such {subject_kind}: {subject_id}"));
    }
    Ok(())
}

/// Resolves what a user may actually do, combining their class and individual rules.
///
/// - Class and individual are **AND**ed, so a class exclusion cannot be undone
///   by an individual grant.
/// - `None` means no grant at all — callers must deny. Absent expressions are
///   deliberately not treated as "no restriction": under AND that would give a
///   user with no permissions whatsoever full access.
/// - Write implies read, so the effective read rule is `read OR write`.
/// - Under strict write scoping the write rule is narrowed further — see
///   [`strict_write_for`] and [`crate::permex::require_all`].
pub fn effective_permission_expr(
    conn: &Connection,
    user_id: &str,
    permission: &str,
) -> Result<Option<crate::permex::Expr>, String> {
    let class_id: Option<String> = conn
        .query_row(
            "SELECT class_id FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
        .flatten();

    // Stored text is always re-parsed rather than trusted: a row edited outside
    // the app must fail closed.
    let load = |kind: &str, id: &str, perm: &str| -> Result<Option<crate::permex::Expr>, String> {
        Ok(get_permission_expr(conn, kind, id, perm)?
            .and_then(|src| crate::permex::parse(&src).ok()))
    };

    let raw = |perm: &str| -> Result<Option<crate::permex::Expr>, String> {
        let individual = load("user", user_id, perm)?;
        let class = match &class_id {
            Some(cid) => load("class", cid, perm)?,
            None => None,
        };
        Ok(crate::permex::combine(class, individual))
    };

    match permission {
        // Strict mode narrows writes only. Reads keep ANY-match semantics
        // deliberately: a user who cannot see an entry cannot review what they
        // are about to change, and tightening reads here would make the strict
        // user's own vault look empty.
        "write" => Ok(raw("write")?.map(|e| {
            if strict_write_for(conn, user_id).unwrap_or(false) {
                crate::permex::require_all(e)
            } else {
                e
            }
        })),
        // Note this reads the *unstrictified* write rule, so turning strict mode
        // on never removes visibility — only the ability to change.
        "read" => Ok(crate::permex::any_of(raw("read")?, raw("write")?)),
        other => Err(format!("unknown permission '{other}'")),
    }
}

/// Seeds the three built-in user classes: Admin, Moderator, Viewer.
fn seed_default_classes(conn: &Connection) -> Result<(), String> {
    let now = iso_now();

    struct ClassSeed<'a> {
        id: &'a str,
        name: &'a str,
        description: &'a str,
        cap_manage_users: i32,
        cap_manage_classes: i32,
        cap_delete_projects: i32,
        perms: &'a [(&'a str, &'a str, &'a str)], // (scope_type, scope_value, permission)
    }

    let seeds = [
        ClassSeed {
            id: "cls-admin",
            name: "Admin",
            description: "Full vault access. Can manage users and classes.",
            cap_manage_users: 1,
            cap_manage_classes: 1,
            cap_delete_projects: 1,
            perms: &[("vault", "*", "write")],
        },
        ClassSeed {
            id: "cls-moderator",
            name: "Moderator",
            description: "Full vault access. Can manage users but not classes or project deletion.",
            cap_manage_users: 1,
            cap_manage_classes: 0,
            cap_delete_projects: 0,
            perms: &[("vault", "*", "write")],
        },
        ClassSeed {
            id: "cls-viewer",
            name: "Viewer",
            description: "Read-only access to the entire vault.",
            cap_manage_users: 0,
            cap_manage_classes: 0,
            cap_delete_projects: 0,
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
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};

    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(32_768, 2, 1, None).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password(password.as_bytes(), &salt)
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
        use argon2::password_hash::PasswordHash;
        use argon2::{Argon2, PasswordVerifier};
        let Ok(parsed) = PasswordHash::new(stored) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    } else {
        // Legacy: "<salt_hex>:<sha256_hex>" — upgrade on next login
        let mut parts = stored.splitn(2, ':');
        let (Some(salt_hex), Some(hash_hex)) = (parts.next(), parts.next()) else {
            return false;
        };
        let Ok(salt) = hex::decode(salt_hex) else {
            return false;
        };
        let Ok(expected) = hex::decode(hash_hex) else {
            return false;
        };
        let mut h = Sha256::new();
        h.update(&salt);
        h.update(password.as_bytes());
        let computed = h.finalize();
        // Constant-time comparison — avoids timing side-channel on legacy hashes.
        computed.len() == expected.len()
            && computed
                .iter()
                .zip(expected.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
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
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

// ── User CRUD ─────────────────────────────────────────────────────────────────

/// Creates a new user.  Pass `password = None` for token-only auth.
pub fn create_user(
    conn: &Connection,
    username: &str,
    password: Option<&str>,
    is_owner: bool,
) -> Result<UserRecord, String> {
    let id = new_uuid();
    let now = iso_now();
    let password_hash = password.map(hash_password);
    conn.execute(
        "INSERT INTO users (id, username, password_hash, is_owner, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![id, username, password_hash, is_owner as i32, now],
    )
    .map_err(|e| e.to_string())?;
    Ok(UserRecord {
        id,
        username: username.to_string(),
        has_password: password.is_some(),
        is_owner,
        created_at: now,
        last_seen_at: None,
    })
}

/// Renames a user (owner or non-owner).  Fails if `new_username` is already taken.
pub fn rename_user(conn: &Connection, user_id: &str, new_username: &str) -> Result<(), String> {
    conn.execute(
        "UPDATE users SET username = ?1 WHERE id = ?2",
        rusqlite::params![new_username, user_id],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Updates (or clears) a user's password.
pub fn set_user_password(
    conn: &Connection,
    user_id: &str,
    password: Option<&str>,
) -> Result<(), String> {
    conn.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        rusqlite::params![password.map(hash_password), user_id],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Verifies username + password.  Returns `None` on invalid credentials.
pub fn verify_user_password(
    conn: &Connection,
    username: &str,
    password: &str,
) -> Result<Option<UserRecord>, String> {
    let row: Option<UserRow> = conn
        .query_row(
            "SELECT id, username, password_hash, is_owner, created_at, last_seen_at \
             FROM users WHERE username = ?1",
            rusqlite::params![username],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let Some((id, uname, hash_opt, is_owner_i, created_at, last_seen)) = row else {
        return Ok(None);
    };
    // A user with no password (token-only, or the owner row) simply cannot
    // authenticate this way — that is an ordinary credential failure, not a
    // server error.
    //
    // This previously returned Err, which the server turned into a 500 while a
    // nonexistent username returned 401, and only the 401 path incremented the
    // rate limiter. The 500-vs-401 difference was an unthrottled username
    // enumeration oracle.
    let Some(stored) = hash_opt else {
        return Ok(None);
    };
    if !verify_password_hash(password, &stored) {
        return Ok(None);
    }
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
        id,
        username: uname,
        has_password: true,
        is_owner: is_owner_i != 0,
        created_at,
        last_seen_at: last_seen,
    }))
}

/// Verifies a raw 64-char hex token.  Returns `None` if invalid or expired.
pub fn verify_user_token(conn: &Connection, token: &str) -> Result<Option<UserRecord>, String> {
    let token_hash = sha256_hex(token);
    let now = iso_now();
    let row: Option<UserRow> = conn
        .query_row(
            "SELECT u.id, u.username, u.password_hash, u.is_owner, u.created_at, u.last_seen_at \
             FROM user_tokens t JOIN users u ON u.id = t.user_id \
             WHERE t.token_hash = ?1 AND (t.expires_at IS NULL OR t.expires_at > ?2)",
            rusqlite::params![token_hash, now],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let Some((id, uname, hash_opt, is_owner_i, created_at, last_seen)) = row else {
        return Ok(None);
    };
    touch_last_seen(conn, &id)?;
    Ok(Some(UserRecord {
        id,
        username: uname,
        has_password: hash_opt.is_some(),
        is_owner: is_owner_i != 0,
        created_at,
        last_seen_at: last_seen,
    }))
}

/// Lists all users, owners first, then by creation date.
pub fn list_users(conn: &Connection) -> Result<Vec<UserRecord>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, username, password_hash, is_owner, created_at, last_seen_at \
         FROM users ORDER BY is_owner DESC, created_at ASC",
        )
        .map_err(|e| e.to_string())?;
    let rows: Vec<Result<UserRecord, _>> = stmt
        .query_map([], |r| {
            Ok(UserRecord {
                id: r.get(0)?,
                username: r.get(1)?,
                has_password: r.get::<_, Option<String>>(2)?.is_some(),
                is_owner: r.get::<_, i32>(3)? != 0,
                created_at: r.get(4)?,
                last_seen_at: r.get(5)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect();
    rows.into_iter()
        .map(|r| r.map_err(|e| e.to_string()))
        .collect()
}

/// Deletes a user plus all their tokens and permissions.
/// Returns `Err` if `user_id` belongs to the owner account.
pub fn delete_user(conn: &Connection, user_id: &str) -> Result<(), String> {
    let is_owner: Option<i32> = conn
        .query_row(
            "SELECT is_owner FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if is_owner == Some(1) {
        return Err("Cannot delete the owner account".to_string());
    }
    conn.execute(
        "DELETE FROM user_permissions WHERE user_id = ?1",
        rusqlite::params![user_id],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM user_tokens WHERE user_id = ?1",
        rusqlite::params![user_id],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM users WHERE id = ?1",
        rusqlite::params![user_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ── User class CRUD ───────────────────────────────────────────────────────────

pub fn list_user_classes(conn: &Connection) -> Result<Vec<UserClass>, String> {
    let mut stmt = conn.prepare(
        "SELECT id, name, description, cap_manage_users, cap_manage_classes, cap_delete_projects, created_at \
         FROM user_classes ORDER BY created_at ASC"
    ).map_err(|e| e.to_string())?;
    let rows: Vec<Result<UserClass, _>> = stmt
        .query_map([], |r| {
            Ok(UserClass {
                id: r.get(0)?,
                name: r.get(1)?,
                description: r.get(2)?,
                cap_manage_users: r.get::<_, i32>(3)? != 0,
                cap_manage_classes: r.get::<_, i32>(4)? != 0,
                cap_delete_projects: r.get::<_, i32>(5)? != 0,
                created_at: r.get(6)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect();
    rows.into_iter()
        .map(|r| r.map_err(|e| e.to_string()))
        .collect()
}

pub fn create_user_class(
    conn: &Connection,
    name: &str,
    description: &str,
    cap_manage_users: bool,
    cap_manage_classes: bool,
    cap_delete_projects: bool,
) -> Result<UserClass, String> {
    let id = new_uuid();
    let now = iso_now();
    conn.execute(
        "INSERT INTO user_classes (id, name, description, cap_manage_users, cap_manage_classes, cap_delete_projects, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![id, name, description, cap_manage_users as i32, cap_manage_classes as i32, cap_delete_projects as i32, now],
    ).map_err(|e| e.to_string())?;
    Ok(UserClass {
        id,
        name: name.to_string(),
        description: description.to_string(),
        cap_manage_users,
        cap_manage_classes,
        cap_delete_projects,
        created_at: now,
    })
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
    conn.execute(
        "UPDATE users SET class_id = NULL WHERE class_id = ?1",
        rusqlite::params![class_id],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM user_class_permissions WHERE class_id = ?1",
        rusqlite::params![class_id],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM user_classes WHERE id = ?1",
        rusqlite::params![class_id],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

pub fn get_class_permissions(
    conn: &Connection,
    class_id: &str,
) -> Result<Vec<ClassPermission>, String> {
    let mut stmt = conn.prepare(
        "SELECT class_id, scope_type, scope_value, permission FROM user_class_permissions WHERE class_id = ?1"
    ).map_err(|e| e.to_string())?;
    let rows: Vec<Result<ClassPermission, _>> = stmt
        .query_map(rusqlite::params![class_id], |r| {
            Ok(ClassPermission {
                class_id: r.get(0)?,
                scope_type: r.get(1)?,
                scope_value: r.get(2)?,
                permission: r.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect();
    rows.into_iter()
        .map(|r| r.map_err(|e| e.to_string()))
        .collect()
}

pub fn set_class_permissions(
    conn: &Connection,
    class_id: &str,
    permissions: &[ClassPermission],
) -> Result<(), String> {
    conn.execute(
        "DELETE FROM user_class_permissions WHERE class_id = ?1",
        rusqlite::params![class_id],
    )
    .map_err(|e| e.to_string())?;
    for p in permissions {
        conn.execute(
            "INSERT INTO user_class_permissions (class_id, scope_type, scope_value, permission) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![class_id, p.scope_type, p.scope_value, p.permission],
        ).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn assign_user_class(
    conn: &Connection,
    user_id: &str,
    class_id: Option<&str>,
) -> Result<(), String> {
    conn.execute(
        "UPDATE users SET class_id = ?1 WHERE id = ?2",
        rusqlite::params![class_id, user_id],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Returns the capabilities of the user's class (None values mean no class = no extra capabilities).
pub fn get_user_capabilities(
    conn: &Connection,
    user_id: &str,
) -> Result<(bool, bool, bool), String> {
    let class_id: Option<String> = conn
        .query_row(
            "SELECT class_id FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?
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

// ── Authority hierarchy (Discord-style: owner > admin > moderator > user) ──────

/// Derives an authority tier from capability flags. Higher acts on strictly lower.
/// - 3 = owner (master-password session; never a stored user row)
/// - 2 = admin     (`cap_manage_classes`)
/// - 1 = moderator (`cap_manage_users` only)
/// - 0 = user      (no management capabilities)
pub fn authority_tier(is_owner: bool, cap_manage_users: bool, cap_manage_classes: bool) -> i32 {
    if is_owner {
        3
    } else if cap_manage_classes {
        2
    } else if cap_manage_users {
        1
    } else {
        0
    }
}

/// Authority tier implied by a class's stored capabilities. Returns 0 if unknown.
pub fn class_authority_tier(conn: &Connection, class_id: &str) -> Result<i32, String> {
    let row: Option<(i32, i32)> = conn
        .query_row(
            "SELECT cap_manage_users, cap_manage_classes FROM user_classes WHERE id = ?1",
            rusqlite::params![class_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(row
        .map(|(u, c)| authority_tier(false, u != 0, c != 0))
        .unwrap_or(0))
}

/// Returns the owning user id of a token, or `None` if the token id is unknown.
pub fn token_user_id(conn: &Connection, token_id: &str) -> Result<Option<String>, String> {
    conn.query_row(
        "SELECT user_id FROM user_tokens WHERE id = ?1",
        rusqlite::params![token_id],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| e.to_string())
}

/// Authority tier of a stored user (by their class capabilities, or the `is_owner` flag).
/// Returns 0 for an unknown user id.
pub fn user_authority_tier(conn: &Connection, user_id: &str) -> Result<i32, String> {
    let is_owner: Option<i32> = conn
        .query_row(
            "SELECT is_owner FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let Some(owner_flag) = is_owner else {
        return Ok(0);
    };
    let (mu, mc, _) = get_user_capabilities(conn, user_id)?;
    Ok(authority_tier(owner_flag != 0, mu, mc))
}

/// Ensures the vault has exactly one owner row and returns its id.
///
/// The owner is whoever can derive the SQLCipher key from the master password.
/// Before this existed the server represented them with the magic string
/// `"owner"`, which meant they appeared in no user list, carried no class, and
/// could not be named in an audit row.
///
/// The row is deliberately created with **`password_hash = NULL`**. Storing a
/// hash of the master password here would put an offline oracle for the vault
/// key back into the database — the exact hole removed from the desktop
/// `unlock_vault`. Proof of ownership stays "your password opened the
/// database"; `verify_user_password` refuses a NULL hash, so this row can never
/// be logged into via `/api/auth`.
pub fn ensure_owner_user(conn: &Connection) -> Result<String, String> {
    if let Some(id) = conn
        .query_row("SELECT id FROM users WHERE is_owner = 1 LIMIT 1", [], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .map_err(|e| e.to_string())?
    {
        return Ok(id);
    }

    // `username` is UNIQUE, so fall back if a normal user already took "owner".
    let taken: bool = conn
        .query_row("SELECT 1 FROM users WHERE username = 'owner'", [], |r| {
            r.get::<_, i32>(0)
        })
        .optional()
        .map_err(|e| e.to_string())?
        .is_some();
    let id = new_uuid();
    let username = if taken {
        format!("owner-{}", &id[..8])
    } else {
        "owner".to_string()
    };

    conn.execute(
        "INSERT INTO users (id, username, password_hash, is_owner, created_at) \
         VALUES (?1, ?2, NULL, 1, ?3)",
        rusqlite::params![id, username, iso_now()],
    )
    .map_err(|e| e.to_string())?;
    Ok(id)
}

/// Outcome of [`seed_default_admin`].
pub enum AdminSeed {
    /// An `admin` user already existed — nothing was created.
    Exists,
    /// A new `admin` user (assigned the built-in `cls-admin` class) was created.
    /// `generated_password` is `Some` only when no env password was supplied and a
    /// random one was generated — the caller must surface it once.
    Created { generated_password: Option<String> },
}

/// Idempotently seeds a default `admin` user assigned to the built-in `cls-admin`
/// class. Never hardcodes a credential: uses `env_password` when present, otherwise
/// generates a 128-bit random password the caller is responsible for displaying once.
pub fn seed_default_admin(
    conn: &Connection,
    env_password: Option<&str>,
) -> Result<AdminSeed, String> {
    let exists: Option<String> = conn
        .query_row("SELECT id FROM users WHERE username = 'admin'", [], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|e| e.to_string())?;
    if exists.is_some() {
        return Ok(AdminSeed::Exists);
    }

    let (password, generated) = match env_password {
        Some(p) if !p.is_empty() => (p.to_string(), None),
        _ => {
            let mut raw = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut raw);
            let pw = hex::encode(raw);
            (pw.clone(), Some(pw))
        }
    };

    let user = create_user(conn, "admin", Some(&password), false)?;
    assign_user_class(conn, &user.id, Some("cls-admin"))?;
    Ok(AdminSeed::Created {
        generated_password: generated,
    })
}

// ── Token management ──────────────────────────────────────────────────────────

/// Creates a token for `user_id`.
/// Returns `(token_id, plaintext_token)` — the plaintext is shown **once**.
pub fn create_user_token(
    conn: &Connection,
    user_id: &str,
    description: Option<&str>,
    expires_at: Option<&str>,
) -> Result<(String, String), String> {
    let token_id = new_uuid();
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let plaintext = hex::encode(raw);
    let token_hash = sha256_hex(&plaintext);
    conn.execute(
        "INSERT INTO user_tokens (id, token_hash, user_id, description, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            token_id,
            token_hash,
            user_id,
            description,
            iso_now(),
            expires_at
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok((token_id, plaintext))
}

/// Revokes a token by its UUID.
pub fn revoke_user_token(conn: &Connection, token_id: &str) -> Result<(), String> {
    conn.execute(
        "DELETE FROM user_tokens WHERE id = ?1",
        rusqlite::params![token_id],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Lists all tokens for a user (no hashes).
pub fn list_user_tokens(conn: &Connection, user_id: &str) -> Result<Vec<TokenRecord>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, user_id, description, created_at, expires_at \
         FROM user_tokens WHERE user_id = ?1 ORDER BY created_at",
        )
        .map_err(|e| e.to_string())?;
    let rows: Vec<Result<TokenRecord, _>> = stmt
        .query_map(rusqlite::params![user_id], |r| {
            Ok(TokenRecord {
                id: r.get(0)?,
                user_id: r.get(1)?,
                description: r.get(2)?,
                created_at: r.get(3)?,
                expires_at: r.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect();
    rows.into_iter()
        .map(|r| r.map_err(|e| e.to_string()))
        .collect()
}

// ── Permission management ─────────────────────────────────────────────────────

/// Returns all permissions for a user.
pub fn get_user_permissions(
    conn: &Connection,
    user_id: &str,
) -> Result<Vec<PermissionRecord>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT user_id, scope_type, scope_value, permission \
         FROM user_permissions WHERE user_id = ?1 \
         ORDER BY scope_type, scope_value",
        )
        .map_err(|e| e.to_string())?;
    let rows: Vec<Result<PermissionRecord, _>> = stmt
        .query_map(rusqlite::params![user_id], |r| {
            Ok(PermissionRecord {
                user_id: r.get(0)?,
                scope_type: r.get(1)?,
                scope_value: r.get(2)?,
                permission: r.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect();
    rows.into_iter()
        .map(|r| r.map_err(|e| e.to_string()))
        .collect()
}

/// Atomically replaces all permissions for a user.
pub fn set_user_permissions(
    conn: &Connection,
    user_id: &str,
    permissions: &[PermissionRecord],
) -> Result<(), String> {
    conn.execute(
        "DELETE FROM user_permissions WHERE user_id = ?1",
        rusqlite::params![user_id],
    )
    .map_err(|e| e.to_string())?;
    for p in permissions {
        conn.execute(
            "INSERT INTO user_permissions (user_id, scope_type, scope_value, permission) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![user_id, p.scope_type, p.scope_value, p.permission],
        )
        .map_err(|e| e.to_string())?;
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
            star_pi = pi;
            star_vi = vi;
            pi += 1;
        } else if pi < pb.len() && (pb[pi] == vb[vi] || pb[pi] == b'?') {
            pi += 1;
            vi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_vi += 1;
            vi = star_vi;
        } else {
            return false;
        }
    }
    while pi < pb.len() && pb[pi] == b'*' {
        pi += 1;
    }
    pi == pb.len()
}

fn build_project_names(vault: &serde_json::Value) -> HashMap<String, String> {
    vault
        .get("projects")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    Some((
                        p.get("id")?.as_str()?.to_string(),
                        p.get("name")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Returns a filtered copy of `vault` containing only entries readable under `read`.
/// Also trims the `projects` and `user_categories` lists to what the visible
/// entries actually reference, so the taxonomy itself does not leak.
///
/// `read = None` means no grant at all and yields an empty vault.
pub fn filter_vault_for_user(
    vault: serde_json::Value,
    read: Option<&crate::permex::Expr>,
) -> serde_json::Value {
    let Some(expr) = read else {
        return serde_json::json!({ "api_keys": [], "user_categories": [], "projects": [] });
    };

    let project_names = build_project_names(&vault);
    let empty = vec![];
    let api_keys = vault
        .get("api_keys")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);

    let visible: Vec<serde_json::Value> = api_keys
        .iter()
        .filter(|e| {
            crate::permex::eval(
                expr,
                &crate::permex::EntryView::from_entry(e, &project_names),
            )
        })
        .cloned()
        .collect();

    let visible_pids: HashSet<String> = visible
        .iter()
        .flat_map(|e| {
            e.get("projectIds")
                .and_then(|v| v.as_array())
                .unwrap_or(&empty)
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
        })
        .collect();

    let projects = vault
        .get("projects")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let visible_projects: Vec<serde_json::Value> = projects
        .iter()
        .filter(|p| {
            p.get("id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == "Universal" || visible_pids.contains(id))
        })
        .cloned()
        .collect();

    // Don't leak the full category taxonomy: expose only category tags that a
    // visible entry actually carries (plus their slash-hierarchy parents so the
    // sidebar tree still renders).
    let visible_cats: HashSet<String> = visible
        .iter()
        .flat_map(|e| {
            e.get("categories")
                .and_then(|v| v.as_array())
                .unwrap_or(&empty)
                .iter()
                .filter_map(|v| v.as_str())
        })
        .flat_map(|c| {
            // "Cloud/AWS/Prod" -> ["Cloud", "Cloud/AWS", "Cloud/AWS/Prod"]
            let parts: Vec<&str> = c.split('/').collect();
            (1..=parts.len()).map(move |n| parts[..n].join("/"))
        })
        .collect();
    let user_categories: Vec<serde_json::Value> = vault
        .get("user_categories")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
        .iter()
        .filter(|c| c.as_str().is_some_and(|s| visible_cats.contains(s)))
        .cloned()
        .collect();

    serde_json::json!({
        "api_keys":        visible,
        "user_categories": user_categories,
        "projects":        visible_projects,
    })
}

/// Is every entry currently referencing `pid` writable by this user?
///
/// The same ALL-scope rule entry writes already use: a container is writable
/// only when the user could write everything it holds. Anything weaker lets a
/// user with one entry in a shared project rename or delete the project for
/// everybody.
///
/// A project nothing references is vacuously writable, which is correct — it is
/// also invisible, so the caller only reaches this for one the user was served.
fn project_write_allowed(
    pid: &str,
    full_keys: &[serde_json::Value],
    writable: &dyn Fn(&serde_json::Value) -> bool,
) -> bool {
    full_keys
        .iter()
        .filter(|e| {
            e.get("projectIds")
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(pid)))
        })
        .all(writable)
}

/// The category equivalent of [`project_write_allowed`].
fn category_write_allowed(
    cat: &str,
    full_keys: &[serde_json::Value],
    writable: &dyn Fn(&serde_json::Value) -> bool,
) -> bool {
    full_keys
        .iter()
        .filter(|e| {
            e.get("categories")
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(cat)))
        })
        .all(writable)
}

/// Merges one collection of named, string-keyed objects (`projects`) or plain
/// strings (`user_categories`) from a sub-user's submission.
///
/// The submission is a *filtered* view, so "absent" is ambiguous: it means
/// either "deleted" or "you were never shown it". `served` — recomputed here
/// from the read expression, which is exactly what the client was handed —
/// resolves it. Anything outside `served` is preserved untouched; anything
/// inside it is honoured, subject to `allowed`.
fn merge_named_collection(
    full: &[serde_json::Value],
    submitted: &[serde_json::Value],
    served: &HashSet<String>,
    key_of: &dyn Fn(&serde_json::Value) -> Option<String>,
    allowed: &dyn Fn(&str) -> bool,
    what: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let sub_map: HashMap<String, &serde_json::Value> = submitted
        .iter()
        .filter_map(|v| key_of(v).map(|k| (k, v)))
        .collect();

    let mut out: Vec<serde_json::Value> = Vec::new();
    for item in full {
        let Some(k) = key_of(item) else {
            out.push(item.clone());
            continue;
        };
        if !served.contains(&k) {
            // The client never saw it, so it cannot have meant to change it.
            out.push(item.clone());
            continue;
        }
        match sub_map.get(&k) {
            Some(&sub) if sub == item => out.push(item.clone()),
            Some(&sub) => {
                if !allowed(&k) {
                    return Err(format!("Write permission denied for {what} '{k}'"));
                }
                out.push(sub.clone());
            }
            None => {
                if !allowed(&k) {
                    return Err(format!("Delete permission denied for {what} '{k}'"));
                }
                // omitted from a view that contained it → deleted
            }
        }
    }

    // Genuinely new ones. A submitted key that exists in `full` but was not
    // served is deliberately *not* treated as new: it would overwrite something
    // the user was never allowed to see.
    let full_keys: HashSet<String> = full.iter().filter_map(key_of).collect();
    for item in submitted {
        if let Some(k) = key_of(item) {
            if !full_keys.contains(&k) {
                out.push(item.clone());
            }
        }
    }
    Ok(out)
}

/// Merges a user's submitted vault data into the full vault, respecting write permissions.
///
/// - Entries the user submitted within their write scope → applied (add / update).
/// - Entries in the user's write scope that are absent from the submission → deleted.
/// - Entries outside the user's write scope → unchanged from `full_vault`.
/// - `projects` and `user_categories` are merged the same way, against what the
///   read expression would have served, with container writability defined as
///   "every entry inside it is writable".
///
/// Returns `Err` if the user's submission contains an entry outside their write
/// scope, or changes a project or category they may not change.
///
/// **`projects` and `user_categories` used to be dropped silently.** The merge
/// rebuilt `api_keys` only and took both collections from `full_vault`, and the
/// server answered `204 No Content`. A sub-user creating a project, renaming a
/// category, editing a WireGuard peer or adding a chunk got a success toast and
/// a UI that showed the change — because the frontend had already applied it to
/// its own copy — while the server persisted nothing. It surfaced on the next
/// reload, attributable to nothing.
pub fn merge_user_vault_write(
    full_vault: serde_json::Value,
    user_data: serde_json::Value,
    read: Option<&crate::permex::Expr>,
    write: Option<&crate::permex::Expr>,
) -> Result<serde_json::Value, String> {
    let project_names = build_project_names(&full_vault);
    let Some(write_expr) = write else {
        return Err("No write permissions".to_string());
    };
    let writable = |e: &serde_json::Value| {
        crate::permex::eval(
            write_expr,
            &crate::permex::EntryView::from_entry(e, &project_names),
        )
    };

    let empty = vec![];
    let full_keys = full_vault
        .get("api_keys")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let user_keys = user_data
        .get("api_keys")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);

    // Identity comes from the shared `crate::entry_ck` so this merge and
    // `save_vault` can never disagree about what "the same entry" means. A
    // mismatch here would let a write-scoped entry alias one in an out-of-scope
    // project (overwrite/delete bypass).
    use crate::entry_ck;

    // Validate: every submitted entry must satisfy the write expression.
    for entry in user_keys {
        if !writable(entry) {
            return Err(format!(
                "Write permission denied for '{}'",
                entry
                    .get("provider")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
            ));
        }
    }

    let user_map: HashMap<String, &serde_json::Value> =
        user_keys.iter().map(|e| (entry_ck(e), e)).collect();

    let user_writable_cks: HashSet<String> = full_keys
        .iter()
        .filter(|e| writable(e))
        .map(entry_ck)
        .collect();

    let full_cks: HashSet<String> = full_keys.iter().map(entry_ck).collect();

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

    // ── projects and user_categories ──────────────────────────────────────────
    //
    // Recompute what a GET would have handed this user. That is the only way to
    // read the submission correctly: it is a filtered document, so an absent
    // project means "deleted" when the user could see it and "never shown"
    // otherwise, and the two must not be confused.
    let served = filter_vault_for_user(full_vault.clone(), read);
    let served_projects: HashSet<String> = served
        .get("projects")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
        .iter()
        .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    let served_cats: HashSet<String> = served
        .get("user_categories")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
        .iter()
        .filter_map(|c| c.as_str().map(str::to_string))
        .collect();

    // An *absent* key is not an empty one. A caller that PUTs only `api_keys` —
    // which the server's payload validation permits, and which any hand-rolled
    // agent client will do — means "I am not touching the taxonomy", not "delete
    // every project I can see". Only a key that is present is merged.
    let full_projects = full_vault
        .get("projects")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let merged_projects = match user_data.get("projects").and_then(|v| v.as_array()) {
        None => full_projects.clone(),
        Some(user_projects) => merge_named_collection(
            &full_projects,
            user_projects,
            &served_projects,
            &|p| p.get("id").and_then(|v| v.as_str()).map(str::to_string),
            &|pid| project_write_allowed(pid, full_keys, &writable),
            "project",
        )?,
    };

    let full_cats = full_vault
        .get("user_categories")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let merged_cats = match user_data.get("user_categories").and_then(|v| v.as_array()) {
        None => full_cats.clone(),
        Some(user_cats) => merge_named_collection(
            &full_cats,
            user_cats,
            &served_cats,
            &|c| c.as_str().map(str::to_string),
            &|cat| category_write_allowed(cat, full_keys, &writable),
            "category",
        )?,
    };

    let mut out = full_vault.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("api_keys".to_string(), serde_json::Value::Array(result));
        obj.insert(
            "projects".to_string(),
            serde_json::Value::Array(merged_projects),
        );
        obj.insert(
            "user_categories".to_string(),
            serde_json::Value::Array(merged_cats),
        );
    }
    Ok(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Glob matching ─────────────────────────────────────────────────────────

    #[test]
    fn glob_exact_and_wildcards() {
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("*", ""));
        assert!(glob_matches("Cloud/AWS", "Cloud/AWS"));
        assert!(!glob_matches("Cloud/AWS", "Cloud/GCP"));
        assert!(glob_matches("wg0-*", "wg0-office"));
        assert!(!glob_matches("wg0-*", "wg1-office"));
        assert!(glob_matches("*-prod", "app-prod"));
        assert!(glob_matches("a?c", "abc"));
        assert!(!glob_matches("a?c", "ac"));
        assert!(glob_matches("a*b*c", "axxbyyc"));
    }

    #[test]
    fn glob_does_not_match_prefix_by_accident() {
        // "Cloud" must not grant access to "CloudSecrets".
        assert!(!glob_matches("Cloud", "CloudSecrets"));
        assert!(glob_matches("Cloud*", "CloudSecrets"));
    }

    // ── Password hashing ──────────────────────────────────────────────────────

    #[test]
    fn argon2_hash_roundtrips_and_rejects_wrong_password() {
        let stored = hash_password("correct horse");
        assert!(
            stored.starts_with("$argon2id$"),
            "must emit PHC format, got {stored}"
        );
        assert!(verify_password_hash("correct horse", &stored));
        assert!(!verify_password_hash("wrong horse", &stored));
    }

    #[test]
    fn hashes_are_salted_per_call() {
        assert_ne!(
            hash_password("same"),
            hash_password("same"),
            "identical passwords must not produce identical hashes"
        );
    }

    #[test]
    fn legacy_sha256_hashes_still_verify() {
        // Phase 5.0 format: "<salt_hex>:<sha256(salt||password)_hex>"
        let salt = [0xABu8; 16];
        let mut h = Sha256::new();
        h.update(salt);
        h.update(b"legacy-pass");
        let legacy = format!("{}:{}", hex::encode(salt), hex::encode(h.finalize()));
        assert!(verify_password_hash("legacy-pass", &legacy));
        assert!(!verify_password_hash("nope", &legacy));
    }

    #[test]
    fn malformed_hashes_are_rejected_not_accepted() {
        assert!(!verify_password_hash("x", ""));
        assert!(!verify_password_hash("x", "garbage"));
        assert!(!verify_password_hash("x", "$argon2id$broken"));
        assert!(!verify_password_hash("x", "nothex:alsonothex"));
    }

    // ── Authority hierarchy ───────────────────────────────────────────────────

    #[test]
    fn authority_tiers_are_ordered() {
        let owner = authority_tier(true, false, false);
        let admin = authority_tier(false, true, true);
        let moder = authority_tier(false, true, false);
        let user = authority_tier(false, false, false);
        assert!(
            owner > admin && admin > moder && moder > user,
            "owner {owner} > admin {admin} > moderator {moder} > user {user}"
        );
    }

    // ── Write scoping ─────────────────────────────────────────────────────────
    //
    // Predicate-level semantics (wildcards, Universal, globs) are covered by the
    // permex tests. What matters here is that the merge honours the expression.

    fn ex(src: &str) -> crate::permex::Expr {
        crate::permex::parse(src).unwrap()
    }

    // ── Owner row ─────────────────────────────────────────────────────────────

    fn scratch_conn(tag: &str) -> Connection {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("envvault-users-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let key = crate::derive_key("pw", b"0123456789abcdef").unwrap();
        let conn = crate::open_db(&dir.join("vault.db"), &key).unwrap();
        crate::init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn owner_row_is_created_once_and_is_idempotent() {
        let conn = scratch_conn("owner");
        let a = ensure_owner_user(&conn).unwrap();
        let b = ensure_owner_user(&conn).unwrap();
        assert_eq!(a, b, "must not create a second owner");
        let owners: i32 = conn
            .query_row("SELECT COUNT(*) FROM users WHERE is_owner = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(owners, 1);
    }

    #[test]
    fn owner_row_has_no_password_and_cannot_be_logged_into() {
        let conn = scratch_conn("owner-nopw");
        ensure_owner_user(&conn).unwrap();
        // Storing a hash of the master password here would be an offline oracle
        // for the vault key, so the row must never have one.
        let hash: Option<String> = conn
            .query_row(
                "SELECT password_hash FROM users WHERE is_owner = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(hash.is_none(), "owner row must have a NULL password_hash");
        assert!(verify_user_password(&conn, "owner", "anything")
            .unwrap()
            .is_none());
        assert!(verify_user_password(&conn, "owner", "").unwrap().is_none());
    }

    #[test]
    fn passwordless_user_is_a_credential_failure_not_an_error() {
        // 500-vs-401 used to leak which usernames existed, unthrottled, because
        // only the Ok(None) path incremented the rate limiter.
        let conn = scratch_conn("nopw");
        create_user(&conn, "tokenonly", None, false).unwrap();
        let existing = verify_user_password(&conn, "tokenonly", "guess");
        let missing = verify_user_password(&conn, "ghost", "guess");
        assert!(existing.is_ok() && existing.unwrap().is_none());
        assert!(missing.is_ok() && missing.unwrap().is_none());
    }

    #[test]
    fn owner_username_collision_falls_back() {
        let conn = scratch_conn("collide");
        create_user(&conn, "owner", Some("pw"), false).unwrap();
        let id = ensure_owner_user(&conn).unwrap();
        let uname: String = conn
            .query_row(
                "SELECT username FROM users WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(
            uname, "owner",
            "must not collide with the existing UNIQUE username"
        );
        assert!(uname.starts_with("owner-"));
    }

    #[test]
    fn owner_outranks_every_class() {
        let conn = scratch_conn("tier");
        let id = ensure_owner_user(&conn).unwrap();
        assert_eq!(user_authority_tier(&conn, &id).unwrap(), 3);
    }

    // ── Permission expressions ────────────────────────────────────────────────

    #[test]
    fn legacy_rows_are_migrated_into_expressions() {
        let conn = scratch_conn("permmig");
        let u = create_user(&conn, "u1", Some("pw"), false).unwrap();
        set_user_permissions(
            &conn,
            &u.id,
            &[
                PermissionRecord {
                    user_id: u.id.clone(),
                    scope_type: "project".into(),
                    scope_value: "Alpha".into(),
                    permission: "write".into(),
                },
                PermissionRecord {
                    user_id: u.id.clone(),
                    scope_type: "category".into(),
                    scope_value: "dev".into(),
                    permission: "read".into(),
                },
            ],
        )
        .unwrap();
        // Re-run the migration as a fresh database would.
        conn.execute(
            "DELETE FROM vault_meta WHERE key = 'perm_expr_migrated'",
            [],
        )
        .unwrap();
        migrate_rows_to_expressions(&conn).unwrap();

        let read = get_permission_expr(&conn, "user", &u.id, "read")
            .unwrap()
            .unwrap();
        let write = get_permission_expr(&conn, "user", &u.id, "write")
            .unwrap()
            .unwrap();
        assert!(
            read.contains("project:Alpha") && read.contains("category:dev"),
            "read should be the OR of every row, got {read}"
        );
        assert!(
            write.contains("project:Alpha") && !write.contains("category:dev"),
            "write should only include write rows, got {write}"
        );
    }

    #[test]
    fn migration_runs_once_only() {
        let conn = scratch_conn("permmig-once");
        let u = create_user(&conn, "u1", Some("pw"), false).unwrap();
        set_permission_expr(&conn, "user", &u.id, "read", "tag:mine").unwrap();
        set_user_permissions(
            &conn,
            &u.id,
            &[PermissionRecord {
                user_id: u.id.clone(),
                scope_type: "vault".into(),
                scope_value: "*".into(),
                permission: "write".into(),
            }],
        )
        .unwrap();
        migrate_rows_to_expressions(&conn).unwrap();
        // Already migrated at schema init, so the legacy rows must not clobber
        // an expression an admin has since written.
        assert_eq!(
            get_permission_expr(&conn, "user", &u.id, "read")
                .unwrap()
                .unwrap(),
            "tag:mine"
        );
    }

    #[test]
    fn built_in_classes_get_expressions_on_a_fresh_vault() {
        // The seeded class rows must be compiled, or Admin/Viewer would silently
        // grant nothing at all.
        let conn = scratch_conn("permmig-seed");
        let admin = get_permission_expr(&conn, "class", "cls-admin", "write").unwrap();
        let viewer_read = get_permission_expr(&conn, "class", "cls-viewer", "read").unwrap();
        assert_eq!(admin.as_deref(), Some("vault:*"));
        assert_eq!(viewer_read.as_deref(), Some("vault:*"));
        assert!(
            get_permission_expr(&conn, "class", "cls-viewer", "write")
                .unwrap()
                .is_none(),
            "Viewer is read-only"
        );
    }

    #[test]
    fn invalid_expressions_are_rejected_on_save() {
        let conn = scratch_conn("permbad");
        let u = create_user(&conn, "u1", Some("pw"), false).unwrap();
        assert!(set_permission_expr(&conn, "user", &u.id, "read", "project:a AND").is_err());
        assert!(set_permission_expr(&conn, "user", &u.id, "read", "bogus:a").is_err());
        assert!(
            get_permission_expr(&conn, "user", &u.id, "read")
                .unwrap()
                .is_none(),
            "a rejected expression must not be stored"
        );
    }

    #[test]
    fn blank_expression_clears_the_rule() {
        let conn = scratch_conn("permclear");
        let u = create_user(&conn, "u1", Some("pw"), false).unwrap();
        set_permission_expr(&conn, "user", &u.id, "read", "tag:x").unwrap();
        set_permission_expr(&conn, "user", &u.id, "read", "   ").unwrap();
        assert!(get_permission_expr(&conn, "user", &u.id, "read")
            .unwrap()
            .is_none());
    }

    #[test]
    fn effective_read_includes_write_because_write_implies_read() {
        let conn = scratch_conn("permeff");
        let u = create_user(&conn, "u1", Some("pw"), false).unwrap();
        set_permission_expr(&conn, "user", &u.id, "write", "project:Alpha").unwrap();
        let read = effective_permission_expr(&conn, &u.id, "read")
            .unwrap()
            .expect("write should imply read");
        assert!(read.to_string().contains("project:Alpha"));
    }

    #[test]
    fn effective_expr_ands_class_with_individual() {
        let conn = scratch_conn("permand");
        let u = create_user(&conn, "u1", Some("pw"), false).unwrap();
        let cls = create_user_class(&conn, "Contractor", "", false, false, false).unwrap();
        assign_user_class(&conn, &u.id, Some(&cls.id)).unwrap();
        set_permission_expr(&conn, "class", &cls.id, "read", "NOT category:secret").unwrap();
        set_permission_expr(&conn, "user", &u.id, "read", "vault:*").unwrap();

        let expr = effective_permission_expr(&conn, &u.id, "read")
            .unwrap()
            .unwrap();
        let pn: HashMap<String, String> = HashMap::new();
        let secret =
            json!({ "provider": "S", "categories": ["secret"], "projectIds": ["Universal"] });
        let plain =
            json!({ "provider": "P", "categories": ["dev"],    "projectIds": ["Universal"] });
        assert!(
            !crate::permex::eval(&expr, &crate::permex::EntryView::from_entry(&secret, &pn)),
            "the class exclusion must survive the individual grant"
        );
        assert!(crate::permex::eval(
            &expr,
            &crate::permex::EntryView::from_entry(&plain, &pn)
        ));
    }

    #[test]
    fn a_user_with_no_rules_gets_nothing() {
        let conn = scratch_conn("permnone");
        let u = create_user(&conn, "u1", Some("pw"), false).unwrap();
        assert!(effective_permission_expr(&conn, &u.id, "read")
            .unwrap()
            .is_none());
        assert!(effective_permission_expr(&conn, &u.id, "write")
            .unwrap()
            .is_none());
    }

    // ── Vault filtering ───────────────────────────────────────────────────────

    fn sample_vault() -> serde_json::Value {
        json!({
            "api_keys": [
                { "id": "1", "provider": "Mine",   "categories": ["dev"],  "projectIds": ["Universal", "p1"] },
                { "id": "2", "provider": "Theirs", "categories": ["ops"],  "projectIds": ["Universal", "p2"] },
            ],
            "user_categories": ["dev", "ops", "secret/taxonomy"],
            "projects": [
                { "id": "Universal", "name": "Universal" },
                { "id": "p1", "name": "Alpha" },
                { "id": "p2", "name": "Beta" },
            ],
        })
    }

    #[test]
    fn vault_scope_sees_everything_untouched() {
        let out = filter_vault_for_user(sample_vault(), Some(&ex("vault:*")));
        assert_eq!(out["api_keys"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn project_scope_hides_other_projects() {
        let out = filter_vault_for_user(sample_vault(), Some(&ex("project:Alpha")));
        let keys = out["api_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["provider"], "Mine");
    }

    #[test]
    fn filtering_does_not_leak_the_category_taxonomy() {
        let out = filter_vault_for_user(sample_vault(), Some(&ex("project:Alpha")));
        let cats: Vec<&str> = out["user_categories"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.as_str())
            .collect();
        assert!(
            cats.contains(&"dev"),
            "categories on visible entries are kept"
        );
        assert!(
            !cats.contains(&"ops"),
            "categories only on hidden entries must not leak"
        );
        assert!(
            !cats.contains(&"secret/taxonomy"),
            "unused category names must not leak"
        );
    }

    // ── Write merge ───────────────────────────────────────────────────────────

    #[test]
    fn merge_rejects_submission_outside_write_scope() {
        let full = sample_vault();
        let submitted = json!({ "api_keys": [
            { "id": "2", "provider": "Theirs", "categories": ["ops"], "projectIds": ["Universal", "p2"] }
        ]});
        let err = merge_user_vault_write(
            full,
            submitted,
            Some(&ex("vault:*")),
            Some(&ex("project:Alpha")),
        )
        .expect_err("writing an out-of-scope entry must be refused");
        assert!(
            err.contains("Theirs"),
            "error should name the offending entry, got: {err}"
        );
    }

    #[test]
    fn merge_requires_some_write_permission() {
        let err = merge_user_vault_write(
            sample_vault(),
            json!({ "api_keys": [] }),
            Some(&ex("vault:*")),
            None,
        )
        .expect_err("read-only users must not be able to write at all");
        assert_eq!(err, "No write permissions");
    }

    /// Write coverage for entry "Mine" — under ANY-match the project grant alone
    /// is sufficient, since the entry belongs to project Alpha.

    #[test]
    fn merge_applies_in_scope_edits_and_preserves_the_rest() {
        let submitted = json!({ "api_keys": [
            { "id": "1", "provider": "Mine", "api_key": "updated",
              "categories": ["dev"], "projectIds": ["Universal", "p1"] }
        ]});
        let out = merge_user_vault_write(
            sample_vault(),
            submitted,
            Some(&ex("vault:*")),
            Some(&ex("project:Alpha")),
        )
        .unwrap();
        let keys = out["api_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2, "the out-of-scope entry must survive");
        let mine = keys.iter().find(|e| e["id"] == "1").unwrap();
        assert_eq!(mine["api_key"], "updated");
        assert!(
            keys.iter().any(|e| e["id"] == "2"),
            "Theirs must be untouched"
        );
    }

    #[test]
    fn merge_deletes_in_scope_entries_omitted_from_the_submission() {
        let out = merge_user_vault_write(
            sample_vault(),
            json!({ "api_keys": [] }),
            Some(&ex("vault:*")),
            Some(&ex("project:Alpha")),
        )
        .unwrap();
        let keys = out["api_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1, "the in-scope entry is deleted");
        assert_eq!(keys[0]["id"], "2", "the out-of-scope entry is not");
    }

    // ── projects and categories (regression: they used to vanish) ─────────────
    //
    // `merge_user_vault_write` rebuilt `api_keys` only and took `projects` and
    // `user_categories` straight from `full_vault`. The server then answered
    // 204. A sub-user creating a project or editing a chunk saw the change (the
    // frontend applies it to its own copy first) and the server kept nothing.

    /// A read+write grant over Alpha, which is what a project-scoped sub-user has.
    fn alpha() -> (crate::permex::Expr, crate::permex::Expr) {
        (ex("project:Alpha"), ex("project:Alpha"))
    }

    #[test]
    fn a_new_project_from_a_sub_user_is_persisted() {
        let (r, w) = alpha();
        let served = filter_vault_for_user(sample_vault(), Some(&r));
        let mut submitted = served.clone();
        submitted["projects"].as_array_mut().unwrap().push(json!({
            "id": "p9", "name": "Fresh", "project_type": "generic", "chunks": []
        }));
        let out = merge_user_vault_write(sample_vault(), submitted, Some(&r), Some(&w)).unwrap();
        let ids: Vec<&str> = out["projects"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["id"].as_str())
            .collect();
        assert!(ids.contains(&"p9"), "the new project must survive: {ids:?}");
        assert!(ids.contains(&"p2"), "Beta, which they cannot see, must too");
    }

    #[test]
    fn editing_a_project_they_fully_own_is_persisted() {
        // Alpha is referenced only by entry "Mine", which this user can write,
        // so the whole project is theirs to change — chunks included.
        let (r, w) = alpha();
        let mut submitted = filter_vault_for_user(sample_vault(), Some(&r));
        for p in submitted["projects"].as_array_mut().unwrap() {
            if p["id"] == "p1" {
                p["chunks"] = json!([{ "id": "c1", "name": "peer", "chunk_type": "wg_peer",
                                       "fields": [] }]);
            }
        }
        let out = merge_user_vault_write(sample_vault(), submitted, Some(&r), Some(&w)).unwrap();
        let alpha_out = out["projects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "p1")
            .unwrap();
        assert_eq!(
            alpha_out["chunks"][0]["name"], "peer",
            "the chunk the user added must be stored, not silently dropped"
        );
    }

    #[test]
    fn a_project_they_do_not_fully_own_is_refused_not_silently_ignored() {
        // Universal is referenced by both entries, one of which is out of scope.
        // Under the same ALL-scope rule entry writes use, it is not theirs.
        let (r, w) = alpha();
        let mut submitted = filter_vault_for_user(sample_vault(), Some(&r));
        for p in submitted["projects"].as_array_mut().unwrap() {
            if p["id"] == "Universal" {
                p["name"] = json!("Hijacked");
            }
        }
        let err = merge_user_vault_write(sample_vault(), submitted, Some(&r), Some(&w))
            .expect_err("must refuse rather than accept-and-discard");
        assert!(err.contains("Universal"), "must name the refusal: {err}");
    }

    #[test]
    fn a_project_the_user_cannot_see_survives_a_full_submission() {
        // The submission is a filtered document. Beta's absence from it means
        // "never shown", not "deleted" — confusing the two deletes other
        // people's projects on every sub-user save.
        let (r, w) = alpha();
        let submitted = filter_vault_for_user(sample_vault(), Some(&r));
        assert!(
            !submitted["projects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["id"] == "p2"),
            "fixture precondition: Beta is not served to this user"
        );
        let out = merge_user_vault_write(sample_vault(), submitted, Some(&r), Some(&w)).unwrap();
        assert!(
            out["projects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["id"] == "p2"),
            "Beta must survive"
        );
    }

    #[test]
    fn a_hidden_category_is_neither_deleted_nor_overwritable() {
        let (r, w) = alpha();
        let mut submitted = filter_vault_for_user(sample_vault(), Some(&r));
        submitted["user_categories"]
            .as_array_mut()
            .unwrap()
            .push(json!("newcat"));
        let out = merge_user_vault_write(sample_vault(), submitted, Some(&r), Some(&w)).unwrap();
        let cats: Vec<&str> = out["user_categories"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.as_str())
            .collect();
        assert!(cats.contains(&"newcat"), "the added category persists");
        assert!(
            cats.contains(&"secret/taxonomy"),
            "a category never served must not be pruned away: {cats:?}"
        );
        assert!(cats.contains(&"ops"), "nor one belonging to hidden entries");
    }

    #[test]
    fn omitting_the_collections_entirely_changes_nothing() {
        // A hand-rolled agent client PUTs only `api_keys`. Absent must mean
        // "unchanged", never "empty" — otherwise one such call wipes the
        // taxonomy for everybody.
        let (r, w) = alpha();
        let out = merge_user_vault_write(
            sample_vault(),
            json!({ "api_keys": [
                { "id": "1", "provider": "Mine", "categories": ["dev"],
                  "projectIds": ["Universal", "p1"] }
            ]}),
            Some(&r),
            Some(&w),
        )
        .unwrap();
        assert_eq!(out["projects"].as_array().unwrap().len(), 3);
        assert_eq!(out["user_categories"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn a_sub_user_cannot_overwrite_a_project_by_guessing_its_id() {
        // p2 exists but was never served. Submitting it as if it were new must
        // not clobber it — that would be a read-scope bypass through the write
        // path.
        let (r, w) = alpha();
        let mut submitted = filter_vault_for_user(sample_vault(), Some(&r));
        submitted["projects"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "id": "p2", "name": "Stolen" }));
        let out = merge_user_vault_write(sample_vault(), submitted, Some(&r), Some(&w)).unwrap();
        let betas: Vec<&serde_json::Value> = out["projects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["id"] == "p2")
            .collect();
        assert_eq!(betas.len(), 1, "must not duplicate it either");
        assert_eq!(betas[0]["name"], "Beta", "the real Beta is untouched");
    }

    #[test]
    fn merge_cannot_alias_an_out_of_scope_entry_via_key_id() {
        // Identity includes key_id. If it did not, a writable entry could be
        // crafted to collide with an out-of-scope one and overwrite it.
        let full = json!({ "api_keys": [
            { "provider": "AWS", "account_name": "acct", "key_id": "locked",
              "api_key": "secret", "categories": ["ops"], "projectIds": ["Universal", "p2"] },
            { "provider": "AWS", "account_name": "acct", "key_id": "mine",
              "api_key": "ok",     "categories": ["dev"], "projectIds": ["Universal", "p1"] },
        ],
        "projects": [{ "id": "p1", "name": "Alpha" }, { "id": "p2", "name": "Beta" }]});

        let submitted = json!({ "api_keys": [
            { "provider": "AWS", "account_name": "acct", "key_id": "mine",
              "api_key": "changed", "categories": ["dev"], "projectIds": ["Universal", "p1"] }
        ]});
        let out = merge_user_vault_write(
            full,
            submitted,
            Some(&ex("vault:*")),
            Some(&ex("project:Alpha")),
        )
        .unwrap();
        let keys = out["api_keys"].as_array().unwrap();
        let locked = keys.iter().find(|e| e["key_id"] == "locked").unwrap();
        assert_eq!(
            locked["api_key"], "secret",
            "the out-of-scope key must be untouched"
        );
    }
}

#[cfg(test)]
mod strict_write_tests {
    use super::*;
    use crate::permex;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        // The user schema's expression migration writes a marker into
        // `vault_meta`, which the vault schema owns — so the vault schema comes
        // first here, exactly as it does in `unlock_vault`.
        crate::init_schema(&c).unwrap();
        init_users_schema(&c).unwrap();
        c
    }

    /// The transform is the feature: an OR chain becomes an AND chain.
    #[test]
    fn require_all_turns_any_scope_into_every_scope() {
        let e = permex::parse("project:web OR project:api OR project:db").unwrap();
        let strict = permex::require_all(e);
        assert_eq!(
            strict.to_string(),
            "((project:web AND project:api) AND project:db)"
        );
    }

    /// Explicit grouping an author wrote is left alone.
    ///
    /// `(a OR b) AND c` is a rule someone stated precisely. Rewriting its inner
    /// alternation would change a decision that was already made, and strictness
    /// is about the implicit OR that scope-joining introduced.
    #[test]
    fn require_all_does_not_rewrite_nested_groups() {
        let e = permex::parse("(project:web OR project:api) AND env:prod").unwrap();
        let before = e.to_string();
        assert_eq!(permex::require_all(e).to_string(), before);
    }

    /// Strict mode narrows writes and leaves reads alone.
    ///
    /// Regression test for the tempting mistake: strictifying reads too. A user
    /// who cannot see an entry cannot review the change they are making, and
    /// their vault would appear empty the moment the flag went on.
    #[test]
    fn strict_mode_narrows_writes_only() {
        let c = db();
        let uid = create_user(&c, "alice", Some("password-1234"), false)
            .unwrap()
            .id;
        set_permission_expr(&c, "user", &uid, "write", "project:web OR project:api").unwrap();

        let lax = effective_permission_expr(&c, &uid, "write")
            .unwrap()
            .unwrap();
        assert_eq!(lax.to_string(), "(project:web OR project:api)");

        set_strict_write(&c, "user", &uid, true).unwrap();
        let strict = effective_permission_expr(&c, &uid, "write")
            .unwrap()
            .unwrap();
        assert_eq!(strict.to_string(), "(project:web AND project:api)");

        // Read still sees either, via "write implies read".
        let read = effective_permission_expr(&c, &uid, "read")
            .unwrap()
            .unwrap();
        assert_eq!(read.to_string(), "(project:web OR project:api)");
    }

    /// A class can impose strictness its members cannot shed.
    #[test]
    fn a_strict_class_makes_its_members_strict() {
        let c = db();
        let cid = create_user_class(&c, "Deployers", "", false, false, false)
            .unwrap()
            .id;
        let uid = create_user(&c, "bob", Some("password-1234"), false)
            .unwrap()
            .id;
        assign_user_class(&c, &uid, Some(&cid)).unwrap();
        set_permission_expr(&c, "user", &uid, "write", "project:web OR project:api").unwrap();

        assert!(!strict_write_for(&c, &uid).unwrap());
        set_strict_write(&c, "class", &cid, true).unwrap();
        assert!(
            strict_write_for(&c, &uid).unwrap(),
            "a strict class must bind its members, or the class is not a boundary"
        );
    }

    /// Existing users are untouched by the migration.
    ///
    /// A release that silently tightened permissions would break running
    /// deployments in a way nobody could attribute to the upgrade.
    #[test]
    fn strict_is_off_by_default() {
        let c = db();
        let uid = create_user(&c, "carol", Some("password-1234"), false)
            .unwrap()
            .id;
        assert!(!strict_write_for(&c, &uid).unwrap());
    }

    /// Setting the flag on something that does not exist is an error, not a
    /// silent no-op that leaves an operator believing they hardened an account.
    #[test]
    fn setting_strict_on_a_missing_subject_fails() {
        let c = db();
        assert!(set_strict_write(&c, "user", "no-such-id", true).is_err());
        assert!(set_strict_write(&c, "banana", "x", true).is_err());
    }
}
