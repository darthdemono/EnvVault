//! API Vault — Tauri backend library.
//!
//! Provides an SQLCipher-encrypted vault for storing API keys and other
//! secrets.  The master password never touches disk; it is derived into a
//! 32-byte AES key via Argon2id and held in [`VaultState`] for the duration
//! of the session.
//!
//! # Architecture
//!
//! ```text
//! Frontend (TypeScript)
//!     │  window.__TAURI__.core.invoke(...)
//!     ▼
//! mod commands   ← all #[tauri::command] functions live here
//!     │          (separate namespace avoids Tauri 2 E0255 proc-macro collision)
//!     ▼
//! SQLCipher DB  ←  open_db() + init_schema()
//!     │
//! Argon2id KDF  ←  derive_key()
//!     │
//! vault.salt    ←  16-byte random salt persisted next to the DB
//! ```
//!
//! # Command overview
//!
//! | Command | Description |
//! |---------|-------------|
//! | `unlock_vault` | KDF → open DB → store key in memory |
//! | `lock_vault` | Zeroize key from memory |
//! | `vault_is_unlocked` | Non-destructive lock check |
//! | `vault_exists` | Check whether a DB file is present |
//! | `reset_vault` | Wipe DB and salt from disk |
//! | `load_vault` | Decrypt and return vault JSON |
//! | `save_vault` | Encrypt and persist vault JSON |
//! | `get_vault_path` | Return absolute path to `vault.db` |
//! | `load_settings` | Read plain-text `settings.json` |
//! | `save_settings` | Write pretty-printed `settings.json` |
//! | `generate_certificate` | Generate self-signed X.509 cert + key PEM |
//! | `generate_ssh_keypair` | Generate Ed25519 SSH key pair |

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::Zeroize;
use rcgen::{CertificateParams, KeyPair, DnType, DistinguishedName};
use time::Duration;

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

/// Byte length of the random Argon2id salt stored in `vault.salt`.
const SALT_LEN: usize = 16;

/// Byte length of the derived AES-256 key stored in [`VaultState`].
const KEY_LEN:  usize = 32;

/// Argon2id memory cost in KiB (64 MiB).
const A2_M_COST: u32  = 65_536;

/// Argon2id time cost (number of passes).
const A2_T_COST: u32  = 3;

/// Argon2id parallelism factor.
const A2_P_COST: u32  = 1;

// ── MANAGED STATE ─────────────────────────────────────────────────────────────

/// Tauri-managed state holding the in-memory AES-256 vault key.
///
/// Wrapped in `Mutex<Option<_>>` so that:
/// - Multiple Tauri commands can safely share the key across threads.
/// - `None` unambiguously means the vault is locked.
/// - `lock_vault` can zeroize the key bytes before dropping them.
///
/// The key is **never** written to disk; only the 16-byte random salt is
/// persisted alongside the encrypted database.
pub struct VaultState(pub Mutex<Option<[u8; KEY_LEN]>>);

// ── PATH HELPERS ──────────────────────────────────────────────────────────────

/// Returns the absolute path to `vault.db` inside the app data directory.
///
/// # Errors
/// Returns `Err(String)` if Tauri cannot resolve `app_data_dir`.
fn db_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir()
        .map(|d| d.join("vault.db"))
        .map_err(|e| e.to_string())
}

/// Returns the absolute path to `vault.salt` inside the app data directory.
///
/// The salt file is created on first [`commands::unlock_vault`] and must never
/// be deleted while the database exists, as it is required to re-derive the key.
///
/// # Errors
/// Returns `Err(String)` if Tauri cannot resolve `app_data_dir`.
fn salt_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir()
        .map(|d| d.join("vault.salt"))
        .map_err(|e| e.to_string())
}

/// Returns the path to the legacy Phase 1 `vault.json` export file.
///
/// Used during the one-time migration in [`commands::unlock_vault`]: if this
/// file exists it is imported into SQLCipher and then removed.
///
/// # Errors
/// Returns `Err(String)` if Tauri cannot resolve `app_data_dir`.
fn legacy_json_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir()
        .map(|d| d.join("vault.json"))
        .map_err(|e| e.to_string())
}

/// Returns the absolute path to `settings.json` inside the app *config* directory.
///
/// Settings are stored in plain JSON (not encrypted) so they survive a vault
/// reset without requiring the master password.
///
/// # Errors
/// Returns `Err(String)` if Tauri cannot resolve `app_config_dir`.
fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_config_dir()
        .map(|d| d.join("settings.json"))
        .map_err(|e| e.to_string())
}

/// Creates all missing parent directories for `path`.
///
/// Called before writing any file to ensure the app data / config directories
/// exist on the first run.
///
/// # Errors
/// Returns `Err(String)` if directory creation fails.
fn ensure_parent(path: &PathBuf) -> Result<(), String> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── KDF ───────────────────────────────────────────────────────────────────────

/// Derives a 32-byte AES-256 key from `password` and `salt` using Argon2id.
///
/// Parameters: m=65536 KiB, t=3, p=1, output=32 bytes (OWASP 2023 recommendation).
///
/// # Arguments
/// * `password` – Master password in UTF-8.
/// * `salt`     – 16-byte random salt read from `vault.salt`.
///
/// # Returns
/// A `[u8; 32]` key suitable for use as an SQLCipher PRAGMA key.
///
/// # Errors
/// Returns `Err(String)` if Argon2id parameter construction or hashing fails.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let params = Params::new(A2_M_COST, A2_T_COST, A2_P_COST, Some(KEY_LEN))
        .map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

// ── SQLCIPHER ─────────────────────────────────────────────────────────────────

/// Opens (or creates) the SQLCipher database at `db` using the 32-byte `key`.
///
/// The key is passed as a hex-encoded `PRAGMA key` string.  A test query
/// (`SELECT count(*) FROM sqlite_master`) is executed immediately to verify
/// that the key is correct; a wrong password causes this query to fail.
///
/// # Arguments
/// * `db`  – Path to `vault.db`.
/// * `key` – Derived AES-256 key bytes.
///
/// # Returns
/// An open, authenticated [`rusqlite::Connection`].
///
/// # Errors
/// * `Err("Wrong master password")` – Key derivation succeeded but the DB
///   reports a decryption error (wrong password or corrupt file).
/// * Other `Err(String)` – SQLite / SQLCipher I/O errors.
fn open_db(db: &PathBuf, key: &[u8; KEY_LEN]) -> Result<Connection, String> {
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    ).map_err(|e| e.to_string())?;

    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key)))
        .map_err(|e| e.to_string())?;

    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|_| "Wrong master password".to_string())?;

    Ok(conn)
}

/// Creates the `vault` table if it does not already exist.
///
/// The table holds a single row (`id = 1`) containing the entire vault as a
/// JSON blob.  The `CHECK (id = 1)` constraint enforces the single-row invariant
/// at the database level.
///
/// # Errors
/// Returns `Err(String)` if the DDL statement fails.
fn init_schema(conn: &Connection) -> Result<(), String> {
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
    ).map_err(|e| e.to_string())
}

// ── COMMANDS ──────────────────────────────────────────────────────────────────
// All #[tauri::command] functions live here so their __cmd__* proc-macro
// outputs stay in this namespace, separate from the generate_handler![] call
// in run() above.

/// Tauri command handlers.
///
/// Commands are isolated in this submodule to avoid the Tauri 2 proc-macro
/// namespace collision described in the crate-level documentation (`E0255`).
mod commands {
    use super::*;
    use tauri::State;

    /// Unlocks the vault by deriving the AES key from the master password.
    ///
    /// Steps:
    /// 1. Read or generate the 16-byte random salt from `vault.salt`.
    /// 2. Derive a 32-byte Argon2id key from `password` + salt.
    /// 3. Open (or create) the SQLCipher database and verify the key.
    /// 4. Initialise the schema if this is the first run.
    /// 5. Migrate a legacy Phase 1 `vault.json` if present.
    /// 6. Store the key in [`VaultState`] for subsequent commands.
    ///
    /// # Arguments
    /// * `app`      – Tauri app handle used to resolve data directory paths.
    /// * `state`    – Shared vault key state.
    /// * `password` – Master password entered by the user.
    ///
    /// # Returns
    /// `Ok(true)` on success.
    ///
    /// # Errors
    /// * Wrong password → `"Wrong master password"`.
    /// * Corrupt salt file → `"vault.salt is corrupt"`.
    /// * I/O or Argon2 failures.
    #[tauri::command]
    pub fn unlock_vault(
        app: AppHandle,
        state: State<VaultState>,
        password: String,
    ) -> Result<bool, String> {
        let db        = db_path(&app)?;
        let salt_file = salt_path(&app)?;
        ensure_parent(&db)?;

        let salt: [u8; SALT_LEN] = if salt_file.exists() {
            let raw = fs::read(&salt_file).map_err(|e| e.to_string())?;
            raw.try_into().map_err(|_| "vault.salt is corrupt".to_string())?
        } else {
            use rand::RngCore;
            let mut s = [0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut s);
            fs::write(&salt_file, &s).map_err(|e| e.to_string())?;
            s
        };

        let key  = derive_key(&password, &salt)?;
        let conn = open_db(&db, &key)?;
        init_schema(&conn)?;

        // Phase 1 migration: import legacy vault.json into SQLCipher, then remove it.
        let legacy = legacy_json_path(&app)?;
        if legacy.exists() {
            let raw = fs::read_to_string(&legacy).map_err(|e| e.to_string())?;
            let _: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| format!("Legacy vault.json invalid: {e}"))?;
            conn.execute(
                "INSERT OR REPLACE INTO vault (id, data) VALUES (1, ?1)",
                rusqlite::params![raw],
            ).map_err(|e| e.to_string())?;
            fs::remove_file(&legacy).ok();
        }

        let mut guard = state.0.lock().map_err(|_| "State lock poisoned".to_string())?;
        *guard = Some(key);
        Ok(true)
    }

    /// Locks the vault by zeroizing the in-memory key.
    ///
    /// After this call `vault_is_unlocked` returns `false` and any subsequent
    /// `load_vault` / `save_vault` calls will fail with `"Vault is locked"`.
    ///
    /// # Errors
    /// Returns `Err("State lock poisoned")` if the Mutex has been poisoned.
    #[tauri::command]
    pub fn lock_vault(state: State<VaultState>) -> Result<(), String> {
        let mut guard = state.0.lock().map_err(|_| "State lock poisoned".to_string())?;
        if let Some(mut k) = guard.take() { k.zeroize(); }
        Ok(())
    }

    /// Returns `true` if the vault is currently unlocked (key is in memory).
    ///
    /// This is a non-destructive check safe to call at any time.
    #[tauri::command]
    pub fn vault_is_unlocked(state: State<VaultState>) -> bool {
        state.0.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Returns `true` if the `vault.db` file exists on disk.
    ///
    /// Used by the frontend on startup to decide whether to show the
    /// "Create Master Password" flow or the "Unlock" form.
    ///
    /// # Errors
    /// Returns `Err(String)` if the app data directory cannot be resolved.
    #[tauri::command]
    pub fn vault_exists(app: AppHandle) -> Result<bool, String> {
        Ok(db_path(&app)?.exists())
    }

    /// Wipes the vault database and salt file from disk, and clears the in-memory key.
    ///
    /// This is a destructive, irreversible operation used by the "Reset Vault"
    /// button.  After this call the user must create a new master password.
    ///
    /// # Errors
    /// Returns `Err("State lock poisoned")` if the Mutex has been poisoned.
    #[tauri::command]
    pub fn reset_vault(app: AppHandle, state: State<VaultState>) -> Result<(), String> {
        let mut guard = state.0.lock().map_err(|_| "State lock poisoned".to_string())?;
        if let Some(mut k) = guard.take() { k.zeroize(); }
        let _ = fs::remove_file(db_path(&app)?);
        let _ = fs::remove_file(salt_path(&app)?);
        Ok(())
    }

    /// Loads and decrypts the entire vault JSON from SQLCipher.
    ///
    /// Opens the database fresh on each call (no persistent connection) to
    /// keep the locking model simple and avoid dangling connections.
    ///
    /// # Returns
    /// `Ok(Some(value))` with the parsed `VaultData` JSON, or `Ok(None)` if
    /// the vault table exists but contains no row yet (first run after unlock).
    ///
    /// # Errors
    /// * `"Vault is locked"` – No key in memory.
    /// * `"State lock poisoned"` – Mutex poisoned.
    /// * I/O / SQLite / JSON parse errors.
    #[tauri::command]
    pub fn load_vault(
        app: AppHandle,
        state: State<VaultState>,
    ) -> Result<Option<serde_json::Value>, String> {
        let guard = state.0.lock().map_err(|_| "State lock poisoned".to_string())?;
        let key = guard.as_ref().ok_or("Vault is locked")?;

        let conn = open_db(&db_path(&app)?, key)?;
        let raw: Option<String> = conn
            .query_row("SELECT data FROM vault WHERE id = 1", [], |row| row.get(0))
            .optional()
            .map_err(|e| e.to_string())?;

        match raw {
            None => Ok(None),
            Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| e.to_string()),
        }
    }

    /// Serialises `data` to JSON and writes it to the encrypted SQLCipher vault.
    ///
    /// Before writing, diffs the incoming entries against the current row:
    /// - Changed `api_key`: old value is prepended to `version_history` (capped at 50).
    /// - Added / deleted / updated entries are recorded in `vault_audit`.
    ///
    /// # Arguments
    /// * `app`   – App handle for path resolution.
    /// * `state` – Shared vault key state.
    /// * `data`  – Arbitrary JSON value (the serialised `VaultData` object).
    ///
    /// # Errors
    /// * `"Vault is locked"` – No key in memory.
    /// * I/O / SQLite / JSON serialisation errors.
    #[tauri::command]
    pub fn save_vault(
        app: AppHandle,
        state: State<VaultState>,
        data: serde_json::Value,
    ) -> Result<(), String> {
        use std::collections::{HashMap, HashSet};

        let guard = state.0.lock().map_err(|_| "State lock poisoned".to_string())?;
        let key = guard.as_ref().ok_or("Vault is locked")?;

        let conn = open_db(&db_path(&app)?, key)?;

        // ISO-8601 UTC timestamp for this save operation
        let ts = time::OffsetDateTime::now_utc();
        let now_str = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            ts.year(), ts.month() as u8, ts.day(),
            ts.hour(), ts.minute(), ts.second());

        // Load existing vault for diffing (None on first save)
        let existing: Option<serde_json::Value> = conn
            .query_row("SELECT data FROM vault WHERE id = 1", [], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|e| e.to_string())?
            .and_then(|s| serde_json::from_str(&s).ok());

        // Build map: "provider|account_name" → old entry
        let old_map: HashMap<String, serde_json::Value> = existing
            .as_ref()
            .and_then(|v| v.get("api_keys"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        let p = e.get("provider")?.as_str()?.to_string();
                        let a = e.get("account_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        Some((format!("{}|{}", p, a), e.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Set of composite keys present in incoming data (for delete detection)
        let new_keys: HashSet<String> = data
            .get("api_keys")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        let p = e.get("provider")?.as_str()?.to_string();
                        let a = e.get("account_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        Some(format!("{}|{}", p, a))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Audit: deleted entries
        for (ck, old_e) in &old_map {
            if !new_keys.contains(ck) {
                let provider = old_e.get("provider").and_then(|v| v.as_str()).unwrap_or("");
                conn.execute(
                    "INSERT INTO vault_audit (action, entry_provider, timestamp, details) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params!["delete", provider, now_str, Option::<&str>::None],
                ).map_err(|e| e.to_string())?;
            }
        }

        // Inject version_history + audit add/update for each entry
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
                        // Inherit history from old entry if the frontend stripped it
                        let mut history: Vec<serde_json::Value> = entry
                            .get("version_history")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_else(|| {
                                old_e.get("version_history")
                                    .and_then(|v| v.as_array())
                                    .cloned()
                                    .unwrap_or_default()
                            });

                        history.insert(0, serde_json::json!({ "value": old_val, "saved_at": now_str }));
                        history.truncate(50);

                        if let Some(obj) = entry.as_object_mut() {
                            obj.insert("version_history".to_string(), serde_json::Value::Array(history));
                        }

                        conn.execute(
                            "INSERT INTO vault_audit (action, entry_provider, timestamp, details) VALUES (?1, ?2, ?3, ?4)",
                            rusqlite::params!["update", provider, now_str, "api_key rotated"],
                        ).map_err(|e| e.to_string())?;
                    }
                } else {
                    // Brand-new entry
                    conn.execute(
                        "INSERT INTO vault_audit (action, entry_provider, timestamp, details) VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params!["add", provider, now_str, Option::<&str>::None],
                    ).map_err(|e| e.to_string())?;
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

    /// Returns the absolute filesystem path to `vault.db` as a string.
    ///
    /// Used by the frontend "Show in Explorer" / path-display feature.
    ///
    /// # Errors
    /// Returns `Err(String)` if the app data directory cannot be resolved.
    #[tauri::command]
    pub fn get_vault_path(app: AppHandle) -> Result<String, String> {
        db_path(&app).map(|p| p.display().to_string())
    }

    /// Reads `settings.json` from the app config directory and returns it as JSON.
    ///
    /// Settings are stored unencrypted so they are accessible before the vault
    /// is unlocked.  Returns `Ok(None)` if no settings file exists yet.
    ///
    /// # Errors
    /// Returns `Err(String)` on I/O or JSON parse failure.
    #[tauri::command]
    pub fn load_settings(app: AppHandle) -> Result<Option<serde_json::Value>, String> {
        let path = settings_path(&app)?;
        if !path.exists() { return Ok(None); }
        let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        serde_json::from_str(&raw).map(Some).map_err(|e| e.to_string())
    }

    /// Serialises `data` to pretty-printed JSON and writes it to `settings.json`.
    ///
    /// Parent directories are created if they do not exist.
    ///
    /// # Errors
    /// Returns `Err(String)` on JSON serialisation or I/O failure.
    #[tauri::command]
    pub fn save_settings(app: AppHandle, data: serde_json::Value) -> Result<(), String> {
        let path = settings_path(&app)?;
        ensure_parent(&path)?;
        let pretty = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
        fs::write(&path, pretty).map_err(|e| e.to_string())
    }

    /// Generates a self-signed X.509 certificate and its private key.
    ///
    /// Returns `{"cert_pem": "...", "key_pem": "..."}`.
    #[tauri::command]
    pub fn generate_certificate(common_name: String, validity_days: u32) -> Result<serde_json::Value, String> {
        let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = CertificateParams::new(vec![common_name.clone()])
            .map_err(|e| e.to_string())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.not_after = time::OffsetDateTime::now_utc()
            + Duration::days(validity_days.max(1) as i64);
        let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "cert_pem": cert.pem(),
            "key_pem": key_pair.serialize_pem()
        }))
    }

    /// Generates an Ed25519 SSH key pair in OpenSSH format.
    ///
    /// Returns `{"public_key": "...", "private_key": "..."}`.
    #[tauri::command]
    pub fn generate_ssh_keypair(comment: String) -> Result<serde_json::Value, String> {
        use ssh_key::{PrivateKey, Algorithm, LineEnding};
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let mut private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .map_err(|e| e.to_string())?;
        private_key.set_comment(&comment);
        let public_key_str = private_key.public_key().to_openssh()
            .map_err(|e| e.to_string())?;
        let private_key_str = private_key.to_openssh(LineEnding::LF)
            .map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "public_key": public_key_str,
            "private_key": private_key_str.to_string()
        }))
    }
}

// ── APP ENTRY ─────────────────────────────────────────────────────────────────

/// Builds and runs the Tauri application.
///
/// Performs Linux-specific WebKitGTK setup before constructing the Tauri builder:
/// - Sets `GDK_BACKEND=x11` to prevent Wayland protocol errors on compositors
///   that do not fully support the Wayland XDG-shell protocol.
/// - Sets `WEBKIT_DISABLE_COMPOSITING_MODE=1` to avoid GPU compositing crashes
///   on some Mesa/EGL configurations.
/// - Sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` to disable the DMA-BUF renderer
///   which can cause blank windows on Nvidia proprietary drivers.
///
/// Registers [`VaultState`] as managed Tauri state and exposes all commands
/// from [`commands`] via `generate_handler!`.
///
/// # Panics
/// Panics with `"error while running API Vault"` if the Tauri event loop exits
/// with an error (e.g. the window could not be created).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "linux")]
    {
        std::env::set_var("GDK_BACKEND", "x11");
        std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(VaultState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            commands::unlock_vault,
            commands::lock_vault,
            commands::vault_is_unlocked,
            commands::vault_exists,
            commands::reset_vault,
            commands::load_vault,
            commands::save_vault,
            commands::get_vault_path,
            commands::load_settings,
            commands::save_settings,
            commands::generate_certificate,
            commands::generate_ssh_keypair,
        ])
        .run(tauri::generate_context!())
        .expect("error while running API Vault");
}
