// API Vault — Tauri backend (Phase 2)
//
// Commands are in a submodule to avoid a Tauri 2 proc-macro scoping collision:
// #[tauri::command] emits __cmd__* macros into the enclosing module, and
// generate_handler![] in that same module tries to import them again → E0255.
// Placing commands in mod commands { } gives each macro its own namespace.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::Zeroize;

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

const SALT_LEN: usize = 16;
const KEY_LEN:  usize = 32;
const A2_M_COST: u32  = 65_536;
const A2_T_COST: u32  = 3;
const A2_P_COST: u32  = 1;

// ── MANAGED STATE ─────────────────────────────────────────────────────────────

pub struct VaultState(pub Mutex<Option<[u8; KEY_LEN]>>);

// ── PATH HELPERS ──────────────────────────────────────────────────────────────

fn db_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir()
        .map(|d| d.join("vault.db"))
        .map_err(|e| e.to_string())
}

fn salt_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir()
        .map(|d| d.join("vault.salt"))
        .map_err(|e| e.to_string())
}

fn legacy_json_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir()
        .map(|d| d.join("vault.json"))
        .map_err(|e| e.to_string())
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_config_dir()
        .map(|d| d.join("settings.json"))
        .map_err(|e| e.to_string())
}

fn ensure_parent(path: &PathBuf) -> Result<(), String> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── KDF ───────────────────────────────────────────────────────────────────────

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

fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault (
             id   INTEGER PRIMARY KEY CHECK (id = 1),
             data TEXT    NOT NULL
         );"
    ).map_err(|e| e.to_string())
}

// ── COMMANDS ──────────────────────────────────────────────────────────────────
// All #[tauri::command] functions live here so their __cmd__* proc-macro
// outputs stay in this namespace, separate from the generate_handler![] call
// in run() above.

mod commands {
    use super::*;
    use tauri::State;

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

        // Phase 1 migration
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

    #[tauri::command]
    pub fn lock_vault(state: State<VaultState>) -> Result<(), String> {
        let mut guard = state.0.lock().map_err(|_| "State lock poisoned".to_string())?;
        if let Some(mut k) = guard.take() { k.zeroize(); }
        Ok(())
    }

    #[tauri::command]
    pub fn vault_is_unlocked(state: State<VaultState>) -> bool {
        state.0.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    #[tauri::command]
    pub fn vault_exists(app: AppHandle) -> Result<bool, String> {
        Ok(db_path(&app)?.exists())
    }

    #[tauri::command]
    pub fn reset_vault(app: AppHandle, state: State<VaultState>) -> Result<(), String> {
        let mut guard = state.0.lock().map_err(|_| "State lock poisoned".to_string())?;
        if let Some(mut k) = guard.take() { k.zeroize(); }
        let _ = fs::remove_file(db_path(&app)?);
        let _ = fs::remove_file(salt_path(&app)?);
        Ok(())
    }

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

    #[tauri::command]
    pub fn save_vault(
        app: AppHandle,
        state: State<VaultState>,
        data: serde_json::Value,
    ) -> Result<(), String> {
        let guard = state.0.lock().map_err(|_| "State lock poisoned".to_string())?;
        let key = guard.as_ref().ok_or("Vault is locked")?;

        let conn = open_db(&db_path(&app)?, key)?;
        let raw  = serde_json::to_string(&data).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO vault (id, data) VALUES (1, ?1)",
            rusqlite::params![raw],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[tauri::command]
    pub fn get_vault_path(app: AppHandle) -> Result<String, String> {
        db_path(&app).map(|p| p.display().to_string())
    }

    #[tauri::command]
    pub fn load_settings(app: AppHandle) -> Result<Option<serde_json::Value>, String> {
        let path = settings_path(&app)?;
        if !path.exists() { return Ok(None); }
        let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        serde_json::from_str(&raw).map(Some).map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub fn save_settings(app: AppHandle, data: serde_json::Value) -> Result<(), String> {
        let path = settings_path(&app)?;
        ensure_parent(&path)?;
        let pretty = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
        fs::write(&path, pretty).map_err(|e| e.to_string())
    }
}

// ── APP ENTRY ─────────────────────────────────────────────────────────────────

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
        ])
        .run(tauri::generate_context!())
        .expect("error while running API Vault");
}