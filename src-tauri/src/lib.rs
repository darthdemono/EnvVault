//! API Vault — Tauri backend.
//!
//! Thin wrappers around `vault-core`; resolves filesystem paths via Tauri's
//! `AppHandle` and exposes each operation as a `#[tauri::command]`.
//!
//! All commands live inside `mod commands {}` to avoid Tauri 2 E0255
//! proc-macro namespace collision.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};
use vault_core::VaultKey;
use zeroize::Zeroize;

// ── Managed state ─────────────────────────────────────────────────────────────

/// Holds the in-memory AES-256 vault key.  `None` means locked.
pub struct VaultState(pub Mutex<Option<VaultKey>>);

// ── Path helpers ──────────────────────────────────────────────────────────────

fn db_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir().map(|d| d.join("vault.db")).map_err(|e| e.to_string())
}
fn salt_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir().map(|d| d.join("vault.salt")).map_err(|e| e.to_string())
}
fn legacy_json_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir().map(|d| d.join("vault.json")).map_err(|e| e.to_string())
}
fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_config_dir().map(|d| d.join("settings.json")).map_err(|e| e.to_string())
}
fn ensure_parent(path: &PathBuf) -> Result<(), String> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── Commands ──────────────────────────────────────────────────────────────────

mod commands {
    use super::*;
    use tauri::State;
    // Use fully-qualified vault_core:: calls inside each fn to avoid
    // name collision with the Tauri command functions (which keep original names).

    #[tauri::command]
    pub fn unlock_vault(
        app: AppHandle,
        state: State<VaultState>,
        password: String,
    ) -> Result<bool, String> {
        let db        = db_path(&app)?;
        let salt_file = salt_path(&app)?;
        ensure_parent(&db)?;

        let salt = vault_core::read_or_create_salt(&salt_file)?;
        let key  = vault_core::derive_key(&password, &salt)?;
        let conn = vault_core::open_db(&db, &key)?;
        vault_core::init_schema(&conn)?;

        // Phase 1 migration: import legacy vault.json then remove it.
        let legacy = legacy_json_path(&app)?;
        if legacy.exists() {
            let raw = fs::read_to_string(&legacy).map_err(|e| e.to_string())?;
            let _: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| format!("Legacy vault.json invalid: {e}"))?;
            vault_core::migrate_legacy_json(&conn, &raw)?;
            fs::remove_file(&legacy).ok();
        }

        *state.0.lock().map_err(|_| "State lock poisoned")? = Some(key);
        Ok(true)
    }

    #[tauri::command]
    pub fn lock_vault(state: State<VaultState>) -> Result<(), String> {
        let mut g = state.0.lock().map_err(|_| "State lock poisoned")?;
        if let Some(mut k) = g.take() { k.zeroize(); }
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
        let mut g = state.0.lock().map_err(|_| "State lock poisoned")?;
        if let Some(mut k) = g.take() { k.zeroize(); }
        let _ = fs::remove_file(db_path(&app)?);
        let _ = fs::remove_file(salt_path(&app)?);
        Ok(())
    }

    #[tauri::command]
    pub fn load_vault(
        app:   AppHandle,
        state: State<VaultState>,
    ) -> Result<Option<serde_json::Value>, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::load_vault(&conn)
    }

    #[tauri::command]
    pub fn save_vault(
        app:   AppHandle,
        state: State<VaultState>,
        data:  serde_json::Value,
    ) -> Result<(), String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::save_vault(&conn, data)
    }

    #[tauri::command]
    pub fn get_vault_path(app: AppHandle) -> Result<String, String> {
        db_path(&app).map(|p| p.display().to_string())
    }

    #[tauri::command]
    pub fn load_settings(app: AppHandle) -> Result<Option<serde_json::Value>, String> {
        let path = settings_path(&app)?;
        if !path.exists() { return Ok(None); }
        serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map(Some).map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub fn save_settings(app: AppHandle, data: serde_json::Value) -> Result<(), String> {
        let path = settings_path(&app)?;
        ensure_parent(&path)?;
        fs::write(path, serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub fn get_expiring(
        app:   AppHandle,
        state: State<VaultState>,
        days:  u32,
    ) -> Result<Vec<serde_json::Value>, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::get_expiring_entries(&conn, days)
    }

    #[tauri::command]
    pub fn get_audit_log(
        app:   AppHandle,
        state: State<VaultState>,
    ) -> Result<Vec<vault_core::AuditRow>, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::load_audit(&conn)
    }

    #[tauri::command]
    pub fn generate_certificate(
        common_name:   String,
        validity_days: u32,
    ) -> Result<serde_json::Value, String> {
        vault_core::generate_certificate(&common_name, validity_days)
    }

    #[tauri::command]
    pub fn generate_ssh_keypair(comment: String) -> Result<serde_json::Value, String> {
        vault_core::generate_ssh_keypair(&comment)
    }
}

// ── App entry ─────────────────────────────────────────────────────────────────

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
            commands::get_expiring,
            commands::get_audit_log,
            commands::generate_certificate,
            commands::generate_ssh_keypair,
        ])
        .run(tauri::generate_context!())
        .expect("error while running API Vault");
}
