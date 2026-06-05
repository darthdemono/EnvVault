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

        // Seed owner account "admin" on first unlock (no users yet).
        let user_count: i32 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .unwrap_or(0);
        if user_count == 0 {
            vault_core::create_user(&conn, "admin", Some(&password), true).ok();
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

    // ── User management (owner-only Tauri commands) ────────────────────────

    #[tauri::command]
    pub fn list_users(
        app:   AppHandle,
        state: State<VaultState>,
    ) -> Result<Vec<vault_core::UserRecord>, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::list_users(&conn)
    }

    #[tauri::command]
    pub fn create_user(
        app:      AppHandle,
        state:    State<VaultState>,
        username: String,
        password: Option<String>,
    ) -> Result<vault_core::UserRecord, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::create_user(&conn, &username, password.as_deref(), false)
    }

    // ── User class commands ──────────────────────────────────────────────────

    #[tauri::command]
    pub fn list_user_classes(
        app: AppHandle, state: State<VaultState>,
    ) -> Result<Vec<vault_core::UserClass>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::list_user_classes(&vault_core::open_db(&db_path(&app)?, key)?)
    }

    #[tauri::command]
    pub fn create_user_class(
        app: AppHandle, state: State<VaultState>,
        name: String, description: String,
        cap_manage_users: bool, cap_manage_classes: bool, cap_delete_projects: bool,
    ) -> Result<vault_core::UserClass, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::create_user_class(
            &vault_core::open_db(&db_path(&app)?, key)?,
            &name, &description, cap_manage_users, cap_manage_classes, cap_delete_projects,
        )
    }

    #[tauri::command]
    pub fn update_user_class(
        app: AppHandle, state: State<VaultState>,
        class_id: String, name: String, description: String,
        cap_manage_users: bool, cap_manage_classes: bool, cap_delete_projects: bool,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::update_user_class(
            &vault_core::open_db(&db_path(&app)?, key)?,
            &class_id, &name, &description, cap_manage_users, cap_manage_classes, cap_delete_projects,
        )
    }

    #[tauri::command]
    pub fn delete_user_class(
        app: AppHandle, state: State<VaultState>, class_id: String,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::delete_user_class(&vault_core::open_db(&db_path(&app)?, key)?, &class_id)
    }

    #[tauri::command]
    pub fn get_class_permissions(
        app: AppHandle, state: State<VaultState>, class_id: String,
    ) -> Result<Vec<vault_core::ClassPermission>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::get_class_permissions(&vault_core::open_db(&db_path(&app)?, key)?, &class_id)
    }

    #[tauri::command]
    pub fn set_class_permissions(
        app: AppHandle, state: State<VaultState>,
        class_id: String, permissions: Vec<vault_core::ClassPermission>,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::set_class_permissions(&vault_core::open_db(&db_path(&app)?, key)?, &class_id, &permissions)
    }

    #[tauri::command]
    pub fn assign_user_class(
        app: AppHandle, state: State<VaultState>,
        user_id: String, class_id: Option<String>,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::assign_user_class(
            &vault_core::open_db(&db_path(&app)?, key)?,
            &user_id, class_id.as_deref(),
        )
    }

    #[tauri::command]
    pub fn set_user_password(
        app:      AppHandle,
        state:    State<VaultState>,
        user_id:  String,
        password: Option<String>,
    ) -> Result<(), String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::set_user_password(&conn, &user_id, password.as_deref())
    }

    #[tauri::command]
    pub fn rename_user(
        app:          AppHandle,
        state:        State<VaultState>,
        user_id:      String,
        new_username: String,
    ) -> Result<(), String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::rename_user(&conn, &user_id, &new_username)
    }

    #[tauri::command]
    pub fn delete_user(
        app:     AppHandle,
        state:   State<VaultState>,
        user_id: String,
    ) -> Result<(), String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::delete_user(&conn, &user_id)
    }

    /// Creates a token and returns the plaintext (shown once only).
    #[tauri::command]
    pub fn create_user_token(
        app:         AppHandle,
        state:       State<VaultState>,
        user_id:     String,
        description: String,
    ) -> Result<serde_json::Value, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        let (token_id, plaintext) = vault_core::create_user_token(
            &conn, &user_id,
            if description.is_empty() { None } else { Some(description.as_str()) },
            None,
        )?;
        Ok(serde_json::json!({ "token_id": token_id, "token": plaintext }))
    }

    #[tauri::command]
    pub fn revoke_user_token(
        app:      AppHandle,
        state:    State<VaultState>,
        token_id: String,
    ) -> Result<(), String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::revoke_user_token(&conn, &token_id)
    }

    #[tauri::command]
    pub fn list_user_tokens(
        app:     AppHandle,
        state:   State<VaultState>,
        user_id: String,
    ) -> Result<Vec<vault_core::TokenRecord>, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::list_user_tokens(&conn, &user_id)
    }

    #[tauri::command]
    pub fn get_user_permissions(
        app:     AppHandle,
        state:   State<VaultState>,
        user_id: String,
    ) -> Result<Vec<vault_core::PermissionRecord>, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::get_user_permissions(&conn, &user_id)
    }

    #[tauri::command]
    pub fn set_user_permissions(
        app:         AppHandle,
        state:       State<VaultState>,
        user_id:     String,
        permissions: Vec<vault_core::PermissionRecord>,
    ) -> Result<(), String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::set_user_permissions(&conn, &user_id, &permissions)
    }

    // ── TOTP commands (item 4) ───────────────────────────────────────────────

    #[tauri::command]
    pub fn enable_user_totp(
        app: AppHandle, state: State<VaultState>, user_id: String,
    ) -> Result<serde_json::Value, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        let secret = vault_core::enable_totp(&conn, &user_id)?;
        Ok(serde_json::json!({
            "secret": secret,
            "otpauth": format!("otpauth://totp/APIVault:{}?secret={}&issuer=APIVault", user_id, secret)
        }))
    }

    #[tauri::command]
    pub fn disable_user_totp(
        app: AppHandle, state: State<VaultState>, user_id: String,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::disable_totp(&conn, &user_id)
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
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
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
            commands::list_users,
            commands::create_user,
            commands::set_user_password,
            commands::rename_user,
            commands::delete_user,
            commands::list_user_classes,
            commands::create_user_class,
            commands::update_user_class,
            commands::delete_user_class,
            commands::get_class_permissions,
            commands::set_class_permissions,
            commands::assign_user_class,
            commands::create_user_token,
            commands::revoke_user_token,
            commands::list_user_tokens,
            commands::get_user_permissions,
            commands::set_user_permissions,
            commands::enable_user_totp,
            commands::disable_user_totp,
        ])
        .setup(|app| {
            // ── System Tray (item 18) ────────────────────────────────────────
            let tray = tauri::tray::TrayIconBuilder::new()
                .tooltip("API Vault")
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click { .. } = event {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window("main") {
                            if win.is_visible().unwrap_or(false) {
                                let _ = win.hide();
                            } else {
                                let _ = win.show();
                                let _ = win.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;
            let _ = tray; // keep alive

            // ── Global hotkey Ctrl+Shift+V (item 19) ─────────────────────────
            use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};
            let shortcut: Shortcut = "Ctrl+Shift+V".parse().unwrap_or_else(|_| "Alt+Shift+A".parse().unwrap());
            let app_handle = app.handle().clone();
            app.global_shortcut().on_shortcut(shortcut, move |_app, _shortcut, event| {
                if event.state == ShortcutState::Pressed {
                    if let Some(win) = app_handle.get_webview_window("main") {
                        if win.is_visible().unwrap_or(false) {
                            let _ = win.hide();
                        } else {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                }
            })?;

            // ── Lock on minimize / window hide (item 20) ─────────────────────
            // Done in JavaScript via visibilitychange event; Rust side exposes
            // the lock_vault command which JS calls when the window is hidden.

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running API Vault");
}
