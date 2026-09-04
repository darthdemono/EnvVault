//! EnvVault — Tauri backend.
//!
//! Thin wrappers around `vault-core`; resolves filesystem paths via Tauri's
//! `AppHandle` and exposes each operation as a `#[tauri::command]`.
//!
//! All commands live inside `mod commands {}` to avoid Tauri 2 E0255
//! proc-macro namespace collision.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{AppHandle, Manager};
use vault_core::VaultKey;
use zeroize::Zeroize;

// ── Managed state ─────────────────────────────────────────────────────────────

/// Holds the in-memory AES-256 vault key.  `None` means locked.
pub struct VaultState(pub Mutex<Option<VaultKey>>);

/// A running "Open to LAN" server.
pub struct LanServer {
    /// Firing this asks axum to shut down gracefully.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    state: envv_server::AppState,
    port: u16,
    url: String,
    fingerprint: Option<String>,
}

/// The LAN server, when one is running. `None` means we are not serving.
pub struct LanState(pub Mutex<Option<LanServer>>);

/// Best-effort LAN address of this machine, for display.
///
/// Opens a UDP socket toward a routable address and reads back which local
/// interface the kernel picked. No packet is ever sent — UDP `connect` only sets
/// the peer — so this works offline and needs no interface-enumeration crate.
fn local_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("192.0.2.1:80").ok()?; // TEST-NET-1: reserved, never routed
    Some(sock.local_addr().ok()?.ip().to_string())
}

// ── Path helpers ──────────────────────────────────────────────────────────────

fn db_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|d| d.join("vault.db"))
        .map_err(|e| e.to_string())
}
fn salt_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|d| d.join("vault.salt"))
        .map_err(|e| e.to_string())
}
fn legacy_json_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|d| d.join("vault.json"))
        .map_err(|e| e.to_string())
}
fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|d| d.join("settings.json"))
        .map_err(|e| e.to_string())
}
fn ensure_parent(path: &Path) -> Result<(), String> {
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
        let db = db_path(&app)?;
        let salt_file = salt_path(&app)?;
        ensure_parent(&db)?;

        // A database whose salt has gone missing must say so. Generating a fresh
        // one here made every unlock report "Wrong master password" for a
        // password that was perfectly correct.
        vault_core::check_salt_pairing(&db, &salt_file)?;
        let salt = vault_core::read_or_create_salt(&salt_file)?;
        let key = vault_core::derive_key(&password, &salt)?;
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

        // Ensure the owner row exists (password_hash NULL — it cannot be logged
        // into; it exists so owner actions have a resolvable identity in the
        // audit log and the user list).
        //
        // Deliberately no *password* seeding: a previous version created an
        // "admin" row whose hash was the master password itself, turning the
        // sub-user login path into an oracle for the vault key.
        vault_core::ensure_owner_user(&conn)?;

        *state.0.lock().map_err(|_| "State lock poisoned")? = Some(key);
        Ok(true)
    }

    /// Lock the vault.
    ///
    /// Stops the LAN server first: it holds a copy of the key, so leaving it up
    /// would mean "locked" on screen while peers kept reading and writing.
    #[tauri::command]
    pub fn lock_vault(state: State<VaultState>, lan: State<LanState>) -> Result<(), String> {
        lan_stop(lan)?;
        let mut g = state.0.lock().map_err(|_| "State lock poisoned")?;
        if let Some(mut k) = g.take() {
            k.zeroize();
        }
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
    pub fn reset_vault(
        app: AppHandle,
        state: State<VaultState>,
        lan: State<LanState>,
    ) -> Result<(), String> {
        lan_stop(lan)?;
        let mut g = state.0.lock().map_err(|_| "State lock poisoned")?;
        if let Some(mut k) = g.take() {
            k.zeroize();
        }
        let _ = fs::remove_file(db_path(&app)?);
        let _ = fs::remove_file(salt_path(&app)?);
        Ok(())
    }

    /// Vault contents plus the version they were read at.
    #[derive(serde::Serialize)]
    pub struct VersionedVault {
        pub data: serde_json::Value,
        /// Pass back to `save_vault` so a concurrent write cannot be clobbered.
        pub version: Option<String>,
    }

    #[tauri::command]
    pub fn load_vault(
        app: AppHandle,
        state: State<VaultState>,
    ) -> Result<Option<VersionedVault>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        // Version first, then data — see the same ordering note in the server's
        // PUT handler. Mis-pairing this way fails closed.
        let version = vault_core::vault_version(&conn)?;
        Ok(vault_core::load_vault(&conn)?.map(|data| VersionedVault { data, version }))
    }

    /// Persist the vault, returning its new version.
    ///
    /// `expect_version` makes this a compare-and-swap. The desktop must pass the
    /// version it last read: while "Open to LAN" is running, peers write to this
    /// same database, and an unconditional write would silently discard whatever
    /// they had just saved.
    #[tauri::command]
    pub fn save_vault(
        app: AppHandle,
        state: State<VaultState>,
        data: serde_json::Value,
        expect_version: Option<String>,
    ) -> Result<String, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        // Local desktop edits are always the owner acting directly; attribute
        // them to the owner row so the audit log is uniform with the server's.
        let actor = vault_core::ensure_owner_user(&conn).ok();
        vault_core::save_vault(
            &conn,
            data,
            vault_core::SaveCtx {
                actor: actor.as_deref(),
                expect_version: expect_version.as_deref(),
            },
        )
    }

    #[tauri::command]
    pub fn get_vault_path(app: AppHandle) -> Result<String, String> {
        db_path(&app).map(|p| p.display().to_string())
    }

    #[tauri::command]
    pub fn load_settings(app: AppHandle) -> Result<Option<serde_json::Value>, String> {
        let path = settings_path(&app)?;
        if !path.exists() {
            return Ok(None);
        }
        serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map(Some)
            .map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub fn save_settings(app: AppHandle, data: serde_json::Value) -> Result<(), String> {
        let path = settings_path(&app)?;
        ensure_parent(&path)?;
        fs::write(
            path,
            serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }

    #[tauri::command]
    pub fn get_expiring(
        app: AppHandle,
        state: State<VaultState>,
        days: u32,
    ) -> Result<Vec<serde_json::Value>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::get_expiring_entries(&conn, days)
    }

    #[tauri::command]
    pub fn get_audit_log(
        app: AppHandle,
        state: State<VaultState>,
    ) -> Result<Vec<vault_core::AuditRow>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::load_audit(&conn)
    }

    // ── Key pools ────────────────────────────────────────────────────────────
    //
    // Pool state (cursor, cooldowns, use counts) lives in `pools.json` in the
    // per-user state directory, NOT in the vault — see `vault_core::pool` for
    // why. The CLI writes the same file, and the app's `app_data_dir` resolves
    // to the same `io.envvault` directory the CLI defaults to, so a key reported
    // rate limited from CI shows as cooling here.
    //
    // Note what does NOT cross this boundary: the frontend sends only the
    // identity fields needed to compute `entry_ck` (id, provider, account_name,
    // key_id) and the pool name. No secret is passed in either direction, so
    // these commands cannot leak one however they are called.

    /// Identity of one entry, as the frontend knows it.
    ///
    /// Deliberately not `VaultEntry`: `entry_ck` needs exactly these four
    /// fields, and accepting the whole entry would mean secrets crossing the IPC
    /// boundary for a feature that has no use for them.
    #[derive(serde::Deserialize)]
    pub struct PoolMemberRef {
        #[serde(default)]
        pub id: Option<String>,
        #[serde(default)]
        pub provider: Option<String>,
        #[serde(default)]
        pub account_name: Option<String>,
        #[serde(default)]
        pub key_id: Option<String>,
    }

    impl PoolMemberRef {
        /// The stable key this member's state is filed under.
        ///
        /// Computed by `vault_core::entry_ck`, the same function version history
        /// and audit attribution use — reimplementing it in TypeScript would be
        /// a second identity scheme that agrees until it does not.
        fn ck(&self) -> String {
            vault_core::entry_ck(&serde_json::json!({
                "id": self.id.clone().unwrap_or_default(),
                "provider": self.provider.clone().unwrap_or_default(),
                "account_name": self.account_name.clone().unwrap_or_default(),
                "key_id": self.key_id.clone().unwrap_or_default(),
            }))
        }
    }

    /// What the panel shows for one member.
    #[derive(serde::Serialize)]
    pub struct PoolMemberState {
        pub ck: String,
        pub uses: u64,
        pub cooling: bool,
        pub cooling_until: Option<String>,
        pub last_used_at: Option<String>,
    }

    /// Which vault's state to read.
    ///
    /// `remote_base` is passed by the frontend when it is connected to a remote
    /// vault, so the panel does not show the local vault's cursors under the
    /// remote's data — the same class of mistake the LAN gate exists to prevent.
    fn pool_vault_key(app: &AppHandle, remote_base: Option<String>) -> Result<String, String> {
        Ok(match remote_base.filter(|b| !b.trim().is_empty()) {
            Some(base) => vault_core::pool::remote_vault_key(base.trim()),
            None => vault_core::pool::local_vault_key(&db_path(app)?),
        })
    }

    /// Per-member pool state for the given entries.
    #[tauri::command]
    pub fn pool_state(
        app: AppHandle,
        pool: String,
        members: Vec<PoolMemberRef>,
        remote_base: Option<String>,
    ) -> Result<Vec<PoolMemberState>, String> {
        let vk = pool_vault_key(&app, remote_base)?;
        let st = vault_core::pool::load();
        let now = vault_core::pool::now_ts();
        Ok(members
            .into_iter()
            .map(|m| {
                let ck = m.ck();
                let s = vault_core::pool::member_state(&st, &vk, &pool, &ck);
                PoolMemberState {
                    cooling: vault_core::pool::is_cooling(s.cooling_until.as_deref(), now),
                    uses: s.uses,
                    cooling_until: s.cooling_until,
                    last_used_at: s.last_used_at,
                    ck,
                }
            })
            .collect())
    }

    /// Put one member on cooldown, or clear it with `seconds: None`.
    #[tauri::command]
    pub fn pool_set_cooldown(
        app: AppHandle,
        pool: String,
        member: PoolMemberRef,
        seconds: Option<i64>,
        remote_base: Option<String>,
    ) -> Result<(), String> {
        let vk = pool_vault_key(&app, remote_base)?;
        let mut st = vault_core::pool::load();
        // A negative or zero cooldown is a cleared cooldown, not one that
        // expired in the past: writing a stale timestamp would leave the panel
        // showing a "cooling until" that already passed.
        let until = seconds
            .filter(|s| *s > 0)
            .map(|s| vault_core::pool::now_ts() + s);
        vault_core::pool::set_cooldown(&mut st, &vk, &pool, &member.ck(), until);
        vault_core::pool::save(&st)
    }

    /// Forget a pool's cursor, cooldowns and counts on this machine.
    #[tauri::command]
    pub fn pool_reset(
        app: AppHandle,
        pool: String,
        remote_base: Option<String>,
    ) -> Result<(), String> {
        let vk = pool_vault_key(&app, remote_base)?;
        let mut st = vault_core::pool::load();
        vault_core::pool::forget(&mut st, &vk, &pool);
        vault_core::pool::save(&st)
    }

    /// Where `pools.json` is, for the panel's footer.
    ///
    /// Worth showing: the file is outside the vault and outside the backup, so
    /// someone looking for "where did my cursor go" has nothing to search for
    /// unless the UI says.
    #[tauri::command]
    pub fn pool_state_path() -> Option<String> {
        vault_core::pool::state_path().map(|p| p.display().to_string())
    }

    #[tauri::command]
    pub fn generate_certificate(
        common_name: String,
        validity_days: u32,
        entropy_source: Option<String>,
    ) -> Result<serde_json::Value, String> {
        let source = vault_core::entropy::Source::parse(entropy_source.as_deref().unwrap_or("os"))?;
        vault_core::generate_certificate(&common_name, validity_days, &source)
    }

    #[tauri::command]
    pub fn generate_ssh_keypair(
        comment: String,
        entropy_source: Option<String>,
    ) -> Result<serde_json::Value, String> {
        let source = vault_core::entropy::Source::parse(entropy_source.as_deref().unwrap_or("os"))?;
        vault_core::generate_ssh_keypair(&comment, &source)
    }

    /// Entropy sources this build offers, and whether each one is usable here.
    ///
    /// The UI dropdown is populated from this rather than from a hard-coded
    /// list, so it can never offer a source the backend would refuse.
    #[tauri::command]
    pub fn entropy_sources() -> Vec<serde_json::Value> {
        use vault_core::entropy::{Availability, Source};
        let candidates = [
            Source::Os,
            Source::File {
                path: "/dev/random".into(),
            },
            Source::File {
                path: "/dev/hwrng".into(),
            },
        ];
        candidates
            .iter()
            .map(|s| {
                let (ready, why) = match s.availability() {
                    Availability::Ready => (true, String::new()),
                    Availability::Missing(w) => (false, w),
                };
                serde_json::json!({
                    "id": s.label(),
                    "ready": ready,
                    "detail": why,
                    "hardware": s.is_external(),
                })
            })
            .collect()
    }

    // ── User management (owner-only Tauri commands) ────────────────────────

    #[tauri::command]
    pub fn list_users(
        app: AppHandle,
        state: State<VaultState>,
    ) -> Result<Vec<vault_core::UserRecord>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::list_users(&conn)
    }

    #[tauri::command]
    pub fn create_user(
        app: AppHandle,
        state: State<VaultState>,
        username: String,
        password: Option<String>,
    ) -> Result<vault_core::UserRecord, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::create_user(&conn, &username, password.as_deref(), false)
    }

    // ── User class commands ──────────────────────────────────────────────────

    #[tauri::command]
    pub fn list_user_classes(
        app: AppHandle,
        state: State<VaultState>,
    ) -> Result<Vec<vault_core::UserClass>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::list_user_classes(&vault_core::open_db(&db_path(&app)?, key)?)
    }

    #[tauri::command]
    pub fn create_user_class(
        app: AppHandle,
        state: State<VaultState>,
        name: String,
        description: String,
        cap_manage_users: bool,
        cap_manage_classes: bool,
        cap_delete_projects: bool,
    ) -> Result<vault_core::UserClass, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::create_user_class(
            &vault_core::open_db(&db_path(&app)?, key)?,
            &name,
            &description,
            cap_manage_users,
            cap_manage_classes,
            cap_delete_projects,
        )
    }

    #[tauri::command]
    pub fn update_user_class(
        app: AppHandle,
        state: State<VaultState>,
        class_id: String,
        name: String,
        description: String,
        cap_manage_users: bool,
        cap_manage_classes: bool,
        cap_delete_projects: bool,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::update_user_class(
            &vault_core::open_db(&db_path(&app)?, key)?,
            &class_id,
            &name,
            &description,
            cap_manage_users,
            cap_manage_classes,
            cap_delete_projects,
        )
    }

    #[tauri::command]
    pub fn delete_user_class(
        app: AppHandle,
        state: State<VaultState>,
        class_id: String,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::delete_user_class(&vault_core::open_db(&db_path(&app)?, key)?, &class_id)
    }

    /// Read/write permission expressions for one subject (user or class).
    #[derive(serde::Serialize, serde::Deserialize, Default)]
    pub struct PermissionExprs {
        pub read: String,
        pub write: String,
    }

    fn load_exprs(
        conn: &vault_core::SqlConnection,
        kind: &str,
        id: &str,
    ) -> Result<PermissionExprs, String> {
        Ok(PermissionExprs {
            read: vault_core::get_permission_expr(conn, kind, id, "read")?.unwrap_or_default(),
            write: vault_core::get_permission_expr(conn, kind, id, "write")?.unwrap_or_default(),
        })
    }

    fn store_exprs(
        conn: &vault_core::SqlConnection,
        kind: &str,
        id: &str,
        e: &PermissionExprs,
    ) -> Result<(), String> {
        vault_core::set_permission_expr(conn, kind, id, "read", &e.read)?;
        vault_core::set_permission_expr(conn, kind, id, "write", &e.write)?;
        Ok(())
    }

    #[tauri::command]
    pub fn get_class_permissions(
        app: AppHandle,
        state: State<VaultState>,
        class_id: String,
    ) -> Result<PermissionExprs, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        load_exprs(
            &vault_core::open_db(&db_path(&app)?, key)?,
            "class",
            &class_id,
        )
    }

    #[tauri::command]
    pub fn set_class_permissions(
        app: AppHandle,
        state: State<VaultState>,
        class_id: String,
        permissions: PermissionExprs,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        store_exprs(
            &vault_core::open_db(&db_path(&app)?, key)?,
            "class",
            &class_id,
            &permissions,
        )
    }

    #[tauri::command]
    pub fn assign_user_class(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
        class_id: Option<String>,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        vault_core::assign_user_class(
            &vault_core::open_db(&db_path(&app)?, key)?,
            &user_id,
            class_id.as_deref(),
        )
    }

    #[tauri::command]
    pub fn set_user_password(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
        password: Option<String>,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::set_user_password(&conn, &user_id, password.as_deref())
    }

    // ── TOTP (sub-user second factor) ────────────────────────────────────────
    //
    // The owner is refused inside `vault-core` rather than here, so the CLI and
    // the app cannot disagree about who may have a factor.

    #[tauri::command]
    pub fn totp_status(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
    ) -> Result<vault_core::users::TotpStatus, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::users::totp_status(&conn, &user_id)
    }

    /// Phase one. This is the **only** call that ever returns the secret.
    #[tauri::command]
    pub fn totp_enroll(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
    ) -> Result<vault_core::users::TotpStatus, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::users::totp_enroll(&conn, &user_id, "EnvVault")
    }

    #[tauri::command]
    pub fn totp_confirm(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
        code: String,
    ) -> Result<bool, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::users::totp_confirm(&conn, &user_id, &code)
    }

    #[tauri::command]
    pub fn totp_disable(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::users::totp_disable(&conn, &user_id)
    }

    #[tauri::command]
    pub fn rename_user(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
        new_username: String,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::rename_user(&conn, &user_id, &new_username)
    }

    #[tauri::command]
    pub fn delete_user(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::delete_user(&conn, &user_id)
    }

    /// Creates a token and returns the plaintext (shown once only).
    #[tauri::command]
    pub fn create_user_token(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
        description: String,
    ) -> Result<serde_json::Value, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        let (token_id, plaintext) = vault_core::create_user_token(
            &conn,
            &user_id,
            if description.is_empty() {
                None
            } else {
                Some(description.as_str())
            },
            None,
        )?;
        Ok(serde_json::json!({ "token_id": token_id, "token": plaintext }))
    }

    #[tauri::command]
    pub fn revoke_user_token(
        app: AppHandle,
        state: State<VaultState>,
        token_id: String,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::revoke_user_token(&conn, &token_id)
    }

    #[tauri::command]
    pub fn list_user_tokens(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
    ) -> Result<Vec<vault_core::TokenRecord>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::list_user_tokens(&conn, &user_id)
    }

    #[tauri::command]
    pub fn get_user_permissions(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
    ) -> Result<PermissionExprs, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        load_exprs(&conn, "user", &user_id)
    }

    #[tauri::command]
    pub fn set_user_permissions(
        app: AppHandle,
        state: State<VaultState>,
        user_id: String,
        permissions: PermissionExprs,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        store_exprs(&conn, "user", &user_id, &permissions)
    }

    // ── Open to LAN (Phase 10) ────────────────────────────────────────────────

    /// What the UI needs to render the LAN card.
    #[derive(serde::Serialize, Default)]
    pub struct LanStatus {
        pub running: bool,
        pub port: u16,
        pub url: String,
        pub fingerprint: Option<String>,
        pub peers: usize,
        /// Seconds since a peer last made a request; drives the idle shutdown.
        pub idle_secs: u64,
    }

    /// Serve this vault to the local network.
    ///
    /// Runs the `envv-server` router in-process against the vault that is
    /// already open, so there is no second database, no second master password
    /// and no subprocess to supervise. The server dies with the app.
    ///
    /// `POST /api/unlock` is disabled in this mode — peers sign in as named
    /// users, which keeps the master password off the wire and gives every peer
    /// its own RBAC scope and audit trail.
    #[tauri::command]
    pub async fn lan_start(
        app: AppHandle,
        vault: State<'_, VaultState>,
        lan: State<'_, LanState>,
        port: Option<u16>,
        tls: Option<bool>,
    ) -> Result<LanStatus, String> {
        if lan.0.lock().map_err(|_| "State lock poisoned")?.is_some() {
            return Err("The LAN server is already running".into());
        }

        let key = {
            let g = vault.0.lock().map_err(|_| "State lock poisoned")?;
            *g.as_ref()
                .ok_or("Unlock the vault before opening it to the LAN")?
        };

        let db = db_path(&app)?;
        let salt = salt_path(&app)?;
        let conn = vault_core::open_db(&db, &key)?;

        // Peers can only authenticate as users. Starting without one would
        // advertise a server nobody can log into, so refuse and say why.
        let users = vault_core::list_users(&conn)?;
        if !users.iter().any(|u| u.has_password && !u.is_owner) {
            return Err(
                "No user account exists yet. Create one in the Users panel first — \
                 peers sign in with a username and password, never the master password."
                    .into(),
            );
        }
        let owner_id = vault_core::ensure_owner_user(&conn)?;
        drop(conn);

        let use_tls = tls.unwrap_or(true);
        let cert_dir = app
            .path()
            .app_data_dir()
            .map_err(|e| e.to_string())?
            .join("lan");
        let (tls_files, fingerprint) = if use_tls {
            let (files, fp) = envv_server::ensure_self_signed_cert(&cert_dir)?;
            (Some(files), Some(fp))
        } else {
            (None, None)
        };

        // Default 8744 so a Docker envv-server on 8743 can coexist; step forward
        // if something already holds it.
        let start_port = port.unwrap_or(8744);
        let bound = envv_server::find_free_port("0.0.0.0", start_port, 20)
            .ok_or_else(|| format!("No free port in {start_port}..{}", start_port + 20))?;

        let state = envv_server::AppState::new(
            db,
            salt,
            fingerprint.clone(),
            480,
            // Absolute session ceiling, in hours. A LAN share is a deliberate,
            // supervised act with a stop button on screen; 24h outlives any
            // realistic session while still bounding a peer token that leaks.
            24,
            /* lan_mode */ true,
        );
        // Hand the server the key we already hold: nobody re-enters a password.
        state.adopt_owner_key(key, owner_id);

        let addr: std::net::SocketAddr = format!("0.0.0.0:{bound}")
            .parse()
            .map_err(|e| format!("invalid bind address: {e}"))?;
        let (tx, rx) = tokio::sync::oneshot::channel();

        let serve_state = state.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = envv_server::serve(serve_state, addr, tls_files, rx).await {
                eprintln!("LAN server stopped: {e}");
            }
        });

        let scheme = if use_tls { "https" } else { "http" };
        let host = local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
        let url = format!("{scheme}://{host}:{bound}");

        let status = LanStatus {
            running: true,
            port: bound,
            url: url.clone(),
            fingerprint: fingerprint.clone(),
            peers: 0,
            idle_secs: 0,
        };

        *lan.0.lock().map_err(|_| "State lock poisoned")? = Some(LanServer {
            shutdown: Some(tx),
            state,
            port: bound,
            url,
            fingerprint,
        });
        Ok(status)
    }

    /// Stop serving and drop every peer session.
    #[tauri::command]
    pub fn lan_stop(lan: State<LanState>) -> Result<(), String> {
        let mut g = lan.0.lock().map_err(|_| "State lock poisoned")?;
        if let Some(mut server) = g.take() {
            // Zeroize the keys held by peer sessions before dropping the state.
            server.state.shutdown_all_sessions();
            if let Some(tx) = server.shutdown.take() {
                let _ = tx.send(());
            }
        }
        Ok(())
    }

    #[tauri::command]
    pub fn lan_status(lan: State<LanState>) -> Result<LanStatus, String> {
        let g = lan.0.lock().map_err(|_| "State lock poisoned")?;
        Ok(match g.as_ref() {
            None => LanStatus::default(),
            Some(s) => LanStatus {
                running: true,
                port: s.port,
                url: s.url.clone(),
                fingerprint: s.fingerprint.clone(),
                peers: s.state.peer_count(),
                idle_secs: s.state.idle_secs(),
            },
        })
    }

    // ── Remote HTTP proxy (Phase 6 — TLS cert pinning) ────────────────────────

    /// Response type returned by `remote_request`.
    #[derive(serde::Serialize)]
    pub struct RemoteResponse {
        pub status: u16,
        pub body: String,
    }

    // The pinning and capturing verifiers used to be defined here, ~150 lines of
    // them. They now live in `vault_core::tls`, because the CLI needs the same
    // trust decision and two implementations of "is this server who it claims to
    // be" is how one of them ends up accepting anything. See vault-core/src/tls.rs.

    /// Learn a server's leaf-certificate SHA-256 fingerprint on first contact.
    ///
    /// Sends **no credentials** — it performs the TLS handshake and an
    /// unauthenticated `GET /api/status`, then reports the fingerprint so the UI
    /// can show it and ask the user to confirm before pinning. A MITM can of
    /// course present its own certificate here; that is the trust decision the
    /// user is being asked to make, exactly as with SSH's host-key prompt.
    /// Every subsequent request goes through `remote_request` and is pinned.
    #[tauri::command]
    pub async fn probe_cert_fingerprint(url: String) -> Result<String, String> {
        let (tls_config, seen) = vault_core::tls::capturing_config()?;

        let client = reqwest::ClientBuilder::new()
            .use_preconfigured_tls(tls_config)
            .build()
            .map_err(|e| e.to_string())?;

        let status_url = format!("{}/api/status", url.trim_end_matches('/'));
        client
            .get(&status_url)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let fp = seen.lock().unwrap().clone();
        fp.ok_or_else(|| "Server did not present a TLS certificate".to_string())
    }

    /// Proxy an HTTP(S) request through Rust/reqwest so self-signed server certs
    /// can be used.  When `fingerprint` is provided the TLS connection is accepted
    /// **only** if the server's leaf certificate matches that SHA-256 fingerprint
    /// (pinning); when absent, normal CA validation applies.
    #[tauri::command]
    pub async fn remote_request(
        url: String,
        method: String,
        headers_json: String,
        body: Option<String>,
        fingerprint: Option<String>,
    ) -> Result<RemoteResponse, String> {
        let mut builder = reqwest::ClientBuilder::new();
        if let Some(fp) = &fingerprint {
            let policy = vault_core::tls::TlsPolicy::Pin(fp.clone());
            builder = builder.use_preconfigured_tls(vault_core::tls::client_config(&policy)?);
        }
        let client = builder.build().map_err(|e| e.to_string())?;

        let headers: std::collections::HashMap<String, String> =
            serde_json::from_str(&headers_json).unwrap_or_default();

        let mut req = client.request(
            method
                .parse::<reqwest::Method>()
                .map_err(|e| e.to_string())?,
            &url,
        );
        for (k, v) in &headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(b) = body {
            req = req.body(b);
        }

        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();
        Ok(RemoteResponse {
            status,
            body: body_text,
        })
    }
}

// ── Linux display-stack workarounds ───────────────────────────────────────────

/// Apply the WebKitGTK workarounds this app needs, without dictating a backend.
///
/// These were unconditional, which is wrong in two directions. Forcing
/// `GDK_BACKEND=x11` on a Wayland session pushes the whole window through
/// XWayland: blurry on fractional scaling, wrong cursor size on HiDPI, and
/// broken on the distros now shipping without XWayland at all. Meanwhile the
/// compositing and DMABUF flags are genuinely needed — WebKitGTK's DMABUF
/// renderer is a reliable source of blank windows on Nvidia and on older Mesa —
/// but a user with working hardware acceleration should be able to turn them
/// back on.
///
/// So: every variable is a default, not an override. Anything already set in the
/// environment wins, which makes `WEBKIT_DISABLE_COMPOSITING_MODE=0 envvault` a
/// working escape hatch instead of a no-op.
#[cfg(target_os = "linux")]
fn configure_linux_webkit() {
    fn default_env(key: &str, value: &str) {
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }

    // Native Wayland is the better path where it exists; X11 stays the default
    // only when the session is not Wayland to begin with.
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var("XDG_SESSION_TYPE")
            .map(|v| v == "wayland")
            .unwrap_or(false);
    if !wayland {
        default_env("GDK_BACKEND", "x11");
    }

    default_env("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
    default_env("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
}

// ── App entry ─────────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Structured logging first, so anything the platform setup below reports is
    // captured. `info` matches the server: a desktop session is long-lived and
    // its log is read after the fact, when something has already gone wrong.
    //
    // The rule from `vault_core::telemetry` applies here too and matters most in
    // this binary: log fingerprints, entry ids and provider names — never a
    // stored value, never the master password, never a session token.
    vault_core::telemetry::init("envvault-desktop", "info");

    #[cfg(target_os = "linux")]
    configure_linux_webkit();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "desktop starting");
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        // Restore the window where the user left it.
        //
        // VISIBLE is deliberately excluded from the saved flags. Clicking the
        // tray icon hides the window (see the tray handler in `setup` below),
        // so with VISIBLE on, hiding to the tray and then quitting would save
        // "not visible" and the next launch would restore an invisible window —
        // the app would appear to start and do nothing, with only the tray icon
        // as a way back. Size and position are what the user actually wants
        // remembered; visibility is a transient tray state.
        //
        // MAXIMIZED is kept: it is an explicit window-manager state the user
        // set, and restoring maximized is the expected behaviour.
        .plugin(
            tauri_plugin_window_state::Builder::default()
                .with_state_flags(
                    tauri_plugin_window_state::StateFlags::SIZE
                        | tauri_plugin_window_state::StateFlags::POSITION
                        | tauri_plugin_window_state::StateFlags::MAXIMIZED,
                )
                .build(),
        )
        .manage(VaultState(Mutex::new(None)))
        .manage(LanState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            commands::unlock_vault,
            commands::lock_vault,
            commands::vault_is_unlocked,
            commands::vault_exists,
            commands::reset_vault,
            commands::load_vault,
            commands::save_vault,
            commands::get_vault_path,
            commands::pool_state,
            commands::pool_set_cooldown,
            commands::pool_reset,
            commands::pool_state_path,
            commands::load_settings,
            commands::save_settings,
            commands::get_expiring,
            commands::get_audit_log,
            commands::generate_certificate,
            commands::generate_ssh_keypair,
            commands::entropy_sources,
            commands::list_users,
            commands::create_user,
            commands::set_user_password,
            commands::totp_status,
            commands::totp_enroll,
            commands::totp_confirm,
            commands::totp_disable,
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
            commands::get_expiring,
            commands::get_audit_log,
            commands::lan_start,
            commands::lan_stop,
            commands::lan_status,
            commands::remote_request,
            commands::probe_cert_fingerprint,
        ])
        .setup(|app| {
            // ── System Tray (item 18) ────────────────────────────────────────
            let tray = tauri::tray::TrayIconBuilder::new()
                .tooltip("EnvVault")
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

            // Global hotkey removed — Ctrl+Shift+V conflicts with paste in
            // Linux terminals and intercepted system-wide, causing vault lock
            // on unintended keypresses. Use the system tray to show/hide.

            // ── Lock on minimize / window hide (item 20) ─────────────────────
            // Done in JavaScript via visibilitychange event; Rust side exposes
            // the lock_vault command which JS calls when the window is hidden.

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running EnvVault");
}
