//! EnvVault — Tauri backend.
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

/// A running "Open to LAN" server.
pub struct LanServer {
    /// Firing this asks axum to shut down gracefully.
    shutdown:    Option<tokio::sync::oneshot::Sender<()>>,
    state:       envv_server::AppState,
    port:        u16,
    url:         String,
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
    sock.connect("192.0.2.1:80").ok()?;      // TEST-NET-1: reserved, never routed
    Some(sock.local_addr().ok()?.ip().to_string())
}

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
    pub fn reset_vault(app: AppHandle, state: State<VaultState>, lan: State<LanState>) -> Result<(), String> {
        lan_stop(lan)?;
        let mut g = state.0.lock().map_err(|_| "State lock poisoned")?;
        if let Some(mut k) = g.take() { k.zeroize(); }
        let _ = fs::remove_file(db_path(&app)?);
        let _ = fs::remove_file(salt_path(&app)?);
        Ok(())
    }

    /// Vault contents plus the version they were read at.
    #[derive(serde::Serialize)]
    pub struct VersionedVault {
        pub data:    serde_json::Value,
        /// Pass back to `save_vault` so a concurrent write cannot be clobbered.
        pub version: Option<String>,
    }

    #[tauri::command]
    pub fn load_vault(
        app:   AppHandle,
        state: State<VaultState>,
    ) -> Result<Option<VersionedVault>, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
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
        app:            AppHandle,
        state:          State<VaultState>,
        data:           serde_json::Value,
        expect_version: Option<String>,
    ) -> Result<String, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        // Local desktop edits are always the owner acting directly; attribute
        // them to the owner row so the audit log is uniform with the server's.
        let actor = vault_core::ensure_owner_user(&conn).ok();
        vault_core::save_vault(&conn, data, vault_core::SaveCtx {
            actor: actor.as_deref(),
            expect_version: expect_version.as_deref(),
        })
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

    /// Read/write permission expressions for one subject (user or class).
    #[derive(serde::Serialize, serde::Deserialize, Default)]
    pub struct PermissionExprs { pub read: String, pub write: String }

    fn load_exprs(conn: &vault_core::SqlConnection, kind: &str, id: &str) -> Result<PermissionExprs, String> {
        Ok(PermissionExprs {
            read:  vault_core::get_permission_expr(conn, kind, id, "read")?.unwrap_or_default(),
            write: vault_core::get_permission_expr(conn, kind, id, "write")?.unwrap_or_default(),
        })
    }

    fn store_exprs(conn: &vault_core::SqlConnection, kind: &str, id: &str, e: &PermissionExprs) -> Result<(), String> {
        vault_core::set_permission_expr(conn, kind, id, "read",  &e.read)?;
        vault_core::set_permission_expr(conn, kind, id, "write", &e.write)?;
        Ok(())
    }

    #[tauri::command]
    pub fn get_class_permissions(
        app: AppHandle, state: State<VaultState>, class_id: String,
    ) -> Result<PermissionExprs, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        load_exprs(&vault_core::open_db(&db_path(&app)?, key)?, "class", &class_id)
    }

    #[tauri::command]
    pub fn set_class_permissions(
        app: AppHandle, state: State<VaultState>,
        class_id: String, permissions: PermissionExprs,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        store_exprs(&vault_core::open_db(&db_path(&app)?, key)?, "class", &class_id, &permissions)
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
    ) -> Result<PermissionExprs, String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        load_exprs(&conn, "user", &user_id)
    }

    #[tauri::command]
    pub fn set_user_permissions(
        app:         AppHandle,
        state:       State<VaultState>,
        user_id:     String,
        permissions: PermissionExprs,
    ) -> Result<(), String> {
        let g   = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        store_exprs(&conn, "user", &user_id, &permissions)
    }

    // ── Open to LAN (Phase 10) ────────────────────────────────────────────────

    /// What the UI needs to render the LAN card.
    #[derive(serde::Serialize, Default)]
    pub struct LanStatus {
        pub running:     bool,
        pub port:        u16,
        pub url:         String,
        pub fingerprint: Option<String>,
        pub peers:       usize,
        /// Seconds since a peer last made a request; drives the idle shutdown.
        pub idle_secs:   u64,
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
        app:      AppHandle,
        vault:    State<'_, VaultState>,
        lan:      State<'_, LanState>,
        port:     Option<u16>,
        tls:      Option<bool>,
    ) -> Result<LanStatus, String> {
        if lan.0.lock().map_err(|_| "State lock poisoned")?.is_some() {
            return Err("The LAN server is already running".into());
        }

        let key = {
            let g = vault.0.lock().map_err(|_| "State lock poisoned")?;
            *g.as_ref().ok_or("Unlock the vault before opening it to the LAN")?
        };

        let db   = db_path(&app)?;
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
        let cert_dir = app.path().app_data_dir().map_err(|e| e.to_string())?.join("lan");
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

        let state = envv_server::AppState::new(db, salt, fingerprint.clone(), 480, /* lan_mode */ true);
        // Hand the server the key we already hold: nobody re-enters a password.
        state.adopt_owner_key(key, owner_id);

        let addr: std::net::SocketAddr = format!("0.0.0.0:{bound}")
            .parse().map_err(|e| format!("invalid bind address: {e}"))?;
        let (tx, rx) = tokio::sync::oneshot::channel();

        let serve_state = state.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = envv_server::serve(serve_state, addr, tls_files, rx).await {
                eprintln!("LAN server stopped: {e}");
            }
        });

        let scheme = if use_tls { "https" } else { "http" };
        let host   = local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
        let url    = format!("{scheme}://{host}:{bound}");

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
            if let Some(tx) = server.shutdown.take() { let _ = tx.send(()); }
        }
        Ok(())
    }

    #[tauri::command]
    pub fn lan_status(lan: State<LanState>) -> Result<LanStatus, String> {
        let g = lan.0.lock().map_err(|_| "State lock poisoned")?;
        Ok(match g.as_ref() {
            None => LanStatus::default(),
            Some(s) => LanStatus {
                running:     true,
                port:        s.port,
                url:         s.url.clone(),
                fingerprint: s.fingerprint.clone(),
                peers:       s.state.peer_count(),
                idle_secs:   s.state.idle_secs(),
            },
        })
    }

    // ── Remote HTTP proxy (Phase 6 — TLS cert pinning) ────────────────────────

    /// Response type returned by `remote_request`.
    #[derive(serde::Serialize)]
    pub struct RemoteResponse { pub status: u16, pub body: String }

    /// Rustls verifier that pins the server's leaf certificate to a SHA-256
    /// fingerprint (hex of the DER encoding).  This enforces the pin **during the
    /// TLS handshake** — before any request body (e.g. the master password) is
    /// sent — so a MITM presenting a different cert is rejected up front.
    ///
    /// Signature verification is delegated to the active crypto provider; only
    /// the certificate identity check is replaced.
    #[derive(Debug)]
    struct FingerprintVerifier {
        expected: String,
        provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
    }

    impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &rustls_pki_types::CertificateDer<'_>,
            _intermediates: &[rustls_pki_types::CertificateDer<'_>],
            _server_name: &rustls_pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            use sha2::{Sha256, Digest};
            let actual = hex::encode(Sha256::digest(end_entity.as_ref()));
            if actual.eq_ignore_ascii_case(&self.expected) {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General(
                    "TLS certificate fingerprint does not match the pinned value".into(),
                ))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls_pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message, cert, dss, &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls_pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message, cert, dss, &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.provider.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Verifier used only by [`probe_cert_fingerprint`]: accepts whatever the
    /// server presents and records its SHA-256 so the fingerprint can be shown
    /// to the user for confirmation.
    ///
    /// This is the trust-on-first-use step, and it is deliberately confined to
    /// one unauthenticated request. Without it TOFU could not bootstrap at all:
    /// `remote_request` pins when given a fingerprint and applies normal CA
    /// validation when not, so reaching a self-signed server required a
    /// fingerprint that could only be obtained by reaching it.
    #[derive(Debug)]
    struct CapturingVerifier {
        seen: std::sync::Arc<std::sync::Mutex<Option<String>>>,
        provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
    }

    impl rustls::client::danger::ServerCertVerifier for CapturingVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &rustls_pki_types::CertificateDer<'_>,
            _intermediates: &[rustls_pki_types::CertificateDer<'_>],
            _server_name: &rustls_pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            use sha2::{Sha256, Digest};
            *self.seen.lock().unwrap() = Some(hex::encode(Sha256::digest(end_entity.as_ref())));
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls_pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message, cert, dss, &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls_pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message, cert, dss, &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.provider.signature_verification_algorithms.supported_schemes()
        }
    }

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
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls_config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(CapturingVerifier {
                seen: seen.clone(),
                provider,
            }))
            .with_no_client_auth();

        let client = reqwest::ClientBuilder::new()
            .use_preconfigured_tls(tls_config)
            .build()
            .map_err(|e| e.to_string())?;

        let status_url = format!("{}/api/status", url.trim_end_matches('/'));
        client.get(&status_url).send().await.map_err(|e| e.to_string())?;

        let fp = seen.lock().unwrap().clone();
        fp.ok_or_else(|| "Server did not present a TLS certificate".to_string())
    }

    /// Proxy an HTTP(S) request through Rust/reqwest so self-signed server certs
    /// can be used.  When `fingerprint` is provided the TLS connection is accepted
    /// **only** if the server's leaf certificate matches that SHA-256 fingerprint
    /// (pinning); when absent, normal CA validation applies.
    #[tauri::command]
    pub async fn remote_request(
        url:         String,
        method:      String,
        headers_json: String,
        body:        Option<String>,
        fingerprint: Option<String>,
    ) -> Result<RemoteResponse, String> {
        let mut builder = reqwest::ClientBuilder::new();
        if let Some(fp) = &fingerprint {
            let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let tls_config = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(FingerprintVerifier {
                    expected: fp.trim().to_string(),
                    provider,
                }))
                .with_no_client_auth();
            builder = builder.use_preconfigured_tls(tls_config);
        }
        let client = builder.build().map_err(|e| e.to_string())?;

        let headers: std::collections::HashMap<String, String> =
            serde_json::from_str(&headers_json).unwrap_or_default();

        let mut req = client.request(
            method.parse::<reqwest::Method>().map_err(|e| e.to_string())?,
            &url,
        );
        for (k, v) in &headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(b) = body { req = req.body(b); }

        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();
        Ok(RemoteResponse { status, body: body_text })
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
