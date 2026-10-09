//! UnENVerse — Tauri backend.
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

    /// Current lock state from the desktop session, or `None` where the
    /// platform cannot report it. Linux reads GDK's keymap (X11 and Wayland);
    /// Windows reads the Caps Lock toggle bit.
    #[tauri::command]
    pub fn caps_lock_state() -> Option<bool> {
        #[cfg(target_os = "linux")]
        {
            let display = gtk::gdk::Display::default()?;
            gtk::gdk::Keymap::for_display(&display).map(|keymap| keymap.is_caps_locked())
        }
        #[cfg(target_os = "windows")]
        {
            #[link(name = "user32")]
            unsafe extern "system" {
                fn GetKeyState(key: i32) -> i16;
            }
            // VK_CAPITAL = 0x14; the low bit is the toggle state.
            Some(unsafe { GetKeyState(0x14) } & 1 != 0)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            None
        }
    }

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
        // PUT handler. Mis-pairing this way fails closed. A v1 vault is converted
        // first, or the version read here would be the old blob's hash.
        vault_core::ensure_current_schema(&conn)?;
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
        // Phase 35: the config history renders from the document that was saved.
        let for_history = data.clone();
        let version = vault_core::save_vault(
            &conn,
            data,
            vault_core::SaveCtx {
                actor: actor.as_deref(),
                expect_version: expect_version.as_deref(),
            },
        )?;
        // Best effort: a history that cannot record is logged, never a failed save.
        envv_cli::history::after_save(&conn, &for_history, actor.as_deref());
        Ok(version)
    }

    /// Phase 30.1: save a delta (see `vault_core::apply_row_patch`) instead of the
    /// whole document. Same compare-and-swap, audit and history as `save_vault`.
    #[tauri::command]
    pub fn save_vault_rows(
        app: AppHandle,
        state: State<VaultState>,
        patch: serde_json::Value,
        expect_version: Option<String>,
    ) -> Result<String, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        let actor = vault_core::ensure_owner_user(&conn).ok();
        let doc = vault_core::load_vault(&conn)?.unwrap_or_else(
            || serde_json::json!({ "api_keys": [], "user_categories": [], "projects": [] }),
        );
        let data = vault_core::apply_row_patch(doc, &patch)?;
        let for_history = data.clone();
        let version = vault_core::save_vault(
            &conn,
            data,
            vault_core::SaveCtx {
                actor: actor.as_deref(),
                expect_version: expect_version.as_deref(),
            },
        )?;
        envv_cli::history::after_save(&conn, &for_history, actor.as_deref());
        Ok(version)
    }

    /// Phase 24.5: what an OpenPGP key says about itself (`gpg_key`). Pure over
    /// its argument. Public values only: fingerprint, key id, user ids and when it
    /// expires; the private half is never read.
    #[tauri::command]
    pub fn pgp_inspect(text: String) -> Result<serde_json::Value, String> {
        let k = vault_core::pgp::inspect(text.as_bytes())?;
        Ok(serde_json::json!({
            "fingerprint": k.primary.fingerprint,
            "key_id": k.primary.key_id,
            "user_ids": k.user_ids,
            "expires_at": k.soonest_expiry().map(vault_core::pgp::iso),
        }))
    }

    /// Phase 34: what reading a pulled `.env` file back into an `env_file` chunk
    /// would change. Pure over its arguments (the chunk's fields and the text), so
    /// it needs no vault key and the rules are the CLI's, once. Returns names
    /// only, plus the fields the chunk would have afterwards.
    #[tauri::command]
    pub fn env_import_plan(fields: Vec<serde_json::Value>, text: String) -> serde_json::Value {
        let vars = envv_cli::envfile::parse_env_file(&text);
        let plan = envv_cli::node_cmd::plan_env_import(&fields, &vars);
        serde_json::json!({
            "fields": plan.fields, "added": plan.added, "changed": plan.changed,
            "removed": plan.removed, "kept_references": plan.kept_references,
        })
    }

    /// Phase 36: the app's clipboard writes, for the materialisation log that
    /// `unv blast-radius --host local` reads. The renderer sends the text it just
    /// copied and the vault it holds; Rust records which vault secrets that text
    /// contained, as entry, field and fingerprint, never the value, and writes
    /// nothing when it contained none. Best effort: it never fails a copy.
    #[tauri::command]
    pub fn matlog_note(text: String, note: String, vault: serde_json::Value) {
        if text.len() > 1 << 20 {
            return;
        }
        envv_cli::matlog::remember(&vault, "app");
        envv_cli::matlog::note("clipboard", &note, &text);
    }

    /// Phase 37.1: this machine's approver public key and fingerprint, the key made
    /// on first use. The seed never crosses this boundary; only signatures do. The
    /// CLI reads the same file (`unv node approver show`).
    #[tauri::command]
    pub fn approver_public(app: AppHandle) -> Result<serde_json::Value, String> {
        let dir = db_path(&app)?
            .parent()
            .map(std::path::Path::to_path_buf)
            .ok_or("no data directory")?;
        let seed = vault_core::nodes::approver_seed(&dir)?;
        let public = vault_core::nodes::hub_public(&seed)?;
        let fingerprint = vault_core::nodes::key_fingerprint(&public)?;
        Ok(serde_json::json!({ "public_key": public, "fingerprint": fingerprint }))
    }

    /// Phase 37.1: sign a yes for exactly one held push with this machine's
    /// approver key. The renderer names the request; the token (lifetime, nonce,
    /// approver) is built here, so a compromised page cannot choose any of them.
    #[tauri::command]
    pub fn approver_sign(
        app: AppHandle,
        node_id: String,
        target: String,
        sha256: String,
        approval_id: String,
    ) -> Result<vault_core::nodes::SignedApproval, String> {
        let dir = db_path(&app)?
            .parent()
            .map(std::path::Path::to_path_buf)
            .ok_or("no data directory")?;
        let seed = vault_core::nodes::approver_seed(&dir)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        vault_core::nodes::sign_device_approval(
            &seed,
            &node_id,
            &target,
            &sha256,
            &approval_id,
            now,
            &vault_core::iso_now(),
        )
    }

    /// One config-history operation (Phase 35, ADR-0141). The desktop app, the
    /// server's `POST /api/history` and `unv history` all call the same
    /// dispatcher, so the three cannot disagree. Local vault only: a remote
    /// vault's history is reached over HTTP by the frontend.
    #[tauri::command]
    pub fn history_call(
        app: AppHandle,
        state: State<VaultState>,
        op: String,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        let actor = vault_core::ensure_owner_user(&conn).ok();
        envv_cli::history::call(&conn, &op, &args, actor.as_deref())
    }

    /// The version marker of what is on disk right now.
    ///
    /// This is the `data_hash` `save_vault` writes, in the same transaction as
    /// the data — so it is by construction the hash of exactly the bytes stored,
    /// and it is already what the compare-and-swap compares. Reading it is one
    /// indexed `SELECT` against a table with a handful of rows.
    ///
    /// It exists because the desktop app holds the vault in memory and had no
    /// way to learn that something else had written to it: `unv entry set` from
    /// a terminal, `unv totp advance`, or a LAN peer would change the database
    /// under an app that went on showing — and saving — what it read at unlock.
    /// The app polls this and reloads when it moves (`src/ts/vault-watch.ts`).
    ///
    /// Returns `None` rather than an error while the vault is locked: the poller
    /// runs on a timer, and a locked vault is the ordinary state rather than a
    /// failure worth reporting once a second.
    #[tauri::command]
    pub fn vault_version(
        app: AppHandle,
        state: State<VaultState>,
    ) -> Result<Option<String>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let Some(key) = g.as_ref() else {
            return Ok(None);
        };
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::vault_version(&conn)
    }

    #[tauri::command]
    pub fn get_vault_path(app: AppHandle) -> Result<String, String> {
        db_path(&app).map(|p| p.display().to_string())
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

    /// Picks the next non-cooling member, round-robin, and advances the
    /// cursor — Phase 24.2's pool card Copy button, and the pure IPC twin of
    /// `unv pool next` / `unv get --pool`. `None` when every member is
    /// cooling, so the caller can say so rather than copying nothing with no
    /// explanation.
    #[tauri::command]
    pub fn pool_next(
        app: AppHandle,
        pool: String,
        members: Vec<PoolMemberRef>,
        remote_base: Option<String>,
    ) -> Result<Option<usize>, String> {
        let vk = pool_vault_key(&app, remote_base)?;
        let mut st = vault_core::pool::load();
        let now = vault_core::pool::now_ts();
        let cks: Vec<String> = members.iter().map(|m| m.ck()).collect();
        let cooling: Vec<bool> = cks
            .iter()
            .map(|ck| {
                let s = vault_core::pool::member_state(&st, &vk, &pool, ck);
                vault_core::pool::is_cooling(s.cooling_until.as_deref(), now)
            })
            .collect();
        let cursor = vault_core::pool::cursor(&st, &vk, &pool);
        let Some(i) = vault_core::pool::pick_index(&cooling, cursor) else {
            return Ok(None);
        };
        let n = cks.len();
        vault_core::pool::record_use(&mut st, &vk, &pool, &cks[i], (i + 1) % n, now);
        // Not fatal: the caller already has the chosen index and can copy the
        // member's value. A cursor that fails to advance on a read-only state
        // directory is a worse day than a repeated pick, not a blocked copy.
        let _ = vault_core::pool::save(&st);
        Ok(Some(i))
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

    /// Phase 33.3: `unv backup archive` in the app. Returns the encrypted
    /// `.vaultarc` text for the caller to save with `saveFile` (0600). The vault's
    /// connections are opened and closed per command, so the file on disk is whole;
    /// an archive taken while another process (a LAN server, `unv`) is mid-write
    /// could still miss its last pages, so the pane says to lock first.
    #[tauri::command]
    pub fn backup_archive_build(app: AppHandle, password: String) -> Result<String, String> {
        let db = fs::read(db_path(&app)?).map_err(|e| format!("Cannot read the vault: {e}"))?;
        let salt = fs::read(salt_path(&app)?).map_err(|e| format!("Cannot read the salt: {e}"))?;
        envv_cli::backup::build_archive(&db, &salt, &password)
            .map(|(text, _)| text)
            .map_err(|e| e.message)
    }

    /// Phase 33.3: `unv backup restore-archive` in the app. Verifies the archive
    /// (password, checksums, salt length) before touching a file, then stops the
    /// LAN server, zeroizes the in-memory key like `reset_vault`, writes the salt
    /// first (a salt without a database is recoverable, the reverse is not), then
    /// the database, and removes a stale WAL. The renderer reloads afterwards.
    #[tauri::command]
    pub fn backup_archive_restore(
        app: AppHandle,
        state: State<VaultState>,
        lan: State<LanState>,
        text: String,
        password: String,
    ) -> Result<(), String> {
        let (db, salt) = envv_cli::backup::open_archive(&text, &password).map_err(|e| e.message)?;
        lan_stop(lan)?;
        let mut g = state.0.lock().map_err(|_| "State lock poisoned")?;
        if let Some(mut k) = g.take() {
            k.zeroize();
        }
        let (dbp, sp) = (db_path(&app)?, salt_path(&app)?);
        ensure_parent(&dbp)?;
        fs::write(&sp, &salt).map_err(|e| format!("Cannot write the salt: {e}"))?;
        vault_core::restrict_to_owner(&sp)?;
        fs::write(&dbp, &db).map_err(|e| format!("Cannot write the vault: {e}"))?;
        vault_core::restrict_to_owner(&dbp)?;
        for suffix in ["-wal", "-shm"] {
            let mut p = dbp.clone().into_os_string();
            p.push(suffix);
            let _ = fs::remove_file(p);
        }
        Ok(())
    }

    /// Phase 33.3: `unv import-vault` in the app. Pure over its arguments (the
    /// renderer holds the decrypted vault, the A1 rule): parses a Bitwarden,
    /// 1Password or Proton export and returns what importing would do, plus the
    /// entry array after it. Nothing is written here; the caller applies it with
    /// its own save, so the compare-and-swap covers the whole import.
    #[tauri::command]
    pub fn import_vault_plan(
        vendor: String,
        text: String,
        vault: serde_json::Value,
        project: Option<String>,
        keep_folders: bool,
    ) -> Result<serde_json::Value, String> {
        let (doc, warnings) = envv_cli::import_vaults::source_value(&vendor, &text)?;
        let opts = envv_cli::import_vaults::ImportOpts {
            apply: false,
            project: project.as_deref(),
            category: None,
            keep_folders,
        };
        let plan = envv_cli::import_vaults::plan_import(&vault, &vendor, &doc, &opts)
            .map_err(|e| e.message)?;
        Ok(serde_json::json!({
            "entries": plan.entries, "created": plan.created, "updated": plan.updated,
            "unchanged": plan.unchanged, "skipped": plan.skipped, "preview": plan.preview,
            "warnings": warnings,
        }))
    }

    /// Phase 33.4: bytes from a chosen entropy source for the UI generators, the
    /// app side of `--entropy-source`. Returned as hex. The source is mixed with OS
    /// entropy exactly as the CLI does (`vault_core::entropy::fill`), so picking a
    /// hardware device can add to the OS CSPRNG but never replace it. Capped,
    /// because the renderer asks for a pool, not a stream.
    #[tauri::command]
    pub fn entropy_fill(source: String, length: usize) -> Result<String, String> {
        let source = vault_core::entropy::Source::parse(&source)?;
        if length == 0 || length > 8192 {
            return Err("length must be between 1 and 8192".into());
        }
        let mut buf = vec![0u8; length];
        vault_core::entropy::fill(&source, "ui-generator", &mut buf)?;
        Ok(hex::encode(buf))
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
        vault_core::users::totp_enroll(&conn, &user_id, "UnENVerse")
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

    // ── Stored TOTP seeds (Phase 22) ─────────────────────────────────────────
    //
    // The *other* TOTP: a seed a third-party service issued, held on an entry,
    // from which we generate the code the user types into that service. Above is
    // the second factor on UnENVerse's own login; the two never meet.

    /// The code an entry's stored seed produces right now, with its countdown.
    ///
    /// The seed travels in rather than being looked up here: the frontend
    /// already holds the decrypted vault, and re-reading the entry over the
    /// vault path would mean this command needed an entry id, an ambiguity rule
    /// and a second definition of which field the seed lives in.
    ///
    /// **A11 (2026-09-14): no longer gated on the local `VaultState`.** It used
    /// to refuse with "Vault is locked" whenever the *local* SQLCipher key was
    /// absent — which is the ordinary state of a session connected only to a
    /// remote vault. The renderer had already decrypted the entry it is asking
    /// about (locally or over the remote API); the gate was checking the wrong
    /// vault, the same bug class as the Phase 12 LAN wrong-vault fix. Every 2FA
    /// code on every remote vault came back blank because of this one check.
    /// The command is pure over its arguments now, and the caller gates on
    /// `st.vaultOpen` instead (`src/ts/totp.ts`).
    ///
    /// Generation happens here and only here. The TypeScript side parses seeds
    /// (`src/ts/totp.ts`) and asks for codes; it does not own an HMAC.
    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub fn entry_totp_code(
        secret: String,
        kind: Option<String>,
        algorithm: Option<String>,
        digits: Option<u32>,
        period: Option<u64>,
        counter: Option<u64>,
        with_next: Option<bool>,
    ) -> Result<vault_core::totp::LiveCode, String> {
        // `Params::from_fields` is the only reader of these three values in the
        // project — the CLI's `params_of` and the form's `totpParamsOf` are the
        // other two callers of that one rule. Reading them here instead meant
        // this command answered an out-of-range `digits` with an error where the
        // CLI answered with a code, so the same entry showed a blank card and a
        // working `unv totp code`.
        let params = vault_core::totp::Params::from_fields(
            kind.as_deref(),
            algorithm.as_deref(),
            digits.map(u64::from),
            period,
            counter,
        );
        vault_core::totp::live_code_with(&secret, &params, with_next.unwrap_or(false))
    }

    /// Phase 29: the cross-chunk checks. Pure over its arguments, so it needs no
    /// vault key and works on a remote session (the A1 rule). The rules live in
    /// `vault_core::config_check`, which `unv check` calls too.
    #[tauri::command]
    pub fn config_check_project(
        project: serde_json::Value,
        vault_names: Vec<String>,
        elsewhere: Option<Vec<String>>,
    ) -> Vec<serde_json::Value> {
        vault_core::config_check::check_project_scoped(
            &project,
            &vault_names,
            &elsewhere.unwrap_or_default(),
        )
        .iter()
        .map(vault_core::config_check::Finding::to_json)
        .collect()
    }

    #[tauri::command]
    pub fn parse_toml_import(source: String) -> Result<Vec<(String, String)>, String> {
        vault_core::toml_import::parse(&source)
    }

    /// Parses a DevTools capture (Copy as cURL, HAR, Set-Cookie lines) into
    /// cookies, a User-Agent and the headers worth keeping — Phase 24.5. Pure
    /// over its arguments, like `parse_toml_import`: one implementation in
    /// `vault_core::session_import`, shared with `unv cookie import`.
    #[tauri::command]
    pub fn session_capture_parse(
        text: String,
        origin: Option<String>,
    ) -> Result<vault_core::session_import::Capture, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        vault_core::session_import::parse_auto(&text, origin.as_deref(), now)
    }

    /// Refreshes an `oauth_client` entry's access token at its `token_url`
    /// (Phase 24.5) and returns the updated entry; the caller **persists it
    /// before using the token**, because a rotating issuer has already killed the
    /// old refresh token. No redirects are followed — one would forward the client
    /// secret — and http is allowed to localhost only. Same
    /// `vault_core::oauth` as `unv oauth refresh`.
    #[tauri::command]
    pub async fn oauth_refresh(mut entry: serde_json::Value) -> Result<serde_json::Value, String> {
        let (url, form) = vault_core::oauth::refresh_request(&entry)?;
        let host = vault_core::oauth::refresh_host(&url).to_string();
        let client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client
            .post(&url)
            .header("Accept", "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("could not reach {host}: {}", e.without_url()))?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if !status.is_success() && body.get("error").is_none() {
            return Err(format!("{host} answered HTTP {status}"));
        }
        let grant = vault_core::oauth::parse_grant(&body)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let rotated = vault_core::oauth::apply_grant(&mut entry, &grant, now);
        Ok(serde_json::json!({ "entry": entry, "rotated": rotated }))
    }

    /// Renders a credential in the file its tool reads (`.npmrc`, a DSN, a Wi-Fi
    /// string…) — Phase 24.5. Pure over its arguments; the same
    /// `vault_core::type_emit` as `unv emit`.
    #[tauri::command]
    pub fn type_emit(entry: serde_json::Value, format: String) -> Result<String, String> {
        vault_core::type_emit::emit(&entry, &format)
    }

    /// Phase 33.1: `unv enrich` without `--online`. Pure over its arguments (the
    /// renderer already holds the decrypted vault, the A1 rule): returns, per
    /// entry, the proposals `plan_entry` makes with their reasons and the secret's
    /// fingerprint. The values it proposes are metadata, never the secret, and
    /// nothing is written here: the caller applies what the user accepts.
    #[tauri::command]
    pub fn enrich_plan(entries: Vec<serde_json::Value>, force: bool) -> Vec<serde_json::Value> {
        entries
            .iter()
            .map(|e| {
                let plan = envv_cli::enrich::plan_entry(e, force);
                serde_json::json!({
                    "id": e.get("id"),
                    "provider": plan.provider,
                    "fingerprint": plan.fingerprint,
                    "proposals": plan.proposals.iter().map(|p| serde_json::json!({
                        "field": p.field, "value": p.value, "reason": p.reason,
                    })).collect::<Vec<_>>(),
                })
            })
            .filter(|p| p["proposals"].as_array().is_some_and(|a| !a.is_empty()))
            .collect()
    }

    /// Phase 33.1b: which issuer `enrich --online` would send each entry's secret
    /// to. Makes no request. The consent screen shows this list before
    /// `enrich_online` is allowed to run.
    #[tauri::command]
    pub fn enrich_online_targets(entries: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
        entries
            .iter()
            .filter_map(|e| {
                envv_cli::enrich::issuer_for(e).map(|issuer| {
                    serde_json::json!({ "id": e.get("id"), "provider": e.get("provider"), "issuer": issuer })
                })
            })
            .collect()
    }

    /// Phase 33.1b: `unv enrich --online`. Sends each given entry's secret over
    /// TLS to the issuer that issued it, and nowhere else, then returns what the
    /// issuer said. Public-CA validation, no redirects (`probe_entry` builds the
    /// client). Blocking HTTP, so it runs off the async runtime. The renderer only
    /// calls this after the user has seen `enrich_online_targets`.
    #[tauri::command]
    pub async fn enrich_online(
        entries: Vec<serde_json::Value>,
        force: bool,
    ) -> Result<Vec<serde_json::Value>, String> {
        tauri::async_runtime::spawn_blocking(move || {
            entries
                .iter()
                .filter_map(|e| {
                    envv_cli::enrich::probe_entry(e, 10, force).map(|live| {
                        serde_json::json!({
                            "id": e.get("id"),
                            "provider": e.get("provider"),
                            "issuer": live.issuer,
                            "status": live.status,
                            "detail": live.detail,
                            "proposals": live.proposals.iter().map(|p| serde_json::json!({
                                "field": p.field, "value": p.value, "reason": p.reason,
                            })).collect::<Vec<_>>(),
                        })
                    })
                })
                .collect()
        })
        .await
        .map_err(|e| e.to_string())
    }

    /// Phase 33.2b: the file half of `unv doctor` (integrity, storage hashes, salt
    /// pairing, permissions, audit chain) over this machine's vault. Local only:
    /// against a remote the database is the server's, and `unv doctor` there.
    #[tauri::command]
    pub fn doctor_file(
        app: AppHandle,
        state: State<VaultState>,
    ) -> Result<Vec<serde_json::Value>, String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = *g.as_ref().ok_or("Vault is locked")?;
        envv_cli::access::set_paths(Some(db_path(&app)?), Some(salt_path(&app)?));
        Ok(envv_cli::doctor::file_findings(
            &envv_cli::access::Access::Local(key),
        ))
    }

    /// Phase 33.2: the document half of `unv doctor`. Pure over its argument.
    #[tauri::command]
    pub fn doctor_document(vault: serde_json::Value) -> Vec<serde_json::Value> {
        envv_cli::doctor::document_findings(&vault)
    }

    /// Phase 31: which table `enrich` uses (`unv catalogue show`). Reads the
    /// cache and re-verifies it; touches neither the vault nor the network.
    #[tauri::command]
    pub fn catalogue_status() -> serde_json::Value {
        match vault_core::catalogue::load_cached() {
            Some(c) => serde_json::json!({
                "source": "catalogue", "generated_at": c.generated_at, "providers": c.providers.len(),
            }),
            None => serde_json::json!({ "source": "bundled" }),
        }
    }

    /// Phase 31: `unv catalogue update`. Fetches one whole file over https (CA
    /// validation, https only, 4 MiB cap), then `vault_core::catalogue::store`
    /// verifies the signature and refuses a rollback before caching.
    #[tauri::command]
    pub async fn catalogue_update(url: Option<String>) -> Result<serde_json::Value, String> {
        let url = url.unwrap_or_else(|| vault_core::catalogue::DEFAULT_URL.to_string());
        if !url.starts_with("https://") {
            return Err("the catalogue is only fetched over https".into());
        }
        let client = reqwest::ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;
        let bytes = client
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("could not fetch the catalogue: {}", e.without_url()))?
            .bytes()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("catalogue is over 4 MiB; refusing".into());
        }
        let c = vault_core::catalogue::store(&bytes)?;
        Ok(serde_json::json!({ "generated_at": c.generated_at, "providers": c.providers.len() }))
    }

    /// `Ok(())` when `mnemonic` is a valid BIP39 phrase; the error never echoes a word.
    #[tauri::command]
    pub fn bip39_validate(mnemonic: String) -> Result<(), String> {
        vault_core::type_emit::bip39_validate(&mnemonic)
    }

    /// Converts a CXF document's text into entries ready to append — Phase
    /// 24.5's desktop path for the same `vault_core::cxf::import` the CLI's
    /// `unv cxf import` calls. Pure over its argument: the caller already
    /// holds the decrypted vault and does the appending and the save, the
    /// same split `calendar_build_ics` uses.
    #[tauri::command]
    pub fn cxf_import(text: String) -> Result<Vec<serde_json::Value>, String> {
        let doc = vault_core::cxf::parse(text.as_bytes())?;
        let now = vault_core::iso_now();
        Ok(vault_core::cxf::import(&doc, vault_core::new_uuid, &now))
    }

    /// Builds a CXF document from entries the caller already holds. Returns
    /// pretty-printed JSON text; the caller writes it with `saveFile`, the
    /// same materialising-path rule every export in this project follows —
    /// there is no stdout-equivalent form of this command.
    #[tauri::command]
    pub fn cxf_export(entries: Vec<serde_json::Value>) -> Result<String, String> {
        let doc = vault_core::cxf::export(&entries);
        serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
    }

    /// Builds the `.ics` calendar feed from entries the caller already holds.
    ///
    /// Phase 24.3: `src/ts/calendar.ts` used to be a second implementation of
    /// this format, pinned against `vault-core/src/calendar.rs` by a golden
    /// fixture — the twin-pair shape. It is gone now; this is the one builder,
    /// exactly as `unv-server`'s `/ics/{token}.ics` route and `unv calendar
    /// export` both already use it. Pure over its arguments rather than reading
    /// `VaultState` — the caller already holds the decrypted vault, local or
    /// remote, the same reasoning as `entry_totp_code` — so a Timeline export
    /// works on a remote vault too, which the old local-only TypeScript builder
    /// never could.
    #[tauri::command]
    pub fn calendar_build_ics(
        entries: Vec<serde_json::Value>,
        kinds: Vec<String>,
        calendar_name: String,
    ) -> Result<String, String> {
        let mut parsed: Vec<vault_core::calendar::EventKind> = kinds
            .iter()
            .filter_map(|k| vault_core::calendar::EventKind::parse(k))
            .collect();
        if parsed.is_empty() {
            parsed = vec![
                vault_core::calendar::EventKind::Created,
                vault_core::calendar::EventKind::Expires,
                vault_core::calendar::EventKind::Rotation,
            ];
        }
        Ok(vault_core::calendar::build_ics(
            &entries,
            &vault_core::calendar::IcsOptions {
                kinds: parsed,
                now: vault_core::iso_now(),
                calendar_name,
            },
        ))
    }

    /// Merge an authenticator export into the entries the frontend holds.
    ///
    /// Parse, plan and apply in one call, returning the new entry array and a
    /// report. One round trip rather than three, and — the reason it exists at
    /// all — the merge rules stay in `vault_core::totp_import`, where
    /// `unv totp import` also reads them. Whether a working second factor
    /// survives an import must not be able to differ between the app and the
    /// terminal.
    ///
    /// `entries` goes in and comes back rather than being read from the vault
    /// here: the frontend is the thing holding the decrypted vault, and having
    /// this command load and save independently would put two writers on one
    /// file with no compare-and-swap between them.
    /// **A11: no longer gated on `VaultState`** — pure over `entries` and
    /// `text`, same reasoning as the other authenticator commands.
    #[tauri::command]
    pub fn totp_import_merge(
        entries: Vec<serde_json::Value>,
        text: String,
        force: bool,
        project: Option<String>,
        category: Option<String>,
    ) -> Result<serde_json::Value, String> {
        use vault_core::totp_import::{self as imp, Plan};

        let report = imp::parse(&text)?;
        let plans = imp::plan(&entries, &report.items, force);
        let mut entries = entries;
        let (mut created, mut updated, mut unchanged, mut conflicts) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());

        for (item, plan) in report.items.iter().zip(plans.iter()) {
            let label = serde_json::json!({
                "provider": item.suggested_provider(),
                "account": item.account.clone().unwrap_or_default(),
            });
            match plan {
                Plan::Unchanged { .. } => unchanged.push(label),
                Plan::Conflict { .. } => conflicts.push(label),
                Plan::Update { index } => {
                    imp::write_fields(&mut entries[*index], &item.stored);
                    updated.push(label);
                }
                Plan::Create => {
                    entries.push(imp::new_entry(
                        item,
                        &vault_core::new_uuid(),
                        &vault_core::iso_now(),
                        project.as_deref(),
                        category.as_deref(),
                    ));
                    created.push(label);
                }
            }
        }

        Ok(serde_json::json!({
            "entries": entries,
            "format": report.format.as_str(),
            "created": created,
            "updated": updated,
            "unchanged": unchanged,
            "conflicts": conflicts,
            "skipped": report.skipped,
        }))
    }

    /// Write seeds in a format another authenticator reads.
    ///
    /// **The returned string is nothing but secret material.** The frontend hands
    /// it straight to a save dialog; it never reaches a log, a toast or the
    /// clipboard by default. Same rule as `unv totp export --out`.
    ///
    /// **A11: no longer gated on `VaultState`** — pure over `items`.
    #[tauri::command]
    pub fn totp_export_build(
        items: Vec<vault_core::totp_import::Imported>,
        format: String,
    ) -> Result<String, String> {
        let fmt = vault_core::totp_import::Format::parse(&format)
            .ok_or_else(|| format!("Unknown format '{format}'"))?;
        vault_core::totp_import::build(&items, fmt)
    }

    /// Phase 33.4: `unv user strict-write` / `class` in the app. `subject_kind`
    /// is `user` or `class`; the owner is the only caller the app can have.
    #[tauri::command]
    pub fn set_strict_write(
        app: AppHandle,
        state: State<VaultState>,
        subject_kind: String,
        subject_id: String,
        strict: bool,
    ) -> Result<(), String> {
        let g = state.0.lock().map_err(|_| "State lock poisoned")?;
        let key = g.as_ref().ok_or("Vault is locked")?;
        let conn = vault_core::open_db(&db_path(&app)?, key)?;
        vault_core::users::set_strict_write(&conn, &subject_kind, &subject_id, strict)
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
    /// Runs the `unv-server` router in-process against the vault that is
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

        // Default 8744 so a Docker unv-server on 8743 can coexist; step forward
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
        /// `ETag`, so a save over the pinned proxy can send the next `If-Match`.
        pub etag: Option<String>,
        /// `X-Vault-Merged: 1`: the save folded in another writer's changes.
        pub merged: bool,
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

    /// Writes an export to disk and returns the absolute path it landed at.
    ///
    /// **ADR-0003.** Every app export — ICS included — built a `Blob`,
    /// clicked a `<a download>` anchor, and toasted "Exported ✓" unconditionally
    /// (`downloadText` in `src/ts/import-export.ts`). Tauri's WebKitGTK webview
    /// has no download handler registered and no `tauri-plugin-dialog`/`-fs`
    /// capability either, so the click silently went nowhere — the toast was
    /// true only in a plain browser dev server. This is the app's `--out`: it
    /// writes real bytes before the caller is told anything succeeded.
    ///
    /// No save dialog (the app has no `tauri-plugin-dialog` dependency, and
    /// adding one is a larger change than this defect fix warrants): resolves
    /// the platform downloads directory, falling back to the home directory and
    /// then the OS temp directory if neither exists, and disambiguates a
    /// filename that is already there (`name (2).ext`) rather than silently
    /// overwriting yesterday's export — the write is trusted precisely because
    /// it never clobbers.
    ///
    /// `0600` on Unix: most of what flows through here is a `.env` or a backup,
    /// and there is no reason to leave either group/world-readable. Windows
    /// inherits the directory ACL, the same gap `session.rs` already documents
    /// for `sessions.json`.
    #[tauri::command]
    pub fn write_export_file(filename: String, content: String) -> Result<String, String> {
        let dir = dirs::download_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(std::env::temp_dir);
        write_export_file_to(&dir, &filename, &content)
    }

    pub(super) fn write_export_file_to(
        dir: &Path,
        filename: &str,
        content: &str,
    ) -> Result<String, String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        // Take only the final path component of whatever the caller sent — this
        // is a *filename*, not a path, and untrusted vault-derived text (a
        // provider name, invariant 4) must never be able to write outside the
        // resolved directory.
        let safe_name = Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .unwrap_or("envvault-export")
            .to_string();

        let stem = Path::new(&safe_name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&safe_name)
            .to_string();
        let ext = Path::new(&safe_name)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{e}"))
            .unwrap_or_default();

        let mut path = dir.join(&safe_name);
        let mut n = 2;
        while path.exists() {
            path = dir.join(format!("{stem} ({n}){ext}"));
            n += 1;
        }

        fs::write(&path, content.as_bytes()).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(path.display().to_string())
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
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let merged = resp
            .headers()
            .get("x-vault-merged")
            .is_some_and(|v| v == "1");
        let body_text = resp.text().await.unwrap_or_default();
        Ok(RemoteResponse {
            status,
            body: body_text,
            etag,
            merged,
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
            commands::caps_lock_state,
            commands::lock_vault,
            commands::vault_is_unlocked,
            commands::vault_exists,
            commands::reset_vault,
            commands::load_vault,
            commands::save_vault,
            commands::save_vault_rows,
            commands::approver_public,
            commands::matlog_note,
            commands::env_import_plan,
            commands::pgp_inspect,
            commands::approver_sign,
            commands::history_call,
            commands::get_vault_path,
            commands::pool_state,
            commands::pool_next,
            commands::pool_set_cooldown,
            commands::pool_reset,
            commands::pool_state_path,
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
            commands::vault_version,
            commands::entry_totp_code,
            commands::config_check_project,
            commands::parse_toml_import,
            commands::session_capture_parse,
            commands::type_emit,
            commands::oauth_refresh,
            commands::bip39_validate,
            commands::enrich_plan,
            commands::enrich_online_targets,
            commands::enrich_online,
            commands::set_strict_write,
            commands::entropy_fill,
            commands::import_vault_plan,
            commands::backup_archive_build,
            commands::backup_archive_restore,
            commands::doctor_document,
            commands::doctor_file,
            commands::catalogue_status,
            commands::catalogue_update,
            commands::calendar_build_ics,
            commands::cxf_import,
            commands::cxf_export,
            commands::totp_import_merge,
            commands::totp_export_build,
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
            commands::get_audit_log,
            commands::lan_start,
            commands::lan_stop,
            commands::lan_status,
            commands::remote_request,
            commands::probe_cert_fingerprint,
            commands::write_export_file,
        ])
        .setup(|app| {
            // ── System Tray (item 18) ────────────────────────────────────────
            let tray = tauri::tray::TrayIconBuilder::new()
                .tooltip("UnENVerse")
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
        .expect("error while running UnENVerse");
}

#[cfg(test)]
mod export_file_tests {
    //! `write_export_file` (A3, 2026-09-14). The rest of `mod commands` needs a
    //! live `AppHandle`/`VaultState`; this one is a plain function over its
    //! arguments, so it is the one command in this file that can be unit
    //! tested directly without a test harness for the others.
    use super::commands::write_export_file_to;
    use std::fs;
    use std::path::PathBuf;

    fn scratch() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("envvault-export-test-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn writes_the_content_and_returns_the_real_path() {
        let content = "SPOTIFY_ID=abc123\n";
        let dir = scratch();
        let path = write_export_file_to(&dir, "basic.env", content).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_filename_that_already_exists_is_disambiguated_rather_than_overwritten() {
        // The whole point of not asking for a save location: the write must
        // never silently clobber yesterday's export.
        let dir = scratch();
        let a = write_export_file_to(&dir, "dup.env", "first").unwrap();
        let b = write_export_file_to(&dir, "dup.env", "second").unwrap();
        assert_ne!(a, b);
        assert_eq!(fs::read_to_string(&a).unwrap(), "first");
        assert_eq!(fs::read_to_string(&b).unwrap(), "second");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_path_in_the_filename_cannot_escape_the_resolved_directory() {
        // The filename is vault-derived text on some call sites (a provider or
        // project name) — untrusted input, invariant 4. `../../etc/passwd`
        // must land as a file literally named that inside the resolved
        // directory, never traverse out of it.
        let dir = scratch();
        let path = write_export_file_to(&dir, "../../etc/passwd", "x").unwrap();
        assert!(!path.contains(".."));
        assert_eq!(PathBuf::from(&path).parent(), Some(dir.as_path()));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn is_written_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let path = write_export_file_to(&dir, "perms.env", "x").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }
}
