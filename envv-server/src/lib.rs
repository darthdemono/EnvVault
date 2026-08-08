//! `envv-server` — remote vault HTTP server, usable as a binary or embedded.
//!
//! The desktop app hosts this same router in-process for "Open to LAN", serving
//! the vault it already has open. Everything here is therefore free of CLI and
//! process assumptions: no `std::process::exit`, no reading argv, nothing that
//! would take the whole desktop app down with it.
//!
//! # Auth flows
//! - Owner: `POST /api/unlock` with the master password → owner session token.
//! - User:  `POST /api/auth` with username+password or `{ token }` → user session.
//!
//! In **LAN mode** `/api/unlock` is refused outright: the host is already
//! unlocked, so there is no reason for the master password to cross a network.
//! Peers authenticate as named users, which also gives them their own RBAC scope
//! and audit trail.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use utoipa::{OpenApi, ToSchema};
use vault_core::{
    derive_key, filter_vault_for_user, get_expiring_entries, get_expiring_entries_for_user,
    effective_permission_expr,
    init_schema, load_audit, load_vault, merge_user_vault_write, open_db,
    read_or_create_salt, save_vault, verify_vault_integrity, ensure_owner_user,
    VaultKey, Zeroize,
};
use std::time::{Duration, Instant};

// ── Session model ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Session {
    vault_key:  VaultKey,
    user_id:    String,
    is_owner:   bool,
    /// Absolute deadline. Refreshed on every authenticated request (rolling
    /// window), so an active client never gets logged out mid-session while an
    /// abandoned one — or a stolen token — stops working after `session_ttl`.
    expires_at: Instant,
}

/// Drops every session past its deadline, zeroizing the vault key it held.
/// Cheap enough to run on each lookup: the map is small and bounded by it.
fn purge_expired(sessions: &mut HashMap<String, Session>) {
    let now = Instant::now();
    sessions.retain(|_, s| {
        if s.expires_at > now { return true; }
        s.vault_key.zeroize();
        false
    });
}

/// Live (non-expired) sessions, purging as a side effect.
fn live_sessions(state: &AppState) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
    let mut guard = state.sessions.lock().unwrap();
    purge_expired(&mut guard);
    guard
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct RateBucket { failures: u32, window_start: Option<Instant> }

/// Returns `true` when the caller is **not** rate-limited (i.e. they may proceed).
/// Does NOT increment the counter — call `record_auth_failure` on a failed attempt.
fn rate_is_allowed(buckets: &mut HashMap<String, RateBucket>, key: &str) -> bool {
    let bucket = buckets.entry(key.to_string()).or_default();
    let now = Instant::now();
    match bucket.window_start {
        Some(ws) if now.duration_since(ws) < Duration::from_secs(60) => bucket.failures < 10,
        _ => {
            // Reset window on expiry
            bucket.window_start = Some(now);
            bucket.failures = 0;
            true
        }
    }
}

/// Increments the failure counter for `key`.  Call this only after a confirmed
/// authentication failure (wrong password / invalid token).
fn record_auth_failure(buckets: &mut HashMap<String, RateBucket>, key: &str) {
    let bucket = buckets.entry(key.to_string()).or_default();
    let now = Instant::now();
    if bucket.window_start.map_or(true, |ws| now.duration_since(ws) >= Duration::from_secs(60)) {
        bucket.window_start = Some(now);
        bucket.failures = 0;
    }
    bucket.failures += 1;
    // Evict expired buckets periodically to prevent unbounded memory growth.
    if buckets.len() > 1000 {
        buckets.retain(|_, b| {
            b.window_start.map_or(false, |ws| now.duration_since(ws) < Duration::from_secs(300))
        });
    }
}

// ── TLS certificate helpers ───────────────────────────────────────────────────

/// SHA-256 hex fingerprint of the first certificate DER found in a PEM file.
///
/// Parsing is delegated to `rustls-pemfile` — a hand-rolled decoder previously
/// used here silently mapped invalid base64 characters to zero, so a corrupt
/// cert produced a plausible-looking but wrong fingerprint that clients would
/// then pin to.
fn fingerprint_of_cert_pem(path: &std::path::Path) -> Result<String, String> {
    use sha2::{Sha256, Digest};
    let file = std::fs::File::open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let der = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| format!("no certificate in {}", path.display()))?
        .map_err(|e| format!("malformed PEM in {}: {e}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&der)))
}

/// Generate a self-signed TLS certificate valid for `localhost` / `127.0.0.1`.
/// Saves PEM files to `data_dir/server.crt` + `server.key`.
/// Returns `(cert_path, key_path, sha256_hex_fingerprint)`.
fn generate_self_signed_cert(data_dir: &std::path::Path) -> Result<(PathBuf, PathBuf, String), String> {
    use rcgen::{CertificateParams, KeyPair, SanType};
    use sha2::{Sha256, Digest};

    let cert_path = data_dir.join("server.crt");
    let key_path  = data_dir.join("server.key");

    let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| e.to_string())?;
    params.subject_alt_names.push(SanType::IpAddress(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    params.not_after = time::OffsetDateTime::now_utc()
        .checked_add(time::Duration::days(365 * 3))
        .ok_or("date overflow")?;

    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    std::fs::write(&cert_path, cert.pem()).map_err(|e| format!("write cert: {e}"))?;
    std::fs::write(&key_path,  key_pair.serialize_pem()).map_err(|e| format!("write key: {e}"))?;

    let fingerprint = hex::encode(Sha256::digest(cert.der()));
    Ok((cert_path, key_path, fingerprint))
}

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    sessions:        Arc<Mutex<HashMap<String, Session>>>,
    rate_limiter:    Arc<Mutex<HashMap<String, RateBucket>>>,
    db_path:         PathBuf,
    salt_path:       PathBuf,
    /// SHA-256 hex fingerprint of the TLS certificate (None when running plain HTTP).
    cert_fingerprint: Option<String>,
    /// Idle lifetime of a session. Every authenticated request resets the clock.
    session_ttl:     Duration,
    /// True when embedded in the desktop app serving an already-open vault.
    ///
    /// Refuses `POST /api/unlock` so the master password never travels over the
    /// network, and lets the host pre-seed the owner session from the key it
    /// already holds.
    lan_mode:        bool,
    /// Instant of the last request from a non-owner session, for idle shutdown.
    last_peer_activity: Arc<Mutex<Instant>>,
}

impl AppState {
    /// Builds server state. `session_ttl_mins == 0` disables session expiry.
    pub fn new(
        db_path: PathBuf,
        salt_path: PathBuf,
        cert_fingerprint: Option<String>,
        session_ttl_mins: u64,
        lan_mode: bool,
    ) -> Self {
        AppState {
            sessions:     Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            db_path,
            salt_path,
            cert_fingerprint,
            // "Never" is represented as a decade rather than special-casing every
            // comparison site.
            session_ttl: if session_ttl_mins == 0 {
                Duration::from_secs(86_400 * 365 * 10)
            } else {
                Duration::from_secs(session_ttl_mins * 60)
            },
            lan_mode,
            last_peer_activity: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Seeds an owner session directly from a vault key the caller already holds.
    ///
    /// This is how the desktop hosts its own vault without anyone re-entering the
    /// master password. The returned token is not handed out over the network —
    /// it exists so the key stays reachable for `POST /api/auth`, which borrows
    /// it after verifying a peer's own credentials.
    pub fn adopt_owner_key(&self, key: VaultKey, owner_id: String) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        self.sessions.lock().unwrap().insert(token.clone(), Session {
            vault_key:  key,
            user_id:    owner_id,
            is_owner:   true,
            // The host holds this for as long as it serves; peers have their own
            // expiring sessions.
            expires_at: Instant::now() + Duration::from_secs(86_400 * 365 * 10),
        });
        token
    }

    /// Number of connected non-owner sessions.
    pub fn peer_count(&self) -> usize {
        let mut g = self.sessions.lock().unwrap();
        purge_expired(&mut g);
        g.values().filter(|s| !s.is_owner).count()
    }

    /// Seconds since a peer last made a request.
    pub fn idle_secs(&self) -> u64 {
        Instant::now().duration_since(*self.last_peer_activity.lock().unwrap()).as_secs()
    }
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct UnlockRequest { password: String }

#[derive(Serialize, ToSchema)]
struct UnlockResponse { token: String }

#[derive(Serialize, ToSchema)]
struct StatusResponse {
    unlocked:        bool,
    vault_exists:    bool,
    /// SHA-256 hex fingerprint of the server TLS certificate, or null when running plain HTTP.
    cert_fingerprint: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ErrorResponse { error: String }

#[derive(Deserialize, ToSchema)]
struct AuthRequest {
    username:  Option<String>,
    password:  Option<String>,
    token:     Option<String>,
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: Option<String>,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    description: Option<String>,
    expires_at:  Option<String>,
}

#[derive(Deserialize)]
struct RenameUserRequest { username: String }

#[derive(Deserialize)]
struct SetPasswordRequest { password: Option<String> }

#[derive(Deserialize)]
struct AssignClassRequest { class_id: Option<String> }

#[derive(Deserialize)]
struct ClassRequest {
    name:                String,
    #[serde(default)]
    description:         String,
    #[serde(default)]
    cap_manage_users:    bool,
    #[serde(default)]
    cap_manage_classes:  bool,
    #[serde(default)]
    cap_delete_projects: bool,
}

#[derive(Deserialize)]
struct ExpiringQuery {
    #[serde(default = "default_days")]
    days: u32,
}
fn default_days() -> u32 { 30 }

#[derive(Serialize, ToSchema)]
struct StatsResponse {
    secrets_stored:  usize,
    users_total:     usize,
    users_connected: usize,
    vault_unlocked:  bool,
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

fn extract_session(headers: &HeaderMap, state: &AppState) -> Result<(String, Session), (StatusCode, Json<serde_json::Value>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err_json(StatusCode::UNAUTHORIZED, "Missing Bearer token"))?;

    let mut sessions = live_sessions(state);
    // Slide the deadline forward: activity keeps a session alive, idleness kills it.
    let session = sessions.get_mut(token).map(|s| {
        s.expires_at = Instant::now() + state.session_ttl;
        s.clone()
    });
    drop(sessions);

    let Some(s) = session else {
        return Err(err_json(StatusCode::UNAUTHORIZED, "Invalid or expired token"));
    };
    // Peer traffic (not the host's own owner session) is what keeps a LAN server
    // from idling out — otherwise the host merely having the app open would look
    // like activity forever.
    if !s.is_owner {
        *state.last_peer_activity.lock().unwrap() = Instant::now();
    }
    Ok((token.to_string(), s))
}

fn require_owner(session: &Session) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if session.is_owner { Ok(()) } else { Err(err_json(StatusCode::FORBIDDEN, "Owner access required")) }
}

/// Authority of the acting session: `(tier, cap_manage_users, cap_manage_classes, cap_delete_projects)`.
/// Owner is tier 3 with all capabilities; sub-users derive tier from their class.
/// See `vault_core::authority_tier` for the Discord-style hierarchy.
fn actor_authority(conn: &vault_core::SqlConnection, session: &Session) -> (i32, bool, bool, bool) {
    if session.is_owner { return (3, true, true, true); }
    let (mu, mc, dp) = vault_core::get_user_capabilities(conn, &session.user_id).unwrap_or((false, false, false));
    (vault_core::authority_tier(false, mu, mc), mu, mc, dp)
}

fn forbidden(msg: &str) -> axum::response::Response {
    err_json(StatusCode::FORBIDDEN, msg).into_response()
}

/// Tier required to mint/grant a class with the given capabilities. A grantor must
/// outrank the grant: only an owner (tier 3) may confer `cap_manage_classes` or
/// `cap_delete_projects`; `cap_manage_users` (tier 2 grant) needs at least an admin.
/// Prevents privilege escalation — you can never create a peer or superior role.
fn min_tier_to_grant(cap_manage_users: bool, cap_manage_classes: bool, cap_delete_projects: bool) -> i32 {
    if cap_manage_classes || cap_delete_projects { 3 }
    else if cap_manage_users { 2 }
    else { 1 }
}

/// Authority tier implied by a class's stored capabilities (0 if class is unknown).
fn class_authority_tier(conn: &vault_core::SqlConnection, class_id: &str) -> i32 {
    vault_core::class_authority_tier(conn, class_id).unwrap_or(0)
}

/// Guard for acting on another user: actor needs manage-users capability and must
/// strictly outrank the target (owner outranks everyone).
fn guard_manage_user(conn: &vault_core::SqlConnection, session: &Session, target: &str) -> Result<(), axum::response::Response> {
    let (tier, mu, _, _) = actor_authority(conn, session);
    if !(session.is_owner || mu) { return Err(forbidden("Requires the manage-users capability")); }
    let target_tier = vault_core::user_authority_tier(conn, target).unwrap_or(0);
    if tier <= target_tier { return Err(forbidden("Cannot act on a user of equal or higher authority")); }
    Ok(())
}

fn err_json(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": msg })))
}

fn owner_vault_key(state: &AppState) -> Option<VaultKey> {
    live_sessions(state).values().find(|s| s.is_owner).map(|s| s.vault_key)
}

// ── Vault key management ──────────────────────────────────────────────────────

/// Authenticate with master password; receive owner session token.
#[utoipa::path(
    post, path = "/api/unlock",
    request_body = UnlockRequest,
    responses(
        (status = 200, description = "Authenticated", body = UnlockResponse),
        (status = 401, description = "Wrong password", body = ErrorResponse),
    ),
    tag = "auth"
)]
async fn unlock(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<UnlockRequest>,
) -> impl IntoResponse {
    // In LAN mode the vault is already open on the host. Accepting the master
    // password here would put the root credential on the wire and hand every
    // caller tier-3 ownership; peers authenticate as named users instead.
    if state.lan_mode {
        return err_json(
            StatusCode::FORBIDDEN,
            "This server is hosted from an unlocked desktop vault — sign in with your user account",
        ).into_response();
    }

    // Rate-limit by socket address — not by X-Forwarded-For (spoofable).
    let ip = addr.ip().to_string();
    if !rate_is_allowed(&mut state.rate_limiter.lock().unwrap(), &ip) {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many failed attempts — try again in a minute").into_response();
    }

    let salt = match read_or_create_salt(&state.salt_path) {
        Ok(s) => s, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let key = match derive_key(&req.password, &salt) {
        Ok(k) => k, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let conn = match open_db(&state.db_path, &key) {
        Ok(conn) => { let _ = init_schema(&conn); conn }
        Err(_)   => {
            record_auth_failure(&mut state.rate_limiter.lock().unwrap(), &ip);
            return err_json(StatusCode::UNAUTHORIZED, "Wrong master password").into_response();
        }
    };
    // Integrity check on unlock (item 5)
    match verify_vault_integrity(&conn) {
        Ok(false) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "Vault integrity check failed — data may be tampered").into_response(),
        Err(e)    => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        Ok(true)  => {}
    }
    seed_default_admin_logged(&conn);
    // The owner is a real user row (password_hash NULL — it cannot be logged
    // into, only reached by deriving the key from the master password). Using
    // its id rather than the old magic string "owner" means owner actions land
    // in the audit log under a resolvable identity.
    let owner_id = match ensure_owner_user(&conn) {
        Ok(id) => id,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let token = uuid::Uuid::new_v4().to_string();
    live_sessions(&state).insert(token.clone(), Session {
        vault_key:  key,
        user_id:    owner_id,
        is_owner:   true,
        expires_at: Instant::now() + state.session_ttl,
    });
    (StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response()
}

/// Idempotently seed the default `admin` user (class: Admin) and log the outcome.
/// Credential source: `ENVV_ADMIN_PASSWORD` if set, else a random one printed once.
fn seed_default_admin_logged(conn: &vault_core::SqlConnection) {
    let env_pw = std::env::var("ENVV_ADMIN_PASSWORD").ok();
    match vault_core::seed_default_admin(conn, env_pw.as_deref()) {
        Ok(vault_core::AdminSeed::Exists) => {}
        Ok(vault_core::AdminSeed::Created { generated_password: Some(pw) }) => {
            eprintln!("\n════════════ Default admin created ════════════");
            eprintln!("  username: admin");
            eprintln!("  password: {pw}");
            eprintln!("  class:    Admin (manage users/classes below you)");
            eprintln!("  Set ENVV_ADMIN_PASSWORD to choose this yourself.");
            eprintln!("═══════════════════════════════════════════════\n");
        }
        Ok(vault_core::AdminSeed::Created { generated_password: None }) => {
            eprintln!("Default admin user created (username: admin) from ENVV_ADMIN_PASSWORD.");
        }
        Err(e) => eprintln!("Warning: default admin seeding failed: {e}"),
    }
}

/// Lock the vault.
///
/// An **owner** lock is global: every session is dropped and its key zeroized,
/// so the vault is genuinely closed and users must re-authenticate once the
/// owner unlocks again. Previously this only removed the caller's own row from
/// the session map, while every user session held its *own copy* of the vault
/// key — so the owner "locking" left everyone else reading and writing
/// indefinitely, and the word meant nothing.
///
/// A non-owner lock stays a personal logout.
#[utoipa::path(
    delete, path = "/api/unlock",
    responses((status = 204, description = "Locked")),
    tag = "auth", security(("bearer_auth" = []))
)]
async fn lock(headers: HeaderMap, State(state): State<AppState>) -> StatusCode {
    let Some(token) = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
    else { return StatusCode::NO_CONTENT; };

    let mut sessions = live_sessions(&state);
    let is_owner = sessions.get(&token).map(|s| s.is_owner).unwrap_or(false);

    if is_owner {
        for (_, mut s) in sessions.drain() { s.vault_key.zeroize(); }
    } else if let Some(mut s) = sessions.remove(&token) {
        s.vault_key.zeroize();
    }
    StatusCode::NO_CONTENT
}

/// Return vault locked/exists status plus the TLS cert fingerprint (if TLS is enabled).
#[utoipa::path(
    get, path = "/api/status",
    responses((status = 200, description = "OK", body = StatusResponse)),
    tag = "auth"
)]
async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        unlocked:         live_sessions(&state).values().any(|s| s.is_owner),
        vault_exists:     state.db_path.exists(),
        cert_fingerprint: state.cert_fingerprint.clone(),
    })
}

// ── User auth ─────────────────────────────────────────────────────────────────

/// Authenticate as a regular user (username+password or token).
/// Requires the vault to be unlocked by the owner first.
#[utoipa::path(
    post, path = "/api/auth",
    request_body = AuthRequest,
    responses(
        (status = 200, description = "Authenticated"),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 503, description = "Vault not unlocked", body = ErrorResponse),
    ),
    tag = "auth"
)]
async fn auth_user(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> impl IntoResponse {
    // Rate-limit by socket address — not by X-Forwarded-For (spoofable).
    let ip = addr.ip().to_string();
    if !rate_is_allowed(&mut state.rate_limiter.lock().unwrap(), &ip) {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many failed attempts — try again in a minute").into_response();
    }

    let key = match owner_vault_key(&state) {
        Some(k) => k,
        None    => return err_json(StatusCode::SERVICE_UNAVAILABLE, "Vault not unlocked by owner").into_response(),
    };
    let conn = match open_db(&state.db_path, &key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };

    let user_opt = match (&req.username, &req.password, &req.token) {
        (Some(u), Some(p), _) => vault_core::verify_user_password(&conn, u, p),
        (_, _, Some(t))       => vault_core::verify_user_token(&conn, t),
        _                     => return err_json(StatusCode::BAD_REQUEST, "Provide username+password or token").into_response(),
    };

    match user_opt {
        Ok(Some(user)) => {
            let session_token = uuid::Uuid::new_v4().to_string();
            live_sessions(&state).insert(session_token.clone(), Session {
                vault_key:  key,
                user_id:    user.id,
                is_owner:   false,
                expires_at: Instant::now() + state.session_ttl,
            });
            (StatusCode::OK, Json(serde_json::json!({ "token": session_token }))).into_response()
        }
        Ok(None) => {
            record_auth_failure(&mut state.rate_limiter.lock().unwrap(), &ip);
            err_json(StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
        }
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

// ── Vault read/write ──────────────────────────────────────────────────────────

/// Load vault data (filtered by user permissions for non-owner sessions).
#[utoipa::path(
    get, path = "/api/vault",
    responses(
        (status = 200, description = "Vault data"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tag = "vault", security(("bearer_auth" = []))
)]
async fn get_vault(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s, Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let vault = match load_vault(&conn) {
        Ok(Some(d)) => d,
        Ok(None)    => return StatusCode::NOT_FOUND.into_response(),
        Err(e)      => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };

    // Version token (ETag) is the full-vault hash so a later PUT can detect drift.
    // The ETag must be the *same* value save_vault compares against, so read the
    // stored data_hash rather than re-hashing the parsed JSON. Re-serialising a
    // Value happens to reproduce the stored bytes today, but relying on that
    // would make every If-Match request 409 the moment it stopped being true.
    let ver = vault_core::vault_version(&conn).ok().flatten().unwrap_or_default();
    // Reads are deliberately not audited. Every GET wrote a row, so a polling
    // client grew the table without bound, and pruning it would have broken the
    // hash chain that makes the log tamper-evident. Mutations carry the actor
    // instead — bounded by how often the vault actually changes.

    if session.is_owner {
        return ([(axum::http::header::ETAG, ver)], Json(vault)).into_response();
    }

    // Non-owner: evaluate their effective read expression (class AND individual,
    // ORed with write since write implies read). No expression means no grant.
    match effective_permission_expr(&conn, &session.user_id, "read") {
        Ok(read) => ([(axum::http::header::ETAG, ver)],
                     Json(filter_vault_for_user(vault, read.as_ref()))).into_response(),
        Err(e)   => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

/// Save vault data (owner: full replace; user: writes only to permitted scopes).
#[utoipa::path(
    put, path = "/api/vault",
    responses(
        (status = 204, description = "Saved"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "Forbidden",    body = ErrorResponse),
    ),
    tag = "vault", security(("bearer_auth" = []))
)]
async fn put_vault(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(data): Json<serde_json::Value>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s, Err(e) => return e.into_response(),
    };

    // Guard: api_keys must be an array. Reject malformed/empty payloads that would wipe the vault.
    if data.get("api_keys").and_then(|v| v.as_array()).is_none() {
        return err_json(StatusCode::BAD_REQUEST, "Invalid vault data: api_keys array required").into_response();
    }
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };

    // Optimistic concurrency. The comparison happens inside save_vault's write
    // transaction rather than here: checking first and writing afterwards leaves
    // a window in which another writer can land between the two, which is
    // exactly the race this is supposed to prevent.
    let expect = headers.get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_matches('"').to_string());

    let ctx = vault_core::SaveCtx {
        actor: Some(&session.user_id),
        expect_version: expect.as_deref(),
    };

    if session.is_owner {
        return match save_vault(&conn, data, ctx) {
            Ok(_)  => StatusCode::NO_CONTENT.into_response(),
            Err(e) if e.starts_with(vault_core::CONFLICT_ERR) =>
                err_json(StatusCode::CONFLICT, "Vault changed since last read — reload and retry").into_response(),
            Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        };
    }

    // Non-owner: merge, honouring their effective write expression.
    let write = match effective_permission_expr(&conn, &session.user_id, "write") {
        Ok(p) => p, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    // Read the version *before* the data it describes.
    //
    // The merge is computed against `full_vault`, so the write has to be
    // conditional on that same version even when the client sent no If-Match —
    // otherwise a concurrent write landing between the load and the save is
    // silently merged away.
    //
    // Order matters. Version-then-data can only mis-pair by pinning an older
    // version than the data, which makes the compare-and-swap fail and the
    // request retry: safe. Data-then-version mis-pairs the other way, passing
    // the check while merging against a stale base: exactly the clobber.
    let merge_base = vault_core::vault_version(&conn).ok().flatten();
    let full_vault = match load_vault(&conn) {
        Ok(Some(v)) => v,
        Ok(None)    => serde_json::json!({ "api_keys": [], "user_categories": [], "projects": [] }),
        Err(e)      => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let merged = match merge_user_vault_write(full_vault, data, write.as_ref()) {
        Ok(v)  => v,
        Err(e) => return err_json(StatusCode::FORBIDDEN, &e).into_response(),
    };
    let ctx = vault_core::SaveCtx {
        actor: Some(&session.user_id),
        expect_version: expect.as_deref().or(merge_base.as_deref()),
    };
    match save_vault(&conn, merged, ctx) {
        Ok(_)  => StatusCode::NO_CONTENT.into_response(),
        Err(e) if e.starts_with(vault_core::CONFLICT_ERR) =>
            err_json(StatusCode::CONFLICT, "Vault changed since last read — reload and retry").into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

/// List entries expiring within N days (default: 30).
#[utoipa::path(
    get, path = "/api/vault/expiring",
    params(("days" = Option<u32>, Query, description = "Lookahead days")),
    responses(
        (status = 200, description = "Expiring entries"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tag = "vault", security(("bearer_auth" = []))
)]
async fn expiring(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(q): Query<ExpiringQuery>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s, Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    // Owner sees everything; a non-owner only sees expiring entries within their RBAC scope.
    let result = if session.is_owner {
        get_expiring_entries(&conn, q.days)
    } else {
        match effective_permission_expr(&conn, &session.user_id, "read") {
            Ok(read) => get_expiring_entries_for_user(&conn, q.days, read.as_ref()),
            Err(e)   => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        }
    };
    match result {
        Ok(entries) => Json(entries).into_response(),
        Err(e)      => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

/// Return the audit log (newest first).
#[utoipa::path(
    get, path = "/api/audit",
    responses(
        (status = 200, description = "Audit rows"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tag = "audit", security(("bearer_auth" = []))
)]
async fn audit(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s, Err(e) => return e.into_response(),
    };
    match require_owner(&session) {
        Ok(()) => {}
        Err(e) => return e.into_response(),
    }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match load_audit(&conn) {
            Ok(rows) => Json(rows).into_response(),
            Err(e)   => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

// ── User management (capability-gated, Discord-style hierarchy) ───────────────

async fn list_users_handler(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (_, mu, _, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mu) { return forbidden("Requires the manage-users capability"); }
    match vault_core::list_users(&conn) {
        Ok(users) => Json(users).into_response(),
        Err(e)    => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn create_user_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (_, mu, _, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mu) { return forbidden("Requires the manage-users capability"); }
    // New user starts with no class (tier 0) — strictly below any creator. Safe.
    match vault_core::create_user(&conn, &req.username, req.password.as_deref(), false) {
        Ok(user) => (StatusCode::CREATED, Json(serde_json::to_value(user).unwrap())).into_response(),
        Err(e)   => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn delete_user_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) { return e; }
    match vault_core::delete_user(&conn, &user_id) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn list_tokens_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) { return e; }
    match vault_core::list_user_tokens(&conn, &user_id) {
        Ok(tokens) => Json(tokens).into_response(),
        Err(e)     => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn create_token_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) { return e; }
    match vault_core::create_user_token(
        &conn, &user_id,
        req.description.as_deref(),
        req.expires_at.as_deref(),
    ) {
        Ok((token_id, plaintext)) => (StatusCode::CREATED, Json(serde_json::json!({
            "token_id": token_id,
            "token": plaintext,
            "note": "Store this token now — it will not be shown again."
        }))).into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn revoke_token_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((_user_id, token_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    // Authorize against the token's actual owner (the path user_id is not trusted —
    // delete is keyed on token_id alone, so a forged low-rank path could otherwise
    // revoke a higher-ranked user's token).
    let owner = vault_core::token_user_id(&conn, &token_id).ok().flatten();
    let Some(owner_id) = owner else { return StatusCode::NO_CONTENT.into_response(); };
    if let Err(e) = guard_manage_user(&conn, &session, &owner_id) { return e; }
    match vault_core::revoke_user_token(&conn, &token_id) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

/// Read/write permission expressions for a subject.
#[derive(Serialize, Deserialize, Default)]
struct PermissionExprs {
    #[serde(default)]
    read:  String,
    #[serde(default)]
    write: String,
}

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

async fn get_permissions_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) { return e; }
    match load_exprs(&conn, "user", &user_id) {
        Ok(e)  => Json(e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn set_permissions_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(exprs): Json<PermissionExprs>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) { return e; }
    // set_permission_expr parses before storing, so a malformed rule is a 400
    // rather than a silently-denies-everything grant.
    match store_exprs(&conn, "user", &user_id, &exprs) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn rename_user_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<RenameUserRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) { return e; }
    match vault_core::rename_user(&conn, &user_id, &req.username) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn set_password_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<SetPasswordRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) { return e; }
    match vault_core::set_user_password(&conn, &user_id, req.password.as_deref()) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn assign_class_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<AssignClassRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) { return e; }
    // Can't promote a user into a class at or above your own authority.
    if let Some(cid) = req.class_id.as_deref() {
        let (actor_tier, ..) = actor_authority(&conn, &session);
        if !session.is_owner && actor_tier <= class_authority_tier(&conn, cid) {
            return forbidden("Cannot assign a class of equal or higher authority");
        }
    }
    match vault_core::assign_user_class(&conn, &user_id, req.class_id.as_deref()) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

// ── Class management (capability-gated) ───────────────────────────────────────

async fn list_classes_handler(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (_, mu, mc, _) = actor_authority(&conn, &session);
    // Managers (users or classes) may read the class list to assign roles.
    if !(session.is_owner || mu || mc) { return forbidden("Requires a management capability"); }
    match vault_core::list_user_classes(&conn) {
        Ok(classes) => Json(classes).into_response(),
        Err(e)      => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn create_class_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ClassRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (actor_tier, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) { return forbidden("Requires the manage-classes capability"); }
    // No minting a class you couldn't be: the grant must require strictly less authority than you hold.
    if !session.is_owner && actor_tier < min_tier_to_grant(req.cap_manage_users, req.cap_manage_classes, req.cap_delete_projects) {
        return forbidden("Cannot create a class with capabilities at or above your own authority");
    }
    match vault_core::create_user_class(&conn, &req.name, &req.description, req.cap_manage_users, req.cap_manage_classes, req.cap_delete_projects) {
        Ok(cls) => (StatusCode::CREATED, Json(serde_json::to_value(cls).unwrap())).into_response(),
        Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn update_class_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(class_id): Path<String>,
    Json(req): Json<ClassRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (actor_tier, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) { return forbidden("Requires the manage-classes capability"); }
    if !session.is_owner {
        // Must outrank both the class as it is now and the capabilities being requested.
        if actor_tier <= class_authority_tier(&conn, &class_id) {
            return forbidden("Cannot modify a class of equal or higher authority");
        }
        if actor_tier < min_tier_to_grant(req.cap_manage_users, req.cap_manage_classes, req.cap_delete_projects) {
            return forbidden("Cannot grant capabilities at or above your own authority");
        }
    }
    match vault_core::update_user_class(&conn, &class_id, &req.name, &req.description, req.cap_manage_users, req.cap_manage_classes, req.cap_delete_projects) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn delete_class_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(class_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (actor_tier, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) { return forbidden("Requires the manage-classes capability"); }
    // Built-in classes (cls-*) are part of the hierarchy itself — owner-only.
    if !session.is_owner {
        if class_id.starts_with("cls-") { return forbidden("Built-in classes can only be deleted by the owner"); }
        if actor_tier <= class_authority_tier(&conn, &class_id) {
            return forbidden("Cannot delete a class of equal or higher authority");
        }
    }
    match vault_core::delete_user_class(&conn, &class_id) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn get_class_perms_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(class_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (_, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) { return forbidden("Requires the manage-classes capability"); }
    match load_exprs(&conn, "class", &class_id) {
        Ok(e)  => Json(e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn set_class_perms_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(class_id): Path<String>,
    Json(exprs): Json<PermissionExprs>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (actor_tier, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) { return forbidden("Requires the manage-classes capability"); }
    if !session.is_owner && actor_tier <= class_authority_tier(&conn, &class_id) {
        return forbidden("Cannot modify a class of equal or higher authority");
    }
    match store_exprs(&conn, "class", &class_id, &exprs) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

// ── Keep-alive ping (item 16) ─────────────────────────────────────────────────

/// Extend the current session expiry (`extract_session` slides the deadline).
/// Returns the server timestamp and how many seconds the session now has left.
async fn ping(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    match extract_session(&headers, &state) {
        Ok((_, session)) => (StatusCode::OK, Json(serde_json::json!({
            "ok": true,
            "ts": vault_core::iso_now(),
            "expires_in_secs": session.expires_at.saturating_duration_since(Instant::now()).as_secs(),
        }))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ── Public stats (Homepage / Homarr widget) ───────────────────────────────────

/// Public statistics — no auth required.
/// Returns 0 for vault-backed counts when locked.
#[utoipa::path(
    get, path = "/api/stats",
    responses((status = 200, description = "Instance statistics", body = StatsResponse)),
    tag = "meta"
)]
async fn stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let (vault_unlocked, users_connected, owner_key) = {
        let sessions = live_sessions(&state);
        let unlocked  = sessions.values().any(|s| s.is_owner);
        let connected = sessions.values().filter(|s| !s.is_owner).count();
        let key       = sessions.values().find(|s| s.is_owner).map(|s| s.vault_key);
        (unlocked, connected, key)
    };

    let (secrets_stored, users_total) = match owner_key.and_then(|k| open_db(&state.db_path, &k).ok()) {
        Some(conn) => {
            let secrets = load_vault(&conn)
                .ok().flatten()
                .and_then(|v| v["api_keys"].as_array().map(|a| a.len()))
                .unwrap_or(0);
            let users = vault_core::list_users(&conn).map(|u| u.len()).unwrap_or(0);
            (secrets, users)
        }
        None => (0, 0),
    };

    Json(StatsResponse { secrets_stored, users_total, users_connected, vault_unlocked })
}

// ── OpenAPI spec ──────────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    paths(unlock, lock, status, auth_user, get_vault, put_vault, expiring, audit, stats),
    components(schemas(UnlockRequest, UnlockResponse, StatusResponse, ErrorResponse, AuthRequest, StatsResponse)),
    info(
        title   = "EnvVault Server",
        version = env!("CARGO_PKG_VERSION"),
        description = "Remote vault API — owner unlocks, users authenticate with /api/auth."
    ),
    tags(
        (name = "auth",  description = "Session management"),
        (name = "vault", description = "Vault read/write"),
        (name = "audit", description = "Append-only audit log"),
        (name = "meta",  description = "Public instance metadata"),
    ),
    security(("bearer_auth" = [])),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).bearer_format("UUID").build()),
            );
        }
    }
}


/// Unlock the vault from a password string (used by ENVV_PASSWORD env var on startup).
pub fn auto_unlock(state: &AppState, password: &str) -> Result<(), String> {
    let salt = read_or_create_salt(&state.salt_path)?;
    let key  = derive_key(password, &salt)?;
    let conn = open_db(&state.db_path, &key)
        .map_err(|_| "Wrong master password — check ENVV_PASSWORD".to_string())?;
    let _ = init_schema(&conn);
    match verify_vault_integrity(&conn) {
        Ok(false) => return Err("Vault integrity check failed — possible tampering".to_string()),
        Err(e)    => return Err(e),
        Ok(true)  => {}
    }
    seed_default_admin_logged(&conn);
    let owner_id = ensure_owner_user(&conn)?;
    state.sessions.lock().unwrap().insert(
        uuid::Uuid::new_v4().to_string(),
        Session {
            vault_key:  key,
            user_id:    owner_id,
            is_owner:   true,
            // Auto-unlock is for unattended deployments (Docker + ENVV_PASSWORD).
            // Nothing ever pings this session, so it must not be allowed to lapse.
            expires_at: Instant::now() + Duration::from_secs(86_400 * 365 * 10),
        },
    );
    Ok(())
}


// ── Router / serving ──────────────────────────────────────────────────────────

/// Builds the complete API router for `state`.
///
/// Shared by the standalone binary and the desktop's in-process LAN server so
/// the two can never drift apart in what they expose.
pub fn build_router(state: AppState, port: u16) -> Router {
    use axum::routing::{delete, post};

    // Explicit origin allow-list. Peers on the LAN talk to the API directly
    // rather than from a browser page, so this only needs to cover the desktop
    // webview and local development.
    let mut origins = vec![
        "tauri://localhost".parse::<axum::http::HeaderValue>().unwrap(),
    ];
    for scheme in ["http", "https"] {
        for host in ["localhost", "127.0.0.1"] {
            origins.push(format!("{scheme}://{host}").parse().unwrap());
            origins.push(format!("{scheme}://{host}:{port}").parse().unwrap());
        }
    }
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);

    let vault_routes = Router::new()
        .route("/api/unlock",                   post(unlock).delete(lock))
        .route("/api/status",                   get(status))
        .route("/api/auth",                     post(auth_user))
        .route("/api/vault",                    get(get_vault).put(put_vault))
        .route("/api/vault/expiring",           get(expiring))
        .route("/api/audit",                    get(audit))
        .route("/api/users",                    get(list_users_handler).post(create_user_handler))
        .route("/api/users/{user_id}",          delete(delete_user_handler))
        .route("/api/users/{user_id}/tokens",   get(list_tokens_handler).post(create_token_handler))
        .route("/api/users/{user_id}/tokens/{token_id}", delete(revoke_token_handler))
        .route("/api/users/{user_id}/permissions", get(get_permissions_handler).put(set_permissions_handler))
        .route("/api/users/{user_id}/rename",   axum::routing::put(rename_user_handler))
        .route("/api/users/{user_id}/password", axum::routing::put(set_password_handler))
        .route("/api/users/{user_id}/class",    axum::routing::put(assign_class_handler))
        .route("/api/classes",                  get(list_classes_handler).post(create_class_handler))
        .route("/api/classes/{class_id}",       axum::routing::put(update_class_handler).delete(delete_class_handler))
        .route("/api/classes/{class_id}/permissions", get(get_class_perms_handler).put(set_class_perms_handler))
        .route("/api/ping",                     get(ping))
        .route("/api/stats",                    get(stats))
        .with_state(state);

    Router::new()
        .merge(vault_routes)
        .route("/api/openapi.json", get(|| async { Json(ApiDoc::openapi()) }))
        .layer(cors)
}

/// TLS material for [`serve`].
pub struct TlsFiles { pub cert: PathBuf, pub key: PathBuf }

/// Generates a self-signed certificate at `dir` if one is not already there.
///
/// Reuses an existing pair on purpose: regenerating per launch would change the
/// fingerprint every time and break every peer's pin.
pub fn ensure_self_signed_cert(dir: &std::path::Path) -> Result<(TlsFiles, String), String> {
    let cert = dir.join("server.crt");
    let key  = dir.join("server.key");
    if cert.exists() && key.exists() {
        if let Ok(fp) = fingerprint_of_cert_pem(&cert) {
            return Ok((TlsFiles { cert, key }, fp));
        }
        // Unreadable or corrupt — fall through and regenerate.
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let (c, k, fp) = generate_self_signed_cert(dir)?;
    Ok((TlsFiles { cert: c, key: k }, fp))
}

/// Reads the SHA-256 fingerprint of a certificate PEM.
pub fn cert_fingerprint(path: &std::path::Path) -> Result<String, String> {
    fingerprint_of_cert_pem(path)
}

/// Serves until `shutdown` resolves.
///
/// Returns `Err` rather than exiting the process — this runs inside the desktop
/// app, where a failed bind must surface as a message, not a crash.
pub async fn serve(
    state: AppState,
    addr: SocketAddr,
    tls: Option<TlsFiles>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), String> {
    let app = build_router(state, addr.port());
    let svc = app.into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        Some(files) => {
            let cfg = axum_server::tls_rustls::RustlsConfig::from_pem_file(&files.cert, &files.key)
                .await.map_err(|e| format!("TLS config error: {e}"))?;
            let handle = axum_server::Handle::new();
            let h = handle.clone();
            tokio::spawn(async move {
                let _ = shutdown.await;
                // Give in-flight requests a moment rather than cutting them dead.
                h.graceful_shutdown(Some(Duration::from_secs(3)));
            });
            axum_server::bind_rustls(addr, cfg)
                .handle(handle)
                .serve(svc)
                .await.map_err(|e| format!("server error: {e}"))
        }
        None => {
            let listener = tokio::net::TcpListener::bind(addr).await
                .map_err(|e| format!("bind {addr}: {e}"))?;
            axum::serve(listener, svc)
                .with_graceful_shutdown(async { let _ = shutdown.await; })
                .await.map_err(|e| format!("server error: {e}"))
        }
    }
}

/// Binds the first free port at or after `start`, giving up after `tries`.
///
/// Lets "Open to LAN" coexist with a Docker `envv-server` already holding the
/// default port instead of just failing.
pub fn find_free_port(host: &str, start: u16, tries: u16) -> Option<u16> {
    (start..start.saturating_add(tries))
        .find(|p| std::net::TcpListener::bind((host, *p)).is_ok())
}

impl AppState {
    /// Drops every session, zeroizing each vault key.
    ///
    /// Used when the desktop stops serving: peers must not keep a usable key in
    /// server memory after the host closes the LAN, and the host's own adopted
    /// owner session must go with it.
    pub fn shutdown_all_sessions(&self) {
        let mut g = self.sessions.lock().unwrap();
        for (_, mut s) in g.drain() { s.vault_key.zeroize(); }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("envv-server-test-{tag}-{nanos}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn state(lan: bool) -> AppState {
        let d = scratch("state");
        AppState::new(d.join("vault.db"), d.join("vault.salt"), None, 480, lan)
    }

    #[test]
    fn adopted_owner_session_counts_as_owner_not_peer() {
        // The host's own session must not look like a connected peer, or the
        // idle shutdown and the "N peers connected" warning would both be wrong.
        let s = state(true);
        s.adopt_owner_key([7u8; 32], "owner-id".into());
        assert_eq!(s.peer_count(), 0);
    }

    #[test]
    fn shutdown_drops_every_session() {
        let s = state(true);
        s.adopt_owner_key([7u8; 32], "owner-id".into());
        s.shutdown_all_sessions();
        assert!(s.sessions.lock().unwrap().is_empty(),
                "stopping the LAN server must not leave a usable key in memory");
    }

    #[test]
    fn expired_sessions_are_purged_and_not_counted() {
        let s = state(false);
        s.sessions.lock().unwrap().insert("dead".into(), Session {
            vault_key:  [1u8; 32],
            user_id:    "u".into(),
            is_owner:   false,
            expires_at: Instant::now() - Duration::from_secs(1),
        });
        assert_eq!(s.peer_count(), 0);
        assert!(s.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn lan_mode_is_recorded_on_state() {
        assert!(state(true).lan_mode);
        assert!(!state(false).lan_mode);
    }

    #[test]
    fn find_free_port_skips_a_taken_one() {
        let taken = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = taken.local_addr().unwrap().port();
        let found = find_free_port("127.0.0.1", port, 20).expect("a free port after the taken one");
        assert_ne!(found, port, "must not hand back a port already bound");
        assert!(found > port);
    }

    #[test]
    fn self_signed_cert_is_reused_so_pins_stay_valid() {
        // Regenerating per launch would change the fingerprint every time and
        // break every peer's pinned certificate.
        let dir = scratch("cert");
        let (_, first)  = ensure_self_signed_cert(&dir).unwrap();
        let (_, second) = ensure_self_signed_cert(&dir).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64, "SHA-256 hex fingerprint");
    }

    #[test]
    fn idle_seconds_start_near_zero() {
        assert!(state(true).idle_secs() < 5);
    }
}
