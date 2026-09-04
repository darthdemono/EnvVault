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
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use utoipa::{OpenApi, ToSchema};
use vault_core::{
    derive_key, effective_permission_expr, ensure_owner_user, filter_vault_for_user,
    get_expiring_entries, get_expiring_entries_for_user, init_schema, load_audit, load_vault,
    merge_user_vault_write, open_db, read_or_create_salt, save_vault, verify_vault_integrity,
    VaultKey, Zeroize,
};

// ── Session model ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Session {
    vault_key: VaultKey,
    user_id: String,
    is_owner: bool,
    /// Idle deadline. Refreshed on every authenticated request (rolling
    /// window), so an active client never gets logged out mid-session while an
    /// abandoned one stops working after `session_ttl`.
    ///
    /// This alone does **not** bound a stolen token: the desktop pings every 90
    /// seconds by design, so any token an attacker actually uses slides its own
    /// deadline forward forever. `hard_expires_at` is what bounds it.
    expires_at: Instant,
    /// Absolute ceiling, fixed when the session was minted and never moved.
    /// `extract_session` clamps the rolling deadline to it, so a session dies at
    /// `issued_at + session_max_lifetime` however busy it is — which is the only
    /// thing that limits a leaked bearer token to a finite window.
    hard_expires_at: Instant,
}

impl Session {
    /// The deadline that actually governs: whichever of the two comes first.
    fn deadline(&self) -> Instant {
        self.expires_at.min(self.hard_expires_at)
    }
}

/// Drops every session past its deadline, zeroizing the vault key it held.
/// Cheap enough to run on each lookup: the map is small and bounded by it.
fn purge_expired(sessions: &mut HashMap<String, Session>) {
    let now = Instant::now();
    sessions.retain(|_, s| {
        if s.deadline() > now {
            return true;
        }
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
struct RateBucket {
    failures: u32,
    window_start: Option<Instant>,
}

/// Returns `true` when the caller is **not** rate-limited (i.e. they may proceed).
/// Does NOT increment the counter — call `record_auth_failure` on a failed attempt.
/// Length of the failure window. Ten failures inside it and the caller waits.
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// `None` when the caller may proceed; `Some(secs)` when it is rate limited,
/// carrying the whole seconds until the current window resets.
///
/// The seconds matter as much as the refusal. A script driving this API cannot
/// tell "slow down" from "denied" without them, so it either gives up on a
/// transient block or hammers a server that has already said no — and the
/// agent-driven CLI is the main consumer here. The value goes out as
/// `Retry-After`, which is the header every HTTP client already understands.
fn rate_retry_after(buckets: &mut HashMap<String, RateBucket>, key: &str) -> Option<u64> {
    let bucket = buckets.entry(key.to_string()).or_default();
    let now = Instant::now();
    match bucket.window_start {
        Some(ws) if now.duration_since(ws) < RATE_WINDOW => {
            if bucket.failures < 10 {
                None
            } else {
                // Round *up*: a client told to wait 0 seconds retries instantly
                // and is refused again, which reads as a broken server.
                let remaining = RATE_WINDOW.saturating_sub(now.duration_since(ws));
                Some(remaining.as_secs().max(1))
            }
        }
        _ => {
            // Reset window on expiry
            bucket.window_start = Some(now);
            bucket.failures = 0;
            None
        }
    }
}

/// Increments the failure counter for `key`.  Call this only after a confirmed
/// authentication failure (wrong password / invalid token).
fn record_auth_failure(buckets: &mut HashMap<String, RateBucket>, key: &str) {
    let bucket = buckets.entry(key.to_string()).or_default();
    let now = Instant::now();
    if bucket
        .window_start
        .is_none_or(|ws| now.duration_since(ws) >= Duration::from_secs(60))
    {
        bucket.window_start = Some(now);
        bucket.failures = 0;
    }
    bucket.failures += 1;
    // Evict expired buckets periodically to prevent unbounded memory growth.
    if buckets.len() > 1000 {
        buckets.retain(|_, b| {
            b.window_start
                .is_some_and(|ws| now.duration_since(ws) < Duration::from_secs(300))
        });
    }
}

// ── Request context ───────────────────────────────────────────────────────────

tokio::task_local! {
    /// Correlation id for the request currently being served on this task.
    ///
    /// A task-local rather than an `Extension`: [`err_json`] is a free function
    /// called from every handler and from helpers several frames deep
    /// (`forbidden`, `guard_manage_user`), none of which can reach an extractor.
    /// Scoping the id to the request future gives all of them the same answer
    /// without threading a parameter through forty call sites.
    static REQUEST_ID: String;
}

/// The current request's id, or `None` outside a request (unit tests, the
/// desktop app calling a handler directly).
fn current_request_id() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// Middleware: assigns a request id, opens a span, echoes the id back.
///
/// The id is honoured from the caller when it supplies `X-Request-Id` — a
/// caller correlating across several services has already made one up, and
/// overwriting it destroys the only link between the two logs. It is truncated
/// and filtered rather than trusted verbatim: this value is echoed into a
/// response header and a log line, and neither is a place to put 4 KB of
/// attacker-chosen bytes.
async fn request_context(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let inbound = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(64)
                .collect::<String>()
        })
        .filter(|v| !v.is_empty());

    let id = inbound.unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let span = tracing::info_span!("request", %method, path = %path, request_id = %id);
    let started = Instant::now();

    let mut resp = REQUEST_ID
        .scope(id.clone(), async move {
            tracing::Instrument::instrument(next.run(req), span).await
        })
        .await;

    let status = resp.status().as_u16();
    let elapsed_ms = started.elapsed().as_millis();
    // One line per request, at a level that matches what happened: a 500 is not
    // something an operator should have to raise the log level to see, and a
    // 200 is not something they should have to filter out.
    if resp.status().is_server_error() {
        tracing::error!(request_id = %id, %method, path = %path, status, elapsed_ms, "request failed");
    } else if resp.status().is_client_error() {
        tracing::warn!(request_id = %id, %method, path = %path, status, elapsed_ms, "request rejected");
    } else {
        tracing::debug!(request_id = %id, %method, path = %path, status, elapsed_ms, "request served");
    }

    if let Ok(v) = axum::http::HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

// ── TLS certificate helpers ───────────────────────────────────────────────────

/// SHA-256 hex fingerprint of the first certificate DER found in a PEM file.
///
/// Parsing is delegated to `rustls-pemfile` — a hand-rolled decoder previously
/// used here silently mapped invalid base64 characters to zero, so a corrupt
/// cert produced a plausible-looking but wrong fingerprint that clients would
/// then pin to.
fn fingerprint_of_cert_pem(path: &std::path::Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let file = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
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
fn generate_self_signed_cert(
    data_dir: &std::path::Path,
) -> Result<(PathBuf, PathBuf, String), String> {
    use rcgen::{CertificateParams, KeyPair, SanType};
    use sha2::{Digest, Sha256};

    let cert_path = data_dir.join("server.crt");
    let key_path = data_dir.join("server.key");

    let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params =
        CertificateParams::new(vec!["localhost".to_string()]).map_err(|e| e.to_string())?;
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    params.not_after = time::OffsetDateTime::now_utc()
        .checked_add(time::Duration::days(365 * 3))
        .ok_or("date overflow")?;

    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    std::fs::write(&cert_path, cert.pem()).map_err(|e| format!("write cert: {e}"))?;
    std::fs::write(&key_path, key_pair.serialize_pem()).map_err(|e| format!("write key: {e}"))?;

    let fingerprint = hex::encode(Sha256::digest(cert.der()));
    Ok((cert_path, key_path, fingerprint))
}

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    rate_limiter: Arc<Mutex<HashMap<String, RateBucket>>>,
    db_path: PathBuf,
    salt_path: PathBuf,
    /// SHA-256 hex fingerprint of the TLS certificate (None when running plain HTTP).
    cert_fingerprint: Option<String>,
    /// Idle lifetime of a session. Every authenticated request resets the clock.
    session_ttl: Duration,
    /// Hard ceiling on a session's total life, measured from when it was minted
    /// and never extended. Without it the rolling `session_ttl` bounds only
    /// *abandoned* sessions — a token being actively used refreshes itself.
    session_max_lifetime: Duration,
    /// True when embedded in the desktop app serving an already-open vault.
    ///
    /// Refuses `POST /api/unlock` so the master password never travels over the
    /// network, and lets the host pre-seed the owner session from the key it
    /// already holds.
    lan_mode: bool,
    /// Instant of the last request from a non-owner session, for idle shutdown.
    last_peer_activity: Arc<Mutex<Instant>>,
    /// When this state was constructed — reported by `/api/health` as uptime.
    started_at: Instant,
}

/// "Never expires", as a duration rather than a special case at every
/// comparison site. A decade outlives any process that could hold the session.
const NEVER: Duration = Duration::from_secs(86_400 * 365 * 10);

impl AppState {
    /// Builds server state. `session_ttl_mins == 0` disables idle expiry;
    /// `session_max_hours == 0` disables the absolute ceiling.
    pub fn new(
        db_path: PathBuf,
        salt_path: PathBuf,
        cert_fingerprint: Option<String>,
        session_ttl_mins: u64,
        session_max_hours: u64,
        lan_mode: bool,
    ) -> Self {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            db_path,
            salt_path,
            cert_fingerprint,
            // "Never" is represented as a decade rather than special-casing every
            // comparison site.
            session_ttl: if session_ttl_mins == 0 {
                NEVER
            } else {
                Duration::from_secs(session_ttl_mins * 60)
            },
            session_max_lifetime: if session_max_hours == 0 {
                NEVER
            } else {
                Duration::from_secs(session_max_hours * 3600)
            },
            lan_mode,
            last_peer_activity: Arc::new(Mutex::new(Instant::now())),
            started_at: Instant::now(),
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
        self.sessions.lock().unwrap().insert(
            token.clone(),
            Session {
                vault_key: key,
                user_id: owner_id,
                is_owner: true,
                // The host holds this for as long as it serves; peers have their own
                // expiring sessions. This token is never handed out over the
                // network, so the ceiling that bounds a leaked bearer token has
                // nothing to bound here.
                expires_at: Instant::now() + NEVER,
                hard_expires_at: Instant::now() + NEVER,
            },
        );
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
        Instant::now()
            .duration_since(*self.last_peer_activity.lock().unwrap())
            .as_secs()
    }
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct UnlockRequest {
    password: String,
}

#[derive(Serialize, ToSchema)]
struct UnlockResponse {
    token: String,
}

#[derive(Serialize, ToSchema)]
struct StatusResponse {
    unlocked: bool,
    vault_exists: bool,
    /// SHA-256 hex fingerprint of the server TLS certificate, or null when running plain HTTP.
    cert_fingerprint: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize, ToSchema)]
struct AuthRequest {
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    /// Second-factor code. Required only when the user has a confirmed factor
    /// **and** authenticated by password — never for token auth, which is what
    /// CI uses and which has no human present to read a phone.
    totp: Option<String>,
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: Option<String>,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    description: Option<String>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct RenameUserRequest {
    username: String,
}

#[derive(Deserialize)]
struct SetPasswordRequest {
    password: Option<String>,
}

#[derive(Deserialize)]
struct AssignClassRequest {
    class_id: Option<String>,
}

#[derive(Deserialize)]
struct ClassRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    cap_manage_users: bool,
    #[serde(default)]
    cap_manage_classes: bool,
    #[serde(default)]
    cap_delete_projects: bool,
}

#[derive(Deserialize)]
struct ExpiringQuery {
    #[serde(default = "default_days")]
    days: u32,
}
fn default_days() -> u32 {
    30
}

#[derive(Serialize, ToSchema)]
struct HealthResponse {
    /// `"ok"` or `"degraded"`. Anything but `"ok"` is also a 503.
    status: &'static str,
    version: &'static str,
    /// Whether an owner session currently holds the vault key.
    unlocked: bool,
    /// Whether the database file is present. False is not a fault — a server
    /// that has never been unlocked has no file yet.
    vault_exists: bool,
    /// Seconds since this process began serving.
    uptime_secs: u64,
    /// Present only when `status` is not `"ok"`; says what failed, without
    /// naming a path or anything about the vault's contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct StatsResponse {
    secrets_stored: usize,
    users_total: usize,
    users_connected: usize,
    vault_unlocked: bool,
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

fn extract_session(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(String, Session), (StatusCode, Json<serde_json::Value>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err_json(StatusCode::UNAUTHORIZED, "Missing Bearer token"))?;

    let mut sessions = live_sessions(state);
    // Slide the idle deadline forward: activity keeps a session alive, idleness
    // kills it. The slide is clamped to `hard_expires_at`, which never moves —
    // otherwise a token that is being used (by its owner or by whoever stole it)
    // renews itself indefinitely and `session_ttl` bounds nothing that matters.
    let session = sessions.get_mut(token).map(|s| {
        s.expires_at = (Instant::now() + state.session_ttl).min(s.hard_expires_at);
        s.clone()
    });
    drop(sessions);

    let Some(s) = session else {
        return Err(err_json(
            StatusCode::UNAUTHORIZED,
            "Invalid or expired token",
        ));
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
    if session.is_owner {
        Ok(())
    } else {
        Err(err_json(StatusCode::FORBIDDEN, "Owner access required"))
    }
}

/// Authority of the acting session: `(tier, cap_manage_users, cap_manage_classes, cap_delete_projects)`.
/// Owner is tier 3 with all capabilities; sub-users derive tier from their class.
/// See `vault_core::authority_tier` for the Discord-style hierarchy.
fn actor_authority(conn: &vault_core::SqlConnection, session: &Session) -> (i32, bool, bool, bool) {
    if session.is_owner {
        return (3, true, true, true);
    }
    let (mu, mc, dp) =
        vault_core::get_user_capabilities(conn, &session.user_id).unwrap_or((false, false, false));
    (vault_core::authority_tier(false, mu, mc), mu, mc, dp)
}

fn forbidden(msg: &str) -> axum::response::Response {
    err_json(StatusCode::FORBIDDEN, msg).into_response()
}

/// Tier required to mint/grant a class with the given capabilities. A grantor must
/// outrank the grant: only an owner (tier 3) may confer `cap_manage_classes` or
/// `cap_delete_projects`; `cap_manage_users` (tier 2 grant) needs at least an admin.
/// Prevents privilege escalation — you can never create a peer or superior role.
fn min_tier_to_grant(
    cap_manage_users: bool,
    cap_manage_classes: bool,
    cap_delete_projects: bool,
) -> i32 {
    if cap_manage_classes || cap_delete_projects {
        3
    } else if cap_manage_users {
        2
    } else {
        1
    }
}

/// Authority tier implied by a class's stored capabilities (0 if class is unknown).
fn class_authority_tier(conn: &vault_core::SqlConnection, class_id: &str) -> i32 {
    vault_core::class_authority_tier(conn, class_id).unwrap_or(0)
}

/// Guard for acting on another user: actor needs manage-users capability and must
/// strictly outrank the target (owner outranks everyone).
fn guard_manage_user(
    conn: &vault_core::SqlConnection,
    session: &Session,
    target: &str,
) -> Result<(), axum::response::Response> {
    let (tier, mu, _, _) = actor_authority(conn, session);
    if !(session.is_owner || mu) {
        return Err(forbidden("Requires the manage-users capability"));
    }
    let target_tier = vault_core::user_authority_tier(conn, target).unwrap_or(0);
    if tier <= target_tier {
        return Err(forbidden(
            "Cannot act on a user of equal or higher authority",
        ));
    }
    Ok(())
}

/// Error envelope. Every failure the server emits goes through here, so every
/// failure carries the same `request_id` the response header does.
///
/// The id is what makes a user's "it returned 403" reportable: it appears in
/// the response, in the log line for that request, and in nothing else. Without
/// it the only way to find the matching log entry on a busy server is a
/// timestamp and a guess.
fn err_json(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    match current_request_id() {
        Some(id) => (
            status,
            Json(serde_json::json!({ "error": msg, "request_id": id })),
        ),
        None => (status, Json(serde_json::json!({ "error": msg }))),
    }
}

/// As [`err_json`], plus a `Retry-After` header.
///
/// Split out rather than folded into `err_json` because `Retry-After` is
/// meaningful on exactly one status here (429) and a header that appears on
/// unrelated errors trains clients to ignore it.
fn err_json_retry(
    status: StatusCode,
    msg: &str,
    retry_after_secs: u64,
) -> axum::response::Response {
    let mut resp = err_json(status, msg).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("retry-after", v);
    }
    resp
}

fn owner_vault_key(state: &AppState) -> Option<VaultKey> {
    live_sessions(state)
        .values()
        .find(|s| s.is_owner)
        .map(|s| s.vault_key)
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
        )
        .into_response();
    }

    // Rate-limit by socket address — not by X-Forwarded-For (spoofable).
    let ip = addr.ip().to_string();
    if let Some(retry) = rate_retry_after(&mut state.rate_limiter.lock().unwrap(), &ip) {
        tracing::warn!(retry_after_secs = retry, "rate limited");
        return err_json_retry(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Too many failed attempts — try again in {retry}s"),
            retry,
        );
    }

    let salt = match read_or_create_salt(&state.salt_path) {
        Ok(s) => s,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let key = match derive_key(&req.password, &salt) {
        Ok(k) => k,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let conn = match open_db(&state.db_path, &key) {
        Ok(conn) => {
            let _ = init_schema(&conn);
            conn
        }
        Err(_) => {
            record_auth_failure(&mut state.rate_limiter.lock().unwrap(), &ip);
            return err_json(StatusCode::UNAUTHORIZED, "Wrong master password").into_response();
        }
    };
    // Integrity check on unlock (item 5)
    match verify_vault_integrity(&conn) {
        Ok(false) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Vault integrity check failed — data may be tampered",
            )
            .into_response()
        }
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        Ok(true) => {}
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
    live_sessions(&state).insert(
        token.clone(),
        Session {
            vault_key: key,
            user_id: owner_id,
            is_owner: true,
            expires_at: Instant::now() + state.session_ttl,
            hard_expires_at: Instant::now() + state.session_max_lifetime,
        },
    );
    (StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response()
}

/// Idempotently seed the default `admin` user (class: Admin) and log the outcome.
/// Credential source: `ENVV_ADMIN_PASSWORD` if set, else a random one printed once.
fn seed_default_admin_logged(conn: &vault_core::SqlConnection) {
    let env_pw = std::env::var("ENVV_ADMIN_PASSWORD").ok();
    match vault_core::seed_default_admin(conn, env_pw.as_deref()) {
        Ok(vault_core::AdminSeed::Exists) => {}
        Ok(vault_core::AdminSeed::Created {
            generated_password: Some(pw),
        }) => {
            eprintln!("\n════════════ Default admin created ════════════");
            eprintln!("  username: admin");
            eprintln!("  password: {pw}");
            eprintln!("  class:    Admin (manage users/classes below you)");
            eprintln!("  Set ENVV_ADMIN_PASSWORD to choose this yourself.");
            eprintln!("═══════════════════════════════════════════════\n");
        }
        Ok(vault_core::AdminSeed::Created {
            generated_password: None,
        }) => {
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
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
    else {
        return StatusCode::NO_CONTENT;
    };

    let mut sessions = live_sessions(&state);
    let is_owner = sessions.get(&token).map(|s| s.is_owner).unwrap_or(false);

    if is_owner {
        for (_, mut s) in sessions.drain() {
            s.vault_key.zeroize();
        }
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
        unlocked: live_sessions(&state).values().any(|s| s.is_owner),
        vault_exists: state.db_path.exists(),
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
    if let Some(retry) = rate_retry_after(&mut state.rate_limiter.lock().unwrap(), &ip) {
        tracing::warn!(retry_after_secs = retry, "rate limited");
        return err_json_retry(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Too many failed attempts — try again in {retry}s"),
            retry,
        );
    }

    let key = match owner_vault_key(&state) {
        Some(k) => k,
        None => {
            return err_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "Vault not unlocked by owner",
            )
            .into_response()
        }
    };
    let conn = match open_db(&state.db_path, &key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };

    // Which credential was used decides whether a second factor applies at all.
    let (user_opt, via_password) = match (&req.username, &req.password, &req.token) {
        (Some(u), Some(p), _) => (vault_core::verify_user_password(&conn, u, p), true),
        (_, _, Some(t)) => (vault_core::verify_user_token(&conn, t), false),
        _ => {
            return err_json(
                StatusCode::BAD_REQUEST,
                "Provide username+password or token",
            )
            .into_response()
        }
    };

    match user_opt {
        Ok(Some(user)) => {
            // TOTP gates the password path only. Demanding it on token auth
            // breaks every CI integration, and that exact regression is already
            // in this project's bug history from Phase 5.1.
            if via_password {
                match vault_core::users::totp_required(&conn, &user.id) {
                    Ok(true) => {
                        let Some(code) = req.totp.as_deref() else {
                            // Not a failure to throttle: the password was
                            // correct, and the client simply has to ask the user
                            // for the second half. A distinguishable code is what
                            // lets the CLI prompt instead of guessing.
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(serde_json::json!({
                                    "error": "Second factor required",
                                    "totp_required": true,
                                })),
                            )
                                .into_response();
                        };
                        match vault_core::users::verify_user_totp(&conn, &user.id, code) {
                            Ok(true) => {}
                            Ok(false) => {
                                record_auth_failure(&mut state.rate_limiter.lock().unwrap(), &ip);
                                return err_json(StatusCode::UNAUTHORIZED, "Invalid credentials")
                                    .into_response();
                            }
                            Err(e) => {
                                return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e)
                                    .into_response()
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(e) => {
                        return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response()
                    }
                }
            }

            let session_token = uuid::Uuid::new_v4().to_string();
            live_sessions(&state).insert(
                session_token.clone(),
                Session {
                    vault_key: key,
                    user_id: user.id,
                    is_owner: false,
                    expires_at: Instant::now() + state.session_ttl,
                    hard_expires_at: Instant::now() + state.session_max_lifetime,
                },
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({ "token": session_token })),
            )
                .into_response()
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
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let vault = match load_vault(&conn) {
        Ok(Some(d)) => d,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };

    // Version token (ETag) is the full-vault hash so a later PUT can detect drift.
    // The ETag must be the *same* value save_vault compares against, so read the
    // stored data_hash rather than re-hashing the parsed JSON. Re-serialising a
    // Value happens to reproduce the stored bytes today, but relying on that
    // would make every If-Match request 409 the moment it stopped being true.
    let ver = vault_core::vault_version(&conn)
        .ok()
        .flatten()
        .unwrap_or_default();
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
        Ok(read) => (
            [(axum::http::header::ETAG, ver)],
            Json(filter_vault_for_user(vault, read.as_ref())),
        )
            .into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

/// Query for [`get_entries`].
#[derive(serde::Deserialize)]
struct EntryQuery {
    /// Project id or name.
    project: Option<String>,
    /// Entry provider name. Exact match.
    provider: Option<String>,
    /// Category name.
    category: Option<String>,
    /// Environment (`production`, `staging`, …).
    env: Option<String>,
    /// Comma-separated provider names, for reading several at once.
    providers: Option<String>,
}

/// Selective read: the entries matching a filter, rather than the whole vault.
///
/// `GET /api/vault` returns everything, which is fine for a personal vault and
/// increasingly silly for a large one — a scoped sub-user currently downloads a
/// filtered copy of the *entire* vault to read one value.
///
/// Two properties this must keep, both easy to lose:
///
/// * **Permissions are applied before the filter, never after.** Filtering first
///   and checking later would let a caller learn that an entry exists by the
///   shape of the response. `filter_vault_for_user` runs on the whole vault
///   exactly as it does for `GET /api/vault`, and the query narrows what is
///   already visible.
/// * **A filter matching nothing returns an empty list, not 404.** "No entries
///   in project X" and "no such project" must look identical from outside, or
///   the endpoint becomes an enumeration oracle for project names.
async fn get_entries(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(q): Query<EntryQuery>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let vault = match load_vault(&conn) {
        Ok(Some(d)) => d,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };

    // Same visibility rules as the whole-vault read, applied first.
    let visible = if session.is_owner {
        vault
    } else {
        match effective_permission_expr(&conn, &session.user_id, "read") {
            Ok(read) => filter_vault_for_user(vault, read.as_ref()),
            Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        }
    };

    // Resolve a project name to its id so callers can use either.
    let project_ids: Option<Vec<String>> = q.project.as_ref().map(|want| {
        visible
            .get("projects")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|p| {
                        p.get("id").and_then(|v| v.as_str()) == Some(want.as_str())
                            || p.get("name").and_then(|v| v.as_str()) == Some(want.as_str())
                    })
                    .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    });

    let wanted_providers: Option<Vec<String>> = q.providers.as_ref().map(|list| {
        list.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    });

    let entries = filter_entries(
        &visible,
        &q,
        project_ids.as_deref(),
        wanted_providers.as_deref(),
    );

    Json(serde_json::json!({
        "count": entries.len(),
        "entries": entries,
    }))
    .into_response()
}

/// The query filter, split out of the handler so it can be tested without a
/// running server, a database, or a session.
///
/// Takes the **already permission-filtered** vault. Passing the raw vault here
/// would make every test pass while the endpoint leaked, so the parameter is
/// named for what it must be.
fn filter_entries(
    visible: &serde_json::Value,
    q: &EntryQuery,
    project_ids: Option<&[String]>,
    wanted_providers: Option<&[String]>,
) -> Vec<serde_json::Value> {
    let empty = vec![];
    visible
        .get("api_keys")
        .and_then(|k| k.as_array())
        .unwrap_or(&empty)
        .iter()
        .filter(|e| {
            let field = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("");
            if let Some(p) = &q.provider {
                if field("provider") != p {
                    return false;
                }
            }
            if let Some(list) = wanted_providers {
                if !list.iter().any(|p| p == field("provider")) {
                    return false;
                }
            }
            if let Some(env) = &q.env {
                if field("environment") != env {
                    return false;
                }
            }
            if let Some(cat) = &q.category {
                let has = e
                    .get("categories")
                    .and_then(|c| c.as_array())
                    .map(|a| a.iter().any(|c| c.as_str() == Some(cat.as_str())))
                    .unwrap_or(false);
                if !has {
                    return false;
                }
            }
            if let Some(ids) = project_ids {
                let in_project = e
                    .get("projectIds")
                    .and_then(|p| p.as_array())
                    .map(|a| {
                        a.iter()
                            .any(|p| p.as_str().is_some_and(|s| ids.iter().any(|w| w == s)))
                    })
                    .unwrap_or(false);
                if !in_project {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect()
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
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    // Guard: api_keys must be an array. Reject malformed/empty payloads that would wipe the vault.
    if data.get("api_keys").and_then(|v| v.as_array()).is_none() {
        return err_json(
            StatusCode::BAD_REQUEST,
            "Invalid vault data: api_keys array required",
        )
        .into_response();
    }
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };

    // Optimistic concurrency. The comparison happens inside save_vault's write
    // transaction rather than here: checking first and writing afterwards leaves
    // a window in which another writer can land between the two, which is
    // exactly the race this is supposed to prevent.
    let expect = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_matches('"').to_string());

    let ctx = vault_core::SaveCtx {
        actor: Some(&session.user_id),
        expect_version: expect.as_deref(),
    };

    if session.is_owner {
        return match save_vault(&conn, data, ctx) {
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(e) if e.starts_with(vault_core::CONFLICT_ERR) => err_json(
                StatusCode::CONFLICT,
                "Vault changed since last read — reload and retry",
            )
            .into_response(),
            Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        };
    }

    // Non-owner: merge, honouring their effective write expression.
    let write = match effective_permission_expr(&conn, &session.user_id, "write") {
        Ok(p) => p,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
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
        Ok(None) => serde_json::json!({ "api_keys": [], "user_categories": [], "projects": [] }),
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    // The merge needs the read expression too: the submission is the *filtered*
    // document this user was served, so an absent project or category means
    // "deleted" only if they could see it in the first place.
    let read = match effective_permission_expr(&conn, &session.user_id, "read") {
        Ok(p) => p,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let merged = match merge_user_vault_write(full_vault, data, read.as_ref(), write.as_ref()) {
        Ok(v) => v,
        Err(e) => return err_json(StatusCode::FORBIDDEN, &e).into_response(),
    };
    let ctx = vault_core::SaveCtx {
        actor: Some(&session.user_id),
        expect_version: expect.as_deref().or(merge_base.as_deref()),
    };
    match save_vault(&conn, merged, ctx) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) if e.starts_with(vault_core::CONFLICT_ERR) => err_json(
            StatusCode::CONFLICT,
            "Vault changed since last read — reload and retry",
        )
        .into_response(),
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
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    // Owner sees everything; a non-owner only sees expiring entries within their RBAC scope.
    let result = if session.is_owner {
        get_expiring_entries(&conn, q.days)
    } else {
        match effective_permission_expr(&conn, &session.user_id, "read") {
            Ok(read) => get_expiring_entries_for_user(&conn, q.days, read.as_ref()),
            Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        }
    };
    match result {
        Ok(entries) => Json(entries).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
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
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    match require_owner(&session) {
        Ok(()) => {}
        Err(e) => return e.into_response(),
    }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match load_audit(&conn) {
            Ok(rows) => Json(rows).into_response(),
            Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

// ── User management (capability-gated, Discord-style hierarchy) ───────────────

async fn list_users_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (_, mu, _, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mu) {
        return forbidden("Requires the manage-users capability");
    }
    match vault_core::list_users(&conn) {
        Ok(users) => Json(users).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn create_user_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (_, mu, _, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mu) {
        return forbidden("Requires the manage-users capability");
    }
    // New user starts with no class (tier 0) — strictly below any creator. Safe.
    match vault_core::create_user(&conn, &req.username, req.password.as_deref(), false) {
        Ok(user) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(user).unwrap()),
        )
            .into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn delete_user_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match vault_core::delete_user(&conn, &user_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn list_tokens_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match vault_core::list_user_tokens(&conn, &user_id) {
        Ok(tokens) => Json(tokens).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn create_token_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match vault_core::create_user_token(
        &conn,
        &user_id,
        req.description.as_deref(),
        req.expires_at.as_deref(),
    ) {
        Ok((token_id, plaintext)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "token_id": token_id,
                "token": plaintext,
                "note": "Store this token now — it will not be shown again."
            })),
        )
            .into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn revoke_token_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((_user_id, token_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    // Authorize against the token's actual owner (the path user_id is not trusted —
    // delete is keyed on token_id alone, so a forged low-rank path could otherwise
    // revoke a higher-ranked user's token).
    let owner = vault_core::token_user_id(&conn, &token_id).ok().flatten();
    let Some(owner_id) = owner else {
        return StatusCode::NO_CONTENT.into_response();
    };
    if let Err(e) = guard_manage_user(&conn, &session, &owner_id) {
        return e;
    }
    match vault_core::revoke_user_token(&conn, &token_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

/// Read/write permission expressions for a subject.
#[derive(Serialize, Deserialize, Default)]
struct PermissionExprs {
    #[serde(default)]
    read: String,
    #[serde(default)]
    write: String,
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

async fn get_permissions_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match load_exprs(&conn, "user", &user_id) {
        Ok(e) => Json(e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn set_permissions_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(exprs): Json<PermissionExprs>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    // set_permission_expr parses before storing, so a malformed rule is a 400
    // rather than a silently-denies-everything grant.
    match store_exprs(&conn, "user", &user_id, &exprs) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn rename_user_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<RenameUserRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match vault_core::rename_user(&conn, &user_id, &req.username) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn set_password_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<SetPasswordRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match vault_core::set_user_password(&conn, &user_id, req.password.as_deref()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn assign_class_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<AssignClassRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    // Can't promote a user into a class at or above your own authority.
    if let Some(cid) = req.class_id.as_deref() {
        let (actor_tier, ..) = actor_authority(&conn, &session);
        if !session.is_owner && actor_tier <= class_authority_tier(&conn, cid) {
            return forbidden("Cannot assign a class of equal or higher authority");
        }
    }
    match vault_core::assign_user_class(&conn, &user_id, req.class_id.as_deref()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

// ── TOTP (sub-user second factor) ─────────────────────────────────────────────
//
// Gated by `guard_manage_user`, the same tier check that governs setting a
// password: managing someone's second factor is exactly as strong as being able
// to reset their credentials, so it must not be a weaker door to the same room.
// A user reaches their *own* factor because `guard_manage_user` already permits
// acting on oneself.

#[derive(Deserialize)]
struct TotpCodeRequest {
    code: String,
}

async fn totp_status_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match vault_core::users::totp_status(&conn, &user_id) {
        Ok(st) => (StatusCode::OK, Json(st)).into_response(),
        Err(e) => err_json(StatusCode::NOT_FOUND, &e).into_response(),
    }
}

/// Phase one of enrollment. Returns the secret **once**; nothing else ever does.
async fn totp_enroll_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match vault_core::users::totp_enroll(&conn, &user_id, "EnvVault") {
        Ok(st) => (StatusCode::OK, Json(st)).into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

/// Phase two: a correct code is what enables the factor.
async fn totp_confirm_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<TotpCodeRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match vault_core::users::totp_confirm(&conn, &user_id, &req.code) {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "enabled": true }))).into_response(),
        Ok(false) => err_json(StatusCode::UNAUTHORIZED, "Incorrect code").into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn totp_disable_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if let Err(e) = guard_manage_user(&conn, &session, &user_id) {
        return e;
    }
    match vault_core::users::totp_disable(&conn, &user_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

// ── Class management (capability-gated) ───────────────────────────────────────

async fn list_classes_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (_, mu, mc, _) = actor_authority(&conn, &session);
    // Managers (users or classes) may read the class list to assign roles.
    if !(session.is_owner || mu || mc) {
        return forbidden("Requires a management capability");
    }
    match vault_core::list_user_classes(&conn) {
        Ok(classes) => Json(classes).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn create_class_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ClassRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (actor_tier, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) {
        return forbidden("Requires the manage-classes capability");
    }
    // No minting a class you couldn't be: the grant must require strictly less authority than you hold.
    if !session.is_owner
        && actor_tier
            < min_tier_to_grant(
                req.cap_manage_users,
                req.cap_manage_classes,
                req.cap_delete_projects,
            )
    {
        return forbidden("Cannot create a class with capabilities at or above your own authority");
    }
    match vault_core::create_user_class(
        &conn,
        &req.name,
        &req.description,
        req.cap_manage_users,
        req.cap_manage_classes,
        req.cap_delete_projects,
    ) {
        Ok(cls) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(cls).unwrap()),
        )
            .into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn update_class_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(class_id): Path<String>,
    Json(req): Json<ClassRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (actor_tier, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) {
        return forbidden("Requires the manage-classes capability");
    }
    if !session.is_owner {
        // Must outrank both the class as it is now and the capabilities being requested.
        if actor_tier <= class_authority_tier(&conn, &class_id) {
            return forbidden("Cannot modify a class of equal or higher authority");
        }
        if actor_tier
            < min_tier_to_grant(
                req.cap_manage_users,
                req.cap_manage_classes,
                req.cap_delete_projects,
            )
        {
            return forbidden("Cannot grant capabilities at or above your own authority");
        }
    }
    match vault_core::update_user_class(
        &conn,
        &class_id,
        &req.name,
        &req.description,
        req.cap_manage_users,
        req.cap_manage_classes,
        req.cap_delete_projects,
    ) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn delete_class_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(class_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (actor_tier, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) {
        return forbidden("Requires the manage-classes capability");
    }
    // Built-in classes (cls-*) are part of the hierarchy itself — owner-only.
    if !session.is_owner {
        if class_id.starts_with("cls-") {
            return forbidden("Built-in classes can only be deleted by the owner");
        }
        if actor_tier <= class_authority_tier(&conn, &class_id) {
            return forbidden("Cannot delete a class of equal or higher authority");
        }
    }
    match vault_core::delete_user_class(&conn, &class_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

async fn get_class_perms_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(class_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (_, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) {
        return forbidden("Requires the manage-classes capability");
    }
    match load_exprs(&conn, "class", &class_id) {
        Ok(e) => Json(e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn set_class_perms_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(class_id): Path<String>,
    Json(exprs): Json<PermissionExprs>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let (actor_tier, _, mc, _) = actor_authority(&conn, &session);
    if !(session.is_owner || mc) {
        return forbidden("Requires the manage-classes capability");
    }
    if !session.is_owner && actor_tier <= class_authority_tier(&conn, &class_id) {
        return forbidden("Cannot modify a class of equal or higher authority");
    }
    match store_exprs(&conn, "class", &class_id, &exprs) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
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

// ── Health and public stats ───────────────────────────────────────────────────

/// Liveness and lock state, deliberately without any counts.
///
/// Distinct from `/api/stats` on purpose, and the distinction is a security
/// one: usage data about a secrets manager is itself sensitive, so the
/// unauthenticated endpoint a monitor polls every few seconds must never grow a
/// field that answers "how much is in there".
///
/// It also has to fail when the process is *wedged* rather than merely bound.
/// The old Docker healthcheck opened the TCP port, which a hung process answers
/// perfectly well; supervised restart is worthless on top of a check that
/// cannot go red. So when an owner session claims the vault is unlocked, this
/// actually opens the database and runs a query. If that cannot be done, the
/// answer is 503 — which is the signal `restart: unless-stopped` needs.
#[utoipa::path(
    get, path = "/api/health",
    responses(
        (status = 200, description = "Serving normally", body = HealthResponse),
        (status = 503, description = "Wedged — bound but not functional", body = HealthResponse),
    ),
    tag = "ops"
)]
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let unlocked = live_sessions(&state).values().any(|s| s.is_owner);
    let vault_exists = state.db_path.exists();
    let uptime_secs = state.started_at.elapsed().as_secs();

    // Only probe when there is something to probe. A locked server holds no key,
    // so "cannot open the database" is its normal state and not a fault.
    let detail = if unlocked {
        match owner_vault_key(&state) {
            Some(key) => match open_db(&state.db_path, &key) {
                Ok(conn) => match conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)) {
                    Ok(_) => None,
                    Err(_) => Some("vault is open but not answering queries".into()),
                },
                // Deliberately not the underlying error. SQLCipher reports a
                // corrupt database as "wrong master password", because it cannot
                // tell the two apart — the header simply fails to decrypt. Passing
                // that through unedited sends an operator hunting for a password
                // problem when the file underneath the running server was replaced
                // or truncated.
                Err(_) => Some(
                    "vault unreadable with this session's key — the database file may have been replaced or truncated"
                        .into(),
                ),
            },
            // Raced with a lock between the two reads. Not a fault.
            None => None,
        }
    } else {
        None
    };

    let degraded = detail.is_some();
    if let Some(d) = &detail {
        tracing::error!(detail = %d, "health check degraded");
    }

    let body = Json(HealthResponse {
        status: if degraded { "degraded" } else { "ok" },
        version: env!("CARGO_PKG_VERSION"),
        unlocked,
        vault_exists,
        uptime_secs,
        detail,
    });

    if degraded {
        (StatusCode::SERVICE_UNAVAILABLE, body).into_response()
    } else {
        (StatusCode::OK, body).into_response()
    }
}

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
        let unlocked = sessions.values().any(|s| s.is_owner);
        let connected = sessions.values().filter(|s| !s.is_owner).count();
        let key = sessions.values().find(|s| s.is_owner).map(|s| s.vault_key);
        (unlocked, connected, key)
    };

    let (secrets_stored, users_total) =
        match owner_key.and_then(|k| open_db(&state.db_path, &k).ok()) {
            Some(conn) => {
                let secrets = load_vault(&conn)
                    .ok()
                    .flatten()
                    .and_then(|v| v["api_keys"].as_array().map(|a| a.len()))
                    .unwrap_or(0);
                let users = vault_core::list_users(&conn).map(|u| u.len()).unwrap_or(0);
                (secrets, users)
            }
            None => (0, 0),
        };

    Json(StatsResponse {
        secrets_stored,
        users_total,
        users_connected,
        vault_unlocked,
    })
}

// ── OpenAPI spec ──────────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    paths(unlock, lock, status, auth_user, get_vault, put_vault, expiring, audit, stats, health),
    components(schemas(UnlockRequest, UnlockResponse, StatusResponse, ErrorResponse, AuthRequest, StatsResponse, HealthResponse)),
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
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("UUID")
                        .build(),
                ),
            );
        }
    }
}

/// Unlock the vault from a password string (used by ENVV_PASSWORD env var on startup).
pub fn auto_unlock(state: &AppState, password: &str) -> Result<(), String> {
    let salt = read_or_create_salt(&state.salt_path)?;
    let key = derive_key(password, &salt)?;
    let conn = open_db(&state.db_path, &key)
        .map_err(|_| "Wrong master password — check ENVV_PASSWORD".to_string())?;
    let _ = init_schema(&conn);
    match verify_vault_integrity(&conn) {
        Ok(false) => return Err("Vault integrity check failed — possible tampering".to_string()),
        Err(e) => return Err(e),
        Ok(true) => {}
    }
    seed_default_admin_logged(&conn);
    let owner_id = ensure_owner_user(&conn)?;
    state.sessions.lock().unwrap().insert(
        uuid::Uuid::new_v4().to_string(),
        Session {
            vault_key: key,
            user_id: owner_id,
            is_owner: true,
            // Auto-unlock is for unattended deployments (Docker + ENVV_PASSWORD).
            // Nothing ever pings this session, so it must not be allowed to lapse.
            // Its token is never returned to any caller — it exists so the key
            // stays reachable for `POST /api/auth` — so no ceiling applies.
            expires_at: Instant::now() + NEVER,
            hard_expires_at: Instant::now() + NEVER,
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
    let mut origins = vec!["tauri://localhost"
        .parse::<axum::http::HeaderValue>()
        .unwrap()];
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
        .route("/api/unlock", post(unlock).delete(lock))
        .route("/api/status", get(status))
        .route("/api/auth", post(auth_user))
        .route("/api/vault", get(get_vault).put(put_vault))
        .route("/api/vault/entries", get(get_entries))
        .route("/api/vault/expiring", get(expiring))
        .route("/api/audit", get(audit))
        .route(
            "/api/users",
            get(list_users_handler).post(create_user_handler),
        )
        .route("/api/users/{user_id}", delete(delete_user_handler))
        .route(
            "/api/users/{user_id}/tokens",
            get(list_tokens_handler).post(create_token_handler),
        )
        .route(
            "/api/users/{user_id}/tokens/{token_id}",
            delete(revoke_token_handler),
        )
        .route(
            "/api/users/{user_id}/permissions",
            get(get_permissions_handler).put(set_permissions_handler),
        )
        .route(
            "/api/users/{user_id}/rename",
            axum::routing::put(rename_user_handler),
        )
        .route(
            "/api/users/{user_id}/password",
            axum::routing::put(set_password_handler),
        )
        .route(
            "/api/users/{user_id}/class",
            axum::routing::put(assign_class_handler),
        )
        // One `.route()` per path, methods chained. Registering the same path
        // twice is a startup panic in axum 0.8, not a compile error — the same
        // class of failure as the `:param` syntax change.
        .route(
            "/api/users/{user_id}/totp",
            get(totp_status_handler).delete(totp_disable_handler),
        )
        .route(
            "/api/users/{user_id}/totp/enroll",
            axum::routing::post(totp_enroll_handler),
        )
        .route(
            "/api/users/{user_id}/totp/confirm",
            axum::routing::post(totp_confirm_handler),
        )
        .route(
            "/api/classes",
            get(list_classes_handler).post(create_class_handler),
        )
        .route(
            "/api/classes/{class_id}",
            axum::routing::put(update_class_handler).delete(delete_class_handler),
        )
        .route(
            "/api/classes/{class_id}/permissions",
            get(get_class_perms_handler).put(set_class_perms_handler),
        )
        .route("/api/ping", get(ping))
        .route("/api/stats", get(stats))
        .route("/api/health", get(health))
        .with_state(state);

    Router::new()
        .merge(vault_routes)
        .route(
            "/api/openapi.json",
            get(|| async { Json(ApiDoc::openapi()) }),
        )
        .layer(cors)
        // Outermost, so the id exists before any handler runs and the log line
        // covers the whole request including CORS rejections.
        .layer(axum::middleware::from_fn(request_context))
}

/// TLS material for [`serve`].
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Generates a self-signed certificate at `dir` if one is not already there.
///
/// Reuses an existing pair on purpose: regenerating per launch would change the
/// fingerprint every time and break every peer's pin.
pub fn ensure_self_signed_cert(dir: &std::path::Path) -> Result<(TlsFiles, String), String> {
    let cert = dir.join("server.crt");
    let key = dir.join("server.key");
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
                .await
                .map_err(|e| format!("TLS config error: {e}"))?;
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
                .await
                .map_err(|e| format!("server error: {e}"))
        }
        None => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| format!("bind {addr}: {e}"))?;
            axum::serve(listener, svc)
                .with_graceful_shutdown(async {
                    let _ = shutdown.await;
                })
                .await
                .map_err(|e| format!("server error: {e}"))
        }
    }
}

/// Binds the first free port at or after `start`, giving up after `tries`.
///
/// Lets "Open to LAN" coexist with a Docker `envv-server` already holding the
/// default port instead of just failing.
pub fn find_free_port(host: &str, start: u16, tries: u16) -> Option<u16> {
    (start..start.saturating_add(tries)).find(|p| std::net::TcpListener::bind((host, *p)).is_ok())
}

impl AppState {
    /// Drops every session, zeroizing each vault key.
    ///
    /// Used when the desktop stops serving: peers must not keep a usable key in
    /// server memory after the host closes the LAN, and the host's own adopted
    /// owner session must go with it.
    pub fn shutdown_all_sessions(&self) {
        let mut g = self.sessions.lock().unwrap();
        for (_, mut s) in g.drain() {
            s.vault_key.zeroize();
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("envv-server-test-{tag}-{nanos}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn state(lan: bool) -> AppState {
        let d = scratch("state");
        AppState::new(d.join("vault.db"), d.join("vault.salt"), None, 480, 24, lan)
    }

    #[test]
    fn the_router_builds_without_a_duplicate_path_panic() {
        // axum 0.8 panics at *startup*, not compile time, when two `.route()`
        // calls name the same path — the TOTP status and disable handlers were
        // written that way first. A compiling binary that cannot boot is the
        // worst shape this can take, so the router is constructed in a test.
        let _ = build_router(state(false), 8080);
    }

    #[test]
    fn rate_limit_reports_seconds_until_the_window_resets() {
        // Regression: the limiter used to answer only "no". A client that cannot
        // tell "slow down" from "denied" either gives up on a transient block or
        // retries into it forever, and the agent-driven CLI is the main caller.
        let mut buckets = HashMap::new();
        for _ in 0..10 {
            assert!(rate_retry_after(&mut buckets, "1.2.3.4").is_none());
            record_auth_failure(&mut buckets, "1.2.3.4");
        }
        let retry = rate_retry_after(&mut buckets, "1.2.3.4").expect("11th attempt is limited");
        assert!(
            (1..=60).contains(&retry),
            "Retry-After must be inside the window, got {retry}"
        );
    }

    #[test]
    fn rate_limit_never_tells_a_client_to_retry_in_zero_seconds() {
        // Retry-After: 0 means "immediately", which is refused again — the
        // server reads as broken rather than busy. The value is floored at 1.
        let mut buckets = HashMap::new();
        for _ in 0..10 {
            record_auth_failure(&mut buckets, "ip");
        }
        // Age the window to the very last moment before it resets.
        buckets.get_mut("ip").unwrap().window_start =
            Some(Instant::now() - RATE_WINDOW + Duration::from_millis(1));
        assert_eq!(rate_retry_after(&mut buckets, "ip"), Some(1));
    }

    #[test]
    fn a_separate_ip_is_not_caught_by_another_ip_s_window() {
        let mut buckets = HashMap::new();
        for _ in 0..10 {
            record_auth_failure(&mut buckets, "noisy");
        }
        assert!(rate_retry_after(&mut buckets, "noisy").is_some());
        assert!(rate_retry_after(&mut buckets, "quiet").is_none());
    }

    #[tokio::test]
    async fn error_envelopes_carry_the_request_id_inside_a_request() {
        // The id in the body is what makes a report actionable: it appears in
        // the response and in that request's log line, and nowhere else.
        let body = REQUEST_ID
            .scope("abc123".to_string(), async {
                let (_, Json(v)) = err_json(StatusCode::FORBIDDEN, "nope");
                v
            })
            .await;
        assert_eq!(body["request_id"], "abc123");
        assert_eq!(body["error"], "nope");
    }

    #[test]
    fn error_envelopes_omit_the_request_id_outside_a_request() {
        // The desktop app calls into these helpers directly. A null or empty id
        // would look like a correlation handle that leads nowhere.
        let (_, Json(v)) = err_json(StatusCode::NOT_FOUND, "gone");
        assert!(v.get("request_id").is_none());
    }

    #[tokio::test]
    async fn health_is_ok_and_reports_no_counts_when_locked() {
        // /api/stats may report counts; /api/health must not. It is polled by
        // unauthenticated monitors, and how much is in a vault is itself
        // sensitive.
        let s = state(false);
        let resp = health(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["unlocked"], false);
        for leaky in ["secrets_stored", "users_total", "users_connected"] {
            assert!(
                v.get(leaky).is_none(),
                "/api/health must not report {leaky}"
            );
        }
    }

    #[tokio::test]
    async fn health_is_degraded_when_unlocked_but_the_vault_cannot_be_read() {
        // The state the old TCP-port healthcheck could not see: bound, accepting
        // connections, and unable to reach its own database. Without this,
        // `restart: unless-stopped` sits on top of a check that never goes red.
        let s = state(false);
        std::fs::write(&s.db_path, b"not a database").unwrap();
        s.adopt_owner_key([9u8; 32], "owner".into());

        let resp = health(State(s)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "degraded");
        let detail = v["detail"].as_str().unwrap_or_default();
        assert!(
            !detail.to_lowercase().contains("password"),
            "SQLCipher calls a corrupt file a wrong password; passing that on \
             sends the operator after the wrong problem: {detail}"
        );
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
        assert!(
            s.sessions.lock().unwrap().is_empty(),
            "stopping the LAN server must not leave a usable key in memory"
        );
    }

    #[test]
    fn expired_sessions_are_purged_and_not_counted() {
        let s = state(false);
        s.sessions.lock().unwrap().insert(
            "dead".into(),
            Session {
                vault_key: [1u8; 32],
                user_id: "u".into(),
                is_owner: false,
                expires_at: Instant::now() - Duration::from_secs(1),
                hard_expires_at: Instant::now() + NEVER,
            },
        );
        assert_eq!(s.peer_count(), 0);
        assert!(s.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn the_rolling_deadline_cannot_outlive_the_hard_ceiling() {
        // Regression: `extract_session` set `expires_at = now + session_ttl` on
        // every authenticated request, `/api/ping` included, and the desktop
        // pings every 90 seconds. So the only token the idle timeout ever
        // expired was one nobody was using — a stolen bearer token, which is
        // being used by definition, renewed itself forever. The comment on
        // `Session` claimed otherwise, which is worse than no comment.
        let s = state(false);
        let issued = Instant::now();
        let sess = Session {
            vault_key: [7u8; 32],
            user_id: "u".into(),
            is_owner: false,
            // A full idle window ahead, as a request that just landed would set.
            expires_at: issued + s.session_ttl,
            // …but the session was minted a minute ago with a ceiling that has
            // already passed.
            hard_expires_at: issued - Duration::from_secs(1),
        };
        assert!(
            sess.deadline() < Instant::now(),
            "a session past its ceiling must be dead however recently it was used"
        );

        let mut map = HashMap::new();
        map.insert("stolen".to_string(), sess);
        purge_expired(&mut map);
        assert!(
            map.is_empty(),
            "purge must drop it, zeroizing the vault key"
        );
    }

    #[test]
    fn a_zero_ceiling_means_no_ceiling() {
        let d = scratch("nocap");
        let s = AppState::new(
            d.join("vault.db"),
            d.join("vault.salt"),
            None,
            480,
            0,
            false,
        );
        assert_eq!(s.session_max_lifetime, NEVER);
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
        let (_, first) = ensure_self_signed_cert(&dir).unwrap();
        let (_, second) = ensure_self_signed_cert(&dir).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64, "SHA-256 hex fingerprint");
    }

    #[test]
    fn idle_seconds_start_near_zero() {
        assert!(state(true).idle_secs() < 5);
    }
}

#[cfg(test)]
mod selective_read_tests {
    use super::*;

    fn q() -> EntryQuery {
        EntryQuery {
            project: None,
            provider: None,
            category: None,
            env: None,
            providers: None,
        }
    }

    fn vault() -> serde_json::Value {
        serde_json::json!({
            "api_keys": [
                { "provider": "WebKey", "projectIds": ["web"], "environment": "production",
                  "categories": ["infra"] },
                { "provider": "ApiKey", "projectIds": ["api"], "environment": "staging",
                  "categories": [] },
                { "provider": "Shared", "projectIds": ["Universal"], "categories": ["infra"] }
            ],
            "projects": [
                { "id": "web", "name": "Web" },
                { "id": "api", "name": "Api" }
            ]
        })
    }

    fn names(v: &[serde_json::Value]) -> Vec<&str> {
        v.iter()
            .map(|e| e["provider"].as_str().unwrap_or(""))
            .collect()
    }

    #[test]
    fn no_filter_returns_everything_visible() {
        let out = filter_entries(&vault(), &q(), None, None);
        assert_eq!(names(&out), ["WebKey", "ApiKey", "Shared"]);
    }

    #[test]
    fn filters_by_project_id() {
        let out = filter_entries(&vault(), &q(), Some(&["web".to_string()]), None);
        assert_eq!(names(&out), ["WebKey"]);
    }

    #[test]
    fn filters_by_provider_environment_and_category() {
        let mut qq = q();
        qq.provider = Some("ApiKey".into());
        assert_eq!(
            names(&filter_entries(&vault(), &qq, None, None)),
            ["ApiKey"]
        );

        let mut qq = q();
        qq.env = Some("production".into());
        assert_eq!(
            names(&filter_entries(&vault(), &qq, None, None)),
            ["WebKey"]
        );

        let mut qq = q();
        qq.category = Some("infra".into());
        assert_eq!(
            names(&filter_entries(&vault(), &qq, None, None)),
            ["WebKey", "Shared"]
        );
    }

    #[test]
    fn a_batch_read_returns_only_the_names_asked_for() {
        let wanted = ["Shared".to_string(), "ApiKey".to_string()];
        let out = filter_entries(&vault(), &q(), None, Some(&wanted));
        assert_eq!(names(&out), ["ApiKey", "Shared"]);
    }

    #[test]
    fn filters_combine_with_and_not_or() {
        // Two filters must narrow, not widen. ORing them would return entries
        // the caller did not ask for, and for a scoped user that reads as a leak
        // even when permissions were applied correctly upstream.
        let mut qq = q();
        qq.env = Some("production".into());
        let out = filter_entries(&vault(), &qq, Some(&["api".to_string()]), None);
        assert!(out.is_empty(), "{:?}", names(&out));
    }

    #[test]
    fn an_unmatched_filter_is_empty_not_an_error() {
        // "no entries in project X" and "no such project X" must be
        // indistinguishable from outside, or the endpoint enumerates project
        // names for anyone who can reach it.
        let out = filter_entries(&vault(), &q(), Some(&[]), None);
        assert!(out.is_empty());
        let out = filter_entries(&vault(), &q(), Some(&["nonexistent".to_string()]), None);
        assert!(out.is_empty());
    }

    #[test]
    fn the_filter_can_only_narrow_what_it_was_given() {
        // The handler passes an already permission-filtered vault. This pins the
        // property that makes that safe: nothing here can produce an entry that
        // was not in the input.
        let restricted = serde_json::json!({
            "api_keys": [{ "provider": "WebKey", "projectIds": ["web"] }],
            "projects": [{ "id": "web", "name": "Web" }]
        });
        let mut qq = q();
        qq.provider = Some("ApiKey".into());
        assert!(filter_entries(&restricted, &qq, None, None).is_empty());
        let all = filter_entries(&restricted, &q(), None, None);
        assert_eq!(names(&all), ["WebKey"]);
    }
}
