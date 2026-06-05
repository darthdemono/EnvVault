//! `apiv-server` — remote vault HTTP server (Phase 5 with multi-user RBAC).
//!
//! # Auth flows
//! - Owner: `POST /api/unlock` with master password → owner session token.
//! - User:  `POST /api/auth` with username+password or `{ token }` → user session token.
//!          Requires the vault to be unlocked by the owner first.
//!
//! # Sessions
//! All sessions are in-memory (restart = re-auth).  Each session stores:
//! - The vault key (AES-256 — owner's key, shared to user sessions after auth)
//! - Whether the session belongs to the owner
//! - The user ID (for permission lookups)

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use utoipa::{OpenApi, ToSchema};
use vault_core::{
    derive_key, filter_vault_for_user, get_expiring_entries, get_user_permissions,
    init_schema, load_audit, load_vault, merge_user_vault_write, open_db,
    read_or_create_salt, save_vault, verify_vault_integrity,
    verify_totp_code, totp_enabled, enable_totp, disable_totp,
    PermissionRecord, VaultKey, Zeroize,
};
use std::time::{Duration, Instant};

// ── Session model ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Session {
    vault_key: VaultKey,
    user_id:   String,
    is_owner:  bool,
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct RateBucket { attempts: u32, window_start: Option<Instant> }

fn check_rate_limit(buckets: &mut HashMap<String, RateBucket>, key: &str) -> bool {
    let bucket = buckets.entry(key.to_string()).or_default();
    let now = Instant::now();
    match bucket.window_start {
        Some(ws) if now.duration_since(ws) < Duration::from_secs(60) => {
            bucket.attempts += 1;
            bucket.attempts <= 10  // 10 attempts per minute per IP
        }
        _ => {
            bucket.window_start = Some(now);
            bucket.attempts = 1;
            true
        }
    }
}

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    sessions:  Arc<Mutex<HashMap<String, Session>>>,
    rate_limiter: Arc<Mutex<HashMap<String, RateBucket>>>,
    db_path:   PathBuf,
    salt_path: PathBuf,
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct UnlockRequest { password: String }

#[derive(Serialize, ToSchema)]
struct UnlockResponse { token: String }

#[derive(Serialize, ToSchema)]
struct StatusResponse { unlocked: bool, vault_exists: bool }

#[derive(Serialize, ToSchema)]
struct ErrorResponse { error: String }

#[derive(Deserialize, ToSchema)]
struct AuthRequest {
    username:  Option<String>,
    password:  Option<String>,
    token:     Option<String>,
    totp_code: Option<String>,  // 6-digit TOTP code when 2FA is enabled
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
struct ExpiringQuery {
    #[serde(default = "default_days")]
    days: u32,
}
fn default_days() -> u32 { 30 }

// ── Auth helpers ──────────────────────────────────────────────────────────────

fn extract_session<'a>(headers: &HeaderMap, state: &'a AppState) -> Result<(String, Session), (StatusCode, Json<serde_json::Value>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err_json(StatusCode::UNAUTHORIZED, "Missing Bearer token"))?;
    let session = state.sessions.lock().unwrap().get(token).cloned()
        .ok_or_else(|| err_json(StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;
    Ok((token.to_string(), session))
}

fn require_owner(session: &Session) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if session.is_owner { Ok(()) } else { Err(err_json(StatusCode::FORBIDDEN, "Owner access required")) }
}

fn err_json(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": msg })))
}

fn owner_vault_key(state: &AppState) -> Option<VaultKey> {
    state.sessions.lock().unwrap().values().find(|s| s.is_owner).map(|s| s.vault_key)
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
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<UnlockRequest>,
) -> impl IntoResponse {
    // Rate limit by IP (item 1)
    let ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    if !check_rate_limit(&mut state.rate_limiter.lock().unwrap(), &ip) {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many attempts — try again in a minute").into_response();
    }

    let salt = match read_or_create_salt(&state.salt_path) {
        Ok(s) => s, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let key = match derive_key(&req.password, &salt) {
        Ok(k) => k, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let conn = match open_db(&state.db_path, &key) {
        Ok(conn) => { let _ = init_schema(&conn); conn }
        Err(_)   => return err_json(StatusCode::UNAUTHORIZED, "Wrong master password").into_response(),
    };
    // Integrity check on unlock (item 5)
    match verify_vault_integrity(&conn) {
        Ok(false) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "Vault integrity check failed — data may be tampered").into_response(),
        Err(e)    => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        Ok(true)  => {}
    }
    let token = uuid::Uuid::new_v4().to_string();
    state.sessions.lock().unwrap().insert(token.clone(), Session {
        vault_key: key, user_id: "owner".to_string(), is_owner: true,
    });
    (StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response()
}

/// Lock the vault (invalidate current session).
#[utoipa::path(
    delete, path = "/api/unlock",
    responses((status = 204, description = "Locked")),
    tag = "auth", security(("bearer_auth" = []))
)]
async fn lock(headers: HeaderMap, State(state): State<AppState>) -> StatusCode {
    if let Some(token) = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        let mut sessions = state.sessions.lock().unwrap();
        if let Some(mut s) = sessions.remove(token) { s.vault_key.zeroize(); }
    }
    StatusCode::NO_CONTENT
}

/// Return vault locked/exists status.
#[utoipa::path(
    get, path = "/api/status",
    responses((status = 200, description = "OK", body = StatusResponse)),
    tag = "auth"
)]
async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        unlocked:     !state.sessions.lock().unwrap().is_empty(),
        vault_exists: state.db_path.exists(),
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
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> impl IntoResponse {
    // Rate limit by IP (item 1)
    let ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    if !check_rate_limit(&mut state.rate_limiter.lock().unwrap(), &ip) {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many attempts — try again in a minute").into_response();
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
            // TOTP check (item 4) — if user has 2FA enabled, require valid code
            if totp_enabled(&conn, &user.id).unwrap_or(false) {
                let code = req.totp_code.as_deref().unwrap_or("");
                if code.is_empty() {
                    return err_json(StatusCode::UNAUTHORIZED, "TOTP code required").into_response();
                }
                match verify_totp_code(&conn, &user.id, code) {
                    Ok(true) => {}
                    Ok(false) => return err_json(StatusCode::UNAUTHORIZED, "Invalid TOTP code").into_response(),
                    Err(e)   => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
                }
            }
            let session_token = uuid::Uuid::new_v4().to_string();
            state.sessions.lock().unwrap().insert(session_token.clone(), Session {
                vault_key: key,
                user_id:   user.id,
                is_owner:  false,
            });
            (StatusCode::OK, Json(serde_json::json!({ "token": session_token }))).into_response()
        }
        Ok(None) => err_json(StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
        Err(e)   => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
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
        Ok(None)    => serde_json::json!({ "api_keys": [], "user_categories": [], "projects": [] }),
        Err(e)      => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };

    if session.is_owner {
        return Json(vault).into_response();
    }

    // Filter vault for non-owner
    match get_user_permissions(&conn, &session.user_id) {
        Ok(perms) => Json(filter_vault_for_user(vault, &perms)).into_response(),
        Err(e)    => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
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
    let conn = match open_db(&state.db_path, &session.vault_key) {
        Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };

    if session.is_owner {
        return match save_vault(&conn, data) {
            Ok(())  => StatusCode::NO_CONTENT.into_response(),
            Err(e)  => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        };
    }

    // Non-owner: merge with write permission check
    let perms = match get_user_permissions(&conn, &session.user_id) {
        Ok(p) => p, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let full_vault = match load_vault(&conn) {
        Ok(Some(v)) => v,
        Ok(None)    => serde_json::json!({ "api_keys": [], "user_categories": [], "projects": [] }),
        Err(e)      => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    let merged = match merge_user_vault_write(full_vault, data, &perms) {
        Ok(v)  => v,
        Err(e) => return err_json(StatusCode::FORBIDDEN, &e).into_response(),
    };
    match save_vault(&conn, merged) {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
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
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match get_expiring_entries(&conn, q.days) {
            Ok(entries) => Json(entries).into_response(),
            Err(e)      => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        },
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

// ── User management (owner-only) ──────────────────────────────────────────────

async fn list_users_handler(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    if let Err(e) = require_owner(&session) { return e.into_response(); }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match vault_core::list_users(&conn) {
            Ok(users) => Json(users).into_response(),
            Err(e)    => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn create_user_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    if let Err(e) = require_owner(&session) { return e.into_response(); }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match vault_core::create_user(&conn, &req.username, req.password.as_deref(), false) {
            Ok(user) => (StatusCode::CREATED, Json(serde_json::to_value(user).unwrap())).into_response(),
            Err(e)   => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn delete_user_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    if let Err(e) = require_owner(&session) { return e.into_response(); }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match vault_core::delete_user(&conn, &user_id) {
            Ok(())  => StatusCode::NO_CONTENT.into_response(),
            Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn list_tokens_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    if let Err(e) = require_owner(&session) { return e.into_response(); }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match vault_core::list_user_tokens(&conn, &user_id) {
            Ok(tokens) => Json(tokens).into_response(),
            Err(e)     => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn create_token_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(req): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    if let Err(e) = require_owner(&session) { return e.into_response(); }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match vault_core::create_user_token(
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
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn revoke_token_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((_user_id, token_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    if let Err(e) = require_owner(&session) { return e.into_response(); }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match vault_core::revoke_user_token(&conn, &token_id) {
            Ok(())  => StatusCode::NO_CONTENT.into_response(),
            Err(e)  => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn get_permissions_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    if let Err(e) = require_owner(&session) { return e.into_response(); }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match vault_core::get_user_permissions(&conn, &user_id) {
            Ok(perms) => Json(perms).into_response(),
            Err(e)    => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn set_permissions_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(perms): Json<Vec<PermissionRecord>>,
) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    if let Err(e) = require_owner(&session) { return e.into_response(); }
    match open_db(&state.db_path, &session.vault_key) {
        Ok(conn) => match vault_core::set_user_permissions(&conn, &user_id, &perms) {
            Ok(())  => StatusCode::NO_CONTENT.into_response(),
            Err(e)  => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

// ── Keep-alive ping (item 16) ─────────────────────────────────────────────────

/// Extend the current session expiry. Returns 200 OK with server timestamp.
async fn ping(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    match extract_session(&headers, &state) {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({ "ok": true, "ts": vault_core::iso_now() }))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ── TOTP management (item 4) ──────────────────────────────────────────────────

async fn totp_enable_handler(headers: HeaderMap, State(state): State<AppState>, axum::extract::Path(user_id): axum::extract::Path<String>) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let key = session.vault_key;
    let conn = match open_db(&state.db_path, &key) { Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response() };
    match enable_totp(&conn, &user_id) {
        Ok(secret) => (StatusCode::OK, Json(serde_json::json!({ "secret": secret, "otpauth": format!("otpauth://totp/APIVault:{}?secret={}&issuer=APIVault", user_id, secret) }))).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

async fn totp_disable_handler(headers: HeaderMap, State(state): State<AppState>, axum::extract::Path(user_id): axum::extract::Path<String>) -> impl IntoResponse {
    let (_, session) = match extract_session(&headers, &state) { Ok(s) => s, Err(e) => return e.into_response() };
    let conn = match open_db(&state.db_path, &session.vault_key) { Ok(c) => c, Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response() };
    match disable_totp(&conn, &user_id) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

// ── OpenAPI spec ──────────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    paths(unlock, lock, status, auth_user, get_vault, put_vault, expiring, audit),
    components(schemas(UnlockRequest, UnlockResponse, StatusResponse, ErrorResponse, AuthRequest)),
    info(
        title   = "API Vault Server",
        version = "0.5.0",
        description = "Remote vault API — owner unlocks, users authenticate with /api/auth."
    ),
    tags(
        (name = "auth",  description = "Session management"),
        (name = "vault", description = "Vault read/write"),
        (name = "audit", description = "Append-only audit log"),
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

// ── CLI args ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "apiv-server", version = "0.5.0", about = "API Vault remote vault server")]
struct Args {
    #[arg(long, default_value_t = 8743)] port:      u16,
    #[arg(long, default_value = "127.0.0.1")] host: String,
    #[arg(long)] db_path:   Option<PathBuf>,
    #[arg(long)] salt_path: Option<PathBuf>,
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/var/lib"))
        .join("apiv-server");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let db_path   = args.db_path.unwrap_or_else(|| data_dir.join("vault.db"));
    let salt_path = args.salt_path.unwrap_or_else(|| data_dir.join("vault.salt"));

    let state = AppState {
        sessions:     Arc::new(Mutex::new(HashMap::new())),
        rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        db_path,
        salt_path,
    };

    let cors = tower_http::cors::CorsLayer::permissive();

    use axum::routing::{delete, post};
    let vault_routes = Router::new()
        .route("/api/unlock",                   post(unlock).delete(lock))
        .route("/api/status",                   get(status))
        .route("/api/auth",                     post(auth_user))
        .route("/api/vault",                    get(get_vault).put(put_vault))
        .route("/api/vault/expiring",           get(expiring))
        .route("/api/audit",                    get(audit))
        // User management (owner-only)
        .route("/api/users",                    get(list_users_handler).post(create_user_handler))
        .route("/api/users/{user_id}",           delete(delete_user_handler))
        .route("/api/users/{user_id}/tokens",    get(list_tokens_handler).post(create_token_handler))
        .route("/api/users/{user_id}/tokens/{token_id}", delete(revoke_token_handler))
        .route("/api/users/{user_id}/permissions", get(get_permissions_handler).put(set_permissions_handler))
        .route("/api/users/{user_id}/totp",        axum::routing::post(totp_enable_handler).delete(totp_disable_handler))
        .route("/api/ping",                        get(ping))
        .with_state(state);

    let app: Router = Router::new()
        .merge(vault_routes)
        .route("/api/openapi.json", get(|| async { Json(ApiDoc::openapi()) }))
        .layer(cors);

    let addr = format!("{}:{}", args.host, args.port);
    println!("apiv-server  →  http://{addr}");
    println!("OpenAPI JSON →  http://{addr}/api/openapi.json");
    println!("Users API    →  http://{addr}/api/users  (owner-only)");

    let listener = tokio::net::TcpListener::bind(&addr).await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    axum::serve(listener, app).await.expect("server error");
}
